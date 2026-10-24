//! Service builder for constructing all services from configuration.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use observability::logging::RedactedUrl;

use crate::orchestrator::dispatch::DispatchLimits;
use crate::orchestrator::{OrchestratorConfig, PubkeyMap};
use crate::quiesce::{QuiesceRegistry, QuiescingEnablement, TrackedKeys};
use beacon::{BeaconClient, BeaconClientConfig};
#[cfg(test)]
use bn_manager::DutiesProvider;
use bn_manager::{AttestationSubmitter, BeaconNodeClient, BnManager, BnManagerConfig, Propagator};
use builder::BuilderService;
use crypto::{CompositeSigner, KeyManager};
use doppelganger::{
    DoppelgangerDisabledByOperator, ForwardWindowMachine, MonotonicEpochClock, SigningEnablement,
    DEFAULT_MONITORING_EPOCHS,
};
#[cfg(test)]
use duty_tracker::DutyTracker;
use eth_types::{Epoch, ForkSchedule, Root, SLOTS_PER_EPOCH};
use rvc_config::TimingConfig;
use signer::{SignerService, ValidatorSigner};
use slashing::{GroupCommitConfig, SlashingDb};
use timing::{DeadlineBps, DeadlineSchedule, SystemSlotClock};
use validator_store::ValidatorStore;

use secret_provider::SecretProvider;

use super::error::ConfigError;
use super::types::Config;

fn format_version(v: eth_types::Version) -> String {
    format!("0x{}", hex::encode(v))
}

/// Resolve a filesystem identity for `path` by walking up to the nearest existing
/// ancestor (Unix: `st_dev`). Returns `None` when the device cannot be determined
/// (non-Unix, or no existing ancestor).
fn filesystem_id(path: &Path) -> Option<u64> {
    let mut current = path;
    loop {
        if let Ok(meta) = std::fs::metadata(current) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                return Some(meta.dev());
            }
            #[cfg(not(unix))]
            {
                let _ = meta;
                return None;
            }
        }
        current = current.parent()?;
        if current.as_os_str().is_empty() {
            return None;
        }
    }
}

/// Returns `Some(true)` when the two paths resolve to different filesystems,
/// `Some(false)` when they share a device, and `None` when the comparison is
/// unavailable (non-Unix or neither path has an existing ancestor).
fn paths_on_different_filesystems(a: &Path, b: &Path) -> Option<bool> {
    let a_id = filesystem_id(a)?;
    let b_id = filesystem_id(b)?;
    Some(a_id != b_id)
}

/// SEC-3 post-open gate: a fresh create without opt-in must never proceed to sign.
///
/// Closes the TOCTOU between the builder's pre-open `path.exists()` check and
/// `SlashingDb::open_with_create_info` (volume unmount / concurrent delete).
fn reject_accidental_fresh_create(
    path: &std::path::Path,
    created_fresh: bool,
    allow_fresh_db: bool,
) -> Result<(), ConfigError> {
    if created_fresh && !allow_fresh_db {
        error!(
            path = %path.display(),
            "Refusing accidental fresh slashing DB (created without allow_fresh_db / \
             --init-slashing-db). Path was missing at open time — possible TOCTOU \
             (volume unmounted, concurrent delete, or path race). Restore history \
             from backup or re-run with explicit opt-in for a genuine first deploy."
        );
        return Err(ConfigError::SlashingDbMissing(path.to_path_buf()));
    }
    Ok(())
}

/// Best-effort cleanup of a DB file created without opt-in (and SQLite sidecars).
///
/// SQLite WAL filenames use `-wal` / `-shm` suffixes (no separator dot).
fn remove_accidental_fresh_db(path: &std::path::Path) {
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let stem = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let candidates = [
        path.to_path_buf(),
        parent.join(format!("{stem}-wal")),
        parent.join(format!("{stem}-shm")),
    ];
    for p in &candidates {
        if !p.exists() {
            continue;
        }
        if let Err(e) = std::fs::remove_file(p) {
            error!(
                path = %p.display(),
                error = %e,
                "failed to remove accidental fresh slashing DB artifact; \
                 delete it manually before retrying"
            );
        }
    }
}

/// Builder for constructing services from configuration.
pub struct ServiceBuilder {
    config: Config,
}

/// Wall-clock length of the doppelganger store hold and import-meta re-arm.
///
/// [`DEFAULT_MONITORING_EPOCHS`] at `slot_duration_ms` from the beacon node.
/// Boot sidecar classification does not use this value: a sidecar stays
/// unfinished until this process removes it after the forward window reaches Safe.
///
/// `slot_duration_ms` must be the positive duration from the beacon node spec.
pub(crate) fn doppelganger_import_window(slot_duration_ms: u64) -> Duration {
    Duration::from_millis(
        DEFAULT_MONITORING_EPOCHS.saturating_mul(SLOTS_PER_EPOCH).saturating_mul(slot_duration_ms),
    )
}

/// Pubkeys that must use [`ForwardWindowMachine::register_for_import`] at boot.
struct UnfinishedImports {
    /// The keystore directory or validators file could not be read.
    /// Every loaded key is then import-strict.
    force_all: bool,
    pubkeys: HashSet<[u8; 48]>,
}

impl UnfinishedImports {
    fn contains(&self, pubkey: &[u8; 48]) -> bool {
        self.force_all || self.pubkeys.contains(pubkey)
    }
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

/// Kind of import-meta sidecar on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportSidecarKind {
    /// Final `0x<pubkey>.import_meta.json`.
    Final,
    /// Staged `0x<pubkey>.import_meta.json.partial`.
    Partial,
    /// Leftover `0x<pubkey>.import_meta.json.removing.<n>` from an older
    /// rename-aside cleanup. Boot treats these as unfinished so a crash
    /// between rename and put-back cannot lose the marker.
    Removing,
}

/// Sidecars under `keystore_dir` that still mark an import as unfinished.
///
/// A missing directory is an empty set. A path that is not a directory, or
/// a directory that cannot be listed, is an error (caller fails closed).
/// Any `*.import_meta.json`, `*.import_meta.json.partial`, or leftover
/// `*.import_meta.json.removing.*` is unfinished, whatever its timestamp.
/// Completion is [`clear_completed_import_sidecars`], which runs only after
/// this process has observed the forward window to Safe. A sidecar that
/// cannot be read or parsed is unfinished as well.
fn scan_import_sidecars(keystore_dir: &Path) -> Result<HashSet<[u8; 48]>, String> {
    // `Path::exists` collapses permission errors into "missing". A missing
    // directory has no sidecars. Any other metadata error, or a path that is
    // not a directory, fails closed.
    match std::fs::metadata(keystore_dir) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(format!("{} is not a directory", keystore_dir.display()));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(HashSet::new());
        }
        Err(err) => return Err(err.to_string()),
    }
    let entries = std::fs::read_dir(keystore_dir).map_err(|e| e.to_string())?;
    let mut strict = HashSet::new();
    for entry in entries {
        let entry = entry.map_err(|e| e.to_string())?;
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some((pubkey, kind)) = import_sidecar_pubkey(&name) else {
            continue;
        };
        note_import_sidecar(&entry.path(), kind);
        strict.insert(pubkey);
    }
    Ok(strict)
}

/// `(pubkey, kind)` when `name` is an import-meta sidecar (final, partial, or
/// leftover `.removing.*`).
pub(crate) fn import_sidecar_pubkey(name: &str) -> Option<([u8; 48], ImportSidecarKind)> {
    let hex_part = name.strip_prefix("0x")?;
    let (hex_body, kind) = if let Some(rest) = hex_part.strip_suffix(".import_meta.json.partial") {
        (rest, ImportSidecarKind::Partial)
    } else if let Some(idx) = hex_part.find(".import_meta.json.removing.") {
        let rest = &hex_part[..idx];
        let after = &hex_part[idx + ".import_meta.json.removing.".len()..];
        if after.is_empty() || !after.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        (rest, ImportSidecarKind::Removing)
    } else {
        let rest = hex_part.strip_suffix(".import_meta.json")?;
        (rest, ImportSidecarKind::Final)
    };
    let bytes = hex::decode(hex_body).ok()?;
    if bytes.len() != 48 {
        return None;
    }
    let mut pubkey = [0u8; 48];
    pubkey.copy_from_slice(&bytes);
    Some((pubkey, kind))
}

/// Log why a present sidecar keeps its key Pending. Presence itself is the marker.
fn note_import_sidecar(path: &Path, kind: ImportSidecarKind) {
    match kind {
        ImportSidecarKind::Partial => {
            warn!(
                path = %path.display(),
                "doppelganger: staged import sidecar still present; key stays Pending"
            );
            return;
        }
        ImportSidecarKind::Removing => {
            warn!(
                path = %path.display(),
                "doppelganger: leftover import-sidecar set-aside still present; key stays Pending"
            );
            return;
        }
        ImportSidecarKind::Final => {}
    }
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) => {
            warn!(
                path = %path.display(),
                error = %err,
                "doppelganger: unreadable import sidecar; key stays Pending"
            );
            return;
        }
    };
    let has_timestamp = serde_json::from_str::<serde_json::Value>(&content)
        .ok()
        .and_then(|v| v.get("imported_unix_seconds").and_then(|t| t.as_u64()))
        .is_some();
    if !has_timestamp {
        warn!(
            path = %path.display(),
            "doppelganger: import sidecar has no imported_unix_seconds; key stays Pending"
        );
    }
}

fn fsync_keystore_dir(keystore_dir: &Path, context: &str) {
    match std::fs::File::open(keystore_dir) {
        Ok(dir) => {
            if let Err(err) = dir.sync_all() {
                warn!(
                    path = %keystore_dir.display(),
                    error = %err,
                    context,
                    "doppelganger: failed to fsync keystore directory after import-sidecar update"
                );
            }
        }
        Err(err) => {
            warn!(
                path = %keystore_dir.display(),
                error = %err,
                context,
                "doppelganger: failed to open keystore directory to fsync after import-sidecar update"
            );
        }
    }
}

/// Remove import sidecars for keys this process has observed to Safe.
///
/// The sidecar is the durable unfinished marker. Deleting it, then fsyncing
/// the directory, records that this VC completed the forward window. A key
/// that is not Safe keeps its sidecar. A failed delete leaves the marker, so
/// the next boot stays Pending. Age is not an input.
///
/// Unlink holds [`TrackedKeys`] across the Safe re-check and `unlink`, the
/// same lock DELETE and import use. That serializes cleanup against a
/// concurrent DELETE + re-import that would otherwise publish a newer sidecar
/// between the Safe check and the unlink. Markers are never deleted unless
/// that lock is held and the key is still Safe. Leftover
/// `*.import_meta.json.removing.*` files from older rename-aside cleanups are
/// removed the same way when the key is Safe.
pub(crate) fn clear_completed_import_sidecars(
    keystore_dir: &Path,
    tracked_keys: &TrackedKeys,
    is_safe: impl Fn(&[u8; 48]) -> bool,
) {
    clear_completed_import_sidecars_inner(keystore_dir, tracked_keys, is_safe, None);
}

fn clear_completed_import_sidecars_inner(
    keystore_dir: &Path,
    tracked_keys: &TrackedKeys,
    is_safe: impl Fn(&[u8; 48]) -> bool,
    during_locked: Option<&dyn Fn(&Path)>,
) {
    let entries = match std::fs::read_dir(keystore_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return,
        Err(err) => {
            warn!(
                path = %keystore_dir.display(),
                error = %err,
                "doppelganger: cannot list keystore directory to record forward-window completion"
            );
            return;
        }
    };
    let mut removed = false;
    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Some((pubkey, _kind)) = import_sidecar_pubkey(&name) else {
            continue;
        };
        // Hold the same lock as DELETE/import for the Safe re-check and unlink.
        // Releasing earlier would let a concurrent re-import publish a newer
        // sidecar that this cleanup would then delete.
        let _guard = tracked_keys.lock();
        if !is_safe(&pubkey) {
            continue;
        }
        let path = entry.path();
        // Confirm the path still looks like a marker under the lock. A DELETE
        // that ran before we took the lock may have already removed it.
        if !path.exists() {
            continue;
        }
        if !is_safe(&pubkey) {
            continue;
        }
        if let Some(hook) = during_locked {
            hook(&path);
        }
        // Re-check after the test hook: a concurrent re-import that somehow
        // mutated Safe without the lock must not lose its marker. Production
        // import holds this same lock, so the hook is the only way Safe can
        // flip here.
        if !is_safe(&pubkey) {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(()) => {
                removed = true;
                let pk_hex = hex::encode(pubkey);
                info!(
                    pubkey = %observability::logging::TruncatedPubkey::new(&pk_hex),
                    path = %path.display(),
                    "doppelganger: forward window observed; removed import sidecar"
                );
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                warn!(
                    path = %path.display(),
                    error = %err,
                    "doppelganger: failed to unlink import sidecar while holding tracked_keys; \
                     the marker remains on disk so the next boot stays Pending"
                );
            }
        }
    }
    if !removed {
        return;
    }
    fsync_keystore_dir(keystore_dir, "removing an import sidecar");
}

/// Holds whose deadline is still in the future. An unreadable file is an error.
fn open_doppelganger_holds(
    path: &Path,
    pubkey_map: &PubkeyMap,
    now_unix: u64,
) -> Result<HashSet<[u8; 48]>, String> {
    let store = ValidatorStore::load_from_config(path).map_err(|e| e.to_string())?;
    let mut open = HashSet::new();
    for pubkey in pubkey_map.read().keys() {
        let Some(until) = store.get_config(pubkey).and_then(|cfg| cfg.doppelganger_hold_until)
        else {
            continue;
        };
        if until > now_unix {
            open.insert(*pubkey);
        }
    }
    Ok(open)
}

impl ServiceBuilder {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn log_effective_config(&self) {
        let redacted_bns: Vec<String> = self
            .config
            .effective_beacon_nodes()
            .iter()
            .map(|u| format!("{}", RedactedUrl(u)))
            .collect();

        info!(
            bn_urls = ?redacted_bns,
            key_dir = ?self.config.keystore_path,
            network = %self.config.network,
            features = %format!(
                "doppelganger={}, builder=true, keymanager={}",
                self.config.doppelganger_detection,
                self.config.keymanager.enabled
            ),
            "Effective configuration"
        );

        info!(
            doppelganger_enabled = self.config.doppelganger_detection,
            builder_enabled = true,
            keymanager_enabled = self.config.keymanager.enabled,
            "Feature toggles"
        );

        self.warn_keystore_slashing_path_divergence();
    }

    /// Warn when `keystore_path` and `slashing_db_path` resolve to different
    /// filesystems (SEC-10).
    ///
    /// Independently settable paths can hide a copied-data-dir deployment where
    /// only one of the two volumes is moved to a new host, defeating same-host
    /// mutual exclusion and risking double-signing.
    pub fn warn_keystore_slashing_path_divergence(&self) {
        let keystore = &self.config.keystore_path;
        let slashing = &self.config.slashing_db_path;
        if paths_on_different_filesystems(keystore, slashing) == Some(true) {
            warn!(
                keystore_path = %keystore.display(),
                slashing_db_path = %slashing.display(),
                "keystore_path and slashing_db_path appear to be on different \
                 filesystems; a partial data-dir copy can leave the slashing DB \
                 behind and enable double-signing. Keep both on the same durable \
                 volume, and never run the same keys on two hosts."
            );
        }
    }

    /// Build a single-endpoint [`BeaconClient`].
    ///
    /// Still constructed at startup. Not the keymanager voluntary-exit path:
    /// that uses [`Self::build_bn_manager`]. Runtime block production, duties,
    /// and attestation use the pool as well ([`Self::build_proposer_bn_manager`]
    /// when a proposer pool is configured).
    ///
    /// Unlike `BnManager` (which sets `max_retries = 0` and relies on pool
    /// failover — see `bn_manager::BnManager`), a standalone client keeps a
    /// small HTTP retry budget.
    pub fn build_beacon(&self) -> Result<Arc<BeaconClient>, ConfigError> {
        let beacon_config = BeaconClientConfig::new(&self.config.beacon_url)
            .with_timeout(Duration::from_secs(30))
            .with_max_retries(3)
            .with_max_body_bytes(self.config.beacon_max_body_bytes);

        let client = BeaconClient::new(beacon_config)?;
        info!(
            url = %self.config.beacon_url,
            max_body_bytes = self.config.beacon_max_body_bytes,
            "Created single-endpoint beacon client (not the keymanager exit path)"
        );
        Ok(Arc::new(client))
    }

    /// Shared pool config for main and proposer `BnManager`s: H-12 body cap and
    /// global broadcast-topic policy (including `blocks` for publish path).
    fn pool_bn_manager_config(&self, endpoints: Vec<String>) -> BnManagerConfig {
        let mut config =
            BnManagerConfig::new(endpoints).with_max_body_bytes(self.config.beacon_max_body_bytes);
        config.broadcast_topics = self.config.effective_broadcast_topics();
        config.fee_recipient_policy = self.config.fee_recipient_policy;
        config
    }

    pub fn build_bn_manager(&self) -> Result<Arc<BnManager>, ConfigError> {
        self.build_bn_manager_with_timeouts(bn_manager::OperationTimeouts::default())
    }

    /// Build the main-pool [`BnManager`] with operator-configured per-op timeouts.
    pub fn build_bn_manager_with_timeouts(
        &self,
        timeouts: bn_manager::OperationTimeouts,
    ) -> Result<Arc<BnManager>, ConfigError> {
        let endpoints = self.config.effective_beacon_nodes();
        let config = self.pool_bn_manager_config(endpoints.clone());
        let broadcast_topics = config.broadcast_topics.clone();
        let manager = BnManager::new(config)
            .map_err(|e| {
                ConfigError::InvalidBeaconUrl(format!("failed to create BnManager: {}", e))
            })?
            .with_operation_timeouts(timeouts);
        info!(
            endpoints = ?endpoints,
            broadcast_topics = ?broadcast_topics,
            max_body_bytes = self.config.beacon_max_body_bytes,
            "Created BnManager with {} beacon nodes",
            endpoints.len()
        );
        Ok(Arc::new(manager))
    }

    /// Builds a separate BnManager for proposer nodes if configured.
    ///
    /// Returns `None` if `proposer_nodes` is empty (main pool handles all).
    ///
    /// Uses the same body-size cap, broadcast-topic policy, and per-operation
    /// timeouts as the main pool, so dedicated proposer publish/produce honor
    /// operator DoS, broadcast, and budget settings.
    ///
    /// An empty `proposer_nodes` list returns `Ok(None)` and does not connect.
    /// A URL that is not `http` or `https` is [`ConfigError::InvalidBeaconUrl`]
    /// and no manager is returned.
    pub fn build_proposer_bn_manager(&self) -> Result<Option<Arc<BnManager>>, ConfigError> {
        if self.config.proposer_nodes.is_empty() {
            return Ok(None);
        }
        let endpoints = self.config.proposer_nodes.clone();
        let config = self.pool_bn_manager_config(endpoints.clone());
        let manager = BnManager::new(config)
            .map_err(|e| {
                ConfigError::InvalidBeaconUrl(format!("failed to create proposer BnManager: {}", e))
            })?
            .with_metric_pool(bn_manager::METRIC_POOL_PROPOSER)
            .with_operation_timeouts(self.config.operation_timeouts());
        info!(
            endpoints = ?endpoints,
            max_body_bytes = self.config.beacon_max_body_bytes,
            "Created proposer BnManager with {} proposer nodes",
            endpoints.len()
        );
        Ok(Some(Arc::new(manager)))
    }

    pub fn build_key_manager(&self) -> Result<Arc<KeyManager>, ConfigError> {
        self.build_key_manager_filtered(None)
    }

    /// Load keystore-dir keys, skipping any pubkey in `denylist` (SEC-1b).
    ///
    /// Returns an owned [`KeyManager`] so callers (notably bootstrap
    /// `load_signing_keys`) can build a [`CompositeSigner`] without
    /// `Arc::try_unwrap`.
    pub fn build_key_manager_owned_filtered(
        &self,
        denylist: Option<&std::collections::HashSet<[u8; 48]>>,
    ) -> Result<KeyManager, ConfigError> {
        let passwords = self.config.load_passwords()?;

        if !self.config.keystore_path.exists() {
            return Err(ConfigError::KeystorePathNotFound(self.config.keystore_path.clone()));
        }

        let mut report = crypto::KeystoreLoadReport::default();
        let key_manager = match KeyManager::load_from_directory_with_threads_filtered_reporting(
            &self.config.keystore_path,
            &passwords,
            self.config.key_decrypt_threads,
            denylist,
            &mut report,
        ) {
            Ok(manager) => manager,
            Err(err @ crypto::KeyManagerError::NoKeystoreFiles) => {
                let empty = KeyManager::new();
                self.config.reject_undecrypted_import_secrets(&empty, denylist, &report)?;
                return Err(err.into());
            }
            Err(err) => return Err(err.into()),
        };
        self.config.reject_undecrypted_import_secrets(&key_manager, denylist, &report)?;
        info!(
            key_count = key_manager.len(),
            path = ?self.config.keystore_path,
            "Loaded validator keys"
        );
        Ok(key_manager)
    }

    /// Load keystore-dir keys, skipping any pubkey in `denylist` (SEC-1b).
    pub fn build_key_manager_filtered(
        &self,
        denylist: Option<&std::collections::HashSet<[u8; 48]>>,
    ) -> Result<Arc<KeyManager>, ConfigError> {
        Ok(Arc::new(self.build_key_manager_owned_filtered(denylist)?))
    }

    pub fn build_slashing_db(&self) -> Result<Arc<SlashingDb>, ConfigError> {
        // SEC-10: surface keystore / slashing-DB volume divergence early.
        self.warn_keystore_slashing_path_divergence();

        let path = &self.config.slashing_db_path;

        if let Some(parent) = path.parent() {
            if !parent.exists() && parent != std::path::Path::new("") {
                return Err(ConfigError::SlashingDbPathInvalid(path.clone()));
            }
        }

        // SEC-3: fail closed on missing / 0-byte / corrupt-header DB.
        //
        // - Missing → require explicit opt-in (`allow_fresh_db` / `--init-slashing-db`).
        // - Present-and-0-byte or bad SQLite header → hard error always (corruption).
        // - Present-and-valid → normal open. Opt-in never wipes a non-empty DB.
        if path.exists() {
            let meta = std::fs::metadata(path).map_err(ConfigError::ReadError)?;
            if meta.len() == 0 {
                return Err(ConfigError::SlashingDbCorrupt(path.clone()));
            }
        } else if !self.config.allow_fresh_db {
            return Err(ConfigError::SlashingDbMissing(path.clone()));
        } else {
            error!(
                path = %path.display(),
                "CREATING A NEW EMPTY SLASHING PROTECTION DATABASE. \
                 This DB has ZERO signing history. If this validator was \
                 previously active (or this path previously held a slashing \
                 DB), signing with a fresh DB can DOUBLE-SIGN and get the \
                 validator SLASHED. Only proceed for a genuine first-time \
                 deployment. Opt-in was granted via allow_fresh_db / \
                 --init-slashing-db."
            );
        }

        let (db, created_fresh) = SlashingDb::open_with_create_info(path).map_err(|e| {
            // Surface corrupt/empty as the dedicated config error for clearer
            // operator guidance; other slashing errors pass through unchanged.
            match e {
                slashing::SlashingError::CorruptOrEmpty { .. } => {
                    ConfigError::SlashingDbCorrupt(path.clone())
                }
                other => ConfigError::SlashingDbError(other),
            }
        })?;

        // SEC-3 TOCTOU close: pre-open `path.exists()` can race with a disappearing
        // volume / concurrent delete. `open_with_create_info` reports whether it
        // actually created a fresh zero-history DB — refuse that outcome without
        // opt-in so we never sign with accidental empty history.
        if let Err(e) =
            reject_accidental_fresh_create(path, created_fresh, self.config.allow_fresh_db)
        {
            // Drop the connection so the accidental file can be unlinked.
            drop(db);
            remove_accidental_fresh_db(path);
            return Err(e);
        }

        if created_fresh {
            error!(
                path = %path.display(),
                "Opened freshly created slashing protection database (zero history)"
            );
        } else {
            info!(path = ?path, "Opened slashing protection database");
        }
        db.set_group_commit(
            GroupCommitConfig::try_from_knobs(
                self.config.group_commit_batch_size,
                self.config.group_commit_wait_to_fill_ms,
            )
            .map_err(|e| ConfigError::MissingField(e.to_string()))?,
        );
        Ok(Arc::new(db))
    }

    /// Build the production [`SignerService`] with the given signing enablement.
    ///
    /// Callers must supply the enablement produced by
    /// [`Self::build_signing_enablement`] (or an equivalent). That value is
    /// wrapped in [`QuiescingEnablement`] before [`SignerService::with_enablement`],
    /// so the signer re-checks the quiesce gate under the per-pubkey lock. The
    /// returned registry is the one the wrapper reads.
    ///
    /// `ValidatorStore`'s `enabled` flag is a different gate and is not installed
    /// here (SEC-2a/2b). An open doppelganger hold is applied in
    /// [`Self::build_signing_enablement`]: that key is registered with
    /// `register_for_import`, so this signer gate stays closed for voluntary
    /// exit until the forward window completes.
    pub fn build_signer(
        &self,
        composite_signer: Arc<CompositeSigner>,
        slashing_db: Arc<SlashingDb>,
        enablement: Arc<dyn SigningEnablement>,
    ) -> (Arc<SignerService>, Arc<QuiesceRegistry>) {
        let registry = Arc::new(QuiesceRegistry::new());
        let enablement: Arc<dyn SigningEnablement> =
            Arc::new(QuiescingEnablement::new(enablement, Arc::clone(&registry)));
        let signer = SignerService::new(composite_signer, slashing_db).with_enablement(enablement);
        info!("Created signer service with signing enablement (SEC-2b)");
        (Arc::new(signer), registry)
    }

    /// Keys whose import did not finish, or whose import evidence cannot be read.
    ///
    /// A missing keystore directory is not evidence (no sidecars). An unset
    /// validators path means there is no hold file. A directory or file that
    /// exists but cannot be read fails closed: every loaded key is included.
    fn unfinished_imports(&self, pubkey_map: &PubkeyMap) -> UnfinishedImports {
        let now_unix = unix_now_secs();
        let mut unfinished = UnfinishedImports { force_all: false, pubkeys: HashSet::new() };

        match scan_import_sidecars(&self.config.keystore_path) {
            Ok(keys) => unfinished.pubkeys.extend(keys),
            Err(err) => {
                error!(
                    path = %self.config.keystore_path.display(),
                    error = %err,
                    "doppelganger: cannot list keystore directory; every loaded key stays Pending"
                );
                unfinished.force_all = true;
            }
        }

        if let Some(path) = &self.config.validators_config {
            match open_doppelganger_holds(path, pubkey_map, now_unix) {
                Ok(keys) => unfinished.pubkeys.extend(keys),
                Err(err) => {
                    error!(
                        path = %path.display(),
                        error = %err,
                        "doppelganger: cannot read validators file; every loaded key stays Pending"
                    );
                    unfinished.force_all = true;
                }
            }
        }

        unfinished
    }

    /// Construct the production [`SigningEnablement`] (SEC-2b).
    ///
    /// - When doppelganger detection is **enabled** (default): builds a
    ///   [`ForwardWindowMachine`], registers every loaded key at
    ///   `current_epoch`, and returns it as the enablement. Keys remain
    ///   closed until `monitoring_epochs + 1` closed not-live epochs are
    ///   observed (driven by SEC-2c). A gap delays `Safe`; there is no
    ///   timeout. Epoch-0 registration of a normally registered key is
    ///   immediately `Safe` (pre-genesis bypass). Default cost: three closed
    ///   epochs (`DEFAULT_MONITORING_EPOCHS + 1`).
    /// - When **disabled** (`--no-doppelganger-detection`): returns
    ///   [`DoppelgangerDisabledByOperator`], which enables every key.
    ///
    /// The optional machine handle is returned so keymanager import /
    /// secret-provider refresh can `register_for_import` against the same
    /// instance (import-strict: no restart Safe-skip).
    ///
    /// # Restart-aware safe-skip (boot only, normal keys)
    ///
    /// Boot `register` may mark a **normally registered** key `Safe` if local
    /// slashing history shows a recent attestation under this GVR (same-host
    /// restart). **Do not copy a live slashing DB to a second VC** — that
    /// would dual-open signing without network liveness.
    ///
    /// A key whose import did not finish does not take that bypass, and does
    /// not take the epoch-0 bypass. It is registered with `register_for_import`
    /// when any of the following is true:
    ///
    /// - the validators file has `doppelganger_hold_until` still in the future
    /// - `keystore_path` still has a `*.import_meta.json` sidecar (any age), a
    ///   leftover `*.import_meta.json.removing.*` set-aside, or that sidecar
    ///   cannot be read or parsed. The sidecar is removed only after this
    ///   process observes the forward window to Safe while holding the same
    ///   `tracked_keys` lock as DELETE/import
    /// - a staged `*.import_meta.json.partial` sidecar is still present
    /// - the keystore directory exists but cannot be listed, or the validators
    ///   file cannot be read (every loaded key stays Pending)
    ///
    /// `register_for_import` does not downgrade a key that is already `Safe`,
    /// so this choice is made on the first registration.
    pub fn build_signing_enablement(
        &self,
        slashing_db: Arc<SlashingDb>,
        gvr: Root,
        current_epoch: Epoch,
        pubkey_map: &PubkeyMap,
        genesis_confirmed: bool,
    ) -> (Arc<dyn SigningEnablement>, Option<Arc<ForwardWindowMachine>>) {
        let closed_epochs = DEFAULT_MONITORING_EPOCHS + 1;
        if !self.config.doppelganger_detection {
            tracing::warn!(
                closed_epochs,
                "Doppelganger detection disabled by operator (--no-doppelganger-detection). \
                 Forward-window protection is off; a duplicate live instance can double-sign. \
                 Default on withholds signing until {closed_epochs} closed not-live epochs \
                 are observed (a gap delays Safe)."
            );
            return (Arc::new(DoppelgangerDisabledByOperator), None);
        }

        let reader: Arc<dyn slashing::SlashingDbReader> = slashing_db;
        let mut machine = ForwardWindowMachine::new(reader, DEFAULT_MONITORING_EPOCHS, gvr)
            .with_detection_marker_path(crate::detection_marker::marker_path(
                &self.config.keystore_path,
            ))
            .with_force_window_path(crate::detection_marker::force_window_path(
                &self.config.keystore_path,
            ));
        if genesis_confirmed {
            machine = machine.with_confirmed_genesis();
        }
        let machine = Arc::new(machine);

        // Unfinished imports must be classified before `register`. A later
        // `register_for_import` leaves an existing Safe state unchanged.
        let unfinished = self.unfinished_imports(pubkey_map);
        let mut registered = 0usize;
        let mut import_strict = 0usize;
        for pubkey in pubkey_map.read().values() {
            let pk_bytes = pubkey.to_bytes();
            if unfinished.contains(&pk_bytes) {
                let pk_hex = hex::encode(pk_bytes);
                warn!(
                    pubkey = %observability::logging::TruncatedPubkey::new(&pk_hex),
                    current_epoch,
                    "doppelganger: unfinished import — boot uses register_for_import \
                     (no epoch-0 or history bypass)"
                );
                machine.register_for_import(pubkey, current_epoch);
                import_strict += 1;
            } else {
                machine.register(pubkey, current_epoch);
            }
            registered += 1;
        }

        info!(
            monitoring_epochs = DEFAULT_MONITORING_EPOCHS,
            closed_epochs,
            current_epoch,
            registered,
            import_strict,
            "ForwardWindowMachine constructed (SEC-2b/2c). Keys stay closed until \
             {closed_epochs} closed not-live epochs are observed (a gap delays \
             Safe; there is no timeout). The liveness loop (SEC-2c) feeds \
             observe_liveness via bn-manager failover. Epoch-0 bypass and \
             restart-aware safe-skip apply only to keys that are not an unfinished \
             import (open hold, any import sidecar, staged sidecar, \
             or an unreadable keystore directory or validators file)."
        );

        (Arc::clone(&machine) as Arc<dyn SigningEnablement>, Some(machine))
    }

    pub fn build_propagator<S: AttestationSubmitter>(
        &self,
        submitter: Arc<S>,
    ) -> Arc<Propagator<S>> {
        let propagator = Propagator::new(submitter);
        info!("Created propagator service");
        Arc::new(propagator)
    }

    /// Test-only duty tracker.
    ///
    /// The beacon argument is whatever the test passes. A production caller
    /// could hand this a single-endpoint client and skip `BnManager` failover.
    /// Production wiring is `DutyTracker::new_with_source` on `beacon.bn_manager`
    /// in `bootstrap/services.rs`. This helper is not in a library build.
    #[cfg(test)]
    pub fn build_duty_tracker(
        &self,
        beacon: Arc<dyn DutiesProvider>,
        validator_indices: Vec<String>,
        fork_schedule: ForkSchedule,
    ) -> Arc<DutyTracker> {
        let tracker = DutyTracker::new(beacon, validator_indices).with_fork_schedule(fork_schedule);
        info!("Created duty tracker");
        Arc::new(tracker)
    }

    /// Duration and confirmation from the configured beacon nodes.
    ///
    /// Named networks must report [`Network::slot_duration_ms`]. Responding
    /// nodes must report the same duration, the same `SLOTS_PER_EPOCH` as
    /// [`Network::slots_per_epoch`], and the same genesis time as the
    /// configured genesis. A named network skips a BN that does not respond
    /// and fails when none do. Custom requires every configured BN. A miss,
    /// a bound failure, or a disagreement fails closed.
    ///
    /// The returned flag is the epoch-0 Safe bypass. It is set only on a
    /// named network whose clock has reached genesis. Custom duration comes
    /// from the beacon nodes, so an inflated length can hold the clock at
    /// epoch 0; the flag stays false. A clock reading before genesis is not
    /// a counted epoch, and the flag stays false there too.
    pub async fn resolve_slot_duration_ms(
        &self,
        beacon: &BnManager,
    ) -> Result<(u64, bool), ConfigError> {
        info!("Fetching slot duration from configured beacon nodes");
        let agreement = if matches!(self.config.network, super::Network::Custom) {
            bn_manager::SpecAgreement::All
        } else {
            bn_manager::SpecAgreement::Responding
        };
        let configured_root = self.config.effective_genesis_validators_root()?;
        let (slot_duration_ms, slots_per_epoch, genesis_time) =
            beacon.agreed_spec_and_genesis(agreement, &configured_root).await?;
        let expected_slots = self.config.network.slots_per_epoch();
        if slots_per_epoch != expected_slots {
            return Err(ConfigError::InvalidNetwork(format!(
                "SLOTS_PER_EPOCH {slots_per_epoch} does not match preset {expected_slots}"
            )));
        }
        if !matches!(self.config.network, super::Network::Custom) {
            let preset = self.config.network.slot_duration_ms();
            if slot_duration_ms != preset {
                return Err(ConfigError::InvalidNetwork(format!(
                    "slot duration {slot_duration_ms} ms does not match {} preset {preset} ms",
                    self.config.network
                )));
            }
        }
        let configured_genesis = self.config.effective_genesis_time()?;
        if genesis_time != configured_genesis {
            return Err(ConfigError::InvalidNetwork(format!(
                "beacon genesis_time {genesis_time} does not match configured {configured_genesis}"
            )));
        }
        info!(slot_duration_ms, slots_per_epoch, genesis_time, "Resolved chain timing");
        let named_network = !matches!(self.config.network, super::Network::Custom);
        let genesis_confirmed =
            MonotonicEpochClock::allow_epoch0_bypass(named_network, unix_now_secs(), genesis_time);
        Ok((slot_duration_ms, genesis_confirmed))
    }

    pub fn build_slot_clock(
        &self,
        slot_duration_ms: u64,
    ) -> Result<Arc<SystemSlotClock>, ConfigError> {
        if !(eth_types::MIN_SLOT_DURATION_MS..=eth_types::MAX_SLOT_DURATION_MS)
            .contains(&slot_duration_ms)
        {
            return Err(ConfigError::InvalidNetwork(format!(
                "slot duration {slot_duration_ms} ms is outside {}..={}",
                eth_types::MIN_SLOT_DURATION_MS,
                eth_types::MAX_SLOT_DURATION_MS
            )));
        }
        let genesis_time = self.config.effective_genesis_time()?;
        let slot_duration = Duration::from_millis(slot_duration_ms);
        // Preset value. `resolve_slot_duration_ms` already rejected a BN that
        // omitted SLOTS_PER_EPOCH or reported a different count.
        let slots_per_epoch = self.config.network.slots_per_epoch();
        if slots_per_epoch == 0 {
            return Err(ConfigError::InvalidNetwork(
                "SLOTS_PER_EPOCH must be greater than zero".to_string(),
            ));
        }

        let clock = SystemSlotClock::new(genesis_time, slot_duration, slots_per_epoch)
            .map_err(|e| ConfigError::MissingField(format!("invalid slot clock: {e}")))?
            .with_deadline_schedule(deadline_schedule_from_timing(&self.config.timing)?);
        info!(
            genesis_time = genesis_time,
            slot_duration_ms,
            slot_duration_secs = slot_duration.as_secs(),
            slots_per_epoch = slots_per_epoch,
            "Created slot clock"
        );
        Ok(Arc::new(clock))
    }

    pub fn build_pubkey_map(&self, key_manager: &KeyManager) -> PubkeyMap {
        let mut map = HashMap::new();
        for pubkey in key_manager.list_public_keys() {
            // Key by compressed BLS bytes — no hex normalization on hot paths.
            map.insert(pubkey.to_bytes(), pubkey);
        }
        info!(count = map.len(), "Built public key map");
        Arc::new(parking_lot::RwLock::new(map))
    }

    pub fn parse_genesis_validators_root(&self) -> Result<Root, ConfigError> {
        let root_hex = self.config.effective_genesis_validators_root()?;
        let root_hex = root_hex.strip_prefix("0x").unwrap_or(&root_hex);

        let bytes = hex::decode(root_hex).map_err(|_| {
            ConfigError::InvalidNetwork(format!(
                "invalid genesis validators root hex: {}",
                root_hex
            ))
        })?;

        if bytes.len() != 32 {
            return Err(ConfigError::InvalidNetwork(format!(
                "genesis validators root must be 32 bytes, got {}",
                bytes.len()
            )));
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes);
        Ok(root)
    }

    pub async fn build_fork_schedule(
        &self,
        beacon: &dyn BeaconNodeClient,
    ) -> Result<Arc<ForkSchedule>, ConfigError> {
        info!("Fetching fork schedule from beacon node");
        let schedule = beacon.get_fork_schedule().await?;
        info!(
            genesis_version = %format_version(schedule.genesis_fork_version),
            altair_epoch = schedule.altair_fork_epoch,
            altair_version = %format_version(schedule.altair_fork_version),
            bellatrix_epoch = schedule.bellatrix_fork_epoch,
            bellatrix_version = %format_version(schedule.bellatrix_fork_version),
            capella_epoch = schedule.capella_fork_epoch,
            capella_version = %format_version(schedule.capella_fork_version),
            deneb_epoch = schedule.deneb_fork_epoch,
            deneb_version = %format_version(schedule.deneb_fork_version),
            electra_epoch = schedule.electra_fork_epoch,
            electra_version = %format_version(schedule.electra_fork_version),
            fulu_epoch = schedule.fulu_fork_epoch,
            fulu_version = %format_version(schedule.fulu_fork_version),
            gloas_epoch = schedule.gloas_fork_epoch,
            gloas_version = %format_version(schedule.gloas_fork_version),
            "Loaded fork schedule from beacon node"
        );
        Ok(Arc::new(schedule))
    }

    /// Constructs the [`ValidatorStore`], loading defaults from a TOML file if
    /// one is provided.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::EmptyValidatorsConfig`] when the file exists and
    /// is empty or whitespace. Returns [`ConfigError::ZeroFeeRecipient`] if the
    /// effective default fee recipient is the zero address. Operators must set
    /// a non-zero address in the validators config file passed via
    /// `--validators-config`.
    ///
    /// `--block-selection-mode` and the top-level TOML key `block_selection_mode`
    /// become the store's global default after builder settings apply. A
    /// per-validator mode still wins. A builder-settings error returns before
    /// that default is published. The mode does not read the fork schedule.
    pub fn build_validator_store(
        &self,
        validators_config: Option<&std::path::Path>,
    ) -> Result<Arc<ValidatorStore>, ConfigError> {
        let store = match validators_config {
            Some(path) => {
                let raw = std::fs::read_to_string(path)
                    .map_err(|e| ConfigError::ValidatorStoreError(e.to_string()))?;
                if raw.trim().is_empty() {
                    return Err(ConfigError::EmptyValidatorsConfig);
                }
                ValidatorStore::load_from_config(path)
                    .map_err(|e| ConfigError::ValidatorStoreError(e.to_string()))?
            }
            None => ValidatorStore::new([0u8; 20], 30_000_000),
        };

        if store.default_fee_recipient() == [0u8; 20] {
            return Err(ConfigError::ZeroFeeRecipient);
        }

        crate::startup::apply_builder_settings(&store, &self.config.builder)?;
        store.set_global_block_selection_mode(self.config.block_selection_mode);

        if let Some(raw) = self.config.graffiti.as_deref() {
            let applied = validator_store::parse_graffiti(raw);
            store.set_default_graffiti(applied);
            // Hex, not Display: CR/LF/ESC in the 32-byte field must not split this line.
            let graffiti = hex::encode(applied);
            info!(graffiti = ?graffiti, "Created validator store");
        } else {
            info!("Created validator store");
        }
        Ok(Arc::new(store))
    }

    /// Registers every loaded validator pubkey in the [`ValidatorStore`] so the
    /// per-validator signing gate ([`ValidatorStore::is_signing_enabled`]) treats
    /// keystore-loaded keys as tracked-and-enabled.
    ///
    /// D-3 (Issue 2.11) flipped the unknown-pubkey default to fail-closed
    /// (`false`). The common production deployment supplies no per-validator
    /// `validators_config` TOML — the actual keys are loaded into the
    /// `KeyManager`/`pubkey_map`, not the store — so without this registration
    /// every loaded validator would hit the fail-closed default and be silently
    /// blocked from signing (a catastrophic availability regression).
    ///
    /// Registration is additive and idempotent: a pubkey already tracked by the
    /// store (e.g. set `enabled = false` by the doppelganger window or via the
    /// validators TOML) is left untouched, so the doppelganger flow's ability to
    /// keep a freshly-imported key disabled is preserved.
    pub fn register_loaded_validators(&self, store: &ValidatorStore, pubkey_map: &PubkeyMap) {
        let mut registered = 0usize;
        for pubkey in pubkey_map.read().values() {
            let pk_bytes = pubkey.to_bytes();
            if !store.has_validator(&pk_bytes) {
                store
                    .add_validator(validator_store::ValidatorConfig::new(pk_bytes))
                    .expect("ValidatorConfig::new has no builder URLs");
                registered += 1;
            }
        }
        info!(
            registered,
            enabled_total = store.list_enabled_pubkeys().len(),
            "Registered loaded validators in the validator store (D-3 fail-closed)"
        );
    }

    pub fn build_builder_service(
        &self,
        signer: Arc<SignerService>,
        beacon: Arc<dyn BeaconNodeClient>,
        validator_store: Arc<ValidatorStore>,
        genesis_fork_version: [u8; 4],
        fork_schedule: Arc<ForkSchedule>,
    ) -> Arc<BuilderService> {
        // Bridge full trait objects onto the narrow builder seams
        // (`RegistrationSigner` / `BuilderBeaconClient`).
        let signer: Arc<dyn ValidatorSigner> = signer;
        let service = BuilderService::new(
            Arc::new(signer),
            Arc::new(beacon),
            validator_store,
            genesis_fork_version,
            fork_schedule,
        );
        info!("Created builder service");
        Arc::new(service)
    }

    pub async fn build_secret_providers(
        &self,
    ) -> Result<Vec<Box<dyn SecretProvider>>, ConfigError> {
        #[allow(unused_mut)]
        let mut providers: Vec<Box<dyn SecretProvider>> = Vec::new();

        #[allow(clippy::never_loop)] // loop continues when gcp-secret feature is enabled
        for provider_name in &self.config.secret_provider.providers {
            match provider_name.as_str() {
                "gcp" => {
                    #[cfg(not(feature = "gcp-secret"))]
                    {
                        return Err(ConfigError::FeatureNotEnabled(
                            "gcp provider requires the `gcp-secret` feature. \
                             Rebuild with: cargo build --features gcp-secret"
                                .to_string(),
                        ));
                    }
                    #[cfg(feature = "gcp-secret")]
                    {
                        use secret_provider::gcp::{GcpSecretProvider, GcpSecretProviderConfig};
                        let gcp_config = GcpSecretProviderConfig {
                            project_id: self
                                .config
                                .secret_provider
                                .gcp
                                .project_id
                                .clone()
                                .ok_or_else(|| {
                                    ConfigError::MissingField(
                                        "gcp_project_id is required for GCP secret provider".into(),
                                    )
                                })?,
                            prefix: self.config.secret_provider.gcp.secret_prefix.clone(),
                        };
                        let gcp_provider =
                            GcpSecretProvider::new(gcp_config).await.map_err(|e| {
                                ConfigError::SecretProviderError(format!(
                                    "failed to create GCP secret provider: {}",
                                    e
                                ))
                            })?;
                        providers.push(Box::new(gcp_provider));
                        info!("Created GCP secret provider");
                    }
                }
                other => {
                    return Err(ConfigError::SecretProviderError(format!(
                        "unknown secret provider: {}",
                        other
                    )));
                }
            }
        }

        Ok(providers)
    }

    pub fn build_orchestrator_config(
        &self,
        genesis_validators_root: Root,
        fork_schedule: Arc<ForkSchedule>,
    ) -> Result<OrchestratorConfig, ConfigError> {
        let limits = DispatchLimits::validated(
            self.config.duties.duty_dispatch_concurrency,
            self.config.duties.duty_publish_concurrency,
        )
        .expect("Config::validate rejects zero duty concurrency");
        let schedule = deadline_schedule_from_timing(&self.config.timing)?;
        Ok(OrchestratorConfig::new(genesis_validators_root, fork_schedule)
            .with_shutdown_timeout(Duration::from_secs(30))
            .with_deadline_schedule(schedule)
            .with_dispatch_limits(limits))
    }
}

fn checked_bps(field: &'static str, value: u64) -> Result<u64, ConfigError> {
    if (1..=timing::BASIS_POINTS).contains(&value) {
        Ok(value)
    } else {
        Err(ConfigError::Invalid {
            field,
            message: format!("must be 1..={}, got {value}", timing::BASIS_POINTS),
            source_layer: rvc_config::ConfigSource::Default,
        })
    }
}

/// Build both deadline sets from `[timing]`.
///
/// Every pre-Gloas and Gloas basis-point field must be in `1..=10000`.
/// Attestation must not land after aggregate, and the Gloas aggregate must
/// not land after the payload attestation. A zero or oversized field fails
/// closed instead of building a deadline at the start of the slot.
fn deadline_schedule_from_timing(timing: &TimingConfig) -> Result<DeadlineSchedule, ConfigError> {
    let attestation = checked_bps("timing.attestation_due_bps", timing.attestation_due_bps)?;
    let aggregate = checked_bps("timing.aggregate_due_bps", timing.aggregate_due_bps)?;
    let attestation_gloas =
        checked_bps("timing.attestation_due_bps_gloas", timing.attestation_due_bps_gloas)?;
    let aggregate_gloas =
        checked_bps("timing.aggregate_due_bps_gloas", timing.aggregate_due_bps_gloas)?;
    let sync_message =
        checked_bps("timing.sync_message_due_bps_gloas", timing.sync_message_due_bps_gloas)?;
    let contribution =
        checked_bps("timing.contribution_due_bps_gloas", timing.contribution_due_bps_gloas)?;
    let payload = checked_bps("timing.payload_due_bps", timing.payload_due_bps)?;
    let payload_attestation =
        checked_bps("timing.payload_attestation_due_bps", timing.payload_attestation_due_bps)?;
    if attestation > aggregate {
        return Err(ConfigError::Invalid {
            field: "timing.aggregate_due_bps",
            message: format!(
                "must be >= timing.attestation_due_bps ({attestation}), got {aggregate}"
            ),
            source_layer: rvc_config::ConfigSource::Default,
        });
    }
    if attestation_gloas > aggregate_gloas {
        return Err(ConfigError::Invalid {
            field: "timing.aggregate_due_bps_gloas",
            message: format!(
                "must be >= timing.attestation_due_bps_gloas ({attestation_gloas}), got {aggregate_gloas}"
            ),
            source_layer: rvc_config::ConfigSource::Default,
        });
    }
    if aggregate_gloas > payload_attestation {
        return Err(ConfigError::Invalid {
            field: "timing.payload_attestation_due_bps",
            message: format!(
                "must be >= timing.aggregate_due_bps_gloas ({aggregate_gloas}), got {payload_attestation}"
            ),
            source_layer: rvc_config::ConfigSource::Default,
        });
    }
    Ok(DeadlineSchedule {
        pre_gloas: DeadlineBps {
            attestation,
            aggregate,
            // Pre-Gloas waits: sync messages share attestation, contributions share aggregate.
            sync_message: attestation,
            contribution: aggregate,
            payload: aggregate,
            payload_attestation: aggregate,
        },
        gloas: DeadlineBps {
            attestation: attestation_gloas,
            aggregate: aggregate_gloas,
            sync_message,
            contribution,
            payload,
            payload_attestation,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TimingConfig;
    use crate::orchestrator::dispatch::DispatchLimits;
    use crypto::{LocalSigner, Signer as _};
    use eth_types::{ForkName, NetworkPreset, SLOTS_PER_EPOCH, SLOT_DURATION_MS};
    use tempfile::TempDir;
    use timing::{due_ms, SlotClock};

    fn create_minimal_config() -> Config {
        Config {
            beacon_url: "http://localhost:5052".to_string(),
            keystore_path: std::path::PathBuf::from("/tmp/nonexistent"),
            slashing_db_path: std::path::PathBuf::from("./test_slashing.db"),
            ..Default::default()
        }
    }

    #[test]
    fn test_service_builder_new() {
        let config = create_minimal_config();
        let _builder = ServiceBuilder::new(config);
    }

    #[test]
    fn test_build_beacon() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_beacon();
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_slashing_db() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("slashing.db");

        // Pre-create a valid DB so open does not require the fresh-init opt-in.
        SlashingDb::open(&db_path).unwrap();

        let config = Config { slashing_db_path: db_path.clone(), ..create_minimal_config() };

        let builder = ServiceBuilder::new(config);
        let result = builder.build_slashing_db();

        assert!(result.is_ok());
        assert!(db_path.exists());
    }

    #[test]
    fn test_build_slashing_db_invalid_parent() {
        let config = Config {
            slashing_db_path: std::path::PathBuf::from("/nonexistent/path/slashing.db"),
            ..create_minimal_config()
        };

        let builder = ServiceBuilder::new(config);
        let result = builder.build_slashing_db();

        assert!(matches!(result, Err(ConfigError::SlashingDbPathInvalid(_))));
    }

    // ── SEC-3: slashing DB fails closed on missing / 0-byte file ───────────

    /// Missing DB without opt-in must abort (never silently create).
    #[test]
    fn test_missing_db_without_optin_aborts_startup() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("missing.db");
        assert!(!db_path.exists());

        let config = Config {
            slashing_db_path: db_path.clone(),
            allow_fresh_db: false,
            ..create_minimal_config()
        };
        let result = ServiceBuilder::new(config).build_slashing_db();

        match result {
            Err(ConfigError::SlashingDbMissing(_)) => {}
            Ok(_) => panic!("expected SlashingDbMissing, got Ok"),
            Err(e) => panic!("expected SlashingDbMissing, got: {e}"),
        }
        assert!(!db_path.exists(), "must not create the DB without opt-in");
    }

    /// Missing DB with opt-in creates the file and succeeds.
    #[test]
    fn test_missing_db_with_optin_creates_and_warns() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("fresh.db");
        assert!(!db_path.exists());

        let config = Config {
            slashing_db_path: db_path.clone(),
            allow_fresh_db: true,
            ..create_minimal_config()
        };
        let result = ServiceBuilder::new(config).build_slashing_db();

        if let Err(e) = result {
            panic!("opt-in fresh create must succeed: {e}");
        }
        assert!(db_path.exists(), "opt-in must create the DB file");
        // Fresh DB must be a real non-empty SQLite file (not left 0-byte).
        assert!(std::fs::metadata(&db_path).unwrap().len() > 0);
    }

    /// 0-byte DB always aborts, with and without opt-in.
    #[test]
    fn test_zero_byte_db_always_aborts() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("zero.db");
        std::fs::write(&db_path, b"").unwrap();

        for allow_fresh_db in [false, true] {
            let config = Config {
                slashing_db_path: db_path.clone(),
                allow_fresh_db,
                ..create_minimal_config()
            };
            let result = ServiceBuilder::new(config).build_slashing_db();
            match result {
                Err(ConfigError::SlashingDbCorrupt(_)) => {}
                Ok(_) => panic!("0-byte DB must abort (allow_fresh_db={allow_fresh_db}), got Ok"),
                Err(e) => {
                    panic!("0-byte DB must abort (allow_fresh_db={allow_fresh_db}), got: {e}")
                }
            }
        }
        // Must not have wiped/replaced the 0-byte file with a fresh DB.
        assert_eq!(std::fs::metadata(&db_path).unwrap().len(), 0);
    }

    /// SEC-3 TOCTOU: post-open `created_fresh && !allow_fresh_db` must refuse.
    #[test]
    fn test_created_fresh_without_optin_is_rejected() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("race.db");

        // Simulate the library outcome of a disappear-between-check race:
        // open reports created_fresh without the builder opt-in flag.
        let (db, created_fresh) = SlashingDb::open_with_create_info(&db_path).unwrap();
        assert!(created_fresh);
        drop(db);

        assert!(
            reject_accidental_fresh_create(&db_path, true, false).is_err(),
            "created_fresh without opt-in must error"
        );
        assert!(
            reject_accidental_fresh_create(&db_path, true, true).is_ok(),
            "created_fresh with opt-in must be allowed"
        );
        assert!(
            reject_accidental_fresh_create(&db_path, false, false).is_ok(),
            "existing open without create is always ok"
        );

        // Cleanup path used after the gate fails.
        remove_accidental_fresh_db(&db_path);
        assert!(!db_path.exists(), "accidental fresh DB must be removed");
    }

    /// Builder maps corrupt-header open failures to `SlashingDbCorrupt`.
    #[test]
    fn test_corrupt_header_db_always_aborts() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("garbage.db");
        std::fs::write(&db_path, b"not a sqlite database!!!!").unwrap();

        for allow_fresh_db in [false, true] {
            let config = Config {
                slashing_db_path: db_path.clone(),
                allow_fresh_db,
                ..create_minimal_config()
            };
            let result = ServiceBuilder::new(config).build_slashing_db();
            match result {
                Err(ConfigError::SlashingDbCorrupt(_)) => {}
                Ok(_) => panic!("corrupt header must abort (allow_fresh_db={allow_fresh_db})"),
                Err(e) => panic!(
                    "corrupt header must map to SlashingDbCorrupt \
                     (allow_fresh_db={allow_fresh_db}), got: {e}"
                ),
            }
        }
        // Must not wipe the non-empty garbage file.
        assert_eq!(std::fs::read(&db_path).unwrap(), b"not a sqlite database!!!!");
    }

    /// Opt-in must never wipe or overwrite a non-empty existing DB.
    #[test]
    fn test_optin_never_wipes_nonempty_db() {
        let temp_dir = TempDir::new().unwrap();
        let db_path = temp_dir.path().join("existing.db");

        // Seed a real DB with one attestation so we can assert history survives.
        {
            let db = SlashingDb::open(&db_path).unwrap();
            let gvr = [0u8; 32];
            db.seed_attestation("0xabcd", 1, 2, Some("0xdead".to_string()), &gvr).unwrap();
        }
        let size_before = std::fs::metadata(&db_path).unwrap().len();
        assert!(size_before > 0);

        let config = Config {
            slashing_db_path: db_path.clone(),
            allow_fresh_db: true, // opt-in set, but DB already exists
            ..create_minimal_config()
        };
        let db = ServiceBuilder::new(config).build_slashing_db().expect("open existing");

        let records = db.get_attestations("0xabcd").expect("read history");
        assert_eq!(records.len(), 1, "opt-in must not wipe existing history");
        assert_eq!(records[0].target_epoch, 2);
    }

    #[test]
    fn test_build_key_manager_path_not_found() {
        let config = Config {
            keystore_path: std::path::PathBuf::from("/nonexistent/keystores"),
            ..create_minimal_config()
        };

        let builder = ServiceBuilder::new(config);
        let result = builder.build_key_manager();

        assert!(matches!(result, Err(ConfigError::KeystorePathNotFound(_))));
    }

    #[cfg(unix)]
    fn write_import_secret(keystore: &std::path::Path, pubkey: &[u8; 48], password: &str) {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let dir = keystore.join(Config::IMPORT_SECRETS_DIR);
        std::fs::create_dir_all(&dir).unwrap();
        let mut dir_perms = std::fs::metadata(&dir).unwrap().permissions();
        dir_perms.set_mode(0o700);
        std::fs::set_permissions(&dir, dir_perms).unwrap();
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(dir.join(format!("0x{}", hex::encode(pubkey))))
            .unwrap();
        file.write_all(password.as_bytes()).unwrap();
    }

    #[cfg(unix)]
    fn write_encrypted_keystore(dir: &std::path::Path, password: &str) -> [u8; 48] {
        let sk = crypto::SecretKey::generate();
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .unwrap();
        let pk = sk.public_key().to_bytes();
        std::fs::write(
            dir.join(format!("keystore-{}.json", hex::encode(pk))),
            serde_json::to_string(&keystore).unwrap(),
        )
        .unwrap();
        pk
    }

    #[cfg(unix)]
    fn password_file(dir: &std::path::Path, body: &str) -> std::path::PathBuf {
        let path = dir.join("passwords.txt");
        std::fs::write(&path, body).unwrap();
        path
    }

    /// The persisted secret decrypts the key when the password file is wrong.
    #[cfg(unix)]
    #[test]
    fn build_key_manager_secret_wins_over_password_file() {
        let dir = TempDir::new().unwrap();
        let secret = "secret-wins-password";
        let file_pw = "file-entry-password";
        let wildcard = "wildcard-entry-password";
        let pk = write_encrypted_keystore(dir.path(), secret);
        write_import_secret(dir.path(), &pk, secret);
        let bare = hex::encode(pk);
        let passwords = password_file(dir.path(), &format!("{bare}={file_pw}\n*={wildcard}\n"));
        let config = Config {
            keystore_path: dir.path().to_path_buf(),
            password_file: Some(passwords),
            ..create_minimal_config()
        };
        let loaded = ServiceBuilder::new(config)
            .build_key_manager_owned_filtered(None)
            .expect("secret decrypts the keystore");
        assert!(loaded.contains(&pk));
    }

    /// An uppercase keystore pubkey still selects the lowercase secret.
    #[cfg(unix)]
    #[test]
    fn build_key_manager_loads_an_uppercase_pubkey_with_its_secret() {
        let dir = TempDir::new().unwrap();
        let secret = "uppercase-field-secret";
        let wildcard = "wrong-wildcard-password";
        let pk = write_encrypted_keystore(dir.path(), secret);
        let json_path = dir.path().join(format!("keystore-{}.json", hex::encode(pk)));
        let mut value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&json_path).unwrap()).unwrap();
        let field = value["pubkey"].as_str().unwrap().to_ascii_uppercase();
        assert!(field.bytes().any(|b| b.is_ascii_uppercase()), "{field}");
        value["pubkey"] = serde_json::Value::String(field);
        std::fs::write(&json_path, value.to_string()).unwrap();
        write_import_secret(dir.path(), &pk, secret);
        let passwords = password_file(dir.path(), &format!("*={wildcard}\n"));
        let config = Config {
            keystore_path: dir.path().to_path_buf(),
            password_file: Some(passwords),
            ..create_minimal_config()
        };
        let loaded = ServiceBuilder::new(config)
            .build_key_manager_owned_filtered(None)
            .expect("the lowercase secret decrypts an uppercase pubkey field");
        assert!(loaded.contains(&pk));
    }

    /// A secret that does not decrypt its keystore aborts, even when the file is right.
    #[cfg(unix)]
    #[tracing_test::traced_test]
    #[test]
    fn build_key_manager_rejects_a_secret_that_does_not_decrypt() {
        let dir = TempDir::new().unwrap();
        let real = "real-keystore-password";
        let wrong = "wrong-secret-password";
        let pk = write_encrypted_keystore(dir.path(), real);
        write_import_secret(dir.path(), &pk, wrong);
        let bare = hex::encode(pk);
        let passwords = password_file(dir.path(), &format!("{bare}={real}\n*={real}\n"));
        let config = Config {
            keystore_path: dir.path().to_path_buf(),
            password_file: Some(passwords),
            ..create_minimal_config()
        };
        let err = match ServiceBuilder::new(config).build_key_manager() {
            Err(err) => err,
            Ok(_) => panic!("a secret that does not decrypt must abort startup"),
        };
        let msg = err.to_string();
        assert!(msg.contains("password did not decrypt the keystore"), "{msg}");
        assert!(msg.contains(&format!("0x{bare}")), "{msg}");
        assert!(!msg.contains(real), "{msg}");
        assert!(!msg.contains(wrong), "{msg}");
        assert!(!logs_contain(real), "password file value was logged");
        assert!(!logs_contain(wrong), "import secret was logged");
    }

    /// A keystore that does not parse is an error when its secret is present.
    #[cfg(unix)]
    #[test]
    fn build_key_manager_errors_on_a_corrupt_keystore_with_a_secret() {
        let dir = TempDir::new().unwrap();
        let pk = [0xabu8; 48];
        let bare = hex::encode(pk);
        let secret = "corrupt-keystore-secret";
        std::fs::write(
            dir.path().join("bad.json"),
            format!(
                r#"{{"crypto":{{"kdf":{{"function":"scrypt","params":{{"dklen":32,"n":2,"p":1,"r":1,"salt":"aa"}},"message":""}},"checksum":{{"function":"sha256","params":{{}},"message":"bb"}},"cipher":{{"function":"aes-128-ctr","params":{{"iv":"cc"}},"message":"dd"}}}},"pubkey":"{bare}","path":"m/12381/3600/0/0/0","uuid":"00000000-0000-0000-0000-000000000000","version":3}}"#
            ),
        )
        .unwrap();
        write_import_secret(dir.path(), &pk, secret);
        let config = Config { keystore_path: dir.path().to_path_buf(), ..create_minimal_config() };
        let err = match ServiceBuilder::new(config).build_key_manager() {
            Err(err) => err,
            Ok(_) => panic!("a corrupt keystore must not be an orphan warning"),
        };
        let msg = err.to_string();
        assert!(msg.contains("keystore is corrupt"), "{msg}");
        assert!(!msg.contains(secret), "{msg}");
        assert!(!msg.contains("password did not decrypt"), "{msg}");
    }

    /// A missing `version` or a `crypto` value that is not an object is corrupt.
    ///
    /// A pubkey plus only `version` is corrupt on the canonical name. The same
    /// document under another name is not a keystore.
    #[cfg(unix)]
    #[test]
    fn build_key_manager_errors_when_version_is_missing_or_crypto_is_not_an_object() {
        let secret = "malformed-keystore-secret";
        let cases = [
            (r#"{"crypto":{"kdf":{"function":"scrypt"}},"pubkey":"{bare}"}"#, false),
            (r#"{"crypto":"not-an-object","pubkey":"{bare}","version":4}"#, false),
            (r#"{"pubkey":"{bare}","path":"m/12381/3600/0/0/0","version":4}"#, true),
        ];
        for (body, canonical) in cases {
            let dir = TempDir::new().unwrap();
            let pk = [0xabu8; 48];
            let bare = hex::encode(pk);
            let name = if canonical { format!("0x{bare}.json") } else { "bad.json".to_string() };
            std::fs::write(dir.path().join(name), body.replace("{bare}", &bare)).unwrap();
            write_import_secret(dir.path(), &pk, secret);
            let config =
                Config { keystore_path: dir.path().to_path_buf(), ..create_minimal_config() };
            let err = match ServiceBuilder::new(config).build_key_manager() {
                Err(err) => err,
                Ok(_) => panic!("a malformed keystore must not be an orphan warning"),
            };
            let msg = err.to_string();
            assert!(msg.contains("keystore is corrupt"), "{msg}");
            assert!(!msg.contains("has no keystore"), "{msg}");
            assert!(!msg.contains(secret), "{msg}");
        }
    }

    /// A non-canonical file that only names the secret's pubkey does not abort.
    #[cfg(unix)]
    #[tracing_test::traced_test]
    #[test]
    fn build_key_manager_warns_when_only_an_unrelated_json_names_the_secret_pubkey() {
        let dir = TempDir::new().unwrap();
        let kept_pw = "kept-keystore-password";
        let unrelated_pw = "unrelated-json-secret";
        let pk = write_encrypted_keystore(dir.path(), kept_pw);
        write_import_secret(dir.path(), &pk, kept_pw);
        let unrelated = [0xabu8; 48];
        let bare = hex::encode(unrelated);
        write_import_secret(dir.path(), &unrelated, unrelated_pw);
        let names = [
            format!("0x{}.json", bare.to_ascii_uppercase()),
            format!("0X{bare}.json"),
            format!("0x{bare}\u{200d}.json"),
            format!("0x{bare}Z.json"),
            "notes.json".to_string(),
        ];
        let body = format!(r#"{{"pubkey":"{bare}","path":"m/12381/3600/0/0/0","version":4}}"#);
        for name in &names {
            std::fs::write(dir.path().join(name), &body).unwrap();
        }
        let config = Config { keystore_path: dir.path().to_path_buf(), ..create_minimal_config() };
        let loaded = ServiceBuilder::new(config)
            .build_key_manager()
            .expect("a non-canonical version field is not a corrupt keystore");
        assert!(loaded.contains(&pk), "a renamed keystore still loads");
        assert!(!loaded.contains(&unrelated));
        assert!(logs_contain("import password secret has no keystore"));
        assert!(!logs_contain("keystore is corrupt"));
        assert!(!logs_contain(kept_pw));
        assert!(!logs_contain(unrelated_pw));
    }

    /// A valid keystore under another name still loads when `0x<pk>.json` is empty.
    #[cfg(unix)]
    #[test]
    fn build_key_manager_loads_a_renamed_keystore_when_the_canonical_file_is_empty() {
        let dir = TempDir::new().unwrap();
        let password = "renamed-keystore-password";
        let pk = write_encrypted_keystore(dir.path(), password);
        write_import_secret(dir.path(), &pk, password);
        std::fs::write(dir.path().join(format!("0x{}.json", hex::encode(pk))), b"").unwrap();
        let config = Config { keystore_path: dir.path().to_path_buf(), ..create_minimal_config() };
        let loaded = ServiceBuilder::new(config)
            .build_key_manager()
            .expect("a valid non-canonical keystore still loads");
        assert!(loaded.contains(&pk));
    }

    /// An empty, truncated, or unreadable canonical keystore fails boot.
    #[cfg(unix)]
    #[test]
    fn build_key_manager_errors_on_an_empty_truncated_or_unreadable_canonical_keystore_with_a_secret(
    ) {
        let secret = "canonical-keystore-secret";
        let cases: &[(&str, Option<&[u8]>)] =
            &[("empty", Some(b"")), ("truncated", Some(br#"{"pubkey":"#)), ("unreadable", None)];
        for (label, body) in cases {
            let dir = TempDir::new().unwrap();
            let pk = [0xabu8; 48];
            let bare = hex::encode(pk);
            let name = format!("0x{bare}.json");
            let path = dir.path().join(&name);
            match body {
                Some(bytes) => std::fs::write(&path, bytes).unwrap(),
                None => std::os::unix::fs::symlink("/no/such/keystore.json", &path).unwrap(),
            }
            write_import_secret(dir.path(), &pk, secret);
            let config =
                Config { keystore_path: dir.path().to_path_buf(), ..create_minimal_config() };
            let err = match ServiceBuilder::new(config).build_key_manager() {
                Err(err) => err,
                Ok(_) => panic!("{label} canonical keystore must not be an orphan warning"),
            };
            let msg = err.to_string();
            assert!(msg.contains("keystore is corrupt"), "{label}: {msg}");
            assert!(msg.contains(&format!("0x{bare}")), "{label}: {msg}");
            assert!(!msg.contains("has no keystore"), "{label}: {msg}");
            assert!(!msg.contains(secret), "{label}: {msg}");
        }
    }

    /// `0x<other>.json` whose body validates as a different pubkey is corrupt.
    #[cfg(unix)]
    #[test]
    fn build_key_manager_errors_when_a_canonical_file_validates_as_another_pubkey() {
        let dir = TempDir::new().unwrap();
        let password = "mismatched-canonical-name";
        let body = write_encrypted_keystore(dir.path(), password);
        let named = [0xcdu8; 48];
        assert_ne!(body, named);
        let json = std::fs::read_to_string(
            dir.path().join(format!("keystore-{}.json", hex::encode(body))),
        )
        .unwrap();
        let named_hex = hex::encode(named);
        std::fs::write(dir.path().join(format!("0x{named_hex}.json")), json).unwrap();
        write_import_secret(dir.path(), &named, password);
        let config = Config { keystore_path: dir.path().to_path_buf(), ..create_minimal_config() };
        let err = match ServiceBuilder::new(config).build_key_manager() {
            Err(err) => err,
            Ok(_) => panic!("a mismatched canonical name must not be an orphan warning"),
        };
        let msg = err.to_string();
        assert!(msg.contains("keystore is corrupt"), "{msg}");
        assert!(msg.contains(&format!("0x{named_hex}")), "{msg}");
        assert!(!msg.contains("has no keystore"), "{msg}");
        assert!(!msg.contains(password), "{msg}");
    }

    /// Deposit data and an interchange file that contain the pubkey do not abort.
    #[cfg(unix)]
    #[tracing_test::traced_test]
    #[test]
    fn build_key_manager_ignores_deposit_data_and_interchange_json() {
        let dir = TempDir::new().unwrap();
        let kept_pw = "kept-keystore-password";
        let pk = write_encrypted_keystore(dir.path(), kept_pw);
        write_import_secret(dir.path(), &pk, kept_pw);
        let bare = hex::encode(pk);
        std::fs::write(
            dir.path().join("deposit_data.json"),
            format!(
                r#"[{{"pubkey":"{bare}","withdrawal_credentials":"00","amount":32000000000,"signature":"aa","deposit_data_root":"bb"}}]"#
            ),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("slashing_protection.json"),
            format!(
                r#"{{"metadata":{{"interchange_format_version":"5"}},"data":[{{"pubkey":"0x{bare}","signed_blocks":[],"signed_attestations":[]}}]}}"#
            ),
        )
        .unwrap();
        std::fs::write(dir.path().join("notes.json"), format!("not-json {bare}")).unwrap();
        let notes_pk = [0x22u8; 48];
        let notes_secret = "notes-object-secret";
        write_import_secret(dir.path(), &notes_pk, notes_secret);
        std::fs::write(
            dir.path().join("notes_object.json"),
            format!(r#"{{"pubkey":"{}","note":"not a keystore"}}"#, hex::encode(notes_pk)),
        )
        .unwrap();
        let config = Config { keystore_path: dir.path().to_path_buf(), ..create_minimal_config() };
        let loaded = ServiceBuilder::new(config)
            .build_key_manager()
            .expect("deposit data and interchange must not abort boot");
        assert!(loaded.contains(&pk));
        assert!(!logs_contain("keystore is corrupt"));
        assert!(logs_contain("import password secret has no keystore"));
        assert!(!logs_contain(kept_pw));
        assert!(!logs_contain(notes_secret));
    }

    /// An orphan secret warns and does not abort a keystore that still loads.
    #[cfg(unix)]
    #[tracing_test::traced_test]
    #[test]
    fn build_key_manager_warns_on_an_orphan_import_secret() {
        let dir = TempDir::new().unwrap();
        let kept_pw = "kept-keystore-password";
        let orphan_pw = "orphan-secret-value";
        let pk = write_encrypted_keystore(dir.path(), kept_pw);
        let orphan = [0x11u8; 48];
        write_import_secret(dir.path(), &orphan, orphan_pw);
        let passwords = password_file(dir.path(), &format!("*={kept_pw}\n"));
        let config = Config {
            keystore_path: dir.path().to_path_buf(),
            password_file: Some(passwords),
            ..create_minimal_config()
        };
        let loaded =
            ServiceBuilder::new(config).build_key_manager().expect("an orphan secret is a warning");
        assert!(loaded.contains(&pk));
        assert!(logs_contain("import password secret has no keystore"));
        assert!(!logs_contain(orphan_pw));
        assert!(!logs_contain(kept_pw));
    }

    /// A denylisted keystore is not a startup error when its secret is wrong.
    #[cfg(unix)]
    #[test]
    fn build_key_manager_skips_a_denylisted_keystore_with_a_bad_secret() {
        let dir = TempDir::new().unwrap();
        let real = "real-keystore-password";
        let wrong = "wrong-secret-password";
        let pk = write_encrypted_keystore(dir.path(), real);
        write_import_secret(dir.path(), &pk, wrong);
        let passwords = password_file(dir.path(), &format!("*={real}\n"));
        let config = Config {
            keystore_path: dir.path().to_path_buf(),
            password_file: Some(passwords),
            ..create_minimal_config()
        };
        let mut denylist = std::collections::HashSet::new();
        denylist.insert(pk);
        let loaded = ServiceBuilder::new(config)
            .build_key_manager_owned_filtered(Some(&denylist))
            .expect("denylisted keystore is skipped");
        assert!(!loaded.contains(&pk));
    }

    #[test]
    fn test_build_slot_clock() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_slot_clock(6_000);

        assert!(result.is_ok());
        let clock = result.unwrap();
        assert_eq!(clock.genesis_time(), 1606824023);
        assert_eq!(clock.slot_duration(), Duration::from_secs(6));
        assert_eq!(clock.deadlines().attestation, 3333);
        assert_eq!(clock.deadlines().aggregate, 6667);
    }

    #[test]
    fn test_build_slot_clock_forwards_timing_bps_fields() {
        let config = Config {
            timing: TimingConfig {
                attestation_due_bps: 2500,
                aggregate_due_bps: 4000,
                ..Default::default()
            },
            ..create_minimal_config()
        };
        let clock = ServiceBuilder::new(config).build_slot_clock(12_000).unwrap();
        assert_eq!(clock.deadlines().attestation, 2500);
        assert_eq!(clock.deadlines().aggregate, 4000);
    }

    #[test]
    fn test_build_slot_clock_rejects_zero_and_huge_duration() {
        let builder = ServiceBuilder::new(create_minimal_config());
        for bad in [0, 86_400_000] {
            let err = match builder.build_slot_clock(bad) {
                Ok(_) => panic!("out of range duration must fail"),
                Err(err) => err,
            };
            assert!(err.to_string().contains("outside"), "{err}");
        }
    }

    #[test]
    fn test_gloas_aggregate_deadline_cannot_follow_payload_attestation() {
        let config = Config {
            timing: TimingConfig {
                aggregate_due_bps_gloas: 8000,
                payload_attestation_due_bps: 7500,
                ..Default::default()
            },
            ..create_minimal_config()
        };
        let err = match ServiceBuilder::new(config).build_slot_clock(12_000) {
            Ok(_) => panic!("Gloas aggregate after payload attestation must fail"),
            Err(err) => err,
        };
        let msg = err.to_string();
        assert!(msg.contains("payload_attestation_due_bps"), "{msg}");
        assert!(msg.contains("aggregate_due_bps_gloas"), "{msg}");
    }

    #[test]
    fn test_build_slot_clock_rejects_zero_gloas_payload_bps() {
        let config = Config {
            timing: TimingConfig { payload_due_bps: 0, ..Default::default() },
            ..create_minimal_config()
        };
        let err = match ServiceBuilder::new(config).build_slot_clock(12_000) {
            Ok(_) => panic!("zero payload bps must fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("payload_due_bps"), "{err}");
    }

    #[test]
    fn test_parse_genesis_validators_root() {
        let config = Config {
            genesis_validators_root: Some(NetworkPreset::MAINNET.genesis_validators_root_hex()),
            ..create_minimal_config()
        };

        let builder = ServiceBuilder::new(config);
        let result = builder.parse_genesis_validators_root();

        assert!(result.is_ok());
        let root = result.unwrap();
        assert_eq!(root, NetworkPreset::MAINNET.genesis_validators_root);
    }

    #[test]
    fn test_parse_genesis_validators_root_from_network() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.parse_genesis_validators_root();

        assert!(result.is_ok());
    }

    #[test]
    fn test_builder_default_gvr_is_mainnet_preset() {
        // Default config uses Network::Mainnet; GVR must match the shared preset.
        let config = create_minimal_config();
        assert_eq!(config.network, crate::config::Network::Mainnet);
        assert_eq!(
            config.effective_genesis_validators_root().unwrap(),
            NetworkPreset::MAINNET.genesis_validators_root_hex()
        );
        let root = ServiceBuilder::new(config).parse_genesis_validators_root().unwrap();
        assert_eq!(root, NetworkPreset::MAINNET.genesis_validators_root);
    }

    /// RF6-31: ingestion keys by compressed BLS bytes (no hex string keys).
    #[test]
    fn test_build_pubkey_map_keys_are_compressed_bytes() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let (key_manager, pubkey_map) = loaded_key_manager(&builder, 2);
        let listed: Vec<_> = key_manager.list_public_keys();
        let map = pubkey_map.read();
        assert_eq!(map.len(), listed.len());
        for pk in &listed {
            assert!(
                map.contains_key(&pk.to_bytes()),
                "build_pubkey_map must key by PublicKey::to_bytes()"
            );
        }
    }

    #[test]
    fn test_build_pubkey_map_empty() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let key_manager = KeyManager::new();
        let pubkey_map = builder.build_pubkey_map(&key_manager);

        assert!(pubkey_map.read().is_empty());
    }

    #[test]
    fn test_build_signer() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);

        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let enablement: Arc<dyn SigningEnablement> = Arc::new(DoppelgangerDisabledByOperator);
        let (signer, _quiesce_registry) = builder.build_signer(composite, slashing_db, enablement);

        assert!(signer.signer().public_keys().is_empty());
    }

    #[test]
    fn test_build_duty_tracker() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);

        let beacon = builder.build_beacon().unwrap();
        let tracker = builder.build_duty_tracker(
            beacon,
            vec!["1234".to_string()],
            ForkSchedule::unscheduled_gloas(),
        );

        assert!(Arc::strong_count(&tracker) > 0);
    }

    fn sample_fork_schedule() -> Arc<ForkSchedule> {
        Arc::new(ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 74240,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 144896,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 194048,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 269568,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 364544,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [6, 0, 0, 0],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [7, 0, 0, 0],
        })
    }

    #[test]
    fn test_build_orchestrator_config() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);

        let root = [0xaa; 32];
        let orch_config =
            builder.build_orchestrator_config(root, sample_fork_schedule()).expect("timing");

        assert_eq!(orch_config.genesis_validators_root, root);
        assert_eq!(orch_config.shutdown_timeout, Duration::from_secs(30));
        assert_eq!(orch_config.deadline_schedule.pre_gloas.attestation, 3333);
        assert_eq!(orch_config.deadline_schedule.pre_gloas.aggregate, 6667);
        assert_eq!(orch_config.deadline_schedule.gloas.attestation, 2500);
        assert_eq!(orch_config.deadline_schedule.gloas.aggregate, 5000);
        assert_eq!(orch_config.deadline_schedule.gloas.sync_message, 2500);
        assert_eq!(orch_config.deadline_schedule.gloas.contribution, 5000);
        assert_eq!(orch_config.deadline_schedule.gloas.payload, 5000);
        assert_eq!(orch_config.deadline_schedule.gloas.payload_attestation, 7500);
        assert_eq!(orch_config.dispatch_limits.concurrency, DispatchLimits::DEFAULT_CONCURRENCY);
        assert_eq!(
            orch_config.dispatch_limits.publish_concurrency,
            DispatchLimits::DEFAULT_PUBLISH_CONCURRENCY
        );
    }

    #[test]
    fn test_build_orchestrator_config_forwards_timing_bps_fields() {
        let config = Config {
            timing: TimingConfig {
                attestation_due_bps: 2500,
                aggregate_due_bps: 4000,
                ..Default::default()
            },
            ..create_minimal_config()
        };
        let builder = ServiceBuilder::new(config);
        let orch_config =
            builder.build_orchestrator_config([0xaa; 32], sample_fork_schedule()).expect("timing");
        assert_eq!(orch_config.deadline_schedule.pre_gloas.attestation, 2500);
        assert_eq!(orch_config.deadline_schedule.pre_gloas.aggregate, 4000);
    }

    #[test]
    fn test_payload_due_bps_toml_reaches_orchestrator_schedule() {
        let config = Config {
            timing: TimingConfig { payload_due_bps: 1234, ..Default::default() },
            ..create_minimal_config()
        };
        let builder = ServiceBuilder::new(config);
        let orch_config =
            builder.build_orchestrator_config([0xaa; 32], sample_fork_schedule()).expect("timing");
        assert_eq!(orch_config.deadline_schedule.gloas.payload, 1234);
        assert_eq!(
            timing::due_ms(orch_config.deadline_schedule.gloas.payload, 12_000),
            timing::due_ms(1234, 12_000)
        );
    }

    #[test]
    fn test_gloas_timing_keys_do_not_change_pre_gloas_deadlines() {
        let config = Config {
            timing: TimingConfig {
                attestation_due_bps: 3333,
                aggregate_due_bps: 6667,
                attestation_due_bps_gloas: 2500,
                aggregate_due_bps_gloas: 6667,
                sync_message_due_bps_gloas: 2500,
                contribution_due_bps_gloas: 5000,
                payload_due_bps: 5000,
                payload_attestation_due_bps: 7500,
            },
            ..create_minimal_config()
        };
        let builder = ServiceBuilder::new(config);
        let clock = builder.build_slot_clock(12_000).unwrap();
        let orch =
            builder.build_orchestrator_config([0xaa; 32], sample_fork_schedule()).expect("timing");
        assert_eq!(clock.deadlines().attestation, 3333);
        assert_eq!(clock.deadlines().aggregate, 6667);
        assert_eq!(orch.deadline_schedule.pre_gloas.attestation, 3333);
        assert_eq!(orch.deadline_schedule.pre_gloas.aggregate, 6667);
        assert_eq!(orch.deadline_schedule.gloas.aggregate, 6667);
        assert_eq!(orch.deadline_schedule.gloas.contribution, 5000);
        assert_eq!(orch.deadline_schedule.gloas.payload, 5000);
        assert_eq!(timing::due_ms(clock.deadlines().attestation, 12_000), 3999);
        assert_eq!(timing::due_ms(clock.deadlines().aggregate, 12_000), 8000);
    }

    #[test]
    fn test_aggregate_due_bps_gloas_toml_changes_offset_without_rebuild() {
        let root = [0xaau8; 32];
        let schedule = sample_fork_schedule();
        let defaulted = ServiceBuilder::new(create_minimal_config())
            .build_orchestrator_config(root, schedule.clone())
            .expect("timing");
        assert_eq!(defaulted.deadline_schedule.gloas.aggregate, 5000);
        assert_eq!(timing::due_ms(defaulted.deadline_schedule.gloas.aggregate, 12_000), 6000);

        let timing: TimingConfig =
            toml::from_str("aggregate_due_bps_gloas = 6667").expect("TOML-only override");
        let mut config = create_minimal_config();
        config.timing = timing;
        let orch =
            ServiceBuilder::new(config).build_orchestrator_config(root, schedule).expect("timing");
        assert_eq!(orch.deadline_schedule.gloas.aggregate, 6667);
        assert_eq!(timing::due_ms(orch.deadline_schedule.gloas.aggregate, 12_000), 8000);
        assert_eq!(orch.deadline_schedule.pre_gloas.aggregate, 6667);
    }

    fn gloas_at_epoch(epoch: u64) -> Arc<ForkSchedule> {
        let mut schedule = ForkSchedule::unscheduled_gloas();
        schedule.gloas_fork_epoch = epoch;
        Arc::new(schedule)
    }

    /// D9 / 6.14: a TOML-only Gloas attestation bps change moves the benchmark
    /// helper's reported deadline with no rebuild. The helper is the coordinator
    /// path (`from_epoch` → `for_fork` → `due_ms`); this test names the config
    /// key, the bench harness must not.
    #[test]
    fn test_attestation_due_bps_gloas_toml_moves_benchmark_deadline_without_rebuild() {
        let root = [0xaau8; 32];
        let fork_schedule = gloas_at_epoch(1);
        let gloas_slot = SLOTS_PER_EPOCH;
        let pre_gloas_slot = 0;
        let slot_duration_ms = SLOT_DURATION_MS;

        assert_eq!(
            ForkName::from_epoch(gloas_slot / SLOTS_PER_EPOCH, &fork_schedule),
            ForkName::Gloas
        );
        assert!(
            ForkName::from_epoch(pre_gloas_slot / SLOTS_PER_EPOCH, &fork_schedule)
                < ForkName::Gloas
        );

        let defaulted = ServiceBuilder::new(create_minimal_config())
            .build_orchestrator_config(root, fork_schedule.clone())
            .expect("timing");
        let default_deadline = defaulted.attestation_deadline_ms(gloas_slot, slot_duration_ms);
        let default_pre = defaulted.attestation_deadline_ms(pre_gloas_slot, slot_duration_ms);

        let timing: TimingConfig =
            toml::from_str("attestation_due_bps_gloas = 4000").expect("TOML-only override");
        let mut config = create_minimal_config();
        config.timing = timing;
        let orch = ServiceBuilder::new(config)
            .build_orchestrator_config(root, fork_schedule)
            .expect("timing");
        let moved = orch.attestation_deadline_ms(gloas_slot, slot_duration_ms);

        assert_ne!(moved, default_deadline);
        assert_eq!(moved, due_ms(4000, slot_duration_ms));
        assert_eq!(orch.attestation_deadline_ms(pre_gloas_slot, slot_duration_ms), default_pre);
    }

    #[test]
    fn test_build_bn_manager_single_node() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_bn_manager();
        assert!(result.is_ok());
    }

    #[test]
    fn test_build_bn_manager_multi_node() {
        let config = Config {
            beacon_nodes: vec!["http://bn1:5052".to_string(), "http://bn2:5052".to_string()],
            ..create_minimal_config()
        };
        let builder = ServiceBuilder::new(config);
        let result = builder.build_bn_manager();
        assert!(result.is_ok());
    }

    /// H-12: main + proposer pool construction must forward `beacon_max_body_bytes`
    /// (not leave `BnManagerConfig` at the 32 MiB default).
    #[test]
    fn test_pool_bn_manager_config_forwards_body_cap() {
        let cap = 64 * 1024;
        let config = Config { beacon_max_body_bytes: cap, ..create_minimal_config() };
        let builder = ServiceBuilder::new(config);

        let main_cfg = builder.pool_bn_manager_config(vec!["http://main:5052".to_string()]);
        assert_eq!(main_cfg.max_body_bytes, cap);

        let proposer_cfg = builder.pool_bn_manager_config(vec!["http://proposer:5052".to_string()]);
        assert_eq!(proposer_cfg.max_body_bytes, cap);
    }

    /// Proposer pool must honor the same global broadcast-topic policy as main.
    #[test]
    fn test_pool_bn_manager_config_forwards_broadcast_topics() {
        let config = Config {
            broadcast: vec![crate::config::BroadcastTopic::None],
            ..create_minimal_config()
        };
        let builder = ServiceBuilder::new(config);
        let expected = bn_manager::BroadcastTopics {
            attestations: false,
            blocks: false,
            sync_committee: false,
            subscriptions: false,
        };

        let main_cfg = builder.pool_bn_manager_config(vec!["http://main:5052".to_string()]);
        assert_eq!(main_cfg.broadcast_topics, expected);

        let proposer_cfg = builder.pool_bn_manager_config(vec!["http://proposer:5052".to_string()]);
        assert_eq!(proposer_cfg.broadcast_topics, expected);
    }

    /// Both pools sign or reject a readable fee mismatch together.
    #[test]
    fn test_pool_bn_manager_config_forwards_fee_recipient_policy() {
        let config = Config {
            fee_recipient_policy: bn_manager::FeeRecipientPolicy::Reject,
            ..create_minimal_config()
        };
        let builder = ServiceBuilder::new(config);

        let main_cfg = builder.pool_bn_manager_config(vec!["http://main:5052".to_string()]);
        assert_eq!(main_cfg.fee_recipient_policy, bn_manager::FeeRecipientPolicy::Reject);

        let proposer_cfg = builder.pool_bn_manager_config(vec!["http://proposer:5052".to_string()]);
        assert_eq!(proposer_cfg.fee_recipient_policy, bn_manager::FeeRecipientPolicy::Reject);
    }

    /// End-to-end: `build_bn_manager` applies the operator body cap to clients.
    #[tokio::test]
    async fn test_build_bn_manager_applies_beacon_max_body_bytes() {
        use beacon::BeaconError;
        use bn_manager::NodeStatusApi;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let body = vec![b'x'; 100 * 1024];
                    let header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
                    let _ = stream.write_all(header.as_bytes()).await;
                    let chunk_header = format!("{:x}\r\n", body.len());
                    let _ = stream.write_all(chunk_header.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
                    let _ = stream.flush().await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                });
            }
        });

        let config = Config {
            beacon_url: format!("http://127.0.0.1:{port}"),
            beacon_max_body_bytes: 32 * 1024,
            ..create_minimal_config()
        };
        let manager = ServiceBuilder::new(config).build_bn_manager().expect("main BnManager");
        let result = manager.get_genesis().await;
        server.abort();

        assert!(
            matches!(result, Err(BeaconError::BodyTooLarge { .. })),
            "main pool must apply beacon_max_body_bytes; got {result:?}"
        );
    }

    /// End-to-end: `build_proposer_bn_manager` applies the same body cap.
    #[tokio::test]
    async fn test_build_proposer_bn_manager_applies_beacon_max_body_bytes() {
        use beacon::BeaconError;
        use bn_manager::NodeStatusApi;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { break };
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let body = vec![b'x'; 100 * 1024];
                    let header = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n";
                    let _ = stream.write_all(header.as_bytes()).await;
                    let chunk_header = format!("{:x}\r\n", body.len());
                    let _ = stream.write_all(chunk_header.as_bytes()).await;
                    let _ = stream.write_all(&body).await;
                    let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
                    let _ = stream.flush().await;
                    tokio::time::sleep(Duration::from_secs(2)).await;
                });
            }
        });

        let config = Config {
            proposer_nodes: vec![format!("http://127.0.0.1:{port}")],
            beacon_max_body_bytes: 32 * 1024,
            ..create_minimal_config()
        };
        let manager = ServiceBuilder::new(config)
            .build_proposer_bn_manager()
            .expect("proposer BnManager ok")
            .expect("proposer pool Some");
        let result = manager.get_genesis().await;
        server.abort();

        assert!(
            matches!(result, Err(BeaconError::BodyTooLarge { .. })),
            "proposer pool must apply beacon_max_body_bytes; got {result:?}"
        );
    }

    #[tokio::test]
    async fn test_build_secret_providers_empty() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_secret_providers().await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_build_secret_providers_gcp_without_feature() {
        use super::super::types::{GcpSecretConfig, SecretProviderConfig};
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig {
                    project_id: Some("my-project".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..create_minimal_config()
        };
        let builder = ServiceBuilder::new(config);
        let result = builder.build_secret_providers().await;
        // Without gcp-secret feature, should return an error
        #[cfg(not(feature = "gcp-secret"))]
        assert!(result.is_err());
        #[cfg(feature = "gcp-secret")]
        {
            // With feature, would attempt GCP client construction (may fail without credentials)
            let _ = result;
        }
    }

    #[tokio::test]
    async fn test_build_secret_providers_unknown_provider() {
        let mut config = create_minimal_config();
        config.secret_provider.providers = vec!["unknown".to_string()];
        let builder = ServiceBuilder::new(config);
        let result = builder.build_secret_providers().await;
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("unknown secret provider"));
    }

    #[test]
    fn test_build_builder_service() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);

        let beacon = builder.build_beacon().unwrap();
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let enablement: Arc<dyn SigningEnablement> = Arc::new(DoppelgangerDisabledByOperator);
        let (signer, _quiesce_registry) = builder.build_signer(composite, slashing_db, enablement);

        // Build a temp validators config with a non-zero fee_recipient to satisfy the guard.
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        std::fs::write(&config_path, format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n"))
            .unwrap();
        let validator_store = builder.build_validator_store(Some(&config_path)).unwrap();

        let _builder_service = builder.build_builder_service(
            signer,
            beacon,
            validator_store,
            [0, 0, 0, 0],
            Arc::new(eth_types::ForkSchedule::unscheduled_gloas()),
        );
    }

    #[test]
    fn test_log_effective_config_does_not_panic() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        builder.log_effective_config();
    }

    /// SEC-10: paths under the same temp dir share a filesystem → not divergent.
    #[test]
    fn test_warn_when_keystore_and_slashing_paths_same_fs() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = temp_dir.path().join("keystores");
        let slashing = temp_dir.path().join("slashing.db");
        std::fs::create_dir_all(&keystore).unwrap();
        // slashing path need not exist; filesystem_id walks to the parent.
        assert_eq!(
            paths_on_different_filesystems(&keystore, &slashing),
            Some(false),
            "sibling paths on the same volume must not report divergence"
        );

        let config = Config {
            keystore_path: keystore,
            slashing_db_path: slashing,
            ..create_minimal_config()
        };
        // Must not panic; no warning expected for same-FS paths.
        ServiceBuilder::new(config).warn_keystore_slashing_path_divergence();
    }

    /// SEC-10: when both sides can be resolved, different device IDs report divergence.
    ///
    /// We cannot create two real mount points in unit tests, so pin the pure
    /// helper against the same-device case and the "cannot determine" path.
    #[test]
    fn test_warn_when_keystore_and_slashing_paths_differ_fs() {
        let temp_dir = TempDir::new().unwrap();
        let keystore = temp_dir.path().join("keys");
        std::fs::create_dir_all(&keystore).unwrap();

        // Non-existent absolute path with no existing ancestor on a typical
        // layout still resolves via `/` → comparable, same device as temp.
        // On Unix, an empty path cannot be resolved → None.
        assert_eq!(paths_on_different_filesystems(Path::new(""), Path::new("")), None);

        // Same existing directory compared to itself is never divergent.
        assert_eq!(paths_on_different_filesystems(&keystore, &keystore), Some(false));

        // Distinct subpaths under one temp dir share st_dev.
        let slashing = temp_dir.path().join("nested").join("slash.db");
        assert_eq!(paths_on_different_filesystems(&keystore, &slashing), Some(false));
    }

    // --- ISSUE-2.1: H-1 fee recipient + gas-limit defaults ---

    /// Zero fee recipient must be refused with a loud, actionable error.
    #[test]
    fn test_zero_fee_recipient_refused() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        // No config file → default fee recipient is [0u8; 20] → must fail
        let result = builder.build_validator_store(None);
        assert!(
            matches!(result, Err(ConfigError::ZeroFeeRecipient)),
            "expected ZeroFeeRecipient, got: {:?}",
            result.err()
        );
    }

    /// The empty-file error points at the rejected-file recovery steps.
    #[test]
    fn test_empty_validators_config_points_at_rejected_recovery() {
        let msg = ConfigError::EmptyValidatorsConfig.to_string();
        assert!(
            !msg.to_ascii_lowercase().contains("fee recipient"),
            "empty validators config must point at the rejected-file recovery, got {msg}"
        );
        assert!(msg.contains("validators.toml.rejected"), "{msg}");
        assert!(msg.contains("doppelganger_hold_until"), "{msg}");
    }

    /// Omitting the validators file fails closed with the zero fee recipient.
    #[test]
    fn test_docs_say_omitting_validators_config_is_zero_fee_recipient() {
        let validators = include_str!("../../../../docs/validators-config.md");
        let notes = include_str!("../../../../docs/releases/UNRELEASED.md");
        for text in [validators, notes] {
            assert!(
                !text.contains("registers every loaded key as enabled"),
                "dropping --validators-config fails with ZeroFeeRecipient"
            );
        }
    }

    /// An empty validators file is a boot error, distinct from a zero fee recipient.
    #[test]
    fn test_empty_validators_config_is_an_explicit_boot_error() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        std::fs::write(&config_path, "").unwrap();
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_validator_store(Some(&config_path));
        assert!(
            matches!(result, Err(ConfigError::EmptyValidatorsConfig)),
            "an empty validators file must be an explicit boot error, got {:?}",
            result.err()
        );

        std::fs::write(&config_path, " \n\t").unwrap();
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_validator_store(Some(&config_path));
        assert!(
            matches!(result, Err(ConfigError::EmptyValidatorsConfig)),
            "a whitespace validators file must be an explicit boot error, got {:?}",
            result.err()
        );
    }

    /// When the TOML does not specify gas_limit the store must default to 30_000_000.
    #[test]
    fn test_default_gas_limit_30m() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        // TOML with non-zero fee_recipient but no gas_limit field
        let toml = format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n", fr_hex = fr_hex);
        std::fs::write(&config_path, toml).unwrap();

        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_validator_store(Some(&config_path));
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        let store = result.unwrap();
        assert_eq!(store.default_gas_limit(), 30_000_000);
    }

    /// `build_validator_store` must wire `load_from_config` so TOML defaults are reflected.
    #[test]
    fn test_from_toml_paths_wired() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xbbu8; 20]);
        let toml = format!(
            "[defaults]\nfee_recipient = \"{fr_hex}\"\ngas_limit = 50000000\n",
            fr_hex = fr_hex
        );
        std::fs::write(&config_path, toml).unwrap();

        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let result = builder.build_validator_store(Some(&config_path));
        assert!(result.is_ok(), "expected Ok, got: {:?}", result.err());
        let store = result.unwrap();
        assert_eq!(store.default_fee_recipient(), [0xbbu8; 20]);
        assert_eq!(store.default_gas_limit(), 50_000_000);
    }

    #[test]
    fn test_build_validator_store_applies_builder_urls() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        std::fs::write(&config_path, format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n"))
            .unwrap();

        let config = Config {
            builder: crate::config::BuilderSettings {
                builders: vec!["https://relay.example".to_string()],
                min_bid: Some(10_000_000),
                builder_boost_factor: Some(80),
            },
            ..create_minimal_config()
        };
        let store =
            ServiceBuilder::new(config).build_validator_store(Some(&config_path)).expect("store");
        let unknown = [0xffu8; 48];
        assert_eq!(store.builders(&unknown), vec!["https://relay.example".to_string()]);
        assert_eq!(store.min_bid(&unknown), 10_000_000);
        assert_eq!(store.builder_boost_factor(&unknown), 80);
    }

    #[test]
    fn test_build_validator_store_rejects_malformed_builder_url() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        std::fs::write(&config_path, format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n"))
            .unwrap();

        let config = Config {
            builder: crate::config::BuilderSettings {
                builders: vec!["not a url".to_string()],
                ..Default::default()
            },
            ..create_minimal_config()
        };
        let err = match ServiceBuilder::new(config).build_validator_store(Some(&config_path)) {
            Err(e) => e,
            Ok(_) => panic!("malformed URL"),
        };
        let msg = err.to_string();
        assert!(msg.contains("not a url"), "{msg}");
    }

    // --- D-3 (Issue 2.11): no-availability-regression for fail-closed default ---

    /// Builds an in-memory `KeyManager` populated with `count` freshly generated
    /// keys, returning the manager and the matching `pubkey_map`. Mirrors the
    /// startup path where keystore-loaded keys flow into `build_pubkey_map`.
    fn loaded_key_manager(builder: &ServiceBuilder, count: usize) -> (KeyManager, PubkeyMap) {
        let mut key_manager = KeyManager::new();
        for _ in 0..count {
            key_manager.insert(crypto::SecretKey::generate());
        }
        let pubkey_map = builder.build_pubkey_map(&key_manager);
        (key_manager, pubkey_map)
    }

    /// CRITICAL (D-3 fail-closed safety): after flipping the unknown-pubkey
    /// default to fail-closed, every validator the VC actually loads from
    /// keystores — with NO per-validator `validators_config` TOML entry — must
    /// still be permitted to sign, because startup registers each loaded pubkey
    /// in the `ValidatorStore`. Without `register_loaded_validators`, every
    /// keystore-loaded key would hit the fail-closed default and be silently
    /// blocked (catastrophic availability regression).
    #[test]
    fn test_loaded_validators_registered_so_signing_enabled() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xccu8; 20]);
        // Non-zero default fee recipient but NO per-validator entries — the common
        // production case where keys are loaded into the KeyManager, not the store.
        std::fs::write(&config_path, format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n"))
            .unwrap();

        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let store = builder.build_validator_store(Some(&config_path)).unwrap();
        let (key_manager, pubkey_map) = loaded_key_manager(&builder, 3);

        // Before registration the loaded keys are untracked → fail-closed.
        for pubkey in key_manager.list_public_keys() {
            assert!(
                !store.is_signing_enabled(&pubkey.to_bytes()),
                "untracked loaded key must be fail-closed before registration"
            );
        }

        builder.register_loaded_validators(&store, &pubkey_map);

        // After registration every loaded key is tracked & enabled.
        for pubkey in key_manager.list_public_keys() {
            assert!(
                store.is_signing_enabled(&pubkey.to_bytes()),
                "loaded keystore key must be permitted to sign after startup registration"
            );
        }
    }

    /// `register_loaded_validators` must NOT clobber an existing disabled entry
    /// (e.g. a validator set `enabled = false` by the doppelganger window or via
    /// the validators TOML). Registration only adds keys that are not already
    /// tracked.
    #[test]
    fn test_register_loaded_validators_preserves_disabled_entry() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xddu8; 20]);
        std::fs::write(&config_path, format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n"))
            .unwrap();

        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let store = builder.build_validator_store(Some(&config_path)).unwrap();
        let (key_manager, pubkey_map) = loaded_key_manager(&builder, 1);
        let pk = key_manager.list_public_keys()[0].to_bytes();

        // Simulate the doppelganger window having disabled this validator before
        // registration runs.
        let mut disabled = validator_store::ValidatorConfig::new(pk);
        disabled.enabled = false;
        store.add_validator(disabled).unwrap();

        builder.register_loaded_validators(&store, &pubkey_map);

        assert!(
            !store.is_signing_enabled(&pk),
            "registration must not re-enable a validator already tracked as disabled"
        );
    }

    // ── SEC-2b: ForwardWindowMachine construction + wiring ─────────────────

    /// Startup wiring: with doppelganger on, `build_signing_enablement` returns
    /// a live `ForwardWindowMachine` (not the opt-out / fail-closed default).
    #[test]
    fn test_bin_rvc_constructs_forward_window_machine() {
        let config = create_minimal_config(); // doppelganger_detection defaults true
        assert!(config.doppelganger_detection);
        let builder = ServiceBuilder::new(config);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let gvr = [0x11u8; 32];
        let (_, pubkey_map) = loaded_key_manager(&builder, 1);

        let (enablement, machine) =
            builder.build_signing_enablement(slashing_db, gvr, 10, &pubkey_map, false);

        let machine = machine.expect("doppelganger on must construct ForwardWindowMachine");
        // Same object is both the enablement and the machine handle.
        let pk = pubkey_map.read().values().next().unwrap().clone();
        assert!(
            !enablement.is_signing_enabled(&pk),
            "registered key at epoch>0 must be gate-closed before liveness window"
        );
        assert!(
            !machine.is_signing_enabled(&pk),
            "machine handle must agree with enablement for the registered key"
        );
        assert_eq!(
            machine.status(&pk),
            doppelganger::ForwardWindowStatus::Pending,
            "fresh registration at epoch 10 must be Pending"
        );
    }

    /// A key registered at epoch E cannot sign before the window elapses when
    /// no external liveness is observed (D-2 fail-closed; SEC-2c loop supplies observations).
    #[test]
    fn test_registered_key_gate_closed_until_window_elapses() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let gvr = [0x22u8; 32];
        let (key_manager, pubkey_map) = loaded_key_manager(&builder, 1);
        let pk = key_manager.list_public_keys()[0].clone();

        let (enablement, machine) =
            builder.build_signing_enablement(slashing_db, gvr, 50, &pubkey_map, false);
        let machine = machine.expect("machine present");

        assert!(!enablement.is_signing_enabled(&pk));

        // Tick well past the boundary WITHOUT observe_liveness → still closed.
        let end_epoch = 50 + DEFAULT_MONITORING_EPOCHS;
        machine.tick(end_epoch + 5, 0);
        assert!(
            !enablement.is_signing_enabled(&pk),
            "without complete liveness observation the gate must stay closed (D-2 fail-closed)"
        );
    }

    /// A detection marker in the keystore directory blocks the epoch-0 bypass.
    #[test]
    fn test_detection_marker_blocks_epoch0_bypass() {
        let dir = tempfile::tempdir().expect("temp");
        crate::detection_marker::write_marker(
            dir.path(),
            &crate::detection_marker::DetectionMarker {
                epoch: 3,
                unix_secs: 4,
                pubkeys: vec!["0x".to_string() + &"ab".repeat(48)],
            },
        )
        .expect("marker");
        let config = Config { keystore_path: dir.path().to_path_buf(), ..create_minimal_config() };
        let builder = ServiceBuilder::new(config);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (_, pubkey_map) = loaded_key_manager(&builder, 1);
        let pk = pubkey_map.read().values().next().unwrap().clone();
        let (_, machine) =
            builder.build_signing_enablement(slashing_db, [0x44; 32], 0, &pubkey_map, true);
        let machine = machine.expect("machine");
        assert_eq!(machine.status(&pk), doppelganger::ForwardWindowStatus::Pending);
        assert!(!machine.is_signing_enabled(&pk));
    }

    /// Epoch-0 (pre-genesis) bypass: registered keys are immediately Safe.
    #[test]
    fn test_epoch0_bypass_preserved() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let gvr = [0x33u8; 32];
        let (key_manager, pubkey_map) = loaded_key_manager(&builder, 1);
        let pk = key_manager.list_public_keys()[0].clone();

        let (enablement, machine) =
            builder.build_signing_enablement(slashing_db, gvr, 0, &pubkey_map, true);

        assert!(machine.is_some());
        assert!(
            enablement.is_signing_enabled(&pk),
            "epoch-0 register must immediately enable signing (pre-genesis bypass)"
        );
    }

    #[test]
    fn test_epoch0_without_genesis_confirmation_stays_closed() {
        let config = create_minimal_config();
        let builder = ServiceBuilder::new(config);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (key_manager, pubkey_map) = loaded_key_manager(&builder, 1);
        let pk = key_manager.list_public_keys()[0].clone();
        let (enablement, _) =
            builder.build_signing_enablement(slashing_db, [0x33u8; 32], 0, &pubkey_map, false);
        assert!(
            !enablement.is_signing_enabled(&pk),
            "epoch 0 without a confirmed genesis must not mark keys Safe"
        );
    }

    /// Operator opt-out: no machine, every key enabled.
    #[test]
    fn test_doppelganger_opt_out_uses_disabled_by_operator() {
        let config = Config { doppelganger_detection: false, ..create_minimal_config() };
        let builder = ServiceBuilder::new(config);
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let gvr = [0x44u8; 32];
        let (key_manager, pubkey_map) = loaded_key_manager(&builder, 1);
        let pk = key_manager.list_public_keys()[0].clone();

        let (enablement, machine) =
            builder.build_signing_enablement(slashing_db, gvr, 99, &pubkey_map, false);

        assert!(machine.is_none(), "opt-out must not construct ForwardWindowMachine");
        assert!(
            enablement.is_signing_enabled(&pk),
            "DoppelgangerDisabledByOperator must enable all keys"
        );
        // Untracked pubkey also enabled (opt-out is total).
        let other = crypto::SecretKey::generate().public_key();
        assert!(enablement.is_signing_enabled(&other));
    }

    /// RF5-13: ServiceBuilder / config readers observe nested sub-struct knobs
    /// (one representative field per nested group).
    #[test]
    fn test_builder_reads_nested_config_sections() {
        use super::super::types::{
            BuilderLimits, GrpcSignerConfig, KeymanagerConfig, LogfileConfig, MonitoringConfig,
            ProposerConfigSource, TracingConfig, TracingExporter,
        };

        let config = Config {
            keymanager: KeymanagerConfig {
                enabled: true,
                address: Some("127.0.0.1:5062".to_string()),
                ..Default::default()
            },
            tracing: TracingConfig {
                endpoint: Some("http://otel:4318".to_string()),
                exporter: TracingExporter::Gcp,
                sample_rate: Some(0.25),
                ..Default::default()
            },
            logfile: LogfileConfig {
                path: Some(std::path::PathBuf::from("/tmp/rvc.log")),
                max_size: 50,
                max_number: 3,
                compress: true,
                level: Some("debug".to_string()),
            },
            grpc_signer: GrpcSignerConfig {
                url: Some("https://signer:50051".to_string()),
                ..Default::default()
            },
            monitoring: MonitoringConfig {
                endpoint: Some("https://mon.example/metrics".to_string()),
                interval: 60,
                endpoint_insecure: true,
            },
            proposer_config: ProposerConfigSource {
                url: Some("https://cfg.example/p.json".to_string()),
                refresh_interval: 120,
                ..Default::default()
            },
            builder_limits: BuilderLimits {
                circuit_breaker_consecutive_limit: 9,
                circuit_breaker_epoch_limit: 11,
            },
            ..Default::default()
        };

        assert!(config.keymanager.enabled);
        assert_eq!(config.keymanager.address.as_deref(), Some("127.0.0.1:5062"));
        assert_eq!(config.tracing.endpoint.as_deref(), Some("http://otel:4318"));
        assert_eq!(config.tracing.exporter, TracingExporter::Gcp);
        assert_eq!(config.tracing.sample_rate, Some(0.25));
        assert_eq!(config.logfile.max_size, 50);
        assert_eq!(config.logfile.max_number, 3);
        assert!(config.logfile.compress);
        assert_eq!(config.grpc_signer.url.as_deref(), Some("https://signer:50051"));
        assert_eq!(config.monitoring.interval, 60);
        assert!(config.monitoring.endpoint_insecure);
        assert_eq!(config.proposer_config.refresh_interval, 120);
        assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 9);
        assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 11);

        // Builder constructs and reads nested keymanager.enabled for feature logging.
        let builder = ServiceBuilder::new(config);
        builder.log_effective_config();
    }

    #[test]
    fn doppelganger_import_window_is_two_spec_epochs() {
        assert_eq!(
            doppelganger_import_window(SLOT_DURATION_MS).as_secs(),
            DEFAULT_MONITORING_EPOCHS * SLOTS_PER_EPOCH * SLOT_DURATION_MS / 1000
        );
        assert_eq!(doppelganger_import_window(6_000).as_secs(), 384);
        assert_eq!(doppelganger_import_window(12_000).as_secs(), 768);
    }

    // ── #626: unfinished import must not take the boot bypass ──────────────

    const RESTART_EPOCH: u64 = 100;

    fn restart_keypair() -> (crypto::SecretKey, crypto::PublicKey) {
        let sk = crypto::SecretKey::generate();
        let pk = sk.public_key();
        (sk, pk)
    }

    fn map_of(keys: &[crypto::PublicKey]) -> PubkeyMap {
        let mut map = HashMap::new();
        for pk in keys {
            map.insert(pk.to_bytes(), pk.clone());
        }
        Arc::new(parking_lot::RwLock::new(map))
    }

    fn composite_with(secrets: Vec<crypto::SecretKey>) -> Arc<CompositeSigner> {
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
        for sk in secrets {
            composite.add_local_key(sk);
        }
        composite
    }

    fn seed_recent_attestation(db: &SlashingDb, pk: &crypto::PublicKey, gvr: &Root) {
        seed_attestation_at(db, pk, gvr, RESTART_EPOCH - 1);
    }

    fn seed_attestation_at(db: &SlashingDb, pk: &crypto::PublicKey, gvr: &Root, target: u64) {
        let pk_hex = hex::encode(pk.to_bytes());
        db.set_genesis_validators_root(gvr).unwrap();
        db.check_and_record_attestation(&pk_hex, target.saturating_sub(1), target, None, gvr)
            .expect("seed attestation");
    }

    fn sign_exit(
        signer: &SignerService,
        pk: &crypto::PublicKey,
        gvr: &Root,
    ) -> Result<crypto::Signature, signer::SignerError> {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(signer.sign_voluntary_exit(
            &eth_types::VoluntaryExit { epoch: 1, validator_index: 1 },
            pk,
            &ForkSchedule::unscheduled_gloas(),
            gvr,
        ))
    }

    fn satisfy_import_window(machine: &ForwardWindowMachine, pk: &crypto::PublicKey) {
        satisfy_window_from(machine, pk, RESTART_EPOCH);
    }

    fn satisfy_window_from(machine: &ForwardWindowMachine, pk: &crypto::PublicKey, start: u64) {
        let sample = doppelganger::ValidatorLivenessData {
            index: hex::encode(pk.to_bytes()),
            is_live: false,
        };
        // Import sets next_check to start + 1 and needs monitoring_epochs + 1
        // closed not-live epochs. The registration epoch itself does not count.
        let remaining = DEFAULT_MONITORING_EPOCHS + 1;
        for offset in 0..remaining {
            let epoch = start + 1 + offset;
            assert!(
                machine
                    .observe_liveness(
                        epoch,
                        std::slice::from_ref(&sample),
                        epoch + 1,
                        doppelganger::CLOSED_EPOCH_SLOT,
                    )
                    .is_empty(),
                "liveness sample"
            );
        }
    }

    struct RestartPaths {
        _dir: TempDir,
        keystores: std::path::PathBuf,
        validators: std::path::PathBuf,
    }

    fn restart_paths() -> RestartPaths {
        let dir = TempDir::new().unwrap();
        let keystores = dir.path().join("keystores");
        let validators = dir.path().join("validators.toml");
        std::fs::create_dir(&keystores).unwrap();
        RestartPaths { _dir: dir, keystores, validators }
    }

    fn builder_for(paths: &RestartPaths, validators: bool) -> ServiceBuilder {
        let mut config = create_minimal_config();
        config.keystore_path = paths.keystores.clone();
        if validators {
            config.validators_config = Some(paths.validators.clone());
        }
        ServiceBuilder::new(config)
    }

    fn write_validators(path: &std::path::Path, rows: &str) {
        let body = format!(
            "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\n\n{rows}"
        );
        std::fs::write(path, body).unwrap();
    }

    fn hold_row(pk: &crypto::PublicKey, until: u64) -> String {
        format!(
            "[[validators]]\npubkey = \"0x{}\"\nenabled = false\ndoppelganger_hold_until = {until}\n",
            hex::encode(pk.to_bytes())
        )
    }

    fn disabled_row(pk: &crypto::PublicKey) -> String {
        format!("[[validators]]\npubkey = \"0x{}\"\nenabled = false\n", hex::encode(pk.to_bytes()))
    }

    fn write_sidecar(
        dir: &std::path::Path,
        pk: &crypto::PublicKey,
        imported_unix: u64,
        partial: bool,
    ) {
        let suffix = if partial { ".import_meta.json.partial" } else { ".import_meta.json" };
        let name = format!("0x{}{suffix}", hex::encode(pk.to_bytes()));
        std::fs::write(dir.join(name), format!("{{\"imported_unix_seconds\":{imported_unix}}}"))
            .unwrap();
    }

    /// Restart of an interrupted import: open hold, recent slashing history.
    ///
    /// The imported key must start Pending and refuse a voluntary exit. A
    /// normally registered key in the same boot, including one that is
    /// operator-disabled with no hold, still takes the history bypass.
    /// After the forward window is observed, the imported key may sign.
    #[test]
    fn restart_with_open_hold_stays_pending_and_refuses_voluntary_exit() {
        let gvr = [0x62u8; 32];
        let (sk_import, pk_import) = restart_keypair();
        let (sk_normal, pk_normal) = restart_keypair();
        let (sk_disabled, pk_disabled) = restart_keypair();
        let paths = restart_paths();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        write_validators(
            &paths.validators,
            &format!(
                "{}{}",
                hold_row(&pk_import, now.saturating_add(10_000)),
                disabled_row(&pk_disabled)
            ),
        );

        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        for pk in [&pk_import, &pk_normal, &pk_disabled] {
            seed_recent_attestation(&db, pk, &gvr);
        }
        let pubkey_map = map_of(&[pk_import.clone(), pk_normal.clone(), pk_disabled.clone()]);
        let builder = builder_for(&paths, true);
        let (enablement, machine) = builder.build_signing_enablement(
            Arc::clone(&db),
            gvr,
            RESTART_EPOCH,
            &pubkey_map,
            false,
        );
        let machine = machine.expect("doppelganger on");
        let composite = composite_with(vec![sk_import, sk_normal, sk_disabled]);
        let (signer, _quiesce) = builder.build_signer(composite, db, enablement);

        assert_eq!(
            machine.status(&pk_import),
            doppelganger::ForwardWindowStatus::Pending,
            "open hold must start Pending after restart"
        );
        assert!(
            matches!(
                sign_exit(signer.as_ref(), &pk_import, &gvr),
                Err(signer::SignerError::BlockedByDoppelganger)
            ),
            "voluntary exit must be refused while the import window is open"
        );

        assert_eq!(
            machine.status(&pk_normal),
            doppelganger::ForwardWindowStatus::Safe,
            "a normally registered key with recent history stays Safe"
        );
        assert!(
            sign_exit(signer.as_ref(), &pk_normal, &gvr).is_ok(),
            "a normally registered key may still sign a voluntary exit"
        );
        assert_eq!(
            machine.status(&pk_disabled),
            doppelganger::ForwardWindowStatus::Safe,
            "an operator disable without a hold is not an unfinished import"
        );

        satisfy_import_window(&machine, &pk_import);
        assert_eq!(
            machine.status(&pk_import),
            doppelganger::ForwardWindowStatus::Safe,
            "the import window can still complete after restart"
        );
        assert!(
            sign_exit(signer.as_ref(), &pk_import, &gvr).is_ok(),
            "voluntary exit is allowed once the restarted window completes"
        );
    }

    /// A recent import sidecar, with no validators hold, is the same bypass.
    #[test]
    fn restart_with_import_sidecar_stays_pending_and_refuses_voluntary_exit() {
        let gvr = [0x63u8; 32];
        let (sk_import, pk_import) = restart_keypair();
        let (sk_normal, pk_normal) = restart_keypair();
        let paths = restart_paths();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        write_sidecar(&paths.keystores, &pk_import, now.saturating_sub(10), false);

        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        seed_recent_attestation(&db, &pk_import, &gvr);
        seed_recent_attestation(&db, &pk_normal, &gvr);
        let pubkey_map = map_of(&[pk_import.clone(), pk_normal.clone()]);
        let builder = builder_for(&paths, false);
        let (enablement, machine) = builder.build_signing_enablement(
            Arc::clone(&db),
            gvr,
            RESTART_EPOCH,
            &pubkey_map,
            false,
        );
        let machine = machine.expect("doppelganger on");
        let (signer, _quiesce) =
            builder.build_signer(composite_with(vec![sk_import, sk_normal]), db, enablement);

        assert_eq!(machine.status(&pk_import), doppelganger::ForwardWindowStatus::Pending);
        assert!(matches!(
            sign_exit(signer.as_ref(), &pk_import, &gvr),
            Err(signer::SignerError::BlockedByDoppelganger)
        ));
        assert_eq!(machine.status(&pk_normal), doppelganger::ForwardWindowStatus::Safe);
        assert!(sign_exit(signer.as_ref(), &pk_normal, &gvr).is_ok());
    }

    /// Epoch 0 must not Safe-skip a key that still has an open hold.
    #[test]
    fn restart_epoch0_open_hold_stays_pending() {
        let gvr = [0x64u8; 32];
        let (_sk, pk) = restart_keypair();
        let paths = restart_paths();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        write_validators(&paths.validators, &hold_row(&pk, now.saturating_add(10_000)));
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let pubkey_map = map_of(std::slice::from_ref(&pk));
        let builder = builder_for(&paths, true);
        let (_enablement, machine) =
            builder.build_signing_enablement(db, gvr, 0, &pubkey_map, false);
        let machine = machine.expect("doppelganger on");
        assert_eq!(
            machine.status(&pk),
            doppelganger::ForwardWindowStatus::Pending,
            "epoch 0 must not bypass an open import hold"
        );
        assert!(!machine.is_signing_enabled(&pk));
    }

    /// Epoch 0 must not Safe-skip a key that still has an import sidecar.
    #[test]
    fn restart_epoch0_import_sidecar_stays_pending_and_refuses_voluntary_exit() {
        let gvr = [0x6au8; 32];
        let (sk, pk) = restart_keypair();
        let paths = restart_paths();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        write_sidecar(&paths.keystores, &pk, now.saturating_sub(900), false);
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let pubkey_map = map_of(std::slice::from_ref(&pk));
        let builder = builder_for(&paths, false);
        let (enablement, machine) =
            builder.build_signing_enablement(Arc::clone(&db), gvr, 0, &pubkey_map, false);
        let machine = machine.expect("doppelganger on");
        let (signer, _quiesce) = builder.build_signer(composite_with(vec![sk]), db, enablement);
        assert_eq!(
            machine.status(&pk),
            doppelganger::ForwardWindowStatus::Pending,
            "epoch 0 must not bypass a remaining import sidecar"
        );
        assert!(matches!(
            sign_exit(signer.as_ref(), &pk, &gvr),
            Err(signer::SignerError::BlockedByDoppelganger)
        ));
    }

    /// A leftover staged sidecar means the import publish did not finish.
    #[test]
    fn restart_with_partial_import_sidecar_stays_pending() {
        let gvr = [0x65u8; 32];
        let (sk, pk) = restart_keypair();
        let paths = restart_paths();
        // Timestamp is long expired. The partial file itself is the signal.
        write_sidecar(&paths.keystores, &pk, 1, true);
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        seed_recent_attestation(&db, &pk, &gvr);
        let pubkey_map = map_of(std::slice::from_ref(&pk));
        let builder = builder_for(&paths, false);
        let (enablement, machine) = builder.build_signing_enablement(
            Arc::clone(&db),
            gvr,
            RESTART_EPOCH,
            &pubkey_map,
            false,
        );
        let machine = machine.expect("doppelganger on");
        let (signer, _quiesce) = builder.build_signer(composite_with(vec![sk]), db, enablement);
        assert_eq!(machine.status(&pk), doppelganger::ForwardWindowStatus::Pending);
        assert!(!machine.is_signing_enabled(&pk));
        assert!(matches!(
            sign_exit(signer.as_ref(), &pk, &gvr),
            Err(signer::SignerError::BlockedByDoppelganger)
        ));
    }

    /// An unreadable or malformed sidecar cannot prove the window elapsed.
    #[test]
    fn restart_with_malformed_import_sidecar_stays_pending() {
        let gvr = [0x66u8; 32];
        let (sk, pk) = restart_keypair();
        let paths = restart_paths();
        let name = format!("0x{}.import_meta.json", hex::encode(pk.to_bytes()));
        std::fs::write(paths.keystores.join(name), "not-json").unwrap();
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        seed_recent_attestation(&db, &pk, &gvr);
        let pubkey_map = map_of(std::slice::from_ref(&pk));
        let builder = builder_for(&paths, false);
        let (enablement, machine) = builder.build_signing_enablement(
            Arc::clone(&db),
            gvr,
            RESTART_EPOCH,
            &pubkey_map,
            false,
        );
        let machine = machine.expect("doppelganger on");
        let (signer, _quiesce) = builder.build_signer(composite_with(vec![sk]), db, enablement);
        assert_eq!(machine.status(&pk), doppelganger::ForwardWindowStatus::Pending);
        assert!(!machine.is_signing_enabled(&pk));
        assert!(matches!(
            sign_exit(signer.as_ref(), &pk, &gvr),
            Err(signer::SignerError::BlockedByDoppelganger)
        ));
    }

    /// Sidecar age is not a completed forward window.
    ///
    /// Import epoch `e`, history target `e`, boot at `e+2`. Distance 2 is inside
    /// the restart skip (`monitoring_epochs` is 2). The sidecar is ~900s old,
    /// past the 768s store hold, and the hold itself has elapsed. A normal key
    /// in the same boot still safe-skips. The imported key stays Pending and
    /// voluntary exit is `BlockedByDoppelganger`.
    #[test]
    fn restart_aged_sidecar_before_forward_window_stays_pending() {
        const IMPORT_EPOCH: u64 = 100;
        const BOOT_EPOCH: u64 = IMPORT_EPOCH + 2;
        let gvr = [0x67u8; 32];
        let (sk_import, pk_import) = restart_keypair();
        let (sk_normal, pk_normal) = restart_keypair();
        let paths = restart_paths();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        write_sidecar(&paths.keystores, &pk_import, now.saturating_sub(900), false);
        write_validators(&paths.validators, &hold_row(&pk_import, now.saturating_sub(100)));
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        seed_attestation_at(&db, &pk_import, &gvr, IMPORT_EPOCH);
        seed_attestation_at(&db, &pk_normal, &gvr, IMPORT_EPOCH);
        let pubkey_map = map_of(&[pk_import.clone(), pk_normal.clone()]);
        let builder = builder_for(&paths, true);
        let (enablement, machine) =
            builder.build_signing_enablement(Arc::clone(&db), gvr, BOOT_EPOCH, &pubkey_map, false);
        let machine = machine.expect("doppelganger on");
        let (signer, _quiesce) =
            builder.build_signer(composite_with(vec![sk_import, sk_normal]), db, enablement);

        assert_eq!(
            machine.status(&pk_import),
            doppelganger::ForwardWindowStatus::Pending,
            "a sidecar older than the store hold is still an unfinished import"
        );
        assert!(
            matches!(
                sign_exit(signer.as_ref(), &pk_import, &gvr),
                Err(signer::SignerError::BlockedByDoppelganger)
            ),
            "voluntary exit must stay blocked until the forward window is observed"
        );
        let sidecar = paths
            .keystores
            .join(format!("0x{}.import_meta.json", hex::encode(pk_import.to_bytes())));
        assert!(sidecar.exists(), "boot must not treat sidecar age as completion");
        assert_eq!(
            machine.status(&pk_normal),
            doppelganger::ForwardWindowStatus::Safe,
            "a key with no import marker still safe-skips from history at e, boot at e+2"
        );
        assert!(sign_exit(signer.as_ref(), &pk_normal, &gvr).is_ok());
    }

    /// A concurrent re-import that takes `tracked_keys` cannot lose its newer
    /// sidecar to cleanup. Without the lock spanning Safe re-check and unlink,
    /// the re-import thread would publish gen 999 between those steps and
    /// cleanup would unlink it.
    #[test]
    fn clear_completed_import_sidecars_lock_keeps_concurrent_reimport() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let dir = TempDir::new().unwrap();
        let (_sk, pk) = restart_keypair();
        let path = dir.path().join(format!("0x{}.import_meta.json", hex::encode(pk.to_bytes())));
        write_sidecar(dir.path(), &pk, 100, false);
        let tracked = Arc::new(TrackedKeys::new());
        let still_safe = Arc::new(AtomicBool::new(true));
        let ready = Arc::new(AtomicBool::new(false));

        let tracked_reimport = Arc::clone(&tracked);
        let still_safe_reimport = Arc::clone(&still_safe);
        let ready_reimport = Arc::clone(&ready);
        let path_reimport = path.clone();
        let pk_reimport = pk.clone();
        let reimport = thread::spawn(move || {
            while !ready_reimport.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(1));
            }
            // Same lock order as production DELETE + import.
            let _guard = tracked_reimport.lock();
            write_sidecar(path_reimport.parent().unwrap(), &pk_reimport, 999, false);
            still_safe_reimport.store(false, Ordering::SeqCst);
        });

        let tracked_cleanup = Arc::clone(&tracked);
        let still_safe_cleanup = Arc::clone(&still_safe);
        let ready_cleanup = Arc::clone(&ready);
        clear_completed_import_sidecars_inner(
            dir.path(),
            tracked_cleanup.as_ref(),
            |_| still_safe_cleanup.load(Ordering::SeqCst),
            Some(&|_| {
                ready_cleanup.store(true, Ordering::SeqCst);
                // Wait until the re-import thread is blocked on tracked_keys.
                let start = std::time::Instant::now();
                while tracked_cleanup.contended() == 0 {
                    assert!(
                        start.elapsed() < Duration::from_secs(2),
                        "re-import thread never contended on tracked_keys"
                    );
                    thread::sleep(Duration::from_millis(1));
                }
            }),
        );
        reimport.join().expect("re-import thread");
        assert!(path.exists(), "a concurrent re-import's sidecar must survive cleanup");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("999"), "cleanup must keep generation 999, not unlink it: {body}");
    }

    /// If the key leaves Safe while cleanup holds `tracked_keys`, the marker
    /// is left in place (no rename-aside / restore path).
    #[test]
    fn clear_completed_import_sidecars_keeps_marker_when_key_leaves_safe() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = TempDir::new().unwrap();
        let (_sk, pk) = restart_keypair();
        let path = dir.path().join(format!("0x{}.import_meta.json", hex::encode(pk.to_bytes())));
        write_sidecar(dir.path(), &pk, 100, false);
        let tracked = TrackedKeys::new();
        let still_safe = AtomicBool::new(true);
        clear_completed_import_sidecars_inner(
            dir.path(),
            &tracked,
            |_| still_safe.load(Ordering::SeqCst),
            Some(&|_| {
                still_safe.store(false, Ordering::SeqCst);
            }),
        );
        assert!(path.exists(), "leaving Safe under the lock must keep the unfinished marker");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("100"), "marker bytes must be unchanged: {body}");
    }

    /// A leftover `.removing.*` set-aside from an older cleanup is unfinished
    /// at boot, and Safe cleanup removes it under `tracked_keys`.
    #[test]
    fn leftover_removing_sidecar_is_unfinished_and_cleared_when_safe() {
        let gvr = [0x6cu8; 32];
        let (sk, pk) = restart_keypair();
        let paths = restart_paths();
        let removing = paths
            .keystores
            .join(format!("0x{}.import_meta.json.removing.100", hex::encode(pk.to_bytes())));
        std::fs::write(&removing, "{\"imported_unix_seconds\":100}").unwrap();
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        seed_recent_attestation(&db, &pk, &gvr);
        let pubkey_map = map_of(std::slice::from_ref(&pk));
        let builder = builder_for(&paths, false);
        let (enablement, machine) = builder.build_signing_enablement(
            Arc::clone(&db),
            gvr,
            RESTART_EPOCH,
            &pubkey_map,
            false,
        );
        let machine = machine.expect("doppelganger on");
        let (signer, _quiesce) = builder.build_signer(composite_with(vec![sk]), db, enablement);
        assert_eq!(
            machine.status(&pk),
            doppelganger::ForwardWindowStatus::Pending,
            "leftover .removing.* must fail closed as unfinished"
        );
        assert!(matches!(
            sign_exit(signer.as_ref(), &pk, &gvr),
            Err(signer::SignerError::BlockedByDoppelganger)
        ));

        satisfy_window_from(&machine, &pk, RESTART_EPOCH);
        assert_eq!(machine.status(&pk), doppelganger::ForwardWindowStatus::Safe);
        let tracked = TrackedKeys::new();
        clear_completed_import_sidecars(&paths.keystores, &tracked, |bytes| {
            bytes == &pk.to_bytes()
        });
        assert!(!removing.exists(), "Safe cleanup must remove leftover .removing.* under the lock");
    }

    /// Observing the window removes the sidecar. The next boot may safe-skip.
    #[test]
    fn restart_after_observed_forward_window_removes_sidecar_and_safe_skips() {
        const IMPORT_EPOCH: u64 = 100;
        const BOOT_EPOCH: u64 = IMPORT_EPOCH + 2;
        let gvr = [0x6bu8; 32];
        let (sk, pk) = restart_keypair();
        let paths = restart_paths();
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        write_sidecar(&paths.keystores, &pk, now.saturating_sub(900), false);
        write_validators(&paths.validators, &hold_row(&pk, now.saturating_sub(100)));
        let sidecar =
            paths.keystores.join(format!("0x{}.import_meta.json", hex::encode(pk.to_bytes())));
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        seed_attestation_at(&db, &pk, &gvr, IMPORT_EPOCH);
        let pubkey_map = map_of(std::slice::from_ref(&pk));
        let builder = builder_for(&paths, true);
        let (_enablement, machine) =
            builder.build_signing_enablement(Arc::clone(&db), gvr, BOOT_EPOCH, &pubkey_map, false);
        let machine = machine.expect("doppelganger on");
        assert_eq!(machine.status(&pk), doppelganger::ForwardWindowStatus::Pending);

        satisfy_window_from(&machine, &pk, BOOT_EPOCH);
        assert_eq!(machine.status(&pk), doppelganger::ForwardWindowStatus::Safe);
        let tracked = TrackedKeys::new();
        clear_completed_import_sidecars(&paths.keystores, &tracked, |bytes| {
            bytes == &pk.to_bytes()
        });
        assert!(!sidecar.exists(), "Safe observation must remove the unfinished marker");

        let (enablement, machine) =
            builder.build_signing_enablement(Arc::clone(&db), gvr, BOOT_EPOCH, &pubkey_map, false);
        let machine = machine.expect("doppelganger on");
        let (signer, _quiesce) = builder.build_signer(composite_with(vec![sk]), db, enablement);
        assert_eq!(
            machine.status(&pk),
            doppelganger::ForwardWindowStatus::Safe,
            "once the sidecar is gone, an elapsed hold and recent history may safe-skip"
        );
        assert!(sign_exit(signer.as_ref(), &pk, &gvr).is_ok());
    }

    /// A validators file that cannot be parsed must not grant the bypass.
    #[test]
    fn restart_unreadable_validators_file_fails_closed() {
        let gvr = [0x68u8; 32];
        let (sk, pk) = restart_keypair();
        let paths = restart_paths();
        std::fs::write(&paths.validators, "this is not a validators file [[[").unwrap();
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        seed_recent_attestation(&db, &pk, &gvr);
        let pubkey_map = map_of(std::slice::from_ref(&pk));
        let builder = builder_for(&paths, true);
        let (enablement, machine) = builder.build_signing_enablement(
            Arc::clone(&db),
            gvr,
            RESTART_EPOCH,
            &pubkey_map,
            false,
        );
        let machine = machine.expect("doppelganger on");
        let (signer, _quiesce) = builder.build_signer(composite_with(vec![sk]), db, enablement);
        assert_eq!(machine.status(&pk), doppelganger::ForwardWindowStatus::Pending);
        assert!(!machine.is_signing_enabled(&pk));
        assert!(matches!(
            sign_exit(signer.as_ref(), &pk, &gvr),
            Err(signer::SignerError::BlockedByDoppelganger)
        ));
    }

    /// A keystore directory that cannot be listed must not grant the bypass.
    #[test]
    fn restart_unreadable_keystore_dir_fails_closed() {
        let gvr = [0x69u8; 32];
        let (sk, pk) = restart_keypair();
        let dir = TempDir::new().unwrap();
        let not_a_dir = dir.path().join("keystores");
        std::fs::write(&not_a_dir, "file").unwrap();
        let mut config = create_minimal_config();
        config.keystore_path = not_a_dir;
        let builder = ServiceBuilder::new(config);
        let db = Arc::new(SlashingDb::open_in_memory().unwrap());
        seed_recent_attestation(&db, &pk, &gvr);
        let pubkey_map = map_of(std::slice::from_ref(&pk));
        let (enablement, machine) = builder.build_signing_enablement(
            Arc::clone(&db),
            gvr,
            RESTART_EPOCH,
            &pubkey_map,
            false,
        );
        let machine = machine.expect("doppelganger on");
        let (signer, _quiesce) = builder.build_signer(composite_with(vec![sk]), db, enablement);
        assert_eq!(machine.status(&pk), doppelganger::ForwardWindowStatus::Pending);
        assert!(!machine.is_signing_enabled(&pk));
        assert!(matches!(
            sign_exit(signer.as_ref(), &pk, &gvr),
            Err(signer::SignerError::BlockedByDoppelganger)
        ));
    }
}
