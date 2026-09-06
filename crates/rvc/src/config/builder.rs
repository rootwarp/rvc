//! Service builder for constructing all services from configuration.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use observability::logging::RedactedUrl;

use crate::orchestrator::{OrchestratorConfig, PubkeyMap};
use beacon::{parse_slot_duration_ms, BeaconClient, BeaconClientConfig};
use bn_manager::{AttestationSubmitter, BeaconNodeClient, BnManager, BnManagerConfig, Propagator};
use builder::BuilderService;
use crypto::{CompositeSigner, KeyManager};
use doppelganger::{
    DoppelgangerDisabledByOperator, ForwardWindowMachine, SigningEnablement,
    DEFAULT_MONITORING_EPOCHS,
};
use duty_tracker::DutyTracker;
use eth_types::{Epoch, ForkSchedule, Root};
use signer::{SignerService, ValidatorSigner};
use slashing::{GroupCommitConfig, SlashingDb};
use timing::{DeadlineBps, SystemSlotClock};
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

    /// Build a single-endpoint [`BeaconClient`] for exit tooling.
    ///
    /// Runtime block production, duties, and attestation paths must use
    /// [`Self::build_bn_manager`] / [`Self::build_proposer_bn_manager`] so
    /// multi-BN failover applies. This helper is intentionally limited to
    /// single-client needs (keymanager voluntary exit and similar).
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
            "Created beacon client (exit tooling)"
        );
        Ok(Arc::new(client))
    }

    /// Shared pool config for main and proposer `BnManager`s: H-12 body cap and
    /// global broadcast-topic policy (including `blocks` for publish path).
    fn pool_bn_manager_config(&self, endpoints: Vec<String>) -> BnManagerConfig {
        let mut config =
            BnManagerConfig::new(endpoints).with_max_body_bytes(self.config.beacon_max_body_bytes);
        config.broadcast_topics = self.config.effective_broadcast_topics();
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
    /// Uses the same body-size cap and broadcast-topic policy as the main pool
    /// so dedicated proposer publish/produce honor operator DoS and broadcast
    /// settings (not `BnManagerConfig` defaults alone).
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
            .with_operation_timeouts(bn_manager::OperationTimeouts::default());
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

        let key_manager = KeyManager::load_from_directory_with_threads_filtered(
            &self.config.keystore_path,
            &passwords,
            self.config.key_decrypt_threads,
            denylist,
        )?;
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
    /// [`Self::build_signing_enablement`] (or an equivalent). The enablement is
    /// the doppelganger gate consulted on every duty-signing path (SEC-2a/2b).
    pub fn build_signer(
        &self,
        composite_signer: Arc<CompositeSigner>,
        slashing_db: Arc<SlashingDb>,
        enablement: Arc<dyn SigningEnablement>,
    ) -> Arc<SignerService> {
        let signer = SignerService::new(composite_signer, slashing_db).with_enablement(enablement);
        info!("Created signer service with signing enablement (SEC-2b)");
        Arc::new(signer)
    }

    /// Construct the production [`SigningEnablement`] (SEC-2b).
    ///
    /// - When doppelganger detection is **enabled** (default): builds a
    ///   [`ForwardWindowMachine`], registers every loaded key at
    ///   `current_epoch`, and returns it as the enablement. Keys remain
    ///   closed until the monitoring window elapses with complete liveness
    ///   observations (driven by SEC-2c). Epoch-0 registration is immediately
    ///   `Safe` (pre-genesis bypass). Cost: ~[`DEFAULT_MONITORING_EPOCHS`]
    ///   epochs (~12.8 min on mainnet).
    /// - When **disabled** (`--no-doppelganger-detection`): returns
    ///   [`DoppelgangerDisabledByOperator`], which enables every key.
    ///
    /// The optional machine handle is returned so keymanager import /
    /// secret-provider refresh can `register_for_import` against the same
    /// instance (import-strict: no restart Safe-skip).
    ///
    /// # Restart-aware safe-skip (boot only)
    ///
    /// Boot `register` may mark a key `Safe` if local slashing history shows a
    /// recent attestation under this GVR (same-host restart). **Do not copy a
    /// live slashing DB to a second VC** — that would dual-open signing without
    /// network liveness. API import uses `register_for_import` and never skips.
    pub fn build_signing_enablement(
        &self,
        slashing_db: Arc<SlashingDb>,
        gvr: Root,
        current_epoch: Epoch,
        pubkey_map: &PubkeyMap,
    ) -> (Arc<dyn SigningEnablement>, Option<Arc<ForwardWindowMachine>>) {
        if !self.config.doppelganger_detection {
            tracing::warn!(
                "Doppelganger detection disabled by operator (--no-doppelganger-detection). \
                 Forward-window protection is off; a duplicate live instance can double-sign. \
                 Default on costs ~{DEFAULT_MONITORING_EPOCHS} epochs of withheld signing \
                 (~12.8 min on mainnet)."
            );
            return (Arc::new(DoppelgangerDisabledByOperator), None);
        }

        let reader: Arc<dyn slashing::SlashingDbReader> = slashing_db;
        let machine = Arc::new(ForwardWindowMachine::new(reader, DEFAULT_MONITORING_EPOCHS, gvr));

        let mut registered = 0usize;
        for pubkey in pubkey_map.read().values() {
            machine.register(pubkey, current_epoch);
            registered += 1;
        }

        info!(
            monitoring_epochs = DEFAULT_MONITORING_EPOCHS,
            current_epoch,
            registered,
            "ForwardWindowMachine constructed (SEC-2b/2c). Keys stay closed until \
             {DEFAULT_MONITORING_EPOCHS} epochs of network liveness are observed \
             (~12.8 min on mainnet). The per-slot liveness loop (SEC-2c) feeds \
             observe_liveness via bn-manager failover; epoch-0 bypass and \
             restart-aware safe-skip still apply on boot register only."
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

    pub fn build_duty_tracker(
        &self,
        beacon: Arc<dyn BeaconNodeClient>,
        validator_indices: Vec<String>,
        fork_schedule: ForkSchedule,
    ) -> Arc<DutyTracker> {
        let tracker = DutyTracker::new(beacon, validator_indices).with_fork_schedule(fork_schedule);
        info!("Created duty tracker");
        Arc::new(tracker)
    }

    pub async fn resolve_slot_duration_ms(
        &self,
        beacon: &dyn BeaconNodeClient,
    ) -> Result<u64, ConfigError> {
        info!("Fetching slot duration from beacon node config spec");
        let spec = beacon.get_config_spec().await?;
        let slot_duration_ms = parse_slot_duration_ms(&spec.data)?;
        info!(slot_duration_ms, "Resolved slot duration from beacon node spec");
        Ok(slot_duration_ms)
    }

    pub fn build_slot_clock(
        &self,
        slot_duration_ms: u64,
    ) -> Result<Arc<SystemSlotClock>, ConfigError> {
        let genesis_time = self.config.effective_genesis_time()?;
        let slot_duration = Duration::from_millis(slot_duration_ms);
        let slots_per_epoch = self.config.network.slots_per_epoch();

        let clock = SystemSlotClock::new(genesis_time, slot_duration, slots_per_epoch)
            .map_err(|e| ConfigError::MissingField(format!("invalid slot clock: {e}")))?
            .with_deadlines(DeadlineBps {
                attestation: self.config.timing.attestation_due_bps,
                aggregate: self.config.timing.aggregate_due_bps,
            });
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
    /// Returns [`ConfigError::ZeroFeeRecipient`] if the effective default fee
    /// recipient is the zero address.  Operators must set a non-zero address in
    /// the validators config file passed via `--validators-config`.
    pub fn build_validator_store(
        &self,
        validators_config: Option<&std::path::Path>,
    ) -> Result<Arc<ValidatorStore>, ConfigError> {
        let store = match validators_config {
            Some(path) => ValidatorStore::load_from_config(path)
                .map_err(|e| ConfigError::ValidatorStoreError(e.to_string()))?,
            None => ValidatorStore::new([0u8; 20], 30_000_000),
        };

        if store.default_fee_recipient() == [0u8; 20] {
            return Err(ConfigError::ZeroFeeRecipient);
        }

        info!("Created validator store");
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
                store.add_validator(validator_store::ValidatorConfig::new(pk_bytes));
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
    ) -> Arc<BuilderService> {
        // Bridge full trait objects onto the narrow builder seams
        // (`RegistrationSigner` / `BuilderBeaconClient`).
        let signer: Arc<dyn ValidatorSigner> = signer;
        let service = BuilderService::new(
            Arc::new(signer),
            Arc::new(beacon),
            validator_store,
            genesis_fork_version,
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
    ) -> OrchestratorConfig {
        OrchestratorConfig::new(genesis_validators_root, fork_schedule)
            .with_shutdown_timeout(Duration::from_secs(30))
            .with_attestation_due_bps(self.config.timing.attestation_due_bps)
            .with_aggregate_due_bps(self.config.timing.aggregate_due_bps)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::TimingConfig;
    use crypto::{LocalSigner, Signer as _};
    use eth_types::NetworkPreset;
    use tempfile::TempDir;
    use timing::SlotClock;

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
        let signer = builder.build_signer(composite, slashing_db, enablement);

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
        let orch_config = builder.build_orchestrator_config(root, sample_fork_schedule());

        assert_eq!(orch_config.genesis_validators_root, root);
        assert_eq!(orch_config.shutdown_timeout, Duration::from_secs(30));
        assert_eq!(orch_config.attestation_due_bps, 3333);
        assert_eq!(orch_config.aggregate_due_bps, 6667);
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
        let orch_config = builder.build_orchestrator_config([0xaa; 32], sample_fork_schedule());
        assert_eq!(orch_config.attestation_due_bps, 2500);
        assert_eq!(orch_config.aggregate_due_bps, 4000);
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
        let orch = builder.build_orchestrator_config([0xaa; 32], sample_fork_schedule());
        assert_eq!(clock.deadlines().attestation, 3333);
        assert_eq!(clock.deadlines().aggregate, 6667);
        assert_eq!(orch.attestation_due_bps, 3333);
        assert_eq!(orch.aggregate_due_bps, 6667);
        assert_eq!(timing::due_ms(clock.deadlines().attestation, 12_000), 3999);
        assert_eq!(timing::due_ms(clock.deadlines().aggregate, 12_000), 8000);
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
        let signer = builder.build_signer(composite, slashing_db, enablement);

        // Build a temp validators config with a non-zero fee_recipient to satisfy the guard.
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("validators.toml");
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        std::fs::write(&config_path, format!("[defaults]\nfee_recipient = \"{fr_hex}\"\n"))
            .unwrap();
        let validator_store = builder.build_validator_store(Some(&config_path)).unwrap();

        let _builder_service =
            builder.build_builder_service(signer, beacon, validator_store, [0, 0, 0, 0]);
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
        store.add_validator(disabled);

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
            builder.build_signing_enablement(slashing_db, gvr, 10, &pubkey_map);

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
            builder.build_signing_enablement(slashing_db, gvr, 50, &pubkey_map);
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
            builder.build_signing_enablement(slashing_db, gvr, 0, &pubkey_map);

        assert!(machine.is_some());
        assert!(
            enablement.is_signing_enabled(&pk),
            "epoch-0 register must immediately enable signing (pre-genesis bypass)"
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
            builder.build_signing_enablement(slashing_db, gvr, 99, &pubkey_map);

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
}
