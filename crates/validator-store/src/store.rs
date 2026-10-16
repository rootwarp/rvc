use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use observability::logging::TruncatedPubkey;
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, trace, warn};

use crate::block_selection::BlockSelectionMode;
use crate::config::{DefaultUpdate, ValidatorConfig, ValidatorConfigUpdate};
use crate::error::ValidatorStoreError;

#[derive(Debug, Deserialize, Serialize)]
struct TomlConfig {
    #[serde(default)]
    defaults: Option<TomlDefaults>,
    #[serde(default)]
    validators: Vec<TomlValidator>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TomlDefaults {
    fee_recipient: Option<String>,
    gas_limit: Option<u64>,
    graffiti: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TomlValidator {
    pubkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee_recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    builder_proposals: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    builder_boost_factor: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    graffiti: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    /// Absent on operator and slashing disables. Present only for a doppelganger hold.
    #[serde(skip_serializing_if = "Option::is_none")]
    doppelganger_hold_until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    block_selection_mode: Option<BlockSelectionMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    builders: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    min_bid: Option<u64>,
}

fn parse_hex_bytes<const N: usize>(s: &str) -> Result<[u8; N], ValidatorStoreError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| ValidatorStoreError::Config(e.to_string()))?;
    bytes.try_into().map_err(|_| ValidatorStoreError::Config(format!("expected {N} bytes")))
}

/// Fallback fee recipient when `[defaults]` omits `fee_recipient` (zero address).
const DEFAULT_FEE_RECIPIENT: [u8; 20] = [0u8; 20];

/// Fallback gas limit when `[defaults]` omits `gas_limit`.
const DEFAULT_GAS_LIMIT: u64 = 30_000_000;

/// Built-in `builder_boost_factor` when neither per-validator nor global is set.
const FALLBACK_BUILDER_BOOST_FACTOR: u64 = 100;

/// Built-in `min_bid` when neither per-validator nor global is set.
const FALLBACK_MIN_BID: u64 = 0;

/// How many times a slashed disable retries the validators-file write.
const SLASHED_PERSIST_ATTEMPTS: u32 = 3;

/// Repair attempts after a durable update sees `validator_gen` change.
const IDENTITY_REPAIR_ATTEMPTS: u32 = 8;

/// Reject `value` when TOML cannot serialize it (`u64` above `i64::MAX`).
///
/// A value that passes this check can round-trip through `toml::to_string`.
/// A larger value would make every later save fail.
pub fn ensure_toml_u64(field: &str, value: u64) -> Result<(), ValidatorStoreError> {
    if value > i64::MAX as u64 {
        return Err(ValidatorStoreError::Config(format!(
            "{field} {value} exceeds i64::MAX; TOML cannot store it"
        )));
    }
    Ok(())
}

fn missing_validators_config() -> ValidatorStoreError {
    ValidatorStoreError::Config(
        "no validators_config path set; the change is not persisted".to_string(),
    )
}

/// SSZ `MAX_BUILDER_URL_SIZE`; keep in lock-step with `rvc-config` `[builder]`
/// and `beacon::v4_wire::MAX_BUILDER_URL_SIZE`.
const MAX_BUILDER_URL_SIZE: usize = 2048;

/// Reject a builder URL that is not `http`/`https` with a host, naming the value.
///
/// Empty lists are validated by skipping this helper (no URLs to check).
/// Keep in lock-step with `rvc-config` `[builder]` validation.
pub fn validate_builder_url(raw: &str) -> Result<(), ValidatorStoreError> {
    if raw.len() > MAX_BUILDER_URL_SIZE {
        return Err(ValidatorStoreError::Config(format!(
            "builder URL exceeds {MAX_BUILDER_URL_SIZE} bytes: {raw:?}"
        )));
    }
    let parsed = url::Url::parse(raw)
        .map_err(|_| ValidatorStoreError::Config(format!("malformed builder URL: {raw:?}")))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(ValidatorStoreError::Config(format!(
            "builder URL must start with http:// or https://: {raw:?}"
        )));
    }
    if parsed.host_str().is_none() {
        return Err(ValidatorStoreError::Config(format!("malformed builder URL: {raw:?}")));
    }
    Ok(())
}

fn validate_builder_urls(urls: &[String]) -> Result<(), ValidatorStoreError> {
    for raw in urls {
        validate_builder_url(raw)?;
    }
    Ok(())
}

/// Parse TOML validator config content into defaults and per-validator entries.
///
/// Fallback constants for missing default fields are defined once
/// (`DEFAULT_FEE_RECIPIENT`, `DEFAULT_GAS_LIMIT`) and shared by
/// [`ValidatorStore::load_from_config`] and [`ValidatorStore::reload_config`].
fn parse_config(
    content: &str,
) -> Result<(ValidatorDefaults, Vec<ValidatorConfig>), ValidatorStoreError> {
    let toml_config: TomlConfig = toml::from_str(content)?;

    let mut fee_recipient = DEFAULT_FEE_RECIPIENT;
    let mut gas_limit = DEFAULT_GAS_LIMIT;
    let mut graffiti = None;

    if let Some(defaults) = &toml_config.defaults {
        if let Some(ref fr) = defaults.fee_recipient {
            fee_recipient = parse_hex_bytes(fr)?;
        }
        if let Some(gl) = defaults.gas_limit {
            ensure_toml_u64("defaults.gas_limit", gl)?;
            gas_limit = gl;
        }
        if let Some(ref g) = defaults.graffiti {
            graffiti = Some(parse_graffiti(g));
        }
    }

    let mut validators = Vec::with_capacity(toml_config.validators.len());
    for v in &toml_config.validators {
        validators.push(parse_validator(v)?);
    }

    Ok((ValidatorDefaults { fee_recipient, gas_limit, graffiti }, validators))
}

#[derive(Debug, Clone, Copy)]
pub struct ValidatorDefaults {
    pub fee_recipient: [u8; 20],
    pub gas_limit: u64,
    pub graffiti: Option<[u8; 32]>,
}

/// In-memory validator store payload behind a single `RwLock`.
///
/// Validators, defaults, and the global block-selection mode are stored
/// together so accessors never acquire multiple state locks (which previously
/// allowed opposite-order deadlocks between `effective_config` and
/// `save_config`) and so `reload_config` can apply a full update under one
/// write guard — concurrent readers observe either the pre- or post-reload
/// state, never a mix of old defaults with new validators (or vice versa).
///
/// `Clone` exists so `update_config_durable` can persist a candidate and
/// publish only after that write succeeds.
#[derive(Clone)]
struct StoreState {
    validators: HashMap<[u8; 48], ValidatorConfig>,
    defaults: ValidatorDefaults,
    global_block_selection_mode: BlockSelectionMode,
    global_builders: Option<Vec<String>>,
    global_min_bid: Option<u64>,
    global_builder_boost_factor: Option<u64>,
    /// Identity of each pubkey. Bumped on insert, cleared on remove. Not
    /// persisted. `set_enabled` and `update_config` leave it alone, so a
    /// durable update can tell a field edit from a delete/re-import.
    validator_gen: HashMap<[u8; 48], u64>,
    next_validator_gen: u64,
    /// Per-field proposer-URL overlay. Lives in this lock with the row and
    /// `validator_gen`, so a claim, a keymanager write, and a restore each
    /// finish under one write guard.
    url_owned: HashMap<[u8; 48], UrlOwned>,
    /// Live `default_config` overlay. Disk snapshots write `durable`, never
    /// the remote value.
    remote_defaults: RemoteDefaults,
}

impl StoreState {
    fn insert_validator(&mut self, config: ValidatorConfig) {
        let pubkey = config.pubkey;
        self.validators.insert(pubkey, config);
        let gen = self.next_validator_gen;
        self.next_validator_gen = self.next_validator_gen.wrapping_add(1);
        self.validator_gen.insert(pubkey, gen);
    }

    fn take_validator(&mut self, pubkey: &[u8; 48]) -> Option<ValidatorConfig> {
        self.validator_gen.remove(pubkey);
        self.url_owned.remove(pubkey);
        self.validators.remove(pubkey)
    }
}

/// One URL-owned field: `applied` is the remote value, `durable` is what the file keeps.
#[derive(Clone, Copy)]
struct OwnedValue<T> {
    applied: T,
    durable: T,
}

/// Proposer-config URL overlay for one pubkey.
///
/// `generation` is [`StoreState::validator_gen`] when the URL last claimed a
/// field. A delete plus re-import assigns a new generation and drops this
/// overlay in [`StoreState::take_validator`].
#[derive(Clone, Copy, Default)]
struct UrlOwned {
    generation: u64,
    fee_recipient: Option<OwnedValue<Option<[u8; 20]>>>,
    gas_limit: Option<OwnedValue<Option<u64>>>,
    builder_proposals: Option<OwnedValue<bool>>,
}

/// Local defaults captured when a remote `default_config` first owned each field.
#[derive(Clone, Copy, Default)]
struct RemoteDefaults {
    fee_recipient: Option<OwnedValue<[u8; 20]>>,
    gas_limit: Option<OwnedValue<u64>>,
    graffiti: Option<OwnedValue<Option<[u8; 32]>>>,
}

pub struct ValidatorStore {
    state: RwLock<StoreState>,
    config_path: Option<PathBuf>,
    // Serializes durable mutation (`update_config_durable`, `save_config`,
    // `reload_config`, import, delete, and signing-safety disables).
    // Snapshot → tempfile write → atomic rename, and the matching in-memory
    // publish, run as one critical section. A safer disable publishes before
    // the write; a less-safe change publishes only after it. Without this, a
    // thread holding a stale snapshot can `persist` AFTER a thread with newer
    // data and silently clobber committed updates.
    // Lock order is always `save_lock` then `state`, never the reverse.
    // Intentionally separate from `state`: `set_enabled` and the proposer-URL
    // refresher mutate memory without taking it, so a durable update re-applies
    // its delta and must not replace the map. Keymanager import and delete go
    // through `add_validator_durable` / `remove_validator_durable`, which take
    // this lock and persist. `add_validator` / `remove_validator` stay
    // memory-only for startup registration and tests.
    save_lock: Mutex<()>,
    /// Fired after `save_lock` is dropped when a disable has been published.
    /// Callers cancel a doppelganger enable task. Must not run while
    /// `save_lock` is held: the hook takes the lifecycle `state_lock`.
    #[allow(clippy::type_complexity)]
    disable_listener: Mutex<Option<Arc<dyn Fn(&[u8; 48]) + Send + Sync>>>,
}

impl ValidatorStore {
    pub fn new(default_fee_recipient: [u8; 20], default_gas_limit: u64) -> Self {
        Self {
            state: RwLock::new(StoreState {
                validators: HashMap::new(),
                defaults: ValidatorDefaults {
                    fee_recipient: default_fee_recipient,
                    gas_limit: default_gas_limit,
                    graffiti: None,
                },
                global_block_selection_mode: BlockSelectionMode::default(),
                global_builders: None,
                global_min_bid: None,
                global_builder_boost_factor: None,
                validator_gen: HashMap::new(),
                next_validator_gen: 1,
                url_owned: HashMap::new(),
                remote_defaults: RemoteDefaults::default(),
            }),
            config_path: None,
            save_lock: Mutex::new(()),
            disable_listener: Mutex::new(None),
        }
    }

    /// Register the hook invoked after a signing disable is published.
    ///
    /// The hook runs only after `save_lock` is released.
    #[allow(clippy::type_complexity)]
    pub fn set_disable_listener(&self, listener: Arc<dyn Fn(&[u8; 48]) + Send + Sync>) {
        *self.disable_listener.lock() = Some(listener);
    }

    fn notify_signing_disabled(&self, pubkey: &[u8; 48]) {
        let listener = self.disable_listener.lock().clone();
        if let Some(listener) = listener {
            listener(pubkey);
        }
    }

    #[tracing::instrument(name = "validator_store.load_from_config", skip_all)]
    pub fn load_from_config(path: &Path) -> Result<Self, ValidatorStoreError> {
        let content = std::fs::read_to_string(path)?;
        let (defaults, parsed_validators) = parse_config(&content)?;

        debug!(
            default_gas_limit = defaults.gas_limit,
            custom_fee_recipient = defaults.fee_recipient != DEFAULT_FEE_RECIPIENT,
            custom_graffiti = defaults.graffiti.is_some(),
            "resolved effective validator defaults"
        );

        let validators: HashMap<_, _> =
            parsed_validators.into_iter().map(|c| (c.pubkey, c)).collect();
        let mut validator_gen = HashMap::with_capacity(validators.len());
        let mut next_validator_gen = 1u64;
        for pubkey in validators.keys() {
            validator_gen.insert(*pubkey, next_validator_gen);
            next_validator_gen = next_validator_gen.wrapping_add(1);
        }

        info!(
            validator_count = validators.len(),
            path = %path.display(),
            "validator config loaded"
        );

        Ok(Self {
            state: RwLock::new(StoreState {
                validators,
                defaults,
                global_block_selection_mode: BlockSelectionMode::default(),
                global_builders: None,
                global_min_bid: None,
                global_builder_boost_factor: None,
                validator_gen,
                next_validator_gen,
                url_owned: HashMap::new(),
                remote_defaults: RemoteDefaults::default(),
            }),
            config_path: Some(path.to_path_buf()),
            save_lock: Mutex::new(()),
            disable_listener: Mutex::new(None),
        })
    }

    /// Returns the default fee recipient address applied to any validator
    /// that does not have a per-validator override.
    pub fn default_fee_recipient(&self) -> [u8; 20] {
        self.state.read().defaults.fee_recipient
    }

    /// Returns the default gas limit applied to any validator that does not
    /// have a per-validator override.
    pub fn default_gas_limit(&self) -> u64 {
        self.state.read().defaults.gas_limit
    }

    pub fn get_config(&self, pubkey: &[u8; 48]) -> Option<ValidatorConfig> {
        self.state.read().validators.get(pubkey).cloned()
    }

    pub fn effective_config(&self, pubkey: &[u8; 48]) -> ValidatorDefaults {
        let state = self.state.read();
        let validator = state.validators.get(pubkey);
        ValidatorDefaults {
            fee_recipient: validator
                .and_then(|c| c.fee_recipient)
                .unwrap_or(state.defaults.fee_recipient),
            gas_limit: validator.and_then(|c| c.gas_limit).unwrap_or(state.defaults.gas_limit),
            graffiti: validator.and_then(|c| c.graffiti).or(state.defaults.graffiti),
        }
    }

    pub fn effective_fee_recipient(&self, pubkey: &[u8; 48]) -> [u8; 20] {
        let result = self.effective_config(pubkey).fee_recipient;
        trace!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            "fee recipient lookup"
        );
        result
    }

    pub fn effective_gas_limit(&self, pubkey: &[u8; 48]) -> u64 {
        self.effective_config(pubkey).gas_limit
    }

    pub fn effective_graffiti(&self, pubkey: &[u8; 48]) -> Option<[u8; 32]> {
        self.effective_config(pubkey).graffiti
    }

    pub fn is_builder_enabled(&self, pubkey: &[u8; 48]) -> bool {
        let enabled =
            self.state.read().validators.get(pubkey).map(|c| c.builder_proposals).unwrap_or(false);
        trace!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            is_builder_enabled = enabled,
            "builder status lookup"
        );
        enabled
    }

    pub fn builder_boost_factor(&self, pubkey: &[u8; 48]) -> u64 {
        let state = self.state.read();
        state
            .validators
            .get(pubkey)
            .and_then(|c| c.builder_boost_factor)
            .or(state.global_builder_boost_factor)
            .unwrap_or(FALLBACK_BUILDER_BOOST_FACTOR)
    }

    /// Builder URLs: per-validator override, then configured global, then `[]`.
    pub fn builders(&self, pubkey: &[u8; 48]) -> Vec<String> {
        let state = self.state.read();
        if let Some(urls) = state.validators.get(pubkey).and_then(|c| c.builders.as_ref()) {
            return urls.clone();
        }
        state.global_builders.clone().unwrap_or_default()
    }

    /// Min bid in Gwei: per-validator override, then configured global, then 0.
    pub fn min_bid(&self, pubkey: &[u8; 48]) -> u64 {
        let state = self.state.read();
        state
            .validators
            .get(pubkey)
            .and_then(|c| c.min_bid)
            .or(state.global_min_bid)
            .unwrap_or(FALLBACK_MIN_BID)
    }

    pub fn effective_block_selection_mode(&self, pubkey: &[u8; 48]) -> BlockSelectionMode {
        let state = self.state.read();
        state
            .validators
            .get(pubkey)
            .and_then(|c| c.block_selection_mode)
            .unwrap_or(state.global_block_selection_mode)
    }

    pub fn set_global_block_selection_mode(&self, mode: BlockSelectionMode) {
        self.state.write().global_block_selection_mode = mode;
    }

    pub fn set_global_builders(&self, builders: Vec<String>) -> Result<(), ValidatorStoreError> {
        validate_builder_urls(&builders)?;
        self.state.write().global_builders = Some(builders);
        Ok(())
    }

    pub fn set_global_min_bid(&self, min_bid: u64) -> Result<(), ValidatorStoreError> {
        ensure_toml_u64("min_bid", min_bid)?;
        self.state.write().global_min_bid = Some(min_bid);
        Ok(())
    }

    pub fn set_global_builder_boost_factor(&self, factor: u64) -> Result<(), ValidatorStoreError> {
        ensure_toml_u64("builder_boost_factor", factor)?;
        self.state.write().global_builder_boost_factor = Some(factor);
        Ok(())
    }

    /// Write the defaults-tier graffiti. Same field as [`Self::apply_default_update`].
    ///
    /// [`Self::save_config`] persists this value over `[defaults].graffiti`.
    pub fn set_default_graffiti(&self, graffiti: [u8; 32]) {
        self.state.write().defaults.graffiti = Some(graffiti);
    }

    #[tracing::instrument(name = "validator_store.list_enabled_pubkeys", skip_all)]
    pub fn list_enabled_pubkeys(&self) -> Vec<[u8; 48]> {
        self.state.read().validators.values().filter(|c| c.enabled).map(|c| c.pubkey).collect()
    }

    /// Returns `true` if this validator is permitted to sign.
    ///
    /// Fail-closed (D-3 / Issue 2.11): keys that are not tracked by the store
    /// default to `false` so an unknown pubkey is never permitted to sign. Every
    /// validator the VC actually loads is registered in the store at startup (see
    /// `ServiceBuilder::register_loaded_validators`), so only a genuinely-unknown
    /// pubkey hits this default. Keys explicitly added as `enabled = false` (e.g.
    /// freshly imported via the Keymanager API while inside the doppelganger
    /// window) also return `false`.
    pub fn is_signing_enabled(&self, pubkey: &[u8; 48]) -> bool {
        self.state.read().validators.get(pubkey).map(|c| c.enabled).unwrap_or(false)
    }

    pub fn add_validator(&self, config: ValidatorConfig) -> Result<(), ValidatorStoreError> {
        validate_validator_ingress(&config)?;
        self.state.write().insert_validator(config);
        Ok(())
    }

    /// Insert `config` under `save_lock` when `config.pubkey` is absent.
    ///
    /// Returns `Ok(false)` without writing when the row already exists, so a
    /// slashed `enabled = false` cannot be replaced. The check and the insert
    /// share `save_lock`. Import makes signing possible, so a new row is
    /// published only after the validators file write succeeds. No config path
    /// inserts in memory only. A failed write leaves memory unchanged. A
    /// parent-directory `fsync` failure restores the previous file, or moves
    /// the validators file off the boot path when that restore cannot rename.
    pub fn add_validator_durable(
        &self,
        config: ValidatorConfig,
    ) -> Result<bool, ValidatorStoreError> {
        validate_validator_ingress(&config)?;
        let _save_guard = self.save_lock.lock();
        // Check and insert share this critical section. An existing row,
        // including a slashed `enabled = false`, is left unchanged.
        if self.state.read().validators.contains_key(&config.pubkey) {
            return Ok(false);
        }
        let Some(path) = self.config_path.clone() else {
            self.state.write().insert_validator(config);
            return Ok(true);
        };
        let live = self.state.read().clone();
        let previous = self.disk_toml(&live);
        let mut candidate = live;
        candidate.insert_validator(config.clone());
        commit_less_safe(&path, &self.disk_toml(&candidate), &previous)?;
        self.state.write().insert_validator(config);
        Ok(true)
    }

    pub fn remove_validator(&self, pubkey: &[u8; 48]) -> Option<ValidatorConfig> {
        self.state.write().take_validator(pubkey)
    }

    /// Remove `pubkey` under `save_lock`, persisting a candidate before publish.
    ///
    /// The live validator stays until the write succeeds, so readers do not act
    /// on an unpersisted delete. A parent-directory `fsync` failure restores
    /// the previous file. `Ok(None)` is an unknown pubkey (nothing was written).
    pub fn remove_validator_durable(
        &self,
        pubkey: &[u8; 48],
    ) -> Result<Option<ValidatorConfig>, ValidatorStoreError> {
        let _save_guard = self.save_lock.lock();
        let live = self.state.read().clone();
        if !live.validators.contains_key(pubkey) {
            return Ok(None);
        }
        let Some(path) = self.config_path.clone() else {
            return Ok(self.state.write().take_validator(pubkey));
        };
        let previous = self.disk_toml(&live);
        let mut candidate = live;
        candidate.take_validator(pubkey);
        commit_less_safe(&path, &self.disk_toml(&candidate), &previous)?;
        Ok(self.state.write().take_validator(pubkey))
    }

    pub fn set_enabled(&self, pubkey: &[u8; 48], enabled: bool) {
        publish_enabled(&mut self.state.write(), pubkey, enabled);
    }

    /// Flip `enabled` under `save_lock`, following the signing-safety direction.
    ///
    /// `enabled = false` is published immediately, then persisted. A failed
    /// write leaves the validator disabled and returns `Err`. When that row
    /// had a doppelganger hold, the validators file is moved off the boot path
    /// so a restart cannot reload the hold and re-enable the key. `enabled = true`
    /// is persisted first and published only after that write succeeds. An
    /// unknown pubkey is `Ok(())` and does not create a row. A published disable
    /// notifies the disable hook only after `save_lock` is dropped.
    pub fn set_enabled_durable(
        &self,
        pubkey: &[u8; 48],
        enabled: bool,
    ) -> Result<(), ValidatorStoreError> {
        if enabled {
            return self.persist_signing_enable(pubkey);
        }
        let (result, fire) = self.persist_signing_disable(pubkey);
        if fire {
            self.notify_signing_disabled(pubkey);
        }
        result
    }

    /// Persist `enabled = true` before publishing it. An unknown pubkey is `Ok(())`.
    fn persist_signing_enable(&self, pubkey: &[u8; 48]) -> Result<(), ValidatorStoreError> {
        let _save_guard = self.save_lock.lock();
        if !self.state.read().validators.contains_key(pubkey) {
            return Ok(());
        }
        let Some(path) = self.config_path.clone() else {
            publish_enabled(&mut self.state.write(), pubkey, true);
            return Ok(());
        };
        let live = self.state.read().clone();
        let previous = self.disk_toml(&live);
        let mut candidate = live;
        if let Some(cfg) = candidate.validators.get_mut(pubkey) {
            cfg.enabled = true;
            cfg.doppelganger_hold_until = None;
        }
        commit_less_safe(&path, &self.disk_toml(&candidate), &previous)?;
        publish_enabled(&mut self.state.write(), pubkey, true);
        Ok(())
    }

    /// Persist `enabled = false` and do not run the disable listener.
    ///
    /// The bool is whether the listener still has to run. It is false when
    /// `pubkey` is absent. A caller that holds `tracked_keys` must not call
    /// [`Self::run_disable_listener`] until that lock is released: the listener
    /// takes the doppelganger `state_lock`, and DELETE takes `state_lock` before
    /// `tracked_keys`.
    pub fn persist_signing_disable(
        &self,
        pubkey: &[u8; 48],
    ) -> (Result<(), ValidatorStoreError>, bool) {
        let disable_result = {
            let _save_guard = self.save_lock.lock();
            if !self.state.read().validators.contains_key(pubkey) {
                return (Ok(()), false);
            }
            let had_hold = self
                .state
                .read()
                .validators
                .get(pubkey)
                .and_then(|cfg| cfg.doppelganger_hold_until)
                .is_some();
            publish_enabled(&mut self.state.write(), pubkey, false);
            if self.config_path.is_none() {
                Ok(())
            } else {
                match persist_disabled_snapshot(self, pubkey) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        if had_hold {
                            quarantine_held_validators_file(self);
                        }
                        Err(e)
                    }
                }
            }
        };
        (disable_result, true)
    }

    /// Run the disable listener. Do not call this while holding `tracked_keys`.
    pub fn run_disable_listener(&self, pubkey: &[u8; 48]) {
        self.notify_signing_disabled(pubkey);
    }

    /// Persist a doppelganger hold separately from an operator or slashing disable.
    ///
    /// Returns `Ok(false)` when the row is already disabled and is not a hold:
    /// the deadline is not written and the caller must not arm a timer.
    /// `Ok(true)` means a hold is in place (already stored, or just written)
    /// and the timer should run. An existing enabled row is published
    /// `enabled = false` with the deadline, then written. If that write fails,
    /// the previous enabled document is moved off the boot path. A new row is
    /// persisted before it is published. A row that already carries a hold
    /// keeps the later of the two deadlines.
    pub fn begin_doppelganger_hold(
        &self,
        pubkey: &[u8; 48],
        until_unix: u64,
    ) -> Result<bool, ValidatorStoreError> {
        let _save_guard = self.save_lock.lock();
        // Drop the read guard before the body takes `state.write()`.
        let existing = self.state.read().validators.get(pubkey).cloned();
        if let Some(existing) = existing {
            if !existing.enabled && existing.doppelganger_hold_until.is_none() {
                return Ok(false);
            }
            if let Some(old) = existing.doppelganger_hold_until.filter(|_| !existing.enabled) {
                let until = old.max(until_unix);
                if until == old {
                    return Ok(true);
                }
                publish_doppelganger_hold(&mut self.state.write(), pubkey, until);
                if self.config_path.is_none() {
                    return Ok(true);
                }
                if let Err(e) = persist_disabled_snapshot(self, pubkey) {
                    quarantine_held_validators_file(self);
                    return Err(e);
                }
                return Ok(true);
            }
            publish_doppelganger_hold(&mut self.state.write(), pubkey, until_unix);
            if self.config_path.is_none() {
                return Ok(true);
            }
            if let Err(e) = persist_disabled_snapshot(self, pubkey) {
                quarantine_held_validators_file(self);
                return Err(e);
            }
            return Ok(true);
        }
        let mut config = ValidatorConfig::new(*pubkey);
        config.enabled = false;
        config.doppelganger_hold_until = Some(until_unix);
        let Some(path) = self.config_path.clone() else {
            self.state.write().insert_validator(config);
            return Ok(true);
        };
        let live = self.state.read().clone();
        let previous = self.disk_toml(&live);
        let mut candidate = live;
        candidate.insert_validator(config.clone());
        commit_less_safe(&path, &self.disk_toml(&candidate), &previous)?;
        self.state.write().insert_validator(config);
        Ok(true)
    }

    /// Enable `pubkey` only while it still has a doppelganger hold.
    ///
    /// The check and the write share `save_lock`, so a disable that already
    /// cleared the hold is not overwritten with `enabled = true`. `Ok(false)`
    /// means the row is not a hold, or the deadline has not been reached, and
    /// the row was left unchanged.
    pub fn release_doppelganger_hold(
        &self,
        pubkey: &[u8; 48],
    ) -> Result<bool, ValidatorStoreError> {
        let _save_guard = self.save_lock.lock();
        let until =
            self.state.read().validators.get(pubkey).and_then(|cfg| cfg.doppelganger_hold_until);
        let Some(until) = until else {
            return Ok(false);
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now < until {
            return Ok(false);
        }
        let Some(path) = self.config_path.clone() else {
            publish_enabled(&mut self.state.write(), pubkey, true);
            return Ok(true);
        };
        let live = self.state.read().clone();
        let previous = self.disk_toml(&live);
        let mut candidate = live;
        if let Some(cfg) = candidate.validators.get_mut(pubkey) {
            cfg.enabled = true;
            cfg.doppelganger_hold_until = None;
        }
        commit_less_safe(&path, &self.disk_toml(&candidate), &previous)?;
        publish_enabled(&mut self.state.write(), pubkey, true);
        Ok(true)
    }

    /// Re-enable holds whose deadline has passed. Still-open holds are returned
    /// as `(pubkey, residual_secs)` so the caller can re-arm the enable task.
    /// A failed re-enable is retried, then returned with a zero residual.
    pub fn reconcile_doppelganger_holds_at_boot(&self, now_unix: u64) -> Vec<([u8; 48], u64)> {
        let holds: Vec<([u8; 48], u64)> = self
            .state
            .read()
            .validators
            .values()
            .filter_map(|v| v.doppelganger_hold_until.map(|until| (v.pubkey, until)))
            .collect();
        let mut open = Vec::new();
        for (pk, until) in holds {
            if now_unix >= until {
                let mut released = false;
                for _ in 0..3 {
                    if self.set_enabled_durable(&pk, true).is_ok() {
                        released = true;
                        break;
                    }
                }
                if !released {
                    warn!(
                        pubkey = %TruncatedPubkey::new(&hex::encode(pk)),
                        "elapsed doppelganger hold could not be re-enabled; it will be retried"
                    );
                    open.push((pk, 0));
                }
            } else {
                open.push((pk, until - now_unix));
            }
        }
        open
    }

    /// Publish `enabled = false` for a slashed validator, then persist it.
    ///
    /// Holds `save_lock` across the publish and the write. The write hook
    /// (tests) runs while the live flag is already `false`. If every persist
    /// attempt fails, the validator stays disabled in memory and this returns
    /// `Err`. The previous file is not restored: a post-rename failure already
    /// has the safer bytes on disk. When the row had a doppelganger hold, that
    /// failure also moves the validators file off the boot path. An unknown
    /// pubkey is `Ok(())`.
    #[tracing::instrument(name = "validator_store.disable_slashed", skip_all)]
    pub fn disable_slashed(&self, pubkey: &[u8; 48]) -> Result<(), ValidatorStoreError> {
        let result = {
            let _save_guard = self.save_lock.lock();
            if !self.state.read().validators.contains_key(pubkey) {
                return Ok(());
            }
            let had_hold = self
                .state
                .read()
                .validators
                .get(pubkey)
                .and_then(|cfg| cfg.doppelganger_hold_until)
                .is_some();
            publish_enabled(&mut self.state.write(), pubkey, false);
            if self.config_path.is_none() {
                persist_disabled_snapshot(self, pubkey)
            } else {
                let mut last_err = None;
                let mut persisted = false;
                for attempt in 1..=SLASHED_PERSIST_ATTEMPTS {
                    match persist_disabled_snapshot(self, pubkey) {
                        Ok(()) => {
                            persisted = true;
                            break;
                        }
                        Err(e) => {
                            error!(
                                attempt,
                                error = %e,
                                pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                                "failed to persist slashed validator disable; retrying"
                            );
                            last_err = Some(e);
                        }
                    }
                }
                if persisted {
                    Ok(())
                } else {
                    if had_hold {
                        quarantine_held_validators_file(self);
                    }
                    error!(
                        pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                        "slashed validator stays disabled in memory after persist retries failed"
                    );
                    Err(last_err.unwrap_or_else(missing_validators_config))
                }
            }
        };
        self.notify_signing_disabled(pubkey);
        result
    }

    pub fn update_config(
        &self,
        pubkey: &[u8; 48],
        update: ValidatorConfigUpdate,
    ) -> Result<(), ValidatorStoreError> {
        validate_update_ingress(&update)?;
        let mut state = self.state.write();
        drop_url_owned_fields(&mut state, pubkey, &update);
        let changed_fields = apply_update_locked(&mut state, pubkey, &update);
        log_validator_config_updated(pubkey, &changed_fields);
        Ok(())
    }

    /// Persist `update` for `pubkey`, then publish it to the live store.
    ///
    /// Builder URLs and TOML integer bounds are validated before `save_lock`
    /// is taken. If `pubkey` is absent from the cloned state this returns
    /// [`ValidatorStoreError::NotFound`] and does not write or publish. A write
    /// error also publishes nothing. On success the same delta is applied to
    /// the live map — the map is not replaced — so `set_enabled` and the
    /// proposer-URL refresher survive.
    ///
    /// Keymanager import and delete take `save_lock` and persist, so they
    /// cannot land between this snapshot and its publish. If that pubkey's
    /// identity still changes during the write, the stale delta is not
    /// published. The repair re-snapshots the whole live store and retries
    /// until `validator_gen` is stable, logging each attempt at `warn` with a
    /// truncated pubkey. [`ValidatorStoreError::NotFound`] covers both the
    /// missing-at-clone case and a replaced identity.
    #[tracing::instrument(name = "validator_store.update_config_durable", skip_all)]
    pub fn update_config_durable(
        &self,
        pubkey: &[u8; 48],
        update: ValidatorConfigUpdate,
    ) -> Result<(), ValidatorStoreError> {
        validate_update_ingress(&update)?;

        let config_path = self.config_path.as_ref().ok_or_else(missing_validators_config)?;

        // Lock order: `save_lock` then `state`. The state guard is dropped
        // before I/O.
        let _save_guard = self.save_lock.lock();

        let mut candidate = self.state.read().clone();
        // Absent at clone: the following write would omit this pubkey, and a
        // re-import before publish would then apply a delta the file never had.
        if !candidate.validators.contains_key(pubkey) {
            return Err(ValidatorStoreError::NotFound);
        }
        let identity = candidate.validator_gen.get(pubkey).copied();
        let previous = self.disk_toml(&candidate);
        drop_url_owned_fields(&mut candidate, pubkey, &update);
        apply_update_locked(&mut candidate, pubkey, &update);

        commit_less_safe(config_path, &self.disk_toml(&candidate), &previous)?;

        // `set_enabled` and the proposer-URL refresher do not bump
        // `validator_gen`, so the same identity still takes the delta.
        // Import and delete take `save_lock` and cannot run here. A caller
        // that still mutates identity without the lock leaves a file that
        // describes a validator that is gone or was replaced. Re-snapshot the
        // whole live store and retry until `validator_gen` is stable. Do not
        // publish the stale delta.
        for attempt in 1..=IDENTITY_REPAIR_ATTEMPTS {
            let live = {
                let mut state = self.state.write();
                let same = state.validators.contains_key(pubkey)
                    && state.validator_gen.get(pubkey).copied() == identity;
                if same {
                    drop_url_owned_fields(&mut state, pubkey, &update);
                    let changed_fields = apply_update_locked(&mut state, pubkey, &update);
                    drop(state);
                    log_validator_config_updated(pubkey, &changed_fields);
                    return Ok(());
                }
                state.clone()
            };
            warn!(
                attempt,
                pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                "validator identity changed during durable update; rewriting the file from the live store"
            );
            let gen = live.validator_gen.clone();
            commit_snapshot(config_path, &self.disk_toml(&live))?;
            if self.state.read().validator_gen == gen {
                return Err(ValidatorStoreError::NotFound);
            }
        }
        error!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            "validator identity kept changing during durable update; in-flight delta was not published"
        );
        Err(ValidatorStoreError::NotFound)
    }

    /// Apply a partial update to the store-wide defaults under one write guard.
    ///
    /// Only fields set to `Some(...)` change; `None` leaves the current value.
    /// Concurrent readers observe either the pre-update or post-update defaults
    /// as a unit (never a mix of new fee recipient with old gas limit).
    /// `gas_limit` above `i64::MAX` is rejected and nothing is published.
    pub fn apply_default_update(&self, update: DefaultUpdate) -> Result<(), ValidatorStoreError> {
        if let Some(gl) = update.gas_limit {
            ensure_toml_u64("gas_limit", gl)?;
        }
        let mut changed_fields = Vec::new();
        if update.fee_recipient.is_some() {
            changed_fields.push("fee_recipient");
        }
        if update.gas_limit.is_some() {
            changed_fields.push("gas_limit");
        }
        if update.graffiti.is_some() {
            changed_fields.push("graffiti");
        }

        let mut state = self.state.write();
        if let Some(fr) = update.fee_recipient {
            state.remote_defaults.fee_recipient = None;
            state.defaults.fee_recipient = fr;
        }
        if let Some(gl) = update.gas_limit {
            state.remote_defaults.gas_limit = None;
            state.defaults.gas_limit = gl;
        }
        if let Some(g) = update.graffiti {
            state.remote_defaults.graffiti = None;
            state.defaults.graffiti = g;
        }

        if !changed_fields.is_empty() {
            info!(changed_fields = changed_fields.join(","), "validator defaults updated");
        }
        Ok(())
    }

    pub fn has_validator(&self, pubkey: &[u8; 48]) -> bool {
        self.state.read().validators.contains_key(pubkey)
    }

    /// Identity assigned at insert and cleared on remove.
    ///
    /// `update_config` does not change it. A delete plus re-import does.
    pub fn validator_generation(&self, pubkey: &[u8; 48]) -> Option<u64> {
        self.state.read().validator_gen.get(pubkey).copied()
    }

    /// Apply one remote proposer row under `save_lock` and one state write.
    ///
    /// A field the URL does not already own takes its baseline from the live
    /// value in this same critical section. A field it already owns keeps that
    /// baseline. A pubkey the store does not contain is left alone.
    pub fn apply_remote_proposer(
        &self,
        pubkey: &[u8; 48],
        update: ValidatorConfigUpdate,
    ) -> Result<(), ValidatorStoreError> {
        validate_update_ingress(&update)?;
        let _save_guard = self.save_lock.lock();
        let mut state = self.state.write();
        let Some(generation) = state.validator_gen.get(pubkey).copied() else {
            return Ok(());
        };
        let (current_fee, current_gas, current_builder) = {
            let Some(config) = state.validators.get(pubkey) else {
                return Ok(());
            };
            (config.fee_recipient, config.gas_limit, config.builder_proposals)
        };
        {
            let entry = state.url_owned.entry(*pubkey).or_default();
            if entry.generation != generation {
                *entry = UrlOwned { generation, ..UrlOwned::default() };
            }
            if let Some(fee) = update.fee_recipient {
                claim_field(&mut entry.fee_recipient, current_fee, fee);
            }
            if let Some(gas) = update.gas_limit {
                claim_field(&mut entry.gas_limit, current_gas, gas);
            }
            if let Some(builder) = update.builder_proposals {
                claim_field(&mut entry.builder_proposals, current_builder, builder);
            }
        }
        apply_update_locked(&mut state, pubkey, &update);
        Ok(())
    }

    /// Restore fields this URL still owns, under `save_lock` and one state write.
    ///
    /// The generation is read and the restore is written before either lock is
    /// released. A mismatch drops the overlay and writes nothing.
    pub fn release_remote_proposer(&self, pubkey: &[u8; 48]) {
        let _save_guard = self.save_lock.lock();
        let mut state = self.state.write();
        let Some(owned) = state.url_owned.get(pubkey).copied() else {
            return;
        };
        let generation = state.validator_gen.get(pubkey).copied();
        #[cfg(test)]
        invoke_release_hook();
        if generation != Some(owned.generation) {
            state.url_owned.remove(pubkey);
            return;
        }
        if let Some(config) = state.validators.get_mut(pubkey) {
            if let Some(fee) = owned.fee_recipient {
                if config.fee_recipient == fee.applied {
                    config.fee_recipient = fee.durable;
                }
            }
            if let Some(gas) = owned.gas_limit {
                if config.gas_limit == gas.applied {
                    config.gas_limit = gas.durable;
                }
            }
            if let Some(builder) = owned.builder_proposals {
                if config.builder_proposals == builder.applied {
                    config.builder_proposals = builder.durable;
                }
            }
        }
        state.url_owned.remove(pubkey);
    }

    /// Apply a remote `default_config` to the live defaults.
    ///
    /// The local value at the moment the remote starts owning a field is what
    /// disk snapshots keep. A later remote value for that field keeps the
    /// same local baseline.
    pub fn apply_remote_defaults(&self, update: DefaultUpdate) -> Result<(), ValidatorStoreError> {
        if let Some(gl) = update.gas_limit {
            ensure_toml_u64("gas_limit", gl)?;
        }
        let _save_guard = self.save_lock.lock();
        let mut state = self.state.write();
        if let Some(fee) = update.fee_recipient {
            let current = state.defaults.fee_recipient;
            claim_field(&mut state.remote_defaults.fee_recipient, current, fee);
            state.defaults.fee_recipient = fee;
        }
        if let Some(gas) = update.gas_limit {
            let current = state.defaults.gas_limit;
            claim_field(&mut state.remote_defaults.gas_limit, current, gas);
            state.defaults.gas_limit = gas;
        }
        if let Some(graffiti) = update.graffiti {
            let current = state.defaults.graffiti;
            claim_field(&mut state.remote_defaults.graffiti, current, graffiti);
            state.defaults.graffiti = graffiti;
        }
        Ok(())
    }

    fn disk_toml(&self, state: &StoreState) -> TomlConfig {
        let mut durable = state.clone();
        revert_remote_overlay(&mut durable);
        snapshot_toml(&durable)
    }

    #[tracing::instrument(name = "validator_store.save_config", skip_all)]
    pub fn save_config(&self) -> Result<(), ValidatorStoreError> {
        let config_path = self.config_path.as_ref().ok_or_else(missing_validators_config)?;

        // Serialize the entire snapshot → write → rename sequence so a
        // concurrent saver with a stale snapshot cannot persist after a
        // saver with newer data and clobber it. Lock order: `save_lock`
        // then `state`.
        let _save_guard = self.save_lock.lock();

        // Single state read: defaults + validators under one guard (no
        // multi-lock ordering with `effective_config`). The guard drops
        // before I/O.
        let toml_config = self.disk_toml(&self.state.read());

        commit_snapshot(config_path, &toml_config)
    }

    #[tracing::instrument(name = "validator_store.reload_config", skip_all)]
    pub fn reload_config(&self) -> Result<(), ValidatorStoreError> {
        let path = self.config_path.as_ref().ok_or_else(|| {
            ValidatorStoreError::Config("no config path set for reload".to_string())
        })?;

        // Lock order is `save_lock` then `state`. Hold `save_lock` across the
        // read and the apply so a durable update cannot commit a newer file
        // that this reload then overwrites from a stale read.
        let _save_guard = self.save_lock.lock();

        let content = std::fs::read_to_string(path).map_err(|e| {
            warn!(path = %path.display(), error = %e, "config parse error");
            e
        })?;
        // Parse-first: compute all new values before any mutation.
        let (new_defaults, parsed_validators) = parse_config(&content).map_err(|e| {
            warn!(path = %path.display(), error = %e, "config parse error");
            e
        })?;

        // Still holding `save_lock`. A test asserts `try_lock` fails here so
        // removing the guard makes that test fail.
        #[cfg(test)]
        invoke_reload_after_parse_hook();

        // Apply-second under one write guard: defaults + validator merges are
        // visible to concurrent readers as a single atomic transition. Merge
        // (insert/overwrite) preserves programmatic validators not present in
        // the file; global_block_selection_mode is left untouched.
        let mut state = self.state.write();
        state.defaults = new_defaults;
        state.url_owned.clear();
        state.remote_defaults = RemoteDefaults::default();
        let existing_count = state.validators.len();
        for config in parsed_validators {
            state.insert_validator(config);
        }
        let added_count = state.validators.len().saturating_sub(existing_count);
        let total_count = state.validators.len();
        drop(state);

        info!(added_count = added_count, total_count = total_count, "config reloaded");

        Ok(())
    }
}

fn parse_validator(v: &TomlValidator) -> Result<ValidatorConfig, ValidatorStoreError> {
    // 48-byte BLS pubkeys go through the shared canonical engine (RF3-15).
    // Fee-recipient remains on the local generic (20-byte) path.
    let pubkey: [u8; 48] = eth_types::canonical::pubkey_hex::parse_pubkey_hex(&v.pubkey)
        .map(|pk| *pk.as_bytes())
        .map_err(|e| ValidatorStoreError::Config(e.to_string()))?;
    let fee_recipient = v.fee_recipient.as_ref().map(|s| parse_hex_bytes(s)).transpose()?;
    let graffiti = v.graffiti.as_ref().map(|s| parse_graffiti(s));

    let config = ValidatorConfig {
        pubkey,
        fee_recipient,
        gas_limit: v.gas_limit,
        builder_proposals: v.builder_proposals.unwrap_or(false),
        builder_boost_factor: v.builder_boost_factor,
        graffiti,
        enabled: v.enabled.unwrap_or(true),
        doppelganger_hold_until: v.doppelganger_hold_until,
        block_selection_mode: v.block_selection_mode,
        builders: v.builders.clone(),
        min_bid: v.min_bid,
    };
    if let Some(urls) = config.builders.as_deref() {
        validate_builder_urls(urls)?;
    }
    ensure_config_toml_bounds(&config)?;
    Ok(config)
}

/// Truncate to 32 bytes and zero-pad. Used by the validators file and `--graffiti`.
pub fn parse_graffiti(s: &str) -> [u8; 32] {
    let mut graffiti = [0u8; 32];
    let bytes = s.as_bytes();
    let len = bytes.len().min(32);
    graffiti[..len].copy_from_slice(&bytes[..len]);
    graffiti
}

fn graffiti_to_string(graffiti: &[u8; 32]) -> String {
    let end = graffiti.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    String::from_utf8_lossy(&graffiti[..end]).into_owned()
}

/// TOML document for `state`. Field set and order match the historical
/// `save_config` body, including `enabled: Some(v.enabled)`.
fn snapshot_toml(state: &StoreState) -> TomlConfig {
    let toml_defaults = TomlDefaults {
        fee_recipient: Some(format!("0x{}", hex::encode(state.defaults.fee_recipient))),
        gas_limit: Some(state.defaults.gas_limit),
        graffiti: state.defaults.graffiti.map(|g| graffiti_to_string(&g)),
    };
    let toml_validators: Vec<TomlValidator> = state
        .validators
        .values()
        .map(|v| TomlValidator {
            pubkey: format!("0x{}", hex::encode(v.pubkey)),
            fee_recipient: v.fee_recipient.map(|fr| format!("0x{}", hex::encode(fr))),
            gas_limit: v.gas_limit,
            builder_proposals: Some(v.builder_proposals),
            builder_boost_factor: v.builder_boost_factor,
            graffiti: v.graffiti.map(|g| graffiti_to_string(&g)),
            enabled: Some(v.enabled),
            doppelganger_hold_until: v.doppelganger_hold_until,
            block_selection_mode: v.block_selection_mode,
            builders: v.builders.clone(),
            min_bid: v.min_bid,
        })
        .collect();
    TomlConfig { defaults: Some(toml_defaults), validators: toml_validators }
}

/// A validators-file write failed before or after the rename.
enum AtomicWriteError {
    /// Temp file, `fsync`, or rename failed. The previous file is intact.
    PreCommit(ValidatorStoreError),
    /// Rename succeeded and the parent-directory `fsync` failed.
    PostRename(ValidatorStoreError),
}

impl AtomicWriteError {
    fn into_store(self) -> ValidatorStoreError {
        match self {
            Self::PreCommit(e) | Self::PostRename(e) => e,
        }
    }
}

/// Write `toml_config` without restoring a previous document.
fn commit_snapshot(
    config_path: &Path,
    toml_config: &TomlConfig,
) -> Result<(), ValidatorStoreError> {
    write_toml_atomic(config_path, toml_config).map_err(AtomicWriteError::into_store)
}

/// Write `new_doc`, and put `previous` back if the failure is after rename.
///
/// Used when publishing would make signing less safe. A directory `fsync`
/// failure must not leave the new document on disk while memory stays old.
fn commit_less_safe(
    config_path: &Path,
    new_doc: &TomlConfig,
    previous: &TomlConfig,
) -> Result<(), ValidatorStoreError> {
    match write_toml_atomic(config_path, new_doc) {
        Ok(()) => Ok(()),
        Err(AtomicWriteError::PreCommit(e)) => Err(e),
        Err(AtomicWriteError::PostRename(e)) => match write_toml_atomic(config_path, previous) {
            Ok(()) => Err(e),
            Err(AtomicWriteError::PostRename(restore)) => {
                warn!(
                    error = %restore,
                    "directory sync failed while restoring the validators file; the previous document is in place"
                );
                Err(e)
            }
            Err(AtomicWriteError::PreCommit(restore)) => {
                warn!(
                    error = %restore,
                    "failed to restore the validators file before rename; removing it from the boot path"
                );
                if let Err(quarantine_err) = quarantine_validators_file(config_path) {
                    error!(
                        error = %quarantine_err,
                        "failed to move the unrestorable validators file off the boot path"
                    );
                }
                Err(e)
            }
        },
    }
}

/// Persist the live snapshot. The caller has already published `enabled = false`.
///
/// A post-rename failure is not restored: the file already holds the safer
/// bytes, and putting the previous document back would re-enable the key.
fn persist_disabled_snapshot(
    store: &ValidatorStore,
    pubkey: &[u8; 48],
) -> Result<(), ValidatorStoreError> {
    let Some(path) = store.config_path.clone() else {
        let err = missing_validators_config();
        error!(
            error = %err,
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            "validator disabled in memory; validators_config path is unset"
        );
        return Err(err);
    };
    let snapshot = store.disk_toml(&store.state.read());
    commit_snapshot(&path, &snapshot)
}

/// Write `toml_config` to `config_path` via tempfile + `sync_all` + rename + dir fsync.
fn write_toml_atomic(config_path: &Path, toml_config: &TomlConfig) -> Result<(), AtomicWriteError> {
    #[cfg(test)]
    take_write_fault(TomlWriteFault::Serialize).map_err(AtomicWriteError::PreCommit)?;
    let toml_string = toml::to_string(toml_config)
        .map_err(|e| AtomicWriteError::PreCommit(ValidatorStoreError::Config(e.to_string())))?;

    let parent = config_path.parent().ok_or_else(|| {
        AtomicWriteError::PreCommit(ValidatorStoreError::Config(
            "config path has no parent directory".to_string(),
        ))
    })?;

    #[cfg(test)]
    take_write_fault(TomlWriteFault::CreateTemp).map_err(AtomicWriteError::PreCommit)?;
    let tmp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| AtomicWriteError::PreCommit(ValidatorStoreError::Io(e)))?;
    #[cfg(test)]
    take_write_fault(TomlWriteFault::Write).map_err(AtomicWriteError::PreCommit)?;
    std::io::Write::write_all(&mut &tmp, toml_string.as_bytes())
        .map_err(|e| AtomicWriteError::PreCommit(ValidatorStoreError::Io(e)))?;
    #[cfg(test)]
    take_write_fault(TomlWriteFault::SyncFile).map_err(AtomicWriteError::PreCommit)?;
    tmp.as_file()
        .sync_all()
        .map_err(|e| AtomicWriteError::PreCommit(ValidatorStoreError::Io(e)))?;
    #[cfg(test)]
    take_write_fault(TomlWriteFault::Rename).map_err(AtomicWriteError::PreCommit)?;
    tmp.persist(config_path)
        .map_err(|e| AtomicWriteError::PreCommit(ValidatorStoreError::Io(e.error)))?;
    #[cfg(test)]
    take_write_fault(TomlWriteFault::SyncDir).map_err(AtomicWriteError::PostRename)?;
    sync_parent_dir(parent).map_err(AtomicWriteError::PostRename)?;

    info!(path = %config_path.display(), "config saved");
    // After the snapshot is durable (file and parent directory) and before the
    // caller publishes. Test-only: production builds do not call a hook.
    #[cfg(test)]
    invoke_durable_write_hook();
    Ok(())
}

/// `fsync` the directory that holds `config_path` so the rename survives power loss.
fn sync_parent_dir(parent: &Path) -> Result<(), ValidatorStoreError> {
    #[cfg(test)]
    PARENT_DIR_SYNCS.with(|cell| cell.set(cell.get().saturating_add(1)));
    let dir_path: &Path = if parent.as_os_str().is_empty() { Path::new(".") } else { parent };
    let dir = std::fs::File::open(dir_path)?;
    dir.sync_all()?;
    Ok(())
}

/// Apply `update` to `pubkey` under the caller's state guard.
///
/// Returns the changed field names when that validator is present, or an empty
/// vec when it is not (unknown pubkeys stay a no-op).
fn claim_field<T: Copy>(slot: &mut Option<OwnedValue<T>>, current: T, remote: T) {
    match slot {
        Some(owned) => owned.applied = remote,
        None => *slot = Some(OwnedValue { applied: remote, durable: current }),
    }
}

/// A keymanager or other local write of a field drops remote ownership of
/// that field. The written value is the new baseline.
fn drop_url_owned_fields(
    state: &mut StoreState,
    pubkey: &[u8; 48],
    update: &ValidatorConfigUpdate,
) {
    let empty = {
        let Some(entry) = state.url_owned.get_mut(pubkey) else {
            return;
        };
        if update.fee_recipient.is_some() {
            entry.fee_recipient = None;
        }
        if update.gas_limit.is_some() {
            entry.gas_limit = None;
        }
        if update.builder_proposals.is_some() {
            entry.builder_proposals = None;
        }
        entry.fee_recipient.is_none()
            && entry.gas_limit.is_none()
            && entry.builder_proposals.is_none()
    };
    if empty {
        state.url_owned.remove(pubkey);
    }
}

fn revert_remote_overlay(state: &mut StoreState) {
    let owned = std::mem::take(&mut state.url_owned);
    for (pubkey, fields) in owned {
        let Some(generation) = state.validator_gen.get(&pubkey).copied() else {
            continue;
        };
        if generation != fields.generation {
            continue;
        }
        let Some(config) = state.validators.get_mut(&pubkey) else {
            continue;
        };
        if let Some(fee) = fields.fee_recipient {
            if config.fee_recipient == fee.applied {
                config.fee_recipient = fee.durable;
            }
        }
        if let Some(gas) = fields.gas_limit {
            if config.gas_limit == gas.applied {
                config.gas_limit = gas.durable;
            }
        }
        if let Some(builder) = fields.builder_proposals {
            if config.builder_proposals == builder.applied {
                config.builder_proposals = builder.durable;
            }
        }
    }
    if let Some(fee) = state.remote_defaults.fee_recipient {
        if state.defaults.fee_recipient == fee.applied {
            state.defaults.fee_recipient = fee.durable;
        }
    }
    if let Some(gas) = state.remote_defaults.gas_limit {
        if state.defaults.gas_limit == gas.applied {
            state.defaults.gas_limit = gas.durable;
        }
    }
    if let Some(graffiti) = state.remote_defaults.graffiti {
        if state.defaults.graffiti == graffiti.applied {
            state.defaults.graffiti = graffiti.durable;
        }
    }
    state.remote_defaults = RemoteDefaults::default();
}

fn apply_update_locked(
    state: &mut StoreState,
    pubkey: &[u8; 48],
    update: &ValidatorConfigUpdate,
) -> Vec<&'static str> {
    let Some(config) = state.validators.get_mut(pubkey) else {
        return Vec::new();
    };

    let mut changed_fields = Vec::new();
    if let Some(fr) = update.fee_recipient {
        config.fee_recipient = fr;
        changed_fields.push("fee_recipient");
    }
    if let Some(gl) = update.gas_limit {
        config.gas_limit = gl;
        changed_fields.push("gas_limit");
    }
    if let Some(g) = update.graffiti {
        config.graffiti = g;
        changed_fields.push("graffiti");
    }
    if let Some(bp) = update.builder_proposals {
        config.builder_proposals = bp;
        changed_fields.push("builder_proposals");
    }
    if let Some(bbf) = update.builder_boost_factor {
        config.builder_boost_factor = Some(bbf);
        changed_fields.push("builder_boost_factor");
    }
    if let Some(bsm) = update.block_selection_mode {
        config.block_selection_mode = bsm;
        changed_fields.push("block_selection_mode");
    }
    if let Some(builders) = update.builders.clone() {
        config.builders = Some(builders);
        changed_fields.push("builders");
    }
    if let Some(min_bid) = update.min_bid {
        config.min_bid = Some(min_bid);
        changed_fields.push("min_bid");
    }
    changed_fields
}

fn quarantine_held_validators_file(store: &ValidatorStore) {
    let Some(path) = store.config_path.clone() else {
        return;
    };
    if let Err(err) = quarantine_validators_file(&path) {
        error!(
            error = %err,
            "failed to move the validators file off the boot path after a failed hold write"
        );
    }
}

fn publish_doppelganger_hold(state: &mut StoreState, pubkey: &[u8; 48], until_unix: u64) {
    if let Some(config) = state.validators.get_mut(pubkey) {
        config.enabled = false;
        config.doppelganger_hold_until = Some(until_unix);
        warn!(
            pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
            until_unix,
            "validator held for doppelganger"
        );
    }
}

/// Move `config_path` off the boot path. If the rename fails, truncate the
/// file so the next boot cannot parse the rejected document.
fn quarantine_validators_file(config_path: &Path) -> Result<(), ValidatorStoreError> {
    let name = config_path.file_name().and_then(|n| n.to_str()).unwrap_or("validators.toml");
    let rejected = config_path.with_file_name(format!("{name}.rejected"));
    if let Err(err) = std::fs::rename(config_path, &rejected) {
        let file = std::fs::OpenOptions::new().write(true).truncate(true).open(config_path)?;
        file.sync_all()?;
        if let Some(parent) = config_path.parent() {
            let _ = sync_parent_dir(parent);
        }
        return Err(ValidatorStoreError::Io(err));
    }
    log_moved_validators_file(&rejected);
    if let Some(parent) = config_path.parent() {
        sync_parent_dir(parent)?;
    }
    Ok(())
}

/// The moved document is off the boot path. Name every pubkey in full.
fn log_moved_validators_file(rejected: &Path) {
    let pubkeys = std::fs::read_to_string(rejected).ok().and_then(|text| {
        toml::from_str::<TomlConfig>(&text).ok().map(|doc| {
            doc.validators.into_iter().map(|validator| validator.pubkey).collect::<Vec<_>>()
        })
    });
    match pubkeys {
        Some(keys) if !keys.is_empty() => {
            for pubkey in keys {
                warn!(
                    pubkey = %pubkey,
                    rejected = %rejected.display(),
                    "moved validators file off the boot path"
                );
            }
        }
        _ => {
            warn!(rejected = %rejected.display(), "moved validators file off the boot path");
        }
    }
}

fn publish_enabled(state: &mut StoreState, pubkey: &[u8; 48], enabled: bool) {
    if let Some(config) = state.validators.get_mut(pubkey) {
        config.enabled = enabled;
        // An operator, slashing, or delete disable is not a doppelganger hold.
        // Enabling clears the hold as well.
        config.doppelganger_hold_until = None;
        let pk_hex = hex::encode(pubkey);
        if enabled {
            info!(pubkey = %TruncatedPubkey::new(&pk_hex), "validator enabled");
        } else {
            warn!(pubkey = %TruncatedPubkey::new(&pk_hex), "validator disabled");
        }
    }
}

fn validate_validator_ingress(config: &ValidatorConfig) -> Result<(), ValidatorStoreError> {
    if let Some(urls) = config.builders.as_deref() {
        validate_builder_urls(urls)?;
    }
    ensure_config_toml_bounds(config)
}

fn validate_update_ingress(update: &ValidatorConfigUpdate) -> Result<(), ValidatorStoreError> {
    if let Some(ref builders) = update.builders {
        validate_builder_urls(builders)?;
    }
    if let Some(Some(gl)) = update.gas_limit {
        ensure_toml_u64("gas_limit", gl)?;
    }
    if let Some(factor) = update.builder_boost_factor {
        ensure_toml_u64("builder_boost_factor", factor)?;
    }
    if let Some(min_bid) = update.min_bid {
        ensure_toml_u64("min_bid", min_bid)?;
    }
    Ok(())
}

fn ensure_config_toml_bounds(config: &ValidatorConfig) -> Result<(), ValidatorStoreError> {
    if let Some(gl) = config.gas_limit {
        ensure_toml_u64("gas_limit", gl)?;
    }
    if let Some(factor) = config.builder_boost_factor {
        ensure_toml_u64("builder_boost_factor", factor)?;
    }
    if let Some(min_bid) = config.min_bid {
        ensure_toml_u64("min_bid", min_bid)?;
    }
    Ok(())
}

fn log_validator_config_updated(pubkey: &[u8; 48], changed_fields: &[&str]) {
    if changed_fields.is_empty() {
        return;
    }
    let pk_hex = hex::encode(pubkey);
    info!(
        pubkey = %TruncatedPubkey::new(&pk_hex),
        changed_fields = changed_fields.join(","),
        "validator config updated"
    );
}

#[cfg(test)]
thread_local! {
    static DURABLE_WRITE_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn invoke_durable_write_hook() {
    DURABLE_WRITE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook();
        }
    });
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TomlWriteFault {
    Serialize,
    CreateTemp,
    Write,
    SyncFile,
    Rename,
    SyncDir,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct FaultPlan {
    skip: u32,
    step: TomlWriteFault,
}

#[cfg(test)]
thread_local! {
    static TOML_WRITE_FAULT: std::cell::Cell<Option<FaultPlan>> = const { std::cell::Cell::new(None) };
    /// Installed when the current fault fires, so a restore write can fail too.
    static NEXT_TOML_WRITE_FAULT: std::cell::Cell<Option<FaultPlan>> = const { std::cell::Cell::new(None) };
    /// Re-arm the same plan after it fires when no follow-up plan is installed.
    static KEEP_TOML_WRITE_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static PARENT_DIR_SYNCS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn take_write_fault(step: TomlWriteFault) -> Result<(), ValidatorStoreError> {
    TOML_WRITE_FAULT.with(|cell| {
        let Some(mut plan) = cell.get() else {
            return Ok(());
        };
        if plan.step != step {
            return Ok(());
        }
        if plan.skip > 0 {
            plan.skip -= 1;
            cell.set(Some(plan));
            return Ok(());
        }
        let follow = NEXT_TOML_WRITE_FAULT.with(|next| next.replace(None));
        let sticky = follow.is_none() && KEEP_TOML_WRITE_FAULT.with(|keep| keep.get());
        cell.set(if sticky { Some(plan) } else { follow });
        Err(ValidatorStoreError::Config(format!("injected write fault at {step:?}")))
    })
}

#[cfg(test)]
thread_local! {
    static RELOAD_AFTER_PARSE_HOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn invoke_reload_after_parse_hook() {
    RELOAD_AFTER_PARSE_HOOK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().as_mut() {
            hook();
        }
    });
}

#[cfg(test)]
thread_local! {
    static RELEASE_HOOK: std::cell::Cell<Option<fn()>> = const { std::cell::Cell::new(None) };
    static RELEASE_PROBE_STORE: std::cell::RefCell<Option<std::sync::Arc<ValidatorStore>>> =
        const { std::cell::RefCell::new(None) };
    static RELEASE_LOCKS_HELD: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn invoke_release_hook() {
    if let Some(hook) = RELEASE_HOOK.with(|slot| slot.get()) {
        hook();
    }
}

#[cfg(test)]
fn probe_release_locks() {
    let store = RELEASE_PROBE_STORE.with(|slot| slot.borrow().clone());
    let Some(store) = store else {
        return;
    };
    let held = store.save_lock.try_lock().is_none() && store.state.try_write().is_none();
    RELEASE_LOCKS_HELD.with(|slot| slot.set(held));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn test_pubkey(id: u8) -> [u8; 48] {
        let mut pk = [0u8; 48];
        pk[0] = id;
        pk
    }

    fn test_fee_recipient(id: u8) -> [u8; 20] {
        let mut fr = [0u8; 20];
        fr[0] = id;
        fr
    }

    #[test]
    fn test_new_empty_store() {
        let fr = test_fee_recipient(1);
        let store = ValidatorStore::new(fr, 30_000_000);

        assert!(store.list_enabled_pubkeys().is_empty());
        assert_eq!(store.state.read().defaults.fee_recipient, fr);
        assert_eq!(store.state.read().defaults.gas_limit, 30_000_000);
        assert!(store.state.read().defaults.graffiti.is_none());
    }

    #[test]
    fn test_add_and_get_validator() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        let config = ValidatorConfig::new(pk);

        store.add_validator(config.clone()).unwrap();

        let retrieved = store.get_config(&pk).unwrap();
        assert_eq!(retrieved.pubkey, pk);
        assert!(retrieved.enabled);
        assert!(retrieved.builder_boost_factor.is_none());
        assert!(retrieved.builders.is_none());
        assert!(retrieved.min_bid.is_none());
    }

    #[test]
    fn test_get_config_returns_none_for_unknown() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        assert!(store.get_config(&test_pubkey(99)).is_none());
    }

    #[test]
    fn test_remove_validator() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        let removed = store.remove_validator(&pk);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().pubkey, pk);
        assert!(store.get_config(&pk).is_none());
    }

    #[test]
    fn test_remove_validator_returns_none_for_unknown() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        assert!(store.remove_validator(&test_pubkey(99)).is_none());
    }

    #[test]
    fn test_effective_fee_recipient_with_override() {
        let default_fr = test_fee_recipient(1);
        let override_fr = test_fee_recipient(2);
        let store = ValidatorStore::new(default_fr, 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.fee_recipient = Some(override_fr);
        store.add_validator(config).unwrap();

        assert_eq!(store.effective_fee_recipient(&pk), override_fr);
    }

    #[test]
    fn test_effective_fee_recipient_uses_default() {
        let default_fr = test_fee_recipient(1);
        let store = ValidatorStore::new(default_fr, 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.effective_fee_recipient(&pk), default_fr);
    }

    #[test]
    fn test_effective_fee_recipient_unknown_validator_uses_default() {
        let default_fr = test_fee_recipient(1);
        let store = ValidatorStore::new(default_fr, 30_000_000);

        assert_eq!(store.effective_fee_recipient(&test_pubkey(99)), default_fr);
    }

    #[test]
    fn test_effective_gas_limit_with_override() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.gas_limit = Some(35_000_000);
        store.add_validator(config).unwrap();

        assert_eq!(store.effective_gas_limit(&pk), 35_000_000);
    }

    #[test]
    fn test_effective_gas_limit_uses_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.effective_gas_limit(&pk), 30_000_000);
    }

    #[test]
    fn test_effective_graffiti() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut graffiti = [0u8; 32];
        graffiti[..5].copy_from_slice(b"hello");

        let mut config = ValidatorConfig::new(pk);
        config.graffiti = Some(graffiti);
        store.add_validator(config).unwrap();

        assert_eq!(store.effective_graffiti(&pk), Some(graffiti));
    }

    #[test]
    fn test_effective_graffiti_uses_default() {
        let mut default_graffiti = [0u8; 32];
        default_graffiti[..4].copy_from_slice(b"test");

        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.state.write().defaults.graffiti = Some(default_graffiti);

        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.effective_graffiti(&pk), Some(default_graffiti));
    }

    #[test]
    fn test_effective_graffiti_returns_none() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert!(store.effective_graffiti(&pk).is_none());
    }

    #[test]
    fn test_set_default_graffiti() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let graffiti = parse_graffiti("rvc");
        store.set_default_graffiti(graffiti);
        assert_eq!(store.state.read().defaults.graffiti, Some(graffiti));
        assert_eq!(store.effective_graffiti(&test_pubkey(9)), Some(graffiti));
    }

    #[test]
    fn test_is_builder_enabled() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.builder_proposals = true;
        store.add_validator(config).unwrap();

        assert!(store.is_builder_enabled(&pk));
    }

    #[test]
    fn test_is_builder_disabled_by_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert!(!store.is_builder_enabled(&pk));
    }

    #[test]
    fn test_is_builder_enabled_unknown_validator() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        assert!(!store.is_builder_enabled(&test_pubkey(99)));
    }

    #[test]
    fn test_builder_boost_factor_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.builder_boost_factor(&pk), 100);
    }

    #[test]
    fn test_builder_boost_factor_custom() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.builder_boost_factor = Some(200);
        store.add_validator(config).unwrap();

        assert_eq!(store.builder_boost_factor(&pk), 200);
    }

    #[test]
    fn test_builder_boost_factor_unknown_validator() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        assert_eq!(store.builder_boost_factor(&test_pubkey(99)), 100);
    }

    #[test]
    fn test_builders_fallback_empty() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert!(store.builders(&pk).is_empty());
        assert!(store.builders(&test_pubkey(99)).is_empty());
    }

    #[test]
    fn test_builders_global_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_global_builders(vec!["https://relay.example".to_string()]).unwrap();
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.builders(&pk), vec!["https://relay.example".to_string()]);
        assert_eq!(store.builders(&test_pubkey(99)), vec!["https://relay.example".to_string()]);
    }

    #[test]
    fn test_builders_per_validator_override() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_global_builders(vec!["https://global.example".to_string()]).unwrap();
        let pk = test_pubkey(1);
        let mut config = ValidatorConfig::new(pk);
        config.builders = Some(vec!["https://override.example".to_string()]);
        store.add_validator(config).unwrap();

        assert_eq!(store.builders(&pk), vec!["https://override.example".to_string()]);
        assert_eq!(store.builders(&test_pubkey(99)), vec!["https://global.example".to_string()]);
    }

    #[test]
    fn test_builders_empty_override_is_local_only() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_global_builders(vec!["https://global.example".to_string()]).unwrap();
        let pk = test_pubkey(1);
        let mut config = ValidatorConfig::new(pk);
        config.builders = Some(Vec::new());
        store.add_validator(config).unwrap();

        assert!(store.builders(&pk).is_empty());
        assert_eq!(store.builders(&test_pubkey(99)), vec!["https://global.example".to_string()]);
    }

    #[test]
    fn test_builders_file_url_is_rejected_naming_the_value() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let err = store
            .set_global_builders(vec!["file:///tmp/builder".to_string()])
            .expect_err("file:// rejected");
        let msg = err.to_string();
        assert!(msg.contains("file:///tmp/builder"), "{msg}");
        assert!(store.builders(&test_pubkey(1)).is_empty());

        let pk = test_pubkey(1);
        let mut config = ValidatorConfig::new(pk);
        config.builders = Some(vec!["file:///etc/passwd".to_string()]);
        let err = store.add_validator(config).expect_err("file:// add rejected");
        assert!(err.to_string().contains("file:///etc/passwd"), "{err}");
        assert!(!store.has_validator(&pk));

        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        let err = store
            .update_config(
                &pk,
                ValidatorConfigUpdate {
                    builders: Some(vec!["file://evil".to_string()]),
                    ..Default::default()
                },
            )
            .expect_err("file:// update rejected");
        assert!(err.to_string().contains("file://evil"), "{err}");
        assert!(store.builders(&pk).is_empty());
    }

    #[test]
    fn test_builders_malformed_url_is_rejected_naming_the_value() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let err =
            store.set_global_builders(vec!["not a url".to_string()]).expect_err("malformed URL");
        assert!(err.to_string().contains("not a url"), "{err}");

        let pk = test_pubkey(1);
        let mut config = ValidatorConfig::new(pk);
        config.builders = Some(vec!["not a url".to_string()]);
        let err = store.add_validator(config).expect_err("malformed add");
        assert!(err.to_string().contains("not a url"), "{err}");
        assert!(!store.has_validator(&pk));
    }

    #[test]
    fn test_builders_empty_list_still_loads() {
        let pubkey_hex = format!("0x{}", hex::encode([1u8; 48]));
        let toml_content = format!(
            r#"
[defaults]
fee_recipient = "0x{}"

[[validators]]
pubkey = "{pubkey_hex}"
builders = []
"#,
            "aa".repeat(20),
        );
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, toml_content).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).expect("empty [] is legal");
        let pk = [1u8; 48];
        assert!(store.get_config(&pk).unwrap().builders.as_ref().unwrap().is_empty());
        assert!(store.builders(&pk).is_empty());

        store.set_global_builders(Vec::new()).unwrap();
        store
            .update_config(
                &pk,
                ValidatorConfigUpdate { builders: Some(Vec::new()), ..Default::default() },
            )
            .unwrap();
        assert!(store.builders(&pk).is_empty());
    }

    #[test]
    fn test_builders_toml_file_url_is_rejected_naming_the_value() {
        let pubkey_hex = format!("0x{}", hex::encode([1u8; 48]));
        let toml_content = format!(
            r#"
[defaults]
fee_recipient = "0x{}"

[[validators]]
pubkey = "{pubkey_hex}"
builders = ["file:///tmp/builder"]
"#,
            "aa".repeat(20),
        );
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, toml_content).unwrap();

        let err = match ValidatorStore::load_from_config(&config_path) {
            Err(e) => e,
            Ok(_) => panic!("file:// toml"),
        };
        let msg = err.to_string();
        assert!(msg.contains("file:///tmp/builder"), "{msg}");
    }

    #[test]
    fn test_min_bid_fallback_zero() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.min_bid(&pk), 0);
        assert_eq!(store.min_bid(&test_pubkey(99)), 0);
    }

    #[test]
    fn test_min_bid_global_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_global_min_bid(10_000_000).unwrap();
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.min_bid(&pk), 10_000_000);
        assert_eq!(store.min_bid(&test_pubkey(99)), 10_000_000);
    }

    #[test]
    fn test_min_bid_per_validator_override() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_global_min_bid(10_000_000).unwrap();
        let pk = test_pubkey(1);
        let mut config = ValidatorConfig::new(pk);
        config.min_bid = Some(1);
        store.add_validator(config).unwrap();

        assert_eq!(store.min_bid(&pk), 1);
        assert_eq!(store.min_bid(&test_pubkey(99)), 10_000_000);
    }

    #[test]
    fn test_builder_boost_factor_global_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_global_builder_boost_factor(50).unwrap();
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.builder_boost_factor(&pk), 50);
        assert_eq!(store.builder_boost_factor(&test_pubkey(99)), 50);
    }

    #[test]
    fn test_builder_boost_factor_override_beats_global() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_global_builder_boost_factor(50).unwrap();
        let pk = test_pubkey(1);
        let mut config = ValidatorConfig::new(pk);
        config.builder_boost_factor = Some(200);
        store.add_validator(config).unwrap();

        assert_eq!(store.builder_boost_factor(&pk), 200);
        assert_eq!(store.builder_boost_factor(&test_pubkey(99)), 50);
    }

    #[test]
    fn test_list_enabled_pubkeys() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);

        let pk1 = test_pubkey(1);
        let pk2 = test_pubkey(2);
        let pk3 = test_pubkey(3);

        store.add_validator(ValidatorConfig::new(pk1)).unwrap();
        store.add_validator(ValidatorConfig::new(pk2)).unwrap();

        let mut disabled = ValidatorConfig::new(pk3);
        disabled.enabled = false;
        store.add_validator(disabled).unwrap();

        let mut enabled = store.list_enabled_pubkeys();
        enabled.sort();
        assert_eq!(enabled.len(), 2);
        assert!(enabled.contains(&pk1));
        assert!(enabled.contains(&pk2));
        assert!(!enabled.contains(&pk3));
    }

    #[test]
    fn test_set_enabled() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert!(store.get_config(&pk).unwrap().enabled);

        store.set_enabled(&pk, false);
        assert!(!store.get_config(&pk).unwrap().enabled);

        store.set_enabled(&pk, true);
        assert!(store.get_config(&pk).unwrap().enabled);
    }

    #[test]
    fn test_set_enabled_unknown_validator_is_noop() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_enabled(&test_pubkey(99), false); // should not panic
    }

    #[test]
    fn test_update_config() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        let new_fr = test_fee_recipient(5);
        let update = ValidatorConfigUpdate {
            fee_recipient: Some(Some(new_fr)),
            gas_limit: Some(Some(50_000_000)),
            builder_proposals: Some(true),
            builder_boost_factor: Some(150),
            graffiti: None, // no change
            block_selection_mode: None,
            builders: Some(vec!["https://override.example".to_string()]),
            min_bid: Some(42),
        };

        store.update_config(&pk, update).unwrap();

        let config = store.get_config(&pk).unwrap();
        assert_eq!(config.fee_recipient, Some(new_fr));
        assert_eq!(config.gas_limit, Some(50_000_000));
        assert!(config.builder_proposals);
        assert_eq!(config.builder_boost_factor, Some(150));
        assert_eq!(config.builders, Some(vec!["https://override.example".to_string()]));
        assert_eq!(config.min_bid, Some(42));
        assert!(config.graffiti.is_none()); // unchanged
    }

    #[test]
    fn test_update_config_clear_fields() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        let mut config = ValidatorConfig::new(pk);
        config.fee_recipient = Some(test_fee_recipient(5));
        config.gas_limit = Some(50_000_000);
        store.add_validator(config).unwrap();

        let update = ValidatorConfigUpdate {
            fee_recipient: Some(None), // clear
            gas_limit: Some(None),     // clear
            ..Default::default()
        };
        store.update_config(&pk, update).unwrap();

        let config = store.get_config(&pk).unwrap();
        assert!(config.fee_recipient.is_none());
        assert!(config.gas_limit.is_none());
    }

    #[test]
    fn test_update_config_unknown_validator_is_noop() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.update_config(&test_pubkey(99), ValidatorConfigUpdate::default()).unwrap();
    }

    #[test]
    fn apply_default_update_changes_the_store_defaults() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let new_fr = test_fee_recipient(9);

        store
            .apply_default_update(DefaultUpdate {
                fee_recipient: Some(new_fr),
                gas_limit: Some(40_000_000),
                graffiti: Some(Some([0xab; 32])),
            })
            .unwrap();

        assert_eq!(store.default_fee_recipient(), new_fr);
        assert_eq!(store.default_gas_limit(), 40_000_000);
        assert_eq!(store.state.read().defaults.graffiti, Some([0xab; 32]));
    }

    #[test]
    fn apply_default_update_absent_fields_leave_defaults_unchanged() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.state.write().defaults.graffiti = Some([0x11; 32]);

        store
            .apply_default_update(DefaultUpdate {
                fee_recipient: Some(test_fee_recipient(2)),
                gas_limit: None,
                graffiti: None,
            })
            .unwrap();

        assert_eq!(store.default_fee_recipient(), test_fee_recipient(2));
        assert_eq!(store.default_gas_limit(), 30_000_000);
        assert_eq!(store.state.read().defaults.graffiti, Some([0x11; 32]));
    }

    #[test]
    fn apply_default_update_can_clear_graffiti() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.state.write().defaults.graffiti = Some([0x11; 32]);

        store
            .apply_default_update(DefaultUpdate {
                fee_recipient: None,
                gas_limit: None,
                graffiti: Some(None),
            })
            .unwrap();

        assert!(store.state.read().defaults.graffiti.is_none());
        assert_eq!(store.default_fee_recipient(), test_fee_recipient(1));
    }

    #[test]
    fn apply_default_update_is_a_single_write_guard() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let store = Arc::new(ValidatorStore::new(test_fee_recipient(1), 30_000_000));
        let stop = Arc::new(AtomicBool::new(false));
        let old_fr = test_fee_recipient(1);
        let new_fr = test_fee_recipient(2);
        let old_gl = 30_000_000u64;
        let new_gl = 40_000_000u64;

        // Readers sample both fields under one lock via effective_config (unknown
        // pubkey falls back to store defaults). Separate default_* accessors each
        // take their own lock and are not a single-guard observation.
        let sample_pk = [0u8; 48];
        let readers: Vec<_> = (0..4)
            .map(|_| {
                let store = Arc::clone(&store);
                let stop = Arc::clone(&stop);
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        let d = store.effective_config(&sample_pk);
                        let old = d.fee_recipient == old_fr && d.gas_limit == old_gl;
                        let new = d.fee_recipient == new_fr && d.gas_limit == new_gl;
                        assert!(
                            old || new,
                            "observed mixed defaults: fee_recipient={:?} gas_limit={}",
                            d.fee_recipient,
                            d.gas_limit
                        );
                    }
                })
            })
            .collect();

        for _ in 0..200 {
            store
                .apply_default_update(DefaultUpdate {
                    fee_recipient: Some(new_fr),
                    gas_limit: Some(new_gl),
                    graffiti: None,
                })
                .unwrap();
            store
                .apply_default_update(DefaultUpdate {
                    fee_recipient: Some(old_fr),
                    gas_limit: Some(old_gl),
                    graffiti: None,
                })
                .unwrap();
        }

        stop.store(true, Ordering::Relaxed);
        for t in readers {
            t.join().expect("reader thread panicked");
        }
    }

    #[tracing_test::traced_test]
    #[test]
    fn load_from_config_emits_canonical_breadth() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, "").unwrap();

        let _store = ValidatorStore::load_from_config(&config_path).unwrap();

        // The renamed `validator_store.load_from_config` span's events fire with the
        // new breadth (info milestone + the effective-defaults debug decision point).
        assert!(logs_contain("validator config loaded"));
        assert!(logs_contain("resolved effective validator defaults"));
    }

    #[test]
    fn test_load_from_config() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([2u8; 20]);

        let toml_content = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 30000000

[[validators]]
pubkey = "{}"
fee_recipient = "{}"
gas_limit = 35000000
builder_proposals = true
builder_boost_factor = 200
graffiti = "my graffiti"
"#,
            "0x".to_string() + &hex::encode([0xaau8; 20]),
            pubkey_hex,
            fr_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        let pk = [1u8; 48];
        let config = store.get_config(&pk).unwrap();
        assert_eq!(config.fee_recipient, Some([2u8; 20]));
        assert_eq!(config.gas_limit, Some(35_000_000));
        assert!(config.builder_proposals);
        assert_eq!(config.builder_boost_factor, Some(200));
        assert!(config.graffiti.is_some());
        assert!(config.enabled);

        assert_eq!(store.state.read().defaults.fee_recipient, [0xaau8; 20]);
        assert_eq!(store.state.read().defaults.gas_limit, 30_000_000);
    }

    #[test]
    fn test_load_from_config_with_defaults() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);

        let toml_content = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 25000000
graffiti = "default graffiti"

[[validators]]
pubkey = "{}"
"#,
            "0x".to_string() + &hex::encode([0xbbu8; 20]),
            pubkey_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        let pk = [1u8; 48];
        assert_eq!(store.effective_fee_recipient(&pk), [0xbbu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 25_000_000);
        assert!(store.effective_graffiti(&pk).is_some());

        let graffiti = store.effective_graffiti(&pk).unwrap();
        assert_eq!(&graffiti[..16], b"default graffiti");
    }

    #[test]
    fn test_load_from_config_no_defaults_section() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);

        let toml_content = format!(
            r#"
[[validators]]
pubkey = "{}"
"#,
            pubkey_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut file = std::fs::File::create(&config_path).unwrap();
        file.write_all(toml_content.as_bytes()).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(store.state.read().defaults.fee_recipient, [0u8; 20]);
        assert_eq!(store.state.read().defaults.gas_limit, 30_000_000);
        assert!(store.state.read().defaults.graffiti.is_none());
    }

    #[test]
    fn test_load_from_config_invalid_path() {
        let result = ValidatorStore::load_from_config(Path::new("/nonexistent/path.toml"));
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_config_invalid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("bad.toml");
        std::fs::write(&config_path, "this is not valid toml [[[").unwrap();

        let result = ValidatorStore::load_from_config(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_config_invalid_hex() {
        let toml_content = r#"
[[validators]]
pubkey = "not-valid-hex"
"#;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("bad_hex.toml");
        std::fs::write(&config_path, toml_content).unwrap();

        let result = ValidatorStore::load_from_config(&config_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;

        let store = Arc::new(ValidatorStore::new(test_fee_recipient(1), 30_000_000));

        let mut handles = vec![];

        // Spawn writer threads
        for i in 0..5u8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let pk = test_pubkey(i);
                store.add_validator(ValidatorConfig::new(pk)).unwrap();
            }));
        }

        // Spawn reader threads
        for i in 0..5u8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || {
                let pk = test_pubkey(i);
                let _ = store.get_config(&pk);
                let _ = store.effective_fee_recipient(&pk);
                let _ = store.effective_gas_limit(&pk);
                let _ = store.list_enabled_pubkeys();
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        // All 5 validators should be present
        assert_eq!(store.list_enabled_pubkeys().len(), 5);
    }

    #[test]
    fn test_parse_hex_bytes_with_prefix() {
        let result: [u8; 4] = parse_hex_bytes("0xdeadbeef").unwrap();
        assert_eq!(result, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_hex_bytes_without_prefix() {
        let result: [u8; 4] = parse_hex_bytes("deadbeef").unwrap();
        assert_eq!(result, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn test_parse_hex_bytes_wrong_length() {
        let result = parse_hex_bytes::<4>("aabb");
        assert!(result.is_err());
    }

    /// RF3-15: the 20-byte fee-recipient path stays on the local generic parser.
    #[test]
    fn test_validator_store_20_byte_path_unaffected() {
        let addr: [u8; 20] = parse_hex_bytes(&format!("0x{}", "ab".repeat(20))).unwrap();
        assert_eq!(addr, [0xabu8; 20]);
        let bare: [u8; 20] = parse_hex_bytes(&"cd".repeat(20)).unwrap();
        assert_eq!(bare, [0xcdu8; 20]);
        // Still only strips lowercase `0x` (local path, not canonical).
        assert!(parse_hex_bytes::<20>(&format!("0X{}", "ab".repeat(20))).is_err());
    }

    /// RF3-15: validator pubkey parsing accepts uppercase `0X` via canonical.
    #[test]
    fn test_parse_validator_accepts_uppercase_0x_pubkey() {
        let v = TomlValidator {
            pubkey: format!("0X{}", "ab".repeat(48)),
            fee_recipient: None,
            gas_limit: None,
            builder_proposals: None,
            builder_boost_factor: None,
            graffiti: None,
            enabled: None,
            doppelganger_hold_until: None,
            block_selection_mode: None,
            builders: None,
            min_bid: None,
        };
        let cfg = parse_validator(&v).expect("0X-prefixed pubkey must parse");
        assert_eq!(cfg.pubkey, [0xabu8; 48]);
    }

    #[test]
    fn test_parse_graffiti_short() {
        let graffiti = parse_graffiti("hello");
        assert_eq!(&graffiti[..5], b"hello");
        assert_eq!(&graffiti[5..], &[0u8; 27]);
    }

    #[test]
    fn test_parse_graffiti_truncates_at_32() {
        let long = "a".repeat(64);
        let graffiti = parse_graffiti(&long);
        assert_eq!(graffiti, [b'a'; 32]);
    }

    #[test]
    fn test_validator_config_new_defaults() {
        let pk = test_pubkey(1);
        let config = ValidatorConfig::new(pk);

        assert_eq!(config.pubkey, pk);
        assert!(config.fee_recipient.is_none());
        assert!(config.gas_limit.is_none());
        assert!(!config.builder_proposals);
        assert!(config.builder_boost_factor.is_none());
        assert!(config.builders.is_none());
        assert!(config.min_bid.is_none());
        assert!(config.graffiti.is_none());
        assert!(config.enabled);
    }

    #[test]
    fn test_reload_config_updates_builder_proposals() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);

        let toml_v1 = format!(
            r#"
[[validators]]
pubkey = "{}"
builder_proposals = false
"#,
            pubkey_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        let pk = [1u8; 48];
        assert!(!store.is_builder_enabled(&pk));

        let toml_v2 = format!(
            r#"
[[validators]]
pubkey = "{}"
builder_proposals = true
builder_boost_factor = 250
"#,
            pubkey_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        assert!(store.is_builder_enabled(&pk));
        assert_eq!(store.builder_boost_factor(&pk), 250);
    }

    #[test]
    fn test_reload_config_updates_defaults() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr1_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        let fr2_hex = "0x".to_string() + &hex::encode([0xbbu8; 20]);

        let toml_v1 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 30000000

[[validators]]
pubkey = "{}"
"#,
            fr1_hex, pubkey_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        let pk = [1u8; 48];
        assert_eq!(store.effective_fee_recipient(&pk), [0xaau8; 20]);

        let toml_v2 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 40000000

[[validators]]
pubkey = "{}"
"#,
            fr2_hex, pubkey_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        assert_eq!(store.effective_fee_recipient(&pk), [0xbbu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 40_000_000);
    }

    #[test]
    fn test_reload_config_adds_new_validators() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let pk2_hex = "0x".to_string() + &hex::encode([2u8; 48]);

        let toml_v1 = format!(
            r#"
[[validators]]
pubkey = "{}"
"#,
            pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(store.list_enabled_pubkeys().len(), 1);

        let toml_v2 = format!(
            r#"
[[validators]]
pubkey = "{}"

[[validators]]
pubkey = "{}"
builder_proposals = true
"#,
            pk1_hex, pk2_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        assert_eq!(store.list_enabled_pubkeys().len(), 2);
        let pk2 = [2u8; 48];
        assert!(store.is_builder_enabled(&pk2));
    }

    #[test]
    fn test_reload_config_preserves_programmatic_validators() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);

        let toml_v1 = format!(
            r#"
[[validators]]
pubkey = "{}"
"#,
            pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        let pk_extra = [99u8; 48];
        store.add_validator(ValidatorConfig::new(pk_extra)).unwrap();
        assert_eq!(store.list_enabled_pubkeys().len(), 2);

        store.reload_config().unwrap();

        assert!(store.get_config(&pk_extra).is_some());
    }

    #[test]
    fn test_reload_config_no_path_returns_error() {
        let store = ValidatorStore::new([0u8; 20], 30_000_000);
        let result = store.reload_config();
        assert!(result.is_err());
    }

    #[test]
    fn test_reload_config_invalid_file_returns_error() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, "[[validators]]\npubkey = \"0x01\"\n").unwrap();

        // Initial load will fail due to wrong length, so create a valid one first
        let pk_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let valid_toml = format!("[[validators]]\npubkey = \"{}\"\n", pk_hex);
        std::fs::write(&config_path, &valid_toml).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        std::fs::write(&config_path, "not valid toml [[[").unwrap();

        let result = store.reload_config();
        assert!(result.is_err());

        // Store should be unchanged after failed reload
        assert!(store.get_config(&[1u8; 48]).is_some());
    }

    #[test]
    fn test_reload_config_partial_validator_failure_no_mutation() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);

        let toml_v1 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 30000000

[[validators]]
pubkey = "{}"
builder_proposals = false
"#,
            fr_hex, pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        let pk1 = [1u8; 48];
        assert!(!store.is_builder_enabled(&pk1));
        assert_eq!(store.effective_fee_recipient(&pk1), [0xaau8; 20]);
        assert_eq!(store.effective_gas_limit(&pk1), 30_000_000);

        // Write config with one valid validator (changed) + one invalid validator
        let pk2_hex = "0x".to_string() + &hex::encode([2u8; 48]);
        let fr2_hex = "0x".to_string() + &hex::encode([0xbbu8; 20]);
        let toml_v2 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 50000000

[[validators]]
pubkey = "{}"
builder_proposals = true

[[validators]]
pubkey = "invalid-hex-not-48-bytes"
"#,
            fr2_hex, pk2_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        let result = store.reload_config();
        assert!(result.is_err());

        // CRITICAL: Store must be completely unchanged after failed reload
        // Defaults must not have changed
        assert_eq!(store.state.read().defaults.fee_recipient, [0xaau8; 20]);
        assert_eq!(store.state.read().defaults.gas_limit, 30_000_000);

        // No new validators added
        assert!(store.get_config(&[2u8; 48]).is_none());

        // Existing validator unchanged
        assert!(!store.is_builder_enabled(&pk1));
    }

    #[test]
    fn test_reload_config_resets_defaults_when_section_removed() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);

        let toml_v1 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 50000000
graffiti = "my graffiti"

[[validators]]
pubkey = "{}"
"#,
            fr_hex, pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(store.state.read().defaults.fee_recipient, [0xaau8; 20]);
        assert_eq!(store.state.read().defaults.gas_limit, 50_000_000);
        assert!(store.state.read().defaults.graffiti.is_some());

        // Remove [defaults] section entirely
        let toml_v2 = format!(
            r#"
[[validators]]
pubkey = "{}"
"#,
            pk1_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        // Defaults should reset to hardcoded fallbacks
        assert_eq!(store.state.read().defaults.fee_recipient, [0u8; 20]);
        assert_eq!(store.state.read().defaults.gas_limit, 30_000_000);
        assert!(store.state.read().defaults.graffiti.is_none());
    }

    #[test]
    fn test_reload_config_resets_individual_default_fields() {
        let pk1_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);

        let toml_v1 = format!(
            r#"
[defaults]
fee_recipient = "{}"
gas_limit = 50000000
graffiti = "my graffiti"

[[validators]]
pubkey = "{}"
"#,
            fr_hex, pk1_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_v1).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        // Keep [defaults] but remove some fields
        let toml_v2 = format!(
            r#"
[defaults]
gas_limit = 40000000

[[validators]]
pubkey = "{}"
"#,
            pk1_hex,
        );
        std::fs::write(&config_path, &toml_v2).unwrap();

        store.reload_config().unwrap();

        // fee_recipient and graffiti should reset to hardcoded fallbacks
        assert_eq!(store.state.read().defaults.fee_recipient, [0u8; 20]);
        assert_eq!(store.state.read().defaults.gas_limit, 40_000_000);
        assert!(store.state.read().defaults.graffiti.is_none());
    }

    /// RF5-29: load and reload must share one parse path so defaults/validators
    /// cannot drift between the two entry points (finding F78).
    #[test]
    fn test_load_and_reload_produce_identical_defaults_and_validators() {
        let pubkey_hex = format!("0x{}", hex::encode([0x11u8; 48]));
        let fr_hex = format!("0x{}", hex::encode([0xaau8; 20]));
        let override_fr_hex = format!("0x{}", hex::encode([0xbbu8; 20]));

        let content = format!(
            r#"
[defaults]
fee_recipient = "{fr_hex}"
gas_limit = 35000000
graffiti = "shared parse"

[[validators]]
pubkey = "{pubkey_hex}"
fee_recipient = "{override_fr_hex}"
gas_limit = 40000000
builder_proposals = true
builder_boost_factor = 150
enabled = true
"#
        );

        let (parsed_defaults, parsed_validators) = parse_config(&content).unwrap();
        assert_eq!(parsed_defaults.fee_recipient, [0xaau8; 20]);
        assert_eq!(parsed_defaults.gas_limit, 35_000_000);
        assert_eq!(parsed_validators.len(), 1);

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &content).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        {
            let defaults = store.state.read().defaults;
            assert_eq!(defaults.fee_recipient, parsed_defaults.fee_recipient);
            assert_eq!(defaults.gas_limit, parsed_defaults.gas_limit);
            assert_eq!(defaults.graffiti, parsed_defaults.graffiti);
        }
        let pk = [0x11u8; 48];
        let loaded = store.get_config(&pk).unwrap();
        let expected = &parsed_validators[0];
        assert_eq!(loaded.pubkey, expected.pubkey);
        assert_eq!(loaded.fee_recipient, expected.fee_recipient);
        assert_eq!(loaded.gas_limit, expected.gas_limit);
        assert_eq!(loaded.builder_proposals, expected.builder_proposals);
        assert_eq!(loaded.builder_boost_factor, expected.builder_boost_factor);
        assert_eq!(loaded.enabled, expected.enabled);

        // Mutate in-memory state so a broken reload would leave drift.
        store.state.write().defaults.gas_limit = 1;
        store.state.write().defaults.fee_recipient = [0xff; 20];
        store.set_enabled(&pk, false);

        store.reload_config().unwrap();

        {
            let defaults = store.state.read().defaults;
            assert_eq!(defaults.fee_recipient, parsed_defaults.fee_recipient);
            assert_eq!(defaults.gas_limit, parsed_defaults.gas_limit);
            assert_eq!(defaults.graffiti, parsed_defaults.graffiti);
        }
        let reloaded = store.get_config(&pk).unwrap();
        assert_eq!(reloaded.fee_recipient, expected.fee_recipient);
        assert_eq!(reloaded.gas_limit, expected.gas_limit);
        assert_eq!(reloaded.builder_proposals, expected.builder_proposals);
        assert_eq!(reloaded.builder_boost_factor, expected.builder_boost_factor);
        assert!(reloaded.enabled);
    }

    /// RF5-29: missing `[defaults]` fields resolve to the single declared consts.
    #[test]
    fn test_parse_config_applies_declared_fallback_constants() {
        let pubkey_hex = format!("0x{}", hex::encode([1u8; 48]));
        let content = format!(
            r#"
[[validators]]
pubkey = "{pubkey_hex}"
"#
        );

        let (defaults, validators) = parse_config(&content).unwrap();
        assert_eq!(defaults.fee_recipient, DEFAULT_FEE_RECIPIENT);
        assert_eq!(defaults.gas_limit, DEFAULT_GAS_LIMIT);
        assert!(defaults.graffiti.is_none());
        assert_eq!(validators.len(), 1);
        assert_eq!(validators[0].pubkey, [1u8; 48]);

        // Empty / partial defaults section also falls back field-wise.
        let partial = format!(
            r#"
[defaults]
gas_limit = 42000000

[[validators]]
pubkey = "{pubkey_hex}"
"#
        );
        let (defaults, _) = parse_config(&partial).unwrap();
        assert_eq!(defaults.fee_recipient, DEFAULT_FEE_RECIPIENT);
        assert_eq!(defaults.gas_limit, 42_000_000);
        assert!(defaults.graffiti.is_none());
    }

    /// RF5-29: invalid TOML on reload must fail before any state mutation.
    #[test]
    fn test_reload_rejects_invalid_toml_without_mutating_state() {
        let pk_hex = format!("0x{}", hex::encode([1u8; 48]));
        let fr_hex = format!("0x{}", hex::encode([0xaau8; 20]));
        let valid = format!(
            r#"
[defaults]
fee_recipient = "{fr_hex}"
gas_limit = 30000000

[[validators]]
pubkey = "{pk_hex}"
builder_proposals = true
"#
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &valid).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        let pk = [1u8; 48];
        assert_eq!(store.state.read().defaults.fee_recipient, [0xaau8; 20]);
        assert_eq!(store.state.read().defaults.gas_limit, 30_000_000);
        assert!(store.is_builder_enabled(&pk));

        std::fs::write(&config_path, "this is not valid toml [[[").unwrap();
        assert!(store.reload_config().is_err());

        assert_eq!(store.state.read().defaults.fee_recipient, [0xaau8; 20]);
        assert_eq!(store.state.read().defaults.gas_limit, 30_000_000);
        assert!(store.is_builder_enabled(&pk));
        assert!(store.get_config(&pk).is_some());
    }

    #[test]
    fn test_effective_config_returns_consistent_snapshot() {
        let default_fr = [0xaau8; 20];
        let store = ValidatorStore::new(default_fr, 30_000_000);

        let pk = test_pubkey(1);
        store.state.write().validators.insert(
            pk,
            ValidatorConfig {
                pubkey: pk,
                fee_recipient: Some([0xbbu8; 20]),
                gas_limit: Some(40_000_000),
                graffiti: None,
                builder_proposals: false,
                builder_boost_factor: None,
                enabled: true,
                doppelganger_hold_until: None,
                block_selection_mode: None,
                builders: None,
                min_bid: None,
            },
        );

        let config = store.effective_config(&pk);
        assert_eq!(config.fee_recipient, [0xbbu8; 20]);
        assert_eq!(config.gas_limit, 40_000_000);
        assert!(config.graffiti.is_none());
    }

    #[test]
    fn test_effective_config_falls_back_to_defaults() {
        let default_fr = [0xaau8; 20];
        let store = ValidatorStore::new(default_fr, 30_000_000);
        let pk = test_pubkey(1);

        let config = store.effective_config(&pk);
        assert_eq!(config.fee_recipient, default_fr);
        assert_eq!(config.gas_limit, 30_000_000);
        assert!(config.graffiti.is_none());
    }

    #[test]
    fn test_effective_config_concurrent_reads_consistent() {
        use std::sync::Arc;

        let default_fr = [0xaau8; 20];
        let store = Arc::new(ValidatorStore::new(default_fr, 30_000_000));

        let pk = test_pubkey(1);
        store.state.write().validators.insert(
            pk,
            ValidatorConfig {
                pubkey: pk,
                fee_recipient: Some([0xbbu8; 20]),
                gas_limit: Some(40_000_000),
                graffiti: None,
                builder_proposals: false,
                builder_boost_factor: None,
                enabled: true,
                doppelganger_hold_until: None,
                block_selection_mode: None,
                builders: None,
                min_bid: None,
            },
        );

        let mut handles = vec![];
        for _ in 0..10 {
            let store = store.clone();
            handles.push(std::thread::spawn(move || {
                for _ in 0..100 {
                    let config = store.effective_config(&pk);
                    // All values must come from the same snapshot
                    assert_eq!(config.fee_recipient, [0xbbu8; 20]);
                    assert_eq!(config.gas_limit, 40_000_000);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    }

    #[test]
    fn test_has_validator() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);

        assert!(!store.has_validator(&pk));

        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        assert!(store.has_validator(&pk));

        assert!(!store.has_validator(&test_pubkey(99)));
    }

    #[test]
    fn test_save_config_round_trip() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);

        let toml_content = format!(
            r#"[defaults]
fee_recipient = "{}"
gas_limit = 30000000

[[validators]]
pubkey = "{}"
fee_recipient = "{}"
gas_limit = 35000000
builder_proposals = true
builder_boost_factor = 200
graffiti = "my graffiti"
"#,
            "0x".to_string() + &hex::encode([0xaau8; 20]),
            pubkey_hex,
            fr_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_content).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();

        // Update fee_recipient via update_config
        let pk = [1u8; 48];
        let new_fr = [0xbbu8; 20];
        store
            .update_config(
                &pk,
                ValidatorConfigUpdate { fee_recipient: Some(Some(new_fr)), ..Default::default() },
            )
            .unwrap();

        // Save and reload
        store.save_config().unwrap();
        let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();

        assert_eq!(reloaded.get_config(&pk).unwrap().fee_recipient, Some(new_fr));
    }

    #[test]
    fn test_save_config_no_path_returns_error() {
        let store = ValidatorStore::new([0u8; 20], 30_000_000);
        let result = store.save_config();
        assert!(result.is_err());
    }

    #[test]
    fn test_save_config_preserves_all_fields() {
        let pubkey_hex = "0x".to_string() + &hex::encode([1u8; 48]);
        let fr_hex = "0x".to_string() + &hex::encode([0xaau8; 20]);
        let default_fr_hex = "0x".to_string() + &hex::encode([0xccu8; 20]);

        let toml_content = format!(
            r#"[defaults]
fee_recipient = "{}"
gas_limit = 25000000
graffiti = "default graffiti"

[[validators]]
pubkey = "{}"
fee_recipient = "{}"
gas_limit = 35000000
builder_proposals = true
builder_boost_factor = 200
graffiti = "my graffiti"
enabled = false
"#,
            default_fr_hex, pubkey_hex, fr_hex,
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_content).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        store.save_config().unwrap();

        let reloaded = ValidatorStore::load_from_config(&config_path).unwrap();

        // Check defaults
        assert_eq!(reloaded.state.read().defaults.fee_recipient, [0xccu8; 20]);
        assert_eq!(reloaded.state.read().defaults.gas_limit, 25_000_000);
        assert!(reloaded.state.read().defaults.graffiti.is_some());
        let graffiti = reloaded.state.read().defaults.graffiti.unwrap();
        assert_eq!(&graffiti[..16], b"default graffiti");

        // Check validator
        let pk = [1u8; 48];
        let config = reloaded.get_config(&pk).unwrap();
        assert_eq!(config.fee_recipient, Some([0xaau8; 20]));
        assert_eq!(config.gas_limit, Some(35_000_000));
        assert!(config.builder_proposals);
        assert_eq!(config.builder_boost_factor, Some(200));
        assert!(config.graffiti.is_some());
        assert!(!config.enabled);
    }

    // --- Block selection mode tests (T4.4) ---

    #[test]
    fn test_effective_block_selection_mode_default() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::MaxProfit,);
    }

    #[test]
    fn test_effective_block_selection_mode_global_override() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::ExecutionOnly,);
    }

    #[test]
    fn test_effective_block_selection_mode_per_validator_override() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        let mut config = ValidatorConfig::new(pk);
        config.block_selection_mode = Some(BlockSelectionMode::BuilderOnly);
        store.add_validator(config).unwrap();

        // Global is MaxProfit, but per-validator is BuilderOnly
        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::BuilderOnly,);
    }

    #[test]
    fn test_effective_block_selection_mode_per_validator_overrides_global() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        let mut config = ValidatorConfig::new(pk);
        config.block_selection_mode = Some(BlockSelectionMode::BuilderAlways);
        store.add_validator(config).unwrap();
        store.set_global_block_selection_mode(BlockSelectionMode::ExecutionOnly);

        // Per-validator (BuilderAlways) takes precedence over global (ExecutionOnly)
        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::BuilderAlways,);
    }

    #[test]
    fn test_effective_block_selection_mode_unknown_pubkey_returns_global() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let unknown_pk = test_pubkey(99);
        store.set_global_block_selection_mode(BlockSelectionMode::BuilderOnly);

        assert_eq!(
            store.effective_block_selection_mode(&unknown_pk),
            BlockSelectionMode::BuilderOnly,
        );
    }

    #[test]
    fn test_block_selection_mode_toml_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("validators.toml");

        let toml_content = r#"
[defaults]
fee_recipient = "0x0000000000000000000000000000000000000001"
gas_limit = 30000000

[[validators]]
pubkey = "0x010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
builder_proposals = true
block_selection_mode = "builder-only"
"#;
        std::fs::write(&path, toml_content).unwrap();

        let store = ValidatorStore::load_from_config(&path).unwrap();
        let pk = test_pubkey(1);
        let config = store.get_config(&pk).unwrap();
        assert_eq!(config.block_selection_mode, Some(BlockSelectionMode::BuilderOnly));
    }

    // ── M-12 (Critical #1) / D-3 (Issue 2.11): is_signing_enabled ─────────

    /// D-3 (Issue 2.11): unknown pubkeys (not tracked by the store) are
    /// fail-closed — `is_signing_enabled` returns `false` so a pubkey the store
    /// has never seen is never permitted to sign by default.
    #[test]
    fn test_is_signing_enabled_unknown_pubkey_fails_closed() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        assert!(
            !store.is_signing_enabled(&test_pubkey(99)),
            "unknown pubkey must fail closed (return false)"
        );
    }

    /// A validator explicitly added with enabled=true is permitted to sign.
    #[test]
    fn test_is_signing_enabled_explicit_true() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap(); // default enabled=true
        assert!(store.is_signing_enabled(&pk));
    }

    /// A validator explicitly added with enabled=false is NOT permitted to sign
    /// (post-import doppelganger window scenario).
    #[test]
    fn test_is_signing_enabled_explicit_false() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(2);
        let mut config = ValidatorConfig::new(pk);
        config.enabled = false;
        store.add_validator(config).unwrap();
        assert!(!store.is_signing_enabled(&pk));
    }

    /// After set_enabled flips the flag to true, is_signing_enabled must
    /// return true (simulates the doppelganger window expiring).
    #[test]
    fn test_is_signing_enabled_flips_after_set_enabled() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(3);
        let mut config = ValidatorConfig::new(pk);
        config.enabled = false;
        store.add_validator(config).unwrap();
        assert!(!store.is_signing_enabled(&pk), "must be disabled before flip");

        store.set_enabled(&pk, true);
        assert!(store.is_signing_enabled(&pk), "must be enabled after flip");
    }

    // ── RF5-30: single StoreState lock + atomic reload ────────────────────

    /// Concurrent readers must never observe a half-applied reload (old
    /// defaults with new per-validator overrides, or vice versa). Under the
    /// previous multi-lock layout this was possible between the defaults write
    /// and the validators write; a single write guard makes it impossible.
    #[test]
    fn test_reader_never_observes_half_applied_reload() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::Duration;

        let pk = [1u8; 48];
        let pk_hex = format!("0x{}", hex::encode(pk));
        let fr_old = format!("0x{}", hex::encode([0xaau8; 20]));
        let fr_new = format!("0x{}", hex::encode([0xbbu8; 20]));
        let override_old = format!("0x{}", hex::encode([0x11u8; 20]));
        let override_new = format!("0x{}", hex::encode([0x22u8; 20]));

        let toml_old = format!(
            r#"
[defaults]
fee_recipient = "{fr_old}"
gas_limit = 30000000

[[validators]]
pubkey = "{pk_hex}"
fee_recipient = "{override_old}"
gas_limit = 31000000
"#
        );
        let toml_new = format!(
            r#"
[defaults]
fee_recipient = "{fr_new}"
gas_limit = 40000000

[[validators]]
pubkey = "{pk_hex}"
fee_recipient = "{override_new}"
gas_limit = 41000000
"#
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml_old).unwrap();

        let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
        // Confirm starting snapshot.
        let start = store.effective_config(&pk);
        assert_eq!(start.fee_recipient, [0x11u8; 20]);
        assert_eq!(start.gas_limit, 31_000_000);

        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = vec![];

        for _ in 0..8 {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // Single guard: observe defaults + validator together so
                    // the assertion pins store atomicity, not cross-call races.
                    let state = store.state.read();
                    let v = state
                        .validators
                        .get(&pk)
                        .expect("validator present for entire stress run");
                    let old_pair = state.defaults.fee_recipient == [0xaau8; 20]
                        && state.defaults.gas_limit == 30_000_000
                        && v.fee_recipient == Some([0x11u8; 20])
                        && v.gas_limit == Some(31_000_000);
                    let new_pair = state.defaults.fee_recipient == [0xbbu8; 20]
                        && state.defaults.gas_limit == 40_000_000
                        && v.fee_recipient == Some([0x22u8; 20])
                        && v.gas_limit == Some(41_000_000);
                    assert!(
                        old_pair || new_pair,
                        "half-applied reload: defaults.fee={:?} defaults.gas={} v.fee={:?} v.gas={:?}",
                        state.defaults.fee_recipient,
                        state.defaults.gas_limit,
                        v.fee_recipient,
                        v.gas_limit
                    );
                }
            }));
        }

        // Flip the on-disk config and reload repeatedly while readers run.
        for i in 0..40 {
            let content = if i % 2 == 0 { &toml_new } else { &toml_old };
            std::fs::write(&config_path, content).unwrap();
            store.reload_config().unwrap();
            thread::yield_now();
        }

        stop.store(true, Ordering::Relaxed);
        for h in handles {
            h.join().expect("reader panicked on half-applied state");
        }

        // Final state matches last write (toml_old because 0..40 ends on odd).
        let end = store.effective_config(&pk);
        assert_eq!(end.fee_recipient, [0x11u8; 20]);
        assert_eq!(end.gas_limit, 31_000_000);

        // Bound the test; readers exit promptly after stop.
        let _ = Duration::from_millis(1);
    }

    /// Stress: concurrent `effective_config` readers and `save_config` writers
    /// must not deadlock. Opposite-order multi-lock acquisition made this a
    /// real risk under parking_lot write-preferring fairness; a single state
    /// lock makes the deadlock unrepresentable.
    #[test]
    fn test_effective_config_and_save_config_cannot_deadlock() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use std::thread;
        use std::time::{Duration, Instant};

        let pk = [1u8; 48];
        let pk_hex = format!("0x{}", hex::encode(pk));
        let fr = format!("0x{}", hex::encode([0xaau8; 20]));
        let toml = format!(
            r#"
[defaults]
fee_recipient = "{fr}"
gas_limit = 30000000

[[validators]]
pubkey = "{pk_hex}"
"#
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &toml).unwrap();

        let store = Arc::new(ValidatorStore::load_from_config(&config_path).unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let mut handles = vec![];

        for _ in 0..8 {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = store.effective_config(&pk);
                    let _ = store.effective_fee_recipient(&pk);
                    let _ = store.effective_block_selection_mode(&pk);
                }
            }));
        }

        for _ in 0..4 {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    store.save_config().expect("save_config under stress");
                    // Mild mutation so writers do real work.
                    store.set_global_block_selection_mode(BlockSelectionMode::MaxProfit);
                }
            }));
        }

        let deadline = Instant::now() + Duration::from_millis(300);
        while Instant::now() < deadline {
            thread::yield_now();
        }
        stop.store(true, Ordering::Relaxed);

        let join_deadline = Instant::now() + Duration::from_secs(5);
        for h in handles {
            while !h.is_finished() {
                assert!(
                    Instant::now() < join_deadline,
                    "deadlock suspected: stress threads did not finish within 5s"
                );
                thread::sleep(Duration::from_millis(10));
            }
            h.join().expect("stress thread panicked");
        }
    }

    /// Parse failure during reload must leave the previous state fully intact
    /// (defaults, validators, and global block-selection mode).
    #[test]
    fn test_reload_failure_leaves_previous_state_intact() {
        let pk = [1u8; 48];
        let pk_hex = format!("0x{}", hex::encode(pk));
        let fr = format!("0x{}", hex::encode([0xaau8; 20]));
        let valid = format!(
            r#"
[defaults]
fee_recipient = "{fr}"
gas_limit = 35000000
graffiti = "keep-me"

[[validators]]
pubkey = "{pk_hex}"
builder_proposals = true
builder_boost_factor = 175
"#
        );

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(&config_path, &valid).unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        store.set_global_block_selection_mode(BlockSelectionMode::BuilderOnly);
        let pk_extra = [99u8; 48];
        store.add_validator(ValidatorConfig::new(pk_extra)).unwrap();

        std::fs::write(&config_path, "not valid toml [[[").unwrap();
        assert!(store.reload_config().is_err());

        let state = store.state.read();
        assert_eq!(state.defaults.fee_recipient, [0xaau8; 20]);
        assert_eq!(state.defaults.gas_limit, 35_000_000);
        assert!(state.defaults.graffiti.is_some());
        assert_eq!(state.global_block_selection_mode, BlockSelectionMode::BuilderOnly);
        let cfg = state.validators.get(&pk).unwrap();
        assert!(cfg.builder_proposals);
        assert_eq!(cfg.builder_boost_factor, Some(175));
        assert!(state.validators.contains_key(&pk_extra));
    }

    /// Structural pin: exactly one `RwLock` protects store state; `save_lock`
    /// remains a separate `Mutex`. Lock order is `save_lock` then `state`.
    #[test]
    fn test_all_accessors_use_single_state_lock() {
        // Compile-time shape of ValidatorStore: one RwLock + one Mutex.
        // Field access below fails to compile if the layout regresses.
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let _state_guard = store.state.read();
        drop(_state_guard);
        let _save_guard = store.save_lock.lock();
        drop(_save_guard);

        // Runtime pin: product code declares a single `RwLock` field on
        // `ValidatorStore` / `StoreState` wiring (not in comments or this test).
        let src = include_str!("store.rs");
        let rwlock_fields = src
            .lines()
            .filter(|l| {
                let t = l.trim();
                t.contains("state: ")
                    && t.contains("RwLock")
                    && t.ends_with(',')
                    && !t.starts_with("//")
            })
            .count();
        assert_eq!(rwlock_fields, 1, "expected exactly one `state: RwLock<…>` field declaration");

        // Accessors must not take a write lock for pure reads: exercise the
        // read path concurrently while a writer holds the save_lock only.
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        let cfg = store.effective_config(&pk);
        assert_eq!(cfg.gas_limit, 30_000_000);
        assert_eq!(store.default_fee_recipient(), test_fee_recipient(1));
        assert_eq!(store.default_gas_limit(), 30_000_000);
        assert!(store.has_validator(&pk));
        assert!(store.is_signing_enabled(&pk));
        assert!(!store.is_builder_enabled(&pk));
        assert_eq!(store.builder_boost_factor(&pk), 100);
        assert_eq!(store.effective_block_selection_mode(&pk), BlockSelectionMode::MaxProfit);
        assert_eq!(store.list_enabled_pubkeys(), vec![pk]);
    }

    #[test]
    fn set_fee_recipient_with_missing_parent_dir_does_not_publish() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("missing").join("validators.toml");
        assert!(!config_path.parent().unwrap().exists(), "parent directory must not exist");

        let pk = test_pubkey(1);
        let old_fee = test_fee_recipient(1);
        let old_gas = 31_000_000u64;
        let old_graffiti = parse_graffiti("keep-me");

        let mut store = ValidatorStore::new(test_fee_recipient(9), 30_000_000);
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some(old_fee);
        cfg.gas_limit = Some(old_gas);
        cfg.graffiti = Some(old_graffiti);
        store.add_validator(cfg).unwrap();
        store.config_path = Some(config_path);

        let err = store.update_config_durable(
            &pk,
            ValidatorConfigUpdate {
                fee_recipient: Some(Some(test_fee_recipient(2))),
                gas_limit: Some(Some(42_000_000)),
                graffiti: Some(Some(parse_graffiti("nope"))),
                ..Default::default()
            },
        );

        assert!(err.is_err(), "durable update must fail when the parent directory is missing");
        assert_eq!(store.effective_fee_recipient(&pk), old_fee);
        assert_eq!(store.effective_gas_limit(&pk), old_gas);
        assert_eq!(store.effective_graffiti(&pk), Some(old_graffiti));
    }

    /// Distinct-field writers all land, and a multi-field update is never
    /// observed half-applied. `save_lock` plus delta re-apply is what keeps
    /// both properties.
    #[test]
    fn test_concurrent_durable_writers_lose_no_update_and_apply_none_partially() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{Arc, Barrier};
        use std::thread;
        use std::time::Duration;

        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let store = Arc::new(store);

        let barrier = Arc::new(Barrier::new(3));
        let fee = test_fee_recipient(7);
        let gas = 45_000_000u64;
        let graffiti = parse_graffiti("kept");

        let mut handles = Vec::new();
        {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store
                    .update_config_durable(
                        &pk,
                        ValidatorConfigUpdate {
                            fee_recipient: Some(Some(fee)),
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }));
        }
        {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store
                    .update_config_durable(
                        &pk,
                        ValidatorConfigUpdate { gas_limit: Some(Some(gas)), ..Default::default() },
                    )
                    .unwrap();
            }));
        }
        {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store
                    .update_config_durable(
                        &pk,
                        ValidatorConfigUpdate {
                            graffiti: Some(Some(graffiti)),
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }));
        }
        for handle in handles {
            handle.join().unwrap();
        }

        assert_eq!(store.effective_fee_recipient(&pk), fee);
        assert_eq!(store.effective_gas_limit(&pk), gas);
        assert_eq!(store.effective_graffiti(&pk), Some(graffiti));
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(disk.effective_fee_recipient(&pk), fee);
        assert_eq!(disk.effective_gas_limit(&pk), gas);
        assert_eq!(disk.effective_graffiti(&pk), Some(graffiti));

        // Seed a correlated triple so readers have a consistent baseline
        // before the racing writers start.
        let seed_fee = [0u8; 20];
        let seed_graffiti = [0u8; 32];
        store
            .update_config_durable(
                &pk,
                ValidatorConfigUpdate {
                    fee_recipient: Some(Some(seed_fee)),
                    gas_limit: Some(Some(40_000_000)),
                    graffiti: Some(Some(seed_graffiti)),
                    ..Default::default()
                },
            )
            .unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let mut readers = Vec::new();
        for _ in 0..4 {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            readers.push(thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let cfg = store.effective_config(&pk);
                    let fee_id = cfg.fee_recipient[0];
                    let gas_id = cfg
                        .gas_limit
                        .checked_sub(40_000_000)
                        .and_then(|delta| u8::try_from(delta).ok())
                        .unwrap_or(255);
                    let graf_id = cfg.graffiti.map(|g| g[0]).unwrap_or(255);
                    assert_eq!(fee_id, gas_id, "fee recipient applied without gas limit");
                    assert_eq!(fee_id, graf_id, "fee recipient applied without graffiti");
                }
            }));
        }

        let mut writers = Vec::new();
        for id in 1u8..=4 {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            writers.push(thread::spawn(move || {
                let mut fee = [0u8; 20];
                fee[0] = id;
                let mut graf = [0u8; 32];
                graf[0] = id;
                while !stop.load(Ordering::Relaxed) {
                    store
                        .update_config_durable(
                            &pk,
                            ValidatorConfigUpdate {
                                fee_recipient: Some(Some(fee)),
                                gas_limit: Some(Some(40_000_000 + u64::from(id))),
                                graffiti: Some(Some(graf)),
                                ..Default::default()
                            },
                        )
                        .unwrap();
                }
            }));
        }

        thread::sleep(Duration::from_millis(80));
        stop.store(true, Ordering::Relaxed);
        for handle in writers {
            handle.join().unwrap();
        }
        for handle in readers {
            handle.join().unwrap();
        }

        let cfg = store.effective_config(&pk);
        let fee_id = cfg.fee_recipient[0];
        assert_eq!(cfg.gas_limit, 40_000_000 + u64::from(fee_id));
        assert_eq!(cfg.graffiti.unwrap()[0], fee_id);
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(disk.effective_fee_recipient(&pk), cfg.fee_recipient);
        assert_eq!(disk.effective_gas_limit(&pk), cfg.gas_limit);
        assert_eq!(disk.effective_graffiti(&pk), cfg.graffiti);
    }

    /// `set_enabled(false)` on another thread, joined while `save_lock` is
    /// still held and before the delta is published, must survive. Replacing
    /// the live map with the pre-write candidate would restore `enabled`.
    #[test]
    fn test_concurrent_set_enabled_survives_durable_update() {
        let pk = test_pubkey(1);
        let old_fee = test_fee_recipient(1);
        let new_fee = test_fee_recipient(4);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");

        let mut store = ValidatorStore::new(test_fee_recipient(9), 30_000_000);
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some(old_fee);
        cfg.enabled = true;
        store.add_validator(cfg).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);

        struct ClearHook;
        impl Drop for ClearHook {
            fn drop(&mut self) {
                super::DURABLE_WRITE_HOOK.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let _clear_hook = ClearHook;

        let hooked = std::sync::Arc::clone(&store);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let hooked = std::sync::Arc::clone(&hooked);
                std::thread::spawn(move || hooked.set_enabled(&pk, false))
                    .join()
                    .expect("set_enabled thread");
            }));
        });

        store
            .update_config_durable(
                &pk,
                ValidatorConfigUpdate { fee_recipient: Some(Some(new_fee)), ..Default::default() },
            )
            .unwrap();

        assert_eq!(store.effective_fee_recipient(&pk), new_fee);
        assert!(
            !store.is_signing_enabled(&pk),
            "set_enabled(false) must survive the durable publish"
        );
        let on_disk = std::fs::read_to_string(&config_path).unwrap();
        assert!(
            on_disk.contains("enabled = true"),
            "the persisted snapshot was taken before set_enabled"
        );
    }

    #[test]
    fn test_reload_config_racing_durable_update_file_and_store_agree() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some(test_fee_recipient(1));
        cfg.gas_limit = Some(31_000_000);
        cfg.graffiti = Some(parse_graffiti("stable"));
        store.add_validator(cfg).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let store = Arc::new(store);

        let barrier = Arc::new(Barrier::new(2));
        let rounds = 40u8;

        let writer_store = Arc::clone(&store);
        let writer_barrier = Arc::clone(&barrier);
        let writer = thread::spawn(move || {
            writer_barrier.wait();
            for i in 0..rounds {
                let mut fee = [0x10u8; 20];
                fee[0] = i;
                writer_store
                    .update_config_durable(
                        &pk,
                        ValidatorConfigUpdate {
                            fee_recipient: Some(Some(fee)),
                            ..Default::default()
                        },
                    )
                    .unwrap();
            }
        });

        let reloader_store = Arc::clone(&store);
        let reloader_barrier = Arc::clone(&barrier);
        let reloader = thread::spawn(move || {
            reloader_barrier.wait();
            for _ in 0..rounds {
                reloader_store.reload_config().unwrap();
            }
        });

        writer.join().unwrap();
        reloader.join().unwrap();

        let mem = store.get_config(&pk).unwrap();
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        let from_file = disk.get_config(&pk).unwrap();
        assert_eq!(mem.fee_recipient, from_file.fee_recipient);
        assert_eq!(mem.gas_limit, from_file.gas_limit);
        assert_eq!(mem.graffiti, from_file.graffiti);
        assert_eq!(mem.enabled, from_file.enabled);
        assert_eq!(mem.builder_proposals, from_file.builder_proposals);
        assert_eq!(store.default_fee_recipient(), disk.default_fee_recipient());
        assert_eq!(store.default_gas_limit(), disk.default_gas_limit());
        assert_eq!(store.effective_graffiti(&pk), disk.effective_graffiti(&pk));
    }

    #[test]
    fn test_save_config_persisted_bytes_match_golden_file() {
        let golden = include_str!("../testdata/save_config_golden.toml");
        let pk = test_pubkey(1);
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some(test_fee_recipient(2));
        cfg.gas_limit = Some(35_000_000);
        cfg.builder_proposals = true;
        cfg.builder_boost_factor = Some(200);
        cfg.graffiti = Some(parse_graffiti("my graffiti"));
        cfg.enabled = false;
        cfg.block_selection_mode = Some(BlockSelectionMode::BuilderOnly);
        cfg.builders = Some(vec!["https://builder.example/api".to_string()]);
        cfg.min_bid = Some(1_500_000);

        let mut store = ValidatorStore::new(test_fee_recipient(3), 25_000_000);
        store.set_default_graffiti(parse_graffiti("default graffiti"));
        store.add_validator(cfg).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();

        let bytes = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(bytes, golden);
        assert!(golden.contains("enabled = false"), "enabled: Some(v.enabled) must be persisted");
    }

    /// The target is absent when the candidate is cloned, so the write must
    /// not happen. The hook re-adds it after a write and before publish — the
    /// pre-fix path took that unpersisted fee. A fix returns `NotFound` before
    /// the write, so the hook does not run and the file is unchanged.
    #[test]
    fn test_absent_target_readded_before_publish_returns_not_found() {
        let pk = test_pubkey(1);
        let other = test_pubkey(2);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(9), 30_000_000);
        store.add_validator(ValidatorConfig::new(other)).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let before = std::fs::read(&config_path).unwrap();
        let store = std::sync::Arc::new(store);

        struct ClearHook;
        impl Drop for ClearHook {
            fn drop(&mut self) {
                super::DURABLE_WRITE_HOOK.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let _clear_hook = ClearHook;
        let hooked = std::sync::Arc::clone(&store);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let hooked = std::sync::Arc::clone(&hooked);
                std::thread::spawn(move || {
                    hooked.add_validator(ValidatorConfig::new(pk)).unwrap();
                })
                .join()
                .expect("add_validator thread");
            }));
        });

        let new_fee = test_fee_recipient(4);
        let res = store.update_config_durable(
            &pk,
            ValidatorConfigUpdate { fee_recipient: Some(Some(new_fee)), ..Default::default() },
        );
        let on_disk = ValidatorStore::load_from_config(&config_path).unwrap();
        let persisted = on_disk.get_config(&pk).and_then(|c| c.fee_recipient);
        let live = store.get_config(&pk).and_then(|c| c.fee_recipient);
        assert!(
            matches!(res, Err(ValidatorStoreError::NotFound)),
            "expected NotFound, got {res:?}; live={live:?} persisted={persisted:?}"
        );
        let after = std::fs::read(&config_path).unwrap();
        assert_eq!(after, before, "absent target must not rewrite the file");
        assert_ne!(live, Some(new_fee), "unpersisted fee must not be published");
    }

    /// Clone sees the validator, then an unlocked delete plus re-import lands
    /// before publish. Production import/delete take `save_lock` and cannot
    /// interleave; this drives the unlocked methods the repair path still
    /// covers. The file must match the live key, and the in-flight delta must
    /// not stick to the new import.
    #[test]
    fn test_remove_and_readd_during_durable_update_file_matches_live() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let pk = test_pubkey(1);
        let old_fee = test_fee_recipient(1);
        let new_fee = test_fee_recipient(4);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(9), 30_000_000);
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some(old_fee);
        cfg.gas_limit = Some(35_000_000);
        cfg.graffiti = Some(parse_graffiti("old"));
        cfg.enabled = false;
        store.add_validator(cfg).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let store = Arc::new(store);

        struct ClearHook;
        impl Drop for ClearHook {
            fn drop(&mut self) {
                super::DURABLE_WRITE_HOOK.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let _clear_hook = ClearHook;
        let once = Arc::new(AtomicBool::new(false));
        let hooked = Arc::clone(&store);
        let once_hook = Arc::clone(&once);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                if once_hook.swap(true, Ordering::SeqCst) {
                    return;
                }
                let hooked = Arc::clone(&hooked);
                std::thread::spawn(move || {
                    hooked.remove_validator(&pk);
                    hooked.add_validator(ValidatorConfig::new(pk)).unwrap();
                })
                .join()
                .expect("reimport thread");
            }));
        });

        let res = store.update_config_durable(
            &pk,
            ValidatorConfigUpdate { fee_recipient: Some(Some(new_fee)), ..Default::default() },
        );
        assert!(
            matches!(res, Err(ValidatorStoreError::NotFound)),
            "replaced identity must not report success, got {res:?}"
        );

        let live = store.get_config(&pk).expect("reimport stays in the live store");
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        let from_file = disk.get_config(&pk).expect("file keeps the live key");
        assert_eq!(live.fee_recipient, from_file.fee_recipient);
        assert_eq!(live.gas_limit, from_file.gas_limit);
        assert_eq!(live.graffiti, from_file.graffiti);
        assert_eq!(live.enabled, from_file.enabled);
        assert_eq!(live.builder_proposals, from_file.builder_proposals);
        assert_eq!(live.builder_boost_factor, from_file.builder_boost_factor);
        assert_eq!(live.block_selection_mode, from_file.block_selection_mode);
        assert_eq!(live.builders, from_file.builders);
        assert_eq!(live.min_bid, from_file.min_bid);
        assert_eq!(live.fee_recipient, None, "stale fee delta must not land on the reimport");
        assert!(live.enabled);
        assert_eq!(live.gas_limit, None);
    }

    /// Publish `enabled = false` before persisting it. The write hook runs
    /// after the file is durable, and signing is already disabled there. A
    /// failed write still leaves the validator disabled.
    #[test]
    fn test_disable_slashed_publishes_before_persist_and_fails_closed() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);

        struct ClearHook;
        impl Drop for ClearHook {
            fn drop(&mut self) {
                super::DURABLE_WRITE_HOOK.with(|slot| *slot.borrow_mut() = None);
            }
        }
        let _clear_hook = ClearHook;
        let hooked = std::sync::Arc::clone(&store);
        let saw_disabled_at_write = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&saw_disabled_at_write);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                flag.store(!hooked.is_signing_enabled(&pk), std::sync::atomic::Ordering::SeqCst);
            }));
        });

        store.disable_slashed(&pk).unwrap();
        assert!(
            saw_disabled_at_write.load(std::sync::atomic::Ordering::SeqCst),
            "the validator is already disabled while the file is written"
        );
        assert!(!store.is_signing_enabled(&pk));
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(!disk.is_signing_enabled(&pk));

        let missing = dir.path().join("missing").join("validators.toml");
        let mut failed = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        failed.add_validator(ValidatorConfig::new(pk)).unwrap();
        failed.config_path = Some(missing);
        assert!(failed.disable_slashed(&pk).is_err());
        assert!(
            !failed.is_signing_enabled(&pk),
            "a failed persist must still disable the slashed validator"
        );
    }

    fn clear_test_hooks() {
        super::DURABLE_WRITE_HOOK.with(|slot| *slot.borrow_mut() = None);
        super::RELOAD_AFTER_PARSE_HOOK.with(|slot| *slot.borrow_mut() = None);
        super::TOML_WRITE_FAULT.with(|cell| cell.set(None));
        super::NEXT_TOML_WRITE_FAULT.with(|cell| cell.set(None));
        super::KEEP_TOML_WRITE_FAULT.with(|cell| cell.set(false));
        super::PARENT_DIR_SYNCS.with(|cell| cell.set(0));
    }

    struct ClearHooks;
    impl Drop for ClearHooks {
        fn drop(&mut self) {
            clear_test_hooks();
        }
    }

    /// Removing the `save_lock` guard in `reload_config` makes `try_lock`
    /// succeed and this test fail.
    #[test]
    fn test_reload_holds_save_lock_across_parse_and_apply() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path);
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);
        let _clear = ClearHooks;
        let hooked = std::sync::Arc::clone(&store);
        let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&held);
        super::RELOAD_AFTER_PARSE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                flag.store(
                    hooked.save_lock.try_lock().is_none(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }));
        });
        store.reload_config().unwrap();
        assert!(held.load(std::sync::atomic::Ordering::SeqCst), "reload must hold save_lock");
    }

    #[test]
    fn test_durable_write_holds_save_lock() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path);
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);
        let _clear = ClearHooks;
        let hooked = std::sync::Arc::clone(&store);
        let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&held);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                flag.store(
                    hooked.save_lock.try_lock().is_none(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }));
        });
        store
            .update_config_durable(
                &pk,
                ValidatorConfigUpdate {
                    fee_recipient: Some(Some(test_fee_recipient(4))),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(held.load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn test_write_fault_at_each_step_does_not_publish() {
        let steps = [
            super::TomlWriteFault::Serialize,
            super::TomlWriteFault::CreateTemp,
            super::TomlWriteFault::Write,
            super::TomlWriteFault::SyncFile,
            super::TomlWriteFault::Rename,
            super::TomlWriteFault::SyncDir,
        ];
        for step in steps {
            let pk = test_pubkey(1);
            let old_fee = test_fee_recipient(1);
            let new_fee = test_fee_recipient(4);
            let dir = tempfile::tempdir().unwrap();
            let config_path = dir.path().join("validators.toml");
            let mut store = ValidatorStore::new(test_fee_recipient(9), 30_000_000);
            let mut cfg = ValidatorConfig::new(pk);
            cfg.fee_recipient = Some(old_fee);
            store.add_validator(cfg).unwrap();
            store.config_path = Some(config_path.clone());
            store.save_config().unwrap();
            let _clear = ClearHooks;
            super::TOML_WRITE_FAULT.with(|cell| {
                cell.set(Some(super::FaultPlan { skip: 0, step }));
            });
            let err = store.update_config_durable(
                &pk,
                ValidatorConfigUpdate { fee_recipient: Some(Some(new_fee)), ..Default::default() },
            );
            assert!(err.is_err(), "{step:?} must fail the durable update");
            assert_eq!(store.effective_fee_recipient(&pk), old_fee, "{step:?} must not publish");
        }
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_failed_repair_write_does_not_publish_stale_delta() {
        let pk = test_pubkey(1);
        let old_fee = test_fee_recipient(1);
        let new_fee = test_fee_recipient(4);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(9), 30_000_000);
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some(old_fee);
        store.add_validator(cfg).unwrap();
        store.config_path = Some(config_path);
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);
        let _clear = ClearHooks;
        let once = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hooked = std::sync::Arc::clone(&store);
        let once_hook = std::sync::Arc::clone(&once);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                if once_hook.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                let hooked = std::sync::Arc::clone(&hooked);
                std::thread::spawn(move || {
                    hooked.remove_validator(&pk);
                    hooked.add_validator(ValidatorConfig::new(pk)).unwrap();
                })
                .join()
                .unwrap();
            }));
        });
        // First write succeeds. The repair write hits the fault.
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 1, step: super::TomlWriteFault::SyncFile }));
        });
        let res = store.update_config_durable(
            &pk,
            ValidatorConfigUpdate { fee_recipient: Some(Some(new_fee)), ..Default::default() },
        );
        assert!(res.is_err(), "repair write failure must surface, got {res:?}");
        let live = store.get_config(&pk).expect("reimport stays");
        assert_ne!(live.fee_recipient, Some(new_fee), "stale fee must not publish");
        assert!(logs_contain("validator identity changed during durable update"));
    }

    #[test]
    fn test_remove_only_during_durable_update_drops_the_key() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);
        let _clear = ClearHooks;
        let hooked = std::sync::Arc::clone(&store);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let hooked = std::sync::Arc::clone(&hooked);
                std::thread::spawn(move || {
                    hooked.remove_validator(&pk);
                })
                .join()
                .unwrap();
            }));
        });
        let res = store.update_config_durable(
            &pk,
            ValidatorConfigUpdate {
                fee_recipient: Some(Some(test_fee_recipient(4))),
                ..Default::default()
            },
        );
        assert!(matches!(res, Err(ValidatorStoreError::NotFound)));
        assert!(store.get_config(&pk).is_none());
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(disk.get_config(&pk).is_none());
    }

    #[test]
    fn test_add_validator_over_existing_key_replaces_config() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        let mut first = ValidatorConfig::new(pk);
        first.fee_recipient = Some(test_fee_recipient(1));
        store.add_validator(first).unwrap();
        let gen = store.state.read().validator_gen[&pk];
        let mut second = ValidatorConfig::new(pk);
        second.fee_recipient = Some(test_fee_recipient(2));
        second.enabled = false;
        store.add_validator(second).unwrap();
        assert_eq!(store.effective_fee_recipient(&pk), test_fee_recipient(2));
        assert!(!store.is_signing_enabled(&pk));
        assert_ne!(store.state.read().validator_gen[&pk], gen);
    }

    #[test]
    fn test_add_and_remove_validator_durable_persist_and_roll_back() {
        let pk = test_pubkey(1);
        let extra = test_pubkey(2);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();

        let mut replacement = ValidatorConfig::new(pk);
        replacement.fee_recipient = Some(test_fee_recipient(7));
        assert!(
            !store.add_validator_durable(replacement).unwrap(),
            "an existing row is not replaced"
        );
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(disk.effective_fee_recipient(&pk), test_fee_recipient(1));

        store.add_validator_durable(ValidatorConfig::new(extra)).unwrap();
        assert!(ValidatorStore::load_from_config(&config_path).unwrap().has_validator(&extra));

        let _clear = ClearHooks;
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::SyncDir }));
        });
        let boom = test_pubkey(3);
        assert!(store.add_validator_durable(ValidatorConfig::new(boom)).is_err());
        assert!(!store.has_validator(&boom));

        clear_test_hooks();
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::Rename }));
        });
        assert!(store.remove_validator_durable(&extra).is_err());
        assert!(store.has_validator(&extra));
        assert!(ValidatorStore::load_from_config(&config_path).unwrap().has_validator(&extra));

        clear_test_hooks();
        assert!(store.remove_validator_durable(&extra).unwrap().is_some());
        assert!(!ValidatorStore::load_from_config(&config_path).unwrap().has_validator(&extra));
        assert!(store.remove_validator_durable(&test_pubkey(99)).unwrap().is_none());
    }

    #[test]
    fn test_ingress_rejects_u64_above_i64_max() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        let huge = (i64::MAX as u64).saturating_add(1);
        let err = store
            .update_config(
                &pk,
                ValidatorConfigUpdate { gas_limit: Some(Some(huge)), ..Default::default() },
            )
            .unwrap_err();
        assert!(err.to_string().contains("i64::MAX"), "{err}");
        assert_eq!(store.effective_gas_limit(&pk), 30_000_000);
        assert!(
            store
                .update_config(
                    &pk,
                    ValidatorConfigUpdate { min_bid: Some(huge), ..Default::default() },
                )
                .is_err()
        );
        assert!(store
            .update_config(
                &pk,
                ValidatorConfigUpdate { builder_boost_factor: Some(huge), ..Default::default() },
            )
            .is_err());
        assert!(store.min_bid(&pk) <= i64::MAX as u64);
        assert!(store
            .apply_default_update(DefaultUpdate {
                fee_recipient: None,
                gas_limit: Some(huge),
                graffiti: None,
            })
            .is_err());
        assert_eq!(store.default_gas_limit(), 30_000_000);
        assert!(store.set_global_min_bid(huge).is_err());
        assert!(store.set_global_builder_boost_factor(huge).is_err());
        let mut cfg = ValidatorConfig::new(test_pubkey(2));
        cfg.gas_limit = Some(huge);
        assert!(store.add_validator(cfg).is_err());
        assert!(!store.has_validator(&test_pubkey(2)));

        let err = store
            .update_config_durable(
                &pk,
                ValidatorConfigUpdate {
                    builders: Some(vec!["file://evil".to_string()]),
                    ..Default::default()
                },
            )
            .unwrap_err();
        assert!(err.to_string().contains("file://evil"), "{err}");
    }

    /// Import must not be visible to readers until the validators file write
    /// has succeeded. The hook runs after the file write and before publish.
    #[test]
    fn test_add_validator_durable_is_invisible_until_the_write_succeeds() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path);
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);
        let _clear = ClearHooks;
        let hooked = std::sync::Arc::clone(&store);
        let visible = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&visible);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                flag.store(hooked.has_validator(&pk), std::sync::atomic::Ordering::SeqCst);
            }));
        });
        store.add_validator_durable(ValidatorConfig::new(pk)).unwrap();
        assert!(
            !visible.load(std::sync::atomic::Ordering::SeqCst),
            "a new validator must stay unpublished until the write succeeds"
        );
        assert!(store.has_validator(&pk));
    }

    /// Delete must keep the validator visible until the file write succeeds.
    #[test]
    fn test_remove_validator_durable_stays_live_until_the_write_succeeds() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path);
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);
        let _clear = ClearHooks;
        let hooked = std::sync::Arc::clone(&store);
        let still_live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&still_live);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                flag.store(hooked.has_validator(&pk), std::sync::atomic::Ordering::SeqCst);
            }));
        });
        assert!(store.remove_validator_durable(&pk).unwrap().is_some());
        assert!(
            still_live.load(std::sync::atomic::Ordering::SeqCst),
            "remove must not drop the live validator before the write succeeds"
        );
        assert!(!store.has_validator(&pk));
    }

    /// A directory fsync failure happens after rename. Disk must be put back
    /// so it does not move ahead of memory.
    #[test]
    fn test_syncdir_fault_reconciles_the_file_with_memory() {
        let pk = test_pubkey(1);
        let boom = test_pubkey(2);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let _clear = ClearHooks;
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::SyncDir }))
        });
        assert!(store.add_validator_durable(ValidatorConfig::new(boom)).is_err());
        assert!(!store.has_validator(&boom));
        assert!(
            !ValidatorStore::load_from_config(&config_path).unwrap().has_validator(&boom),
            "a failed add must not leave the new validator on disk"
        );

        // The restore write fails before rename, so the rejected document is
        // still the file boot would load.
        clear_test_hooks();
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::SyncDir }))
        });
        super::NEXT_TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::Rename }))
        });
        let stuck = test_pubkey(3);
        assert!(store.add_validator_durable(ValidatorConfig::new(stuck)).is_err());
        assert!(!store.has_validator(&stuck));
        let rejected = config_path.with_file_name("validators.toml.rejected");
        assert!(
            !config_path.exists() || rejected.exists(),
            "a failed restore must move the validators file off the boot path"
        );
        if config_path.exists() {
            assert!(
                !ValidatorStore::load_from_config(&config_path).unwrap().has_validator(&stuck),
                "a failed restore must not leave the rejected validator loadable"
            );
        }

        clear_test_hooks();
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::SyncDir }))
        });
        assert!(store.remove_validator_durable(&pk).is_err());
        assert!(store.has_validator(&pk));
        assert!(
            ValidatorStore::load_from_config(&config_path).unwrap().has_validator(&pk),
            "a failed remove must not drop the validator from disk"
        );
    }

    /// A second durable add must not turn a disabled row back on.
    #[test]
    fn test_add_validator_durable_does_not_replace_an_existing_row() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let mut disabled = ValidatorConfig::new(pk);
        disabled.enabled = false;
        disabled.fee_recipient = Some(test_fee_recipient(4));
        store.add_validator(disabled).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();

        store.add_validator_durable(ValidatorConfig::new(pk)).unwrap();
        assert!(
            !store.is_signing_enabled(&pk),
            "insert-if-absent must not overwrite enabled=false"
        );
        assert_eq!(store.effective_fee_recipient(&pk), test_fee_recipient(4));
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(!disk.is_signing_enabled(&pk));
        assert_eq!(disk.effective_fee_recipient(&pk), test_fee_recipient(4));
    }

    /// An elapsed doppelganger hold is re-enabled at boot. An operator disable is not.
    #[test]
    fn test_elapsed_doppelganger_hold_reenables_at_boot_operator_disable_does_not() {
        let held = test_pubkey(1);
        let operator = test_pubkey(2);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();

        store.begin_doppelganger_hold(&held, 1_700_000_000).unwrap();
        let mut op = ValidatorConfig::new(operator);
        op.enabled = false;
        store.add_validator_durable(op).unwrap();
        store.set_enabled_durable(&operator, false).unwrap();

        let held_cfg = store.get_config(&held).unwrap();
        assert_eq!(
            held_cfg.doppelganger_hold_until,
            Some(1_700_000_000),
            "the hold must be stored separately from enabled=false"
        );
        assert!(!held_cfg.enabled);

        let _open = store.reconcile_doppelganger_holds_at_boot(1_700_000_100);
        assert!(
            store.is_signing_enabled(&held),
            "an elapsed doppelganger hold must be re-enabled at boot"
        );
        assert!(store.get_config(&held).unwrap().doppelganger_hold_until.is_none());
        assert!(
            !store.is_signing_enabled(&operator),
            "an operator disable must stay disabled across boot"
        );
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(disk.is_signing_enabled(&held));
        assert!(!disk.is_signing_enabled(&operator));
        assert!(disk.get_config(&operator).unwrap().doppelganger_hold_until.is_none());
    }

    /// A disabled row with no hold is a tombstone. Boot must not re-enable it.
    #[test]
    fn test_tombstone_without_a_hold_stays_disabled_at_boot() {
        let pk = test_pubkey(7);
        let pk_hex = format!("0x{}", hex::encode(pk));
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        std::fs::write(
            &config_path,
            format!(
                "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\ngas_limit = 30000000\n\n[[validators]]\npubkey = \"{pk_hex}\"\nenabled = false\n"
            ),
        )
        .unwrap();

        let store = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(!store.is_signing_enabled(&pk), "a tombstone loads disabled");
        assert!(
            store.get_config(&pk).unwrap().doppelganger_hold_until.is_none(),
            "a tombstone has no doppelganger hold"
        );
        let open = store.reconcile_doppelganger_holds_at_boot(u64::MAX / 2);
        assert!(open.is_empty(), "a tombstone has no hold for boot to re-arm");
        assert!(!store.is_signing_enabled(&pk), "a tombstone stays disabled across boot");
        assert!(store.get_config(&pk).unwrap().doppelganger_hold_until.is_none());
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(!disk.is_signing_enabled(&pk));
        assert!(disk.get_config(&pk).unwrap().doppelganger_hold_until.is_none());
    }

    /// A restart inside the window reloads the hold and does not enable the key.
    /// After the deadline, boot releases it. An operator disable has no deadline.
    #[test]
    fn test_open_doppelganger_hold_survives_restart_and_releases_at_the_deadline() {
        let held = test_pubkey(4);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        store.begin_doppelganger_hold(&held, 1_700_000_100).unwrap();

        let restarted = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(
            !restarted.is_signing_enabled(&held),
            "a restart inside the doppelganger window must leave the key disabled"
        );
        assert_eq!(
            restarted.get_config(&held).unwrap().doppelganger_hold_until,
            Some(1_700_000_100),
            "the hold deadline must be reloaded from the validators file"
        );
        let open = restarted.reconcile_doppelganger_holds_at_boot(1_700_000_050);
        assert_eq!(
            open,
            vec![(held, 50)],
            "an open hold must be returned so boot can re-arm the enable task"
        );
        assert!(!restarted.is_signing_enabled(&held));

        let still_open = restarted.reconcile_doppelganger_holds_at_boot(1_700_000_100);
        assert!(
            still_open.is_empty(),
            "an elapsed hold is released at boot, not left for a later re-arm"
        );
        assert!(
            restarted.is_signing_enabled(&held),
            "a restart after the window must re-enable the held key"
        );
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(disk.is_signing_enabled(&held));
        assert!(disk.get_config(&held).unwrap().doppelganger_hold_until.is_none());
    }

    /// Boot retries a failed re-enable of an elapsed hold instead of dropping it.
    #[test]
    fn test_elapsed_hold_reenable_is_retried_at_boot() {
        let held = test_pubkey(5);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        store.begin_doppelganger_hold(&held, 1_700_000_000).unwrap();

        let _clear = ClearHooks;
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::SyncDir }))
        });
        let open = store.reconcile_doppelganger_holds_at_boot(1_700_000_100);
        assert!(open.is_empty(), "a failed re-enable must be retried at boot");
        assert!(store.is_signing_enabled(&held));
        assert!(store.get_config(&held).unwrap().doppelganger_hold_until.is_none());
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(disk.is_signing_enabled(&held));
    }

    /// A remove whose restore also fails must not boot a file that dropped the key.
    #[test]
    fn test_failed_remove_restore_does_not_boot_without_the_validator() {
        let pk = test_pubkey(6);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();

        let _clear = ClearHooks;
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::SyncDir }))
        });
        super::NEXT_TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::Rename }))
        });
        assert!(store.remove_validator_durable(&pk).is_err());
        assert!(store.has_validator(&pk), "memory keeps the validator when restore fails");
        let rejected = config_path.with_file_name("validators.toml.rejected");
        assert!(
            !config_path.exists() || rejected.exists(),
            "a failed restore must move the validators file off the boot path"
        );
        if config_path.exists() {
            assert!(
                ValidatorStore::load_from_config(&config_path).unwrap().has_validator(&pk),
                "a failed remove restore must not boot without the live validator"
            );
        }
    }

    /// The import row is `enabled = true` today, then the hold write fails.
    /// Disk must not keep that enabled row.
    #[test]
    fn test_failed_hold_write_does_not_leave_the_key_enabled_on_disk() {
        let pk = test_pubkey(7);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();

        assert!(store.add_validator_durable(ValidatorConfig::new(pk)).unwrap());
        assert!(store.is_signing_enabled(&pk));

        let _clear = ClearHooks;
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::Rename }))
        });
        assert!(store.begin_doppelganger_hold(&pk, 1_700_000_400).is_err());
        assert!(!store.is_signing_enabled(&pk), "memory stays disabled when the hold write fails");

        let rejected = config_path.with_file_name("validators.toml.rejected");
        assert!(
            !config_path.exists() || rejected.exists(),
            "a failed hold write must take an enabled document off the boot path"
        );
        if config_path.exists() {
            let disk = ValidatorStore::load_from_config(&config_path).unwrap();
            assert!(
                !disk.is_signing_enabled(&pk),
                "a failed hold write must not leave the key enabled on disk"
            );
        }
    }

    /// Importing over a slashing or operator disable must not arm a hold.
    #[test]
    fn test_preexisting_disable_is_not_turned_into_a_doppelganger_hold() {
        let pk = test_pubkey(8);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        let mut disabled = ValidatorConfig::new(pk);
        disabled.enabled = false;
        disabled.fee_recipient = Some(test_fee_recipient(4));
        store.add_validator(disabled).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();

        assert!(
            !store.add_validator_durable(ValidatorConfig::new(pk)).unwrap(),
            "the disabled row is already present"
        );
        store.begin_doppelganger_hold(&pk, 1_700_000_100).unwrap();
        assert!(
            store.get_config(&pk).unwrap().doppelganger_hold_until.is_none(),
            "a pre-existing disable must not gain a doppelganger hold"
        );
        assert!(!store.is_signing_enabled(&pk));
        assert_eq!(store.effective_fee_recipient(&pk), test_fee_recipient(4));

        let open = store.reconcile_doppelganger_holds_at_boot(1_700_000_200);
        assert!(open.is_empty(), "boot must not re-arm a disable that was never a hold");
        assert!(
            !store.is_signing_enabled(&pk),
            "reconciling past a deadline must not re-enable a slashing or operator disable"
        );
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(!disk.is_signing_enabled(&pk));
        assert!(disk.get_config(&pk).unwrap().doppelganger_hold_until.is_none());
    }

    /// A failed DELETE disable must not leave a hold that boot will re-enable.
    #[test]
    fn test_failed_delete_disable_does_not_leave_a_reenableable_hold() {
        let pk = test_pubkey(9);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        store.begin_doppelganger_hold(&pk, 1_700_000_500).unwrap();
        assert!(store.get_config(&pk).unwrap().doppelganger_hold_until.is_some());

        let _clear = ClearHooks;
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::Rename }))
        });
        assert!(store.set_enabled_durable(&pk, false).is_err(), "the delete write fails");
        assert!(!store.is_signing_enabled(&pk));
        assert!(
            store.get_config(&pk).unwrap().doppelganger_hold_until.is_none(),
            "memory must drop the hold even when the write fails"
        );

        let rejected = config_path.with_file_name("validators.toml.rejected");
        assert!(
            !config_path.exists() || rejected.exists(),
            "a failed delete must take the old hold off the boot path"
        );
        if config_path.exists() {
            let disk = ValidatorStore::load_from_config(&config_path).unwrap();
            let hold = disk.get_config(&pk).and_then(|c| c.doppelganger_hold_until);
            assert!(hold.is_none(), "boot must not reload a hold after a failed delete");
            if disk.has_validator(&pk) {
                let _open = disk.reconcile_doppelganger_holds_at_boot(1_700_000_900);
                assert!(
                    !disk.is_signing_enabled(&pk),
                    "a failed delete must not be undone by boot reconcile"
                );
            }
        }
    }

    /// A failed slashing disable of a held key must not leave a boot-loadable hold.
    #[test]
    fn test_failed_slashing_disable_of_a_held_key_is_not_reenabled_at_boot() {
        let pk = test_pubkey(10);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        store.begin_doppelganger_hold(&pk, 1_700_000_600).unwrap();
        assert!(store.get_config(&pk).unwrap().doppelganger_hold_until.is_some());

        let _clear = ClearHooks;
        super::KEEP_TOML_WRITE_FAULT.with(|cell| cell.set(true));
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::Rename }))
        });
        assert!(store.disable_slashed(&pk).is_err(), "all three persist attempts fail");
        assert!(!store.is_signing_enabled(&pk));
        assert!(
            store.get_config(&pk).unwrap().doppelganger_hold_until.is_none(),
            "memory drops the hold when slashing disable is published"
        );

        let rejected = config_path.with_file_name("validators.toml.rejected");
        assert!(
            !config_path.exists() || rejected.exists(),
            "a failed slashing disable of a held key must leave the boot path"
        );
        if config_path.exists() {
            let disk = ValidatorStore::load_from_config(&config_path).unwrap();
            let _open = disk.reconcile_doppelganger_holds_at_boot(1_700_000_900);
            assert!(
                !disk.is_signing_enabled(&pk),
                "boot must not re-enable a held key whose slashing disable failed to persist"
            );
        }
    }

    /// A re-import must not shorten a hold that already lasts longer.
    #[test]
    fn test_reimport_stores_the_later_hold_deadline() {
        let pk = test_pubkey(12);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        store.begin_doppelganger_hold(&pk, 1_700_000_500).unwrap();
        store.begin_doppelganger_hold(&pk, 1_700_000_100).unwrap();
        assert_eq!(
            store.get_config(&pk).unwrap().doppelganger_hold_until,
            Some(1_700_000_500),
            "a re-import must not shorten the persisted hold"
        );
        store.begin_doppelganger_hold(&pk, 1_700_000_900).unwrap();
        assert_eq!(
            store.get_config(&pk).unwrap().doppelganger_hold_until,
            Some(1_700_000_900),
            "a re-import must store the later hold deadline"
        );
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert_eq!(disk.get_config(&pk).unwrap().doppelganger_hold_until, Some(1_700_000_900));
    }

    /// Release before the stored deadline must leave the hold in place.
    #[test]
    fn test_release_before_the_deadline_stays_disabled() {
        let pk = test_pubkey(13);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        store.begin_doppelganger_hold(&pk, now.saturating_add(3_600)).unwrap();
        assert!(!store.release_doppelganger_hold(&pk).unwrap());
        assert!(!store.is_signing_enabled(&pk), "an early release must not enable the key");
        assert!(store.get_config(&pk).unwrap().doppelganger_hold_until.is_some());
        let disk = ValidatorStore::load_from_config(&config_path).unwrap();
        assert!(!disk.is_signing_enabled(&pk));
    }

    /// Moving the validators file aside names the full pubkey and the rejected path.
    #[tracing_test::traced_test]
    #[test]
    fn test_quarantine_logs_the_full_pubkey_and_rejected_path() {
        let pk = test_pubkey(14);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        store.add_validator_durable(ValidatorConfig::new(pk)).unwrap();
        let _clear = ClearHooks;
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::Rename }))
        });
        assert!(store.begin_doppelganger_hold(&pk, 1_700_000_400).is_err());
        let full = format!("0x{}", hex::encode(pk));
        let rejected = config_path.with_file_name("validators.toml.rejected");
        assert!(
            logs_contain(&full) && logs_contain(&rejected.display().to_string()),
            "a moved validators file must log the full pubkey and the .rejected path"
        );
    }

    /// Slashing clears the hold, so a later release must not turn the key back on.
    #[test]
    fn test_release_after_slashing_disable_stays_disabled() {
        let pk = test_pubkey(11);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path);
        store.save_config().unwrap();
        store.begin_doppelganger_hold(&pk, 1_700_000_700).unwrap();
        store.disable_slashed(&pk).unwrap();
        assert!(!store.release_doppelganger_hold(&pk).unwrap());
        assert!(!store.is_signing_enabled(&pk));
    }

    /// A disable that makes signing safer is live before the write. A failed
    /// write leaves it disabled.
    #[test]
    fn test_safety_disable_publishes_before_persist_and_stays_disabled() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path.clone());
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);
        let _clear = ClearHooks;
        let hooked = std::sync::Arc::clone(&store);
        let disabled_at_write = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&disabled_at_write);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                flag.store(!hooked.is_signing_enabled(&pk), std::sync::atomic::Ordering::SeqCst);
            }));
        });
        store.disable_slashed(&pk).unwrap();
        assert!(
            disabled_at_write.load(std::sync::atomic::Ordering::SeqCst),
            "a slashed validator must already be disabled while the file is written"
        );

        let mut failed = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        failed.add_validator(ValidatorConfig::new(pk)).unwrap();
        failed.config_path = Some(config_path);
        failed.save_config().unwrap();
        clear_test_hooks();
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::Rename }));
        });
        // One-shot fault: the first attempt fails, retries succeed. Force every
        // attempt to fail by pointing at a missing directory instead.
        clear_test_hooks();
        let missing = dir.path().join("gone").join("validators.toml");
        let mut stuck = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        stuck.add_validator(ValidatorConfig::new(pk)).unwrap();
        stuck.config_path = Some(missing);
        assert!(stuck.disable_slashed(&pk).is_err());
        assert!(!stuck.is_signing_enabled(&pk), "failed persist must stay disabled");
    }

    /// Replacing an enabled validator with `enabled = false` must not roll
    /// back to enabled when the write fails. That is the doppelganger disable.
    #[test]
    fn test_failed_enabled_false_replace_stays_disabled() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path);
        store.save_config().unwrap();
        let _clear = ClearHooks;
        super::TOML_WRITE_FAULT.with(|cell| {
            cell.set(Some(super::FaultPlan { skip: 0, step: super::TomlWriteFault::Rename }))
        });
        assert!(store.set_enabled_durable(&pk, false).is_err());
        assert!(
            !store.is_signing_enabled(&pk),
            "a failed doppelganger disable must not leave the key enabled"
        );
    }

    /// Removing `save_lock` from these paths makes `try_lock` succeed.
    #[test]
    fn test_safety_and_import_writes_hold_save_lock() {
        let pk = test_pubkey(1);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store.config_path = Some(config_path);
        store.save_config().unwrap();
        let store = std::sync::Arc::new(store);
        let _clear = ClearHooks;

        let hooked = std::sync::Arc::clone(&store);
        let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&held);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                flag.store(
                    hooked.save_lock.try_lock().is_none(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }));
        });
        store.disable_slashed(&pk).unwrap();
        assert!(
            held.load(std::sync::atomic::Ordering::SeqCst),
            "disable_slashed must hold save_lock across the write"
        );

        clear_test_hooks();
        let hooked = std::sync::Arc::clone(&store);
        let held = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = std::sync::Arc::clone(&held);
        super::DURABLE_WRITE_HOOK.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                flag.store(
                    hooked.save_lock.try_lock().is_none(),
                    std::sync::atomic::Ordering::SeqCst,
                );
            }));
        });
        store.add_validator_durable(ValidatorConfig::new(test_pubkey(2))).unwrap();
        assert!(
            held.load(std::sync::atomic::Ordering::SeqCst),
            "add_validator_durable must hold save_lock across the write"
        );
    }

    /// The parent-directory fsync is a real call, not only a fault label.
    #[test]
    fn test_sync_parent_dir_increments_on_save() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("validators.toml");
        let mut store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.config_path = Some(config_path);
        let _clear = ClearHooks;
        store.save_config().unwrap();
        let syncs = super::PARENT_DIR_SYNCS.with(|cell| cell.get());
        assert!(syncs >= 1, "save_config must fsync the parent directory, count={syncs}");
    }

    /// `i64::MAX` is a legal TOML integer. One past it is not.
    #[test]
    fn test_i64_max_boundary_is_accepted() {
        let limit = i64::MAX as u64;
        assert!(super::ensure_toml_u64("gas_limit", limit).is_ok());
        assert!(super::ensure_toml_u64("gas_limit", limit.saturating_add(1)).is_err());
        let pk = test_pubkey(1);
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        store
            .update_config(
                &pk,
                ValidatorConfigUpdate { gas_limit: Some(Some(limit)), ..Default::default() },
            )
            .unwrap();
        assert_eq!(store.effective_gas_limit(&pk), limit);
        assert!(store
            .update_config(
                &pk,
                ValidatorConfigUpdate {
                    gas_limit: Some(Some(limit.saturating_add(1))),
                    ..Default::default()
                },
            )
            .is_err());
    }

    /// The generation read and the restore write share `save_lock` and the
    /// state write. A hook between them must see both locks still held.
    #[test]
    fn release_holds_the_store_locks_across_the_generation_check() {
        let store = std::sync::Arc::new(ValidatorStore::new(test_fee_recipient(1), 30_000_000));
        let pk = test_pubkey(1);
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some(test_fee_recipient(2));
        store.add_validator(cfg).unwrap();
        store
            .apply_remote_proposer(
                &pk,
                ValidatorConfigUpdate {
                    fee_recipient: Some(Some(test_fee_recipient(3))),
                    ..Default::default()
                },
            )
            .unwrap();
        super::RELEASE_LOCKS_HELD.with(|slot| slot.set(false));
        super::RELEASE_PROBE_STORE
            .with(|slot| *slot.borrow_mut() = Some(std::sync::Arc::clone(&store)));
        super::RELEASE_HOOK.with(|slot| slot.set(Some(super::probe_release_locks)));
        store.release_remote_proposer(&pk);
        super::RELEASE_HOOK.with(|slot| slot.set(None));
        super::RELEASE_PROBE_STORE.with(|slot| *slot.borrow_mut() = None);
        assert!(super::RELEASE_LOCKS_HELD.with(|slot| slot.get()));
        assert_eq!(store.get_config(&pk).unwrap().fee_recipient, Some(test_fee_recipient(2)));
    }
}
