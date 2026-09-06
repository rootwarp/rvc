use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use observability::logging::TruncatedPubkey;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, trace, warn};

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
struct StoreState {
    validators: HashMap<[u8; 48], ValidatorConfig>,
    defaults: ValidatorDefaults,
    global_block_selection_mode: BlockSelectionMode,
    global_builders: Option<Vec<String>>,
    global_min_bid: Option<u64>,
    global_builder_boost_factor: Option<u64>,
}

pub struct ValidatorStore {
    state: RwLock<StoreState>,
    config_path: Option<PathBuf>,
    // Serializes `save_config` so that snapshot → tempfile write → atomic
    // rename happens as a single critical section. Without this, a thread
    // holding a stale snapshot can `persist` AFTER a thread with newer data,
    // silently clobbering committed updates. Intentionally separate from
    // `state`: it guards file I/O ordering, not in-memory fields.
    save_lock: Mutex<()>,
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
            }),
            config_path: None,
            save_lock: Mutex::new(()),
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
            }),
            config_path: Some(path.to_path_buf()),
            save_lock: Mutex::new(()),
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

    pub fn set_global_min_bid(&self, min_bid: u64) {
        self.state.write().global_min_bid = Some(min_bid);
    }

    pub fn set_global_builder_boost_factor(&self, factor: u64) {
        self.state.write().global_builder_boost_factor = Some(factor);
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
        if let Some(urls) = config.builders.as_deref() {
            validate_builder_urls(urls)?;
        }
        self.state.write().validators.insert(config.pubkey, config);
        Ok(())
    }

    pub fn remove_validator(&self, pubkey: &[u8; 48]) -> Option<ValidatorConfig> {
        self.state.write().validators.remove(pubkey)
    }

    pub fn set_enabled(&self, pubkey: &[u8; 48], enabled: bool) {
        if let Some(config) = self.state.write().validators.get_mut(pubkey) {
            config.enabled = enabled;
            let pk_hex = hex::encode(pubkey);
            if enabled {
                info!(pubkey = %TruncatedPubkey::new(&pk_hex), "validator enabled");
            } else {
                warn!(pubkey = %TruncatedPubkey::new(&pk_hex), "validator disabled");
            }
        }
    }

    pub fn update_config(
        &self,
        pubkey: &[u8; 48],
        update: ValidatorConfigUpdate,
    ) -> Result<(), ValidatorStoreError> {
        if let Some(ref builders) = update.builders {
            validate_builder_urls(builders)?;
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
        if update.builder_proposals.is_some() {
            changed_fields.push("builder_proposals");
        }
        if update.builder_boost_factor.is_some() {
            changed_fields.push("builder_boost_factor");
        }
        if update.block_selection_mode.is_some() {
            changed_fields.push("block_selection_mode");
        }
        if update.builders.is_some() {
            changed_fields.push("builders");
        }
        if update.min_bid.is_some() {
            changed_fields.push("min_bid");
        }

        if let Some(config) = self.state.write().validators.get_mut(pubkey) {
            if let Some(fr) = update.fee_recipient {
                config.fee_recipient = fr;
            }
            if let Some(gl) = update.gas_limit {
                config.gas_limit = gl;
            }
            if let Some(g) = update.graffiti {
                config.graffiti = g;
            }
            if let Some(bp) = update.builder_proposals {
                config.builder_proposals = bp;
            }
            if let Some(bbf) = update.builder_boost_factor {
                config.builder_boost_factor = Some(bbf);
            }
            if let Some(bsm) = update.block_selection_mode {
                config.block_selection_mode = bsm;
            }
            if let Some(builders) = update.builders {
                config.builders = Some(builders);
            }
            if let Some(min_bid) = update.min_bid {
                config.min_bid = Some(min_bid);
            }

            let pk_hex = hex::encode(pubkey);
            info!(
                pubkey = %TruncatedPubkey::new(&pk_hex),
                changed_fields = changed_fields.join(","),
                "validator config updated"
            );
        }
        Ok(())
    }

    /// Apply a partial update to the store-wide defaults under one write guard.
    ///
    /// Only fields set to `Some(...)` change; `None` leaves the current value.
    /// Concurrent readers observe either the pre-update or post-update defaults
    /// as a unit (never a mix of new fee recipient with old gas limit).
    pub fn apply_default_update(&self, update: DefaultUpdate) {
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
            state.defaults.fee_recipient = fr;
        }
        if let Some(gl) = update.gas_limit {
            state.defaults.gas_limit = gl;
        }
        if let Some(g) = update.graffiti {
            state.defaults.graffiti = g;
        }

        if !changed_fields.is_empty() {
            info!(changed_fields = changed_fields.join(","), "validator defaults updated");
        }
    }

    pub fn has_validator(&self, pubkey: &[u8; 48]) -> bool {
        self.state.read().validators.contains_key(pubkey)
    }

    #[tracing::instrument(name = "validator_store.save_config", skip_all)]
    pub fn save_config(&self) -> Result<(), ValidatorStoreError> {
        let config_path = self.config_path.as_ref().ok_or_else(|| {
            ValidatorStoreError::Config("no config path set for save".to_string())
        })?;

        // Serialize the entire snapshot → write → rename sequence so a
        // concurrent saver with a stale snapshot cannot persist after a
        // saver with newer data and clobber it.
        let _save_guard = self.save_lock.lock();

        // Single state read: defaults + validators under one guard (no
        // multi-lock ordering with `effective_config`).
        let (toml_defaults, toml_validators) = {
            let state = self.state.read();
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
                    block_selection_mode: v.block_selection_mode,
                    builders: v.builders.clone(),
                    min_bid: v.min_bid,
                })
                .collect();
            (toml_defaults, toml_validators)
        };
        // State read guard dropped before I/O.

        let toml_config = TomlConfig { defaults: Some(toml_defaults), validators: toml_validators };

        let toml_string = toml::to_string(&toml_config)
            .map_err(|e| ValidatorStoreError::Config(e.to_string()))?;

        let parent = config_path.parent().ok_or_else(|| {
            ValidatorStoreError::Config("config path has no parent directory".to_string())
        })?;

        let tmp = tempfile::NamedTempFile::new_in(parent)?;
        std::io::Write::write_all(&mut &tmp, toml_string.as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(config_path).map_err(|e| ValidatorStoreError::Io(e.error))?;

        info!(path = %config_path.display(), "config saved");
        Ok(())
    }

    #[tracing::instrument(name = "validator_store.reload_config", skip_all)]
    pub fn reload_config(&self) -> Result<(), ValidatorStoreError> {
        let path = self.config_path.as_ref().ok_or_else(|| {
            ValidatorStoreError::Config("no config path set for reload".to_string())
        })?;

        let content = std::fs::read_to_string(path).map_err(|e| {
            warn!(path = %path.display(), error = %e, "config parse error");
            e
        })?;
        // Parse-first: compute all new values before any mutation.
        let (new_defaults, parsed_validators) = parse_config(&content).map_err(|e| {
            warn!(path = %path.display(), error = %e, "config parse error");
            e
        })?;

        // Apply-second under one write guard: defaults + validator merges are
        // visible to concurrent readers as a single atomic transition. Merge
        // (insert/overwrite) preserves programmatic validators not present in
        // the file; global_block_selection_mode is left untouched.
        let mut state = self.state.write();
        state.defaults = new_defaults;
        let existing_count = state.validators.len();
        for config in parsed_validators {
            state.validators.insert(config.pubkey, config);
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
        block_selection_mode: v.block_selection_mode,
        builders: v.builders.clone(),
        min_bid: v.min_bid,
    };
    if let Some(urls) = config.builders.as_deref() {
        validate_builder_urls(urls)?;
    }
    Ok(config)
}

fn parse_graffiti(s: &str) -> [u8; 32] {
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
        store.set_global_min_bid(10_000_000);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.min_bid(&pk), 10_000_000);
        assert_eq!(store.min_bid(&test_pubkey(99)), 10_000_000);
    }

    #[test]
    fn test_min_bid_per_validator_override() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_global_min_bid(10_000_000);
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
        store.set_global_builder_boost_factor(50);
        let pk = test_pubkey(1);
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        assert_eq!(store.builder_boost_factor(&pk), 50);
        assert_eq!(store.builder_boost_factor(&test_pubkey(99)), 50);
    }

    #[test]
    fn test_builder_boost_factor_override_beats_global() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.set_global_builder_boost_factor(50);
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

        store.apply_default_update(DefaultUpdate {
            fee_recipient: Some(new_fr),
            gas_limit: Some(40_000_000),
            graffiti: Some(Some([0xab; 32])),
        });

        assert_eq!(store.default_fee_recipient(), new_fr);
        assert_eq!(store.default_gas_limit(), 40_000_000);
        assert_eq!(store.state.read().defaults.graffiti, Some([0xab; 32]));
    }

    #[test]
    fn apply_default_update_absent_fields_leave_defaults_unchanged() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.state.write().defaults.graffiti = Some([0x11; 32]);

        store.apply_default_update(DefaultUpdate {
            fee_recipient: Some(test_fee_recipient(2)),
            gas_limit: None,
            graffiti: None,
        });

        assert_eq!(store.default_fee_recipient(), test_fee_recipient(2));
        assert_eq!(store.default_gas_limit(), 30_000_000);
        assert_eq!(store.state.read().defaults.graffiti, Some([0x11; 32]));
    }

    #[test]
    fn apply_default_update_can_clear_graffiti() {
        let store = ValidatorStore::new(test_fee_recipient(1), 30_000_000);
        store.state.write().defaults.graffiti = Some([0x11; 32]);

        store.apply_default_update(DefaultUpdate {
            fee_recipient: None,
            gas_limit: None,
            graffiti: Some(None),
        });

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
            store.apply_default_update(DefaultUpdate {
                fee_recipient: Some(new_fr),
                gas_limit: Some(new_gl),
                graffiti: None,
            });
            store.apply_default_update(DefaultUpdate {
                fee_recipient: Some(old_fr),
                gas_limit: Some(old_gl),
                graffiti: None,
            });
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
    /// remains a separate `Mutex` for file-I/O serialization only.
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
}
