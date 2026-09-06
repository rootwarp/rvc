//! Configuration types for the validator client.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use bn_manager::BnRole;
use observability::hex::{strip_prefix_strict, HexError};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use tracing::warn;

use url::Url;

use beacon::ResponseCaps;

use super::error::ConfigError;
use super::network::Network;
use super::start::StartArgs;
use rvc_config::ConfigSource;
use slashing::GroupCommitConfig;

pub use rvc_config::{
    BeaconArgs, BeaconConfig, BuilderLimits, BuilderLimitsArgs, BuilderSettings,
    ForkScheduleConfig, GcpSecretArgs, GcpSecretConfig, GrpcSignerArgs, GrpcSignerConfig,
    KeymanagerArgs, KeymanagerConfig, KeysArgs, KeysConfig, LogfileArgs, LogfileConfig,
    MonitoringArgs, MonitoringConfig, NetworkArgs, NetworkConfig, ProposerConfigArgs,
    ProposerConfigSource, SafetyArgs, SafetyConfig, SecretProviderArgs, SecretProviderConfig,
    ServerArgs, ServerConfig, SlashedAction, SlashingArgs, SlashingConfig, TimingConfig,
    TracingArgs, TracingConfig, TracingExporter,
};

/// Message types that may be broadcast to all beacon nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BroadcastTopic {
    Attestations,
    Blocks,
    SyncCommittee,
    Subscriptions,
    /// Disable all broadcast (must appear alone).
    None,
}

impl fmt::Display for BroadcastTopic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Attestations => write!(f, "attestations"),
            Self::Blocks => write!(f, "blocks"),
            Self::SyncCommittee => write!(f, "sync-committee"),
            Self::Subscriptions => write!(f, "subscriptions"),
            Self::None => write!(f, "none"),
        }
    }
}

impl FromStr for BroadcastTopic {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "attestations" => Ok(Self::Attestations),
            "blocks" => Ok(Self::Blocks),
            "sync-committee" => Ok(Self::SyncCommittee),
            "subscriptions" => Ok(Self::Subscriptions),
            "none" => Ok(Self::None),
            other => Err(format!(
                "invalid broadcast topic '{other}': must be one of attestations, blocks, sync-committee, subscriptions, none"
            )),
        }
    }
}

/// Validator client configuration.
///
/// Related knobs are grouped into nested sub-structs (`logfile`, `tracing`,
/// `keymanager`, `grpc_signer`, `proposer_config`, `monitoring`,
/// `builder_limits`, `timing`, `fork_schedule`). ARCH-4h invents `[beacon]` / `[server]` /
/// `[network]` / `[safety]` / `[slashing]` / `[keys]` on the wire; `Config`'s
/// public / serialize shape stays flat so ARCH-4d snapshots stay byte-identical.
/// Existing operator TOML may still use the **flat** keys; both spellings are
/// accepted (see `ConfigWire`).
#[derive(Debug, Clone, Serialize)]
#[serde(default)]
pub struct Config {
    pub beacon_url: String,

    #[serde(default)]
    pub beacon_nodes: Vec<String>,

    pub keystore_path: PathBuf,

    pub password_file: Option<PathBuf>,

    pub slashing_db_path: PathBuf,

    /// Allow creating a fresh empty slashing-protection DB when the path is
    /// missing (SEC-3).
    ///
    /// Default `false`: a missing DB aborts startup so a lost volume, path typo,
    /// or ephemeral container storage cannot silently produce zero-history
    /// signing. Set via config `allow_fresh_db = true` or CLI
    /// `--init-slashing-db`. A 0-byte / corrupt-header file is **always** a hard
    /// error regardless of this flag. Never wipes a non-empty DB.
    #[serde(default)]
    pub allow_fresh_db: bool,

    /// Max slashing-DB reserve checks per COMMIT. `None` uses the measured default of 50.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_commit_batch_size: Option<usize>,

    /// Milliseconds to wait for a group-commit batch to fill. `None` uses 1 ms; 0 disables wait.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_commit_wait_to_fill_ms: Option<u64>,

    /// Allow startup when the beacon node's current fork version is not in the
    /// client's fork schedule (SEC-9 / M-15).
    ///
    /// Default `false`: an unknown fork aborts startup so the VC cannot produce
    /// invalid signatures after a network upgrade. Set `true` only for testnets
    /// or experimental forks where the schedule is intentionally incomplete.
    #[serde(default)]
    pub allow_unsupported_fork: bool,

    pub metrics_address: IpAddr,

    pub metrics_port: u16,

    pub network: Network,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_time: Option<u64>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_validators_root: Option<String>,

    pub graffiti: Option<String>,

    pub log_level: String,

    pub doppelganger_detection: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_decrypt_threads: Option<usize>,

    #[serde(default)]
    pub secret_provider: SecretProviderConfig,

    #[serde(default)]
    pub disable_attesting: bool,

    #[serde(default)]
    pub slashed_validators_action: SlashedAction,

    #[serde(default)]
    pub disable_keystore_locking: bool,

    // --- Nested groups (source of truth for serde + RF5-13 call sites) ---
    #[serde(default)]
    pub logfile: LogfileConfig,

    #[serde(default)]
    pub tracing: TracingConfig,

    #[serde(default)]
    pub keymanager: KeymanagerConfig,

    #[serde(default)]
    pub grpc_signer: GrpcSignerConfig,

    #[serde(default)]
    pub proposer_config: ProposerConfigSource,

    #[serde(default)]
    pub monitoring: MonitoringConfig,

    #[serde(default)]
    pub builder_limits: BuilderLimits,

    /// Global builder URLs / min_bid for produceBlockV4 (`[builder]`).
    #[serde(default, skip_serializing_if = "BuilderSettings::is_default")]
    pub builder: BuilderSettings,

    #[serde(default)]
    pub timing: TimingConfig,

    /// Local Gloas schedule; reconciled against the BN spec at startup.
    #[serde(default)]
    pub fork_schedule: ForkScheduleConfig,

    // --- Proposer nodes / broadcast (remain flat) ---
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proposer_nodes: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub broadcast: Vec<BroadcastTopic>,

    // --- Health tier fields (T4.5/T4.8) ---
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bn_sync_tolerances: Option<String>,

    // --- Role-based BN fields (T4.9/T4.11) ---
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub beacon_nodes_config: Vec<BeaconNodeEntry>,

    // --- Block selection mode (T4.1/T4.4) ---
    #[serde(default)]
    pub block_selection_mode: validator_store::BlockSelectionMode,

    // --- Registration batching (T4.12/T4.13) ---
    #[serde(default = "default_validator_registration_batch_size")]
    pub validator_registration_batch_size: usize,

    #[serde(default = "default_validator_registration_batch_delay")]
    pub validator_registration_batch_delay: u64,

    // --- Validator per-validator config (ISSUE-2.1 / H-1) ---
    /// Path to a TOML file containing per-validator and default fee_recipient /
    /// gas_limit overrides.  rvc refuses to start if `default_fee_recipient`
    /// resolves to the zero address (0x000…000).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validators_config: Option<PathBuf>,

    // --- BN HTTP caps (ISSUE-2.13 / H-12) ---
    /// Maximum JSON response body size in bytes from the beacon node (H-12).
    ///
    /// Requests whose body (or `Content-Length`) exceeds this value are rejected before
    /// the full body is allocated.  Default: 32 MiB.
    #[serde(default = "default_beacon_max_body_bytes")]
    pub beacon_max_body_bytes: usize,

    // --- BN operation timeouts (ARCH-4j) ---
    // Seconds; `None` folds to `OperationTimeouts::default()` (A-4.12).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_production_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aggregate_timeout: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duty_fetch_timeout: Option<u64>,
}

fn default_beacon_max_body_bytes() -> usize {
    ResponseCaps::DEFAULT_MAX_BODY_BYTES
}

/// Per-BN configuration entry for `[[beacon_nodes]]` TOML tables.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconNodeEntry {
    pub url: String,
    #[serde(default = "default_bn_roles")]
    pub roles: Vec<BnRole>,
}

fn default_bn_roles() -> Vec<BnRole> {
    vec![BnRole::All]
}

fn default_validator_registration_batch_size() -> usize {
    500
}

fn default_validator_registration_batch_delay() -> u64 {
    500
}

impl Default for Config {
    fn default() -> Self {
        Self {
            beacon_url: "http://localhost:5052".to_string(),
            beacon_nodes: Vec::new(),
            keystore_path: PathBuf::from("./keystores"),
            password_file: None,
            slashing_db_path: PathBuf::from("./slashing_protection.sqlite"),
            allow_fresh_db: false,
            group_commit_batch_size: None,
            group_commit_wait_to_fill_ms: None,
            allow_unsupported_fork: false,
            metrics_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            metrics_port: 8080,
            network: Network::Mainnet,
            genesis_time: None,
            genesis_validators_root: None,
            graffiti: None,
            log_level: "info".to_string(),
            doppelganger_detection: true,
            key_decrypt_threads: None,
            secret_provider: SecretProviderConfig::default(),
            disable_attesting: false,
            slashed_validators_action: SlashedAction::default(),
            disable_keystore_locking: false,
            logfile: LogfileConfig::default(),
            tracing: TracingConfig::default(),
            keymanager: KeymanagerConfig::default(),
            grpc_signer: GrpcSignerConfig::default(),
            proposer_config: ProposerConfigSource::default(),
            monitoring: MonitoringConfig::default(),
            builder_limits: BuilderLimits::default(),
            builder: BuilderSettings::default(),
            timing: TimingConfig::default(),
            fork_schedule: ForkScheduleConfig::default(),
            proposer_nodes: Vec::new(),
            broadcast: Vec::new(),
            bn_sync_tolerances: None,
            beacon_nodes_config: Vec::new(),
            block_selection_mode: validator_store::BlockSelectionMode::default(),
            validator_registration_batch_size: default_validator_registration_batch_size(),
            validator_registration_batch_delay: default_validator_registration_batch_delay(),
            validators_config: None,
            beacon_max_body_bytes: default_beacon_max_body_bytes(),
            block_production_timeout: None,
            attestation_timeout: None,
            aggregate_timeout: None,
            duty_fetch_timeout: None,
        }
    }
}

/// `[beacon]` table plus the TOML-only `beacon_nodes_config` array (names
/// [`BnRole`], so it cannot live on `rvc-config::BeaconConfig`).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct BeaconSection {
    #[serde(flatten)]
    inner: BeaconConfig,
    #[serde(default)]
    beacon_nodes_config: Vec<BeaconNodeEntry>,
}

/// `[server]` table plus leftover-key sentinels.
///
/// Without these fields a leftover `[server] grpc_port` would parse silently
/// (`#[serde(default)]`, no `deny_unknown_fields`).
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ServerSection {
    #[serde(flatten)]
    inner: ServerConfig,
    grpc_port: Option<toml::Value>,
    grpc_address: Option<toml::Value>,
}

/// Replacement probes named in `ConfigError::RemovedKey`.
const GRPC_KEY_REPLACEMENT: &str = "GET /health and GET /readyz on the metrics HTTP server";

/// Intermediate wire format that accepts **both** nested tables and legacy flat
/// keys. Flat keys fill fields that the corresponding nested table left at
/// default; when both spellings set the same logical field, the **flat** key
/// wins (operators with existing files keep working without edits).
///
/// ARCH-4h: shrinks to the flat→section lift for the 22 newly sectioned knobs
/// plus the 31 4f/4g legacy keys (VD-4.1). Not deleted — serde `alias` cannot
/// lift a top-level key into a nested table.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConfigWire {
    beacon_url: String,
    beacon_nodes: Vec<String>,
    keystore_path: PathBuf,
    password_file: Option<PathBuf>,
    slashing_db_path: PathBuf,
    /// `Option` so a nested `[slashing] allow_fresh_db` can fill when the
    /// flat key is absent (bool would treat absent as `false` and clobber).
    allow_fresh_db: Option<bool>,
    allow_unsupported_fork: Option<bool>,
    metrics_address: Option<IpAddr>,
    metrics_port: Option<u16>,
    /// Presence must fail startup; otherwise leftover TOML is ignored.
    grpc_port: Option<toml::Value>,
    grpc_address: Option<toml::Value>,
    // `network` as a flat string is pulled in Config's custom Deserialize
    // (dual-shape with `[network]` — same class as `logfile`).
    genesis_time: Option<u64>,
    genesis_validators_root: Option<String>,
    graffiti: Option<String>,
    log_level: Option<String>,
    doppelganger_detection: Option<bool>,
    key_decrypt_threads: Option<usize>,
    secret_provider: SecretProviderConfig,
    disable_attesting: Option<bool>,
    slashed_validators_action: Option<SlashedAction>,
    disable_keystore_locking: Option<bool>,
    proposer_nodes: Vec<String>,
    broadcast: Vec<BroadcastTopic>,
    bn_sync_tolerances: Option<String>,
    beacon_nodes_config: Vec<BeaconNodeEntry>,
    block_selection_mode: validator_store::BlockSelectionMode,
    validator_registration_batch_size: Option<usize>,
    validator_registration_batch_delay: Option<u64>,
    validators_config: Option<PathBuf>,
    beacon_max_body_bytes: Option<usize>,
    block_production_timeout: Option<u64>,
    attestation_timeout: Option<u64>,
    aggregate_timeout: Option<u64>,
    duty_fetch_timeout: Option<u64>,

    // Nested tables (4f/4g + invented 4h sections). Flat keys above win.
    #[serde(default)]
    beacon: BeaconSection,
    #[serde(default)]
    keys: KeysConfig,
    #[serde(default)]
    server: ServerSection,
    /// Table half of the `network` dual-shape (string pulled in Deserialize).
    #[serde(default)]
    network: NetworkConfig,
    #[serde(default)]
    safety: SafetyConfig,
    #[serde(default)]
    slashing: SlashingConfig,
    #[serde(default)]
    logfile: LogfileConfig,
    #[serde(default)]
    tracing: TracingConfig,
    #[serde(default)]
    keymanager: KeymanagerConfig,
    #[serde(default)]
    grpc_signer: GrpcSignerConfig,
    #[serde(default)]
    proposer_config: ProposerConfigSource,
    #[serde(default)]
    monitoring: MonitoringConfig,
    #[serde(default)]
    builder_limits: BuilderLimits,
    #[serde(default)]
    builder: BuilderSettings,
    #[serde(default)]
    timing: TimingConfig,
    #[serde(default)]
    fork_schedule: ForkScheduleConfig,

    // Flat legacy keys (old spelling) — Option so we can detect presence
    keymanager_enabled: Option<bool>,
    keymanager_address: Option<String>,
    keymanager_token_file: Option<PathBuf>,
    remote_signer_url: Option<String>,
    remote_signer_allowed_hosts: Option<Vec<String>>,
    allow_insecure_remote_signer: Option<bool>,
    keymanager_cors_origins: Option<Vec<String>>,
    keymanager_body_limit: Option<usize>,
    tracing_endpoint: Option<String>,
    tracing_exporter: Option<TracingExporter>,
    tracing_sample_rate: Option<f64>,
    tracing_max_queue_size: Option<usize>,
    tracing_max_export_batch_size: Option<usize>,
    grpc_signer_url: Option<String>,
    grpc_signer_tls_cert: Option<PathBuf>,
    grpc_signer_tls_key: Option<PathBuf>,
    grpc_signer_tls_ca_cert: Option<PathBuf>,
    builder_circuit_breaker_consecutive_limit: Option<u32>,
    builder_circuit_breaker_epoch_limit: Option<u32>,
    monitoring_endpoint: Option<String>,
    monitoring_interval: Option<u64>,
    monitoring_endpoint_insecure: Option<bool>,
    proposer_config_url: Option<String>,
    proposer_config_file: Option<String>,
    proposer_config_refresh_interval: Option<u64>,
    proposer_config_url_token: Option<String>,
    proposer_config_url_insecure: Option<bool>,
    logfile_max_size: Option<u64>,
    logfile_max_number: Option<usize>,
    logfile_compress: Option<bool>,
    logfile_level: Option<String>,
}

fn removed_grpc_key(w: &ConfigWire) -> Option<&'static str> {
    if w.grpc_port.is_some() || w.server.grpc_port.is_some() {
        Some("grpc_port")
    } else if w.grpc_address.is_some() || w.server.grpc_address.is_some() {
        Some("grpc_address")
    } else {
        None
    }
}

impl Config {
    fn from_wire(w: ConfigWire) -> Result<Self, ConfigError> {
        if let Some(key) = removed_grpc_key(&w) {
            return Err(ConfigError::RemovedKey { key, replacement: GRPC_KEY_REPLACEMENT });
        }
        let mut logfile = w.logfile;
        if let Some(v) = w.logfile_max_size {
            logfile.max_size = v;
        }
        if let Some(v) = w.logfile_max_number {
            logfile.max_number = v;
        }
        if let Some(v) = w.logfile_compress {
            logfile.compress = v;
        }
        if let Some(v) = w.logfile_level {
            logfile.level = Some(v);
        }
        // flat path handled in custom deserialize (toml Value path)

        let mut tracing = w.tracing;
        if let Some(v) = w.tracing_endpoint {
            tracing.endpoint = Some(v);
        }
        if let Some(v) = w.tracing_exporter {
            tracing.exporter = v;
        }
        if let Some(v) = w.tracing_sample_rate {
            tracing.sample_rate = Some(v);
        }
        if let Some(v) = w.tracing_max_queue_size {
            tracing.max_queue_size = Some(v);
        }
        if let Some(v) = w.tracing_max_export_batch_size {
            tracing.max_export_batch_size = Some(v);
        }

        let mut keymanager = w.keymanager;
        if let Some(v) = w.keymanager_enabled {
            keymanager.enabled = v;
        }
        if let Some(v) = w.keymanager_address {
            keymanager.address = Some(v);
        }
        if let Some(v) = w.keymanager_token_file {
            keymanager.token_file = Some(v);
        }
        if let Some(v) = w.remote_signer_url {
            keymanager.remote_signer_url = Some(v);
        }
        if let Some(v) = w.remote_signer_allowed_hosts {
            keymanager.remote_signer_allowed_hosts = Some(v);
        }
        if let Some(v) = w.allow_insecure_remote_signer {
            keymanager.allow_insecure_remote_signer = v;
        }
        if let Some(v) = w.keymanager_cors_origins {
            keymanager.cors_origins = v;
        }
        if let Some(v) = w.keymanager_body_limit {
            keymanager.body_limit = v;
        }

        let mut grpc_signer = w.grpc_signer;
        if let Some(v) = w.grpc_signer_url {
            grpc_signer.url = Some(v);
        }
        if let Some(v) = w.grpc_signer_tls_cert {
            grpc_signer.tls_cert = Some(v);
        }
        if let Some(v) = w.grpc_signer_tls_key {
            grpc_signer.tls_key = Some(v);
        }
        if let Some(v) = w.grpc_signer_tls_ca_cert {
            grpc_signer.tls_ca_cert = Some(v);
        }

        let mut proposer_config = w.proposer_config;
        if let Some(v) = w.proposer_config_url {
            proposer_config.url = Some(v);
        }
        if let Some(v) = w.proposer_config_file {
            proposer_config.file = Some(v);
        }
        if let Some(v) = w.proposer_config_refresh_interval {
            proposer_config.refresh_interval = v;
        }
        if let Some(v) = w.proposer_config_url_token {
            proposer_config.url_token = Some(v);
        }
        if let Some(v) = w.proposer_config_url_insecure {
            proposer_config.url_insecure = v;
        }

        let mut monitoring = w.monitoring;
        if let Some(v) = w.monitoring_endpoint {
            monitoring.endpoint = Some(v);
        }
        if let Some(v) = w.monitoring_interval {
            monitoring.interval = v;
        }
        if let Some(v) = w.monitoring_endpoint_insecure {
            monitoring.endpoint_insecure = v;
        }

        let mut builder_limits = w.builder_limits;
        if let Some(v) = w.builder_circuit_breaker_consecutive_limit {
            builder_limits.circuit_breaker_consecutive_limit = v;
        }
        if let Some(v) = w.builder_circuit_breaker_epoch_limit {
            builder_limits.circuit_breaker_epoch_limit = v;
        }

        let def = Config::default();
        // Flat-wins lift (VD-4.1): nested 4h tables fill only when the flat
        // key is absent. The `network` string-or-table split is applied in
        // Deserialize (same class as `logfile`).
        Ok(Config {
            beacon_url: if !w.beacon_url.is_empty() {
                w.beacon_url
            } else {
                w.beacon.inner.url.unwrap_or(def.beacon_url)
            },
            beacon_nodes: if !w.beacon_nodes.is_empty() {
                w.beacon_nodes
            } else {
                w.beacon.inner.nodes
            },
            keystore_path: if !w.keystore_path.as_os_str().is_empty() {
                w.keystore_path
            } else {
                w.keys.keystore_path.unwrap_or(def.keystore_path)
            },
            password_file: w.password_file.or(w.keys.password_file),
            slashing_db_path: if !w.slashing_db_path.as_os_str().is_empty() {
                w.slashing_db_path
            } else {
                w.slashing.slashing_db_path.unwrap_or(def.slashing_db_path)
            },
            allow_fresh_db: w
                .allow_fresh_db
                .or(w.slashing.allow_fresh_db)
                .unwrap_or(def.allow_fresh_db),
            group_commit_batch_size: w.slashing.group_commit_batch_size,
            group_commit_wait_to_fill_ms: w.slashing.group_commit_wait_to_fill_ms,
            allow_unsupported_fork: w
                .allow_unsupported_fork
                .or(w.safety.allow_unsupported_fork)
                .unwrap_or(def.allow_unsupported_fork),
            metrics_address: w
                .metrics_address
                .or(w.server.inner.metrics_address)
                .unwrap_or(def.metrics_address),
            metrics_port: w
                .metrics_port
                .or(w.server.inner.metrics_port)
                .unwrap_or(def.metrics_port),
            network: w.network.network.unwrap_or(def.network),
            genesis_time: w.genesis_time.or(w.network.genesis_time),
            genesis_validators_root: w
                .genesis_validators_root
                .or(w.network.genesis_validators_root),
            graffiti: w.graffiti.or(w.network.graffiti),
            log_level: w.log_level.unwrap_or(def.log_level),
            doppelganger_detection: w
                .doppelganger_detection
                .or(w.safety.doppelganger_detection)
                .unwrap_or(def.doppelganger_detection),
            key_decrypt_threads: w.key_decrypt_threads.or(w.keys.key_decrypt_threads),
            secret_provider: w.secret_provider,
            disable_attesting: w
                .disable_attesting
                .or(w.safety.disable_attesting)
                .unwrap_or(def.disable_attesting),
            slashed_validators_action: w
                .slashed_validators_action
                .or(w.safety.slashed_validators_action)
                .unwrap_or(def.slashed_validators_action),
            disable_keystore_locking: w
                .disable_keystore_locking
                .or(w.keys.disable_keystore_locking)
                .unwrap_or(def.disable_keystore_locking),
            logfile,
            tracing,
            keymanager,
            grpc_signer,
            proposer_config,
            monitoring,
            builder_limits,
            builder: w.builder,
            timing: w.timing,
            fork_schedule: w.fork_schedule,
            proposer_nodes: w.proposer_nodes,
            broadcast: w.broadcast,
            bn_sync_tolerances: w.bn_sync_tolerances.or(w.beacon.inner.bn_sync_tolerances),
            beacon_nodes_config: if !w.beacon_nodes_config.is_empty() {
                w.beacon_nodes_config
            } else {
                w.beacon.beacon_nodes_config
            },
            block_selection_mode: w.block_selection_mode,
            validator_registration_batch_size: w
                .validator_registration_batch_size
                .unwrap_or(def.validator_registration_batch_size),
            validator_registration_batch_delay: w
                .validator_registration_batch_delay
                .unwrap_or(def.validator_registration_batch_delay),
            validators_config: w.validators_config.or(w.keys.validators_config),
            beacon_max_body_bytes: w
                .beacon_max_body_bytes
                .or(w.beacon.inner.max_body_bytes)
                .unwrap_or(def.beacon_max_body_bytes),
            block_production_timeout: w
                .block_production_timeout
                .or(w.beacon.inner.block_production_timeout),
            attestation_timeout: w.attestation_timeout.or(w.beacon.inner.attestation_timeout),
            aggregate_timeout: w.aggregate_timeout.or(w.beacon.inner.aggregate_timeout),
            duty_fetch_timeout: w.duty_fetch_timeout.or(w.beacon.inner.duty_fetch_timeout),
        })
    }

    fn from_toml_value(value: toml::Value) -> Result<Self, ConfigError> {
        let mut map = match value {
            toml::Value::Table(t) => t,
            other => {
                return Err(ConfigError::Invalid {
                    field: "config",
                    message: format!("config must be a TOML table, got {other:?}"),
                    source_layer: ConfigSource::Default,
                });
            }
        };

        let flat_logfile_path = match map.remove("logfile") {
            Some(toml::Value::String(s)) => Some(PathBuf::from(s)),
            Some(toml::Value::Table(t)) => {
                map.insert("logfile".into(), toml::Value::Table(t));
                None
            }
            Some(other) => {
                return Err(ConfigError::Invalid {
                    field: "logfile",
                    message: format!("logfile must be a string path or a table, got {other:?}"),
                    source_layer: ConfigSource::Default,
                });
            }
            None => None,
        };

        let flat_network = match map.remove("network") {
            Some(toml::Value::String(s)) => Some(
                Network::deserialize(toml::Value::String(s)).map_err(ConfigError::ParseError)?,
            ),
            Some(toml::Value::Table(t)) => {
                map.insert("network".into(), toml::Value::Table(t));
                None
            }
            Some(other) => {
                return Err(ConfigError::Invalid {
                    field: "network",
                    message: format!("network must be a string preset or a table, got {other:?}"),
                    source_layer: ConfigSource::Default,
                });
            }
            None => None,
        };

        let wire: ConfigWire =
            ConfigWire::deserialize(toml::Value::Table(map)).map_err(ConfigError::ParseError)?;
        let mut cfg = Self::from_wire(wire)?;
        if let Some(path) = flat_logfile_path {
            cfg.logfile.path = Some(path);
        }
        if let Some(net) = flat_network {
            cfg.network = net;
        }
        Ok(cfg)
    }
}

impl<'de> Deserialize<'de> for Config {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = toml::Value::deserialize(deserializer)?;
        Config::from_toml_value(value).map_err(serde::de::Error::custom)
    }
}

fn csv_items(csv: &str) -> Vec<String> {
    csv.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        if !path.exists() {
            return Err(ConfigError::FileNotFound(path.to_path_buf()));
        }

        let content = fs::read_to_string(path)?;
        let value: toml::Value = toml::from_str(&content)?;
        Self::from_toml_value(value)
    }

    pub fn effective_genesis_time(&self) -> Result<u64, ConfigError> {
        if let Some(genesis_time) = self.genesis_time {
            return Ok(genesis_time);
        }

        self.network
            .genesis_time()
            .ok_or_else(|| ConfigError::MissingField("genesis_time".to_string()))
    }

    pub fn effective_genesis_validators_root(&self) -> Result<String, ConfigError> {
        if let Some(ref root) = self.genesis_validators_root {
            return Ok(root.clone());
        }

        self.network
            .genesis_validators_root()
            .ok_or_else(|| ConfigError::MissingField("genesis_validators_root".to_string()))
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.beacon_url.is_empty() {
            return Err(ConfigError::InvalidBeaconUrl("beacon URL cannot be empty".to_string()));
        }

        if !self.beacon_url.starts_with("http://") && !self.beacon_url.starts_with("https://") {
            return Err(ConfigError::InvalidBeaconUrl(format!(
                "beacon URL must start with http:// or https://: {}",
                self.beacon_url
            )));
        }

        for node_url in &self.beacon_nodes {
            if node_url.is_empty() {
                return Err(ConfigError::InvalidBeaconUrl(
                    "beacon_nodes entry cannot be empty".to_string(),
                ));
            }
            if !node_url.starts_with("http://") && !node_url.starts_with("https://") {
                return Err(ConfigError::InvalidBeaconUrl(format!(
                    "beacon_nodes entry must start with http:// or https://: {}",
                    node_url
                )));
            }
        }

        if self.metrics_port == 0 {
            return Err(ConfigError::InvalidPort(self.metrics_port));
        }

        if let Some(ref graffiti) = self.graffiti {
            if graffiti.len() > 32 {
                return Err(ConfigError::InvalidGraffiti(
                    "graffiti must be 32 bytes or less".to_string(),
                ));
            }
        }

        if self.secret_provider.providers.contains(&"gcp".to_string()) {
            match &self.secret_provider.gcp.project_id {
                None => {
                    return Err(ConfigError::MissingField(
                        "gcp_project_id is required when secret_providers contains 'gcp'"
                            .to_string(),
                    ));
                }
                Some(id) if id.trim().is_empty() => {
                    return Err(ConfigError::MissingField(
                        "gcp_project_id must not be empty or whitespace-only".to_string(),
                    ));
                }
                _ => {}
            }
        }

        self.effective_genesis_time()?;
        self.effective_genesis_validators_root()?;

        if self.keymanager.allow_insecure_remote_signer {
            self.validate_insecure_env_var()?;
        }

        // Validate proposer_config_url and proposer_config_file mutual exclusivity
        if self.proposer_config.url.is_some() && self.proposer_config.file.is_some() {
            return Err(ConfigError::MissingField(
                "--proposer-config-url and --proposer-config-file are mutually exclusive; use only one".to_string(),
            ));
        }

        // Broadcast topic values are typed (serde / FromStr). Cross-field rule only:
        // `none` cannot be combined with other topics.
        if self.broadcast.contains(&BroadcastTopic::None) && self.broadcast.len() > 1 {
            return Err(ConfigError::MissingField(
                "broadcast topic 'none' cannot be combined with other topics".to_string(),
            ));
        }

        if self.block_production_timeout == Some(0) {
            return Err(ConfigError::MissingField(
                "--block-production-timeout must be greater than 0".to_string(),
            ));
        }
        if self.attestation_timeout == Some(0) {
            return Err(ConfigError::MissingField(
                "--attestation-timeout must be greater than 0".to_string(),
            ));
        }
        if self.aggregate_timeout == Some(0) {
            return Err(ConfigError::MissingField(
                "--aggregate-timeout must be greater than 0".to_string(),
            ));
        }
        if self.duty_fetch_timeout == Some(0) {
            return Err(ConfigError::MissingField(
                "--duty-fetch-timeout must be greater than 0".to_string(),
            ));
        }
        if let Err(e) = GroupCommitConfig::try_from_knobs(
            self.group_commit_batch_size,
            self.group_commit_wait_to_fill_ms,
        ) {
            return Err(ConfigError::MissingField(e.to_string()));
        }

        for (field, value) in [
            ("timing.attestation_due_bps", self.timing.attestation_due_bps),
            ("timing.aggregate_due_bps", self.timing.aggregate_due_bps),
            ("timing.attestation_due_bps_gloas", self.timing.attestation_due_bps_gloas),
            ("timing.aggregate_due_bps_gloas", self.timing.aggregate_due_bps_gloas),
            ("timing.sync_message_due_bps_gloas", self.timing.sync_message_due_bps_gloas),
            ("timing.contribution_due_bps_gloas", self.timing.contribution_due_bps_gloas),
            ("timing.payload_due_bps", self.timing.payload_due_bps),
            ("timing.payload_attestation_due_bps", self.timing.payload_attestation_due_bps),
        ] {
            if !(1..=10000).contains(&value) {
                return Err(ConfigError::Invalid {
                    field,
                    message: format!("must be 1..=10000, got {value}"),
                    source_layer: ConfigSource::Default,
                });
            }
        }

        if self.timing.attestation_due_bps_gloas > self.timing.aggregate_due_bps_gloas {
            return Err(ConfigError::Invalid {
                field: "timing.aggregate_due_bps_gloas",
                message: format!(
                    "must be >= timing.attestation_due_bps_gloas ({}), got {}",
                    self.timing.attestation_due_bps_gloas, self.timing.aggregate_due_bps_gloas
                ),
                source_layer: ConfigSource::Default,
            });
        }
        if self.timing.aggregate_due_bps_gloas > self.timing.payload_attestation_due_bps {
            return Err(ConfigError::Invalid {
                field: "timing.payload_attestation_due_bps",
                message: format!(
                    "must be >= timing.aggregate_due_bps_gloas ({}), got {}",
                    self.timing.aggregate_due_bps_gloas, self.timing.payload_attestation_due_bps
                ),
                source_layer: ConfigSource::Default,
            });
        }

        self.builder.validate()?;

        // Validate proposer node URLs
        for node_url in &self.proposer_nodes {
            if node_url.is_empty() {
                return Err(ConfigError::InvalidBeaconUrl(
                    "proposer_nodes entry cannot be empty".to_string(),
                ));
            }
            if !node_url.starts_with("http://") && !node_url.starts_with("https://") {
                return Err(ConfigError::InvalidBeaconUrl(format!(
                    "proposer_nodes entry must start with http:// or https://: {}",
                    node_url
                )));
            }
        }

        Ok(())
    }

    fn validate_insecure_env_var(&self) -> Result<(), ConfigError> {
        match std::env::var("RVC_ALLOW_INSECURE") {
            Ok(val) if val == "true" => Ok(()),
            _ => Err(ConfigError::InsecureFlagRequiresEnvVar),
        }
    }

    pub fn load_passwords(&self) -> Result<HashMap<String, SecretString>, ConfigError> {
        let password_file = match &self.password_file {
            Some(path) => path,
            None => return Ok(HashMap::new()),
        };

        if !password_file.exists() {
            return Err(ConfigError::PasswordFileNotFound(password_file.clone()));
        }

        let content = fs::read_to_string(password_file).map_err(|e| {
            ConfigError::PasswordReadError(format!("failed to read password file: {}", e))
        })?;

        let mut passwords = HashMap::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some((pubkey, password)) = line.split_once('=') {
                let pubkey_trimmed = pubkey.trim();
                if pubkey_trimmed == crypto::WILDCARD_KEY {
                    passwords.insert(
                        crypto::WILDCARD_KEY.to_string(),
                        SecretString::from(password.trim().to_string()),
                    );
                    continue;
                }
                let pubkey = match strip_prefix_strict(pubkey_trimmed) {
                    Ok(s) => s,
                    Err(HexError::DoubleZeroXPrefix) => {
                        warn!(
                            pubkey = pubkey_trimmed,
                            "skipping password entry: double 0x prefix in pubkey"
                        );
                        continue;
                    }
                };
                let password = password.trim();
                passwords.insert(pubkey.to_string(), SecretString::from(password.to_string()));
            }
        }

        Ok(passwords)
    }

    /// Parses the `broadcast` config field into `BroadcastTopics`.
    ///
    /// If empty, returns default (all enabled). If `none`, all disabled.
    /// Otherwise, only listed topics are enabled.
    pub fn effective_broadcast_topics(&self) -> bn_manager::BroadcastTopics {
        if self.broadcast.is_empty() {
            return bn_manager::BroadcastTopics::default();
        }
        if self.broadcast.len() == 1 && self.broadcast[0] == BroadcastTopic::None {
            return bn_manager::BroadcastTopics {
                attestations: false,
                blocks: false,
                sync_committee: false,
                subscriptions: false,
            };
        }
        bn_manager::BroadcastTopics {
            attestations: self.broadcast.contains(&BroadcastTopic::Attestations),
            blocks: self.broadcast.contains(&BroadcastTopic::Blocks),
            sync_committee: self.broadcast.contains(&BroadcastTopic::SyncCommittee),
            subscriptions: self.broadcast.contains(&BroadcastTopic::Subscriptions),
        }
    }

    /// Returns the effective list of beacon node endpoints.
    ///
    /// Prefers `beacon_nodes` if non-empty, otherwise falls back to `beacon_url`.
    pub fn effective_beacon_nodes(&self) -> Vec<String> {
        if !self.beacon_nodes.is_empty() {
            self.beacon_nodes.clone()
        } else {
            vec![self.beacon_url.clone()]
        }
    }

    /// Fold the four `[beacon]` timeout knobs into [`bn_manager::OperationTimeouts`].
    ///
    /// Unset knobs keep [`bn_manager::OperationTimeouts::default`] (A-4.12).
    /// `aggregate_timeout` sets both `aggregate_fetch` and `aggregate_submit`.
    pub fn operation_timeouts(&self) -> bn_manager::OperationTimeouts {
        let mut timeouts = bn_manager::OperationTimeouts::default();
        if let Some(secs) = self.block_production_timeout {
            timeouts.block_production = std::time::Duration::from_secs(secs);
        }
        if let Some(secs) = self.attestation_timeout {
            timeouts.attestation_fetch = std::time::Duration::from_secs(secs);
        }
        if let Some(secs) = self.aggregate_timeout {
            timeouts.aggregate_fetch = std::time::Duration::from_secs(secs);
            timeouts.aggregate_submit = std::time::Duration::from_secs(secs);
        }
        if let Some(secs) = self.duty_fetch_timeout {
            timeouts.duty_fetch = std::time::Duration::from_secs(secs);
        }
        timeouts
    }

    /// Load with explicit precedence: defaults < file < CLI.
    ///
    /// `*Config` stays the live home for defaults (`Config::default` /
    /// `from_file`). Present CLI flags overlay last. File errors name
    /// [`ConfigSource::File`]. `resolved()` is not called — empty CLI vecs
    /// stay unset so they cannot invert ConfigWire's flat-wins lift.
    pub fn load(file: Option<&Path>, cli: StartArgs) -> Result<Self, ConfigError> {
        let mut config = match file {
            Some(path) => Self::from_file(path).map_err(|err| match err {
                removed @ ConfigError::RemovedKey { .. } => removed,
                err => ConfigError::Invalid {
                    field: "config",
                    message: err.to_string(),
                    source_layer: ConfigSource::File(path.to_path_buf()),
                },
            })?,
            None => Self::default(),
        };
        config.apply_cli(&cli);
        Ok(config)
    }

    /// Overlay present `StartArgs` flags onto this config (CLI wins).
    fn apply_cli(&mut self, cli: &StartArgs) {
        let StartArgs {
            config: _,
            beacon,
            keys,
            server,
            network,
            logging,
            tracing,
            keymanager,
            grpc_signer,
            safety,
            builder,
            proposer,
            monitoring,
            slashing,
        } = cli;

        if let Some(v) = &beacon.url {
            self.beacon_url = v.clone();
        }
        if let Some(v) = &beacon.nodes {
            self.beacon_nodes = v.clone();
        }
        if let Some(v) = beacon.max_body_bytes {
            self.beacon_max_body_bytes = v;
        }
        if let Some(v) = beacon.block_production_timeout {
            self.block_production_timeout = Some(v);
        }
        if let Some(v) = beacon.attestation_timeout {
            self.attestation_timeout = Some(v);
        }
        if let Some(v) = beacon.aggregate_timeout {
            self.aggregate_timeout = Some(v);
        }
        if let Some(v) = beacon.duty_fetch_timeout {
            self.duty_fetch_timeout = Some(v);
        }

        if let Some(v) = &keys.keystore_path {
            self.keystore_path = v.clone();
        }
        if let Some(v) = &keys.password_file {
            self.password_file = Some(v.clone());
        }
        if let Some(v) = keys.key_decrypt_threads {
            self.key_decrypt_threads = Some(v);
        }
        if keys.disable_keystore_locking == Some(true) {
            self.disable_keystore_locking = true;
        }
        if let Some(v) = &keys.validators_config {
            self.validators_config = Some(v.clone());
        }
        if let Some(csv) = &keys.secret_provider.providers {
            let items = csv_items(csv);
            if !items.is_empty() {
                self.secret_provider.providers = items;
            }
        }
        if let Some(v) = &keys.secret_provider.gcp.project_id {
            self.secret_provider.gcp.project_id = Some(v.clone());
        }
        if let Some(v) = &keys.secret_provider.gcp.secret_prefix {
            self.secret_provider.gcp.secret_prefix = v.clone();
        }
        if let Some(v) = keys.secret_provider.refresh_interval {
            self.secret_provider.refresh_interval = Some(v);
        }
        if keys.secret_provider.strict == Some(true) {
            self.secret_provider.strict = true;
        }

        if let Some(v) = server.metrics_address {
            self.metrics_address = v;
        }
        if let Some(v) = server.metrics_port {
            self.metrics_port = v;
        }

        if let Some(v) = network.network {
            self.network = v;
        }
        if let Some(v) = network.genesis_time {
            self.genesis_time = Some(v);
        }
        if let Some(v) = &network.genesis_validators_root {
            self.genesis_validators_root = Some(v.clone());
        }
        if let Some(v) = &network.graffiti {
            self.graffiti = Some(v.clone());
        }

        if let Some(v) = &logging.log_level {
            self.log_level = v.clone();
        }
        if let Some(v) = &logging.logfile.path {
            self.logfile.path = Some(v.clone());
        }
        if let Some(v) = logging.logfile.max_size {
            self.logfile.max_size = v;
        }
        if let Some(v) = logging.logfile.max_number {
            self.logfile.max_number = v;
        }
        if logging.logfile.compress == Some(true) {
            self.logfile.compress = true;
        }
        if let Some(v) = &logging.logfile.level {
            self.logfile.level = Some(v.clone());
        }

        if let Some(v) = &tracing.endpoint {
            self.tracing.endpoint = Some(v.clone());
        }
        if let Some(v) = tracing.exporter {
            self.tracing.exporter = v;
        }
        if let Some(v) = tracing.sample_rate {
            self.tracing.sample_rate = Some(v);
        }
        if let Some(v) = tracing.max_queue_size {
            self.tracing.max_queue_size = Some(v);
        }
        if let Some(v) = tracing.max_export_batch_size {
            self.tracing.max_export_batch_size = Some(v);
        }

        if keymanager.no_keymanager {
            self.keymanager.enabled = false;
        } else if keymanager.enabled == Some(true) {
            self.keymanager.enabled = true;
        }
        if let Some(v) = &keymanager.address {
            self.keymanager.address = Some(v.clone());
        }
        if let Some(v) = &keymanager.token_file {
            self.keymanager.token_file = Some(v.clone());
        }
        if let Some(v) = &keymanager.remote_signer_url {
            self.keymanager.remote_signer_url = Some(v.clone());
        }
        if let Some(csv) = &keymanager.remote_signer_allowed_hosts {
            let items = csv_items(csv);
            if !items.is_empty() {
                self.keymanager.remote_signer_allowed_hosts = Some(items);
            }
        }
        if keymanager.allow_insecure_remote_signer == Some(true) {
            self.keymanager.allow_insecure_remote_signer = true;
        }
        if let Some(v) = &keymanager.cors_origins {
            self.keymanager.cors_origins = v.clone();
        }
        if let Some(v) = keymanager.body_limit {
            self.keymanager.body_limit = v;
        }

        if let Some(v) = &grpc_signer.url {
            self.grpc_signer.url = Some(v.clone());
        }
        if let Some(v) = &grpc_signer.tls_cert {
            self.grpc_signer.tls_cert = Some(v.clone());
        }
        if let Some(v) = &grpc_signer.tls_key {
            self.grpc_signer.tls_key = Some(v.clone());
        }
        if let Some(v) = &grpc_signer.tls_ca_cert {
            self.grpc_signer.tls_ca_cert = Some(v.clone());
        }

        if let Some(v) = builder.builder_limits.circuit_breaker_consecutive_limit {
            self.builder_limits.circuit_breaker_consecutive_limit = v;
        }
        if let Some(v) = builder.builder_limits.circuit_breaker_epoch_limit {
            self.builder_limits.circuit_breaker_epoch_limit = v;
        }
        if let Some(v) = builder.block_selection_mode {
            self.block_selection_mode = v;
        }
        if let Some(v) = builder.validator_registration_batch_size {
            self.validator_registration_batch_size = v;
        }
        if let Some(v) = builder.validator_registration_batch_delay {
            self.validator_registration_batch_delay = v;
        }

        if let Some(v) = &proposer.proposer_nodes {
            self.proposer_nodes = v.clone();
        }
        if let Some(v) = &proposer.broadcast {
            self.broadcast = v.clone();
        }
        if let Some(v) = &proposer.proposer_config.url {
            self.proposer_config.url = Some(v.clone());
        }
        if let Some(v) = &proposer.proposer_config.file {
            self.proposer_config.file = Some(v.clone());
        }
        if let Some(v) = proposer.proposer_config.refresh_interval {
            self.proposer_config.refresh_interval = v;
        }
        if let Some(v) = &proposer.proposer_config.url_token {
            self.proposer_config.url_token = Some(v.clone());
        }
        if proposer.proposer_config.url_insecure == Some(true) {
            self.proposer_config.url_insecure = true;
        }

        if let Some(v) = &monitoring.endpoint {
            self.monitoring.endpoint = Some(v.clone());
        }
        if let Some(v) = monitoring.interval {
            self.monitoring.interval = v;
        }
        if monitoring.endpoint_insecure == Some(true) {
            self.monitoring.endpoint_insecure = true;
        }

        if safety.no_doppelganger_detection {
            self.doppelganger_detection = false;
        }
        if safety.disable_attesting {
            self.disable_attesting = true;
        }
        if let Some(v) = safety.slashed_validators_action {
            self.slashed_validators_action = v;
        }
        if safety.allow_unsupported_fork {
            self.allow_unsupported_fork = true;
        }

        if let Some(v) = &slashing.slashing_db_path {
            self.slashing_db_path = v.clone();
        }
        if slashing.init_slashing_db {
            self.allow_fresh_db = true;
        }
        if let Some(v) = slashing.group_commit_batch_size {
            self.group_commit_batch_size = Some(v);
        }
        if let Some(v) = slashing.group_commit_wait_to_fill_ms {
            self.group_commit_wait_to_fill_ms = Some(v);
        }
    }
}

/// Redacts credentials from a URL for safe logging.
///
/// If the URL contains a username, both the username and password are replaced
/// with `***`. Unparseable URLs are returned as-is.
pub fn redact_url(raw: &str) -> String {
    match Url::parse(raw) {
        Ok(mut parsed) => {
            if !parsed.username().is_empty() {
                let _ = parsed.set_username("***");
                let _ = parsed.set_password(Some("***"));
            }
            parsed.to_string()
        }
        Err(_) => raw.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip secret material (passwords) for assertions; not a logging surface
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn overlay(f: impl FnOnce(&mut StartArgs)) -> Config {
        let mut cli = StartArgs::default();
        f(&mut cli);
        Config::load(None, cli).expect("load")
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.beacon_url, "http://localhost:5052");
        assert_eq!(config.keystore_path, PathBuf::from("./keystores"));
        assert_eq!(config.metrics_port, 8080);
        assert_eq!(config.metrics_address, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
        assert_eq!(config.network, Network::Mainnet);
        assert!(config.genesis_time.is_none());
        assert!(config.genesis_validators_root.is_none());
        assert_eq!(config.timing.attestation_due_bps, 3333);
        assert_eq!(config.timing.aggregate_due_bps, 6667);
        assert_eq!(config.timing.attestation_due_bps_gloas, 2500);
        assert_eq!(config.timing.aggregate_due_bps_gloas, 5000);
        assert_eq!(config.timing.sync_message_due_bps_gloas, 2500);
        assert_eq!(config.timing.contribution_due_bps_gloas, 5000);
        assert_eq!(config.timing.payload_due_bps, 5000);
        assert_eq!(config.timing.payload_attestation_due_bps, 7500);
        assert!(config.fork_schedule.gloas_fork_epoch.is_none());
        assert!(config.fork_schedule.gloas_fork_version.is_none());
    }

    #[test]
    fn test_merge_with_cli_metrics_address() {
        let config = overlay(|cli| {
            cli.server.metrics_address =
                Some(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        });

        assert_eq!(config.metrics_address, std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn test_merge_with_cli_metrics_address_none_preserves_default() {
        let config = overlay(|_| {});

        assert_eq!(config.metrics_address, std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn test_config_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
metrics_port = 9090
network = "hoodi"
log_level = "debug"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.beacon_url, "http://beacon:5052");
        assert_eq!(config.keystore_path, PathBuf::from("/data/keystores"));
        assert_eq!(config.slashing_db_path, PathBuf::from("/data/slashing.db"));
        assert!(!config.allow_fresh_db, "SEC-3: allow_fresh_db defaults false");
        assert_eq!(config.metrics_port, 9090);
        assert_eq!(config.network, Network::Hoodi);
        assert_eq!(config.log_level, "debug");
    }

    /// SEC-3: `allow_fresh_db` parses from TOML and `--init-slashing-db` merges in.
    #[test]
    fn test_allow_fresh_db_toml_and_cli() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
allow_fresh_db = true
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.allow_fresh_db);

        let mut config = Config::default();
        assert!(!config.allow_fresh_db);
        config.apply_cli(&StartArgs {
            slashing: SlashingArgs { init_slashing_db: true, ..Default::default() },
            ..Default::default()
        });
        assert!(config.allow_fresh_db);
    }

    #[test]
    fn test_config_file_not_found() {
        let result = Config::from_file("/nonexistent/config.toml");
        assert!(matches!(result, Err(ConfigError::FileNotFound(_))));
    }

    #[test]
    fn test_effective_genesis_time_from_network() {
        let config = Config { network: Network::Mainnet, genesis_time: None, ..Default::default() };
        assert_eq!(config.effective_genesis_time().unwrap(), 1606824023);
    }

    #[test]
    fn test_effective_genesis_time_override() {
        let config =
            Config { network: Network::Mainnet, genesis_time: Some(12345), ..Default::default() };
        assert_eq!(config.effective_genesis_time().unwrap(), 12345);
    }

    #[test]
    fn test_effective_genesis_time_custom_network_requires_explicit() {
        let config = Config { network: Network::Custom, genesis_time: None, ..Default::default() };
        assert!(config.effective_genesis_time().is_err());
    }

    #[test]
    fn test_effective_genesis_validators_root_from_network() {
        let config = Config {
            network: Network::Mainnet,
            genesis_validators_root: None,
            ..Default::default()
        };
        let root = config.effective_genesis_validators_root().unwrap();
        assert_eq!(root, eth_types::NetworkPreset::MAINNET.genesis_validators_root_hex());
    }

    #[test]
    fn test_effective_genesis_validators_root_override() {
        let config = Config {
            network: Network::Mainnet,
            genesis_validators_root: Some("0xcustom".to_string()),
            ..Default::default()
        };
        assert_eq!(config.effective_genesis_validators_root().unwrap(), "0xcustom");
    }

    #[test]
    fn test_validate_valid_config() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_empty_beacon_url() {
        let config = Config { beacon_url: "".to_string(), ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_invalid_beacon_url_scheme() {
        let config =
            Config { beacon_url: "ftp://localhost:5052".to_string(), ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_invalid_port() {
        let config = Config { metrics_port: 0, ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidPort(_))));
    }

    #[test]
    fn test_validate_graffiti_too_long() {
        let config = Config {
            graffiti: Some("a".repeat(33)), // 33 bytes, exceeds 32 byte limit
            ..Default::default()
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidGraffiti(_))));
    }

    #[test]
    fn test_timing_attestation_due_bps_from_toml_is_observable() {
        let config: Config = toml::from_str(
            r#"
[timing]
attestation_due_bps = 2500
aggregate_due_bps = 4000
"#,
        )
        .expect("[timing] must bind through ConfigWire");
        assert_eq!(config.timing.attestation_due_bps, 2500);
        assert_eq!(config.timing.aggregate_due_bps, 4000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timing_bps_zero_fails_validate_naming_key() {
        let config: Config = toml::from_str(
            r#"
[timing]
attestation_due_bps = 0
"#,
        )
        .expect("0 is a u64; reject at validate");
        let err = config.validate().expect_err("bps=0 must fail validate");
        let msg = err.to_string();
        assert!(msg.contains("timing.attestation_due_bps"), "{msg}");
    }

    #[test]
    fn test_timing_bps_above_range_fails_validate_naming_key() {
        let config: Config = toml::from_str(
            r#"
[timing]
aggregate_due_bps = 10001
"#,
        )
        .expect("10001 is a u64; reject at validate");
        let err = config.validate().expect_err("bps=10001 must fail validate");
        let msg = err.to_string();
        assert!(msg.contains("timing.aggregate_due_bps"), "{msg}");
    }

    #[test]
    fn test_timing_bps_non_integer_fails_naming_key() {
        let err = toml::from_str::<Config>(
            r#"
[timing]
attestation_due_bps = "not-an-integer"
"#,
        )
        .expect_err("non-integer bps must fail");
        let msg = err.to_string();
        assert!(msg.contains("attestation_due_bps"), "{msg}");
    }

    #[test]
    fn test_timing_gloas_keys_from_toml_are_observable() {
        let config: Config = toml::from_str(
            r#"
[timing]
attestation_due_bps_gloas = 2500
aggregate_due_bps_gloas = 6667
sync_message_due_bps_gloas = 1111
contribution_due_bps_gloas = 2222
payload_due_bps = 3333
payload_attestation_due_bps = 8000
"#,
        )
        .expect("[timing] Gloas keys must bind through ConfigWire");
        assert_eq!(config.timing.attestation_due_bps_gloas, 2500);
        assert_eq!(config.timing.aggregate_due_bps_gloas, 6667);
        assert_eq!(config.timing.sync_message_due_bps_gloas, 1111);
        assert_eq!(config.timing.contribution_due_bps_gloas, 2222);
        assert_eq!(config.timing.payload_due_bps, 3333);
        assert_eq!(config.timing.payload_attestation_due_bps, 8000);
        assert_eq!(config.timing.attestation_due_bps, 3333);
        assert_eq!(config.timing.aggregate_due_bps, 6667);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_timing_aggregate_due_bps_gloas_default_5000_toml_6667() {
        let defaulted: Config = toml::from_str("").expect("empty config");
        assert_eq!(defaulted.timing.aggregate_due_bps_gloas, 5000);
        let from_toml: Config = toml::from_str(
            r#"
[timing]
aggregate_due_bps_gloas = 6667
"#,
        )
        .expect("TOML-only override");
        assert_eq!(from_toml.timing.aggregate_due_bps_gloas, 6667);
        assert_eq!(from_toml.timing.attestation_due_bps, 3333);
        assert_eq!(from_toml.timing.aggregate_due_bps, 6667);
        assert!(from_toml.validate().is_ok());
    }

    #[test]
    fn test_timing_unknown_key_fails_naming_key() {
        let err = toml::from_str::<Config>(
            r#"
[timing]
not_a_timing_key = 1
"#,
        )
        .expect_err("unknown timing.* key must fail deserialize");
        let msg = err.to_string();
        assert!(msg.contains("not_a_timing_key"), "{msg}");
    }

    #[test]
    fn test_fork_schedule_from_toml_is_observable() {
        let config: Config = toml::from_str(
            r#"
[fork_schedule]
gloas_fork_epoch = 600000
gloas_fork_version = "0X07000000"
"#,
        )
        .expect("[fork_schedule] must bind through ConfigWire");
        assert_eq!(config.fork_schedule.gloas_fork_epoch, Some(600000));
        assert_eq!(config.fork_schedule.gloas_fork_version.as_deref(), Some("0X07000000"));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_fork_schedule_sentinel_epoch_string_is_u64_max() {
        let config: Config = toml::from_str(
            r#"
[fork_schedule]
gloas_fork_epoch = "18446744073709551615"
"#,
        )
        .expect("sentinel decimal string must bind");
        assert_eq!(config.fork_schedule.gloas_fork_epoch, Some(u64::MAX));
        assert!(config.fork_schedule.gloas_fork_version.is_none());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_fork_schedule_unknown_key_fails_naming_key() {
        let err = toml::from_str::<Config>(
            r#"
[fork_schedule]
not_a_fork_key = 1
"#,
        )
        .expect_err("unknown fork_schedule.* key must fail deserialize");
        let msg = err.to_string();
        assert!(msg.contains("not_a_fork_key"), "{msg}");
    }

    #[test]
    fn test_timing_gloas_bps_zero_fails_validate_naming_key() {
        let config: Config = toml::from_str(
            r#"
[timing]
aggregate_due_bps_gloas = 0
"#,
        )
        .expect("0 is a u64; reject at validate");
        let err = config.validate().expect_err("bps=0 must fail validate");
        let msg = err.to_string();
        assert!(msg.contains("timing.aggregate_due_bps_gloas"), "{msg}");
    }

    #[test]
    fn test_timing_gloas_bps_above_range_fails_validate_naming_key() {
        let config: Config = toml::from_str(
            r#"
[timing]
payload_attestation_due_bps = 10001
"#,
        )
        .expect("10001 is a u64; reject at validate");
        let err = config.validate().expect_err("bps=10001 must fail validate");
        let msg = err.to_string();
        assert!(msg.contains("timing.payload_attestation_due_bps"), "{msg}");
    }

    #[test]
    fn test_timing_gloas_phase_order_names_aggregate_when_before_attestation() {
        let config: Config = toml::from_str(
            r#"
[timing]
attestation_due_bps_gloas = 5000
aggregate_due_bps_gloas = 4000
"#,
        )
        .expect("in-range values; reject at validate");
        let err = config.validate().expect_err("attestation > aggregate must fail");
        let msg = err.to_string();
        assert!(msg.contains("timing.aggregate_due_bps_gloas"), "{msg}");
        assert!(msg.contains("4000"), "{msg}");
    }

    #[test]
    fn test_timing_gloas_phase_order_names_payload_attestation_when_before_aggregate() {
        let config: Config = toml::from_str(
            r#"
[timing]
aggregate_due_bps_gloas = 5000
payload_attestation_due_bps = 4000
"#,
        )
        .expect("in-range values; reject at validate");
        let err = config.validate().expect_err("aggregate > payload_attestation must fail");
        let msg = err.to_string();
        assert!(msg.contains("timing.payload_attestation_due_bps"), "{msg}");
        assert!(msg.contains("4000"), "{msg}");
    }

    #[test]
    fn test_validate_graffiti_valid() {
        let config = Config {
            graffiti: Some("rvc".to_string()), // Valid graffiti
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_load_passwords() {
        let mut file = NamedTempFile::new().unwrap();
        // Use obviously fake test values to avoid secret detection warnings
        let test_pw_1 = format!("test_value_{}", 1);
        let test_pw_2 = format!("test_value_{}", 2);
        writeln!(file, "# Comment line\nabcd1234 = {}\n0x5678efgh = {}", test_pw_1, test_pw_2)
            .unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 2);
        assert!(passwords.contains_key("abcd1234"));
        assert!(passwords.contains_key("5678efgh"));
    }

    #[test]
    fn test_load_passwords_no_file() {
        let config = Config { password_file: None, ..Default::default() };
        let passwords = config.load_passwords().unwrap();
        assert!(passwords.is_empty());
    }

    #[test]
    fn test_load_passwords_wildcard_only() {
        use secrecy::ExposeSecret;

        let mut file = NamedTempFile::new().unwrap();
        let shared_pw = format!("shared_value_{}", 1);
        writeln!(file, "*={}", shared_pw).unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1);
        let entry = passwords.get(crypto::WILDCARD_KEY).unwrap();
        assert_eq!(entry.expose_secret(), shared_pw);
    }

    #[test]
    fn test_load_passwords_wildcard_and_per_key() {
        use secrecy::ExposeSecret;

        let mut file = NamedTempFile::new().unwrap();
        let shared_pw = format!("shared_value_{}", 1);
        let special_pw = format!("special_value_{}", 2);
        writeln!(file, "*={}\n0xabcd1234 = {}", shared_pw, special_pw).unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 2);
        assert_eq!(passwords.get(crypto::WILDCARD_KEY).unwrap().expose_secret(), shared_pw);
        assert_eq!(passwords.get("abcd1234").unwrap().expose_secret(), special_pw);
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_load_passwords_wildcard_not_hex_validated() {
        use secrecy::ExposeSecret;

        // The wildcard line is never hex-validated: the password VALUE is stored verbatim
        // (even a pathological `0x0x...` value that would trip the double-0x check were it
        // ever passed to `strip_prefix_strict`), and the `*` key never emits the double-0x
        // warning. The verbatim-value assertion is the real teeth here -- the original
        // version of this test asserted no value at all and so proved nothing.
        let mut file = NamedTempFile::new().unwrap();
        let shared_pw = "0x0xdeadbeef";
        writeln!(file, "* = {}", shared_pw).unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1);
        let entry = passwords.get(crypto::WILDCARD_KEY).unwrap();
        assert_eq!(entry.expose_secret(), shared_pw, "wildcard value stored verbatim");
        assert!(
            !logs_contain("double 0x prefix"),
            "wildcard line must not trigger the double-0x warn path"
        );
    }

    #[test]
    fn test_load_passwords_wildcard_empty_value() {
        use secrecy::ExposeSecret;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "*=").unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords.get(crypto::WILDCARD_KEY).unwrap().expose_secret(), "");
    }

    #[test]
    fn test_load_passwords_wildcard_last_wins() {
        use secrecy::ExposeSecret;

        let mut file = NamedTempFile::new().unwrap();
        let first_pw = format!("first_value_{}", 1);
        let second_pw = format!("second_value_{}", 2);
        writeln!(file, "*={}\n*={}", first_pw, second_pw).unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1);
        assert_eq!(passwords.get(crypto::WILDCARD_KEY).unwrap().expose_secret(), second_pw);
    }

    #[test]
    fn test_merge_with_cli() {
        let config = overlay(|cli| {
            cli.beacon.url = Some("http://custom:5052".to_string());
            cli.server.metrics_port = Some(9999);
            cli.network.network = Some(Network::Hoodi);
        });

        assert_eq!(config.beacon_url, "http://custom:5052");
        assert_eq!(config.metrics_port, 9999);
        assert_eq!(config.network, Network::Hoodi);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        assert!(toml_str.contains("beacon_url"));
        assert!(toml_str.contains("network"));
    }

    // -- beacon_nodes tests --

    #[test]
    fn test_default_config_beacon_nodes_empty() {
        let config = Config::default();
        assert!(config.beacon_nodes.is_empty());
    }

    #[test]
    fn test_default_config_doppelganger_detection_enabled() {
        let config = Config::default();
        assert!(config.doppelganger_detection);
    }

    #[test]
    fn test_effective_beacon_nodes_falls_back_to_beacon_url() {
        let config = Config { beacon_url: "http://primary:5052".to_string(), ..Default::default() };
        assert_eq!(config.effective_beacon_nodes(), vec!["http://primary:5052"]);
    }

    #[test]
    fn test_effective_beacon_nodes_uses_beacon_nodes_when_set() {
        let config = Config {
            beacon_url: "http://primary:5052".to_string(),
            beacon_nodes: vec!["http://bn1:5052".to_string(), "http://bn2:5052".to_string()],
            ..Default::default()
        };
        assert_eq!(config.effective_beacon_nodes(), vec!["http://bn1:5052", "http://bn2:5052"]);
    }

    #[test]
    fn test_merge_with_cli_beacon_nodes() {
        let config = overlay(|cli| {
            cli.beacon.nodes =
                Some(vec!["http://bn1:5052".to_string(), "http://bn2:5052".to_string()]);
        });
        assert_eq!(config.beacon_nodes.len(), 2);
        assert_eq!(config.beacon_nodes[0], "http://bn1:5052");
    }

    #[test]
    fn test_merge_with_cli_doppelganger_detection() {
        let config = Config::default();
        assert!(config.doppelganger_detection);

        let config = overlay(|cli| {
            cli.safety.no_doppelganger_detection = true;
        });
        assert!(!config.doppelganger_detection);
    }

    #[test]
    fn test_validate_beacon_nodes_invalid_scheme() {
        let config = Config {
            beacon_nodes: vec!["http://bn1:5052".to_string(), "ftp://bn2:5052".to_string()],
            ..Default::default()
        };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_beacon_nodes_empty_entry() {
        let config = Config { beacon_nodes: vec!["".to_string()], ..Default::default() };
        assert!(matches!(config.validate(), Err(ConfigError::InvalidBeaconUrl(_))));
    }

    #[test]
    fn test_validate_beacon_nodes_valid() {
        let config = Config {
            beacon_nodes: vec!["http://bn1:5052".to_string(), "https://bn2:5052".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_from_file_with_beacon_nodes() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://primary:5052"
beacon_nodes = ["http://bn1:5052", "http://bn2:5052"]
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
doppelganger_detection = false
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.beacon_nodes.len(), 2);
        assert!(!config.doppelganger_detection);
    }

    // -- keymanager config tests --

    #[test]
    fn test_default_config_keymanager_disabled() {
        let config = Config::default();
        assert!(!config.keymanager.enabled);
        assert!(config.keymanager.address.is_none());
        assert!(config.keymanager.token_file.is_none());
        assert!(config.keymanager.remote_signer_url.is_none());
    }

    #[test]
    fn test_merge_with_cli_keymanager_fields() {
        let config = overlay(|cli| {
            cli.keymanager.enabled = Some(true);
            cli.keymanager.address = Some("0.0.0.0:5062".to_string());
            cli.keymanager.token_file = Some(PathBuf::from("/data/token.txt"));
            cli.keymanager.remote_signer_url = Some("https://signer.example.com".to_string());
        });

        assert!(config.keymanager.enabled);
        assert_eq!(config.keymanager.address.as_deref(), Some("0.0.0.0:5062"));
        assert_eq!(config.keymanager.token_file, Some(PathBuf::from("/data/token.txt")));
        assert_eq!(
            config.keymanager.remote_signer_url.as_deref(),
            Some("https://signer.example.com")
        );
    }

    #[test]
    fn test_config_from_file_with_keymanager() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
keymanager_enabled = true
keymanager_address = "0.0.0.0:5062"
keymanager_token_file = "/data/token.txt"
remote_signer_url = "https://signer.example.com"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.keymanager.enabled);
        assert_eq!(config.keymanager.address.as_deref(), Some("0.0.0.0:5062"));
        assert_eq!(config.keymanager.token_file, Some(PathBuf::from("/data/token.txt")));
        assert_eq!(
            config.keymanager.remote_signer_url.as_deref(),
            Some("https://signer.example.com")
        );
    }

    #[test]
    fn test_merge_with_cli_keymanager_none_preserves_defaults() {
        let config = overlay(|_| {});

        assert!(!config.keymanager.enabled);
        assert!(config.keymanager.address.is_none());
        assert!(config.keymanager.token_file.is_none());
        assert!(config.keymanager.remote_signer_url.is_none());
    }

    // -- key_decrypt_threads tests --

    #[test]
    fn test_default_config_key_decrypt_threads_none() {
        let config = Config::default();
        assert!(config.key_decrypt_threads.is_none());
    }

    #[test]
    fn test_merge_with_cli_key_decrypt_threads() {
        assert!(Config::default().key_decrypt_threads.is_none());
        let config = overlay(|cli| {
            cli.keys.key_decrypt_threads = Some(4);
        });
        assert_eq!(config.key_decrypt_threads, Some(4));
    }

    #[test]
    fn test_merge_with_cli_key_decrypt_threads_none_preserves_default() {
        let config = overlay(|_| {});
        assert!(config.key_decrypt_threads.is_none());
    }

    #[test]
    fn test_config_from_file_with_key_decrypt_threads() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
key_decrypt_threads = 4
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.key_decrypt_threads, Some(4));
    }

    // -- tracing config tests --

    #[test]
    fn test_default_config_tracing_fields() {
        let config = Config::default();
        assert!(config.tracing.endpoint.is_none());
        assert_eq!(config.tracing.exporter, TracingExporter::Otlp);
        // Unset end-to-end (RF5-15); resolved default is 0.01.
        assert!(config.tracing.sample_rate.is_none());
        assert!((config.tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_merge_with_cli_tracing_endpoint() {
        let config = overlay(|cli| {
            cli.tracing.endpoint = Some("http://collector:4318".to_string());
        });
        assert_eq!(config.tracing.endpoint.as_deref(), Some("http://collector:4318"));
    }

    #[test]
    fn test_merge_with_cli_tracing_exporter() {
        let config = overlay(|cli| {
            cli.tracing.exporter = Some(TracingExporter::Gcp);
        });
        assert_eq!(config.tracing.exporter, TracingExporter::Gcp);
    }

    #[test]
    fn test_merge_with_cli_tracing_sample_rate() {
        let config = overlay(|cli| {
            cli.tracing.sample_rate = Some(0.5);
        });
        assert_eq!(config.tracing.sample_rate, Some(0.5));
    }

    #[test]
    fn test_merge_with_cli_tracing_none_preserves_defaults() {
        let config = overlay(|_| {});
        assert!(config.tracing.endpoint.is_none());
        assert_eq!(config.tracing.exporter, TracingExporter::Otlp);
        assert!(config.tracing.sample_rate.is_none());
    }

    #[test]
    fn test_config_from_file_with_tracing() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
tracing_endpoint = "http://otel-collector:4318"
tracing_exporter = "otlp"
tracing_sample_rate = 0.1
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.tracing.endpoint.as_deref(), Some("http://otel-collector:4318"));
        assert_eq!(config.tracing.exporter, TracingExporter::Otlp);
        assert_eq!(config.tracing.sample_rate, Some(0.1));
    }

    #[test]
    fn test_config_from_file_without_tracing_uses_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.tracing.endpoint.is_none());
        assert_eq!(config.tracing.exporter, TracingExporter::Otlp);
        assert!(config.tracing.sample_rate.is_none());
        assert!((config.tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
    }

    // -- RF5-15: OTEL precedence + Option sample_rate --

    /// Serialize tests that touch OTEL env vars.
    fn otel_env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_explicit_default_sample_rate_survives_env_override() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.5");
        // Explicit 0.01 (the old "default") must NOT be treated as unset.
        let tracing = TracingConfig { sample_rate: Some(0.01), ..Default::default() };
        assert!((tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn test_env_sample_rate_applies_when_unset() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.5");
        let tracing = TracingConfig::default(); // sample_rate: None
        assert!((tracing.resolve_sample_rate() - 0.5).abs() < f64::EPSILON);
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn test_sample_rate_default_is_0_01_when_unset_everywhere() {
        let _guard = otel_env_lock();
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
        let tracing = TracingConfig::default();
        assert!(tracing.sample_rate.is_none());
        assert!((tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
    }

    #[test]
    fn test_otlp_endpoint_precedence_cli_over_file_over_env() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env:4318");

        // Env only
        let env_only = TracingConfig::default();
        assert_eq!(env_only.resolve_endpoint().as_deref(), Some("http://env:4318"));

        // File/config beats env
        let from_file =
            TracingConfig { endpoint: Some("http://file:4318".into()), ..Default::default() };
        assert_eq!(from_file.resolve_endpoint().as_deref(), Some("http://file:4318"));

        // CLI merge beats file (and env)
        let mut cfg = Config {
            tracing: TracingConfig {
                endpoint: Some("http://file:4318".into()),
                ..Default::default()
            },
            ..Default::default()
        };
        cfg.apply_cli(&StartArgs {
            tracing: TracingArgs { endpoint: Some("http://cli:4318".into()), ..Default::default() },
            ..Default::default()
        });
        assert_eq!(cfg.tracing.resolve_endpoint().as_deref(), Some("http://cli:4318"));

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
    }

    #[test]
    fn test_merge_covers_every_cli_override_field() {
        // Representative override from each group still lands on Config.
        let config = overlay(|cli| {
            cli.beacon.url = Some("http://bn:5052".into());
            cli.tracing.sample_rate = Some(0.01);
            cli.keymanager.enabled = Some(true);
            cli.logging.logfile.path = Some(std::path::PathBuf::from("/tmp/rvc.log"));
            cli.monitoring.interval = Some(42);
        });
        assert_eq!(config.beacon_url, "http://bn:5052");
        assert_eq!(config.tracing.sample_rate, Some(0.01));
        assert!(config.keymanager.enabled);
        assert_eq!(config.logfile.path.as_deref(), Some(std::path::Path::new("/tmp/rvc.log")));
        assert_eq!(config.monitoring.interval, 42);
    }

    #[test]
    fn test_cli_sample_rate_0_01_survives_merge_and_env() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.9");
        let config = overlay(|cli| {
            cli.tracing.sample_rate = Some(0.01);
        });
        assert_eq!(config.tracing.sample_rate, Some(0.01));
        assert!((config.tracing.resolve_sample_rate() - 0.01).abs() < f64::EPSILON);
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    // -- tracing batch config tests --

    #[test]
    fn test_default_config_tracing_batch_fields_none() {
        let config = Config::default();
        assert!(config.tracing.max_queue_size.is_none());
        assert!(config.tracing.max_export_batch_size.is_none());
    }

    #[test]
    fn test_merge_with_cli_tracing_max_queue_size() {
        let config = overlay(|cli| {
            cli.tracing.max_queue_size = Some(4096);
        });
        assert_eq!(config.tracing.max_queue_size, Some(4096));
    }

    #[test]
    fn test_merge_with_cli_tracing_max_export_batch_size() {
        let config = overlay(|cli| {
            cli.tracing.max_export_batch_size = Some(1024);
        });
        assert_eq!(config.tracing.max_export_batch_size, Some(1024));
    }

    #[test]
    fn test_merge_with_cli_tracing_batch_none_preserves_defaults() {
        let config = overlay(|_| {});
        assert!(config.tracing.max_queue_size.is_none());
        assert!(config.tracing.max_export_batch_size.is_none());
    }

    #[test]
    fn test_config_from_file_with_tracing_batch() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
tracing_max_queue_size = 4096
tracing_max_export_batch_size = 1024
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.tracing.max_queue_size, Some(4096));
        assert_eq!(config.tracing.max_export_batch_size, Some(1024));
    }

    #[test]
    fn test_config_from_file_without_tracing_batch_uses_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.tracing.max_queue_size.is_none());
        assert!(config.tracing.max_export_batch_size.is_none());
    }

    // -- redact_url tests --

    #[test]
    fn test_redact_url_with_credentials() {
        let result = redact_url("http://user:pass@host:5052");
        assert_eq!(result, "http://***:***@host:5052/");
    }

    #[test]
    fn test_redact_url_with_username_only() {
        let result = redact_url("http://user@host:5052");
        assert_eq!(result, "http://***:***@host:5052/");
    }

    #[test]
    fn test_redact_url_without_credentials() {
        let result = redact_url("http://host:5052");
        assert_eq!(result, "http://host:5052/");
    }

    #[test]
    fn test_redact_url_https_without_credentials() {
        let result = redact_url("https://beacon.example.com:5052/eth/v1");
        assert_eq!(result, "https://beacon.example.com:5052/eth/v1");
    }

    #[test]
    fn test_redact_url_invalid_input() {
        let result = redact_url("not-a-url");
        assert_eq!(result, "not-a-url");
    }

    #[test]
    fn test_redact_url_empty_input() {
        let result = redact_url("");
        assert_eq!(result, "");
    }

    #[test]
    fn test_config_from_file_without_key_decrypt_threads() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.key_decrypt_threads.is_none());
    }

    // -- remote_signer_allowed_hosts tests --

    #[test]
    fn test_default_config_remote_signer_allowed_hosts_none() {
        let config = Config::default();
        assert!(config.keymanager.remote_signer_allowed_hosts.is_none());
    }

    #[test]
    fn test_merge_with_cli_remote_signer_allowed_hosts() {
        let config = overlay(|cli| {
            cli.keymanager.remote_signer_allowed_hosts = Some("host1.com,host2.com".to_string());
        });
        assert_eq!(
            config.keymanager.remote_signer_allowed_hosts,
            Some(vec!["host1.com".to_string(), "host2.com".to_string()])
        );
    }

    #[test]
    fn test_merge_with_cli_remote_signer_allowed_hosts_with_spaces() {
        let config = overlay(|cli| {
            cli.keymanager.remote_signer_allowed_hosts =
                Some(" host1.com , host2.com ".to_string());
        });
        assert_eq!(
            config.keymanager.remote_signer_allowed_hosts,
            Some(vec!["host1.com".to_string(), "host2.com".to_string()])
        );
    }

    #[test]
    fn test_merge_with_cli_remote_signer_allowed_hosts_none_preserves_default() {
        let config = overlay(|_| {});
        assert!(config.keymanager.remote_signer_allowed_hosts.is_none());
    }

    #[test]
    fn test_config_from_file_with_remote_signer_allowed_hosts() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
remote_signer_allowed_hosts = ["signer1.com", "signer2.com"]
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(
            config.keymanager.remote_signer_allowed_hosts,
            Some(vec!["signer1.com".to_string(), "signer2.com".to_string()])
        );
    }

    // -- secret provider config tests --

    #[test]
    fn test_default_config_secret_providers_empty() {
        let config = Config::default();
        assert!(config.secret_provider.providers.is_empty());
        assert!(config.secret_provider.gcp.project_id.is_none());
        assert_eq!(config.secret_provider.gcp.secret_prefix, "validator-key-");
    }

    #[test]
    fn test_merge_with_cli_secret_provider() {
        let config = overlay(|cli| {
            cli.keys.secret_provider.providers = Some("gcp".to_string());
            cli.keys.secret_provider.gcp.project_id = Some("my-project".to_string());
            cli.keys.secret_provider.gcp.secret_prefix = Some("key-".to_string());
        });
        assert_eq!(config.secret_provider.providers, vec!["gcp".to_string()]);
        assert_eq!(config.secret_provider.gcp.project_id, Some("my-project".to_string()));
        assert_eq!(config.secret_provider.gcp.secret_prefix, "key-");
    }

    #[test]
    fn test_merge_with_cli_secret_provider_comma_separated() {
        let config = overlay(|cli| {
            cli.keys.secret_provider.providers = Some("gcp,aws".to_string());
        });
        assert_eq!(config.secret_provider.providers, vec!["gcp".to_string(), "aws".to_string()]);
    }

    #[test]
    fn test_merge_with_cli_secret_provider_none_preserves_defaults() {
        let config = overlay(|_| {});
        assert!(config.secret_provider.providers.is_empty());
        assert!(config.secret_provider.gcp.project_id.is_none());
        assert_eq!(config.secret_provider.gcp.secret_prefix, "validator-key-");
    }

    #[test]
    fn test_validate_gcp_provider_missing_project_id() {
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig { project_id: None, ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("gcp_project_id"),
            "error should mention gcp_project_id: {}",
            err
        );
    }

    #[test]
    fn test_validate_gcp_provider_with_project_id_ok() {
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig {
                    project_id: Some("my-project".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_no_providers_ok() {
        let config = Config::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_from_file_with_secret_provider() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"

[secret_provider]
providers = ["gcp"]

[secret_provider.gcp]
project_id = "my-gcp-project"
secret_prefix = "val-key-"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.secret_provider.providers, vec!["gcp".to_string()]);
        assert_eq!(config.secret_provider.gcp.project_id, Some("my-gcp-project".to_string()));
        assert_eq!(config.secret_provider.gcp.secret_prefix, "val-key-");
    }

    #[test]
    fn test_merge_with_cli_no_gcp_secret_prefix_preserves_config_file() {
        let mut config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig {
                    project_id: Some("my-project".to_string()),
                    secret_prefix: "custom-prefix-".to_string(),
                },
                ..Default::default()
            },
            ..Default::default()
        };
        config.apply_cli(&StartArgs::default());
        assert_eq!(
            config.secret_provider.gcp.secret_prefix, "custom-prefix-",
            "config file gcp_secret_prefix should be preserved when CLI does not specify it"
        );
    }

    #[test]
    fn test_validate_gcp_provider_empty_project_id() {
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig { project_id: Some("".to_string()), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err(), "empty gcp_project_id should fail validation");
    }

    #[test]
    fn test_validate_gcp_provider_whitespace_project_id() {
        let config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig { project_id: Some("   ".to_string()), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err(), "whitespace-only gcp_project_id should fail validation");
    }

    #[test]
    fn test_config_from_file_with_nested_gcp_section() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"

[secret_provider]
providers = ["gcp"]
refresh_interval = 300

[secret_provider.gcp]
project_id = "my-project"
secret_prefix = "validator-key-"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert_eq!(config.secret_provider.providers, vec!["gcp".to_string()]);
        assert_eq!(config.secret_provider.refresh_interval, Some(300));
        assert_eq!(config.secret_provider.gcp.project_id, Some("my-project".to_string()));
        assert_eq!(config.secret_provider.gcp.secret_prefix, "validator-key-");
    }

    #[test]
    fn test_config_from_file_without_secret_provider_uses_defaults() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
network = "mainnet"
log_level = "info"
"#
        )
        .unwrap();

        let config = Config::from_file(file.path()).unwrap();
        assert!(config.secret_provider.providers.is_empty());
        assert!(config.secret_provider.refresh_interval.is_none());
        assert!(config.secret_provider.gcp.project_id.is_none());
        assert_eq!(config.secret_provider.gcp.secret_prefix, "validator-key-");
    }

    #[test]
    fn test_merge_with_cli_overrides_gcp_project_id() {
        let mut config = Config {
            secret_provider: SecretProviderConfig {
                providers: vec!["gcp".to_string()],
                gcp: GcpSecretConfig {
                    project_id: Some("config-project".to_string()),
                    secret_prefix: "config-prefix-".to_string(),
                },
                ..Default::default()
            },
            ..Default::default()
        };
        config.apply_cli(&StartArgs {
            keys: KeysArgs {
                secret_provider: SecretProviderArgs {
                    gcp: GcpSecretArgs {
                        project_id: Some("cli-project".to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        });
        assert_eq!(
            config.secret_provider.gcp.project_id,
            Some("cli-project".to_string()),
            "CLI should override config.toml gcp project_id"
        );
        assert_eq!(
            config.secret_provider.gcp.secret_prefix, "config-prefix-",
            "config.toml secret_prefix should be preserved when CLI does not specify it"
        );
    }

    #[test]
    fn test_default_config_refresh_interval_none() {
        let config = Config::default();
        assert!(config.secret_provider.refresh_interval.is_none());
    }

    #[test]
    fn test_merge_with_cli_secret_refresh_interval() {
        let config = overlay(|cli| {
            cli.keys.secret_provider.refresh_interval = Some(120);
        });
        assert_eq!(config.secret_provider.refresh_interval, Some(120));
    }

    #[test]
    fn test_merge_with_cli_no_secret_refresh_interval_preserves_config() {
        let mut config = Config {
            secret_provider: SecretProviderConfig {
                refresh_interval: Some(300),
                ..Default::default()
            },
            ..Default::default()
        };
        config.apply_cli(&StartArgs::default());
        assert_eq!(config.secret_provider.refresh_interval, Some(300));
    }

    #[test]
    fn test_insecure_flag_env_var_validation() {
        use std::sync::Mutex;
        static ENV_LOCK: Mutex<()> = Mutex::new(());
        let _guard = ENV_LOCK.lock().unwrap();

        // Case 1: insecure flag false skips env check
        std::env::remove_var("RVC_ALLOW_INSECURE");
        let config = Config::default();
        assert!(!config.keymanager.allow_insecure_remote_signer);
        assert!(config.validate().is_ok(), "Should pass when insecure flag is false");

        // Case 2: insecure flag true without env var fails
        let config = Config {
            keymanager: KeymanagerConfig {
                allow_insecure_remote_signer: true,
                ..Default::default()
            },
            ..Config::default()
        };
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string().contains("RVC_ALLOW_INSECURE"),
            "Error should mention RVC_ALLOW_INSECURE, got: {}",
            err
        );

        // Case 3: insecure flag true with wrong env var value fails
        std::env::set_var("RVC_ALLOW_INSECURE", "yes");
        let config = Config {
            keymanager: KeymanagerConfig {
                allow_insecure_remote_signer: true,
                ..Default::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_err(), "Should fail with RVC_ALLOW_INSECURE=yes (not 'true')");

        // Case 4: insecure flag true with correct env var passes
        std::env::set_var("RVC_ALLOW_INSECURE", "true");
        let config = Config {
            keymanager: KeymanagerConfig {
                allow_insecure_remote_signer: true,
                ..Default::default()
            },
            ..Config::default()
        };
        assert!(config.validate().is_ok(), "Should pass with RVC_ALLOW_INSECURE=true");

        std::env::remove_var("RVC_ALLOW_INSECURE");
    }

    #[test]
    fn test_default_circuit_breaker_limits() {
        let config = Config::default();
        assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 3);
        assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 5);
    }

    #[test]
    fn test_default_keystore_locking_enabled() {
        let config = Config::default();
        assert!(!config.disable_keystore_locking);
    }

    #[test]
    fn test_merge_circuit_breaker_limits() {
        let config = overlay(|cli| {
            cli.builder.builder_limits.circuit_breaker_consecutive_limit = Some(10);
            cli.builder.builder_limits.circuit_breaker_epoch_limit = Some(20);
        });
        assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 10);
        assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 20);
    }

    #[test]
    fn test_merge_disable_keystore_locking() {
        let config = overlay(|cli| {
            cli.keys.disable_keystore_locking = Some(true);
        });
        assert!(config.disable_keystore_locking);
    }

    #[test]
    fn test_circuit_breaker_toml_parsing() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
builder_circuit_breaker_consecutive_limit = 7
builder_circuit_breaker_epoch_limit = 12
disable_keystore_locking = true
"#
        )
        .unwrap();
        let config = Config::from_file(f.path()).unwrap();
        assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 7);
        assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 12);
        assert_eq!(config.builder_limits.circuit_breaker_consecutive_limit, 7);
        assert_eq!(config.builder_limits.circuit_breaker_epoch_limit, 12);
        assert!(config.disable_keystore_locking);
    }

    // --- T3.2/T3.4: Proposer nodes and broadcast topics config ---

    #[test]
    fn test_effective_broadcast_topics_default() {
        let config = Config::default();
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(topics.sync_committee);
        assert!(topics.subscriptions);
    }

    #[test]
    fn test_effective_broadcast_topics_none() {
        let config = Config { broadcast: vec![BroadcastTopic::None], ..Default::default() };
        let topics = config.effective_broadcast_topics();
        assert!(!topics.attestations);
        assert!(!topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn test_effective_broadcast_topics_partial() {
        let config = Config {
            broadcast: vec![BroadcastTopic::Blocks, BroadcastTopic::Attestations],
            ..Default::default()
        };
        let topics = config.effective_broadcast_topics();
        assert!(topics.attestations);
        assert!(topics.blocks);
        assert!(!topics.sync_committee);
        assert!(!topics.subscriptions);
    }

    #[test]
    fn test_invalid_broadcast_topic_fails_at_deserialization() {
        let toml = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
broadcast = ["invalid-topic"]
"#;
        let err = toml::from_str::<Config>(toml).unwrap_err().to_string();
        assert!(
            err.contains("broadcast") || err.contains("invalid-topic") || err.contains("unknown"),
            "serde error should name the field or value: {err}"
        );
    }

    #[test]
    fn test_broadcast_none_exclusivity_still_enforced_in_validate() {
        let config = Config {
            broadcast: vec![BroadcastTopic::None, BroadcastTopic::Blocks],
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
        assert!(
            result.unwrap_err().to_string().contains("none"),
            "error should mention none exclusivity"
        );
    }

    #[test]
    fn test_validate_proposer_config_mutual_exclusivity() {
        let config = Config {
            proposer_config: ProposerConfigSource {
                url: Some("https://example.com/config".to_string()),
                file: Some("/path/to/config.json".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_proposer_config_url_only() {
        let config = Config {
            proposer_config: ProposerConfigSource {
                url: Some("https://example.com/config".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_validate_proposer_config_file_only() {
        let config = Config {
            proposer_config: ProposerConfigSource {
                file: Some("/path/to/config.json".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_default_config_proposer_fields() {
        let config = Config::default();
        assert!(config.proposer_nodes.is_empty());
        assert!(config.broadcast.is_empty());
        assert!(config.proposer_config.url.is_none());
        assert!(config.proposer_config.file.is_none());
        assert_eq!(config.proposer_config.refresh_interval, 384);
        assert!(config.proposer_config.url_token.is_none());
        assert!(!config.proposer_config.url_insecure);
        assert!(config.proposer_config.url.is_none());
        assert_eq!(config.proposer_config.refresh_interval, 384);
    }

    #[test]
    fn test_proposer_nodes_toml_parsing() {
        let mut f = NamedTempFile::new().unwrap();
        writeln!(
            f,
            r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
proposer_nodes = ["http://proposer1:5052", "http://proposer2:5052"]
broadcast = ["blocks", "attestations"]
"#
        )
        .unwrap();
        let config = Config::from_file(f.path()).unwrap();
        assert_eq!(config.proposer_nodes.len(), 2);
        assert_eq!(config.proposer_nodes[0], "http://proposer1:5052");
        assert_eq!(config.broadcast.len(), 2);
    }

    #[test]
    fn test_validate_invalid_proposer_node_url() {
        let config =
            Config { proposer_nodes: vec!["ftp://invalid:5052".to_string()], ..Default::default() };
        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_merge_with_cli_proposer_fields() {
        let config = overlay(|cli| {
            cli.proposer.proposer_nodes = Some(vec!["http://p1:5052".to_string()]);
            cli.proposer.broadcast = Some(vec![BroadcastTopic::Blocks]);
            cli.proposer.proposer_config.url = Some("https://example.com/config".to_string());
            cli.proposer.proposer_config.refresh_interval = Some(60);
            cli.proposer.proposer_config.url_token = Some("my-token".to_string());
            cli.proposer.proposer_config.url_insecure = Some(true);
        });
        assert_eq!(config.proposer_nodes.len(), 1);
        assert_eq!(config.broadcast, vec![BroadcastTopic::Blocks]);
        assert_eq!(config.proposer_config.url, Some("https://example.com/config".to_string()));
        assert_eq!(config.proposer_config.refresh_interval, 60);
        assert_eq!(config.proposer_config.url_token, Some("my-token".to_string()));
        assert!(config.proposer_config.url_insecure);
    }

    // -- RF5-11: typed config enums (fail-early deserialize) --

    #[test]
    fn test_invalid_slashed_action_fails_at_deserialization_not_validate() {
        let toml = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
slashed_validators_action = "not-a-real-action"
"#;
        let err = toml::from_str::<Config>(toml).unwrap_err().to_string();
        assert!(
            err.contains("slashed_validators_action")
                || err.contains("not-a-real-action")
                || err.contains("unknown variant"),
            "serde error should name the field or value: {err}"
        );
    }

    #[test]
    fn test_all_previously_accepted_slashed_actions_still_parse() {
        for (literal, expected) in [
            ("disable-only", SlashedAction::DisableOnly),
            ("shutdown", SlashedAction::Shutdown),
            ("none", SlashedAction::None),
        ] {
            let toml = format!(
                r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
slashed_validators_action = "{literal}"
"#
            );
            let config: Config = toml::from_str(&toml).unwrap_or_else(|e| {
                panic!("accepted slashed action {literal:?} must still parse: {e}")
            });
            assert_eq!(config.slashed_validators_action, expected);
            assert_eq!(literal.parse::<SlashedAction>().unwrap(), expected);
        }
    }

    #[test]
    fn test_all_previously_accepted_broadcast_topics_still_parse() {
        for (literal, expected) in [
            ("attestations", BroadcastTopic::Attestations),
            ("blocks", BroadcastTopic::Blocks),
            ("sync-committee", BroadcastTopic::SyncCommittee),
            ("subscriptions", BroadcastTopic::Subscriptions),
            ("none", BroadcastTopic::None),
        ] {
            assert_eq!(literal.parse::<BroadcastTopic>().unwrap(), expected);
            let toml = format!(
                r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
broadcast = ["{literal}"]
"#
            );
            let config: Config = toml::from_str(&toml).unwrap_or_else(|e| {
                panic!("accepted broadcast topic {literal:?} must still parse: {e}")
            });
            assert_eq!(config.broadcast, vec![expected]);
        }
    }

    #[test]
    fn test_bn_role_and_tracing_exporter_round_trip() {
        for (literal, expected) in [
            ("attestation", BnRole::Attestation),
            ("proposal", BnRole::Proposal),
            ("sync-committee", BnRole::SyncCommittee),
            ("aggregation", BnRole::Aggregation),
            ("submission", BnRole::Submission),
            ("all", BnRole::All),
        ] {
            let toml = format!(
                r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"

[[beacon_nodes_config]]
url = "http://bn:5052"
roles = ["{literal}"]
"#
            );
            let config: Config = toml::from_str(&toml)
                .unwrap_or_else(|e| panic!("accepted BnRole {literal:?} must still parse: {e}"));
            assert_eq!(config.beacon_nodes_config[0].roles, vec![expected]);
        }

        for (literal, expected) in [("otlp", TracingExporter::Otlp), ("gcp", TracingExporter::Gcp)]
        {
            let toml = format!(
                r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
tracing_exporter = "{literal}"
"#
            );
            let config: Config = toml::from_str(&toml).unwrap_or_else(|e| {
                panic!("accepted tracing_exporter {literal:?} must still parse: {e}")
            });
            assert_eq!(config.tracing.exporter, expected);
            assert_eq!(literal.parse::<TracingExporter>().unwrap(), expected);
            let json = serde_json::to_string(&expected).unwrap();
            let back: TracingExporter = serde_json::from_str(&json).unwrap();
            assert_eq!(back, expected);
        }
    }

    #[test]
    fn test_invalid_tracing_exporter_fails_at_deserialization() {
        let toml = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"
tracing_exporter = "unknown"
"#;
        let err = toml::from_str::<Config>(toml).unwrap_err().to_string();
        assert!(
            err.contains("tracing_exporter") || err.contains("unknown") || err.contains("variant"),
            "serde error should name the field or value: {err}"
        );
    }

    #[test]
    fn test_invalid_bn_role_fails_at_deserialization() {
        let toml = r#"
beacon_url = "http://localhost:5052"
keystore_path = "./keystores"
slashing_db_path = "./slashing.sqlite"

[[beacon_nodes_config]]
url = "http://bn:5052"
roles = ["not-a-role"]
"#;
        let err = toml::from_str::<Config>(toml).unwrap_err().to_string();
        assert!(
            err.contains("roles") || err.contains("not-a-role") || err.contains("variant"),
            "serde error should name the field or value: {err}"
        );
    }

    #[test]
    fn test_validate_no_longer_lists_typed_enum_values() {
        // Typed enums cannot hold invalid variants, so validate only needs
        // cross-field rules. A fully-valid typed config still validates.
        let config = Config {
            slashed_validators_action: SlashedAction::Shutdown,
            tracing: TracingConfig { exporter: TracingExporter::Gcp, ..Default::default() },
            broadcast: vec![BroadcastTopic::Blocks, BroadcastTopic::Attestations],
            beacon_nodes_config: vec![BeaconNodeEntry {
                url: "http://bn:5052".to_string(),
                roles: vec![BnRole::Proposal],
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn builder_section_urls_and_min_bid_parse() {
        let config: Config = toml::from_str(
            r#"
beacon_url = "http://localhost:5052"
[builder]
builders = ["https://relay.example"]
min_bid = 10000000
builder_boost_factor = 80
"#,
        )
        .expect("parse [builder]");
        assert_eq!(config.builder.builders, vec!["https://relay.example".to_string()]);
        assert_eq!(config.builder.min_bid, Some(10_000_000));
        assert_eq!(config.builder.builder_boost_factor, Some(80));
        assert!(config.validate().is_ok());
    }

    #[test]
    fn builder_section_malformed_url_fails_validate_naming_the_value() {
        let config: Config = toml::from_str(
            r#"
beacon_url = "http://localhost:5052"
[builder]
builders = ["not a url"]
"#,
        )
        .expect("parse");
        let err = config.validate().expect_err("malformed URL");
        let msg = err.to_string();
        assert!(msg.contains("not a url"), "{msg}");
    }

    // -- CQ-2.5: strip_prefix_strict adoption test --

    /// load_passwords must warn and skip a pubkey entry that carries a double 0x prefix.
    #[test]
    #[tracing_test::traced_test]
    fn test_load_passwords_double_0x_prefix_warns_and_skips() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "0x0xabcd1234 = test_value_1").unwrap();
        // Also write a valid entry so we can confirm only the bad one is skipped
        writeln!(file, "0xdeadbeef = test_value_2").unwrap();

        let config =
            Config { password_file: Some(file.path().to_path_buf()), ..Default::default() };
        let passwords = config.load_passwords().unwrap();

        assert_eq!(passwords.len(), 1, "only the valid entry should be loaded");
        assert!(!passwords.contains_key("0x0xabcd1234"), "double-0x key must be absent");
        assert!(
            passwords.contains_key("deadbeef"),
            "valid entry must be present (prefix stripped)"
        );
        assert!(logs_contain("double 0x prefix"), "expected warn log about double prefix");
    }

    // -- RF5-13: nested call sites; flat shims deleted --

    /// Source-level guard: flat field shims must not reappear on `Config`.
    ///
    /// `ConfigWire` still uses the historical flat key names for serde alias
    /// compatibility — only the public `Config` shims are forbidden.
    #[test]
    fn test_no_flat_field_accessors_remain() {
        let full = include_str!("types.rs");
        // Exclude this test module so assertion strings do not self-match.
        let src = full.split("#[cfg(test)]").next().expect("production source before tests");

        assert!(
            !src.contains("removed in RF5-13"),
            "shim markers must be gone from production source"
        );
        assert!(!src.contains("sync_flat_shims"), "sync_flat_shims must be deleted");
        assert!(
            !src.contains("sync_nested_from_flat_shims"),
            "sync_nested_from_flat_shims must be deleted"
        );

        let start = src.find("pub struct Config {").expect("Config struct");
        let after = &src[start..];
        let end = after.find("\nfn default_").expect("end of Config struct region");
        let config_struct = &after[..end];

        for nested in [
            "pub logfile: LogfileConfig",
            "pub tracing: TracingConfig",
            "pub keymanager: KeymanagerConfig",
            "pub grpc_signer: GrpcSignerConfig",
            "pub proposer_config: ProposerConfigSource",
            "pub monitoring: MonitoringConfig",
            "pub builder_limits: BuilderLimits",
            "pub builder: BuilderSettings",
            "pub timing: TimingConfig",
            "pub fork_schedule: ForkScheduleConfig",
        ] {
            assert!(config_struct.contains(nested), "nested group missing from Config: {nested}");
        }

        for field in [
            "keymanager_enabled",
            "keymanager_address",
            "keymanager_token_file",
            "remote_signer_url",
            "remote_signer_allowed_hosts",
            "allow_insecure_remote_signer",
            "keymanager_cors_origins",
            "keymanager_body_limit",
            "tracing_endpoint",
            "tracing_exporter",
            "tracing_sample_rate",
            "tracing_max_queue_size",
            "tracing_max_export_batch_size",
            "grpc_signer_url",
            "grpc_signer_tls_cert",
            "grpc_signer_tls_key",
            "grpc_signer_tls_ca_cert",
            "builder_circuit_breaker_consecutive_limit",
            "builder_circuit_breaker_epoch_limit",
            "monitoring_endpoint",
            "monitoring_interval",
            "monitoring_endpoint_insecure",
            "proposer_config_url",
            "proposer_config_file",
            "proposer_config_refresh_interval",
            "proposer_config_url_token",
            "proposer_config_url_insecure",
            "logfile_max_size",
            "logfile_max_number",
            "logfile_compress",
            "logfile_level",
        ] {
            assert!(
                !config_struct.contains(field),
                "flat Config field shim must be deleted: {field}"
            );
        }

        for method in [
            "fn keymanager_enabled(",
            "fn tracing_sample_rate(",
            "fn logfile_max_size(",
            "fn logfile_path(",
        ] {
            assert!(!src.contains(method), "flat accessor method must be deleted: {method}");
        }
    }
}
