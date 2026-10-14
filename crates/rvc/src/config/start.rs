//! `rvc start` clap overlay (ARCH-4i).
//!
//! The 13 flattened groups *are* the CLI overlay. There is no `CliOverrides`
//! translation. [`Config::load`](super::Config::load) applies present flags
//! onto the live [`Config`](super::Config) (`defaults < file < CLI`).

use std::path::PathBuf;

use clap::Args;

use super::{
    BeaconArgs, BlockSelectionMode, BroadcastTopic, BuilderLimitsArgs, DutiesArgs, GrpcSignerArgs,
    KeymanagerArgs, KeysArgs, LogfileArgs, MonitoringArgs, NetworkArgs, ProposerConfigArgs,
    SafetyArgs, ServerArgs, SlashingArgs, TracingArgs,
};

/// Arguments for `rvc start`, composed of flattened clap groups that mirror
/// the nested config sections introduced in RF5-12.
#[derive(Args, Debug, Default, Clone)]
pub struct StartArgs {
    /// Path to the configuration file (TOML format)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    #[command(flatten)]
    pub beacon: BeaconArgs,

    #[command(flatten)]
    pub keys: KeysArgs,

    #[command(flatten)]
    pub server: ServerArgs,

    #[command(flatten)]
    pub network: NetworkArgs,

    #[command(flatten)]
    pub logging: LoggingArgs,

    #[command(flatten)]
    pub tracing: TracingArgs,

    #[command(flatten)]
    pub keymanager: KeymanagerArgs,

    #[command(flatten)]
    pub grpc_signer: GrpcSignerArgs,

    #[command(flatten)]
    pub safety: SafetyArgs,

    #[command(flatten)]
    pub builder: BuilderArgs,

    #[command(flatten)]
    pub proposer: ProposerArgs,

    #[command(flatten)]
    pub monitoring: MonitoringArgs,

    #[command(flatten)]
    pub slashing: SlashingArgs,

    #[command(flatten)]
    pub duties: DutiesArgs,
}

/// Console logging plus flattened `[logfile]` knobs (ARCH-4g / A-4.4).
///
/// `[logfile]` keeps its TOML name/shape. `log_level` stays bare (ARCH-4h).
/// `log_format` / `enable_log_reload` stay CLI-only (G-2 `BYPASS`).
#[derive(Args, Debug, Default, Clone)]
pub struct LoggingArgs {
    /// Log level (trace, debug, info, warn, error). Default when unset: info.
    #[arg(long)]
    pub log_level: Option<String>,

    /// Console log output format: `pretty` (default, human-readable) or
    /// `json` (one structured object per event, for log-aggregation backends
    /// such as Loki / Elasticsearch / a SIEM). Also settable via the
    /// `RVC_LOG_FORMAT` env var; an explicit flag wins. Applies to the console
    /// stream only — the file appender keeps its own format (issue 5.5).
    #[arg(long, default_value = "pretty")]
    pub log_format: String,

    /// Enable runtime log-level reload on SIGHUP (opt-in; issue 5.4).
    ///
    /// When set, sending `SIGHUP` to the process re-reads `RUST_LOG` and
    /// swaps the active log filter in place — raising or lowering verbosity
    /// without a restart. Disabled by default so the steady-state log path is
    /// unchanged; the always-on reload *layer* is free on the disabled hot
    /// path either way. Unix only (a no-op on other platforms).
    #[arg(long, default_value_t = false)]
    pub enable_log_reload: bool,

    #[command(flatten)]
    pub logfile: LogfileArgs,
}

/// Builder circuit-breaker plus bare registration knobs (ARCH-4g / A-4.4).
///
/// `[builder_limits]` keeps its TOML name/shape. The three bare knobs keep
/// top-level TOML spelling (out of ARCH-4h's 22-knob table).
#[derive(Args, Debug, Default, Clone)]
pub struct BuilderArgs {
    #[command(flatten)]
    pub builder_limits: BuilderLimitsArgs,

    /// Block selection mode: max-profit (default), execution-only, builder-always, builder-only
    #[arg(long)]
    pub block_selection_mode: Option<BlockSelectionMode>,

    /// Maximum number of validator registrations per batch (default: 500, 0 = send all at once)
    #[arg(long)]
    pub validator_registration_batch_size: Option<usize>,

    /// Delay in milliseconds between registration batches (default: 500)
    #[arg(long)]
    pub validator_registration_batch_delay: Option<u64>,
}

/// Proposer-nodes, broadcast topics, and flattened `[proposer_config]` (ARCH-4g / A-4.4).
///
/// `[proposer_config]` keeps its TOML name/shape. `proposer_nodes` and
/// `broadcast` keep top-level TOML spelling.
#[derive(Args, Debug, Default, Clone)]
pub struct ProposerArgs {
    /// Comma-separated list of dedicated proposer beacon node URLs for block production
    #[arg(long, value_delimiter = ',')]
    pub proposer_nodes: Option<Vec<String>>,

    /// Comma-separated list of message types to broadcast to all BNs (attestations,blocks,sync-committee,subscriptions,none)
    #[arg(long, value_delimiter = ',')]
    pub broadcast: Option<Vec<BroadcastTopic>>,

    #[command(flatten)]
    pub proposer_config: ProposerConfigArgs,
}
