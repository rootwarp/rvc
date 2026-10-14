use std::path::{Path, PathBuf};

use clap::Parser;
use rvc_config::ForkScheduleConfig;
use serde::Deserialize;
use zeroize::Zeroizing;

// ── Built-in defaults (single source of truth for merge + docs) ──────────────

/// Default gRPC listen address (loopback).
pub const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:50052";

/// Default HTTP Remote Signing API listen address: **loopback** on the
/// Web3Signer port 9000.
///
/// Secure-by-default: the address is passed verbatim to `TcpListener::bind`
/// (there is no host normalization), so the default must be a concrete bindable
/// host. Loopback works out of the box for a same-host validator client and
/// fails safe (not exposed) for a remote one — an operator with a remote VC must
/// consciously set a routable **private-network** address behind a firewall, and
/// must never bind a public interface (see `docs/web3signer-http-api.md`).
pub const DEFAULT_HTTP_LISTEN_ADDRESS: &str = "127.0.0.1:9000";

/// Default HTTP TLS mode: mutual TLS (the recommended posture, FR-29).
pub const DEFAULT_HTTP_TLS_MODE: &str = "mtls";

/// Default keystore hot-reload interval (seconds).
pub const DEFAULT_RELOAD_INTERVAL_SECS: u64 = 30;

/// Default DVT per-peer RPC timeout (milliseconds).
pub const DEFAULT_DVT_TIMEOUT_MS: u64 = 2000;

/// Default Prometheus metrics listen address.
pub const DEFAULT_METRICS_ADDRESS: &str = "127.0.0.1:9101";

/// Default network name for builder-registration genesis fork version.
pub const DEFAULT_NETWORK: &str = "mainnet";

/// Default console log format token.
pub const DEFAULT_LOG_FORMAT: &str = "pretty";

// ── Signing backend ──────────────────────────────────────────────────────────

/// Signing backend type.
///
/// Kept as an enum end-to-end (CLI → TOML → [`ResolvedConfig`] → `server::build_backend`)
/// so selection is exhaustively matched at compile time. `Display` / [`Self::as_str`]
/// exist only for metric labels, audit logs, and operator-facing text.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// Local keystore-based signing
    #[default]
    Basic,
    /// Distributed Validator Technology (DVT) signing
    #[cfg(feature = "dvt")]
    Dvt,
}

impl Backend {
    /// Stable wire/label string for metrics and audit logs (`"basic"` / `"dvt"`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Basic => "basic",
            #[cfg(feature = "dvt")]
            Self::Dvt => "dvt",
        }
    }
}

impl std::fmt::Display for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── TOML config surface ──────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct SignerConfig {
    pub signer: Option<SignerSection>,
    /// Same `[fork_schedule]` table as the VC. Unset = Gloas unscheduled
    /// (`u64::MAX` sentinel). FU-33 uses `gloas_fork_epoch` from here — not a
    /// second `[signer]` knob — so a shared operator file cannot leave the
    /// remote-signer DB lenient.
    #[serde(default)]
    pub fork_schedule: ForkScheduleConfig,
}

/// TLS posture for the HTTP Remote Signing API listener (FR-28/FR-29, ADR-004).
///
/// In both modes the server presents a certificate and the CA stays required;
/// only the *client*-auth requirement differs. Server authentication is never
/// weakened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpTlsMode {
    /// Mutual TLS: client cert required and verified against the configured CA.
    /// Recommended/default posture (Lighthouse).
    Mtls,
    /// Server-TLS-only: server presents a cert; client cert is optional/absent.
    /// Required for Prysm. Only the client-auth requirement is relaxed (opt-in).
    ServerTlsOnly,
}

impl HttpTlsMode {
    /// Parse from the config/CLI string. Accepts `"mtls"` and
    /// `"server-tls-only"`; any other value is a hard resolve error (no silent
    /// fallback).
    fn parse(s: &str) -> Result<Self, String> {
        match s {
            "mtls" => Ok(Self::Mtls),
            "server-tls-only" => Ok(Self::ServerTlsOnly),
            other => Err(format!(
                "invalid [signer.http] tls_mode {other:?}: expected \"mtls\" or \"server-tls-only\""
            )),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
pub struct SignerSection {
    pub listen_address: Option<String>,
    pub keystore_dir: Option<PathBuf>,
    pub password_file: Option<PathBuf>,
    pub backend: Option<Backend>,
    pub dry_run: Option<bool>,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_ca_cert: Option<PathBuf>,
    pub reload_interval_secs: Option<u64>,
    /// ISSUE-4.6 / L-6: keystore hot-reload is opt-in. When unset (or false)
    /// the reloader is not spawned regardless of `reload_interval_secs`.
    pub enable_hot_reload: Option<bool>,
    /// Network name for builder-registration genesis fork version
    /// (`mainnet` / `hoodi` / `holesky` / `sepolia`). Default `mainnet`.
    pub network: Option<String>,
    pub dvt: Option<DvtConfig>,
    /// Opt-in Web3Signer HTTP API listener block (FR-25/27/28/30). Absent =
    /// HTTP disabled; gRPC stays default-on.
    pub http: Option<HttpSection>,
    /// Max slashing-DB reserve checks per COMMIT (`[signer] group_commit_batch_size`).
    pub group_commit_batch_size: Option<usize>,
    /// Milliseconds to wait for a group-commit batch to fill
    /// (`[signer] group_commit_wait_to_fill_ms`).
    pub group_commit_wait_to_fill_ms: Option<u64>,
}

/// Opt-in `[signer.http]` config block for the Web3Signer HTTP API.
///
/// Parsed/resolved only in this phase — the listener is wired in Phase 3. The
/// HTTP TLS material is independent of the gRPC listener's (FR-30), so gRPC can
/// run mTLS while HTTP runs server-TLS-only.
#[derive(Debug, Default, Deserialize)]
pub struct HttpSection {
    /// Enable the HTTP API. Default `false` (opt-in, FR-27).
    pub enabled: Option<bool>,
    /// Listen address. Default `127.0.0.1:9000` (FR-25); set an explicit
    /// private-network address for a remote validator client.
    pub listen_address: Option<String>,
    /// `"mtls"` (default) or `"server-tls-only"` (FR-28/29).
    pub tls_mode: Option<String>,
    /// Server cert / key / client CA — independent of the gRPC TLS material.
    /// The CA is required in both modes (the requirement is enforced in Phase 3;
    /// here the path is only resolved).
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_ca_cert: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
pub struct DvtConfig {
    pub peers: Option<Vec<String>>,
    pub threshold: Option<u64>,
    pub index: Option<u64>,
    pub timeout_ms: Option<u64>,
}

// ── Resolved runtime config ──────────────────────────────────────────────────

#[derive(Debug)]
pub struct ResolvedConfig {
    pub listen_address: String,
    pub keystore_dir: PathBuf,
    pub password_file: Option<PathBuf>,
    pub backend: Backend,
    pub dry_run: bool,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub tls_ca_cert: Option<PathBuf>,
    pub reload_interval_secs: u64,
    /// ISSUE-4.6 / L-6: hot-reload is opt-in. The reloader is only spawned
    /// when this is `true` AND `reload_interval_secs > 0`.
    pub enable_hot_reload: bool,
    pub dvt_peers: Vec<String>,
    pub dvt_threshold: Option<u64>,
    pub dvt_index: Option<u64>,
    pub dvt_timeout_ms: u64,
    /// Web3Signer HTTP API (opt-in; default off). gRPC is unaffected by these.
    pub http_enabled: bool,
    pub http_listen_address: String,
    pub http_tls_mode: HttpTlsMode,
    pub http_tls_cert: Option<PathBuf>,
    pub http_tls_key: Option<PathBuf>,
    pub http_tls_ca_cert: Option<PathBuf>,
    /// Network genesis fork version for builder registration (from NetworkPreset).
    pub genesis_fork_version: [u8; 4],

    // ── Serve-runtime fields ─────────────────────────────────────────────────
    /// Allow starting without TLS (`--insecure`).
    pub insecure: bool,
    /// Data directory for signer state (default: parent of keystore_dir).
    pub data_dir: Option<PathBuf>,
    /// Disable slashing protection (also requires `RVC_ALLOW_INSECURE=true`).
    pub disable_slashing_protection: bool,
    /// Allow creating a fresh empty slashing DB when the path is missing.
    pub init_slashing_db: bool,
    /// Max slashing-DB reserve checks per COMMIT. `None` = default 50.
    pub group_commit_batch_size: Option<usize>,
    /// Milliseconds to wait for a group-commit batch to fill. `None` = default 1.
    pub group_commit_wait_to_fill_ms: Option<u64>,
    /// Gloas fork epoch for the FU-33 `None==None` leniency gate.
    /// `u64::MAX` is the unscheduled sentinel.
    pub gloas_fork_epoch: u64,
    /// Prometheus metrics listen address.
    pub metrics_address: String,
    /// Opt-in SIGHUP log-level reload (owned by `main` / `init_logging`).
    pub enable_log_reload: bool,
    /// Optional primary client-CN allow-list path (SEC-4).
    pub allowed_client_cns: Option<PathBuf>,
    /// DVT allow-list TOML path (required when backend=dvt).
    #[cfg(feature = "dvt")]
    pub dvt_allowed_peers: Option<PathBuf>,
}

// ── CLI args (serve subcommand) ──────────────────────────────────────────────

/// Arguments for `rvc-signer serve`.
///
/// Fields that previously carried clap `default_value` / `default_value_t` are
/// now `Option<T>` (or plain `bool` with `SetTrue` for pure opt-in flags) so
/// "not passed" is representable. Built-in defaults live only in
/// [`merge_with_cli`] / the `DEFAULT_*` constants — never inferred by comparing
/// a filled clap default against a magic string.
///
/// Precedence: **explicit CLI > config file > built-in default**. An operator
/// who passes `--listen-address 127.0.0.1:50052` (the built-in default value)
/// still wins over a config-file override.
#[derive(Parser, Debug, Clone, Default)]
pub struct ServeArgs {
    /// Path to config.toml file
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// gRPC listen address (host:port) [default: 127.0.0.1:50052]
    #[arg(long)]
    pub listen_address: Option<String>,

    /// Path to the keystore directory
    #[arg(long)]
    pub keystore_dir: Option<PathBuf>,

    /// Path to a single password file used for all keystores
    #[arg(long)]
    pub password_file: Option<PathBuf>,

    /// Path to the TLS certificate file (PEM)
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,

    /// Path to the TLS private key file (PEM)
    #[arg(long)]
    pub tls_key: Option<PathBuf>,

    /// Path to the TLS CA certificate file for client authentication (PEM)
    #[arg(long)]
    pub tls_ca_cert: Option<PathBuf>,

    /// Enable the Web3Signer HTTP Remote Signing API (opt-in; gRPC stays on).
    /// Parsed/resolved only for now; the listener is wired in a later phase.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub http_enabled: bool,

    /// HTTP Remote Signing API listen address (host:port) [default: 127.0.0.1:9000]
    #[arg(long)]
    pub http_listen_address: Option<String>,

    /// HTTP API TLS mode: "mtls" (default) or "server-tls-only"
    #[arg(long)]
    pub http_tls_mode: Option<String>,

    /// HTTP API server certificate (PEM). Independent of the gRPC TLS material.
    #[arg(long)]
    pub http_tls_cert: Option<PathBuf>,

    /// HTTP API server private key (PEM). Independent of the gRPC TLS material.
    #[arg(long)]
    pub http_tls_key: Option<PathBuf>,

    /// HTTP API client CA certificate (PEM). Required in both TLS modes.
    #[arg(long)]
    pub http_tls_ca_cert: Option<PathBuf>,

    /// Validate configuration and exit without starting the server
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub dry_run: bool,

    /// Allow starting without TLS (NOT recommended for production)
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub insecure: bool,

    /// Data directory for signer state (default: parent of keystore_dir).
    /// The slashing protection DB is stored here as signer-slashing.db.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// Disable slashing protection (UNSAFE).
    /// Requires ALSO setting RVC_ALLOW_INSECURE=true in the environment.
    /// Both checks are required to prevent accidental opt-out.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub disable_slashing_protection: bool,

    /// Allow creating a fresh empty signer slashing DB when the path is missing
    /// (SEC-3). DANGEROUS on a previously-active signer: the new DB has zero
    /// signing history and can enable double-signing / slashing. Use only for
    /// genuine first-time deployments. A 0-byte or corrupt DB is always a hard
    /// error regardless of this flag.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub init_slashing_db: bool,

    /// Max slashing-DB reserve checks per COMMIT [default: 50].
    #[arg(long)]
    pub slashing_group_commit_batch_size: Option<usize>,

    /// Milliseconds to wait for a group-commit batch to fill [default: 1]. 0 = no wait.
    #[arg(long)]
    pub slashing_group_commit_wait_to_fill_ms: Option<u64>,

    /// Signing backend to use [default: basic]
    #[arg(long, value_enum)]
    pub backend: Option<Backend>,

    /// Prometheus metrics listen address (host:port) [default: 127.0.0.1:9101]
    #[arg(long)]
    pub metrics_address: Option<String>,

    /// Enable keystore hot-reload (ISSUE-4.6 / L-6).
    ///
    /// Disabled by default. When enabled, the signer periodically rescans
    /// `keystore_dir` and reconciles the loaded set with files on disk —
    /// a key-injection vector if the directory is writable by anyone other
    /// than the signer UID. Requires the directory to be 0o700 and owned
    /// by the signer UID at every reload pass; otherwise the reload is
    /// skipped with a warn log.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub enable_hot_reload: bool,

    /// Keystore hot-reload interval in seconds (only honoured when
    /// `--enable-hot-reload` is set) [default: 30]
    #[arg(long)]
    pub reload_interval: Option<u64>,

    /// Enable runtime log-level reload on SIGHUP (opt-in; issue 5.4).
    ///
    /// When set, sending `SIGHUP` to the process re-reads `RUST_LOG` and swaps
    /// the active log filter in place — raising or lowering verbosity without a
    /// restart. Disabled by default so the steady-state log path is unchanged;
    /// the always-on reload *layer* is free on the disabled hot path either way.
    /// Distinct from `--enable-hot-reload` (which reloads keystores, not logs).
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub enable_log_reload: bool,

    /// Console log output format: `pretty` (default, human-readable) or `json`
    /// (one structured object per event, for log-aggregation backends). Also
    /// settable via the `RVC_LOG_FORMAT` env var; an explicit flag wins. Identical
    /// to `bin/rvc`'s `--log-format` (issue 5.5); console-only (rvc-signer wires no
    /// file appender, see ADR-004 / OPERATOR_GUIDE §7).
    #[arg(long)]
    pub log_format: Option<String>,

    /// Comma-separated list of DVT peer addresses (host:port)
    #[cfg(feature = "dvt")]
    #[arg(long, value_delimiter = ',')]
    pub dvt_peers: Vec<String>,

    /// DVT threshold for signature reconstruction
    #[cfg(feature = "dvt")]
    #[arg(long)]
    pub dvt_threshold: Option<u64>,

    /// This node's DVT share index
    #[cfg(feature = "dvt")]
    #[arg(long)]
    pub dvt_index: Option<u64>,

    /// DVT per-peer RPC timeout in milliseconds [default: 2000]
    #[cfg(feature = "dvt")]
    #[arg(long)]
    pub dvt_timeout: Option<u64>,

    /// Path to the DVT allow-list TOML file (required when backend=dvt).
    /// Format: [[peer]] entries with peer_cn and share_index.
    #[cfg(feature = "dvt")]
    #[arg(long)]
    pub dvt_allowed_peers: Option<PathBuf>,

    /// Path to the primary (non-DVT) client-CN allow-list TOML (SEC-4).
    ///
    /// Optional. When set, only listed mTLS Common Names may invoke signing
    /// RPCs on the primary `SignerService`. Format:
    ///
    /// ```toml
    /// [[client]]
    /// client_cn = "validator-client-1.local"
    /// ```
    ///
    /// When unset, a startup warning is logged and any CA-issued client cert is
    /// accepted (backward compatible). mTLS remains mandatory either way.
    #[arg(long)]
    pub allowed_client_cns: Option<PathBuf>,

    /// Network name for builder-registration genesis fork version
    /// (`mainnet`, `hoodi`, `holesky`, `sepolia`) [default: mainnet].
    /// Both gRPC and HTTP use this single source so identical registrations
    /// produce identical signatures across transports.
    #[arg(long)]
    pub network: Option<String>,
}

// ── Load / merge ─────────────────────────────────────────────────────────────

pub fn load_config(path: &Path) -> Result<SignerConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read config file {}: {}", path.display(), e))?;
    let config: SignerConfig =
        toml::from_str(&content).map_err(|e| format!("failed to parse config: {}", e))?;
    Ok(config)
}

/// Load the config file (if any) and merge with CLI args.
///
/// Precedence: explicit CLI (`Some` / flag set) > file > built-in default.
pub fn resolve_config(args: &ServeArgs) -> Result<ResolvedConfig, Box<dyn std::error::Error>> {
    let file_config =
        if let Some(ref path) = args.config { load_config(path)? } else { SignerConfig::default() };
    merge_with_cli(file_config, args)
}

/// Merge file config with CLI args into a fully-resolved runtime config.
///
/// An explicitly-passed CLI value **always wins**, even when it equals the
/// built-in default (fixes the previous "value equals default ⇒ not passed"
/// heuristic).
pub fn merge_with_cli(
    config: SignerConfig,
    cli: &ServeArgs,
) -> Result<ResolvedConfig, Box<dyn std::error::Error>> {
    let section = config.signer.unwrap_or_default();
    let dvt = section.dvt.unwrap_or_default();

    let listen_address = cli
        .listen_address
        .clone()
        .or(section.listen_address)
        .unwrap_or_else(|| DEFAULT_LISTEN_ADDRESS.to_string());

    let keystore_dir = cli.keystore_dir.clone().or(section.keystore_dir).ok_or(
        "keystore_dir is required (set via --keystore-dir or config [signer].keystore_dir)",
    )?;

    let password_file = cli.password_file.clone().or(section.password_file);

    let backend = cli.backend.or(section.backend).unwrap_or(Backend::Basic);

    // Opt-in flags: CLI SetTrue OR TOML true (cannot cleanly pass explicit false).
    let dry_run = cli.dry_run || section.dry_run.unwrap_or(false);

    let tls_cert = cli.tls_cert.clone().or(section.tls_cert);
    let tls_key = cli.tls_key.clone().or(section.tls_key);
    let tls_ca_cert = cli.tls_ca_cert.clone().or(section.tls_ca_cert);

    let reload_interval_secs = cli
        .reload_interval
        .or(section.reload_interval_secs)
        .unwrap_or(DEFAULT_RELOAD_INTERVAL_SECS);

    // ISSUE-4.6 / L-6: hot-reload opt-in. CLI flag OR TOML true.
    let enable_hot_reload = cli.enable_hot_reload || section.enable_hot_reload.unwrap_or(false);

    #[cfg(feature = "dvt")]
    let dvt_peers = if !cli.dvt_peers.is_empty() {
        cli.dvt_peers.clone()
    } else {
        dvt.peers.unwrap_or_default()
    };
    #[cfg(not(feature = "dvt"))]
    let dvt_peers = dvt.peers.unwrap_or_default();

    #[cfg(feature = "dvt")]
    let dvt_threshold = cli.dvt_threshold.or(dvt.threshold);
    #[cfg(not(feature = "dvt"))]
    let dvt_threshold = dvt.threshold;

    #[cfg(feature = "dvt")]
    let dvt_index = cli.dvt_index.or(dvt.index);
    #[cfg(not(feature = "dvt"))]
    let dvt_index = dvt.index;

    #[cfg(feature = "dvt")]
    let dvt_timeout_ms = cli.dvt_timeout.or(dvt.timeout_ms).unwrap_or(DEFAULT_DVT_TIMEOUT_MS);
    #[cfg(not(feature = "dvt"))]
    let dvt_timeout_ms = dvt.timeout_ms.unwrap_or(DEFAULT_DVT_TIMEOUT_MS);

    // --- Web3Signer HTTP API (opt-in; FR-25/27/28/30). ---
    let http = section.http.unwrap_or_default();

    // Opt-in: CLI flag OR TOML `enabled = true` (mirrors `enable_hot_reload`).
    let http_enabled = cli.http_enabled || http.enabled.unwrap_or(false);

    let http_listen_address = cli
        .http_listen_address
        .clone()
        .or(http.listen_address)
        .unwrap_or_else(|| DEFAULT_HTTP_LISTEN_ADDRESS.to_string());

    // CLI > TOML > default; the resolved string is then parsed into the enum,
    // so an invalid value is a hard error rather than a silent fallback.
    let http_tls_mode_str = cli
        .http_tls_mode
        .clone()
        .or(http.tls_mode)
        .unwrap_or_else(|| DEFAULT_HTTP_TLS_MODE.to_string());
    let http_tls_mode = HttpTlsMode::parse(&http_tls_mode_str)?;

    // Independent of the gRPC TLS material (FR-30) — do not alias the gRPC paths.
    let http_tls_cert = cli.http_tls_cert.clone().or(http.tls_cert);
    let http_tls_key = cli.http_tls_key.clone().or(http.tls_key);
    let http_tls_ca_cert = cli.http_tls_ca_cert.clone().or(http.tls_ca_cert);

    // Network genesis for builder registration: CLI > TOML > mainnet.
    let network_name =
        cli.network.clone().or(section.network).unwrap_or_else(|| DEFAULT_NETWORK.to_string());
    let genesis_fork_version = resolve_network_genesis_fork_version(&network_name)?;

    Ok(ResolvedConfig {
        listen_address,
        keystore_dir,
        password_file,
        backend,
        dry_run,
        tls_cert,
        tls_key,
        tls_ca_cert,
        reload_interval_secs,
        enable_hot_reload,
        dvt_peers,
        dvt_threshold,
        dvt_index,
        dvt_timeout_ms,
        http_enabled,
        http_listen_address,
        http_tls_mode,
        http_tls_cert,
        http_tls_key,
        http_tls_ca_cert,
        genesis_fork_version,
        insecure: cli.insecure,
        data_dir: cli.data_dir.clone(),
        disable_slashing_protection: cli.disable_slashing_protection,
        init_slashing_db: cli.init_slashing_db,
        group_commit_batch_size: cli
            .slashing_group_commit_batch_size
            .or(section.group_commit_batch_size),
        group_commit_wait_to_fill_ms: cli
            .slashing_group_commit_wait_to_fill_ms
            .or(section.group_commit_wait_to_fill_ms),
        gloas_fork_epoch: config.fork_schedule.gloas_fork_epoch.unwrap_or(u64::MAX),
        metrics_address: cli
            .metrics_address
            .clone()
            .unwrap_or_else(|| DEFAULT_METRICS_ADDRESS.to_string()),
        enable_log_reload: cli.enable_log_reload,
        allowed_client_cns: cli.allowed_client_cns.clone(),
        #[cfg(feature = "dvt")]
        dvt_allowed_peers: cli.dvt_allowed_peers.clone(),
    })
}

/// Map a network name onto [`eth_types::NetworkPreset`] genesis fork version.
pub fn resolve_network_genesis_fork_version(
    name: &str,
) -> Result<[u8; 4], Box<dyn std::error::Error>> {
    eth_types::network_from_name(name).map(|p| p.genesis_fork_version).ok_or_else(|| {
        format!("unknown network {name:?}: expected mainnet, hoodi, holesky, or sepolia").into()
    })
}

/// Load the shared keystore password for `serve`.
///
/// Requires `--password-file` / `signer.password_file`. A missing source is a
/// hard startup error (RF1-10): the previous empty-string fallback deferred
/// failure into confusing per-keystore decrypt errors.
pub fn load_serve_password(
    resolved: &ResolvedConfig,
) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let Some(ref file) = resolved.password_file else {
        return Err(
            "password source is required: set --password-file or [signer].password_file".into()
        );
    };
    let content = std::fs::read_to_string(file)
        .map_err(|e| format!("failed to read password file {}: {}", file.display(), e))?;
    Ok(Zeroizing::new(content.trim_end_matches('\n').to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f
    }

    /// Empty CLI args (= nothing passed): all Options None, flags false.
    fn empty_cli() -> ServeArgs {
        ServeArgs::default()
    }

    fn cli_with_keystore(dir: &str) -> ServeArgs {
        ServeArgs { keystore_dir: Some(PathBuf::from(dir)), ..empty_cli() }
    }

    // --- load_config tests ---

    #[test]
    fn test_load_config_full() {
        let f = write_toml(
            r#"
[signer]
listen_address = "0.0.0.0:9000"
keystore_dir = "/data/keystores"
password_file = "/data/password.txt"
backend = "basic"
tls_cert = "/tls/cert.pem"
tls_key = "/tls/key.pem"
tls_ca_cert = "/tls/ca.pem"

[signer.dvt]
peers = ["peer1:50052", "peer2:50052"]
threshold = 2
index = 0
timeout_ms = 5000
"#,
        );

        let cfg = load_config(f.path()).unwrap();
        let s = cfg.signer.unwrap();
        assert_eq!(s.listen_address.unwrap(), "0.0.0.0:9000");
        assert_eq!(s.keystore_dir.unwrap(), PathBuf::from("/data/keystores"));
        assert_eq!(s.password_file.unwrap(), PathBuf::from("/data/password.txt"));
        assert_eq!(s.backend.unwrap(), Backend::Basic);
        assert_eq!(s.tls_cert.unwrap(), PathBuf::from("/tls/cert.pem"));
        assert_eq!(s.tls_key.unwrap(), PathBuf::from("/tls/key.pem"));
        assert_eq!(s.tls_ca_cert.unwrap(), PathBuf::from("/tls/ca.pem"));

        let dvt = s.dvt.unwrap();
        assert_eq!(dvt.peers.unwrap(), vec!["peer1:50052", "peer2:50052"]);
        assert_eq!(dvt.threshold.unwrap(), 2);
        assert_eq!(dvt.index.unwrap(), 0);
        assert_eq!(dvt.timeout_ms.unwrap(), 5000);
    }

    #[test]
    fn test_load_config_partial() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/data/keystores"
"#,
        );

        let cfg = load_config(f.path()).unwrap();
        let s = cfg.signer.unwrap();
        assert_eq!(s.keystore_dir.unwrap(), PathBuf::from("/data/keystores"));
        assert!(s.listen_address.is_none());
        assert!(s.backend.is_none());
        assert!(s.dvt.is_none());
    }

    #[test]
    fn test_load_config_empty_file() {
        let f = write_toml("");
        let cfg = load_config(f.path()).unwrap();
        assert!(cfg.signer.is_none());
    }

    #[test]
    fn test_load_config_nonexistent_file() {
        let result = load_config(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to read config file"));
    }

    #[test]
    fn test_load_config_invalid_toml() {
        let f = write_toml("[invalid toml!!! =");
        let result = load_config(f.path());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("failed to parse config"));
    }

    #[test]
    fn test_load_config_dvt_section_only() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"

[signer.dvt]
threshold = 3
index = 1
"#,
        );

        let cfg = load_config(f.path()).unwrap();
        let dvt = cfg.signer.unwrap().dvt.unwrap();
        assert_eq!(dvt.threshold.unwrap(), 3);
        assert_eq!(dvt.index.unwrap(), 1);
        assert!(dvt.peers.is_none());
        assert!(dvt.timeout_ms.is_none());
    }

    // --- merge_with_cli tests ---

    #[test]
    fn test_merge_defaults_only() {
        let cli = cli_with_keystore("/cli/keystores");
        let resolved = merge_with_cli(SignerConfig::default(), &cli).unwrap();
        assert_eq!(resolved.listen_address, DEFAULT_LISTEN_ADDRESS);
        assert_eq!(resolved.keystore_dir, PathBuf::from("/cli/keystores"));
        assert_eq!(resolved.backend, Backend::Basic);
        assert_eq!(resolved.dvt_timeout_ms, DEFAULT_DVT_TIMEOUT_MS);
        assert!(resolved.dvt_peers.is_empty());
        assert_eq!(
            resolved.genesis_fork_version,
            eth_types::NetworkPreset::MAINNET.genesis_fork_version
        );
    }

    #[test]
    fn test_network_toml_holesky_when_cli_default() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                network: Some("holesky".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolved = merge_with_cli(config, &empty_cli()).unwrap();
        assert_eq!(
            resolved.genesis_fork_version,
            eth_types::NetworkPreset::HOLESKY.genesis_fork_version
        );
    }

    #[test]
    fn test_network_cli_overrides_toml() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                network: Some("mainnet".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cli = ServeArgs {
            keystore_dir: Some(PathBuf::from("/ks")),
            network: Some("sepolia".to_string()),
            ..empty_cli()
        };
        let resolved = merge_with_cli(config, &cli).unwrap();
        assert_eq!(
            resolved.genesis_fork_version,
            eth_types::NetworkPreset::SEPOLIA.genesis_fork_version
        );
    }

    #[test]
    fn test_network_unknown_is_hard_error() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                network: Some("not-a-network".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = merge_with_cli(config, &empty_cli()).unwrap_err().to_string();
        assert!(err.contains("unknown network"), "error: {err}");
        assert!(err.contains("not-a-network"), "error: {err}");
    }

    #[test]
    fn test_resolve_network_genesis_fork_version_table() {
        assert_eq!(
            resolve_network_genesis_fork_version("mainnet").unwrap(),
            eth_types::NetworkPreset::MAINNET.genesis_fork_version
        );
        assert_eq!(
            resolve_network_genesis_fork_version("hoodi").unwrap(),
            eth_types::NetworkPreset::HOODI.genesis_fork_version
        );
        assert_eq!(
            resolve_network_genesis_fork_version("holesky").unwrap(),
            eth_types::NetworkPreset::HOLESKY.genesis_fork_version
        );
        assert_eq!(
            resolve_network_genesis_fork_version("sepolia").unwrap(),
            eth_types::NetworkPreset::SEPOLIA.genesis_fork_version
        );
        assert!(resolve_network_genesis_fork_version("goerli").is_err());
    }

    #[test]
    fn test_merge_config_values_used_when_cli_unset() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                listen_address: Some("0.0.0.0:9000".to_string()),
                keystore_dir: Some(PathBuf::from("/config/ks")),
                password_file: Some(PathBuf::from("/config/pw.txt")),
                #[cfg(feature = "dvt")]
                backend: Some(Backend::Dvt),
                #[cfg(not(feature = "dvt"))]
                backend: Some(Backend::Basic),
                tls_cert: Some(PathBuf::from("/config/cert.pem")),
                dvt: Some(DvtConfig {
                    peers: Some(vec!["p1:5000".to_string()]),
                    threshold: Some(2),
                    index: Some(1),
                    timeout_ms: Some(3000),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let resolved = merge_with_cli(config, &empty_cli()).unwrap();

        assert_eq!(resolved.listen_address, "0.0.0.0:9000");
        assert_eq!(resolved.keystore_dir, PathBuf::from("/config/ks"));
        assert_eq!(resolved.password_file.unwrap(), PathBuf::from("/config/pw.txt"));
        #[cfg(feature = "dvt")]
        assert_eq!(resolved.backend, Backend::Dvt);
        #[cfg(not(feature = "dvt"))]
        assert_eq!(resolved.backend, Backend::Basic);
        assert_eq!(resolved.tls_cert.unwrap(), PathBuf::from("/config/cert.pem"));
        assert_eq!(resolved.dvt_peers, vec!["p1:5000"]);
        assert_eq!(resolved.dvt_threshold.unwrap(), 2);
        assert_eq!(resolved.dvt_index.unwrap(), 1);
        assert_eq!(resolved.dvt_timeout_ms, 3000);
    }

    #[test]
    fn test_merge_cli_overrides_config() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                listen_address: Some("0.0.0.0:9000".to_string()),
                keystore_dir: Some(PathBuf::from("/config/ks")),
                #[cfg(feature = "dvt")]
                backend: Some(Backend::Dvt),
                #[cfg(not(feature = "dvt"))]
                backend: Some(Backend::Basic),
                dvt: Some(DvtConfig {
                    peers: Some(vec!["config-peer:5000".to_string()]),
                    threshold: Some(2),
                    index: Some(1),
                    timeout_ms: Some(3000),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let cli = ServeArgs {
            listen_address: Some("10.0.0.1:8080".to_string()),
            keystore_dir: Some(PathBuf::from("/cli/ks")),
            password_file: Some(PathBuf::from("/cli/pw.txt")),
            backend: Some(Backend::Basic),
            tls_cert: Some(PathBuf::from("/cli/cert.pem")),
            #[cfg(feature = "dvt")]
            dvt_peers: vec!["cli-peer:6000".to_string()],
            #[cfg(feature = "dvt")]
            dvt_threshold: Some(3),
            #[cfg(feature = "dvt")]
            dvt_index: Some(0),
            #[cfg(feature = "dvt")]
            dvt_timeout: Some(5000),
            ..empty_cli()
        };

        let resolved = merge_with_cli(config, &cli).unwrap();

        assert_eq!(resolved.listen_address, "10.0.0.1:8080");
        assert_eq!(resolved.keystore_dir, PathBuf::from("/cli/ks"));
        assert_eq!(resolved.password_file.unwrap(), PathBuf::from("/cli/pw.txt"));
        assert_eq!(resolved.backend, Backend::Basic);
        assert_eq!(resolved.tls_cert.unwrap(), PathBuf::from("/cli/cert.pem"));
        #[cfg(feature = "dvt")]
        {
            assert_eq!(resolved.dvt_peers, vec!["cli-peer:6000"]);
            assert_eq!(resolved.dvt_threshold.unwrap(), 3);
            assert_eq!(resolved.dvt_index.unwrap(), 0);
            assert_eq!(resolved.dvt_timeout_ms, 5000);
        }
    }

    #[test]
    fn test_load_config_dry_run() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"
dry_run = true
"#,
        );

        let cfg = load_config(f.path()).unwrap();
        let s = cfg.signer.unwrap();
        assert_eq!(s.dry_run, Some(true));
    }

    #[test]
    fn test_merge_dry_run_from_config() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                dry_run: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };

        let resolved = merge_with_cli(config, &empty_cli()).unwrap();
        assert!(resolved.dry_run);
    }

    #[test]
    fn test_merge_dry_run_cli_overrides_config() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                dry_run: Some(false),
                ..Default::default()
            }),
            ..Default::default()
        };

        let cli = ServeArgs { dry_run: true, ..empty_cli() };
        let resolved = merge_with_cli(config, &cli).unwrap();
        assert!(resolved.dry_run);
    }

    #[test]
    fn test_merge_dry_run_defaults_false() {
        let cli = cli_with_keystore("/ks");
        let resolved = merge_with_cli(SignerConfig::default(), &cli).unwrap();
        assert!(!resolved.dry_run);
    }

    #[test]
    fn test_merge_missing_keystore_dir_errors() {
        let result = merge_with_cli(SignerConfig::default(), &empty_cli());

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("keystore_dir is required"));
    }

    // RF1-10: deleted `test_merge_password_dir_from_config` and
    // `test_merge_cli_password_dir_overrides_config` (plumbing for removed field).

    #[test]
    fn test_missing_password_source_is_startup_error() {
        let cli = cli_with_keystore("/ks");
        let resolved = merge_with_cli(SignerConfig::default(), &cli).unwrap();
        assert!(resolved.password_file.is_none());

        let err = load_serve_password(&resolved).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("--password-file") || msg.contains("password_file"),
            "error should name --password-file; got: {msg}"
        );
        assert!(
            msg.contains("password source is required"),
            "error should be explicit about missing source; got: {msg}"
        );
    }

    #[test]
    fn test_password_file_still_resolves() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"s3cret\n").unwrap();
        let path = f.path().to_path_buf();

        let cli = ServeArgs {
            keystore_dir: Some(PathBuf::from("/ks")),
            password_file: Some(path),
            ..empty_cli()
        };
        let resolved = merge_with_cli(SignerConfig::default(), &cli).unwrap();
        let password = load_serve_password(&resolved).unwrap();
        // Trailing newline is trimmed (same behavior as pre-RF1-10).
        assert_eq!(password.as_str(), "s3cret");
    }

    #[test]
    fn test_config_with_legacy_password_dir_key() {
        // Serde ignores unknown fields by default; a stale `password_dir` key
        // must not break load, and must not be treated as a password source.
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"
password_dir = "/legacy/pwdir"
"#,
        );
        let cfg = load_config(f.path()).unwrap();
        let section = cfg.signer.as_ref().unwrap();
        assert_eq!(section.keystore_dir.as_ref().unwrap(), &PathBuf::from("/ks"));
        assert!(section.password_file.is_none());

        let resolved = merge_with_cli(cfg, &empty_cli()).unwrap();
        assert!(resolved.password_file.is_none());
        let err = load_serve_password(&resolved).unwrap_err();
        assert!(
            err.to_string().contains("password source is required"),
            "legacy password_dir must not satisfy the password source"
        );
    }

    // --- [signer.http] config surface (Issue 1.3, FR-25/27/28/30) ---

    #[test]
    fn test_load_http_section_full() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"

[signer.http]
enabled = true
listen_address = "0.0.0.0:9000"
tls_mode = "server-tls-only"
tls_cert = "/http/cert.pem"
tls_key = "/http/key.pem"
tls_ca_cert = "/http/ca.pem"
"#,
        );
        let cfg = load_config(f.path()).unwrap();
        let http = cfg.signer.unwrap().http.unwrap();
        assert_eq!(http.enabled, Some(true));
        assert_eq!(http.listen_address.unwrap(), "0.0.0.0:9000");
        assert_eq!(http.tls_mode.unwrap(), "server-tls-only");
        assert_eq!(http.tls_cert.unwrap(), PathBuf::from("/http/cert.pem"));
        assert_eq!(http.tls_key.unwrap(), PathBuf::from("/http/key.pem"));
        assert_eq!(http.tls_ca_cert.unwrap(), PathBuf::from("/http/ca.pem"));
    }

    #[test]
    fn test_http_defaults_when_block_absent() {
        // No [signer.http]: HTTP disabled, default address/mode, gRPC untouched.
        let cli = cli_with_keystore("/ks");
        let resolved = merge_with_cli(SignerConfig::default(), &cli).unwrap();
        assert!(!resolved.http_enabled);
        assert_eq!(resolved.http_listen_address, DEFAULT_HTTP_LISTEN_ADDRESS);
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::Mtls);
        assert!(resolved.http_tls_cert.is_none());
        assert!(resolved.http_tls_key.is_none());
        assert!(resolved.http_tls_ca_cert.is_none());
        // gRPC-side resolution unchanged by the absent HTTP block.
        assert_eq!(resolved.listen_address, DEFAULT_LISTEN_ADDRESS);
        assert_eq!(resolved.backend, Backend::Basic);
    }

    #[test]
    fn test_http_resolved_from_file() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                http: Some(HttpSection {
                    enabled: Some(true),
                    listen_address: Some("0.0.0.0:9000".to_string()),
                    tls_mode: Some("server-tls-only".to_string()),
                    tls_cert: Some(PathBuf::from("/http/cert.pem")),
                    tls_key: Some(PathBuf::from("/http/key.pem")),
                    tls_ca_cert: Some(PathBuf::from("/http/ca.pem")),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolved = merge_with_cli(config, &empty_cli()).unwrap();
        assert!(resolved.http_enabled);
        assert_eq!(resolved.http_listen_address, "0.0.0.0:9000");
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::ServerTlsOnly);
        assert_eq!(resolved.http_tls_cert.unwrap(), PathBuf::from("/http/cert.pem"));
        assert_eq!(resolved.http_tls_key.unwrap(), PathBuf::from("/http/key.pem"));
        assert_eq!(resolved.http_tls_ca_cert.unwrap(), PathBuf::from("/http/ca.pem"));
    }

    #[test]
    fn test_http_cli_overrides_file() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                http: Some(HttpSection {
                    enabled: Some(false),
                    listen_address: Some("0.0.0.0:9000".to_string()),
                    tls_mode: Some("mtls".to_string()),
                    tls_cert: Some(PathBuf::from("/file/cert.pem")),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let cli = ServeArgs {
            keystore_dir: Some(PathBuf::from("/ks")),
            http_enabled: true,
            http_listen_address: Some("127.0.0.1:7000".to_string()),
            http_tls_mode: Some("server-tls-only".to_string()),
            http_tls_cert: Some(PathBuf::from("/cli/cert.pem")),
            ..empty_cli()
        };
        let resolved = merge_with_cli(config, &cli).unwrap();
        assert!(resolved.http_enabled); // CLI flag OR file → enabled
        assert_eq!(resolved.http_listen_address, "127.0.0.1:7000");
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::ServerTlsOnly);
        assert_eq!(resolved.http_tls_cert.unwrap(), PathBuf::from("/cli/cert.pem"));
    }

    #[test]
    fn test_http_invalid_tls_mode_is_hard_error() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                http: Some(HttpSection {
                    tls_mode: Some("none".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let err = merge_with_cli(config, &empty_cli()).unwrap_err().to_string();
        assert!(err.contains("tls_mode"), "error must name the offending field: {err}");
        assert!(err.contains("none"), "error must name the bad value: {err}");
    }

    #[test]
    fn test_http_default_mode_is_mtls_when_enabled_without_mode() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                http: Some(HttpSection { enabled: Some(true), ..Default::default() }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolved = merge_with_cli(config, &empty_cli()).unwrap();
        assert!(resolved.http_enabled);
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::Mtls);
        assert_eq!(resolved.http_listen_address, DEFAULT_HTTP_LISTEN_ADDRESS);
    }

    // ── RF5-23: Option-CLI precedence (F31 bug fix) ──────────────────────────

    /// An explicitly passed CLI value that equals the built-in default must
    /// beat the config file (the F31 default-equals-unset bug).
    #[test]
    fn test_explicit_cli_value_equal_to_default_beats_config_file() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                listen_address: Some("0.0.0.0:9999".to_string()),
                network: Some("holesky".to_string()),
                reload_interval_secs: Some(99),
                #[cfg(feature = "dvt")]
                backend: Some(Backend::Dvt),
                #[cfg(not(feature = "dvt"))]
                backend: Some(Backend::Basic),
                http: Some(HttpSection {
                    listen_address: Some("0.0.0.0:1".to_string()),
                    tls_mode: Some("server-tls-only".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        // Explicitly pass values that equal the built-in defaults.
        let cli = ServeArgs {
            listen_address: Some(DEFAULT_LISTEN_ADDRESS.to_string()),
            network: Some(DEFAULT_NETWORK.to_string()),
            reload_interval: Some(DEFAULT_RELOAD_INTERVAL_SECS),
            backend: Some(Backend::Basic),
            http_listen_address: Some(DEFAULT_HTTP_LISTEN_ADDRESS.to_string()),
            http_tls_mode: Some(DEFAULT_HTTP_TLS_MODE.to_string()),
            ..empty_cli()
        };
        let resolved = merge_with_cli(config, &cli).unwrap();
        assert_eq!(
            resolved.listen_address, DEFAULT_LISTEN_ADDRESS,
            "explicit CLI default-equal value must beat file"
        );
        assert_eq!(
            resolved.genesis_fork_version,
            eth_types::NetworkPreset::MAINNET.genesis_fork_version,
            "explicit --network mainnet must beat file holesky"
        );
        assert_eq!(resolved.reload_interval_secs, DEFAULT_RELOAD_INTERVAL_SECS);
        assert_eq!(resolved.backend, Backend::Basic);
        assert_eq!(resolved.http_listen_address, DEFAULT_HTTP_LISTEN_ADDRESS);
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::Mtls);
    }

    #[test]
    fn test_unset_flag_falls_back_to_config_file() {
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                listen_address: Some("10.1.2.3:4444".to_string()),
                reload_interval_secs: Some(7),
                network: Some("sepolia".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolved = merge_with_cli(config, &empty_cli()).unwrap();
        assert_eq!(resolved.listen_address, "10.1.2.3:4444");
        assert_eq!(resolved.reload_interval_secs, 7);
        assert_eq!(
            resolved.genesis_fork_version,
            eth_types::NetworkPreset::SEPOLIA.genesis_fork_version
        );
    }

    #[test]
    fn test_unset_flag_and_no_file_uses_builtin_default() {
        let cli = cli_with_keystore("/ks");
        let resolved = merge_with_cli(SignerConfig::default(), &cli).unwrap();
        assert_eq!(resolved.listen_address, DEFAULT_LISTEN_ADDRESS);
        assert_eq!(resolved.backend, Backend::Basic);
        assert_eq!(resolved.reload_interval_secs, DEFAULT_RELOAD_INTERVAL_SECS);
        assert_eq!(resolved.dvt_timeout_ms, DEFAULT_DVT_TIMEOUT_MS);
        assert_eq!(resolved.http_listen_address, DEFAULT_HTTP_LISTEN_ADDRESS);
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::Mtls);
        assert_eq!(resolved.metrics_address, DEFAULT_METRICS_ADDRESS);
        assert_eq!(
            resolved.genesis_fork_version,
            eth_types::NetworkPreset::MAINNET.genesis_fork_version
        );
    }

    #[test]
    fn test_dvt_flags_resolve_under_both_feature_sets() {
        // Non-dvt (and dvt) builds always resolve timeout from file/default when
        // the CLI flag is absent. With the dvt feature, an explicit CLI value wins.
        let config = SignerConfig {
            signer: Some(SignerSection {
                keystore_dir: Some(PathBuf::from("/ks")),
                dvt: Some(DvtConfig {
                    timeout_ms: Some(4242),
                    peers: Some(vec!["file-peer:1".to_string()]),
                    threshold: Some(2),
                    index: Some(1),
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let resolved_file = merge_with_cli(config, &empty_cli()).unwrap();
        assert_eq!(resolved_file.dvt_timeout_ms, 4242);
        assert_eq!(resolved_file.dvt_peers, vec!["file-peer:1"]);
        assert_eq!(resolved_file.dvt_threshold, Some(2));
        assert_eq!(resolved_file.dvt_index, Some(1));

        #[cfg(feature = "dvt")]
        {
            let config = SignerConfig {
                signer: Some(SignerSection {
                    keystore_dir: Some(PathBuf::from("/ks")),
                    dvt: Some(DvtConfig {
                        timeout_ms: Some(4242),
                        peers: Some(vec!["file-peer:1".to_string()]),
                        threshold: Some(2),
                        index: Some(1),
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let cli = ServeArgs {
                dvt_timeout: Some(DEFAULT_DVT_TIMEOUT_MS),
                dvt_peers: vec!["cli-peer:9".to_string()],
                dvt_threshold: Some(3),
                dvt_index: Some(0),
                ..empty_cli()
            };
            let resolved = merge_with_cli(config, &cli).unwrap();
            assert_eq!(
                resolved.dvt_timeout_ms, DEFAULT_DVT_TIMEOUT_MS,
                "explicit CLI default-equal dvt timeout must beat file"
            );
            assert_eq!(resolved.dvt_peers, vec!["cli-peer:9"]);
            assert_eq!(resolved.dvt_threshold, Some(3));
            assert_eq!(resolved.dvt_index, Some(0));
        }
    }

    #[test]
    fn test_fork_schedule_toml_sets_gloas_fork_epoch_without_signer_knob() {
        let resolved = merge_with_cli(SignerConfig::default(), &cli_with_keystore("/ks")).unwrap();
        assert_eq!(resolved.gloas_fork_epoch, u64::MAX);

        let config: SignerConfig = toml::from_str(
            r#"
[signer]
keystore_dir = "/ks"

[fork_schedule]
gloas_fork_epoch = 100
"#,
        )
        .expect("[fork_schedule] must parse on SignerConfig");
        assert_eq!(config.fork_schedule.gloas_fork_epoch, Some(100));
        let resolved = merge_with_cli(config, &empty_cli()).unwrap();
        assert_eq!(resolved.gloas_fork_epoch, 100);

        let sentinel: SignerConfig = toml::from_str(
            r#"
[signer]
keystore_dir = "/ks"

[fork_schedule]
gloas_fork_epoch = "18446744073709551615"
"#,
        )
        .expect("sentinel decimal string");
        let resolved = merge_with_cli(sentinel, &empty_cli()).unwrap();
        assert_eq!(resolved.gloas_fork_epoch, u64::MAX);
    }

    /// Defaults are named constants in this module — a source-level pin so
    /// they are not reintroduced as clap `default_value` magic elsewhere.
    #[test]
    fn test_defaults_defined_in_exactly_one_place() {
        // Table-driven pin of the constants merge uses.
        let table: &[(&str, &str)] = &[
            ("listen", DEFAULT_LISTEN_ADDRESS),
            ("http_listen", DEFAULT_HTTP_LISTEN_ADDRESS),
            ("http_tls_mode", DEFAULT_HTTP_TLS_MODE),
            ("metrics", DEFAULT_METRICS_ADDRESS),
            ("network", DEFAULT_NETWORK),
            ("log_format", DEFAULT_LOG_FORMAT),
        ];
        assert_eq!(table[0].1, "127.0.0.1:50052");
        assert_eq!(table[1].1, "127.0.0.1:9000");
        assert_eq!(table[2].1, "mtls");
        assert_eq!(table[3].1, "127.0.0.1:9101");
        assert_eq!(table[4].1, "mainnet");
        assert_eq!(table[5].1, "pretty");
        assert_eq!(DEFAULT_RELOAD_INTERVAL_SECS, 30);
        assert_eq!(DEFAULT_DVT_TIMEOUT_MS, 2000);

        // Empty CLI + empty file must resolve to those constants.
        let resolved = merge_with_cli(SignerConfig::default(), &cli_with_keystore("/ks")).unwrap();
        assert_eq!(resolved.listen_address, DEFAULT_LISTEN_ADDRESS);
        assert_eq!(resolved.reload_interval_secs, DEFAULT_RELOAD_INTERVAL_SECS);
        assert_eq!(resolved.dvt_timeout_ms, DEFAULT_DVT_TIMEOUT_MS);
        assert_eq!(resolved.metrics_address, DEFAULT_METRICS_ADDRESS);
        assert_eq!(resolved.http_listen_address, DEFAULT_HTTP_LISTEN_ADDRESS);
        assert_eq!(resolved.http_tls_mode, HttpTlsMode::Mtls);
        assert_eq!(resolved.backend, Backend::Basic);
    }

    /// Clap parse: omitting a defaulted flag leaves `None` / false, not the
    /// filled default string.
    #[test]
    fn test_serve_args_parse_leaves_defaults_as_none() {
        // `ServeArgs` is an `Args`/`Parser` struct (subcommand body); the first
        // token is the binary name and is ignored by clap.
        let args = ServeArgs::try_parse_from(["rvc-signer"]).expect("empty serve args parse");
        assert!(args.listen_address.is_none());
        assert!(args.backend.is_none());
        assert!(args.reload_interval.is_none());
        assert!(args.http_listen_address.is_none());
        assert!(args.http_tls_mode.is_none());
        assert!(args.network.is_none());
        assert!(args.metrics_address.is_none());
        assert!(args.log_format.is_none());
        assert!(!args.dry_run);
        assert!(!args.http_enabled);
        assert!(!args.enable_hot_reload);
    }

    #[test]
    fn test_serve_args_parse_explicit_default_equal_values() {
        let args = ServeArgs::try_parse_from([
            "serve",
            "--listen-address",
            DEFAULT_LISTEN_ADDRESS,
            "--backend",
            "basic",
            "--reload-interval",
            "30",
            "--network",
            "mainnet",
            "--http-listen-address",
            DEFAULT_HTTP_LISTEN_ADDRESS,
            "--http-tls-mode",
            DEFAULT_HTTP_TLS_MODE,
            "--metrics-address",
            DEFAULT_METRICS_ADDRESS,
            "--log-format",
            "pretty",
        ])
        .expect("explicit default-equal flags must parse");
        assert_eq!(args.listen_address.as_deref(), Some(DEFAULT_LISTEN_ADDRESS));
        assert_eq!(args.backend, Some(Backend::Basic));
        assert_eq!(args.reload_interval, Some(30));
        assert_eq!(args.network.as_deref(), Some("mainnet"));
        assert_eq!(args.http_listen_address.as_deref(), Some(DEFAULT_HTTP_LISTEN_ADDRESS));
        assert_eq!(args.http_tls_mode.as_deref(), Some(DEFAULT_HTTP_TLS_MODE));
        assert_eq!(args.metrics_address.as_deref(), Some(DEFAULT_METRICS_ADDRESS));
        assert_eq!(args.log_format.as_deref(), Some("pretty"));
    }

    #[test]
    fn test_resolve_config_loads_file_and_merges() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/from-file/ks"
listen_address = "0.0.0.0:1"
"#,
        );
        let args = ServeArgs {
            config: Some(f.path().to_path_buf()),
            listen_address: Some(DEFAULT_LISTEN_ADDRESS.to_string()),
            ..empty_cli()
        };
        let resolved = resolve_config(&args).unwrap();
        assert_eq!(resolved.keystore_dir, PathBuf::from("/from-file/ks"));
        assert_eq!(
            resolved.listen_address, DEFAULT_LISTEN_ADDRESS,
            "explicit CLI default-equal must beat file via resolve_config"
        );
    }

    // ── RF5-24: Backend stays an enum through ResolvedConfig ─────────────────

    #[test]
    fn test_backend_deserializes_from_toml_as_enum() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"
backend = "basic"
"#,
        );
        let cfg = load_config(f.path()).unwrap();
        assert_eq!(cfg.signer.as_ref().unwrap().backend, Some(Backend::Basic));
        let resolved = merge_with_cli(cfg, &empty_cli()).unwrap();
        assert_eq!(resolved.backend, Backend::Basic);
        assert_eq!(resolved.backend.as_str(), "basic");
    }

    #[test]
    fn test_invalid_backend_value_rejected_at_deserialization() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"
backend = "not-a-backend"
"#,
        );
        let err = load_config(f.path()).unwrap_err().to_string();
        assert!(
            err.contains("backend") || err.contains("not-a-backend") || err.contains("unknown"),
            "invalid backend must fail deserialization clearly: {err}"
        );
    }

    #[test]
    fn test_backend_label_strings_unchanged_in_metrics() {
        // External contract: metric/audit label tokens are exactly these strings.
        assert_eq!(Backend::Basic.as_str(), "basic");
        assert_eq!(Backend::Basic.to_string(), "basic");
        #[cfg(feature = "dvt")]
        {
            assert_eq!(Backend::Dvt.as_str(), "dvt");
            assert_eq!(Backend::Dvt.to_string(), "dvt");
        }
    }

    #[cfg(feature = "dvt")]
    #[test]
    fn test_dvt_backend_selected_by_enum_match() {
        let f = write_toml(
            r#"
[signer]
keystore_dir = "/ks"
backend = "dvt"
"#,
        );
        let cfg = load_config(f.path()).unwrap();
        assert_eq!(cfg.signer.as_ref().unwrap().backend, Some(Backend::Dvt));
        let resolved = merge_with_cli(cfg, &empty_cli()).unwrap();
        assert_eq!(resolved.backend, Backend::Dvt);
        match resolved.backend {
            Backend::Dvt => {}
            Backend::Basic => panic!("TOML backend=dvt must resolve to Backend::Dvt"),
        }
    }
}
