//! CLI types and command dispatch for the `rvc` binary.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use rvc::config::{Config, StartArgs};
use tracing::{error, info, warn};

use crate::commands;
use crate::logging::{
    build_file_layer_config, build_tracing_config, init_logging, spawn_log_reload_handler,
};

#[derive(Parser)]
#[command(name = "rvc")]
#[command(version)]
#[command(about = "Rust Validator Client - Ethereum consensus layer validator", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Start the validator client
    Start(Box<StartArgs>),

    /// Submit a voluntary exit for a validator
    VoluntaryExit {
        /// Validator public key (hex, with or without 0x prefix)
        #[arg(long)]
        pubkey: String,

        /// Exit epoch (defaults to current epoch if not specified)
        #[arg(long)]
        epoch: Option<u64>,

        /// Skip interactive confirmation prompt
        #[arg(long)]
        confirm: bool,

        /// Beacon node URL (e.g., http://localhost:5052)
        #[arg(long, default_value = "http://localhost:5052")]
        beacon_url: String,

        /// Path to the keystore directory
        #[arg(long)]
        keystore_path: PathBuf,

        /// Path to the password file for keystore decryption
        #[arg(long)]
        password_file: PathBuf,

        /// Path to the slashing protection database
        #[arg(long)]
        slashing_db_path: Option<PathBuf>,

        /// Network preset (mainnet, hoodi, holesky, sepolia, custom)
        #[arg(long)]
        network: Option<String>,

        /// Genesis validators root override (hex string with 0x prefix)
        #[arg(long)]
        genesis_validators_root: Option<String>,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Prepare a pre-signed voluntary exit (sign and save to file, without submitting)
    PrepareExit {
        /// Validator public key (hex, with or without 0x prefix)
        #[arg(long)]
        pubkey: String,

        /// Exit epoch (defaults to current epoch if not specified)
        #[arg(long)]
        epoch: Option<u64>,

        /// Output directory for the signed exit JSON file
        #[arg(long, default_value = ".")]
        output: PathBuf,

        /// Beacon node URL (e.g., http://localhost:5052)
        #[arg(long, default_value = "http://localhost:5052")]
        beacon_url: String,

        /// Path to the keystore directory
        #[arg(long)]
        keystore_path: PathBuf,

        /// Path to the password file for keystore decryption
        #[arg(long)]
        password_file: PathBuf,

        /// Path to the slashing protection database
        #[arg(long)]
        slashing_db_path: Option<PathBuf>,

        /// Network preset (mainnet, hoodi, holesky, sepolia, custom)
        #[arg(long)]
        network: Option<String>,

        /// Genesis validators root override (hex string with 0x prefix)
        #[arg(long)]
        genesis_validators_root: Option<String>,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Submit a pre-signed voluntary exit to the beacon node (no signing keys required)
    SubmitExit {
        /// Path to the signed voluntary exit JSON file
        #[arg(long)]
        file: PathBuf,

        /// Beacon node URL (e.g., http://localhost:5052)
        #[arg(long, default_value = "http://localhost:5052")]
        beacon_url: String,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Slashing-protection maintenance (prune, etc.)
    Slashing {
        #[command(subcommand)]
        command: SlashingCommands,
    },
}

/// Subcommands under `rvc slashing` (RF2-13 / B5). Kept as a small nested enum so
/// Phase 5 F3 can relocate it without redesigning the arg surface.
#[derive(Subcommand)]
pub enum SlashingCommands {
    /// Delete historical slashing-protection rows below per-validator watermarks.
    ///
    /// Destructive and irreversible. Prefer `--dry-run` first; a real prune requires `--yes`.
    /// Refuses to create a fresh empty DB if the path is missing (same class of footgun as
    /// `--init-slashing-db` without opt-in).
    Prune {
        /// Path to an existing slashing protection database
        #[arg(long)]
        slashing_db_path: PathBuf,

        /// Report how many rows would be deleted without deleting them
        #[arg(long, default_value_t = false)]
        dry_run: bool,

        /// Confirm irreversible deletion of rows below watermarks
        #[arg(long, default_value_t = false)]
        yes: bool,

        /// Log level (trace, debug, info, warn, error)
        #[arg(long, default_value = "info")]
        log_level: String,
    },
}

/// Parse CLI and dispatch to the selected subcommand.
pub async fn dispatch(cli: Cli) -> anyhow::Result<()> {
    #[cfg(feature = "gcp-secret")]
    {
        use rustls::crypto::{ring::default_provider, CryptoProvider};
        let _ = CryptoProvider::install_default(default_provider());
    }

    match cli.command {
        Commands::Start(args) => {
            let args = *args;
            // Validate gRPC signer flags: if URL is set, all TLS flags are required
            if args.grpc_signer.url.is_some()
                && (args.grpc_signer.tls_cert.is_none()
                    || args.grpc_signer.tls_key.is_none()
                    || args.grpc_signer.tls_ca_cert.is_none())
            {
                anyhow::bail!(
                    "--grpc-signer-url requires --grpc-signer-tls-cert, \
                     --grpc-signer-tls-key, and --grpc-signer-tls-ca-cert"
                );
            }

            if let Some(n) = args.keys.key_decrypt_threads {
                if n == 0 {
                    anyhow::bail!("--key-decrypt-threads must be greater than 0");
                }
            }

            let config_path = args.config.clone();
            let log_format = args.logging.log_format.clone();
            let enable_log_reload = args.logging.enable_log_reload;
            let strict_permissions = args.slashing.strict_permissions;
            let strict_slashing_semantics = args.slashing.strict_slashing_semantics;

            if let Some(path) = config_path.as_ref() {
                info!(path = ?path, "Loading configuration from file");
            } else {
                info!("Using default configuration");
            }
            let cfg = Config::load(config_path.as_deref(), args)?;

            let tracing_config = build_tracing_config(&cfg);
            let file_layer_config = build_file_layer_config(&cfg);
            let log_format = telemetry::LogFormat::resolve(Some(&log_format));
            // Use post-merge cfg so a TOML log_level is not clobbered by a clap default.
            let logging_guards = init_logging(
                &cfg.log_level,
                log_format,
                tracing_config.as_ref(),
                file_layer_config.as_ref(),
            );

            info!(
                version = env!("CARGO_PKG_VERSION"),
                network = %cfg.network,
                commit = option_env!("GIT_COMMIT").unwrap_or("unknown"),
                "rvc starting"
            );

            if let Err(e) = cfg.validate() {
                error!("Configuration validation failed: {}", e);
                return Err(e.into());
            }
            let timeouts = cfg.operation_timeouts();

            if cfg.keymanager.allow_insecure_remote_signer {
                warn!("INSECURE MODE: HTTP remote signer URLs are allowed. Use only for development/testing.");
            }

            let shutdown_token = tokio_util::sync::CancellationToken::new();
            // ARCH-2h: keep shutdown_rx so panicking tasks trigger process drain.
            let (executor, shutdown_rx) = rvc::bootstrap::TaskExecutor::new(shutdown_token);
            spawn_log_reload_handler(
                enable_log_reload,
                logging_guards.reload_handle.clone(),
                &executor,
            );

            let run_result = rvc::bootstrap::run(
                cfg,
                rvc::bootstrap::RunOptions {
                    strict_permissions,
                    strict_slashing_semantics,
                    timeouts,
                },
                executor,
                shutdown_rx,
            )
            .await;

            // Logging guards drop after run returns (flush last).
            let _ = &logging_guards;

            // Named BootstrapError codes (unsupported-fork 13, keystore-lock 14, …)
            // map in synchronous main after the runtime drops (ARCH-2i); never
            // hard-exit mid-async here.
            run_result?;
        }
        Commands::VoluntaryExit {
            pubkey,
            epoch,
            confirm,
            beacon_url,
            keystore_path,
            password_file,
            slashing_db_path,
            network,
            genesis_validators_root,
            log_level,
        } => {
            // One-shot CLI commands have no `--log-format` flag; honor only the
            // `RVC_LOG_FORMAT` env (default pretty) via `resolve(None)`.
            init_logging(&log_level, telemetry::LogFormat::resolve(None), None, None);

            let args = commands::voluntary_exit::VoluntaryExitArgs {
                pubkey,
                epoch,
                confirm,
                beacon_url,
                keystore_path,
                password_file,
                slashing_db_path,
                network,
                genesis_validators_root,
            };

            commands::voluntary_exit::execute(args).await?;
        }
        Commands::PrepareExit {
            pubkey,
            epoch,
            output,
            beacon_url,
            keystore_path,
            password_file,
            slashing_db_path,
            network,
            genesis_validators_root,
            log_level,
        } => {
            init_logging(&log_level, telemetry::LogFormat::resolve(None), None, None);

            let args = commands::prepare_exit::PrepareExitArgs {
                pubkey,
                epoch,
                output,
                beacon_url,
                keystore_path,
                password_file,
                slashing_db_path,
                network,
                genesis_validators_root,
            };

            commands::prepare_exit::execute(args).await?;
        }
        Commands::SubmitExit { file, beacon_url, log_level } => {
            init_logging(&log_level, telemetry::LogFormat::resolve(None), None, None);

            let args = commands::submit_exit::SubmitExitArgs { file, beacon_url };

            commands::submit_exit::execute(args).await?;
        }
        Commands::Slashing { command } => match command {
            SlashingCommands::Prune { slashing_db_path, dry_run, yes, log_level } => {
                init_logging(&log_level, telemetry::LogFormat::resolve(None), None, None);
                // Ensure prune metrics are registered before the handler increments them.
                metrics::definitions::init_metrics();
                slashing::metrics::init();
                commands::slashing::execute_prune(commands::slashing::PruneArgs {
                    slashing_db_path,
                    dry_run,
                    yes,
                })?;
            }
        },
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;
    use clap::CommandFactory;
    use rvc::config::{
        BlockSelectionMode, BroadcastTopic, Network, SlashedAction, TracingExporter,
    };

    /// Complete long-flag surface for `rvc start` (RF5-14 help snapshot).
    const START_FLAGS: &[&str] = &[
        "--config",
        "--beacon-url",
        "--beacon-nodes",
        "--beacon-max-body-bytes",
        "--block-production-timeout",
        "--attestation-timeout",
        "--aggregate-timeout",
        "--duty-fetch-timeout",
        "--keystore-path",
        "--password-file",
        "--key-decrypt-threads",
        "--disable-keystore-locking",
        "--secret-provider",
        "--gcp-project-id",
        "--gcp-secret-prefix",
        "--secret-refresh-interval",
        "--secret-provider-strict",
        "--validators-config",
        "--metrics-address",
        "--metrics-port",
        "--network",
        "--genesis-time",
        "--genesis-validators-root",
        "--graffiti",
        "--log-level",
        "--log-format",
        "--enable-log-reload",
        "--logfile",
        "--logfile-max-size",
        "--logfile-max-number",
        "--logfile-compress",
        "--logfile-level",
        "--tracing-endpoint",
        "--tracing-exporter",
        "--tracing-sample-rate",
        "--tracing-max-queue-size",
        "--tracing-max-export-batch-size",
        "--keymanager-enabled",
        "--no-keymanager",
        "--keymanager-address",
        "--keymanager-token-file",
        "--remote-signer-url",
        "--remote-signer-allowed-hosts",
        "--allow-insecure-remote-signer",
        "--keymanager-cors-origins",
        "--keymanager-body-limit",
        "--grpc-signer-url",
        "--grpc-signer-tls-cert",
        "--grpc-signer-tls-key",
        "--grpc-signer-tls-ca-cert",
        "--no-doppelganger-detection",
        "--disable-attesting",
        "--slashed-validators-action",
        "--allow-unsupported-fork",
        "--builder-circuit-breaker-consecutive-limit",
        "--builder-circuit-breaker-epoch-limit",
        "--block-selection-mode",
        "--validator-registration-batch-size",
        "--validator-registration-batch-delay",
        "--proposer-nodes",
        "--broadcast",
        "--proposer-config-url",
        "--proposer-config-file",
        "--proposer-config-refresh-interval",
        "--proposer-config-url-token",
        "--proposer-config-url-insecure",
        "--monitoring-endpoint",
        "--monitoring-interval",
        "--monitoring-endpoint-insecure",
        "--slashing-db-path",
        "--init-slashing-db",
        "--strict-permissions",
        "--strict-slashing-semantics",
    ];

    #[test]
    fn test_start_help_lists_every_flag() {
        let mut cmd = Cli::command();
        let start = cmd.find_subcommand_mut("start").expect("start subcommand");
        let help = start.render_long_help().to_string();
        for flag in START_FLAGS {
            assert!(help.contains(flag), "start --help missing flag {flag}\n{help}");
        }
        // Short form for --config preserved.
        assert!(help.contains("-c, --config"), "short -c for --config missing:\n{help}");
    }

    #[test]
    fn test_start_args_load_onto_config() {
        let cli = Cli::try_parse_from([
            "rvc",
            "start",
            "--beacon-url",
            "http://bn:5052",
            "--beacon-nodes",
            "http://a:5052,http://b:5052",
            "--keystore-path",
            "/keys",
            "--password-file",
            "/pw",
            "--slashing-db-path",
            "/slash.db",
            "--init-slashing-db",
            "--allow-unsupported-fork",
            "--metrics-address",
            "0.0.0.0",
            "--metrics-port",
            "9090",
            "--network",
            "hoodi",
            "--genesis-time",
            "1",
            "--genesis-validators-root",
            "0xabc",
            "--graffiti",
            "rvc",
            "--no-doppelganger-detection",
            "--log-level",
            "debug",
            "--keymanager-enabled",
            "--keymanager-address",
            "127.0.0.1:5062",
            "--keymanager-token-file",
            "/token",
            "--remote-signer-url",
            "https://signer",
            "--remote-signer-allowed-hosts",
            "signer.local",
            "--key-decrypt-threads",
            "4",
            "--tracing-endpoint",
            "http://otel:4318",
            "--tracing-exporter",
            "otlp",
            "--tracing-sample-rate",
            "0.5",
            "--tracing-max-queue-size",
            "100",
            "--tracing-max-export-batch-size",
            "50",
            "--secret-provider",
            "gcp",
            "--gcp-project-id",
            "proj",
            "--gcp-secret-prefix",
            "vk-",
            "--secret-refresh-interval",
            "60",
            "--secret-provider-strict",
            "--allow-insecure-remote-signer",
            "--keymanager-cors-origins",
            "https://a,https://b",
            "--keymanager-body-limit",
            "2048",
            "--grpc-signer-url",
            "https://gs:50051",
            "--grpc-signer-tls-cert",
            "/c.pem",
            "--grpc-signer-tls-key",
            "/k.pem",
            "--grpc-signer-tls-ca-cert",
            "/ca.pem",
            "--disable-attesting",
            "--slashed-validators-action",
            "shutdown",
            "--builder-circuit-breaker-consecutive-limit",
            "2",
            "--builder-circuit-breaker-epoch-limit",
            "4",
            "--disable-keystore-locking",
            "--proposer-nodes",
            "http://p:5052",
            "--broadcast",
            "blocks,attestations",
            "--proposer-config-url",
            "https://pc",
            "--proposer-config-refresh-interval",
            "10",
            "--proposer-config-url-token",
            "tok",
            "--proposer-config-url-insecure",
            "--monitoring-endpoint",
            "https://mon",
            "--monitoring-interval",
            "30",
            "--monitoring-endpoint-insecure",
            "--logfile",
            "/var/log/rvc.log",
            "--logfile-max-size",
            "100",
            "--logfile-max-number",
            "3",
            "--logfile-compress",
            "--logfile-level",
            "warn",
            "--block-selection-mode",
            "builder-only",
            "--validator-registration-batch-size",
            "10",
            "--validator-registration-batch-delay",
            "20",
            "--validators-config",
            "/validators.toml",
            "--beacon-max-body-bytes",
            "1024",
        ])
        .expect("argv should parse");

        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        let cfg = Config::load(None, *args).expect("load");

        assert_eq!(cfg.beacon_url, "http://bn:5052");
        assert_eq!(
            cfg.beacon_nodes,
            vec!["http://a:5052".to_string(), "http://b:5052".to_string()]
        );
        assert_eq!(cfg.keystore_path, PathBuf::from("/keys"));
        assert_eq!(cfg.password_file, Some(PathBuf::from("/pw")));
        assert_eq!(cfg.slashing_db_path, PathBuf::from("/slash.db"));
        assert!(cfg.allow_fresh_db);
        assert!(cfg.allow_unsupported_fork);
        assert_eq!(cfg.metrics_address, "0.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(cfg.metrics_port, 9090);
        assert_eq!(cfg.network, Network::Hoodi);
        assert_eq!(cfg.genesis_time, Some(1));
        assert_eq!(cfg.genesis_validators_root.as_deref(), Some("0xabc"));
        assert_eq!(cfg.graffiti.as_deref(), Some("rvc"));
        assert_eq!(cfg.log_level, "debug");
        assert!(!cfg.doppelganger_detection);
        assert!(cfg.keymanager.enabled);
        assert_eq!(cfg.keymanager.address.as_deref(), Some("127.0.0.1:5062"));
        assert_eq!(cfg.keymanager.token_file, Some(PathBuf::from("/token")));
        assert_eq!(cfg.keymanager.remote_signer_url.as_deref(), Some("https://signer"));
        assert_eq!(
            cfg.keymanager.remote_signer_allowed_hosts.as_deref(),
            Some(["signer.local".to_string()].as_slice())
        );
        assert_eq!(cfg.key_decrypt_threads, Some(4));
        assert_eq!(cfg.tracing.endpoint.as_deref(), Some("http://otel:4318"));
        assert_eq!(cfg.tracing.exporter, TracingExporter::Otlp);
        assert_eq!(cfg.tracing.sample_rate, Some(0.5));
        assert_eq!(cfg.tracing.max_queue_size, Some(100));
        assert_eq!(cfg.tracing.max_export_batch_size, Some(50));
        assert_eq!(cfg.secret_provider.providers, vec!["gcp".to_string()]);
        assert_eq!(cfg.secret_provider.gcp.project_id.as_deref(), Some("proj"));
        assert_eq!(cfg.secret_provider.gcp.secret_prefix, "vk-");
        assert_eq!(cfg.secret_provider.refresh_interval, Some(60));
        assert!(cfg.secret_provider.strict);
        assert!(cfg.keymanager.allow_insecure_remote_signer);
        assert_eq!(
            cfg.keymanager.cors_origins,
            vec!["https://a".to_string(), "https://b".to_string()]
        );
        assert_eq!(cfg.keymanager.body_limit, 2048);
        assert_eq!(cfg.grpc_signer.url.as_deref(), Some("https://gs:50051"));
        assert_eq!(cfg.grpc_signer.tls_cert, Some(PathBuf::from("/c.pem")));
        assert_eq!(cfg.grpc_signer.tls_key, Some(PathBuf::from("/k.pem")));
        assert_eq!(cfg.grpc_signer.tls_ca_cert, Some(PathBuf::from("/ca.pem")));
        assert!(cfg.disable_attesting);
        assert_eq!(cfg.slashed_validators_action, SlashedAction::Shutdown);
        assert_eq!(cfg.builder_limits.circuit_breaker_consecutive_limit, 2);
        assert_eq!(cfg.builder_limits.circuit_breaker_epoch_limit, 4);
        assert!(cfg.disable_keystore_locking);
        assert_eq!(cfg.proposer_nodes, vec!["http://p:5052".to_string()]);
        assert_eq!(cfg.broadcast, vec![BroadcastTopic::Blocks, BroadcastTopic::Attestations]);
        assert_eq!(cfg.proposer_config.url.as_deref(), Some("https://pc"));
        assert_eq!(cfg.proposer_config.refresh_interval, 10);
        assert_eq!(cfg.proposer_config.url_token.as_deref(), Some("tok"));
        assert!(cfg.proposer_config.url_insecure);
        assert_eq!(cfg.monitoring.endpoint.as_deref(), Some("https://mon"));
        assert_eq!(cfg.monitoring.interval, 30);
        assert!(cfg.monitoring.endpoint_insecure);
        assert_eq!(cfg.logfile.path, Some(PathBuf::from("/var/log/rvc.log")));
        assert_eq!(cfg.logfile.max_size, 100);
        assert_eq!(cfg.logfile.max_number, 3);
        assert!(cfg.logfile.compress);
        assert_eq!(cfg.logfile.level.as_deref(), Some("warn"));
        assert_eq!(cfg.block_selection_mode, BlockSelectionMode::BuilderOnly);
        assert_eq!(cfg.validator_registration_batch_size, 10);
        assert_eq!(cfg.validator_registration_batch_delay, 20);
        assert_eq!(cfg.validators_config, Some(PathBuf::from("/validators.toml")));
        assert_eq!(cfg.beacon_max_body_bytes, 1024);
    }

    #[test]
    fn test_boolean_flags_absent_yield_none_not_some_false() {
        let cli = Cli::try_parse_from(["rvc", "start"]).expect("default start should parse");
        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        let defaults = Config::default();
        let cfg = Config::load(None, *args).expect("load");

        assert_eq!(cfg.allow_fresh_db, defaults.allow_fresh_db);
        assert_eq!(cfg.allow_unsupported_fork, defaults.allow_unsupported_fork);
        assert_eq!(cfg.doppelganger_detection, defaults.doppelganger_detection);
        assert_eq!(cfg.keymanager.enabled, defaults.keymanager.enabled);
        assert_eq!(cfg.secret_provider.strict, defaults.secret_provider.strict);
        assert_eq!(
            cfg.keymanager.allow_insecure_remote_signer,
            defaults.keymanager.allow_insecure_remote_signer
        );
        assert_eq!(cfg.disable_attesting, defaults.disable_attesting);
        assert_eq!(cfg.disable_keystore_locking, defaults.disable_keystore_locking);
        assert_eq!(cfg.proposer_config.url_insecure, defaults.proposer_config.url_insecure);
        assert_eq!(cfg.monitoring.endpoint_insecure, defaults.monitoring.endpoint_insecure);
        assert_eq!(cfg.logfile.compress, defaults.logfile.compress);
        // RF5-15: no default_value_t — absent flag leaves sample_rate unset.
        assert_eq!(cfg.tracing.sample_rate, defaults.tracing.sample_rate);
        // ADR-009 / ARCH-6b: former clap-default fields stay at Config defaults.
        assert_eq!(cfg.metrics_address, defaults.metrics_address);
        assert_eq!(cfg.metrics_port, defaults.metrics_port);
        assert_eq!(cfg.log_level, defaults.log_level);
        assert_eq!(cfg.tracing.exporter, defaults.tracing.exporter);
        assert_eq!(cfg.keymanager.body_limit, defaults.keymanager.body_limit);
        assert_eq!(cfg.slashed_validators_action, defaults.slashed_validators_action);
        assert_eq!(cfg.beacon_max_body_bytes, defaults.beacon_max_body_bytes);
    }

    #[test]
    fn secret_provider_knobs_reachable_from_both_cli_and_nested_table() {
        use rvc::config::Config;
        use std::io::Write;

        let cli = Cli::try_parse_from([
            "rvc",
            "start",
            "--secret-provider",
            "gcp",
            "--gcp-project-id",
            "X",
            "--gcp-secret-prefix",
            "vk-",
            "--secret-refresh-interval",
            "60",
            "--secret-provider-strict",
        ])
        .expect("secret-provider CLI flags must parse through KeysArgs flatten");
        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        let from_cli = Config::load(None, *args).expect("load");

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
[secret_provider]
providers = ["gcp"]
refresh_interval = 60
strict = true

[secret_provider.gcp]
project_id = "X"
secret_prefix = "vk-"
"#
        )
        .unwrap();
        let from_toml = Config::from_file(file.path()).unwrap();

        assert_eq!(from_cli.secret_provider.providers, from_toml.secret_provider.providers);
        assert_eq!(
            from_cli.secret_provider.refresh_interval,
            from_toml.secret_provider.refresh_interval
        );
        assert_eq!(from_cli.secret_provider.strict, from_toml.secret_provider.strict);
        assert_eq!(
            from_cli.secret_provider.gcp.project_id,
            from_toml.secret_provider.gcp.project_id
        );
        assert_eq!(
            from_cli.secret_provider.gcp.secret_prefix,
            from_toml.secret_provider.gcp.secret_prefix
        );
        assert_eq!(from_cli.secret_provider.gcp.project_id.as_deref(), Some("X"));

        let cli_json = serde_json::to_string(&from_cli).expect("serialize CLI Config");
        let toml_json = serde_json::to_string(&from_toml).expect("serialize TOML Config");
        assert_eq!(
            cli_json, toml_json,
            "CLI flags and [secret_provider] table must yield the same Config"
        );
    }

    /// ADR-009: TOML values must survive when the matching clap flag is absent.
    /// Before ARCH-6b, clap `default_value` + unconditional `Some(...)` forced 8080 over 9090.
    #[test]
    fn a_toml_metrics_port_survives_when_the_flag_is_absent() {
        use rvc::config::Config;
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
metrics_port = 9090
keymanager_body_limit = 2048
beacon_max_body_bytes = 1024
log_level = "debug"
metrics_address = "0.0.0.0"
tracing_exporter = "gcp"
slashed_validators_action = "shutdown"
"#
        )
        .unwrap();

        let cli = Cli::try_parse_from(["rvc", "start"]).expect("default start should parse");
        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        let cfg = Config::load(Some(file.path()), *args).expect("load");

        assert_eq!(
            cfg.metrics_port, 9090,
            "TOML metrics_port must not be clobbered by clap default"
        );
        assert_eq!(
            cfg.keymanager.body_limit, 2048,
            "TOML keymanager_body_limit must not be clobbered by clap default"
        );
        assert_eq!(
            cfg.beacon_max_body_bytes, 1024,
            "TOML beacon_max_body_bytes must not be clobbered by clap default"
        );
        assert_eq!(cfg.log_level, "debug");
        assert_eq!(
            cfg.metrics_address,
            "0.0.0.0".parse::<IpAddr>().unwrap(),
            "TOML metrics_address must not be clobbered"
        );
        assert_eq!(cfg.tracing.exporter, TracingExporter::Gcp);
        assert_eq!(cfg.slashed_validators_action, SlashedAction::Shutdown);
    }

    /// Explicit CLI flags still beat TOML (precedence CLI > file).
    #[test]
    fn an_explicit_flag_still_wins_over_the_toml() {
        use rvc::config::Config;
        use std::io::Write;

        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            r#"
beacon_url = "http://beacon:5052"
keystore_path = "/data/keystores"
slashing_db_path = "/data/slashing.db"
metrics_port = 9090
"#
        )
        .unwrap();

        let cli = Cli::try_parse_from(["rvc", "start", "--metrics-port", "7000"])
            .expect("argv should parse");
        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        let cfg = Config::load(Some(file.path()), *args).expect("load");

        assert_eq!(cfg.metrics_port, 7000);
    }

    #[test]
    fn test_clap_groups_mirror_config_sections() {
        // Each RF5-12 nested config group has a matching clap Args group with
        // the operator-facing flag names (not the nested TOML field names).
        let groups: &[(&str, &[&str])] = &[
            ("LoggingArgs", &["--log-level", "--logfile", "--logfile-max-size"]),
            ("TracingArgs", &["--tracing-endpoint", "--tracing-exporter", "--tracing-sample-rate"]),
            (
                "KeymanagerArgs",
                &["--keymanager-enabled", "--keymanager-address", "--remote-signer-url"],
            ),
            (
                "GrpcSignerArgs",
                &[
                    "--grpc-signer-url",
                    "--grpc-signer-tls-cert",
                    "--grpc-signer-tls-key",
                    "--grpc-signer-tls-ca-cert",
                ],
            ),
            ("ProposerArgs", &["--proposer-nodes", "--proposer-config-url", "--broadcast"]),
            ("MonitoringArgs", &["--monitoring-endpoint", "--monitoring-interval"]),
            (
                "BuilderArgs",
                &[
                    "--builder-circuit-breaker-consecutive-limit",
                    "--builder-circuit-breaker-epoch-limit",
                ],
            ),
            (
                "SlashingArgs",
                &[
                    "--slashing-db-path",
                    "--init-slashing-db",
                    "--slashing-group-commit-batch-size",
                    "--slashing-group-commit-wait-to-fill-ms",
                ],
            ),
            ("BeaconArgs", &["--beacon-url", "--beacon-nodes", "--beacon-max-body-bytes"]),
        ];

        let mut cmd = Cli::command();
        let start = cmd.find_subcommand_mut("start").expect("start");
        let help = start.render_long_help().to_string();
        for (group, flags) in groups {
            for flag in *flags {
                assert!(help.contains(flag), "{group} flag {flag} missing from start help");
            }
        }

        // Structural presence: parse with one flag from each group.
        let cli = Cli::try_parse_from([
            "rvc",
            "start",
            "--beacon-url",
            "http://localhost:5052",
            "--logfile",
            "/tmp/rvc.log",
            "--tracing-endpoint",
            "http://localhost:4318",
            "--keymanager-enabled",
            "--grpc-signer-url",
            "https://s:1",
            "--proposer-config-file",
            "/pc.toml",
            "--monitoring-endpoint",
            "https://m",
            "--builder-circuit-breaker-consecutive-limit",
            "1",
            "--slashing-db-path",
            "/s.db",
        ])
        .expect("group flags should parse together");
        let Commands::Start(args) = cli.command else {
            panic!("expected Start");
        };
        assert!(args.beacon.url.is_some());
        assert!(args.logging.logfile.path.is_some());
        assert!(args.tracing.endpoint.is_some());
        assert_eq!(args.keymanager.enabled, Some(true));
        assert!(args.grpc_signer.url.is_some());
        assert!(args.proposer.proposer_config.file.is_some());
        assert!(args.monitoring.endpoint.is_some());
        assert!(args.builder.builder_limits.circuit_breaker_consecutive_limit.is_some());
        assert!(args.slashing.slashing_db_path.is_some());
    }

    #[test]
    fn test_no_keymanager_and_keymanager_enabled_conflict() {
        let err = match Cli::try_parse_from([
            "rvc",
            "start",
            "--keymanager-enabled",
            "--no-keymanager",
        ]) {
            Ok(_) => panic!("flags must conflict"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("cannot be used with") || msg.contains("conflict"),
            "unexpected conflict message: {msg}"
        );
    }

    #[test]
    fn test_large_enum_variant_allow_removed() {
        // Commands::Start is now a single StartArgs field; the allow attribute
        // must not reappear on the Commands enum definition.
        let src = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cli.rs"));
        let commands_idx = src.find("pub enum Commands").expect("Commands enum");
        let after = &src[commands_idx..];
        let allow_nearby = src[..commands_idx]
            .lines()
            .rev()
            .take(5)
            .any(|l| l.contains("allow(clippy::large_enum_variant)"));
        assert!(
            !allow_nearby,
            "#[allow(clippy::large_enum_variant)] must be removed from Commands"
        );
        assert!(
            after.contains("Start(Box<StartArgs>)"),
            "Commands::Start must wrap Box<StartArgs> (keeps clippy size clean)"
        );
    }
}
