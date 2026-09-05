//! Config section structs (clap `Args` groups).
//!
//! ARCH-4f: tracing, keymanager, grpc_signer, monitoring.
//! ARCH-4g: logfile, proposer_config, builder_limits, secret_provider (+ keys
//! clap group that flattens `SecretProviderArgs`).
//! ARCH-4h: beacon, server, network, safety, slashing; `[keys]` finished.
//! `*Args::resolved()` is not called from `Config::load`.

mod beacon;
mod builder_limits;
mod fork_schedule;
mod grpc_signer;
mod keymanager;
mod keys;
mod logfile;
mod monitoring;
mod network;
mod proposer_config;
mod safety;
mod secret_provider;
mod server;
mod slashing;
mod timing;
mod tracing;

pub use beacon::{BeaconArgs, BeaconConfig};
pub use builder_limits::{BuilderLimits, BuilderLimitsArgs};
pub use fork_schedule::ForkScheduleConfig;
pub use grpc_signer::{GrpcSignerArgs, GrpcSignerConfig};
pub use keymanager::{KeymanagerArgs, KeymanagerConfig};
pub use keys::{KeysArgs, KeysConfig};
pub use logfile::{LogfileArgs, LogfileConfig};
pub use monitoring::{MonitoringArgs, MonitoringConfig};
pub use network::{NetworkArgs, NetworkConfig};
pub use proposer_config::{ProposerConfigArgs, ProposerConfigSource};
pub use safety::{SafetyArgs, SafetyConfig, SlashedAction};
pub use secret_provider::{
    GcpSecretArgs, GcpSecretConfig, SecretProviderArgs, SecretProviderConfig,
};
pub use server::{ServerArgs, ServerConfig};
pub use slashing::{SlashingArgs, SlashingConfig};
pub use timing::TimingConfig;
pub use tracing::{TracingArgs, TracingConfig, TracingExporter};

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    use super::*;

    /// Pre-move `rvc start` long flags for the four clean groups (20 knobs).
    const PRE_MOVE_LONG_FLAGS_4F: &[&str] = &[
        "--allow-insecure-remote-signer",
        "--grpc-signer-tls-ca-cert",
        "--grpc-signer-tls-cert",
        "--grpc-signer-tls-key",
        "--grpc-signer-url",
        "--keymanager-address",
        "--keymanager-body-limit",
        "--keymanager-cors-origins",
        "--keymanager-enabled",
        "--keymanager-token-file",
        "--monitoring-endpoint",
        "--monitoring-endpoint-insecure",
        "--monitoring-interval",
        "--remote-signer-allowed-hosts",
        "--remote-signer-url",
        "--tracing-endpoint",
        "--tracing-exporter",
        "--tracing-max-export-batch-size",
        "--tracing-max-queue-size",
        "--tracing-sample-rate",
    ];

    /// Pre-move longs for the ARCH-4h clap groups (22 knobs + 4 BN timeouts +
    /// 2 slashing BYPASS flags). Timeouts are Config knobs as of ARCH-4j;
    /// `strict_*` stay CLI-only.
    const PRE_MOVE_LONG_FLAGS_4H: &[&str] = &[
        "--aggregate-timeout",
        "--allow-unsupported-fork",
        "--attestation-timeout",
        "--beacon-max-body-bytes",
        "--beacon-nodes",
        "--beacon-url",
        "--block-production-timeout",
        "--disable-attesting",
        "--duty-fetch-timeout",
        "--genesis-time",
        "--genesis-validators-root",
        "--graffiti",
        "--init-slashing-db",
        "--metrics-address",
        "--metrics-port",
        "--network",
        "--no-doppelganger-detection",
        "--slashed-validators-action",
        "--slashing-db-path",
        "--slashing-group-commit-batch-size",
        "--slashing-group-commit-wait-to-fill-ms",
        "--strict-permissions",
        "--strict-slashing-semantics",
    ];

    /// Pre-move longs for the 17 dotted knobs of the four partial sections.
    /// The 6 bare knobs stay on CLI wrappers (`log_level`, `proposer_nodes`,
    /// `broadcast`, `block_selection_mode`, `validator_registration_batch_*`).
    const PRE_MOVE_LONG_FLAGS_4G: &[&str] = &[
        "--builder-circuit-breaker-consecutive-limit",
        "--builder-circuit-breaker-epoch-limit",
        "--gcp-project-id",
        "--gcp-secret-prefix",
        "--logfile",
        "--logfile-compress",
        "--logfile-level",
        "--logfile-max-number",
        "--logfile-max-size",
        "--proposer-config-file",
        "--proposer-config-refresh-interval",
        "--proposer-config-url",
        "--proposer-config-url-insecure",
        "--proposer-config-url-token",
        "--secret-provider",
        "--secret-provider-strict",
        "--secret-refresh-interval",
    ];

    #[derive(Parser, Debug)]
    #[command(name = "rvc-start-probe", no_binary_name = true)]
    struct MigratedSectionsProbe {
        #[command(flatten)]
        tracing: TracingArgs,
        #[command(flatten)]
        keymanager: KeymanagerArgs,
        #[command(flatten)]
        grpc_signer: GrpcSignerArgs,
        #[command(flatten)]
        monitoring: MonitoringArgs,
        #[command(flatten)]
        logfile: LogfileArgs,
        #[command(flatten)]
        proposer_config: ProposerConfigArgs,
        #[command(flatten)]
        builder_limits: BuilderLimitsArgs,
        #[command(flatten)]
        keys: KeysArgs,
        #[command(flatten)]
        beacon: BeaconArgs,
        #[command(flatten)]
        server: ServerArgs,
        #[command(flatten)]
        network: NetworkArgs,
        #[command(flatten)]
        safety: SafetyArgs,
        #[command(flatten)]
        slashing: SlashingArgs,
    }

    fn probe_long_flags() -> Vec<String> {
        let cmd = MigratedSectionsProbe::command();
        let mut flags: Vec<String> = cmd
            .get_arguments()
            .filter_map(|arg| arg.get_long().map(|l| format!("--{l}")))
            .filter(|f| f != "--help" && f != "--version")
            .collect();
        flags.sort();
        flags.dedup();
        flags
    }

    #[test]
    fn tracing_section_flat_alias_still_parses() {
        let flat: TracingArgs =
            toml::from_str(r#"tracing_endpoint = "http://x""#).expect("flat alias");
        let nested: TracingArgs = toml::from_str(r#"endpoint = "http://x""#).expect("nested name");
        assert_eq!(flat.endpoint.as_deref(), Some("http://x"));
        assert_eq!(flat.endpoint, nested.endpoint);
        assert_eq!(flat, nested);
    }

    #[test]
    fn otel_env_fallback_is_still_config_else_env() {
        let _guard = otel_env_lock();
        std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-must-lose:4318");
        std::env::set_var("OTEL_TRACES_SAMPLER_ARG", "0.9");

        let tracing = TracingConfig {
            endpoint: Some("http://config-wins:4318".into()),
            sample_rate: Some(0.25),
            ..Default::default()
        };
        assert_eq!(tracing.resolve_endpoint().as_deref(), Some("http://config-wins:4318"));
        assert!((tracing.resolve_sample_rate() - 0.25).abs() < f64::EPSILON);

        std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
        std::env::remove_var("OTEL_TRACES_SAMPLER_ARG");
    }

    #[test]
    fn clap_long_flags_unchanged_for_migrated_sections() {
        // Parse forces clap debug_asserts (unique arg ids across flattened groups).
        MigratedSectionsProbe::try_parse_from(std::iter::empty::<&str>())
            .expect("flattened groups must parse with unique clap ids");
        let flags = probe_long_flags();
        let expected: Vec<&str> = {
            let mut v = PRE_MOVE_LONG_FLAGS_4F.to_vec();
            v.extend_from_slice(PRE_MOVE_LONG_FLAGS_4G);
            v.push("--no-keymanager");
            v.extend_from_slice(&[
                "--keystore-path",
                "--password-file",
                "--key-decrypt-threads",
                "--disable-keystore-locking",
                "--validators-config",
            ]);
            v.extend_from_slice(PRE_MOVE_LONG_FLAGS_4H);
            v.sort();
            v
        };
        let actual: Vec<&str> = flags.iter().map(String::as_str).collect();
        for flag in PRE_MOVE_LONG_FLAGS_4F {
            assert!(actual.contains(flag), "migrated section missing pre-move flag {flag}");
        }
        for flag in PRE_MOVE_LONG_FLAGS_4G {
            assert!(actual.contains(flag), "ARCH-4g section missing pre-move flag {flag}");
        }
        for flag in PRE_MOVE_LONG_FLAGS_4H {
            assert!(actual.contains(flag), "ARCH-4h section missing pre-move flag {flag}");
        }
        assert_eq!(PRE_MOVE_LONG_FLAGS_4F.len(), 20, "ARCH-4f migrates 20 knobs");
        assert_eq!(PRE_MOVE_LONG_FLAGS_4G.len(), 17, "ARCH-4g migrates 17 dotted knobs");
        assert_eq!(actual, expected, "unexpected extra or renamed long flags: {actual:?}");
    }

    #[test]
    fn keys_args_flattens_secret_provider_args() {
        let parsed = MigratedSectionsProbe::try_parse_from([
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
        .expect("nested KeysArgs → SecretProviderArgs flatten must parse");
        assert_eq!(parsed.keys.secret_provider.providers.as_deref(), Some("gcp"));
        assert_eq!(parsed.keys.secret_provider.gcp.project_id.as_deref(), Some("X"));
        assert_eq!(parsed.keys.secret_provider.gcp.secret_prefix.as_deref(), Some("vk-"));
        assert_eq!(parsed.keys.secret_provider.refresh_interval, Some(60));
        assert_eq!(parsed.keys.secret_provider.strict, Some(true));
    }

    #[test]
    fn migrated_section_fields_have_no_clap_default_value() {
        let src = concat!(
            include_str!("tracing.rs"),
            include_str!("keymanager.rs"),
            include_str!("grpc_signer.rs"),
            include_str!("monitoring.rs"),
            include_str!("logfile.rs"),
            include_str!("proposer_config.rs"),
            include_str!("builder_limits.rs"),
            include_str!("secret_provider.rs"),
            include_str!("keys.rs"),
            include_str!("beacon.rs"),
            include_str!("server.rs"),
            include_str!("network.rs"),
        );
        for line in src.lines() {
            let t = line.trim();
            assert!(
                !t.contains("default_value =") && !t.contains("default_value_t"),
                "ARCH-4f/4g/4h section clap field must not set default_value: {t}"
            );
        }
        // Present-only bools that already had default_value_t = false (verbatim).
        // They go through flag() / Option lift and do not clobber TOML (ADR-009).
        for (path, src) in
            [("safety.rs", include_str!("safety.rs")), ("slashing.rs", include_str!("slashing.rs"))]
        {
            for line in src.lines() {
                let t = line.trim();
                if t.contains("allow-unsupported-fork") || t.contains("init-slashing-db") {
                    continue;
                }
                assert!(
                    !t.contains("default_value =") && !t.contains("default_value_t"),
                    "{path} clap field must not set default_value: {t}"
                );
            }
        }
    }

    #[test]
    fn a_4_4_is_recorded_on_each_partial_section() {
        for (path, src) in [
            ("logfile.rs", include_str!("logfile.rs")),
            ("proposer_config.rs", include_str!("proposer_config.rs")),
            ("builder_limits.rs", include_str!("builder_limits.rs")),
            ("secret_provider.rs", include_str!("secret_provider.rs")),
        ] {
            assert!(
                src.contains("A-4.4"),
                "{path} module doc must record A-4.4 (existing TOML section wins)"
            );
        }
        assert!(
            include_str!("keys.rs").contains("A-4.5"),
            "keys.rs must record A-4.5 (flatten SecretProviderArgs)"
        );
        assert!(
            include_str!("secret_provider.rs").contains("A-4.5"),
            "secret_provider.rs must record A-4.5"
        );
    }

    fn otel_env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
    }
}
