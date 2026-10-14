//! Operator configuration crate (ADR-008).
//!
//! Section `*Args` / `*Config` types live here. The live operator `Config`
//! (flat serialize shape + `ConfigWire` in `rvc`) implements
//! `Config::load(file, cli)` — defaults stay on that `Config`.
//! `*Args::resolved()` is not called from `Config::load`. No figment; env is
//! not a config layer.

mod error;
mod network;
pub mod sections;

pub use error::{ConfigError, ConfigSource};
pub use network::Network;
pub use sections::{
    BeaconArgs, BeaconConfig, BuilderLimits, BuilderLimitsArgs, BuilderSettings, DutiesArgs,
    DutiesConfig, ForkScheduleConfig, GcpSecretArgs, GcpSecretConfig, GrpcSignerArgs,
    GrpcSignerConfig, KeymanagerArgs, KeymanagerConfig, KeysArgs, KeysConfig, LogfileArgs,
    LogfileConfig, MonitoringArgs, MonitoringConfig, NetworkArgs, NetworkConfig,
    ProposerConfigArgs, ProposerConfigSource, SafetyArgs, SafetyConfig, SecretProviderArgs,
    SecretProviderConfig, ServerArgs, ServerConfig, SlashedAction, SlashingArgs, SlashingConfig,
    TimingConfig, TracingArgs, TracingConfig, TracingExporter, DEFAULT_DUTY_DISPATCH_CONCURRENCY,
    DEFAULT_DUTY_PUBLISH_CONCURRENCY, DEFAULT_IMPORT_KDF_CONCURRENCY,
    DEFAULT_IMPORT_KDF_MAX_KEYSTORE_MIB, DEFAULT_IMPORT_KDF_TOTAL_MIB, DEFAULT_TRACING_SAMPLE_RATE,
    MAX_IMPORT_KDF_CONCURRENCY,
};

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn config_error_names_its_provenance_layer() {
        let err = ConfigError::Invalid {
            field: "metrics.port",
            message: "out of range".into(),
            source_layer: ConfigSource::File(PathBuf::from("/tmp/rvc.toml")),
        };
        let rendered = err.to_string();
        assert!(rendered.contains("metrics.port"), "{rendered}");
        assert!(rendered.contains("/tmp/rvc.toml"), "{rendered}");
    }
}
