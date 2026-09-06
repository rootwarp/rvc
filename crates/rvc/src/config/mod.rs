//! Configuration module for the validator client.

mod builder;
mod error;
mod knobs;
mod network;
mod start;
mod types;

pub use bn_manager::BnRole;
pub use builder::ServiceBuilder;
pub use error::ConfigError;
pub use knobs::OPERATOR_KNOB_NAMES;
pub use network::Network;
pub use rvc_config::ConfigSource;
pub use start::{BuilderArgs, LoggingArgs, ProposerArgs, StartArgs};
pub use types::{
    redact_url, BeaconArgs, BeaconConfig, BeaconNodeEntry, BroadcastTopic, BuilderLimits,
    BuilderLimitsArgs, BuilderSettings, Config, ForkScheduleConfig, GcpSecretArgs, GcpSecretConfig,
    GrpcSignerArgs, GrpcSignerConfig, KeymanagerArgs, KeymanagerConfig, KeysArgs, KeysConfig,
    LogfileArgs, LogfileConfig, MonitoringArgs, MonitoringConfig, NetworkArgs, NetworkConfig,
    ProposerConfigArgs, ProposerConfigSource, SafetyArgs, SafetyConfig, SecretProviderArgs,
    SecretProviderConfig, ServerArgs, ServerConfig, SlashedAction, SlashingArgs, SlashingConfig,
    TimingConfig, TracingArgs, TracingConfig, TracingExporter,
};
pub use validator_store::BlockSelectionMode;
