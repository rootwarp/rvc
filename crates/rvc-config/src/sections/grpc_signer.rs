//! gRPC remote-signer section (ARCH-4f).
//!
//! Clap group, TOML `[grpc_signer]` table, and `Config.grpc_signer` share this module.
//! Fields are `Option<T>` with no clap `default_value` (ADR-009).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Clap + serde declaration for the gRPC signer knobs (ADR-008).
///
/// Field names are section-relative; `--flag` strings stay the pre-move longs.
/// Flat legacy TOML keys are accepted via `#[serde(alias)]`.
#[derive(Debug, Clone, PartialEq, Eq, Default, clap::Args, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct GrpcSignerArgs {
    /// gRPC remote signer URL (e.g., https://signer.example.com:50051)
    #[arg(id = "grpc_signer_url", long = "grpc-signer-url")]
    #[serde(alias = "grpc_signer_url", skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Path to the client TLS certificate for gRPC signer mTLS
    #[arg(id = "grpc_signer_tls_cert", long = "grpc-signer-tls-cert")]
    #[serde(alias = "grpc_signer_tls_cert", skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,

    /// Path to the client TLS private key for gRPC signer mTLS
    #[arg(id = "grpc_signer_tls_key", long = "grpc-signer-tls-key")]
    #[serde(alias = "grpc_signer_tls_key", skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,

    /// Path to the CA certificate for gRPC signer mTLS
    #[arg(id = "grpc_signer_tls_ca_cert", long = "grpc-signer-tls-ca-cert")]
    #[serde(alias = "grpc_signer_tls_ca_cert", skip_serializing_if = "Option::is_none")]
    pub tls_ca_cert: Option<PathBuf>,
}

impl GrpcSignerArgs {
    /// Fold this declaration into a [`GrpcSignerConfig`].
    ///
    /// Defaults live on `GrpcSignerConfig`; load overlays Option fields.
    pub fn resolved(&self) -> GrpcSignerConfig {
        GrpcSignerConfig {
            url: self.url.clone(),
            tls_cert: self.tls_cert.clone(),
            tls_key: self.tls_key.clone(),
            tls_ca_cert: self.tls_ca_cert.clone(),
        }
    }
}

/// gRPC remote signer connection settings (resolved / `Config` field).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GrpcSignerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_key: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_ca_cert: Option<PathBuf>,
}
