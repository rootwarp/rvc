//! Remote BLS signer server library (`crates/signer-server`).
//!
//! Server assembly (gRPC + Web3Signer HTTP, backends, config, audit) lives here.
//! The `rvc-signer` binary is a thin CLI shim over [`server::run`].

pub mod audit;
pub mod backend;
#[cfg(feature = "dvt")]
pub mod commands;
pub mod config;
#[cfg(feature = "dvt")]
pub mod dvt;
pub mod error;
#[cfg(test)]
mod gate_shared_across_transports;
pub(crate) mod grpc_common;
pub mod grpc_tls;
pub mod http_api;
pub mod insecure_startup;
pub mod metrics;
pub mod reload;
pub mod server;
pub mod service;
/// Transport-neutral SignPlan engine (RF4-09 / D4).
pub(crate) mod sign_plan;
pub mod slashing;
/// Shared TLS PEM file I/O with path-preserving errors (used by gRPC and HTTP).
pub(crate) mod tls_io;
/// Per-RPC gRPC handler spans (`server_span`). Crate-private.
pub(crate) mod trace_ctx;

pub use error::ServerError;

/// Re-export of the shared v2 signer proto bindings (compiled once in `rvc-signer-proto`).
pub mod proto {
    pub use signer_proto::signer_v2;
}

// V2 server exports
pub use proto::signer_v2::signer_service_server::SignerServiceServer as SignerServiceServerV2;

// V2 PeerSignerService client + server (DVT) — RF2-16: client dials v2 only.
#[cfg(feature = "dvt")]
pub use proto::signer_v2::peer_signer_service_client::PeerSignerServiceClient;
#[cfg(feature = "dvt")]
pub use proto::signer_v2::peer_signer_service_server::{
    PeerSignerService as PeerSignerServiceV2, PeerSignerServiceServer as PeerSignerServiceServerV2,
};
