//! Shared observability primitives for the rvc workspace.
//!
//! Leaf crate: no workspace-internal dependencies. Hosts logging redaction helpers,
//! hex-prefix utilities, and canonical pubkey display normalization so consumers that
//! only need formatting do not pull in BLS/KDF/HTTP via `rvc-crypto`.

pub mod hex;
pub mod logging;
pub mod pubkey;
pub mod span_names;
