//! BLS key operations, EIP-2335 keystore decryption, key management, and Ethereum signing utilities.
//!
//! # Signer hierarchy
//!
//! Signing types stack from raw BLS backends up to the safe-signing gates in the
//! `rvc-signer` library crate. Read bottom-up:
//!
//! | Layer | Type | Crate | Role |
//! |-------|------|-------|------|
//! | 1. Raw backend | [`Signer`] | this crate | Sign a 32-byte root with a pubkey. Implemented by [`LocalSigner`] and [`CompositeSigner`]. |
//! | 2. Typed backend | [`TypedSigner`] | this crate | One method per consensus duty; computes the signing root then signs. [`LocalSigner`] implements it; gRPC remotes are typed-only. |
//! | 3. Key router | [`CompositeSigner`] | this crate | Routes each pubkey to local, HTTP remote, gRPC remote, or dynamic local keys. Implements [`Signer`]. |
//! | 4a. VC service | `SignerService` | `rvc-signer` (`crates/signer`) | Validator-client path: enablement + slashing stage/commit + metrics around the composite. |
//! | 4b. Gate | `SigningGate` | `rvc-signer` (`crates/signer`) | Remote-signer / multi-transport path: same defenses via a shared slashable core (`sign_slashable`) plus non-slashable helpers. |
//!
//! Related helpers (not layers): `LocalSigner` (in-process keys),
//! `remote_signer_client::RemoteSigner` (Web3Signer HTTP, `rvc-remote-signer-client`),
//! `ValidatorSigner` (async trait over duty-shaped methods on the VC path). Prefer
//! constructing a [`CompositeSigner`] and wrapping it in `SignerService` or
//! `SigningGate` rather than calling backends directly from duty code.
//!
//! ## Package-name collision (`rvc-signer`)
//!
//! Cargo package **`rvc-signer`** is the library at `crates/signer` (Rust crate
//! name `signer` via the workspace dep key). Package **`rvc-signer-server`** at
//! `crates/signer-server` (Rust crate `signer_server`) owns server assembly.
//! Package **`rvc-signer-bin`** at `bin/rvc-signer` is a thin CLI that builds the
//! **binary** also named `rvc-signer`.

#![deny(rustdoc::broken_intra_doc_links)]

mod bls;
mod composite_signer;
pub mod eip2333;
mod error;
pub mod insecure;
mod key_manager;
mod keystore;
pub mod mnemonic;
mod signer_trait;
mod signing;
mod signing_root;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod typed_signer;
mod voluntary_exit_signing;

pub use bls::{
    PublicKey, SecretKey, Signature, PUBLIC_KEY_BYTES_LEN, SECRET_KEY_BYTES_LEN,
    SIGNATURE_BYTES_LEN,
};
pub use composite_signer::CompositeSigner;
pub use error::{BlsError, KeyManagerError, KeystoreError, SigningError};
pub use eth_types::{DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
pub use insecure::{InsecureGate, InsecureGateError, InsecureMode};
pub use key_manager::{KeyManager, WILDCARD_KEY};
pub use keystore::{EncryptionKdf, KdfParams, Keystore, Pbkdf2Params, ScryptParams};
pub use signer_trait::{LocalSigner, Signer};
pub use signing::{compute_domain, compute_fork_data_root, compute_signing_root};
pub use signing_root::{
    capella_capped_fork_version, signing_root_for, signing_root_with_fork_version, DutyRef,
    SigningCtx,
};
pub use typed_signer::{SignContext, TypedSigner};
pub use voluntary_exit_signing::sign_voluntary_exit;
