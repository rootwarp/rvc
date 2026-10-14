//! Test-only helpers for EIP-2335 keystore fixtures and the L5 sentinel schedule.
//!
//! Gated by `cfg(any(test, feature = "test-utils"))`. Enable the feature only
//! from `[dev-dependencies]`:
//!
//! ```toml
//! [dev-dependencies]
//! crypto = { workspace = true, features = ["test-utils"] }
//! ```

use std::path::{Path, PathBuf};

use eth_types::{ForkSchedule, Root};

use crate::{EncryptionKdf, Keystore, SecretKey, PUBLIC_KEY_BYTES_LEN};

/// Phase0 block signing root from `crates/crypto/tests/signing_root_kat.rs` (issue 2.9).
pub const KAT_BLOCK_SIGNING_ROOT_PHASE0: Root = [
    0x80, 0x1f, 0xbd, 0x74, 0x17, 0x52, 0xf6, 0xa9, 0xab, 0xaf, 0x0f, 0xd8, 0x20, 0xf9, 0xb3, 0x1b,
    0xb7, 0x8f, 0xc4, 0xba, 0x26, 0x9b, 0x51, 0x3a, 0x38, 0xd6, 0xfd, 0xf3, 0xf7, 0x9d, 0xad, 0x8c,
];
/// Electra-boundary attestation signing root from `signing_root_kat.rs` (issue 2.9).
pub const KAT_ATTESTATION_SIGNING_ROOT_ELECTRA_BOUNDARY: Root = [
    0x28, 0x15, 0x19, 0xab, 0x10, 0xc9, 0x03, 0x76, 0x54, 0x79, 0xae, 0xd8, 0xa4, 0xec, 0x73, 0xae,
    0x7b, 0x3c, 0x9a, 0x2f, 0x90, 0xf8, 0xa2, 0x12, 0x53, 0x1b, 0x93, 0x8e, 0x7b, 0xe7, 0xcb, 0x5c,
];
/// Phase0 aggregate-and-proof signing root from `signing_root_kat.rs` (issue 2.9).
pub const KAT_AGGREGATE_AND_PROOF_SIGNING_ROOT_PHASE0: Root = [
    0xbb, 0x54, 0x16, 0xb3, 0xdc, 0xde, 0xb5, 0x86, 0xb5, 0x4c, 0xe6, 0xcc, 0xe8, 0x39, 0x33, 0xf9,
    0xa0, 0x60, 0x1d, 0xc4, 0xe3, 0x53, 0xc9, 0x85, 0x58, 0x83, 0x25, 0x6a, 0xd4, 0x4b, 0xf3, 0x84,
];
/// Phase0 sync-committee message signing root from `signing_root_kat.rs`.
pub const KAT_SYNC_COMMITTEE_MESSAGE_SIGNING_ROOT_PHASE0: Root = [
    0x5c, 0xfb, 0x10, 0x98, 0xb7, 0x3a, 0x93, 0xeb, 0x68, 0xe3, 0x79, 0x03, 0xf6, 0x6a, 0xcd, 0x7a,
    0xf9, 0xec, 0x54, 0xe1, 0x09, 0x88, 0x8d, 0xf1, 0xab, 0x21, 0x84, 0x1a, 0x97, 0x0f, 0xb0, 0x74,
];
/// EIP-7044 Deneb-capped exit signing root from `signing_root_kat.rs` (issue 2.9).
pub const KAT_VOLUNTARY_EXIT_SIGNING_ROOT_EIP7044_DENEB: Root = [
    0xe7, 0x43, 0x2d, 0x27, 0xaf, 0x0c, 0x7e, 0xe4, 0xe3, 0x98, 0xb6, 0xa9, 0xd6, 0x02, 0xd0, 0x2f,
    0x46, 0xf1, 0xea, 0x97, 0x29, 0xe4, 0x3a, 0xce, 0x3a, 0xa2, 0x78, 0xf9, 0x3e, 0x03, 0xd4, 0xe1,
];
/// Builder-registration signing root from `signing_root_kat.rs` (Altair + zero GVR).
pub const KAT_BUILDER_REGISTRATION_SIGNING_ROOT: Root = [
    0x06, 0x13, 0x1b, 0x3a, 0x74, 0x1b, 0xd5, 0x52, 0x58, 0x93, 0xbf, 0xe1, 0x4d, 0x62, 0xb9, 0xb4,
    0xfc, 0x10, 0x8b, 0x1f, 0x01, 0xc4, 0xc9, 0x51, 0x97, 0xeb, 0x7f, 0xc5, 0x6e, 0xeb, 0x44, 0x89,
];

/// Compressed fork schedule with Gloas at the far-future sentinel (`u64::MAX`).
///
/// Pre-Gloas forks activate at epochs 10/20/30/40/50/60. ADR-009 / L5 (issue
/// 6.13): existing signing roots stay byte-identical while Gloas is unscheduled.
#[must_use]
pub fn sentinel_gloas_schedule() -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
        altair_fork_epoch: 10,
        altair_fork_version: [0x01, 0x00, 0x00, 0x00],
        bellatrix_fork_epoch: 20,
        bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
        capella_fork_epoch: 30,
        capella_fork_version: [0x03, 0x00, 0x00, 0x00],
        deneb_fork_epoch: 40,
        deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
        electra_fork_epoch: 50,
        electra_fork_version: [0x05, 0x00, 0x00, 0x00],
        fulu_fork_epoch: 60,
        fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [0x07, 0x00, 0x00, 0x00],
    }
}

/// On-disk test keystore produced by [`create_test_keystore`].
#[derive(Debug)]
pub struct TestKeystore {
    /// Absolute path of the written JSON file.
    pub path: PathBuf,
    /// Secret key that was encrypted into the file.
    pub secret_key: SecretKey,
    /// Encrypted keystore value (also serialized to [`Self::path`]).
    pub keystore: Keystore,
}

impl TestKeystore {
    /// Compressed BLS public key bytes for the fixture secret key.
    #[must_use]
    pub fn pubkey(&self) -> [u8; PUBLIC_KEY_BYTES_LEN] {
        self.secret_key.public_key().to_bytes()
    }
}

/// Create a cheap EIP-2335 keystore under `dir` for tests.
///
/// Covers the former local helpers (pubkey-only, `(path, sk)`, `(pubkey, sk)`):
/// - Generates a random secret key when `secret_key` is `None`.
/// - Writes `{hex(pubkey)}.json` using [`EncryptionKdf::scrypt_cheap_for_tests`].
/// - Returns path, secret key, and keystore so callers can take what they need.
///
/// # Panics
///
/// Panics on encryption or I/O failure (test helper).
pub fn create_test_keystore(
    dir: &Path,
    password: &str,
    secret_key: Option<SecretKey>,
) -> TestKeystore {
    let secret_key = secret_key.unwrap_or_else(SecretKey::generate);
    let pubkey = secret_key.public_key().to_bytes();
    let keystore = Keystore::encrypt(
        &secret_key,
        password.as_bytes(),
        "",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("test keystore encrypt");
    let path = dir.join(format!("{}.json", hex::encode(pubkey)));
    std::fs::write(&path, keystore.to_json().expect("serialize test keystore"))
        .expect("write test keystore");
    TestKeystore { path, secret_key, keystore }
}
