//! Shared test helpers for v2 RPC integration tests.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crypto::{KeyManager, LocalSigner, SecretKey, Signature, Signer, SigningError};
use eth_types::{encode_beacon_block_ssz, Root};
use signer::{SigningEnablement, SigningGate, ValidatorLockMap};
use slashing::SlashingDb;

use signer_server::backend::{SigningBackend, SigningBackendError};
use signer_server::proto::signer_v2::ForkInfo;
use signer_server::service::SignerServiceImpl;

/// Default injected BLS latency for the ARCH-5a signer-server load profile (A-9).
pub const LOAD_PROFILE_INJECTED_LATENCY: Duration = Duration::from_millis(200);

/// Default key count for the ARCH-5a signer-server load profile (A-9).
pub const LOAD_PROFILE_KEY_COUNT: usize = 200;

/// The BLS secret key used in all happy-path tests.
/// Derived via EIP-2333 from a fixed seed for reproducibility.
pub fn known_secret_key() -> SecretKey {
    use crypto::eip2333::derive_master_sk;
    let seed = [0x42u8; 32];
    derive_master_sk(&seed).expect("derive master sk")
}

/// The public key bytes for `known_secret_key()`.
pub fn known_pubkey_bytes() -> [u8; 48] {
    known_secret_key().public_key().to_bytes()
}

/// The `KNOWN_PUBKEY_BYTES` static — lazily computed on first access.
pub static KNOWN_PUBKEY_BYTES: std::sync::LazyLock<[u8; 48]> =
    std::sync::LazyLock::new(known_pubkey_bytes);

/// On-disk slashing DB path. Dropping this removes the parent directory.
///
/// Bind it for the whole test (`db_path` or `_db_path`). A bare `_` drops the
/// directory before the test body runs.
pub struct TempDbPath {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl AsRef<Path> for TempDbPath {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl std::ops::Deref for TempDbPath {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.path
    }
}

/// Build a `SignerServiceImpl` backed by an in-memory key manager and an
/// on-disk slashing DB. The returned [`TempDbPath`] keeps the directory alive.
pub fn make_service_with_db() -> (SignerServiceImpl, TempDbPath) {
    make_service_with_genesis(eth_types::NetworkPreset::MAINNET.genesis_fork_version)
}

/// Like [`make_service_with_db`] but with an explicit network genesis fork version
/// (builder-registration domain source).
pub fn make_service_with_genesis(genesis_fork_version: [u8; 4]) -> (SignerServiceImpl, TempDbPath) {
    let sk = known_secret_key();
    let (dir, db_path) = make_temp_db_path();

    let mut km = KeyManager::new();
    km.insert(sk);

    let backend = Arc::new(TestBackend { km: Arc::new(km) });
    let db = Arc::new(SlashingDb::open(&db_path).expect("open test DB"));

    let svc = SignerServiceImpl::new_v2(backend as Arc<dyn SigningBackend>, "test".to_string(), db)
        .with_genesis_fork_version(genesis_fork_version);
    (svc, TempDbPath { _dir: dir, path: db_path })
}

/// Same as `make_service_with_db` but the backend has no keys loaded.
/// Calls to `backend.sign()` will return `KeyNotFound`.
pub fn make_service_with_db_unknown_key() -> (SignerServiceImpl, TempDbPath) {
    let (dir, db_path) = make_temp_db_path();
    let backend = Arc::new(TestBackend { km: Arc::new(KeyManager::new()) });
    let db = Arc::new(SlashingDb::open(&db_path).expect("open test DB"));
    let svc = SignerServiceImpl::new_v2(backend as Arc<dyn SigningBackend>, "test".to_string(), db);
    (svc, TempDbPath { _dir: dir, path: db_path })
}

/// Create a temporary path for a slashing DB that does **not** yet exist.
///
/// SEC-3 rejects pre-existing 0-byte files as corrupt; `SlashingDb::open` still
/// creates a fresh DB when the path is missing (library/test convenience).
/// The caller keeps the [`tempfile::TempDir`] so the path stays valid until the
/// test drops it.
fn make_temp_db_path() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::TempDir::new().unwrap();
    let path = dir.path().join("slashing.db");
    (dir, path)
}

// ── TestBackend ───────────────────────────────────────────────────────────────

struct TestBackend {
    km: Arc<KeyManager>,
}

#[async_trait::async_trait]
impl SigningBackend for TestBackend {
    async fn sign(
        &self,
        signing_root: &[u8; 32],
        pubkey: &[u8; 48],
    ) -> Result<[u8; 96], SigningBackendError> {
        let pk = crypto::PublicKey::from_bytes(pubkey)
            .map_err(|_| SigningBackendError::KeyNotFound(*pubkey))?;
        let sk = self.km.get_secret_key(&pk).ok_or(SigningBackendError::KeyNotFound(*pubkey))?;
        let sig = sk.sign(signing_root);
        Ok(sig.to_bytes())
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.km.list_public_keys().iter().map(|pk| pk.to_bytes()).collect()
    }
}

// ── ARCH-5a load fixture ──────────────────────────────────────────────────────

/// Deterministic secret key for load-profile validator `index`.
pub fn load_profile_secret_key(index: u32) -> SecretKey {
    use crypto::eip2333::derive_master_sk;
    let mut seed = [0xA9u8; 32];
    seed[28..32].copy_from_slice(&index.to_be_bytes());
    derive_master_sk(&seed).expect("derive load-profile sk")
}

/// `crypto::Signer` wrapping [`LocalSigner`] with an async sleep before each sign.
///
/// Sleeps on the *async* side so `Handle::block_on(timeout(...))` in
/// `SlashableSignSession::stage_then_sign` observes the delay the same way a
/// remote signer would. Do not replace this with `std::thread::sleep`.
pub struct SlowSigner {
    inner: LocalSigner,
    sleep: Duration,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl SlowSigner {
    /// Wrap `inner` and sleep `sleep` before every `sign`.
    ///
    /// Default profile latency is [`LOAD_PROFILE_INJECTED_LATENCY`] (200 ms).
    pub fn new(inner: LocalSigner, sleep: Duration) -> Self {
        Self { inner, sleep, in_flight: AtomicUsize::new(0), max_in_flight: AtomicUsize::new(0) }
    }

    /// Peak number of overlapping `sign` calls observed so far.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }
}

struct InFlightGuard<'a> {
    current: &'a AtomicUsize,
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.current.fetch_sub(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl Signer for SlowSigner {
    async fn sign(
        &self,
        signing_root: &Root,
        pubkey: &[u8; 48],
    ) -> Result<Signature, SigningError> {
        let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(now, Ordering::SeqCst);
        let _guard = InFlightGuard { current: &self.in_flight };
        tokio::time::sleep(self.sleep).await;
        self.inner.sign(signing_root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.inner.public_keys()
    }
}

/// Always-allow enablement for the load fixture (standalone signer semantics).
struct LoadEnablement;

impl SigningEnablement for LoadEnablement {
    fn is_signing_enabled(&self, _pubkey: &crypto::PublicKey) -> bool {
        true
    }
}

/// signer-server load-profile fixture: N keys, [`SlowSigner`], real `SlashingDb::open`.
pub struct LoadFixture {
    pub service: SignerServiceImpl,
    pub db_path: PathBuf,
    pub pubkeys: Vec<[u8; 48]>,
    pub slow: Arc<SlowSigner>,
    pub injected_latency: Duration,
    pub key_count: usize,
    /// Dropped after `service`, so the slashing DB directory outlives the connection.
    _dir: tempfile::TempDir,
}

/// 200-key / 200 ms load fixture (A-9 defaults).
pub fn make_load_fixture() -> LoadFixture {
    make_load_fixture_with(LOAD_PROFILE_KEY_COUNT, LOAD_PROFILE_INJECTED_LATENCY)
}

/// Load fixture with explicit key count and injected BLS latency.
///
/// Uses the public `SigningGate::new_with_raw_signer` +
/// `SignerServiceImpl::new_v2_with_gate` seams so the injector is a
/// `crypto::Signer` (no production edit). The slashing DB is opened via the
/// real on-disk `SlashingDb::open` path (WAL + `synchronous=EXTRA` +
/// `fullfsync=ON` on macOS).
pub fn make_load_fixture_with(key_count: usize, injected_latency: Duration) -> LoadFixture {
    assert!(key_count > 0, "load fixture requires at least one key");

    let mut km_local = KeyManager::new();
    let mut pubkeys = Vec::with_capacity(key_count);
    for i in 0..key_count {
        let sk = load_profile_secret_key(i as u32);
        pubkeys.push(sk.public_key().to_bytes());
        km_local.insert(sk);
    }

    let slow = Arc::new(SlowSigner::new(LocalSigner::new(km_local), injected_latency));
    let (dir, db_path) = make_temp_db_path();
    let db = Arc::new(SlashingDb::open(&db_path).expect("open load-profile slashing db"));
    let gate = SigningGate::new_with_raw_signer(
        Arc::clone(&db),
        Arc::new(LoadEnablement),
        Arc::clone(&slow) as Arc<dyn Signer>,
        Arc::new(ValidatorLockMap::new()),
        Duration::from_secs(4),
    );
    // Slashable RPCs sign through the gate's SlowSigner. The service still
    // requires a SigningBackend; an empty one is enough for this profile.
    let backend = Arc::new(TestBackend { km: Arc::new(KeyManager::new()) });
    let service = SignerServiceImpl::new_v2_with_gate(
        backend as Arc<dyn SigningBackend>,
        "load-harness".to_string(),
        Arc::new(gate),
    );
    LoadFixture { service, db_path, pubkeys, slow, injected_latency, key_count, _dir: dir }
}

// ── SSZ helpers ───────────────────────────────────────────────────────────────

/// Minimal valid SSZ-encoded `BeaconBlock` for testing (Electra typed body, SEC-6c).
pub fn sample_block_ssz(slot: u64) -> Vec<u8> {
    use eth_types::BeaconBlock;
    let block = BeaconBlock {
        slot,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body: eth_types::external_vector_electra_body().as_ssz_bytes(),
    };
    encode_beacon_block_ssz(&block, 4)
}

/// Minimal valid SSZ-encoded `BlindedBeaconBlock` for testing (Electra typed body).
pub fn sample_blinded_block_ssz(slot: u64) -> Vec<u8> {
    use eth_types::{encode_blinded_beacon_block_ssz, BlindedBeaconBlock};
    let block = BlindedBeaconBlock {
        slot,
        proposer_index: 1,
        parent_root: [0x33; 32],
        state_root: [0x44; 32],
        body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
    };
    encode_blinded_beacon_block_ssz(&block, 4)
}

/// A `ForkInfo` proto message for testing (Deneb fork version, zero GVR).
pub fn sample_fork_info() -> ForkInfo {
    ForkInfo {
        previous_version: vec![0x04, 0x00, 0x00, 0x00],
        current_version: vec![0x04, 0x00, 0x00, 0x00],
        epoch: 0,
        genesis_validators_root: vec![0x00; 32],
    }
}
