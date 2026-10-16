use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use rayon::prelude::*;
use secrecy::{ExposeSecret, SecretString};
use tracing::{debug, info, warn};

use super::bls::{PublicKey, SecretKey, PUBLIC_KEY_BYTES_LEN};
use super::error::{KeyManagerError, KeystoreError};
use super::keystore::Keystore;
use observability::logging::TruncatedPubkey;

/// Reserved password-map key for the wildcard (global default) password.
pub const WILDCARD_KEY: &str = "*";

/// Password-map key for a pubkey hex field.
///
/// Lowercases only. A `0x` prefix stays in the key, so `hex::decode` rejects
/// it and a prefixed keystore field does not select a bare-hex secret.
pub fn password_map_key(pubkey_hex: &str) -> String {
    pubkey_hex.to_ascii_lowercase()
}

/// Pubkey bytes for a password-map key.
///
/// The field is lowercased first, so uppercase hex matches the secret written
/// from the decrypted key. A `0x` prefix does not decode.
pub fn decode_password_map_key(pubkey_hex: &str) -> Option<[u8; PUBLIC_KEY_BYTES_LEN]> {
    let bytes = hex::decode(password_map_key(pubkey_hex)).ok()?;
    if bytes.len() != PUBLIC_KEY_BYTES_LEN {
        return None;
    }
    let mut pubkey = [0u8; PUBLIC_KEY_BYTES_LEN];
    pubkey.copy_from_slice(&bytes);
    Some(pubkey)
}

/// Why keystores in one directory load were not decrypted.
///
/// Filled while results are aggregated. Parallel decryption does not touch it.
#[derive(Debug, Default)]
pub struct KeystoreLoadReport {
    /// Declared pubkeys whose password failed the keystore checksum.
    pub password_rejected: HashSet<[u8; PUBLIC_KEY_BYTES_LEN]>,
    /// Declared pubkeys that failed to load for some other reason.
    pub load_failed: HashSet<[u8; PUBLIC_KEY_BYTES_LEN]>,
}

/// A prepared decryption work item. Produced by Phase 1, consumed by Phase 2.
struct DecryptionTask<'a> {
    file_path: PathBuf,
    keystore: Keystore,
    password: &'a [u8],
    declared_pubkey_hex: String,
}

/// Result of a single decryption attempt. Produced by Phase 2, consumed by Phase 3.
enum DecryptionOutcome {
    Success {
        pubkey_bytes: [u8; PUBLIC_KEY_BYTES_LEN],
        secret_key: SecretKey,
        pubkey_hex: String,
        file_path: PathBuf,
    },
    Failure {
        pubkey_hex: String,
        file_path: PathBuf,
        error: String,
        /// `true` only for [`KeystoreError::ChecksumMismatch`].
        password_rejected: bool,
    },
}

/// Validate that `candidate` resolves inside `base` after canonicalization.
///
/// Rejects symlinks or path traversal (`../`) that resolve outside the base directory.
pub fn validate_key_path(base: &Path, candidate: &Path) -> Result<PathBuf, KeyManagerError> {
    let canonical_base = base.canonicalize().map_err(KeyManagerError::Io)?;
    let canonical_path = candidate.canonicalize().map_err(KeyManagerError::Io)?;
    if !canonical_path.starts_with(&canonical_base) {
        warn!(
            "Rejecting file outside keystore directory (possible path traversal): {:?}",
            candidate
        );
        return Err(KeyManagerError::PathTraversal {
            path: candidate.to_path_buf(),
            base: canonical_base,
        });
    }
    Ok(canonical_path)
}

pub struct KeyManager {
    keys: HashMap<[u8; PUBLIC_KEY_BYTES_LEN], SecretKey>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    /// Loads all keystore files from a directory.
    ///
    /// The `passwords` map uses public key hex strings (without 0x prefix) as keys
    /// and `SecretString` values for secure password handling.
    ///
    /// Passwords are automatically zeroized when the HashMap is dropped.
    /// Corrupted or unreadable keystores are logged and skipped.
    /// Files outside the directory boundary (e.g., via symlinks) are also skipped
    /// to prevent directory traversal attacks.
    ///
    /// Delegates to `load_from_directory_with_threads` with auto-detected thread count.
    pub fn load_from_directory<P: AsRef<Path>>(
        path: P,
        passwords: &HashMap<String, SecretString>,
    ) -> Result<Self, KeyManagerError> {
        Self::load_from_directory_with_threads(path, passwords, None)
    }

    /// Loads all keystore files from a directory using parallel decryption.
    ///
    /// Uses a dedicated rayon thread pool to decrypt keystores in parallel.
    /// The `num_threads` parameter controls the pool size; `None` auto-detects
    /// from available CPU parallelism (clamped to 1..=32).
    ///
    /// The pipeline runs in 3 phases:
    /// 1. **Sequential** — directory scan, validation, keystore parsing, task collection
    /// 2. **Parallel** — keystore decryption and public key verification via rayon
    /// 3. **Sequential** — result aggregation, logging, KeyManager construction
    pub fn load_from_directory_with_threads<P: AsRef<Path>>(
        path: P,
        passwords: &HashMap<String, SecretString>,
        num_threads: Option<usize>,
    ) -> Result<Self, KeyManagerError> {
        Self::load_from_directory_with_threads_filtered(path, passwords, num_threads, None)
    }

    /// Like [`Self::load_from_directory_with_threads`], but skips pubkeys present in
    /// `denylist` (SEC-1b: Keymanager DELETE persistence across restart).
    ///
    /// Denylisted keystores are not decrypted; they are logged and omitted.
    pub fn load_from_directory_with_threads_filtered<P: AsRef<Path>>(
        path: P,
        passwords: &HashMap<String, SecretString>,
        num_threads: Option<usize>,
        denylist: Option<&HashSet<[u8; PUBLIC_KEY_BYTES_LEN]>>,
    ) -> Result<Self, KeyManagerError> {
        Self::load_from_directory_with_threads_filtered_reporting(
            path,
            passwords,
            num_threads,
            denylist,
            &mut KeystoreLoadReport::default(),
        )
    }

    /// Like [`Self::load_from_directory_with_threads_filtered`], and records
    /// why a declared pubkey was not loaded.
    ///
    /// A checksum failure is `report.password_rejected`. Every other decrypt
    /// failure is `report.load_failed`. A keystore that does not parse is not
    /// recorded; the caller reads that file itself.
    pub fn load_from_directory_with_threads_filtered_reporting<P: AsRef<Path>>(
        path: P,
        passwords: &HashMap<String, SecretString>,
        num_threads: Option<usize>,
        denylist: Option<&HashSet<[u8; PUBLIC_KEY_BYTES_LEN]>>,
        report: &mut KeystoreLoadReport,
    ) -> Result<Self, KeyManagerError> {
        let dir_path = path.as_ref();

        if !dir_path.exists() {
            return Err(KeyManagerError::DirectoryNotFound(dir_path.to_path_buf()));
        }

        if !dir_path.is_dir() {
            return Err(KeyManagerError::DirectoryNotFound(dir_path.to_path_buf()));
        }

        let canonical_dir = dir_path.canonicalize().map_err(KeyManagerError::Io)?;

        info!(path = ?canonical_dir, "Loading validator keys from directory");

        // ── Phase 1: Sequential scan ──────────────────────────────────────
        let mut tasks: Vec<DecryptionTask<'_>> = Vec::new();
        let mut found_any_keystore = false;
        let mut denylist_skipped: usize = 0;

        let entries = fs::read_dir(&canonical_dir)?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    warn!("Failed to read directory entry: {}", e);
                    continue;
                }
            };

            let file_path = entry.path();

            let canonical_file = match validate_key_path(&canonical_dir, &file_path) {
                Ok(p) => p,
                Err(KeyManagerError::PathTraversal { .. }) => continue,
                Err(e) => {
                    warn!("Failed to validate path {:?}: {}", file_path, e);
                    continue;
                }
            };

            if !canonical_file.is_file() {
                continue;
            }

            let extension = file_path.extension().and_then(|ext| ext.to_str());
            if extension != Some("json") {
                continue;
            }

            found_any_keystore = true;

            let keystore = match Keystore::from_file(&file_path) {
                Ok(k) => k,
                Err(e) => {
                    warn!("Failed to load keystore from {:?}: {}", file_path, e);
                    continue;
                }
            };

            let pubkey_hex = match &keystore.pubkey {
                Some(pk) => pk.clone(),
                None => {
                    warn!("Keystore {:?} has no public key field, skipping", file_path);
                    continue;
                }
            };

            // SEC-1b: skip keys deleted via Keymanager API (do not decrypt / insert).
            if let Some(deny) = denylist {
                let hex_str = pubkey_hex.strip_prefix("0x").unwrap_or(&pubkey_hex);
                if let Ok(bytes) = hex::decode(hex_str) {
                    if bytes.len() == PUBLIC_KEY_BYTES_LEN {
                        let mut arr = [0u8; PUBLIC_KEY_BYTES_LEN];
                        arr.copy_from_slice(&bytes);
                        if deny.contains(&arr) {
                            info!(
                                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                                file = ?file_path,
                                "Skipping denylisted keystore-dir key"
                            );
                            denylist_skipped += 1;
                            continue;
                        }
                    }
                }
            }

            let password = match passwords
                .get(&password_map_key(&pubkey_hex))
                .or_else(|| passwords.get(WILDCARD_KEY))
            {
                Some(p) => p,
                None => {
                    warn!(
                        "No password found for public key {} in {:?}, skipping",
                        pubkey_hex, file_path
                    );
                    continue;
                }
            };

            // Gate 1: decryption needs the exposed password bytes (never logged).
            #[allow(clippy::disallowed_methods)]
            tasks.push(DecryptionTask {
                file_path,
                keystore,
                password: password.expose_secret().as_bytes(),
                declared_pubkey_hex: pubkey_hex,
            });
        }

        // All keystores were denylisted (or otherwise skipped) — empty manager is OK
        // when at least one keystore file was seen and every remaining candidate was
        // denylisted. If no keystore files existed at all, keep the hard error.
        if !found_any_keystore {
            return Err(KeyManagerError::NoKeystoreFiles);
        }

        if tasks.is_empty() && denylist_skipped > 0 {
            info!(
                denylist_skipped,
                "All keystore-dir keys were denylisted; starting with empty local key set"
            );
            return Ok(Self::new());
        }

        // ── Phase 2: Parallel decryption ──────────────────────────────────
        let num_threads = num_threads
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1));
        let num_threads = num_threads.clamp(1, 32);

        if num_threads > 8 {
            warn!(
                threads = num_threads,
                peak_memory_mib = num_threads * 256,
                "High parallelism for keystore decryption; peak scrypt memory may be significant"
            );
        }

        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(|i| format!("rvc-decrypt-{}", i))
            .build()
            .map_err(|e| KeyManagerError::ThreadPoolError(e.to_string()))?;

        let start = Instant::now();
        let results: Vec<DecryptionOutcome> = pool.install(|| {
            tasks
                .into_par_iter()
                .map(|task| {
                    let secret_key = match task.keystore.decrypt(task.password) {
                        Ok(sk) => sk,
                        Err(e) => {
                            return DecryptionOutcome::Failure {
                                pubkey_hex: task.declared_pubkey_hex,
                                file_path: task.file_path,
                                error: e.to_string(),
                                password_rejected: matches!(e, KeystoreError::ChecksumMismatch),
                            };
                        }
                    };

                    let derived = secret_key.public_key();

                    let expected_bytes = match hex::decode(&task.declared_pubkey_hex) {
                        Ok(b) => b,
                        Err(_) => {
                            return DecryptionOutcome::Failure {
                                pubkey_hex: task.declared_pubkey_hex,
                                file_path: task.file_path,
                                error: "invalid pubkey hex".to_string(),
                                password_rejected: false,
                            };
                        }
                    };

                    let expected = match PublicKey::from_bytes(&expected_bytes) {
                        Ok(pk) => pk,
                        Err(_) => {
                            return DecryptionOutcome::Failure {
                                pubkey_hex: task.declared_pubkey_hex,
                                file_path: task.file_path,
                                error: "invalid pubkey format".to_string(),
                                password_rejected: false,
                            };
                        }
                    };

                    if derived.to_bytes() != expected.to_bytes() {
                        let error = format!(
                            "pubkey mismatch: declared {} but derived {}",
                            task.declared_pubkey_hex,
                            hex::encode(derived.to_bytes())
                        );
                        return DecryptionOutcome::Failure {
                            pubkey_hex: task.declared_pubkey_hex,
                            file_path: task.file_path,
                            error,
                            password_rejected: false,
                        };
                    }

                    DecryptionOutcome::Success {
                        pubkey_bytes: derived.to_bytes(),
                        secret_key,
                        pubkey_hex: task.declared_pubkey_hex,
                        file_path: task.file_path,
                    }
                })
                .collect()
        });

        let elapsed = start.elapsed();

        // ── Phase 3: Sequential aggregation ───────────────────────────────
        let mut keys = HashMap::new();
        let mut success_count: usize = 0;
        let mut fail_count: usize = 0;

        for outcome in results {
            match outcome {
                DecryptionOutcome::Success { pubkey_bytes, secret_key, pubkey_hex, file_path } => {
                    debug!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex),
                        file = ?file_path,
                        "Loaded validator key"
                    );
                    keys.insert(pubkey_bytes, secret_key);
                    success_count += 1;
                }
                DecryptionOutcome::Failure { pubkey_hex, file_path, error, password_rejected } => {
                    if let Some(pubkey) = decode_password_map_key(&pubkey_hex) {
                        if password_rejected {
                            report.password_rejected.insert(pubkey);
                        } else {
                            report.load_failed.insert(pubkey);
                        }
                    }
                    warn!(
                        pubkey = %TruncatedPubkey::new(&pubkey_hex),
                        file = ?file_path,
                        error = %error,
                        "Failed to decrypt keystore"
                    );
                    fail_count += 1;
                }
            }
        }

        info!(
            total = success_count + fail_count,
            loaded = success_count,
            failed = fail_count,
            key_count = success_count,
            elapsed_ms = elapsed.as_millis(),
            threads = num_threads,
            "Finished loading validator keys"
        );

        Ok(Self { keys })
    }

    pub fn get_secret_key(&self, pubkey: &PublicKey) -> Option<&SecretKey> {
        self.keys.get(&pubkey.to_bytes())
    }

    pub fn list_public_keys(&self) -> Vec<PublicKey> {
        self.keys.keys().filter_map(|bytes| PublicKey::from_bytes(bytes).ok()).collect()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Inserts a secret key into the key manager.
    ///
    /// Used to add keys loaded from external sources (e.g., cloud secret managers)
    /// at runtime. If a key with the same public key already exists, it is overwritten
    /// and a warning is logged.
    pub fn insert(&mut self, secret_key: SecretKey) {
        let pubkey = secret_key.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
        if self.keys.contains_key(&pubkey.to_bytes()) {
            warn!(pubkey = %TruncatedPubkey::new(&pubkey_hex), "Inserting key with duplicate public key, overwriting");
        }
        self.keys.insert(pubkey.to_bytes(), secret_key);
    }

    /// Removes a secret key by public key bytes.
    ///
    /// Returns `true` if the key was present and removed.
    pub fn remove(&mut self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        self.keys.remove(pubkey).is_some()
    }

    /// Returns `true` if a key with the given public key is present.
    pub fn contains(&self, pubkey: &[u8; PUBLIC_KEY_BYTES_LEN]) -> bool {
        self.keys.contains_key(pubkey)
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use std::fs::File;
    use std::io::Write;

    use secrecy::SecretString;
    use tempfile::TempDir;

    use super::*;

    const TEST_KEYSTORE_PBKDF2: &str = r#"
    {
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {
                    "dklen": 32,
                    "c": 262144,
                    "prf": "hmac-sha256",
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
            }
        },
        "description": "Test keystore",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/0/0",
        "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        "version": 4
    }
    "#;

    const TEST_PASSWORD: &[u8] = &[
        0x74, 0x65, 0x73, 0x74, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0xf0, 0x9f, 0x94,
        0x91,
    ];

    const TEST_PUBKEY_HEX: &str =
        "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07";

    fn create_test_keystore_file(dir: &TempDir, filename: &str, content: &str) {
        let file_path = dir.path().join(filename);
        let mut file = File::create(file_path).unwrap();
        file.write_all(content.as_bytes()).unwrap();
    }

    fn test_password_string() -> String {
        String::from_utf8(TEST_PASSWORD.to_vec()).unwrap()
    }

    fn test_password_secret() -> SecretString {
        SecretString::from(test_password_string())
    }

    #[test]
    fn test_new_key_manager_is_empty() {
        let manager = KeyManager::new();
        assert!(manager.is_empty());
        assert_eq!(manager.len(), 0);
    }

    #[test]
    fn test_load_from_directory_not_found() {
        let passwords = HashMap::new();
        let result = KeyManager::load_from_directory("/nonexistent/path", &passwords);
        assert!(matches!(result, Err(KeyManagerError::DirectoryNotFound(_))));
    }

    #[test]
    fn test_load_from_directory_empty() {
        let temp_dir = TempDir::new().unwrap();
        let passwords = HashMap::new();
        let result = KeyManager::load_from_directory(temp_dir.path(), &passwords);
        assert!(matches!(result, Err(KeyManagerError::NoKeystoreFiles)));
    }

    #[test]
    fn test_load_from_directory_with_valid_keystore() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
        assert!(!manager.is_empty());
    }

    #[test]
    fn test_get_secret_key() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).unwrap();
        let pubkey = PublicKey::from_bytes(&pubkey_bytes).unwrap();

        let secret_key = manager.get_secret_key(&pubkey);
        assert!(secret_key.is_some());

        let sk = secret_key.unwrap();
        assert_eq!(sk.public_key().to_bytes(), pubkey.to_bytes());
    }

    #[test]
    fn test_get_secret_key_not_found() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        let other_sk = SecretKey::generate();
        let other_pk = other_sk.public_key();

        assert!(manager.get_secret_key(&other_pk).is_none());
    }

    #[test]
    fn test_list_public_keys() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        let public_keys = manager.list_public_keys();
        assert_eq!(public_keys.len(), 1);

        let expected_pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).unwrap();
        assert_eq!(public_keys[0].to_bytes().to_vec(), expected_pubkey_bytes);
    }

    #[test]
    fn test_graceful_handling_of_corrupted_keystore() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "corrupted.json", "{ invalid json }");
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_graceful_handling_of_wrong_password() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords
            .insert(TEST_PUBKEY_HEX.to_string(), SecretString::from("wrong_password".to_string()));

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_graceful_handling_of_missing_password() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let passwords = HashMap::new();

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_ignores_non_json_files() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "readme.txt", "This is not a keystore");
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_keystore_without_pubkey_field() {
        let keystore_without_pubkey = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "no_pubkey.json", keystore_without_pubkey);
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_default_impl() {
        let manager = KeyManager::default();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_secret_key_can_sign() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).unwrap();
        let pubkey = PublicKey::from_bytes(&pubkey_bytes).unwrap();

        let secret_key = manager.get_secret_key(&pubkey).unwrap();
        let message = b"test message";
        let signature = secret_key.sign(message);

        assert!(signature.verify(&pubkey, message).is_ok());
    }

    /// RF2-06 security property: surviving loader rejects declared≠derived pubkey.
    #[test]
    fn test_keystore_with_mismatched_pubkey_is_skipped() {
        // This keystore has a WRONG pubkey field - it declares a different public key
        // than what the secret key actually derives to.
        // The declared pubkey is all zeros (a valid hex string but wrong key).
        let keystore_with_wrong_pubkey = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "Test keystore with wrong pubkey",
            "pubkey": "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a84",
            "version": 4
        }
        "#;

        let wrong_pubkey_hex =
            "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c";

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "wrong_pubkey.json", keystore_with_wrong_pubkey);

        let mut passwords = HashMap::new();
        // We provide the password for the DECLARED (wrong) pubkey
        passwords.insert(wrong_pubkey_hex.to_string(), SecretString::from(test_password_string()));

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        // The keystore should be skipped because the derived pubkey doesn't match the declared one
        assert!(manager.is_empty());
    }

    #[test]
    fn test_keystore_with_invalid_pubkey_hex_is_skipped() {
        // This keystore has an invalid pubkey hex string (not valid hex / wrong length)
        let keystore_with_invalid_pubkey = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "Test keystore with invalid pubkey hex",
            "pubkey": "invalid_hex_string_not_valid_zzz",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a85",
            "version": 4
        }
        "#;

        let invalid_pubkey_hex = "invalid_hex_string_not_valid_zzz";

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "invalid_pubkey.json", keystore_with_invalid_pubkey);

        let mut passwords = HashMap::new();
        passwords
            .insert(invalid_pubkey_hex.to_string(), SecretString::from(test_password_string()));

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();

        // The keystore should be skipped because the pubkey hex is invalid
        assert!(manager.is_empty());
    }

    #[cfg(unix)]
    mod symlink_tests {
        use super::*;
        use std::os::unix::fs::symlink;
        use std::path::PathBuf;

        fn create_keystore_file_at_path(path: &PathBuf, content: &str) {
            let mut file = File::create(path).unwrap();
            file.write_all(content.as_bytes()).unwrap();
        }

        /// RF2-06 security property: surviving loader rejects path-traversal (symlink outside base).
        #[test]
        fn test_symlink_outside_directory_is_skipped() {
            let keystore_dir = TempDir::new().unwrap();
            let outside_dir = TempDir::new().unwrap();

            let outside_keystore = outside_dir.path().join("secret_keystore.json");
            create_keystore_file_at_path(&outside_keystore, TEST_KEYSTORE_PBKDF2);

            let symlink_path = keystore_dir.path().join("malicious_link.json");
            symlink(&outside_keystore, &symlink_path).unwrap();

            let mut passwords = HashMap::new();
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

            let result = KeyManager::load_from_directory(keystore_dir.path(), &passwords);

            assert!(
                matches!(result, Err(KeyManagerError::NoKeystoreFiles)),
                "Symlink pointing outside directory should be skipped"
            );
        }

        #[test]
        fn test_symlink_within_directory_is_allowed() {
            let keystore_dir = TempDir::new().unwrap();

            let actual_keystore = keystore_dir.path().join("actual_keystore.json");
            create_keystore_file_at_path(&actual_keystore, TEST_KEYSTORE_PBKDF2);

            let symlink_path = keystore_dir.path().join("link_to_keystore.json");
            symlink(&actual_keystore, &symlink_path).unwrap();

            let mut passwords = HashMap::new();
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

            let manager = KeyManager::load_from_directory(keystore_dir.path(), &passwords).unwrap();

            assert_eq!(manager.len(), 1, "Symlink within directory should be allowed");
        }

        #[test]
        fn test_symlink_to_parent_directory_is_skipped() {
            let parent_dir = TempDir::new().unwrap();
            let keystore_dir_path = parent_dir.path().join("keystores");
            fs::create_dir(&keystore_dir_path).unwrap();

            let parent_keystore = parent_dir.path().join("parent_keystore.json");
            create_keystore_file_at_path(&parent_keystore, TEST_KEYSTORE_PBKDF2);

            let symlink_path = keystore_dir_path.join("parent_link.json");
            symlink(&parent_keystore, &symlink_path).unwrap();

            let mut passwords = HashMap::new();
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

            let result = KeyManager::load_from_directory(&keystore_dir_path, &passwords);

            assert!(
                matches!(result, Err(KeyManagerError::NoKeystoreFiles)),
                "Symlink pointing to parent directory should be skipped"
            );
        }
    }

    #[test]
    fn test_secret_string_password_is_not_exposed_in_debug() {
        let secret = test_password_secret();
        let debug_output = format!("{:?}", secret);
        assert!(!debug_output.contains(&test_password_string()));
    }

    #[test]
    fn test_insert_duplicate_pubkey_overwrites() {
        let mut manager = KeyManager::new();

        let sk = SecretKey::generate();
        let pubkey = sk.public_key();
        let sk_bytes = sk.to_bytes();

        manager.insert(sk);
        assert_eq!(manager.len(), 1);

        // Recreate the same key from raw bytes (same pubkey)
        let sk_clone = SecretKey::from_bytes(&sk_bytes).unwrap();
        manager.insert(sk_clone);

        // Should still be 1 (overwrite, not append)
        assert_eq!(manager.len(), 1);
        assert!(manager.get_secret_key(&pubkey).is_some());
    }

    // ── Parallel decryption tests ─────────────────────────────────────────

    /// Helper: generates a random key, encrypts it as PBKDF2 keystore, writes JSON
    /// to the given directory, and returns (pubkey_hex, password_string).
    fn create_generated_keystore(dir: &TempDir, index: usize) -> (String, String) {
        use crate::keystore::EncryptionKdf;

        let sk = SecretKey::generate();
        let password = format!("password-{}", index);
        let keystore = Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let pubkey_hex = keystore.pubkey.clone().unwrap();
        let json = keystore.to_json().expect("should serialize");
        let filename = format!("keystore-{}.json", index);
        create_test_keystore_file(dir, &filename, &json);
        (pubkey_hex, password)
    }

    #[test]
    fn test_parallel_load_single_key() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2))
                .unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_parallel_load_multiple_keys() {
        let temp_dir = TempDir::new().unwrap();
        let mut passwords = HashMap::new();

        for i in 0..3 {
            let (pubkey_hex, password) = create_generated_keystore(&temp_dir, i);
            passwords.insert(pubkey_hex, SecretString::from(password));
        }

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2))
                .unwrap();
        assert_eq!(manager.len(), 3);
    }

    #[test]
    fn test_parallel_load_mixed_success_failure() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);
        create_test_keystore_file(&temp_dir, "corrupted.json", "{ invalid json }");

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2))
                .unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_parallel_load_wrong_password_skipped() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords
            .insert(TEST_PUBKEY_HEX.to_string(), SecretString::from("wrong_password".to_string()));

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2))
                .unwrap();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_parallel_load_pubkey_mismatch_skipped() {
        let keystore_with_wrong_pubkey = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": {
                        "iv": "264daa3f303d7259501c93d997d84fe6"
                    },
                    "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"
                }
            },
            "description": "Test keystore with wrong pubkey",
            "pubkey": "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c",
            "path": "m/12381/60/0/0",
            "uuid": "64625def-3331-4eea-ab6f-782f3ed16a84",
            "version": 4
        }
        "#;

        let wrong_pubkey_hex =
            "a99a76ed7796f7be22d5b7e85deeb7c5677e88e511e0b337618f8c4eb61349b4bf2d153f649f7b53359fe8b94a38e44c";

        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "wrong_pubkey.json", keystore_with_wrong_pubkey);

        let mut passwords = HashMap::new();
        passwords.insert(wrong_pubkey_hex.to_string(), SecretString::from(test_password_string()));

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2))
                .unwrap();
        assert!(manager.is_empty());
    }

    #[test]
    fn test_parallel_load_thread_count_1() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(1))
                .unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_parallel_load_thread_count_capped_at_32() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(100))
                .unwrap();
        assert_eq!(manager.len(), 1);
    }

    #[test]
    fn test_parallel_load_no_keystores_error() {
        let temp_dir = TempDir::new().unwrap();
        let passwords = HashMap::new();

        let result =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2));
        assert!(matches!(result, Err(KeyManagerError::NoKeystoreFiles)));
    }

    #[test]
    fn test_load_from_directory_delegates_to_parallel() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

        let manager_default = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        let manager_explicit =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, None)
                .unwrap();

        assert_eq!(manager_default.len(), manager_explicit.len());

        let keys_default: std::collections::BTreeSet<_> =
            manager_default.list_public_keys().iter().map(|pk| pk.to_bytes()).collect();
        let keys_explicit: std::collections::BTreeSet<_> =
            manager_explicit.list_public_keys().iter().map(|pk| pk.to_bytes()).collect();
        assert_eq!(keys_default, keys_explicit);
    }

    #[cfg(unix)]
    mod parallel_symlink_tests {
        use super::*;
        use std::os::unix::fs::symlink;

        #[test]
        fn test_parallel_load_preserves_symlink_check() {
            let keystore_dir = TempDir::new().unwrap();
            let outside_dir = TempDir::new().unwrap();

            let outside_keystore = outside_dir.path().join("secret_keystore.json");
            let mut file = File::create(&outside_keystore).unwrap();
            file.write_all(TEST_KEYSTORE_PBKDF2.as_bytes()).unwrap();

            let symlink_path = keystore_dir.path().join("malicious_link.json");
            symlink(&outside_keystore, &symlink_path).unwrap();

            let mut passwords = HashMap::new();
            passwords.insert(TEST_PUBKEY_HEX.to_string(), test_password_secret());

            let result = KeyManager::load_from_directory_with_threads(
                keystore_dir.path(),
                &passwords,
                Some(2),
            );

            assert!(
                matches!(result, Err(KeyManagerError::NoKeystoreFiles)),
                "Symlink pointing outside directory should be skipped in parallel load"
            );
        }
    }

    #[test]
    fn test_validate_key_path_accepts_file_inside_dir() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("keystore.json");
        File::create(&file_path).unwrap();

        let result = validate_key_path(dir.path(), &file_path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_key_path_rejects_path_outside_dir() {
        let base_dir = TempDir::new().unwrap();
        let outside_dir = TempDir::new().unwrap();
        let outside_file = outside_dir.path().join("evil.json");
        File::create(&outside_file).unwrap();

        let result = validate_key_path(base_dir.path(), &outside_file);
        assert!(
            matches!(result, Err(KeyManagerError::PathTraversal { .. })),
            "Expected PathTraversal error, got: {:?}",
            result
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_key_path_rejects_symlink_outside_dir() {
        let base_dir = TempDir::new().unwrap();
        let outside_dir = TempDir::new().unwrap();
        let outside_file = outside_dir.path().join("evil.json");
        File::create(&outside_file).unwrap();

        let symlink_path = base_dir.path().join("link.json");
        std::os::unix::fs::symlink(&outside_file, &symlink_path).unwrap();

        let result = validate_key_path(base_dir.path(), &symlink_path);
        assert!(
            matches!(result, Err(KeyManagerError::PathTraversal { .. })),
            "Expected PathTraversal error for symlink outside dir, got: {:?}",
            result
        );
    }

    // ── Wildcard ("*") password fallback tests ────────────────────────────

    #[test]
    fn test_threads_wildcard_password_fallback_decrypts() {
        let temp_dir = TempDir::new().unwrap();
        let (_pubkey_hex, password) = create_generated_keystore(&temp_dir, 0);

        // No per-key entry; only the wildcard is present, with the correct password.
        let mut passwords = HashMap::new();
        passwords.insert(WILDCARD_KEY.to_string(), SecretString::from(password));

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2))
                .unwrap();
        assert_eq!(manager.len(), 1, "wildcard password should decrypt the keystore");
    }

    #[test]
    fn test_threads_per_key_password_overrides_wildcard() {
        let temp_dir = TempDir::new().unwrap();
        let (pubkey_hex, password) = create_generated_keystore(&temp_dir, 0);

        // Per-key entry has the correct password; wildcard has a wrong one.
        // If the per-key entry wins, the keystore decrypts.
        let mut passwords = HashMap::new();
        passwords.insert(pubkey_hex, SecretString::from(password));
        passwords
            .insert(WILDCARD_KEY.to_string(), SecretString::from("wrong_password".to_string()));

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2))
                .unwrap();
        assert_eq!(manager.len(), 1, "per-key password must override the wildcard");
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_threads_no_entry_and_no_wildcard_skips_and_warns() {
        let temp_dir = TempDir::new().unwrap();
        let (_pubkey_hex, _password) = create_generated_keystore(&temp_dir, 0);

        // Neither a per-key entry nor a wildcard exists.
        let passwords = HashMap::new();

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2))
                .unwrap();
        assert!(manager.is_empty(), "keystore must be skipped when no password matches");
        assert!(
            logs_contain("No password found"),
            "expected warn log when neither per-key nor wildcard password exists"
        );
    }

    /// Helper mirroring `create_generated_keystore` but with an explicit password,
    /// so multiple keystores can deliberately share (or differ in) their password.
    /// Returns the keystore's pubkey hex.
    fn create_generated_keystore_with_password(
        dir: &TempDir,
        index: usize,
        password: &str,
    ) -> String {
        use crate::keystore::EncryptionKdf;

        let sk = SecretKey::generate();
        let keystore = Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let pubkey_hex = keystore.pubkey.clone().unwrap();
        let json = keystore.to_json().expect("should serialize");
        let filename = format!("keystore-{}.json", index);
        create_test_keystore_file(dir, &filename, &json);
        pubkey_hex
    }

    #[test]
    fn test_threads_mixed_batch_wildcard_and_per_key_override() {
        let temp_dir = TempDir::new().unwrap();

        // Three distinct keystores with distinct pubkeys. Keystores 0 and 2 are
        // encrypted with the shared "wildcard" password; keystore 1 has its own
        // password and must load via a per-key override (the wildcard would NOT
        // decrypt it).
        let wildcard_password = "shared-wildcard-pw";
        let override_password = "per-key-override-pw";
        let pubkey0 = create_generated_keystore_with_password(&temp_dir, 0, wildcard_password);
        let pubkey1 = create_generated_keystore_with_password(&temp_dir, 1, override_password);
        let pubkey2 = create_generated_keystore_with_password(&temp_dir, 2, wildcard_password);

        // Password map: ONLY a wildcard plus a single per-key override for keystore 1.
        let mut passwords = HashMap::new();
        passwords
            .insert(WILDCARD_KEY.to_string(), SecretString::from(wildcard_password.to_string()));
        passwords.insert(pubkey1.clone(), SecretString::from(override_password.to_string()));

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(4))
                .unwrap();

        // All three keystores must load: 0 and 2 via the wildcard, 1 via override.
        assert_eq!(manager.len(), 3, "all keystores in the batch must load");

        for pubkey_hex in [&pubkey0, &pubkey1, &pubkey2] {
            let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
            let pubkey = PublicKey::from_bytes(&pubkey_bytes).unwrap();
            let sk = manager
                .get_secret_key(&pubkey)
                .unwrap_or_else(|| panic!("expected key {pubkey_hex} to be loaded"));
            assert_eq!(
                sk.public_key().to_bytes(),
                pubkey.to_bytes(),
                "loaded secret key must derive the expected pubkey for {pubkey_hex}"
            );
        }
    }

    #[test]
    fn test_threads_wrong_wildcard_no_per_key_skips() {
        let temp_dir = TempDir::new().unwrap();
        let (_pubkey_hex, _password) = create_generated_keystore(&temp_dir, 0);

        // Only a wildcard entry, with the WRONG password, and no per-key entry.
        let mut passwords = HashMap::new();
        passwords
            .insert(WILDCARD_KEY.to_string(), SecretString::from("wrong_password".to_string()));

        let manager =
            KeyManager::load_from_directory_with_threads(temp_dir.path(), &passwords, Some(2))
                .unwrap();
        assert!(manager.is_empty(), "wrong wildcard password must not silently succeed");
    }

    /// RF2-06 security property: surviving loader logs truncated pubkeys, never the full hex.
    #[test]
    #[tracing_test::traced_test]
    fn test_loader_logs_truncated_pubkey_not_full() {
        let temp_dir = TempDir::new().unwrap();
        create_test_keystore_file(&temp_dir, "validator1.json", TEST_KEYSTORE_PBKDF2);

        let mut passwords = HashMap::new();
        passwords
            .insert(TEST_PUBKEY_HEX.to_string(), SecretString::from("wrong_password".to_string()));

        let manager = KeyManager::load_from_directory(temp_dir.path(), &passwords).unwrap();
        assert!(manager.is_empty());

        let truncated = TruncatedPubkey::new(TEST_PUBKEY_HEX).to_string();
        assert!(
            logs_contain(&truncated),
            "decrypt-failure log must include truncated pubkey {truncated}"
        );
        assert!(
            !logs_contain(TEST_PUBKEY_HEX),
            "decrypt-failure log must not include full pubkey hex"
        );
        assert!(logs_contain("Failed to decrypt keystore"));
    }
}
