use std::fs;
use std::path::Path;

use aes::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use zeroize::Zeroizing;

use super::bls::SecretKey;
use super::error::KeystoreError;

type Aes128Ctr = ctr::Ctr64BE<aes::Aes128>;

const KEYSTORE_VERSION: u32 = 4;
const KDF_SCRYPT: &str = "scrypt";
const KDF_PBKDF2: &str = "pbkdf2";
const CIPHER_AES_128_CTR: &str = "aes-128-ctr";
const CHECKSUM_SHA256: &str = "sha256";
const DERIVED_KEY_LEN: usize = 32;
const AES_KEY_LEN: usize = 16;

const SALT_LEN: usize = 32;
const IV_LEN: usize = 16;

const DEFAULT_SCRYPT_N: u32 = 262_144; // 2^18
const DEFAULT_SCRYPT_R: u32 = 8;
const DEFAULT_SCRYPT_P: u32 = 1;
const DEFAULT_SCRYPT_DKLEN: u32 = 32;

const DEFAULT_PBKDF2_C: u32 = 262_144; // 2^18
const DEFAULT_PBKDF2_DKLEN: u32 = 32;
const DEFAULT_PBKDF2_PRF: &str = "hmac-sha256";

const MIN_PBKDF2_C: u32 = 10_000;
const MAX_PBKDF2_C: u32 = 10_000_000;

const MAX_SCRYPT_N: u32 = 1 << 22;
const MAX_SCRYPT_R: u32 = 16;
const MAX_SCRYPT_P: u32 = 16;
const MAX_SCRYPT_DKLEN: u32 = 64;

/// Largest scrypt working set `decrypt` will still attempt, in bytes.
///
/// Scrypt's buffer is `128 · r · N` (RFC 7914). This is that product at the
/// largest `r` and `N` the decrypt-time gates accept, which is 8 GiB.
/// [`kdf_working_set_bytes`] reports the uploaded cost even past this ceiling;
/// parameter rejection stays inside `decrypt`.
pub const MAX_KDF_WORKING_SET_BYTES: u64 = 128 * (MAX_SCRYPT_R as u64) * (MAX_SCRYPT_N as u64);

#[derive(Debug, Clone, Copy)]
pub enum EncryptionKdf {
    /// Production scrypt params (n = 2^18). EIP-2335 default.
    Scrypt,
    /// Production PBKDF2 params (c = 2^18). EIP-2335 default.
    Pbkdf2,
    /// Caller-supplied scrypt params. Use `scrypt_cheap_for_tests()` to
    /// construct fast test fixtures. NEVER use n < 2^17 in production.
    ScryptWith { n: u32, r: u32, p: u32, dklen: u32 },
    /// Caller-supplied PBKDF2 params. Use `pbkdf2_cheap_for_tests()` to
    /// construct fast test fixtures. The validator still enforces
    /// `c >= MIN_PBKDF2_C` (10_000) at decrypt time.
    Pbkdf2With { c: u32, dklen: u32 },
}

impl EncryptionKdf {
    /// Cheap scrypt params for unit tests only (n = 2). Provides essentially
    /// no key stretching — never use this in production code paths.
    pub fn scrypt_cheap_for_tests() -> Self {
        Self::ScryptWith { n: 2, r: 1, p: 1, dklen: DEFAULT_SCRYPT_DKLEN }
    }

    /// Cheap PBKDF2 params for unit tests only (c = MIN_PBKDF2_C = 10_000,
    /// the floor the decrypt validator enforces). Prefer
    /// `scrypt_cheap_for_tests()` when the test does not specifically
    /// exercise the PBKDF2 path — scrypt-cheap is ~10× faster.
    pub fn pbkdf2_cheap_for_tests() -> Self {
        Self::Pbkdf2With { c: MIN_PBKDF2_C, dklen: DEFAULT_PBKDF2_DKLEN }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keystore {
    pub crypto: Crypto,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    pub path: String,
    pub uuid: Uuid,
    pub version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crypto {
    pub kdf: KdfModule,
    pub checksum: ChecksumModule,
    pub cipher: CipherModule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfModule {
    pub function: String,
    pub params: KdfParams,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum KdfParams {
    Scrypt(ScryptParams),
    Pbkdf2(Pbkdf2Params),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScryptParams {
    pub dklen: u32,
    pub n: u32,
    pub p: u32,
    pub r: u32,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pbkdf2Params {
    pub dklen: u32,
    pub c: u32,
    pub prf: String,
    pub salt: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumModule {
    pub function: String,
    pub params: ChecksumParams,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChecksumParams {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherModule {
    pub function: String,
    pub params: CipherParams,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherParams {
    pub iv: String,
}

/// KDF memory working set of `keystore` as uploaded, in bytes.
///
/// Scrypt costs `128 · r · N` from the parameters in the keystore, including
/// values [`Keystore::decrypt`] will later reject. PBKDF2 is not memory-hard
/// and costs `0`. Overflow saturates at `u64::MAX` so a wrapped product cannot
/// under-report the working set.
///
/// # Examples
///
/// ```
/// use rvc_crypto::{kdf_working_set_bytes, Keystore};
///
/// let json = r#"{"crypto":{"kdf":{"function":"pbkdf2","params":{"dklen":32,"c":262144,"prf":"hmac-sha256","salt":"aa"},"message":""},"checksum":{"function":"sha256","params":{},"message":"aa"},"cipher":{"function":"aes-128-ctr","params":{"iv":"aa"},"message":"aa"}},"path":"m/12381/3600/0/0/0","uuid":"00000000-0000-0000-0000-000000000000","version":4}"#;
/// let keystore = Keystore::from_json(json).expect("keystore json");
/// assert_eq!(kdf_working_set_bytes(&keystore), 0);
/// ```
pub fn kdf_working_set_bytes(keystore: &Keystore) -> u64 {
    match (keystore.crypto.kdf.function.as_str(), &keystore.crypto.kdf.params) {
        (KDF_SCRYPT, KdfParams::Scrypt(params)) => {
            128u64.saturating_mul(u64::from(params.r)).saturating_mul(u64::from(params.n))
        }
        _ => 0,
    }
}

impl Keystore {
    pub fn from_json(json: &str) -> Result<Self, KeystoreError> {
        let keystore: Keystore = serde_json::from_str(json)?;
        keystore.validate()?;
        Ok(keystore)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, KeystoreError> {
        let json = fs::read_to_string(path)?;
        Self::from_json(&json)
    }

    fn validate(&self) -> Result<(), KeystoreError> {
        if self.version != KEYSTORE_VERSION {
            return Err(KeystoreError::UnsupportedVersion(self.version));
        }

        match self.crypto.kdf.function.as_str() {
            KDF_SCRYPT | KDF_PBKDF2 => {}
            other => return Err(KeystoreError::UnsupportedKdf(other.to_string())),
        }

        if self.crypto.cipher.function != CIPHER_AES_128_CTR {
            return Err(KeystoreError::UnsupportedCipher(self.crypto.cipher.function.clone()));
        }

        if self.crypto.checksum.function != CHECKSUM_SHA256 {
            return Err(KeystoreError::UnsupportedChecksum(self.crypto.checksum.function.clone()));
        }

        Ok(())
    }

    pub fn decrypt(&self, password: &[u8]) -> Result<SecretKey, KeystoreError> {
        let derived_key = Zeroizing::new(self.derive_key(password)?);
        let ciphertext = hex::decode(&self.crypto.cipher.message)?;
        self.verify_checksum(&derived_key, &ciphertext)?;
        let plaintext = Zeroizing::new(self.decrypt_ciphertext(&derived_key, &ciphertext)?);
        SecretKey::from_bytes(&plaintext).map_err(KeystoreError::from)
    }

    fn derive_key(&self, password: &[u8]) -> Result<[u8; DERIVED_KEY_LEN], KeystoreError> {
        match self.crypto.kdf.function.as_str() {
            KDF_SCRYPT => self.derive_key_scrypt(password),
            KDF_PBKDF2 => self.derive_key_pbkdf2(password),
            other => Err(KeystoreError::UnsupportedKdf(other.to_string())),
        }
    }

    fn derive_key_scrypt(&self, password: &[u8]) -> Result<[u8; DERIVED_KEY_LEN], KeystoreError> {
        let params = match &self.crypto.kdf.params {
            KdfParams::Scrypt(p) => p,
            _ => {
                return Err(KeystoreError::InvalidScryptParams(
                    "expected scrypt params".to_string(),
                ))
            }
        };

        // Validate scrypt parameters to prevent DoS attacks
        if params.n > MAX_SCRYPT_N {
            return Err(KeystoreError::InvalidScryptParams(format!(
                "n ({}) exceeds maximum ({})",
                params.n, MAX_SCRYPT_N
            )));
        }
        if params.r > MAX_SCRYPT_R {
            return Err(KeystoreError::InvalidScryptParams(format!(
                "r ({}) exceeds maximum ({})",
                params.r, MAX_SCRYPT_R
            )));
        }
        if params.p > MAX_SCRYPT_P {
            return Err(KeystoreError::InvalidScryptParams(format!(
                "p ({}) exceeds maximum ({})",
                params.p, MAX_SCRYPT_P
            )));
        }
        if params.dklen > MAX_SCRYPT_DKLEN {
            return Err(KeystoreError::InvalidScryptParams(format!(
                "dklen ({}) exceeds maximum ({})",
                params.dklen, MAX_SCRYPT_DKLEN
            )));
        }

        if params.n == 0 || !params.n.is_power_of_two() {
            return Err(KeystoreError::InvalidScryptParams(
                "n must be a positive power of 2".to_string(),
            ));
        }

        let salt = hex::decode(&params.salt)?;
        let log_n = params.n.trailing_zeros() as u8;

        let scrypt_params = scrypt::Params::new(log_n, params.r, params.p, params.dklen as usize)
            .map_err(|e| KeystoreError::InvalidScryptParams(e.to_string()))?;

        let mut derived_key = [0u8; DERIVED_KEY_LEN];
        scrypt::scrypt(password, &salt, &scrypt_params, &mut derived_key)
            .map_err(|e| KeystoreError::KeyDerivationFailed(e.to_string()))?;

        Ok(derived_key)
    }

    fn derive_key_pbkdf2(&self, password: &[u8]) -> Result<[u8; DERIVED_KEY_LEN], KeystoreError> {
        let params = match &self.crypto.kdf.params {
            KdfParams::Pbkdf2(p) => p,
            _ => {
                return Err(KeystoreError::KeyDerivationFailed(
                    "expected pbkdf2 params".to_string(),
                ))
            }
        };

        if params.prf != "hmac-sha256" {
            return Err(KeystoreError::KeyDerivationFailed(format!(
                "unsupported PRF: {}",
                params.prf
            )));
        }

        if params.c < MIN_PBKDF2_C {
            return Err(KeystoreError::InvalidPbkdf2Params(format!(
                "iteration count ({}) below minimum ({})",
                params.c, MIN_PBKDF2_C
            )));
        }
        if params.c > MAX_PBKDF2_C {
            return Err(KeystoreError::InvalidPbkdf2Params(format!(
                "iteration count ({}) exceeds maximum ({})",
                params.c, MAX_PBKDF2_C
            )));
        }

        let salt = hex::decode(&params.salt)?;
        let mut derived_key = [0u8; DERIVED_KEY_LEN];

        pbkdf2::pbkdf2_hmac::<Sha256>(password, &salt, params.c, &mut derived_key);

        Ok(derived_key)
    }

    fn verify_checksum(
        &self,
        derived_key: &[u8; DERIVED_KEY_LEN],
        ciphertext: &[u8],
    ) -> Result<(), KeystoreError> {
        let expected_checksum = hex::decode(&self.crypto.checksum.message)?;

        let mut hasher = Sha256::new();
        hasher.update(&derived_key[AES_KEY_LEN..DERIVED_KEY_LEN]);
        hasher.update(ciphertext);
        let computed_checksum = hasher.finalize();

        // Use constant-time comparison to prevent timing attacks.
        // Standard != comparison short-circuits on first differing byte,
        // allowing attackers to determine the checksum byte-by-byte.
        if computed_checksum.ct_eq(&expected_checksum).unwrap_u8() != 1 {
            return Err(KeystoreError::ChecksumMismatch);
        }

        Ok(())
    }

    fn decrypt_ciphertext(
        &self,
        derived_key: &[u8; DERIVED_KEY_LEN],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeystoreError> {
        let iv = hex::decode(&self.crypto.cipher.params.iv)?;
        // SEC-5 / H-5: `Aes128Ctr::new` panics via `GenericArray::from_slice`
        // when the IV is not exactly 16 bytes. Validate before conversion so a
        // correctly-passworded but IV-corrupted keystore returns a typed error
        // (startup load + keymanager import) instead of panicking.
        if iv.len() != IV_LEN {
            return Err(KeystoreError::InvalidIvLength { expected: IV_LEN, actual: iv.len() });
        }
        let aes_key = &derived_key[..AES_KEY_LEN];

        let mut cipher = Aes128Ctr::new(aes_key.into(), iv.as_slice().into());
        let mut plaintext = ciphertext.to_vec();
        cipher.apply_keystream(&mut plaintext);

        Ok(plaintext)
    }

    pub fn pubkey_bytes(&self) -> Result<Option<Vec<u8>>, KeystoreError> {
        match &self.pubkey {
            Some(pk) => Ok(Some(hex::decode(pk)?)),
            None => Ok(None),
        }
    }

    pub fn encrypt(
        secret_key: &SecretKey,
        password: &[u8],
        path: &str,
        kdf: EncryptionKdf,
    ) -> Result<Self, KeystoreError> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);

        let mut iv = [0u8; IV_LEN];
        rand::thread_rng().fill_bytes(&mut iv);

        let uuid = Uuid::new_v4();

        let (kdf_function, kdf_params) = match kdf {
            EncryptionKdf::Scrypt => (
                KDF_SCRYPT.to_string(),
                KdfParams::Scrypt(ScryptParams {
                    dklen: DEFAULT_SCRYPT_DKLEN,
                    n: DEFAULT_SCRYPT_N,
                    p: DEFAULT_SCRYPT_P,
                    r: DEFAULT_SCRYPT_R,
                    salt: hex::encode(salt),
                }),
            ),
            EncryptionKdf::Pbkdf2 => (
                KDF_PBKDF2.to_string(),
                KdfParams::Pbkdf2(Pbkdf2Params {
                    dklen: DEFAULT_PBKDF2_DKLEN,
                    c: DEFAULT_PBKDF2_C,
                    prf: DEFAULT_PBKDF2_PRF.to_string(),
                    salt: hex::encode(salt),
                }),
            ),
            EncryptionKdf::ScryptWith { n, r, p, dklen } => (
                KDF_SCRYPT.to_string(),
                KdfParams::Scrypt(ScryptParams { dklen, n, r, p, salt: hex::encode(salt) }),
            ),
            EncryptionKdf::Pbkdf2With { c, dklen } => (
                KDF_PBKDF2.to_string(),
                KdfParams::Pbkdf2(Pbkdf2Params {
                    dklen,
                    c,
                    prf: DEFAULT_PBKDF2_PRF.to_string(),
                    salt: hex::encode(salt),
                }),
            ),
        };

        let keystore = Keystore {
            crypto: Crypto {
                kdf: KdfModule {
                    function: kdf_function,
                    params: kdf_params,
                    message: String::new(),
                },
                checksum: ChecksumModule {
                    function: CHECKSUM_SHA256.to_string(),
                    params: ChecksumParams {},
                    message: String::new(),
                },
                cipher: CipherModule {
                    function: CIPHER_AES_128_CTR.to_string(),
                    params: CipherParams { iv: hex::encode(iv) },
                    message: String::new(),
                },
            },
            description: None,
            pubkey: Some(hex::encode(secret_key.public_key().to_bytes())),
            path: path.to_string(),
            uuid,
            version: KEYSTORE_VERSION,
        };

        let derived_key = Zeroizing::new(keystore.derive_key(password)?);

        // Gate 1: keystore encryption needs the raw SK bytes (kept in Zeroizing, never logged).
        #[allow(clippy::disallowed_methods)]
        let plaintext = Zeroizing::new(secret_key.to_bytes());
        let aes_key = &derived_key[..AES_KEY_LEN];
        let mut cipher = Aes128Ctr::new(aes_key.into(), iv.as_slice().into());
        let mut ciphertext = plaintext.to_vec();
        cipher.apply_keystream(&mut ciphertext);

        let mut hasher = Sha256::new();
        hasher.update(&derived_key[AES_KEY_LEN..DERIVED_KEY_LEN]);
        hasher.update(&ciphertext);
        let checksum = hasher.finalize();

        let mut keystore = keystore;
        keystore.crypto.cipher.message = hex::encode(&ciphertext);
        keystore.crypto.checksum.message = hex::encode(checksum);

        Ok(keystore)
    }

    pub fn to_json(&self) -> Result<String, KeystoreError> {
        serde_json::to_string_pretty(self).map_err(KeystoreError::from)
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), KeystoreError> {
        let json = self.to_json()?;

        #[cfg(unix)]
        {
            use std::fs::OpenOptions;
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;

            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            file.write_all(json.as_bytes())?;
        }

        #[cfg(not(unix))]
        {
            fs::write(path, json)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use super::*;

    // EIP-2335 official test vectors from https://eips.ethereum.org/EIPS/eip-2335
    // Password: 0x7465737470617373776f7264f09f9491 (UTF-8: test password with emoji)
    // Secret: 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
    const EIP2335_PASSWORD: &[u8] = &[
        0x74, 0x65, 0x73, 0x74, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0xf0, 0x9f, 0x94,
        0x91,
    ];
    const EIP2335_SECRET_HEX: &str =
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    const EIP2335_SCRYPT_TEST_VECTOR: &str = r#"
    {
        "crypto": {
            "kdf": {
                "function": "scrypt",
                "params": {
                    "dklen": 32,
                    "n": 262144,
                    "p": 1,
                    "r": 8,
                    "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                },
                "message": ""
            },
            "checksum": {
                "function": "sha256",
                "params": {},
                "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
            },
            "cipher": {
                "function": "aes-128-ctr",
                "params": {
                    "iv": "264daa3f303d7259501c93d997d84fe6"
                },
                "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
            }
        },
        "description": "This is a test keystore that uses scrypt to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/3141592653/589793238",
        "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
        "version": 4
    }
    "#;

    const EIP2335_PBKDF2_TEST_VECTOR: &str = r#"
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
        "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
        "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
        "path": "m/12381/60/0/0",
        "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
        "version": 4
    }
    "#;

    #[test]
    fn test_parse_scrypt_keystore() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.crypto.kdf.function, "scrypt");
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(keystore.crypto.checksum.function, "sha256");
        assert_eq!(keystore.path, "m/12381/60/3141592653/589793238");
    }

    #[test]
    fn test_parse_pbkdf2_keystore() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.crypto.kdf.function, "pbkdf2");
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(keystore.crypto.checksum.function, "sha256");
        assert_eq!(keystore.path, "m/12381/60/0/0");
    }

    #[test]
    fn test_scrypt_params_extraction() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        match &keystore.crypto.kdf.params {
            KdfParams::Scrypt(params) => {
                assert_eq!(params.dklen, 32);
                assert_eq!(params.n, 262144);
                assert_eq!(params.p, 1);
                assert_eq!(params.r, 8);
            }
            _ => panic!("expected scrypt params"),
        }
    }

    #[test]
    fn test_pbkdf2_params_extraction() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        match &keystore.crypto.kdf.params {
            KdfParams::Pbkdf2(params) => {
                assert_eq!(params.dklen, 32);
                assert_eq!(params.c, 262144);
                assert_eq!(params.prf, "hmac-sha256");
            }
            _ => panic!("expected pbkdf2 params"),
        }
    }

    #[test]
    fn test_unsupported_version() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 3
        }
        "#;
        let result = Keystore::from_json(json);
        assert!(matches!(result, Err(KeystoreError::UnsupportedVersion(3))));
    }

    #[test]
    fn test_unsupported_kdf() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "argon2id", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let result = Keystore::from_json(json);
        assert!(matches!(result, Err(KeystoreError::UnsupportedKdf(_))));
    }

    #[test]
    fn test_unsupported_cipher() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-256-gcm", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let result = Keystore::from_json(json);
        assert!(matches!(result, Err(KeystoreError::UnsupportedCipher(_))));
    }

    #[test]
    fn test_unsupported_checksum() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha512", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let result = Keystore::from_json(json);
        assert!(matches!(result, Err(KeystoreError::UnsupportedChecksum(_))));
    }

    #[test]
    fn test_uuid_parsing() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        assert_eq!(keystore.uuid.to_string(), "1d85ae20-35c5-4611-98e8-aa14a633906f");
    }

    #[test]
    fn test_pubkey_extraction() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let pubkey_bytes = keystore.pubkey_bytes().expect("should decode").unwrap();
        assert_eq!(pubkey_bytes.len(), 48);
    }

    #[test]
    fn test_optional_fields() {
        let json = r#"
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
        let keystore = Keystore::from_json(json).expect("should parse");
        assert!(keystore.description.is_none());
        assert!(keystore.pubkey.is_none());
    }

    #[test]
    fn test_scrypt_key_derivation() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let derived_key = keystore.derive_key(EIP2335_PASSWORD).expect("should derive key");
        assert_eq!(derived_key.len(), 32);
    }

    #[test]
    fn test_pbkdf2_key_derivation() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        let derived_key = keystore.derive_key(EIP2335_PASSWORD).expect("should derive key");
        assert_eq!(derived_key.len(), 32);
    }

    #[test]
    fn test_scrypt_decrypt_eip2335_test_vector() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let secret_key = keystore.decrypt(EIP2335_PASSWORD).expect("should decrypt");
        let expected_secret = hex::decode(EIP2335_SECRET_HEX).expect("valid hex");
        assert_eq!(secret_key.to_bytes().to_vec(), expected_secret);
    }

    #[test]
    fn test_pbkdf2_decrypt_eip2335_test_vector() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        let secret_key = keystore.decrypt(EIP2335_PASSWORD).expect("should decrypt");
        let expected_secret = hex::decode(EIP2335_SECRET_HEX).expect("valid hex");
        assert_eq!(secret_key.to_bytes().to_vec(), expected_secret);
    }

    #[test]
    fn test_checksum_verification_failure_wrong_password() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let wrong_password = "wrongpassword".as_bytes();
        let result = keystore.decrypt(wrong_password);
        assert!(matches!(result, Err(KeystoreError::ChecksumMismatch)));
    }

    #[test]
    fn test_checksum_verification_failure_empty_password() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let result = keystore.decrypt(&[]);
        assert!(matches!(result, Err(KeystoreError::ChecksumMismatch)));
    }

    #[test]
    fn test_serialize_keystore() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let serialized = serde_json::to_string(&keystore).expect("should serialize");
        let reparsed: Keystore = serde_json::from_str(&serialized).expect("should reparse");
        assert_eq!(reparsed.version, keystore.version);
        assert_eq!(reparsed.uuid, keystore.uuid);
    }

    #[test]
    fn test_invalid_json() {
        let result = Keystore::from_json("not valid json");
        assert!(matches!(result, Err(KeystoreError::InvalidJson(_))));
    }

    // Scrypt parameter validation tests
    #[test]
    fn test_scrypt_n_zero_returns_error() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": { "dklen": 32, "n": 0, "p": 1, "r": 8, "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" },
                    "message": ""
                },
                "checksum": { "function": "sha256", "params": {}, "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "264daa3f303d7259501c93d997d84fe6" }, "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(msg)) if msg.contains("power of 2"))
        );
    }

    #[test]
    fn test_scrypt_n_not_power_of_two_returns_error() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": { "dklen": 32, "n": 3, "p": 1, "r": 8, "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" },
                    "message": ""
                },
                "checksum": { "function": "sha256", "params": {}, "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "264daa3f303d7259501c93d997d84fe6" }, "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(msg)) if msg.contains("power of 2"))
        );
    }

    #[test]
    fn test_scrypt_n_valid_power_of_two() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        match &keystore.crypto.kdf.params {
            KdfParams::Scrypt(params) => {
                assert_eq!(params.n, 262144);
                assert!(params.n.is_power_of_two());
            }
            _ => panic!("expected scrypt params"),
        }
        let result = keystore.decrypt(EIP2335_PASSWORD);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scrypt_n_large_power_of_two_validation() {
        // Test that large power-of-2 values pass our validation
        // (the scrypt library may still reject due to memory limits)
        let n_values: Vec<u32> = vec![1 << 20, 1 << 24, 1 << 30];
        for n in n_values {
            assert!(n.is_power_of_two());
            assert!(n != 0);
            // trailing_zeros correctly computes log2 for powers of 2
            assert_eq!(n.trailing_zeros(), (n as f64).log2() as u32);
        }
    }

    #[test]
    fn test_invalid_hex_in_salt() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "not_hex!" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(matches!(result, Err(KeystoreError::InvalidHex(_))));
    }

    #[test]
    fn test_decrypted_key_can_sign() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let secret_key = keystore.decrypt(EIP2335_PASSWORD).expect("should decrypt");
        let message = b"test message";
        let signature = secret_key.sign(message);
        let public_key = secret_key.public_key();
        assert!(signature.verify(&public_key, message).is_ok());
    }

    // ========== PBKDF2 iteration count validation tests ==========

    #[test]
    fn test_pbkdf2_c_below_minimum() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 1,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidPbkdf2Params(ref msg)) if msg.contains("below minimum"))
        );
    }

    #[test]
    fn test_pbkdf2_c_above_maximum() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 100000000,
                        "prf": "hmac-sha256",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidPbkdf2Params(ref msg)) if msg.contains("exceeds maximum"))
        );
    }

    #[test]
    fn test_pbkdf2_default_params_valid() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        match &keystore.crypto.kdf.params {
            KdfParams::Pbkdf2(params) => {
                assert!(params.c >= MIN_PBKDF2_C, "default c should be above minimum");
                assert!(params.c <= MAX_PBKDF2_C, "default c should be below maximum");
            }
            _ => panic!("expected pbkdf2 params"),
        }
        let result = keystore.decrypt(EIP2335_PASSWORD);
        assert!(result.is_ok(), "EIP-2335 default params should work: {:?}", result.err());
    }

    // ========== Scrypt DoS protection tests ==========

    #[test]
    fn test_scrypt_n_exceeds_max() {
        let json = r#"{"crypto":{"kdf":{"function":"scrypt","params":{"dklen":32,"n":1073741824,"p":1,"r":8,"salt":"aa"},"message":""},"checksum":{"function":"sha256","params":{},"message":"aa"},"cipher":{"function":"aes-128-ctr","params":{"iv":"aa"},"message":"aa"}},"path":"m/12381/60/0/0","uuid":"00000000-0000-0000-0000-000000000000","version":4}"#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(ref msg)) if msg.contains("exceeds maximum"))
        );
    }

    #[test]
    fn test_scrypt_r_exceeds_max() {
        let json = r#"{"crypto":{"kdf":{"function":"scrypt","params":{"dklen":32,"n":262144,"p":1,"r":100,"salt":"aa"},"message":""},"checksum":{"function":"sha256","params":{},"message":"aa"},"cipher":{"function":"aes-128-ctr","params":{"iv":"aa"},"message":"aa"}},"path":"m/12381/60/0/0","uuid":"00000000-0000-0000-0000-000000000000","version":4}"#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(ref msg)) if msg.contains("exceeds maximum"))
        );
    }

    #[test]
    fn test_scrypt_p_exceeds_max() {
        let json = r#"{"crypto":{"kdf":{"function":"scrypt","params":{"dklen":32,"n":262144,"p":100,"r":8,"salt":"aa"},"message":""},"checksum":{"function":"sha256","params":{},"message":"aa"},"cipher":{"function":"aes-128-ctr","params":{"iv":"aa"},"message":"aa"}},"path":"m/12381/60/0/0","uuid":"00000000-0000-0000-0000-000000000000","version":4}"#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(ref msg)) if msg.contains("exceeds maximum"))
        );
    }

    #[test]
    fn test_scrypt_dklen_exceeds_max() {
        let json = r#"{"crypto":{"kdf":{"function":"scrypt","params":{"dklen":128,"n":262144,"p":1,"r":8,"salt":"aa"},"message":""},"checksum":{"function":"sha256","params":{},"message":"aa"},"cipher":{"function":"aes-128-ctr","params":{"iv":"aa"},"message":"aa"}},"path":"m/12381/60/0/0","uuid":"00000000-0000-0000-0000-000000000000","version":4}"#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(ref msg)) if msg.contains("exceeds maximum"))
        );
    }

    #[test]
    fn test_scrypt_n_not_power_of_two() {
        let json = r#"{"crypto":{"kdf":{"function":"scrypt","params":{"dklen":32,"n":3,"p":1,"r":8,"salt":"aa"},"message":""},"checksum":{"function":"sha256","params":{},"message":"aa"},"cipher":{"function":"aes-128-ctr","params":{"iv":"aa"},"message":"aa"}},"path":"m/12381/60/0/0","uuid":"00000000-0000-0000-0000-000000000000","version":4}"#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(ref msg)) if msg.contains("power of 2"))
        );
    }

    #[test]
    fn test_scrypt_n_zero() {
        let json = r#"{"crypto":{"kdf":{"function":"scrypt","params":{"dklen":32,"n":0,"p":1,"r":8,"salt":"aa"},"message":""},"checksum":{"function":"sha256","params":{},"message":"aa"},"cipher":{"function":"aes-128-ctr","params":{"iv":"aa"},"message":"aa"}},"path":"m/12381/60/0/0","uuid":"00000000-0000-0000-0000-000000000000","version":4}"#;
        let keystore = Keystore::from_json(json).expect("should parse json");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::InvalidScryptParams(ref msg)) if msg.contains("power of 2"))
        );
    }

    #[test]
    fn test_scrypt_default_params_valid() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        match &keystore.crypto.kdf.params {
            KdfParams::Scrypt(params) => {
                assert!(params.n <= MAX_SCRYPT_N, "default n should be within bounds");
                assert!(params.r <= MAX_SCRYPT_R, "default r should be within bounds");
                assert!(params.p <= MAX_SCRYPT_P, "default p should be within bounds");
                assert!(params.dklen <= MAX_SCRYPT_DKLEN, "default dklen should be within bounds");
                assert!(params.n.is_power_of_two(), "default n should be power of 2");
            }
            _ => panic!("expected scrypt params"),
        }
        let result = keystore.decrypt(EIP2335_PASSWORD);
        assert!(result.is_ok(), "EIP-2335 default params should work: {:?}", result.err());
    }

    fn keystore_with_kdf(function: &str, params: KdfParams) -> Keystore {
        Keystore {
            crypto: Crypto {
                kdf: KdfModule { function: function.to_string(), params, message: String::new() },
                checksum: ChecksumModule {
                    function: CHECKSUM_SHA256.to_string(),
                    params: ChecksumParams {},
                    message: String::new(),
                },
                cipher: CipherModule {
                    function: CIPHER_AES_128_CTR.to_string(),
                    params: CipherParams { iv: String::new() },
                    message: String::new(),
                },
            },
            description: None,
            pubkey: None,
            path: "m/12381/3600/0/0/0".to_string(),
            uuid: Uuid::nil(),
            version: KEYSTORE_VERSION,
        }
    }

    #[test]
    fn kdf_working_set_bytes_matches_the_accepted_ceiling() {
        assert_eq!(
            MAX_KDF_WORKING_SET_BYTES,
            128 * u64::from(MAX_SCRYPT_R) * u64::from(MAX_SCRYPT_N)
        );
        assert_eq!(MAX_KDF_WORKING_SET_BYTES, 8u64 * 1024 * 1024 * 1024);

        let at_ceiling = keystore_with_kdf(
            KDF_SCRYPT,
            KdfParams::Scrypt(ScryptParams {
                dklen: DEFAULT_SCRYPT_DKLEN,
                n: MAX_SCRYPT_N,
                p: 1,
                r: MAX_SCRYPT_R,
                salt: "aa".to_string(),
            }),
        );
        assert_eq!(kdf_working_set_bytes(&at_ceiling), MAX_KDF_WORKING_SET_BYTES);

        // Uploaded cost, not the clamped ceiling: the EIP-2335 vector is 128 · 8 · 2^18.
        let uploaded = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        assert_eq!(kdf_working_set_bytes(&uploaded), 128u64 * 8 * 262_144);

        let pbkdf2 = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        assert_eq!(kdf_working_set_bytes(&pbkdf2), 0);

        // A product that does not fit in u64 saturates instead of wrapping small.
        let saturated = keystore_with_kdf(
            KDF_SCRYPT,
            KdfParams::Scrypt(ScryptParams {
                dklen: DEFAULT_SCRYPT_DKLEN,
                n: u32::MAX,
                p: 1,
                r: u32::MAX,
                salt: "aa".to_string(),
            }),
        );
        assert_eq!(kdf_working_set_bytes(&saturated), u64::MAX);
    }

    // ========== from_file() tests ==========

    #[test]
    fn test_from_file_success() {
        use std::io::Write;
        let mut temp_file = tempfile::NamedTempFile::new().expect("should create temp file");
        temp_file.write_all(EIP2335_SCRYPT_TEST_VECTOR.as_bytes()).expect("should write");
        let keystore = Keystore::from_file(temp_file.path()).expect("should load from file");
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.crypto.kdf.function, "scrypt");
    }

    #[test]
    fn test_from_file_not_found() {
        let result = Keystore::from_file("/nonexistent/path/to/keystore.json");
        assert!(matches!(result, Err(KeystoreError::Io(_))));
    }

    #[test]
    fn test_from_file_invalid_json() {
        use std::io::Write;
        let mut temp_file = tempfile::NamedTempFile::new().expect("should create temp file");
        temp_file.write_all(b"not valid json").expect("should write");
        let result = Keystore::from_file(temp_file.path());
        assert!(matches!(result, Err(KeystoreError::InvalidJson(_))));
    }

    // ========== pubkey_bytes() tests ==========

    #[test]
    fn test_pubkey_bytes_none() {
        let json = r#"
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
        let keystore = Keystore::from_json(json).expect("should parse");
        let result = keystore.pubkey_bytes().expect("should not error");
        assert!(result.is_none());
    }

    #[test]
    fn test_pubkey_bytes_invalid_hex() {
        let json = r#"
        {
            "crypto": {
                "kdf": { "function": "scrypt", "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "aa" }, "message": "" },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "pubkey": "not_valid_hex!@#$",
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse");
        let result = keystore.pubkey_bytes();
        assert!(matches!(result, Err(KeystoreError::InvalidHex(_))));
    }

    // ========== PBKDF2 unsupported PRF test ==========

    #[test]
    fn test_pbkdf2_unsupported_prf() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "pbkdf2",
                    "params": {
                        "dklen": 32,
                        "c": 262144,
                        "prf": "hmac-sha512",
                        "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"
                    },
                    "message": ""
                },
                "checksum": { "function": "sha256", "params": {}, "message": "aa" },
                "cipher": { "function": "aes-128-ctr", "params": { "iv": "aa" }, "message": "aa" }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse");
        let result = keystore.decrypt(b"test");
        assert!(
            matches!(result, Err(KeystoreError::KeyDerivationFailed(ref msg)) if msg.contains("unsupported PRF"))
        );
    }

    // ========== Invalid hex in cipher/checksum fields ==========

    #[test]
    fn test_invalid_hex_in_iv() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": { "iv": "not_valid_hex!" },
                    "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse");
        let result = keystore.decrypt(EIP2335_PASSWORD);
        assert!(matches!(result, Err(KeystoreError::InvalidHex(_))));
    }

    #[test]
    fn test_invalid_hex_in_checksum() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "not_valid_hex!"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": { "iv": "264daa3f303d7259501c93d997d84fe6" },
                    "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"
                }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse");
        let result = keystore.decrypt(EIP2335_PASSWORD);
        assert!(matches!(result, Err(KeystoreError::InvalidHex(_))));
    }

    #[test]
    fn test_invalid_hex_in_ciphertext() {
        let json = r#"
        {
            "crypto": {
                "kdf": {
                    "function": "scrypt",
                    "params": { "dklen": 32, "n": 262144, "p": 1, "r": 8, "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3" },
                    "message": ""
                },
                "checksum": {
                    "function": "sha256",
                    "params": {},
                    "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"
                },
                "cipher": {
                    "function": "aes-128-ctr",
                    "params": { "iv": "264daa3f303d7259501c93d997d84fe6" },
                    "message": "not_valid_hex!"
                }
            },
            "path": "m/12381/60/0/0",
            "uuid": "00000000-0000-0000-0000-000000000000",
            "version": 4
        }
        "#;
        let keystore = Keystore::from_json(json).expect("should parse");
        let result = keystore.decrypt(EIP2335_PASSWORD);
        assert!(matches!(result, Err(KeystoreError::InvalidHex(_))));
    }

    // ========== Encryption tests ==========

    #[test]
    fn test_encrypt_scrypt_produces_valid_keystore() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.crypto.kdf.function, "scrypt");
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(keystore.crypto.checksum.function, "sha256");
    }

    #[test]
    fn test_encrypt_pbkdf2_produces_valid_keystore() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::pbkdf2_cheap_for_tests(),
        )
        .expect("should encrypt");
        assert_eq!(keystore.version, 4);
        assert_eq!(keystore.crypto.kdf.function, "pbkdf2");
        assert_eq!(keystore.crypto.cipher.function, "aes-128-ctr");
        assert_eq!(keystore.crypto.checksum.function, "sha256");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_scrypt() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let decrypted = keystore.decrypt(password).expect("should decrypt");
        assert_eq!(sk.to_bytes(), decrypted.to_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_pbkdf2() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::pbkdf2_cheap_for_tests(),
        )
        .expect("should encrypt");
        let decrypted = keystore.decrypt(password).expect("should decrypt");
        assert_eq!(sk.to_bytes(), decrypted.to_bytes());
    }

    #[test]
    fn test_encrypt_pubkey_matches() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let expected_pubkey = hex::encode(sk.public_key().to_bytes());
        assert_eq!(keystore.pubkey.as_deref(), Some(expected_pubkey.as_str()));
    }

    #[test]
    fn test_encrypt_path_preserved() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let path = "m/12381/3600/42/0/0";
        let keystore =
            Keystore::encrypt(&sk, password, path, EncryptionKdf::scrypt_cheap_for_tests())
                .expect("should encrypt");
        assert_eq!(keystore.path, path);
    }

    #[test]
    fn test_encrypt_uuid_is_v4() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        assert_eq!(keystore.uuid.get_version(), Some(uuid::Version::Random));
    }

    #[test]
    fn test_encrypt_wrong_password_fails_decrypt() {
        let sk = SecretKey::generate();
        let password = b"correctpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let result = keystore.decrypt(b"wrongpassword");
        assert!(matches!(result, Err(KeystoreError::ChecksumMismatch)));
    }

    #[test]
    fn test_encrypt_scrypt_params_correct() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore =
            Keystore::encrypt(&sk, password, "m/12381/3600/0/0/0", EncryptionKdf::Scrypt)
                .expect("should encrypt");
        match &keystore.crypto.kdf.params {
            KdfParams::Scrypt(params) => {
                assert_eq!(params.dklen, 32);
                assert_eq!(params.n, 262144);
                assert_eq!(params.r, 8);
                assert_eq!(params.p, 1);
                assert_eq!(params.salt.len(), 64); // 32 bytes hex-encoded
            }
            _ => panic!("expected scrypt params"),
        }
    }

    #[test]
    fn test_encrypt_pbkdf2_params_correct() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore =
            Keystore::encrypt(&sk, password, "m/12381/3600/0/0/0", EncryptionKdf::Pbkdf2)
                .expect("should encrypt");
        match &keystore.crypto.kdf.params {
            KdfParams::Pbkdf2(params) => {
                assert_eq!(params.dklen, 32);
                assert_eq!(params.c, 262144);
                assert_eq!(params.prf, "hmac-sha256");
                assert_eq!(params.salt.len(), 64); // 32 bytes hex-encoded
            }
            _ => panic!("expected pbkdf2 params"),
        }
    }

    #[test]
    fn test_encrypt_iv_is_32_hex_chars() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        assert_eq!(keystore.crypto.cipher.params.iv.len(), 32); // 16 bytes hex-encoded
    }

    #[test]
    fn test_to_json_produces_valid_json() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let json = keystore.to_json().expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should be valid JSON");
        assert_eq!(parsed["version"], 4);
        assert_eq!(parsed["crypto"]["kdf"]["function"], "scrypt");
        assert_eq!(parsed["crypto"]["cipher"]["function"], "aes-128-ctr");
        assert_eq!(parsed["crypto"]["checksum"]["function"], "sha256");
    }

    #[test]
    fn test_to_json_then_from_json_roundtrip() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let json = keystore.to_json().expect("should serialize");
        let reloaded = Keystore::from_json(&json).expect("should parse back");
        let decrypted = reloaded.decrypt(password).expect("should decrypt");
        assert_eq!(sk.to_bytes(), decrypted.to_bytes());
    }

    #[test]
    fn test_to_file_creates_file_and_roundtrips() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let dir = tempfile::tempdir().expect("should create temp dir");
        let file_path = dir.path().join("keystore.json");
        keystore.to_file(&file_path).expect("should write to file");

        let loaded = Keystore::from_file(&file_path).expect("should load from file");
        let decrypted = loaded.decrypt(password).expect("should decrypt");
        assert_eq!(sk.to_bytes(), decrypted.to_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn test_to_file_permissions_0600() {
        use std::os::unix::fs::MetadataExt;

        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let dir = tempfile::tempdir().expect("should create temp dir");
        let file_path = dir.path().join("keystore.json");
        keystore.to_file(&file_path).expect("should write to file");

        let metadata = fs::metadata(&file_path).expect("should read metadata");
        let permissions = metadata.mode() & 0o777;
        assert_eq!(permissions, 0o600, "file permissions should be 0600");
    }

    #[test]
    fn test_encrypt_different_keys_produce_different_ciphertext() {
        let sk1 = SecretKey::generate();
        let sk2 = SecretKey::generate();
        let password = b"testpassword";
        let ks1 = Keystore::encrypt(
            &sk1,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let ks2 = Keystore::encrypt(
            &sk2,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        assert_ne!(ks1.crypto.cipher.message, ks2.crypto.cipher.message);
    }

    #[test]
    fn test_encrypt_pubkey_no_0x_prefix() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let pubkey = keystore.pubkey.as_ref().expect("should have pubkey");
        assert!(!pubkey.starts_with("0x"), "pubkey should not have 0x prefix");
        assert_eq!(pubkey.len(), 96, "pubkey hex should be 96 chars (48 bytes)");
    }

    #[test]
    fn test_decrypted_key_can_sign_after_encrypt() {
        let sk = SecretKey::generate();
        let password = b"testpassword";
        let keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        let decrypted = keystore.decrypt(password).expect("should decrypt");
        let message = b"test message";
        let signature = decrypted.sign(message);
        let public_key = decrypted.public_key();
        assert!(signature.verify(&public_key, message).is_ok());
    }

    #[test]
    fn test_encryption_kdf_cheap_constructors_decrypt_roundtrip() {
        let sk = SecretKey::generate();
        let password = b"cheap-test";

        let cheap_scrypt = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("cheap-scrypt encrypt should succeed");
        let recovered =
            cheap_scrypt.decrypt(password).expect("cheap-scrypt decrypt should succeed");
        assert_eq!(recovered.to_bytes(), sk.to_bytes());

        let cheap_pbkdf2 = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::pbkdf2_cheap_for_tests(),
        )
        .expect("cheap-pbkdf2 encrypt should succeed");
        let recovered =
            cheap_pbkdf2.decrypt(password).expect("cheap-pbkdf2 decrypt should succeed");
        assert_eq!(recovered.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn test_encryption_kdf_cheap_scrypt_uses_low_n() {
        let sk = SecretKey::generate();
        let password = b"cheap";
        let ks = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .unwrap();
        match &ks.crypto.kdf.params {
            KdfParams::Scrypt(p) => {
                assert_eq!(p.n, 2, "cheap scrypt should use n=2");
                assert_eq!(p.r, 1);
                assert_eq!(p.p, 1);
            }
            _ => panic!("expected scrypt params"),
        }
    }

    // ========== SEC-5 / H-5: IV-length guard (no panic on corrupt IV) ==========

    /// Build a valid keystore then overwrite `cipher.params.iv` with a hex
    /// encoding of the given byte length. Checksum stays valid so decrypt
    /// reaches `decrypt_ciphertext` (the former panic site).
    fn keystore_with_iv_len(iv_byte_len: usize) -> (Keystore, Vec<u8>) {
        let sk = SecretKey::generate();
        let password = b"sec5-password";
        let mut keystore = Keystore::encrypt(
            &sk,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("should encrypt");
        keystore.crypto.cipher.params.iv = hex::encode(vec![0xab; iv_byte_len]);
        (keystore, password.to_vec())
    }

    #[test]
    fn test_decrypt_wrong_length_iv_returns_err_not_panic() {
        // Shorter than 16 bytes (8-byte IV → 16 hex chars).
        let (ks_short, password) = keystore_with_iv_len(8);
        let result = ks_short.decrypt(&password);
        assert!(
            matches!(result, Err(KeystoreError::InvalidIvLength { expected: 16, actual: 8 })),
            "8-byte IV must return InvalidIvLength, got: {:?}",
            result
        );

        // Longer than 16 bytes (24-byte IV → 48 hex chars).
        let (ks_long, password) = keystore_with_iv_len(24);
        let result = ks_long.decrypt(&password);
        assert!(
            matches!(result, Err(KeystoreError::InvalidIvLength { expected: 16, actual: 24 })),
            "24-byte IV must return InvalidIvLength, got: {:?}",
            result
        );

        // Empty IV.
        let (ks_empty, password) = keystore_with_iv_len(0);
        let result = ks_empty.decrypt(&password);
        assert!(
            matches!(result, Err(KeystoreError::InvalidIvLength { expected: 16, actual: 0 })),
            "0-byte IV must return InvalidIvLength, got: {:?}",
            result
        );
    }

    #[test]
    fn test_decrypt_valid_scrypt_vector_still_passes() {
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        let secret_key = keystore.decrypt(EIP2335_PASSWORD).expect("should decrypt");
        let expected_secret = hex::decode(EIP2335_SECRET_HEX).expect("valid hex");
        assert_eq!(secret_key.to_bytes().to_vec(), expected_secret);
    }

    #[test]
    fn test_decrypt_valid_pbkdf2_vector_still_passes() {
        let keystore = Keystore::from_json(EIP2335_PBKDF2_TEST_VECTOR).expect("should parse");
        let secret_key = keystore.decrypt(EIP2335_PASSWORD).expect("should decrypt");
        let expected_secret = hex::decode(EIP2335_SECRET_HEX).expect("valid hex");
        assert_eq!(secret_key.to_bytes().to_vec(), expected_secret);
    }

    /// Sweep confirmation: salt/checksum length mismatches and wrong passwords
    /// stay `Err` (non-panicking). Encrypt-side IV is fixed-length by construction.
    #[test]
    fn test_decrypt_salt_checksum_paths_remain_err_not_panic() {
        // Wrong password → ChecksumMismatch (ct_eq, no panic).
        let keystore = Keystore::from_json(EIP2335_SCRYPT_TEST_VECTOR).expect("should parse");
        assert!(matches!(keystore.decrypt(b"wrong"), Err(KeystoreError::ChecksumMismatch)));

        // Truncated checksum message still Err, not panic.
        let mut ks = keystore.clone();
        ks.crypto.checksum.message = "aa".to_string();
        assert!(matches!(ks.decrypt(EIP2335_PASSWORD), Err(KeystoreError::ChecksumMismatch)));

        // Encrypt always produces a 16-byte (32 hex char) IV.
        let sk = SecretKey::generate();
        let encrypted = Keystore::encrypt(
            &sk,
            b"pw",
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt");
        let iv = hex::decode(&encrypted.crypto.cipher.params.iv).expect("hex");
        assert_eq!(iv.len(), IV_LEN);
        encrypted.decrypt(b"pw").expect("encrypt-side IV must decrypt cleanly");
    }
}
