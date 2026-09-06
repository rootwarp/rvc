use std::path::PathBuf;

use thiserror::Error;

/// Errors from a raw [`crate::Signer`] backend (local, remote, or composite).
///
/// Lives next to the trait that produces it. Prefer `crypto::SigningError` at
/// call sites; a deprecated re-export may remain on the former module path for
/// one release.
#[derive(Debug, Error)]
pub enum SigningError {
    #[error("key not found: {0}")]
    KeyNotFound(String),

    /// Local precondition failed with **no remote I/O** and no signature produced.
    ///
    /// Examples: raw-root `Signer::sign` called for a gRPC-only key (TypedSigner
    /// required). Safe to discard a staged slashing row — the remote was never
    /// contacted. Distinct from [`Self::RemoteSignerError`], which may follow
    /// a possible remote sign.
    #[error("signing rejected locally (no remote contact): {0}")]
    LocalRejected(String),

    #[error("remote signer error: {0}")]
    RemoteSignerError(String),

    #[error("remote signer returned invalid signature")]
    InvalidRemoteSignature,

    /// The requested duty type cannot be encoded as a Web3Signer HTTP body
    /// (SEC-8). Never falls back to a bare `{signing_root}` body.
    #[error("unsupported remote signing type: {0}")]
    UnsupportedSigningType(String),

    /// This signer cannot produce a signature for the named duty.
    ///
    /// The duty is dropped; implementations must not sign under a fallback
    /// domain. No remote I/O and no signature.
    #[error("unsupported duty: {duty}")]
    UnsupportedDuty { duty: &'static str },
}

impl SigningError {
    /// True when no remote signature can have been produced (safe to discard staged rows).
    #[must_use]
    pub fn is_unambiguous_no_signature(&self) -> bool {
        matches!(
            self,
            Self::KeyNotFound(_)
                | Self::LocalRejected(_)
                | Self::UnsupportedSigningType(_)
                | Self::UnsupportedDuty { .. }
        )
    }
}

#[derive(Error, Debug)]
pub enum BlsError {
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,
}

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("Invalid JSON format: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("Unsupported keystore version: {0}")]
    UnsupportedVersion(u32),

    #[error("Unsupported KDF function: {0}")]
    UnsupportedKdf(String),

    #[error("Unsupported cipher function: {0}")]
    UnsupportedCipher(String),

    #[error("Unsupported checksum function: {0}")]
    UnsupportedChecksum(String),

    #[error("Invalid hex encoding: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("Checksum mismatch: decryption failed")]
    ChecksumMismatch,

    #[error("Invalid scrypt parameters: {0}")]
    InvalidScryptParams(String),

    #[error("Invalid PBKDF2 parameters: {0}")]
    InvalidPbkdf2Params(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// AES-128-CTR IV must be exactly 16 bytes (EIP-2335). A wrong-length IV
    /// used to panic inside `GenericArray::from_slice`; return a typed error.
    #[error("invalid cipher IV length: expected {expected} bytes, got {actual}")]
    InvalidIvLength { expected: usize, actual: usize },

    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(#[from] BlsError),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Rate limit exceeded for keystore decryption: {0}")]
    RateLimitExceeded(String),
}

#[derive(Error, Debug)]
pub enum KeyManagerError {
    #[error("Directory not found: {0}")]
    DirectoryNotFound(PathBuf),

    #[error("No keystore files found in directory")]
    NoKeystoreFiles,

    #[error("Failed to load keystore from {path}: {source}")]
    KeystoreLoadFailed {
        path: PathBuf,
        #[source]
        source: KeystoreError,
    },

    #[error("Failed to decrypt keystore from {path}: {source}")]
    DecryptionFailed {
        path: PathBuf,
        #[source]
        source: KeystoreError,
    },

    #[error("path traversal detected: {path} resolves outside base directory {base}")]
    PathTraversal { path: PathBuf, base: PathBuf },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to create decryption thread pool: {0}")]
    ThreadPoolError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalid_public_key_display() {
        let err = BlsError::InvalidPublicKey("wrong length".to_string());
        assert_eq!(err.to_string(), "Invalid public key: wrong length");
    }

    #[test]
    fn test_invalid_secret_key_display() {
        let err = BlsError::InvalidSecretKey("invalid bytes".to_string());
        assert_eq!(err.to_string(), "Invalid secret key: invalid bytes");
    }

    #[test]
    fn test_invalid_signature_display() {
        let err = BlsError::InvalidSignature("malformed".to_string());
        assert_eq!(err.to_string(), "Invalid signature: malformed");
    }

    #[test]
    fn test_signature_verification_failed_display() {
        let err = BlsError::SignatureVerificationFailed;
        assert_eq!(err.to_string(), "Signature verification failed");
    }

    #[test]
    fn test_keystore_unsupported_version() {
        let err = KeystoreError::UnsupportedVersion(3);
        assert_eq!(err.to_string(), "Unsupported keystore version: 3");
    }

    #[test]
    fn test_keystore_unsupported_kdf() {
        let err = KeystoreError::UnsupportedKdf("argon2".to_string());
        assert_eq!(err.to_string(), "Unsupported KDF function: argon2");
    }

    #[test]
    fn test_keystore_checksum_mismatch() {
        let err = KeystoreError::ChecksumMismatch;
        assert_eq!(err.to_string(), "Checksum mismatch: decryption failed");
    }

    #[test]
    fn test_key_manager_directory_not_found() {
        let err = KeyManagerError::DirectoryNotFound(PathBuf::from("/nonexistent/path"));
        assert_eq!(err.to_string(), "Directory not found: /nonexistent/path");
    }

    #[test]
    fn test_key_manager_no_keystore_files() {
        let err = KeyManagerError::NoKeystoreFiles;
        assert_eq!(err.to_string(), "No keystore files found in directory");
    }

    #[test]
    fn test_keystore_rate_limit_exceeded() {
        let err = KeystoreError::RateLimitExceeded("abc123".to_string());
        assert_eq!(err.to_string(), "Rate limit exceeded for keystore decryption: abc123");
    }

    #[test]
    fn test_keystore_invalid_iv_length_display() {
        let err = KeystoreError::InvalidIvLength { expected: 16, actual: 8 };
        assert_eq!(err.to_string(), "invalid cipher IV length: expected 16 bytes, got 8");
    }

    #[test]
    fn test_unsupported_duty_display_names_duty() {
        let err = SigningError::UnsupportedDuty { duty: "payload_attestation" };
        assert_eq!(err.to_string(), "unsupported duty: payload_attestation");
        assert!(err.is_unambiguous_no_signature());
    }
}
