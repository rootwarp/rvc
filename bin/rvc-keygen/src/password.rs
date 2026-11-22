use std::path::Path;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

const MIN_PASSWORD_LENGTH: usize = 8;

/// Prompts the user for a password with double-prompt confirmation.
///
/// Returns `Zeroizing<String>` on success, or an error if the passwords don't match
/// or the password is too short.
pub fn prompt_password() -> Result<Zeroizing<String>> {
    let password = Zeroizing::new(
        rpassword::prompt_password_stderr("Enter keystore password: ")
            .context("Failed to read password")?,
    );

    validate_password(&password)?;

    let confirm = Zeroizing::new(
        rpassword::prompt_password_stderr("Confirm password: ")
            .context("Failed to read password")?,
    );

    if *password != *confirm {
        bail!("Passwords do not match");
    }

    Ok(password)
}

/// Resolves a new keystore's password from a file or interactive prompt, and
/// checks its minimum length.
///
/// If `password_file` is `Some`, reads the password from the file.
/// Otherwise, prompts the user interactively with double-prompt confirmation.
pub fn resolve_password(password_file: Option<&Path>) -> Result<Zeroizing<String>> {
    match password_file {
        Some(path) => read_password_file(path),
        None => prompt_password(),
    }
}

/// Resolves an existing keystore's password from a file or one interactive
/// prompt. No minimum length applies: EIP-2335 sets none for decryption.
pub fn resolve_existing_password(password_file: Option<&Path>) -> Result<Zeroizing<String>> {
    match password_file {
        Some(path) => read_password_text(path),
        None => Ok(Zeroizing::new(
            rpassword::prompt_password_stderr("Enter keystore password: ")
                .context("Failed to read password")?,
        )),
    }
}

/// Reads a password from a file, trims trailing newlines, and checks its
/// minimum length.
pub fn read_password_file(path: &Path) -> Result<Zeroizing<String>> {
    let password = read_password_text(path)?;
    validate_password(&password)?;
    Ok(password)
}

fn read_password_text(path: &Path) -> Result<Zeroizing<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read password file: {}", path.display()))?;

    let password = content.trim_end_matches('\n').trim_end_matches('\r');
    Ok(Zeroizing::new(password.to_string()))
}

/// Validates the minimum length of the password the keystore is encrypted
/// with: its [`crypto::process_password`] form, in UTF-8 bytes.
pub fn validate_password(password: &str) -> Result<()> {
    let processed_len = crypto::process_password(password).len();
    if processed_len < MIN_PASSWORD_LENGTH {
        bail!(
            "Password too short after EIP-2335 processing: minimum {} characters, got {}",
            MIN_PASSWORD_LENGTH,
            processed_len
        );
    }
    Ok(())
}

/// Validates an Ethereum execution address (0x + 40 hex chars) with EIP-55 checksum.
pub fn validate_address(addr: &str) -> Result<[u8; 20]> {
    if !addr.starts_with("0x") {
        bail!("Address must start with '0x', got '{}'", addr);
    }
    if addr.len() != 42 {
        bail!("Address must be 42 characters (0x + 40 hex), got {} characters", addr.len());
    }
    let hex_part = &addr[2..];
    let bytes = hex::decode(hex_part)
        .with_context(|| format!("Address contains invalid hex characters: '{}'", addr))?;

    let mut result = [0u8; 20];
    result.copy_from_slice(&bytes);

    // EIP-55 checksum validation: if address has mixed case, verify checksum
    let has_upper = hex_part.chars().any(|c| c.is_ascii_uppercase());
    let has_lower = hex_part.chars().any(|c| c.is_ascii_lowercase());
    if has_upper && has_lower {
        let expected = eip55_checksum(&result);
        if addr != expected {
            bail!("Address has invalid EIP-55 checksum: expected '{}', got '{}'", expected, addr);
        }
    }

    Ok(result)
}

/// Compute the EIP-55 mixed-case checksum encoding for an address.
fn eip55_checksum(addr_bytes: &[u8; 20]) -> String {
    use tiny_keccak::{Hasher, Keccak};

    let hex_addr = hex::encode(addr_bytes);
    let mut keccak = Keccak::v256();
    keccak.update(hex_addr.as_bytes());
    let mut hash = [0u8; 32];
    keccak.finalize(&mut hash);

    let mut checksummed = String::with_capacity(42);
    checksummed.push_str("0x");
    for (i, c) in hex_addr.chars().enumerate() {
        let hash_nibble = if i % 2 == 0 { hash[i / 2] >> 4 } else { hash[i / 2] & 0x0f };
        if hash_nibble >= 8 {
            checksummed.push(c.to_ascii_uppercase());
        } else {
            checksummed.push(c);
        }
    }
    checksummed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_validate_password_minimum_length() {
        assert!(validate_password("12345678").is_ok());
        assert!(validate_password("1234567890abcdef").is_ok());
    }

    #[test]
    fn test_validate_password_too_short() {
        assert!(validate_password("").is_err());
        assert!(validate_password("1234567").is_err());
        assert!(validate_password("abc").is_err());
    }

    #[test]
    fn test_validate_password_error_message() {
        let err = validate_password("short").unwrap_err();
        assert!(err.to_string().contains("minimum 8 characters"));
        assert!(err.to_string().contains("got 5"));
    }

    #[test]
    fn a_password_shorter_than_the_minimum_after_processing_is_rejected() {
        let password = "short\r\n\t\t";
        assert_eq!(password.len(), 9);
        let err = validate_password(password).expect_err("5 bytes after processing");
        assert_eq!(
            err.to_string(),
            "Password too short after EIP-2335 processing: minimum 8 characters, got 5"
        );
        let fullwidth = "\u{FF50}\u{FF41}\u{FF53}\u{FF53}";
        assert_eq!(fullwidth.len(), 12);
        let err = validate_password(fullwidth).expect_err("NFKD maps it to 4 bytes");
        assert!(err.to_string().ends_with("got 4"), "{err}");
    }

    #[test]
    fn the_minimum_counts_utf8_bytes_not_characters() {
        assert!(validate_password("\u{1F511}\u{1F511}").is_ok());
    }

    #[test]
    fn test_validate_address_valid_lowercase() {
        let addr = "0x71c7656ec7ab88b098defb751b7401b5f6d8976f";
        let result = validate_address(addr).unwrap();
        assert_eq!(result.len(), 20);
    }

    #[test]
    fn test_validate_address_valid_eip55() {
        // Known EIP-55 checksummed address
        let addr = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        assert!(validate_address(addr).is_ok());
    }

    #[test]
    fn test_validate_address_invalid_eip55_checksum() {
        // Incorrect mixed-case (not a valid EIP-55 checksum)
        let addr = "0x5AAEB6053f3e94c9b9a09f33669435e7ef1beaed";
        let result = validate_address(addr);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("EIP-55 checksum"));
    }

    #[test]
    fn test_validate_address_all_uppercase_skips_checksum() {
        // All-uppercase hex is treated as non-checksummed (no mixed case)
        let addr = "0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED";
        assert!(validate_address(addr).is_ok());
    }

    #[test]
    fn test_validate_address_missing_prefix() {
        let result = validate_address("71c7656ec7ab88b098defb751b7401b5f6d8976f");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must start with '0x'"));
    }

    #[test]
    fn test_validate_address_too_short() {
        let result = validate_address("0x71c7656ec7ab88b098");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("42 characters"));
    }

    #[test]
    fn test_validate_address_too_long() {
        let result = validate_address("0x71c7656ec7ab88b098defb751b7401b5f6d8976faa");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_address_invalid_hex() {
        let result = validate_address("0xzzc7656ec7ab88b098defb751b7401b5f6d8976f");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid hex characters"));
    }

    #[test]
    fn test_validate_address_returns_bytes() {
        let addr = "0x0000000000000000000000000000000000000001";
        let bytes = validate_address(addr).unwrap();
        assert_eq!(bytes[19], 1);
        assert_eq!(bytes[0..19], [0u8; 19]);
    }

    #[test]
    fn test_eip55_checksum_known_vectors() {
        // EIP-55 test vectors from the spec
        let cases = vec![
            (
                [
                    0x5a, 0xae, 0xb6, 0x05, 0x3f, 0x3e, 0x94, 0xc9, 0xb9, 0xa0, 0x9f, 0x33, 0x66,
                    0x94, 0x35, 0xe7, 0xef, 0x1b, 0xea, 0xed,
                ],
                "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
            ),
            (
                [
                    0xfb, 0x69, 0x16, 0x09, 0x5c, 0xa1, 0xdf, 0x60, 0xbb, 0x79, 0xce, 0x92, 0xce,
                    0x3e, 0xa7, 0x4c, 0x37, 0xc5, 0xd3, 0x59,
                ],
                "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
            ),
        ];
        for (bytes, expected) in cases {
            assert_eq!(eip55_checksum(&bytes), expected);
        }
    }

    #[test]
    fn test_read_password_file_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "mypassword123").unwrap();

        let password = read_password_file(&path).unwrap();
        assert_eq!(*password, "mypassword123");
    }

    #[test]
    fn test_read_password_file_no_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "mypassword123").unwrap();

        let password = read_password_file(&path).unwrap();
        assert_eq!(*password, "mypassword123");
    }

    #[test]
    fn test_read_password_file_windows_newline() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "mypassword123\r\n").unwrap();

        let password = read_password_file(&path).unwrap();
        assert_eq!(*password, "mypassword123");
    }

    #[test]
    fn test_read_password_file_too_short() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "short\n").unwrap();

        let result = read_password_file(&path);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_password_file_not_found() {
        let result = read_password_file(Path::new("/nonexistent/password.txt"));
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_password_with_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "mypassword123\n").unwrap();

        let password = resolve_password(Some(&path)).unwrap();
        assert_eq!(*password, "mypassword123");
    }

    #[test]
    fn test_resolve_password_with_file_too_short() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password.txt");
        std::fs::write(&path, "short\n").unwrap();

        let result = resolve_password(Some(&path));
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_password_with_nonexistent_file() {
        let result = resolve_password(Some(Path::new("/nonexistent/password.txt")));
        assert!(result.is_err());
    }
}
