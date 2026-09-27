use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tracing::info;
use zeroize::Zeroizing;

use crypto::{compute_domain, compute_signing_root, eip2333, mnemonic};
use eth_types::{BLSToExecutionChange, SignedBLSToExecutionChange, DOMAIN_BLS_TO_EXECUTION_CHANGE};

use crate::network;
use crate::password;

pub struct BlsToExecutionArgs {
    pub network: String,
    pub output_dir: PathBuf,
    pub validator_index: u64,
    pub execution_address: String,
    pub bls_withdrawal_index: u32,
    pub mnemonic_passphrase: String,
}

pub fn run(args: BlsToExecutionArgs) -> Result<()> {
    let mnemonic_phrase = Zeroizing::new(
        rpassword::prompt_password_stderr("Enter your mnemonic: ")
            .context("Failed to read mnemonic")?,
    );
    run_with_mnemonic(args, mnemonic_phrase.trim())
}

/// Sign and write a BLS-to-execution change using an already-resolved mnemonic.
///
/// Interactive CLI entry is [`run`]; this is the shared command body used by
/// tests (and any caller that already holds the phrase).
pub fn run_with_mnemonic(args: BlsToExecutionArgs, mnemonic_phrase: &str) -> Result<()> {
    let network = network::from_name(&args.network)?;

    let execution_address = password::validate_address(&args.execution_address)?;

    let mnemonic =
        mnemonic::validate_mnemonic(mnemonic_phrase).context("Invalid mnemonic phrase")?;

    let seed = mnemonic::mnemonic_to_seed(&mnemonic, &args.mnemonic_passphrase);

    // Withdrawal key path: m/12381/3600/{bls_withdrawal_index}/0
    let withdrawal_path = format!("m/12381/3600/{}/0", args.bls_withdrawal_index);
    let withdrawal_key = eip2333::derive_key_from_path(seed.as_ref(), &withdrawal_path)
        .context("Failed to derive withdrawal key")?;

    let withdrawal_pubkey = withdrawal_key.public_key();

    let change = BLSToExecutionChange {
        validator_index: args.validator_index,
        from_bls_pubkey: withdrawal_pubkey.to_bytes(),
        to_execution_address: execution_address,
    };

    // Domain: DOMAIN_BLS_TO_EXECUTION_CHANGE with genesis fork version (EIP-7044) and genesis_validators_root
    let domain = compute_domain(
        DOMAIN_BLS_TO_EXECUTION_CHANGE,
        network.genesis_fork_version,
        network.genesis_validators_root,
    );

    let signing_root = compute_signing_root(&change, domain);
    let signature = withdrawal_key.sign(&signing_root);

    let signed =
        SignedBLSToExecutionChange { message: change, signature: signature.to_bytes().to_vec() };

    let json = serde_json::to_string_pretty(&signed)
        .context("Failed to serialize signed BLS-to-execution change")?;

    fs::create_dir_all(&args.output_dir).with_context(|| {
        format!("Failed to create output directory: {}", args.output_dir.display())
    })?;

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let filename = format!("bls_to_execution-{}-{}.json", timestamp, args.validator_index);
    let output_path = args.output_dir.join(filename);

    crate::fs_util::write_new_0600(&output_path, json.as_bytes())
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;

    eprintln!("BLS-to-execution change written to: {}", output_path.display());

    info!(
        validator_index = args.validator_index,
        network = network.name,
        "generated signed BLS-to-execution change"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Gate 1: tests round-trip raw key bytes for assertions; not a logging surface
    use super::*;
    use crypto::{compute_domain, compute_signing_root, eip2333, mnemonic};
    use eth_types::DOMAIN_BLS_TO_EXECUTION_CHANGE;

    const TEST_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn test_withdrawal_key(index: u32) -> (crypto::SecretKey, crypto::PublicKey) {
        let mnemonic = mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed = mnemonic::mnemonic_to_seed(&mnemonic, "");
        let path = format!("m/12381/3600/{}/0", index);
        let sk = eip2333::derive_key_from_path(seed.as_ref(), &path).unwrap();
        let pk = sk.public_key();
        (sk, pk)
    }

    #[test]
    fn test_bls_to_execution_sign_and_verify() {
        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);

        let change = BLSToExecutionChange {
            validator_index: 42,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: [0x71; 20],
        };

        let network = network::from_name("mainnet").unwrap();
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.genesis_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&change, domain);
        let signature = withdrawal_key.sign(&signing_root);

        assert!(signature.verify(&withdrawal_pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_bls_to_execution_uses_genesis_fork_version() {
        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);

        let change = BLSToExecutionChange {
            validator_index: 42,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: [0x71; 20],
        };

        let network = network::from_name("mainnet").unwrap();

        // Sign with genesis fork version (correct per EIP-7044 / Capella process_bls_to_execution_change)
        let genesis_domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.genesis_fork_version,
            network.genesis_validators_root,
        );
        let genesis_root = compute_signing_root(&change, genesis_domain);
        let signature = withdrawal_key.sign(&genesis_root);

        // Verify with genesis succeeds
        assert!(signature.verify(&withdrawal_pubkey, &genesis_root).is_ok());

        // Verify with Capella fork version fails (proves we use genesis, not Capella)
        let capella_domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let capella_root = compute_signing_root(&change, capella_domain);
        assert!(signature.verify(&withdrawal_pubkey, &capella_root).is_err());
    }

    /// EIP-7044 `BLSToExecutionChange` signing root.
    ///
    /// Document: ethereum/consensus-specs v1.5.0, commit
    /// `b5c3b619887c7850a8c1d3540b471092be73ad84`.
    /// `specs/capella/beacon-chain.md` `process_bls_to_execution_change` signs with
    /// `compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, genesis_validators_root=...)`,
    /// and `specs/phase0/beacon-chain.md` `compute_domain` defaults the fork version to
    /// `GENESIS_FORK_VERSION`. Mainnet inputs are `configs/mainnet.yaml` at that tag:
    /// fork version `0x00000000`, genesis validators root
    /// `0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95`.
    /// Message: validator index 42, `from_bls_pubkey` 48×`0xdd`, `to_execution_address` 20×`0xee`.
    /// The root was produced by remerkleable 0.1.28 (protolambda/remerkleable commit
    /// `1099d0ab038ea25ece506bbed1e8357aba1295be`), not by this crate's `compute_domain`.
    const KAT_BLS_TO_EXECUTION_CHANGE_SIGNING_ROOT: [u8; 32] = [
        0xff, 0x5e, 0x9f, 0x65, 0xe5, 0xd5, 0xd7, 0x57, 0x11, 0xee, 0x5c, 0x0d, 0x32, 0xfc, 0x78,
        0xcc, 0x7e, 0x84, 0x1c, 0x98, 0x56, 0x44, 0x29, 0xd7, 0xc1, 0xda, 0xeb, 0xc7, 0xd2, 0x6b,
        0xb7, 0x4a,
    ];

    #[test]
    fn external_bls_to_execution_change_signing_root() {
        let change = BLSToExecutionChange {
            validator_index: 42,
            from_bls_pubkey: [0xdd; 48],
            to_execution_address: [0xee; 20],
        };
        let network = network::from_name("mainnet").unwrap();
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.genesis_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&change, domain);
        assert_eq!(signing_root, KAT_BLS_TO_EXECUTION_CHANGE_SIGNING_ROOT);
    }

    #[test]
    fn test_bls_to_execution_withdrawal_path_not_signing_path() {
        let mnemonic = mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();
        let seed = mnemonic::mnemonic_to_seed(&mnemonic, "");

        // Withdrawal path: m/12381/3600/0/0 (4 levels)
        let withdrawal_key =
            eip2333::derive_key_from_path(seed.as_ref(), "m/12381/3600/0/0").unwrap();

        // Signing path: m/12381/3600/0/0/0 (5 levels)
        let signing_key =
            eip2333::derive_key_from_path(seed.as_ref(), "m/12381/3600/0/0/0").unwrap();

        // They must be different keys
        assert_ne!(withdrawal_key.to_bytes(), signing_key.to_bytes());
        assert_ne!(withdrawal_key.public_key().to_bytes(), signing_key.public_key().to_bytes());
    }

    #[test]
    fn test_bls_to_execution_output_json_structure() {
        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);
        let exec_addr = [0xAB; 20];

        let change = BLSToExecutionChange {
            validator_index: 42,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: exec_addr,
        };

        let network = network::from_name("mainnet").unwrap();
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.genesis_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&change, domain);
        let signature = withdrawal_key.sign(&signing_root);

        let signed = SignedBLSToExecutionChange {
            message: change,
            signature: signature.to_bytes().to_vec(),
        };

        let json = serde_json::to_string_pretty(&signed).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("message").is_some());
        assert!(parsed.get("signature").is_some());
        assert_eq!(parsed["message"]["validator_index"], "42");

        // from_bls_pubkey should be 0x-prefixed 48-byte hex (98 chars)
        let pubkey_str = parsed["message"]["from_bls_pubkey"].as_str().unwrap();
        assert!(pubkey_str.starts_with("0x"));
        assert_eq!(pubkey_str.len(), 98);

        // to_execution_address should be 0x-prefixed 20-byte hex (42 chars)
        let addr_str = parsed["message"]["to_execution_address"].as_str().unwrap();
        assert!(addr_str.starts_with("0x"));
        assert_eq!(addr_str.len(), 42);

        // signature should be 0x-prefixed 96-byte hex (194 chars)
        let sig_str = parsed["signature"].as_str().unwrap();
        assert!(sig_str.starts_with("0x"));
        assert_eq!(sig_str.len(), 194);
    }

    #[cfg(unix)]
    #[test]
    fn test_bls_to_execution_output_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);

        let change = BLSToExecutionChange {
            validator_index: 1,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: [0x01; 20],
        };

        let network = network::from_name("mainnet").unwrap();
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.genesis_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&change, domain);
        let signature = withdrawal_key.sign(&signing_root);

        let signed = SignedBLSToExecutionChange {
            message: change,
            signature: signature.to_bytes().to_vec(),
        };

        let json = serde_json::to_string_pretty(&signed).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let output_path = dir.path().join("test_bls.json");
        crate::fs_util::write_new_0600(&output_path, json.as_bytes()).unwrap();

        let metadata = fs::metadata(&output_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let content = fs::read_to_string(&output_path).unwrap();
        let parsed: SignedBLSToExecutionChange = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.message.validator_index, 1);
    }

    /// Command body must refuse to overwrite an existing output path (create_new via helper).
    /// Exercises `run_with_mnemonic` (same write path as interactive `run` after the prompt).
    #[test]
    fn test_bls_to_execution_refuses_to_overwrite_existing_output() {
        use std::io::ErrorKind;
        use std::time::{SystemTime, UNIX_EPOCH};

        let dir = tempfile::tempdir().unwrap();
        let output_dir = dir.path().join("out");
        fs::create_dir_all(&output_dir).unwrap();

        let validator_index = 1u64;
        let prior = b"prior bls change";
        // Lowercase address skips EIP-55 mixed-case checksum validation.
        let execution_address = format!("0x{}", "ab".repeat(20));

        for _ in 0..50 {
            for entry in fs::read_dir(&output_dir).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name().to_string_lossy().starts_with("bls_to_execution-") {
                    let _ = fs::remove_file(entry.path());
                }
            }

            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let output_path =
                output_dir.join(format!("bls_to_execution-{}-{}.json", ts, validator_index));
            fs::write(&output_path, prior).unwrap();

            let result = run_with_mnemonic(
                BlsToExecutionArgs {
                    network: "mainnet".into(),
                    output_dir: output_dir.clone(),
                    validator_index,
                    execution_address: execution_address.clone(),
                    bls_withdrawal_index: 0,
                    mnemonic_passphrase: String::new(),
                },
                TEST_MNEMONIC,
            );

            match result {
                Err(e) => {
                    let msg = format!("{e:#}");
                    let name = output_path.file_name().unwrap().to_string_lossy();
                    assert!(
                        msg.contains(name.as_ref())
                            || msg.contains(&output_path.display().to_string()),
                        "error must include path: {msg}"
                    );
                    assert_eq!(fs::read(&output_path).unwrap(), prior);
                    let io_err = e
                        .root_cause()
                        .downcast_ref::<std::io::Error>()
                        .expect("root cause should be io::Error");
                    assert_eq!(io_err.kind(), ErrorKind::AlreadyExists);
                    return;
                }
                Ok(()) => continue,
            }
        }
        panic!("failed to force output path collision through bls_to_execution command path");
    }

    #[test]
    fn test_bls_to_execution_hoodi_network() {
        let (withdrawal_key, withdrawal_pubkey) = test_withdrawal_key(0);

        let change = BLSToExecutionChange {
            validator_index: 99,
            from_bls_pubkey: withdrawal_pubkey.to_bytes(),
            to_execution_address: [0xCC; 20],
        };

        let network = network::from_name("hoodi").unwrap();
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            network.genesis_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&change, domain);
        let signature = withdrawal_key.sign(&signing_root);

        assert!(signature.verify(&withdrawal_pubkey, &signing_root).is_ok());
    }

    #[test]
    fn test_bls_to_execution_different_withdrawal_indices() {
        let (_, pk0) = test_withdrawal_key(0);
        let (_, pk1) = test_withdrawal_key(1);

        // Different withdrawal indices produce different keys
        assert_ne!(pk0.to_bytes(), pk1.to_bytes());
    }

    #[test]
    fn test_bls_to_execution_passphrase_changes_key() {
        let mnemonic = mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();

        // Without passphrase (default)
        let seed_no_pass = mnemonic::mnemonic_to_seed(&mnemonic, "");
        let key_no_pass =
            eip2333::derive_key_from_path(seed_no_pass.as_ref(), "m/12381/3600/0/0").unwrap();

        // With passphrase
        let seed_with_pass = mnemonic::mnemonic_to_seed(&mnemonic, "my secret passphrase");
        let key_with_pass =
            eip2333::derive_key_from_path(seed_with_pass.as_ref(), "m/12381/3600/0/0").unwrap();

        // Keys must differ when passphrase is different
        assert_ne!(key_no_pass.to_bytes(), key_with_pass.to_bytes());
    }

    #[test]
    fn test_bls_to_execution_empty_passphrase_backward_compatible() {
        let mnemonic = mnemonic::validate_mnemonic(TEST_MNEMONIC).unwrap();

        let seed1 = mnemonic::mnemonic_to_seed(&mnemonic, "");
        let seed2 = mnemonic::mnemonic_to_seed(&mnemonic, "");

        // Empty passphrase produces same seed (backward compatible)
        assert_eq!(seed1.as_ref(), seed2.as_ref());
    }

    #[test]
    fn test_bls_to_execution_invalid_address() {
        // Missing 0x prefix
        assert!(password::validate_address("71C7656EC7ab88b098defB751B7401B5f6d8976F").is_err());
        // Too short
        assert!(password::validate_address("0x71C7").is_err());
        // Invalid hex
        assert!(password::validate_address("0xZZC7656EC7ab88b098defB751B7401B5f6d8976F").is_err());
    }
}
