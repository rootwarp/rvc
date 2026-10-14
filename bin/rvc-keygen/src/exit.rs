use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use crypto::{sign_voluntary_exit, Keystore};
use eth_types::{SignedVoluntaryExit, VoluntaryExit};
use tracing::info;

use crate::network;
use crate::password;

pub struct ExitArgs {
    pub network: String,
    pub output_dir: PathBuf,
    pub validator_index: u64,
    pub epoch: u64,
    pub keystore: PathBuf,
    pub password_file: Option<PathBuf>,
}

pub fn run(args: ExitArgs) -> Result<()> {
    let network = network::from_name(&args.network)?;

    let keystore = Keystore::from_file(&args.keystore).context("Failed to load keystore file")?;

    let password = password::resolve_password(args.password_file.as_deref())?;

    let secret_key = keystore.decrypt(password.as_bytes()).context("Failed to decrypt keystore")?;

    let exit = VoluntaryExit { epoch: args.epoch, validator_index: args.validator_index };

    let schedule = network::exit_fork_schedule(network);

    let signature =
        sign_voluntary_exit(&exit, &secret_key, &schedule, network.genesis_validators_root);

    let signed = SignedVoluntaryExit { message: exit, signature: signature.to_bytes().to_vec() };

    let json = serde_json::to_string_pretty(&signed)
        .context("Failed to serialize signed voluntary exit")?;

    fs::create_dir_all(&args.output_dir).with_context(|| {
        format!("Failed to create output directory: {}", args.output_dir.display())
    })?;

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let filename = format!("signed_voluntary_exit-{}-{}.json", timestamp, args.validator_index);
    let output_path = args.output_dir.join(filename);

    crate::fs_util::write_new_0600(&output_path, json.as_bytes())
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;

    eprintln!("Signed voluntary exit written to: {}", output_path.display());

    info!(
        validator_index = args.validator_index,
        epoch = args.epoch,
        network = network.name,
        "generated signed voluntary exit"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{
        compute_domain, compute_signing_root, sign_voluntary_exit, EncryptionKdf, Keystore,
        SecretKey,
    };
    use eth_types::{ForkName, DOMAIN_VOLUNTARY_EXIT};

    /// RED: Round-trip test — encrypt keystore, then use the exit signing flow
    /// to verify the full pipeline produces a valid signature.
    #[test]
    fn test_exit_round_trip_encrypt_decrypt_sign() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();
        let password = b"test-password-123";

        // Encrypt the key into a keystore
        let keystore = Keystore::encrypt(
            &secret_key,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .unwrap();

        // Decrypt it back
        let recovered_key = keystore.decrypt(password).unwrap();

        // Build the exit
        let exit = VoluntaryExit { epoch: 300_000, validator_index: 42 };

        let network = network::from_name("mainnet").unwrap();
        let schedule = network::exit_fork_schedule(network);

        let signature =
            sign_voluntary_exit(&exit, &recovered_key, &schedule, network.genesis_validators_root);

        // Verify the signature against the original public key
        let fork_name = ForkName::from_epoch(exit.epoch, &schedule);
        let capped = if fork_name >= ForkName::Capella { ForkName::Capella } else { fork_name };
        let fork_version = capped.fork_version(&schedule);
        let domain =
            compute_domain(DOMAIN_VOLUNTARY_EXIT, fork_version, network.genesis_validators_root);
        let signing_root = compute_signing_root(&exit, domain);

        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }

    /// RED: EIP-7044 — exit at a far-future epoch signs with Capella, not Deneb.
    #[test]
    fn test_exit_eip7044_caps_at_capella() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();

        let exit = VoluntaryExit {
            epoch: 1_000_000, // far beyond any fork
            validator_index: 42,
        };

        let network = network::from_name("mainnet").unwrap();
        let schedule = network::exit_fork_schedule(network);

        let signature =
            sign_voluntary_exit(&exit, &secret_key, &schedule, network.genesis_validators_root);

        // Must verify with Capella fork version
        let capella_domain = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let capella_root = compute_signing_root(&exit, capella_domain);
        assert!(signature.verify(&public_key, &capella_root).is_ok());

        // Must NOT verify with genesis fork version (proves cap works)
        let genesis_domain = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            network.genesis_fork_version,
            network.genesis_validators_root,
        );
        let genesis_root = compute_signing_root(&exit, genesis_domain);
        assert!(signature.verify(&public_key, &genesis_root).is_err());
    }

    /// At `u64::MAX`, `from_epoch` resolves Gloas; EIP-7044 still signs Capella.
    #[test]
    fn test_exit_eip7044_caps_at_capella_when_from_epoch_is_gloas() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();

        let exit = VoluntaryExit { epoch: u64::MAX, validator_index: 42 };

        let network = network::from_name("mainnet").unwrap();
        let schedule = network::exit_fork_schedule(network);
        assert_eq!(ForkName::from_epoch(exit.epoch, &schedule), ForkName::Gloas);

        let signature =
            sign_voluntary_exit(&exit, &secret_key, &schedule, network.genesis_validators_root);

        let capella_domain = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let capella_root = compute_signing_root(&exit, capella_domain);
        assert!(signature.verify(&public_key, &capella_root).is_ok());
    }

    /// RED: Output JSON has correct structure.
    #[test]
    fn test_exit_output_json_structure() {
        let secret_key = SecretKey::generate();
        let password = b"test-password-123";

        let keystore = Keystore::encrypt(
            &secret_key,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .unwrap();
        let recovered_key = keystore.decrypt(password).unwrap();

        let exit = VoluntaryExit { epoch: 100, validator_index: 7 };

        let network = network::from_name("mainnet").unwrap();
        let schedule = network::exit_fork_schedule(network);
        let signature =
            sign_voluntary_exit(&exit, &recovered_key, &schedule, network.genesis_validators_root);

        let signed =
            SignedVoluntaryExit { message: exit, signature: signature.to_bytes().to_vec() };

        let json = serde_json::to_string_pretty(&signed).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // Verify structure
        assert!(parsed.get("message").is_some());
        assert!(parsed.get("signature").is_some());
        assert_eq!(parsed["message"]["epoch"], "100");
        assert_eq!(parsed["message"]["validator_index"], "7");

        // Signature should be 0x-prefixed 96-byte hex (194 chars)
        let sig_str = parsed["signature"].as_str().unwrap();
        assert!(sig_str.starts_with("0x"));
        assert_eq!(sig_str.len(), 194); // 0x + 192 hex chars = 96 bytes
    }

    /// RED: Output file written with correct permissions on Unix.
    #[cfg(unix)]
    #[test]
    fn test_exit_output_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let secret_key = SecretKey::generate();
        let password = b"test-password-123";

        let keystore = Keystore::encrypt(
            &secret_key,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .unwrap();

        // Write keystore to temp file
        let dir = tempfile::tempdir().unwrap();
        let keystore_path = dir.path().join("keystore.json");
        keystore.to_file(&keystore_path).unwrap();

        // Load and decrypt
        let loaded = Keystore::from_file(&keystore_path).unwrap();
        let recovered_key = loaded.decrypt(password).unwrap();

        let exit = VoluntaryExit { epoch: 100, validator_index: 7 };

        let network = network::from_name("mainnet").unwrap();
        let schedule = network::exit_fork_schedule(network);
        let signature =
            sign_voluntary_exit(&exit, &recovered_key, &schedule, network.genesis_validators_root);

        let signed =
            SignedVoluntaryExit { message: exit, signature: signature.to_bytes().to_vec() };

        let json = serde_json::to_string_pretty(&signed).unwrap();

        let output_dir = dir.path().join("exits");
        fs::create_dir_all(&output_dir).unwrap();

        let output_path = output_dir.join("test_exit.json");
        crate::fs_util::write_new_0600(&output_path, json.as_bytes()).unwrap();

        let metadata = fs::metadata(&output_path).unwrap();
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        // Verify the file content round-trips
        let content = fs::read_to_string(&output_path).unwrap();
        let parsed: SignedVoluntaryExit = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed.message.epoch, 100);
        assert_eq!(parsed.message.validator_index, 7);
    }

    /// `run()` must refuse to overwrite an existing output path (create_new via helper).
    /// Pre-creates the timestamped filename `run` is about to use; retries across second boundaries.
    #[test]
    fn test_exit_command_refuses_to_overwrite_existing_output() {
        use std::io::ErrorKind;
        use std::time::{SystemTime, UNIX_EPOCH};

        let dir = tempfile::tempdir().unwrap();
        let secret_key = SecretKey::generate();
        let password = b"test-password-123";
        let keystore = Keystore::encrypt(
            &secret_key,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .unwrap();

        let keystore_path = dir.path().join("keystore.json");
        keystore.to_file(&keystore_path).unwrap();
        let password_path = dir.path().join("password.txt");
        fs::write(&password_path, password).unwrap();

        let output_dir = dir.path().join("exits");
        fs::create_dir_all(&output_dir).unwrap();

        let validator_index = 7u64;
        let prior = b"prior signed exit";

        for _ in 0..50 {
            for entry in fs::read_dir(&output_dir).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name().to_string_lossy().starts_with("signed_voluntary_exit-") {
                    let _ = fs::remove_file(entry.path());
                }
            }

            let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            let output_path =
                output_dir.join(format!("signed_voluntary_exit-{}-{}.json", ts, validator_index));
            fs::write(&output_path, prior).unwrap();

            let result = run(ExitArgs {
                network: "mainnet".into(),
                output_dir: output_dir.clone(),
                validator_index,
                epoch: 100,
                keystore: keystore_path.clone(),
                password_file: Some(password_path.clone()),
            });

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
                Ok(()) => {
                    // Second advanced between pre-create and open; retry.
                    continue;
                }
            }
        }
        panic!("failed to force output path collision through exit::run()");
    }

    /// RED: Invalid keystore path returns clear error.
    #[test]
    fn test_exit_invalid_keystore_path() {
        let result = Keystore::from_file("/nonexistent/keystore.json");
        assert!(result.is_err());
    }

    /// RED: Wrong password returns decryption error.
    #[test]
    fn test_exit_wrong_password() {
        let secret_key = SecretKey::generate();
        let password = b"correct-password";

        let keystore = Keystore::encrypt(
            &secret_key,
            password,
            "m/12381/3600/0/0/0",
            EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .unwrap();

        let result = keystore.decrypt(b"wrong-password!!");
        assert!(result.is_err());
    }

    /// RED: Hoodi network also produces valid exit signatures.
    #[test]
    fn test_exit_hoodi_network() {
        let secret_key = SecretKey::generate();
        let public_key = secret_key.public_key();

        let exit = VoluntaryExit { epoch: 500, validator_index: 1 };

        let network = network::from_name("hoodi").unwrap();
        let schedule = network::exit_fork_schedule(network);

        let signature =
            sign_voluntary_exit(&exit, &secret_key, &schedule, network.genesis_validators_root);

        // Verify with Capella (since exit_fork_schedule caps at Capella)
        let domain = compute_domain(
            DOMAIN_VOLUNTARY_EXIT,
            network.capella_fork_version,
            network.genesis_validators_root,
        );
        let signing_root = compute_signing_root(&exit, domain);
        assert!(signature.verify(&public_key, &signing_root).is_ok());
    }
}
