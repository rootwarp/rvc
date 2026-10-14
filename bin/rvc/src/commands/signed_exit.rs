//! Shared voluntary-exit signing path used by `voluntary-exit` and `prepare-exit`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use beacon::{BeaconClient, BeaconClientConfig};
use crypto::KeyManager;
use eth_types::{SignedVoluntaryExit, VoluntaryExit, SLOTS_PER_EPOCH};
use rvc::config::{Config, ServiceBuilder};
use signer::{SignerService, ValidatorSigner};
use tracing::info;

/// Common inputs for building a signed voluntary exit (shared by both CLI commands).
pub struct ExitCommonArgs {
    pub pubkey: String,
    pub epoch: Option<u64>,
    pub beacon_url: String,
    pub keystore_path: PathBuf,
    pub password_file: PathBuf,
    pub slashing_db_path: Option<PathBuf>,
    pub network: Option<String>,
    pub genesis_validators_root: Option<String>,
    /// When `Some`, enforces the irreversible-submit confirm gate after index/epoch
    /// resolution and **before** keystore load / signing (`Some(false)` aborts).
    /// `prepare-exit` passes `None` (file write is not a BN submit).
    pub confirm: Option<bool>,
}

/// Result of [`build_signed_exit`]: signed message plus metadata needed by callers.
pub struct BuiltSignedExit {
    pub signed_exit: SignedVoluntaryExit,
    pub validator_index: u64,
    pub epoch: u64,
    /// Canonical `0x`-prefixed lowercase hex pubkey used for BN lookup / filenames.
    pub pubkey_with_prefix: String,
    /// Beacon client used for index/epoch/fork resolution (reuse for submit).
    pub beacon_client: BeaconClient,
}

/// Normalize a validator pubkey to canonical `0x` + lowercase 96-char hex.
///
/// Accepts bare or single-prefixed (`0x`/`0X`) 48-byte keys via
/// [`eth_types::canonical::pubkey_hex::parse_pubkey_hex`].
pub fn normalize_pubkey_hex(raw: &str) -> anyhow::Result<String> {
    let pk = eth_types::canonical::pubkey_hex::parse_pubkey_hex(raw)
        .map_err(|e| anyhow::anyhow!("invalid validator pubkey: {e}"))?;
    Ok(format!("0x{}", hex::encode(pk.as_bytes())))
}

/// Take sole ownership of a [`KeyManager`] from an [`Arc`].
///
/// Returns an error instead of panicking when other references remain
/// (mirrors daemon bootstrap). Prefer [`ServiceBuilder::build_key_manager_owned_filtered`]
/// when the Arc is not required.
pub fn take_owned_key_manager(key_manager: Arc<KeyManager>) -> anyhow::Result<KeyManager> {
    Arc::try_unwrap(key_manager).map_err(|_| {
        anyhow::anyhow!("cannot take ownership of key_manager: outstanding Arc references exist")
    })
}

/// Gate the irreversible submit path behind `--confirm`.
pub fn require_exit_confirm(
    confirm: bool,
    validator_index: u64,
    pubkey_with_prefix: &str,
    epoch: u64,
) -> anyhow::Result<()> {
    if confirm {
        return Ok(());
    }
    eprintln!();
    eprintln!("WARNING: THIS ACTION IS IRREVERSIBLE.");
    eprintln!();
    eprintln!("You are about to submit a voluntary exit for:");
    eprintln!("  Validator index: {}", validator_index);
    eprintln!("  Public key:      {}", pubkey_with_prefix);
    eprintln!("  Exit epoch:      {}", epoch);
    eprintln!();
    eprintln!(
        "The validator will no longer be able to perform duties after the exit is processed."
    );
    eprintln!("Use --confirm to skip this prompt.");
    eprintln!();
    bail!("Voluntary exit aborted: --confirm flag not provided");
}

/// Resolve validator index, epoch, load keys / slashing DB, and sign a voluntary exit.
///
/// Callers differ only in the final step: submit to the BN or write to a file.
pub async fn build_signed_exit(args: ExitCommonArgs) -> anyhow::Result<BuiltSignedExit> {
    let beacon_config = BeaconClientConfig::new(&args.beacon_url);
    let beacon_client =
        BeaconClient::new(beacon_config).context("Failed to create beacon client")?;

    let pubkey_with_prefix = normalize_pubkey_hex(&args.pubkey)?;

    let validators_response = beacon_client
        .get_validators(std::slice::from_ref(&pubkey_with_prefix))
        .await
        .context("Failed to look up validator index from beacon node")?;

    let validator = validators_response
        .data
        .first()
        .ok_or_else(|| anyhow::anyhow!("Validator not found for pubkey: {}", pubkey_with_prefix))?;

    let validator_index: u64 =
        validator.index.parse().context("Failed to parse validator index")?;

    info!(validator_index, pubkey = %pubkey_with_prefix, "Resolved validator index");

    let epoch = match args.epoch {
        Some(e) => e,
        None => {
            let genesis = beacon_client
                .get_genesis()
                .await
                .context("Failed to get genesis info from beacon node")?;

            let genesis_time: u64 =
                genesis.data.genesis_time.parse().context("Failed to parse genesis time")?;

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| anyhow::anyhow!("system time before UNIX epoch"))?
                .as_secs();

            let current_slot =
                now.saturating_sub(genesis_time).saturating_mul(1000) / eth_types::SLOT_DURATION_MS;
            current_slot / SLOTS_PER_EPOCH
        }
    };

    info!(epoch, validator_index, "Preparing voluntary exit");

    // Confirm before touching the keystore / slashing DB (matches prior CLI order).
    if let Some(confirm) = args.confirm {
        require_exit_confirm(confirm, validator_index, &pubkey_with_prefix, epoch)?;
    }

    let mut config = Config {
        beacon_url: args.beacon_url.clone(),
        keystore_path: args.keystore_path,
        password_file: Some(args.password_file),
        genesis_validators_root: args.genesis_validators_root,
        ..Default::default()
    };
    if let Some(db_path) = args.slashing_db_path {
        config.slashing_db_path = db_path;
    }
    if let Some(network) = args.network {
        config.network = network.parse().map_err(|e: String| anyhow::anyhow!("{}", e))?;
    }

    let keystore_path = config.keystore_path.clone();
    let builder = ServiceBuilder::new(config);

    // SEC-1b: skip Keymanager-deleted pubkeys (same filter as daemon boot).
    let denylist = rvc::deletion_denylist::DeletionDenylist::load(&keystore_path)
        .context("Failed to load deletion denylist")?;
    let denylist_snapshot = denylist.snapshot();

    let key_manager = builder
        .build_key_manager_filtered(Some(&denylist_snapshot))
        .context("Failed to load validator keys")?;
    // Error instead of panic when the Arc is unexpectedly shared.
    let key_manager = take_owned_key_manager(key_manager)?;

    let slashing_db = builder.build_slashing_db().context("Failed to open slashing database")?;

    let composite_signer =
        Arc::new(crypto::CompositeSigner::new(crypto::LocalSigner::new(key_manager)));
    let signer = SignerService::new(composite_signer, slashing_db);

    let pk = eth_types::canonical::pubkey_hex::parse_pubkey_hex(&pubkey_with_prefix)
        .map_err(|e| anyhow::anyhow!("invalid validator pubkey: {e}"))?;
    let pubkey = crypto::PublicKey::from_bytes(pk.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid public key: {:?}", e))?;

    let fork_schedule = builder
        .build_fork_schedule(&beacon_client)
        .await
        .context("Failed to fetch fork schedule")?;

    let genesis_validators_root = builder
        .parse_genesis_validators_root()
        .context("Failed to parse genesis validators root")?;

    let voluntary_exit = VoluntaryExit { epoch, validator_index };

    let signature = signer
        .sign_voluntary_exit(&voluntary_exit, &pubkey, &fork_schedule, &genesis_validators_root)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to sign voluntary exit: {}", e))?;

    let signed_exit =
        SignedVoluntaryExit { message: voluntary_exit, signature: signature.to_bytes().to_vec() };

    Ok(BuiltSignedExit { signed_exit, validator_index, epoch, pubkey_with_prefix, beacon_client })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_pubkey_hex() -> String {
        "ab".repeat(48)
    }

    #[test]
    fn test_normalize_pubkey_hex_accepts_prefixed_and_bare() {
        let bare = sample_pubkey_hex();
        let lower = format!("0x{bare}");
        let upper = format!("0X{bare}");

        assert_eq!(normalize_pubkey_hex(&bare).unwrap(), lower);
        assert_eq!(normalize_pubkey_hex(&lower).unwrap(), lower);
        assert_eq!(normalize_pubkey_hex(&upper).unwrap(), lower);
    }

    #[test]
    fn test_normalize_pubkey_hex_rejects_short_and_invalid() {
        assert!(normalize_pubkey_hex("0xabcdef").is_err());
        assert!(normalize_pubkey_hex("zz").is_err());
        assert!(normalize_pubkey_hex("").is_err());
    }

    #[test]
    fn test_build_signed_exit_returns_error_instead_of_panicking_on_shared_key_manager() {
        let km = Arc::new(KeyManager::new());
        let shared = Arc::clone(&km);

        // KeyManager is not Debug; match instead of unwrap_err.
        let err = match take_owned_key_manager(km) {
            Ok(_) => panic!("expected ownership error when Arc is shared"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("outstanding Arc references"),
            "expected ownership error, got: {err}"
        );

        // Sole remaining owner unwraps without panic.
        assert_eq!(Arc::strong_count(&shared), 1);
        let owned = take_owned_key_manager(shared).expect("sole owner must unwrap");
        assert!(owned.is_empty());
    }

    #[test]
    fn test_voluntary_exit_requires_confirm_flag_before_submit() {
        let pk = format!("0x{}", sample_pubkey_hex());
        let err = require_exit_confirm(false, 42, &pk, 100).unwrap_err();
        assert!(
            err.to_string().contains("--confirm"),
            "expected confirm abort message, got: {err}"
        );
        assert!(require_exit_confirm(true, 42, &pk, 100).is_ok());
    }
}
