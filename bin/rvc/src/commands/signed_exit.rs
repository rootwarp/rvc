//! Shared voluntary-exit signing path used by `voluntary-exit` and `prepare-exit`.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use beacon::{BeaconClient, BeaconClientConfig};
use crypto::KeyManager;
use eth_types::{SignedVoluntaryExit, VoluntaryExit, SLOTS_PER_EPOCH};
use rvc::config::{Config, ServiceBuilder};
use signer::{SignerService, ValidatorSigner};
use tracing::{info, warn};

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

/// Epoch from genesis and the beacon node's slot duration.
///
/// Reads `/eth/v1/config/spec`. A missing, zero, or conflicting duration is an
/// error. The 12 s constant is not a fallback.
async fn default_exit_epoch(
    beacon_client: &BeaconClient,
    genesis_time: u64,
    network: rvc::config::Network,
) -> anyhow::Result<u64> {
    // One beacon URL. The daemon cross-checks every configured BN at startup;
    // this path still fail-closes on the bound, a key conflict, SLOTS_PER_EPOCH,
    // a named-network duration preset, and a named-network genesis preset.
    let spec = beacon_client
        .get_config_spec()
        .await
        .context("Failed to read slot duration from beacon node spec")?;
    let slot_duration_ms = beacon::parse_slot_duration_ms(&spec.data)
        .map_err(|e| anyhow::anyhow!("failed to parse slot duration from beacon node spec: {e}"))?;
    let slots_per_epoch = beacon::parse_slots_per_epoch(&spec.data).map_err(|e| {
        anyhow::anyhow!("failed to parse SLOTS_PER_EPOCH from beacon node spec: {e}")
    })?;
    let expected_slots = network.slots_per_epoch();
    if slots_per_epoch != expected_slots {
        bail!("SLOTS_PER_EPOCH {slots_per_epoch} does not match preset {expected_slots}");
    }
    if !matches!(network, rvc::config::Network::Custom) {
        let preset = network.slot_duration_ms();
        if slot_duration_ms != preset {
            bail!(
                "slot duration {slot_duration_ms} ms does not match {network} preset {preset} ms"
            );
        }
        if let Some(preset_genesis) = network.genesis_time() {
            if genesis_time != preset_genesis {
                bail!(
                    "beacon genesis_time {genesis_time} does not match {network} preset {preset_genesis}"
                );
            }
        }
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| anyhow::anyhow!("system time before UNIX epoch"))?
        .as_secs();
    current_exit_epoch(now, genesis_time, slot_duration_ms)
}

/// Current epoch at `now_unix_secs`. Zero duration is an error, not epoch 0.
fn current_exit_epoch(
    now_unix_secs: u64,
    genesis_time: u64,
    slot_duration_ms: u64,
) -> anyhow::Result<u64> {
    if !(eth_types::MIN_SLOT_DURATION_MS..=eth_types::MAX_SLOT_DURATION_MS)
        .contains(&slot_duration_ms)
    {
        bail!(
            "slot duration {slot_duration_ms} ms is outside {}..={}",
            eth_types::MIN_SLOT_DURATION_MS,
            eth_types::MAX_SLOT_DURATION_MS
        );
    }
    let current_slot =
        now_unix_secs.saturating_sub(genesis_time).saturating_mul(1000) / slot_duration_ms;
    Ok(current_slot / SLOTS_PER_EPOCH)
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
        .iter()
        .find(|v| beacon::hex_ids_equal(&v.validator.pubkey, &pubkey_with_prefix))
        .ok_or_else(|| {
            anyhow::anyhow!("validator {pubkey_with_prefix} not found on beacon node")
        })?;

    let validator_index: u64 =
        validator.index.parse().context("Failed to parse validator index")?;

    info!(validator_index, pubkey = %pubkey_with_prefix, "Resolved validator index");

    let network = match args.network.as_deref() {
        Some(name) => name.parse().map_err(|e: String| anyhow::anyhow!("{e}"))?,
        None => rvc::config::Network::default(),
    };

    let epoch = match args.epoch {
        Some(e) => e,
        None => {
            let genesis = beacon_client
                .get_genesis()
                .await
                .context("Failed to get genesis info from beacon node")?;

            let genesis_time: u64 =
                genesis.data.genesis_time.parse().context("Failed to parse genesis time")?;

            default_exit_epoch(&beacon_client, genesis_time, network).await?
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
    config.network = network;

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

    let pk = eth_types::canonical::pubkey_hex::parse_pubkey_hex(&pubkey_with_prefix)
        .map_err(|e| anyhow::anyhow!("invalid validator pubkey: {e}"))?;
    let pubkey = crypto::PublicKey::from_bytes(pk.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid public key: {:?}", e))?;

    let composite_signer =
        Arc::new(crypto::CompositeSigner::new(crypto::LocalSigner::new(key_manager)));
    // Offline CLI: permit only this pubkey. Not the test-only always-enabled helper.
    let signer = SignerService::new(composite_signer, slashing_db)
        .with_enablement(Arc::new(signer::OfflineExitEnablement::new(&pubkey)));

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

    warn!(
        validator_index,
        epoch,
        "voluntary exit signed without a doppelganger window (offline CLI; not doppelganger-gated)"
    );

    let signed_exit =
        SignedVoluntaryExit { message: voluntary_exit, signature: signature.to_bytes().to_vec() };

    Ok(BuiltSignedExit { signed_exit, validator_index, epoch, pubkey_with_prefix, beacon_client })
}

#[cfg(test)]
#[allow(dead_code)]
#[path = "../../tests/common/mock_bn.rs"]
mod mock_bn;

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

    #[test]
    fn test_current_exit_epoch_six_second_slots_are_epoch_ten() {
        let genesis = 1_700_000_000_u64;
        let elapsed = 10 * 192;
        assert_eq!(current_exit_epoch(genesis + elapsed, genesis, 6_000).unwrap(), 10);
        assert_eq!(current_exit_epoch(genesis + elapsed, genesis, 12_000).unwrap(), 5);
    }

    #[test]
    fn test_current_exit_epoch_zero_duration_is_an_error() {
        let err = current_exit_epoch(100, 0, 0).unwrap_err();
        assert!(err.to_string().contains("outside"), "{err}");
    }

    async fn mock_client(
        spec: serde_json::Value,
        genesis_time: u64,
    ) -> (BeaconClient, wiremock::MockServer) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "genesis_time": genesis_time.to_string(),
                    "genesis_validators_root": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "genesis_fork_version": "0x00000000"
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": spec })),
            )
            .mount(&server)
            .await;
        let client = BeaconClient::new(beacon::BeaconClientConfig::new(server.uri()))
            .expect("beacon client");
        (client, server)
    }

    #[tokio::test]
    async fn test_cli_default_exit_epoch_uses_bn_slot_duration() {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let genesis = now - 10 * 192 - 96;
        let (client, _server) = mock_client(
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SLOTS_PER_EPOCH": "32" }),
            genesis,
        )
        .await;
        let epoch = default_exit_epoch(&client, genesis, rvc::config::Network::Custom)
            .await
            .expect("epoch");
        assert_eq!(epoch, 10);
    }

    #[tokio::test]
    async fn test_cli_default_exit_epoch_fails_when_spec_has_no_duration() {
        let (client, _server) =
            mock_client(serde_json::json!({ "SLOTS_PER_EPOCH": "32" }), 1).await;
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Mainnet)
            .await
            .expect_err("missing duration");
        let msg = err.to_string();
        assert!(msg.contains("SLOT_DURATION_MS") || msg.contains("SECONDS_PER_SLOT"), "{msg}");
    }

    #[tokio::test]
    async fn test_cli_default_exit_epoch_fails_when_spec_keys_conflict() {
        let (client, _server) = mock_client(
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SECONDS_PER_SLOT": "12" }),
            1,
        )
        .await;
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Custom)
            .await
            .expect_err("conflict");
        assert!(err.to_string().contains("conflicting"), "{err}");
    }

    #[tokio::test]
    async fn test_cli_default_exit_epoch_rejects_huge_duration() {
        let (client, _server) = mock_client(
            serde_json::json!({ "SLOT_DURATION_MS": "86400000", "SLOTS_PER_EPOCH": "32" }),
            1,
        )
        .await;
        let err =
            default_exit_epoch(&client, 1, rvc::config::Network::Custom).await.expect_err("huge");
        assert!(err.to_string().contains("outside"), "{err}");
    }

    #[tokio::test]
    async fn test_cli_named_network_rejects_non_preset_duration() {
        let (client, _server) = mock_client(
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SLOTS_PER_EPOCH": "32" }),
            1,
        )
        .await;
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Mainnet)
            .await
            .expect_err("preset");
        assert!(err.to_string().contains("preset"), "{err}");
    }

    #[tokio::test]
    async fn test_cli_named_network_rejects_genesis_time_that_is_not_the_preset() {
        let (client, _server) = mock_client(
            serde_json::json!({ "SLOT_DURATION_MS": "12000", "SLOTS_PER_EPOCH": "32" }),
            1,
        )
        .await;
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Mainnet)
            .await
            .expect_err("genesis");
        assert!(err.to_string().contains("genesis_time"), "{err}");
        assert!(err.to_string().contains("preset"), "{err}");
    }

    /// Electra-era epoch on the mock mainnet schedule (Capella is active,
    /// Fulu is not). A future epoch relative to a clock near epoch ~400k.
    const FUTURE_ELECTRA_EPOCH: u64 = 1_000_000;

    /// Local keystore, mock beacon (genesis, spec, fork schedule), and a
    /// tempfile slashing DB. The signature must verify under the EIP-7044
    /// Capella exit domain.
    #[tokio::test]
    async fn test_build_signed_exit_signs_with_a_local_keystore() {
        let sk = crypto::SecretKey::generate();
        let pubkey = sk.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));

        let keystore_dir = tempfile::tempdir().expect("keystore dir");
        let password = "exit-test-password";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt keystore");
        keystore.to_file(keystore_dir.path().join("keystore-0.json")).expect("write keystore");
        let password_file = keystore_dir.path().join("passwords.txt");
        std::fs::write(&password_file, format!("*={password}\n")).expect("password file");

        let db_dir = tempfile::tempdir().expect("slashing dir");
        let db_path = db_dir.path().join("slashing.sqlite");
        {
            let (_db, created) =
                slashing::SlashingDb::open_with_create_info(&db_path).expect("create slashing db");
            assert!(created, "tempfile slashing DB must be a fresh file");
        }

        let bn = super::mock_bn::MockBn::start().await;
        bn.mount_validator(&pubkey_hex, "42").await;

        let built = build_signed_exit(ExitCommonArgs {
            pubkey: pubkey_hex,
            epoch: Some(FUTURE_ELECTRA_EPOCH),
            beacon_url: bn.uri(),
            keystore_path: keystore_dir.path().to_path_buf(),
            password_file,
            slashing_db_path: Some(db_path),
            network: Some("mainnet".to_string()),
            genesis_validators_root: None,
            confirm: Some(true),
        })
        .await
        .expect("local keystore signs a voluntary exit");

        assert_eq!(built.validator_index, 42);
        assert_eq!(built.epoch, FUTURE_ELECTRA_EPOCH);
        assert_eq!(built.signed_exit.message.epoch, FUTURE_ELECTRA_EPOCH);
        assert_eq!(built.signed_exit.message.validator_index, 42);

        let gvr = eth_types::NetworkPreset::MAINNET.genesis_validators_root;
        let capella = eth_types::NetworkPreset::MAINNET.capella_fork_version;
        let exit = &built.signed_exit.message;
        let capella_root = crypto::compute_signing_root(
            exit,
            crypto::compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, capella, gvr),
        );
        let signature =
            crypto::Signature::from_bytes(&built.signed_exit.signature).expect("96-byte signature");
        signature.verify(&pubkey, &capella_root).expect("signature verifies under the exit domain");

        // Head fork at this epoch is Electra (mock ELECTRA_FORK_VERSION).
        // EIP-7044 must not sign the exit under that domain.
        let electra = [0x05, 0x00, 0x00, 0x00];
        let electra_root = crypto::compute_signing_root(
            exit,
            crypto::compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, electra, gvr),
        );
        assert_ne!(capella_root, electra_root, "Capella and Electra exit domains differ");
        assert!(
            signature.verify(&pubkey, &electra_root).is_err(),
            "exit signature must not verify under the Electra domain"
        );
    }

    /// The beacon list can lead with a different validator. The index must be
    /// the requested pubkey, including when that pubkey's case differs.
    #[tokio::test]
    async fn test_build_signed_exit_matches_the_requested_pubkey() {
        let sk = crypto::SecretKey::generate();
        let pubkey = sk.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
        let decoy = format!("0x{}", "ab".repeat(48));

        let keystore_dir = tempfile::tempdir().expect("keystore dir");
        let password = "exit-test-password";
        let keystore = crypto::Keystore::encrypt(
            &sk,
            password.as_bytes(),
            "m/12381/3600/0/0/0",
            crypto::EncryptionKdf::scrypt_cheap_for_tests(),
        )
        .expect("encrypt keystore");
        keystore.to_file(keystore_dir.path().join("keystore-0.json")).expect("write keystore");
        let password_file = keystore_dir.path().join("passwords.txt");
        std::fs::write(&password_file, format!("*={password}\n")).expect("password file");

        let db_dir = tempfile::tempdir().expect("slashing dir");
        let db_path = db_dir.path().join("slashing.sqlite");
        {
            slashing::SlashingDb::open_with_create_info(&db_path).expect("create slashing db");
        }

        let bn = super::mock_bn::MockBn::start().await;
        bn.mount_validators(&[(&decoy, "7"), (&pubkey_hex.to_ascii_uppercase(), "42")]).await;

        let built = build_signed_exit(ExitCommonArgs {
            pubkey: pubkey_hex,
            epoch: Some(FUTURE_ELECTRA_EPOCH),
            beacon_url: bn.uri(),
            keystore_path: keystore_dir.path().to_path_buf(),
            password_file,
            slashing_db_path: Some(db_path),
            network: Some("mainnet".to_string()),
            genesis_validators_root: None,
            confirm: Some(true),
        })
        .await
        .expect("matching pubkey signs even when it is not the first record");

        assert_eq!(built.validator_index, 42);
        assert_ne!(built.validator_index, 7);
    }

    /// A list that does not contain the requested pubkey fails before signing.
    #[tokio::test]
    async fn test_build_signed_exit_rejects_when_no_record_matches_the_pubkey() {
        let bn = super::mock_bn::MockBn::start().await;
        let requested = format!("0x{}", "cd".repeat(48));
        let other = format!("0x{}", "ab".repeat(48));
        bn.mount_validators(&[(&other, "7")]).await;

        let err = match build_signed_exit(ExitCommonArgs {
            pubkey: requested.clone(),
            epoch: Some(1),
            beacon_url: bn.uri(),
            keystore_path: std::path::PathBuf::from("/no/such/keystore"),
            password_file: std::path::PathBuf::from("/no/such/passwords"),
            slashing_db_path: None,
            network: Some("mainnet".to_string()),
            genesis_validators_root: None,
            confirm: None,
        })
        .await
        {
            Err(err) => err,
            Ok(_) => panic!("a validator list that omits the pubkey must not sign"),
        };

        let text = err.to_string();
        assert!(text.contains("not found"), "{text}");
        assert!(text.contains(&requested), "{text}");
        assert!(!text.contains("Failed to sign"), "{text}");
    }

    #[tokio::test]
    async fn test_cli_rejects_slots_per_epoch_that_is_not_the_preset() {
        let (client, _server) = mock_client(
            serde_json::json!({ "SLOT_DURATION_MS": "12000", "SLOTS_PER_EPOCH": "16" }),
            1,
        )
        .await;
        let err =
            default_exit_epoch(&client, 1, rvc::config::Network::Mainnet).await.expect_err("slots");
        assert!(err.to_string().contains("SLOTS_PER_EPOCH"), "{err}");
    }
}
