//! Shared voluntary-exit signing path used by `voluntary-exit` and `prepare-exit`.
//!
//! Before the confirm gate, keystore decrypt, or slashing DB open, the path
//! checks the beacon node's genesis validators root and, on a named network,
//! its Capella fork version. An explicit epoch before Capella is refused.

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
/// error. The 12 s constant is not a fallback. `now_unix_secs` is the clock;
/// production passes [`system_now_unix_secs`] and only from the no-`--epoch` branch.
async fn default_exit_epoch(
    beacon_client: &BeaconClient,
    genesis_time: u64,
    network: rvc::config::Network,
    now_unix_secs: u64,
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
    current_exit_epoch(now_unix_secs, genesis_time, slot_duration_ms)
}

/// Unix seconds from the system clock.
///
/// The same read `default_exit_epoch` used before the clock seam, including the
/// "system time before UNIX epoch" error. Called only when `--epoch` is absent.
fn system_now_unix_secs() -> anyhow::Result<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| anyhow::anyhow!("system time before UNIX epoch"))
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

/// Beacon identity or fork preflight failed before any keystore, slashing-DB, or sign work.
///
/// The `anyhow` boundary of the command stays. Callers downcast with
/// [`anyhow::Error::downcast_ref`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExitPreflightError {
    /// Local genesis validators root and the beacon node's root differ.
    ///
    /// `root_source` names `--network <net>` or `--genesis-validators-root`.
    /// The field is not called `source`: thiserror treats that name as [`std::error::Error::source`].
    #[error(
        "genesis validators root mismatch: local {local} != beacon {beacon} (root source: {root_source}; pass --network or --genesis-validators-root)"
    )]
    GenesisValidatorsRootMismatch { local: String, beacon: String, root_source: String },
    /// Named-network Capella fork version does not match the beacon node.
    #[error("Capella fork version mismatch for {network}: preset {preset} != beacon {beacon}")]
    CapellaForkVersionMismatch { network: rvc::config::Network, preset: String, beacon: String },
    /// Explicit exit epoch is before Capella, or Capella is unscheduled (`u64::MAX`).
    #[error(
        "exit epoch {epoch} is before the Capella fork epoch {capella_fork_epoch}; EIP-7044 exits are valid from Capella onward"
    )]
    PreCapellaEpoch { epoch: u64, capella_fork_epoch: u64 },
}

fn root_hex(root: &eth_types::Root) -> String {
    format!("0x{}", hex::encode(root))
}

fn version_hex(version: &[u8; 4]) -> String {
    format!("0x{}", hex::encode(version))
}

/// Where the local genesis validators root came from.
fn exit_root_source(
    network: rvc::config::Network,
    genesis_validators_root: Option<&str>,
) -> String {
    match genesis_validators_root {
        Some(_) => "--genesis-validators-root".to_string(),
        None => format!("--network {network}"),
    }
}

/// Resolve validator index, epoch, load keys / slashing DB, and sign a voluntary exit.
///
/// Callers differ only in the final step: submit to the BN or write to a file.
/// The clock is [`system_now_unix_secs`], and it is read only when `--epoch` is absent.
pub async fn build_signed_exit(args: ExitCommonArgs) -> anyhow::Result<BuiltSignedExit> {
    build_signed_exit_at(args, system_now_unix_secs).await
}

/// [`build_signed_exit`] with an injected clock.
///
/// `now` is called only in the no-`--epoch` branch. Private to this module:
/// no flag, environment variable, or config value can replace the production clock.
async fn build_signed_exit_at(
    args: ExitCommonArgs,
    now: fn() -> anyhow::Result<u64>,
) -> anyhow::Result<BuiltSignedExit> {
    // 1. Network and builder. No beacon I/O.
    let network = match args.network.as_deref() {
        Some(name) => name.parse().map_err(|e: String| anyhow::anyhow!("{e}"))?,
        None => rvc::config::Network::default(),
    };
    let root_source = exit_root_source(network, args.genesis_validators_root.as_deref());

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

    // 2. Local root. `--network custom` without a root fails here, before any BN request.
    let local_root = builder
        .parse_genesis_validators_root()
        .context("Failed to parse genesis validators root")?;

    // 3. One genesis read. The same response feeds the default epoch.
    let beacon_config = BeaconClientConfig::new(&args.beacon_url);
    let beacon_client =
        BeaconClient::new(beacon_config).context("Failed to create beacon client")?;
    let genesis =
        beacon_client.get_genesis().await.context("Failed to get genesis info from beacon node")?;
    let local_root_hex = root_hex(&local_root);
    if !beacon::hex_ids_equal(&local_root_hex, &genesis.data.genesis_validators_root) {
        return Err(ExitPreflightError::GenesisValidatorsRootMismatch {
            local: local_root_hex,
            beacon: genesis.data.genesis_validators_root,
            root_source,
        }
        .into());
    }

    // 4. Index from a beacon node that already matched the local chain.
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

    // 5. Explicit epoch, or the clock plus the genesis time already fetched.
    // The spec read stays inside `default_exit_epoch`, which runs only here.
    let epoch = match args.epoch {
        Some(epoch) => epoch,
        None => {
            let genesis_time: u64 =
                genesis.data.genesis_time.parse().context("Failed to parse genesis time")?;
            default_exit_epoch(&beacon_client, genesis_time, network, now()?).await?
        }
    };

    // 6. Fork schedule, then the named-network Capella version check.
    // Custom keeps the beacon node's version.
    let fork_schedule = builder
        .build_fork_schedule(&beacon_client)
        .await
        .context("Failed to fetch fork schedule")?;
    if let Some(preset) = network.capella_fork_version() {
        if fork_schedule.capella_fork_version != preset {
            return Err(ExitPreflightError::CapellaForkVersionMismatch {
                network,
                preset: version_hex(&preset),
                beacon: version_hex(&fork_schedule.capella_fork_version),
            }
            .into());
        }
    }

    // 7. Explicit epochs before Capella are refused. Unscheduled Capella
    // (`u64::MAX`) refuses every explicit epoch, including `u64::MAX`.
    // A clock-derived epoch is not checked.
    if let Some(explicit) = args.epoch {
        let capella_fork_epoch = fork_schedule.capella_fork_epoch;
        if capella_fork_epoch == u64::MAX || explicit < capella_fork_epoch {
            return Err(ExitPreflightError::PreCapellaEpoch {
                epoch: explicit,
                capella_fork_epoch,
            }
            .into());
        }
    }

    info!(epoch, validator_index, "Preparing voluntary exit");

    // 8. Confirm, then keys and the slashing DB. A refused exit never reaches this.
    if let Some(confirm) = args.confirm {
        require_exit_confirm(confirm, validator_index, &pubkey_with_prefix, epoch)?;
    }

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

    let voluntary_exit = VoluntaryExit { epoch, validator_index };

    let signature = signer
        .sign_voluntary_exit(&voluntary_exit, &pubkey, &fork_schedule, &local_root)
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
    fn test_current_exit_epoch_future_genesis_is_zero() {
        assert_eq!(current_exit_epoch(1_000, 2_000, 12_000).unwrap(), 0);
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

    /// Fixed genesis. The clock sits in the middle of epoch 10 at 6 s slots
    /// (`10 × 192 + 96`). A 12 s slot length would report epoch 5.
    const GENESIS: u64 = 1_700_000_000;
    const EPOCH_TEN_AT_SIX_SECONDS: u64 = GENESIS + 10 * 192 + 96;

    #[tokio::test]
    async fn test_cli_default_exit_epoch_uses_bn_slot_duration() {
        let (client, _server) = mock_client(
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SLOTS_PER_EPOCH": "32" }),
            GENESIS,
        )
        .await;
        let epoch = default_exit_epoch(
            &client,
            GENESIS,
            rvc::config::Network::Custom,
            EPOCH_TEN_AT_SIX_SECONDS,
        )
        .await
        .expect("epoch");
        assert_eq!(epoch, 10);
    }

    #[tokio::test]
    async fn test_cli_default_exit_epoch_fails_when_spec_has_no_duration() {
        let (client, _server) =
            mock_client(serde_json::json!({ "SLOTS_PER_EPOCH": "32" }), 1).await;
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Mainnet, 0)
            .await
            .map(drop)
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
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Custom, 0)
            .await
            .map(drop)
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
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Custom, 0)
            .await
            .map(drop)
            .expect_err("huge");
        assert!(err.to_string().contains("outside"), "{err}");
    }

    #[tokio::test]
    async fn test_cli_named_network_rejects_non_preset_duration() {
        let (client, _server) = mock_client(
            serde_json::json!({ "SLOT_DURATION_MS": "6000", "SLOTS_PER_EPOCH": "32" }),
            1,
        )
        .await;
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Mainnet, 0)
            .await
            .map(drop)
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
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Mainnet, 0)
            .await
            .map(drop)
            .expect_err("genesis");
        assert!(err.to_string().contains("genesis_time"), "{err}");
        assert!(err.to_string().contains("preset"), "{err}");
    }

    /// Electra-era epoch on the mock mainnet schedule (Capella is active,
    /// Fulu is not). A future epoch relative to a clock near epoch ~400k.
    const FUTURE_ELECTRA_EPOCH: u64 = 1_000_000;
    const MAINNET_CAPELLA_EPOCH: u64 = 194_048;

    fn clock_must_not_be_read() -> anyhow::Result<u64> {
        anyhow::bail!("clock must not be read")
    }

    fn clock_after_mainnet_genesis() -> anyhow::Result<u64> {
        Ok(eth_types::NetworkPreset::MAINNET.genesis_time + 10 * 384 + 96)
    }

    fn clock_at_epoch_ten() -> anyhow::Result<u64> {
        Ok(EPOCH_TEN_AT_SIX_SECONDS)
    }

    struct ExitFixture {
        pubkey: crypto::PublicKey,
        pubkey_hex: String,
        keystore_dir: tempfile::TempDir,
        password_file: std::path::PathBuf,
        _db_dir: tempfile::TempDir,
        db_path: std::path::PathBuf,
    }

    fn exit_fixture() -> ExitFixture {
        let secret = crypto::SecretKey::generate();
        let pubkey = secret.public_key();
        let pubkey_hex = format!("0x{}", hex::encode(pubkey.to_bytes()));
        let keystore_dir = tempfile::tempdir().expect("keystore dir");
        let password = "exit-test-password";
        let keystore = crypto::Keystore::encrypt(
            &secret,
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
        slashing::SlashingDb::open_with_create_info(&db_path).expect("create slashing db");
        ExitFixture { pubkey, pubkey_hex, keystore_dir, password_file, _db_dir: db_dir, db_path }
    }

    fn exit_args(
        fixture: &ExitFixture,
        beacon_url: String,
        epoch: Option<u64>,
        network: Option<&str>,
        genesis_validators_root: Option<&str>,
        confirm: Option<bool>,
    ) -> ExitCommonArgs {
        ExitCommonArgs {
            pubkey: fixture.pubkey_hex.clone(),
            epoch,
            beacon_url,
            keystore_path: fixture.keystore_dir.path().to_path_buf(),
            password_file: fixture.password_file.clone(),
            slashing_db_path: Some(fixture.db_path.clone()),
            network: network.map(str::to_string),
            genesis_validators_root: genesis_validators_root.map(str::to_string),
            confirm,
        }
    }

    fn assert_exit_domain(
        built: &BuiltSignedExit,
        pubkey: &crypto::PublicKey,
        capella: [u8; 4],
        gvr: [u8; 32],
    ) {
        let root = crypto::compute_signing_root(
            &built.signed_exit.message,
            crypto::compute_domain(eth_types::DOMAIN_VOLUNTARY_EXIT, capella, gvr),
        );
        let signature =
            crypto::Signature::from_bytes(&built.signed_exit.signature).expect("96-byte signature");
        signature.verify(pubkey, &root).expect("signature verifies under the exit domain");
    }

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
        let err = default_exit_epoch(&client, 1, rvc::config::Network::Mainnet, 0)
            .await
            .map(drop)
            .expect_err("slots");
        assert!(err.to_string().contains("SLOTS_PER_EPOCH"), "{err}");
    }

    #[tokio::test]
    async fn build_signed_exit_rejects_a_bn_gvr_mismatch() {
        let fixture = exit_fixture();
        let hoodi = eth_types::NetworkPreset::HOODI.genesis_validators_root_hex();
        let mainnet = eth_types::NetworkPreset::MAINNET.genesis_validators_root_hex();
        let bn =
            super::mock_bn::MockBn::builder().with_genesis_validators_root(&hoodi).start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;

        let err = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            None,
            None,
            Some(true),
        ))
        .await
        .map(drop)
        .expect_err("a Hoodi beacon with no --network must not sign a mainnet exit");
        let text = err.to_string();
        assert!(text.contains(&hoodi), "{text}");
        assert!(text.contains(&mainnet), "{text}");
        assert!(text.contains("--network"), "{text}");
        assert!(!text.contains("password"), "{text}");
        assert!(!text.contains("keystore"), "{text}");

        let missing_password = ExitCommonArgs {
            password_file: std::path::PathBuf::from("/no/such/passwords"),
            ..exit_args(&fixture, bn.uri(), Some(FUTURE_ELECTRA_EPOCH), None, None, Some(true))
        };
        let err = build_signed_exit(missing_password)
            .await
            .map(drop)
            .expect_err("a missing password must not be reached");
        let text = err.to_string();
        assert!(text.contains(&hoodi) && text.contains(&mainnet), "{text}");
        assert!(!text.contains("password"), "{text}");
        assert!(!text.contains("No such file"), "{text}");
    }

    #[tokio::test]
    async fn prepare_exit_gvr_mismatch_writes_no_file() {
        let fixture = exit_fixture();
        let hoodi = eth_types::NetworkPreset::HOODI.genesis_validators_root_hex();
        let mainnet = eth_types::NetworkPreset::MAINNET.genesis_validators_root_hex();
        let bn =
            super::mock_bn::MockBn::builder().with_genesis_validators_root(&hoodi).start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let output = tempfile::tempdir().expect("output dir");

        let err = crate::commands::prepare_exit::execute(
            crate::commands::prepare_exit::PrepareExitArgs {
                pubkey: fixture.pubkey_hex.clone(),
                epoch: Some(FUTURE_ELECTRA_EPOCH),
                output: output.path().to_path_buf(),
                beacon_url: bn.uri(),
                keystore_path: fixture.keystore_dir.path().to_path_buf(),
                password_file: fixture.password_file.clone(),
                slashing_db_path: Some(fixture.db_path.clone()),
                network: None,
                genesis_validators_root: None,
            },
        )
        .await
        .map(drop)
        .expect_err("prepare-exit must refuse a Hoodi beacon without --network");
        let text = err.to_string();
        assert!(text.contains(&hoodi) && text.contains(&mainnet), "{text}");
        let entries: Vec<_> = std::fs::read_dir(output.path()).unwrap().collect();
        assert!(entries.is_empty(), "output dir must stay empty, entries={entries:?}");
    }

    #[tokio::test]
    async fn build_signed_exit_reads_genesis_once_with_an_explicit_epoch() {
        let fixture = exit_fixture();
        let bn = super::mock_bn::MockBn::start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            Some("mainnet"),
            None,
            Some(true),
        ))
        .await
        .expect("matching mainnet signs");
        assert_eq!(bn.requests_to("/eth/v1/beacon/genesis").await, 1);
    }

    #[tokio::test]
    async fn build_signed_exit_reads_genesis_once_for_the_default_epoch() {
        let fixture = exit_fixture();
        let bn = super::mock_bn::MockBn::start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let built = build_signed_exit_at(
            exit_args(&fixture, bn.uri(), None, Some("mainnet"), None, Some(true)),
            clock_after_mainnet_genesis,
        )
        .await
        .expect("default epoch signs");
        assert_eq!(bn.requests_to("/eth/v1/beacon/genesis").await, 1);
        assert!(built.epoch > 0, "clock is after mainnet genesis");
    }

    #[tokio::test]
    async fn build_signed_exit_default_epoch_uses_bn_slot_duration() {
        let fixture = exit_fixture();
        let root = super::mock_bn::MAINNET_GVR;
        let bn = super::mock_bn::MockBn::builder()
            .with_genesis_time(GENESIS)
            .with_slot_duration_ms(6_000)
            .start()
            .await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let built = build_signed_exit_at(
            exit_args(&fixture, bn.uri(), None, Some("custom"), Some(root), Some(true)),
            clock_at_epoch_ten,
        )
        .await
        .expect("6 s slots");
        assert_eq!(built.epoch, 10);
    }

    #[tokio::test]
    async fn test_build_signed_exit_rejects_a_capella_version_that_is_not_the_preset() {
        let fixture = exit_fixture();
        let bn = super::mock_bn::MockBn::builder()
            .with_spec_value("CAPELLA_FORK_VERSION", "0x03000001")
            .start()
            .await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let err = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            Some("mainnet"),
            None,
            Some(true),
        ))
        .await
        .map(drop)
        .expect_err("a non-preset Capella version must be refused");
        let text = err.to_string();
        assert!(text.contains("0x03000000"), "{text}");
        assert!(text.contains("0x03000001"), "{text}");
    }

    #[tokio::test]
    async fn build_signed_exit_rejects_a_pre_capella_explicit_epoch() {
        let fixture = exit_fixture();
        let bn = super::mock_bn::MockBn::start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let err = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(MAINNET_CAPELLA_EPOCH - 1),
            Some("mainnet"),
            None,
            Some(true),
        ))
        .await
        .map(drop)
        .expect_err("epoch 194047 is before Capella");
        let text = err.to_string();
        assert!(text.contains("194047"), "{text}");
        assert!(text.contains("194048"), "{text}");
    }

    #[tokio::test]
    async fn build_signed_exit_signs_at_the_capella_epoch() {
        let fixture = exit_fixture();
        let bn = super::mock_bn::MockBn::start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let built = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(MAINNET_CAPELLA_EPOCH),
            Some("mainnet"),
            None,
            Some(true),
        ))
        .await
        .expect("the Capella epoch itself signs");
        assert_eq!(built.epoch, MAINNET_CAPELLA_EPOCH);
        assert_exit_domain(
            &built,
            &fixture.pubkey,
            eth_types::NetworkPreset::MAINNET.capella_fork_version,
            eth_types::NetworkPreset::MAINNET.genesis_validators_root,
        );
    }

    #[tokio::test]
    async fn build_signed_exit_checks_the_root_before_the_confirm_gate() {
        let hoodi = eth_types::NetworkPreset::HOODI.genesis_validators_root_hex();
        let mainnet = eth_types::NetworkPreset::MAINNET.genesis_validators_root_hex();
        let bn =
            super::mock_bn::MockBn::builder().with_genesis_validators_root(&hoodi).start().await;
        let pubkey = format!("0x{}", "ab".repeat(48));
        bn.mount_validator(&pubkey, "42").await;
        let err = build_signed_exit(ExitCommonArgs {
            pubkey,
            epoch: Some(FUTURE_ELECTRA_EPOCH),
            beacon_url: bn.uri(),
            keystore_path: std::path::PathBuf::from("/no/such/keystore"),
            password_file: std::path::PathBuf::from("/no/such/passwords"),
            slashing_db_path: None,
            network: None,
            genesis_validators_root: None,
            confirm: Some(false),
        })
        .await
        .map(drop)
        .expect_err("root mismatch wins over the confirm gate");
        let text = err.to_string();
        assert!(text.contains(&hoodi) && text.contains(&mainnet), "{text}");
        assert!(!text.contains("aborted"), "{text}");
        assert!(!text.contains("--confirm flag not provided"), "{text}");
    }

    #[tokio::test]
    async fn build_signed_exit_custom_network_without_a_root_fails_before_any_bn_request() {
        let bn = super::mock_bn::MockBn::start().await;
        let err = build_signed_exit(ExitCommonArgs {
            pubkey: format!("0x{}", "ab".repeat(48)),
            epoch: Some(FUTURE_ELECTRA_EPOCH),
            beacon_url: bn.uri(),
            keystore_path: std::path::PathBuf::from("/no/such/keystore"),
            password_file: std::path::PathBuf::from("/no/such/passwords"),
            slashing_db_path: None,
            network: Some("custom".to_string()),
            genesis_validators_root: None,
            confirm: Some(true),
        })
        .await
        .map(drop)
        .expect_err("custom without a root");
        let missing = err
            .downcast_ref::<rvc::config::ConfigError>()
            .expect("MissingField reaches the anyhow chain");
        assert!(
            matches!(missing, rvc::config::ConfigError::MissingField(field) if field == "genesis_validators_root"),
            "{missing:?}"
        );
        assert_eq!(bn.request_count().await, 0, "no beacon request of any kind");
    }

    #[tokio::test]
    async fn build_signed_exit_accepts_a_matching_genesis_validators_root_override() {
        let fixture = exit_fixture();
        let root = [0xbb; 32];
        let root_hex = format!("0x{}", hex::encode(root));
        let bn =
            super::mock_bn::MockBn::builder().with_genesis_validators_root(&root_hex).start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let built = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            Some("custom"),
            Some(&root_hex),
            Some(true),
        ))
        .await
        .expect("matching override signs");
        assert_exit_domain(
            &built,
            &fixture.pubkey,
            eth_types::NetworkPreset::MAINNET.capella_fork_version,
            root,
        );
    }

    #[tokio::test]
    async fn build_signed_exit_compares_roots_case_insensitively() {
        let fixture = exit_fixture();
        let root = eth_types::NetworkPreset::MAINNET.genesis_validators_root_hex();
        let bn = super::mock_bn::MockBn::builder()
            .with_genesis_validators_root(root.to_ascii_uppercase())
            .start()
            .await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let built = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            Some("mainnet"),
            None,
            Some(true),
        ))
        .await
        .expect("uppercase beacon root still matches");
        assert_exit_domain(
            &built,
            &fixture.pubkey,
            eth_types::NetworkPreset::MAINNET.capella_fork_version,
            eth_types::NetworkPreset::MAINNET.genesis_validators_root,
        );
    }

    #[tokio::test]
    async fn build_signed_exit_rejects_a_malformed_bn_genesis_root_hex() {
        let fixture = exit_fixture();
        let bn = super::mock_bn::MockBn::builder()
            .with_genesis_validators_root("0xnot-hex")
            .start()
            .await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let err = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            Some("mainnet"),
            None,
            Some(true),
        ))
        .await
        .map(drop)
        .expect_err("a malformed beacon root is a refusal");
        let text = err.to_string();
        assert!(text.contains("0xnot-hex"), "{text}");
        assert!(
            text.contains(&eth_types::NetworkPreset::MAINNET.genesis_validators_root_hex()),
            "{text}"
        );
    }

    #[tokio::test]
    async fn build_signed_exit_explicit_epoch_does_not_read_the_clock() {
        let fixture = exit_fixture();
        let bn = super::mock_bn::MockBn::start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let built = build_signed_exit_at(
            exit_args(
                &fixture,
                bn.uri(),
                Some(FUTURE_ELECTRA_EPOCH),
                Some("mainnet"),
                None,
                Some(true),
            ),
            clock_must_not_be_read,
        )
        .await
        .expect("an explicit epoch never reads the clock");
        assert_eq!(built.epoch, FUTURE_ELECTRA_EPOCH);
    }

    #[tokio::test]
    async fn build_signed_exit_custom_network_uses_the_bn_capella_version() {
        let fixture = exit_fixture();
        let root = [0xcc; 32];
        let root_hex = format!("0x{}", hex::encode(root));
        let bn_capella = [0x03, 0x00, 0x00, 0x01];
        let bn = super::mock_bn::MockBn::builder()
            .with_genesis_validators_root(&root_hex)
            .with_spec_value("CAPELLA_FORK_VERSION", "0x03000001")
            .start()
            .await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let built = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            Some("custom"),
            Some(&root_hex),
            Some(true),
        ))
        .await
        .expect("custom keeps the beacon Capella version");
        assert_exit_domain(&built, &fixture.pubkey, bn_capella, root);
        let preset_root = crypto::compute_signing_root(
            &built.signed_exit.message,
            crypto::compute_domain(
                eth_types::DOMAIN_VOLUNTARY_EXIT,
                eth_types::NetworkPreset::MAINNET.capella_fork_version,
                root,
            ),
        );
        let signature = crypto::Signature::from_bytes(&built.signed_exit.signature).unwrap();
        assert!(
            signature.verify(&fixture.pubkey, &preset_root).is_err(),
            "custom must not sign under the mainnet Capella version"
        );
    }

    #[tokio::test]
    async fn build_signed_exit_hoodi_root_override_without_network_checks_mainnet_capella() {
        let fixture = exit_fixture();
        let hoodi = eth_types::NetworkPreset::HOODI;
        let hoodi_root = hoodi.genesis_validators_root_hex();
        let hoodi_capella = hoodi.capella_fork_version_hex();
        let mainnet_capella = eth_types::NetworkPreset::MAINNET.capella_fork_version_hex();
        let bn = super::mock_bn::MockBn::builder()
            .with_genesis_validators_root(&hoodi_root)
            .with_spec_value("CAPELLA_FORK_VERSION", &hoodi_capella)
            .start()
            .await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let err = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            None,
            Some(&hoodi_root),
            Some(true),
        ))
        .await
        .map(drop)
        .expect_err("omitting --network still runs the mainnet Capella check");
        let text = err.to_string();
        assert!(text.contains(&mainnet_capella), "{text}");
        assert!(text.contains(&hoodi_capella), "{text}");
    }

    #[tokio::test]
    async fn build_signed_exit_rejects_every_explicit_epoch_when_capella_is_unscheduled() {
        let fixture = exit_fixture();
        let root = [0xdd; 32];
        let root_hex = format!("0x{}", hex::encode(root));
        let bn = super::mock_bn::MockBn::builder()
            .with_genesis_validators_root(&root_hex)
            .with_spec_value("CAPELLA_FORK_EPOCH", u64::MAX.to_string())
            .start()
            .await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        for epoch in [1_u64, u64::MAX] {
            let err = build_signed_exit(exit_args(
                &fixture,
                bn.uri(),
                Some(epoch),
                Some("custom"),
                Some(&root_hex),
                Some(true),
            ))
            .await
            .map(drop)
            .expect_err("unscheduled Capella refuses every explicit epoch");
            let text = err.to_string();
            assert!(text.contains(&epoch.to_string()), "{text}");
            assert!(text.contains(&u64::MAX.to_string()), "{text}");
        }
    }

    #[tokio::test]
    async fn exit_preflight_errors_are_typed() {
        let fixture = exit_fixture();
        let hoodi = eth_types::NetworkPreset::HOODI.genesis_validators_root_hex();
        let mainnet = eth_types::NetworkPreset::MAINNET.genesis_validators_root_hex();
        let bn =
            super::mock_bn::MockBn::builder().with_genesis_validators_root(&hoodi).start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let err = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            None,
            None,
            Some(true),
        ))
        .await
        .map(drop)
        .expect_err("typed GVR mismatch");
        match err.downcast_ref::<ExitPreflightError>() {
            Some(ExitPreflightError::GenesisValidatorsRootMismatch {
                local,
                beacon,
                root_source,
            }) => {
                assert_eq!(local, &mainnet);
                assert_eq!(beacon, &hoodi);
                assert_eq!(root_source, "--network mainnet");
            }
            other => panic!("expected GenesisValidatorsRootMismatch, got {other:?}: {err}"),
        }

        let bn = super::mock_bn::MockBn::builder()
            .with_spec_value("CAPELLA_FORK_VERSION", "0x03000001")
            .start()
            .await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let err = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(FUTURE_ELECTRA_EPOCH),
            Some("mainnet"),
            None,
            Some(true),
        ))
        .await
        .map(drop)
        .expect_err("typed Capella mismatch");
        match err.downcast_ref::<ExitPreflightError>() {
            Some(ExitPreflightError::CapellaForkVersionMismatch { network, preset, beacon }) => {
                assert_eq!(*network, rvc::config::Network::Mainnet);
                assert_eq!(preset, "0x03000000");
                assert_eq!(beacon, "0x03000001");
            }
            other => panic!("expected CapellaForkVersionMismatch, got {other:?}: {err}"),
        }

        let bn = super::mock_bn::MockBn::start().await;
        bn.mount_validator(&fixture.pubkey_hex, "42").await;
        let err = build_signed_exit(exit_args(
            &fixture,
            bn.uri(),
            Some(MAINNET_CAPELLA_EPOCH - 1),
            Some("mainnet"),
            None,
            Some(true),
        ))
        .await
        .map(drop)
        .expect_err("typed pre-Capella epoch");
        match err.downcast_ref::<ExitPreflightError>() {
            Some(ExitPreflightError::PreCapellaEpoch { epoch, capella_fork_epoch }) => {
                assert_eq!(*epoch, MAINNET_CAPELLA_EPOCH - 1);
                assert_eq!(*capella_fork_epoch, MAINNET_CAPELLA_EPOCH);
            }
            other => panic!("expected PreCapellaEpoch, got {other:?}: {err}"),
        }
    }
}
