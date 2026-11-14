//! Bootstrap phase: wire signing enablement (forward window, liveness).
//!
//! Extracted from `bin/rvc` startup Step 6 (SEC-2b/2c): constructs the
//! production [`SigningEnablement`] (fail-closed [`ForwardWindowMachine`] or
//! operator opt-out) and spawns the per-slot liveness observation loop.
//! Secret-provider refresh is spawned later in [`super::run`] once
//! `validator_store` and `key_gen_tx` are in scope (ARCH-2a / VD-E1).

use std::sync::Arc;

use bn_manager::{BeaconNodeClient, BnManager, LivenessApi};
use doppelganger::{ForwardWindowMachine, MonotonicEpochClock, SigningEnablement};
use eth_types::Epoch;
use slashing::SlashingDb;
use tracing::{error, info, warn};

use super::beacon::BeaconHandles;
use super::executor::TaskExecutor;
use super::keys::LoadedKeys;
use super::BootstrapError;
use crate::config::{Config, ServiceBuilder};
use crate::liveness_loop::{spawn_liveness_loop, LivenessLoopSpawn};
use crate::orchestrator::PubkeyMap;
use crate::pubkey_index::{
    parse_pubkey_bytes, pubkey_bytes_to_0x, PubkeyIndexRegistry, SharedPubkeyIndexRegistry,
};
use crate::quiesce::TrackedKeys;

/// Handles produced by [`wire_signing_enablement`].
///
/// [`super::services::build_services`] clones `signing_enablement` into the
/// signer. [`super::run::run`] keeps the forward-window machine, the epoch
/// clock, the pubkey index, and `tracked_keys` as locals. None of these fields
/// are stored on [`super::BootstrapCtx`].
pub struct EnablementHandles {
    /// Production signing gate (forward-window machine or operator opt-out).
    pub signing_enablement: Arc<dyn SigningEnablement>,
    /// Same machine as enablement when doppelganger is on; `None` on opt-out.
    /// Keymanager import / refresh call `register_for_import` on this handle.
    pub forward_window_machine: Option<Arc<ForwardWindowMachine>>,
    /// Shared monotonic epoch clock (boot register + keymanager import).
    pub epoch_clock: Arc<MonotonicEpochClock>,
    /// Byte-keyed pubkey map (same `Arc` as [`LoadedKeys::pubkey_map`]).
    pub pubkey_map: PubkeyMap,
    /// Spawned SEC-2c liveness loop; `None` only when doppelganger is off.
    pub liveness_task: Option<LivenessLoopSpawn>,
    /// Shared pubkey ↔ validator-index registry for duty tracking, proposer
    /// preparation, and liveness. Empty when unresolved / no keys.
    pub pubkey_index: SharedPubkeyIndexRegistry,
    /// Import/delete/sidecar-cleanup lock shared with the keystore adapter.
    pub tracked_keys: Arc<TrackedKeys>,
}

/// Construct SEC-2b enablement and spawn the SEC-2c liveness loop.
///
/// # Behaviour preserved from `run_validator`
///
/// - Fail-closed machine when doppelganger is on; unregistered keys cannot sign.
/// - Operator opt-out yields [`doppelganger::DoppelgangerDisabledByOperator`].
/// - Epoch-0 boot register marks normally registered keys Safe only after the
///   clock has reached genesis. A reading before genesis is not a counted epoch.
/// - The epoch is read again after the boot beacon reads. The epoch-0 bypass
///   holds only if that read is still 0, and the keys register with that epoch.
/// - Restart-aware safe-skip on **boot** `register` only, and only for keys
///   with no open import hold and no remaining import sidecar (local slashing
///   history under this GVR). Do **not** copy a live slashing DB to a second VC.
/// - An open hold, any import sidecar (any age) or an unreadable one, a leftover
///   `*.import_meta.json.removing.*` set-aside, a staged
///   `*.import_meta.json.partial`, or an unreadable keystore directory or
///   validators file uses `register_for_import` (Pending). An unreadable
///   directory or file applies that to every loaded key. The liveness loop
///   removes a sidecar only after that key reaches Safe, while holding the
///   same `tracked_keys` lock as DELETE/import.
/// - Dynamically added keys use `register_for_import` (always Pending).
/// - Liveness goes through `bn_manager` (multi-BN failover) and re-resolves
///   indices from `pubkey_map` after import.
///
/// Index resolution failure is fatal only when doppelganger is on and keys are
/// present (same as prior binary behaviour).
///
/// Secret-provider refresh is **not** wired here — see [`super::run::run`]
/// (ARCH-2a / VD-E1): it needs `validator_store` and `key_gen_tx` in scope.
pub async fn wire_signing_enablement(
    config: &Config,
    keys: &LoadedKeys,
    beacon: &BeaconHandles,
    slashing_db: Arc<SlashingDb>,
    executor: &TaskExecutor,
) -> Result<EnablementHandles, BootstrapError> {
    wire_signing_enablement_body(config, keys, beacon, slashing_db, executor, None).await
}

/// [`wire_signing_enablement`] with the boot epoch read from `boot_epoch`.
#[cfg(test)]
pub(crate) async fn wire_signing_enablement_with_boot_epoch(
    config: &Config,
    keys: &LoadedKeys,
    beacon: &BeaconHandles,
    slashing_db: Arc<SlashingDb>,
    executor: &TaskExecutor,
    boot_epoch: Arc<dyn Fn() -> Epoch + Send + Sync>,
) -> Result<EnablementHandles, BootstrapError> {
    wire_signing_enablement_body(config, keys, beacon, slashing_db, executor, Some(boot_epoch))
        .await
}

/// Body of [`wire_signing_enablement`]. Production passes `None` for
/// `boot_epoch` and reads [`MonotonicEpochClock::current_epoch`] on the shared clock.
async fn wire_signing_enablement_body(
    config: &Config,
    keys: &LoadedKeys,
    beacon: &BeaconHandles,
    slashing_db: Arc<SlashingDb>,
    executor: &TaskExecutor,
    boot_epoch: Option<Arc<dyn Fn() -> Epoch + Send + Sync>>,
) -> Result<EnablementHandles, BootstrapError> {
    let builder = ServiceBuilder::new(config.clone());
    let doppelganger_enabled = config.doppelganger_detection;

    // Shared monotonic epoch clock (M-7) for boot register + keymanager import
    // so NTP cannot compress the window and wall-clock alone cannot force epoch 0.
    let epoch_clock =
        Arc::new(MonotonicEpochClock::new(beacon.genesis_time, beacon.slot_duration_ms));
    let read_boot_epoch =
        || boot_epoch.as_ref().map_or_else(|| epoch_clock.current_epoch(), |read| read());
    // This read only decides whether to ask for heads. The bypass and the
    // register epoch use the read after the last boot await, below.
    let epoch_before_reads = read_boot_epoch();
    // Named-network confirmation is not enough: a clock still before genesis
    // saturates to epoch 0 and must not take the Safe bypass. A head outside
    // epoch 0, or a head that cannot be read, closes it too.
    let heads_in_epoch_zero = if doppelganger_enabled
        && beacon.genesis_confirmed
        && !epoch_clock.before_genesis()
        && epoch_before_reads == 0
    {
        admitted_heads_in_epoch_zero(beacon.bn_manager.as_ref()).await
    } else {
        false
    };

    // Resolve validator indices into the shared registry (duty tracker + liveness
    // + prepare_proposers all share this handle).
    let beacon_for_resolve: &dyn BeaconNodeClient = beacon.bn_manager.as_ref();
    let pubkey_index = PubkeyIndexRegistry::shared();
    // Sampled before the fetch: a revocation during it leaves the registry stale.
    let revocation = beacon_for_resolve.revocation_watch();
    let resolve_result = resolve_validator_indices(beacon_for_resolve, &keys.pubkey_map).await;

    if doppelganger_enabled && !keys.pubkey_map.read().is_empty() {
        match &resolve_result {
            Ok(reg) if !reg.is_empty() => {
                pubkey_index.write().extend_from(reg);
            }
            Ok(_) => {
                warn!(
                    total = keys.pubkey_map.read().len(),
                    "No validator indices resolved; validators may be pending activation. \
                     The liveness loop stays on and will not mark those keys Safe until a \
                     closed epoch includes their index"
                );
            }
            Err(e) => {
                error!("Failed to resolve validator indices: {}", e);
                return Err(BootstrapError::IndexResolution(e.to_string()));
            }
        }
    } else {
        match &resolve_result {
            // Duty-tracker indices: keep successful resolution even when doppelganger is off.
            Ok(reg) => pubkey_index.write().extend_from(reg),
            Err(e) => warn!(
                error = %e,
                "validator index resolution failed at boot; \
                 duties stay empty until the index resolver succeeds"
            ),
        }
    }
    if let Some(generation) = revocation.generation() {
        pubkey_index.write().attach_revocation(generation, revocation.seen());
    }
    if let Some(commit) = beacon_for_resolve.revocation_commit() {
        pubkey_index.write().attach_commit(commit);
    }

    // The boot awaits can cross into epoch 1. Read the epoch again: the bypass
    // holds only while it is still 0, and the keys register with this epoch.
    let enablement_epoch = read_boot_epoch();
    let epoch0_bypass = heads_in_epoch_zero && enablement_epoch == 0;

    if epoch0_bypass && doppelganger_enabled {
        info!(
            "Doppelganger detection: pre-genesis (epoch 0) startup — \
             normally registered validators are marked Safe without a monitoring window. \
             An unfinished import (open hold, any or unreadable sidecar, or \
             staged sidecar) stays Pending"
        );
    } else if !doppelganger_enabled {
        warn!("Doppelganger detection is disabled");
    }

    // SEC-2b: construct enablement (ForwardWindowMachine or operator opt-out)
    // and hand it to the production SignerService.
    //
    // Restart-aware safe-skip (boot register, normal keys only): if local
    // slashing history shows a recent attestation under this GVR, the key is
    // marked Safe without network observation. Do NOT copy a live slashing DB
    // to a second VC — that would open a dual-instance fail-open. An unfinished
    // import (open hold, any or unreadable sidecar, staged sidecar, or
    // an unreadable keystore directory or validators file) uses
    // register_for_import (always Pending), including at epoch 0. The sidecar
    // stays until the liveness loop observes Safe and removes it. API import
    // uses the same path.
    let (signing_enablement, forward_window_machine) = builder.build_signing_enablement(
        Arc::clone(&slashing_db),
        beacon.genesis_validators_root,
        enablement_epoch,
        &keys.pubkey_map,
        epoch0_bypass,
    );

    // Shared with keymanager DELETE/import and forward-window sidecar cleanup.
    let tracked_keys = Arc::new(TrackedKeys::new());

    // SEC-2c: spawn the per-slot liveness observation loop when doppelganger is on.
    // bn_manager is Arc; clone for the loop and keep the original for later duties.
    // pubkey_map stays attached for the retained refresh helper. IndexResolver,
    // spawned from `run`, is the production index writer (ADR-R05).
    let liveness_task = if doppelganger_enabled {
        spawn_liveness_loop(
            forward_window_machine.clone(),
            Arc::clone(&beacon.bn_manager) as Arc<dyn LivenessApi>,
            Arc::clone(&pubkey_index),
            Some(Arc::clone(&keys.pubkey_map)),
            Arc::clone(&epoch_clock),
            executor,
            Some((config.keystore_path.clone(), Arc::clone(&tracked_keys))),
        )
    } else {
        None
    };

    Ok(EnablementHandles {
        signing_enablement,
        forward_window_machine,
        epoch_clock,
        pubkey_map: Arc::clone(&keys.pubkey_map),
        liveness_task,
        pubkey_index,
        tracked_keys,
    })
}

/// `true` when every admitted beacon node in the All role reports a head in epoch 0.
///
/// All means a role set that contains [`bn_manager::BnRole::All`]
/// ([`bn_manager::BnRole::matches`]). An error, an empty set, a missing slot,
/// or a slot that does not parse closes the bypass. `head_slot` is the decimal
/// slot from `/eth/v1/node/syncing`.
async fn admitted_heads_in_epoch_zero(manager: &BnManager) -> bool {
    match manager.admitted_head_slots().await {
        Ok(slots)
            if !slots.is_empty()
                && slots.iter().all(|head_slot| *head_slot < eth_types::SLOTS_PER_EPOCH) =>
        {
            true
        }
        Ok(slots) => {
            info!(
                head_slots = ?slots,
                "epoch-0 doppelganger bypass closed: a beacon head is missing or outside epoch 0"
            );
            false
        }
        Err(err) => {
            warn!(
                error = %err,
                "epoch-0 doppelganger bypass closed: beacon head could not be read"
            );
            false
        }
    }
}

/// Resolve validator public keys to numeric beacon indices.
async fn resolve_validator_indices(
    beacon_client: &dyn BeaconNodeClient,
    pubkey_map: &PubkeyMap,
) -> Result<PubkeyIndexRegistry, String> {
    let pubkeys: Vec<String> = {
        let map = pubkey_map.read();
        if map.is_empty() {
            return Ok(PubkeyIndexRegistry::new());
        }
        map.keys().map(pubkey_bytes_to_0x).collect()
    };
    let response = beacon_client.get_validators(&pubkeys).await.map_err(|e| e.to_string())?;

    let mut registry = PubkeyIndexRegistry::new();
    for v in &response.data {
        if let Some(bytes) = parse_pubkey_bytes(&v.validator.pubkey) {
            registry.insert(bytes, v.index.clone());
        }
    }

    if registry.len() < pubkeys.len() {
        warn!(
            resolved = registry.len(),
            total = pubkeys.len(),
            "Some validator public keys could not be resolved to indices"
        );
    }
    info!(count = registry.len(), "Resolved validator indices");
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use beacon::BeaconClient;
    use bn_manager::{BnManager, OperationTimeouts};
    use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey, Signer};
    use doppelganger::ForwardWindowStatus;
    use eth_types::{Root, SLOTS_PER_EPOCH, SLOT_DURATION_MS};
    use slashing::SlashingDbReader;
    use std::collections::{HashMap, HashSet};
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const GVR: Root = [0x11u8; 32];

    fn empty_loaded_keys() -> LoadedKeys {
        let km = KeyManager::new();
        let local_signer = LocalSigner::new(km);
        LoadedKeys {
            composite_signer: Arc::new(CompositeSigner::new(local_signer)),
            validator_count: 0,
            local_pubkeys: HashSet::new(),
            pubkey_map: Arc::new(parking_lot::RwLock::new(HashMap::new())),
            secret_providers: vec![],
            grpc_signer: None,
        }
    }

    fn loaded_keys_with_pubkey(pk: crypto::PublicKey) -> LoadedKeys {
        let km = KeyManager::new();
        // pubkey_map is authoritative for enablement registration.
        let mut map = HashMap::new();
        map.insert(pk.to_bytes(), pk.clone());
        let local_signer = LocalSigner::new(km);
        LoadedKeys {
            composite_signer: Arc::new(CompositeSigner::new(local_signer)),
            validator_count: 1,
            local_pubkeys: HashSet::from([pk.to_bytes()]),
            pubkey_map: Arc::new(parking_lot::RwLock::new(map)),
            secret_providers: vec![],
            grpc_signer: None,
        }
    }

    async fn mock_beacon(genesis_time: u64) -> (MockServer, BeaconHandles) {
        let server = MockServer::start().await;
        // Small pubkey sets use GET; return empty data (pending activation path).
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"0","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .mount(&server)
            .await;

        let config = Config {
            beacon_url: server.uri(),
            beacon_nodes: vec![server.uri()],
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        };
        let builder = ServiceBuilder::new(config);
        let beacon_client: Arc<BeaconClient> = builder.build_beacon().expect("beacon client");
        let bn_manager: Arc<BnManager> = builder
            .build_bn_manager_with_timeouts(OperationTimeouts::default())
            .expect("bn manager");

        (
            server,
            BeaconHandles {
                beacon_client,
                bn_manager,
                genesis_validators_root: GVR,
                genesis_validators_root_hex: format!("0x{}", hex::encode(GVR)),
                genesis_time,
                slot_duration_ms: 12_000,
                genesis_confirmed: true,
            },
        )
    }

    fn base_config(doppelganger: bool) -> Config {
        Config {
            doppelganger_detection: doppelganger,
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        }
    }

    /// Default (doppelganger on): machine present, registered key gate-closed.
    #[tokio::test]
    async fn test_wire_signing_enablement_returns_fail_closed_machine_by_default() {
        // genesis_time = 0 → high current epoch (not epoch-0 bypass).
        let (_server, beacon) = mock_beacon(0).await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        let handles =
            wire_signing_enablement(&base_config(true), &keys, &beacon, slashing_db, &executor)
                .await
                .expect("phase succeeds with empty index resolution");

        assert!(
            handles.forward_window_machine.is_some(),
            "doppelganger on must construct ForwardWindowMachine"
        );
        assert!(
            !handles.signing_enablement.is_signing_enabled(&pk),
            "registered key at epoch>0 must be fail-closed before liveness window"
        );
        // Unregistered key also closed.
        let other = SecretKey::generate().public_key();
        assert!(
            !handles.signing_enablement.is_signing_enabled(&other),
            "unregistered key must be fail-closed"
        );
        executor.token().cancel();
    }

    #[tokio::test]
    async fn test_wire_signing_enablement_optout_yields_always_enabled() {
        let (_server, beacon) = mock_beacon(0).await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        let handles =
            wire_signing_enablement(&base_config(false), &keys, &beacon, slashing_db, &executor)
                .await
                .expect("opt-out phase succeeds");

        assert!(handles.forward_window_machine.is_none());
        assert!(handles.liveness_task.is_none());
        assert!(handles.signing_enablement.is_signing_enabled(&pk));
        let other = SecretKey::generate().public_key();
        assert!(
            handles.signing_enablement.is_signing_enabled(&other),
            "opt-out enables every pubkey"
        );
        executor.token().cancel();
    }

    #[tokio::test]
    async fn test_clock_before_genesis_does_not_mark_boot_keys_safe() {
        // Genesis far in the future → the clock saturates to epoch 0.
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let far_future = now.saturating_add(
            SLOT_DURATION_MS.saturating_mul(SLOTS_PER_EPOCH).saturating_mul(100) / 1000,
        );
        let (_server, beacon) = mock_beacon(far_future).await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        let handles =
            wire_signing_enablement(&base_config(true), &keys, &beacon, slashing_db, &executor)
                .await
                .expect("pre-genesis phase succeeds");

        assert_eq!(handles.epoch_clock.current_epoch(), 0);
        assert!(handles.epoch_clock.before_genesis());
        assert!(
            !handles.signing_enablement.is_signing_enabled(&pk),
            "a clock before genesis must not mark boot keys Safe"
        );
        let machine = handles.forward_window_machine.expect("machine present");
        assert_eq!(machine.status(&pk), ForwardWindowStatus::Pending);
        executor.token().cancel();
    }

    #[tokio::test]
    async fn test_epoch0_after_genesis_still_bypasses() {
        // Thirty seconds after genesis is still epoch 0 (one epoch is 384s at 12s slots).
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let genesis = now.saturating_sub(30);
        let (_server, beacon) = mock_beacon(genesis).await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        let handles =
            wire_signing_enablement(&base_config(true), &keys, &beacon, slashing_db, &executor)
                .await
                .expect("epoch-0 phase succeeds");

        assert_eq!(handles.epoch_clock.current_epoch(), 0);
        assert!(!handles.epoch_clock.before_genesis());
        assert!(
            handles.signing_enablement.is_signing_enabled(&pk),
            "epoch 0 after genesis still marks a boot key Safe"
        );
        let machine = handles.forward_window_machine.expect("machine present");
        assert_eq!(machine.status(&pk), ForwardWindowStatus::Safe);
        executor.token().cancel();
    }

    fn syncing_body(head_slot: &str) -> String {
        format!(
            r#"{{"data":{{"head_slot":"{head_slot}","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}}}"#
        )
    }

    async fn mount_validators(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"data": []})))
            .mount(server)
            .await;
    }

    async fn beacon_with_syncing(
        genesis_time: u64,
        servers: &[(MockServer, Option<String>)],
    ) -> BeaconHandles {
        for (server, body) in servers {
            mount_validators(server).await;
            if let Some(body) = body {
                Mock::given(method("GET"))
                    .and(path("/eth/v1/node/syncing"))
                    .respond_with(ResponseTemplate::new(200).set_body_string(body))
                    .mount(server)
                    .await;
            } else {
                Mock::given(method("GET"))
                    .and(path("/eth/v1/node/syncing"))
                    .respond_with(ResponseTemplate::new(500).set_body_string("down"))
                    .mount(server)
                    .await;
            }
        }
        let nodes: Vec<String> = servers.iter().map(|(server, _)| server.uri()).collect();
        let config = Config {
            beacon_url: nodes[0].clone(),
            beacon_nodes: nodes,
            disable_keystore_locking: true,
            allow_fresh_db: true,
            ..Default::default()
        };
        let builder = ServiceBuilder::new(config);
        let beacon_client = builder.build_beacon().expect("beacon client");
        let bn_manager = builder
            .build_bn_manager_with_timeouts(OperationTimeouts::default())
            .expect("bn manager");
        BeaconHandles {
            beacon_client,
            bn_manager,
            genesis_validators_root: GVR,
            genesis_validators_root_hex: format!("0x{}", hex::encode(GVR)),
            genesis_time,
            slot_duration_ms: 12_000,
            genesis_confirmed: true,
        }
    }

    async fn epoch0_enabled(beacon: &BeaconHandles) -> bool {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let handles =
            wire_signing_enablement(&base_config(true), &keys, beacon, slashing_db, &executor)
                .await
                .expect("epoch-0 phase");
        let enabled = handles.signing_enablement.is_signing_enabled(&pk);
        let status = handles.forward_window_machine.expect("machine").status(&pk);
        executor.token().cancel();
        assert_eq!(enabled, status == ForwardWindowStatus::Safe);
        enabled
    }

    /// A beacon head outside epoch 0, or a head query that fails, closes the bypass.
    #[tokio::test]
    async fn test_epoch0_bypass_requires_beacon_head_in_epoch_zero() {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let genesis = now.saturating_sub(30);

        let late = MockServer::start().await;
        let late_beacon = beacon_with_syncing(genesis, &[(late, Some(syncing_body("40")))]).await;
        assert!(!epoch0_enabled(&late_beacon).await, "a head at slot 40 is outside epoch 0");

        let boundary = MockServer::start().await;
        let boundary_beacon =
            beacon_with_syncing(genesis, &[(boundary, Some(syncing_body("32")))]).await;
        assert!(!epoch0_enabled(&boundary_beacon).await, "slot SLOTS_PER_EPOCH is epoch 1");

        let inside = MockServer::start().await;
        let inside_beacon =
            beacon_with_syncing(genesis, &[(inside, Some(syncing_body("31")))]).await;
        assert!(epoch0_enabled(&inside_beacon).await, "slot 31 is still epoch 0");

        let broken = MockServer::start().await;
        let broken_beacon = beacon_with_syncing(genesis, &[(broken, None)]).await;
        assert!(!epoch0_enabled(&broken_beacon).await, "a head-query error means no bypass");

        let garbled = MockServer::start().await;
        mount_validators(&garbled).await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"nope","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .mount(&garbled)
            .await;
        let garbled_beacon = {
            let config = Config {
                beacon_url: garbled.uri(),
                beacon_nodes: vec![garbled.uri()],
                disable_keystore_locking: true,
                allow_fresh_db: true,
                ..Default::default()
            };
            let builder = ServiceBuilder::new(config);
            BeaconHandles {
                beacon_client: builder.build_beacon().expect("beacon"),
                bn_manager: builder
                    .build_bn_manager_with_timeouts(OperationTimeouts::default())
                    .expect("manager"),
                genesis_validators_root: GVR,
                genesis_validators_root_hex: format!("0x{}", hex::encode(GVR)),
                genesis_time: genesis,
                slot_duration_ms: 12_000,
                genesis_confirmed: true,
            }
        };
        assert!(!epoch0_enabled(&garbled_beacon).await, "a non-numeric head_slot means no bypass");

        let early = MockServer::start().await;
        let far = MockServer::start().await;
        let split = beacon_with_syncing(
            genesis,
            &[(early, Some(syncing_body("0"))), (far, Some(syncing_body("40")))],
        )
        .await;
        assert!(!epoch0_enabled(&split).await, "every admitted All-role head must be in epoch 0");

        let head_zero = MockServer::start().await;
        let head_error = MockServer::start().await;
        let mixed = beacon_with_syncing(
            genesis,
            &[(head_zero, Some(syncing_body("0"))), (head_error, None)],
        )
        .await;
        assert!(!epoch0_enabled(&mixed).await, "one head error closes the epoch-0 bypass");
    }

    /// The pre-genesis log is emitted only when the clock is in epoch 0.
    ///
    /// A beacon head still inside epoch 0 is not enough once the clock has
    /// left epoch 0: `epoch0_bypass` stays false, the key stays Pending, and
    /// the startup line is absent.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_epoch0_bypass_log_only_at_epoch_zero() {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let late_genesis = now.saturating_sub(10_000);
        let (_late_server, late_beacon) = mock_beacon(late_genesis).await;
        let pk = SecretKey::generate().public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let late = wire_signing_enablement(
            &base_config(true),
            &keys,
            &late_beacon,
            Arc::new(SlashingDb::open_in_memory().unwrap()),
            &executor,
        )
        .await
        .expect("clock past epoch 0");
        assert_ne!(late.epoch_clock.current_epoch(), 0);
        assert!(!late.epoch_clock.before_genesis());
        assert!(
            !logs_contain("pre-genesis (epoch 0) startup"),
            "past epoch 0 the startup line is absent"
        );
        assert!(!late.signing_enablement.is_signing_enabled(&pk));
        executor.token().cancel();

        let genesis = now.saturating_sub(30);
        let (_server, beacon) = mock_beacon(genesis).await;
        let pk0 = SecretKey::generate().public_key();
        let keys0 = loaded_keys_with_pubkey(pk0.clone());
        let (executor0, _rx0) = TaskExecutor::new(CancellationToken::new());
        let early = wire_signing_enablement(
            &base_config(true),
            &keys0,
            &beacon,
            Arc::new(SlashingDb::open_in_memory().unwrap()),
            &executor0,
        )
        .await
        .expect("epoch 0");
        assert_eq!(early.epoch_clock.current_epoch(), 0);
        assert!(!early.epoch_clock.before_genesis());
        assert!(logs_contain("pre-genesis (epoch 0) startup"));
        assert!(early.signing_enablement.is_signing_enabled(&pk0));
        executor0.token().cancel();
    }

    /// Restart safe-skip requires local slashing history under this GVR.
    #[tokio::test]
    async fn test_wire_signing_enablement_restart_safe_skip_requires_local_history() {
        let (_server, beacon) = mock_beacon(0).await;
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let pk_hex = hex::encode(pk.to_bytes());
        let keys = loaded_keys_with_pubkey(pk.clone());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        // Without history: Pending (no safe-skip).
        {
            let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
            slashing_db.set_genesis_validators_root(&GVR).unwrap();
            let handles =
                wire_signing_enablement(&base_config(true), &keys, &beacon, slashing_db, &executor)
                    .await
                    .expect("phase");
            assert!(
                !handles.signing_enablement.is_signing_enabled(&pk),
                "no local history → no restart safe-skip"
            );
        }

        // With recent local history: Safe on boot register.
        {
            let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
            slashing_db.set_genesis_validators_root(&GVR).unwrap();
            let epoch = MonotonicEpochClock::new(0, 12_000).current_epoch();
            assert!(epoch > 2, "test needs epoch > monitoring window");
            let target = epoch - 1;
            slashing_db
                .check_and_record_attestation(&pk_hex, target.saturating_sub(1), target, None, &GVR)
                .expect("seed recent attestation");
            assert_eq!(
                SlashingDbReader::last_signed_attestation(slashing_db.as_ref(), &pk_hex, &GVR),
                Some(target)
            );

            let handles =
                wire_signing_enablement(&base_config(true), &keys, &beacon, slashing_db, &executor)
                    .await
                    .expect("phase with history");
            assert!(
                handles.signing_enablement.is_signing_enabled(&pk),
                "recent local attestation under GVR → restart safe-skip → Safe"
            );
        }
        executor.token().cancel();
    }

    #[tokio::test]
    async fn test_liveness_task_cancels_on_shutdown_token() {
        let (_server, beacon) = mock_beacon(0).await;
        // Non-empty pubkey map so the loop starts (empty indices + pubkeys path).
        let sk = SecretKey::generate();
        let keys = loaded_keys_with_pubkey(sk.public_key());
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        let handles =
            wire_signing_enablement(&base_config(true), &keys, &beacon, slashing_db, &executor)
                .await
                .expect("phase");

        assert!(handles.liveness_task.is_some(), "liveness loop should spawn with pubkeys");
        assert!(
            executor.registered_names().contains(&"liveness_loop"),
            "liveness_loop must be registered on the executor"
        );
        // Loop must observe cancellation and exit without hanging.
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            executor.shutdown(crate::bootstrap::executor::TierBudget::default()),
        )
        .await
        .expect("liveness task must terminate on shutdown token");
        assert!(
            outcome.joined.contains(&"liveness_loop") || outcome.aborted.contains(&"liveness_loop"),
            "liveness_loop must drain"
        );
    }

    /// Sanity: empty keystore path still produces a usable enablement handle.
    #[tokio::test]
    async fn test_wire_signing_enablement_empty_keys_ok() {
        let (_server, beacon) = mock_beacon(0).await;
        let keys = empty_loaded_keys();
        let slashing_db = Arc::new(SlashingDb::open_in_memory().unwrap());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());

        let handles =
            wire_signing_enablement(&base_config(true), &keys, &beacon, slashing_db, &executor)
                .await
                .expect("empty keys ok");

        assert!(handles.forward_window_machine.is_some());
        assert!(handles.liveness_task.is_some(), "a zero-key boot still starts the liveness loop");
        assert!(handles.pubkey_index.read().is_empty());
        // Fail-closed for any random key.
        let other = SecretKey::generate().public_key();
        assert!(!handles.signing_enablement.is_signing_enabled(&other));
        // Silence unused import warning paths
        let _ = Signer::public_keys(keys.composite_signer.as_ref());

        let machine = handles.forward_window_machine.clone().expect("machine");
        executor.token().cancel();
        tokio::time::timeout(
            Duration::from_secs(5),
            executor.shutdown(crate::bootstrap::executor::TierBudget::default()),
        )
        .await
        .expect("liveness loop stops before the import is registered");

        let pk = SecretKey::generate().public_key();
        let epoch = 40u64;
        machine.register_for_import(&pk, epoch);
        assert_eq!(machine.status(&pk), ForwardWindowStatus::Pending);
        let bare = hex::encode(pk.to_bytes());
        let sample = doppelganger::ValidatorLivenessData { index: bare, is_live: false };
        for offset in 0..3 {
            let counted = epoch + 1 + offset;
            assert!(
                machine
                    .observe_liveness(
                        counted,
                        std::slice::from_ref(&sample),
                        counted + 1,
                        doppelganger::CLOSED_EPOCH_SLOT,
                    )
                    .is_empty(),
                "closed epoch {counted}"
            );
        }
        assert_eq!(
            machine.status(&pk),
            ForwardWindowStatus::Safe,
            "register_for_import reaches Safe after 3 closed not-live epochs"
        );
    }

    /// WARN events as `target field=value…`, for one test.
    struct Warns(Arc<std::sync::Mutex<Vec<String>>>);

    struct WarnText<'a>(&'a mut String);

    impl tracing::field::Visit for WarnText<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            use std::fmt::Write;
            let _ = write!(self.0, " {}={value:?}", field.name());
        }
    }

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Warns {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            if *event.metadata().level() == tracing::Level::WARN {
                let mut line = event.metadata().target().to_string();
                event.record(&mut WarnText(&mut line));
                self.0.lock().expect("warn log").push(line);
            }
        }
    }

    /// `mock_beacon` whose `validators` route answers 503.
    async fn mock_beacon_validators_503() -> (MockServer, BeaconHandles) {
        let (server, beacon) = mock_beacon(0).await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(503))
            .with_priority(1)
            .mount(&server)
            .await;
        (server, beacon)
    }

    /// #655 AC5: a boot `get_validators` error with doppelganger off warns, and boot goes on.
    #[tokio::test]
    async fn boot_get_validators_err_with_doppelganger_off_warns() {
        use tracing_subscriber::layer::SubscriberExt;

        let (_server, beacon) = mock_beacon_validators_503().await;
        let keys = loaded_keys_with_pubkey(SecretKey::generate().public_key());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let warns = Arc::new(std::sync::Mutex::new(Vec::new()));
        let capture = tracing_subscriber::registry().with(Warns(Arc::clone(&warns)));
        let guard = tracing::subscriber::set_default(capture);

        let handles = wire_signing_enablement(
            &base_config(false),
            &keys,
            &beacon,
            Arc::new(SlashingDb::open_in_memory().unwrap()),
            &executor,
        )
        .await
        .expect("a boot get_validators error with doppelganger off does not stop boot");
        drop(guard);

        assert!(handles.pubkey_index.read().is_empty());
        let warns = warns.lock().expect("warn log").clone();
        let named: Vec<_> = warns
            .iter()
            .filter(|line| line.starts_with("rvc::") && line.contains("index resolver"))
            .collect();
        assert_eq!(named.len(), 1, "one rvc WARN naming the resolver: {warns:?}");
        assert!(
            named[0].contains(
                "validator index resolution failed at boot; \
                 duties stay empty until the index resolver succeeds"
            ) && named[0].contains(" error="),
            "{named:?}"
        );
        executor.token().cancel();
    }

    /// With doppelganger off, a boot `Ok` answer still fills the registry.
    #[tokio::test]
    async fn boot_indices_with_doppelganger_off_reach_the_registry() {
        let (server, beacon) = mock_beacon(0).await;
        let pk = SecretKey::generate().public_key();
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": [{
                    "index": "5",
                    "status": "active_ongoing",
                    "validator": { "pubkey": pubkey_bytes_to_0x(&pk.to_bytes()) }
                }]
            })))
            .with_priority(1)
            .mount(&server)
            .await;
        let keys = loaded_keys_with_pubkey(pk.clone());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let handles = wire_signing_enablement(
            &base_config(false),
            &keys,
            &beacon,
            Arc::new(SlashingDb::open_in_memory().unwrap()),
            &executor,
        )
        .await
        .expect("doppelganger-off boot");
        assert_eq!(handles.pubkey_index.read().index_of(&pk.to_bytes()), Some("5"));
        executor.token().cancel();
    }

    /// Releases a held `validators` responder when dropped, also on a failed assert.
    struct ReleaseOnDrop(std::sync::mpsc::Sender<()>);

    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }

    /// A `validators` answer that blocks wiremock's server thread until released.
    struct HeldValidators {
        arrived: tokio::sync::mpsc::UnboundedSender<()>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
        body: serde_json::Value,
    }

    impl wiremock::Respond for HeldValidators {
        fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
            let _ = self.arrived.send(());
            let _ = self.release.lock().expect("release channel").recv();
            ResponseTemplate::new(200).set_body_json(self.body.clone())
        }
    }

    fn validators_body(pubkey: &crypto::PublicKey, index: &str) -> serde_json::Value {
        serde_json::json!({
            "data": [{
                "index": index,
                "status": "active_ongoing",
                "validator": { "pubkey": pubkey_bytes_to_0x(&pubkey.to_bytes()) }
            }]
        })
    }

    /// A revocation during the boot index fetch leaves the registry stale, and
    /// the resolver's first pass revalidates it.
    ///
    /// Node 1 is revoked while node 0 holds the answer: the pool keeps node 0's
    /// answer, and the process revocation generation still moves.
    #[tokio::test]
    async fn boot_fetch_straddling_a_bump_starts_stale() {
        use crate::index_resolver::{IndexResolver, IndexResolverDeps};
        use crate::pubkey_index::RegistryFreshness;
        use bn_manager::MockBeaconNodeClient;

        let (server, mut beacon) = mock_beacon(0).await;
        let revoked = MockServer::start().await;
        let pool = Config {
            beacon_url: server.uri(),
            beacon_nodes: vec![server.uri(), revoked.uri()],
            ..base_config(false)
        };
        beacon.bn_manager = ServiceBuilder::new(pool)
            .build_bn_manager_with_timeouts(OperationTimeouts::default())
            .expect("two-node pool");
        let pk = SecretKey::generate().public_key();
        let (arrived_tx, mut arrived) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release = ReleaseOnDrop(release_tx);
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(HeldValidators {
                arrived: arrived_tx,
                release: std::sync::Mutex::new(release_rx),
                body: validators_body(&pk, "5"),
            })
            .with_priority(1)
            .mount(&server)
            .await;
        let keys = loaded_keys_with_pubkey(pk.clone());
        let config = base_config(false);
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let revoke_during_fetch = async {
            arrived.recv().await.expect("the boot validators request arrives");
            beacon.bn_manager.testing_revoke_admission(1);
            drop(release);
        };
        let boot = wire_signing_enablement(
            &config,
            &keys,
            &beacon,
            Arc::new(SlashingDb::open_in_memory().unwrap()),
            &executor,
        );
        let (handles, ()) = tokio::join!(boot, revoke_during_fetch);
        let handles = handles.expect("boot");
        let registry = Arc::clone(&handles.pubkey_index);
        assert_eq!(registry.read().index_of(&pk.to_bytes()), Some("5"));
        assert_eq!(
            registry.read().freshness(),
            RegistryFreshness::Stale,
            "attached under the generation sampled before the fetch"
        );

        let answer = validators_body(&pk, "9");
        let revalidating = MockBeaconNodeClient::new().with_get_validators(move |_| {
            Ok(serde_json::from_value(answer.clone()).expect("body"))
        });
        let (key_gen_tx, key_gen_rx) = tokio::sync::watch::channel(0u64);
        let mut resolver = IndexResolver::new(
            IndexResolverDeps {
                registry: Arc::clone(&registry),
                pubkey_map: Arc::clone(&handles.pubkey_map),
                beacon: Arc::new(revalidating),
                key_gen_tx,
                key_gen_rx,
                epoch_clock: Arc::clone(&handles.epoch_clock),
            },
            executor.token(),
        );
        resolver.drive_once_for_test(0).await;
        assert_eq!(registry.read().index_of(&pk.to_bytes()), Some("9"));
        assert_eq!(registry.read().freshness(), RegistryFreshness::Fresh(1));
        executor.token().cancel();
    }

    /// Boots one key with detection on and genesis time 0. The beacon head is slot 31.
    ///
    /// The boot reads its epoch from a `ClockSeam` that starts at epoch 0.
    /// The test holds the `validators` answer until the coordinator releases it.
    /// Before the release, the coordinator sets the seam to `epoch_at_release`
    /// when it is `Some`.
    async fn boot_across_held_validators(
        epoch_at_release: Option<Epoch>,
    ) -> (Arc<ForwardWindowMachine>, crypto::PublicKey) {
        use crate::liveness_loop::ClockSeam;

        let servers = [(MockServer::start().await, Some(syncing_body("31")))];
        let beacon = beacon_with_syncing(0, &servers).await;
        let (arrived_tx, mut arrived) = tokio::sync::mpsc::unbounded_channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let release = ReleaseOnDrop(release_tx);
        Mock::given(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(HeldValidators {
                arrived: arrived_tx,
                release: std::sync::Mutex::new(release_rx),
                body: serde_json::json!({ "data": [] }),
            })
            .with_priority(1)
            .mount(&servers[0].0)
            .await;
        let seam = ClockSeam::new(0, 0);
        let reader = Arc::clone(&seam);
        let pk = SecretKey::generate().public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let config = base_config(true);
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let boot = wire_signing_enablement_with_boot_epoch(
            &config,
            &keys,
            &beacon,
            Arc::new(SlashingDb::open_in_memory().expect("The in-memory slashing DB must open.")),
            &executor,
            Arc::new(move || reader.epoch()),
        );
        let coordinator = async {
            arrived.recv().await.expect("The boot must send the validators request.");
            if let Some(epoch) = epoch_at_release {
                seam.set_epoch(epoch);
            }
            drop(release);
        };
        // Hang guard only. The channels set the order, not this timeout.
        let (handles, ()) = tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(boot, coordinator)
        })
        .await
        .expect("The boot must not stop at the held validators answer.");
        let machine = handles
            .expect("The boot must succeed.")
            .forward_window_machine
            .expect("Detection on must give a forward-window machine.");
        executor.token().cancel();
        (machine, pk)
    }

    /// The boot moves from epoch 0 into epoch 1 while the test holds the
    /// `validators` answer.
    ///
    /// The epoch read after the last boot await is 1. Thus the boot must close
    /// the epoch-0 bypass and register the key Pending at epoch 1.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn epoch0_bypass_closes_when_boot_crosses_into_epoch_one() {
        let (machine, pk) = boot_across_held_validators(Some(1)).await;
        assert_eq!(
            machine.status(&pk),
            ForwardWindowStatus::Pending,
            "A boot that moves into epoch 1 must not mark the key Safe."
        );
        assert_eq!(
            machine.pending_keys(),
            vec![doppelganger::PendingKey {
                pubkey_hex: hex::encode(pk.to_bytes()),
                next_check_epoch: 1,
            }],
            "The key must register with the epoch that the boot reads after the last await."
        );
        assert!(
            !logs_contain("pre-genesis (epoch 0) startup"),
            "A boot that moves into epoch 1 must not log the pre-genesis line."
        );
    }

    /// The boot stays in epoch 0 while the test holds the `validators` answer.
    ///
    /// The epoch read after the last boot await is still 0. Thus the boot must
    /// keep the epoch-0 bypass and mark the key Safe.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn epoch0_bypass_holds_when_boot_stays_in_epoch_zero() {
        let (machine, pk) = boot_across_held_validators(None).await;
        assert_eq!(
            machine.status(&pk),
            ForwardWindowStatus::Safe,
            "A boot that stays in epoch 0 must mark the key Safe."
        );
        assert!(
            logs_contain("pre-genesis (epoch 0) startup"),
            "A boot that stays in epoch 0 must log the pre-genesis line."
        );
    }

    /// A boot that starts in epoch 1 does not ask the beacon node for heads.
    ///
    /// The read before the boot awaits decides if the boot sends a
    /// `/eth/v1/node/syncing` request.
    #[tokio::test]
    async fn boot_outside_epoch_zero_sends_no_syncing_request() {
        let (server, beacon) = mock_beacon(0).await;
        let pk = SecretKey::generate().public_key();
        let keys = loaded_keys_with_pubkey(pk.clone());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let handles = wire_signing_enablement_with_boot_epoch(
            &base_config(true),
            &keys,
            &beacon,
            Arc::new(SlashingDb::open_in_memory().expect("The in-memory slashing DB must open.")),
            &executor,
            Arc::new(|| 1),
        )
        .await
        .expect("The boot must succeed.");
        executor.token().cancel();
        let paths: Vec<String> = server
            .received_requests()
            .await
            .expect("The mock beacon must record the requests.")
            .iter()
            .map(|request| request.url.path().to_string())
            .collect();
        assert!(
            paths.iter().any(|path| path == "/eth/v1/beacon/states/head/validators"),
            "The boot must send the validators request: {paths:?}"
        );
        assert!(
            paths.iter().all(|path| path != "/eth/v1/node/syncing"),
            "A boot that starts in epoch 1 must not send a syncing request: {paths:?}"
        );
        let machine = handles
            .forward_window_machine
            .expect("Detection on must give a forward-window machine.");
        assert_eq!(machine.status(&pk), ForwardWindowStatus::Pending);
    }

    /// The epoch-0 bypass needs a confirmed genesis.
    ///
    /// The boot stays in epoch 0 and the beacon head is slot 0 in both rows.
    /// Only the row with a confirmed genesis gets Safe.
    #[tokio::test]
    async fn epoch0_bypass_needs_confirmed_genesis() {
        for (confirmed, expected) in
            [(true, ForwardWindowStatus::Safe), (false, ForwardWindowStatus::Pending)]
        {
            let (_server, mut beacon) = mock_beacon(0).await;
            beacon.genesis_confirmed = confirmed;
            let pk = SecretKey::generate().public_key();
            let keys = loaded_keys_with_pubkey(pk.clone());
            let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
            let handles = wire_signing_enablement_with_boot_epoch(
                &base_config(true),
                &keys,
                &beacon,
                Arc::new(
                    SlashingDb::open_in_memory().expect("The in-memory slashing DB must open."),
                ),
                &executor,
                Arc::new(|| 0),
            )
            .await
            .expect("The boot must succeed.");
            executor.token().cancel();
            let machine = handles
                .forward_window_machine
                .expect("Detection on must give a forward-window machine.");
            assert_eq!(
                machine.status(&pk),
                expected,
                "With genesis_confirmed {confirmed}, the epoch-0 boot key must be {expected:?}."
            );
        }
    }

    /// With detection on, an empty index answer gives the pending-activation WARN.
    /// Only a boot with detection off gives the disabled-detection WARN.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn boot_warnings_follow_the_detection_setting() {
        let (_server, beacon) = mock_beacon(0).await;
        let keys = loaded_keys_with_pubkey(SecretKey::generate().public_key());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let db = || {
            Arc::new(SlashingDb::open_in_memory().expect("The in-memory slashing DB must open."))
        };

        wire_signing_enablement(&base_config(true), &keys, &beacon, db(), &executor)
            .await
            .expect("The boot with detection on must succeed.");
        assert!(
            logs_contain("No validator indices resolved"),
            "An empty index answer with detection on must give the pending-activation WARN."
        );
        assert!(
            !logs_contain("Doppelganger detection is disabled"),
            "A boot with detection on must not give the disabled-detection WARN."
        );

        wire_signing_enablement(&base_config(false), &keys, &beacon, db(), &executor)
            .await
            .expect("The boot with detection off must succeed.");
        assert!(
            logs_contain("Doppelganger detection is disabled"),
            "A boot with detection off must give the disabled-detection WARN."
        );
        executor.token().cancel();
    }

    /// Every boot mode that goes on, by doppelganger detection on or off. The
    /// detection-on `Err` with keys present returns from boot, so it has no
    /// registry to follow.
    #[derive(Debug, Clone, Copy)]
    enum ContinuingBoot {
        OnIndexed,
        OnUnindexed,
        OnNoKeys,
        OffIndexed,
        OffUnindexed,
        OffResolveErr,
    }

    /// In each continuing mode the registry follows the revocation generation:
    /// fresh (not untracked) after boot, and hidden after a post-boot revocation.
    #[tokio::test]
    async fn every_continuing_boot_mode_attaches_the_revocation_generation() {
        use crate::pubkey_index::{PubkeyIndexSource, RegistryFreshness};
        use duty_tracker::ValidatorIndexSource;
        use ContinuingBoot::*;

        for mode in [OnIndexed, OnUnindexed, OnNoKeys, OffIndexed, OffUnindexed, OffResolveErr] {
            let detection = matches!(mode, OnIndexed | OnUnindexed | OnNoKeys);
            let indexed = matches!(mode, OnIndexed | OffIndexed);
            let (server, beacon) = if matches!(mode, OffResolveErr) {
                mock_beacon_validators_503().await
            } else {
                mock_beacon(0).await
            };
            let pk = SecretKey::generate().public_key();
            if indexed {
                Mock::given(method("GET"))
                    .and(path("/eth/v1/beacon/states/head/validators"))
                    .respond_with(
                        ResponseTemplate::new(200).set_body_json(validators_body(&pk, "5")),
                    )
                    .with_priority(1)
                    .mount(&server)
                    .await;
            }
            let keys = if matches!(mode, OnNoKeys) {
                empty_loaded_keys()
            } else {
                loaded_keys_with_pubkey(pk)
            };
            let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
            let handles = wire_signing_enablement(
                &base_config(detection),
                &keys,
                &beacon,
                Arc::new(SlashingDb::open_in_memory().unwrap()),
                &executor,
            )
            .await
            .unwrap_or_else(|e| panic!("{mode:?}: boot goes on: {e}"));
            let registry = Arc::clone(&handles.pubkey_index);
            let source = PubkeyIndexSource {
                registry: Arc::clone(&registry),
                pubkey_map: Arc::clone(&handles.pubkey_map),
            };
            let booted: Vec<String> = if indexed { vec!["5".to_string()] } else { Vec::new() };

            assert_eq!(registry.read().freshness(), RegistryFreshness::Fresh(0), "{mode:?}");
            let attached = registry.read().revocation_commit();
            let owned = beacon.bn_manager.revocation_commit().expect("BnManager has a commit lock");
            assert!(
                attached.is_some_and(|attached| Arc::ptr_eq(&attached, &owned)),
                "{mode:?}: boot attaches the BnManager's commit lock"
            );
            assert_eq!(source.indices(), booted, "{mode:?}");
            beacon.bn_manager.testing_revoke_admission(0);
            assert_eq!(
                registry.read().freshness(),
                RegistryFreshness::Stale,
                "{mode:?}: a revocation after boot makes the registry stale"
            );
            assert_eq!(source.indices(), Vec::<String>::new(), "{mode:?}: and hides its indices");
            executor.token().cancel();
        }
    }

    /// The same boot error with doppelganger on and keys present still fails closed.
    #[tokio::test]
    async fn boot_get_validators_err_with_doppelganger_on_fails_closed() {
        let (_server, beacon) = mock_beacon_validators_503().await;
        let keys = loaded_keys_with_pubkey(SecretKey::generate().public_key());
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let result = wire_signing_enablement(
            &base_config(true),
            &keys,
            &beacon,
            Arc::new(SlashingDb::open_in_memory().unwrap()),
            &executor,
        )
        .await;
        assert!(matches!(result, Err(BootstrapError::IndexResolution(_))));
        executor.token().cancel();
    }

    /// BN `SLOT_DURATION_MS=6000` and genesis 10 epochs ago at 6 s slots.
    ///
    /// A clock that still divides by 12 s reports epoch 5 for the same instant.
    #[tokio::test]
    async fn test_six_second_beacon_spec_reports_epoch_ten() {
        use crate::bootstrap::connect_beacon;

        let server = MockServer::start().await;
        let gvr = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let genesis = now - 10 * 192 - 96;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "genesis_time": genesis.to_string(),
                    "genesis_validators_root": gvr,
                    "genesis_fork_version": "0x00000000"
                }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"data":{{"SLOT_DURATION_MS":"6000","SLOTS_PER_EPOCH":"32",{}}}}}"#,
                bn_manager::MAINNET_FORK_SPEC_FIELDS
            )))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "version": "mock-bn/rf5-04" }
            })))
            .mount(&server)
            .await;

        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("slashing.db");
        let db = SlashingDb::open(&db_path).unwrap();
        let mut config = base_config(true);
        config.beacon_url = server.uri();
        config.beacon_nodes = vec![server.uri()];
        config.network = crate::config::Network::Custom;
        config.genesis_validators_root = Some(gvr.to_string());
        config.genesis_time = Some(genesis);
        config.slashing_db_path = db_path;
        config.allow_fresh_db = true;
        config.disable_keystore_locking = true;

        let beacon =
            connect_beacon(&config, OperationTimeouts::default(), &db).await.expect("connect");
        assert_eq!(beacon.slot_duration_ms, 6_000);

        let keys = empty_loaded_keys();
        let (executor, _rx) = TaskExecutor::new(CancellationToken::new());
        let handles = wire_signing_enablement(
            &config,
            &keys,
            &beacon,
            Arc::new(SlashingDb::open_in_memory().unwrap()),
            &executor,
        )
        .await
        .expect("enablement");
        assert_eq!(handles.epoch_clock.slot_duration_ms(), 6_000);
        assert_eq!(handles.epoch_clock.current_epoch(), 10);
        executor.token().cancel();
    }
}
