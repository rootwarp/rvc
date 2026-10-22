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
/// Held as locals by the binary composition root until a future `run()` moves
/// selected fields into [`super::BootstrapCtx`] (at most three named fields per
/// the growth rule).
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
    let builder = ServiceBuilder::new(config.clone());
    let doppelganger_enabled = config.doppelganger_detection;

    // Shared monotonic epoch clock (M-7) for boot register + keymanager import
    // so NTP cannot compress the window and wall-clock alone cannot force epoch 0.
    let epoch_clock =
        Arc::new(MonotonicEpochClock::new(beacon.genesis_time, beacon.slot_duration_ms));
    let enablement_epoch = epoch_clock.current_epoch();
    // Named-network confirmation is not enough: a clock still before genesis
    // saturates to epoch 0 and must not take the Safe bypass. A head outside
    // epoch 0, or a head that cannot be read, closes it too.
    let epoch0_bypass = if doppelganger_enabled
        && beacon.genesis_confirmed
        && !epoch_clock.before_genesis()
        && enablement_epoch == 0
    {
        admitted_heads_in_epoch_zero(beacon.bn_manager.as_ref()).await
    } else {
        false
    };

    // Resolve validator indices into the shared registry (duty tracker + liveness
    // + prepare_proposers all share this handle).
    let beacon_for_resolve: &dyn BeaconNodeClient = beacon.bn_manager.as_ref();
    let pubkey_index = PubkeyIndexRegistry::shared();
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
    } else if let Ok(reg) = &resolve_result {
        // Duty-tracker indices: keep successful resolution even when doppelganger is off.
        pubkey_index.write().extend_from(reg);
    }

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
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "SLOT_DURATION_MS": "6000", "SLOTS_PER_EPOCH": "32" }
            })))
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
