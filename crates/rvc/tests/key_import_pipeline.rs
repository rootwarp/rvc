//! RF1-08: key-import → duty-cache integration + doppelganger enablement gate.
//!
//! Proves the RF1-06/07 wiring end-to-end:
//! - Import via `KeystoreManagerAdapter` updates the shared `PubkeyMap` and
//!   fires `key_gen_tx`, so the orchestrator clears its duty cache without a
//!   restart and the new key participates in duty matching.
//! - A newly imported key registered with `ForwardWindowMachine` produces
//!   **no attestation signatures** until the forward window clears; after it
//!   clears, the same pipeline emits a signature.
//!
//! Assertions are on emitted signatures (via [`RecordingSubmitter`]), not logs.
//! Epoch advancement uses the machine's injectable `register_for_import` /
//! `observe_liveness` / `tick` API — no wall-clock sleep.

mod common;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use common::pipeline_fixture::{
    make_beacon_attestation_data, pipeline_fixture, PipelineFixtureOpts, SLOTS_PER_EPOCH, SLOT_A,
    SLOT_B,
};
use crypto::{EncryptionKdf, Keystore, SecretKey};
use doppelganger::{ForwardWindowMachine, SigningEnablement, ValidatorLivenessData};
use eth_types::{Epoch, Root};
use keymanager_api::traits::{DoppelgangerMonitor, KeystoreManager};
use rvc::keymanager_adapters::{ForwardWindowMonitor, KeystoreManagerAdapter};
use slashing::{SlashingDb, SlashingDbReader};
use tokio::sync::watch;
use validator_store::ValidatorConfig;

const PASSWORD: &str = "rf1-08-testpass";
const FAR_EPOCH: u64 = 50;
const FAR_SLOT: u64 = FAR_EPOCH * SLOTS_PER_EPOCH;
/// Import-time epoch for forward-window tests (slot 100 → epoch 3).
const IMPORT_EPOCH: Epoch = 3;
const MONITORING_EPOCHS: u64 = 1;

fn gvr() -> Root {
    [0xaa; 32]
}

fn encrypt_keystore(sk: &SecretKey) -> String {
    let keystore = Keystore::encrypt(
        sk,
        PASSWORD.as_bytes(),
        "m/12381/3600/0/0/0",
        EncryptionKdf::scrypt_cheap_for_tests(),
    )
    .expect("encrypt keystore");
    serde_json::to_string(&keystore).expect("serialize keystore")
}

/// Observe every epoch in `[start, end]` as complete and not-live, then tick
/// past the satisfaction boundary so the validator becomes Safe.
fn clear_forward_window(machine: &ForwardWindowMachine, pubkey: &crypto::PublicKey, start: Epoch) {
    let end = start.saturating_add(MONITORING_EPOCHS);
    let pubkey_hex = hex::encode(pubkey.to_bytes());
    for epoch in start..=end {
        let samples = vec![ValidatorLivenessData { index: pubkey_hex.clone(), is_live: false }];
        machine.observe_liveness(epoch, &samples).expect("complete observation");
    }
    // Past-boundary tick with full observation → Safe.
    machine.tick(end + 1, 0);
    assert!(
        machine.is_signing_enabled(pubkey),
        "window must be clear after observe+tick past end_epoch"
    );
}

fn default_att_map() -> HashMap<u64, beacon::AttestationData> {
    let mut map = HashMap::new();
    map.insert(SLOT_A, make_beacon_attestation_data(SLOT_A, 2, 0x22, 0x33, 0x11));
    map.insert(SLOT_B, make_beacon_attestation_data(SLOT_B, 2, 0x22, 0x44, 0x11));
    map
}

/// RF1-08: importing a keystore notifies the orchestrator, clears a **stale**
/// duty cache, and only then lets the imported key participate in duty matching.
///
/// Causal coupling (F1):
/// 1. Prefetch epoch 3 with duties for a *different* (stale) pubkey.
/// 2. Import the real key into map + signer; flip the mock BN to serve the
///    imported identity on subsequent fetches.
/// 3. `process_slot` **without** cache clear still uses the stale epoch cache →
///    duties filter to empty → no signature.
/// 4. `run()` applies `key_gen` invalidation → clear + refetch → one signature.
///
/// A regression that updates the map but skips cache clear fails step 4's
/// signature assert (stale duties never match). A regression that never
/// notifies `key_gen` also leaves FAR_EPOCH cached.
#[tokio::test(flavor = "current_thread")]
async fn test_imported_key_clears_duty_cache_without_restart() {
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let keystore_json = encrypt_keystore(&secret_key);
    let pubkey_hex_0x = format!("0x{}", hex::encode(pubkey.to_bytes()));
    let pubkey_bytes = pubkey.to_bytes();

    // Pre-import "stale" duty identity — not the key we will import.
    let stale_pk = SecretKey::generate().public_key();
    let stale_hex_0x = format!("0x{}", hex::encode(stale_pk.to_bytes()));

    let (key_gen_tx, key_gen_rx) = watch::channel(0u64);

    // duty_identity seeds fixture hex fields; we immediately override the BN
    // to serve the stale pubkey so the pre-import cache cannot match import.
    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot: default_att_map(),
        duty_slots: vec![SLOT_A, SLOT_B, FAR_SLOT],
        initial_slot: SLOT_A,
        key_gen_rx: Some(key_gen_rx),
        preload_signing_key: false,
        duty_identity: Some(pubkey.clone()),
        ..Default::default()
    });
    fixture.beacon.set_duty_pubkey(stale_hex_0x);

    let current_epoch = SLOT_A / SLOTS_PER_EPOCH;

    // Seed a stale current-epoch duty set *and* a far-future marker epoch.
    fixture
        .duty_tracker
        .fetch_duties_for_epoch(current_epoch)
        .await
        .expect("prefetch current epoch");
    fixture.duty_tracker.fetch_duties_for_epoch(FAR_EPOCH).await.expect("prefetch far epoch");
    assert!(
        fixture.duty_tracker.is_epoch_cached(current_epoch).await,
        "precondition: current epoch must be cached with stale duties"
    );
    assert!(
        fixture.duty_tracker.is_epoch_cached(FAR_EPOCH).await,
        "precondition: far-future epoch must be cached"
    );
    assert!(fixture.pubkey_map.read().is_empty(), "precondition: map empty before import");

    let dir = tempfile::tempdir().expect("tempdir");
    let adapter = KeystoreManagerAdapter::new(
        dir.path().to_path_buf(),
        Arc::clone(&fixture.composite_signer),
        Arc::clone(&fixture.pubkey_map),
        key_gen_tx,
    );

    adapter.import_keystore(&keystore_json, PASSWORD).expect("import keystore");

    assert!(
        fixture.pubkey_map.read().contains_key(&pubkey_bytes),
        "import must update the shared PubkeyMap"
    );
    assert!(
        fixture.composite_signer.has_local_key(&pubkey_bytes),
        "import must add the key to CompositeSigner"
    );

    // Future BN fetches (post clear) return the imported identity.
    fixture.beacon.set_duty_pubkey(pubkey_hex_0x.clone());

    // D-3 store gate open so a successful duty match can reach the signer.
    fixture.validator_store.add_validator(ValidatorConfig::new(pubkey_bytes)).unwrap();

    // ── Without cache clear: stale epoch cache cannot match the new key ────
    let blocked = fixture.process_slot(SLOT_A).await;
    assert!(
        matches!(blocked, Err(rvc::orchestrator::OrchestratorError::NoDutiesForSlot { .. })),
        "stale duty cache must yield no match for the imported key before clear; got {blocked:?}"
    );
    assert_eq!(
        fixture.submitter.signature_count(),
        0,
        "stale duty cache must emit no signature before key_gen clear"
    );
    assert!(
        fixture.duty_tracker.is_epoch_cached(current_epoch).await,
        "process_slot must not clear the duty cache (only key_gen path does)"
    );

    // ── With key_gen clear via run(): refetch + participate ────────────────
    // Park near end of slot so phase waits are short (mirrors RF1-07 unit test).
    fixture.clock.set_slot(SLOT_A);
    fixture.clock.advance_time(9);

    let duty_tracker = Arc::clone(&fixture.duty_tracker);
    let submitter = Arc::clone(&fixture.submitter);
    let submitter_watch = Arc::clone(&fixture.submitter);
    let handle = fixture.handle;
    let mut orchestrator = fixture.orchestrator;

    // Shut down once the cache-clear + participation path has produced a
    // signature (or after a generous bound). Prefer a progress signal over a
    // pure fixed sleep for the success path (review F3 residual).
    tokio::spawn(async move {
        for _ in 0..50 {
            if submitter_watch.signature_count() >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Small grace so run() can finish the slot before shutdown is observed.
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.shutdown();
    });

    let _ = orchestrator.run().await;

    assert!(
        !duty_tracker.is_epoch_cached(FAR_EPOCH).await,
        "import key_gen notification must clear the duty cache (far-future epoch gone)"
    );

    // Participation only after clear: BN now serves the imported identity and
    // the stale epoch entry was dropped, so run() refetched and signed.
    assert_eq!(
        submitter.signature_count(),
        1,
        "imported key must produce exactly one signature after key_gen clear \
         (stale cache blocked matching until clear+refetch)"
    );
}

/// RF1-08 gate: during the forward-window, an imported key produces **zero**
/// attestation signatures (asserted via the recording submitter).
#[tokio::test]
async fn test_imported_key_produces_no_attestations_during_doppelganger_window() {
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let keystore_json = encrypt_keystore(&secret_key);

    let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
    let reader: Arc<dyn SlashingDbReader> = Arc::clone(&slashing_db) as Arc<dyn SlashingDbReader>;
    let machine = Arc::new(ForwardWindowMachine::new(reader, MONITORING_EPOCHS, gvr()));

    // Injectable epoch clock (AtomicU64) — no wall sleep.
    let epoch_now = Arc::new(AtomicU64::new(IMPORT_EPOCH));
    let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> = {
        let epoch_now = Arc::clone(&epoch_now);
        Arc::new(move || epoch_now.load(Ordering::SeqCst))
    };
    let monitor = ForwardWindowMonitor::new(Arc::clone(&machine), epoch_provider);

    let (key_gen_tx, key_gen_rx) = watch::channel(0u64);

    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot: default_att_map(),
        duty_slots: vec![SLOT_A, SLOT_B],
        initial_slot: SLOT_A,
        enablement: Arc::clone(&machine) as Arc<dyn SigningEnablement>,
        slashing_db: Some(slashing_db),
        key_gen_rx: Some(key_gen_rx),
        preload_signing_key: false,
        duty_identity: Some(pubkey.clone()),
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let adapter = KeystoreManagerAdapter::new(
        dir.path().to_path_buf(),
        Arc::clone(&fixture.composite_signer),
        Arc::clone(&fixture.pubkey_map),
        key_gen_tx,
    );
    let pk_bytes = adapter.import_keystore(&keystore_json, PASSWORD).expect("import");
    // Mirror production keymanager handler: register import with the machine.
    monitor.start_monitoring(pk_bytes);

    assert!(
        !machine.is_signing_enabled(&pubkey),
        "imported key must be Pending (signing disabled) immediately after register_for_import"
    );

    // Store gate open so we reach SignerService enablement (the SEC-2 gate).
    fixture.validator_store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).unwrap();

    let results = fixture.process_slot(SLOT_A).await.expect("process_slot returns results");
    assert_eq!(results.len(), 1, "duty must be found for imported key");
    assert!(
        !results[0].success,
        "signing must fail while inside doppelganger window; error={:?}",
        results[0].error
    );
    let err = results[0].error.as_deref().unwrap_or("");
    // SignerError::BlockedByDoppelganger displays as
    // "signing blocked by doppelganger gate". Require "doppelganger" so an
    // unrelated sign failure (missing key, slashing, timeout) cannot pass.
    assert!(
        err.to_lowercase().contains("doppelganger"),
        "error must be the doppelganger enablement block, got: {err}"
    );

    // Hard assertion: absence of signature (not logs / internal flags).
    assert_eq!(
        fixture.submitter.signature_count(),
        0,
        "no attestation signature may be emitted during the doppelganger window"
    );
    assert_eq!(fixture.submitter.batch_count(), 0);
}

/// RF1-08 gate clear: after the forward window is fully observed and ticked
/// past its boundary (injectable epochs — no wall sleep), the imported key
/// produces an attestation signature.
#[tokio::test]
async fn test_imported_key_signs_after_doppelganger_window_clears() {
    let secret_key = SecretKey::generate();
    let pubkey = secret_key.public_key();
    let keystore_json = encrypt_keystore(&secret_key);

    let slashing_db = Arc::new(SlashingDb::open_in_memory().expect("slashing db"));
    let reader: Arc<dyn SlashingDbReader> = Arc::clone(&slashing_db) as Arc<dyn SlashingDbReader>;
    let machine = Arc::new(ForwardWindowMachine::new(reader, MONITORING_EPOCHS, gvr()));

    let epoch_now = Arc::new(AtomicU64::new(IMPORT_EPOCH));
    let epoch_provider: Arc<dyn Fn() -> Epoch + Send + Sync> = {
        let epoch_now = Arc::clone(&epoch_now);
        Arc::new(move || epoch_now.load(Ordering::SeqCst))
    };
    let monitor = ForwardWindowMonitor::new(Arc::clone(&machine), epoch_provider);

    let (key_gen_tx, key_gen_rx) = watch::channel(0u64);

    let fixture = pipeline_fixture(PipelineFixtureOpts {
        attestation_data_by_slot: default_att_map(),
        duty_slots: vec![SLOT_A, SLOT_B],
        initial_slot: SLOT_A,
        enablement: Arc::clone(&machine) as Arc<dyn SigningEnablement>,
        slashing_db: Some(slashing_db),
        key_gen_rx: Some(key_gen_rx),
        preload_signing_key: false,
        duty_identity: Some(pubkey.clone()),
    });

    let dir = tempfile::tempdir().expect("tempdir");
    let adapter = KeystoreManagerAdapter::new(
        dir.path().to_path_buf(),
        Arc::clone(&fixture.composite_signer),
        Arc::clone(&fixture.pubkey_map),
        key_gen_tx,
    );
    let pk_bytes = adapter.import_keystore(&keystore_json, PASSWORD).expect("import");
    monitor.start_monitoring(pk_bytes);
    fixture.validator_store.add_validator(ValidatorConfig::new(pubkey.to_bytes())).unwrap();

    // While Pending: no signature (guard against a broken enablement wire-up).
    let blocked = fixture.process_slot(SLOT_A).await.expect("process during window");
    assert!(!blocked[0].success, "must not sign during window: {:?}", blocked[0].error);
    assert_eq!(fixture.submitter.signature_count(), 0);

    // Advance the forward window deterministically (no wall sleep).
    clear_forward_window(&machine, &pubkey, IMPORT_EPOCH);
    epoch_now.store(IMPORT_EPOCH + MONITORING_EPOCHS + 1, Ordering::SeqCst);

    // After the window clears, the same imported key signs on a later slot.
    let results = fixture.process_slot(SLOT_B).await.expect("process after window");
    assert_eq!(results.len(), 1);
    assert!(
        results[0].success,
        "imported key must sign after doppelganger window clears; error={:?}",
        results[0].error
    );
    assert_eq!(
        fixture.submitter.signature_count(),
        1,
        "exactly one signature after window clears (zero during window + one after)"
    );
}
