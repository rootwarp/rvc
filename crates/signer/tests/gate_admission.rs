//! W4-S4c (750-9, 751-4): `SigningGate` reports a moved beacon admission as
//! [`SigningGateError::BeaconAdmissionRevoked`], and checks doppelganger
//! before admission at entry.
//!
//! An entry refusal returns before the per-validator lock, so the gate's lock
//! map stays empty. The under-lock check would refuse with the same variant,
//! so the empty map is what proves the entry check refused.

mod common;

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use crypto::{PublicKey, SecretKey, Signature, Signer, SigningError};
use doppelganger::SigningEnablement;
use eth_types::Root;
use rvc_signer::{
    classify, require_beacon_admission_scope, with_beacon_admission, BeaconAdmission, SigningGate,
    SigningGateError, ValidatorLockMap,
};
use slashing::SlashingDb;

const GVR: Root = [0xc4; 32];

/// Hang guard for the parked sign's join. Not an ordering wait.
const JOIN_GUARD: Duration = Duration::from_secs(30);

/// Local BLS backend that counts its calls.
struct CountingSigner {
    inner: common::SucceedingSigner,
    calls: AtomicUsize,
}

#[async_trait]
impl Signer for CountingSigner {
    async fn sign(&self, root: &Root, pubkey: &[u8; 48]) -> Result<Signature, SigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.sign(root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.inner.public_keys()
    }
}

/// Detection closed signing for every key.
struct Detected;

impl SigningEnablement for Detected {
    fn is_signing_enabled(&self, _pubkey: &PublicKey) -> bool {
        false
    }

    fn voluntary_exit_only(&self) -> bool {
        false
    }

    fn blocked_by_doppelganger(&self, _pubkey: &PublicKey) -> bool {
        true
    }
}

struct Fixture {
    pubkey: PublicKey,
    gate: Arc<SigningGate>,
    db: Arc<SlashingDb>,
    locks: Arc<ValidatorLockMap>,
    signer: Arc<CountingSigner>,
}

impl Fixture {
    fn new(enablement: Arc<dyn SigningEnablement>) -> Self {
        let sk = SecretKey::generate();
        let pubkey = sk.public_key();
        let signer = Arc::new(CountingSigner {
            inner: common::SucceedingSigner::new(sk),
            calls: AtomicUsize::new(0),
        });
        let db = common::open_db();
        let locks = Arc::new(ValidatorLockMap::new());
        let gate = Arc::new(SigningGate::new_with_raw_signer(
            Arc::clone(&db),
            enablement,
            Arc::clone(&signer) as Arc<dyn Signer>,
            Arc::clone(&locks),
            Duration::from_secs(4),
        ));
        Self { pubkey, gate, db, locks, signer }
    }

    fn bls_calls(&self) -> usize {
        self.signer.calls.load(Ordering::SeqCst)
    }

    /// Block rows plus attestation rows for the fixture's key.
    fn rows(&self) -> usize {
        let pubkey_hex = hex::encode(self.pubkey.to_bytes());
        self.db.get_blocks(&pubkey_hex).expect("block rows").len()
            + self.db.get_attestations(&pubkey_hex).expect("attestation rows").len()
    }

    /// Assert a refusal at entry: no BLS call, no row, lock map untouched.
    fn assert_refused_at_entry(&self, duty: Duty) {
        assert_eq!(self.bls_calls(), 0, "{duty:?}: no BLS call");
        assert_eq!(self.rows(), 0, "{duty:?}: no slashing row");
        assert!(self.locks.is_empty(), "{duty:?}: refused before the per-validator lock");
    }
}

/// One variant per `SigningGate` sign method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Duty {
    Block,
    Attestation,
    SyncCommitteeMessage,
    AggregateAndProof,
    PayloadAttestation,
    ProposerPreferences,
    ContributionAndProof,
    SelectionProof,
    SyncCommitteeSelectionProof,
    RandaoReveal,
    VoluntaryExit,
    BuilderRegistration,
    BuilderRequestAuth,
    ExecutionPayloadEnvelope,
}

impl Duty {
    /// Every `SigningGate` sign method, in `gate.rs` order.
    const ALL: [Self; 14] = [
        Self::Block,
        Self::Attestation,
        Self::SyncCommitteeMessage,
        Self::AggregateAndProof,
        Self::PayloadAttestation,
        Self::ProposerPreferences,
        Self::ContributionAndProof,
        Self::SelectionProof,
        Self::SyncCommitteeSelectionProof,
        Self::RandaoReveal,
        Self::VoluntaryExit,
        Self::BuilderRegistration,
        Self::BuilderRequestAuth,
        Self::ExecutionPayloadEnvelope,
    ];
}

async fn sign(
    gate: &SigningGate,
    pubkey: &PublicKey,
    duty: Duty,
) -> Result<Vec<u8>, SigningGateError> {
    let root = [0x05; 32];
    match duty {
        Duty::Block => gate.sign_block(pubkey, 64, [0x01; 32], GVR, "test").await,
        Duty::Attestation => gate.sign_attestation(pubkey, 3, 4, [0x02; 32], GVR, "test").await,
        Duty::SyncCommitteeMessage => gate.sign_sync_committee_message(pubkey, [0x03; 32]).await,
        Duty::AggregateAndProof => gate.sign_aggregate_and_proof(pubkey, root).await,
        Duty::PayloadAttestation => gate.sign_payload_attestation(pubkey, root).await,
        Duty::ProposerPreferences => gate.sign_proposer_preferences(pubkey, root).await,
        Duty::ContributionAndProof => gate.sign_contribution_and_proof(pubkey, root).await,
        Duty::SelectionProof => gate.sign_selection_proof(pubkey, root).await,
        Duty::SyncCommitteeSelectionProof => {
            gate.sign_sync_committee_selection_proof(pubkey, root).await
        }
        Duty::RandaoReveal => gate.sign_randao_reveal(pubkey, root).await,
        Duty::VoluntaryExit => gate.sign_voluntary_exit(pubkey, [0x04; 32]).await,
        Duty::BuilderRegistration => gate.sign_builder_registration(pubkey, root).await,
        Duty::BuilderRequestAuth => gate.sign_builder_request_auth(pubkey, root).await,
        Duty::ExecutionPayloadEnvelope => gate.sign_execution_payload_envelope(pubkey, root).await,
    }
}

/// A scope whose only generation has already moved.
fn moved_admission() -> BeaconAdmission {
    let generation = Arc::new(AtomicU64::new(0));
    let admission = BeaconAdmission::new(0, Arc::clone(&generation));
    generation.fetch_add(1, Ordering::Release);
    admission
}

#[derive(Clone, Default)]
struct LogBuf(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for LogBuf {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Run `fut` under a thread-local WARN subscriber and return its WARN lines.
///
/// The default `#[tokio::test]` runtime is current-thread, so the subscriber
/// sees every event the gate logs on its way to an entry refusal.
async fn with_warns<T>(fut: impl std::future::Future<Output = T>) -> (T, Vec<String>) {
    let logs = LogBuf::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::WARN)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    let out = fut.await;
    drop(guard);
    let text = String::from_utf8(logs.0.lock().expect("log buffer").clone()).expect("utf8");
    let warns = text.lines().filter(|line| line.contains("WARN")).map(str::to_string).collect();
    (out, warns)
}

/// Exactly one WARN, the entry refusal, naming `reason` and not `other`, with
/// the pubkey truncated.
fn assert_one_entry_warn(
    duty: Duty,
    warns: &[String],
    reason: &str,
    other: &str,
    pubkey: &PublicKey,
) {
    assert_eq!(warns.len(), 1, "{duty:?}: one entry WARN, got {warns:?}");
    let warn = &warns[0];
    assert!(
        warn.contains("refused at entry") && warn.contains(reason) && !warn.contains(other),
        "{duty:?}: the entry WARN must name {reason:?}: {warn}"
    );
    assert!(
        !warn.contains(&hex::encode(pubkey.to_bytes())),
        "{duty:?}: the entry WARN must not log the full pubkey: {warn}"
    );
}

/// 751-4 (mutant R5): a moved admission at the gate's entry is reported as
/// `BeaconAdmissionRevoked`, not as a doppelganger block, and the one entry
/// WARN names that reason. This holds for every `SigningGate` method except
/// `sign_voluntary_exit`, which needs no admission and signs.
#[tokio::test]
async fn signing_gate_refuses_a_moved_admission() {
    for duty in Duty::ALL {
        let fx = Fixture::new(common::always_allowed());

        let (result, warns) =
            with_warns(with_beacon_admission(moved_admission(), sign(&fx.gate, &fx.pubkey, duty)))
                .await;

        if duty == Duty::VoluntaryExit {
            assert!(result.is_ok(), "{duty:?}: needs no admission and signs: {result:?}");
            assert_eq!(fx.bls_calls(), 1, "{duty:?}: one BLS call");
            assert!(warns.is_empty(), "{duty:?}: no WARN, got {warns:?}");
            continue;
        }
        assert!(
            matches!(result, Err(SigningGateError::BeaconAdmissionRevoked)),
            "{duty:?}: expected BeaconAdmissionRevoked, got {result:?}"
        );
        fx.assert_refused_at_entry(duty);
        assert_one_entry_warn(
            duty,
            &warns,
            "beacon node admission revoked",
            "doppelganger",
            &fx.pubkey,
        );
    }
}

/// 751-4: the non-slashable entry reports the moved admission as its own
/// error. The doppelganger re-check inside the non-slashable core is not an
/// admission check, so the entry is the only one on this path.
#[tokio::test]
async fn signing_gate_refuses_a_moved_admission_for_a_non_slashable_duty() {
    let fx = Fixture::new(common::always_allowed());
    let duty = Duty::SyncCommitteeMessage;

    let (result, warns) =
        with_warns(with_beacon_admission(moved_admission(), sign(&fx.gate, &fx.pubkey, duty)))
            .await;

    assert!(
        matches!(result, Err(SigningGateError::BeaconAdmissionRevoked)),
        "expected BeaconAdmissionRevoked, got {result:?}"
    );
    fx.assert_refused_at_entry(duty);
    assert_one_entry_warn(
        duty,
        &warns,
        "beacon node admission revoked",
        "doppelganger",
        &fx.pubkey,
    );
}

/// A voluntary exit needs no beacon admission, so a moved scope still signs.
#[tokio::test]
async fn signing_gate_signs_a_voluntary_exit_under_a_moved_admission() {
    let fx = Fixture::new(common::always_allowed());

    let result =
        with_beacon_admission(moved_admission(), sign(&fx.gate, &fx.pubkey, Duty::VoluntaryExit))
            .await;

    assert!(result.is_ok(), "a voluntary exit must sign: {result:?}");
    assert_eq!(fx.bls_calls(), 1, "one BLS call for the exit");
}

/// #736 contract at the gate's entry: a detected key reports
/// `BlockedByDoppelganger` even when its admission also moved.
#[tokio::test]
async fn signing_gate_doppelganger_wins_over_a_moved_admission() {
    for duty in [Duty::Block, Duty::Attestation, Duty::SyncCommitteeMessage] {
        let fx = Fixture::new(Arc::new(Detected));

        let (result, warns) =
            with_warns(with_beacon_admission(moved_admission(), sign(&fx.gate, &fx.pubkey, duty)))
                .await;

        assert!(
            matches!(result, Err(SigningGateError::BlockedByDoppelganger)),
            "{duty:?}: expected BlockedByDoppelganger, got {result:?}"
        );
        fx.assert_refused_at_entry(duty);
        assert_one_entry_warn(duty, &warns, "doppelganger", "admission", &fx.pubkey);
    }
}

/// The production missing-scope rule, opted into under `test-utils`, refuses
/// at the gate's entry with the admission error.
#[tokio::test]
async fn signing_gate_refuses_a_missing_scope_when_opted_in() {
    for duty in [Duty::Attestation, Duty::SyncCommitteeMessage] {
        let fx = Fixture::new(common::always_allowed());

        let result = require_beacon_admission_scope(sign(&fx.gate, &fx.pubkey, duty)).await;

        assert!(
            matches!(result, Err(SigningGateError::BeaconAdmissionRevoked)),
            "{duty:?}: expected BeaconAdmissionRevoked, got {result:?}"
        );
        fx.assert_refused_at_entry(duty);
    }
}

/// #939 (Harper N3, RSA N5): a generation that moves while the sign waits for
/// the per-validator lock is refused under the lock with the same error, and
/// the same transport class, as a refusal at entry.
///
/// Current-thread: the sign task runs from its entry check to the lock wait
/// without yielding, so the test resumes only once it is parked. An armed
/// commit failure would turn any reservation into `CommitFailed`.
#[tokio::test(flavor = "current_thread")]
async fn signing_gate_under_lock_admission_refusal_matches_the_entry_refusal() {
    let at_entry = Fixture::new(common::always_allowed());
    let entry = with_beacon_admission(
        moved_admission(),
        sign(&at_entry.gate, &at_entry.pubkey, Duty::Attestation),
    )
    .await
    .expect_err("refused at entry");
    at_entry.assert_refused_at_entry(Duty::Attestation);

    let fx = Fixture::new(common::always_allowed());
    let pubkey_bytes = fx.pubkey.to_bytes();
    let generation = Arc::new(AtomicU64::new(0));
    let admission = BeaconAdmission::new(0, Arc::clone(&generation));
    let held = fx.locks.lock(&pubkey_bytes).await;
    let handles = || Arc::strong_count(&fx.locks.get(&pubkey_bytes));
    let before = handles();
    let parked = Arc::new(tokio::sync::Notify::new());
    let fired = Arc::clone(&parked);
    let (gate, pubkey) = (Arc::clone(&fx.gate), fx.pubkey.clone());
    let join = tokio::spawn(async move {
        fired.notify_one();
        with_beacon_admission(admission, sign(&gate, &pubkey, Duty::Attestation)).await
    });
    parked.notified().await;
    assert_eq!(handles(), before + 1, "the sign must be parked on the held per-validator lock");

    generation.fetch_add(1, Ordering::Release);
    fx.db.fail_next_commits(1);
    drop(held);
    let under_lock = tokio::time::timeout(JOIN_GUARD, join)
        .await
        .expect("the parked sign returns")
        .expect("join")
        .expect_err("refused under the lock");

    assert!(
        matches!(entry, SigningGateError::BeaconAdmissionRevoked),
        "entry: expected BeaconAdmissionRevoked, got {entry:?}"
    );
    assert!(
        matches!(under_lock, SigningGateError::BeaconAdmissionRevoked),
        "under the lock: expected BeaconAdmissionRevoked, got {under_lock:?}"
    );
    assert_eq!(classify(&under_lock), classify(&entry), "one transport class for both refusals");
    assert_eq!(fx.bls_calls(), 0, "no BLS call");
    assert_eq!(fx.rows(), 0, "no slashing row");
}
