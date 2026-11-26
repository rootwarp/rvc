//! W4-E8b-signer (#881, #1043 B1): the sign-start gate of `SignerService`.
//!
//! The gate checks the store gate and then the beacon admission just before
//! the backend call, and again when the backend returns. Each test orders its
//! change with a parked barrier or a held backend, not with a sleep.
//!
//! - A change before the backend start stops the sign with no backend call.
//! - A change during the backend sign lets the backend finish. The caller
//!   gets the refusal error and no signature. A slashable row stays.

mod common;

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use crypto::{PublicKey, SecretKey, Signature, Signer, SigningError};
use eth_types::{ForkSchedule, Root};
use rvc_signer::{
    with_beacon_admission, BeaconAdmission, PreReserveBarrier, SignerError, SignerService,
    SigningDuty, StoreGate, ValidatorSigner,
};
use slashing::SlashingDb;
use tokio::sync::Notify;

const GVR: Root = [0x5c; 32];
const SLOT: u64 = 70;

/// Hang guard for the join of a sign task. It does not set the order of events.
const JOIN_GUARD: Duration = Duration::from_secs(30);

type Sign = tokio::task::JoinHandle<Result<Signature, SignerError>>;

async fn join(sign: Sign) -> Result<Signature, SignerError> {
    tokio::time::timeout(JOIN_GUARD, sign).await.expect("hang guard").expect("join")
}

/// Parks a caller until the test releases it.
#[derive(Default)]
struct Park {
    entered: Notify,
    release: Notify,
}

#[async_trait]
impl PreReserveBarrier for Park {
    async fn wait(&self) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

impl Park {
    /// Wait for the parked caller, run `change`, then release the caller.
    async fn change_then_join(
        &self,
        sign: Sign,
        change: impl FnOnce(),
    ) -> Result<Signature, SignerError> {
        self.entered.notified().await;
        change();
        self.release.notify_one();
        join(sign).await
    }
}

/// The BLS backend: it counts its calls and can hold them on a [`Park`].
struct HeldBackend {
    inner: Arc<dyn Signer>,
    calls: AtomicUsize,
    hold: Mutex<Option<Arc<Park>>>,
}

#[async_trait]
impl Signer for HeldBackend {
    async fn sign(&self, root: &Root, pubkey: &[u8; 48]) -> Result<Signature, SigningError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let hold = self.hold.lock().expect("hold").clone();
        if let Some(park) = hold {
            park.wait().await;
        }
        self.inner.sign(root, pubkey).await
    }

    fn public_keys(&self) -> Vec<[u8; 48]> {
        self.inner.public_keys()
    }
}

struct Fixture {
    pubkey: PublicKey,
    service: Arc<SignerService>,
    backend: Arc<HeldBackend>,
    db: Arc<SlashingDb>,
    /// The validator store flag that the store gate reads.
    enabled: Arc<AtomicBool>,
    /// Each duty that the store gate got, in sequence.
    gate_calls: Arc<Mutex<Vec<SigningDuty>>>,
    generation: Arc<AtomicU64>,
}

impl Fixture {
    fn new() -> Self {
        let (pubkey, composite) = common::composite_with_key(SecretKey::generate());
        let backend = Arc::new(HeldBackend {
            inner: Arc::clone(&composite) as Arc<dyn Signer>,
            calls: AtomicUsize::new(0),
            hold: Mutex::new(None),
        });
        let enabled = Arc::new(AtomicBool::new(true));
        let gate_calls = Arc::new(Mutex::new(Vec::new()));
        let store_gate: StoreGate = {
            let enabled = Arc::clone(&enabled);
            let gate_calls = Arc::clone(&gate_calls);
            Arc::new(move |_pubkey: &[u8; 48], duty: SigningDuty| {
                gate_calls.lock().expect("gate calls").push(duty);
                enabled.load(Ordering::SeqCst)
            })
        };
        let db = common::open_db();
        let service = Arc::new(
            SignerService::new(composite, Arc::clone(&db))
                .with_enablement(common::always_allowed())
                .with_sign_backend(Arc::clone(&backend) as Arc<dyn Signer>)
                .with_sign_timeout(JOIN_GUARD)
                .with_store_gate(store_gate),
        );
        let generation = Arc::new(AtomicU64::new(0));
        Self { pubkey, service, backend, db, enabled, gate_calls, generation }
    }

    fn set_store(&self, enabled: bool) {
        self.enabled.store(enabled, Ordering::SeqCst);
    }

    fn revoke_admission(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    fn backend_calls(&self) -> usize {
        self.backend.calls.load(Ordering::SeqCst)
    }

    fn block_rows(&self) -> usize {
        self.db.get_blocks(&hex::encode(self.pubkey.to_bytes())).expect("block rows").len()
    }

    /// Hold each later backend call on a new [`Park`].
    fn hold_backend(&self) -> Arc<Park> {
        let park = Arc::new(Park::default());
        *self.backend.hold.lock().expect("hold") = Some(Arc::clone(&park));
        park
    }

    /// Park the next non-slashable sign after its entry and doppelganger checks.
    fn park_before_the_start(&self) -> Arc<Park> {
        let park = Arc::new(Park::default());
        self.service.set_nonslashable_barrier(Some(park.clone()));
        park
    }

    /// Park the next slashable sign under its lock, before the reservation.
    fn park_before_the_reservation(&self) -> Arc<Park> {
        let park = Arc::new(Park::default());
        self.service.set_pre_reserve_barrier(Some(park.clone()));
        park
    }

    /// Spawn `sign` under an admission scope of the fixture's generation.
    fn spawn<F>(&self, sign: impl FnOnce(Arc<SignerService>, PublicKey) -> F) -> Sign
    where
        F: Future<Output = Result<Signature, SignerError>> + Send + 'static,
    {
        let admission = BeaconAdmission::new(0, Arc::clone(&self.generation));
        let fut = sign(Arc::clone(&self.service), self.pubkey.clone());
        tokio::spawn(with_beacon_admission(admission, fut))
    }

    fn selection_proof(&self) -> Sign {
        self.spawn(|service, pubkey| async move {
            service.sign_selection_proof(SLOT, &pubkey, &schedule(), &GVR).await
        })
    }

    fn block(&self) -> Sign {
        self.spawn(|service, pubkey| async move {
            service.sign_block(&[0x21; 32], SLOT, &pubkey, &schedule(), &GVR).await
        })
    }

    fn envelope(&self, slot: u64) -> Sign {
        self.spawn(move |service, pubkey| async move {
            let gloas = ForkSchedule { gloas_fork_epoch: 0, ..schedule() };
            service
                .sign_execution_payload_envelope_root(&[0x41; 32], slot, &pubkey, &gloas, &GVR)
                .await
        })
    }
}

/// Fulu from epoch 0. The envelope sign sets Gloas from epoch 0.
fn schedule() -> ForkSchedule {
    ForkSchedule::unscheduled_gloas()
}

/// Control: with no change, each path signs. The store gate gets the duty of
/// the sign before and after each backend call.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_path_signs_when_the_store_gate_and_the_admission_hold() {
    let fx = Fixture::new();

    join(fx.selection_proof()).await.expect("the selection proof must sign");
    join(fx.block()).await.expect("the block must sign");

    assert_eq!(fx.backend_calls(), 2, "each sign must call the backend one time");
    assert_eq!(
        *fx.gate_calls.lock().expect("gate calls"),
        [
            SigningDuty::SelectionProof,
            SigningDuty::SelectionProof,
            SigningDuty::Block,
            SigningDuty::Block
        ],
        "the store gate must get the duty before and after each backend call"
    );
}

/// Non-slashable: the store disables the key after the entry check and
/// before the backend start. The signer refuses the selection proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_before_the_backend_start_gets_no_selection_proof() {
    let fx = Fixture::new();
    let park = fx.park_before_the_start();
    let result = park.change_then_join(fx.selection_proof(), || fx.set_store(false)).await;

    assert_eq!(fx.backend_calls(), 0, "the signer must not call the backend for a disabled key");
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "the caller must get the store refusal, got {result:?}"
    );
}

/// Non-slashable: the admission moves after the entry check and before the
/// backend start. The signer refuses the selection proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admission_revoked_before_the_backend_start_gets_no_selection_proof() {
    let fx = Fixture::new();
    let park = fx.park_before_the_start();
    let result = park.change_then_join(fx.selection_proof(), || fx.revoke_admission()).await;

    assert_eq!(fx.backend_calls(), 0, "the signer must not call the backend after a revocation");
    assert!(
        matches!(result, Err(SignerError::BeaconAdmissionRevoked)),
        "the caller must get the admission refusal, got {result:?}"
    );
}

/// Non-slashable: the store disables the key during the backend sign. The
/// backend finishes, and the caller gets no signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_during_the_backend_sign_gets_no_selection_proof() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let result = park.change_then_join(fx.selection_proof(), || fx.set_store(false)).await;

    assert_eq!(fx.backend_calls(), 1, "the backend sign in progress must finish");
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "the caller must get the store refusal and no signature, got {result:?}"
    );
}

/// Non-slashable: the admission moves during the backend sign. The backend
/// finishes, and the caller gets no signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admission_revoked_during_the_backend_sign_gets_no_selection_proof() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let result = park.change_then_join(fx.selection_proof(), || fx.revoke_admission()).await;

    assert_eq!(fx.backend_calls(), 1, "the backend sign in progress must finish");
    assert!(
        matches!(result, Err(SignerError::BeaconAdmissionRevoked)),
        "the caller must get the admission refusal and no signature, got {result:?}"
    );
}

/// A store refusal before the backend start releases the envelope slot. A
/// later sign of the slot can start when the store enables the key again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn envelope_refused_before_the_backend_start_releases_the_slot() {
    let fx = Fixture::new();
    fx.set_store(false);
    let refused = join(fx.envelope(3)).await;
    assert!(
        matches!(refused, Err(SignerError::BlockedByDoppelganger)),
        "a closed store gate must refuse the envelope, got {refused:?}"
    );

    fx.set_store(true);
    join(fx.envelope(3)).await.expect("the released slot must sign");
    assert_eq!(fx.backend_calls(), 1, "only the second envelope sign must call the backend");
}

/// A signature dropped after the backend returned keeps the envelope slot:
/// the backend has signed for that slot.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn envelope_dropped_after_the_backend_returned_keeps_the_slot() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let dropped = park.change_then_join(fx.envelope(4), || fx.set_store(false)).await;
    assert!(
        matches!(dropped, Err(SignerError::BlockedByDoppelganger)),
        "the caller must get the store refusal and no signature, got {dropped:?}"
    );

    *fx.backend.hold.lock().expect("hold") = None;
    fx.set_store(true);
    let again = join(fx.envelope(4)).await;
    assert!(
        matches!(again, Err(SignerError::EnvelopeSlotAlreadySigned { slot: 4 })),
        "the slot of a dropped signature must stay reserved, got {again:?}"
    );
    assert_eq!(fx.backend_calls(), 1, "the signer must not call the backend for a reserved slot");
}

/// Slashable: the store disables the key before the reservation. The check
/// after the reservation refuses the block with no backend call, and the row
/// stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_before_the_backend_start_gets_no_block_and_keeps_the_row() {
    let fx = Fixture::new();
    let park = fx.park_before_the_reservation();
    let result = park.change_then_join(fx.block(), || fx.set_store(false)).await;

    assert_eq!(fx.backend_calls(), 0, "the signer must not call the backend for a disabled key");
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "the caller must get the store refusal, got {result:?}"
    );
    assert_eq!(fx.block_rows(), 1, "the store refusal after the reservation must keep the row");
}

/// Slashable: the store disables the key during the backend sign. The signer
/// drops the block signature, and the row stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_during_the_backend_sign_gets_no_block_and_keeps_the_row() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let result = park.change_then_join(fx.block(), || fx.set_store(false)).await;

    assert_eq!(fx.backend_calls(), 1, "the backend sign in progress must finish");
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "the caller must get the store refusal and no signature, got {result:?}"
    );
    assert_eq!(fx.block_rows(), 1, "a signature dropped after the backend must keep the row");
}

/// Slashable: the admission moves during the backend sign. The signer drops
/// the block signature, and the row stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admission_revoked_during_the_backend_sign_gets_no_block_and_keeps_the_row() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let result = park.change_then_join(fx.block(), || fx.revoke_admission()).await;

    assert_eq!(fx.backend_calls(), 1, "the backend sign in progress must finish");
    assert!(
        matches!(result, Err(SignerError::BeaconAdmissionRevoked)),
        "the caller must get the admission refusal and no signature, got {result:?}"
    );
    assert_eq!(fx.block_rows(), 1, "a signature dropped after the backend must keep the row");
}
