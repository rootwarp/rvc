//! W4-E8b-signer (#881, #1043 B1): the sign-start gate of `SignerService`.
//!
//! The gate checks the beacon admission and then the store gate just before
//! the backend call, and again when the backend returns. Each test orders its
//! change with a parked barrier or a held backend, not with a sleep. One event
//! record keeps each store check, each change of the test, and the start and
//! the end of each backend call, in sequence.
//!
//! - A change before the backend starts stops the sign with no backend call.
//! - A change during the backend sign lets the backend finish. The caller
//!   gets the refusal error and no signature. A slashable row stays.

mod common;

use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use crypto::{PublicKey, SecretKey, Signature, Signer, SigningError};
use eth_types::{ForkSchedule, Root};
use rvc_signer::{
    with_beacon_admission, BeaconAdmission, PreReserveBarrier, SignerError, SignerService,
    SigningDuty, StoreGate, ValidatorSigner,
};
use slashing::{SigningRoot, SlashingDb};
use tokio::sync::Notify;
use Event::{Check, Disable, Enable, End, Revoke, Start};

const GVR: Root = [0x5c; 32];
const SLOT: u64 = 70;
const PROOF: SigningDuty = SigningDuty::SelectionProof;
const BLOCK: SigningDuty = SigningDuty::Block;
const ENVELOPE: SigningDuty = SigningDuty::ExecutionPayloadEnvelope;

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
    /// Wait for the parked caller, run `change`, then release the caller. A
    /// sign that ends before it parks fails the test at once.
    async fn change_then_join(
        &self,
        mut sign: Sign,
        change: impl FnOnce(),
    ) -> Result<Signature, SignerError> {
        tokio::select! {
            () = self.entered.notified() => {}
            ended = &mut sign => panic!("The sign must park, but it ended: {ended:?}."),
        }
        change();
        self.release.notify_one();
        join(sign).await
    }
}

/// Disables the key just after the start check, before the backend call.
struct DisableAfterStartCheck(Arc<Record>);

#[async_trait]
impl PreReserveBarrier for DisableAfterStartCheck {
    async fn wait(&self) {}

    fn after_start_check(&self) {
        self.0.set_store(false);
    }
}

/// One entry of the event record: a store check of a duty (`Check`), a change
/// of the test (`Disable`, `Enable`, `Revoke`), or the start or the end of a
/// backend call (`Start`, `End`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Check(SigningDuty),
    Disable,
    Enable,
    Revoke,
    Start,
    End,
}

/// The store flag, the admission generation and the event record. The store
/// gate, the backend and the test changes share it.
#[derive(Default)]
struct Record {
    disabled: AtomicBool,
    generation: Arc<AtomicU64>,
    events: Mutex<Vec<Event>>,
}

impl Record {
    fn push(&self, event: Event) {
        self.events.lock().expect("events").push(event);
    }

    fn set_store(&self, enabled: bool) {
        self.disabled.store(!enabled, Ordering::SeqCst);
        self.push(if enabled { Enable } else { Disable });
    }

    fn revoke_admission(&self) {
        self.generation.fetch_add(1, Ordering::Release);
        self.push(Revoke);
    }
}

/// The BLS backend: it records the start and the end of each call, and it can
/// hold a call on a [`Park`].
struct HeldBackend {
    inner: Arc<dyn Signer>,
    record: Arc<Record>,
    hold: Mutex<Option<Arc<Park>>>,
}

#[async_trait]
impl Signer for HeldBackend {
    async fn sign(&self, root: &Root, pubkey: &[u8; 48]) -> Result<Signature, SigningError> {
        self.record.push(Start);
        let hold = self.hold.lock().expect("hold").clone();
        if let Some(park) = hold {
            park.wait().await;
        }
        let signed = self.inner.sign(root, pubkey).await;
        self.record.push(End);
        signed
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
    record: Arc<Record>,
}

impl Fixture {
    fn new() -> Self {
        Self::build(true)
    }

    /// A service that gets no `with_store_gate`.
    fn without_store_gate() -> Self {
        Self::build(false)
    }

    fn build(with_store_gate: bool) -> Self {
        let (pubkey, composite) = common::composite_with_key(SecretKey::generate());
        let record = Arc::new(Record::default());
        let backend = Arc::new(HeldBackend {
            inner: Arc::clone(&composite) as Arc<dyn Signer>,
            record: Arc::clone(&record),
            hold: Mutex::new(None),
        });
        let store_gate: StoreGate = {
            let record = Arc::clone(&record);
            Arc::new(move |_pubkey: &[u8; 48], duty: SigningDuty| {
                record.push(Check(duty));
                !record.disabled.load(Ordering::SeqCst)
            })
        };
        let db = common::open_db();
        let service = SignerService::new(composite, Arc::clone(&db))
            .with_enablement(common::always_allowed())
            .with_sign_backend(Arc::clone(&backend) as Arc<dyn Signer>)
            .with_sign_timeout(JOIN_GUARD);
        let service =
            Arc::new(if with_store_gate { service.with_store_gate(store_gate) } else { service });
        Self { pubkey, service, backend, db, record }
    }

    fn set_store(&self, enabled: bool) {
        self.record.set_store(enabled);
    }

    fn revoke_admission(&self) {
        self.record.revoke_admission();
    }

    fn disable_and_revoke(&self) {
        self.set_store(false);
        self.revoke_admission();
    }

    /// Compare the full event record with `want`.
    #[track_caller]
    fn record_is(&self, want: &[Event], rule: &str) {
        assert_eq!(*self.record.events.lock().expect("events"), want, "{rule}");
    }

    /// The slot and the signing root of each block row of the key.
    fn block_rows(&self) -> Vec<(u64, Option<SigningRoot>)> {
        let rows = self.db.get_blocks(&hex::encode(self.pubkey.to_bytes())).expect("block rows");
        rows.into_iter().map(|row| (row.slot, row.signing_root)).collect()
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
        let admission = BeaconAdmission::new(0, Arc::clone(&self.record.generation));
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

/// The block row of a sign with no change. A refusal after the reservation
/// must keep this row.
async fn reserved_block_row() -> Vec<(u64, Option<SigningRoot>)> {
    let fx = Fixture::new();
    join(fx.block()).await.expect("The control block must sign.");
    let rows = fx.block_rows();
    assert!(matches!(rows.as_slice(), [(SLOT, Some(_))]), "The control has one row: {rows:?}.");
    rows
}

/// Control: with no change, each path signs. The store gate checks each duty
/// before the backend starts and after the backend ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_path_signs_when_the_store_gate_and_the_admission_hold() {
    let fx = Fixture::new();

    join(fx.selection_proof()).await.expect("The selection proof must sign.");
    join(fx.block()).await.expect("The block must sign.");

    fx.record_is(
        &[Check(PROOF), Start, End, Check(PROOF), Check(BLOCK), Start, End, Check(BLOCK)],
        "The store gate must check each duty before the backend starts and after it ends.",
    );
}

/// Non-slashable: the store disables the key after the entry check and
/// before the backend starts. The signer refuses the selection proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_before_the_backend_starts_gets_no_selection_proof() {
    let fx = Fixture::new();
    let park = fx.park_before_the_start();
    let result = park.change_then_join(fx.selection_proof(), || fx.set_store(false)).await;

    fx.record_is(&[Disable, Check(PROOF)], "The backend must not start for a disabled key.");
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "The caller must get the store refusal. The result was {result:?}."
    );
}

/// Non-slashable: the admission moves after the entry check and before the
/// backend starts. The signer refuses the selection proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admission_revoked_before_the_backend_starts_gets_no_selection_proof() {
    let fx = Fixture::new();
    let park = fx.park_before_the_start();
    let result = park.change_then_join(fx.selection_proof(), || fx.revoke_admission()).await;

    fx.record_is(&[Revoke], "The backend must not start after a revocation.");
    assert!(
        matches!(result, Err(SignerError::BeaconAdmissionRevoked)),
        "The caller must get the admission refusal. The result was {result:?}."
    );
}

/// Non-slashable: the store disables the key during the backend sign. The
/// backend finishes, and the caller gets no signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_during_the_backend_sign_gets_no_selection_proof() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let result = park.change_then_join(fx.selection_proof(), || fx.set_store(false)).await;

    fx.record_is(&[Check(PROOF), Start, Disable, End, Check(PROOF)], "The started sign must end.");
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "The caller must get the store refusal and no signature. The result was {result:?}."
    );
}

/// Non-slashable: the admission moves during the backend sign. The backend
/// finishes, and the caller gets no signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admission_revoked_during_the_backend_sign_gets_no_selection_proof() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let result = park.change_then_join(fx.selection_proof(), || fx.revoke_admission()).await;

    fx.record_is(&[Check(PROOF), Start, Revoke, End], "The started sign must end.");
    assert!(
        matches!(result, Err(SignerError::BeaconAdmissionRevoked)),
        "The caller must get the admission refusal and no signature. The result was {result:?}."
    );
}

/// A store refusal before the backend starts releases the envelope slot. A
/// later sign of the slot can start when the store enables the key again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn envelope_refused_before_the_backend_starts_releases_the_slot() {
    let fx = Fixture::new();
    fx.set_store(false);
    let refused = join(fx.envelope(3)).await;
    assert!(
        matches!(refused, Err(SignerError::BlockedByDoppelganger)),
        "The store gate must refuse the envelope. The result was {refused:?}."
    );

    fx.set_store(true);
    join(fx.envelope(3)).await.expect("The released slot must sign.");
    fx.record_is(
        &[Disable, Check(ENVELOPE), Enable, Check(ENVELOPE), Start, End, Check(ENVELOPE)],
        "Only the second envelope sign must start the backend.",
    );
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
        "The caller must get the store refusal and no signature. The result was {dropped:?}."
    );

    *fx.backend.hold.lock().expect("hold") = None;
    fx.set_store(true);
    let again = join(fx.envelope(4)).await;
    assert!(
        matches!(again, Err(SignerError::EnvelopeSlotAlreadySigned { slot: 4 })),
        "The slot of a dropped signature must stay reserved. The result was {again:?}."
    );
    fx.record_is(
        &[Check(ENVELOPE), Start, Disable, End, Check(ENVELOPE), Enable],
        "The signer must not call the backend for a reserved slot.",
    );
}

/// Slashable: the store disables the key before the reservation. The check
/// after the reservation refuses the block with no backend call, and the row
/// stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_before_the_backend_starts_gets_no_block_and_keeps_the_row() {
    let fx = Fixture::new();
    let park = fx.park_before_the_reservation();
    let result = park.change_then_join(fx.block(), || fx.set_store(false)).await;

    fx.record_is(&[Disable, Check(BLOCK)], "The backend must not start for a disabled key.");
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "The caller must get the store refusal. The result was {result:?}."
    );
    let reserved = reserved_block_row().await;
    assert_eq!(fx.block_rows(), reserved, "The store refusal must keep the reserved row.");
}

/// Slashable: the store disables the key during the backend sign. The signer
/// drops the block signature, and the row stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_during_the_backend_sign_gets_no_block_and_keeps_the_row() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let result = park.change_then_join(fx.block(), || fx.set_store(false)).await;

    fx.record_is(&[Check(BLOCK), Start, Disable, End, Check(BLOCK)], "The started sign must end.");
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "The caller must get the store refusal and no signature. The result was {result:?}."
    );
    let reserved = reserved_block_row().await;
    assert_eq!(fx.block_rows(), reserved, "A dropped signature must keep the reserved row.");
}

/// Slashable: the admission moves during the backend sign. The signer drops
/// the block signature, and the row stays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_admission_revoked_during_the_backend_sign_gets_no_block_and_keeps_the_row() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let result = park.change_then_join(fx.block(), || fx.revoke_admission()).await;

    fx.record_is(&[Check(BLOCK), Start, Revoke, End], "The started sign must end.");
    assert!(
        matches!(result, Err(SignerError::BeaconAdmissionRevoked)),
        "The caller must get the admission refusal and no signature. The result was {result:?}."
    );
    let reserved = reserved_block_row().await;
    assert_eq!(fx.block_rows(), reserved, "A dropped signature must keep the reserved row.");
}

/// Non-slashable: the store disables the key and the admission moves before
/// the backend starts. The admission check comes first, so the caller gets
/// the admission refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_key_with_a_revoked_admission_gets_the_admission_refusal() {
    let fx = Fixture::new();
    let park = fx.park_before_the_start();
    let result = park.change_then_join(fx.selection_proof(), || fx.disable_and_revoke()).await;

    fx.record_is(&[Disable, Revoke], "The backend must not start after both changes.");
    assert!(
        matches!(result, Err(SignerError::BeaconAdmissionRevoked)),
        "The caller must get BeaconAdmissionRevoked. The result was {result:?}."
    );
}

/// Slashable: the store disables the key and the admission moves after the
/// under-lock check. The admission check comes first, so the signer deletes
/// the row that this call inserted, as the base admission rule does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_disabled_key_with_a_revoked_admission_gets_no_block_and_no_row() {
    let fx = Fixture::new();
    let park = fx.park_before_the_reservation();
    let result = park.change_then_join(fx.block(), || fx.disable_and_revoke()).await;

    assert!(
        matches!(result, Err(SignerError::BeaconAdmissionRevoked)),
        "The caller must get BeaconAdmissionRevoked. The result was {result:?}."
    );
    assert!(fx.block_rows().is_empty(), "The admission refusal must delete the row of this call.");
    fx.record_is(&[Disable, Revoke], "The backend must not start after both changes.");
}

/// With no store gate, a service keeps the base checks: an admission that
/// moves after the entry check does not stop a non-slashable sign.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_store_gate_a_revocation_after_the_entry_check_gets_a_selection_proof() {
    let fx = Fixture::without_store_gate();
    let park = fx.park_before_the_start();
    let result = park.change_then_join(fx.selection_proof(), || fx.revoke_admission()).await;

    assert!(result.is_ok(), "With no store gate, the caller must get the signature: {result:?}.");
    fx.record_is(&[Revoke, Start, End], "With no store gate, the backend must sign.");
}

/// With no store gate, a service keeps the base checks: an admission that
/// moves during the backend sign does not drop a block signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_no_store_gate_a_revocation_during_the_backend_sign_gets_a_block() {
    let fx = Fixture::without_store_gate();
    let park = fx.hold_backend();
    let result = park.change_then_join(fx.block(), || fx.revoke_admission()).await;

    assert!(result.is_ok(), "With no store gate, the caller must get the signature: {result:?}.");
    fx.record_is(&[Start, Revoke, End], "With no store gate, the backend must sign.");
    let reserved = reserved_block_row().await;
    assert_eq!(fx.block_rows(), reserved, "The signed block must keep its row.");
}

/// The start boundary (D1, D2): the store disables the key just after the
/// start check. This is a change during the backend call. The backend gets
/// the call, and the check after the backend returns drops the signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_just_after_the_start_check_gets_no_selection_proof() {
    let fx = Fixture::new();
    let hook = DisableAfterStartCheck(Arc::clone(&fx.record));
    fx.service.set_nonslashable_barrier(Some(Arc::new(hook)));
    let result = join(fx.selection_proof()).await;

    fx.record_is(&[Check(PROOF), Disable, Start, End, Check(PROOF)], "The backend must sign.");
    assert!(
        matches!(result, Err(SignerError::BlockedByDoppelganger)),
        "The caller must get the store refusal and no signature. The result was {result:?}."
    );
}

/// The documented limit (D2): the check after the backend returns reads the
/// store flag at that time. A disable and an enable before the backend
/// returns do not drop the signature.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_key_disabled_and_enabled_during_the_backend_sign_gets_a_selection_proof() {
    let fx = Fixture::new();
    let park = fx.hold_backend();
    let flip = || [false, true].into_iter().for_each(|enabled| fx.set_store(enabled));
    let result = park.change_then_join(fx.selection_proof(), flip).await;

    fx.record_is(
        &[Check(PROOF), Start, Disable, Enable, End, Check(PROOF)],
        "The check after the backend returns must read the store flag at that time.",
    );
    assert!(result.is_ok(), "The caller must get the signature. The result was {result:?}.");
}
