#[cfg(test)]
mod tests {
    //! Detection-latch admission orders while a shutdown drain is in progress.
    //!
    //! Sequence numbers are assigned by the machine hooks, which run under the
    //! states lock. An admitted check must be sequenced before the latch store.
    //! A check sequenced after the latch must be `BlockedByDoppelganger`.

    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use crypto::{
        CompositeSigner, KeyManager, LocalSigner, PublicKey, SecretKey, Signer, SigningError,
    };
    use doppelganger::{
        EpochLiveness, ForwardWindowMachine, SigningEnablement, ValidatorLivenessData,
    };
    use eth_types::{Epoch, ForkSchedule, Root};
    use signer::{PreReserveBarrier, SignerError, SignerService, ValidatorSigner};
    use slashing::SlashingDb;
    use tokio::sync::Notify;

    use crate::bootstrap::executor::{ShutdownTier, TaskExecutor, TierBudget};
    use crate::bootstrap::{await_shutdown_and_drain_with_signal, BootstrapError, ShutdownInputs};
    use crate::orchestrator::OrchestratorHandle;

    const GVR: Root = [0x11; 32];

    #[derive(Clone)]
    struct Oracle {
        next: Arc<AtomicU64>,
        events: Arc<Mutex<Vec<Event>>>,
    }

    #[derive(Clone, Copy)]
    enum Event {
        Latch(u64),
        Check { seq: u64, enabled: bool },
    }

    impl Oracle {
        fn new() -> Self {
            Self { next: Arc::new(AtomicU64::new(0)), events: Arc::new(Mutex::new(Vec::new())) }
        }

        fn install(&self, machine: &ForwardWindowMachine) {
            let oracle = self.clone();
            machine.set_detected_latch_hook(Some(Arc::new(move || {
                let seq = oracle.next.fetch_add(1, Ordering::SeqCst);
                oracle.events.lock().expect("oracle").push(Event::Latch(seq));
            })));
            let oracle = self.clone();
            machine.set_admission_hook(Some(Arc::new(move |enabled| {
                let seq = oracle.next.fetch_add(1, Ordering::SeqCst);
                oracle.events.lock().expect("oracle").push(Event::Check { seq, enabled });
            })));
        }

        fn assert_no_admission_after_latch(&self) {
            let events = self.events.lock().expect("oracle").iter().copied().collect::<Vec<_>>();
            let latch = events.iter().find_map(|event| match event {
                Event::Latch(seq) => Some(*seq),
                Event::Check { .. } => None,
            });
            let latch = latch.expect("the latch must be stored");
            for event in &events {
                if let Event::Check { seq, enabled: true } = event {
                    assert!(*seq < latch, "admitted check {seq} is sequenced after latch {latch}");
                }
            }
        }
    }

    struct Park {
        entered: Notify,
        release: Notify,
        open: AtomicBool,
    }

    impl Park {
        fn new() -> Self {
            Self { entered: Notify::new(), release: Notify::new(), open: AtomicBool::new(false) }
        }

        fn release(&self) {
            self.open.store(true, Ordering::SeqCst);
            self.release.notify_waiters();
        }
    }

    #[async_trait]
    impl PreReserveBarrier for Park {
        async fn wait(&self) {
            self.entered.notify_one();
            loop {
                let notified = self.release.notified();
                if self.open.load(Ordering::SeqCst) {
                    return;
                }
                notified.await;
            }
        }
    }

    struct CountingSigner {
        inner: LocalSigner,
        hits: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Signer for CountingSigner {
        async fn sign(
            &self,
            signing_root: &Root,
            pubkey: &[u8; 48],
        ) -> Result<crypto::Signature, SigningError> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(signing_root, pubkey).await
        }

        fn public_keys(&self) -> Vec<[u8; 48]> {
            self.inner.public_keys()
        }
    }

    struct World {
        machine: Arc<ForwardWindowMachine>,
        signer: Arc<SignerService>,
        db: Arc<SlashingDb>,
        hits: Arc<AtomicUsize>,
        oracle: Oracle,
        safe: PublicKey,
        other: PublicKey,
        pending: PublicKey,
    }

    impl World {
        fn new() -> Self {
            let (safe_sk, safe) = keypair();
            let (other_sk, other) = keypair();
            let pending = SecretKey::generate().public_key();
            let db = Arc::new(SlashingDb::open_in_memory().expect("memory db"));
            let reader: Arc<dyn slashing::SlashingDbReader> = db.clone();
            let machine =
                Arc::new(ForwardWindowMachine::new(reader, 1, GVR).with_confirmed_genesis());
            machine.register(&safe, 0);
            machine.register(&other, 0);
            machine.register(&pending, 5);
            let oracle = Oracle::new();
            oracle.install(&machine);

            let mut km = KeyManager::new();
            km.insert(safe_sk);
            km.insert(other_sk);
            let hits = Arc::new(AtomicUsize::new(0));
            let backend =
                Arc::new(CountingSigner { inner: LocalSigner::new(km), hits: hits.clone() });
            let composite = Arc::new(CompositeSigner::new(LocalSigner::new(KeyManager::new())));
            let enablement: Arc<dyn SigningEnablement> = machine.clone();
            let signer = Arc::new(
                SignerService::new(composite, db.clone())
                    .with_enablement(enablement)
                    .with_sign_backend(backend),
            );
            Self { machine, signer, db, hits, oracle, safe, other, pending }
        }
    }

    fn keypair() -> (SecretKey, PublicKey) {
        let sk = SecretKey::generate();
        let pk = sk.public_key();
        (sk, pk)
    }

    fn detect(machine: &ForwardWindowMachine, pubkey: &PublicKey) {
        let samples =
            vec![ValidatorLivenessData { index: hex::encode(pubkey.to_bytes()), is_live: true }];
        let _ = machine.apply_liveness_tick(
            &[EpochLiveness { epoch: 5, samples: Some(samples) }],
            5 as Epoch,
            0,
        );
    }

    fn schedule() -> ForkSchedule {
        ForkSchedule::unscheduled_gloas()
    }

    async fn sign_randao(
        signer: &SignerService,
        pubkey: &PublicKey,
    ) -> Result<crypto::Signature, SignerError> {
        signer.sign_randao_reveal(1, pubkey, &schedule(), &GVR).await
    }

    async fn sign_block(
        signer: &SignerService,
        pubkey: &PublicKey,
    ) -> Result<crypto::Signature, SignerError> {
        signer.sign_block(&[0x22; 32], 3, pubkey, &schedule(), &GVR).await
    }

    /// Order A: the check runs, then the latch is stored, then the sign finishes.
    async fn order_a(world: &World, after: Arc<Park>) {
        world.signer.set_nonslashable_barrier(Some(after.clone()));
        let signer = world.signer.clone();
        let pubkey = world.safe.clone();
        let task = tokio::spawn(async move { sign_randao(&signer, &pubkey).await });
        after.entered.notified().await;
        detect(&world.machine, &world.pending);
        after.release();
        task.await.expect("sign task").expect("admitted sign completes");
        assert_eq!(world.hits.load(Ordering::SeqCst), 1, "the admitted sign is recorded once");
    }

    /// Order B: the latch is stored before the check. Nothing is signed.
    async fn order_b(world: &World, before: Arc<Park>) {
        world.signer.set_admission_barrier(Some(before.clone()));
        let signer = world.signer.clone();
        let pubkey = world.safe.clone();
        let task = tokio::spawn(async move { sign_randao(&signer, &pubkey).await });
        before.entered.notified().await;
        detect(&world.machine, &world.pending);
        before.release();
        let err = task.await.expect("sign task").expect_err("check after the latch is refused");
        assert!(matches!(err, SignerError::BlockedByDoppelganger), "{err:?}");
        assert_eq!(world.hits.load(Ordering::SeqCst), 0, "a refused check records nothing");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn detection_during_shutdown_drain_refuses_later_admissions() {
        let token = tokio_util::sync::CancellationToken::new();
        let (executor, shutdown_rx) = TaskExecutor::new(token.clone());
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let task_token = executor.token();
        let entered_task = entered.clone();
        let release_task = release.clone();
        executor.spawn("hold_orchestrator", ShutdownTier::Orchestrator, async move {
            task_token.cancelled().await;
            entered_task.notify_one();
            release_task.notified().await;
        });
        let handle = executor.shutdown_handle();
        let budget = TierBudget::new([
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(2),
        ]);
        let drain = tokio::spawn(async move {
            await_shutdown_and_drain_with_signal(
                ShutdownInputs {
                    executor,
                    orchestrator_handle: OrchestratorHandle::for_drain_test(),
                    shutdown_rx,
                    shutdown_token: token,
                    budget,
                    detection: None,
                },
                std::future::pending(),
            )
            .await
        });

        handle.request_exit(12);
        entered.notified().await;

        let admitted = World::new();
        order_a(&admitted, Arc::new(Park::new())).await;
        admitted.oracle.assert_no_admission_after_latch();

        let refused = World::new();
        order_b(&refused, Arc::new(Park::new())).await;
        refused.oracle.assert_no_admission_after_latch();

        release.notify_one();
        let (_outcome, res) = drain.await.expect("drain");
        assert!(
            matches!(res, Err(BootstrapError::DoppelgangerDetected)),
            "drain must exit 12, got {res:?}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn slashable_sign_rechecks_latch_after_reserve_and_does_not_sign() {
        let world = World::new();
        let park = Arc::new(Park::new());
        world.signer.set_pre_reserve_barrier(Some(park.clone()));
        let signer = world.signer.clone();
        let pubkey = world.safe.clone();
        let task = tokio::spawn(async move { sign_block(&signer, &pubkey).await });
        park.entered.notified().await;
        detect(&world.machine, &world.pending);
        park.release();
        let err = task.await.expect("sign task").expect_err("BLS must not run after the latch");
        assert!(matches!(err, SignerError::BlockedByDoppelganger), "{err:?}");
        assert_eq!(world.hits.load(Ordering::SeqCst), 0, "the BLS backend must not be called");
        let rows = world.db.get_blocks(&hex::encode(world.safe.to_bytes())).expect("blocks");
        assert_eq!(rows.len(), 1, "the reservation stays after the pre-BLS refusal");

        let err = sign_block(&world.signer, &world.other).await.expect_err("later key");
        assert!(matches!(err, SignerError::BlockedByDoppelganger), "{err:?}");
        assert!(
            world.db.get_blocks(&hex::encode(world.other.to_bytes())).expect("blocks").is_empty(),
            "a check after the latch must not reserve"
        );
        assert_eq!(world.hits.load(Ordering::SeqCst), 0);
        world.oracle.assert_no_admission_after_latch();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn nonslashable_sign_admitted_before_the_latch_drains() {
        let world = World::new();
        let park = Arc::new(Park::new());
        order_a(&world, park).await;
        let err = sign_randao(&world.signer, &world.other).await.expect_err("later key");
        assert!(matches!(err, SignerError::BlockedByDoppelganger), "{err:?}");
        assert_eq!(world.hits.load(Ordering::SeqCst), 1, "the later check records nothing");
        world.oracle.assert_no_admission_after_latch();
    }

    /// The signer the VC builds wraps the machine. The post-reserve check has
    /// to see the latch through that wrapper.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn production_signer_wrapper_forwards_blocked_by_doppelganger() {
        let (safe_sk, safe) = keypair();
        let pending = SecretKey::generate().public_key();
        let db = Arc::new(SlashingDb::open_in_memory().expect("memory db"));
        let reader: Arc<dyn slashing::SlashingDbReader> = db.clone();
        let machine = Arc::new(ForwardWindowMachine::new(reader, 1, GVR).with_confirmed_genesis());
        machine.register(&safe, 0);
        machine.register(&pending, 5);
        let mut km = KeyManager::new();
        km.insert(safe_sk);
        let composite = Arc::new(CompositeSigner::new(LocalSigner::new(km)));
        let config = crate::config::Config {
            beacon_url: "http://127.0.0.1:1".to_string(),
            ..Default::default()
        };
        let enablement: Arc<dyn SigningEnablement> = machine.clone();
        let (signer, _registry) = crate::config::ServiceBuilder::new(config).build_signer(
            composite,
            db.clone(),
            enablement,
        );
        let park = Arc::new(Park::new());
        signer.set_pre_reserve_barrier(Some(park.clone()));
        let signing = signer.clone();
        let pubkey = safe.clone();
        let task = tokio::spawn(async move { sign_block(&signing, &pubkey).await });
        park.entered.notified().await;
        detect(&machine, &pending);
        park.release();
        let err = task.await.expect("sign task").expect_err("the wrapper must refuse BLS");
        assert!(matches!(err, SignerError::BlockedByDoppelganger), "{err:?}");
        let rows = db.get_blocks(&hex::encode(safe.to_bytes())).expect("blocks");
        assert_eq!(rows.len(), 1, "the reservation stays after the wrapped refusal");
    }
}
