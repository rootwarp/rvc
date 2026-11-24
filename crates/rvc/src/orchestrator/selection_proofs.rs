//! Selection-proof cache shared by aggregation and committee subscriptions.
//!
//! The cache holds one proof per `(slot, pubkey)`. The first caller that misses a key owns it until
//! its sign ends. Concurrent callers wait for the owner's proof and do not sign again. A failed or
//! cancelled owner removes its entry, and one waiter becomes the next owner.
//!
//! [`SelectionProofCache::evict_before`] sets a cutoff slot. The cache admits no new owner for a
//! slot below the cutoff and caches no proof below it. An owner admitted before the eviction can
//! still start and finish its sign. Its proof goes to its waiters but is not cached. Until that
//! owner ends, new callers for its key wait for it.

use std::collections::HashMap;
use std::future::Future;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use crypto::Signature;
use eth_types::Slot;
use parking_lot::Mutex;
use tokio::sync::watch;

/// Cache key: the duty slot and the compressed validator public key.
pub(crate) type SelectionProofKey = (Slot, [u8; 48]);

/// Why [`SelectionProofCache::get_or_sign`] did not return a proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SelectionProofError<E> {
    /// The slot is below the eviction cutoff and no live owner had a proof for it. Nothing was
    /// signed.
    Evicted { slot: Slot },
    /// This caller owned the key and its sign closure failed.
    Sign(E),
}

enum Entry {
    Ready(Signature),
    InFlight { owner: u64, rx: watch::Receiver<Option<Signature>> },
}

#[derive(Default)]
struct Entries {
    map: HashMap<SelectionProofKey, Entry>,
    next_owner: u64,
    cutoff: Slot,
}

/// Selection proofs by `(slot, pubkey)` with per-key in-flight ownership.
#[derive(Default)]
pub(crate) struct SelectionProofCache {
    entries: Mutex<Entries>,
    #[cfg(test)]
    waiter_registrations: AtomicUsize,
}

enum Claim<'a> {
    Ready(Signature),
    Waiter(watch::Receiver<Option<Signature>>),
    Owner(OwnerGuard<'a>),
    Evicted,
}

impl SelectionProofCache {
    /// Returns the proof for `key`. Calls `sign` only if no other caller owns the key.
    ///
    /// A caller that finds the key in flight waits for the owner. If that owner fails or is
    /// cancelled, the caller tries again and can become the owner itself. A failed `sign` returns
    /// its error and leaves no entry. A miss below the eviction cutoff returns
    /// [`SelectionProofError::Evicted`] and does not call `sign`.
    pub(crate) async fn get_or_sign<F, Fut, E>(
        &self,
        key: SelectionProofKey,
        sign: F,
    ) -> Result<Signature, SelectionProofError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Signature, E>>,
    {
        let guard = loop {
            match self.claim(key) {
                Claim::Ready(proof) => return Ok(proof),
                Claim::Owner(guard) => break guard,
                Claim::Evicted => return Err(SelectionProofError::Evicted { slot: key.0 }),
                Claim::Waiter(mut rx) => {
                    let published = match rx.wait_for(Option::is_some).await {
                        Ok(value) => (*value).clone(),
                        Err(_) => None,
                    };
                    if let Some(proof) = published {
                        return Ok(proof);
                    }
                }
            }
        };
        let proof = sign().await.map_err(SelectionProofError::Sign)?;
        guard.complete(&proof);
        Ok(proof)
    }

    /// Raises the cutoff to `slot` and removes the ready proofs below the cutoff.
    ///
    /// The cutoff never goes down. No new owner is admitted below it. An owner admitted before the
    /// eviction keeps its entry and can finish its sign. Its proof then goes to its waiters but not
    /// into the cache.
    pub(crate) fn evict_before(&self, slot: Slot) {
        let mut entries = self.entries.lock();
        entries.cutoff = entries.cutoff.max(slot);
        let cutoff = entries.cutoff;
        entries.map.retain(|(entry_slot, _), entry| {
            *entry_slot >= cutoff || matches!(entry, Entry::InFlight { .. })
        });
    }

    /// Number of entries, ready or in flight.
    pub(crate) fn len(&self) -> usize {
        self.entries.lock().map.len()
    }

    fn claim(&self, key: SelectionProofKey) -> Claim<'_> {
        let mut entries = self.entries.lock();
        match entries.map.get(&key) {
            Some(Entry::Ready(proof)) => return Claim::Ready(proof.clone()),
            Some(Entry::InFlight { rx, .. }) if rx.has_changed().is_ok() => {
                #[cfg(test)]
                self.waiter_registrations.fetch_add(1, Ordering::SeqCst);
                return Claim::Waiter(rx.clone());
            }
            _ => {}
        }
        if key.0 < entries.cutoff {
            entries.map.remove(&key);
            return Claim::Evicted;
        }
        let owner = entries.next_owner;
        entries.next_owner += 1;
        let (tx, rx) = watch::channel(None);
        entries.map.insert(key, Entry::InFlight { owner, rx });
        Claim::Owner(OwnerGuard { cache: self, key, owner, tx, completed: false })
    }
}

struct OwnerGuard<'a> {
    cache: &'a SelectionProofCache,
    key: SelectionProofKey,
    owner: u64,
    tx: watch::Sender<Option<Signature>>,
    completed: bool,
}

impl OwnerGuard<'_> {
    fn complete(mut self, proof: &Signature) {
        {
            let mut entries = self.cache.entries.lock();
            if self.owns_entry(&entries) {
                if self.key.0 >= entries.cutoff {
                    entries.map.insert(self.key, Entry::Ready(proof.clone()));
                } else {
                    entries.map.remove(&self.key);
                }
            }
        }
        self.completed = true;
        self.tx.send_replace(Some(proof.clone()));
    }

    fn owns_entry(&self, entries: &Entries) -> bool {
        matches!(
            entries.map.get(&self.key),
            Some(Entry::InFlight { owner, .. }) if *owner == self.owner
        )
    }
}

impl Drop for OwnerGuard<'_> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut entries = self.cache.entries.lock();
        if self.owns_entry(&entries) {
            entries.map.remove(&self.key);
        }
    }
}

#[cfg(test)]
impl SelectionProofCache {
    pub(crate) fn in_flight_len(&self) -> usize {
        self.entries
            .lock()
            .map
            .values()
            .filter(|entry| matches!(entry, Entry::InFlight { .. }))
            .count()
    }

    pub(crate) fn waiter_registrations(&self) -> usize {
        self.waiter_registrations.load(Ordering::SeqCst)
    }
}

/// Test harness for the cache protocol. W4-E8a2 and W4-E8a3 use it too.
///
/// The harness only counts. It never orders the tasks that it observes. Every wait is a bounded
/// `yield_now` loop, so a wrong design gives a failed assertion and not a hang.
#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::HashMap;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    use crypto::Signature;
    use futures::future::BoxFuture;
    use parking_lot::Mutex;
    use tokio::sync::Semaphore;
    use tokio::task::JoinHandle;

    use super::{SelectionProofCache, SelectionProofError, SelectionProofKey};

    /// Maximum scheduler rounds for each bounded wait.
    pub(crate) const YIELD_ROUNDS: usize = 1_000;

    /// The key that the protocol tests use.
    pub(crate) const KEY: SelectionProofKey = (10, [0x11; 48]);

    const GATE_PERMITS: usize = 64;

    /// The result type of a [`SignProbe`] sign closure.
    pub(crate) type ProbeResult = Result<Signature, ProbeError>;

    /// The result type of a `get_or_sign` call with a [`SignProbe`] closure.
    pub(crate) type CacheResult = Result<Signature, SelectionProofError<ProbeError>>;

    /// The error of a [`SignProbe::fail`] closure.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct ProbeError;

    /// Holds every sign closure until [`Gate::open`]. A drop opens the gate.
    pub(crate) struct Gate {
        permits: Arc<Semaphore>,
        opened: AtomicBool,
    }

    impl Gate {
        pub(crate) fn new() -> Self {
            Self { permits: Arc::new(Semaphore::new(0)), opened: AtomicBool::new(false) }
        }

        pub(crate) fn open(&self) {
            if !self.opened.swap(true, Ordering::SeqCst) {
                self.permits.add_permits(GATE_PERMITS);
            }
        }
    }

    impl Drop for Gate {
        fn drop(&mut self) {
            self.open();
        }
    }

    /// Makes sign closures that count their calls and wait on a [`Gate`].
    ///
    /// Each probe returns its own proof, so two probes give two different proofs.
    #[derive(Clone)]
    pub(crate) struct SignProbe {
        entered: Arc<AtomicUsize>,
        permits: Arc<Semaphore>,
        proof: Signature,
    }

    impl SignProbe {
        pub(crate) fn new(gate: &Gate) -> Self {
            Self {
                entered: Arc::new(AtomicUsize::new(0)),
                permits: Arc::clone(&gate.permits),
                proof: signer::mock_sig(b"selection proof"),
            }
        }

        /// The proof that every successful closure returns.
        pub(crate) fn proof(&self) -> Signature {
            self.proof.clone()
        }

        /// Number of closure calls. A call counts before it waits on the gate.
        pub(crate) fn calls(&self) -> usize {
            self.entered.load(Ordering::SeqCst)
        }

        /// A closure that returns [`SignProbe::proof`] after the gate opens.
        pub(crate) fn sign(&self) -> impl FnOnce() -> BoxFuture<'static, ProbeResult> + Send {
            self.closure(true)
        }

        /// A closure that returns [`ProbeError`] after the gate opens.
        pub(crate) fn fail(&self) -> impl FnOnce() -> BoxFuture<'static, ProbeResult> + Send {
            self.closure(false)
        }

        fn closure(
            &self,
            succeed: bool,
        ) -> impl FnOnce() -> BoxFuture<'static, ProbeResult> + Send {
            let probe = self.clone();
            move || {
                probe.entered.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    let _permit = probe.permits.acquire().await;
                    if succeed {
                        Ok(probe.proof)
                    } else {
                        Err(ProbeError)
                    }
                })
            }
        }
    }

    /// What the second caller on a held key did first.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Competitor {
        /// It entered a sign closure: a second sign for the same key.
        Signing,
        /// It registered as a waiter on the owner.
        Waiting,
        /// Neither happened within [`YIELD_ROUNDS`].
        Neither,
    }

    /// The counters before the competitor starts. Only a change after this point counts.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct Baseline {
        calls: usize,
        registrations: usize,
    }

    impl Baseline {
        pub(crate) fn take(probe: &SignProbe, cache: &impl ProofCacheUnderTest) -> Self {
            Self { calls: probe.calls(), registrations: cache.waiter_registrations() }
        }
    }

    /// Yields until `done` is true. Returns false after [`YIELD_ROUNDS`] rounds.
    pub(crate) async fn wait_until(mut done: impl FnMut() -> bool) -> bool {
        for _ in 0..YIELD_ROUNDS {
            if done() {
                return true;
            }
            tokio::task::yield_now().await;
        }
        done()
    }

    /// Reports the first competitor signal after `baseline`: a new closure call or a new waiter
    /// registration.
    pub(crate) async fn wait_for_competitor(
        probe: &SignProbe,
        cache: &impl ProofCacheUnderTest,
        baseline: Baseline,
    ) -> Competitor {
        for _ in 0..YIELD_ROUNDS {
            if probe.calls() > baseline.calls {
                return Competitor::Signing;
            }
            if cache.waiter_registrations() > baseline.registrations {
                return Competitor::Waiting;
            }
            tokio::task::yield_now().await;
        }
        Competitor::Neither
    }

    /// Yields until every task finishes. Returns the number of tasks that did not finish.
    pub(crate) async fn join_bounded<T>(handles: &[JoinHandle<T>]) -> usize {
        let _ = wait_until(|| handles.iter().all(JoinHandle::is_finished)).await;
        handles.iter().filter(|handle| !handle.is_finished()).count()
    }

    /// The output of a finished task. Aborts an unfinished task and returns `None`.
    pub(crate) async fn finished_output<T>(handle: JoinHandle<T>) -> Option<T> {
        if handle.is_finished() {
            handle.await.ok()
        } else {
            handle.abort();
            None
        }
    }

    /// Aborts `handle` and joins it with a bound. True only if the task ended as cancelled.
    pub(crate) async fn abort_bounded<T>(handle: JoinHandle<T>) -> bool {
        handle.abort();
        let handles = [handle];
        if join_bounded(&handles).await != 0 {
            return false;
        }
        let [handle] = handles;
        handle.await.is_err_and(|error| error.is_cancelled())
    }

    /// The cache surface that the protocol scenarios drive.
    pub(crate) trait ProofCacheUnderTest: Send + Sync + 'static {
        fn get_or_sign<F, Fut, E>(
            &self,
            key: SelectionProofKey,
            sign: F,
        ) -> impl Future<Output = Result<Signature, SelectionProofError<E>>> + Send
        where
            F: FnOnce() -> Fut + Send,
            Fut: Future<Output = Result<Signature, E>> + Send,
            E: Send;

        fn waiter_registrations(&self) -> usize;

        fn in_flight_len(&self) -> usize;
    }

    impl ProofCacheUnderTest for SelectionProofCache {
        fn get_or_sign<F, Fut, E>(
            &self,
            key: SelectionProofKey,
            sign: F,
        ) -> impl Future<Output = Result<Signature, SelectionProofError<E>>> + Send
        where
            F: FnOnce() -> Fut + Send,
            Fut: Future<Output = Result<Signature, E>> + Send,
            E: Send,
        {
            SelectionProofCache::get_or_sign(self, key, sign)
        }

        fn waiter_registrations(&self) -> usize {
            SelectionProofCache::waiter_registrations(self)
        }

        fn in_flight_len(&self) -> usize {
            SelectionProofCache::in_flight_len(self)
        }
    }

    /// The rejected design: get, then `sign().await`, then insert. It never registers a waiter.
    ///
    /// `prior_registrations` is a fixed count that it reports, as if earlier scenarios on the
    /// same cache had registered waiters.
    #[derive(Default)]
    pub(crate) struct GetSignInsert {
        proofs: Mutex<HashMap<SelectionProofKey, Signature>>,
        prior_registrations: usize,
    }

    impl GetSignInsert {
        pub(crate) fn with_prior_registrations(prior_registrations: usize) -> Self {
            Self { proofs: Mutex::default(), prior_registrations }
        }
    }

    impl ProofCacheUnderTest for GetSignInsert {
        async fn get_or_sign<F, Fut, E>(
            &self,
            key: SelectionProofKey,
            sign: F,
        ) -> Result<Signature, SelectionProofError<E>>
        where
            F: FnOnce() -> Fut + Send,
            Fut: Future<Output = Result<Signature, E>> + Send,
            E: Send,
        {
            let hit = self.proofs.lock().get(&key).cloned();
            if let Some(proof) = hit {
                return Ok(proof);
            }
            let proof = sign().await.map_err(SelectionProofError::Sign)?;
            self.proofs.lock().insert(key, proof.clone());
            Ok(proof)
        }

        fn waiter_registrations(&self) -> usize {
            self.prior_registrations
        }

        fn in_flight_len(&self) -> usize {
            0
        }
    }

    /// Spawns one `get_or_sign` call on `cache`.
    pub(crate) fn spawn_get_or_sign<C, F>(
        cache: &Arc<C>,
        key: SelectionProofKey,
        sign: F,
    ) -> JoinHandle<CacheResult>
    where
        C: ProofCacheUnderTest,
        F: FnOnce() -> BoxFuture<'static, ProbeResult> + Send + 'static,
    {
        let cache = Arc::clone(cache);
        tokio::spawn(async move { cache.get_or_sign(key, sign).await })
    }

    /// One `get_or_sign` call in a task, joined with a bound. `None` if it did not finish.
    pub(crate) async fn call_bounded<C, F>(
        cache: &Arc<C>,
        key: SelectionProofKey,
        sign: F,
    ) -> Option<CacheResult>
    where
        C: ProofCacheUnderTest,
        F: FnOnce() -> BoxFuture<'static, ProbeResult> + Send + 'static,
    {
        let handles = [spawn_get_or_sign(cache, key, sign)];
        let _ = join_bounded(&handles).await;
        let [handle] = handles;
        finished_output(handle).await
    }

    /// The observations of [`run_concurrent_miss_scenario`].
    #[derive(Debug)]
    pub(crate) struct MissReport {
        pub(crate) owner_entered: bool,
        pub(crate) competitor: Competitor,
        pub(crate) closure_calls: usize,
        pub(crate) same_proof: bool,
        pub(crate) unfinished: usize,
        pub(crate) in_flight_after: usize,
    }

    /// Two misses on `key` while the first sign is held.
    ///
    /// The gate is open and every task is joined (with a bound) before this returns. The caller
    /// makes all assertions on the report.
    pub(crate) async fn run_concurrent_miss_scenario<C: ProofCacheUnderTest>(
        cache: &Arc<C>,
        key: SelectionProofKey,
    ) -> MissReport {
        let gate = Gate::new();
        let probe = SignProbe::new(&gate);
        let owner = spawn_get_or_sign(cache, key, probe.sign());
        let owner_entered = wait_until(|| probe.calls() >= 1).await;
        let baseline = Baseline::take(&probe, cache.as_ref());
        let competitor = spawn_get_or_sign(cache, key, probe.sign());
        let role = wait_for_competitor(&probe, cache.as_ref(), baseline).await;
        gate.open();
        let handles = [owner, competitor];
        let unfinished = join_bounded(&handles).await;
        let [owner, competitor] = handles;
        let owner = finished_output(owner).await;
        let competitor = finished_output(competitor).await;
        let proof = probe.proof();
        let same_proof = matches!(
            (owner, competitor),
            (Some(Ok(a)), Some(Ok(b))) if a == proof && b == proof
        );
        MissReport {
            owner_entered,
            competitor: role,
            closure_calls: probe.calls(),
            same_proof,
            unfinished,
            in_flight_after: cache.in_flight_len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::watch;

    use super::test_support::{
        abort_bounded, call_bounded, finished_output, join_bounded, run_concurrent_miss_scenario,
        spawn_get_or_sign, wait_for_competitor, wait_until, Baseline, Competitor, Gate,
        GetSignInsert, ProbeError, SignProbe, KEY,
    };
    use super::{Claim, Entry, SelectionProofCache, SelectionProofError, SelectionProofKey};

    const EVICTED: SelectionProofError<ProbeError> = SelectionProofError::Evicted { slot: KEY.0 };

    /// The owner of `key` is held in its sign and a second caller has started.
    struct HeldOwner {
        cache: Arc<SelectionProofCache>,
        gate: Gate,
        probe: SignProbe,
        owner: tokio::task::JoinHandle<super::test_support::CacheResult>,
    }

    async fn hold_owner(sign_fails: bool) -> HeldOwner {
        let cache = Arc::new(SelectionProofCache::default());
        let gate = Gate::new();
        let probe = SignProbe::new(&gate);
        let owner = if sign_fails {
            spawn_get_or_sign(&cache, KEY, probe.fail())
        } else {
            spawn_get_or_sign(&cache, KEY, probe.sign())
        };
        assert!(
            wait_until(|| probe.calls() >= 1).await,
            "the owner never entered its sign closure"
        );
        HeldOwner { cache, gate, probe, owner }
    }

    /// Starts a second caller on `KEY` and asserts that it waits for the held owner.
    async fn start_waiter(
        held: &HeldOwner,
    ) -> tokio::task::JoinHandle<super::test_support::CacheResult> {
        let baseline = Baseline::take(&held.probe, held.cache.as_ref());
        let waiter = spawn_get_or_sign(&held.cache, KEY, held.probe.sign());
        let competitor = wait_for_competitor(&held.probe, held.cache.as_ref(), baseline).await;
        if competitor != Competitor::Waiting {
            held.gate.open();
        }
        assert_eq!(competitor, Competitor::Waiting, "the second caller must wait for the owner");
        assert_eq!(held.probe.calls(), 1, "the second caller must not sign");
        waiter
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_misses_sign_once() {
        let cache = Arc::new(SelectionProofCache::default());

        let report = run_concurrent_miss_scenario(&cache, KEY).await;

        assert!(report.owner_entered, "the owner never entered its sign closure: {report:?}");
        assert_eq!(
            report.competitor,
            Competitor::Waiting,
            "the second miss must wait for the owner: {report:?}"
        );
        assert_eq!(report.closure_calls, 1, "one sign per key: {report:?}");
        assert!(report.same_proof, "both callers get the owner's proof: {report:?}");
        assert_eq!(report.unfinished, 0, "every caller finishes: {report:?}");
        assert_eq!(report.in_flight_after, 0, "no entry stays in flight: {report:?}");
        assert_eq!(cache.len(), 1, "the proof is cached as ready");
        assert_eq!(cache.waiter_registrations(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_miss_scenario_fails_fast_on_get_sign_insert() {
        let cache = Arc::new(GetSignInsert::default());

        let report = run_concurrent_miss_scenario(&cache, KEY).await;

        assert!(report.owner_entered, "{report:?}");
        assert_eq!(report.competitor, Competitor::Signing, "{report:?}");
        assert_eq!(report.closure_calls, 2, "{report:?}");
        assert_eq!(report.unfinished, 0, "the rejected design must not hang: {report:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_miss_scenario_ignores_registrations_before_the_competitor() {
        let cache = Arc::new(GetSignInsert::with_prior_registrations(1));

        let report = run_concurrent_miss_scenario(&cache, KEY).await;

        assert_eq!(
            report.competitor,
            Competitor::Signing,
            "an earlier registration is not evidence about this competitor: {report:?}"
        );
        assert_eq!(report.closure_calls, 2, "{report:?}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_owner_hands_over_to_a_waiter() {
        let held = hold_owner(false).await;
        let waiter = start_waiter(&held).await;
        let HeldOwner { cache, gate, probe, owner } = held;

        assert!(abort_bounded(owner).await, "the aborted owner ends as cancelled");
        gate.open();
        let handles = [waiter];
        let unfinished = join_bounded(&handles).await;
        assert_eq!(unfinished, 0, "the waiter must wake when the owner is cancelled");
        let [waiter] = handles;

        assert_eq!(finished_output(waiter).await, Some(Ok(probe.proof())));
        assert_eq!(probe.calls(), 2, "the waiter took over and signed once");
        assert_eq!(cache.in_flight_len(), 0);
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_owner_leaves_no_poisoned_entry() {
        let lone = Arc::new(SelectionProofCache::default());
        let gate = Gate::new();
        gate.open();
        let probe = SignProbe::new(&gate);
        assert_eq!(
            call_bounded(&lone, KEY, probe.fail()).await,
            Some(Err(SelectionProofError::Sign(ProbeError))),
            "a lone failed owner finishes with its sign error"
        );
        assert_eq!(lone.in_flight_len(), 0, "a failed owner removes its entry");
        assert_eq!(lone.len(), 0);

        let held = hold_owner(true).await;
        let waiter = start_waiter(&held).await;
        let HeldOwner { cache, gate, probe, owner } = held;
        gate.open();
        let handles = [owner, waiter];
        assert_eq!(join_bounded(&handles).await, 0, "every caller finishes");
        let [owner, waiter] = handles;
        assert_eq!(finished_output(owner).await, Some(Err(SelectionProofError::Sign(ProbeError))));
        assert_eq!(finished_output(waiter).await, Some(Ok(probe.proof())));
        assert_eq!(probe.calls(), 2, "the waiter took over and signed once");

        assert_eq!(call_bounded(&cache, KEY, probe.sign()).await, Some(Ok(probe.proof())));
        assert_eq!(probe.calls(), 2, "the third call is a ready hit");
        assert_eq!(cache.in_flight_len(), 0);
        assert_eq!(cache.len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completion_after_eviction_is_not_reinserted() {
        let held = hold_owner(false).await;
        let waiter = start_waiter(&held).await;
        let HeldOwner { cache, gate, probe, owner } = held;

        cache.evict_before(KEY.0 + 1);
        assert_eq!(cache.in_flight_len(), 1, "the live owner keeps its entry through eviction");
        gate.open();
        let handles = [owner, waiter];
        assert_eq!(join_bounded(&handles).await, 0, "every caller finishes");
        let [owner, waiter] = handles;

        assert_eq!(finished_output(owner).await, Some(Ok(probe.proof())));
        assert_eq!(finished_output(waiter).await, Some(Ok(probe.proof())));
        assert_eq!(probe.calls(), 1);
        assert_eq!(cache.len(), 0, "an evicted owner does not insert its proof again");
        assert_eq!(cache.in_flight_len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn caller_after_eviction_waits_for_the_live_owner() {
        let held = hold_owner(false).await;
        held.cache.evict_before(KEY.0 + 1);
        let late = start_waiter(&held).await;
        let HeldOwner { cache, gate, probe, owner } = held;

        gate.open();
        let handles = [owner, late];
        assert_eq!(join_bounded(&handles).await, 0, "every caller finishes");
        let [owner, late] = handles;

        assert_eq!(finished_output(owner).await, Some(Ok(probe.proof())));
        assert_eq!(finished_output(late).await, Some(Ok(probe.proof())));
        assert_eq!(probe.calls(), 1, "the sign ran once for the evicted key");
        assert_eq!(cache.len(), 0, "the cache has no entry for the evicted slot");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_owner_of_an_evicted_slot_leaves_no_stale_proof() {
        let held = hold_owner(true).await;
        let waiter = start_waiter(&held).await;
        let HeldOwner { cache, gate, probe, owner } = held;

        cache.evict_before(KEY.0 + 1);
        gate.open();
        let handles = [owner, waiter];
        assert_eq!(join_bounded(&handles).await, 0, "every caller finishes");
        let [owner, waiter] = handles;

        assert_eq!(finished_output(owner).await, Some(Err(SelectionProofError::Sign(ProbeError))));
        assert_eq!(finished_output(waiter).await, Some(Err(EVICTED)));
        assert_eq!(probe.calls(), 1, "no second sign starts for an evicted slot");
        assert_eq!(cache.len(), 0, "the stale key stays out of the cache");
        assert_eq!(call_bounded(&cache, KEY, probe.sign()).await, Some(Err(EVICTED)));
        assert_eq!(probe.calls(), 1, "a later miss does not sign either");
        assert_eq!(cache.len(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancelled_owner_of_an_evicted_slot_leaves_no_stale_proof() {
        let held = hold_owner(false).await;
        let waiter = start_waiter(&held).await;
        let HeldOwner { cache, gate, probe, owner } = held;

        cache.evict_before(KEY.0 + 1);
        assert!(abort_bounded(owner).await, "the aborted owner ends as cancelled");
        gate.open();
        let handles = [waiter];
        assert_eq!(join_bounded(&handles).await, 0, "the waiter finishes");
        let [waiter] = handles;

        assert_eq!(finished_output(waiter).await, Some(Err(EVICTED)));
        assert_eq!(probe.calls(), 1, "no second sign starts for an evicted slot");
        assert_eq!(cache.len(), 0, "the stale key stays out of the cache");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn evict_before_drops_older_slots() {
        let cache = Arc::new(SelectionProofCache::default());
        let gate = Gate::new();
        gate.open();
        let pubkey = KEY.1;
        let slots = [9, 10, 11];
        let probes = slots.map(|_| SignProbe::new(&gate));
        for (slot, probe) in slots.into_iter().zip(&probes) {
            assert_eq!(
                call_bounded(&cache, (slot, pubkey), probe.sign()).await,
                Some(Ok(probe.proof()))
            );
        }
        assert_eq!(cache.len(), 3);

        cache.evict_before(10);
        cache.evict_before(5);

        assert_eq!(cache.len(), 2, "only slot 9 is below 10");
        let other = SignProbe::new(&gate);
        for (slot, probe) in [(10, &probes[1]), (11, &probes[2])] {
            assert_eq!(
                call_bounded(&cache, (slot, pubkey), other.sign()).await,
                Some(Ok(probe.proof())),
                "a ready hit returns the proof of its own slot"
            );
        }
        assert_eq!(
            call_bounded(&cache, (9, pubkey), other.sign()).await,
            Some(Err(SelectionProofError::Evicted { slot: 9 })),
            "a lower eviction does not lower the cutoff"
        );
        assert_eq!(other.calls(), 0, "ready hits and a miss below the cutoff do not sign");

        let cold_key: SelectionProofKey = (10, [0x55; 48]);
        let cold = SignProbe::new(&gate);
        assert_eq!(
            call_bounded(&cache, cold_key, cold.sign()).await,
            Some(Ok(cold.proof())),
            "a cold miss at the cutoff slot signs"
        );
        assert_eq!(call_bounded(&cache, cold_key, other.sign()).await, Some(Ok(cold.proof())));
        assert_eq!((cold.calls(), other.calls()), (1, 0), "the next call is a ready hit");
        assert_eq!(probes.map(|probe| probe.calls()), [1, 1, 1]);
        assert_eq!(cache.len(), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn distinct_pubkeys_at_one_slot_get_their_own_proofs() {
        let cache = Arc::new(SelectionProofCache::default());
        let gate = Gate::new();
        let probe_a = SignProbe::new(&gate);
        let probe_b = SignProbe::new(&gate);
        assert_ne!(probe_a.proof(), probe_b.proof());
        let key_a: SelectionProofKey = (KEY.0, [0x11; 48]);
        let key_b: SelectionProofKey = (KEY.0, [0x22; 48]);

        let a = spawn_get_or_sign(&cache, key_a, probe_a.sign());
        let b = spawn_get_or_sign(&cache, key_b, probe_b.sign());
        let both_entered = wait_until(|| probe_a.calls() == 1 && probe_b.calls() == 1).await;
        gate.open();
        assert!(both_entered, "each key has its own owner and both sign before the gate opens");
        let handles = [a, b];
        assert_eq!(join_bounded(&handles).await, 0, "every caller finishes");
        let [a, b] = handles;

        assert_eq!(finished_output(a).await, Some(Ok(probe_a.proof())));
        assert_eq!(finished_output(b).await, Some(Ok(probe_b.proof())));
        assert_eq!(call_bounded(&cache, key_a, probe_b.sign()).await, Some(Ok(probe_a.proof())));
        assert_eq!(call_bounded(&cache, key_b, probe_a.sign()).await, Some(Ok(probe_b.proof())));
        assert_eq!((probe_a.calls(), probe_b.calls()), (1, 1), "the later calls are ready hits");
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn stale_in_flight_entry_is_claimed_as_absent() {
        let cache = SelectionProofCache::default();
        let (tx, rx) = watch::channel(None);
        drop(tx);
        cache.entries.lock().map.insert(KEY, Entry::InFlight { owner: 99, rx });

        let claim = cache.claim(KEY);

        assert!(
            matches!(claim, Claim::Owner(_)),
            "an in-flight entry without a live owner is treated as absent"
        );
        assert_eq!(cache.waiter_registrations(), 0);
        drop(claim);
        assert_eq!(cache.in_flight_len(), 0, "the new owner's guard removes its entry on drop");
    }

    #[test]
    fn old_owner_leaves_a_newer_entry_intact() {
        fn owner_of(cache: &SelectionProofCache, key: &SelectionProofKey) -> Option<u64> {
            match cache.entries.lock().map.get(key) {
                Some(Entry::InFlight { owner, .. }) => Some(*owner),
                _ => None,
            }
        }
        let cache = SelectionProofCache::default();
        let (_tx, rx) = watch::channel(None);
        let completing = (KEY.0, [0x33; 48]);
        let dropping = (KEY.0, [0x44; 48]);
        let Claim::Owner(old_completing) = cache.claim(completing) else {
            panic!("the first claim is the owner");
        };
        let Claim::Owner(old_dropping) = cache.claim(dropping) else {
            panic!("the first claim is the owner");
        };
        for key in [completing, dropping] {
            cache.entries.lock().map.insert(key, Entry::InFlight { owner: 99, rx: rx.clone() });
        }

        old_completing.complete(&signer::mock_sig(b"old owner"));
        drop(old_dropping);

        assert_eq!(
            owner_of(&cache, &completing),
            Some(99),
            "an old completion keeps the new entry"
        );
        assert_eq!(owner_of(&cache, &dropping), Some(99), "an old drop keeps the new entry");
    }
}
