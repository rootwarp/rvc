use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{debug, info, trace, warn};

use crate::metrics::{
    RVC_DUTIES_FETCHED_TOTAL, RVC_DUTY_REJECTED_TOTAL, RVC_PTC_DUTIES_FETCHED_TOTAL,
};
use bn_manager::{AttesterDuty, DutiesProvider, ProposerDuty, PtcDuty};
use eth_types::{ForkSchedule, SyncCommitteeDuty, SLOTS_PER_EPOCH};

use crate::duty::{DutyParseError, TypedAttesterDuty, TypedProposerDuty, TypedPtcDuty};
use crate::error::DutyTrackerError;

/// Epochs per sync committee period (256 epochs ~ 27 hours).
const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

fn record_rejection(err: DutyParseError, rejected: &mut Vec<DutyParseError>) {
    RVC_DUTY_REJECTED_TOTAL.with_label_values(&[err.field]).inc();
    match err.validator_index {
        Some(validator_index) => {
            warn!(
                validator_index,
                "rejecting duty: malformed numeric field {} raw {}", err.field, err.raw
            );
        }
        None => {
            warn!("rejecting duty: malformed numeric field {} raw {}", err.field, err.raw);
        }
    }
    rejected.push(err);
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DutyCacheKey {
    pub slot: u64,
    pub committee_index: u64,
    pub validator_index: u64,
}

#[derive(Debug)]
struct EpochDutyCache {
    duties: HashMap<DutyCacheKey, TypedAttesterDuty>,
    dependent_root: String,
    /// Index list posted to produce `duties`. `dependent_root` does not cover it.
    indices: Vec<String>,
    /// Revocation generation captured before the request that produced `duties`.
    fetched_gen: Option<u64>,
}

impl EpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root, indices: Vec::new(), fetched_gen: None }
    }

    /// Parse attester duties from a BN response into a keyed epoch cache.
    ///
    /// All five numeric fields are parsed per duty. A malformed field is a
    /// [`DutyParseError`] (counted and warned); that duty is skipped and the
    /// rest of the response is cached. Per-duty cache inserts are traced.
    fn from_response(
        dependent_root: String,
        duties: &[AttesterDuty],
        epoch: u64,
    ) -> (Self, Vec<DutyParseError>) {
        let mut epoch_cache = Self::new(dependent_root);
        let mut rejected = Vec::new();
        for duty in duties {
            match TypedAttesterDuty::try_from(duty) {
                Ok(typed) => {
                    let key = DutyCacheKey {
                        slot: typed.slot,
                        committee_index: typed.committee_index,
                        validator_index: typed.validator_index,
                    };
                    trace!(
                        slot = key.slot,
                        epoch,
                        validator_index = key.validator_index,
                        committee_index = key.committee_index,
                        "cached attester duty"
                    );
                    epoch_cache.insert(key, typed);
                }
                Err(err) => record_rejection(err, &mut rejected),
            }
        }
        (epoch_cache, rejected)
    }

    fn insert(&mut self, key: DutyCacheKey, duty: TypedAttesterDuty) {
        self.duties.insert(key, duty);
    }

    fn get(&self, key: &DutyCacheKey) -> Option<&TypedAttesterDuty> {
        self.duties.get(key)
    }
}

#[derive(Debug)]
struct ProposerEpochDutyCache {
    duties: HashMap<u64, TypedProposerDuty>,
    dependent_root: String,
    /// Revocation generation captured before the request that produced `duties`.
    fetched_gen: Option<u64>,
}

impl ProposerEpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root, fetched_gen: None }
    }

    /// Parse proposer duties from a BN response into a slot-keyed epoch cache.
    ///
    /// `slot` and `validator_index` are parsed per duty. A malformed field is a
    /// [`DutyParseError`] (counted and warned); that duty is skipped and the
    /// rest of the response is cached.
    fn from_response(
        dependent_root: String,
        duties: &[ProposerDuty],
    ) -> (Self, Vec<DutyParseError>) {
        let mut epoch_cache = Self::new(dependent_root);
        let mut rejected = Vec::new();
        for duty in duties {
            match TypedProposerDuty::try_from(duty) {
                Ok(typed) => epoch_cache.insert(typed.slot, typed),
                Err(err) => record_rejection(err, &mut rejected),
            }
        }
        (epoch_cache, rejected)
    }

    fn insert(&mut self, slot: u64, duty: TypedProposerDuty) {
        self.duties.insert(slot, duty);
    }

    fn get(&self, slot: &u64) -> Option<&TypedProposerDuty> {
        self.duties.get(slot)
    }
}

/// PTC duties for one epoch, keyed by slot (multiple validators per slot).
#[derive(Debug)]
struct PtcEpochDutyCache {
    duties: HashMap<u64, Vec<TypedPtcDuty>>,
    dependent_root: String,
    /// Index list posted to produce `duties`. `dependent_root` does not cover it.
    indices: Vec<String>,
    /// Revocation generation captured before the request that produced `duties`.
    fetched_gen: Option<u64>,
}

impl PtcEpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root, indices: Vec::new(), fetched_gen: None }
    }

    /// Parse PTC duties from a BN response into a slot-keyed epoch cache.
    ///
    /// `slot` and `validator_index` are parsed per duty. A malformed field is a
    /// [`DutyParseError`] (counted and warned); that duty is skipped and the
    /// rest of the response is cached.
    fn from_response(dependent_root: String, duties: &[PtcDuty]) -> (Self, Vec<DutyParseError>) {
        let mut epoch_cache = Self::new(dependent_root);
        let mut rejected = Vec::new();
        for duty in duties {
            match TypedPtcDuty::try_from(duty) {
                Ok(typed) => epoch_cache.insert(typed.slot, typed),
                Err(err) => record_rejection(err, &mut rejected),
            }
        }
        (epoch_cache, rejected)
    }

    fn insert(&mut self, slot: u64, duty: TypedPtcDuty) {
        self.duties.entry(slot).or_default().push(duty);
    }

    fn get(&self, slot: &u64) -> Option<&[TypedPtcDuty]> {
        self.duties.get(slot).map(Vec::as_slice)
    }

    fn duty_count(&self) -> usize {
        self.duties.values().map(Vec::len).sum()
    }
}

/// Sync-committee duties for one sync committee period.
#[derive(Debug)]
struct SyncPeriodDutyCache {
    duties: Vec<SyncCommitteeDuty>,
    /// Index list posted to produce `duties`.
    indices: Vec<String>,
    /// Revocation generation captured before the request that produced `duties`.
    fetched_gen: Option<u64>,
}

impl SyncPeriodDutyCache {
    /// Construct a period cache from a BN sync-committee duties response body.
    fn from_response(duties: Vec<SyncCommitteeDuty>) -> Self {
        Self { duties, indices: Vec::new(), fetched_gen: None }
    }
}

/// Validator indices a [`DutyTracker`] reads when it fetches duties.
///
/// The set may change between [`Self::indices`] calls. Each fetch snapshots it
/// once, at the start of that call, and uses that `Vec` for every beacon
/// request the call makes — one duty request never observes two sets.
/// A cached epoch or sync period stays fresh only while that stored snapshot
/// still equals the current set; `dependent_root` does not identify the posted
/// indices. [`DutyTracker::new`] is the static-set convenience wrapper.
pub trait ValidatorIndexSource: Send + Sync {
    /// Snapshot of the validator indices to query, as decimal strings.
    fn indices(&self) -> Vec<String>;
}

struct StaticIndexSource(Vec<String>);

impl ValidatorIndexSource for StaticIndexSource {
    fn indices(&self) -> Vec<String> {
        self.0.clone()
    }
}

/// Revocation generation captured before a duty request is sent.
///
/// Only [`DutyTracker::fetch_stamp`] creates one, so an entry can only carry
/// a generation sampled before its request.
#[derive(Debug, Clone, Copy)]
struct FetchStamp(Option<u64>);

/// An entry is served only under the generation it was stamped with.
fn visible(stamp: Option<u64>, now: Option<u64>) -> bool {
    stamp == now
}

/// A cache entry that carries the generation captured before its request.
trait Stamped {
    fn fetched_gen(&self) -> Option<u64>;
}

impl Stamped for EpochDutyCache {
    fn fetched_gen(&self) -> Option<u64> {
        self.fetched_gen
    }
}

impl Stamped for ProposerEpochDutyCache {
    fn fetched_gen(&self) -> Option<u64> {
        self.fetched_gen
    }
}

impl Stamped for PtcEpochDutyCache {
    fn fetched_gen(&self) -> Option<u64> {
        self.fetched_gen
    }
}

impl Stamped for SyncPeriodDutyCache {
    fn fetched_gen(&self) -> Option<u64> {
        self.fetched_gen
    }
}

/// The entry at `key` (an epoch, or a sync period) when it is visible under `now`.
///
/// A stale entry reads as absent.
fn servable<E: Stamped>(cache: &HashMap<u64, E>, key: u64, now: Option<u64>) -> Option<&E> {
    let entry = cache.get(&key).filter(|entry| visible(entry.fetched_gen(), now));
    #[cfg(test)]
    hooks::fire(&hooks::AFTER_STAMP_CHECK);
    entry
}

/// Insert `epoch`'s proposer duties stamped with `stamp`, under the write guard.
///
/// Returns `true` when a visible entry for `epoch` had another
/// `dependent_root`: the signal to re-broadcast preferences.
fn insert_proposer(
    cache: &mut RwLockWriteGuard<'_, HashMap<u64, ProposerEpochDutyCache>>,
    epoch: u64,
    dependent_root: String,
    duties: &[ProposerDuty],
    stamp: FetchStamp,
) -> bool {
    let root_changed =
        servable(cache, epoch, stamp.0).is_some_and(|c| c.dependent_root != dependent_root);
    let (mut entry, _rejected) = ProposerEpochDutyCache::from_response(dependent_root, duties);
    entry.fetched_gen = stamp.0;
    cache.insert(epoch, entry);
    root_changed
}

/// Test-only ordering hooks: each runs a closure at one interleaving point.
#[cfg(test)]
mod hooks {
    use std::cell::RefCell;
    use std::thread::LocalKey;

    pub(super) type Slot = RefCell<Option<Box<dyn FnMut()>>>;

    thread_local! {
        /// After a reader takes its guard, before it loads the generation.
        pub(super) static AFTER_READ_LOCK: Slot = const { RefCell::new(None) };
        /// After a reader's stamp check, still inside its guard.
        pub(super) static AFTER_STAMP_CHECK: Slot = const { RefCell::new(None) };
        /// In the `admit_*` helpers, after the re-check and before the insert.
        pub(super) static BEFORE_INSERT: Slot = const { RefCell::new(None) };
        /// In `admit_proposer`, after it takes the write guard, before the re-check.
        pub(super) static AFTER_WRITE_LOCK: Slot = const { RefCell::new(None) };
    }

    pub(super) fn fire(point: &'static LocalKey<Slot>) {
        point.with(|slot| {
            if let Some(hook) = slot.borrow_mut().as_mut() {
                hook();
            }
        });
    }

    /// Clears its hook on drop.
    #[must_use]
    pub(super) struct Armed(&'static LocalKey<Slot>);

    impl Drop for Armed {
        fn drop(&mut self) {
            self.0.with(|slot| slot.borrow_mut().take());
        }
    }

    pub(super) fn arm(point: &'static LocalKey<Slot>, hook: impl FnMut() + 'static) -> Armed {
        point.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
        Armed(point)
    }
}

pub struct DutyTracker {
    beacon: Arc<dyn DutiesProvider>,
    index_source: Arc<dyn ValidatorIndexSource>,
    cache: RwLock<HashMap<u64, EpochDutyCache>>,
    /// Proposer duties keyed by epoch -> ProposerEpochDutyCache.
    proposer_cache: RwLock<HashMap<u64, ProposerEpochDutyCache>>,
    /// PTC duties keyed by epoch -> PtcEpochDutyCache.
    ptc_cache: RwLock<HashMap<u64, PtcEpochDutyCache>>,
    /// Sync committee duties keyed by sync committee period.
    sync_committee_cache: RwLock<HashMap<u64, SyncPeriodDutyCache>>,
    /// Count of [`Self::get_duties_for_slot`] calls (complexity tests; RF6-31).
    slot_duty_lookups: AtomicU64,
    /// Reconciled fork schedule used to route proposer-duties v1/v2.
    fork_schedule: ForkSchedule,
    /// [`DutiesProvider::revocation_generation`], read once at construction.
    revocation: Option<Arc<AtomicU64>>,
}

impl DutyTracker {
    /// Track duties for a fixed validator index set.
    ///
    /// Convenience wrapper around [`Self::new_with_source`]: the set does not
    /// change between fetches.
    pub fn new(beacon: Arc<dyn DutiesProvider>, validator_indices: Vec<String>) -> Self {
        Self::new_with_source(beacon, Arc::new(StaticIndexSource(validator_indices)))
    }

    /// Track duties for an index set that may change between fetches.
    ///
    /// Each fetch calls [`ValidatorIndexSource::indices`] once and uses that
    /// snapshot for every beacon request the call makes. [`Self::new`] wraps a
    /// static set.
    ///
    /// When `beacon` has a [`DutiesProvider::revocation_generation`], a
    /// cached attester, proposer, PTC or sync-committee entry is served only
    /// while that generation equals the one captured before the request that
    /// produced it.
    pub fn new_with_source(
        beacon: Arc<dyn DutiesProvider>,
        index_source: Arc<dyn ValidatorIndexSource>,
    ) -> Self {
        let revocation = beacon.revocation_generation();
        Self {
            beacon,
            index_source,
            cache: RwLock::new(HashMap::new()),
            proposer_cache: RwLock::new(HashMap::new()),
            ptc_cache: RwLock::new(HashMap::new()),
            sync_committee_cache: RwLock::new(HashMap::new()),
            slot_duty_lookups: AtomicU64::new(0),
            fork_schedule: ForkSchedule::unscheduled_gloas(),
            revocation,
        }
    }

    /// Pin the reconciled fork schedule used for proposer-duties v1/v2 routing.
    pub fn with_fork_schedule(mut self, fork_schedule: ForkSchedule) -> Self {
        self.fork_schedule = fork_schedule;
        self
    }

    /// Number of times [`Self::get_duties_for_slot`] has been called (tests).
    pub fn slot_duty_lookup_count(&self) -> u64 {
        self.slot_duty_lookups.load(Ordering::Relaxed)
    }

    /// Read guard on the attester cache. Every attester reader starts here,
    /// then calls [`Self::generation_now`] while it holds the guard.
    async fn attester_read(&self) -> RwLockReadGuard<'_, HashMap<u64, EpochDutyCache>> {
        let guard = self.cache.read().await;
        #[cfg(test)]
        hooks::fire(&hooks::AFTER_READ_LOCK);
        guard
    }

    /// Read guard on the proposer cache. Every proposer reader starts here,
    /// then checks the stamp while it holds the guard.
    async fn proposer_read(&self) -> RwLockReadGuard<'_, HashMap<u64, ProposerEpochDutyCache>> {
        let guard = self.proposer_cache.read().await;
        #[cfg(test)]
        hooks::fire(&hooks::AFTER_READ_LOCK);
        guard
    }

    /// Read guard on the PTC cache. Every PTC reader starts here, then checks
    /// the stamp while it holds the guard.
    async fn ptc_read(&self) -> RwLockReadGuard<'_, HashMap<u64, PtcEpochDutyCache>> {
        let guard = self.ptc_cache.read().await;
        #[cfg(test)]
        hooks::fire(&hooks::AFTER_READ_LOCK);
        guard
    }

    /// Read guard on the sync-committee cache. Every sync reader starts here,
    /// then checks the stamp while it holds the guard.
    async fn sync_read(&self) -> RwLockReadGuard<'_, HashMap<u64, SyncPeriodDutyCache>> {
        let guard = self.sync_committee_cache.read().await;
        #[cfg(test)]
        hooks::fire(&hooks::AFTER_READ_LOCK);
        guard
    }

    fn generation_now(&self) -> Option<u64> {
        self.revocation.as_ref().map(|generation| generation.load(Ordering::Acquire))
    }

    /// Capture the generation. A writer calls this before its BN request.
    fn fetch_stamp(&self) -> FetchStamp {
        FetchStamp(self.generation_now())
    }

    /// Insert `entry` stamped with `stamp`, the only attester insert path.
    ///
    /// The generation is re-loaded under the write guard. If it moved since
    /// `stamp` was captured, nothing is inserted and the caller must not use
    /// the answer.
    fn admit_attester(
        &self,
        cache: &mut RwLockWriteGuard<'_, HashMap<u64, EpochDutyCache>>,
        epoch: u64,
        mut entry: EpochDutyCache,
        stamp: FetchStamp,
    ) -> Result<(), DutyTrackerError> {
        if !visible(stamp.0, self.generation_now()) {
            return Err(DutyTrackerError::RevokedDuringFetch { epoch });
        }
        #[cfg(test)]
        hooks::fire(&hooks::BEFORE_INSERT);
        entry.fetched_gen = stamp.0;
        cache.insert(epoch, entry);
        Ok(())
    }

    /// Insert proposer duties stamped with `stamp`, the only production
    /// proposer insert path.
    ///
    /// The generation is re-loaded under the write guard. If it moved since
    /// `stamp` was captured, nothing is inserted and the caller must not use
    /// the answer. Otherwise returns [`insert_proposer`]'s root-change flag.
    async fn admit_proposer(
        &self,
        epoch: u64,
        dependent_root: String,
        duties: &[ProposerDuty],
        stamp: FetchStamp,
    ) -> Result<bool, DutyTrackerError> {
        let mut cache = self.proposer_cache.write().await;
        #[cfg(test)]
        hooks::fire(&hooks::AFTER_WRITE_LOCK);
        if !visible(stamp.0, self.generation_now()) {
            return Err(DutyTrackerError::RevokedDuringFetch { epoch });
        }
        #[cfg(test)]
        hooks::fire(&hooks::BEFORE_INSERT);
        Ok(insert_proposer(&mut cache, epoch, dependent_root, duties, stamp))
    }

    /// Insert `entry` stamped with `stamp`, the only PTC insert path.
    ///
    /// The generation is re-loaded under the write guard. If it moved since
    /// `stamp` was captured, nothing is inserted and the caller must not use
    /// the answer.
    fn admit_ptc(
        &self,
        cache: &mut RwLockWriteGuard<'_, HashMap<u64, PtcEpochDutyCache>>,
        epoch: u64,
        mut entry: PtcEpochDutyCache,
        stamp: FetchStamp,
    ) -> Result<(), DutyTrackerError> {
        if !visible(stamp.0, self.generation_now()) {
            return Err(DutyTrackerError::RevokedDuringFetch { epoch });
        }
        #[cfg(test)]
        hooks::fire(&hooks::BEFORE_INSERT);
        entry.fetched_gen = stamp.0;
        cache.insert(epoch, entry);
        Ok(())
    }

    /// Insert `entry`, fetched for `epoch`, under its sync period stamped with
    /// `stamp`: the only sync-committee insert path.
    ///
    /// The generation is re-loaded under the write guard. If it moved since
    /// `stamp` was captured, nothing is inserted and the caller must not use
    /// the answer.
    fn admit_sync(
        &self,
        cache: &mut RwLockWriteGuard<'_, HashMap<u64, SyncPeriodDutyCache>>,
        epoch: u64,
        mut entry: SyncPeriodDutyCache,
        stamp: FetchStamp,
    ) -> Result<(), DutyTrackerError> {
        if !visible(stamp.0, self.generation_now()) {
            return Err(DutyTrackerError::RevokedDuringFetch { epoch });
        }
        #[cfg(test)]
        hooks::fire(&hooks::BEFORE_INSERT);
        entry.fetched_gen = stamp.0;
        cache.insert(Self::sync_committee_period(epoch), entry);
        Ok(())
    }

    #[tracing::instrument(name = "duty_tracker.fetch_attester_duties", level = "debug", skip_all, fields(epoch =epoch, duty = %observability::logging::fields::Duty::Attestation.as_str()))]
    pub async fn fetch_duties_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Vec<AttesterDuty>, DutyTrackerError> {
        let indices = self.index_source.indices();
        debug!(epoch = epoch, "Fetching duties for epoch");

        let stamp = self.fetch_stamp();
        let response = self
            .beacon
            .get_attester_duties(epoch, &indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        RVC_DUTIES_FETCHED_TOTAL.with_label_values(&[] as &[&str]).inc();

        let mut cache = self.cache.write().await;

        if let Some(existing_cache) = cache.get(&epoch) {
            if existing_cache.dependent_root != response.dependent_root {
                warn!(
                    epoch = epoch,
                    old_root = %existing_cache.dependent_root,
                    new_root = %response.dependent_root,
                    "Dependent root changed, invalidating cache"
                );
            }
        }

        let (mut epoch_cache, _rejected) =
            EpochDutyCache::from_response(response.dependent_root.clone(), &response.data, epoch);
        epoch_cache.indices = indices;

        self.admit_attester(&mut cache, epoch, epoch_cache, stamp)?;

        info!(
            epoch = epoch,
            duties_count = response.data.len(),
            dependent_root = %response.dependent_root,
            "Cached duties for epoch"
        );

        Ok(response.data)
    }

    #[tracing::instrument(
        name = "duty_tracker.get_duty",
        level = "debug",
        skip_all,
        fields(
            slot = slot,
            epoch = slot / SLOTS_PER_EPOCH,
            validator_index = validator_index,
            committee_index = committee_index
        )
    )]
    pub async fn get_duty(
        &self,
        slot: u64,
        committee_index: u64,
        validator_index: u64,
    ) -> Result<TypedAttesterDuty, DutyTrackerError> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.attester_read().await;
        let now = self.generation_now();

        let key = DutyCacheKey { slot, committee_index, validator_index };

        if let Some(epoch_cache) = servable(&cache, epoch, now) {
            if let Some(duty) = epoch_cache.get(&key) {
                debug!(slot, epoch, cache_type = "attester", "Cache hit");
                return Ok(duty.clone());
            }
        }

        debug!(slot, epoch, cache_type = "attester", "Cache miss");
        Err(DutyTrackerError::DutyNotFound { slot, committee_index, validator_index })
    }

    #[tracing::instrument(name = "duty_tracker.check_attester_reorg", level = "debug", skip_all, fields(epoch =epoch, duty = %observability::logging::fields::Duty::Attestation.as_str()))]
    pub async fn check_and_refetch_if_root_changed(
        &self,
        epoch: u64,
    ) -> Result<bool, DutyTrackerError> {
        let indices = self.index_source.indices();
        let stamp = self.fetch_stamp();
        // Fetch from BN first (no lock held) to avoid TOCTOU race
        let response = self
            .beacon
            .get_attester_duties(epoch, &indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        // Acquire write lock and compare-and-swap atomically. An entry that is
        // stale under the stamp counts as absent.
        let mut cache = self.cache.write().await;
        let cached = servable(&cache, epoch, stamp.0);
        let same_snapshot = cached
            .is_some_and(|c| c.dependent_root == response.dependent_root && c.indices == indices);
        if same_snapshot {
            return Ok(false);
        }

        let root_changed =
            cached.map(|c| c.dependent_root != response.dependent_root).unwrap_or(true);
        if root_changed {
            info!(
                epoch = epoch,
                old_root = ?cached.map(|c| c.dependent_root.clone()),
                new_root = %response.dependent_root,
                "Dependent root changed, refetching duties"
            );
        } else {
            debug!(epoch, "Index snapshot changed, replacing cached attester duties");
        }

        let (mut epoch_cache, _rejected) =
            EpochDutyCache::from_response(response.dependent_root.clone(), &response.data, epoch);
        epoch_cache.indices = indices;

        self.admit_attester(&mut cache, epoch, epoch_cache, stamp)?;
        Ok(root_changed)
    }

    #[tracing::instrument(name = "duty_tracker.evict_old_caches", level = "debug", skip_all, fields(epoch =current_epoch))]
    pub async fn evict_old_caches(&self, current_epoch: u64) {
        let retain_epoch = current_epoch.saturating_sub(2);

        let mut cache = self.cache.write().await;
        let before = cache.len();
        cache.retain(|&epoch, _| epoch >= retain_epoch);
        let attester_removed = before - cache.len();
        drop(cache);

        let mut pcache = self.proposer_cache.write().await;
        let before = pcache.len();
        pcache.retain(|&epoch, _| epoch >= retain_epoch);
        let proposer_removed = before - pcache.len();
        drop(pcache);

        let mut ptcache = self.ptc_cache.write().await;
        let before = ptcache.len();
        ptcache.retain(|&epoch, _| epoch >= retain_epoch);
        let ptc_removed = before - ptcache.len();
        drop(ptcache);

        let current_period = current_epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let retain_period = current_period.saturating_sub(1);
        let mut scache = self.sync_committee_cache.write().await;
        let before = scache.len();
        scache.retain(|&period, _| period >= retain_period);
        let sync_removed = before - scache.len();
        drop(scache);

        if attester_removed > 0 || proposer_removed > 0 || ptc_removed > 0 || sync_removed > 0 {
            debug!(
                current_epoch,
                retain_epoch,
                attester_removed,
                proposer_removed,
                ptc_removed,
                sync_removed,
                reason = "epoch older than retain window",
                "Evicted old duty caches"
            );
        }
    }

    #[tracing::instrument(
        name = "duty_tracker.get_duties_for_slot",
        level = "debug",
        skip_all,
        fields(slot = slot, epoch = slot / SLOTS_PER_EPOCH)
    )]
    pub async fn get_duties_for_slot(&self, slot: u64) -> Vec<TypedAttesterDuty> {
        self.slot_duty_lookups.fetch_add(1, Ordering::Relaxed);
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.attester_read().await;
        let now = self.generation_now();

        let Some(epoch_cache) = servable(&cache, epoch, now) else {
            debug!(slot, epoch, cache_type = "attester", "Cache miss for slot");
            return Vec::new();
        };

        let duties: Vec<TypedAttesterDuty> = epoch_cache
            .duties
            .iter()
            .filter(|(key, _)| key.slot == slot)
            .map(|(_, duty)| duty.clone())
            .collect();

        debug!(slot, epoch, cache_type = "attester", count = duties.len(), "Cache hit for slot");
        duties
    }

    pub async fn clear_epoch_cache(&self, epoch: u64) {
        let mut cache = self.cache.write().await;
        cache.remove(&epoch);
        debug!(epoch = epoch, "Cleared cache for epoch");
    }

    pub async fn clear_cache(&self) {
        self.cache.write().await.clear();
        self.proposer_cache.write().await.clear();
        self.ptc_cache.write().await.clear();
        self.sync_committee_cache.write().await.clear();
        debug!("Cleared all duty caches");
    }

    pub async fn is_epoch_cached(&self, epoch: u64) -> bool {
        let indices = self.index_source.indices();
        let cache = self.attester_read().await;
        let now = self.generation_now();
        servable(&cache, epoch, now).is_some_and(|entry| entry.indices == indices)
    }

    pub async fn get_cached_dependent_root(&self, epoch: u64) -> Option<String> {
        let cache = self.attester_read().await;
        let now = self.generation_now();
        servable(&cache, epoch, now).map(|c| c.dependent_root.clone())
    }

    /// Test-only: write proposer duties with no beacon node request.
    ///
    /// It stamps with the generation loaded inside its write guard, so the
    /// entry is always current. Production writers capture the stamp before
    /// their request and insert through `admit_proposer`.
    ///
    /// Returns `true` when a visible entry for this epoch had a different
    /// `dependent_root` — the signal to re-broadcast preferences.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn cache_proposer_duties(
        &self,
        epoch: u64,
        dependent_root: String,
        duties: &[ProposerDuty],
    ) -> bool {
        let mut cache = self.proposer_cache.write().await;
        let stamp = self.fetch_stamp();
        insert_proposer(&mut cache, epoch, dependent_root, duties, stamp)
    }

    #[tracing::instrument(name = "duty_tracker.fetch_proposer_duties", level = "debug", skip_all, fields(epoch =epoch, duty = %observability::logging::fields::Duty::Block.as_str()))]
    pub async fn fetch_proposer_duties(
        &self,
        epoch: u64,
    ) -> Result<Vec<ProposerDuty>, DutyTrackerError> {
        debug!(epoch = epoch, "Fetching proposer duties for epoch");

        let stamp = self.fetch_stamp();
        let response = self
            .beacon
            .get_proposer_duties(epoch, &self.fork_schedule)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        self.admit_proposer(epoch, response.dependent_root.clone(), &response.data, stamp).await?;

        info!(epoch = epoch, count = response.data.len(), "Cached proposer duties for epoch");

        Ok(response.data)
    }

    #[tracing::instrument(
        name = "duty_tracker.get_proposer_duty",
        level = "debug",
        skip_all,
        fields(slot = slot, epoch = slot / SLOTS_PER_EPOCH)
    )]
    pub async fn get_proposer_duty(&self, slot: u64) -> Option<TypedProposerDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.proposer_read().await;
        let now = self.generation_now();
        let result = servable(&cache, epoch, now).and_then(|c| c.get(&slot)).cloned();
        if result.is_some() {
            debug!(slot, epoch, cache_type = "proposer", "Cache hit");
        } else {
            debug!(slot, epoch, cache_type = "proposer", "Cache miss");
        }
        result
    }

    pub async fn get_cached_proposer_dependent_root(&self, epoch: u64) -> Option<String> {
        let cache = self.proposer_read().await;
        let now = self.generation_now();
        servable(&cache, epoch, now).map(|c| c.dependent_root.clone())
    }

    #[tracing::instrument(name = "duty_tracker.check_proposer_reorg", level = "debug", skip_all, fields(epoch =epoch, duty = %observability::logging::fields::Duty::Block.as_str()))]
    pub async fn check_and_refetch_proposer_if_root_changed(
        &self,
        epoch: u64,
    ) -> Result<bool, DutyTrackerError> {
        let stamp = self.fetch_stamp();
        // A stale entry counts as uncached.
        let cached_root = {
            let cache = self.proposer_read().await;
            let now = self.generation_now();
            servable(&cache, epoch, now).map(|c| c.dependent_root.clone())
        };

        if cached_root.is_none() {
            self.fetch_proposer_duties(epoch).await?;
            return Ok(true);
        }

        let response = self
            .beacon
            .get_proposer_duties(epoch, &self.fork_schedule)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        if cached_root.as_ref() != Some(&response.dependent_root) {
            info!(
                epoch = epoch,
                old_root = ?cached_root,
                new_root = %response.dependent_root,
                "Proposer dependent root changed, refetching duties"
            );

            return self
                .admit_proposer(epoch, response.dependent_root, &response.data, stamp)
                .await;
        }

        Ok(false)
    }

    pub async fn is_proposer_epoch_cached(&self, epoch: u64) -> bool {
        let cache = self.proposer_read().await;
        let now = self.generation_now();
        servable(&cache, epoch, now).is_some()
    }

    #[tracing::instrument(name = "duty_tracker.fetch_ptc_duties", level = "debug", skip_all, fields(epoch =epoch))]
    pub async fn fetch_ptc_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<Vec<PtcDuty>, DutyTrackerError> {
        debug!(epoch = epoch, "Fetching PTC duties for epoch");

        let stamp = self.fetch_stamp();
        let response = self
            .beacon
            .post_ptc_duties(epoch, validator_indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        RVC_PTC_DUTIES_FETCHED_TOTAL.with_label_values(&[] as &[&str]).inc();

        let (mut epoch_cache, _rejected) =
            PtcEpochDutyCache::from_response(response.dependent_root.clone(), &response.data);
        epoch_cache.indices = validator_indices.to_vec();

        let mut cache = self.ptc_cache.write().await;
        self.admit_ptc(&mut cache, epoch, epoch_cache, stamp)?;

        info!(epoch = epoch, count = response.data.len(), "Cached PTC duties for epoch");

        Ok(response.data)
    }

    /// Fetch PTC duties for `epoch` using the tracker's validator indices.
    pub async fn fetch_ptc_duties_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Vec<PtcDuty>, DutyTrackerError> {
        let indices = self.index_source.indices();
        self.fetch_ptc_duties(epoch, &indices).await
    }

    pub async fn get_ptc_duties_for_slot(&self, slot: u64) -> Vec<TypedPtcDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.ptc_read().await;
        let now = self.generation_now();
        match servable(&cache, epoch, now).and_then(|c| c.get(&slot)) {
            Some(duties) => {
                debug!(slot, epoch, cache_type = "ptc", count = duties.len(), "Cache hit");
                duties.to_vec()
            }
            None => {
                debug!(slot, epoch, cache_type = "ptc", "Cache miss");
                Vec::new()
            }
        }
    }

    pub async fn get_cached_ptc_dependent_root(&self, epoch: u64) -> Option<String> {
        let cache = self.ptc_read().await;
        let now = self.generation_now();
        servable(&cache, epoch, now).map(|c| c.dependent_root.clone())
    }

    #[tracing::instrument(name = "duty_tracker.check_ptc_reorg", level = "debug", skip_all, fields(epoch =epoch))]
    pub async fn check_and_refetch_ptc_if_root_changed(
        &self,
        epoch: u64,
    ) -> Result<bool, DutyTrackerError> {
        let stamp = self.fetch_stamp();
        let indices = self.index_source.indices();
        // A stale entry counts as uncached.
        let cached = {
            let cache = self.ptc_read().await;
            let now = self.generation_now();
            servable(&cache, epoch, now).is_some()
        };

        if !cached {
            self.fetch_ptc_duties(epoch, &indices).await?;
            return Ok(true);
        }

        let response = self
            .beacon
            .post_ptc_duties(epoch, &indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        // Compare against the entry visible now, under the write guard: the
        // read above may be outdated by another writer.
        let mut cache = self.ptc_cache.write().await;
        let cached = servable(&cache, epoch, stamp.0);
        let same_snapshot = cached
            .is_some_and(|c| c.dependent_root == response.dependent_root && c.indices == indices);
        if same_snapshot {
            return Ok(false);
        }

        let root_changed =
            cached.map(|c| c.dependent_root != response.dependent_root).unwrap_or(true);
        if root_changed {
            info!(
                epoch = epoch,
                old_root = ?cached.map(|c| c.dependent_root.clone()),
                new_root = %response.dependent_root,
                "PTC dependent root changed, refetching duties"
            );
        } else {
            debug!(epoch, "Index snapshot changed, replacing cached PTC duties");
        }

        let (mut epoch_cache, _rejected) =
            PtcEpochDutyCache::from_response(response.dependent_root.clone(), &response.data);
        epoch_cache.indices = indices;

        self.admit_ptc(&mut cache, epoch, epoch_cache, stamp)?;
        Ok(root_changed)
    }

    pub async fn is_ptc_epoch_cached(&self, epoch: u64) -> bool {
        let indices = self.index_source.indices();
        let cache = self.ptc_read().await;
        let now = self.generation_now();
        servable(&cache, epoch, now).is_some_and(|entry| entry.indices == indices)
    }

    #[tracing::instrument(name = "duty_tracker.fetch_sync_committee_duties", level = "debug", skip_all, fields(epoch =epoch, duty = %observability::logging::fields::Duty::SyncCommittee.as_str()))]
    pub async fn fetch_sync_committee_duties(
        &self,
        epoch: u64,
    ) -> Result<Vec<SyncCommitteeDuty>, DutyTrackerError> {
        let indices = self.index_source.indices();
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        debug!(epoch = epoch, period = period, "Fetching sync committee duties");

        let stamp = self.fetch_stamp();
        let response = self
            .beacon
            .post_sync_committee_duties(epoch, &indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        let mut period_cache = SyncPeriodDutyCache::from_response(response.data.clone());
        period_cache.indices = indices;
        let mut cache = self.sync_committee_cache.write().await;
        self.admit_sync(&mut cache, epoch, period_cache, stamp)?;

        info!(
            epoch = epoch,
            period = period,
            count = response.data.len(),
            "Cached sync committee duties for period"
        );

        Ok(response.data)
    }

    #[tracing::instrument(
        name = "duty_tracker.get_sync_committee_duties",
        level = "debug",
        skip_all,
        fields(slot = slot, epoch = slot / SLOTS_PER_EPOCH)
    )]
    pub async fn get_sync_committee_duties(&self, slot: u64) -> Vec<SyncCommitteeDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let cache = self.sync_read().await;
        let now = self.generation_now();
        match servable(&cache, period, now) {
            Some(period_cache) => {
                debug!(slot, epoch, cache_type = "sync", "Cache hit");
                period_cache.duties.clone()
            }
            None => {
                debug!(slot, epoch, cache_type = "sync", "Cache miss");
                Vec::new()
            }
        }
    }

    pub async fn is_sync_period_cached(&self, epoch: u64) -> bool {
        let indices = self.index_source.indices();
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let cache = self.sync_read().await;
        let now = self.generation_now();
        servable(&cache, period, now).is_some_and(|entry| entry.indices == indices)
    }

    pub fn sync_committee_period(epoch: u64) -> u64 {
        epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD
    }

    pub fn is_sync_committee_period_boundary(epoch: u64) -> bool {
        epoch.is_multiple_of(EPOCHS_PER_SYNC_COMMITTEE_PERIOD)
    }

    pub fn is_epoch_boundary_slot(slot: u64) -> bool {
        slot.is_multiple_of(SLOTS_PER_EPOCH)
    }

    pub fn slot_to_epoch(slot: u64) -> u64 {
        slot / SLOTS_PER_EPOCH
    }

    pub async fn cached_duty_counts(&self, epoch: u64) -> (usize, usize, usize, usize) {
        let attester_count = {
            let cache = self.attester_read().await;
            let now = self.generation_now();
            servable(&cache, epoch, now).map_or(0, |c| c.duties.len())
        };
        let proposer_count = {
            let cache = self.proposer_read().await;
            let now = self.generation_now();
            servable(&cache, epoch, now).map_or(0, |c| c.duties.len())
        };
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let sync_count = {
            let cache = self.sync_read().await;
            let now = self.generation_now();
            servable(&cache, period, now).map_or(0, |c| c.duties.len())
        };
        let ptc_count = {
            let cache = self.ptc_read().await;
            let now = self.generation_now();
            servable(&cache, epoch, now).map_or(0, |c| c.duty_count())
        };
        (attester_count, proposer_count, sync_count, ptc_count)
    }
}

#[cfg(test)]
struct Flipping(std::sync::Mutex<Vec<Vec<String>>>);

#[cfg(test)]
impl ValidatorIndexSource for Flipping {
    fn indices(&self) -> Vec<String> {
        self.0.lock().expect("index sequence").pop().expect("index sequence exhausted")
    }
}

#[cfg(test)]
#[tokio::test]
async fn a_changed_source_is_reflected_in_the_next_duty_request() {
    use bn_manager::MockBeaconNodeClient;

    let first = vec!["111".to_string()];
    let second = vec!["222".to_string()];
    let source = Arc::new(Flipping(std::sync::Mutex::new(vec![second.clone(), first.clone()])));
    let mock = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_attester_duties(|_epoch, _indices| Ok(empty_attester_response())),
    );
    let tracker = DutyTracker::new_with_source(mock.clone(), source);

    tracker.fetch_duties_for_epoch(1).await.unwrap();
    tracker.fetch_duties_for_epoch(2).await.unwrap();

    let calls = mock.get_attester_duties_calls();
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0], (1, first));
    assert_eq!(calls[1], (2, second));
}

#[cfg(test)]
fn empty_attester_response() -> bn_manager::AttesterDutiesResponse {
    bn_manager::AttesterDutiesResponse {
        dependent_root: "0xroot".to_string(),
        execution_optimistic: false,
        data: Vec::new(),
    }
}

#[cfg(test)]
fn empty_sync_response() -> bn_manager::SyncCommitteeDutiesResponse {
    bn_manager::SyncCommitteeDutiesResponse { execution_optimistic: false, data: Vec::new() }
}

#[cfg(test)]
fn empty_ptc_response() -> bn_manager::PtcDutiesResponse {
    bn_manager::PtcDutiesResponse {
        dependent_root: "0xroot".to_string(),
        execution_optimistic: false,
        data: Vec::new(),
    }
}

#[cfg(test)]
#[tokio::test]
async fn one_fetch_call_sees_one_snapshot() {
    use std::sync::Mutex;

    use bn_manager::MockBeaconNodeClient;

    // Pop order is back-to-front. Each set is one indices() result; a fetch
    // that sampled twice would send a later set or exhaust the sequence.
    let attester = vec!["1".to_string(), "1b".to_string()];
    let sync = vec!["2".to_string(), "2b".to_string()];
    let ptc = vec!["3".to_string(), "3b".to_string()];
    let attester_reorg = vec!["4".to_string(), "4b".to_string()];
    let ptc_warm = vec!["5".to_string(), "5b".to_string()];
    let ptc_cold = vec!["6".to_string(), "6b".to_string()];
    let source = Arc::new(Flipping(Mutex::new(vec![
        ptc_cold.clone(),
        ptc_warm.clone(),
        attester_reorg.clone(),
        ptc.clone(),
        sync.clone(),
        attester.clone(),
    ])));

    let sync_seen = Arc::new(Mutex::new(Vec::new()));
    let sync_seen_for_handler = Arc::clone(&sync_seen);
    let mock = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_attester_duties(|_epoch, _indices| Ok(empty_attester_response()))
            .with_post_sync_committee_duties(move |_epoch, indices| {
                sync_seen_for_handler.lock().expect("sync calls").push(indices);
                Ok(empty_sync_response())
            })
            .with_post_ptc_duties(|_epoch, _indices| Ok(empty_ptc_response())),
    );
    let index_source: Arc<dyn ValidatorIndexSource> = source.clone();
    let tracker = DutyTracker::new_with_source(mock.clone(), index_source);

    tracker.fetch_duties_for_epoch(10).await.unwrap();
    tracker.fetch_sync_committee_duties(10).await.unwrap();
    tracker.fetch_ptc_duties_for_epoch(10).await.unwrap();
    tracker.check_and_refetch_if_root_changed(10).await.unwrap();
    tracker.check_and_refetch_ptc_if_root_changed(10).await.unwrap();
    tracker.check_and_refetch_ptc_if_root_changed(11).await.unwrap();

    let attester_calls = mock.get_attester_duties_calls();
    assert_eq!(attester_calls[0].1, attester);
    assert_eq!(attester_calls[1].1, attester_reorg);
    assert_eq!(sync_seen.lock().expect("sync calls").as_slice(), &[sync]);
    let ptc_calls = mock.post_ptc_duties_calls();
    assert_eq!(ptc_calls[0].1, ptc);
    assert_eq!(ptc_calls[1].1, ptc_warm);
    assert_eq!(ptc_calls[2].1, ptc_cold);
    assert!(source.0.lock().expect("index sequence").is_empty());
}

#[cfg(test)]
#[tokio::test]
async fn vec_string_wrapper_preserves_existing_behaviour() {
    use std::sync::Mutex;

    use bn_manager::MockBeaconNodeClient;

    let indices = vec!["1234".to_string(), "5678".to_string()];
    let sync_seen = Arc::new(Mutex::new(Vec::new()));
    let sync_seen_for_handler = Arc::clone(&sync_seen);
    let mock = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_attester_duties(|_epoch, _indices| Ok(empty_attester_response()))
            .with_post_sync_committee_duties(move |_epoch, got| {
                sync_seen_for_handler.lock().expect("sync calls").push(got);
                Ok(empty_sync_response())
            })
            .with_post_ptc_duties(|_epoch, _indices| Ok(empty_ptc_response())),
    );
    let tracker = DutyTracker::new(mock.clone(), indices.clone());

    tracker.fetch_duties_for_epoch(10).await.unwrap();
    tracker.fetch_sync_committee_duties(10).await.unwrap();
    tracker.fetch_ptc_duties_for_epoch(10).await.unwrap();
    tracker.check_and_refetch_if_root_changed(10).await.unwrap();
    tracker.check_and_refetch_ptc_if_root_changed(10).await.unwrap();
    tracker.check_and_refetch_ptc_if_root_changed(11).await.unwrap();

    let attester_calls = mock.get_attester_duties_calls();
    assert_eq!(attester_calls[0], (10, indices.clone()));
    assert_eq!(attester_calls[1], (10, indices.clone()));
    let sync_calls = sync_seen.lock().expect("sync calls");
    assert_eq!(sync_calls.len(), 1);
    assert_eq!(sync_calls[0], indices.clone());
    let ptc_calls = mock.post_ptc_duties_calls();
    assert_eq!(ptc_calls[0], (10, indices.clone()));
    assert_eq!(ptc_calls[1], (10, indices.clone()));
    assert_eq!(ptc_calls[2], (11, indices));
}

#[cfg(test)]
struct HeldIndices(std::sync::Mutex<Vec<String>>);

#[cfg(test)]
impl ValidatorIndexSource for HeldIndices {
    fn indices(&self) -> Vec<String> {
        self.0.lock().expect("indices").clone()
    }
}

#[cfg(test)]
#[tokio::test]
async fn changed_source_replaces_cached_duties_for_the_same_head() {
    use bn_manager::{
        AttesterDutiesResponse, AttesterDuty, MockBeaconNodeClient, PtcDutiesResponse, PtcDuty,
        SyncCommitteeDutiesResponse,
    };
    use eth_types::SyncCommitteeDuty;

    let source = Arc::new(HeldIndices(std::sync::Mutex::new(vec!["111".to_string()])));
    let mock = Arc::new(
        MockBeaconNodeClient::new()
            .with_get_attester_duties(|_epoch, indices| {
                Ok(AttesterDutiesResponse {
                    dependent_root: "0xroot".to_string(),
                    execution_optimistic: false,
                    data: indices
                        .into_iter()
                        .map(|validator_index| AttesterDuty {
                            pubkey: format!("0x{validator_index}"),
                            validator_index,
                            committee_index: "1".to_string(),
                            committee_length: "128".to_string(),
                            committees_at_slot: "64".to_string(),
                            validator_committee_index: "0".to_string(),
                            slot: "320".to_string(),
                        })
                        .collect(),
                })
            })
            .with_post_ptc_duties(|_epoch, indices| {
                Ok(PtcDutiesResponse {
                    dependent_root: "0xroot".to_string(),
                    execution_optimistic: false,
                    data: indices
                        .into_iter()
                        .map(|validator_index| PtcDuty {
                            pubkey: format!("0x{validator_index}"),
                            validator_index,
                            slot: "320".to_string(),
                        })
                        .collect(),
                })
            })
            .with_post_sync_committee_duties(|_epoch, indices| {
                Ok(SyncCommitteeDutiesResponse {
                    execution_optimistic: false,
                    data: indices
                        .into_iter()
                        .map(|validator_index| SyncCommitteeDuty {
                            pubkey: [0x22; 48],
                            validator_index: validator_index.parse().expect("numeric index"),
                            validator_sync_committee_indices: vec![0],
                        })
                        .collect(),
                })
            }),
    );
    let index_source: Arc<dyn ValidatorIndexSource> = source.clone();
    let tracker = DutyTracker::new_with_source(mock, index_source);

    tracker.fetch_duties_for_epoch(10).await.unwrap();
    tracker.fetch_ptc_duties_for_epoch(10).await.unwrap();
    tracker.fetch_sync_committee_duties(10).await.unwrap();
    assert!(tracker.is_epoch_cached(10).await);
    assert!(tracker.is_ptc_epoch_cached(10).await);
    assert!(tracker.is_sync_period_cached(10).await);
    assert_eq!(tracker.get_duties_for_slot(320).await[0].validator_index, 111);
    assert_eq!(tracker.get_ptc_duties_for_slot(320).await[0].validator_index, 111);
    assert_eq!(tracker.get_sync_committee_duties(320).await[0].validator_index, 111);

    *source.0.lock().expect("indices") = vec!["222".to_string()];

    assert!(!tracker.is_epoch_cached(10).await);
    assert!(!tracker.is_ptc_epoch_cached(10).await);
    assert!(!tracker.is_sync_period_cached(10).await);

    let attester_root_changed = tracker.check_and_refetch_if_root_changed(10).await.unwrap();
    assert!(!attester_root_changed);
    let ptc_root_changed = tracker.check_and_refetch_ptc_if_root_changed(10).await.unwrap();
    assert!(!ptc_root_changed);
    tracker.fetch_sync_committee_duties(10).await.unwrap();

    let attester = tracker.get_duties_for_slot(320).await;
    assert_eq!(attester.len(), 1);
    assert_eq!(attester[0].validator_index, 222);
    let ptc = tracker.get_ptc_duties_for_slot(320).await;
    assert_eq!(ptc.len(), 1);
    assert_eq!(ptc[0].validator_index, 222);
    let sync = tracker.get_sync_committee_duties(320).await;
    assert_eq!(sync.len(), 1);
    assert_eq!(sync[0].validator_index, 222);
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use bn_manager::{
        AttesterDutiesResponse, AttesterDuty, BeaconError, DutiesProvider, MockBeaconNodeClient,
        MockMethod, ProposerDutiesResponse, ProposerDuty, PtcDutiesResponse, PtcDuty,
        SyncCommitteeDutiesResponse,
    };
    use eth_types::SyncCommitteeDuty;
    use tracing_subscriber::prelude::*;

    use super::*;

    fn empty_beacon() -> Arc<dyn DutiesProvider> {
        Arc::new(MockBeaconNodeClient::new())
    }

    fn attester_duty(slot: u64, committee_index: u64, validator_index: &str) -> AttesterDuty {
        AttesterDuty {
            pubkey: format!("0xpubkey_{validator_index}"),
            validator_index: validator_index.to_string(),
            committee_index: committee_index.to_string(),
            committee_length: "128".to_string(),
            committees_at_slot: "64".to_string(),
            validator_committee_index: "25".to_string(),
            slot: slot.to_string(),
        }
    }

    fn attester_response(
        duties: Vec<(u64, u64, &str)>,
        dependent_root: &str,
    ) -> AttesterDutiesResponse {
        AttesterDutiesResponse {
            dependent_root: dependent_root.to_string(),
            execution_optimistic: false,
            data: duties
                .into_iter()
                .map(|(slot, committee_index, validator_index)| {
                    attester_duty(slot, committee_index, validator_index)
                })
                .collect(),
        }
    }

    fn proposer_duty(slot: u64, validator_index: &str, pubkey: &str) -> ProposerDuty {
        ProposerDuty {
            pubkey: pubkey.to_string(),
            validator_index: validator_index.to_string(),
            slot: slot.to_string(),
        }
    }

    fn proposer_response(
        duties: Vec<(u64, &str, &str)>,
        dependent_root: &str,
    ) -> ProposerDutiesResponse {
        ProposerDutiesResponse {
            dependent_root: dependent_root.to_string(),
            execution_optimistic: false,
            data: duties
                .into_iter()
                .map(|(slot, validator_index, pubkey)| proposer_duty(slot, validator_index, pubkey))
                .collect(),
        }
    }

    fn mock_sync_pubkey() -> [u8; 48] {
        [0x11; 48]
    }

    fn sync_response(duties: Vec<(u64, [u8; 48], Vec<u64>)>) -> SyncCommitteeDutiesResponse {
        SyncCommitteeDutiesResponse {
            execution_optimistic: false,
            data: duties
                .into_iter()
                .map(|(validator_index, pubkey, indices)| SyncCommitteeDuty {
                    pubkey,
                    validator_index,
                    validator_sync_committee_indices: indices,
                })
                .collect(),
        }
    }

    fn mock_attester(resp: AttesterDutiesResponse) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new()
            .with_get_attester_duties(move |_epoch, _indices| Ok(resp.clone()))
    }

    fn mock_attester_queue(responses: Vec<AttesterDutiesResponse>) -> MockBeaconNodeClient {
        let queue = Arc::new(Mutex::new(VecDeque::from(responses)));
        MockBeaconNodeClient::new().with_get_attester_duties(move |_epoch, _indices| {
            queue
                .lock()
                .expect("queue")
                .pop_front()
                .ok_or_else(|| BeaconError::HttpError("attester response queue exhausted".into()))
        })
    }

    fn mock_attester_by_epoch(map: HashMap<u64, AttesterDutiesResponse>) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_attester_duties(move |epoch, _indices| {
            map.get(&epoch).cloned().ok_or_else(|| {
                BeaconError::HttpError(format!("no attester mock for epoch {epoch}"))
            })
        })
    }

    fn mock_proposer(resp: ProposerDutiesResponse) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_proposer_duties(move |_epoch| Ok(resp.clone()))
    }

    fn mock_proposer_queue(responses: Vec<ProposerDutiesResponse>) -> MockBeaconNodeClient {
        let queue = Arc::new(Mutex::new(VecDeque::from(responses)));
        MockBeaconNodeClient::new().with_get_proposer_duties(move |_epoch| {
            queue
                .lock()
                .expect("queue")
                .pop_front()
                .ok_or_else(|| BeaconError::HttpError("proposer response queue exhausted".into()))
        })
    }

    fn mock_proposer_by_epoch(map: HashMap<u64, ProposerDutiesResponse>) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_proposer_duties(move |epoch| {
            map.get(&epoch).cloned().ok_or_else(|| {
                BeaconError::HttpError(format!("no proposer mock for epoch {epoch}"))
            })
        })
    }

    fn ptc_duty(slot: u64, validator_index: &str, pubkey: &str) -> PtcDuty {
        PtcDuty {
            pubkey: pubkey.to_string(),
            validator_index: validator_index.to_string(),
            slot: slot.to_string(),
        }
    }

    fn ptc_response(duties: Vec<(u64, &str, &str)>, dependent_root: &str) -> PtcDutiesResponse {
        PtcDutiesResponse {
            dependent_root: dependent_root.to_string(),
            execution_optimistic: false,
            data: duties
                .into_iter()
                .map(|(slot, validator_index, pubkey)| ptc_duty(slot, validator_index, pubkey))
                .collect(),
        }
    }

    fn mock_ptc(resp: PtcDutiesResponse) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_post_ptc_duties(move |_epoch, _indices| Ok(resp.clone()))
    }

    fn mock_ptc_queue(responses: Vec<PtcDutiesResponse>) -> MockBeaconNodeClient {
        let queue = Arc::new(Mutex::new(VecDeque::from(responses)));
        MockBeaconNodeClient::new().with_post_ptc_duties(move |_epoch, _indices| {
            queue
                .lock()
                .expect("queue")
                .pop_front()
                .ok_or_else(|| BeaconError::HttpError("ptc response queue exhausted".into()))
        })
    }

    fn mock_ptc_by_epoch(map: HashMap<u64, PtcDutiesResponse>) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_post_ptc_duties(move |epoch, _indices| {
            map.get(&epoch)
                .cloned()
                .ok_or_else(|| BeaconError::HttpError(format!("no ptc mock for epoch {epoch}")))
        })
    }

    fn mock_sync(resp: SyncCommitteeDutiesResponse) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new()
            .with_post_sync_committee_duties(move |_epoch, _indices| Ok(resp.clone()))
    }

    fn as_beacon(mock: MockBeaconNodeClient) -> Arc<dyn DutiesProvider> {
        Arc::new(mock)
    }

    #[tokio::test]
    async fn test_duty_tracker_new() {
        let beacon = empty_beacon();
        let validator_indices = vec!["1234".to_string(), "5678".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        assert!(!tracker.is_epoch_cached(0).await);
    }

    #[tokio::test]
    async fn test_fetch_duties_for_epoch_success() {
        let mock = Arc::new(mock_attester(attester_response(
            vec![(320, 1, "1234"), (321, 2, "1234")],
            "0xdeproot_abc123",
        )));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(mock.clone(), validator_indices);
        let duties = tracker.fetch_duties_for_epoch(10).await.unwrap();

        assert_eq!(duties.len(), 2);
        assert_eq!(duties[0].slot, "320");
        assert_eq!(duties[1].slot, "321");
        assert!(tracker.is_epoch_cached(10).await);

        let calls = mock.get_attester_duties_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 10);
        assert_eq!(calls[0].1, vec!["1234".to_string()]);
    }

    #[tokio::test]
    async fn test_get_duty_from_cache() {
        let beacon =
            as_beacon(mock_attester(attester_response(vec![(320, 1, "1234")], "0xdeproot_abc123")));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let duty = tracker.get_duty(320, 1, 1234).await.unwrap();
        assert_eq!(duty.slot, 320);
        assert_eq!(duty.committee_index, 1);
        assert_eq!(duty.validator_index, 1234);
    }

    /// Issue 2.8: the per-duty fetch-loop detail is `trace` with canonical
    /// fields, and a cache hit is `debug` with the canonical `epoch` (not the
    /// default INFO and not `rvc.epoch`).
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_duty_logging_levels_and_canonical_fields() {
        let beacon =
            as_beacon(mock_attester(attester_response(vec![(320, 1, "1234")], "0xdeproot_abc123")));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();
        let _ = tracker.get_duty(320, 1, 1234).await.unwrap();

        logs_assert(|lines: &[&str]| {
            let cached = lines
                .iter()
                .find(|l| l.contains("cached attester duty"))
                .ok_or_else(|| "no per-duty trace line captured".to_string())?;
            if !cached.contains("TRACE") {
                return Err(format!("per-duty loop detail must be TRACE: {cached}"));
            }
            if !cached.contains("validator_index=1234") {
                return Err(format!("canonical validator_index missing: {cached}"));
            }
            let hit = lines
                .iter()
                .find(|l| l.contains("Cache hit") && l.contains("attester"))
                .ok_or_else(|| "no cache-hit line captured".to_string())?;
            if !hit.contains("DEBUG") {
                return Err(format!("cache hit must be DEBUG: {hit}"));
            }
            if !hit.contains("epoch=10") {
                return Err(format!("canonical epoch missing on cache hit: {hit}"));
            }
            Ok(())
        });
    }

    /// T14 (complete, TRC-4b / #428): exact field key-set of each duty-tracker span at debug.
    ///
    /// Ten sites: six epoch spans (five duty-bearing `{epoch, duty}` plus `evict_old_caches`
    /// `{epoch}` only) and four per-slot lookups. PTC `fetch_ptc_duties` / `check_ptc_reorg`
    /// stay `{epoch}`. `get_ptc_duties_for_slot` stays unspanned.
    /// `evict_old_caches` keeps `fields(epoch = current_epoch)` with no `duty` — a recorded decision.
    #[tokio::test(flavor = "current_thread")]
    async fn test_t14_epoch_span_exact_key_sets_at_debug() {
        let attester = attester_response(vec![(320, 1, "1234")], "0xatt_root");
        let proposer = proposer_response(vec![(320, "1234", "0xpubkey_1234")], "0xprop_root");
        let ptc = ptc_response(vec![(320, "1234", "0xpubkey_1234")], "0xptc_root");
        let sync = sync_response(vec![(1234, mock_sync_pubkey(), vec![0])]);
        let mock = MockBeaconNodeClient::new()
            .with_get_attester_duties({
                let attester = attester.clone();
                move |_epoch, _indices| Ok(attester.clone())
            })
            .with_get_proposer_duties({
                let proposer = proposer.clone();
                move |_epoch| Ok(proposer.clone())
            })
            .with_post_ptc_duties({
                let ptc = ptc.clone();
                move |_epoch, _indices| Ok(ptc.clone())
            })
            .with_post_sync_committee_duties({
                let sync = sync.clone();
                move |_epoch, _indices| Ok(sync.clone())
            });
        let indices = vec!["1234".to_string()];
        let tracker = DutyTracker::new(Arc::new(mock), indices.clone());

        let capture = EpochSpanCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(capture.clone().with_filter(tracing_subscriber::filter::LevelFilter::DEBUG));
        let _guard = tracing::subscriber::set_default(subscriber);

        tracker.fetch_duties_for_epoch(10).await.expect("attester fetch");
        tracker.check_and_refetch_if_root_changed(10).await.expect("attester reorg");
        tracker.fetch_proposer_duties(10).await.expect("proposer fetch");
        tracker.check_and_refetch_proposer_if_root_changed(10).await.expect("proposer reorg");
        tracker.fetch_sync_committee_duties(10).await.expect("sync fetch");
        tracker.fetch_ptc_duties(10, &indices).await.expect("ptc fetch");
        tracker.check_and_refetch_ptc_if_root_changed(10).await.expect("ptc reorg");
        tracker.evict_old_caches(10).await;

        // Four new lookup spans. PTC lookup is called and must not appear.
        let _ = tracker.get_duty(320, 1, 1234).await.expect("attester hit");
        let slot_duties = tracker.get_duties_for_slot(320).await;
        assert_eq!(slot_duties.len(), 1);
        let _ = tracker.get_proposer_duty(320).await.expect("proposer hit");
        assert_eq!(tracker.get_sync_committee_duties(320).await.len(), 1);
        assert_eq!(tracker.get_ptc_duties_for_slot(320).await.len(), 1);

        let spans = capture.state.lock().expect("spans").spans.clone();
        let names: BTreeSet<&str> = spans.iter().map(|s| s.name.as_str()).collect();
        let expected_names: BTreeSet<&str> = [
            "duty_tracker.fetch_attester_duties",
            "duty_tracker.check_attester_reorg",
            "duty_tracker.fetch_proposer_duties",
            "duty_tracker.check_proposer_reorg",
            "duty_tracker.fetch_sync_committee_duties",
            "duty_tracker.evict_old_caches",
            "duty_tracker.fetch_ptc_duties",
            "duty_tracker.check_ptc_reorg",
            "duty_tracker.get_duty",
            "duty_tracker.get_duties_for_slot",
            "duty_tracker.get_proposer_duty",
            "duty_tracker.get_sync_committee_duties",
        ]
        .into_iter()
        .collect();
        assert_eq!(names, expected_names, "eight epoch/ptc spans plus four lookups; no PTC lookup");
        assert!(
            !names.contains("duty_tracker.get_ptc_duties_for_slot"),
            "PTC lookup stays unspanned"
        );

        let duty_bearing = [
            ("duty_tracker.fetch_attester_duties", "attestation"),
            ("duty_tracker.check_attester_reorg", "attestation"),
            ("duty_tracker.fetch_proposer_duties", "block"),
            ("duty_tracker.check_proposer_reorg", "block"),
            ("duty_tracker.fetch_sync_committee_duties", "sync_committee"),
        ];
        let epoch_only = [
            "duty_tracker.evict_old_caches",
            "duty_tracker.fetch_ptc_duties",
            "duty_tracker.check_ptc_reorg",
        ];
        let with_duty = key_set(&["duty", "epoch"]);
        let epoch_keys = key_set(&["epoch"]);

        for (name, duty) in duty_bearing {
            let matched: Vec<_> = spans.iter().filter(|s| s.name == name).collect();
            assert_eq!(matched.len(), 1, "expected one {name} span, got {matched:?}");
            let span = matched[0];
            assert_eq!(span.level, tracing::Level::DEBUG, "{name} must be debug");
            assert_eq!(span.keys, with_duty, "{name} key-set");
            assert_eq!(span.values.get("duty").map(String::as_str), Some(duty), "{name} duty");
            assert_eq!(span.values.get("epoch").map(String::as_str), Some("10"), "{name} epoch");
        }
        for name in epoch_only {
            let matched: Vec<_> = spans.iter().filter(|s| s.name == name).collect();
            assert_eq!(matched.len(), 1, "expected one {name} span, got {matched:?}");
            let span = matched[0];
            assert_eq!(span.level, tracing::Level::DEBUG, "{name} must be debug");
            assert_eq!(span.keys, epoch_keys, "{name} key-set must stay {{epoch}}");
            assert!(!span.values.contains_key("duty"), "{name} must not carry duty");
            assert_eq!(span.values.get("epoch").map(String::as_str), Some("10"), "{name} epoch");
        }

        let lookups: &[(&str, &[&str])] = &[
            ("duty_tracker.get_duty", &["committee_index", "epoch", "slot", "validator_index"]),
            ("duty_tracker.get_duties_for_slot", &["epoch", "slot"]),
            ("duty_tracker.get_proposer_duty", &["epoch", "slot"]),
            ("duty_tracker.get_sync_committee_duties", &["epoch", "slot"]),
        ];
        for (name, keys) in lookups {
            let matched: Vec<_> = spans.iter().filter(|s| s.name == *name).collect();
            assert_eq!(matched.len(), 1, "expected one {name} span, got {matched:?}");
            let span = matched[0];
            assert_eq!(span.level, tracing::Level::DEBUG, "{name} must be debug");
            assert_eq!(span.keys, key_set(keys), "{name} key-set");
            assert!(!span.keys.contains("pubkey"), "{name} must not carry pubkey");
            assert_eq!(span.values.get("slot").map(String::as_str), Some("320"), "{name} slot");
            assert_eq!(span.values.get("epoch").map(String::as_str), Some("10"), "{name} epoch");
        }
        let get_duty = spans.iter().find(|s| s.name == "duty_tracker.get_duty").expect("get_duty");
        assert_eq!(get_duty.values.get("validator_index").map(String::as_str), Some("1234"));
        assert_eq!(get_duty.values.get("committee_index").map(String::as_str), Some("1"));
    }

    /// Negative answer (TRC-4b / #428): a lookup miss is traceable.
    ///
    /// `get_duty` carries `slot`, `validator_index`, and `committee_index` on the span and the
    /// existing "Cache miss" event inside it. `get_duties_for_slot` carries `slot` and `epoch`
    /// and the existing "Cache miss for slot" event.
    #[tokio::test(flavor = "current_thread")]
    async fn test_lookup_miss_span_carries_fields_and_cache_miss_event() {
        let tracker = DutyTracker::new(empty_beacon(), vec!["1234".to_string()]);
        let capture = EpochSpanCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(capture.clone().with_filter(tracing_subscriber::filter::LevelFilter::DEBUG));
        let _guard = tracing::subscriber::set_default(subscriber);

        let missed = tracker.get_duty(320, 1, 1234).await;
        assert!(matches!(missed, Err(DutyTrackerError::DutyNotFound { .. })));
        assert!(tracker.get_duties_for_slot(320).await.is_empty());

        let state = capture.state.lock().expect("spans");
        let get_duty: Vec<_> =
            state.spans.iter().filter(|s| s.name == "duty_tracker.get_duty").collect();
        assert_eq!(get_duty.len(), 1, "get_duty miss must open one span");
        assert_eq!(get_duty[0].level, tracing::Level::DEBUG);
        assert_eq!(
            get_duty[0].keys,
            key_set(&["committee_index", "epoch", "slot", "validator_index"])
        );
        assert_eq!(get_duty[0].values.get("slot").map(String::as_str), Some("320"));
        assert_eq!(get_duty[0].values.get("epoch").map(String::as_str), Some("10"));
        assert_eq!(get_duty[0].values.get("validator_index").map(String::as_str), Some("1234"));
        assert_eq!(get_duty[0].values.get("committee_index").map(String::as_str), Some("1"));
        assert!(!get_duty[0].keys.contains("pubkey"));

        let duty_miss: Vec<_> = state
            .events
            .iter()
            .filter(|e| e.parent_name.as_deref() == Some("duty_tracker.get_duty"))
            .collect();
        assert_eq!(duty_miss.len(), 1, "Cache miss must sit inside get_duty, got {duty_miss:?}");
        assert_eq!(duty_miss[0].message, "Cache miss");
        assert!(duty_miss[0].keys.contains("cache_type"));

        let slot_span: Vec<_> =
            state.spans.iter().filter(|s| s.name == "duty_tracker.get_duties_for_slot").collect();
        assert_eq!(slot_span.len(), 1);
        assert_eq!(slot_span[0].keys, key_set(&["epoch", "slot"]));
        assert_eq!(slot_span[0].values.get("slot").map(String::as_str), Some("320"));
        assert_eq!(slot_span[0].values.get("epoch").map(String::as_str), Some("10"));
        let slot_miss: Vec<_> = state
            .events
            .iter()
            .filter(|e| e.parent_name.as_deref() == Some("duty_tracker.get_duties_for_slot"))
            .collect();
        assert_eq!(slot_miss.len(), 1, "slot miss event must sit inside the span");
        assert_eq!(slot_miss[0].message, "Cache miss for slot");
    }

    /// At info, no `duty_tracker.get_*` span is constructed. An info probe proves the
    /// subscriber is live, so an empty capture is not a vacuous pass.
    #[tokio::test(flavor = "current_thread")]
    async fn test_info_level_constructs_no_duty_tracker_get_spans() {
        let tracker = DutyTracker::new(empty_beacon(), vec!["1234".to_string()]);
        let capture = EpochSpanCapture::default();
        let subscriber = tracing_subscriber::registry()
            .with(capture.clone().with_filter(tracing_subscriber::filter::LevelFilter::INFO));
        let _guard = tracing::subscriber::set_default(subscriber);

        let _probe = tracing::info_span!("info_probe");
        let _ = tracker.get_duty(320, 1, 1234).await;
        let _ = tracker.get_duties_for_slot(320).await;
        let _ = tracker.get_proposer_duty(320).await;
        let _ = tracker.get_sync_committee_duties(320).await;
        let _ = tracker.get_ptc_duties_for_slot(320).await;

        let spans = capture.state.lock().expect("spans").spans.clone();
        let names: Vec<&str> = spans.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"info_probe"),
            "info subscriber must record an info span (non-vacuous), got {names:?}"
        );
        let constructed: Vec<_> =
            names.iter().copied().filter(|n| n.starts_with("duty_tracker.get_")).collect();
        assert!(
            constructed.is_empty(),
            "info must not construct duty_tracker.get_* spans, got {constructed:?}"
        );
    }

    #[tokio::test]
    async fn test_get_duty_not_found() {
        let beacon =
            as_beacon(mock_attester(attester_response(vec![(320, 1, "1234")], "0xdeproot_abc123")));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let result = tracker.get_duty(320, 99, 1234).await;
        assert!(matches!(result, Err(DutyTrackerError::DutyNotFound { .. })));
    }

    #[tokio::test]
    async fn test_get_duty_epoch_not_cached() {
        let beacon = empty_beacon();
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let result = tracker.get_duty(320, 1, 1234).await;
        assert!(matches!(result, Err(DutyTrackerError::DutyNotFound { .. })));
    }

    #[tokio::test]
    async fn test_dependent_root_change_detection() {
        let beacon = as_beacon(mock_attester_queue(vec![
            attester_response(vec![(320, 1, "1234")], "0xroot_first"),
            attester_response(vec![(320, 2, "1234")], "0xroot_second"),
        ]));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_duties_for_epoch(10).await.unwrap();
        let root1 = tracker.get_cached_dependent_root(10).await;
        assert_eq!(root1, Some("0xroot_first".to_string()));

        let changed = tracker.check_and_refetch_if_root_changed(10).await.unwrap();
        assert!(changed);

        let root2 = tracker.get_cached_dependent_root(10).await;
        assert_eq!(root2, Some("0xroot_second".to_string()));
    }

    #[tokio::test]
    async fn test_dependent_root_no_change() {
        let beacon =
            as_beacon(mock_attester(attester_response(vec![(320, 1, "1234")], "0xroot_same")));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let changed = tracker.check_and_refetch_if_root_changed(10).await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn test_clear_epoch_cache() {
        let beacon =
            as_beacon(mock_attester(attester_response(vec![(320, 1, "1234")], "0xdeproot")));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        assert!(tracker.is_epoch_cached(10).await);

        tracker.clear_epoch_cache(10).await;

        assert!(!tracker.is_epoch_cached(10).await);
    }

    #[tokio::test]
    async fn test_is_epoch_boundary_slot() {
        assert!(DutyTracker::is_epoch_boundary_slot(0));
        assert!(DutyTracker::is_epoch_boundary_slot(32));
        assert!(DutyTracker::is_epoch_boundary_slot(64));
        assert!(DutyTracker::is_epoch_boundary_slot(320));

        assert!(!DutyTracker::is_epoch_boundary_slot(1));
        assert!(!DutyTracker::is_epoch_boundary_slot(31));
        assert!(!DutyTracker::is_epoch_boundary_slot(33));
    }

    #[tokio::test]
    async fn test_slot_to_epoch() {
        assert_eq!(DutyTracker::slot_to_epoch(0), 0);
        assert_eq!(DutyTracker::slot_to_epoch(31), 0);
        assert_eq!(DutyTracker::slot_to_epoch(32), 1);
        assert_eq!(DutyTracker::slot_to_epoch(64), 2);
        assert_eq!(DutyTracker::slot_to_epoch(320), 10);
    }

    #[tokio::test]
    async fn test_multiple_validators() {
        let mock = Arc::new(mock_attester(attester_response(
            vec![(320, 1, "1234"), (321, 2, "5678")],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string(), "5678".to_string()];

        let tracker = DutyTracker::new(mock.clone(), validator_indices);
        let duties = tracker.fetch_duties_for_epoch(10).await.unwrap();

        assert_eq!(duties.len(), 2);

        let duty1 = tracker.get_duty(320, 1, 1234).await.unwrap();
        assert_eq!(duty1.validator_index, 1234);

        let duty2 = tracker.get_duty(321, 2, 5678).await.unwrap();
        assert_eq!(duty2.validator_index, 5678);

        let calls = mock.get_attester_duties_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, vec!["1234".to_string(), "5678".to_string()]);
    }

    #[tokio::test]
    async fn test_fetch_duties_beacon_error() {
        let beacon =
            as_beacon(MockBeaconNodeClient::new().with_get_attester_duties(|_epoch, _indices| {
                Err(BeaconError::HttpError("Invalid epoch".into()))
            }));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        let result = tracker.fetch_duties_for_epoch(10).await;

        assert!(matches!(result, Err(DutyTrackerError::BeaconError(_))));
    }

    #[tokio::test]
    async fn test_fetch_next_epoch_while_current_cached() {
        let mut map = HashMap::new();
        map.insert(10, attester_response(vec![(320, 1, "1234")], "0xroot_epoch10"));
        map.insert(11, attester_response(vec![(352, 2, "1234")], "0xroot_epoch11"));
        let beacon = as_beacon(mock_attester_by_epoch(map));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_duties_for_epoch(10).await.unwrap();
        tracker.fetch_duties_for_epoch(11).await.unwrap();

        assert!(tracker.is_epoch_cached(10).await);
        assert!(tracker.is_epoch_cached(11).await);

        let duty10 = tracker.get_duty(320, 1, 1234).await.unwrap();
        assert_eq!(duty10.slot, 320);

        let duty11 = tracker.get_duty(352, 2, 1234).await.unwrap();
        assert_eq!(duty11.slot, 352);
    }

    #[tokio::test]
    async fn test_duty_cache_key_hash_eq() {
        let key1 = DutyCacheKey { slot: 100, committee_index: 1, validator_index: 42 };
        let key2 = DutyCacheKey { slot: 100, committee_index: 1, validator_index: 42 };
        let key3 = DutyCacheKey { slot: 100, committee_index: 2, validator_index: 42 };
        let key4 = DutyCacheKey { slot: 101, committee_index: 1, validator_index: 42 };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);

        let mut map = HashMap::new();
        map.insert(key1.clone(), "value1");
        assert!(map.contains_key(&key2));
        assert!(!map.contains_key(&key3));
    }

    // --- Proposer duty tests ---

    #[tokio::test]
    async fn test_fetch_proposer_duties_success() {
        let beacon = as_beacon(mock_proposer(proposer_response(
            vec![(320, "1234", "0xpubkey_1234"), (325, "5678", "0xpubkey_5678")],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        let duties = tracker.fetch_proposer_duties(10).await.unwrap();

        assert_eq!(duties.len(), 2);
        assert!(tracker.is_proposer_epoch_cached(10).await);
    }

    #[tokio::test]
    async fn test_get_proposer_duty_found() {
        let beacon = as_beacon(mock_proposer(proposer_response(
            vec![(320, "1234", "0xpubkey_1234")],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_proposer_duties(10).await.unwrap();

        let duty = tracker.get_proposer_duty(320).await;
        assert!(duty.is_some());
        assert_eq!(duty.unwrap().validator_index, 1234);
    }

    #[tokio::test]
    async fn test_get_proposer_duty_not_found() {
        let beacon = as_beacon(mock_proposer(proposer_response(
            vec![(320, "1234", "0xpubkey_1234")],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_proposer_duties(10).await.unwrap();

        let duty = tracker.get_proposer_duty(321).await;
        assert!(duty.is_none());
    }

    #[tokio::test]
    async fn test_get_proposer_duty_epoch_not_cached() {
        let beacon = empty_beacon();
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let duty = tracker.get_proposer_duty(320).await;
        assert!(duty.is_none());
    }

    #[tokio::test]
    async fn test_get_cached_proposer_dependent_root() {
        let beacon = as_beacon(mock_proposer(proposer_response(
            vec![(320, "1234", "0xpubkey_1234")],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_proposer_duties(10).await.unwrap();

        let root = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root, Some("0xdeproot".to_string()));
    }

    #[tokio::test]
    async fn test_get_cached_proposer_dependent_root_not_cached() {
        let beacon = empty_beacon();
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let root = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root, None);
    }

    #[tokio::test]
    async fn test_proposer_dependent_root_changes_with_refetch() {
        let beacon = as_beacon(mock_proposer_queue(vec![
            proposer_response(vec![(320, "1234", "0xpubkey_1234")], "0xfirst_root"),
            proposer_response(vec![(320, "1234", "0xpubkey_1234")], "0xsecond_root"),
        ]));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_proposer_duties(10).await.unwrap();
        let root1 = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root1, Some("0xfirst_root".to_string()));

        tracker.fetch_proposer_duties(10).await.unwrap();
        let root2 = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root2, Some("0xsecond_root".to_string()));
    }

    #[tokio::test]
    async fn test_check_and_refetch_proposer_if_root_changed_uncached() {
        let beacon = as_beacon(mock_proposer(proposer_response(
            vec![(320, "1234", "0xpubkey_1234")],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let changed = tracker.check_and_refetch_proposer_if_root_changed(10).await.unwrap();
        assert!(changed);
        assert!(tracker.is_proposer_epoch_cached(10).await);
    }

    #[tokio::test]
    async fn test_check_and_refetch_proposer_if_root_changed_detects_change() {
        let beacon = as_beacon(mock_proposer_queue(vec![
            proposer_response(vec![(320, "1234", "0xpubkey_1234")], "0xfirst_root"),
            proposer_response(vec![(320, "1234", "0xpubkey_1234")], "0xsecond_root"),
        ]));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_proposer_duties(10).await.unwrap();
        let root1 = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root1, Some("0xfirst_root".to_string()));

        let changed = tracker.check_and_refetch_proposer_if_root_changed(10).await.unwrap();
        assert!(changed);

        let root2 = tracker.get_cached_proposer_dependent_root(10).await;
        assert_eq!(root2, Some("0xsecond_root".to_string()));
    }

    #[tokio::test]
    async fn test_check_and_refetch_proposer_if_root_unchanged() {
        let beacon = as_beacon(mock_proposer(proposer_response(
            vec![(320, "1234", "0xpubkey_1234")],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        tracker.fetch_proposer_duties(10).await.unwrap();

        let changed = tracker.check_and_refetch_proposer_if_root_changed(10).await.unwrap();
        assert!(!changed);
    }

    #[tokio::test]
    async fn test_cache_proposer_duties_signals_root_change_without_bn() {
        let tracker = DutyTracker::new(empty_beacon(), vec!["1234".to_string()]);
        let duties = vec![proposer_duty(320, "1234", "0xpubkey_1234")];

        assert!(!tracker.cache_proposer_duties(10, "0xroot_a".into(), &duties).await);
        assert_eq!(
            tracker.get_cached_proposer_dependent_root(10).await.as_deref(),
            Some("0xroot_a")
        );
        assert!(!tracker.cache_proposer_duties(10, "0xroot_a".into(), &duties).await);
        assert!(tracker.cache_proposer_duties(10, "0xroot_b".into(), &duties).await);
        assert_eq!(
            tracker.get_cached_proposer_dependent_root(10).await.as_deref(),
            Some("0xroot_b")
        );
        assert_eq!(tracker.get_proposer_duty(320).await.unwrap().validator_index, 1234);
    }

    // --- PTC duty tests ---

    #[tokio::test]
    async fn test_fetch_ptc_duties_success() {
        let mock = Arc::new(mock_ptc(ptc_response(
            vec![(320, "1234", "0xpubkey_1234"), (321, "5678", "0xpubkey_5678")],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string(), "5678".to_string()];

        let tracker = DutyTracker::new(mock.clone(), validator_indices.clone());
        let duties = tracker.fetch_ptc_duties(10, &validator_indices).await.unwrap();

        assert_eq!(duties.len(), 2);
        assert!(tracker.is_ptc_epoch_cached(10).await);

        let calls = mock.post_ptc_duties_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, 10);
        assert_eq!(calls[0].1, validator_indices);
    }

    #[tokio::test]
    async fn test_get_ptc_duties_for_slot() {
        let beacon = as_beacon(mock_ptc(ptc_response(
            vec![
                (320, "1234", "0xpubkey_1234"),
                (320, "5678", "0xpubkey_5678"),
                (321, "1234", "0xpubkey_1234"),
            ],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string(), "5678".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices.clone());
        tracker.fetch_ptc_duties(10, &validator_indices).await.unwrap();

        let duties_320 = tracker.get_ptc_duties_for_slot(320).await;
        assert_eq!(duties_320.len(), 2);

        let duties_321 = tracker.get_ptc_duties_for_slot(321).await;
        assert_eq!(duties_321.len(), 1);

        let duties_322 = tracker.get_ptc_duties_for_slot(322).await;
        assert!(duties_322.is_empty());
    }

    #[tokio::test]
    async fn test_get_ptc_duties_for_slot_uncached_epoch() {
        let beacon = empty_beacon();
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let duties = tracker.get_ptc_duties_for_slot(320).await;
        assert!(duties.is_empty());
    }

    #[tokio::test]
    async fn test_get_cached_ptc_dependent_root_value() {
        let beacon =
            as_beacon(mock_ptc(ptc_response(vec![(320, "1234", "0xpubkey_1234")], "0xdeproot")));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices.clone());
        tracker.fetch_ptc_duties(10, &validator_indices).await.unwrap();

        let root = tracker.get_cached_ptc_dependent_root(10).await;
        assert_eq!(root, Some("0xdeproot".to_string()));
    }

    #[tokio::test]
    async fn test_get_cached_ptc_dependent_root_not_cached() {
        let beacon = empty_beacon();
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let root = tracker.get_cached_ptc_dependent_root(10).await;
        assert_eq!(root, None);
    }

    #[tokio::test]
    async fn test_ptc_duties_refetched_when_dependent_root_changes() {
        let mock = Arc::new(mock_ptc_queue(vec![
            ptc_response(vec![(320, "1234", "0xpubkey_1234")], "0xfirst_root"),
            ptc_response(vec![(321, "1234", "0xpubkey_1234")], "0xsecond_root"),
        ]));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(mock.clone(), validator_indices.clone());

        tracker.fetch_ptc_duties(10, &validator_indices).await.unwrap();
        let root1 = tracker.get_cached_ptc_dependent_root(10).await;
        assert_eq!(root1, Some("0xfirst_root".to_string()));
        assert_eq!(tracker.get_ptc_duties_for_slot(320).await.len(), 1);

        let changed = tracker.check_and_refetch_ptc_if_root_changed(10).await.unwrap();
        assert!(changed);

        let root2 = tracker.get_cached_ptc_dependent_root(10).await;
        assert_eq!(root2, Some("0xsecond_root".to_string()));
        assert!(
            tracker.get_ptc_duties_for_slot(320).await.is_empty(),
            "changed root must evict the previous epoch cache"
        );
        assert_eq!(tracker.get_ptc_duties_for_slot(321).await.len(), 1);

        let calls = mock.post_ptc_duties_calls();
        assert_eq!(calls.len(), 2, "reorg check re-fetches duties/ptc; no SSE path");
        assert_eq!(calls[0].0, 10);
        assert_eq!(calls[1].0, 10);
        assert_eq!(calls[0].1, validator_indices);
    }

    #[tokio::test]
    async fn test_ptc_duties_not_refetched_when_dependent_root_unchanged() {
        let mock = Arc::new(mock_ptc_queue(vec![
            ptc_response(vec![(320, "1234", "0xpubkey_1234")], "0xsame_root"),
            ptc_response(vec![(321, "5678", "0xpubkey_5678")], "0xsame_root"),
        ]));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(mock.clone(), validator_indices.clone());
        tracker.fetch_ptc_duties(10, &validator_indices).await.unwrap();

        let bn_calls = mock.post_ptc_duties_calls().len();

        let changed = tracker.check_and_refetch_ptc_if_root_changed(10).await.unwrap();
        assert!(!changed);

        assert_eq!(
            tracker.get_ptc_duties_for_slot(320).await.len(),
            1,
            "unchanged root must keep the cached duties"
        );
        assert!(
            tracker.get_ptc_duties_for_slot(321).await.is_empty(),
            "unchanged root must not replace the cache with the comparison response"
        );
        assert_eq!(
            tracker.get_cached_ptc_dependent_root(10).await,
            Some("0xsame_root".to_string())
        );
        // Comparison still hits duties/ptc (proposer-mirror) but must not cache-write
        // (`RVC_PTC_DUTIES_FETCHED_TOTAL` is incremented only in `fetch_ptc_duties`).
        assert_eq!(mock.post_ptc_duties_calls().len(), bn_calls + 1);
    }

    #[tokio::test]
    async fn test_check_and_refetch_ptc_if_root_changed_uncached() {
        let beacon =
            as_beacon(mock_ptc(ptc_response(vec![(320, "1234", "0xpubkey_1234")], "0xdeproot")));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let changed = tracker.check_and_refetch_ptc_if_root_changed(10).await.unwrap();
        assert!(changed);
        assert!(tracker.is_ptc_epoch_cached(10).await);
        assert_eq!(tracker.get_ptc_duties_for_slot(320).await.len(), 1);
    }

    #[tokio::test]
    async fn test_evict_old_caches_ptc() {
        let mut map = HashMap::new();
        for epoch in 5..=9 {
            let slot_base = epoch * 32;
            map.insert(
                epoch,
                ptc_response(vec![(slot_base, "1234", "0xpubkey_1234")], "0xdeproot"),
            );
        }
        let beacon = as_beacon(mock_ptc_by_epoch(map));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices.clone());

        for epoch in 5..=9 {
            tracker.fetch_ptc_duties(epoch, &validator_indices).await.unwrap();
        }
        for epoch in 5..=9 {
            assert!(tracker.is_ptc_epoch_cached(epoch).await);
        }

        tracker.evict_old_caches(9).await;

        assert!(!tracker.is_ptc_epoch_cached(5).await);
        assert!(!tracker.is_ptc_epoch_cached(6).await);
        assert!(tracker.is_ptc_epoch_cached(7).await);
        assert!(tracker.is_ptc_epoch_cached(8).await);
        assert!(tracker.is_ptc_epoch_cached(9).await);
    }

    #[tokio::test]
    async fn test_cached_duty_counts_includes_ptc() {
        let beacon = as_beacon(
            MockBeaconNodeClient::new()
                .with_get_attester_duties(|_epoch, _indices| {
                    Ok(attester_response(vec![(320, 1, "1234")], "0xdeproot"))
                })
                .with_get_proposer_duties(|_epoch| {
                    Ok(proposer_response(vec![(320, "1234", "0xpubkey_1234")], "0xdeproot"))
                })
                .with_post_sync_committee_duties(|_epoch, _indices| {
                    Ok(sync_response(vec![(1234, mock_sync_pubkey(), vec![10])]))
                })
                .with_post_ptc_duties(|_epoch, _indices| {
                    Ok(ptc_response(
                        vec![(320, "1234", "0xpubkey_1234"), (321, "5678", "0xpubkey_5678")],
                        "0xdeproot",
                    ))
                }),
        );
        let validator_indices = vec!["1234".to_string(), "5678".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices.clone());
        tracker.fetch_duties_for_epoch(10).await.unwrap();
        tracker.fetch_proposer_duties(10).await.unwrap();
        tracker.fetch_sync_committee_duties(10).await.unwrap();
        tracker.fetch_ptc_duties(10, &validator_indices).await.unwrap();

        let (attester_count, proposer_count, sync_count, ptc_count) =
            tracker.cached_duty_counts(10).await;
        assert_eq!(attester_count, 1);
        assert_eq!(proposer_count, 1);
        assert_eq!(sync_count, 1);
        assert_eq!(ptc_count, 2);
    }

    #[tokio::test]
    async fn test_fetch_ptc_duties_skips_unparseable_slot() {
        let resp = PtcDutiesResponse {
            dependent_root: "0xdeproot".to_string(),
            execution_optimistic: false,
            data: vec![
                PtcDuty {
                    pubkey: "0xpk1".into(),
                    validator_index: "1234".into(),
                    slot: "invalid".into(),
                },
                ptc_duty(320, "1234", "0xpk2"),
            ],
        };
        let beacon = as_beacon(mock_ptc(resp));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices.clone());
        let duties = tracker.fetch_ptc_duties(10, &validator_indices).await.unwrap();
        assert_eq!(duties.len(), 2);
        assert_eq!(tracker.get_ptc_duties_for_slot(320).await.len(), 1);
        assert!(tracker.get_ptc_duties_for_slot(0).await.is_empty());
    }

    // --- Sync committee duty tests ---

    #[tokio::test]
    async fn test_fetch_sync_committee_duties_success() {
        let beacon =
            as_beacon(mock_sync(sync_response(vec![(1234, mock_sync_pubkey(), vec![10, 20])])));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        let duties = tracker.fetch_sync_committee_duties(10).await.unwrap();

        assert_eq!(duties.len(), 1);
        assert_eq!(duties[0].pubkey, [0x11; 48]);
        assert!(tracker.is_sync_period_cached(10).await);
    }

    #[tokio::test]
    async fn test_get_sync_committee_duties_cached() {
        let beacon =
            as_beacon(mock_sync(sync_response(vec![(1234, mock_sync_pubkey(), vec![10, 20])])));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_sync_committee_duties(10).await.unwrap();

        let duties = tracker.get_sync_committee_duties(320).await; // slot 320 = epoch 10
        assert_eq!(duties.len(), 1);
        assert_eq!(duties[0].validator_index, 1234);
    }

    #[tokio::test]
    async fn test_get_sync_committee_duties_not_cached() {
        let beacon = empty_beacon();
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let duties = tracker.get_sync_committee_duties(320).await;
        assert!(duties.is_empty());
    }

    #[tokio::test]
    async fn test_sync_committee_period_boundary() {
        assert!(DutyTracker::is_sync_committee_period_boundary(0));
        assert!(DutyTracker::is_sync_committee_period_boundary(256));
        assert!(DutyTracker::is_sync_committee_period_boundary(512));
        assert!(!DutyTracker::is_sync_committee_period_boundary(1));
        assert!(!DutyTracker::is_sync_committee_period_boundary(255));
    }

    #[tokio::test]
    async fn test_sync_committee_period() {
        assert_eq!(DutyTracker::sync_committee_period(0), 0);
        assert_eq!(DutyTracker::sync_committee_period(255), 0);
        assert_eq!(DutyTracker::sync_committee_period(256), 1);
        assert_eq!(DutyTracker::sync_committee_period(512), 2);
    }

    #[tokio::test]
    async fn test_get_duties_for_slot() {
        let beacon = as_beacon(mock_attester(attester_response(
            vec![(320, 1, "1234"), (320, 2, "5678"), (321, 0, "1234")],
            "0xdeproot",
        )));
        let validator_indices = vec!["1234".to_string(), "5678".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let duties_320 = tracker.get_duties_for_slot(320).await;
        assert_eq!(duties_320.len(), 2);

        let duties_321 = tracker.get_duties_for_slot(321).await;
        assert_eq!(duties_321.len(), 1);

        let duties_322 = tracker.get_duties_for_slot(322).await;
        assert!(duties_322.is_empty());
    }

    #[tokio::test]
    async fn test_get_duties_for_slot_uncached_epoch() {
        let beacon = empty_beacon();
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        let duties = tracker.get_duties_for_slot(320).await;
        assert!(duties.is_empty());
    }

    #[tokio::test]
    async fn test_evict_old_caches() {
        let mut map = HashMap::new();
        for epoch in 5..=9 {
            let slot_base = epoch * 32;
            map.insert(
                epoch,
                attester_response(vec![(slot_base, 0, "1234")], &format!("0xroot_{epoch}")),
            );
        }
        let beacon = as_beacon(mock_attester_by_epoch(map));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        for epoch in 5..=9 {
            tracker.fetch_duties_for_epoch(epoch).await.unwrap();
        }
        for epoch in 5..=9 {
            assert!(tracker.is_epoch_cached(epoch).await);
        }

        // Evict with current_epoch=9 should keep epochs >= 7
        tracker.evict_old_caches(9).await;

        assert!(!tracker.is_epoch_cached(5).await);
        assert!(!tracker.is_epoch_cached(6).await);
        assert!(tracker.is_epoch_cached(7).await);
        assert!(tracker.is_epoch_cached(8).await);
        assert!(tracker.is_epoch_cached(9).await);
    }

    #[tokio::test]
    async fn test_evict_old_caches_proposer() {
        let mut map = HashMap::new();
        for epoch in 5..=9 {
            let slot_base = epoch * 32;
            map.insert(
                epoch,
                proposer_response(vec![(slot_base, "1234", "0xpubkey_1234")], "0xdeproot"),
            );
        }
        let beacon = as_beacon(mock_proposer_by_epoch(map));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);

        for epoch in 5..=9 {
            tracker.fetch_proposer_duties(epoch).await.unwrap();
        }
        for epoch in 5..=9 {
            assert!(tracker.is_proposer_epoch_cached(epoch).await);
        }

        tracker.evict_old_caches(9).await;

        assert!(!tracker.is_proposer_epoch_cached(5).await);
        assert!(!tracker.is_proposer_epoch_cached(6).await);
        assert!(tracker.is_proposer_epoch_cached(7).await);
        assert!(tracker.is_proposer_epoch_cached(8).await);
        assert!(tracker.is_proposer_epoch_cached(9).await);
    }

    #[tokio::test]
    async fn test_fetch_duties_skips_unparseable_slot() {
        let mut data = vec![attester_duty(320, 1, "1234"), attester_duty(320, 1, "1234")];
        data[0].slot = "invalid".to_string();
        // second entry already has slot 320

        let resp = AttesterDutiesResponse {
            dependent_root: "0xdeproot".to_string(),
            execution_optimistic: false,
            data,
        };
        let beacon = as_beacon(mock_attester(resp));
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        let duties = tracker.fetch_duties_for_epoch(10).await.unwrap();
        // Both returned from API
        assert_eq!(duties.len(), 2);

        // But only the valid one is cached
        let duty = tracker.get_duty(320, 1, 1234).await;
        assert!(duty.is_ok());

        // The invalid slot should not be cached at slot 0 as before
        let duties_at_zero = tracker.get_duties_for_slot(0).await;
        assert!(duties_at_zero.is_empty());
    }

    #[tokio::test]
    async fn test_same_slot_committee_different_validators_both_stored() {
        let beacon = as_beacon(mock_attester(attester_response(
            vec![(320, 1, "100"), (320, 1, "200")],
            "0xdeproot",
        )));
        let validator_indices = vec!["100".to_string(), "200".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let duties = tracker.get_duties_for_slot(320).await;
        assert_eq!(duties.len(), 2, "Both validators should be stored, got {}", duties.len());
    }

    #[tokio::test]
    async fn test_get_duty_with_validator_index() {
        let beacon = as_beacon(mock_attester(attester_response(
            vec![(320, 1, "100"), (320, 1, "200")],
            "0xdeproot",
        )));
        let validator_indices = vec!["100".to_string(), "200".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(10).await.unwrap();

        let duty = tracker.get_duty(320, 1, 100).await.unwrap();
        assert_eq!(duty.validator_index, 100);

        let duty = tracker.get_duty(320, 1, 200).await.unwrap();
        assert_eq!(duty.validator_index, 200);

        let result = tracker.get_duty(320, 1, 999).await;
        assert!(matches!(result, Err(DutyTrackerError::DutyNotFound { .. })));
    }

    #[tokio::test]
    async fn test_check_and_refetch_atomic_compare_and_swap() {
        let beacon = as_beacon(mock_attester_queue(vec![
            attester_response(vec![(0, 0, "100")], "0xroot_a"),
            attester_response(vec![(0, 0, "100")], "0xroot_a"),
            attester_response(vec![(0, 0, "100")], "0xroot_b"),
        ]));
        let validator_indices = vec!["100".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        let changed = tracker.check_and_refetch_if_root_changed(0).await.unwrap();
        assert!(changed, "first fetch should report changed");

        let changed = tracker.check_and_refetch_if_root_changed(0).await.unwrap();
        assert!(!changed, "same root should not report changed");

        let changed = tracker.check_and_refetch_if_root_changed(0).await.unwrap();
        assert!(changed, "different root should report changed");
    }

    #[tokio::test]
    async fn test_clear_cache_empties_all_caches() {
        let beacon = as_beacon(mock_attester(attester_response(vec![(0, 0, "100")], "0xroot_a")));
        let validator_indices = vec!["100".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices);
        tracker.fetch_duties_for_epoch(0).await.unwrap();
        assert!(tracker.is_epoch_cached(0).await);

        tracker.clear_cache().await;
        assert!(!tracker.is_epoch_cached(0).await);
    }

    /// RF4-29: `clear_cache` must clear the sync-committee cache as well as
    /// attester/proposer caches. Key-gen invalidation and reorg recovery call
    /// this path; leaving sync duties live after a key removal is a correctness bug.
    #[tokio::test]
    async fn test_clear_cache_clears_sync_committee_cache() {
        let beacon = as_beacon(
            MockBeaconNodeClient::new()
                .with_get_attester_duties(|_epoch, _indices| {
                    Ok(attester_response(vec![(320, 1, "1234")], "0xdeproot"))
                })
                .with_get_proposer_duties(|_epoch| {
                    Ok(proposer_response(vec![(320, "1234", "0xpubkey_1234")], "0xdeproot"))
                })
                .with_post_sync_committee_duties(|_epoch, _indices| {
                    Ok(sync_response(vec![(1234, mock_sync_pubkey(), vec![10, 20])]))
                })
                .with_post_ptc_duties(|_epoch, _indices| {
                    Ok(ptc_response(vec![(320, "1234", "0xpubkey_1234")], "0xdeproot"))
                }),
        );
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices.clone());
        tracker.fetch_duties_for_epoch(10).await.unwrap();
        tracker.fetch_proposer_duties(10).await.unwrap();
        tracker.fetch_sync_committee_duties(10).await.unwrap();
        tracker.fetch_ptc_duties(10, &validator_indices).await.unwrap();

        assert!(tracker.is_epoch_cached(10).await);
        assert!(tracker.is_proposer_epoch_cached(10).await);
        assert!(tracker.is_sync_period_cached(10).await);
        assert!(tracker.is_ptc_epoch_cached(10).await);
        assert!(!tracker.get_sync_committee_duties(320).await.is_empty());
        assert!(!tracker.get_ptc_duties_for_slot(320).await.is_empty());

        tracker.clear_cache().await;

        assert!(!tracker.is_epoch_cached(10).await);
        assert!(!tracker.is_proposer_epoch_cached(10).await);
        assert!(!tracker.is_sync_period_cached(10).await);
        assert!(!tracker.is_ptc_epoch_cached(10).await);
        assert!(
            tracker.get_sync_committee_duties(320).await.is_empty(),
            "clear_cache must empty the sync-committee cache"
        );
        assert!(
            tracker.get_ptc_duties_for_slot(320).await.is_empty(),
            "clear_cache must empty the PTC cache"
        );
    }

    fn rejection_count(field: &str) -> u64 {
        crate::metrics::RVC_DUTY_REJECTED_TOTAL.with_label_values(&[field]).get()
    }

    macro_rules! assert_rejection_warned {
        ($field:expr, $raw:expr) => {
            logs_assert(|lines| {
                let field = $field;
                let raw = $raw;
                if lines.iter().any(|line| {
                    line.contains("WARN")
                        && line.contains("malformed numeric field")
                        && line.contains(field)
                        && line.contains(raw)
                }) {
                    Ok(())
                } else {
                    Err(format!("no warn naming {field} raw {raw}; lines={lines:?}"))
                }
            });
        };
    }

    /// One malformed numeric field is a named per-duty rejection. The epoch's
    /// other duties stay in the cache.
    #[test]
    #[tracing_test::traced_test]
    fn malformed_committee_length_is_rejected_at_the_cache_with_a_named_error() {
        let mut bad = attester_duty(322, 3, "300");
        bad.committee_length = "not-a-length".to_string();
        let duties = vec![attester_duty(320, 1, "100"), attester_duty(321, 2, "200"), bad];

        let before = rejection_count("committee_length");
        let (cache, errors) = EpochDutyCache::from_response("0xroot".into(), &duties, 10);

        assert_eq!(
            errors,
            vec![DutyParseError {
                field: "committee_length",
                raw: "not-a-length".to_string(),
                validator_index: Some(300),
            }]
        );
        assert!(
            rejection_count("committee_length") > before,
            "rvc_duty_rejected_total{{field=committee_length}} must increment"
        );
        assert_rejection_warned!("committee_length", "not-a-length");

        assert_eq!(cache.duties.len(), 2, "the rest of the epoch stays cached");
        let kept = cache
            .get(&DutyCacheKey { slot: 320, committee_index: 1, validator_index: 100 })
            .expect("sibling duty");
        assert_eq!(kept.slot, 320);
        assert_eq!(kept.committee_index, 1);
        assert_eq!(kept.validator_index, 100);
        assert_eq!(kept.committee_length, 128);
        assert_eq!(kept.validator_committee_index, 25);
        assert_eq!(kept.committees_at_slot, "64");
        assert_eq!(kept.raw.committee_length, "128");
        assert_eq!(kept.raw.validator_index, "100");
        assert!(cache
            .get(&DutyCacheKey { slot: 322, committee_index: 3, validator_index: 300 })
            .is_none());
    }

    #[test]
    #[tracing_test::traced_test]
    fn malformed_validator_committee_index_is_rejected_at_the_cache_with_a_named_error() {
        assert_one_attester_field_rejected(
            "validator_committee_index",
            "not-a-position",
            |duty| duty.validator_committee_index = "not-a-position".to_string(),
            Some(300),
        );
        assert_rejection_warned!("validator_committee_index", "not-a-position");
    }

    #[test]
    #[tracing_test::traced_test]
    fn malformed_slot_is_rejected_at_the_cache_with_a_named_error() {
        assert_one_attester_field_rejected(
            "slot",
            "not-a-slot",
            |duty| duty.slot = "not-a-slot".to_string(),
            Some(300),
        );
        assert_rejection_warned!("slot", "not-a-slot");
    }

    #[test]
    #[tracing_test::traced_test]
    fn malformed_committee_index_is_rejected_at_the_cache_with_a_named_error() {
        assert_one_attester_field_rejected(
            "committee_index",
            "not-a-committee",
            |duty| duty.committee_index = "not-a-committee".to_string(),
            Some(300),
        );
        assert_rejection_warned!("committee_index", "not-a-committee");
    }

    #[test]
    #[tracing_test::traced_test]
    fn malformed_validator_index_is_rejected_at_the_cache_with_a_named_error() {
        assert_one_attester_field_rejected(
            "validator_index",
            "not-an-index",
            |duty| duty.validator_index = "not-an-index".to_string(),
            None,
        );
        assert_rejection_warned!("validator_index", "not-an-index");
    }

    fn assert_one_attester_field_rejected(
        field: &'static str,
        raw: &'static str,
        corrupt: impl FnOnce(&mut AttesterDuty),
        validator_index: Option<u64>,
    ) {
        let mut bad = attester_duty(322, 3, "300");
        corrupt(&mut bad);
        let duties = vec![attester_duty(320, 1, "100"), attester_duty(321, 2, "200"), bad];

        let before = rejection_count(field);
        let (cache, errors) = EpochDutyCache::from_response("0xroot".into(), &duties, 10);

        assert_eq!(errors, vec![DutyParseError { field, raw: raw.to_string(), validator_index }]);
        assert!(
            rejection_count(field) > before,
            "rvc_duty_rejected_total{{field={field}}} must increment"
        );
        assert_eq!(cache.duties.len(), 2, "the rest of the epoch stays cached");
        assert!(cache
            .get(&DutyCacheKey { slot: 320, committee_index: 1, validator_index: 100 })
            .is_some());
        assert!(cache
            .get(&DutyCacheKey { slot: 321, committee_index: 2, validator_index: 200 })
            .is_some());
    }

    #[test]
    #[tracing_test::traced_test]
    fn proposer_cache_rejects_malformed_validator_index() {
        let duties = vec![
            proposer_duty(320, "100", "0xpk100"),
            proposer_duty(321, "not-an-index", "0xpk-bad"),
            proposer_duty(322, "200", "0xpk200"),
        ];
        let before = rejection_count("validator_index");
        let (cache, errors) = ProposerEpochDutyCache::from_response("0xproot".into(), &duties);
        assert_eq!(
            errors,
            vec![DutyParseError {
                field: "validator_index",
                raw: "not-an-index".to_string(),
                validator_index: None,
            }]
        );
        assert!(rejection_count("validator_index") > before);
        assert_rejection_warned!("validator_index", "not-an-index");
        assert_eq!(cache.duties.len(), 2);
        assert!(cache.get(&320).is_some());
        assert!(cache.get(&322).is_some());
        assert!(cache.get(&321).is_none());
        assert_eq!(cache.get(&320).unwrap().raw.validator_index, "100");
    }

    #[test]
    #[tracing_test::traced_test]
    fn proposer_cache_rejects_malformed_slot() {
        let duties = vec![
            proposer_duty(320, "100", "0xpk100"),
            ProposerDuty {
                pubkey: "0xpk-bad".into(),
                validator_index: "300".into(),
                slot: "not-a-slot".into(),
            },
        ];
        let before = rejection_count("slot");
        let (cache, errors) = ProposerEpochDutyCache::from_response("0xproot".into(), &duties);
        assert_eq!(
            errors,
            vec![DutyParseError {
                field: "slot",
                raw: "not-a-slot".to_string(),
                validator_index: Some(300),
            }]
        );
        assert!(rejection_count("slot") > before);
        assert_rejection_warned!("slot", "not-a-slot");
        assert_eq!(cache.duties.len(), 1);
        assert!(cache.get(&320).is_some());
    }

    #[test]
    #[tracing_test::traced_test]
    fn ptc_cache_rejects_malformed_validator_index() {
        let duties = vec![
            ptc_duty(320, "100", "0xpk100"),
            ptc_duty(320, "not-an-index", "0xpk-bad"),
            ptc_duty(321, "200", "0xpk200"),
        ];
        let before = rejection_count("validator_index");
        let (cache, errors) = PtcEpochDutyCache::from_response("0xtroot".into(), &duties);
        assert_eq!(
            errors,
            vec![DutyParseError {
                field: "validator_index",
                raw: "not-an-index".to_string(),
                validator_index: None,
            }]
        );
        assert!(rejection_count("validator_index") > before);
        assert_rejection_warned!("validator_index", "not-an-index");
        assert_eq!(cache.duty_count(), 2);
        assert_eq!(cache.get(&320).map(|d| d.len()), Some(1));
        assert_eq!(cache.get(&321).map(|d| d.len()), Some(1));
        assert_eq!(cache.get(&320).unwrap()[0].raw.validator_index, "100");
    }

    #[test]
    #[tracing_test::traced_test]
    fn ptc_cache_rejects_malformed_slot() {
        let duties = vec![
            ptc_duty(320, "100", "0xpk100"),
            PtcDuty {
                pubkey: "0xpk-bad".into(),
                validator_index: "300".into(),
                slot: "not-a-slot".into(),
            },
        ];
        let before = rejection_count("slot");
        let (cache, errors) = PtcEpochDutyCache::from_response("0xtroot".into(), &duties);
        assert_eq!(
            errors,
            vec![DutyParseError {
                field: "slot",
                raw: "not-a-slot".to_string(),
                validator_index: Some(300),
            }]
        );
        assert!(rejection_count("slot") > before);
        assert_rejection_warned!("slot", "not-a-slot");
        assert_eq!(cache.duty_count(), 1);
        assert_eq!(cache.get(&320).map(|d| d.len()), Some(1));
    }

    /// RF4-29: `from_response` constructors produce the same cache contents
    /// as the previous inline parse loops (keyed by parsed fields, skip bad rows).
    #[test]
    fn test_from_response_constructors_produce_identical_caches() {
        let attester_duties = vec![
            AttesterDuty {
                pubkey: "0xpk1".into(),
                validator_index: "10".into(),
                committee_index: "2".into(),
                committee_length: "128".into(),
                committees_at_slot: "64".into(),
                validator_committee_index: "0".into(),
                slot: "320".into(),
            },
            AttesterDuty {
                pubkey: "0xpk2".into(),
                validator_index: "not_a_number".into(),
                committee_index: "1".into(),
                committee_length: "128".into(),
                committees_at_slot: "64".into(),
                validator_committee_index: "0".into(),
                slot: "321".into(),
            },
            AttesterDuty {
                pubkey: "0xpk3".into(),
                validator_index: "11".into(),
                committee_index: "bad".into(),
                committee_length: "128".into(),
                committees_at_slot: "64".into(),
                validator_committee_index: "0".into(),
                slot: "322".into(),
            },
            AttesterDuty {
                pubkey: "0xpk4".into(),
                validator_index: "12".into(),
                committee_index: "3".into(),
                committee_length: "128".into(),
                committees_at_slot: "64".into(),
                validator_committee_index: "0".into(),
                slot: "not_a_slot".into(),
            },
        ];

        let (attester_cache, _) =
            EpochDutyCache::from_response("0xroot".into(), &attester_duties, 10);
        assert_eq!(attester_cache.dependent_root, "0xroot");
        assert_eq!(attester_cache.duties.len(), 1);
        let key = DutyCacheKey { slot: 320, committee_index: 2, validator_index: 10 };
        assert_eq!(attester_cache.get(&key).map(|d| d.pubkey.as_str()), Some("0xpk1"));

        let proposer_duties = vec![
            ProposerDuty {
                pubkey: "0xpk1".into(),
                validator_index: "10".into(),
                slot: "320".into(),
            },
            ProposerDuty {
                pubkey: "0xpk2".into(),
                validator_index: "11".into(),
                slot: "invalid".into(),
            },
            ProposerDuty {
                pubkey: "0xpk3".into(),
                validator_index: "12".into(),
                slot: "325".into(),
            },
        ];
        let (proposer_cache, _) =
            ProposerEpochDutyCache::from_response("0xproot".into(), &proposer_duties);
        assert_eq!(proposer_cache.dependent_root, "0xproot");
        assert_eq!(proposer_cache.duties.len(), 2);
        assert!(proposer_cache.get(&320).is_some());
        assert!(proposer_cache.get(&325).is_some());
        assert!(proposer_cache.get(&321).is_none());

        let ptc_duties = vec![
            PtcDuty { pubkey: "0xpk1".into(), validator_index: "10".into(), slot: "320".into() },
            PtcDuty {
                pubkey: "0xpk2".into(),
                validator_index: "11".into(),
                slot: "invalid".into(),
            },
            PtcDuty { pubkey: "0xpk3".into(), validator_index: "12".into(), slot: "320".into() },
        ];
        let (ptc_cache, _) = PtcEpochDutyCache::from_response("0xtroot".into(), &ptc_duties);
        assert_eq!(ptc_cache.dependent_root, "0xtroot");
        assert_eq!(ptc_cache.duty_count(), 2);
        assert_eq!(ptc_cache.get(&320).map(|d| d.len()), Some(2));
        assert!(ptc_cache.get(&321).is_none());

        let sync_duties = vec![SyncCommitteeDuty {
            pubkey: [0x11; 48],
            validator_index: 1234,
            validator_sync_committee_indices: vec![1, 2],
        }];
        let sync_cache = SyncPeriodDutyCache::from_response(sync_duties.clone());
        assert_eq!(sync_cache.duties, sync_duties);
    }

    /// RF4-29: `clear_epoch_cache` remains scoped to a single attester epoch
    /// and does not touch proposer or sync caches.
    #[tokio::test]
    async fn test_clear_epoch_cache_still_scoped_to_one_epoch() {
        let mut attester_map = HashMap::new();
        for epoch in [10u64, 11] {
            attester_map
                .insert(epoch, attester_response(vec![(epoch * 32, 1, "1234")], "0xdeproot"));
        }
        let attester_map = Arc::new(attester_map);
        let attester_map_c = Arc::clone(&attester_map);
        let beacon = as_beacon(
            MockBeaconNodeClient::new()
                .with_get_attester_duties(move |epoch, _indices| {
                    attester_map_c.get(&epoch).cloned().ok_or_else(|| {
                        BeaconError::HttpError(format!("no attester mock for epoch {epoch}"))
                    })
                })
                .with_get_proposer_duties(|_epoch| {
                    Ok(proposer_response(vec![(320, "1234", "0xpubkey_1234")], "0xdeproot"))
                })
                .with_post_sync_committee_duties(|_epoch, _indices| {
                    Ok(sync_response(vec![(1234, mock_sync_pubkey(), vec![10])]))
                })
                .with_post_ptc_duties(|_epoch, _indices| {
                    Ok(ptc_response(vec![(320, "1234", "0xpubkey_1234")], "0xdeproot"))
                }),
        );
        let validator_indices = vec!["1234".to_string()];

        let tracker = DutyTracker::new(beacon, validator_indices.clone());
        tracker.fetch_duties_for_epoch(10).await.unwrap();
        tracker.fetch_duties_for_epoch(11).await.unwrap();
        tracker.fetch_proposer_duties(10).await.unwrap();
        tracker.fetch_sync_committee_duties(10).await.unwrap();
        tracker.fetch_ptc_duties(10, &validator_indices).await.unwrap();

        tracker.clear_epoch_cache(10).await;

        assert!(!tracker.is_epoch_cached(10).await);
        assert!(tracker.is_epoch_cached(11).await);
        assert!(tracker.is_proposer_epoch_cached(10).await);
        assert!(tracker.is_sync_period_cached(10).await);
        assert!(tracker.is_ptc_epoch_cached(10).await);
        assert!(!tracker.get_sync_committee_duties(320).await.is_empty());
        assert!(!tracker.get_ptc_duties_for_slot(320).await.is_empty());
    }

    // -- Revocation-stamped attester cache (W4-E7b) --

    /// Hold on a mock duty answer. Longer than every other timer in these tests.
    const HOLD: std::time::Duration = std::time::Duration::from_secs(3_600);
    const STAMP_EPOCH: u64 = 10;
    const STAMP_SLOT: u64 = 320;

    fn stamp_response(committee_index: u64, dependent_root: &str) -> AttesterDutiesResponse {
        attester_response(vec![(STAMP_SLOT, committee_index, "1234")], dependent_root)
    }

    /// `track_admission()` runs before the tracker is built: the tracker reads
    /// the generation once, at construction.
    fn stamped(
        mock: MockBeaconNodeClient,
    ) -> (Arc<MockBeaconNodeClient>, Arc<DutyTracker>, Arc<AtomicU64>) {
        let generation = mock.track_admission();
        let mock = Arc::new(mock);
        let tracker = Arc::new(DutyTracker::new(mock.clone(), vec!["1234".to_string()]));
        (mock, tracker, generation)
    }

    fn bump(generation: &AtomicU64) {
        generation.fetch_add(1, Ordering::Release);
    }

    /// A hook that bumps `generation` the first time it runs.
    fn bump_once(generation: &Arc<AtomicU64>) -> impl FnMut() + 'static {
        let generation = Arc::clone(generation);
        let mut fired = false;
        move || {
            if !fired {
                fired = true;
                bump(&generation);
            }
        }
    }

    /// Yields until `count` calls of `method` have arrived. It never parks, so
    /// a paused clock cannot auto-advance past a held answer.
    async fn wait_for_arrivals(mock: &MockBeaconNodeClient, method: MockMethod, count: usize) {
        for _ in 0..10_000 {
            if mock.call_stamps().iter().filter(|stamp| stamp.method == method).count() >= count {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("{count} {method:?} calls never arrived");
    }

    /// The attester readers that take the cache's read guard.
    #[derive(Debug, Clone, Copy)]
    enum Reader {
        GetDuty,
        DutiesForSlot,
        IsEpochCached,
        DependentRoot,
        DutyCounts,
    }

    impl Reader {
        const ALL: [Self; 5] = [
            Self::GetDuty,
            Self::DutiesForSlot,
            Self::IsEpochCached,
            Self::DependentRoot,
            Self::DutyCounts,
        ];

        /// Whether this reader serves the entry cached for `STAMP_EPOCH`.
        async fn hits(self, tracker: &DutyTracker) -> bool {
            match self {
                Self::GetDuty => tracker.get_duty(STAMP_SLOT, 1, 1234).await.is_ok(),
                Self::DutiesForSlot => !tracker.get_duties_for_slot(STAMP_SLOT).await.is_empty(),
                Self::IsEpochCached => tracker.is_epoch_cached(STAMP_EPOCH).await,
                Self::DependentRoot => {
                    tracker.get_cached_dependent_root(STAMP_EPOCH).await.is_some()
                }
                Self::DutyCounts => tracker.cached_duty_counts(STAMP_EPOCH).await.0 > 0,
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_attester_fetch_revoked_before_release_is_discarded() {
        let mock = mock_attester(stamp_response(1, "0xroot_a"))
            .with_method_delay(MockMethod::GetAttesterDuties, HOLD);
        let (mock, tracker, generation) = stamped(mock);

        let fetch = tokio::spawn({
            let tracker = Arc::clone(&tracker);
            async move { tracker.fetch_duties_for_epoch(STAMP_EPOCH).await }
        });
        wait_for_arrivals(&mock, MockMethod::GetAttesterDuties, 1).await;
        bump(&generation);
        tokio::time::advance(HOLD).await;

        let result = fetch.await.expect("fetch task");
        assert!(
            matches!(result, Err(DutyTrackerError::RevokedDuringFetch { epoch: STAMP_EPOCH })),
            "an answer fetched across a bump must be discarded, got {result:?}"
        );
        assert!(!tracker.is_epoch_cached(STAMP_EPOCH).await);
        assert!(tracker.get_duties_for_slot(STAMP_SLOT).await.is_empty());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_attester_reorg_refresh_revoked_before_release_is_discarded() {
        let mock =
            mock_attester_queue(vec![stamp_response(1, "0xroot_a"), stamp_response(2, "0xroot_b")])
                .with_method_delay(MockMethod::GetAttesterDuties, HOLD);
        let (mock, tracker, generation) = stamped(mock);
        tracker.fetch_duties_for_epoch(STAMP_EPOCH).await.expect("seed root A");
        assert_eq!(
            tracker.get_cached_dependent_root(STAMP_EPOCH).await.as_deref(),
            Some("0xroot_a")
        );

        let refresh = tokio::spawn({
            let tracker = Arc::clone(&tracker);
            async move { tracker.check_and_refetch_if_root_changed(STAMP_EPOCH).await }
        });
        wait_for_arrivals(&mock, MockMethod::GetAttesterDuties, 2).await;
        bump(&generation);
        tokio::time::advance(HOLD).await;

        let result = refresh.await.expect("refresh task");
        assert!(
            matches!(result, Err(DutyTrackerError::RevokedDuringFetch { epoch: STAMP_EPOCH })),
            "a refresh answer fetched across a bump must be discarded, got {result:?}"
        );
        assert_eq!(tracker.get_cached_dependent_root(STAMP_EPOCH).await, None);
        assert!(tracker.get_duties_for_slot(STAMP_SLOT).await.is_empty());
    }

    #[tokio::test]
    async fn reorg_refresh_replaces_a_stale_entry_with_an_unchanged_root() {
        // kat_exempt: cache freshness only; the root is an opaque BN dependent_root string
        let (_mock, tracker, generation) = stamped(mock_attester(stamp_response(1, "0xroot_a")));
        tracker.fetch_duties_for_epoch(STAMP_EPOCH).await.expect("seed");
        bump(&generation);
        assert!(!tracker.is_epoch_cached(STAMP_EPOCH).await, "the entry is stale after a bump");

        let changed =
            tracker.check_and_refetch_if_root_changed(STAMP_EPOCH).await.expect("refresh");

        assert!(changed, "a stale entry counts as absent, so the refresh reports a change");
        assert!(tracker.is_epoch_cached(STAMP_EPOCH).await, "the entry is re-stamped");
        assert_eq!(
            tracker.get_cached_dependent_root(STAMP_EPOCH).await.as_deref(),
            Some("0xroot_a")
        );
    }

    #[tokio::test]
    async fn every_attester_reader_misses_after_a_bump() {
        let (_mock, tracker, generation) = stamped(mock_attester(stamp_response(1, "0xroot_a")));
        tracker.fetch_duties_for_epoch(STAMP_EPOCH).await.expect("fetch");
        for reader in Reader::ALL {
            assert!(reader.hits(&tracker).await, "{reader:?} serves the fresh entry");
        }
        let changed =
            tracker.check_and_refetch_if_root_changed(STAMP_EPOCH).await.expect("refresh");
        assert!(!changed, "the refresh compare sees the fresh entry");

        bump(&generation);

        for reader in Reader::ALL {
            assert!(!reader.hits(&tracker).await, "{reader:?} served a stale entry");
        }
        let changed =
            tracker.check_and_refetch_if_root_changed(STAMP_EPOCH).await.expect("refresh");
        assert!(changed, "the refresh compare treats the stale entry as absent");
    }

    #[tokio::test]
    async fn bump_between_read_lock_and_stamp_check_is_a_miss() {
        let (_mock, tracker, generation) = stamped(mock_attester(stamp_response(1, "0xroot_a")));
        for reader in Reader::ALL {
            tracker.fetch_duties_for_epoch(STAMP_EPOCH).await.expect("fetch");
            assert!(reader.hits(&tracker).await, "{reader:?} serves the fresh entry");
            let before = generation.load(Ordering::Acquire);

            let hit = {
                let _armed = hooks::arm(&hooks::AFTER_READ_LOCK, bump_once(&generation));
                reader.hits(&tracker).await
            };

            assert_eq!(generation.load(Ordering::Acquire), before + 1, "{reader:?}: hook ran");
            assert!(!hit, "{reader:?} must load the generation inside its guard");
        }
    }

    #[tokio::test]
    async fn bump_after_the_stamp_check_is_seen_by_the_next_read() {
        let (_mock, tracker, generation) = stamped(mock_attester(stamp_response(1, "0xroot_a")));
        for reader in Reader::ALL {
            tracker.fetch_duties_for_epoch(STAMP_EPOCH).await.expect("fetch");
            let before = generation.load(Ordering::Acquire);

            let hit = {
                let _armed = hooks::arm(&hooks::AFTER_STAMP_CHECK, bump_once(&generation));
                reader.hits(&tracker).await
            };

            assert_eq!(generation.load(Ordering::Acquire), before + 1, "{reader:?}: hook ran");
            assert!(hit, "{reader:?}: this read is linearised before the bump");
            assert!(!reader.hits(&tracker).await, "{reader:?}: the next read misses");
        }
    }

    #[tokio::test]
    async fn bump_between_generation_check_and_insert_leaves_nothing_servable() {
        let (_mock, tracker, generation) = stamped(mock_attester(stamp_response(1, "0xroot_a")));

        // The refresh runs second, over the entry the bump made stale.
        for (writer, refresh) in [("fetch", false), ("reorg refresh", true)] {
            let before = generation.load(Ordering::Acquire);
            let written = {
                let _armed = hooks::arm(&hooks::BEFORE_INSERT, bump_once(&generation));
                if refresh {
                    tracker.check_and_refetch_if_root_changed(STAMP_EPOCH).await.map(|_| ())
                } else {
                    tracker.fetch_duties_for_epoch(STAMP_EPOCH).await.map(|_| ())
                }
            };

            written.unwrap_or_else(|err| panic!("{writer}: the re-check passed, got {err}"));
            assert_eq!(generation.load(Ordering::Acquire), before + 1, "{writer}: hook ran");
            let stamp = tracker.cache.read().await.get(&STAMP_EPOCH).map(|entry| entry.fetched_gen);
            assert_eq!(
                stamp,
                Some(Some(before)),
                "{writer}: the entry carries the generation captured before the request"
            );
            for reader in Reader::ALL {
                assert!(!reader.hits(&tracker).await, "{writer}: {reader:?} served the entry");
            }
        }
    }

    #[tokio::test]
    async fn without_a_generation_caches_are_never_dropped() {
        let mock = Arc::new(mock_attester(stamp_response(1, "0xroot_a")));
        let tracker = DutyTracker::new(mock, vec!["1234".to_string()]);
        tracker.fetch_duties_for_epoch(STAMP_EPOCH).await.expect("fetch");

        for round in 0..2 {
            for reader in Reader::ALL {
                assert!(reader.hits(&tracker).await, "round {round}: {reader:?} serves the entry");
            }
        }
        let changed =
            tracker.check_and_refetch_if_root_changed(STAMP_EPOCH).await.expect("refresh");
        assert!(!changed, "an unchanged root is not a change without a generation");
        for reader in Reader::ALL {
            assert!(reader.hits(&tracker).await, "{reader:?} serves the entry after the refresh");
        }
    }

    // -- Revocation-stamped proposer cache (W4-E7c1) --

    fn proposer_stamp_response(dependent_root: &str) -> ProposerDutiesResponse {
        proposer_response(vec![(STAMP_SLOT, "1234", "0xpubkey_1234")], dependent_root)
    }

    /// The stored proposer entry for `STAMP_EPOCH`, stale or not: root and stamp.
    async fn proposer_entry(tracker: &DutyTracker) -> Option<(String, Option<u64>)> {
        let cache = tracker.proposer_cache.read().await;
        cache.get(&STAMP_EPOCH).map(|entry| (entry.dependent_root.clone(), entry.fetched_gen))
    }

    fn entry(root: &str, generation: u64) -> Option<(String, Option<u64>)> {
        Some((root.to_string(), Some(generation)))
    }

    /// A hook that bumps `generation` on its `nth` run (1-based).
    fn bump_on_run(generation: &Arc<AtomicU64>, nth: usize) -> impl FnMut() + 'static {
        let generation = Arc::clone(generation);
        let mut runs = 0;
        move || {
            runs += 1;
            if runs == nth {
                bump(&generation);
            }
        }
    }

    /// The proposer readers that take the proposer cache's read guard.
    #[derive(Debug, Clone, Copy)]
    enum ProposerReader {
        Duty,
        DependentRoot,
        IsEpochCached,
        DutyCounts,
    }

    impl ProposerReader {
        const ALL: [Self; 4] =
            [Self::Duty, Self::DependentRoot, Self::IsEpochCached, Self::DutyCounts];

        /// Which run of a read-path hook is this reader's proposer guard.
        /// `cached_duty_counts` takes the attester guard first.
        fn proposer_run(self) -> usize {
            match self {
                Self::DutyCounts => 2,
                _ => 1,
            }
        }

        /// Whether this reader serves the proposer entry cached for `STAMP_EPOCH`.
        async fn hits(self, tracker: &DutyTracker) -> bool {
            match self {
                Self::Duty => tracker.get_proposer_duty(STAMP_SLOT).await.is_some(),
                Self::DependentRoot => {
                    tracker.get_cached_proposer_dependent_root(STAMP_EPOCH).await.is_some()
                }
                Self::IsEpochCached => tracker.is_proposer_epoch_cached(STAMP_EPOCH).await,
                Self::DutyCounts => tracker.cached_duty_counts(STAMP_EPOCH).await.1 > 0,
            }
        }
    }

    async fn assert_no_proposer_reader_hits(tracker: &DutyTracker, context: &str) {
        for reader in ProposerReader::ALL {
            assert!(!reader.hits(tracker).await, "{context}: {reader:?} served the entry");
        }
    }

    fn is_revoked_during_fetch<T>(result: &Result<T, DutyTrackerError>) -> bool {
        matches!(result, Err(DutyTrackerError::RevokedDuringFetch { epoch: STAMP_EPOCH }))
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_proposer_reorg_refresh_revoked_before_release_is_discarded() {
        let mock = mock_proposer_queue(vec![
            proposer_stamp_response("0xroot_a"),
            proposer_stamp_response("0xroot_b"),
        ])
        .with_method_delay(MockMethod::GetProposerDuties, HOLD);
        let (mock, tracker, generation) = stamped(mock);
        tracker.fetch_proposer_duties(STAMP_EPOCH).await.expect("seed root A");
        assert_eq!(
            tracker.get_cached_proposer_dependent_root(STAMP_EPOCH).await.as_deref(),
            Some("0xroot_a")
        );

        let refresh = tokio::spawn({
            let tracker = Arc::clone(&tracker);
            async move { tracker.check_and_refetch_proposer_if_root_changed(STAMP_EPOCH).await }
        });
        wait_for_arrivals(&mock, MockMethod::GetProposerDuties, 2).await;
        bump(&generation);
        tokio::time::advance(HOLD).await;

        let result = refresh.await.expect("refresh task");
        assert!(
            is_revoked_during_fetch(&result),
            "a refresh answer fetched across a bump must be discarded, got {result:?}"
        );
        assert_eq!(proposer_entry(&tracker).await, entry("0xroot_a", 0), "root B is not stored");
        assert_eq!(tracker.get_cached_proposer_dependent_root(STAMP_EPOCH).await, None);
        assert!(tracker.get_proposer_duty(STAMP_SLOT).await.is_none());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_same_root_proposer_refresh_revoked_before_release_does_not_restamp() {
        let mock = mock_proposer_queue(vec![
            proposer_stamp_response("0xroot_a"),
            proposer_stamp_response("0xroot_a"),
        ])
        .with_method_delay(MockMethod::GetProposerDuties, HOLD);
        let (mock, tracker, generation) = stamped(mock);
        let seeded_gen = generation.load(Ordering::Acquire);
        tracker.fetch_proposer_duties(STAMP_EPOCH).await.expect("seed root A");
        assert_eq!(proposer_entry(&tracker).await, entry("0xroot_a", seeded_gen));

        let refresh = tokio::spawn({
            let tracker = Arc::clone(&tracker);
            async move { tracker.check_and_refetch_proposer_if_root_changed(STAMP_EPOCH).await }
        });
        wait_for_arrivals(&mock, MockMethod::GetProposerDuties, 2).await;
        bump(&generation);
        tokio::time::advance(HOLD).await;

        let result = refresh.await.expect("refresh task");
        assert!(
            matches!(result, Ok(false)),
            "a same-root refresh must report no root change, got {result:?}"
        );
        assert_eq!(
            proposer_entry(&tracker).await,
            entry("0xroot_a", seeded_gen),
            "a same-root answer fetched across a bump must not restamp the entry"
        );
        assert_no_proposer_reader_hits(&tracker, "same-root refresh held across a bump").await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_proposer_fetch_revoked_before_release_is_discarded() {
        let mock = mock_proposer(proposer_stamp_response("0xroot_a"))
            .with_method_delay(MockMethod::GetProposerDuties, HOLD);
        let (mock, tracker, generation) = stamped(mock);

        // The refresh of an uncached epoch takes its cold path.
        for (arrivals, writer) in [(1, "fetch"), (2, "cold-path refresh")] {
            let held = tokio::spawn({
                let tracker = Arc::clone(&tracker);
                async move {
                    if arrivals == 1 {
                        tracker.fetch_proposer_duties(STAMP_EPOCH).await.map(|_| ())
                    } else {
                        tracker
                            .check_and_refetch_proposer_if_root_changed(STAMP_EPOCH)
                            .await
                            .map(|_| ())
                    }
                }
            });
            wait_for_arrivals(&mock, MockMethod::GetProposerDuties, arrivals).await;
            bump(&generation);
            tokio::time::advance(HOLD).await;

            let result = held.await.expect("writer task");
            assert!(
                is_revoked_during_fetch(&result),
                "{writer}: an answer fetched across a bump must be discarded, got {result:?}"
            );
            assert_eq!(proposer_entry(&tracker).await, None, "{writer}: nothing is stored");
            assert_no_proposer_reader_hits(&tracker, writer).await;
        }
    }

    #[tokio::test]
    async fn stale_proposer_entry_sends_the_refresh_down_the_cold_path() {
        let (_mock, tracker, generation) =
            stamped(mock_proposer(proposer_stamp_response("0xroot_a")));
        tracker.fetch_proposer_duties(STAMP_EPOCH).await.expect("seed");
        bump(&generation);
        assert!(
            !tracker.is_proposer_epoch_cached(STAMP_EPOCH).await,
            "the entry is stale after a bump"
        );

        let changed =
            tracker.check_and_refetch_proposer_if_root_changed(STAMP_EPOCH).await.expect("refresh");

        assert!(changed, "a stale entry counts as uncached, so the cold path reports Ok(true)");
        assert_eq!(proposer_entry(&tracker).await, entry("0xroot_a", 1), "re-stamped");
        for reader in ProposerReader::ALL {
            assert!(reader.hits(&tracker).await, "{reader:?} serves the re-stamped entry");
        }
    }

    #[tokio::test]
    async fn every_proposer_reader_misses_after_a_bump() {
        let (_mock, tracker, generation) =
            stamped(mock_proposer(proposer_stamp_response("0xroot_a")));
        tracker.fetch_proposer_duties(STAMP_EPOCH).await.expect("fetch");
        for reader in ProposerReader::ALL {
            assert!(reader.hits(&tracker).await, "{reader:?} serves the fresh entry");
        }
        let changed =
            tracker.check_and_refetch_proposer_if_root_changed(STAMP_EPOCH).await.expect("refresh");
        assert!(!changed, "the refresh read sees the fresh entry");

        bump(&generation);

        assert_no_proposer_reader_hits(&tracker, "after a bump").await;
        let changed =
            tracker.check_and_refetch_proposer_if_root_changed(STAMP_EPOCH).await.expect("refresh");
        assert!(changed, "the refresh read treats the stale entry as uncached");
    }

    /// Holds a proposer fetch, runs `clear_cache()`, bumps if asked, then
    /// releases the answer.
    async fn clear_during_a_held_proposer_fetch(
        bump_after_clear: bool,
    ) -> (Result<Vec<ProposerDuty>, DutyTrackerError>, Arc<DutyTracker>) {
        let mock = mock_proposer(proposer_stamp_response("0xroot_a"))
            .with_method_delay(MockMethod::GetProposerDuties, HOLD);
        let (mock, tracker, generation) = stamped(mock);
        let fetch = tokio::spawn({
            let tracker = Arc::clone(&tracker);
            async move { tracker.fetch_proposer_duties(STAMP_EPOCH).await }
        });
        wait_for_arrivals(&mock, MockMethod::GetProposerDuties, 1).await;
        tracker.clear_cache().await;
        if bump_after_clear {
            bump(&generation);
        }
        tokio::time::advance(HOLD).await;
        (fetch.await.expect("fetch task"), tracker)
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn clear_during_a_held_proposer_fetch_then_bump_does_not_reinsert() {
        let (result, tracker) = clear_during_a_held_proposer_fetch(true).await;

        assert!(is_revoked_during_fetch(&result), "got {result:?}");
        assert_eq!(proposer_entry(&tracker).await, None);
        assert_no_proposer_reader_hits(&tracker, "clear then bump").await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn clear_without_a_bump_lets_the_held_fetch_insert() {
        let (result, tracker) = clear_during_a_held_proposer_fetch(false).await;

        assert_eq!(result.expect("clearing is not a revocation").len(), 1);
        let root = proposer_entry(&tracker).await.map(|(root, _)| root);
        assert_eq!(root.as_deref(), Some("0xroot_a"));
        for reader in ProposerReader::ALL {
            assert!(reader.hits(&tracker).await, "{reader:?} serves the inserted entry");
        }
    }

    #[tokio::test]
    async fn bump_between_proposer_read_lock_and_stamp_check_is_a_miss() {
        let (_mock, tracker, generation) =
            stamped(mock_proposer(proposer_stamp_response("0xroot_a")));
        for reader in ProposerReader::ALL {
            tracker.fetch_proposer_duties(STAMP_EPOCH).await.expect("fetch");
            assert!(reader.hits(&tracker).await, "{reader:?} serves the fresh entry");
            let before = generation.load(Ordering::Acquire);

            let hit = {
                let hook = bump_on_run(&generation, reader.proposer_run());
                let _armed = hooks::arm(&hooks::AFTER_READ_LOCK, hook);
                reader.hits(&tracker).await
            };

            assert_eq!(generation.load(Ordering::Acquire), before + 1, "{reader:?}: hook ran");
            assert!(!hit, "{reader:?} must load the generation inside its guard");
        }
    }

    #[tokio::test]
    async fn bump_after_the_proposer_stamp_check_is_seen_by_the_next_read() {
        let (_mock, tracker, generation) =
            stamped(mock_proposer(proposer_stamp_response("0xroot_a")));
        for reader in ProposerReader::ALL {
            tracker.fetch_proposer_duties(STAMP_EPOCH).await.expect("fetch");
            let before = generation.load(Ordering::Acquire);

            let hit = {
                let hook = bump_on_run(&generation, reader.proposer_run());
                let _armed = hooks::arm(&hooks::AFTER_STAMP_CHECK, hook);
                reader.hits(&tracker).await
            };

            assert_eq!(generation.load(Ordering::Acquire), before + 1, "{reader:?}: hook ran");
            assert!(hit, "{reader:?}: this read is linearised before the bump");
            assert!(!reader.hits(&tracker).await, "{reader:?}: the next read misses");
        }
    }

    /// Seeds root A, then runs `writer` with `hook` armed. The warm refresh
    /// answers root B over the visible root A.
    async fn proposer_write_with_hook(
        point: &'static std::thread::LocalKey<hooks::Slot>,
        refresh: bool,
    ) -> (Result<(), DutyTrackerError>, Arc<DutyTracker>, u64) {
        let mock = mock_proposer_queue(vec![
            proposer_stamp_response("0xroot_a"),
            proposer_stamp_response("0xroot_b"),
        ]);
        let (_mock, tracker, generation) = stamped(mock);
        if refresh {
            tracker.fetch_proposer_duties(STAMP_EPOCH).await.expect("seed root A");
        }
        let before = generation.load(Ordering::Acquire);
        let written = {
            let _armed = hooks::arm(point, bump_on_run(&generation, 1));
            if refresh {
                tracker.check_and_refetch_proposer_if_root_changed(STAMP_EPOCH).await.map(|_| ())
            } else {
                tracker.fetch_proposer_duties(STAMP_EPOCH).await.map(|_| ())
            }
        };
        assert_eq!(generation.load(Ordering::Acquire), before + 1, "hook ran");
        (written, tracker, before)
    }

    #[tokio::test]
    async fn bump_between_proposer_write_lock_and_recheck_is_discarded() {
        for (writer, refresh) in [("fetch", false), ("warm refresh", true)] {
            let (written, tracker, before) =
                proposer_write_with_hook(&hooks::AFTER_WRITE_LOCK, refresh).await;

            assert!(
                is_revoked_during_fetch(&written),
                "{writer}: the re-check runs under the write guard, got {written:?}"
            );
            let kept = refresh.then(|| ("0xroot_a".to_string(), Some(before)));
            assert_eq!(proposer_entry(&tracker).await, kept, "{writer}: nothing is inserted");
            assert_no_proposer_reader_hits(&tracker, writer).await;
        }
    }

    #[tokio::test]
    async fn bump_between_proposer_recheck_and_insert_leaves_nothing_servable() {
        for (writer, refresh, root) in
            [("fetch", false, "0xroot_a"), ("warm refresh", true, "0xroot_b")]
        {
            let (written, tracker, before) =
                proposer_write_with_hook(&hooks::BEFORE_INSERT, refresh).await;

            written.unwrap_or_else(|err| panic!("{writer}: the re-check passed, got {err}"));
            assert_eq!(
                proposer_entry(&tracker).await,
                entry(root, before),
                "{writer}: the entry carries the generation captured before the request"
            );
            assert_no_proposer_reader_hits(&tracker, writer).await;
        }
    }

    #[tokio::test]
    async fn test_only_cache_proposer_duties_stamps_the_current_generation() {
        let (_mock, tracker, generation) =
            stamped(mock_proposer(proposer_stamp_response("0xroot_a")));
        let duties = proposer_stamp_response("0xroot_b").data;
        tracker.fetch_proposer_duties(STAMP_EPOCH).await.expect("seed root A");
        bump(&generation);

        let changed = tracker.cache_proposer_duties(STAMP_EPOCH, "0xroot_b".into(), &duties).await;

        assert!(!changed, "the stale root A counts as absent, not as a root change");
        assert_eq!(proposer_entry(&tracker).await, entry("0xroot_b", 1));
        for reader in ProposerReader::ALL {
            assert!(reader.hits(&tracker).await, "{reader:?} serves the entry");
        }
    }

    #[tokio::test]
    async fn bump_between_proposer_refresh_read_lock_and_stamp_check_takes_the_cold_path() {
        let (mock, tracker, generation) =
            stamped(mock_proposer(proposer_stamp_response("0xroot_a")));
        tracker.fetch_proposer_duties(STAMP_EPOCH).await.expect("seed");

        let changed = {
            let _armed = hooks::arm(&hooks::AFTER_READ_LOCK, bump_on_run(&generation, 1));
            tracker.check_and_refetch_proposer_if_root_changed(STAMP_EPOCH).await
        };

        assert_eq!(generation.load(Ordering::Acquire), 1, "hook ran");
        assert!(
            changed.expect("refresh"),
            "the refresh read loads the generation inside its guard, so it sees a stale entry"
        );
        assert_eq!(mock.get_proposer_duties_calls().len(), 2, "seed, then the cold-path fetch");
        assert_eq!(proposer_entry(&tracker).await, entry("0xroot_a", 1), "re-stamped");
    }

    // -- Revocation-stamped PTC and sync caches (W4-E7c2) --

    fn ptc_stamp_response(dependent_root: &str) -> PtcDutiesResponse {
        ptc_response(vec![(STAMP_SLOT, "1234", "0xpubkey_1234")], dependent_root)
    }

    /// PTC duties from `ptc` in order, and one sync-committee duty.
    fn mock_ptc_and_sync(ptc: Vec<PtcDutiesResponse>) -> MockBeaconNodeClient {
        mock_ptc_queue(ptc).with_post_sync_committee_duties(|_epoch, _indices| {
            Ok(sync_response(vec![(1234, mock_sync_pubkey(), vec![0])]))
        })
    }

    async fn seed_ptc_and_sync(tracker: &DutyTracker) {
        tracker.fetch_ptc_duties_for_epoch(STAMP_EPOCH).await.expect("seed PTC");
        tracker.fetch_sync_committee_duties(STAMP_EPOCH).await.expect("seed sync");
    }

    /// The stored PTC root for `STAMP_EPOCH`, stale or not.
    async fn stored_ptc_root(tracker: &DutyTracker) -> Option<String> {
        tracker.ptc_cache.read().await.get(&STAMP_EPOCH).map(|entry| entry.dependent_root.clone())
    }

    /// Whether a sync entry is stored for `STAMP_EPOCH`'s period, stale or not.
    async fn sync_period_stored(tracker: &DutyTracker) -> bool {
        let period = DutyTracker::sync_committee_period(STAMP_EPOCH);
        tracker.sync_committee_cache.read().await.contains_key(&period)
    }

    /// The stored PTC entry for `STAMP_EPOCH`, stale or not: root and stamp.
    async fn ptc_entry(tracker: &DutyTracker) -> Option<(String, Option<u64>)> {
        let cache = tracker.ptc_cache.read().await;
        cache.get(&STAMP_EPOCH).map(|entry| (entry.dependent_root.clone(), entry.fetched_gen))
    }

    /// Polls `future` on the test task until `reached()` holds; it must stay
    /// pending. Not spawned, it makes no progress while the test awaits
    /// anything else.
    async fn poll_until<F>(
        future: &mut std::pin::Pin<Box<F>>,
        reached: impl Fn() -> bool,
        what: &str,
    ) where
        F: std::future::Future,
        F::Output: std::fmt::Debug,
    {
        for _ in 0..10_000 {
            let polled =
                std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx))).await;
            if let std::task::Poll::Ready(output) = polled {
                panic!("{what} finished early: {output:?}");
            }
            if reached() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("{what} never got there");
    }

    /// The PTC and sync readers that take a cache read guard.
    #[derive(Debug, Clone, Copy)]
    enum PtcSyncReader {
        PtcDuties,
        PtcDependentRoot,
        IsPtcEpochCached,
        PtcCount,
        SyncDuties,
        IsSyncPeriodCached,
        SyncCount,
    }

    impl PtcSyncReader {
        const ALL: [Self; 7] = [
            Self::PtcDuties,
            Self::PtcDependentRoot,
            Self::IsPtcEpochCached,
            Self::PtcCount,
            Self::SyncDuties,
            Self::IsSyncPeriodCached,
            Self::SyncCount,
        ];

        /// Which run of a read-path hook is this reader's guard.
        /// `cached_duty_counts` takes the attester, proposer, sync, then PTC guard.
        fn guard_run(self) -> usize {
            match self {
                Self::SyncCount => 3,
                Self::PtcCount => 4,
                _ => 1,
            }
        }

        /// Whether this reader serves the entry cached for `STAMP_EPOCH`.
        async fn hits(self, tracker: &DutyTracker) -> bool {
            match self {
                Self::PtcDuties => !tracker.get_ptc_duties_for_slot(STAMP_SLOT).await.is_empty(),
                Self::PtcDependentRoot => {
                    tracker.get_cached_ptc_dependent_root(STAMP_EPOCH).await.is_some()
                }
                Self::IsPtcEpochCached => tracker.is_ptc_epoch_cached(STAMP_EPOCH).await,
                Self::PtcCount => tracker.cached_duty_counts(STAMP_EPOCH).await.3 > 0,
                Self::SyncDuties => !tracker.get_sync_committee_duties(STAMP_SLOT).await.is_empty(),
                Self::IsSyncPeriodCached => tracker.is_sync_period_cached(STAMP_EPOCH).await,
                Self::SyncCount => tracker.cached_duty_counts(STAMP_EPOCH).await.2 > 0,
            }
        }
    }

    async fn assert_no_ptc_or_sync_reader_hits(tracker: &DutyTracker, context: &str) {
        for reader in PtcSyncReader::ALL {
            assert!(!reader.hits(tracker).await, "{context}: {reader:?} served the entry");
        }
    }

    /// A PTC or sync writer that sends one BN request.
    #[derive(Debug, Clone, Copy)]
    enum PtcSyncWriter {
        PtcFetch,
        PtcRefresh,
        SyncFetch,
    }

    impl PtcSyncWriter {
        async fn write(self, tracker: &DutyTracker) -> Result<(), DutyTrackerError> {
            match self {
                Self::PtcFetch => {
                    tracker.fetch_ptc_duties(STAMP_EPOCH, &["1234".to_string()]).await.map(|_| ())
                }
                Self::PtcRefresh => {
                    tracker.check_and_refetch_ptc_if_root_changed(STAMP_EPOCH).await.map(|_| ())
                }
                Self::SyncFetch => {
                    tracker.fetch_sync_committee_duties(STAMP_EPOCH).await.map(|_| ())
                }
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_ptc_reorg_refresh_revoked_before_release_is_discarded() {
        let mock =
            mock_ptc_queue(vec![ptc_stamp_response("0xroot_a"), ptc_stamp_response("0xroot_b")])
                .with_method_delay(MockMethod::PostPtcDuties, HOLD);
        let (mock, tracker, generation) = stamped(mock);
        tracker.fetch_ptc_duties_for_epoch(STAMP_EPOCH).await.expect("seed root A");
        assert_eq!(
            tracker.get_cached_ptc_dependent_root(STAMP_EPOCH).await.as_deref(),
            Some("0xroot_a")
        );

        let refresh = tokio::spawn({
            let tracker = Arc::clone(&tracker);
            async move { tracker.check_and_refetch_ptc_if_root_changed(STAMP_EPOCH).await }
        });
        wait_for_arrivals(&mock, MockMethod::PostPtcDuties, 2).await;
        bump(&generation);
        tokio::time::advance(HOLD).await;

        let result = refresh.await.expect("refresh task");
        assert!(
            is_revoked_during_fetch(&result),
            "a refresh answer fetched across a bump must be discarded, got {result:?}"
        );
        assert_eq!(stored_ptc_root(&tracker).await.as_deref(), Some("0xroot_a"), "B is not stored");
        assert_eq!(tracker.get_cached_ptc_dependent_root(STAMP_EPOCH).await, None);
        assert!(tracker.get_ptc_duties_for_slot(STAMP_SLOT).await.is_empty());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_same_root_ptc_refresh_revoked_before_release_does_not_restamp() {
        let mock = mock_ptc_queue(vec![ptc_stamp_response("0xroot_a"); 2])
            .with_method_delay(MockMethod::PostPtcDuties, HOLD);
        let (mock, tracker, generation) = stamped(mock);
        tracker.fetch_ptc_duties_for_epoch(STAMP_EPOCH).await.expect("seed root A");

        let refresh = tokio::spawn({
            let tracker = Arc::clone(&tracker);
            async move { tracker.check_and_refetch_ptc_if_root_changed(STAMP_EPOCH).await }
        });
        wait_for_arrivals(&mock, MockMethod::PostPtcDuties, 2).await;
        bump(&generation);
        tokio::time::advance(HOLD).await;

        let result = refresh.await.expect("refresh task");
        assert!(
            matches!(result, Ok(false)),
            "a same-root refresh must report no root change, got {result:?}"
        );
        assert_eq!(stored_ptc_root(&tracker).await.as_deref(), Some("0xroot_a"));
        assert_no_ptc_or_sync_reader_hits(&tracker, "same-root refresh held across a bump").await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_ptc_refresh_compares_against_the_entry_under_its_write_guard() {
        let mock = mock_ptc_queue(vec![ptc_stamp_response("0xroot_a"); 2])
            .with_method_delay(MockMethod::PostPtcDuties, HOLD);
        let (mock, tracker, _generation) = stamped(mock);
        tracker.fetch_ptc_duties_for_epoch(STAMP_EPOCH).await.expect("seed root A");

        let refresh = tokio::spawn({
            let tracker = Arc::clone(&tracker);
            async move { tracker.check_and_refetch_ptc_if_root_changed(STAMP_EPOCH).await }
        });
        wait_for_arrivals(&mock, MockMethod::PostPtcDuties, 2).await;
        tracker.clear_cache().await;
        tokio::time::advance(HOLD).await;

        let changed =
            refresh.await.expect("refresh task").expect("no bump: the answer is admitted");
        assert!(changed, "the entry read before the request is gone, so root A is a change");
        assert_eq!(stored_ptc_root(&tracker).await.as_deref(), Some("0xroot_a"), "re-inserted");
        for reader in &PtcSyncReader::ALL[..4] {
            assert!(reader.hits(&tracker).await, "{reader:?} serves the re-inserted entry");
        }
    }

    /// A warm refresh requested under G0 finishes after a fetch requested
    /// under G1 stored the same answer. It compares against the entry visible
    /// under its own stamp, so it refuses its answer and keeps the newer entry.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_ptc_refresh_overtaken_by_a_newer_same_snapshot_write_is_refused() {
        for answer in ["0xroot_a", "0xroot_b"] {
            let ptc = ["0xroot_a", answer, answer].map(ptc_stamp_response).to_vec();
            let mock = mock_ptc_queue(ptc).with_method_delay(MockMethod::PostPtcDuties, HOLD);
            let (mock, tracker, generation) = stamped(mock);
            tracker.fetch_ptc_duties_for_epoch(STAMP_EPOCH).await.expect("seed root A");

            let mut refresh = Box::pin(tracker.check_and_refetch_ptc_if_root_changed(STAMP_EPOCH));
            let arrived = || mock.call_stamps().len() == 2;
            poll_until(&mut refresh, arrived, "the warm refresh request").await;
            bump(&generation);
            tracker.fetch_ptc_duties_for_epoch(STAMP_EPOCH).await.expect("newer fetch");
            assert_eq!(ptc_entry(&tracker).await, entry(answer, 1), "{answer}: newer entry");

            let result = refresh.await;
            assert!(
                is_revoked_during_fetch(&result),
                "{answer}: an answer requested before the bump must be refused, got {result:?}"
            );
            assert_eq!(ptc_entry(&tracker).await, entry(answer, 1), "{answer}: newer entry kept");
            assert_eq!(mock.post_ptc_duties_calls().len(), 3, "{answer}: no cold-path fetch");
            for reader in &PtcSyncReader::ALL[..4] {
                assert!(reader.hits(&tracker).await, "{answer}: {reader:?} serves the newer entry");
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_ptc_and_sync_fetches_revoked_before_release_are_discarded() {
        let mock = mock_ptc_and_sync(vec![ptc_stamp_response("0xroot_a"); 2])
            .with_method_delay(MockMethod::PostPtcDuties, HOLD)
            .with_method_delay(MockMethod::PostSyncCommitteeDuties, HOLD);
        let (mock, tracker, generation) = stamped(mock);

        // The refresh of an uncached epoch takes its cold path.
        for (writer, method, arrivals) in [
            (PtcSyncWriter::PtcFetch, MockMethod::PostPtcDuties, 1),
            (PtcSyncWriter::PtcRefresh, MockMethod::PostPtcDuties, 2),
            (PtcSyncWriter::SyncFetch, MockMethod::PostSyncCommitteeDuties, 1),
        ] {
            let held = tokio::spawn({
                let tracker = Arc::clone(&tracker);
                async move { writer.write(&tracker).await }
            });
            wait_for_arrivals(&mock, method, arrivals).await;
            bump(&generation);
            tokio::time::advance(HOLD).await;

            let result = held.await.expect("writer task");
            assert!(
                is_revoked_during_fetch(&result),
                "{writer:?}: an answer fetched across a bump must be discarded, got {result:?}"
            );
            assert_eq!(stored_ptc_root(&tracker).await, None, "{writer:?}: no PTC entry");
            assert!(!sync_period_stored(&tracker).await, "{writer:?}: no sync entry");
            assert_no_ptc_or_sync_reader_hits(&tracker, &format!("{writer:?}")).await;
        }
    }

    /// The writer has its BN answer and waits for the cache write guard when
    /// the generation moves: the re-check under that guard refuses the answer.
    #[tokio::test]
    async fn bump_while_a_ptc_or_sync_fetch_waits_for_its_write_guard_is_discarded() {
        for (writer, answered) in
            [(PtcSyncWriter::PtcFetch, (1, 0)), (PtcSyncWriter::SyncFetch, (0, 1))]
        {
            let sync_answers = Arc::new(AtomicU64::new(0));
            let mock = mock_ptc_queue(vec![ptc_stamp_response("0xroot_a")])
                .with_post_sync_committee_duties({
                    let sync_answers = Arc::clone(&sync_answers);
                    move |_epoch, _indices| {
                        sync_answers.fetch_add(1, Ordering::Relaxed);
                        Ok(sync_response(vec![(1234, mock_sync_pubkey(), vec![0])]))
                    }
                });
            let (mock, tracker, generation) = stamped(mock);
            let answers =
                || (mock.post_ptc_duties_calls().len(), sync_answers.load(Ordering::Relaxed));
            let ptc_guard = tracker.ptc_cache.write().await;
            let sync_guard = tracker.sync_committee_cache.write().await;

            let mut write = Box::pin(writer.write(&tracker));
            poll_until(&mut write, || answers() == answered, &format!("{writer:?}")).await;
            bump(&generation);
            drop((ptc_guard, sync_guard));

            let result = write.await;
            assert!(
                is_revoked_during_fetch(&result),
                "{writer:?}: the re-check runs under the write guard it waited for, got {result:?}"
            );
            assert_eq!(ptc_entry(&tracker).await, None, "{writer:?}: no PTC entry");
            assert!(!sync_period_stored(&tracker).await, "{writer:?}: no sync entry");
            assert_no_ptc_or_sync_reader_hits(&tracker, &format!("{writer:?}")).await;
        }
    }

    #[tokio::test]
    async fn every_ptc_and_sync_reader_misses_after_a_bump() {
        let (_mock, tracker, generation) =
            stamped(mock_ptc_and_sync(vec![ptc_stamp_response("0xroot_a"); 3]));
        seed_ptc_and_sync(&tracker).await;
        for reader in PtcSyncReader::ALL {
            assert!(reader.hits(&tracker).await, "{reader:?} serves the fresh entry");
        }
        let changed =
            tracker.check_and_refetch_ptc_if_root_changed(STAMP_EPOCH).await.expect("refresh");
        assert!(!changed, "the refresh read sees the fresh entry");

        bump(&generation);

        assert_no_ptc_or_sync_reader_hits(&tracker, "after a bump").await;
        let changed =
            tracker.check_and_refetch_ptc_if_root_changed(STAMP_EPOCH).await.expect("refresh");
        assert!(changed, "the refresh read treats the stale entry as uncached");
    }

    #[tokio::test]
    async fn bump_between_ptc_or_sync_read_lock_and_stamp_check_is_a_miss() {
        let mock =
            mock_ptc_and_sync(vec![ptc_stamp_response("0xroot_a"); PtcSyncReader::ALL.len()]);
        let (_mock, tracker, generation) = stamped(mock);
        for reader in PtcSyncReader::ALL {
            seed_ptc_and_sync(&tracker).await;
            assert!(reader.hits(&tracker).await, "{reader:?} serves the fresh entry");
            let before = generation.load(Ordering::Acquire);

            let hit = {
                let hook = bump_on_run(&generation, reader.guard_run());
                let _armed = hooks::arm(&hooks::AFTER_READ_LOCK, hook);
                reader.hits(&tracker).await
            };

            assert_eq!(generation.load(Ordering::Acquire), before + 1, "{reader:?}: hook ran");
            assert!(!hit, "{reader:?} must load the generation inside its guard");
        }
    }

    #[tokio::test]
    async fn bump_between_ptc_refresh_read_lock_and_stamp_check_takes_the_cold_path() {
        let (mock, tracker, generation) =
            stamped(mock_ptc_queue(vec![ptc_stamp_response("0xroot_a"); 2]));
        tracker.fetch_ptc_duties_for_epoch(STAMP_EPOCH).await.expect("seed");

        let changed = {
            let _armed = hooks::arm(&hooks::AFTER_READ_LOCK, bump_on_run(&generation, 1));
            tracker.check_and_refetch_ptc_if_root_changed(STAMP_EPOCH).await
        };

        assert_eq!(generation.load(Ordering::Acquire), 1, "hook ran");
        assert!(
            changed.expect("refresh"),
            "the refresh read loads the generation inside its guard, so it sees a stale entry"
        );
        assert_eq!(mock.post_ptc_duties_calls().len(), 2, "seed, then the cold-path fetch");
        assert!(tracker.is_ptc_epoch_cached(STAMP_EPOCH).await, "re-stamped");
    }

    /// The refresh captures its stamp before its cached read, so a bump right
    /// after that read is a bump during its request.
    #[tokio::test]
    async fn ptc_refresh_captures_its_stamp_before_its_cached_read() {
        for (answer, same_root) in [("0xroot_a", true), ("0xroot_b", false)] {
            let (mock, tracker, generation) =
                stamped(mock_ptc_queue(["0xroot_a", answer].map(ptc_stamp_response).to_vec()));
            tracker.fetch_ptc_duties_for_epoch(STAMP_EPOCH).await.expect("seed root A");

            let result = {
                let _armed = hooks::arm(&hooks::AFTER_STAMP_CHECK, bump_on_run(&generation, 1));
                tracker.check_and_refetch_ptc_if_root_changed(STAMP_EPOCH).await
            };

            assert_eq!(generation.load(Ordering::Acquire), 1, "{answer}: hook ran");
            assert_eq!(mock.post_ptc_duties_calls().len(), 2, "{answer}: seed, then the warm path");
            if same_root {
                assert!(
                    matches!(result, Ok(false)),
                    "{answer}: the entry visible under the stamp has this root, got {result:?}"
                );
            } else {
                assert!(
                    is_revoked_during_fetch(&result),
                    "{answer}: an answer requested before the bump must be refused, got {result:?}"
                );
            }
            assert_eq!(ptc_entry(&tracker).await, entry("0xroot_a", 0), "{answer}: not restamped");
            assert_no_ptc_or_sync_reader_hits(&tracker, answer).await;
        }
    }

    #[tokio::test]
    async fn bump_between_ptc_or_sync_recheck_and_insert_leaves_nothing_servable() {
        // The warm refresh answers root B over a freshly seeded root A.
        let ptc = ["0xroot_a", "0xroot_a", "0xroot_b"].map(ptc_stamp_response).to_vec();
        let (_mock, tracker, generation) = stamped(mock_ptc_and_sync(ptc));

        for (writer, root) in [
            (PtcSyncWriter::PtcFetch, Some("0xroot_a")),
            (PtcSyncWriter::PtcRefresh, Some("0xroot_b")),
            (PtcSyncWriter::SyncFetch, None),
        ] {
            if matches!(writer, PtcSyncWriter::PtcRefresh) {
                tracker.fetch_ptc_duties_for_epoch(STAMP_EPOCH).await.expect("seed root A");
            }
            let before = generation.load(Ordering::Acquire);
            let written = {
                let _armed = hooks::arm(&hooks::BEFORE_INSERT, bump_on_run(&generation, 1));
                writer.write(&tracker).await
            };

            written.unwrap_or_else(|err| panic!("{writer:?}: the re-check passed, got {err}"));
            assert_eq!(generation.load(Ordering::Acquire), before + 1, "{writer:?}: hook ran");
            match root {
                Some(root) => assert_eq!(stored_ptc_root(&tracker).await.as_deref(), Some(root)),
                None => assert!(sync_period_stored(&tracker).await, "{writer:?}: stored"),
            }
            assert_no_ptc_or_sync_reader_hits(&tracker, &format!("{writer:?}")).await;
        }
    }

    // -- Source scans: every cache read and insert follows the stamp rule (W4-E7c2) --

    /// `tracker.rs` before its test module, with `//` comments removed.
    fn production_code() -> String {
        let source = include_str!("tracker.rs");
        let end = source.find("\n#[cfg(test)]\nmod tests {").expect("test module boundary");
        let lines = source[..end].lines().map(|line| line.split("//").next().unwrap_or_default());
        lines.collect::<Vec<_>>().join("\n")
    }

    /// One `fn` with a body: its name, whether it is `pub`, and its signature
    /// and braced body with whitespace removed, so a call that rustfmt splits
    /// over lines still matches.
    struct FnItem<'a> {
        name: &'a str,
        public: bool,
        signature: String,
        body: String,
    }

    fn compact(code: &str) -> String {
        code.split_whitespace().collect()
    }

    /// Every `fn` with a body in `code`, outermost only, in source order.
    fn fn_items(code: &str) -> Vec<FnItem<'_>> {
        let mut items = Vec::new();
        let mut from = 0;
        while let Some(found) = code[from..].find("fn ") {
            let start = from + found;
            from = start + "fn ".len();
            if code[..start].ends_with(|c: char| c.is_alphanumeric() || c == '_') {
                continue;
            }
            let rest = &code[from..];
            let name_len = rest.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(0);
            let Some(open) = rest.find(['{', ';']) else { break };
            if rest[open..].starts_with(';') {
                continue;
            }
            let body_start = from + open;
            let mut depth = 0;
            let mut body_end = code.len();
            for (offset, c) in code[body_start..].char_indices() {
                depth += i32::from(c == '{') - i32::from(c == '}');
                if depth == 0 {
                    body_end = body_start + offset + 1;
                    break;
                }
            }
            let line = code[..start].rsplit('\n').next().unwrap_or_default();
            items.push(FnItem {
                name: &rest[..name_len],
                public: line.split_whitespace().any(|word| word.starts_with("pub")),
                signature: compact(&code[start..body_start]),
                body: compact(&code[body_start..body_end]),
            });
            from = body_end;
        }
        items
    }

    /// The `fn`s in `code` that read a cache without checking the stamp before
    /// their next `.await`, once per unchecked read.
    ///
    /// A read is `.read().await`, or a call to a guard helper: a `fn` returning
    /// `RwLockReadGuard`, which leaves the check to its caller. A check is
    /// `visible(`, or a call to a `fn` whose body calls `visible(`.
    fn unchecked_reads(code: &str) -> Vec<String> {
        let items = fn_items(code);
        let is_guard_helper = |item: &FnItem<'_>| item.signature.contains("->RwLockReadGuard<");
        let mut reads = vec![".read().await".to_string()];
        reads.extend(
            items.iter().filter(|i| is_guard_helper(i)).map(|i| format!(".{}().await", i.name)),
        );
        let mut checks = vec!["visible(".to_string()];
        checks.extend(
            items.iter().filter(|i| i.body.contains("visible(")).map(|i| format!("{}(", i.name)),
        );

        let mut offenders = Vec::new();
        for item in items.iter().filter(|item| !is_guard_helper(item)) {
            let mut at: Vec<usize> = reads
                .iter()
                .flat_map(|read| item.body.match_indices(read.as_str()).map(|(i, m)| i + m.len()))
                .collect();
            at.sort_unstable();
            for end in at {
                let section = item.body[end..].split(".await").next().unwrap_or_default();
                if !checks.iter().any(|check| section.contains(check.as_str())) {
                    offenders.push(item.name.to_string());
                }
            }
        }
        offenders
    }

    /// The only `admit_*` helpers: with `insert_proposer`, the only cache inserters.
    const ADMIT_HELPERS: [&str; 4] =
        ["admit_attester", "admit_proposer", "admit_ptc", "admit_sync"];

    /// The `fn`s in `code` that break the insert rule, with the reason.
    ///
    /// A cache guard (`.write().await` or a `RwLockWriteGuard` parameter) is
    /// inserted into only by one of `ADMIT_HELPERS` or by `insert_proposer`,
    /// which only `admit_proposer` and the test-only `cache_proposer_duties`
    /// call. Each of these insert helpers is private and takes a `FetchStamp`.
    /// A `fn` that names an admit helper in any form (`self.admit_ptc(`,
    /// `Self::admit_ptc(`, a fn pointer) sends a BN request, and every `fn`
    /// that sends one assigns `fetch_stamp()` before its first `self.beacon.`.
    fn unstamped_writes(code: &str) -> Vec<String> {
        let mut offenders = Vec::new();
        for item in fn_items(code) {
            let holds_guard =
                item.signature.contains("RwLockWriteGuard") || item.body.contains(".write().await");
            let inserter = ADMIT_HELPERS.contains(&item.name) || item.name == "insert_proposer";
            if holds_guard && item.body.contains(".insert(") && !inserter {
                offenders.push(format!("{}: inserts outside the admit_* helpers", item.name));
            }
            let proposer_admitters = ["admit_proposer", "cache_proposer_duties"];
            if item.body.contains("insert_proposer(") && !proposer_admitters.contains(&item.name) {
                offenders.push(format!("{}: calls insert_proposer", item.name));
            }
            let first_request = item.body.find("self.beacon.");
            let admits = ADMIT_HELPERS.iter().any(|helper| item.body.contains(helper));
            if admits && first_request.is_none() {
                offenders.push(format!("{}: admits an answer it did not request", item.name));
            }
            if first_request.is_some_and(|at| !item.body[..at].contains("=self.fetch_stamp();")) {
                offenders.push(format!("{}: no fetch_stamp() before its first request", item.name));
            }
            if inserter && item.public {
                offenders.push(format!("{}: insert helper is public", item.name));
            }
            if inserter && !item.signature.contains(":FetchStamp") {
                offenders.push(format!("{}: insert helper takes no FetchStamp", item.name));
            }
        }
        offenders
    }

    #[test]
    fn every_cache_read_checks_the_revocation_stamp() {
        let code = production_code();
        assert_eq!(unchecked_reads(&code), Vec::<String>::new(), "unchecked cache reads");

        let items = fn_items(&code);
        let read_count = |name: &str| {
            let item = items.iter().find(|item| item.name == name).expect(name);
            item.body.matches("read().await").count()
        };
        for helper in ["attester_read", "proposer_read", "ptc_read", "sync_read"] {
            assert_eq!(read_count(helper), 1, "{helper} takes one read guard");
        }
        for reader in [
            "get_duty",
            "get_duties_for_slot",
            "is_epoch_cached",
            "get_cached_dependent_root",
            "get_proposer_duty",
            "get_cached_proposer_dependent_root",
            "check_and_refetch_proposer_if_root_changed",
            "is_proposer_epoch_cached",
            "get_ptc_duties_for_slot",
            "get_cached_ptc_dependent_root",
            "check_and_refetch_ptc_if_root_changed",
            "is_ptc_epoch_cached",
            "get_sync_committee_duties",
            "is_sync_period_cached",
        ] {
            assert_eq!(read_count(reader), 1, "the scan sees {reader}'s read");
        }
        assert_eq!(read_count("cached_duty_counts"), 4, "one read per cache");

        let fixture = "
            fn check(stamp: u64) -> bool { visible(stamp, 0) }
            async fn guard(&self) -> RwLockReadGuard<'_, Map> { self.map.read().await }
            async fn checked(&self) -> bool { let m = self.guard().await; check(m.len()) }
            async fn skipped(&self) -> bool { let m = self.map.read().await; m.is_empty() }
            async fn late(&self) -> bool { let m = self.guard().await; self.x().await; check(1) }
            async fn twice(&self) { let a = self.guard().await; check(a.len()); self.guard().await; }
        ";
        assert_eq!(unchecked_reads(fixture), ["skipped", "late", "twice"]);
    }

    #[test]
    fn every_cache_insert_is_stamped_before_the_bn_request() {
        let code = production_code();
        assert_eq!(unstamped_writes(&code), Vec::<String>::new(), "unstamped cache writes");

        let items = fn_items(&code);
        let body = |name: &str| &items.iter().find(|item| item.name == name).expect(name).body;
        for admit in ADMIT_HELPERS {
            assert!(body(admit).contains("visible("), "the scan sees {admit}'s re-check");
        }
        for writer in [
            "fetch_duties_for_epoch",
            "check_and_refetch_if_root_changed",
            "fetch_proposer_duties",
            "check_and_refetch_proposer_if_root_changed",
            "fetch_ptc_duties",
            "check_and_refetch_ptc_if_root_changed",
            "fetch_sync_committee_duties",
        ] {
            let writer_body = body(writer);
            assert!(writer_body.contains("self.beacon."), "the scan sees {writer}'s request");
            assert!(writer_body.contains(".admit_"), "{writer} inserts through an admit_* helper");
        }
        let test_only = "#[cfg(any(test,feature=\"test-utils\"))]pubasyncfncache_proposer_duties(";
        assert!(
            compact(&code).contains(test_only),
            "the insert_proposer exception stays test-only"
        );

        let fixture = "
            fn admit_ptc(c: &mut RwLockWriteGuard<'_, Map>, e: E, s: FetchStamp) { c.insert(1, e); }
            async fn stamped_first(&self) { let s = self.fetch_stamp(); let e = self.beacon.x().await; let mut c = self.m.write().await; self.admit_ptc(&mut c, e, s); }
            async fn ufcs(&self) { let s = self.fetch_stamp(); let e = self.beacon.x().await; let mut c = self.m.write().await; Self::admit_ptc(self, &mut c, e, s); }
            async fn bypass(&self) { let s = self.fetch_stamp(); let e = self.beacon.x().await; self.m.write().await.insert(1, e); }
            async fn late(&self) { let e = self.beacon.x().await; let s = self.fetch_stamp(); let mut c = self.m.write().await; self.admit_ptc(&mut c, e, s); }
            async fn setter(&self, e: E) { let mut c = self.m.write().await; self.admit_ptc(&mut c, e, self.fetch_stamp()); }
            async fn ufcs_setter(&self, e: E) { let mut c = self.m.write().await; Self::admit_ptc(self, &mut c, e, self.fetch_stamp()); }
            pub async fn admit_unrequested(&self, e: E) { let mut c = self.m.write().await; c.insert(1, e); }
            fn helper(c: &mut RwLockWriteGuard<'_, Map>, e: E) { c.insert(1, e); }
            async fn reuse(&self, e: E) { let mut c = self.m.write().await; insert_proposer(&mut c, e); }
            pub fn admit_sync(c: &mut RwLockWriteGuard<'_, Map>, e: E, s: FetchStamp) { c.insert(1, e); }
            fn admit_attester(c: &mut RwLockWriteGuard<'_, Map>, e: E, g: Option<u64>) { c.insert(1, e); }
        ";
        assert_eq!(
            unstamped_writes(fixture),
            [
                "bypass: inserts outside the admit_* helpers",
                "late: no fetch_stamp() before its first request",
                "setter: admits an answer it did not request",
                "ufcs_setter: admits an answer it did not request",
                "admit_unrequested: inserts outside the admit_* helpers",
                "helper: inserts outside the admit_* helpers",
                "reuse: calls insert_proposer",
                "admit_sync: insert helper is public",
                "admit_attester: insert helper takes no FetchStamp",
            ]
        );
    }

    fn key_set(keys: &[&str]) -> BTreeSet<String> {
        keys.iter().map(|k| (*k).to_string()).collect()
    }

    #[derive(Clone, Debug)]
    struct CapturedSpan {
        name: String,
        level: tracing::Level,
        keys: BTreeSet<String>,
        values: BTreeMap<String, String>,
    }

    #[derive(Default, Clone)]
    struct EpochSpanCapture {
        state: Arc<Mutex<CaptureState>>,
    }

    #[derive(Clone, Debug)]
    struct CapturedEvent {
        parent_name: Option<String>,
        message: String,
        keys: BTreeSet<String>,
    }

    #[derive(Default)]
    struct CaptureState {
        spans: Vec<CapturedSpan>,
        events: Vec<CapturedEvent>,
        index: HashMap<u64, usize>,
    }

    struct FieldVisitor<'a>(&'a mut CapturedSpan);

    impl tracing::field::Visit for FieldVisitor<'_> {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            let name = field.name().to_string();
            let rendered = format!("{value:?}").trim_matches('"').to_string();
            self.0.keys.insert(name.clone());
            self.0.values.insert(name, rendered);
        }
    }

    impl<S> tracing_subscriber::Layer<S> for EpochSpanCapture
    where
        S: tracing::Subscriber,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            id: &tracing::span::Id,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut span = CapturedSpan {
                name: attrs.metadata().name().to_string(),
                level: *attrs.metadata().level(),
                keys: BTreeSet::new(),
                values: BTreeMap::new(),
            };
            attrs.record(&mut FieldVisitor(&mut span));
            let mut state = self.state.lock().expect("span capture");
            let idx = state.spans.len();
            state.index.insert(id.into_u64(), idx);
            state.spans.push(span);
        }

        fn on_record(
            &self,
            id: &tracing::span::Id,
            values: &tracing::span::Record<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut state = self.state.lock().expect("span capture");
            let Some(idx) = state.index.get(&id.into_u64()).copied() else {
                return;
            };
            values.record(&mut FieldVisitor(&mut state.spans[idx]));
        }

        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut recorded = CapturedSpan {
                name: String::new(),
                level: *event.metadata().level(),
                keys: BTreeSet::new(),
                values: BTreeMap::new(),
            };
            event.record(&mut FieldVisitor(&mut recorded));
            let parent_id = event.parent().cloned().or_else(|| ctx.current_span().id().cloned());
            let mut state = self.state.lock().expect("span capture");
            let parent_name = parent_id.as_ref().and_then(|id| {
                state.index.get(&id.into_u64()).map(|idx| state.spans[*idx].name.clone())
            });
            let message = recorded.values.get("message").cloned().unwrap_or_default();
            state.events.push(CapturedEvent { parent_name, message, keys: recorded.keys });
        }
    }
}
