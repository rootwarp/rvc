use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::metrics::{
    RVC_DUTIES_FETCHED_TOTAL, RVC_DUTY_REJECTED_TOTAL, RVC_PTC_DUTIES_FETCHED_TOTAL,
};
use bn_manager::{AttesterDuty, BeaconNodeClient, ProposerDuty, PtcDuty};
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
}

impl EpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root, indices: Vec::new() }
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
}

impl ProposerEpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root }
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
}

impl PtcEpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root, indices: Vec::new() }
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
}

impl SyncPeriodDutyCache {
    /// Construct a period cache from a BN sync-committee duties response body.
    fn from_response(duties: Vec<SyncCommitteeDuty>) -> Self {
        Self { duties, indices: Vec::new() }
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

pub struct DutyTracker {
    beacon: Arc<dyn BeaconNodeClient>,
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
}

impl DutyTracker {
    /// Track duties for a fixed validator index set.
    ///
    /// Convenience wrapper around [`Self::new_with_source`]: the set does not
    /// change between fetches.
    pub fn new(beacon: Arc<dyn BeaconNodeClient>, validator_indices: Vec<String>) -> Self {
        Self::new_with_source(beacon, Arc::new(StaticIndexSource(validator_indices)))
    }

    /// Track duties for an index set that may change between fetches.
    ///
    /// Each fetch calls [`ValidatorIndexSource::indices`] once and uses that
    /// snapshot for every beacon request the call makes. [`Self::new`] wraps a
    /// static set.
    pub fn new_with_source(
        beacon: Arc<dyn BeaconNodeClient>,
        index_source: Arc<dyn ValidatorIndexSource>,
    ) -> Self {
        Self {
            beacon,
            index_source,
            cache: RwLock::new(HashMap::new()),
            proposer_cache: RwLock::new(HashMap::new()),
            ptc_cache: RwLock::new(HashMap::new()),
            sync_committee_cache: RwLock::new(HashMap::new()),
            slot_duty_lookups: AtomicU64::new(0),
            fork_schedule: ForkSchedule::unscheduled_gloas(),
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

    #[tracing::instrument(name = "duty_tracker.fetch_attester_duties", level = "debug", skip_all, fields(epoch =epoch, duty = %observability::logging::fields::Duty::Attestation.as_str()))]
    pub async fn fetch_duties_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Vec<AttesterDuty>, DutyTrackerError> {
        let indices = self.index_source.indices();
        debug!(epoch = epoch, "Fetching duties for epoch");

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

        info!(
            epoch = epoch,
            duties_count = response.data.len(),
            dependent_root = %response.dependent_root,
            "Cached duties for epoch"
        );

        cache.insert(epoch, epoch_cache);

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
    ) -> Result<AttesterDuty, DutyTrackerError> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.cache.read().await;

        let key = DutyCacheKey { slot, committee_index, validator_index };

        if let Some(epoch_cache) = cache.get(&epoch) {
            if let Some(duty) = epoch_cache.get(&key) {
                debug!(slot, epoch, cache_type = "attester", "Cache hit");
                return Ok(duty.raw.clone());
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
        // Fetch from BN first (no lock held) to avoid TOCTOU race
        let response = self
            .beacon
            .get_attester_duties(epoch, &indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        // Acquire write lock and compare-and-swap atomically
        let mut cache = self.cache.write().await;
        let cached = cache.get(&epoch);
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

        cache.insert(epoch, epoch_cache);
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
    pub async fn get_duties_for_slot(&self, slot: u64) -> Vec<AttesterDuty> {
        self.slot_duty_lookups.fetch_add(1, Ordering::Relaxed);
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.cache.read().await;

        let Some(epoch_cache) = cache.get(&epoch) else {
            debug!(slot, epoch, cache_type = "attester", "Cache miss for slot");
            return Vec::new();
        };

        let duties: Vec<AttesterDuty> = epoch_cache
            .duties
            .iter()
            .filter(|(key, _)| key.slot == slot)
            .map(|(_, duty)| duty.raw.clone())
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
        let cache = self.cache.read().await;
        cache.get(&epoch).is_some_and(|entry| entry.indices == indices)
    }

    pub async fn get_cached_dependent_root(&self, epoch: u64) -> Option<String> {
        let cache = self.cache.read().await;
        cache.get(&epoch).map(|c| c.dependent_root.clone())
    }

    /// Write proposer duties into the in-process cache.
    ///
    /// Returns `true` when this epoch was already cached under a different
    /// `dependent_root` — the signal to re-broadcast preferences.
    pub async fn cache_proposer_duties(
        &self,
        epoch: u64,
        dependent_root: String,
        duties: &[ProposerDuty],
    ) -> bool {
        let mut cache = self.proposer_cache.write().await;
        let root_changed = cache.get(&epoch).is_some_and(|c| c.dependent_root != dependent_root);
        let (epoch_cache, _rejected) =
            ProposerEpochDutyCache::from_response(dependent_root, duties);
        cache.insert(epoch, epoch_cache);
        root_changed
    }

    #[tracing::instrument(name = "duty_tracker.fetch_proposer_duties", level = "debug", skip_all, fields(epoch =epoch, duty = %observability::logging::fields::Duty::Block.as_str()))]
    pub async fn fetch_proposer_duties(
        &self,
        epoch: u64,
    ) -> Result<Vec<ProposerDuty>, DutyTrackerError> {
        debug!(epoch = epoch, "Fetching proposer duties for epoch");

        let response = self
            .beacon
            .get_proposer_duties(epoch, &self.fork_schedule)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        let _ = self
            .cache_proposer_duties(epoch, response.dependent_root.clone(), &response.data)
            .await;

        info!(epoch = epoch, count = response.data.len(), "Cached proposer duties for epoch");

        Ok(response.data)
    }

    #[tracing::instrument(
        name = "duty_tracker.get_proposer_duty",
        level = "debug",
        skip_all,
        fields(slot = slot, epoch = slot / SLOTS_PER_EPOCH)
    )]
    pub async fn get_proposer_duty(&self, slot: u64) -> Option<ProposerDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.proposer_cache.read().await;
        let result = cache.get(&epoch).and_then(|c| c.get(&slot)).map(|duty| duty.raw.clone());
        if result.is_some() {
            debug!(slot, epoch, cache_type = "proposer", "Cache hit");
        } else {
            debug!(slot, epoch, cache_type = "proposer", "Cache miss");
        }
        result
    }

    pub async fn get_cached_proposer_dependent_root(&self, epoch: u64) -> Option<String> {
        let cache = self.proposer_cache.read().await;
        cache.get(&epoch).map(|c| c.dependent_root.clone())
    }

    #[tracing::instrument(name = "duty_tracker.check_proposer_reorg", level = "debug", skip_all, fields(epoch =epoch, duty = %observability::logging::fields::Duty::Block.as_str()))]
    pub async fn check_and_refetch_proposer_if_root_changed(
        &self,
        epoch: u64,
    ) -> Result<bool, DutyTrackerError> {
        let cached_root = {
            let cache = self.proposer_cache.read().await;
            cache.get(&epoch).map(|c| c.dependent_root.clone())
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

            let _ =
                self.cache_proposer_duties(epoch, response.dependent_root, &response.data).await;
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn is_proposer_epoch_cached(&self, epoch: u64) -> bool {
        let cache = self.proposer_cache.read().await;
        cache.contains_key(&epoch)
    }

    #[tracing::instrument(name = "duty_tracker.fetch_ptc_duties", level = "debug", skip_all, fields(epoch =epoch))]
    pub async fn fetch_ptc_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<Vec<PtcDuty>, DutyTrackerError> {
        debug!(epoch = epoch, "Fetching PTC duties for epoch");

        let response = self
            .beacon
            .post_ptc_duties(epoch, validator_indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        RVC_PTC_DUTIES_FETCHED_TOTAL.with_label_values(&[] as &[&str]).inc();

        let (mut epoch_cache, _rejected) =
            PtcEpochDutyCache::from_response(response.dependent_root.clone(), &response.data);
        epoch_cache.indices = validator_indices.to_vec();

        info!(epoch = epoch, count = response.data.len(), "Cached PTC duties for epoch");

        let mut cache = self.ptc_cache.write().await;
        cache.insert(epoch, epoch_cache);

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

    pub async fn get_ptc_duties_for_slot(&self, slot: u64) -> Vec<PtcDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.ptc_cache.read().await;
        match cache.get(&epoch).and_then(|c| c.get(&slot)) {
            Some(duties) => {
                debug!(slot, epoch, cache_type = "ptc", count = duties.len(), "Cache hit");
                duties.iter().map(|duty| duty.raw.clone()).collect()
            }
            None => {
                debug!(slot, epoch, cache_type = "ptc", "Cache miss");
                Vec::new()
            }
        }
    }

    pub async fn get_cached_ptc_dependent_root(&self, epoch: u64) -> Option<String> {
        let cache = self.ptc_cache.read().await;
        cache.get(&epoch).map(|c| c.dependent_root.clone())
    }

    #[tracing::instrument(name = "duty_tracker.check_ptc_reorg", level = "debug", skip_all, fields(epoch =epoch))]
    pub async fn check_and_refetch_ptc_if_root_changed(
        &self,
        epoch: u64,
    ) -> Result<bool, DutyTrackerError> {
        let indices = self.index_source.indices();
        let cached = {
            let cache = self.ptc_cache.read().await;
            cache.get(&epoch).map(|c| (c.dependent_root.clone(), c.indices.clone()))
        };

        let Some((cached_root, cached_indices)) = cached else {
            self.fetch_ptc_duties(epoch, &indices).await?;
            return Ok(true);
        };

        let response = self
            .beacon
            .post_ptc_duties(epoch, &indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        if cached_root == response.dependent_root && cached_indices == indices {
            return Ok(false);
        }

        let root_changed = cached_root != response.dependent_root;
        if root_changed {
            info!(
                epoch = epoch,
                old_root = %cached_root,
                new_root = %response.dependent_root,
                "PTC dependent root changed, refetching duties"
            );
        } else {
            debug!(epoch, "Index snapshot changed, replacing cached PTC duties");
        }

        let (mut epoch_cache, _rejected) =
            PtcEpochDutyCache::from_response(response.dependent_root.clone(), &response.data);
        epoch_cache.indices = indices;

        let mut cache = self.ptc_cache.write().await;
        cache.insert(epoch, epoch_cache);
        Ok(root_changed)
    }

    pub async fn is_ptc_epoch_cached(&self, epoch: u64) -> bool {
        let indices = self.index_source.indices();
        let cache = self.ptc_cache.read().await;
        cache.get(&epoch).is_some_and(|entry| entry.indices == indices)
    }

    #[tracing::instrument(name = "duty_tracker.fetch_sync_committee_duties", level = "debug", skip_all, fields(epoch =epoch, duty = %observability::logging::fields::Duty::SyncCommittee.as_str()))]
    pub async fn fetch_sync_committee_duties(
        &self,
        epoch: u64,
    ) -> Result<Vec<SyncCommitteeDuty>, DutyTrackerError> {
        let indices = self.index_source.indices();
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        debug!(epoch = epoch, period = period, "Fetching sync committee duties");

        let response = self
            .beacon
            .post_sync_committee_duties(epoch, &indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        info!(
            epoch = epoch,
            period = period,
            count = response.data.len(),
            "Cached sync committee duties for period"
        );

        let mut period_cache = SyncPeriodDutyCache::from_response(response.data.clone());
        period_cache.indices = indices;
        let mut cache = self.sync_committee_cache.write().await;
        cache.insert(period, period_cache);

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
        let cache = self.sync_committee_cache.read().await;
        match cache.get(&period) {
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
        let cache = self.sync_committee_cache.read().await;
        cache.get(&period).is_some_and(|entry| entry.indices == indices)
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
        let attester_count = self.cache.read().await.get(&epoch).map_or(0, |c| c.duties.len());
        let proposer_count =
            self.proposer_cache.read().await.get(&epoch).map_or(0, |c| c.duties.len());
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let sync_count =
            self.sync_committee_cache.read().await.get(&period).map_or(0, |c| c.duties.len());
        let ptc_count = self.ptc_cache.read().await.get(&epoch).map_or(0, |c| c.duty_count());
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
    assert_eq!(tracker.get_duties_for_slot(320).await[0].validator_index, "111");
    assert_eq!(tracker.get_ptc_duties_for_slot(320).await[0].validator_index, "111");
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
    assert_eq!(attester[0].validator_index, "222");
    let ptc = tracker.get_ptc_duties_for_slot(320).await;
    assert_eq!(ptc.len(), 1);
    assert_eq!(ptc[0].validator_index, "222");
    let sync = tracker.get_sync_committee_duties(320).await;
    assert_eq!(sync.len(), 1);
    assert_eq!(sync[0].validator_index, 222);
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use bn_manager::{
        AttesterDutiesResponse, AttesterDuty, BeaconError, BeaconNodeClient, MockBeaconNodeClient,
        ProposerDutiesResponse, ProposerDuty, PtcDutiesResponse, PtcDuty,
        SyncCommitteeDutiesResponse,
    };
    use eth_types::SyncCommitteeDuty;
    use tracing_subscriber::prelude::*;

    use super::*;

    fn empty_beacon() -> Arc<dyn BeaconNodeClient> {
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

    fn as_beacon(mock: MockBeaconNodeClient) -> Arc<dyn BeaconNodeClient> {
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
        assert_eq!(duty.slot, "320");
        assert_eq!(duty.committee_index, "1");
        assert_eq!(duty.validator_index, "1234");
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
        assert_eq!(duty1.validator_index, "1234");

        let duty2 = tracker.get_duty(321, 2, 5678).await.unwrap();
        assert_eq!(duty2.validator_index, "5678");

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
        assert_eq!(duty10.slot, "320");

        let duty11 = tracker.get_duty(352, 2, 1234).await.unwrap();
        assert_eq!(duty11.slot, "352");
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
        assert_eq!(duty.unwrap().validator_index, "1234");
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
        assert_eq!(tracker.get_proposer_duty(320).await.unwrap().validator_index, "1234");
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
        assert_eq!(duty.validator_index, "100");

        let duty = tracker.get_duty(320, 1, 200).await.unwrap();
        assert_eq!(duty.validator_index, "200");

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
