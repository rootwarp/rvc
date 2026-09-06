use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

use crate::metrics::{RVC_DUTIES_FETCHED_TOTAL, RVC_PTC_DUTIES_FETCHED_TOTAL};
use bn_manager::{AttesterDuty, BeaconNodeClient, ProposerDuty, PtcDuty};
use eth_types::{ForkSchedule, SyncCommitteeDuty, SLOTS_PER_EPOCH};

use crate::error::DutyTrackerError;

/// Epochs per sync committee period (256 epochs ~ 27 hours).
const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DutyCacheKey {
    pub slot: u64,
    pub committee_index: u64,
    pub validator_index: u64,
}

#[derive(Debug)]
struct EpochDutyCache {
    duties: HashMap<DutyCacheKey, AttesterDuty>,
    dependent_root: String,
}

impl EpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root }
    }

    /// Parse attester duties from a BN response into a keyed epoch cache.
    ///
    /// Duties with unparseable slot / committee_index / validator_index are
    /// skipped (with a warn log). Per-duty cache inserts are traced.
    fn from_response(dependent_root: String, duties: &[AttesterDuty], epoch: u64) -> Self {
        let mut epoch_cache = Self::new(dependent_root);
        for duty in duties {
            let slot: u64 = match duty.slot.parse() {
                Ok(s) => s,
                Err(_) => {
                    warn!(raw_slot = %duty.slot, "Skipping duty with unparseable slot");
                    continue;
                }
            };
            let committee_index: u64 = match duty.committee_index.parse() {
                Ok(c) => c,
                Err(_) => {
                    warn!(raw_committee_index = %duty.committee_index, "Skipping duty with unparseable committee_index");
                    continue;
                }
            };
            let validator_index: u64 = match duty.validator_index.parse() {
                Ok(v) => v,
                Err(_) => {
                    warn!(raw_validator_index = %duty.validator_index, "Skipping duty with unparseable validator_index");
                    continue;
                }
            };

            let key = DutyCacheKey { slot, committee_index, validator_index };
            trace!(slot, epoch, validator_index, committee_index, "cached attester duty");
            epoch_cache.insert(key, duty.clone());
        }
        epoch_cache
    }

    fn insert(&mut self, key: DutyCacheKey, duty: AttesterDuty) {
        self.duties.insert(key, duty);
    }

    fn get(&self, key: &DutyCacheKey) -> Option<&AttesterDuty> {
        self.duties.get(key)
    }
}

#[derive(Debug)]
struct ProposerEpochDutyCache {
    duties: HashMap<u64, ProposerDuty>,
    dependent_root: String,
}

impl ProposerEpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root }
    }

    /// Parse proposer duties from a BN response into a slot-keyed epoch cache.
    ///
    /// Duties with an unparseable slot are skipped (with a warn log).
    fn from_response(dependent_root: String, duties: &[ProposerDuty]) -> Self {
        let mut epoch_cache = Self::new(dependent_root);
        for duty in duties {
            let slot: u64 = match duty.slot.parse() {
                Ok(s) => s,
                Err(_) => {
                    warn!(raw_slot = %duty.slot, "Skipping proposer duty with unparseable slot");
                    continue;
                }
            };
            epoch_cache.insert(slot, duty.clone());
        }
        epoch_cache
    }

    fn insert(&mut self, slot: u64, duty: ProposerDuty) {
        self.duties.insert(slot, duty);
    }

    fn get(&self, slot: &u64) -> Option<&ProposerDuty> {
        self.duties.get(slot)
    }
}

/// PTC duties for one epoch, keyed by slot (multiple validators per slot).
#[derive(Debug)]
struct PtcEpochDutyCache {
    duties: HashMap<u64, Vec<PtcDuty>>,
    dependent_root: String,
}

impl PtcEpochDutyCache {
    fn new(dependent_root: String) -> Self {
        Self { duties: HashMap::new(), dependent_root }
    }

    /// Parse PTC duties from a BN response into a slot-keyed epoch cache.
    ///
    /// Duties with an unparseable slot are skipped (with a warn log).
    fn from_response(dependent_root: String, duties: &[PtcDuty]) -> Self {
        let mut epoch_cache = Self::new(dependent_root);
        for duty in duties {
            let slot: u64 = match duty.slot.parse() {
                Ok(s) => s,
                Err(_) => {
                    warn!(raw_slot = %duty.slot, "Skipping PTC duty with unparseable slot");
                    continue;
                }
            };
            epoch_cache.insert(slot, duty.clone());
        }
        epoch_cache
    }

    fn insert(&mut self, slot: u64, duty: PtcDuty) {
        self.duties.entry(slot).or_default().push(duty);
    }

    fn get(&self, slot: &u64) -> Option<&[PtcDuty]> {
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
}

impl SyncPeriodDutyCache {
    /// Construct a period cache from a BN sync-committee duties response body.
    fn from_response(duties: Vec<SyncCommitteeDuty>) -> Self {
        Self { duties }
    }
}

pub struct DutyTracker {
    beacon: Arc<dyn BeaconNodeClient>,
    validator_indices: Vec<String>,
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
    pub fn new(beacon: Arc<dyn BeaconNodeClient>, validator_indices: Vec<String>) -> Self {
        Self {
            beacon,
            validator_indices,
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

    #[tracing::instrument(name = "duty_tracker.fetch_attester_duties", level = "debug", skip_all, fields(epoch =epoch))]
    pub async fn fetch_duties_for_epoch(
        &self,
        epoch: u64,
    ) -> Result<Vec<AttesterDuty>, DutyTrackerError> {
        debug!(epoch = epoch, "Fetching duties for epoch");

        let response = self
            .beacon
            .get_attester_duties(epoch, &self.validator_indices)
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

        let epoch_cache =
            EpochDutyCache::from_response(response.dependent_root.clone(), &response.data, epoch);

        info!(
            epoch = epoch,
            duties_count = response.data.len(),
            dependent_root = %response.dependent_root,
            "Cached duties for epoch"
        );

        cache.insert(epoch, epoch_cache);

        Ok(response.data)
    }

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
                return Ok(duty.clone());
            }
        }

        debug!(slot, epoch, cache_type = "attester", "Cache miss");
        Err(DutyTrackerError::DutyNotFound { slot, committee_index, validator_index })
    }

    #[tracing::instrument(name = "duty_tracker.check_attester_reorg", level = "debug", skip_all, fields(epoch =epoch))]
    pub async fn check_and_refetch_if_root_changed(
        &self,
        epoch: u64,
    ) -> Result<bool, DutyTrackerError> {
        // Fetch from BN first (no lock held) to avoid TOCTOU race
        let response = self
            .beacon
            .get_attester_duties(epoch, &self.validator_indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        // Acquire write lock and compare-and-swap atomically
        let mut cache = self.cache.write().await;
        let cached_root = cache.get(&epoch).map(|c| c.dependent_root.clone());

        if cached_root.as_ref() == Some(&response.dependent_root) {
            return Ok(false);
        }

        info!(
            epoch = epoch,
            old_root = ?cached_root,
            new_root = %response.dependent_root,
            "Dependent root changed, refetching duties"
        );

        let epoch_cache =
            EpochDutyCache::from_response(response.dependent_root.clone(), &response.data, epoch);

        cache.insert(epoch, epoch_cache);
        Ok(true)
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
        let cache = self.cache.read().await;
        cache.contains_key(&epoch)
    }

    pub async fn get_cached_dependent_root(&self, epoch: u64) -> Option<String> {
        let cache = self.cache.read().await;
        cache.get(&epoch).map(|c| c.dependent_root.clone())
    }

    #[tracing::instrument(name = "duty_tracker.fetch_proposer_duties", level = "debug", skip_all, fields(epoch =epoch))]
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

        let epoch_cache =
            ProposerEpochDutyCache::from_response(response.dependent_root.clone(), &response.data);

        info!(epoch = epoch, count = response.data.len(), "Cached proposer duties for epoch");

        let mut cache = self.proposer_cache.write().await;
        cache.insert(epoch, epoch_cache);

        Ok(response.data)
    }

    pub async fn get_proposer_duty(&self, slot: u64) -> Option<ProposerDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.proposer_cache.read().await;
        let result = cache.get(&epoch).and_then(|c| c.get(&slot)).cloned();
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

    #[tracing::instrument(name = "duty_tracker.check_proposer_reorg", level = "debug", skip_all, fields(epoch =epoch))]
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

            let epoch_cache = ProposerEpochDutyCache::from_response(
                response.dependent_root.clone(),
                &response.data,
            );

            let mut cache = self.proposer_cache.write().await;
            cache.insert(epoch, epoch_cache);
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

        let epoch_cache =
            PtcEpochDutyCache::from_response(response.dependent_root.clone(), &response.data);

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
        self.fetch_ptc_duties(epoch, &self.validator_indices).await
    }

    pub async fn get_ptc_duties_for_slot(&self, slot: u64) -> Vec<PtcDuty> {
        let epoch = slot / SLOTS_PER_EPOCH;
        let cache = self.ptc_cache.read().await;
        match cache.get(&epoch).and_then(|c| c.get(&slot)) {
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
        let cache = self.ptc_cache.read().await;
        cache.get(&epoch).map(|c| c.dependent_root.clone())
    }

    #[tracing::instrument(name = "duty_tracker.check_ptc_reorg", level = "debug", skip_all, fields(epoch =epoch))]
    pub async fn check_and_refetch_ptc_if_root_changed(
        &self,
        epoch: u64,
    ) -> Result<bool, DutyTrackerError> {
        let cached_root = {
            let cache = self.ptc_cache.read().await;
            cache.get(&epoch).map(|c| c.dependent_root.clone())
        };

        if cached_root.is_none() {
            self.fetch_ptc_duties(epoch, &self.validator_indices).await?;
            return Ok(true);
        }

        let response = self
            .beacon
            .post_ptc_duties(epoch, &self.validator_indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        if cached_root.as_ref() != Some(&response.dependent_root) {
            info!(
                epoch = epoch,
                old_root = ?cached_root,
                new_root = %response.dependent_root,
                "PTC dependent root changed, refetching duties"
            );

            let epoch_cache =
                PtcEpochDutyCache::from_response(response.dependent_root.clone(), &response.data);

            let mut cache = self.ptc_cache.write().await;
            cache.insert(epoch, epoch_cache);
            return Ok(true);
        }

        Ok(false)
    }

    pub async fn is_ptc_epoch_cached(&self, epoch: u64) -> bool {
        let cache = self.ptc_cache.read().await;
        cache.contains_key(&epoch)
    }

    #[tracing::instrument(name = "duty_tracker.fetch_sync_committee_duties", level = "debug", skip_all, fields(epoch =epoch))]
    pub async fn fetch_sync_committee_duties(
        &self,
        epoch: u64,
    ) -> Result<Vec<SyncCommitteeDuty>, DutyTrackerError> {
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        debug!(epoch = epoch, period = period, "Fetching sync committee duties");

        let response = self
            .beacon
            .post_sync_committee_duties(epoch, &self.validator_indices)
            .await
            .map_err(DutyTrackerError::BeaconError)?;

        info!(
            epoch = epoch,
            period = period,
            count = response.data.len(),
            "Cached sync committee duties for period"
        );

        let period_cache = SyncPeriodDutyCache::from_response(response.data.clone());
        let mut cache = self.sync_committee_cache.write().await;
        cache.insert(period, period_cache);

        Ok(response.data)
    }

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
        let period = epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
        let cache = self.sync_committee_cache.read().await;
        cache.contains_key(&period)
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
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use bn_manager::{
        AttesterDutiesResponse, AttesterDuty, BeaconError, BeaconNodeClient, MockBeaconNodeClient,
        ProposerDutiesResponse, ProposerDuty, PtcDutiesResponse, PtcDuty,
        SyncCommitteeDutiesResponse,
    };
    use eth_types::SyncCommitteeDuty;

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

        let attester_cache = EpochDutyCache::from_response("0xroot".into(), &attester_duties, 10);
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
        let proposer_cache =
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
        let ptc_cache = PtcEpochDutyCache::from_response("0xtroot".into(), &ptc_duties);
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
}
