use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconClient, BeaconCommitteeSubscription,
    BeaconError, BlockRootResponse, ConfigSpecResponse, GenesisResponse, ProduceBlockResponse,
    ProposerDutiesResponse, ProposerPreparation, SignedContributionAndProof, StateForkResponse,
    SubmitAttestationResult, SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse,
    SyncCommitteeMessage, SyncingResponse, ValidatorLiveness, ValidatorLivenessResponse,
    ValidatorsResponse, VersionedAggregateAttestation, VersionedAttestation,
    VersionedSignedAggregateAndProof,
};
use eth_types::{
    ForkSchedule, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedValidatorRegistration,
};
use futures::future::join_all;
use tracing::Instrument;
use tracing::{debug, error, trace, warn};
use url::Url;

use observability::logging::RedactedUrl;

use crate::sync_status::BnSyncStatus;

use crate::broadcast::{BnOutcome, BroadcastResult};
use crate::health::{new_shared_health_trackers, SharedHealthTrackers};
use crate::sse::{self, SseConfig, SseEvent};
use crate::sync_status::{
    check_all_sync_statuses, new_shared_sync_statuses, start_sync_monitor, SharedSyncStatuses,
};
use crate::traits::{
    AttestationApi, BeaconNodeClient, BlockProducer, BnHealthScore, BnManagerConfig,
    DutiesProvider, LivenessApi, NodeStatusApi, OperationTimeouts, SyncCommitteeApi,
};
use crate::types::{BnRole, HealthTier, TierThresholds};
use crate::BnManagerError;

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, BeaconError>> + Send + 'a>>;
type IndexedTimedResultFut<'a, T> =
    Pin<Box<dyn Future<Output = (usize, String, Result<T, BeaconError>, Duration)> + Send + 'a>>;

/// Health-tracker outcome for one BN attempt (success with latency, or error).
#[derive(Debug, Clone, Copy)]
enum TrackerOutcome {
    Success(Duration),
    Error,
}

/// Default sync check interval: once per epoch (~384 seconds).
const DEFAULT_SYNC_CHECK_INTERVAL: Duration = Duration::from_secs(384);

/// Beacon node manager with multi-BN support, failover, and broadcast.
///
/// # Per-operation selection policy
///
/// Selection is hard-coded per endpoint method (not a config knob):
/// - **Query-first**: try healthy BNs in health-score order, fail over on error —
///   duty fetches, attestation/aggregate data, genesis/config, sync status reads.
/// - **Best-of**: query healthy BNs in parallel and pick the highest-value result —
///   block production (`produce_block_v3`).
/// - **Broadcast**: send to **role-matching** BNs (subject to `BroadcastTopics`),
///   succeed if any succeeds — attestations, blocks, sync committee messages,
///   subscriptions, preparations, validator registrations. Role filter only;
///   health **tier is not applied** and unhealthy role-matching peers are not
///   dropped (a lagging / previously-erroring BN still gossips). `All`-role
///   fallback is shared with the query path. An empty role+All selection is
///   `BeaconError::NoEligibleBn` — never off-role fan-out, never Ok.
///
/// # Retries under multi-BN failover
///
/// Every underlying `BeaconClient` is constructed with **`max_retries = 0`**.
/// Transient failures are handled by this manager (try the next healthy BN /
/// broadcast to peers), not by per-client HTTP retries. Stacking both would
/// multiply tail latency on a dead primary. Single-client tooling that bypasses
/// `BnManager` (e.g. voluntary-exit helpers via `ServiceBuilder::build_beacon`)
/// may set a non-zero retry budget; that is the only intentional exception.
/// Other call sites that need the same policy should link here rather than
/// restate it.
///
/// Tracks per-BN sync status and skips unsynced BNs for query operations.
/// In single-BN mode, logs warnings but continues with the only available BN.
pub struct BnManager {
    clients: Vec<BeaconClient>,
    sync_statuses: SharedSyncStatuses,
    health_trackers: SharedHealthTrackers,
    operation_timeouts: Option<OperationTimeouts>,
    broadcast_topics: crate::traits::BroadcastTopics,
    roles: Vec<HashSet<BnRole>>,
    tier_thresholds: TierThresholds,
}

impl BnManager {
    /// Creates a new `BnManager` from the given configuration.
    ///
    /// Validates that the endpoints list is non-empty and that all endpoints
    /// have valid URL schemes (http:// or https://). Creates a `BeaconClient`
    /// for each endpoint with the configured per-BN timeout.
    pub fn new(config: BnManagerConfig) -> Result<Self, BnManagerError> {
        if config.endpoints.is_empty() {
            return Err(BnManagerError::NoEndpoints);
        }

        let mut clients = Vec::with_capacity(config.endpoints.len());

        for endpoint in &config.endpoints {
            let parsed = Url::parse(endpoint).map_err(|e| {
                BnManagerError::InvalidEndpoint(format!("failed to parse URL: {e}"))
            })?;

            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err(BnManagerError::InvalidEndpoint(format!(
                    "endpoint must use http or https scheme: {endpoint}"
                )));
            }

            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(BnManagerError::InvalidEndpoint(
                    "endpoint must not contain credentials".to_string(),
                ));
            }

            if parsed.host_str().is_none() || parsed.host_str() == Some("") {
                return Err(BnManagerError::InvalidEndpoint(
                    "endpoint must contain a host".to_string(),
                ));
            }

            // max_retries=0: failover lives in BnManager, not per-client HTTP
            // retries. See type-level docs on [`BnManager`].
            let client_config = beacon::BeaconClientConfig::new(endpoint.clone())
                .with_timeout(config.timeout)
                .with_max_retries(0)
                .with_max_body_bytes(config.max_body_bytes);
            let client = BeaconClient::new(client_config)?;
            clients.push(client);
        }

        let broadcast_topics = config.broadcast_topics.clone();
        let roles = if config.roles.len() == clients.len() {
            config.roles.clone()
        } else {
            vec![
                {
                    let mut s = HashSet::new();
                    s.insert(BnRole::All);
                    s
                };
                clients.len()
            ]
        };
        let tier_thresholds = config.tier_thresholds.clone();
        let sync_statuses = new_shared_sync_statuses(clients.len());
        let endpoints: Vec<String> = clients.iter().map(|c| c.endpoint().to_string()).collect();
        let health_trackers = new_shared_health_trackers(&endpoints);
        Ok(Self {
            clients,
            sync_statuses,
            health_trackers,
            operation_timeouts: None,
            broadcast_topics,
            roles,
            tier_thresholds,
        })
    }

    /// Returns the shared sync status tracker.
    pub fn sync_statuses(&self) -> &SharedSyncStatuses {
        &self.sync_statuses
    }

    /// Returns the shared health trackers.
    pub fn health_trackers(&self) -> &SharedHealthTrackers {
        &self.health_trackers
    }

    /// Sets per-operation timeouts for BN API calls.
    ///
    /// When set, each BN operation is wrapped in `tokio::time::timeout` using the
    /// corresponding field from `OperationTimeouts`. If an operation exceeds its
    /// timeout, `BeaconError::OperationTimeout` is returned.
    pub fn with_operation_timeouts(mut self, timeouts: OperationTimeouts) -> Self {
        self.operation_timeouts = Some(timeouts);
        self
    }

    /// Wraps a future with an optional per-operation timeout.
    async fn with_op_timeout<T>(
        &self,
        op_name: &str,
        timeout: Option<Duration>,
        fut: impl Future<Output = Result<T, BeaconError>>,
    ) -> Result<T, BeaconError> {
        match timeout {
            Some(d) => tokio::time::timeout(d, fut).await.map_err(|_| {
                warn!(op = op_name, timeout_ms = d.as_millis() as u64, "operation timed out");
                BeaconError::OperationTimeout { operation: op_name.to_string(), timeout: d }
            })?,
            None => fut.await,
        }
    }

    /// Returns the per-operation timeout for a given field selector.
    fn op_timeout(&self, f: impl FnOnce(&OperationTimeouts) -> Duration) -> Option<Duration> {
        self.operation_timeouts.as_ref().map(f)
    }

    /// Apply health-tracker updates under a single write lock.
    ///
    /// Selection strategies collect outcomes during the round and call this once
    /// so the health write lock is taken at most once per selection round.
    async fn record_outcomes(&self, outcomes: &[(usize, TrackerOutcome)]) {
        if outcomes.is_empty() {
            return;
        }
        let mut trackers = self.health_trackers.write().await;
        for &(idx, outcome) in outcomes {
            match outcome {
                TrackerOutcome::Success(latency) => trackers[idx].record_success(latency),
                TrackerOutcome::Error => trackers[idx].record_error(),
            }
        }
    }

    /// Dispatch a submission via broadcast or query_first based on the topic flag.
    ///
    /// Encapsulates the repeated `if broadcast_topics.X { broadcast } else { query_first }`
    /// branch and wraps it in the per-operation timeout.
    async fn submit<'s, T, F>(
        &'s self,
        op_name: &str,
        topic_enabled: bool,
        role: BnRole,
        min_tier: HealthTier,
        timeout: Option<Duration>,
        op: F,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        if topic_enabled {
            self.with_op_timeout(op_name, timeout, self.broadcast_with_result(op_name, role, op))
                .await
        } else {
            self.with_op_timeout(op_name, timeout, self.query_first(op_name, role, min_tier, op))
                .await
        }
    }

    /// Returns current health scores for all BNs.
    #[tracing::instrument(name = "bn_manager.health_scores", skip_all)]
    pub async fn health_scores(&self) -> Vec<BnHealthScore> {
        let health_guard = self.health_trackers.read().await;
        let sync_guard = self.sync_statuses.read().await;
        health_guard
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let detail = sync_guard
                    .get(i)
                    .cloned()
                    .unwrap_or_else(crate::sync_status::BnSyncDetail::unknown);
                BnHealthScore {
                    endpoint: t.endpoint().to_string(),
                    is_reachable: !matches!(detail.status, BnSyncStatus::Unreachable),
                    is_synced: matches!(detail.status, BnSyncStatus::Synced),
                    is_el_offline: matches!(detail.status, BnSyncStatus::ElOffline),
                    head_slot: detail.head_slot,
                    latency: t.latency_ema_ms().map(|ms| Duration::from_secs_f64(ms / 1000.0)),
                    latency_ms: t.latency_ema_ms().unwrap_or(0.0),
                    error_rate: t.error_rate(),
                    score: t.score(),
                }
            })
            .collect()
    }

    /// Checks sync status of all configured BNs immediately.
    #[tracing::instrument(name = "bn_manager.check_sync_status", skip_all)]
    pub async fn check_sync_status(&self) {
        check_all_sync_statuses(&self.clients, &self.sync_statuses).await;
    }

    /// Starts a background task that periodically polls sync status.
    ///
    /// Uses the default interval of one epoch (~384 seconds) if `interval` is None.
    pub fn start_sync_monitor(
        &self,
        interval: Option<Duration>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let interval = interval.unwrap_or(DEFAULT_SYNC_CHECK_INTERVAL);
        start_sync_monitor(self.clients.clone(), self.sync_statuses.clone(), interval, shutdown)
    }

    /// Returns the endpoint URL of the first (primary) client.
    #[cfg(test)]
    fn primary_endpoint(&self) -> &str {
        self.clients[0].endpoint()
    }

    /// Starts SSE event subscription on the primary beacon node.
    ///
    /// The returned `JoinHandle` runs the SSE loop in a background task.
    /// Send `true` on `shutdown` to stop the subscription.
    pub fn start_sse<F>(
        &self,
        callback: F,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()>
    where
        F: Fn(SseEvent) + Send + Sync + 'static,
    {
        let configs: Vec<SseConfig> =
            self.clients.iter().map(|c| SseConfig::new(c.endpoint().to_string())).collect();
        tokio::spawn(async move {
            sse::subscribe_events(configs, callback, shutdown).await;
        })
    }

    /// Role match, then `All`-role fallback. Does **not** fall back to every client.
    /// Shared by query (`synced_indices`) and broadcast so All-fallback is one path.
    fn role_matching_indices(&self, role: BnRole) -> Vec<usize> {
        let matched: Vec<usize> =
            (0..self.clients.len()).filter(|&i| BnRole::matches(&self.roles[i], role)).collect();
        if !matched.is_empty() {
            return matched;
        }
        warn!(
            role = %role,
            "no BNs assigned for role, falling back to all-role BNs"
        );
        (0..self.clients.len()).filter(|&i| self.roles[i].contains(&BnRole::All)).collect()
    }

    /// Returns indices of BNs matching the given role and meeting the minimum health tier,
    /// ordered by health score (highest first).
    ///
    /// Filtering order: role → tier → health score.
    ///
    /// Fallback chain:
    /// 1. If no BNs match the role, fall back to `All`-role BNs with WARN
    /// 2. If no BNs meet the tier, try the next lower tier with WARN
    /// 3. If still empty, fall back to all BNs (query path only)
    #[tracing::instrument(name = "bn_manager.synced_indices", skip_all, fields(role = %role, min_tier = %min_tier))]
    async fn synced_indices(&self, role: BnRole, min_tier: HealthTier) -> Vec<usize> {
        let sync_guard = self.sync_statuses.read().await;
        let health_guard = self.health_trackers.read().await;

        let healthy_count = health_guard.iter().filter(|t| t.is_healthy()).count();
        debug!(bn_count = self.clients.len(), healthy_count = healthy_count, "Health check cycle");

        let role_indices = self.role_matching_indices(role);

        // If still empty after role fallback, use all BNs
        let role_indices = if role_indices.is_empty() {
            warn!("no BNs with All role either, falling back to all BNs");
            (0..self.clients.len()).collect()
        } else {
            role_indices
        };

        // Step 2: Filter by tier
        let mut tier_filtered: Vec<usize> = role_indices
            .iter()
            .copied()
            .filter(|&i| sync_guard[i].tier(&self.tier_thresholds) <= min_tier)
            .collect();

        // Tier fallback: progressively relax tier requirement
        if tier_filtered.is_empty() {
            let fallback_tiers = match min_tier {
                HealthTier::Synced => {
                    vec![HealthTier::SmallLag, HealthTier::LargeLag, HealthTier::Unsynced]
                }
                HealthTier::SmallLag => vec![HealthTier::LargeLag, HealthTier::Unsynced],
                HealthTier::LargeLag => vec![HealthTier::Unsynced],
                HealthTier::Unsynced => vec![],
            };

            for fallback_tier in fallback_tiers {
                tier_filtered = role_indices
                    .iter()
                    .copied()
                    .filter(|&i| sync_guard[i].tier(&self.tier_thresholds) <= fallback_tier)
                    .collect();
                if !tier_filtered.is_empty() {
                    warn!(
                        requested_tier = %min_tier,
                        actual_tier = %fallback_tier,
                        "no BNs at requested tier, falling back to lower tier"
                    );
                    break;
                }
            }
        }

        // Last resort: use all role-matching BNs regardless of tier
        if tier_filtered.is_empty() {
            if self.clients.len() == 1 {
                warn!(
                    endpoint = %RedactedUrl(self.clients[0].endpoint()),
                    "single BN is not synced, continuing with degraded service"
                );
            } else {
                warn!("no BNs meet tier requirements, falling back to all role-matching BNs");
            }
            tier_filtered = role_indices;
        }

        // Step 3: Filter out unhealthy BNs (unless it would leave none)
        let healthy: Vec<usize> =
            tier_filtered.iter().copied().filter(|&i| health_guard[i].is_healthy()).collect();

        let mut result = if healthy.is_empty() {
            error!(
                bn_count = tier_filtered.len(),
                "All BNs unhealthy, using all tier-matching BNs"
            );
            tier_filtered
        } else {
            healthy
        };

        // Sort by health score descending (highest score first)
        result.sort_by(|&a, &b| {
            health_guard[b]
                .score()
                .partial_cmp(&health_guard[a].score())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        result
    }

    /// Query using the `First` strategy: try synced BNs in order, fail over on error.
    async fn query_first<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        op: F,
    ) -> Result<T, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let strategy_span = tracing::info_span!(
            "bn.strategy.first",
            strategy = "first",
            tried = tracing::field::Empty,
        );
        self.query_first_inner(op_name, role, min_tier, &op).instrument(strategy_span).await
    }

    async fn query_first_inner<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        op: &F,
    ) -> Result<T, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let indices = self.synced_indices(role, min_tier).await;
        let mut last_err = None;
        let mut tried: usize = 0;
        let mut failed_indices: Vec<usize> = Vec::new();

        for (pos, i) in indices.iter().copied().enumerate() {
            let client = &self.clients[i];
            tried += 1;
            let attempt_span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl(client.endpoint()),
            );
            let start = tokio::time::Instant::now();
            match op(client).instrument(attempt_span).await {
                Ok(result) => {
                    let elapsed = start.elapsed();
                    // Batch update: record success + all prior errors in one lock acquisition
                    let mut outcomes: Vec<(usize, TrackerOutcome)> =
                        failed_indices.iter().map(|&fi| (fi, TrackerOutcome::Error)).collect();
                    outcomes.push((i, TrackerOutcome::Success(elapsed)));
                    self.record_outcomes(&outcomes).await;
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        latency_ms = elapsed.as_millis() as u64,
                        "query succeeded"
                    );
                    tracing::Span::current().record("tried", tried);
                    return Ok(result);
                }
                Err(e) => {
                    failed_indices.push(i);
                    if let Some(&next_i) = indices.get(pos + 1) {
                        let next_client = &self.clients[next_i];
                        warn!(
                            failed_bn = %RedactedUrl(client.endpoint()),
                            selected_bn = %RedactedUrl(next_client.endpoint()),
                            reason = %e,
                            "BN failover triggered"
                        );
                    } else {
                        warn!(
                            op = op_name,
                            bn_index = i,
                            endpoint = %RedactedUrl(client.endpoint()),
                            error = %e,
                            "BN query failed, no more BNs to try"
                        );
                    }
                    last_err = Some(e);
                }
            }
        }

        // All failed — batch record errors
        let outcomes: Vec<(usize, TrackerOutcome)> =
            failed_indices.iter().map(|&fi| (fi, TrackerOutcome::Error)).collect();
        self.record_outcomes(&outcomes).await;

        tracing::Span::current().record("tried", tried);
        Err(last_err.expect("at least one client exists"))
    }

    /// Query using the `Best` strategy: query synced BNs in parallel, pick best result.
    ///
    /// The `pick_best` function returns `true` if the first argument is better than the second.
    /// Falls back to `First` strategy if only one synced BN is available.
    /// When all synced BNs fail, falls back to trying unsynced BNs sequentially.
    async fn query_best<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        op: F,
        pick_best: fn(&T, &T) -> bool,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let strategy_span = tracing::info_span!(
            "bn.strategy.best",
            strategy = "best",
            tried = tracing::field::Empty,
        );
        self.query_best_inner(op_name, role, min_tier, &op, pick_best)
            .instrument(strategy_span)
            .await
    }

    async fn query_best_inner<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        op: &F,
        pick_best: fn(&T, &T) -> bool,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let indices = self.synced_indices(role, min_tier).await;
        tracing::Span::current().record("tried", indices.len());

        if indices.len() == 1 {
            let client = &self.clients[indices[0]];
            let i = indices[0];
            let attempt_span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl(client.endpoint()),
            );
            let start = tokio::time::Instant::now();
            match op(client).instrument(attempt_span).await {
                Ok(result) => {
                    self.record_outcomes(&[(i, TrackerOutcome::Success(start.elapsed()))]).await;
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        "query succeeded (single synced BN)"
                    );
                    return Ok(result);
                }
                Err(e) => {
                    self.record_outcomes(&[(i, TrackerOutcome::Error)]).await;
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        error = %e,
                        "BN query failed, trying unsynced BNs"
                    );
                    return self.fallback_unsynced(op_name, &op, &indices).await.ok_or(e);
                }
            }
        }

        let mut futs: Vec<IndexedTimedResultFut<'_, T>> = Vec::with_capacity(indices.len());

        for i in &indices {
            let client = &self.clients[*i];
            let endpoint = client.endpoint().to_string();
            let idx = *i;
            let fut = op(client);
            let attempt_span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl(client.endpoint()),
            );
            futs.push(Box::pin(
                async move {
                    let start = tokio::time::Instant::now();
                    let result = fut.await;
                    let elapsed = start.elapsed();
                    (idx, endpoint, result, elapsed)
                }
                .instrument(attempt_span),
            ));
        }

        let results = join_all(futs).await;

        let mut best: Option<(usize, T)> = None;
        let mut outcomes: Vec<(usize, TrackerOutcome)> = Vec::with_capacity(results.len());

        for (i, endpoint, result, elapsed) in results {
            match result {
                Ok(value) => {
                    outcomes.push((i, TrackerOutcome::Success(elapsed)));
                    best = Some(match best {
                        None => (i, value),
                        Some((prev_i, prev_value)) => {
                            if pick_best(&value, &prev_value) {
                                (i, value)
                            } else {
                                (prev_i, prev_value)
                            }
                        }
                    });
                }
                Err(e) => {
                    outcomes.push((i, TrackerOutcome::Error));
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(&endpoint),
                        error = %e,
                        "BN query failed in best-selection"
                    );
                }
            }
        }

        self.record_outcomes(&outcomes).await;

        match best {
            Some((i, value)) => {
                debug!(
                    op = op_name,
                    bn_index = i,
                    endpoint = %RedactedUrl(self.clients[i].endpoint()),
                    "best-selection picked BN"
                );
                Ok(value)
            }
            None => {
                if let Some(result) = self.fallback_unsynced(op_name, &op, &indices).await {
                    return Ok(result);
                }
                Err(BeaconError::HttpError(format!("{op_name}: all BNs failed in best-selection")))
            }
        }
    }

    /// Tries unsynced BNs sequentially as a fallback when all synced BNs have failed.
    async fn fallback_unsynced<'s, T, F>(
        &'s self,
        op_name: &str,
        op: &F,
        tried_indices: &[usize],
    ) -> Option<T>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let unsynced: Vec<usize> =
            (0..self.clients.len()).filter(|i| !tried_indices.contains(i)).collect();

        if unsynced.is_empty() {
            return None;
        }

        warn!(op = op_name, "all synced BNs failed, falling back to unsynced BNs");

        let mut outcomes: Vec<(usize, TrackerOutcome)> = Vec::new();
        for i in unsynced {
            let client = &self.clients[i];
            let start = tokio::time::Instant::now();
            match op(client).await {
                Ok(result) => {
                    let elapsed = start.elapsed();
                    outcomes.push((i, TrackerOutcome::Success(elapsed)));
                    self.record_outcomes(&outcomes).await;
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        latency_ms = elapsed.as_millis() as u64,
                        "query succeeded on unsynced BN (degraded)"
                    );
                    return Some(result);
                }
                Err(e) => {
                    outcomes.push((i, TrackerOutcome::Error));
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        error = %e,
                        "unsynced BN fallback also failed"
                    );
                }
            }
        }

        self.record_outcomes(&outcomes).await;
        None
    }

    /// Broadcast an operation to role-matching BNs (**regardless of sync / health
    /// tier / health-score**). Returns first success. If all fail, returns the last
    /// error. If no BN matches the role and no `All`-role BN exists, returns
    /// [`BeaconError::NoEligibleBn`] without publishing (fail-closed).
    ///
    /// Role: yes. Tier: no. Health-score prune: no. Selection is
    /// [`Self::role_matching_indices`] so All-fallback is shared with the query
    /// path but the query last-resort (every client) and the health-score cut
    /// are not. `tried` is the filtered count.
    async fn broadcast<'s, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        op: F,
    ) -> Result<(), BeaconError>
    where
        F: Fn(&'s BeaconClient) -> BoxFut<'s, ()>,
    {
        let strategy_span = tracing::info_span!(
            "bn.strategy.broadcast",
            strategy = "broadcast",
            tried = tracing::field::Empty,
        );
        async {
            let broadcast = self.broadcast_inner(op_name, role, &op).await;
            Self::log_partial_failure(op_name, &broadcast);
            if broadcast.outcomes.is_empty() {
                return Err(BeaconError::NoEligibleBn {
                    operation: op_name.to_string(),
                    role: role.to_string(),
                });
            }
            broadcast.into_result()
        }
        .instrument(strategy_span)
        .await
    }

    async fn broadcast_inner<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        op: &F,
    ) -> BroadcastResult<T>
    where
        T: Send + 'static,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let indices = self.role_matching_indices(role);
        if indices.is_empty() {
            warn!(
                op = op_name,
                role = %role,
                "no BNs eligible for broadcast; not publishing to off-role clients"
            );
        }
        tracing::Span::current().record("tried", indices.len());

        let mut futs: Vec<IndexedTimedResultFut<'_, T>> = Vec::with_capacity(indices.len());

        for i in indices {
            let client = &self.clients[i];
            let endpoint = client.endpoint().to_string();
            let fut = op(client);
            let attempt_span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl(client.endpoint()),
            );
            futs.push(Box::pin(
                async move {
                    let start = tokio::time::Instant::now();
                    let result = fut.await;
                    let elapsed = start.elapsed();
                    (i, endpoint, result, elapsed)
                }
                .instrument(attempt_span),
            ));
        }

        let results = join_all(futs).await;

        let mut health_outcomes = Vec::with_capacity(results.len());
        let mut outcomes = Vec::with_capacity(results.len());
        for (i, endpoint, result, elapsed) in results {
            match &result {
                Ok(_) => {
                    health_outcomes.push((i, TrackerOutcome::Success(elapsed)));
                    // Per-BN broadcast success scales with node count, so it
                    // is `trace` (the per-item loop rule), not `debug`.
                    trace!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(&endpoint),
                        "broadcast succeeded on BN"
                    );
                }
                Err(e) => {
                    health_outcomes.push((i, TrackerOutcome::Error));
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(&endpoint),
                        error = %e,
                        "broadcast failed on BN"
                    );
                }
            }
            outcomes.push(BnOutcome { endpoint, result, latency: elapsed });
        }
        self.record_outcomes(&health_outcomes).await;

        BroadcastResult { outcomes }
    }

    fn log_partial_failure<T>(op_name: &str, broadcast: &BroadcastResult<T>) {
        if broadcast.any_success() && !broadcast.all_success() {
            let (ok, fail) = broadcast.counts();
            // Redact each endpoint — a raw `Vec<&str>` Debug-printed here would
            // leak `user:pass@` credentials from the configured BN URLs.
            let failed_endpoints: Vec<String> =
                broadcast.failures().into_iter().map(|(e, _)| RedactedUrl(e).to_string()).collect();
            let failed_latency_ms: Vec<u64> = broadcast
                .outcomes
                .iter()
                .filter(|o| o.result.is_err())
                .map(|o| o.latency.as_millis() as u64)
                .collect();
            warn!(
                op = op_name,
                successes = ok,
                failures = fail,
                failed_endpoints = ?failed_endpoints,
                failed_latency_ms = ?failed_latency_ms,
                "partial broadcast failure"
            );
        }
    }

    /// Broadcast an operation that returns a non-unit result.
    /// Returns first success. If all fail, returns the last error.
    async fn broadcast_with_result<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        op: F,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let strategy_span = tracing::info_span!(
            "bn.strategy.broadcast",
            strategy = "broadcast",
            tried = tracing::field::Empty,
        );
        async {
            let broadcast = self.broadcast_inner(op_name, role, &op).await;
            Self::log_partial_failure(op_name, &broadcast);
            if broadcast.outcomes.is_empty() {
                return Err(BeaconError::NoEligibleBn {
                    operation: op_name.to_string(),
                    role: role.to_string(),
                });
            }
            broadcast.into_result()
        }
        .instrument(strategy_span)
        .await
    }
}

/// Compares two `ProduceBlockResponse` values by execution payload value.
/// Returns `true` if `a` is better than `b`.
fn is_better_block(a: &ProduceBlockResponse, b: &ProduceBlockResponse) -> bool {
    let val_a =
        a.execution_payload_value.as_deref().and_then(|v| v.parse::<u128>().ok()).unwrap_or(0);
    let val_b =
        b.execution_payload_value.as_deref().and_then(|v| v.parse::<u128>().ok()).unwrap_or(0);
    val_a > val_b
}

/// OR-merge `is_live` per validator index across broadcast outcomes.
///
/// Fail-safe: any BN reporting live wins. Errors contribute nothing. All-fail
/// returns `Err` so the observation loop stays fail-closed.
fn merge_liveness_broadcast(
    broadcast: BroadcastResult<ValidatorLivenessResponse>,
) -> Result<ValidatorLivenessResponse, BeaconError> {
    if !broadcast.any_success() {
        return broadcast.into_result();
    }

    let mut live_by_index: HashMap<String, bool> = HashMap::new();
    let mut order: Vec<String> = Vec::new();
    for outcome in broadcast.outcomes {
        let Ok(resp) = outcome.result else {
            continue;
        };
        for entry in resp.data {
            match live_by_index.get_mut(&entry.index) {
                Some(live) => *live |= entry.is_live,
                None => {
                    live_by_index.insert(entry.index.clone(), entry.is_live);
                    order.push(entry.index);
                }
            }
        }
    }

    Ok(ValidatorLivenessResponse {
        data: order
            .into_iter()
            .filter_map(|index| {
                live_by_index.remove(&index).map(|is_live| ValidatorLiveness { index, is_live })
            })
            .collect(),
    })
}

#[async_trait]
impl NodeStatusApi for BnManager {
    // -- State / Config: query(First), any role, accept SmallLag --

    async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
        self.query_first("get_genesis", BnRole::All, HealthTier::SmallLag, |c| {
            Box::pin(c.get_genesis())
        })
        .await
    }

    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        self.query_first("get_config_spec", BnRole::All, HealthTier::SmallLag, |c| {
            Box::pin(c.get_config_spec())
        })
        .await
    }

    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        self.query_first("get_fork_schedule", BnRole::All, HealthTier::SmallLag, |c| {
            Box::pin(c.get_fork_schedule())
        })
        .await
    }

    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        self.query_first("get_fork", BnRole::All, HealthTier::SmallLag, |c| {
            Box::pin(c.get_fork(state_id))
        })
        .await
    }

    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError> {
        self.query_first("get_validators", BnRole::All, HealthTier::SmallLag, |c| {
            Box::pin(c.get_validators(pubkeys))
        })
        .await
    }

    // -- Blocks --

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        self.query_first("get_block_root", BnRole::All, HealthTier::SmallLag, |c| {
            Box::pin(c.get_block_root(block_id))
        })
        .await
    }

    // -- Node status: query(First), any role --

    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        self.query_first("get_node_syncing", BnRole::All, HealthTier::Unsynced, |c| {
            Box::pin(c.get_node_syncing())
        })
        .await
    }

    async fn get_node_version(&self) -> Result<String, BeaconError> {
        self.query_first("get_node_version", BnRole::All, HealthTier::Unsynced, |c| {
            Box::pin(c.get_node_version())
        })
        .await
    }
}

#[async_trait]
impl DutiesProvider for BnManager {
    // -- Duties: query(First) + duty_fetch timeout, accept SmallLag --

    async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        self.with_op_timeout(
            "get_attester_duties",
            self.op_timeout(|t| t.duty_fetch),
            self.query_first(
                "get_attester_duties",
                BnRole::Attestation,
                HealthTier::SmallLag,
                |c| Box::pin(c.get_attester_duties(epoch, validator_indices)),
            ),
        )
        .await
    }

    async fn get_proposer_duties(
        &self,
        epoch: u64,
        schedule: &ForkSchedule,
    ) -> Result<ProposerDutiesResponse, BeaconError> {
        self.with_op_timeout(
            "get_proposer_duties",
            self.op_timeout(|t| t.duty_fetch),
            self.query_first("get_proposer_duties", BnRole::Proposal, HealthTier::Synced, |c| {
                Box::pin(c.get_proposer_duties(epoch, schedule))
            }),
        )
        .await
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        self.with_op_timeout(
            "post_sync_committee_duties",
            self.op_timeout(|t| t.duty_fetch),
            self.query_first(
                "post_sync_committee_duties",
                BnRole::SyncCommittee,
                HealthTier::SmallLag,
                |c| Box::pin(c.post_sync_committee_duties(epoch, validator_indices)),
            ),
        )
        .await
    }
}

#[async_trait]
impl BlockProducer for BnManager {
    // -- Block production: query(Best), Proposal role, require Synced --

    async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        self.with_op_timeout(
            "produce_block_v3",
            self.op_timeout(|t| t.block_production),
            self.query_best(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                |c| {
                    Box::pin(c.produce_block_v3(
                        slot,
                        randao_reveal,
                        graffiti,
                        builder_boost_factor,
                    ))
                },
                is_better_block,
            ),
        )
        .await
    }

    // -- Submissions: broadcast or query_first via submit() helper --

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.submit(
            "publish_block",
            self.broadcast_topics.blocks,
            BnRole::Submission,
            HealthTier::LargeLag,
            self.op_timeout(|t| t.block_publication),
            |c| Box::pin(c.publish_block(signed_block, consensus_version)),
        )
        .await
    }

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.submit(
            "publish_blinded_block",
            self.broadcast_topics.blocks,
            BnRole::Submission,
            HealthTier::LargeLag,
            self.op_timeout(|t| t.block_publication),
            |c| Box::pin(c.publish_blinded_block(signed_blinded_block, consensus_version)),
        )
        .await
    }

    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
    ) -> Result<(), BeaconError> {
        if self.broadcast_topics.blocks {
            self.with_op_timeout(
                "publish_block_ssz",
                self.op_timeout(|t| t.block_publication),
                self.broadcast("publish_block_ssz", BnRole::Submission, |c| {
                    Box::pin(c.publish_block_ssz(ssz_bytes, consensus_version, is_blinded))
                }),
            )
            .await
        } else {
            self.with_op_timeout(
                "publish_block_ssz",
                self.op_timeout(|t| t.block_publication),
                self.query_first(
                    "publish_block_ssz",
                    BnRole::Submission,
                    HealthTier::LargeLag,
                    |c| Box::pin(c.publish_block_ssz(ssz_bytes, consensus_version, is_blinded)),
                ),
            )
            .await
        }
    }

    // -- Proposer preparation: broadcast --

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "prepare_beacon_proposer",
            self.op_timeout(|t| t.preparation),
            self.broadcast("prepare_beacon_proposer", BnRole::Proposal, |c| {
                Box::pin(c.prepare_beacon_proposer(preparations))
            }),
        )
        .await
    }

    // -- Builder: broadcast --

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "register_validators",
            self.op_timeout(|t| t.preparation),
            self.broadcast("register_validators", BnRole::Proposal, |c| {
                Box::pin(c.register_validators(registrations))
            }),
        )
        .await
    }
}

#[async_trait]
impl AttestationApi for BnManager {
    // -- Attestation data: query(First), Attestation role, accept SmallLag --

    async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        self.with_op_timeout(
            "get_attestation_data",
            self.op_timeout(|t| t.attestation_fetch),
            self.query_first(
                "get_attestation_data",
                BnRole::Attestation,
                HealthTier::SmallLag,
                |c| Box::pin(c.get_attestation_data(slot, committee_index)),
            ),
        )
        .await
    }

    // -- Attestation submission: broadcast by Attestation role; query_first
    //    stays Submission + LargeLag when the topic is off. --

    async fn submit_attestation(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError> {
        if self.broadcast_topics.attestations {
            self.with_op_timeout(
                "submit_attestation",
                self.op_timeout(|t| t.attestation_submit),
                self.broadcast_with_result("submit_attestation", BnRole::Attestation, |c| {
                    Box::pin(c.submit_attestation(attestations))
                }),
            )
            .await
        } else {
            self.with_op_timeout(
                "submit_attestation",
                self.op_timeout(|t| t.attestation_submit),
                self.query_first(
                    "submit_attestation",
                    BnRole::Submission,
                    HealthTier::LargeLag,
                    |c| Box::pin(c.submit_attestation(attestations)),
                ),
            )
            .await
        }
    }

    // -- Aggregation: Aggregation role, accept SmallLag for fetch; broadcast for submit --

    async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
    ) -> Result<VersionedAggregateAttestation, BeaconError> {
        self.with_op_timeout(
            "get_aggregate_attestation",
            self.op_timeout(|t| t.aggregate_fetch),
            self.query_first(
                "get_aggregate_attestation",
                BnRole::Aggregation,
                HealthTier::SmallLag,
                |c| {
                    Box::pin(c.get_aggregate_attestation(
                        slot,
                        attestation_data_root,
                        committee_index,
                    ))
                },
            ),
        )
        .await
    }

    async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "submit_aggregate_and_proofs",
            self.op_timeout(|t| t.aggregate_submit),
            self.broadcast("submit_aggregate_and_proofs", BnRole::Aggregation, |c| {
                Box::pin(c.submit_aggregate_and_proofs(proofs))
            }),
        )
        .await
    }

    // -- Committee subscriptions: broadcast or Submission role --

    async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.submit(
            "submit_beacon_committee_subscriptions",
            self.broadcast_topics.subscriptions,
            BnRole::Submission,
            HealthTier::LargeLag,
            self.op_timeout(|t| t.preparation),
            |c| Box::pin(c.submit_beacon_committee_subscriptions(subscriptions)),
        )
        .await
    }
}

#[async_trait]
impl SyncCommitteeApi for BnManager {
    // -- Sync committee: SyncCommittee role, accept SmallLag --

    async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.submit(
            "submit_sync_committee_messages",
            self.broadcast_topics.sync_committee,
            BnRole::SyncCommittee,
            HealthTier::SmallLag,
            self.op_timeout(|t| t.sync_message),
            |c| Box::pin(c.submit_sync_committee_messages(messages)),
        )
        .await
    }

    async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        self.with_op_timeout(
            "get_sync_committee_contribution",
            self.op_timeout(|t| t.sync_contribution),
            self.query_first(
                "get_sync_committee_contribution",
                BnRole::SyncCommittee,
                HealthTier::SmallLag,
                |c| {
                    Box::pin(c.get_sync_committee_contribution(
                        slot,
                        subcommittee_index,
                        beacon_block_root,
                    ))
                },
            ),
        )
        .await
    }

    async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "submit_contribution_and_proofs",
            self.op_timeout(|t| t.sync_contribution),
            self.broadcast("submit_contribution_and_proofs", BnRole::SyncCommittee, |c| {
                Box::pin(c.submit_contribution_and_proofs(proofs))
            }),
        )
        .await
    }
}

#[async_trait]
impl LivenessApi for BnManager {
    // -- Doppelganger / liveness (SEC-2c): query_first failover, SmallLag --

    async fn post_validator_liveness(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        self.query_first("post_validator_liveness", BnRole::All, HealthTier::SmallLag, |c| {
            Box::pin(c.post_validator_liveness(epoch, validator_indices))
        })
        .await
    }

    // -- ARCH-3n: fan-out + per-index OR-merge (fail-safe live-wins) --

    async fn post_validator_liveness_merged(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        let broadcast = self
            .broadcast_inner("post_validator_liveness_merged", BnRole::All, &|c| {
                Box::pin(c.post_validator_liveness(epoch, validator_indices))
            })
            .await;
        Self::log_partial_failure("post_validator_liveness_merged", &broadcast);
        if broadcast.outcomes.is_empty() {
            return Err(BeaconError::NoEligibleBn {
                operation: "post_validator_liveness_merged".to_string(),
                role: BnRole::All.to_string(),
            });
        }
        merge_liveness_broadcast(broadcast)
    }
}

impl BeaconNodeClient for BnManager {}

/// Forward every role-trait method on `BeaconClient` to the inherent method of
/// the same name. Adding a role-trait endpoint requires adding it to this
/// list (compile error until then) — no 165-line hand-written passthrough.
///
/// `BEACON_CLIENT_PASSTHROUGH_METHODS` is emitted for the coverage test.
macro_rules! impl_beacon_client_passthrough {
    (
        $(
            $trait_name:ident {
                $(
                    async fn $method:ident(
                        &self $(, $arg:ident : $arg_ty:ty)* $(,)?
                    ) -> $ret:ty ;
                )*
            }
        )*
    ) => {
        $(
            #[async_trait]
            impl $trait_name for BeaconClient {
                $(
                    async fn $method(
                        &self $(, $arg: $arg_ty)*
                    ) -> $ret {
                        BeaconClient::$method(self $(, $arg)*).await
                    }
                )*
            }
        )*

        /// Method names covered by the `BeaconClient` passthrough macro.
        #[cfg(test)]
        pub(crate) const BEACON_CLIENT_PASSTHROUGH_METHODS: &[&str] = &[
            $($(stringify!($method),)*)*
        ];
    };
}

impl_beacon_client_passthrough! {
    NodeStatusApi {
        async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError>;
        async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError>;
        async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError>;
        async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError>;
        async fn get_validators(
            &self,
            pubkeys: &[String],
        ) -> Result<ValidatorsResponse, BeaconError>;
        async fn get_block_root(
            &self,
            block_id: &str,
        ) -> Result<BlockRootResponse, BeaconError>;
        async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError>;
        async fn get_node_version(&self) -> Result<String, BeaconError>;
    }
    DutiesProvider {
        async fn get_attester_duties(
            &self,
            epoch: u64,
            validator_indices: &[String],
        ) -> Result<AttesterDutiesResponse, BeaconError>;
        async fn get_proposer_duties(
            &self,
            epoch: u64,
            schedule: &ForkSchedule,
        ) -> Result<ProposerDutiesResponse, BeaconError>;
        async fn post_sync_committee_duties(
            &self,
            epoch: u64,
            validator_indices: &[String],
        ) -> Result<SyncCommitteeDutiesResponse, BeaconError>;
    }
    BlockProducer {
        async fn produce_block_v3(
            &self,
            slot: u64,
            randao_reveal: &str,
            graffiti: Option<&str>,
            builder_boost_factor: Option<u64>,
        ) -> Result<ProduceBlockResponse, BeaconError>;
        async fn publish_block(
            &self,
            signed_block: &SignedBeaconBlock,
            consensus_version: &str,
        ) -> Result<(), BeaconError>;
        async fn publish_blinded_block(
            &self,
            signed_blinded_block: &SignedBlindedBeaconBlock,
            consensus_version: &str,
        ) -> Result<(), BeaconError>;
        async fn publish_block_ssz(
            &self,
            ssz_bytes: &[u8],
            consensus_version: &str,
            is_blinded: bool,
        ) -> Result<(), BeaconError>;
        async fn prepare_beacon_proposer(
            &self,
            preparations: &[ProposerPreparation],
        ) -> Result<(), BeaconError>;
        async fn register_validators(
            &self,
            registrations: &[SignedValidatorRegistration],
        ) -> Result<(), BeaconError>;
    }
    AttestationApi {
        async fn get_attestation_data(
            &self,
            slot: u64,
            committee_index: u64,
        ) -> Result<AttestationDataResponse, BeaconError>;
        async fn submit_attestation(
            &self,
            attestations: &VersionedAttestation,
        ) -> Result<SubmitAttestationResult, BeaconError>;
        async fn get_aggregate_attestation(
            &self,
            slot: u64,
            attestation_data_root: &str,
            committee_index: Option<u64>,
        ) -> Result<VersionedAggregateAttestation, BeaconError>;
        async fn submit_aggregate_and_proofs(
            &self,
            proofs: &VersionedSignedAggregateAndProof,
        ) -> Result<(), BeaconError>;
        async fn submit_beacon_committee_subscriptions(
            &self,
            subscriptions: &[BeaconCommitteeSubscription],
        ) -> Result<(), BeaconError>;
    }
    SyncCommitteeApi {
        async fn submit_sync_committee_messages(
            &self,
            messages: &[SyncCommitteeMessage],
        ) -> Result<(), BeaconError>;
        async fn get_sync_committee_contribution(
            &self,
            slot: u64,
            subcommittee_index: u64,
            beacon_block_root: &str,
        ) -> Result<SyncCommitteeContributionResponse, BeaconError>;
        async fn submit_contribution_and_proofs(
            &self,
            proofs: &[SignedContributionAndProof],
        ) -> Result<(), BeaconError>;
    }
    LivenessApi {
        async fn post_validator_liveness(
            &self,
            epoch: u64,
            validator_indices: &[String],
        ) -> Result<ValidatorLivenessResponse, BeaconError>;
        async fn post_validator_liveness_merged(
            &self,
            epoch: u64,
            validator_indices: &[String],
        ) -> Result<ValidatorLivenessResponse, BeaconError>;
    }
}

impl BeaconNodeClient for BeaconClient {}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    /// Guard: the passthrough macro list must name every role-trait method.
    /// Primary enforcement is compile-time (missing method → trait not satisfied).
    /// This test documents the expected surface and catches accidental list drift.
    #[test]
    fn test_beacon_client_passthrough_covers_every_trait_method() {
        // Type-level: BeaconClient implements the full supertrait surface.
        fn _assert_full_client<T: BeaconNodeClient>() {}
        _assert_full_client::<BeaconClient>();

        // 27 methods across the six role traits (see impl_beacon_client_passthrough!).
        assert_eq!(
            BEACON_CLIENT_PASSTHROUGH_METHODS.len(),
            27,
            "update impl_beacon_client_passthrough! when adding a role-trait method"
        );

        let mut sorted: Vec<&str> = BEACON_CLIENT_PASSTHROUGH_METHODS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            BEACON_CLIENT_PASSTHROUGH_METHODS.len(),
            "passthrough method list must not contain duplicates: {sorted:?}"
        );

        // Spot-check that each role trait is represented.
        for required in [
            "get_genesis",
            "get_attester_duties",
            "produce_block_v3",
            "publish_block_ssz",
            "submit_attestation",
            "submit_sync_committee_messages",
            "post_validator_liveness",
            "post_validator_liveness_merged",
        ] {
            assert!(
                BEACON_CLIENT_PASSTHROUGH_METHODS.contains(&required),
                "passthrough list missing {required}"
            );
        }
    }

    /// Gate 3 (high-risk redaction): the `bn.attempt` span's `bn_url` field MUST redact
    /// URL credentials. Capturing the span's creation attributes, a credentialed endpoint
    /// renders via RedactedUrl with no `user:pass@` reaching the log.
    #[test]
    fn attempt_span_redacts_bn_url_credentials() {
        use std::sync::Mutex;

        use tracing::field::{Field, Visit};
        use tracing::span::Attributes;
        use tracing_subscriber::layer::{Context, Layer};
        use tracing_subscriber::prelude::*;
        use tracing_subscriber::registry::LookupSpan;

        #[derive(Clone, Default)]
        struct Cap(Arc<Mutex<String>>);
        struct V<'a>(&'a mut String);
        impl Visit for V<'_> {
            fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
                use std::fmt::Write;
                let _ = write!(self.0, " {}={:?}", f.name(), v);
            }
        }
        impl<S> Layer<S> for Cap
        where
            S: tracing::Subscriber + for<'a> LookupSpan<'a>,
        {
            fn on_new_span(&self, attrs: &Attributes<'_>, _id: &tracing::Id, _ctx: Context<'_, S>) {
                if let Ok(mut buf) = self.0.lock() {
                    attrs.record(&mut V(&mut buf));
                }
            }
        }

        let cap = Cap::default();
        let subscriber = tracing_subscriber::registry().with(cap.clone());
        tracing::subscriber::with_default(subscriber, || {
            let _span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl("http://user:pass@localhost:5052")
            );
        });

        let captured = cap.0.lock().unwrap();
        assert!(captured.contains("bn_url"), "bn_url field not captured: {captured}");
        assert!(
            !captured.contains("user:pass"),
            "credentials leaked into the bn_url log field: {captured}"
        );
    }

    // -- Construction tests --

    #[test]
    fn test_new_with_single_endpoint() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        let manager = BnManager::new(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_new_with_https_endpoint() {
        let config = BnManagerConfig::new(vec!["https://beacon.example.com".to_string()]);
        let manager = BnManager::new(config);
        assert!(manager.is_ok());
    }

    #[test]
    fn test_new_with_empty_endpoints() {
        let config = BnManagerConfig::new(vec![]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::NoEndpoints));
    }

    #[test]
    fn test_new_with_invalid_scheme() {
        let config = BnManagerConfig::new(vec!["ftp://localhost:5052".to_string()]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::InvalidEndpoint(_)));
    }

    #[test]
    fn test_new_with_no_scheme() {
        let config = BnManagerConfig::new(vec!["localhost:5052".to_string()]);
        let result = BnManager::new(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_rejects_scheme_only_url() {
        let config = BnManagerConfig::new(vec!["http://".to_string()]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::InvalidEndpoint(_)));
    }

    #[test]
    fn test_new_rejects_url_with_credentials() {
        let config = BnManagerConfig::new(vec!["http://user:pass@localhost:5052".to_string()]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::InvalidEndpoint(_)));
    }

    #[test]
    fn test_new_accepts_valid_urls() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        assert!(BnManager::new(config).is_ok());

        let config = BnManagerConfig::new(vec!["https://beacon.example.com".to_string()]);
        assert!(BnManager::new(config).is_ok());
    }

    #[test]
    fn test_new_uses_first_endpoint() {
        let config = BnManagerConfig::new(vec![
            "http://first:5052".to_string(),
            "http://second:5052".to_string(),
        ]);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.primary_endpoint(), "http://first:5052");
    }

    #[test]
    fn test_new_respects_timeout() {
        let mut config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        config.timeout = Duration::from_secs(10);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.clients[0].timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_new_with_trailing_slash() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052/".to_string()]);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.primary_endpoint(), "http://localhost:5052");
    }

    #[test]
    fn test_new_creates_multiple_clients() {
        let config = BnManagerConfig::new(vec![
            "http://bn1:5052".to_string(),
            "http://bn2:5052".to_string(),
            "http://bn3:5052".to_string(),
        ]);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.clients.len(), 3);
        assert_eq!(manager.clients[0].endpoint(), "http://bn1:5052");
        assert_eq!(manager.clients[1].endpoint(), "http://bn2:5052");
        assert_eq!(manager.clients[2].endpoint(), "http://bn3:5052");
    }

    #[test]
    fn test_new_validates_all_endpoints() {
        let config = BnManagerConfig::new(vec![
            "http://good:5052".to_string(),
            "ftp://bad:5052".to_string(),
        ]);
        let err = BnManager::new(config).err().expect("should fail");
        assert!(matches!(err, BnManagerError::InvalidEndpoint(_)));
    }

    #[test]
    fn test_new_all_clients_use_same_timeout() {
        let mut config = BnManagerConfig::new(vec![
            "http://bn1:5052".to_string(),
            "http://bn2:5052".to_string(),
        ]);
        config.timeout = Duration::from_secs(15);
        let manager = BnManager::new(config).unwrap();
        assert_eq!(manager.clients[0].timeout(), Duration::from_secs(15));
        assert_eq!(manager.clients[1].timeout(), Duration::from_secs(15));
    }

    // -- Trait object compatibility --

    #[test]
    fn test_bn_manager_as_arc_dyn() {
        let config = BnManagerConfig::new(vec!["http://localhost:5052".to_string()]);
        let manager = BnManager::new(config).unwrap();
        let _dyn_client: Arc<dyn BeaconNodeClient> = Arc::new(manager);
    }

    #[test]
    fn test_beacon_client_as_arc_dyn() {
        let config = beacon::BeaconClientConfig::new("http://localhost:5052");
        let client = BeaconClient::new(config).unwrap();
        let _dyn_client: Arc<dyn BeaconNodeClient> = Arc::new(client);
    }

    // -- is_better_block unit tests --

    #[test]
    fn test_is_better_block_higher_value() {
        let a = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("5000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        };
        assert!(is_better_block(&a, &b));
        assert!(!is_better_block(&b, &a));
    }

    #[test]
    fn test_is_better_block_none_vs_some() {
        let a = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
            is_ssz: false,
            ssz_bytes: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        };
        assert!(!is_better_block(&a, &b));
        assert!(is_better_block(&b, &a));
    }

    #[test]
    fn test_is_better_block_both_none() {
        let a = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
            is_ssz: false,
            ssz_bytes: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
            is_ssz: false,
            ssz_bytes: None,
        };
        assert!(!is_better_block(&a, &b));
    }

    #[test]
    fn test_is_better_block_equal_values() {
        let a = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
        };
        assert!(!is_better_block(&a, &b));
    }
}
