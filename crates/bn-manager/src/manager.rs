use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    AttestationDataResponse, AttesterDutiesResponse, BeaconClient, BeaconCommitteeSubscription,
    BeaconError, BlockRootResponse, BuilderConfig, BuilderPreferencesEntry, ConfigSpecResponse,
    GenesisResponse, IndexedFailure, PayloadAttestationDataResponse, ProduceBlockResponse,
    ProposerDutiesResponse, ProposerPreparation, PtcDutiesResponse, SignedContributionAndProof,
    StateForkResponse, SubmitAttestationResult, SubmitBuilderPreferencesResult,
    SyncCommitteeContributionResponse, SyncCommitteeDutiesResponse, SyncCommitteeMessage,
    SyncingResponse, ValidatorLiveness, ValidatorLivenessResponse, ValidatorsResponse,
    VersionedAggregateAttestation, VersionedAttestation, VersionedSignedAggregateAndProof,
    WireBody,
};
use eth_types::{
    ForkName, ForkSchedule, PayloadAttestationMessage, SignedBeaconBlock, SignedBlindedBeaconBlock,
    SignedBlockContentsJson, SignedProposerPreferences, SignedValidatorRegistration,
};
use futures::future::join_all;
use tracing::Instrument;
use tracing::{debug, error, trace, warn};
use url::Url;

use observability::logging::RedactedUrl;

use crate::sync_status::BnSyncStatus;

use crate::broadcast::{BnOutcome, BroadcastResult};
use crate::health::{new_shared_health_trackers, BnHealthTracker, SharedHealthTrackers};
use crate::sse::{self, SseConfig, SseEvent};
use crate::sync_status::{
    check_all_sync_statuses, new_shared_sync_statuses, start_sync_monitor, SharedSyncStatuses,
};
use crate::traits::{
    AttestationApi, BeaconNodeClient, BlockProducer, BnHealthScore, BnManagerConfig,
    DutiesProvider, LivenessApi, NodeStatusApi, OperationTimeouts, PayloadAttestationApi,
    SyncCommitteeApi,
};
use crate::types::{bn_capability, BnRole, HealthTier, TierThresholds};
use crate::BnManagerError;

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, BeaconError>> + Send + 'a>>;
type IndexedTimedResultFut<'a, T> =
    Pin<Box<dyn Future<Output = (usize, String, Result<T, BeaconError>, Duration)> + Send + 'a>>;

/// Health-tracker outcome for one BN attempt (success with latency, or error).
#[derive(Debug, Clone, Copy)]
enum TrackerOutcome {
    Success(Duration),
    Error,
    /// Missing `/eth/v4` (404/405/501) or an unrecognised fork — skip this BN
    /// for the operation until a later success re-probes it.
    Incapable {
        unrecognised_fork: bool,
    },
}

/// D29: V4 production may fail over only on connect / timeout / 5xx — never after
/// a 2xx (ParseError) or a 4xx that the BN understood.
///
/// 404/405/501 mean the BN does not serve the endpoint (capability gap), not
/// that it understood a bad request; those are retryable so a peer with `/eth/v4`
/// can still produce. 400/429 stay fail-closed. `HttpError` is the client's
/// connect/request class (serialize failures use the same variant and fail
/// identically on every BN).
fn is_production_failover_error(err: &BeaconError) -> bool {
    match err {
        BeaconError::Timeout | BeaconError::OperationTimeout { .. } | BeaconError::HttpError(_) => {
            true
        }
        BeaconError::ApiError { status, .. }
            if matches!(status, 404 | 405) || (500..600).contains(status) =>
        {
            true
        }
        _ => false,
    }
}

fn is_unrecognised_fork(err: &BeaconError) -> bool {
    match err {
        BeaconError::ParseError(msg) => {
            msg.contains("invalid Eth-Consensus-Version")
                || msg.contains("unparseable Eth-Consensus-Version")
        }
        _ => false,
    }
}

fn is_v4_capability_gap(op_name: &str, err: &BeaconError) -> bool {
    op_name == bn_capability::PRODUCE_BLOCK_V4
        && matches!(err, BeaconError::ApiError { status: 404 | 405 | 501, .. })
}

fn error_outcome(op_name: &str, err: &BeaconError) -> TrackerOutcome {
    if is_unrecognised_fork(err) {
        TrackerOutcome::Incapable { unrecognised_fork: true }
    } else if is_v4_capability_gap(op_name, err) {
        TrackerOutcome::Incapable { unrecognised_fork: false }
    } else {
        TrackerOutcome::Error
    }
}

fn no_eligible_bn(op_name: &str, role: BnRole) -> BeaconError {
    BeaconError::NoEligibleBn { operation: op_name.to_string(), role: role.to_string() }
}

/// `scheme://host:port` with userinfo and path stripped — dashboards key on host,
/// not credentials or request path (issue 8.3 label hygiene).
fn capability_endpoint_label(endpoint: &str) -> String {
    match Url::parse(endpoint) {
        Ok(mut parsed) if parsed.scheme() == "http" || parsed.scheme() == "https" => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            parsed.set_path("");
            parsed.set_query(None);
            parsed.set_fragment(None);
            parsed.to_string().trim_end_matches('/').to_string()
        }
        // Unparseable (or non-http) input must not become a label — userinfo
        // can sit in a raw string that `Url::parse` rejects.
        _ => "unknown".to_string(),
    }
}

fn publish_capability(endpoint: &str, capability: &str, capable: bool) {
    #[cfg(not(test))]
    debug_assert!(
        bn_capability::ALL.contains(&capability),
        "capability label `{capability}` is not in bn_capability::ALL"
    );
    if !bn_capability::ALL.contains(&capability) {
        return;
    }
    let endpoint_label = capability_endpoint_label(endpoint);
    crate::metrics::RVC_BN_CAPABILITY_STATE
        .with_label_values(&[endpoint_label.as_str(), capability])
        .set(i64::from(capable));
}

fn capable_of(tracker: &BnHealthTracker, op_name: &str) -> bool {
    tracker.is_capable(op_name)
        && (op_name != bn_capability::PRODUCE_BLOCK_V4
            || tracker.is_capable(bn_capability::FORK_RECOGNISED))
}

/// Consume mixed-fleet skip budget. `true` excludes this selection.
fn skip_capability(tracker: &BnHealthTracker, op_name: &str) -> bool {
    let skip_op = tracker.consume_reprobe_skip(op_name);
    if op_name == bn_capability::PRODUCE_BLOCK_V4 {
        tracker.consume_reprobe_skip(bn_capability::FORK_RECOGNISED) || skip_op
    } else {
        skip_op
    }
}

fn sort_indices_by_health(indices: &mut [usize], health_guard: &[BnHealthTracker]) {
    indices.sort_by(|&a, &b| {
        health_guard[b]
            .score()
            .partial_cmp(&health_guard[a].score())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.cmp(&b))
    });
}

/// Split remaining slot budget across BNs still to try (last BN gets the rest).
fn split_attempt_timeout(remaining: Duration, remaining_bns: usize) -> Duration {
    if remaining_bns <= 1 {
        return remaining;
    }
    let split = remaining / remaining_bns as u32;
    if split.is_zero() {
        remaining
    } else {
        split
    }
}

/// Lower bound on a useful attempt when the deadline can still afford it.
///
/// Each attempt uses `min(remaining, max(split, ATTEMPT_TIMEOUT_FLOOR))`.
/// A remainder below the floor is not raised (REV-07).
pub const ATTEMPT_TIMEOUT_FLOOR: Duration = Duration::from_millis(250);

// G7 scales this below the production floor so a tens-of-ms budget can still
// reach a second BN. Unset in production and in tests that do not call the setter.
#[cfg(test)]
thread_local! {
    static TEST_ATTEMPT_FLOOR: std::cell::Cell<Option<Duration>> =
        const { std::cell::Cell::new(None) };
}

fn current_attempt_floor() -> Duration {
    #[cfg(test)]
    {
        TEST_ATTEMPT_FLOOR.with(|slot| slot.get().unwrap_or(ATTEMPT_TIMEOUT_FLOOR))
    }
    #[cfg(not(test))]
    {
        ATTEMPT_TIMEOUT_FLOOR
    }
}

/// Per-attempt bound: `min(remaining, max(split, FLOOR))`.
///
/// `None` when `remaining` is zero. Callers must not start the attempt in that
/// case: `tokio::time::timeout(Duration::ZERO, fut)` still polls `fut` once and
/// can emit the HTTP request. `remaining < FLOOR` yields `remaining`, not the floor.
fn attempt_timeout(remaining: Duration, bns_left: usize) -> Option<Duration> {
    if remaining.is_zero() {
        return None;
    }
    let split = split_attempt_timeout(remaining, bns_left);
    Some(remaining.min(split.max(current_attempt_floor())))
}

/// `Ok(None)` when the caller passed no deadline (attempts stay unbounded).
/// `Err` when that absolute deadline is already exhausted.
fn attempt_limit(
    op_name: &str,
    deadline: Option<tokio::time::Instant>,
    bns_left: usize,
) -> Result<Option<Duration>, BeaconError> {
    let Some(end) = deadline else {
        return Ok(None);
    };
    let remaining = end.saturating_duration_since(tokio::time::Instant::now());
    match attempt_timeout(remaining, bns_left) {
        Some(bound) => Ok(Some(bound)),
        None => Err(BeaconError::OperationTimeout {
            operation: op_name.to_string(),
            timeout: Duration::ZERO,
        }),
    }
}

/// Await one attempt. Expiry becomes [`BeaconError::OperationTimeout`].
/// `None` means the caller supplied no deadline.
async fn await_attempt<T>(
    op_name: &str,
    bound: Option<Duration>,
    fut: impl Future<Output = Result<T, BeaconError>>,
) -> Result<T, BeaconError> {
    match bound {
        Some(d) => match tokio::time::timeout(d, fut).await {
            Ok(inner) => inner,
            Err(_) => {
                Err(BeaconError::OperationTimeout { operation: op_name.to_string(), timeout: d })
            }
        },
        None => fut.await,
    }
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
/// - **Failover**: sequential, one in-flight; retry connect / timeout / 5xx only —
///   `produce_block_v4` (D29). Never after a 2xx, never in parallel. 404/405/501
///   are a capability gap (missing `/eth/v4`) and do fail over; a later success
///   re-probes. All-incapable is `NoEligibleBn`, never V3.
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
/// multiply tail latency on a dead primary. Callers that bypass this pool may
/// set a non-zero retry budget; that is the only intentional exception. The CLI
/// exit helper `build_signed_exit` in `bin/rvc` still builds its own
/// `BeaconClient`. The keymanager exit path does not.
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
        for ep in &endpoints {
            for capability in bn_capability::ALL {
                publish_capability(ep, capability, true);
            }
        }
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
    /// Query-first sites turn the matching field into an absolute deadline
    /// before their first await and bound each BN attempt inside it. Broadcast,
    /// best-of, and `produce_block_v4` keep an outer `tokio::time::timeout`.
    /// Exceeding the budget returns `BeaconError::OperationTimeout`.
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

    /// Apply health-tracker updates. Each call takes the write lock once.
    ///
    /// Sequential strategies flush per attempt so cancellation cannot drop
    /// earlier failures. [`Self::query_best_inner`] still batches at the end
    /// of the round.
    async fn record_outcomes(&self, op_name: &str, outcomes: &[(usize, TrackerOutcome)]) {
        if outcomes.is_empty() {
            return;
        }
        let mut trackers = self.health_trackers.write().await;
        for &(idx, outcome) in outcomes {
            match outcome {
                TrackerOutcome::Success(latency) => {
                    trackers[idx].record_success(latency);
                    trackers[idx].mark_capable(op_name);
                    if op_name == bn_capability::PRODUCE_BLOCK_V4 {
                        let endpoint = trackers[idx].endpoint().to_string();
                        trackers[idx].mark_capable(bn_capability::FORK_RECOGNISED);
                        publish_capability(&endpoint, bn_capability::PRODUCE_BLOCK_V4, true);
                        publish_capability(&endpoint, bn_capability::FORK_RECOGNISED, true);
                    }
                }
                TrackerOutcome::Error => trackers[idx].record_error(),
                TrackerOutcome::Incapable { unrecognised_fork } => {
                    trackers[idx].record_error();
                    trackers[idx].mark_incapable(op_name);
                    let endpoint = trackers[idx].endpoint().to_string();
                    if op_name == bn_capability::PRODUCE_BLOCK_V4 {
                        publish_capability(&endpoint, bn_capability::PRODUCE_BLOCK_V4, false);
                    }
                    if unrecognised_fork {
                        trackers[idx].mark_incapable(bn_capability::FORK_RECOGNISED);
                        publish_capability(&endpoint, bn_capability::FORK_RECOGNISED, false);
                    }
                }
            }
        }
    }

    /// Dispatch a submission via broadcast or query_first based on the topic flag.
    ///
    /// Encapsulates the repeated `if broadcast_topics.X { broadcast } else { query_first }`
    /// branch. The broadcast arm keeps [`Self::with_op_timeout`]. The query_first
    /// arm takes an absolute deadline from `timeout` before it awaits (ADR-R03).
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
            let deadline = timeout.map(|budget| tokio::time::Instant::now() + budget);
            self.query_first(op_name, role, min_tier, deadline, op).await
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
    /// Filtering order: role → tier → capability → health score.
    ///
    /// Fallback chain:
    /// 1. If no BNs match the role, fall back to `All`-role BNs with WARN
    /// 2. If no BNs meet the tier, try the next lower tier with WARN
    /// 3. If still empty, fall back to all BNs (query path only)
    /// 4. Capability is a hard exclude for one selection when a capable peer
    ///    remains; the next selection re-probes flagged BNs first (bounded
    ///    schedule). If every remaining BN is incapable of `op_name`, those BNs
    ///    are returned immediately so the caller can re-probe — never V3.
    #[tracing::instrument(name = "bn_manager.synced_indices", skip_all, fields(role = %role, min_tier = %min_tier, op = op_name))]
    async fn synced_indices(
        &self,
        role: BnRole,
        min_tier: HealthTier,
        op_name: &str,
    ) -> Vec<usize> {
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

        let capable: Vec<usize> = tier_filtered
            .iter()
            .copied()
            .filter(|&i| capable_of(&health_guard[i], op_name))
            .collect();

        if capable.is_empty() {
            if !tier_filtered.is_empty() {
                warn!(
                    op = op_name,
                    bn_count = tier_filtered.len(),
                    "all eligible BNs incapable of operation, re-probing"
                );
            }
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
            sort_indices_by_health(&mut result, &health_guard);
            return result;
        }

        // Mixed fleet: skip flagged BNs for one selection, then re-probe them
        // first so a recovered BN is contacted while a capable peer stays healthy.
        let mut reprobe = Vec::new();
        for &i in &tier_filtered {
            if capable_of(&health_guard[i], op_name) {
                continue;
            }
            if skip_capability(&health_guard[i], op_name) {
                continue;
            }
            reprobe.push(i);
        }

        let healthy_capable: Vec<usize> =
            capable.iter().copied().filter(|&i| health_guard[i].is_healthy()).collect();
        let mut capable_pool = if healthy_capable.is_empty() {
            error!(bn_count = capable.len(), "All BNs unhealthy, using all tier-matching BNs");
            capable
        } else {
            healthy_capable
        };
        sort_indices_by_health(&mut reprobe, &health_guard);
        sort_indices_by_health(&mut capable_pool, &health_guard);
        reprobe.extend(capable_pool);
        reprobe
    }

    /// Query using the `First` strategy: try synced BNs in order, fail over on error.
    ///
    /// `deadline`, when `Some`, is an absolute [`tokio::time::Instant`] captured
    /// before this call's first `.await` (ADR-R03). `None` leaves attempts unbounded.
    async fn query_first<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        deadline: Option<tokio::time::Instant>,
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
        self.query_first_inner(op_name, role, min_tier, deadline, &op)
            .instrument(strategy_span)
            .await
    }

    /// `deadline`, when `Some`, is an absolute [`tokio::time::Instant`] and must
    /// be captured before the first `.await` of the calling operation (ADR-R03).
    /// Each attempt is bounded by [`attempt_timeout`]; an exhausted deadline
    /// returns [`BeaconError::OperationTimeout`] without starting that attempt.
    /// `None` leaves attempts unbounded (the caller has no operation budget).
    async fn query_first_inner<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        deadline: Option<tokio::time::Instant>,
        op: &F,
    ) -> Result<T, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let indices = self.synced_indices(role, min_tier, op_name).await;
        if indices.is_empty() {
            return Err(no_eligible_bn(op_name, role));
        }
        let mut last_err = None;
        let mut tried: usize = 0;

        for (pos, i) in indices.iter().copied().enumerate() {
            let bns_left = indices.len() - pos;
            let bound = match attempt_limit(op_name, deadline, bns_left) {
                Ok(bound) => bound,
                Err(e) => {
                    tracing::Span::current().record("tried", tried);
                    return Err(e);
                }
            };
            let client = &self.clients[i];
            tried += 1;
            let attempt_span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl(client.endpoint()),
            );
            let start = tokio::time::Instant::now();
            // Build the future only after the deadline check. A zero timeout
            // still polls once and would send the request.
            let fut = op(client).instrument(attempt_span);
            match await_attempt(op_name, bound, fut).await {
                Ok(result) => {
                    let elapsed = start.elapsed();
                    // Earlier failures were recorded before this attempt.
                    self.record_outcomes(op_name, &[(i, TrackerOutcome::Success(elapsed))]).await;
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
                    self.record_outcomes(op_name, &[(i, error_outcome(op_name, &e))]).await;
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

        tracing::Span::current().record("tried", tried);
        Err(last_err.unwrap_or_else(|| no_eligible_bn(op_name, role)))
    }

    /// Like [`Self::query_first`], but `Ok(None)` is not a cluster answer.
    ///
    /// A per-BN 204 (`Ok(None)`) means that node has not seen the slot; a peer
    /// may still have data. 204 is not recorded as health success, so the empty
    /// BN does not stay preferred.
    async fn query_first_prefer_some<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        deadline: Option<tokio::time::Instant>,
        op: F,
    ) -> Result<Option<T>, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, Option<T>>,
    {
        let strategy_span = tracing::info_span!(
            "bn.strategy.first",
            strategy = "first",
            tried = tracing::field::Empty,
        );
        self.query_first_prefer_some_inner(op_name, role, min_tier, deadline, &op)
            .instrument(strategy_span)
            .await
    }

    /// `deadline`, when `Some`, is an absolute [`tokio::time::Instant`] and must
    /// be captured before the first `.await` of the calling operation (ADR-R03).
    /// Each attempt is bounded by [`attempt_timeout`]; an exhausted deadline
    /// returns [`BeaconError::OperationTimeout`] without starting that attempt.
    /// `None` leaves attempts unbounded (the caller has no operation budget).
    ///
    /// `Ok(None)` (HTTP 204) is not a health outcome and is not a cluster answer.
    ///
    /// A per-attempt [`BeaconError::OperationTimeout`] fails over while a later
    /// beacon node remains and [`attempt_limit`] still yields a bound. It is
    /// returned only when that deadline is already exhausted or the timed-out
    /// attempt is the last one. A stored `OperationTimeout` wins over
    /// `Ok(None)`, so an earlier HTTP 204 cannot hide a hang.
    async fn query_first_prefer_some_inner<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        deadline: Option<tokio::time::Instant>,
        op: &F,
    ) -> Result<Option<T>, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, Option<T>>,
    {
        let indices = self.synced_indices(role, min_tier, op_name).await;
        if indices.is_empty() {
            return Err(no_eligible_bn(op_name, role));
        }
        let mut last_err = None;
        let mut saw_none = false;
        let mut tried: usize = 0;

        for (pos, i) in indices.iter().copied().enumerate() {
            let bns_left = indices.len() - pos;
            let bound = match attempt_limit(op_name, deadline, bns_left) {
                Ok(bound) => bound,
                Err(e) => {
                    tracing::Span::current().record("tried", tried);
                    return Err(e);
                }
            };
            let client = &self.clients[i];
            tried += 1;
            let attempt_span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl(client.endpoint()),
            );
            let start = tokio::time::Instant::now();
            // Build the future only after the deadline check. A zero timeout
            // still polls once and would send the request.
            let fut = op(client).instrument(attempt_span);
            match await_attempt(op_name, bound, fut).await {
                Ok(Some(result)) => {
                    let elapsed = start.elapsed();
                    // Earlier failures were recorded before this attempt.
                    self.record_outcomes(op_name, &[(i, TrackerOutcome::Success(elapsed))]).await;
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        latency_ms = elapsed.as_millis() as u64,
                        "query succeeded"
                    );
                    tracing::Span::current().record("tried", tried);
                    return Ok(Some(result));
                }
                Ok(None) => {
                    saw_none = true;
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        "BN returned no data, trying next"
                    );
                }
                Err(e) => {
                    self.record_outcomes(op_name, &[(i, error_outcome(op_name, &e))]).await;
                    if matches!(e, BeaconError::OperationTimeout { .. }) {
                        let has_next = pos + 1 < indices.len();
                        if !has_next {
                            tracing::Span::current().record("tried", tried);
                            return Err(e);
                        }
                        let next_left = indices.len() - (pos + 1);
                        if let Err(exhausted) = attempt_limit(op_name, deadline, next_left) {
                            tracing::Span::current().record("tried", tried);
                            return Err(exhausted);
                        }
                    }
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

        tracing::Span::current().record("tried", tried);

        // A hang is not "no data". An earlier 204 must not hide it.
        match last_err {
            Some(err @ BeaconError::OperationTimeout { .. }) => Err(err),
            other => {
                if saw_none {
                    Ok(None)
                } else {
                    Err(other.unwrap_or_else(|| no_eligible_bn(op_name, role)))
                }
            }
        }
    }

    /// Sequential production failover (D29): one in-flight request, health-score
    /// order. Retry connect error / timeout / 5xx / missing-endpoint 404/405 —
    /// never after a 2xx (including a 2xx whose body later fails to parse) and
    /// never in parallel.
    ///
    /// `budget` is the slot-budget remaining for the whole round. Each attempt
    /// uses [`attempt_timeout`] so a hung primary cannot consume it alone, and
    /// the floor never extends past that deadline.
    ///
    /// One-in-flight is the client future this method polls. A per-attempt
    /// timeout drops that future before the next POST; a cancelled reqwest
    /// may still be aborting on the wire.
    async fn query_failover<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        budget: Option<Duration>,
        op: F,
    ) -> Result<T, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let strategy_span = tracing::info_span!(
            "bn.strategy.failover",
            strategy = "failover",
            tried = tracing::field::Empty,
        );
        self.query_failover_inner(op_name, role, min_tier, budget, &op)
            .instrument(strategy_span)
            .await
    }

    async fn query_failover_inner<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        budget: Option<Duration>,
        op: &F,
    ) -> Result<T, BeaconError>
    where
        T: Send,
        F: Fn(&'s BeaconClient) -> BoxFut<'s, T>,
    {
        let indices = self.synced_indices(role, min_tier, op_name).await;
        if indices.is_empty() {
            return Err(no_eligible_bn(op_name, role));
        }

        let deadline = budget.map(|d| (tokio::time::Instant::now() + d, d));
        let mut last_err = None;
        let mut tried: usize = 0;
        let mut failure_count: usize = 0;
        let mut incapable_count: usize = 0;

        for (pos, i) in indices.iter().copied().enumerate() {
            let remaining_bns = indices.len() - pos;
            // Per-attempt expiry stays `BeaconError::Timeout` (failover-retryable).
            // `OperationTimeout` here is only the already-exhausted deadline, which
            // must not start the attempt.
            let bound = if let Some((end, total)) = deadline {
                let remaining = end.saturating_duration_since(tokio::time::Instant::now());
                match attempt_timeout(remaining, remaining_bns) {
                    Some(d) => Some(d),
                    None => {
                        last_err = Some(BeaconError::OperationTimeout {
                            operation: op_name.to_string(),
                            timeout: total,
                        });
                        break;
                    }
                }
            } else {
                None
            };

            let client = &self.clients[i];
            tried += 1;
            let attempt_span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl(client.endpoint()),
            );
            let start = tokio::time::Instant::now();
            let fut = op(client).instrument(attempt_span);
            let result = match bound {
                Some(d) => tokio::time::timeout(d, fut).await.unwrap_or(Err(BeaconError::Timeout)),
                None => fut.await,
            };

            match result {
                Ok(value) => {
                    let elapsed = start.elapsed();
                    // Earlier failures were recorded before this attempt.
                    self.record_outcomes(op_name, &[(i, TrackerOutcome::Success(elapsed))]).await;
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        latency_ms = elapsed.as_millis() as u64,
                        "query succeeded"
                    );
                    tracing::Span::current().record("tried", tried);
                    return Ok(value);
                }
                Err(e) => {
                    let outcome = error_outcome(op_name, &e);
                    failure_count += 1;
                    if matches!(outcome, TrackerOutcome::Incapable { .. }) {
                        incapable_count += 1;
                    }
                    self.record_outcomes(op_name, &[(i, outcome)]).await;
                    if is_production_failover_error(&e) {
                        if let Some(&next_i) = indices.get(pos + 1) {
                            warn!(
                                failed_bn = %RedactedUrl(client.endpoint()),
                                selected_bn = %RedactedUrl(self.clients[next_i].endpoint()),
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
                    } else {
                        warn!(
                            op = op_name,
                            bn_index = i,
                            endpoint = %RedactedUrl(client.endpoint()),
                            error = %e,
                            "BN production error is not failover-retryable"
                        );
                        last_err = Some(e);
                        break;
                    }
                }
            }
        }

        tracing::Span::current().record("tried", tried);
        let all_incapable = failure_count > 0 && incapable_count == failure_count;
        if all_incapable
            && last_err
                .as_ref()
                .is_none_or(|e| is_v4_capability_gap(op_name, e) || is_unrecognised_fork(e))
        {
            // Every tried BN lacks this endpoint / fork — fail closed, never V3.
            return Err(no_eligible_bn(op_name, role));
        }
        Err(last_err.unwrap_or_else(|| no_eligible_bn(op_name, role)))
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
        let indices = self.synced_indices(role, min_tier, op_name).await;
        tracing::Span::current().record("tried", indices.len());
        if indices.is_empty() {
            return Err(no_eligible_bn(op_name, role));
        }

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
                    self.record_outcomes(op_name, &[(i, TrackerOutcome::Success(start.elapsed()))])
                        .await;
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        "query succeeded (single synced BN)"
                    );
                    return Ok(result);
                }
                Err(e) => {
                    self.record_outcomes(op_name, &[(i, error_outcome(op_name, &e))]).await;
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
                    outcomes.push((i, error_outcome(op_name, &e)));
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

        self.record_outcomes(op_name, &outcomes).await;

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
                    self.record_outcomes(op_name, &outcomes).await;
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
                    outcomes.push((i, error_outcome(op_name, &e)));
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

        self.record_outcomes(op_name, &outcomes).await;
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
                    health_outcomes.push((i, error_outcome(op_name, e)));
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
        self.record_outcomes(op_name, &health_outcomes).await;

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

/// Union Indexed failures across BNs so a sibling reject is never cached.
fn merge_builder_preferences_broadcast(
    broadcast: BroadcastResult<SubmitBuilderPreferencesResult>,
) -> Result<SubmitBuilderPreferencesResult, BeaconError> {
    if !broadcast.any_success() {
        return broadcast.into_result();
    }
    let mut by_index: HashMap<u32, String> = HashMap::new();
    for outcome in broadcast.outcomes {
        let Ok(SubmitBuilderPreferencesResult::PartialFailure { failures }) = outcome.result else {
            continue;
        };
        for f in failures {
            by_index.entry(f.index).or_insert(f.message);
        }
    }
    if by_index.is_empty() {
        return Ok(SubmitBuilderPreferencesResult::Success);
    }
    let mut failures: Vec<IndexedFailure> =
        by_index.into_iter().map(|(index, message)| IndexedFailure { index, message }).collect();
    failures.sort_by_key(|f| f.index);
    Ok(SubmitBuilderPreferencesResult::PartialFailure { failures })
}

#[async_trait]
impl NodeStatusApi for BnManager {
    // -- State / Config: query(First), any role, accept SmallLag --

    async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
        // no budget: startup chain identity; OperationTimeouts has no field for it
        self.query_first("get_genesis", BnRole::All, HealthTier::SmallLag, None, |c| {
            Box::pin(c.get_genesis())
        })
        .await
    }

    async fn get_genesis_matching_validators_root(
        &self,
        expected_root_hex: &str,
    ) -> Result<GenesisResponse, BeaconError> {
        // no budget: same startup-style read as get_genesis. A 200 whose
        // validators root is not the configured one must not win the pool.
        let expected = expected_root_hex.to_string();
        let found = self
            .query_first_prefer_some(
                "get_genesis_matching_validators_root",
                BnRole::All,
                HealthTier::SmallLag,
                None,
                move |c| {
                    let expected = expected.clone();
                    Box::pin(async move {
                        let genesis = c.get_genesis().await?;
                        if beacon::hex_ids_equal(&genesis.data.genesis_validators_root, &expected) {
                            Ok(Some(genesis))
                        } else {
                            Ok(None)
                        }
                    })
                },
            )
            .await?;
        found.ok_or_else(|| {
            BeaconError::HttpError(
                "no beacon node returned the configured genesis_validators_root".into(),
            )
        })
    }

    async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        // no budget: startup spec read; OperationTimeouts has no field for it
        self.query_first("get_config_spec", BnRole::All, HealthTier::SmallLag, None, |c| {
            Box::pin(c.get_config_spec())
        })
        .await
    }

    async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        // no budget: startup fork table; OperationTimeouts has no field for it
        self.query_first("get_fork_schedule", BnRole::All, HealthTier::SmallLag, None, |c| {
            Box::pin(c.get_fork_schedule())
        })
        .await
    }

    async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        // no budget: state fork read; OperationTimeouts has no field for it
        self.query_first("get_fork", BnRole::All, HealthTier::SmallLag, None, |c| {
            Box::pin(c.get_fork(state_id))
        })
        .await
    }

    async fn get_validators(&self, pubkeys: &[String]) -> Result<ValidatorsResponse, BeaconError> {
        // no budget: validator registry read; OperationTimeouts has no field for it
        // An empty or non-matching 200 is not the cluster answer: voluntary exit
        // must not sign `data.first()` from the wrong node, and `{"data":[]}`
        // must not hide a later BN. Other endpoints stay on `query_first`.
        if pubkeys.is_empty() {
            return self
                .query_first("get_validators", BnRole::All, HealthTier::SmallLag, None, |c| {
                    Box::pin(c.get_validators(pubkeys))
                })
                .await;
        }
        let requested = pubkeys.to_vec();
        let found = self
            .query_first_prefer_some(
                "get_validators",
                BnRole::All,
                HealthTier::SmallLag,
                None,
                move |c| {
                    let requested = requested.clone();
                    Box::pin(async move {
                        let resp = c.get_validators(&requested).await?;
                        if resp.data.iter().any(|v| {
                            requested
                                .iter()
                                .any(|pk| beacon::hex_ids_equal(&v.validator.pubkey, pk))
                        }) {
                            Ok(Some(resp))
                        } else {
                            Ok(None)
                        }
                    })
                },
            )
            .await?;
        Ok(found.unwrap_or(ValidatorsResponse { data: Vec::new() }))
    }

    // -- Blocks --

    async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        // no budget: block-root lookup; OperationTimeouts has no field for it
        self.query_first("get_block_root", BnRole::All, HealthTier::SmallLag, None, |c| {
            Box::pin(c.get_block_root(block_id))
        })
        .await
    }

    // -- Node status: query(First), any role --

    async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        // no budget: sync probe must not inherit a duty budget; OperationTimeouts has no field for it
        self.query_first("get_node_syncing", BnRole::All, HealthTier::Unsynced, None, |c| {
            Box::pin(c.get_node_syncing())
        })
        .await
    }

    async fn get_node_version(&self) -> Result<String, BeaconError> {
        // no budget: version probe; OperationTimeouts has no field for it
        self.query_first("get_node_version", BnRole::All, HealthTier::Unsynced, None, |c| {
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
        let deadline =
            self.op_timeout(|t| t.duty_fetch).map(|budget| tokio::time::Instant::now() + budget);
        self.query_first(
            "get_attester_duties",
            BnRole::Attestation,
            HealthTier::SmallLag,
            deadline,
            |c| Box::pin(c.get_attester_duties(epoch, validator_indices)),
        )
        .await
    }

    async fn get_proposer_duties(
        &self,
        epoch: u64,
        schedule: &ForkSchedule,
    ) -> Result<ProposerDutiesResponse, BeaconError> {
        let deadline =
            self.op_timeout(|t| t.duty_fetch).map(|budget| tokio::time::Instant::now() + budget);
        self.query_first(
            "get_proposer_duties",
            BnRole::Proposal,
            HealthTier::Synced,
            deadline,
            |c| Box::pin(c.get_proposer_duties(epoch, schedule)),
        )
        .await
    }

    async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        let deadline =
            self.op_timeout(|t| t.duty_fetch).map(|budget| tokio::time::Instant::now() + budget);
        self.query_first(
            "post_sync_committee_duties",
            BnRole::SyncCommittee,
            HealthTier::SmallLag,
            deadline,
            |c| Box::pin(c.post_sync_committee_duties(epoch, validator_indices)),
        )
        .await
    }

    async fn post_ptc_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<PtcDutiesResponse, BeaconError> {
        let deadline =
            self.op_timeout(|t| t.duty_fetch).map(|budget| tokio::time::Instant::now() + budget);
        self.query_first(
            "post_ptc_duties",
            BnRole::Attestation,
            HealthTier::SmallLag,
            deadline,
            |c| Box::pin(c.post_ptc_duties(epoch, validator_indices)),
        )
        .await
    }
}

#[async_trait]
impl BlockProducer for BnManager {
    // -- produce_block_v3: query(Best), Proposal role, require Synced --

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

    async fn produce_block_v4(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        let budget = self.op_timeout(|t| t.block_production);
        self.with_op_timeout(
            "produce_block_v4",
            budget,
            self.query_failover(
                "produce_block_v4",
                BnRole::Proposal,
                HealthTier::Synced,
                budget,
                |c| Box::pin(c.produce_block_v4(slot, randao_reveal, graffiti, builder_config)),
            ),
        )
        .await
    }

    // -- Submissions: broadcast or query_first via submit() helper --

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
        builder_url: Option<&str>,
    ) -> Result<(), BeaconError> {
        self.submit(
            "publish_block",
            self.broadcast_topics.blocks,
            BnRole::Submission,
            HealthTier::LargeLag,
            self.op_timeout(|t| t.block_publication),
            |c| Box::pin(c.publish_block(signed_block, consensus_version, builder_url)),
        )
        .await
    }

    async fn publish_block_contents(
        &self,
        contents: &SignedBlockContentsJson,
        consensus_version: &str,
        builder_url: Option<&str>,
    ) -> Result<(), BeaconError> {
        self.submit(
            "publish_block_contents",
            self.broadcast_topics.blocks,
            BnRole::Submission,
            HealthTier::LargeLag,
            self.op_timeout(|t| t.block_publication),
            |c| Box::pin(c.publish_block_contents(contents, consensus_version, builder_url)),
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
        builder_url: Option<&str>,
    ) -> Result<(), BeaconError> {
        if self.broadcast_topics.blocks {
            self.with_op_timeout(
                "publish_block_ssz",
                self.op_timeout(|t| t.block_publication),
                self.broadcast("publish_block_ssz", BnRole::Submission, |c| {
                    Box::pin(c.publish_block_ssz(
                        ssz_bytes,
                        consensus_version,
                        is_blinded,
                        builder_url,
                    ))
                }),
            )
            .await
        } else {
            let deadline = self
                .op_timeout(|t| t.block_publication)
                .map(|budget| tokio::time::Instant::now() + budget);
            self.query_first(
                "publish_block_ssz",
                BnRole::Submission,
                HealthTier::LargeLag,
                deadline,
                |c| {
                    Box::pin(c.publish_block_ssz(
                        ssz_bytes,
                        consensus_version,
                        is_blinded,
                        builder_url,
                    ))
                },
            )
            .await
        }
    }

    async fn publish_execution_payload_envelope(
        &self,
        signed_envelope: &WireBody,
        blobs: &WireBody,
        kzg_proofs: &WireBody,
        consensus_version: &str,
        broadcast_validation: Option<&str>,
    ) -> Result<(), BeaconError> {
        self.submit(
            "publish_execution_payload_envelope",
            self.broadcast_topics.blocks,
            BnRole::Submission,
            HealthTier::LargeLag,
            self.op_timeout(|t| t.block_publication),
            |c| {
                Box::pin(c.publish_execution_payload_envelope(
                    signed_envelope,
                    blobs,
                    kzg_proofs,
                    consensus_version,
                    broadcast_validation,
                ))
            },
        )
        .await
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

    async fn submit_proposer_preferences(
        &self,
        preferences: &[SignedProposerPreferences],
    ) -> Result<(), BeaconError> {
        self.with_op_timeout(
            "submit_proposer_preferences",
            self.op_timeout(|t| t.preparation),
            self.broadcast("submit_proposer_preferences", BnRole::Proposal, |c| {
                Box::pin(c.submit_proposer_preferences(preferences))
            }),
        )
        .await
    }

    async fn submit_builder_preferences(
        &self,
        entries: &[BuilderPreferencesEntry],
    ) -> Result<SubmitBuilderPreferencesResult, BeaconError> {
        self.with_op_timeout(
            "submit_builder_preferences",
            self.op_timeout(|t| t.preparation),
            async {
                let strategy_span = tracing::info_span!(
                    "bn.strategy.broadcast",
                    strategy = "broadcast",
                    tried = tracing::field::Empty,
                );
                async {
                    let broadcast = self
                        .broadcast_inner(
                            "submit_builder_preferences",
                            BnRole::Proposal,
                            &|c: &BeaconClient| Box::pin(c.submit_builder_preferences(entries)),
                        )
                        .await;
                    Self::log_partial_failure("submit_builder_preferences", &broadcast);
                    if broadcast.outcomes.is_empty() {
                        return Err(BeaconError::NoEligibleBn {
                            operation: "submit_builder_preferences".to_string(),
                            role: BnRole::Proposal.to_string(),
                        });
                    }
                    merge_builder_preferences_broadcast(broadcast)
                }
                .instrument(strategy_span)
                .await
            },
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
        let deadline = self
            .op_timeout(|t| t.attestation_fetch)
            .map(|budget| tokio::time::Instant::now() + budget);
        self.query_first(
            "get_attestation_data",
            BnRole::Attestation,
            HealthTier::SmallLag,
            deadline,
            |c| Box::pin(c.get_attestation_data(slot, committee_index)),
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
            let deadline = self
                .op_timeout(|t| t.attestation_submit)
                .map(|budget| tokio::time::Instant::now() + budget);
            self.query_first(
                "submit_attestation",
                BnRole::Submission,
                HealthTier::LargeLag,
                deadline,
                |c| Box::pin(c.submit_attestation(attestations)),
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
        fork: ForkName,
    ) -> Result<VersionedAggregateAttestation, BeaconError> {
        let deadline = self
            .op_timeout(|t| t.aggregate_fetch)
            .map(|budget| tokio::time::Instant::now() + budget);
        self.query_first(
            "get_aggregate_attestation",
            BnRole::Aggregation,
            HealthTier::SmallLag,
            deadline,
            |c| {
                Box::pin(c.get_aggregate_attestation(
                    slot,
                    attestation_data_root,
                    committee_index,
                    fork,
                ))
            },
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
impl PayloadAttestationApi for BnManager {
    async fn get_payload_attestation_data(
        &self,
        slot: u64,
    ) -> Result<Option<PayloadAttestationDataResponse>, BeaconError> {
        let deadline = self
            .op_timeout(|t| t.attestation_fetch)
            .map(|budget| tokio::time::Instant::now() + budget);
        self.query_first_prefer_some(
            "get_payload_attestation_data",
            BnRole::Attestation,
            HealthTier::SmallLag,
            deadline,
            |c| Box::pin(c.get_payload_attestation_data(slot)),
        )
        .await
    }

    async fn submit_payload_attestations(
        &self,
        messages: &[PayloadAttestationMessage],
    ) -> Result<(), BeaconError> {
        if self.broadcast_topics.attestations {
            self.with_op_timeout(
                "submit_payload_attestations",
                self.op_timeout(|t| t.attestation_submit),
                self.broadcast("submit_payload_attestations", BnRole::Attestation, |c| {
                    Box::pin(c.submit_payload_attestations(messages))
                }),
            )
            .await
        } else {
            let deadline = self
                .op_timeout(|t| t.attestation_submit)
                .map(|budget| tokio::time::Instant::now() + budget);
            self.query_first(
                "submit_payload_attestations",
                BnRole::Submission,
                HealthTier::LargeLag,
                deadline,
                |c| Box::pin(c.submit_payload_attestations(messages)),
            )
            .await
        }
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
        let deadline = self
            .op_timeout(|t| t.sync_contribution)
            .map(|budget| tokio::time::Instant::now() + budget);
        self.query_first(
            "get_sync_committee_contribution",
            BnRole::SyncCommittee,
            HealthTier::SmallLag,
            deadline,
            |c| {
                Box::pin(c.get_sync_committee_contribution(
                    slot,
                    subcommittee_index,
                    beacon_block_root,
                ))
            },
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
        // no budget: doppelganger liveness is off the slot hot path; OperationTimeouts has no field for it
        self.query_first("post_validator_liveness", BnRole::All, HealthTier::SmallLag, None, |c| {
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
        async fn get_genesis_matching_validators_root(
            &self,
            expected_root_hex: &str,
        ) -> Result<GenesisResponse, BeaconError>;
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
        async fn post_ptc_duties(
            &self,
            epoch: u64,
            validator_indices: &[String],
        ) -> Result<PtcDutiesResponse, BeaconError>;
    }
    BlockProducer {
        async fn produce_block_v3(
            &self,
            slot: u64,
            randao_reveal: &str,
            graffiti: Option<&str>,
            builder_boost_factor: Option<u64>,
        ) -> Result<ProduceBlockResponse, BeaconError>;
        async fn produce_block_v4(
            &self,
            slot: u64,
            randao_reveal: &str,
            graffiti: Option<&str>,
            builder_config: &BuilderConfig,
        ) -> Result<ProduceBlockResponse, BeaconError>;
        async fn publish_block(
            &self,
            signed_block: &SignedBeaconBlock,
            consensus_version: &str,
            builder_url: Option<&str>,
        ) -> Result<(), BeaconError>;
        async fn publish_block_contents(
            &self,
            contents: &SignedBlockContentsJson,
            consensus_version: &str,
            builder_url: Option<&str>,
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
            builder_url: Option<&str>,
        ) -> Result<(), BeaconError>;
        async fn publish_execution_payload_envelope(
            &self,
            signed_envelope: &WireBody,
            blobs: &WireBody,
            kzg_proofs: &WireBody,
            consensus_version: &str,
            broadcast_validation: Option<&str>,
        ) -> Result<(), BeaconError>;
        async fn prepare_beacon_proposer(
            &self,
            preparations: &[ProposerPreparation],
        ) -> Result<(), BeaconError>;
        async fn register_validators(
            &self,
            registrations: &[SignedValidatorRegistration],
        ) -> Result<(), BeaconError>;
        async fn submit_proposer_preferences(
            &self,
            preferences: &[SignedProposerPreferences],
        ) -> Result<(), BeaconError>;
        async fn submit_builder_preferences(
            &self,
            entries: &[BuilderPreferencesEntry],
        ) -> Result<SubmitBuilderPreferencesResult, BeaconError>;
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
            fork: ForkName,
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
    PayloadAttestationApi {
        async fn get_payload_attestation_data(
            &self,
            slot: u64,
        ) -> Result<Option<PayloadAttestationDataResponse>, BeaconError>;
        async fn submit_payload_attestations(
            &self,
            messages: &[PayloadAttestationMessage],
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
    use crate::types::bn_capability;

    /// Guard: the passthrough macro list must name every role-trait method.
    /// Primary enforcement is compile-time (missing method → trait not satisfied).
    /// This test documents the expected surface and catches accidental list drift.
    #[test]
    fn test_beacon_client_passthrough_covers_every_trait_method() {
        // Type-level: BeaconClient implements the full supertrait surface.
        fn _assert_full_client<T: BeaconNodeClient>() {}
        _assert_full_client::<BeaconClient>();

        // 36 methods across the seven role traits (see impl_beacon_client_passthrough!).
        assert_eq!(
            BEACON_CLIENT_PASSTHROUGH_METHODS.len(),
            36,
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
            "get_genesis_matching_validators_root",
            "get_attester_duties",
            "post_ptc_duties",
            "produce_block_v3",
            "produce_block_v4",
            "publish_block",
            "publish_block_contents",
            "publish_block_ssz",
            "publish_execution_payload_envelope",
            "submit_proposer_preferences",
            "submit_builder_preferences",
            "submit_attestation",
            "get_payload_attestation_data",
            "submit_payload_attestations",
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

    fn pref_outcome(
        endpoint: &str,
        result: Result<SubmitBuilderPreferencesResult, BeaconError>,
    ) -> BnOutcome<SubmitBuilderPreferencesResult> {
        BnOutcome { endpoint: endpoint.to_string(), result, latency: Duration::from_millis(1) }
    }

    #[test]
    fn test_merge_builder_preferences_unions_indexed_failures() {
        let merged = merge_builder_preferences_broadcast(BroadcastResult {
            outcomes: vec![
                pref_outcome(
                    "http://bn1",
                    Ok(SubmitBuilderPreferencesResult::PartialFailure {
                        failures: vec![IndexedFailure { index: 0, message: "a".into() }],
                    }),
                ),
                pref_outcome(
                    "http://bn2",
                    Ok(SubmitBuilderPreferencesResult::PartialFailure {
                        failures: vec![IndexedFailure { index: 1, message: "b".into() }],
                    }),
                ),
            ],
        })
        .unwrap();
        match merged {
            SubmitBuilderPreferencesResult::PartialFailure { failures } => {
                assert_eq!(failures.iter().map(|f| f.index).collect::<Vec<_>>(), vec![0, 1]);
            }
            other => panic!("expected unioned PartialFailure, got {other:?}"),
        }
    }

    #[test]
    fn test_merge_builder_preferences_never_caches_index_any_bn_failed() {
        let merged = merge_builder_preferences_broadcast(BroadcastResult {
            outcomes: vec![
                pref_outcome("http://bn1", Ok(SubmitBuilderPreferencesResult::Success)),
                pref_outcome(
                    "http://bn2",
                    Ok(SubmitBuilderPreferencesResult::PartialFailure {
                        failures: vec![IndexedFailure { index: 1, message: "reject".into() }],
                    }),
                ),
            ],
        })
        .unwrap();
        match merged {
            SubmitBuilderPreferencesResult::PartialFailure { failures } => {
                assert_eq!(failures.len(), 1);
                assert_eq!(failures[0].index, 1);
            }
            other => panic!("a sibling Indexed reject must remain failed, got {other:?}"),
        }
    }

    #[test]
    fn test_merge_builder_preferences_all_errors_stay_err() {
        let err = merge_builder_preferences_broadcast(BroadcastResult {
            outcomes: vec![pref_outcome("http://bn1", Err(BeaconError::HttpError("down".into())))],
        })
        .unwrap_err();
        assert!(matches!(err, BeaconError::HttpError(_)));
    }

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
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
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
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
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
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: None,
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        };
        assert!(!is_better_block(&a, &b));
    }

    #[test]
    fn test_production_failover_retryable_errors() {
        assert!(is_production_failover_error(&BeaconError::Timeout));
        assert!(is_production_failover_error(&BeaconError::HttpError(
            "connection refused".to_string()
        )));
        assert!(is_production_failover_error(&BeaconError::ApiError {
            status: 500,
            message: "x".to_string(),
        }));
        assert!(is_production_failover_error(&BeaconError::ApiError {
            status: 503,
            message: "x".to_string(),
        }));
        assert!(is_production_failover_error(&BeaconError::OperationTimeout {
            operation: "produce_block_v4".to_string(),
            timeout: Duration::from_millis(1),
        }));
        assert!(!is_production_failover_error(&BeaconError::ApiError {
            status: 400,
            message: "x".to_string(),
        }));
        assert!(
            is_production_failover_error(&BeaconError::ApiError {
                status: 404,
                message: "x".to_string(),
            }),
            "404 is a missing-endpoint gap, not a 4xx the BN understood"
        );
        assert!(is_production_failover_error(&BeaconError::ApiError {
            status: 405,
            message: "x".to_string(),
        }));
        assert!(!is_production_failover_error(&BeaconError::ApiError {
            status: 429,
            message: "x".to_string(),
        }));
        assert!(!is_production_failover_error(&BeaconError::ParseError("bad json".to_string())));
    }

    #[test]
    fn test_capability_endpoint_label_strips_userinfo_and_path() {
        assert_eq!(capability_endpoint_label("http://127.0.0.1:5052"), "http://127.0.0.1:5052");
        assert_eq!(
            capability_endpoint_label("http://user:secret@bn.example:5052/eth/v4"),
            "http://bn.example:5052"
        );
        assert_eq!(capability_endpoint_label("not a url"), "unknown");
        assert_eq!(
            capability_endpoint_label("user:secret@host"),
            "unknown",
            "parse failure (or non-http scheme) must not emit userinfo"
        );
    }

    #[test]
    fn test_capability_labels_are_code_derived() {
        let endpoint = "http://cap-hygiene.example:5052";
        let _mgr = BnManager::new(BnManagerConfig::new(vec![endpoint.to_string()]))
            .expect("valid endpoint");

        let series = crate::metrics::gather_capability_state_series();
        assert!(!series.is_empty(), "rvc_bn_capability_state must emit at least one series");
        for (_ep, cap) in &series {
            assert!(
                bn_capability::ALL.contains(&cap.as_str()),
                "emitted capability {cap:?} is not a member of bn_capability::ALL"
            );
        }
        let caps_for_ep: Vec<&str> =
            series.iter().filter(|(ep, _)| ep == endpoint).map(|(_, cap)| cap.as_str()).collect();
        for expected in bn_capability::ALL {
            assert!(
                caps_for_ep.contains(expected),
                "expected code-derived capability {expected} to be emitted"
            );
        }
    }

    #[test]
    fn test_endpoint_label_carries_no_credentials() {
        let raw = "http://user:s3cretpw@cap-redact.example:5052/eth/v4/validator/blocks?token=abc";
        let expected = "http://cap-redact.example:5052";
        publish_capability(raw, bn_capability::PRODUCE_BLOCK_V4, true);
        publish_capability(raw, bn_capability::FORK_RECOGNISED, true);

        let series = crate::metrics::gather_capability_state_series();
        let ours: Vec<&(String, String)> = series
            .iter()
            .filter(|(ep, _)| ep.contains("cap-redact.example") || ep.contains("s3cretpw"))
            .collect();
        assert!(!ours.is_empty(), "credentialed URL must emit a series; got {series:?}");
        for (ep, cap) in &ours {
            assert_eq!(ep, expected, "endpoint must be scheme://host:port without userinfo");
            assert!(
                bn_capability::ALL.contains(&cap.as_str()),
                "emitted capability {cap:?} is not a member of bn_capability::ALL"
            );
        }
        assert!(
            ours.iter().any(|(_, cap)| cap == bn_capability::PRODUCE_BLOCK_V4),
            "produce_block_v4 must be labelled with the redacted endpoint"
        );
        assert!(
            !series.iter().any(|(ep, _)| ep.as_str() == raw),
            "raw userinfo URL must not be a label"
        );
    }

    #[test]
    fn test_unknown_capability_is_not_emitted() {
        let endpoint = "http://cap-unknown.example:5052";
        let request_derived = "/eth/v4/validator/blocks";
        publish_capability(endpoint, request_derived, false);
        let series = crate::metrics::gather_capability_state_series();
        assert!(
            series.iter().all(|(_, cap)| cap != request_derived),
            "request-derived capability must not be emitted; got {series:?}"
        );
    }

    #[test]
    fn test_v4_capability_gap_classifier() {
        let not_found = BeaconError::ApiError { status: 404, message: "no v4".to_string() };
        assert!(is_v4_capability_gap(bn_capability::PRODUCE_BLOCK_V4, &not_found));
        assert!(!is_v4_capability_gap("get_attester_duties", &not_found));
        assert!(!is_v4_capability_gap(
            bn_capability::PRODUCE_BLOCK_V4,
            &BeaconError::ApiError { status: 400, message: "bad body".to_string() },
        ));
        assert!(is_unrecognised_fork(&BeaconError::ParseError(
            "invalid Eth-Consensus-Version: gloas2".to_string()
        )));
        assert!(!is_unrecognised_fork(&BeaconError::ParseError("bad json".to_string())));
    }

    #[test]
    fn test_split_attempt_timeout_divides_remaining() {
        let remaining = Duration::from_millis(400);
        assert_eq!(split_attempt_timeout(remaining, 2), Duration::from_millis(200));
        assert_eq!(split_attempt_timeout(remaining, 1), remaining);
        // Truncating division that would be zero still spends the remainder.
        assert_eq!(split_attempt_timeout(Duration::from_nanos(2), 3), Duration::from_nanos(2));
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
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        };
        let b = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1000".to_string()),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        };
        assert!(!is_better_block(&a, &b));
    }

    /// BN-1 fails fast, BN-2 hangs past the outer operation budget. The fast
    /// failure must already be on BN-1's tracker when `with_op_timeout` cancels
    /// the rest of the round (the batched `failed` vec used to be dropped).
    #[tokio::test]
    async fn outer_timeout_no_longer_drops_a_recorded_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        let budget = Duration::from_millis(200);

        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/1"))
            .respond_with(ResponseTemplate::new(500).set_body_string("primary down"))
            .expect(1)
            .mount(&bn1)
            .await;
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"{"dependent_root":"0xabc","execution_optimistic":false,"data":[]}"#,
                    )
                    .set_delay(Duration::from_secs(3)),
            )
            .mount(&bn2)
            .await;

        let manager = BnManager::new(BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]))
            .unwrap()
            .with_operation_timeouts(OperationTimeouts {
                duty_fetch: budget,
                ..OperationTimeouts::default()
            });

        let err = manager.get_attester_duties(1, &["1".to_string()]).await.unwrap_err();
        assert!(
            matches!(err, BeaconError::OperationTimeout { ref operation, .. } if operation == "get_attester_duties"),
            "outer with_op_timeout must still fire, got {err:?}"
        );

        let trackers = manager.health_trackers().read().await;
        assert!(
            trackers[0].error_rate() > 0.0,
            "BN-1's fast 500 must be recorded before the outer timeout drops the round; error_rate={}",
            trackers[0].error_rate()
        );
    }

    /// A 400 is not failover-retryable on `query_failover`, but `query_first`
    /// must still reach BN-2.
    #[tokio::test]
    async fn a_400_from_bn1_still_reaches_bn2() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .expect(1)
            .mount(&bn1)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"genesis_time":"1606824999","genesis_validators_root":"0xdef","genesis_fork_version":"0x00000000"}}"#,
            ))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = BnManager::new(BnManagerConfig::new(vec![bn1.uri(), bn2.uri()])).unwrap();
        let result = manager.get_genesis().await.expect("400 must fail over to BN-2");
        assert_eq!(result.data.genesis_time, "1606824999");
        assert_eq!(bn1.received_requests().await.unwrap().len(), 1);
        assert_eq!(bn2.received_requests().await.unwrap().len(), 1);
    }

    /// 204 is not a cluster answer and is not a health success.
    #[tokio::test]
    async fn query_first_prefer_some_204_semantics_are_unchanged() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let root = "11".repeat(32);
        let body = format!(
            r#"{{"data":{{"beacon_block_root":"0x{root}","slot":"7","payload_present":true,"blob_data_available":false}}}}"#
        );

        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/payload_attestation_data"))
            .and(query_param("slot", "7"))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&bn1)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/payload_attestation_data"))
            .and(query_param("slot", "7"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&body))
            .expect(1)
            .mount(&bn2)
            .await;

        let manager = BnManager::new(BnManagerConfig::new(vec![bn1.uri(), bn2.uri()])).unwrap();
        let data = manager
            .get_payload_attestation_data(7)
            .await
            .expect("204 must fail over")
            .expect("peer data is the cluster answer");
        assert!(data.data.payload_present);
        {
            let trackers = manager.health_trackers().read().await;
            assert_eq!(trackers[0].error_rate(), 0.0, "204 must not be recorded as an error");
            assert!(trackers[0].latency_ema_ms().is_none(), "204 must not be recorded as success");
            assert!(trackers[1].latency_ema_ms().is_some(), "BN-2 success must be recorded");
        }

        let only_empty = [MockServer::start().await, MockServer::start().await];
        for server in &only_empty {
            Mock::given(method("GET"))
                .and(path("/eth/v1/validator/payload_attestation_data"))
                .and(query_param("slot", "7"))
                .respond_with(ResponseTemplate::new(204))
                .expect(1)
                .mount(server)
                .await;
        }
        let manager =
            BnManager::new(BnManagerConfig::new(vec![only_empty[0].uri(), only_empty[1].uri()]))
                .unwrap();
        let result = manager.get_payload_attestation_data(7).await.expect("all-204 is Ok(None)");
        assert!(result.is_none());
    }

    #[test]
    fn split_attempt_timeout_is_floored() {
        let n = 8;
        // N = 8 and a small per-BN slice. Twice the floor still divides below it,
        // and the budget can pay the floor.
        let remaining = ATTEMPT_TIMEOUT_FLOOR * 2;
        assert!(remaining > ATTEMPT_TIMEOUT_FLOOR);
        let split = split_attempt_timeout(remaining, n);
        assert!(split < ATTEMPT_TIMEOUT_FLOOR, "raw split {split:?} should be the starvation case");
        assert_eq!(attempt_timeout(remaining, n), Some(ATTEMPT_TIMEOUT_FLOOR));
    }

    #[test]
    fn attempt_timeout_never_exceeds_the_remaining_budget() {
        let floor = ATTEMPT_TIMEOUT_FLOOR;
        let below = floor / 4;
        assert!(!below.is_zero() && below < floor);
        assert_eq!(attempt_timeout(below, 8), Some(below), "remaining < FLOOR yields remaining");
        assert_eq!(attempt_timeout(below, 1), Some(below));

        assert_eq!(attempt_timeout(Duration::ZERO, 1), None);
        assert_eq!(attempt_timeout(Duration::ZERO, 8), None);

        let one_left = floor + Duration::from_millis(25);
        assert_eq!(attempt_timeout(one_left, 1), Some(one_left), "one BN left gets remaining");

        let ample = floor * 8;
        let n = 4;
        let split = split_attempt_timeout(ample, n);
        assert!(split > floor);
        assert_eq!(attempt_timeout(ample, n), Some(split.max(floor)));

        let tight = floor * 2;
        let split_tight = split_attempt_timeout(tight, 8);
        assert!(split_tight < floor);
        assert!(tight > floor);
        let bound = attempt_timeout(tight, 8).unwrap();
        assert_eq!(bound, split_tight.max(floor));
        assert!(bound <= tight);
    }

    #[tokio::test]
    async fn exhausted_deadline_returns_operation_timeout_without_starting_an_attempt() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let bn = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0xabc","genesis_fork_version":"0x00000000"}}"#,
            ))
            .mount(&bn)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/payload_attestation_data"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&bn)
            .await;

        let manager = BnManager::new(BnManagerConfig::new(vec![bn.uri()])).unwrap();
        let past = tokio::time::Instant::now().checked_sub(Duration::from_secs(5)).unwrap();
        let epsilon = Duration::from_millis(50);
        assert!(ATTEMPT_TIMEOUT_FLOOR > epsilon * 3, "a floor-sized sleep must miss this bound");

        let started = std::time::Instant::now();
        let err = manager
            .query_first_inner("get_genesis", BnRole::All, HealthTier::SmallLag, Some(past), &|c| {
                Box::pin(c.get_genesis())
            })
            .await
            .unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            matches!(err, BeaconError::OperationTimeout { ref operation, .. } if operation == "get_genesis"),
            "{err:?}"
        );
        assert!(elapsed <= epsilon, "elapsed {elapsed:?} exceeded {epsilon:?}");

        let started = std::time::Instant::now();
        let err = manager
            .query_first_prefer_some_inner(
                "get_payload_attestation_data",
                BnRole::Attestation,
                HealthTier::SmallLag,
                Some(past),
                &|c| Box::pin(c.get_payload_attestation_data(7)),
            )
            .await
            .unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            matches!(err, BeaconError::OperationTimeout { ref operation, .. } if operation == "get_payload_attestation_data"),
            "{err:?}"
        );
        assert!(elapsed <= epsilon, "elapsed {elapsed:?} exceeded {epsilon:?}");

        assert!(
            bn.received_requests().await.unwrap().is_empty(),
            "exhausted deadline must not send a request"
        );
    }

    /// A 204 from BN-1 must not turn BN-2's deadline expiry into `Ok(None)`.
    #[tokio::test]
    async fn prefer_some_204_then_hang_is_operation_timeout() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        use wiremock::MockServer;

        let epsilon = Duration::from_millis(50);
        let budget = Duration::from_millis(20);
        assert!(ATTEMPT_TIMEOUT_FLOOR.saturating_sub(budget) > epsilon * 3);

        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;
        let primary_ep = primary.uri();
        let secondary_ep = secondary.uri();
        let secondary_started = Arc::new(AtomicBool::new(false));
        let manager =
            BnManager::new(BnManagerConfig::new(vec![primary_ep.clone(), secondary_ep.clone()]))
                .unwrap();

        let flag = Arc::clone(&secondary_started);
        let hang = ATTEMPT_TIMEOUT_FLOOR + Duration::from_millis(500);
        let deadline = tokio::time::Instant::now() + budget;
        let started = std::time::Instant::now();
        let err = manager
            .query_first_prefer_some_inner(
                "get_payload_attestation_data",
                BnRole::Attestation,
                HealthTier::SmallLag,
                Some(deadline),
                &move |c| {
                    let ep = c.endpoint().to_string();
                    let secondary_ep = secondary_ep.clone();
                    let flag = Arc::clone(&flag);
                    Box::pin(async move {
                        let result: Result<Option<()>, BeaconError> = if ep == secondary_ep {
                            flag.store(true, Ordering::SeqCst);
                            tokio::time::sleep(hang).await;
                            Err(BeaconError::HttpError("hung".into()))
                        } else {
                            Ok(None)
                        };
                        result
                    })
                },
            )
            .await
            .unwrap_err();
        let elapsed = started.elapsed();

        assert!(
            matches!(err, BeaconError::OperationTimeout { .. }),
            "204 then hang must stay OperationTimeout, got {err:?}"
        );
        assert!(secondary_started.load(Ordering::SeqCst), "BN-2's attempt must start");
        assert!(
            elapsed <= budget + epsilon,
            "elapsed {elapsed:?} exceeded deadline+ε ({:?}); floor is {:?}",
            budget + epsilon,
            ATTEMPT_TIMEOUT_FLOOR
        );
    }

    /// Budget above the production floor, so a hung primary's slice leaves time
    /// for the secondary. Real elapsed time; the test floor override stays unset.
    #[tokio::test]
    async fn get_payload_attestation_data_hung_primary_secondary_answers() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let budget = Duration::from_millis(600);
        let epsilon = Duration::from_millis(150);
        let hang = Duration::from_secs(2);
        assert!(budget > ATTEMPT_TIMEOUT_FLOOR);
        assert_eq!(current_attempt_floor(), ATTEMPT_TIMEOUT_FLOOR);
        assert!(hang > budget);

        let root = "11".repeat(32);
        let body = format!(
            r#"{{"data":{{"beacon_block_root":"0x{root}","slot":"7","payload_present":true,"blob_data_available":false}}}}"#
        );

        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/payload_attestation_data"))
            .and(query_param("slot", "7"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&body).set_delay(hang))
            .mount(&primary)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/validator/payload_attestation_data"))
            .and(query_param("slot", "7"))
            .respond_with(ResponseTemplate::new(200).set_body_string(&body))
            .expect(1)
            .mount(&secondary)
            .await;

        let manager = BnManager::new(BnManagerConfig::new(vec![primary.uri(), secondary.uri()]))
            .unwrap()
            .with_operation_timeouts(OperationTimeouts {
                attestation_fetch: budget,
                ..OperationTimeouts::default()
            });

        let started = std::time::Instant::now();
        let data = manager
            .get_payload_attestation_data(7)
            .await
            .expect("hung primary must fail over")
            .expect("secondary has payload attestation data");
        let elapsed = started.elapsed();

        assert!(data.data.payload_present);
        assert!(
            !secondary.received_requests().await.unwrap().is_empty(),
            "the healthy secondary must be contacted"
        );
        assert!(
            manager.health_trackers().read().await[0].error_rate() > 0.0,
            "the hung primary must record an error"
        );
        assert!(
            elapsed <= budget + epsilon,
            "elapsed {elapsed:?} exceeded budget+ε ({:?})",
            budget + epsilon
        );
        assert!(elapsed < hang, "elapsed {elapsed:?} waited for the primary hang {hang:?}");
    }

    #[tokio::test]
    async fn remaining_below_floor_bounds_the_whole_operation() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let epsilon = Duration::from_millis(50);
        let budget = Duration::from_millis(20);
        assert!(
            ATTEMPT_TIMEOUT_FLOOR.saturating_sub(budget) > epsilon * 3,
            "FLOOR - remaining must be several times ε"
        );

        let bn = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(
                        r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0xabc","genesis_fork_version":"0x00000000"}}"#,
                    )
                    .set_delay(ATTEMPT_TIMEOUT_FLOOR + Duration::from_millis(500)),
            )
            .mount(&bn)
            .await;

        let manager = BnManager::new(BnManagerConfig::new(vec![bn.uri()])).unwrap();
        let deadline = tokio::time::Instant::now() + budget;
        let started = std::time::Instant::now();
        let err = manager
            .query_first_inner(
                "get_genesis",
                BnRole::All,
                HealthTier::SmallLag,
                Some(deadline),
                &|c| Box::pin(c.get_genesis()),
            )
            .await
            .unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            matches!(err, BeaconError::OperationTimeout { ref operation, .. } if operation == "get_genesis"),
            "{err:?}"
        );
        assert!(
            elapsed <= budget + epsilon,
            "elapsed {elapsed:?} exceeded deadline+ε ({:?}); a bare floor would overshoot by {:?}",
            budget + epsilon,
            ATTEMPT_TIMEOUT_FLOOR.saturating_sub(budget)
        );
    }

    #[tokio::test]
    async fn single_remaining_bn_is_bounded_by_the_deadline() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        use wiremock::MockServer;

        let epsilon = Duration::from_millis(50);
        let budget = Duration::from_millis(20);
        assert!(ATTEMPT_TIMEOUT_FLOOR.saturating_sub(budget) > epsilon * 3);

        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;
        let primary_ep = primary.uri();
        let secondary_ep = secondary.uri();
        let secondary_started = Arc::new(AtomicBool::new(false));
        let manager =
            BnManager::new(BnManagerConfig::new(vec![primary_ep.clone(), secondary_ep.clone()]))
                .unwrap();

        let flag = Arc::clone(&secondary_started);
        let hang = ATTEMPT_TIMEOUT_FLOOR + Duration::from_millis(500);
        let deadline = tokio::time::Instant::now() + budget;
        let started = std::time::Instant::now();
        let err = manager
            .query_first_inner(
                "get_genesis",
                BnRole::All,
                HealthTier::SmallLag,
                Some(deadline),
                &move |c| {
                    let ep = c.endpoint().to_string();
                    let primary_ep = primary_ep.clone();
                    let secondary_ep = secondary_ep.clone();
                    let flag = Arc::clone(&flag);
                    Box::pin(async move {
                        let result: Result<(), BeaconError> = if ep == secondary_ep {
                            flag.store(true, Ordering::SeqCst);
                            tokio::time::sleep(hang).await;
                            Err(BeaconError::HttpError("hung".into()))
                        } else {
                            assert_eq!(ep, primary_ep);
                            Err(BeaconError::ApiError { status: 500, message: "fast".into() })
                        };
                        result
                    })
                },
            )
            .await
            .unwrap_err();
        let elapsed = started.elapsed();

        assert!(
            matches!(err, BeaconError::OperationTimeout { .. }),
            "last BN must end at the deadline, got {err:?}"
        );
        assert!(secondary_started.load(Ordering::SeqCst), "BN-2's attempt must start");
        assert!(
            elapsed <= budget + epsilon,
            "elapsed {elapsed:?} exceeded deadline+ε ({:?}), not deadline+FLOOR ({:?})",
            budget + epsilon,
            budget + ATTEMPT_TIMEOUT_FLOOR
        );
    }

    /// The other two accumulators: a fast failure is on the tracker when the
    /// outer wrapper cancels the hung attempt.
    #[tokio::test]
    async fn eager_recording_on_prefer_some_and_failover_survives_outer_timeout() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let budget = Duration::from_millis(200);
        let hang = Duration::from_secs(3);

        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        for (server, status, delay) in [(&bn1, 500u16, Duration::ZERO), (&bn2, 200, hang)] {
            Mock::given(method("GET"))
                .and(path("/eth/v1/validator/payload_attestation_data"))
                .respond_with(
                    ResponseTemplate::new(status)
                        .set_body_string(if status == 200 {
                            r#"{"data":{"beacon_block_root":"0x11","slot":"7","payload_present":true,"blob_data_available":false}}"#
                        } else {
                            "down"
                        })
                        .set_delay(delay),
                )
                .mount(server)
                .await;
        }
        let manager = BnManager::new(BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]))
            .unwrap()
            .with_operation_timeouts(OperationTimeouts {
                attestation_fetch: budget,
                ..OperationTimeouts::default()
            });
        let err = manager.get_payload_attestation_data(7).await.unwrap_err();
        assert!(matches!(err, BeaconError::OperationTimeout { .. }), "{err:?}");
        assert!(manager.health_trackers().read().await[0].error_rate() > 0.0);

        // Inner budget stays long so BN-2's attempt is cut by the outer wrapper,
        // not by `query_failover`'s own per-attempt timeout (that path records on
        // the way out and would not prove the eager write).
        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        let secondary = bn2.uri();
        let manager =
            BnManager::new(BnManagerConfig::new(vec![bn1.uri(), secondary.clone()])).unwrap();
        let err = manager
            .with_op_timeout(
                "produce_block_v4",
                Some(budget),
                manager.query_failover(
                    "produce_block_v4",
                    BnRole::Proposal,
                    HealthTier::Synced,
                    Some(hang),
                    move |c| {
                        let ep = c.endpoint().to_string();
                        let secondary = secondary.clone();
                        Box::pin(async move {
                            let result: Result<(), BeaconError> = if ep == secondary {
                                tokio::time::sleep(hang).await;
                                Err(BeaconError::Timeout)
                            } else {
                                Err(BeaconError::ApiError { status: 500, message: "fast".into() })
                            };
                            result
                        })
                    },
                ),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, BeaconError::OperationTimeout { .. }), "{err:?}");
        assert!(
            manager.health_trackers().read().await[0].error_rate() > 0.0,
            "produce_block_v4 must record the earlier BN before its outer wrapper cancels the hang"
        );
    }

    const G7_EPSILON: Duration = Duration::from_millis(50);
    const ATTESTER_DUTIES_BODY: &str =
        r#"{"dependent_root":"0xabc","execution_optimistic":false,"data":[]}"#;

    struct AttemptFloorGuard {
        previous: Option<Duration>,
    }

    impl Drop for AttemptFloorGuard {
        fn drop(&mut self) {
            let previous = self.previous;
            TEST_ATTEMPT_FLOOR.with(|slot| slot.set(previous));
        }
    }

    /// Scale the attempt floor for this thread. Production stays at
    /// [`ATTEMPT_TIMEOUT_FLOOR`]; G7(a)/(b) need a floor below a tens-of-ms
    /// split so a hung primary still leaves time for the next BN.
    fn set_attempt_floor_for_test(floor: Duration) -> AttemptFloorGuard {
        AttemptFloorGuard { previous: TEST_ATTEMPT_FLOOR.with(|slot| slot.replace(Some(floor))) }
    }

    fn assert_within_budget(elapsed: Duration, budget: Duration) {
        assert!(
            ATTEMPT_TIMEOUT_FLOOR.saturating_sub(budget) > G7_EPSILON * 3,
            "FLOOR ({ATTEMPT_TIMEOUT_FLOOR:?}) - budget ({budget:?}) must be several times ε ({G7_EPSILON:?})"
        );
        assert!(
            elapsed <= budget + G7_EPSILON,
            "elapsed {elapsed:?} exceeded budget+ε ({:?}); an uncapped floor is {:?}",
            budget + G7_EPSILON,
            ATTEMPT_TIMEOUT_FLOOR
        );
    }

    async fn mount_attester_duties(server: &wiremock::MockServer, delay: Duration) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/duties/attester/1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(ATTESTER_DUTIES_BODY).set_delay(delay),
            )
            .mount(server)
            .await;
    }

    fn attester_manager(endpoints: Vec<String>, budget: Duration) -> BnManager {
        BnManager::new(BnManagerConfig::new(endpoints)).unwrap().with_operation_timeouts(
            OperationTimeouts { duty_fetch: budget, ..OperationTimeouts::default() },
        )
    }

    /// Primary hangs, secondary answers. The primary's health drops and the
    /// secondary is actually contacted. Real elapsed time, budget below the
    /// production floor, test floor small enough that the split still reaches BN-2.
    #[tokio::test(flavor = "current_thread")]
    async fn g7a_primary_hung_secondary_serves_and_primary_is_demoted() {
        use wiremock::MockServer;

        let budget = Duration::from_millis(60);
        let test_floor = Duration::from_millis(8);
        let hang = Duration::from_millis(400);
        assert!(test_floor < budget / 2, "test floor must leave a slice for the secondary");
        assert!(hang > budget);
        let _floor = set_attempt_floor_for_test(test_floor);

        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;
        mount_attester_duties(&primary, hang).await;
        mount_attester_duties(&secondary, Duration::ZERO).await;
        let manager = attester_manager(vec![primary.uri(), secondary.uri()], budget);

        let started = std::time::Instant::now();
        let duties =
            manager.get_attester_duties(1, &["1".to_string()]).await.expect("secondary must serve");
        let elapsed = started.elapsed();
        assert!(duties.data.is_empty());
        assert_within_budget(elapsed, budget);
        assert!(
            !secondary.received_requests().await.unwrap().is_empty(),
            "at least one request must reach the secondary"
        );

        let trackers = manager.health_trackers().read().await;
        assert!(trackers[0].error_rate() > 0.0, "hung primary must record an error");
        assert!(!trackers[0].is_healthy(), "primary must drop below the healthy threshold");
        assert!(
            trackers[0].score() < trackers[1].score(),
            "primary score {} must be demoted below secondary {}",
            trackers[0].score(),
            trackers[1].score()
        );
    }

    /// Every hung BN is attempted and records an error, and the call still
    /// ends by the absolute deadline rather than the production floor.
    #[tokio::test(flavor = "current_thread")]
    async fn g7b_all_bns_hung_returns_operation_timeout_and_every_tracker_records_an_error() {
        use wiremock::MockServer;

        let budget = Duration::from_millis(60);
        let test_floor = Duration::from_millis(8);
        let hang = Duration::from_millis(400);
        assert!(test_floor < budget / 2);
        let _floor = set_attempt_floor_for_test(test_floor);

        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        mount_attester_duties(&bn1, hang).await;
        mount_attester_duties(&bn2, hang).await;
        let manager = attester_manager(vec![bn1.uri(), bn2.uri()], budget);

        let started = std::time::Instant::now();
        let err = manager.get_attester_duties(1, &["1".to_string()]).await.unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            matches!(err, BeaconError::OperationTimeout { ref operation, .. } if operation == "get_attester_duties"),
            "{err:?}"
        );
        assert_within_budget(elapsed, budget);

        let trackers = manager.health_trackers().read().await;
        assert_eq!(trackers.len(), 2);
        for (i, tracker) in trackers.iter().enumerate() {
            assert!(tracker.error_rate() > 0.0, "BN {i} must record the hang");
        }
    }

    /// One hung BN is bounded by the caller's budget, not the production floor,
    /// and that single error drops it below the healthy threshold.
    #[tokio::test(flavor = "current_thread")]
    async fn g7c_single_bn_hung_drops_its_tier() {
        use wiremock::MockServer;

        let budget = Duration::from_millis(40);
        let hang = Duration::from_millis(400);
        assert!(hang > ATTEMPT_TIMEOUT_FLOOR, "hang must outlast an uncapped floor");

        let bn = MockServer::start().await;
        mount_attester_duties(&bn, hang).await;
        let manager = attester_manager(vec![bn.uri()], budget);
        assert!(manager.health_trackers().read().await[0].is_healthy());

        let started = std::time::Instant::now();
        let err = manager.get_attester_duties(1, &["1".to_string()]).await.unwrap_err();
        let elapsed = started.elapsed();
        assert!(
            matches!(err, BeaconError::OperationTimeout { ref operation, .. } if operation == "get_attester_duties"),
            "{err:?}"
        );
        assert_within_budget(elapsed, budget);

        let trackers = manager.health_trackers().read().await;
        assert!(trackers[0].error_rate() > 0.0, "the hung BN must record an error");
        assert!(
            !trackers[0].is_healthy(),
            "a single hang must drop the BN below the healthy threshold"
        );
        assert!(trackers[0].score() < 0.8, "score must fall from the no-sample baseline");
    }

    #[test]
    fn retained_with_op_timeout_does_not_enclose_query_first() {
        let src = include_str!("manager.rs");
        let production = src.split("#[cfg(test)]\nmod tests {").next().expect("test module");
        let calls = with_op_timeout_calls(production);
        assert_eq!(
            calls.len(),
            12,
            "expected the broadcast arm, query_best, query_failover, and nine broadcast wrappers"
        );
        for call in &calls {
            assert!(
                !call.contains("query_first"),
                "with_op_timeout must not enclose query_first or query_first_prefer_some:\n{call}"
            );
        }
        assert_eq!(production.matches("// no budget:").count(), 9);
        assert_eq!(
            production.matches("tokio::time::Instant::now() + budget").count(),
            12,
            "each converted site takes an absolute deadline before it awaits"
        );
    }

    fn with_op_timeout_calls(src: &str) -> Vec<&str> {
        let mut calls = Vec::new();
        let mut rest = src;
        let needle = "with_op_timeout(";
        while let Some(idx) = rest.find(needle) {
            let args_and_rest = &rest[idx + "with_op_timeout".len()..];
            let end = balanced_paren_end(args_and_rest);
            calls.push(&args_and_rest[..=end]);
            rest = &args_and_rest[end + 1..];
        }
        calls
    }

    fn balanced_paren_end(src: &str) -> usize {
        let bytes = src.as_bytes();
        assert_eq!(bytes.first().copied(), Some(b'('), "with_op_timeout call must open with '('");
        let mut depth = 0i32;
        for (i, &byte) in bytes.iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return i;
                    }
                }
                _ => {}
            }
        }
        panic!("unbalanced with_op_timeout call");
    }

    fn sample_block_contents() -> SignedBlockContentsJson {
        SignedBlockContentsJson {
            signed_block: eth_types::signed_block_contents_json::SignedBeaconBlockJson {
                message: eth_types::signed_block_contents_json::BeaconBlockJson {
                    slot: 1,
                    proposer_index: 0,
                    parent_root: [1u8; 32],
                    state_root: [2u8; 32],
                    body: serde_json::json!({"randao_reveal": "0x01"}),
                },
                signature: vec![0xaa; 96],
            },
            kzg_proofs: vec![vec![0x11; 48]],
            blobs: vec![vec![0x22; 8]],
        }
    }

    #[tokio::test]
    async fn publish_block_contents_broadcasts_when_the_blocks_topic_is_enabled() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let bn1 = MockServer::start().await;
        let bn2 = MockServer::start().await;
        for bn in [&bn1, &bn2] {
            Mock::given(method("POST"))
                .and(path("/eth/v2/beacon/blocks"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(bn)
                .await;
        }
        let mut config = BnManagerConfig::new(vec![bn1.uri(), bn2.uri()]);
        config.broadcast_topics.blocks = true;
        let manager = BnManager::new(config).expect("BnManager");
        manager
            .publish_block_contents(&sample_block_contents(), "electra", None)
            .await
            .expect("broadcast publish_block_contents");
        assert_eq!(bn1.received_requests().await.unwrap().len(), 1);
        assert_eq!(bn2.received_requests().await.unwrap().len(), 1);
    }

    /// Hanging BN, blocks topic off so `query_first` owns the deadline.
    /// Real time: budget + the RR-1.3 ε, not `tokio::time::pause`.
    #[tokio::test(flavor = "current_thread")]
    async fn publish_block_contents_uses_the_block_publication_timeout() {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let budget = Duration::from_millis(40);
        let epsilon = Duration::from_millis(50);
        let hang = Duration::from_millis(400);
        assert!(hang > ATTEMPT_TIMEOUT_FLOOR, "hang must outlast an uncapped floor");
        assert!(
            ATTEMPT_TIMEOUT_FLOOR.saturating_sub(budget) > epsilon * 3,
            "FLOOR ({ATTEMPT_TIMEOUT_FLOOR:?}) - budget ({budget:?}) must be several times ε ({epsilon:?})"
        );

        let bn = MockServer::start().await;
        Mock::given(any())
            .respond_with(ResponseTemplate::new(200).set_body_string("{}").set_delay(hang))
            .mount(&bn)
            .await;

        let mut config = BnManagerConfig::new(vec![bn.uri()]);
        config.broadcast_topics.blocks = false;
        let manager =
            BnManager::new(config).expect("BnManager").with_operation_timeouts(OperationTimeouts {
                block_publication: budget,
                ..OperationTimeouts::default()
            });

        let started = std::time::Instant::now();
        let err = manager
            .publish_block_contents(&sample_block_contents(), "electra", None)
            .await
            .expect_err("hanging BN must time out");
        let elapsed = started.elapsed();
        assert!(
            matches!(
                err,
                BeaconError::OperationTimeout { ref operation, .. } if operation == "publish_block_contents"
            ),
            "{err:?}"
        );
        assert!(
            elapsed <= budget + epsilon,
            "elapsed {elapsed:?} exceeded block_publication budget+ε ({:?})",
            budget + epsilon
        );
    }
}
