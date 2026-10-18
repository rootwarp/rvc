use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use beacon::{
    block_value, AttestationDataResponse, AttesterDutiesResponse, BeaconClient,
    BeaconCommitteeSubscription, BeaconError, BlockHeaderSummary, BlockRootResponse, BuilderConfig,
    BuilderPreferencesEntry, ConfigSpecResponse, GenesisResponse, IndexedFailure,
    PayloadAttestationDataResponse, ProduceBlockResponse, ProposerDutiesResponse,
    ProposerPreparation, PtcDutiesResponse, RankedBlock, SignedContributionAndProof,
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
use tracing::Instrument;
use tracing::{debug, error, warn};
use url::Url;

use observability::logging::RedactedUrl;

use crate::sync_status::BnSyncStatus;

use crate::broadcast::BroadcastResult;
use crate::fan_out::{self, BnAttempt};
use crate::health::{new_shared_health_trackers, BnHealthTracker, SharedHealthTrackers};
use crate::sse::{self, SseConfig, SseEvent};
use crate::sync_status::{
    check_all_sync_statuses, new_shared_sync_statuses, start_sync_monitor, AfterSyncPoll,
    SharedSyncStatuses,
};
use crate::traits::{
    AttestationApi, BeaconNodeClient, BlockProducer, BnHealthScore, BnManagerConfig,
    DutiesProvider, FeeRecipientPolicy, LivenessApi, NodeStatusApi, OperationTimeouts,
    PayloadAttestationApi, ProduceDuty, SyncCommitteeApi,
};
use crate::types::{bn_capability, BnRole, HealthTier, TierThresholds};
use crate::BnManagerError;

pub(crate) type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, BeaconError>> + Send + 'a>>;

/// Health-tracker outcome for one BN attempt (success with latency, or error).
#[derive(Debug, Clone, Copy)]
pub(crate) enum TrackerOutcome {
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

pub(crate) fn error_outcome(op_name: &str, err: &BeaconError) -> TrackerOutcome {
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

fn publish_capability(endpoint: &str, capability: &str, capable: bool) {
    #[cfg(not(test))]
    debug_assert!(
        bn_capability::ALL.contains(&capability),
        "capability label `{capability}` is not in bn_capability::ALL"
    );
    if !bn_capability::ALL.contains(&capability) {
        return;
    }
    let endpoint_label = crate::metrics::endpoint_label(endpoint);
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
pub(crate) async fn await_attempt<T>(
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
/// - **Best-of**: query role-matching synced BNs in parallel and pick the
///   highest strictly parsed execution payload value plus consensus block
///   value — `produce_block_v3`. With a block-production budget, accepted
///   blocks in hand are returned at the soft deadline (half the budget). A
///   block that fails the slot, proposer, or parent check is not in hand. If
///   none have been accepted, the first accepted block before the hard
///   deadline (the budget) is kept. The round also returns once every
///   selected BN has answered. Attempts still running are drained, and a
///   timeout is recorded as an error. Health recording is queued and does not
///   block the return or the drain. Nothing accepted, or every selected BN
///   failed, falls back only to untried proposal-role BNs above the health
///   floor, and only when the expected parent root is known, inside the time
///   left in the backstop (budget plus 250 ms). The outer timeout is that
///   backstop. A zero budget is no budget. With no budget, the round waits
///   for every BN.
/// - **Failover**: sequential, one in-flight; retry connect / timeout / 5xx only —
///   `produce_block_v4` (D29). Never after a 2xx, never in parallel. 404/405/501
///   are a capability gap (missing `/eth/v4`) and do fail over; a later success
///   re-probes. All-incapable is `NoEligibleBn`, never V3.
/// - **Broadcast**: send to **role-matching** BNs (subject to `BroadcastTopics`),
///   return on the first complete `Ok` — attestations, blocks, sync committee
///   messages, subscriptions, preparations, validator registrations. A partial
///   attestation acceptance waits for a full acceptance from another node
///   until the caller deadline or the attempts finish. The best partial seen
///   so far is kept when that deadline wins. The caller returns 50 ms early
///   so that result wins the race against the outer timeout; if the timeout
///   still wins, its error path keeps the same partial. Once any node has
///   accepted, the remaining publishes run on a detached task, so cancelling
///   the caller does not cancel them. Each attempt is bounded by that operation's
///   budget; attempts still running are drained. At most 16 drains record
///   health at once. That cap limits health recording, not sends. A full pool
///   still finishes every remaining publish. Those overflow drains end at the
///   attempt budget, or at the HTTP client timeout when no budget is set.
///   The overflow gauge drops when the HTTP call finishes. Only a success
///   health sample is skipped when the pool is full; an error or a timeout
///   is still recorded when the recorder queue has room. A sample that does
///   not fit on that queue is counted and dropped, including an error or a
///   timeout, and the attempt does not wait. The skip is logged and counted.
///   With no budget configured, attempts stay unbounded up to that HTTP
///   timeout. The
///   outer timeout is only a backstop at the budget plus 250 ms. Role filter
///   only; health **tier is not applied** and unhealthy role-matching peers
///   are not dropped (a lagging / previously-erroring BN still gossips).
///   `All`-role fallback is shared with the query path. An empty role+All
///   selection is `BeaconError::NoEligibleBn` — never off-role fan-out, never
///   Ok. Liveness and builder-preference merges wait for every BN.
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
    fee_recipient_policy: FeeRecipientPolicy,
    /// `true` until boot skips the node. Duties and liveness ignore `false`
    /// until the node matches the boot chain.
    admitted: Arc<Vec<AtomicBool>>,
    /// Identity from the beacon nodes that completed spec and genesis.
    chain_identity: Arc<tokio::sync::RwLock<Option<AgreedChain>>>,
}

/// Apply health-tracker updates. Each call takes the write lock once.
///
/// Sequential strategies flush per attempt so cancellation cannot drop
/// earlier failures. Best-of, its drain, and the proposal fallback queue
/// samples and do not wait on this lock. A broadcast attempt queues this
/// when it finishes and does not wait on the queue. When the queue is full,
/// an error or a timeout sample can be dropped, and that drop is counted.
/// Cancelling the caller does not drop a sample
/// already queued. Process shutdown drops the recorder, so a queued sample
/// is not kept. A full health-sample pool skips a success that is still in
/// flight. An error or a timeout is still recorded when the queue has room.
pub(crate) async fn record_outcomes(
    health_trackers: &SharedHealthTrackers,
    op_name: &str,
    outcomes: &[(usize, TrackerOutcome)],
) {
    if outcomes.is_empty() {
        return;
    }
    let observe_latency = crate::metrics::is_proposer_block_production_op(op_name);
    let mut trackers = health_trackers.write().await;
    for &(idx, outcome) in outcomes {
        match outcome {
            TrackerOutcome::Success(latency) => {
                if observe_latency {
                    crate::metrics::observe_proposer_bn_latency(trackers[idx].endpoint(), latency);
                }
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

/// Log a partial broadcast failure, including failures the drain records
/// after the first `Ok` has already been returned.
pub(crate) fn log_partial_failure_endpoints(
    op_name: &str,
    successes: usize,
    failures: &[(String, Duration)],
) {
    if successes == 0 || failures.is_empty() {
        return;
    }
    let failed_endpoints: Vec<String> =
        failures.iter().map(|(endpoint, _)| RedactedUrl(endpoint).to_string()).collect();
    let failed_latency_ms: Vec<u64> =
        failures.iter().map(|(_, latency)| latency.as_millis() as u64).collect();
    warn!(
        op = op_name,
        successes,
        failures = failures.len(),
        failed_endpoints = ?failed_endpoints,
        failed_latency_ms = ?failed_latency_ms,
        "partial broadcast failure"
    );
}

type Pred<T> = Arc<dyn Fn(&T) -> bool + Send + Sync>;
type Rank<T> = Arc<dyn Fn(&T, &T) -> bool + Send + Sync>;
type RejectFn<T> = Arc<dyn Fn(usize, &str, &T) + Send + Sync>;
type ChosenFn<T> = Arc<dyn Fn(usize, &T) + Send + Sync>;

/// Ranking predicate, pre-rank filter, and whether fallback may run.
struct BestSelect<T> {
    pick_best: Rank<T>,
    /// Hard checks. `false` is dropped.
    accept: Pred<T>,
    /// Fallback hard checks. The re-org parent fails this even when [`Self::accept`] allows it.
    fallback_accept: Pred<T>,
    /// Hard checks, the right fee, and the primary parent. Closes the soft window.
    in_hand: Pred<T>,
    /// Called once for each `Ok` that fails [`Self::accept`], including on the drain.
    on_reject: RejectFn<T>,
    /// Called once for the head of the ranked list.
    ///
    /// The fee-penalty warning is not emitted here. Block proposal emits it
    /// for the candidate that is signed.
    on_chosen: ChosenFn<T>,
    allow_fallback: bool,
}

/// Return a held block this long before the outer backstop.
///
/// [`BnManager::with_op_timeout`] uses that same backstop. Waiting until the
/// instant itself drops the held block as `OperationTimeout`.
const HELD_RETURN_MARGIN: Duration = Duration::from_millis(50);

/// A budget `tokio::time::timeout` can add to `now`, including the 250 ms backstop.
///
/// `u64::MAX` seconds cannot. That budget is already due, so the call returns
/// instead of panicking inside `Instant + Duration`.
fn representable_budget(budget: Duration) -> Duration {
    let now = tokio::time::Instant::now();
    let padded = budget.saturating_add(fan_out::BACKSTOP_MARGIN);
    if now.checked_add(padded).is_some() {
        budget
    } else {
        Duration::ZERO
    }
}

fn checked_deadline(start: tokio::time::Instant, budget: Duration) -> tokio::time::Instant {
    start.checked_add(budget).unwrap_or(start)
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
        let admitted = Arc::new((0..clients.len()).map(|_| AtomicBool::new(true)).collect());
        Ok(Self {
            clients,
            sync_statuses,
            health_trackers,
            operation_timeouts: None,
            broadcast_topics,
            roles,
            tier_thresholds,
            fee_recipient_policy: config.fee_recipient_policy,
            admitted,
            chain_identity: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    /// Override [`FeeRecipientPolicy`]. Tests and the config builder use this
    /// after [`Self::new`].
    pub fn with_fee_recipient_policy(mut self, policy: FeeRecipientPolicy) -> Self {
        self.fee_recipient_policy = policy;
        self
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
    /// before their first await and bound each BN attempt inside it. Broadcast
    /// bounds each BN attempt at the same budget and returns on the first `Ok`;
    /// the outer timeout is a backstop at that budget plus 250 ms. Best-of
    /// block production uses the same backstop: each attempt is bounded by the
    /// budget, blocks in hand return at half that budget, and a miss falls
    /// back inside the remaining margin. With no budget configured, attempts
    /// stay unbounded. `produce_block_v4` keeps an outer `tokio::time::timeout`
    /// at the budget. Exceeding the budget returns `BeaconError::OperationTimeout`.
    pub fn with_operation_timeouts(mut self, timeouts: OperationTimeouts) -> Self {
        self.operation_timeouts = Some(timeouts);
        self
    }

    /// Returns the budgets stored by [`Self::with_operation_timeouts`].
    ///
    /// `None` means [`Self::with_operation_timeouts`] was not called. A stored
    /// zero duration is returned as zero. Call sites that bound an attempt
    /// still treat zero as no budget.
    pub fn operation_timeouts(&self) -> Option<&OperationTimeouts> {
        self.operation_timeouts.as_ref()
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
    ///
    /// A zero duration is not a budget. Configuration rejects zero, but
    /// [`OperationTimeouts`] is a public struct and can still carry it. Treating
    /// zero as "no budget" keeps the synced pool from timing out immediately
    /// and leaving only the fallback window. This budget is not a slot
    /// deadline. Proposer-pool block production passes its slot end into
    /// [`Self::production_budget`]. Attestation, sync, aggregate, duty fetch,
    /// and publication keep the duration selected here.
    fn op_timeout(&self, f: impl FnOnce(&OperationTimeouts) -> Duration) -> Option<Duration> {
        self.operation_timeouts
            .as_ref()
            .map(f)
            .filter(|budget| !budget.is_zero())
            .map(representable_budget)
    }

    /// Block-production budget, capped at a per-call deadline when one is set.
    ///
    /// `None` is the configured `block_production` budget. A deadline is the
    /// end of the proposal slot and applies only to the produce call that
    /// received it. A later call does not see it.
    fn production_budget(&self, deadline: Option<tokio::time::Instant>) -> Option<Duration> {
        let configured = self.op_timeout(|t| t.block_production);
        let Some(deadline) = deadline else {
            return configured;
        };
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        let budget = configured.unwrap_or(remaining).min(remaining);
        Some(representable_budget(budget))
    }

    /// Dispatch a submission via broadcast or query_first based on the topic flag.
    ///
    /// Encapsulates the repeated `if broadcast_topics.X { broadcast } else { query_first }`
    /// branch. The broadcast arm keeps [`Self::with_op_timeout`] as a backstop at
    /// the budget plus 250 ms. The query_first arm takes an absolute deadline
    /// from `timeout` before it awaits (ADR-R03). `op` clones the client and
    /// payload into a `'static` future so both arms can share it.
    async fn submit<T, F>(
        &self,
        op_name: &str,
        topic_enabled: bool,
        role: BnRole,
        min_tier: HealthTier,
        timeout: Option<Duration>,
        op: F,
    ) -> Result<T, BeaconError>
    where
        T: Clone + Send + 'static,
        F: Fn(&BeaconClient) -> BoxFut<'static, T>,
    {
        if topic_enabled {
            self.with_op_timeout(
                op_name,
                fan_out::broadcast_backstop(timeout),
                self.broadcast_with_result(op_name, role, timeout, op),
            )
            .await
        } else {
            let deadline =
                timeout.map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
            self.query_first(op_name, role, min_tier, deadline, |client| op(client)).await
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
    ///
    /// Updates `rvc_bn_health_tier` for each endpoint from the polled sync detail.
    #[tracing::instrument(name = "bn_manager.check_sync_status", skip_all)]
    pub async fn check_sync_status(&self) {
        check_all_sync_statuses(&self.clients, &self.sync_statuses, &self.tier_thresholds).await;
        // A syncing recovery does not admit a node boot skipped. The identity
        // check does, and only after this poll shows the node is reachable.
        admit_reachable_clients(
            &self.clients,
            &self.sync_statuses,
            &self.admitted,
            &self.chain_identity,
        )
        .await;
    }

    /// Starts a background task that periodically polls sync status.
    ///
    /// Uses the default interval of one epoch (~384 seconds) if `interval` is None.
    /// Each poll refreshes `rvc_bn_health_tier` (DSR-2.2).
    pub fn start_sync_monitor(
        &self,
        interval: Option<Duration>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        let interval = interval.unwrap_or(DEFAULT_SYNC_CHECK_INTERVAL);
        let clients = self.clients.clone();
        let statuses = Arc::clone(&self.sync_statuses);
        let admitted = Arc::clone(&self.admitted);
        let identity = Arc::clone(&self.chain_identity);
        let after_poll: AfterSyncPoll = Arc::new(move || {
            let clients = clients.clone();
            let statuses = Arc::clone(&statuses);
            let admitted = Arc::clone(&admitted);
            let identity = Arc::clone(&identity);
            Box::pin(async move {
                admit_reachable_clients(&clients, &statuses, &admitted, &identity).await;
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        });
        start_sync_monitor(
            self.clients.clone(),
            self.sync_statuses.clone(),
            self.tier_thresholds.clone(),
            interval,
            shutdown,
            Some(after_poll),
        )
    }

    /// Returns the endpoint URL of the first (primary) client.
    #[cfg(test)]
    fn primary_endpoint(&self) -> &str {
        self.clients[0].endpoint()
    }

    /// Starts SSE event subscription on admitted beacon nodes.
    ///
    /// An unadmitted node is not connected, so its head and reorg events are
    /// not delivered. Once it is admitted, a later pass may connect.
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
        let admitted = Arc::clone(&self.admitted);
        tokio::spawn(async move {
            sse::subscribe_events_admitted(configs, admitted, callback, shutdown).await;
        })
    }

    /// Role match, then `All`-role fallback. Does **not** fall back to every client.
    /// Shared by query (`synced_indices`) and broadcast so All-fallback is one path.
    fn is_admitted(&self, index: usize) -> bool {
        self.admitted.get(index).is_some_and(|flag| flag.load(Ordering::Acquire))
    }

    fn mark_unadmitted(&self, index: usize) {
        if let Some(flag) = self.admitted.get(index) {
            flag.store(false, Ordering::Release);
        }
    }

    /// Role match among admitted beacon nodes, then `All`-role fallback.
    ///
    /// Does not fall back to an unadmitted node. An empty result fails closed.
    fn role_matching_indices(&self, role: BnRole) -> Vec<usize> {
        let matched: Vec<usize> = (0..self.clients.len())
            .filter(|&i| self.is_admitted(i) && BnRole::matches(&self.roles[i], role))
            .collect();
        if !matched.is_empty() {
            return matched;
        }
        warn!(
            role = %role,
            "no admitted BNs assigned for role, falling back to admitted all-role BNs"
        );
        (0..self.clients.len())
            .filter(|&i| self.is_admitted(i) && self.roles[i].contains(&BnRole::All))
            .collect()
    }

    /// Returns indices of BNs matching the given role and meeting the minimum health tier,
    /// ordered by health score (highest first).
    ///
    /// Filtering order: role → tier → capability → health score.
    ///
    /// Fallback chain:
    /// 1. If no BNs match the role, fall back to `All`-role BNs with WARN
    /// 2. If no BNs meet the tier, try the next lower tier with WARN
    /// 3. If still empty, fall back to every admitted BN (query path only)
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

        // If still empty after role fallback, use every admitted BN.
        // Unadmitted nodes stay out: a syncing recovery is not chain identity.
        let role_indices = if role_indices.is_empty() {
            warn!("no admitted BNs with All role either, falling back to all admitted BNs");
            (0..self.clients.len()).filter(|&i| self.is_admitted(i)).collect()
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
        self.query_first_attributed(op_name, role, min_tier, deadline, op)
            .await
            .map(|(_endpoint, value)| value)
    }

    /// [`Self::query_first`] plus the endpoint of the beacon node that answered.
    async fn query_first_attributed<'s, T, F>(
        &'s self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        deadline: Option<tokio::time::Instant>,
        op: F,
    ) -> Result<(String, T), BeaconError>
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
    ) -> Result<(String, T), BeaconError>
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
                    record_outcomes(
                        &self.health_trackers,
                        op_name,
                        &[(i, TrackerOutcome::Success(elapsed))],
                    )
                    .await;
                    debug!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        latency_ms = elapsed.as_millis() as u64,
                        "query succeeded"
                    );
                    tracing::Span::current().record("tried", tried);
                    return Ok((client.endpoint().to_string(), result));
                }
                Err(e) => {
                    record_outcomes(
                        &self.health_trackers,
                        op_name,
                        &[(i, error_outcome(op_name, &e))],
                    )
                    .await;
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
                    record_outcomes(
                        &self.health_trackers,
                        op_name,
                        &[(i, TrackerOutcome::Success(elapsed))],
                    )
                    .await;
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
                    record_outcomes(
                        &self.health_trackers,
                        op_name,
                        &[(i, error_outcome(op_name, &e))],
                    )
                    .await;
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

        let deadline = budget.map(|d| (checked_deadline(tokio::time::Instant::now(), d), d));
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
                    record_outcomes(
                        &self.health_trackers,
                        op_name,
                        &[(i, TrackerOutcome::Success(elapsed))],
                    )
                    .await;
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
                    record_outcomes(&self.health_trackers, op_name, &[(i, outcome)]).await;
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

    /// Query synced BNs in parallel and keep the best result.
    ///
    /// `pick_best` returns `true` when its first argument is better. `budget`
    /// is the hard deadline; the soft deadline is half of that. `None` waits
    /// for every selected BN. Every candidate is accepted, and fallback is on.
    /// That fallback is untried proposal-role BNs above [`FALLBACK_TIER_FLOOR`].
    /// After a hard-deadline miss it is bounded by the time left before the
    /// budget plus 250 ms.
    #[cfg(test)]
    async fn query_best<T, F>(
        &self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        budget: Option<Duration>,
        op: F,
        pick_best: fn(&T, &T) -> bool,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&BeaconClient) -> BoxFut<'static, T>,
    {
        let accept: Pred<T> = Arc::new(|_: &T| true);
        let op_label = op_name.to_owned();
        let on_reject: RejectFn<T> = Arc::new(move |index, endpoint, _: &T| {
            warn!(
                op = %op_label,
                bn_index = index,
                endpoint = %RedactedUrl(endpoint),
                "best-of candidate rejected"
            );
        });
        self.query_best_filtered(
            op_name,
            role,
            min_tier,
            budget,
            op,
            BestSelect {
                pick_best: Arc::new(pick_best),
                in_hand: Arc::clone(&accept),
                fallback_accept: Arc::clone(&accept),
                accept,
                on_reject,
                on_chosen: Arc::new(|_, _| {}),
                allow_fallback: true,
            },
        )
        .await
    }

    #[cfg(test)]
    async fn query_best_filtered<T, F>(
        &self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        budget: Option<Duration>,
        op: F,
        select: BestSelect<T>,
    ) -> Result<T, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&BeaconClient) -> BoxFut<'static, T>,
    {
        let strategy_span = tracing::info_span!(
            "bn.strategy.best",
            strategy = "best",
            tried = tracing::field::Empty,
        );
        let ranked = self
            .query_best_inner(op_name, role, min_tier, budget, &op, select)
            .instrument(strategy_span)
            .await?;
        ranked.into_iter().next().map(|(_, value)| value).ok_or_else(|| {
            BeaconError::HttpError(format!("{op_name}: all BNs failed in best-selection"))
        })
    }

    async fn query_best_inner<T, F>(
        &self,
        op_name: &str,
        role: BnRole,
        min_tier: HealthTier,
        budget: Option<Duration>,
        op: &F,
        select: BestSelect<T>,
    ) -> Result<Vec<(usize, T)>, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&BeaconClient) -> BoxFut<'static, T>,
    {
        let indices = self.synced_indices(role, min_tier, op_name).await;
        tracing::Span::current().record("tried", indices.len());
        if indices.is_empty() {
            return Err(no_eligible_bn(op_name, role));
        }

        let started = tokio::time::Instant::now();
        let backstop = budget.map(|budget| {
            checked_deadline(started, budget.saturating_add(fan_out::BACKSTOP_MARGIN))
        });
        let attempts = indices
            .iter()
            .map(|&index| {
                let client = &self.clients[index];
                BnAttempt { index, endpoint: client.endpoint().to_string(), fut: op(client) }
            })
            .collect();
        let round = fan_out::best_of(
            op_name,
            &role.to_string(),
            attempts,
            fan_out::BestWindow { soft: budget.map(fan_out::soft_deadline), hard: budget },
            &self.health_trackers,
            fan_out::global_drain_pool(),
            &fan_out::BestFilter {
                accept: Arc::clone(&select.accept),
                in_hand: Arc::clone(&select.in_hand),
                on_reject: Arc::clone(&select.on_reject),
            },
        )
        .await?;

        let mut arrived = round.values;
        let mut held = round.held;
        if arrived.is_empty() && select.allow_fallback {
            match self
                .fallback_unsynced(
                    op_name,
                    role,
                    op,
                    &indices,
                    FallbackWindow { deadline: backstop, already_held: !held.is_empty() },
                    &select,
                )
                .await
            {
                Some(FallbackPick::Ready(index, value)) => held.push((index, value)),
                Some(FallbackPick::Held(more)) => held.extend(more),
                None => {}
            }
        }
        arrived.extend(held);
        if arrived.is_empty() {
            return Err(round.last_error.unwrap_or_else(|| {
                BeaconError::HttpError(format!("{op_name}: all BNs failed in best-selection"))
            }));
        }
        let ranked = sort_by_pick(arrived, select.pick_best.as_ref());
        let (best_index, best_value) = &ranked[0];
        self.log_best_pick(op_name, *best_index);
        (select.on_chosen)(*best_index, best_value);
        Ok(ranked)
    }

    fn log_best_pick(&self, op_name: &str, index: usize) {
        debug!(
            op = op_name,
            bn_index = index,
            endpoint = %RedactedUrl(self.clients[index].endpoint()),
            "best-selection picked BN"
        );
    }

    /// Tries untried proposal-role BNs above [`FALLBACK_TIER_FLOOR`].
    ///
    /// `window.deadline` bounds each attempt by the time still left. `None`
    /// leaves the attempts unbounded, matching a round with no budget configured. An `Ok`
    /// that fails `fallback_accept` is not returned. A candidate that is not in hand is
    /// held so a later matching candidate can win. Once a block is held, a
    /// later attempt stops [`HELD_RETURN_MARGIN`] before `deadline`, so the
    /// outer backstop cannot drop that block. The best held candidate is
    /// returned when none match. Health samples are queued per attempt and
    /// this function does not wait on the health write lock.
    async fn fallback_unsynced<T, F>(
        &self,
        op_name: &str,
        role: BnRole,
        op: &F,
        tried_indices: &[usize],
        window: FallbackWindow,
        select: &BestSelect<T>,
    ) -> Option<FallbackPick<T>>
    where
        T: Send,
        F: Fn(&BeaconClient) -> BoxFut<'static, T>,
    {
        let candidates = {
            let sync_guard = self.sync_statuses.read().await;
            let health_guard = self.health_trackers.read().await;
            self.role_matching_indices(role)
                .into_iter()
                .filter(|index| !tried_indices.contains(index))
                .filter(|&index| {
                    above_fallback_floor(
                        &sync_guard[index],
                        &health_guard[index],
                        &self.tier_thresholds,
                    )
                })
                .collect::<Vec<_>>()
        };

        if candidates.is_empty() {
            debug!(op = op_name, "no untried proposal-role BN above the health floor for fallback");
            return None;
        }

        warn!(
            op = op_name,
            candidates = candidates.len(),
            "synced proposal BNs failed; trying proposal-role BNs above the health floor"
        );

        let mut held: Vec<(usize, T)> = Vec::new();
        let mut holding = window.already_held;
        for i in candidates {
            let bound = fallback_attempt_bound(window.deadline, holding);
            if window.deadline.is_some() && bound.is_none() {
                break;
            }
            let client = &self.clients[i];
            let start = tokio::time::Instant::now();
            let attempt_span = tracing::info_span!(
                "bn.attempt",
                bn_url = %RedactedUrl(client.endpoint()),
            );
            match await_attempt(op_name, bound, op(client)).instrument(attempt_span).await {
                Ok(result) => {
                    let elapsed = start.elapsed();
                    fan_out::queue_health_sample(
                        &self.health_trackers,
                        op_name,
                        i,
                        TrackerOutcome::Success(elapsed),
                    );
                    if !(select.fallback_accept)(&result) {
                        (select.on_reject)(i, client.endpoint(), &result);
                        continue;
                    }
                    if !(select.in_hand)(&result) {
                        keep_better(&mut held, i, result, select.pick_best.as_ref());
                        holding = true;
                        continue;
                    }
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        latency_ms = elapsed.as_millis() as u64,
                        "query succeeded on a proposal-role fallback BN"
                    );
                    return Some(FallbackPick::Ready(i, result));
                }
                Err(e) => {
                    fan_out::queue_health_sample(
                        &self.health_trackers,
                        op_name,
                        i,
                        error_outcome(op_name, &e),
                    );
                    warn!(
                        op = op_name,
                        bn_index = i,
                        endpoint = %RedactedUrl(client.endpoint()),
                        error = %e,
                        "proposal-role fallback BN failed"
                    );
                }
            }
        }

        if held.is_empty() {
            None
        } else {
            Some(FallbackPick::Held(held))
        }
    }

    /// Best-of `produce_block_v3`.
    ///
    /// `checks` filters candidates before ranking. Slot, proposer, parent,
    /// and consensus version are hard checks, as are an unreadable fee, a
    /// missing fee on a full Bellatrix-or-later block, and a header-only full
    /// block. A readable wrong fee is a penalty under [`FeeRecipientPolicy::Sign`]:
    /// it does not count as in hand, and it is returned only when no matching
    /// block arrives before every beacon node has answered or the hard
    /// deadline passes. [`FeeRecipientPolicy::Reject`] drops that mismatch.
    /// A blinded block skips the fee penalty. The penalty warning and
    /// `rvc_produce_block_fee_recipient_penalty_total` are emitted for the
    /// candidate that is signed, not for the head of this list.
    /// Fallback runs only when the expected parent root is known, and only
    /// against untried proposal-role BNs above the health floor.
    async fn produce_block_v3_checked(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        checks: Option<BlockDutyChecks>,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Vec<RankedBlock>, BeaconError> {
        let budget = self.production_budget(deadline);
        let randao_reveal = randao_reveal.to_owned();
        let graffiti = graffiti.map(str::to_owned);
        let select = produce_best_select(checks, self.fee_recipient_policy);
        let strategy_span = tracing::info_span!(
            "bn.strategy.best",
            strategy = "best",
            tried = tracing::field::Empty,
        );
        let ranked = self
            .with_op_timeout(
                "produce_block_v3",
                fan_out::broadcast_backstop(budget),
                self.query_best_inner(
                    "produce_block_v3",
                    BnRole::Proposal,
                    HealthTier::Synced,
                    budget,
                    &move |client: &BeaconClient| {
                        let client = client.clone();
                        let randao_reveal = randao_reveal.clone();
                        let graffiti = graffiti.clone();
                        Box::pin(async move {
                            client
                                .produce_block_v3(
                                    slot,
                                    &randao_reveal,
                                    graffiti.as_deref(),
                                    builder_boost_factor,
                                )
                                .await
                        })
                    },
                    select,
                )
                .instrument(strategy_span),
            )
            .await?;
        Ok(ranked
            .into_iter()
            .map(|(bn_index, response)| RankedBlock { bn_index, response })
            .collect())
    }

    /// Broadcast an operation to role-matching BNs (**regardless of sync / health
    /// tier / health-score**). Returns on the first `Ok`. If all fail, returns
    /// the last error. If no BN matches the role and no `All`-role BN exists,
    /// returns [`BeaconError::NoEligibleBn`] without publishing (fail-closed).
    ///
    /// `budget` bounds each attempt. `None` leaves attempts unbounded. Role:
    /// yes. Tier: no. Health-score prune: no. Selection is
    /// [`Self::role_matching_indices`] so All-fallback is shared with the query
    /// path but the query last-resort (every client) and the health-score cut
    /// are not. `tried` is the filtered count.
    async fn broadcast<F>(
        &self,
        op_name: &str,
        role: BnRole,
        budget: Option<Duration>,
        op: F,
    ) -> Result<(), BeaconError>
    where
        F: Fn(&BeaconClient) -> BoxFut<'static, ()>,
    {
        self.broadcast_with_result(op_name, role, budget, op).await.map(|_| ())
    }

    fn fan_attempts<T, F>(&self, role: BnRole, op: &F) -> Vec<BnAttempt<T>>
    where
        F: Fn(&BeaconClient) -> BoxFut<'static, T>,
    {
        self.role_matching_indices(role)
            .into_iter()
            .map(|index| {
                let client = &self.clients[index];
                BnAttempt { index, endpoint: client.endpoint().to_string(), fut: op(client) }
            })
            .collect()
    }

    fn log_partial_failure<T>(op_name: &str, broadcast: &BroadcastResult<T>) {
        if !broadcast.any_success() || broadcast.all_success() {
            return;
        }
        let (successes, _) = broadcast.counts();
        // `failures()` is the credential-safe view of which endpoints erred.
        // Latencies stay on the outcomes; both are redacted at the log site.
        let erred: std::collections::HashSet<&str> =
            broadcast.failures().into_iter().map(|(endpoint, _)| endpoint).collect();
        let failures: Vec<(String, Duration)> = broadcast
            .outcomes
            .iter()
            .filter(|outcome| erred.contains(outcome.endpoint.as_str()))
            .map(|outcome| (outcome.endpoint.clone(), outcome.latency))
            .collect();
        log_partial_failure_endpoints(op_name, successes, &failures);
    }

    /// Broadcast an operation that returns a non-unit result.
    /// Returns the first `Ok`. If all fail, returns the last error.
    async fn broadcast_with_result<T, F>(
        &self,
        op_name: &str,
        role: BnRole,
        budget: Option<Duration>,
        op: F,
    ) -> Result<T, BeaconError>
    where
        T: Clone + Send + 'static,
        F: Fn(&BeaconClient) -> BoxFut<'static, T>,
    {
        self.broadcast_with_result_attributed(
            op_name,
            role,
            budget,
            fan_out::PublishPolicy::any_ok(),
            op,
        )
        .await
        .map(|(_endpoint, value)| value)
    }

    /// [`Self::broadcast_with_result`] plus the endpoint of the kept `Ok`.
    ///
    /// The endpoint is whichever role-matching beacon node produced that
    /// result, not the lowest index. No cross-BN merge and no extra retry.
    /// A plain `Ok` returns on the first success. An attestation submit treats
    /// only a full acceptance as complete: a 400 that lists failed attestations
    /// waits for another node's full acceptance until the attempts finish, and
    /// the partial with the fewest failures is kept if none arrives.
    async fn broadcast_with_result_attributed<T, F>(
        &self,
        op_name: &str,
        role: BnRole,
        budget: Option<Duration>,
        policy: fan_out::PublishPolicy<T>,
        op: F,
    ) -> Result<(String, T), BeaconError>
    where
        T: Clone + Send + 'static,
        F: Fn(&BeaconClient) -> BoxFut<'static, T>,
    {
        let strategy_span = tracing::info_span!(
            "bn.strategy.broadcast",
            strategy = "broadcast",
            tried = tracing::field::Empty,
        );
        async {
            let attempts = self.fan_attempts(role, &op);
            tracing::Span::current().record("tried", attempts.len());
            fan_out::first_ok_with(
                op_name,
                &role.to_string(),
                attempts,
                budget,
                &self.health_trackers,
                fan_out::global_drain_pool(),
                policy,
            )
            .await
        }
        .instrument(strategy_span)
        .await
    }

    /// Every role-matching BN, each bounded by `budget`. Merges use this so a
    /// late `Ok` is not dropped when an earlier BN already answered.
    async fn broadcast_all<T, F>(
        &self,
        op_name: &str,
        role: BnRole,
        budget: Option<Duration>,
        op: F,
    ) -> Result<BroadcastResult<T>, BeaconError>
    where
        T: Send + 'static,
        F: Fn(&BeaconClient) -> BoxFut<'static, T>,
    {
        let attempts = self.fan_attempts(role, &op);
        tracing::Span::current().record("tried", attempts.len());
        fan_out::all(op_name, &role.to_string(), attempts, budget, &self.health_trackers).await
    }
}

/// Deneb, Electra, and Fulu publish `{message, signature}` with an object body.
///
/// Gloas and pre-Deneb keep [`SignedBeaconBlock`] serde. Gloas has no JSON
/// body encoder. A Deneb+ body that does not encode is an error, not hex.
fn json_signed_block(
    signed_block: &SignedBeaconBlock,
    consensus_version: &str,
) -> Result<serde_json::Value, BeaconError> {
    match eth_types::body_fork_layout(consensus_version) {
        Some(layout @ (eth_types::BodyForkLayout::Deneb | eth_types::BodyForkLayout::Electra)) => {
            let wire = eth_types::signed_block_contents_json::SignedBeaconBlockJson::from_signed(
                signed_block,
                layout,
            )
            .map_err(|err| BeaconError::ParseError(format!("invalid JSON block body: {err}")))?;
            serde_json::to_value(&wire)
                .map_err(|err| BeaconError::ParseError(format!("invalid JSON block body: {err}")))
        }
        Some(eth_types::BodyForkLayout::Gloas) | None => serde_json::to_value(signed_block)
            .map_err(|err| BeaconError::ParseError(format!("invalid JSON block body: {err}"))),
    }
}

/// Clone the beacon client and an `Arc` payload into a `'static` attempt.
///
/// The drain outlives the call, so the attempt cannot borrow the request.
macro_rules! owned_attempt {
    ($payload:expr, |$client:ident, $payload_ident:ident| $body:expr) => {{
        let $payload_ident = std::sync::Arc::new($payload);
        move |$client: &BeaconClient| {
            let $client = $client.clone();
            let $payload_ident = std::sync::Arc::clone(&$payload_ident);
            Box::pin(async move { $body })
        }
    }};
}

/// Hard deadline for fallback attempts, and whether a signable block is already held.
struct FallbackWindow {
    deadline: Option<tokio::time::Instant>,
    already_held: bool,
}

enum FallbackPick<T> {
    /// Hard checks and the right fee. Fallback stops on this block.
    Ready(usize, T),
    /// Readable wrong-fee blocks. The caller ranks them with any earlier hold.
    Held(Vec<(usize, T)>),
}

/// Better candidates first. Ties keep the lower beacon-node index.
fn sort_by_pick<T>(
    mut items: Vec<(usize, T)>,
    pick_best: &dyn Fn(&T, &T) -> bool,
) -> Vec<(usize, T)> {
    items.sort_by(|left, right| {
        if pick_best(&left.1, &right.1) {
            std::cmp::Ordering::Less
        } else if pick_best(&right.1, &left.1) {
            std::cmp::Ordering::Greater
        } else {
            left.0.cmp(&right.0)
        }
    });
    items
}

fn keep_better<T>(
    held: &mut Vec<(usize, T)>,
    index: usize,
    result: T,
    pick_best: &dyn Fn(&T, &T) -> bool,
) {
    match held.pop() {
        None => held.push((index, result)),
        Some((_current_index, current)) if pick_best(&result, &current) => {
            held.push((index, result));
        }
        Some(current) => held.push(current),
    }
}

/// Bound for one fallback attempt.
///
/// `None` with a `deadline` of `Some` means the window is already closed.
/// Once a block is held, the bound ends [`HELD_RETURN_MARGIN`] before the
/// outer backstop.
fn fallback_attempt_bound(
    deadline: Option<tokio::time::Instant>,
    holding: bool,
) -> Option<Duration> {
    let end = deadline?;
    let end = if holding { end.checked_sub(HELD_RETURN_MARGIN).unwrap_or(end) } else { end };
    let remaining = end.saturating_duration_since(tokio::time::Instant::now());
    if remaining.is_zero() {
        None
    } else {
        Some(remaining)
    }
}

fn produce_best_select(
    checks: Option<BlockDutyChecks>,
    policy: FeeRecipientPolicy,
) -> BestSelect<ProduceBlockResponse> {
    let allow_fallback =
        checks.as_ref().is_some_and(|checks| !checks.parent_closed && checks.parent_root.is_some());
    let accept_checks = checks;
    let accept: Pred<ProduceBlockResponse> = Arc::new(move |block| match accept_checks.as_ref() {
        Some(checks) => block_passes_duty(block, checks, policy),
        None => true,
    });
    let hand_checks = checks;
    let in_hand: Pred<ProduceBlockResponse> = Arc::new(move |block| match hand_checks.as_ref() {
        Some(checks) => {
            block_passes_duty(block, checks, policy)
                && fee_preferred(block, checks)
                && parent_is_primary(block, checks)
        }
        None => true,
    });
    let fallback_checks = checks;
    let fallback_accept: Pred<ProduceBlockResponse> =
        Arc::new(move |block| match fallback_checks.as_ref() {
            Some(checks) => {
                block_passes_duty(block, checks, policy) && parent_is_primary(block, checks)
            }
            None => true,
        });
    let rank_checks = checks;
    let pick_best: Rank<ProduceBlockResponse> =
        Arc::new(move |left, right| candidate_ranks_above(left, right, rank_checks.as_ref()));
    let reject_checks = checks;
    let on_reject: RejectFn<ProduceBlockResponse> = Arc::new(move |index, endpoint, block| {
        if let Some(checks) = reject_checks.as_ref() {
            log_produce_rejection(index, endpoint, block, checks, policy);
        }
    });
    let on_chosen: ChosenFn<ProduceBlockResponse> = Arc::new(|_, _| {});
    BestSelect { pick_best, accept, fallback_accept, in_hand, on_reject, on_chosen, allow_fallback }
}

/// Fallback may use a proposal-role BN at this tier or healthier.
///
/// `SmallLag` is the floor: large-lag, unsynced, optimistic, and
/// execution-offline nodes stay out. Healthier means `tier <=` this value.
const FALLBACK_TIER_FLOOR: HealthTier = HealthTier::SmallLag;

/// Slot, proposer, parent, consensus version, and fee recipient for one
/// `produce_block_v3` duty.
#[derive(Clone, Copy)]
struct BlockDutyChecks {
    slot: u64,
    proposer_index: u64,
    parent_root: Option<[u8; 32]>,
    alternate_parent_root: Option<[u8; 32]>,
    parent_closed: bool,
    fee_recipient: Option<[u8; 20]>,
    consensus_version: ForkName,
}

fn checks_from_duty(slot: u64, duty: ProduceDuty) -> BlockDutyChecks {
    BlockDutyChecks {
        slot,
        proposer_index: duty.expected_proposer_index,
        parent_root: duty.expected_parent_root,
        alternate_parent_root: duty.alternate_parent_root,
        parent_closed: duty.parent_closed,
        fee_recipient: duty.expected_fee_recipient,
        consensus_version: duty.expected_consensus_version,
    }
}

fn above_fallback_floor(
    sync: &crate::sync_status::BnSyncDetail,
    health: &BnHealthTracker,
    thresholds: &TierThresholds,
) -> bool {
    if sync.is_optimistic || sync.el_offline {
        return false;
    }
    if !health.is_healthy() {
        return false;
    }
    sync.tier(thresholds) <= FALLBACK_TIER_FLOOR
}

enum FeeOnBlock {
    /// No full-payload fee recipient (blinded, or JSON without one).
    Unknown,
    Present([u8; 20]),
    /// A fee recipient field is present and is not a 20-byte hex address.
    Invalid,
}

struct DutyFields {
    slot: u64,
    proposer_index: u64,
    parent_root: [u8; 32],
    fee: FeeOnBlock,
}

/// Why a candidate is dropped before ranking.
enum HardReject {
    Fork,
    Unreadable,
    Slot,
    Proposer,
    Parent,
    /// Unreadable fee, missing fee on a full Bellatrix+ block, header-only
    /// full block, or a readable mismatch under [`FeeRecipientPolicy::Reject`].
    Fee,
}

fn hard_reject_label(reason: HardReject) -> &'static str {
    match reason {
        HardReject::Fork => "fork",
        HardReject::Unreadable => "unreadable",
        HardReject::Slot => "slot",
        HardReject::Proposer => "proposer",
        HardReject::Parent => "parent",
        HardReject::Fee => "fee",
    }
}

/// `true` when `block` passes the hard duty checks.
///
/// The consensus version must be the duty's fork. A block whose slot,
/// proposer, or parent cannot be read does not match. A missing or unreadable
/// fee on a full post-Bellatrix block does not match. A readable wrong fee
/// matches only under [`FeeRecipientPolicy::Sign`].
fn block_passes_duty(
    block: &ProduceBlockResponse,
    checks: &BlockDutyChecks,
    policy: FeeRecipientPolicy,
) -> bool {
    hard_reject_reason(block, checks, policy).is_none()
}

fn hard_reject_reason(
    block: &ProduceBlockResponse,
    checks: &BlockDutyChecks,
    policy: FeeRecipientPolicy,
) -> Option<HardReject> {
    if block.consensus_version.parse::<ForkName>().ok() != Some(checks.consensus_version) {
        return Some(HardReject::Fork);
    }
    let Some(fields) = duty_fields(block) else {
        return Some(HardReject::Unreadable);
    };
    if fields.slot != checks.slot {
        return Some(HardReject::Slot);
    }
    if fields.proposer_index != checks.proposer_index {
        return Some(HardReject::Proposer);
    }
    if checks.parent_closed {
        return Some(HardReject::Parent);
    }
    if let Some(expected) = checks.parent_root {
        let on_primary = fields.parent_root == expected;
        let on_alternate =
            checks.alternate_parent_root.is_some_and(|alternate| fields.parent_root == alternate);
        if !on_primary && !on_alternate {
            return Some(HardReject::Parent);
        }
    }
    if fee_is_hard_reject(block, checks, &fields, policy) {
        return Some(HardReject::Fee);
    }
    None
}

/// Unreadable, missing, or policy-rejected fee.
///
/// A blinded block is never a fee reject. Before Bellatrix a missing fee is
/// not a fee reject. A readable wrong fee is a reject only when `policy` is
/// [`FeeRecipientPolicy::Reject`].
fn fee_is_hard_reject(
    block: &ProduceBlockResponse,
    checks: &BlockDutyChecks,
    fields: &DutyFields,
    policy: FeeRecipientPolicy,
) -> bool {
    if block.is_blinded {
        return false;
    }
    let Some(expected) = checks.fee_recipient else {
        return false;
    };
    match fields.fee {
        FeeOnBlock::Present(got) if got == expected => false,
        FeeOnBlock::Present(_) => policy == FeeRecipientPolicy::Reject,
        FeeOnBlock::Unknown if !checks.consensus_version.carries_execution_payload() => false,
        FeeOnBlock::Unknown | FeeOnBlock::Invalid => true,
    }
}

/// `true` when `block` should outrank a fee-penalized candidate.
///
/// A blinded block is preferred: the builder header's fee recipient is the
/// builder's address, and the proposer is paid inside the builder's
/// transaction. With no expected fee, every block is preferred. Before
/// Bellatrix a missing fee is preferred. Only a readable fee that does not
/// match is penalized. An unreadable or missing post-Bellatrix fee is a hard
/// reject, not a penalty.
fn fee_preferred(block: &ProduceBlockResponse, checks: &BlockDutyChecks) -> bool {
    if block.is_blinded {
        return true;
    }
    let Some(expected) = checks.fee_recipient else {
        return true;
    };
    let Some(fields) = duty_fields(block) else {
        return false;
    };
    match fields.fee {
        FeeOnBlock::Present(got) if got == expected => true,
        FeeOnBlock::Unknown if !checks.consensus_version.carries_execution_payload() => true,
        FeeOnBlock::Present(_) | FeeOnBlock::Unknown | FeeOnBlock::Invalid => false,
    }
}

/// `true` when `block` uses the primary parent, or no parent was required.
///
/// The re-org parent is accepted by [`block_passes_duty`] and is not primary.
/// A closed parent set is never primary.
fn parent_is_primary(block: &ProduceBlockResponse, checks: &BlockDutyChecks) -> bool {
    if checks.parent_closed {
        return false;
    }
    let Some(expected) = checks.parent_root else {
        return true;
    };
    duty_fields(block).is_some_and(|fields| fields.parent_root == expected)
}

/// 2 is the primary parent (or no parent constraint), 1 is the re-org parent.
fn parent_rank(block: &ProduceBlockResponse, checks: &BlockDutyChecks) -> u8 {
    if checks.parent_closed {
        return 0;
    }
    let Some(fields) = duty_fields(block) else {
        return 0;
    };
    match checks.parent_root {
        None => 2,
        Some(expected) if fields.parent_root == expected => 2,
        Some(_) if checks.alternate_parent_root.is_some_and(|alt| fields.parent_root == alt) => 1,
        Some(_) => 0,
    }
}

/// `true` when `left` ranks strictly above `right`.
///
/// The primary parent outranks the re-org parent. Within that class, a
/// fee-preferred block outranks a penalized one regardless of value. Within
/// the same fee class, [`block_value`] decides. A missing or unparsable
/// header contributes 0, and the sum saturates.
fn candidate_ranks_above(
    left: &ProduceBlockResponse,
    right: &ProduceBlockResponse,
    checks: Option<&BlockDutyChecks>,
) -> bool {
    if let Some(checks) = checks {
        match parent_rank(left, checks).cmp(&parent_rank(right, checks)) {
            std::cmp::Ordering::Greater => return true,
            std::cmp::Ordering::Less => return false,
            std::cmp::Ordering::Equal => {}
        }
        match (fee_preferred(left, checks), fee_preferred(right, checks)) {
            (true, false) => return true,
            (false, true) => return false,
            (true, true) | (false, false) => {}
        }
    }
    block_value(left) > block_value(right)
}

struct ObservedDuty {
    slot: Option<u64>,
    proposer: Option<u64>,
    parent: Option<[u8; 32]>,
    fee: FeeOnBlock,
}

fn observe_duty(block: &ProduceBlockResponse) -> ObservedDuty {
    match duty_fields(block) {
        Some(fields) => ObservedDuty {
            slot: Some(fields.slot),
            proposer: Some(fields.proposer_index),
            parent: Some(fields.parent_root),
            fee: fields.fee,
        },
        None => ObservedDuty { slot: None, proposer: None, parent: None, fee: FeeOnBlock::Unknown },
    }
}

fn log_produce_rejection(
    index: usize,
    endpoint: &str,
    block: &ProduceBlockResponse,
    checks: &BlockDutyChecks,
    policy: FeeRecipientPolicy,
) {
    let observed = observe_duty(block);
    let reason =
        hard_reject_reason(block, checks, policy).map(hard_reject_label).unwrap_or("rejected");
    warn!(
        op = "produce_block_v3",
        bn_index = index,
        endpoint = %RedactedUrl(endpoint),
        reason,
        slot_expected = checks.slot,
        slot_got = %display_opt_u64(observed.slot),
        proposer_expected = checks.proposer_index,
        proposer_got = %display_opt_u64(observed.proposer),
        parent_expected = %display_expected_root(checks.parent_root),
        parent_reorg = %display_expected_root(checks.alternate_parent_root),
        parent_closed = checks.parent_closed,
        parent_got = %display_opt_root(observed.parent),
        fork_expected = checks.consensus_version.as_ref(),
        fork_got = %block.consensus_version,
        fee_expected = %display_fee_expected(checks.fee_recipient),
        fee_got = %display_fee_got(&observed.fee),
        value_parse = %display_value_parse(block),
        "best-of candidate rejected"
    );
}

fn display_opt_u64(value: Option<u64>) -> String {
    value.map(|n| n.to_string()).unwrap_or_else(|| "unreadable".to_string())
}

fn display_opt_root(value: Option<[u8; 32]>) -> String {
    value.map(|root| hex_prefixed(&root)).unwrap_or_else(|| "unreadable".to_string())
}

fn display_expected_root(value: Option<[u8; 32]>) -> String {
    value.map(|root| hex_prefixed(&root)).unwrap_or_else(|| "unset".to_string())
}

fn display_fee_expected(value: Option<[u8; 20]>) -> String {
    value.map(|fee| hex_prefixed(&fee)).unwrap_or_else(|| "unset".to_string())
}

fn display_fee_got(fee: &FeeOnBlock) -> String {
    match fee {
        FeeOnBlock::Present(bytes) => hex_prefixed(bytes),
        FeeOnBlock::Unknown => "missing".to_string(),
        FeeOnBlock::Invalid => "invalid".to_string(),
    }
}

fn display_value_parse(block: &ProduceBlockResponse) -> String {
    match parsed_display_value(block) {
        Some(wei) => format!("ok:{wei}"),
        None => match block.execution_payload_value.as_deref() {
            Some("") => "unparsed:empty".to_string(),
            Some(raw) => format!("unparsed:{raw}"),
            None => "unparsed:missing".to_string(),
        },
    }
}

/// Execution wei plus consensus wei, when every present header is a whole decimal.
///
/// A missing consensus header is 0. An empty, signed, non-digit, or overflowing
/// header is unparsed, and so is a present consensus header that does not parse.
/// [`block_value`] still ranks those as 0; this label must not report `ok:0`.
fn parsed_display_value(block: &ProduceBlockResponse) -> Option<u128> {
    let execution = strict_wei(block.execution_payload_value.as_deref()?)?;
    let consensus = match block.consensus_block_value.as_deref() {
        Some(raw) => strict_wei(raw)?,
        None => 0,
    };
    Some(execution.saturating_add(consensus))
}

fn strict_wei(raw: &str) -> Option<u128> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

fn hex_prefixed(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn duty_fields(block: &ProduceBlockResponse) -> Option<DutyFields> {
    if block.is_ssz {
        let bytes = block.ssz_bytes.as_deref()?;
        let format = ssz_produce_format(block.is_blinded, &block.consensus_version)?;
        let (parsed, _) =
            beacon::ssz_deser::deserialize_beacon_block_from_ssz(bytes, format).ok()?;
        let fee = if block.is_blinded {
            FeeOnBlock::Unknown
        } else {
            ssz_execution_fee(&block.consensus_version, &parsed.body)
        };
        return Some(DutyFields {
            slot: parsed.slot,
            proposer_index: parsed.proposer_index,
            parent_root: parsed.parent_root,
            fee,
        });
    }
    json_duty_fields(&block.data)
}

/// Fee recipient from a full (unblinded) execution payload.
///
/// Bellatrix and Capella read the payload fee at the spec offset.
/// [`ForkName::body_layout`] stays the KZG layout and is `None` for those
/// forks. Deneb uses the Deneb body layout. Electra and Fulu share the
/// Electra layout. Anything else, including a body that does not decode, is
/// [`FeeOnBlock::Invalid`] so the duty check fails closed.
fn ssz_execution_fee(consensus_version: &str, body: &[u8]) -> FeeOnBlock {
    let Ok(fork) = consensus_version.parse::<ForkName>() else {
        return FeeOnBlock::Invalid;
    };
    if let Some(fixed_len) = fork.pre_deneb_body_fixed_len() {
        return execution_fee_at_payload_offset(body, fixed_len);
    }
    let address = match fork.body_layout() {
        Some(eth_types::BodyForkLayout::Deneb) => {
            eth_types::BeaconBlockBodyDeneb::from_ssz_bytes(body)
                .ok()
                .map(|decoded| decoded.execution_payload.fee_recipient)
        }
        Some(eth_types::BodyForkLayout::Electra) => {
            eth_types::BeaconBlockBodyElectra::from_ssz_bytes(body)
                .ok()
                .map(|decoded| decoded.execution_payload.fee_recipient)
        }
        Some(eth_types::BodyForkLayout::Gloas) | None => None,
    };
    address.map_or(FeeOnBlock::Invalid, FeeOnBlock::Present)
}

fn ssz_produce_format(
    is_blinded: bool,
    consensus_version: &str,
) -> Option<beacon::ssz_deser::SszBlockFormat> {
    use beacon::ssz_deser::SszBlockFormat;
    if is_blinded {
        return Some(SszBlockFormat::BeaconBlock);
    }
    match consensus_version {
        "deneb" | "electra" | "fulu" => Some(SszBlockFormat::BlockContents),
        "phase0" | "altair" | "bellatrix" | "capella" | "gloas" => {
            Some(SszBlockFormat::BeaconBlock)
        }
        _ => None,
    }
}

/// `fee_recipient` from a Bellatrix or Capella execution payload.
///
/// `fixed_len` is the body fixed section. The payload offset is the little-endian
/// u32 at byte 380. The fee recipient is the 20 bytes at payload+32. A short
/// body, an offset inside the fixed section, or a payload that does not contain
/// the fee is [`FeeOnBlock::Invalid`].
fn execution_fee_at_payload_offset(body: &[u8], fixed_len: usize) -> FeeOnBlock {
    const PAYLOAD_OFFSET_AT: usize = 380;
    const FEE_AT: usize = 32;
    const FEE_LEN: usize = 20;
    let Some(offset_bytes) = body.get(PAYLOAD_OFFSET_AT..PAYLOAD_OFFSET_AT + 4) else {
        return FeeOnBlock::Invalid;
    };
    let offset_bytes: [u8; 4] = offset_bytes.try_into().expect("payload offset is 4 bytes");
    let offset = u32::from_le_bytes(offset_bytes) as usize;
    if offset < fixed_len {
        return FeeOnBlock::Invalid;
    }
    let Some(start) = offset.checked_add(FEE_AT) else {
        return FeeOnBlock::Invalid;
    };
    let Some(end) = start.checked_add(FEE_LEN) else {
        return FeeOnBlock::Invalid;
    };
    let Some(fee) = body.get(start..end) else {
        return FeeOnBlock::Invalid;
    };
    let mut address = [0u8; FEE_LEN];
    address.copy_from_slice(fee);
    FeeOnBlock::Present(address)
}

fn json_duty_fields(data: &serde_json::Value) -> Option<DutyFields> {
    let block = eth_types::block_object(data).ok()?;
    let slot = json_u64(block.get("slot")?)?;
    let proposer_index = json_u64(block.get("proposer_index")?)?;
    let parent_root = json_fixed_hex::<32>(block.get("parent_root")?.as_str()?)?;
    Some(DutyFields { slot, proposer_index, parent_root, fee: fee_on_block(block.get("body")) })
}

fn json_u64(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::String(text) => text.parse().ok(),
        serde_json::Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

fn fee_on_block(body: Option<&serde_json::Value>) -> FeeOnBlock {
    let Some(body) = body.filter(|body| body.is_object()) else {
        return FeeOnBlock::Unknown;
    };
    let Some(payload) = body.get("execution_payload") else {
        return FeeOnBlock::Unknown;
    };
    match payload.get("fee_recipient") {
        Some(value) => match value.as_str().and_then(json_fixed_hex::<20>) {
            Some(bytes) => FeeOnBlock::Present(bytes),
            None => FeeOnBlock::Invalid,
        },
        None => FeeOnBlock::Unknown,
    }
}

fn json_fixed_hex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let hex = text.strip_prefix("0x").unwrap_or(text);
    if hex.len() != N * 2 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
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

/// Which configured beacon nodes must answer before a spec is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecAgreement {
    /// Custom networks. Every configured BN must respond and the values must agree.
    All,
    /// Named networks. The preset already pins duration and genesis, so a BN
    /// that does not respond is skipped. At least one must respond. Responders
    /// that disagree fail closed.
    Responding,
}

impl BnManager {
    /// Slot duration, slots per epoch, and genesis time.
    ///
    /// A missing key, a value outside the slot-duration bound, or any
    /// disagreement among responders fails closed. [`SpecAgreement::All`]
    /// also fails when any configured BN does not respond.
    /// [`SpecAgreement::Responding`] skips a connect failure, a timeout, or a
    /// proxy status (429, 502, 503, 504) and fails when nobody returned both
    /// spec and genesis. A spec is compared before genesis is fetched, so a
    /// genesis timeout cannot hide a disagreeing spec. `configured_root` seeds
    /// the validators-root check: a responder that differs is not admitted and
    /// is not the chain identity. A skipped node stays unadmitted until
    /// [`Self::admit_skipped_beacon`]. Endpoints are not included in the error.
    pub async fn agreed_spec_and_genesis(
        &self,
        agreement: SpecAgreement,
        configured_root: &str,
    ) -> Result<(u64, u64, u64), BeaconError> {
        if self.clients.is_empty() {
            return Err(BeaconError::HttpError("no beacon nodes configured".into()));
        }
        let mut duration_ms = None;
        let mut slots_per_epoch = None;
        let mut genesis_time = None;
        let mut responded = 0u32;
        let mut saw_root_mismatch = false;
        for (index, client) in self.clients.iter().enumerate() {
            let spec = match client.get_config_spec().await {
                Ok(spec) => spec,
                Err(e) if agreement == SpecAgreement::Responding && is_unreachable(&e) => {
                    self.mark_unadmitted(index);
                    continue;
                }
                Err(e) => return Err(e),
            };
            let ms = beacon::parse_slot_duration_ms(&spec.data)?;
            let slots = beacon::parse_slots_per_epoch(&spec.data)?;
            // Compare the spec before fetching genesis. A timeout on genesis
            // must not discard a duration the other nodes disagree with.
            duration_ms = agree(duration_ms, ms, "slot duration")?;
            slots_per_epoch = agree(slots_per_epoch, slots, "SLOTS_PER_EPOCH")?;
            let genesis = match client.get_genesis().await {
                Ok(genesis) => genesis,
                Err(e) if agreement == SpecAgreement::Responding && is_unreachable(&e) => {
                    self.mark_unadmitted(index);
                    continue;
                }
                Err(e) => return Err(e),
            };
            let parsed_genesis = genesis
                .data
                .genesis_time
                .parse::<u64>()
                .map_err(|e| BeaconError::ParseError(format!("invalid genesis_time: {e}")))?;
            genesis_time = agree(genesis_time, parsed_genesis, "genesis_time")?;
            if !beacon::hex_ids_equal(configured_root, &genesis.data.genesis_validators_root) {
                saw_root_mismatch = true;
                self.mark_unadmitted(index);
                if agreement == SpecAgreement::All {
                    return Err(BeaconError::ParseError(
                        "beacon nodes disagree on genesis_validators_root".into(),
                    ));
                }
                continue;
            }
            responded += 1;
        }
        if responded == 0 {
            if saw_root_mismatch {
                return Err(BeaconError::ParseError(
                    "beacon nodes disagree on genesis_validators_root".into(),
                ));
            }
            return Err(BeaconError::HttpError(
                "no beacon node responded with spec and genesis".into(),
            ));
        }
        match (duration_ms, slots_per_epoch, genesis_time) {
            (Some(duration_ms), Some(slots_per_epoch), Some(genesis_time)) => {
                *self.chain_identity.write().await = Some(AgreedChain {
                    slot_duration_ms: duration_ms,
                    slots_per_epoch,
                    genesis_time,
                    genesis_validators_root: configured_root.to_string(),
                });
                Ok((duration_ms, slots_per_epoch, genesis_time))
            }
            _ => {
                Err(BeaconError::HttpError("no beacon node responded with spec and genesis".into()))
            }
        }
    }

    /// Admit one boot-skipped beacon node after its spec and genesis match
    /// the chain the responding nodes agreed on.
    ///
    /// `/eth/v1/node/syncing` does not admit the node. A mismatch leaves it
    /// unadmitted.
    pub async fn admit_skipped_beacon(&self, index: usize) -> Result<(), BeaconError> {
        admit_client(&self.clients, &self.admitted, &self.chain_identity, index).await
    }
}

/// Chain identity the boot responders agreed on.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AgreedChain {
    slot_duration_ms: u64,
    slots_per_epoch: u64,
    genesis_time: u64,
    genesis_validators_root: String,
}

fn is_unreachable(err: &BeaconError) -> bool {
    match err {
        BeaconError::HttpError(_) | BeaconError::Timeout | BeaconError::OperationTimeout { .. } => {
            true
        }
        // Proxy unavailable. 500 stays boot-fatal. Production failover does
        // not treat 429 as a produce failover.
        BeaconError::ApiError { status, .. } if matches!(*status, 429 | 502..=504) => true,
        _ => false,
    }
}

fn agree(prev: Option<u64>, next: u64, field: &str) -> Result<Option<u64>, BeaconError> {
    match prev {
        Some(prev) if prev != next => Err(BeaconError::ParseError(format!(
            "beacon nodes disagree on {field}: {prev} vs {next}"
        ))),
        _ => Ok(Some(next)),
    }
}

async fn admit_reachable_clients(
    clients: &[BeaconClient],
    statuses: &SharedSyncStatuses,
    admitted: &Arc<Vec<AtomicBool>>,
    identity: &tokio::sync::RwLock<Option<AgreedChain>>,
) {
    let snapshot = statuses.read().await.clone();
    for (index, detail) in snapshot.iter().enumerate() {
        if admitted.get(index).is_some_and(|flag| flag.load(Ordering::Acquire)) {
            continue;
        }
        if matches!(detail.status, BnSyncStatus::Unreachable | BnSyncStatus::Unknown) {
            continue;
        }
        if let Err(err) = admit_client(clients, admitted, identity, index).await {
            warn!(
                bn_index = index,
                error = %err,
                "skipped beacon node did not match the boot chain"
            );
        }
    }
}

async fn admit_client(
    clients: &[BeaconClient],
    admitted: &[AtomicBool],
    identity: &tokio::sync::RwLock<Option<AgreedChain>>,
    index: usize,
) -> Result<(), BeaconError> {
    let Some(client) = clients.get(index) else {
        return Err(BeaconError::HttpError("beacon node index out of range".into()));
    };
    // The stored root is the configured genesis validators root, not whichever
    // responder answered first. A recovered node must match that root.
    let agreed =
        identity.read().await.clone().ok_or_else(|| {
            BeaconError::HttpError("beacon chain identity is not established".into())
        })?;
    let spec = client.get_config_spec().await?;
    let duration_ms = beacon::parse_slot_duration_ms(&spec.data)?;
    let slots = beacon::parse_slots_per_epoch(&spec.data)?;
    if duration_ms != agreed.slot_duration_ms {
        return Err(BeaconError::ParseError(format!(
            "beacon nodes disagree on slot duration: {} vs {duration_ms}",
            agreed.slot_duration_ms
        )));
    }
    if slots != agreed.slots_per_epoch {
        return Err(BeaconError::ParseError(format!(
            "beacon nodes disagree on SLOTS_PER_EPOCH: {} vs {slots}",
            agreed.slots_per_epoch
        )));
    }
    let genesis = client.get_genesis().await?;
    let parsed_genesis = genesis
        .data
        .genesis_time
        .parse::<u64>()
        .map_err(|e| BeaconError::ParseError(format!("invalid genesis_time: {e}")))?;
    if parsed_genesis != agreed.genesis_time {
        return Err(BeaconError::ParseError(format!(
            "beacon nodes disagree on genesis_time: {} vs {parsed_genesis}",
            agreed.genesis_time
        )));
    }
    if !beacon::hex_ids_equal(
        &agreed.genesis_validators_root,
        &genesis.data.genesis_validators_root,
    ) {
        return Err(BeaconError::ParseError(
            "beacon nodes disagree on genesis_validators_root".into(),
        ));
    }
    if let Some(flag) = admitted.get(index) {
        flag.store(true, Ordering::Release);
    }
    Ok(())
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

    async fn confirm_genesis_validators_root(
        &self,
        expected_root_hex: &str,
    ) -> Result<(), BeaconError> {
        let mut matched = 0u32;
        let mut mismatch = None;
        for (index, client) in self.clients.iter().enumerate() {
            match client.get_genesis().await {
                Ok(genesis) => {
                    if beacon::hex_ids_equal(
                        &genesis.data.genesis_validators_root,
                        expected_root_hex,
                    ) {
                        matched += 1;
                    } else {
                        self.mark_unadmitted(index);
                        mismatch = Some(genesis.data.genesis_validators_root);
                    }
                }
                Err(err) if is_unreachable(&err) => self.mark_unadmitted(index),
                Err(err) => return Err(err),
            }
        }
        if matched == 0 {
            return Err(match mismatch {
                Some(root) => BeaconError::GenesisValidatorsRootMismatch { root },
                None => BeaconError::HttpError("no beacon node responded with genesis".into()),
            });
        }
        Ok(())
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
        // Head capture uses this budget so one hung beacon node cannot consume
        // the phase. `query_first` splits the remaining time across attempts.
        let deadline = self
            .op_timeout(|t| t.attestation_fetch)
            .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
        self.query_first("get_block_root", BnRole::All, HealthTier::SmallLag, deadline, |c| {
            Box::pin(c.get_block_root(block_id))
        })
        .await
    }

    async fn get_block_header(&self, block_id: &str) -> Result<BlockHeaderSummary, BeaconError> {
        // no budget: header lookup; OperationTimeouts has no field for it
        self.query_first("get_block_header", BnRole::All, HealthTier::SmallLag, None, |c| {
            Box::pin(c.get_block_header(block_id))
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
        let deadline = self
            .op_timeout(|t| t.duty_fetch)
            .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
        let deadline = self
            .op_timeout(|t| t.duty_fetch)
            .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
        let deadline = self
            .op_timeout(|t| t.duty_fetch)
            .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
        let deadline = self
            .op_timeout(|t| t.duty_fetch)
            .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
        // No duty context: do not fall back. The parent root is unknown, so a
        // degraded node must not supply the block.
        let ranked = self
            .produce_block_v3_ranked(slot, randao_reveal, graffiti, builder_boost_factor, None)
            .await?;
        first_ranked(ranked)
    }

    async fn produce_block_v3_ranked(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        duty: Option<ProduceDuty>,
    ) -> Result<Vec<RankedBlock>, BeaconError> {
        self.produce_block_v3_ranked_by(
            slot,
            randao_reveal,
            graffiti,
            builder_boost_factor,
            duty,
            None,
        )
        .await
    }

    async fn produce_block_v3_ranked_by(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        duty: Option<ProduceDuty>,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Vec<RankedBlock>, BeaconError> {
        let checks = duty.map(|duty| checks_from_duty(slot, duty));
        self.produce_block_v3_checked(
            slot,
            randao_reveal,
            graffiti,
            builder_boost_factor,
            checks,
            deadline,
        )
        .await
    }

    async fn produce_block_v3_for_duty(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        duty: ProduceDuty,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        let ranked = self
            .produce_block_v3_ranked(
                slot,
                randao_reveal,
                graffiti,
                builder_boost_factor,
                Some(duty),
            )
            .await?;
        first_ranked(ranked)
    }

    async fn produce_block_v4(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        self.produce_block_v4_by(slot, randao_reveal, graffiti, builder_config, None).await
    }

    async fn produce_block_v4_by(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        let budget = self.production_budget(deadline);
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
        // Deneb+ JSON is the object body that was hashed. Hex serde of
        // `BeaconBlock` is what the beacon node rejects after the signature.
        let wire = json_signed_block(signed_block, consensus_version)?;
        self.submit(
            "publish_block",
            self.broadcast_topics.blocks,
            BnRole::Submission,
            HealthTier::LargeLag,
            self.op_timeout(|t| t.block_publication),
            owned_attempt!(
                (wire, consensus_version.to_owned(), builder_url.map(str::to_owned)),
                |client, payload| client
                    .publish_block(&payload.0, &payload.1, payload.2.as_deref())
                    .await
            ),
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
            owned_attempt!(
                (contents.clone(), consensus_version.to_owned(), builder_url.map(str::to_owned)),
                |client, payload| client
                    .publish_block_contents(&payload.0, &payload.1, payload.2.as_deref())
                    .await
            ),
        )
        .await
    }

    async fn publish_blinded_block(
        &self,
        signed_blinded_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        // One JSON object for every fan-out attempt. A bad fork or body returns
        // before submit, so no beacon node is called and nothing is signed here.
        let layout = eth_types::body_fork_layout(consensus_version).ok_or_else(|| {
            BeaconError::ParseError(format!(
                "JSON blinded block is unsupported for consensus version {consensus_version}"
            ))
        })?;
        let wire = eth_types::SignedBlindedBeaconBlockJson::from_signed_blinded(
            signed_blinded_block,
            layout,
        )
        .map_err(|err| {
            BeaconError::ParseError(format!("invalid JSON blinded block body: {err}"))
        })?;
        self.submit(
            "publish_blinded_block",
            self.broadcast_topics.blocks,
            BnRole::Submission,
            HealthTier::LargeLag,
            self.op_timeout(|t| t.block_publication),
            owned_attempt!((wire, consensus_version.to_owned()), |client, payload| client
                .publish_blinded_block(&payload.0, &payload.1)
                .await),
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
            let budget = self.op_timeout(|t| t.block_publication);
            self.with_op_timeout(
                "publish_block_ssz",
                fan_out::broadcast_backstop(budget),
                self.broadcast(
                    "publish_block_ssz",
                    BnRole::Submission,
                    budget,
                    owned_attempt!(
                        (
                            ssz_bytes.to_vec(),
                            consensus_version.to_owned(),
                            is_blinded,
                            builder_url.map(str::to_owned),
                        ),
                        |client, payload| client
                            .publish_block_ssz(
                                &payload.0,
                                &payload.1,
                                payload.2,
                                payload.3.as_deref()
                            )
                            .await
                    ),
                ),
            )
            .await
        } else {
            let deadline = self
                .op_timeout(|t| t.block_publication)
                .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
            owned_attempt!(
                (
                    signed_envelope.clone(),
                    blobs.clone(),
                    kzg_proofs.clone(),
                    consensus_version.to_owned(),
                    broadcast_validation.map(str::to_owned),
                ),
                |client, payload| client
                    .publish_execution_payload_envelope(
                        &payload.0,
                        &payload.1,
                        &payload.2,
                        &payload.3,
                        payload.4.as_deref(),
                    )
                    .await
            ),
        )
        .await
    }

    // -- Proposer preparation: broadcast --

    async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        let budget = self.op_timeout(|t| t.preparation);
        self.with_op_timeout(
            "prepare_beacon_proposer",
            fan_out::broadcast_backstop(budget),
            self.broadcast(
                "prepare_beacon_proposer",
                BnRole::Proposal,
                budget,
                owned_attempt!(preparations.to_vec(), |client, payload| client
                    .prepare_beacon_proposer(payload.as_slice())
                    .await),
            ),
        )
        .await
    }

    // -- Builder: broadcast --

    async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        let budget = self.op_timeout(|t| t.preparation);
        self.with_op_timeout(
            "register_validators",
            fan_out::broadcast_backstop(budget),
            self.broadcast(
                "register_validators",
                BnRole::Proposal,
                budget,
                owned_attempt!(registrations.to_vec(), |client, payload| client
                    .register_validators(payload.as_slice())
                    .await),
            ),
        )
        .await
    }

    async fn submit_proposer_preferences(
        &self,
        preferences: &[SignedProposerPreferences],
    ) -> Result<(), BeaconError> {
        let budget = self.op_timeout(|t| t.preparation);
        self.with_op_timeout(
            "submit_proposer_preferences",
            fan_out::broadcast_backstop(budget),
            self.broadcast(
                "submit_proposer_preferences",
                BnRole::Proposal,
                budget,
                owned_attempt!(preferences.to_vec(), |client, payload| client
                    .submit_proposer_preferences(payload.as_slice())
                    .await),
            ),
        )
        .await
    }

    async fn submit_builder_preferences(
        &self,
        entries: &[BuilderPreferencesEntry],
    ) -> Result<SubmitBuilderPreferencesResult, BeaconError> {
        let budget = self.op_timeout(|t| t.preparation);
        self.with_op_timeout(
            "submit_builder_preferences",
            fan_out::broadcast_backstop(budget),
            async {
                let strategy_span = tracing::info_span!(
                    "bn.strategy.broadcast",
                    strategy = "broadcast",
                    tried = tracing::field::Empty,
                );
                async {
                    let broadcast = self
                        .broadcast_all(
                            "submit_builder_preferences",
                            BnRole::Proposal,
                            budget,
                            owned_attempt!(entries.to_vec(), |client, payload| client
                                .submit_builder_preferences(payload.as_slice())
                                .await),
                        )
                        .await?;
                    Self::log_partial_failure("submit_builder_preferences", &broadcast);
                    merge_builder_preferences_broadcast(broadcast)
                }
                .instrument(strategy_span)
                .await
            },
        )
        .await
    }
}

fn first_ranked(ranked: Vec<RankedBlock>) -> Result<ProduceBlockResponse, BeaconError> {
    ranked.into_iter().next().map(|block| block.response).ok_or_else(|| {
        BeaconError::HttpError("produce_block_v3: all BNs failed in best-selection".into())
    })
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
            .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
        self.submit_attestation_attributed(attestations).await.map(|(_endpoint, result)| result)
    }

    async fn submit_attestation_attributed(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<(Option<String>, SubmitAttestationResult), BeaconError> {
        if self.broadcast_topics.attestations {
            let budget = self.op_timeout(|t| t.attestation_submit);
            self.with_op_timeout(
                "submit_attestation",
                fan_out::broadcast_backstop(budget),
                self.broadcast_with_result_attributed(
                    "submit_attestation",
                    BnRole::Attestation,
                    budget,
                    fan_out::PublishPolicy::attestation(),
                    owned_attempt!(attestations.clone(), |client, payload| client
                        .submit_attestation(payload.as_ref())
                        .await),
                ),
            )
            .await
            .map(|(endpoint, result)| (Some(endpoint), result))
        } else {
            let deadline = self
                .op_timeout(|t| t.attestation_submit)
                .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
            self.query_first_attributed(
                "submit_attestation",
                BnRole::Submission,
                HealthTier::LargeLag,
                deadline,
                |c| Box::pin(c.submit_attestation(attestations)),
            )
            .await
            .map(|(endpoint, result)| (Some(endpoint), result))
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
            .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
        let budget = self.op_timeout(|t| t.aggregate_submit);
        self.with_op_timeout(
            "submit_aggregate_and_proofs",
            fan_out::broadcast_backstop(budget),
            self.broadcast(
                "submit_aggregate_and_proofs",
                BnRole::Aggregation,
                budget,
                owned_attempt!(proofs.clone(), |client, payload| client
                    .submit_aggregate_and_proofs(payload.as_ref())
                    .await),
            ),
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
            owned_attempt!(subscriptions.to_vec(), |client, payload| client
                .submit_beacon_committee_subscriptions(payload.as_slice())
                .await),
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
            .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
            let budget = self.op_timeout(|t| t.attestation_submit);
            self.with_op_timeout(
                "submit_payload_attestations",
                fan_out::broadcast_backstop(budget),
                self.broadcast(
                    "submit_payload_attestations",
                    BnRole::Attestation,
                    budget,
                    owned_attempt!(messages.to_vec(), |client, payload| client
                        .submit_payload_attestations(payload.as_slice())
                        .await),
                ),
            )
            .await
        } else {
            let deadline = self
                .op_timeout(|t| t.attestation_submit)
                .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
            owned_attempt!(messages.to_vec(), |client, payload| client
                .submit_sync_committee_messages(payload.as_slice())
                .await),
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
            .map(|budget| checked_deadline(tokio::time::Instant::now(), budget));
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
        let budget = self.op_timeout(|t| t.sync_contribution);
        self.with_op_timeout(
            "submit_contribution_and_proofs",
            fan_out::broadcast_backstop(budget),
            self.broadcast(
                "submit_contribution_and_proofs",
                BnRole::SyncCommittee,
                budget,
                owned_attempt!(proofs.to_vec(), |client, payload| client
                    .submit_contribution_and_proofs(payload.as_slice())
                    .await),
            ),
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
            .broadcast_all(
                "post_validator_liveness_merged",
                BnRole::All,
                None,
                owned_attempt!((epoch, validator_indices.to_vec()), |client, payload| client
                    .post_validator_liveness(payload.0, &payload.1)
                    .await),
            )
            .await?;
        Self::log_partial_failure("post_validator_liveness_merged", &broadcast);
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
        async fn confirm_genesis_validators_root(
            &self,
            expected_root_hex: &str,
        ) -> Result<(), BeaconError>;
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
        async fn get_block_header(
            &self,
            block_id: &str,
        ) -> Result<BlockHeaderSummary, BeaconError>;
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
    use crate::broadcast::BnOutcome;
    use crate::traits::{LivenessApi, NodeStatusApi};
    use crate::types::bn_capability;

    fn higher_block_value(left: &ProduceBlockResponse, right: &ProduceBlockResponse) -> bool {
        block_value(left) > block_value(right)
    }

    fn testing_select(
        accept: impl Fn(&ProduceBlockResponse) -> bool + Send + Sync + 'static,
        in_hand: impl Fn(&ProduceBlockResponse) -> bool + Send + Sync + 'static,
        pick_best: impl Fn(&ProduceBlockResponse, &ProduceBlockResponse) -> bool + Send + Sync + 'static,
        on_reject: impl Fn(usize, &str, &ProduceBlockResponse) + Send + Sync + 'static,
        allow_fallback: bool,
    ) -> BestSelect<ProduceBlockResponse> {
        let accept: Pred<ProduceBlockResponse> = Arc::new(accept);
        BestSelect {
            pick_best: Arc::new(pick_best),
            fallback_accept: Arc::clone(&accept),
            accept,
            in_hand: Arc::new(in_hand),
            on_reject: Arc::new(on_reject),
            on_chosen: Arc::new(|_, _| {}),
            allow_fallback,
        }
    }

    fn passes_sign(block: &ProduceBlockResponse, checks: &BlockDutyChecks) -> bool {
        block_passes_duty(block, checks, FeeRecipientPolicy::Sign)
    }

    /// Guard: the passthrough macro list must name every role-trait method.
    /// Primary enforcement is compile-time (missing method → trait not satisfied).
    /// This test documents the expected surface and catches accidental list drift.
    #[test]
    fn test_beacon_client_passthrough_covers_every_trait_method() {
        // Type-level: BeaconClient implements the full supertrait surface.
        fn _assert_full_client<T: BeaconNodeClient>() {}
        _assert_full_client::<BeaconClient>();

        // 38 methods across the seven role traits (see impl_beacon_client_passthrough!).
        assert_eq!(
            BEACON_CLIENT_PASSTHROUGH_METHODS.len(),
            38,
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
            "get_block_header",
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

    fn block_with_value(value: &str) -> ProduceBlockResponse {
        ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some(value.to_string()),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        }
    }

    fn manager_with_endpoints(endpoints: &[&str]) -> BnManager {
        let config = BnManagerConfig::new(
            endpoints.iter().map(|endpoint| format!("http://{endpoint}")).collect(),
        );
        BnManager::new(config).unwrap()
    }

    async fn set_sync(manager: &BnManager, index: usize, status: BnSyncStatus, distance: u64) {
        manager.sync_statuses().write().await[index] = crate::sync_status::BnSyncDetail {
            status,
            sync_distance: Some(distance),
            head_slot: Some(1000),
            is_optimistic: false,
            el_offline: false,
        };
    }

    async fn wait_until_error(manager: &BnManager, index: usize) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            let scores = manager.health_scores().await;
            if scores[index].error_rate == 1.0 {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "BN {index} error was not recorded: {scores:?}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// B-002. Budget 3s, BN-A at 300ms, BN-B at 4s. The block in hand is
    /// returned at the 1.5s soft deadline and BN-B is recorded as an error.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn best_of_returns_at_soft_deadline_and_records_the_slow_bn() {
        let manager = manager_with_endpoints(&["bn-a", "bn-b"]);
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("bn-a") {
                            tokio::time::sleep(Duration::from_millis(300)).await;
                            Ok(block_with_value("1000"))
                        } else {
                            tokio::time::sleep(Duration::from_secs(4)).await;
                            Ok(block_with_value("9000"))
                        }
                    })
                },
                higher_block_value,
            )
            .await
            .expect("BN-A's block");
        assert_eq!(start.elapsed(), Duration::from_millis(1500));
        assert_eq!(result.execution_payload_value.as_deref(), Some("1000"));
        let recorded = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let scores = manager.health_scores().await;
            if scores[0].latency_ms > 0.0 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < recorded,
                "BN-A's success was not queued: {scores:?}"
            );
            drop(scores);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        wait_until_error(&manager, 1).await;
    }

    /// No block by the soft deadline. The one at 2s is returned then.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn best_of_returns_the_first_block_after_the_soft_deadline() {
        let manager = manager_with_endpoints(&["bn-a", "bn-b"]);
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("bn-a") {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            Ok(block_with_value("1000"))
                        } else {
                            tokio::time::sleep(Duration::from_secs(4)).await;
                            Ok(block_with_value("9000"))
                        }
                    })
                },
                higher_block_value,
            )
            .await
            .expect("block at 2s");
        assert_eq!(start.elapsed(), Duration::from_secs(2));
        assert_eq!(result.execution_payload_value.as_deref(), Some("1000"));
    }

    /// Both blocks arrive before the soft deadline. The higher payload value
    /// wins, and the round does not wait out the soft deadline.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn best_of_picks_the_higher_value_when_both_arrive_before_soft() {
        let manager = manager_with_endpoints(&["bn-low", "bn-high"]);
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("bn-low") {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            Ok(block_with_value("1000"))
                        } else {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            Ok(block_with_value("5000"))
                        }
                    })
                },
                higher_block_value,
            )
            .await
            .expect("higher block");
        assert_eq!(start.elapsed(), Duration::from_millis(200));
        assert_eq!(result.execution_payload_value.as_deref(), Some("5000"));
    }

    /// With no budget the round still waits for every selected BN.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn best_of_without_a_budget_waits_for_every_bn() {
        let manager = manager_with_endpoints(&["bn-fast", "bn-slow"]);
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                None,
                |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("bn-slow") {
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            Ok(block_with_value("9000"))
                        } else {
                            Ok(block_with_value("1000"))
                        }
                    })
                },
                higher_block_value,
            )
            .await
            .expect("slow higher block");
        assert_eq!(start.elapsed(), Duration::from_secs(5));
        assert_eq!(result.execution_payload_value.as_deref(), Some("9000"));
    }

    /// One selected BN answers as soon as it is done, not at the soft deadline.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn best_of_single_bn_returns_when_that_bn_answers() {
        let manager = manager_with_endpoints(&["bn-only"]);
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                |_client| {
                    Box::pin(async {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                        Ok(block_with_value("2000"))
                    })
                },
                higher_block_value,
            )
            .await
            .expect("single block");
        assert_eq!(start.elapsed(), Duration::from_millis(300));
        assert_eq!(result.execution_payload_value.as_deref(), Some("2000"));
    }

    /// Every synced BN fails. The unsynced BN's block is returned.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn best_of_falls_back_when_every_synced_bn_fails() {
        let manager = manager_with_endpoints(&["synced-a", "synced-b", "unsynced"]);
        set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&manager, 1, BnSyncStatus::Synced, 0).await;
        set_sync(&manager, 2, BnSyncStatus::Syncing, 9).await;
        let result = manager
            .query_best(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("unsynced") {
                            Ok(block_with_value("7000"))
                        } else {
                            Err(BeaconError::ApiError { status: 500, message: "no".to_string() })
                        }
                    })
                },
                higher_block_value,
            )
            .await
            .expect("unsynced block");
        assert_eq!(result.execution_payload_value.as_deref(), Some("7000"));
    }

    /// After the hard deadline the unsynced attempt only gets the backstop.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn best_of_bounds_unsynced_fallback_by_the_backstop() {
        let manager = manager_with_endpoints(&["synced", "unsynced"]);
        set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&manager, 1, BnSyncStatus::Syncing, 9).await;
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_millis(200)),
                |_client| {
                    Box::pin(async {
                        tokio::time::sleep(Duration::from_secs(10)).await;
                        Ok(block_with_value("7000"))
                    })
                },
                higher_block_value,
            )
            .await;
        assert!(result.is_err(), "fallback past the backstop must not return a block: {result:?}");
        assert_eq!(start.elapsed(), Duration::from_millis(450));
    }

    fn parent_hex(parent: &[u8; 32]) -> String {
        let mut hex = String::from("0x");
        for byte in parent {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }

    fn duty_response(
        execution: &str,
        slot: u64,
        proposer: u64,
        parent: [u8; 32],
        fee: Option<[u8; 20]>,
    ) -> ProduceBlockResponse {
        let body = match fee {
            Some(fee) => serde_json::json!({
                "execution_payload": { "fee_recipient": parent_hex_n(&fee) }
            }),
            None => serde_json::json!({}),
        };
        ProduceBlockResponse {
            data: serde_json::json!({
                "slot": slot.to_string(),
                "proposer_index": proposer.to_string(),
                "parent_root": parent_hex(&parent),
                "state_root": parent_hex(&[0u8; 32]),
                "body": body,
            }),
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some(execution.to_string()),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        }
    }

    fn parent_hex_n(bytes: &[u8]) -> String {
        let mut hex = String::from("0x");
        for byte in bytes {
            hex.push_str(&format!("{byte:02x}"));
        }
        hex
    }

    /// A fast block that fails the proposer check must not close the soft
    /// window. The later block that matches the duty is the one returned.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn rejected_candidate_does_not_close_the_soft_deadline() {
        let manager = manager_with_endpoints(&["bn-junk", "bn-valid"]);
        let parent = [0xabu8; 32];
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: None,
            consensus_version: ForkName::Deneb,
        };
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("bn-junk") {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            Ok(duty_response("9000", 1, 99, parent, None))
                        } else {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            Ok(duty_response("1000", 1, 7, parent, None))
                        }
                    })
                },
                testing_select(
                    move |block| passes_sign(block, &checks),
                    move |block| passes_sign(block, &checks),
                    higher_block_value,
                    |_, _, _| {},
                    false,
                ),
            )
            .await
            .expect("the valid block");
        assert_eq!(start.elapsed(), Duration::from_secs(2));
        assert_eq!(result.execution_payload_value.as_deref(), Some("1000"));
    }

    /// Both candidates are in hand before the soft deadline. The higher value
    /// fails the duty check, so the lower valid block is the one returned.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn invalid_high_value_candidate_yields_the_next_valid_one() {
        let parent = [0xabu8; 32];
        let valid = duty_response("1000", 1, 7, parent, None);
        let wrong_proposer = duty_response("9000", 1, 99, parent, None);
        let (elapsed, picked) = ranked_valid_block(wrong_proposer, valid.clone()).await;
        assert_eq!(picked.execution_payload_value.as_deref(), Some("1000"));
        assert_eq!(elapsed, Duration::from_millis(80));

        let mut wrong_version = duty_response("9000", 1, 7, parent, None);
        wrong_version.consensus_version = "phase0".to_string();
        let (elapsed, picked) = ranked_valid_block(wrong_version, valid).await;
        assert_eq!(picked.execution_payload_value.as_deref(), Some("1000"));
        assert_eq!(elapsed, Duration::from_millis(80));
    }

    async fn ranked_valid_block(
        junk: ProduceBlockResponse,
        valid: ProduceBlockResponse,
    ) -> (Duration, ProduceBlockResponse) {
        let manager = manager_with_endpoints(&["bn-junk", "bn-valid"]);
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some([0xab; 32]),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: None,
            consensus_version: ForkName::Deneb,
        };
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                move |client| {
                    let endpoint = client.endpoint().to_string();
                    let junk = junk.clone();
                    let valid = valid.clone();
                    Box::pin(async move {
                        if endpoint.contains("bn-junk") {
                            tokio::time::sleep(Duration::from_millis(20)).await;
                            Ok(junk)
                        } else {
                            tokio::time::sleep(Duration::from_millis(80)).await;
                            Ok(valid)
                        }
                    })
                },
                testing_select(
                    move |block| passes_sign(block, &checks),
                    move |block| passes_sign(block, &checks),
                    higher_block_value,
                    |_, _, _| {},
                    false,
                ),
            )
            .await
            .expect("the next valid block");
        (start.elapsed(), result)
    }

    /// Fallback stays on untried proposal-role BNs above the health floor.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn fallback_stays_on_proposal_role_bns_above_the_health_floor() {
        let mut manager = manager_with_endpoints(&[
            "synced",
            "attest",
            "stale",
            "large",
            "optimistic",
            "unhealthy",
            "offline",
            "small",
        ]);
        set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&manager, 1, BnSyncStatus::Syncing, 9).await;
        set_sync(&manager, 2, BnSyncStatus::Syncing, 500).await;
        set_sync(&manager, 3, BnSyncStatus::Syncing, 17).await;
        manager.sync_statuses().write().await[4] = crate::sync_status::BnSyncDetail {
            status: BnSyncStatus::Syncing,
            sync_distance: Some(9),
            head_slot: Some(1000),
            is_optimistic: true,
            el_offline: false,
        };
        set_sync(&manager, 5, BnSyncStatus::Syncing, 9).await;
        manager.health_trackers().write().await[5].record_error();
        manager.sync_statuses().write().await[6] = crate::sync_status::BnSyncDetail {
            status: BnSyncStatus::Syncing,
            sync_distance: Some(9),
            head_slot: Some(1000),
            is_optimistic: false,
            el_offline: true,
        };
        set_sync(&manager, 7, BnSyncStatus::Syncing, 9).await;
        manager.roles[1] = std::collections::HashSet::from([BnRole::Attestation]);

        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen_op = std::sync::Arc::clone(&seen);
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                move |client| {
                    let endpoint = client.endpoint().to_string();
                    let seen_op = std::sync::Arc::clone(&seen_op);
                    Box::pin(async move {
                        seen_op.lock().expect("seen").push(endpoint.clone());
                        if endpoint.contains("synced") {
                            Err(BeaconError::ApiError { status: 500, message: "no".to_string() })
                        } else if endpoint.contains("small") {
                            Ok(block_with_value("7000"))
                        } else {
                            Ok(block_with_value("bad"))
                        }
                    })
                },
                testing_select(|_| true, |_| true, higher_block_value, |_, _, _| {}, true),
            )
            .await
            .expect("small-lag proposal block");
        assert_eq!(result.execution_payload_value.as_deref(), Some("7000"));
        let seen = seen.lock().expect("seen");
        assert!(seen.iter().any(|endpoint| endpoint.contains("synced")));
        assert!(seen.iter().any(|endpoint| endpoint.contains("small")));
        for forbidden in ["attest", "stale", "large", "optimistic", "unhealthy", "offline"] {
            assert!(
                seen.iter().all(|endpoint| !endpoint.contains(forbidden)),
                "{forbidden} was tried: {seen:?}"
            );
        }
    }

    /// No known parent root: do not fall back, even when a proposal-role BN
    /// above the floor would answer.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn fallback_requires_a_known_parent() {
        let manager = manager_with_endpoints(&["synced", "small"]);
        set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&manager, 1, BnSyncStatus::Syncing, 9).await;
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen_op = std::sync::Arc::clone(&seen);
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                move |client| {
                    let endpoint = client.endpoint().to_string();
                    let seen_op = std::sync::Arc::clone(&seen_op);
                    Box::pin(async move {
                        seen_op.lock().expect("seen").push(endpoint.clone());
                        if endpoint.contains("small") {
                            Ok(block_with_value("7000"))
                        } else {
                            Err(BeaconError::ApiError { status: 500, message: "no".to_string() })
                        }
                    })
                },
                testing_select(|_| true, |_| true, higher_block_value, |_, _, _| {}, false),
            )
            .await;
        assert!(result.is_err(), "fallback without a parent must not return a block: {result:?}");
        let seen = seen.lock().expect("seen");
        assert!(seen.iter().all(|endpoint| !endpoint.contains("small")), "tried {seen:?}");
    }

    /// A fallback block with the wrong parent is not returned. A fee mismatch
    /// is held so the later matching proposal-role BN wins.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn fallback_rejects_a_parent_mismatch_and_ranks_fee_below_a_match() {
        let manager = manager_with_endpoints(&["synced", "wrong", "right"]);
        set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&manager, 1, BnSyncStatus::Syncing, 9).await;
        set_sync(&manager, 2, BnSyncStatus::Syncing, 9).await;
        let parent = [0xabu8; 32];
        let fee = [0x11u8; 20];
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some(fee),
            consensus_version: ForkName::Deneb,
        };
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                move |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("wrong") {
                            Ok(duty_response("9000", 1, 7, parent, Some([0x22; 20])))
                        } else if endpoint.contains("right") {
                            Ok(duty_response("1000", 1, 7, parent, Some(fee)))
                        } else {
                            Err(BeaconError::ApiError { status: 500, message: "no".to_string() })
                        }
                    })
                },
                testing_select(
                    move |block| passes_sign(block, &checks),
                    move |block| passes_sign(block, &checks) && fee_preferred(block, &checks),
                    move |left, right| candidate_ranks_above(left, right, Some(&checks)),
                    |_, _, _| {},
                    true,
                ),
            )
            .await
            .expect("matching fallback block");
        assert_eq!(result.execution_payload_value.as_deref(), Some("1000"));
    }

    /// A full Bellatrix+ block with no fee recipient is a hard reject.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn fallback_rejects_a_block_with_no_fee_recipient() {
        let manager = manager_with_endpoints(&["synced", "small"]);
        set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&manager, 1, BnSyncStatus::Syncing, 9).await;
        let parent = [0xabu8; 32];
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some([0x11; 20]),
            consensus_version: ForkName::Deneb,
        };
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                move |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("small") {
                            Ok(duty_response("1000", 1, 7, parent, None))
                        } else {
                            Err(BeaconError::ApiError { status: 500, message: "no".to_string() })
                        }
                    })
                },
                testing_select(
                    move |block| passes_sign(block, &checks),
                    move |block| passes_sign(block, &checks) && fee_preferred(block, &checks),
                    higher_block_value,
                    |_, _, _| {},
                    true,
                ),
            )
            .await;
        assert!(
            result.is_err(),
            "a full block without a fee recipient must be rejected: {result:?}"
        );
    }

    /// A wrong fee at 50ms must not close the soft window. The matching fee
    /// at 1.6s, past the 1.5s soft deadline of a 3s budget, is the block returned.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn wrong_fee_at_50ms_loses_to_a_correct_fee_at_1600ms() {
        let manager = manager_with_endpoints(&["bn-wrong", "bn-right"]);
        let parent = [0xabu8; 32];
        let fee = [0x11u8; 20];
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some(fee),
            consensus_version: ForkName::Deneb,
        };
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                move |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("bn-wrong") {
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            Ok(duty_response("9000", 1, 7, parent, Some([0x22; 20])))
                        } else {
                            tokio::time::sleep(Duration::from_millis(1600)).await;
                            Ok(duty_response("1000", 1, 7, parent, Some(fee)))
                        }
                    })
                },
                testing_select(
                    move |block| passes_sign(block, &checks),
                    move |block| passes_sign(block, &checks) && fee_preferred(block, &checks),
                    move |left, right| candidate_ranks_above(left, right, Some(&checks)),
                    |_, _, _| {},
                    false,
                ),
            )
            .await
            .expect("the matching fee");
        assert_eq!(result.execution_payload_value.as_deref(), Some("1000"));
        assert_eq!(start.elapsed(), Duration::from_millis(1600));
    }

    /// BN1 returns a signable wrong-fee block. BN2 hangs. The held block must
    /// come back before the outer backstop turns it into OperationTimeout.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_fee_penalty_returns_before_the_outer_backstop_when_fallback_hangs() {
        let budget = Duration::from_millis(200);
        let manager =
            manager_with_endpoints(&["synced", "penalty", "hang"]).with_operation_timeouts(
                OperationTimeouts { block_production: budget, ..OperationTimeouts::default() },
            );
        set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&manager, 1, BnSyncStatus::Syncing, 9).await;
        set_sync(&manager, 2, BnSyncStatus::Syncing, 9).await;
        let parent = [0xabu8; 32];
        let fee = [0x11u8; 20];
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some(fee),
            consensus_version: ForkName::Deneb,
        };
        let start = tokio::time::Instant::now();
        let result = manager
            .with_op_timeout(
                "produce_block_v3",
                fan_out::broadcast_backstop(Some(budget)),
                manager.query_best_filtered(
                    "produce_block_v3",
                    BnRole::Proposal,
                    HealthTier::Synced,
                    Some(budget),
                    move |client| {
                        let endpoint = client.endpoint().to_string();
                        Box::pin(async move {
                            if endpoint.contains("penalty") {
                                Ok(duty_response("9000", 1, 7, parent, Some([0x22; 20])))
                            } else if endpoint.contains("hang") {
                                tokio::time::sleep(Duration::from_secs(10)).await;
                                Ok(duty_response("1", 1, 7, parent, Some(fee)))
                            } else {
                                Err(BeaconError::ApiError {
                                    status: 500,
                                    message: "no".to_string(),
                                })
                            }
                        })
                    },
                    testing_select(
                        move |block| passes_sign(block, &checks),
                        move |block| passes_sign(block, &checks) && fee_preferred(block, &checks),
                        move |left, right| candidate_ranks_above(left, right, Some(&checks)),
                        |_, _, _| {},
                        true,
                    ),
                ),
            )
            .await;
        let elapsed = start.elapsed();
        let block = result.expect("a held wrong-fee block must beat the outer backstop");
        assert_eq!(block.execution_payload_value.as_deref(), Some("9000"));
        assert!(
            elapsed < budget + fan_out::BACKSTOP_MARGIN,
            "held block returned at {elapsed:?}, which is the outer backstop"
        );
    }

    /// Two penalized fallback blocks and no match: the higher value wins.
    /// Keeping the first held block would return 1000.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn held_fee_penalty_keeps_the_higher_value_not_the_first() {
        let manager = manager_with_endpoints(&["synced", "low", "high"]);
        set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&manager, 1, BnSyncStatus::Syncing, 9).await;
        set_sync(&manager, 2, BnSyncStatus::Syncing, 9).await;
        let parent = [0xabu8; 32];
        let fee = [0x11u8; 20];
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some(fee),
            consensus_version: ForkName::Deneb,
        };
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                move |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("low") {
                            Ok(duty_response("1000", 1, 7, parent, Some([0x22; 20])))
                        } else if endpoint.contains("high") {
                            Ok(duty_response("9000", 1, 7, parent, Some([0x33; 20])))
                        } else {
                            Err(BeaconError::ApiError { status: 500, message: "no".to_string() })
                        }
                    })
                },
                testing_select(
                    move |block| passes_sign(block, &checks),
                    move |block| passes_sign(block, &checks) && fee_preferred(block, &checks),
                    move |left, right| candidate_ranks_above(left, right, Some(&checks)),
                    |_, _, _| {},
                    true,
                ),
            )
            .await
            .expect("the higher penalized block");
        assert_eq!(result.execution_payload_value.as_deref(), Some("9000"));
    }

    #[test]
    fn zero_operation_budget_is_no_budget() {
        let manager = manager_with_endpoints(&["bn"]).with_operation_timeouts(OperationTimeouts {
            block_production: Duration::ZERO,
            attestation_fetch: Duration::from_millis(1),
            ..OperationTimeouts::default()
        });
        assert_eq!(manager.op_timeout(|timeouts| timeouts.block_production), None);
        assert_eq!(
            manager.op_timeout(|timeouts| timeouts.attestation_fetch),
            Some(Duration::from_millis(1))
        );
        let stored = manager.operation_timeouts().expect("budgets were stored");
        assert_eq!(stored.block_production, Duration::ZERO);
        assert_eq!(stored.attestation_fetch, Duration::from_millis(1));
    }

    #[test]
    fn operation_timeouts_getter_is_none_until_budgets_are_stored() {
        let manager = manager_with_endpoints(&["bn"]);
        assert!(manager.operation_timeouts().is_none());
    }

    #[test]
    fn ssz_block_passes_slot_proposer_and_parent() {
        let mut bytes = vec![0u8; 84];
        bytes[0..8].copy_from_slice(&7u64.to_le_bytes());
        bytes[8..16].copy_from_slice(&42u64.to_le_bytes());
        bytes[16..48].copy_from_slice(&[0xab; 32]);
        bytes[80..84].copy_from_slice(&84u32.to_le_bytes());
        let block = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: true,
            consensus_version: "deneb".to_string(),
            execution_payload_value: Some("1".to_string()),
            is_ssz: true,
            ssz_bytes: Some(bytes),
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        };
        let checks = BlockDutyChecks {
            slot: 7,
            proposer_index: 42,
            parent_root: Some([0xab; 32]),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some([0x11; 20]),
            consensus_version: ForkName::Deneb,
        };
        assert!(passes_sign(&block, &checks));
        let wrong_parent = BlockDutyChecks { parent_root: Some([0xcd; 32]), ..checks };
        assert!(!passes_sign(&block, &wrong_parent));
    }

    #[test]
    fn duty_checks_reject_slot_proposer_parent_and_fork_not_a_wrong_fee() {
        let parent = [0xabu8; 32];
        let fee = [0x11u8; 20];
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some(fee),
            consensus_version: ForkName::Deneb,
        };
        let matching = duty_response("1", 1, 7, parent, Some(fee));
        assert!(passes_sign(&matching, &checks));
        assert!(fee_preferred(&matching, &checks));
        assert!(!passes_sign(&duty_response("1", 2, 7, parent, Some(fee)), &checks));
        assert!(!passes_sign(&duty_response("1", 1, 8, parent, Some(fee)), &checks));
        assert!(!passes_sign(&duty_response("1", 1, 7, [0xcd; 32], Some(fee)), &checks));
        let mismatched = duty_response("1", 1, 7, parent, Some([0x22; 20]));
        assert!(passes_sign(&mismatched, &checks));
        assert!(!fee_preferred(&mismatched, &checks));
        let missing = duty_response("1", 1, 7, parent, None);
        assert!(!passes_sign(&missing, &checks));
        assert!(!block_passes_duty(&mismatched, &checks, FeeRecipientPolicy::Reject));
        let mut wrong_version = duty_response("9000", 1, 7, parent, Some(fee));
        wrong_version.consensus_version = "phase0".to_string();
        assert!(!passes_sign(&wrong_version, &checks));
        wrong_version.consensus_version = "not-a-fork".to_string();
        assert!(!passes_sign(&wrong_version, &checks));

        let high = duty_response("9000", 1, 7, parent, Some([0x22; 20]));
        let low = duty_response("1000", 1, 7, parent, Some(fee));
        assert!(candidate_ranks_above(&low, &high, Some(&checks)));
        assert!(!candidate_ranks_above(&high, &low, Some(&checks)));
    }

    /// The re-org parent is copied onto the duty checks, ranks below the
    /// primary parent, and does not count as in hand.
    #[test]
    fn reorg_parent_is_stored_on_the_duty_checks() {
        let primary = [0x11u8; 32];
        let reorg = [0x22u8; 32];
        let checks = checks_from_duty(
            1,
            ProduceDuty {
                expected_proposer_index: 7,
                expected_parent_root: Some(primary),
                alternate_parent_root: Some(reorg),
                parent_closed: false,
                expected_fee_recipient: None,
                expected_consensus_version: ForkName::Deneb,
            },
        );
        assert_eq!(checks.parent_root, Some(primary));
        assert_eq!(checks.alternate_parent_root, Some(reorg));
        assert!(!checks.parent_closed);

        let primary_block = duty_response("1000", 1, 7, primary, None);
        let reorg_block = duty_response("9000", 1, 7, reorg, None);
        let other = duty_response("9000", 1, 7, [0x33; 32], None);
        assert!(passes_sign(&primary_block, &checks));
        assert!(passes_sign(&reorg_block, &checks));
        assert!(!passes_sign(&other, &checks));
        assert!(parent_is_primary(&primary_block, &checks));
        assert!(!parent_is_primary(&reorg_block, &checks));
        assert!(candidate_ranks_above(&primary_block, &reorg_block, Some(&checks)));
        assert!(!candidate_ranks_above(&reorg_block, &primary_block, Some(&checks)));

        let closed = checks_from_duty(
            1,
            ProduceDuty {
                expected_proposer_index: 7,
                expected_parent_root: None,
                alternate_parent_root: None,
                parent_closed: true,
                expected_fee_recipient: None,
                expected_consensus_version: ForkName::Deneb,
            },
        );
        assert!(matches!(
            hard_reject_reason(&primary_block, &closed, FeeRecipientPolicy::Sign),
            Some(HardReject::Parent)
        ));
        assert!(!passes_sign(&duty_response("1", 1, 7, [0u8; 32], None), &closed));
    }

    /// A fast re-org parent must not close the soft window ahead of the primary.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn alternate_parent_does_not_close_the_soft_deadline() {
        let manager = manager_with_endpoints(&["bn-reorg", "bn-primary"]);
        let primary = [0x11u8; 32];
        let reorg = [0x22u8; 32];
        let checks = checks_from_duty(
            1,
            ProduceDuty {
                expected_proposer_index: 7,
                expected_parent_root: Some(primary),
                alternate_parent_root: Some(reorg),
                parent_closed: false,
                expected_fee_recipient: None,
                expected_consensus_version: ForkName::Deneb,
            },
        );
        let start = tokio::time::Instant::now();
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("bn-reorg") {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            Ok(duty_response("9000", 1, 7, reorg, None))
                        } else {
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            Ok(duty_response("1000", 1, 7, primary, None))
                        }
                    })
                },
                produce_best_select(Some(checks), FeeRecipientPolicy::Sign),
            )
            .await
            .expect("primary parent");
        assert_eq!(result.execution_payload_value.as_deref(), Some("1000"));
        assert!(
            start.elapsed() >= Duration::from_secs(2),
            "reorg parent must not win at the soft deadline, elapsed {:?}",
            start.elapsed()
        );
    }

    /// Fallback keeps the primary parent and drops the re-org parent.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn fallback_accepts_only_the_primary_parent() {
        let primary = [0x11u8; 32];
        let reorg = [0x22u8; 32];
        let checks = checks_from_duty(
            1,
            ProduceDuty {
                expected_proposer_index: 7,
                expected_parent_root: Some(primary),
                alternate_parent_root: Some(reorg),
                parent_closed: false,
                expected_fee_recipient: None,
                expected_consensus_version: ForkName::Deneb,
            },
        );

        let reorg_only = manager_with_endpoints(&["synced", "fallback-reorg"]);
        set_sync(&reorg_only, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&reorg_only, 1, BnSyncStatus::Syncing, 9).await;
        let rejected = reorg_only
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("fallback-reorg") {
                            Ok(duty_response("9000", 1, 7, reorg, None))
                        } else {
                            Err(BeaconError::ApiError { status: 500, message: "no".to_string() })
                        }
                    })
                },
                produce_best_select(Some(checks), FeeRecipientPolicy::Sign),
            )
            .await;
        assert!(rejected.is_err(), "fallback must not return the reorg parent: {rejected:?}");

        let primary_fallback = manager_with_endpoints(&["synced", "fallback-primary"]);
        set_sync(&primary_fallback, 0, BnSyncStatus::Synced, 0).await;
        set_sync(&primary_fallback, 1, BnSyncStatus::Syncing, 9).await;
        let accepted = primary_fallback
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                |client| {
                    let endpoint = client.endpoint().to_string();
                    Box::pin(async move {
                        if endpoint.contains("fallback-primary") {
                            Ok(duty_response("7000", 1, 7, primary, None))
                        } else {
                            Err(BeaconError::ApiError { status: 500, message: "no".to_string() })
                        }
                    })
                },
                produce_best_select(Some(checks), FeeRecipientPolicy::Sign),
            )
            .await
            .expect("primary parent on fallback");
        assert_eq!(accepted.execution_payload_value.as_deref(), Some("7000"));
    }

    /// A hard reject logs slot, proposer, parent, fork, fee, and the value parse.
    #[tokio::test(flavor = "current_thread")]
    #[tracing_test::traced_test]
    async fn rejected_candidate_logs_the_duty_comparison() {
        let manager = manager_with_endpoints(&["bn-junk"]);
        let parent = [0xabu8; 32];
        let fee = [0x11u8; 20];
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some(fee),
            consensus_version: ForkName::Deneb,
        };
        let result = manager
            .query_best_filtered(
                "produce_block_v3",
                BnRole::Proposal,
                HealthTier::Synced,
                Some(Duration::from_secs(3)),
                move |_client| {
                    Box::pin(async move { Ok(duty_response("1", 2, 7, parent, Some(fee))) })
                },
                testing_select(
                    move |block| passes_sign(block, &checks),
                    move |block| passes_sign(block, &checks),
                    higher_block_value,
                    move |index, endpoint, block| {
                        log_produce_rejection(
                            index,
                            endpoint,
                            block,
                            &checks,
                            FeeRecipientPolicy::Sign,
                        );
                    },
                    false,
                ),
            )
            .await;
        assert!(result.is_err(), "a wrong slot must still be rejected: {result:?}");
        assert!(logs_contain("best-of candidate rejected"));
        assert!(logs_contain("reason=slot") || logs_contain("reason=\"slot\""));
        assert!(logs_contain("slot_expected=1"));
        assert!(logs_contain("slot_got=2"));
        assert!(logs_contain("proposer_expected=7"));
        assert!(logs_contain("proposer_got=7"));
        assert!(logs_contain("fork_expected=deneb") || logs_contain("fork_expected=\"deneb\""));
        assert!(logs_contain("fork_got=deneb") || logs_contain("fork_got=\"deneb\""));
        assert!(logs_contain("0x1111111111111111111111111111111111111111"));
        assert!(logs_contain(&hex_prefixed(&parent)));
        assert!(logs_contain("value_parse=ok:1") || logs_contain("value_parse=\"ok:1\""));
    }

    #[test]
    fn display_value_parse_names_an_unparsed_header() {
        let parent = [0xabu8; 32];
        let mut block = duty_response("12abc", 1, 7, parent, None);
        assert_eq!(display_value_parse(&block), "unparsed:12abc");
        block.execution_payload_value = Some(String::new());
        assert_eq!(display_value_parse(&block), "unparsed:empty");
        block.execution_payload_value = None;
        assert_eq!(display_value_parse(&block), "unparsed:missing");
        block.execution_payload_value = Some("5".to_string());
        block.consensus_block_value = Some("nope".to_string());
        assert_eq!(display_value_parse(&block), "unparsed:5");
        block.consensus_block_value = None;
        assert_eq!(display_value_parse(&block), "ok:5");
        block.consensus_block_value = Some("10".to_string());
        assert_eq!(display_value_parse(&block), "ok:15");
        block.execution_payload_value = Some(u128::MAX.to_string());
        block.consensus_block_value = Some("1".to_string());
        assert_eq!(display_value_parse(&block), format!("ok:{}", u128::MAX));
    }

    /// A builder header's fee recipient is the builder's address. It must not
    /// drop the bid. A full block is checked from `execution_payload` only.
    #[test]
    fn blinded_header_fee_does_not_reject_the_block() {
        let parent = [0xabu8; 32];
        let expected = [0x11u8; 20];
        let checks = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some(expected),
            consensus_version: ForkName::Deneb,
        };
        let mut blinded = duty_response("1", 1, 7, parent, None);
        blinded.is_blinded = true;
        blinded.data["body"] = serde_json::json!({
            "execution_payload_header": { "fee_recipient": parent_hex_n(&[0x22; 20]) }
        });
        assert!(passes_sign(&blinded, &checks));
        assert!(
            fee_preferred(&blinded, &checks),
            "a blinded header fee is the builder's address and must stay preferred"
        );
        let wrong_full = duty_response("9000", 1, 7, parent, Some([0x22; 20]));
        assert!(candidate_ranks_above(&blinded, &wrong_full, Some(&checks)));
        assert!(!candidate_ranks_above(&wrong_full, &blinded, Some(&checks)));

        let mut header_only = blinded.clone();
        header_only.is_blinded = false;
        assert!(
            !passes_sign(&header_only, &checks),
            "a full block that only carries a header fee is unreadable"
        );

        let mut payload = duty_response("1", 1, 7, parent, Some(expected));
        payload.data["body"]["execution_payload_header"] =
            serde_json::json!({ "fee_recipient": parent_hex_n(&[0x22; 20]) });
        assert!(passes_sign(&payload, &checks));
        assert!(fee_preferred(&payload, &checks));
    }

    /// A document with both a top-level block and a nested `block` is not ranked.
    ///
    /// The top-level fee matches the duty. A reader that prefers `slot` would
    /// return the block and the nested block would be the one signed.
    #[tokio::test]
    async fn hybrid_block_contents_is_a_hard_reject() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let parent = "ab".repeat(32);
        let state = "00".repeat(32);
        let fee = "11".repeat(20);
        let nested = format!(
            r#"{{"slot":"1","proposer_index":"7","parent_root":"0x{parent}","state_root":"0x{state}","body":{{"execution_payload":{{"fee_recipient":"0x{fee}"}}}}}}"#
        );
        let contents =
            format!(r#"{{"data":{{"block":{nested},"kzg_proofs":["0xab"],"blobs":["0xcd"]}}}}"#);
        let hybrid = format!(
            r#"{{"data":{{"slot":"1","proposer_index":"7","parent_root":"0x{parent}","state_root":"0x{state}","body":{{"execution_payload":{{"fee_recipient":"0x{fee}"}}}},"block":{nested},"kzg_proofs":["0xab"],"blobs":["0xcd"]}}}}"#
        );
        let duty = ProduceDuty {
            expected_proposer_index: 7,
            expected_parent_root: Some([0xab; 32]),
            alternate_parent_root: None,
            parent_closed: false,
            expected_fee_recipient: Some([0x11; 20]),
            expected_consensus_version: ForkName::Deneb,
        };

        async fn ranked(body: &str, duty: ProduceDuty) -> Result<Vec<RankedBlock>, BeaconError> {
            let bn = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/eth/v3/validator/blocks/1"))
                .respond_with(
                    ResponseTemplate::new(200)
                        .insert_header("Eth-Consensus-Version", "deneb")
                        .insert_header("Eth-Execution-Payload-Blinded", "false")
                        .insert_header("Eth-Execution-Payload-Value", "9000")
                        .set_body_string(body),
                )
                .expect(1)
                .mount(&bn)
                .await;
            let manager = BnManager::new(BnManagerConfig::new(vec![bn.uri()]))
                .expect("manager")
                .with_operation_timeouts(OperationTimeouts {
                    block_production: Duration::from_secs(5),
                    ..OperationTimeouts::default()
                });
            set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
            manager.produce_block_v3_ranked_by(1, "0xrandao", None, None, Some(duty), None).await
        }

        let conforming = ranked(&contents, duty).await.expect("BlockContents is one shape");
        assert_eq!(conforming.len(), 1, "a nested block with no top-level fields is readable");

        let err = ranked(&hybrid, duty).await.expect_err("hybrid must be a hard reject");
        let msg = err.to_string();
        assert!(
            msg.contains("all BNs failed in best-selection"),
            "hybrid must be dropped before ranking, got {err:?}"
        );
    }

    /// A missing fee recipient is preferred only before Bellatrix. From
    /// Bellatrix on a full block with no fee is a hard reject.
    #[test]
    fn missing_fee_recipient_is_rejected_from_bellatrix() {
        let parent = [0xabu8; 32];
        let expected = [0x11u8; 20];
        let base = BlockDutyChecks {
            slot: 1,
            proposer_index: 7,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some(expected),
            consensus_version: ForkName::Deneb,
        };
        for (fork, version, preferred) in [
            (ForkName::Phase0, "phase0", true),
            (ForkName::Altair, "altair", true),
            (ForkName::Bellatrix, "bellatrix", false),
            (ForkName::Capella, "capella", false),
            (ForkName::Deneb, "deneb", false),
            (ForkName::Electra, "electra", false),
            (ForkName::Fulu, "fulu", false),
            (ForkName::Gloas, "gloas", false),
        ] {
            let checks = BlockDutyChecks { consensus_version: fork, ..base };
            let mut block = duty_response("1", 1, 7, parent, None);
            block.consensus_version = version.to_string();
            assert_eq!(passes_sign(&block, &checks), preferred, "{version}");
            assert_eq!(fee_preferred(&block, &checks), preferred, "{version}");
        }

        let mut present = duty_response("1", 1, 7, parent, Some(expected));
        present.consensus_version = "bellatrix".to_string();
        let bellatrix = BlockDutyChecks { consensus_version: ForkName::Bellatrix, ..base };
        assert!(passes_sign(&present, &bellatrix));
        assert!(fee_preferred(&present, &bellatrix));

        let mut wrong = duty_response("1", 1, 7, parent, Some([0x22; 20]));
        wrong.consensus_version = "altair".to_string();
        let altair = BlockDutyChecks { consensus_version: ForkName::Altair, ..base };
        assert!(passes_sign(&wrong, &altair));
        assert!(!fee_preferred(&wrong, &altair));
    }

    fn ssz_contents(
        slot: u64,
        proposer: u64,
        parent: [u8; 32],
        body: &[u8],
        version: &str,
    ) -> ProduceBlockResponse {
        let encoded = eth_types::encode_beacon_block_ssz(
            &eth_types::BeaconBlock {
                slot,
                proposer_index: proposer,
                parent_root: parent,
                state_root: [0u8; 32],
                body: body.to_vec(),
            },
            0,
        );
        let block_off = 12u32;
        let after = block_off + encoded.len() as u32;
        let mut bytes = Vec::with_capacity(after as usize);
        bytes.extend_from_slice(&block_off.to_le_bytes());
        bytes.extend_from_slice(&after.to_le_bytes());
        bytes.extend_from_slice(&after.to_le_bytes());
        bytes.extend_from_slice(&encoded);
        ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: version.to_string(),
            execution_payload_value: Some("1".to_string()),
            is_ssz: true,
            ssz_bytes: Some(bytes),
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        }
    }

    /// Full SSZ blocks carry the fee inside the execution payload. A mismatch
    /// or a body that does not decode stays eligible and is penalized. Fulu
    /// shares the Electra body.
    #[test]
    fn full_ssz_fee_mismatch_or_undecodable_fee_is_penalized() {
        let parent = [0xabu8; 32];
        let mut deneb = eth_types::external_vector_deneb_body();
        let fee = deneb.execution_payload.fee_recipient;
        let checks = BlockDutyChecks {
            slot: 7,
            proposer_index: 42,
            parent_root: Some(parent),
            alternate_parent_root: None,
            parent_closed: false,
            fee_recipient: Some(fee),
            consensus_version: ForkName::Deneb,
        };
        let matching = ssz_contents(7, 42, parent, &deneb.as_ssz_bytes(), "deneb");
        assert!(passes_sign(&matching, &checks));
        assert!(fee_preferred(&matching, &checks));

        deneb.execution_payload.fee_recipient = [0x11; 20];
        let wrong = ssz_contents(7, 42, parent, &deneb.as_ssz_bytes(), "deneb");
        assert!(passes_sign(&wrong, &checks));
        assert!(!fee_preferred(&wrong, &checks));

        let garbage = ssz_contents(7, 42, parent, &[0xff; 8], "deneb");
        assert!(!passes_sign(&garbage, &checks), "undecodable SSZ fee is a hard reject");

        let electra = eth_types::external_vector_electra_body();
        let fulu_fee = electra.execution_payload.fee_recipient;
        let fulu = ssz_contents(7, 42, parent, &electra.as_ssz_bytes(), "fulu");
        let fulu_checks = BlockDutyChecks {
            fee_recipient: Some(fulu_fee),
            consensus_version: ForkName::Fulu,
            ..checks
        };
        assert!(passes_sign(&fulu, &fulu_checks));

        let gloas = ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "gloas".to_string(),
            execution_payload_value: Some("1".to_string()),
            is_ssz: true,
            ssz_bytes: Some(eth_types::encode_beacon_block_ssz(
                &eth_types::BeaconBlock {
                    slot: 7,
                    proposer_index: 42,
                    parent_root: parent,
                    state_root: [0u8; 32],
                    body: Vec::new(),
                },
                0,
            )),
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        };
        let gloas_checks = BlockDutyChecks { consensus_version: ForkName::Gloas, ..checks };
        assert!(!passes_sign(&gloas, &gloas_checks), "an unreadable Gloas fee is a hard reject");
    }

    /// Bellatrix and Capella full SSZ bodies have no KZG body layout.
    /// The fee is the 20 bytes at payload+32, and the payload offset is at byte 380.
    #[test]
    fn bellatrix_and_capella_ssz_fees_must_match() {
        let parent = [0xabu8; 32];
        let fee = [0x66u8; 20];
        for (version, fork, fixed_len) in
            [("bellatrix", ForkName::Bellatrix, 384usize), ("capella", ForkName::Capella, 388)]
        {
            let checks = BlockDutyChecks {
                slot: 7,
                proposer_index: 42,
                parent_root: Some(parent),
                alternate_parent_root: None,
                parent_closed: false,
                fee_recipient: Some(fee),
                consensus_version: fork,
            };
            let block = |body: Vec<u8>| ProduceBlockResponse {
                data: serde_json::Value::Null,
                is_blinded: false,
                consensus_version: version.to_string(),
                execution_payload_value: Some("1".to_string()),
                is_ssz: true,
                ssz_bytes: Some(eth_types::encode_beacon_block_ssz(
                    &eth_types::BeaconBlock {
                        slot: 7,
                        proposer_index: 42,
                        parent_root: parent,
                        state_root: [0u8; 32],
                        body,
                    },
                    0,
                )),
                payload_included: false,
                builder_url: None,
                consensus_block_value: None,
            };
            let matching = block(pre_deneb_body(fixed_len, fee));
            assert!(passes_sign(&matching, &checks), "{version}");
            assert!(fee_preferred(&matching, &checks), "{version}");
            let mismatched = block(pre_deneb_body(fixed_len, [0x11; 20]));
            assert!(passes_sign(&mismatched, &checks), "{version} mismatch stays eligible");
            assert!(!fee_preferred(&mismatched, &checks), "{version} mismatch");
            let short = block(vec![0u8; 8]);
            assert!(!passes_sign(&short, &checks), "{version} short body is a hard reject");
        }
    }

    /// Body whose execution payload starts at `fixed_len` and carries `fee` at payload+32.
    fn pre_deneb_body(fixed_len: usize, fee: [u8; 20]) -> Vec<u8> {
        const PAYLOAD_OFFSET_AT: usize = 380;
        let mut body = vec![0u8; fixed_len + 32 + 20];
        body[PAYLOAD_OFFSET_AT..PAYLOAD_OFFSET_AT + 4]
            .copy_from_slice(&(fixed_len as u32).to_le_bytes());
        body[fixed_len + 32..fixed_len + 52].copy_from_slice(&fee);
        body
    }

    // -- higher_block_value unit tests --

    #[test]
    fn test_higher_block_value_higher_value() {
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
        assert!(higher_block_value(&a, &b));
        assert!(!higher_block_value(&b, &a));
    }

    #[test]
    fn test_higher_block_value_none_vs_some() {
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
        assert!(!higher_block_value(&a, &b));
        assert!(higher_block_value(&b, &a));
    }

    #[test]
    fn test_higher_block_value_both_none() {
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
        assert!(!higher_block_value(&a, &b));
    }

    fn response_with_values(
        execution: Option<&str>,
        consensus: Option<&str>,
    ) -> ProduceBlockResponse {
        ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded: false,
            consensus_version: "deneb".to_string(),
            execution_payload_value: execution.map(str::to_string),
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: consensus.map(str::to_string),
        }
    }

    #[test]
    fn test_block_value_sums_execution_and_consensus() {
        let with_consensus = response_with_values(Some("5"), Some("10"));
        let execution_only = response_with_values(Some("10"), Some("0"));
        assert_eq!(block_value(&with_consensus), 15);
        assert_eq!(block_value(&execution_only), 10);
        assert!(higher_block_value(&with_consensus, &execution_only));
        assert!(!higher_block_value(&execution_only, &with_consensus));
    }

    #[test]
    fn test_block_value_missing_and_unparsable_headers_are_zero() {
        let missing = response_with_values(None, None);
        let empty = response_with_values(Some(""), None);
        let garbage = response_with_values(Some("12abc"), None);
        let plus = response_with_values(Some("+1"), None);
        let minus = response_with_values(Some("-1"), None);
        let zero = response_with_values(Some("0"), None);
        assert_eq!(block_value(&missing), 0);
        assert_eq!(block_value(&empty), 0);
        assert_eq!(block_value(&garbage), 0);
        assert_eq!(block_value(&plus), 0);
        assert_eq!(block_value(&minus), 0);
        assert_eq!(block_value(&zero), 0);
        assert!(!higher_block_value(&zero, &garbage));
        assert!(!higher_block_value(&garbage, &zero));
        assert!(!higher_block_value(&zero, &plus));
        assert!(!higher_block_value(&plus, &zero));

        // A bad consensus header does not zero a valid execution value.
        let bad_consensus = response_with_values(Some("9999"), Some("nope"));
        let strict = response_with_values(Some("1"), None);
        assert_eq!(block_value(&bad_consensus), 9999);
        assert!(higher_block_value(&bad_consensus, &strict));
        assert!(!higher_block_value(&strict, &bad_consensus));

        let overflow = response_with_values(Some(&u128::MAX.to_string()), Some("1"));
        assert_eq!(block_value(&overflow), u128::MAX);
        assert!(higher_block_value(&overflow, &strict));
        assert!(!higher_block_value(&strict, &overflow));

        // 2^128 does not fit in u128.
        let too_wide = response_with_values(Some("340282366920938463463374607431768211456"), None);
        assert_eq!(block_value(&too_wide), 0);
        assert!(!higher_block_value(&too_wide, &zero));
        assert!(!higher_block_value(&zero, &too_wide));
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
    fn test_higher_block_value_equal_values() {
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
        assert!(!higher_block_value(&a, &b));
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
        let deadline = checked_deadline(tokio::time::Instant::now(), budget);
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

    /// BN-1 stalls `blocks/{slot}/root`. BN-2's root is returned inside one
    /// `attestation_fetch` budget plus BN-2's own latency.
    #[tokio::test]
    async fn get_block_root_hung_primary_secondary_answers_within_attestation_fetch() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let budget = Duration::from_millis(600);
        let secondary_delay = Duration::from_millis(40);
        let epsilon = Duration::from_millis(150);
        let hang = Duration::from_secs(2);
        let slot = "33";
        assert!(budget > ATTEMPT_TIMEOUT_FLOOR);
        assert_eq!(current_attempt_floor(), ATTEMPT_TIMEOUT_FLOOR);

        let primary_root = "11".repeat(32);
        let secondary_root = "22".repeat(32);
        let primary_body = format!(r#"{{"data":{{"root":"0x{primary_root}"}}}}"#);
        let secondary_body = format!(r#"{{"data":{{"root":"0x{secondary_root}"}}}}"#);

        let primary = MockServer::start().await;
        let secondary = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/beacon/blocks/{slot}/root")))
            .respond_with(ResponseTemplate::new(200).set_body_string(&primary_body).set_delay(hang))
            .mount(&primary)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/beacon/blocks/{slot}/root")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(&secondary_body)
                    .set_delay(secondary_delay),
            )
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
        let response =
            manager.get_block_root(slot).await.expect("secondary answers the block root");
        let elapsed = started.elapsed();

        assert_eq!(response.data.root, format!("0x{secondary_root}"));
        assert_ne!(response.data.root, format!("0x{primary_root}"));
        let limit = budget + secondary_delay + epsilon;
        assert!(
            elapsed <= limit,
            "elapsed {elapsed:?} exceeded one attestation_fetch plus BN-2 latency ({limit:?})"
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
        let deadline = checked_deadline(tokio::time::Instant::now(), budget);
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
        let deadline = checked_deadline(tokio::time::Instant::now(), budget);
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
        let no_budget_sites: Vec<String> = production
            .lines()
            .enumerate()
            .filter(|(_, line)| line.contains("// no budget:"))
            .map(|(index, _)| format!("manager.rs:{}", index + 1))
            .collect();
        let expected_no_budget_sites = 10;
        let actual_no_budget_sites = no_budget_sites.len();
        let sites = no_budget_sites.join(", ");
        assert_eq!(
            actual_no_budget_sites,
            expected_no_budget_sites,
            "expected {expected_no_budget_sites} `// no budget:` markers, found {actual_no_budget_sites}: {sites}"
        );
        assert_eq!(
            production.matches("checked_deadline(tokio::time::Instant::now(), budget)").count(),
            13,
            "get_block_root and each earlier converted site take an absolute deadline before they await"
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
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            fn count_block_posts(requests: &[wiremock::Request]) -> usize {
                requests
                    .iter()
                    .filter(|req| {
                        req.method.as_str() == "POST" && req.url.path() == "/eth/v2/beacon/blocks"
                    })
                    .count()
            }
            let n1 = count_block_posts(&bn1.received_requests().await.expect("bn1 requests"));
            let n2 = count_block_posts(&bn2.received_requests().await.expect("bn2 requests"));
            if n1 >= 1 && n2 >= 1 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for both block publishes, saw bn1={n1} bn2={n2}"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
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

    fn sample_signed_blinded_block() -> SignedBlindedBeaconBlock {
        SignedBlindedBeaconBlock {
            message: eth_types::external_vector_deneb_blinded_block(),
            signature: vec![0xbb; 96],
        }
    }

    /// Hanging BN, blocks topic off so `query_first` owns this call's deadline.
    #[tokio::test(flavor = "current_thread")]
    async fn publish_blinded_block_uses_the_block_publication_timeout() {
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
            .publish_blinded_block(&sample_signed_blinded_block(), "deneb")
            .await
            .expect_err("hanging BN must time out");
        let elapsed = started.elapsed();
        assert!(
            matches!(
                err,
                BeaconError::OperationTimeout { ref operation, .. } if operation == "publish_blinded_block"
            ),
            "{err:?}"
        );
        assert!(
            elapsed <= budget + epsilon,
            "elapsed {elapsed:?} exceeded block_publication budget+ε ({:?})",
            budget + epsilon
        );
    }

    fn huge_pool_timeouts() -> OperationTimeouts {
        let hour = Duration::from_secs(3600);
        OperationTimeouts {
            block_production: hour,
            attestation_fetch: hour,
            aggregate_fetch: hour,
            aggregate_submit: hour,
            duty_fetch: hour,
            ..OperationTimeouts::default()
        }
    }

    async fn hanging_synced_manager(
        timeouts: OperationTimeouts,
    ) -> (BnManager, wiremock::MockServer) {
        use wiremock::matchers::any;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let bn = MockServer::start().await;
        Mock::given(any())
            .respond_with(
                ResponseTemplate::new(200).set_body_string("{}").set_delay(Duration::from_secs(2)),
            )
            .mount(&bn)
            .await;
        let manager = BnManager::new(BnManagerConfig::new(vec![bn.uri()]))
            .expect("BnManager")
            .with_operation_timeouts(timeouts);
        set_sync(&manager, 0, BnSyncStatus::Synced, 0).await;
        (manager, bn)
    }

    fn assert_cut_short(label: &str, started: std::time::Instant, err: BeaconError) {
        let elapsed = started.elapsed();
        assert!(
            matches!(err, BeaconError::OperationTimeout { .. } | BeaconError::Timeout),
            "{label} must time out, got {err:?}"
        );
        assert!(
            elapsed < Duration::from_millis(800),
            "{label} held the caller for {elapsed:?}; the 2s hang must not run"
        );
    }

    /// A 3600s produce budget must not outlive the per-call slot deadline.
    /// The hanging beacon node delays every request by 2s. The deadline is
    /// 40ms ahead and is an argument of that produce call only.
    #[tokio::test(flavor = "current_thread")]
    async fn a_hanging_bn_stops_at_the_remaining_slot_deadline() {
        let (manager, _bn) = hanging_synced_manager(huge_pool_timeouts()).await;
        let cap = Duration::from_millis(40);
        let deadline = tokio::time::Instant::now() + cap;

        let started = std::time::Instant::now();
        let err = manager
            .produce_block_v3_ranked_by(1, "0x01", None, None, None, Some(deadline))
            .await
            .expect_err("produce v3");
        assert_cut_short("produce_block_v3", started, err);

        let deadline = tokio::time::Instant::now() + cap;
        let started = std::time::Instant::now();
        let err = manager
            .produce_block_v4_by(1, "0x01", None, &BuilderConfig::default(), Some(deadline))
            .await
            .expect_err("produce v4");
        assert_cut_short("produce_block_v4", started, err);
    }

    /// A produce deadline from an earlier slot does not clamp a later produce
    /// call, and it does not clamp attestation, aggregate, or publication.
    #[tokio::test(flavor = "current_thread")]
    async fn a_stale_produce_deadline_does_not_clamp_the_next_call() {
        let mut timeouts = huge_pool_timeouts();
        timeouts.attestation_fetch = Duration::from_millis(120);
        timeouts.aggregate_fetch = Duration::from_millis(120);
        timeouts.block_publication = Duration::from_millis(120);
        let (manager, _bn) = hanging_synced_manager(timeouts).await;

        let stale = tokio::time::Instant::now() + Duration::from_millis(30);
        let err = manager
            .produce_block_v3_ranked_by(1, "0x01", None, None, None, Some(stale))
            .await
            .expect_err("stale produce");
        assert!(matches!(err, BeaconError::OperationTimeout { .. } | BeaconError::Timeout));

        let started = std::time::Instant::now();
        let err = manager
            .produce_block_v3_ranked_by(
                2,
                "0x01",
                None,
                None,
                None,
                Some(tokio::time::Instant::now() + Duration::from_millis(350)),
            )
            .await
            .expect_err("later produce");
        let elapsed = started.elapsed();
        assert!(matches!(err, BeaconError::OperationTimeout { .. } | BeaconError::Timeout));
        assert!(
            elapsed > Duration::from_millis(200) && elapsed < Duration::from_millis(700),
            "later produce used the new deadline, elapsed {elapsed:?}"
        );

        let started = std::time::Instant::now();
        let err = manager.get_attestation_data(1, 0).await.expect_err("attestation");
        assert_own_budget("get_attestation_data", started, err);

        let started = std::time::Instant::now();
        let err = manager
            .get_aggregate_attestation(1, "0x01", Some(0), ForkName::Electra)
            .await
            .expect_err("aggregate");
        assert_own_budget("get_aggregate_attestation", started, err);

        let started = std::time::Instant::now();
        let err = manager
            .publish_block_contents(&sample_block_contents(), "deneb", None)
            .await
            .expect_err("publish");
        assert_own_budget("publish_block_contents", started, err);
    }

    fn assert_own_budget(label: &str, started: std::time::Instant, err: BeaconError) {
        let elapsed = started.elapsed();
        assert!(
            matches!(err, BeaconError::OperationTimeout { .. } | BeaconError::Timeout),
            "{label} must time out on its own budget, got {err:?}"
        );
        assert!(
            elapsed > Duration::from_millis(80) && elapsed < Duration::from_millis(400),
            "{label} must use its 120ms budget, not a leftover slot deadline; elapsed {elapsed:?}"
        );
    }

    /// `u64::MAX` seconds must not panic inside `Instant + Duration`.
    #[tokio::test(flavor = "current_thread")]
    async fn an_unrepresentable_budget_returns_without_panicking() {
        let unrepresentable = Duration::from_secs(u64::MAX);
        let timeouts = OperationTimeouts {
            block_production: unrepresentable,
            attestation_fetch: unrepresentable,
            aggregate_fetch: unrepresentable,
            duty_fetch: unrepresentable,
            ..OperationTimeouts::default()
        };
        let (manager, _bn) = hanging_synced_manager(timeouts).await;

        let started = std::time::Instant::now();
        let err = manager.produce_block_v3(1, "0x01", None, None).await.expect_err("produce v3");
        assert_cut_short("produce_block_v3 u64::MAX", started, err);

        let started = std::time::Instant::now();
        let err = manager
            .produce_block_v4(1, "0x01", None, &BuilderConfig::default())
            .await
            .expect_err("produce v4");
        assert_cut_short("produce_block_v4 u64::MAX", started, err);
    }

    fn spec_body(slot_ms: &str) -> String {
        format!(r#"{{"data":{{"SLOT_DURATION_MS":"{slot_ms}","SLOTS_PER_EPOCH":"32"}}}}"#)
    }

    fn genesis_body(genesis_time: &str) -> String {
        format!(
            r#"{{"data":{{"genesis_time":"{genesis_time}","genesis_validators_root":"0xabc","genesis_fork_version":"0x00000000"}}}}"#
        )
    }

    async fn mount_spec_and_genesis(
        server: &wiremock::MockServer,
        slot_ms: &str,
        genesis_time: &str,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_string(spec_body(slot_ms)))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(genesis_body(genesis_time)))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn agreed_spec_on_named_network_skips_an_unreachable_bn() {
        use wiremock::MockServer;
        let live = MockServer::start().await;
        mount_spec_and_genesis(&live, "12000", "1606824023").await;
        let manager = BnManager::new(BnManagerConfig::new(vec![
            "http://127.0.0.1:1".to_string(),
            live.uri(),
        ]))
        .expect("manager");
        let (duration, slots, genesis) = manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect("unreachable peer is skipped");
        assert_eq!((duration, slots, genesis), (12_000, 32, 1_606_824_023));
    }

    #[tokio::test]
    async fn agreed_spec_fails_when_no_bn_responds() {
        let manager = BnManager::new(BnManagerConfig::new(vec!["http://127.0.0.1:1".to_string()]))
            .expect("manager");
        let err = manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect_err("at least one response");
        assert!(err.to_string().contains("no beacon node responded"), "{err}");
    }

    #[tokio::test]
    async fn agreed_spec_on_custom_requires_every_bn() {
        use wiremock::MockServer;
        let live = MockServer::start().await;
        mount_spec_and_genesis(&live, "6000", "1606824023").await;
        let manager = BnManager::new(BnManagerConfig::new(vec![
            "http://127.0.0.1:1".to_string(),
            live.uri(),
        ]))
        .expect("manager");
        let err = manager
            .agreed_spec_and_genesis(SpecAgreement::All, "0xabc")
            .await
            .expect_err("custom requires every BN");
        assert!(err.to_string().contains("HTTP request failed"), "{err}");
    }

    #[tokio::test]
    async fn agreed_spec_fails_closed_when_responders_disagree() {
        use wiremock::MockServer;
        let first = MockServer::start().await;
        let second = MockServer::start().await;
        mount_spec_and_genesis(&first, "12000", "1606824023").await;
        mount_spec_and_genesis(&second, "6000", "1606824023").await;
        let manager =
            BnManager::new(BnManagerConfig::new(vec![first.uri(), second.uri()])).expect("manager");
        let err = manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect_err("disagreement");
        assert!(err.to_string().contains("disagree"), "{err}");
    }

    fn manager_with_timeout(endpoints: Vec<String>, timeout: Duration) -> BnManager {
        let mut config = BnManagerConfig::new(endpoints);
        config.timeout = timeout;
        BnManager::new(config).expect("manager")
    }

    async fn mount_spec(server: &wiremock::MockServer, slot_ms: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_string(spec_body(slot_ms)))
            .mount(server)
            .await;
    }

    async fn mount_genesis_delayed(server: &wiremock::MockServer, delay: Duration) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(genesis_body("1606824023"))
                    .set_delay(delay),
            )
            .mount(server)
            .await;
    }

    async fn mount_status(server: &wiremock::MockServer, route: &str, status: u16) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(route))
            .respond_with(ResponseTemplate::new(status).set_body_string("unavailable"))
            .mount(server)
            .await;
    }

    async fn mount_synced(server: &wiremock::MockServer) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"100","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .mount(server)
            .await;
    }

    async fn mount_liveness(server: &wiremock::MockServer, status: u16) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        let template = if status == 200 {
            ResponseTemplate::new(200).set_body_string(r#"{"data":[{"index":"1","is_live":true}]}"#)
        } else {
            ResponseTemplate::new(status).set_body_string("down")
        };
        Mock::given(method("POST"))
            .and(path("/eth/v1/validator/liveness/1"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    async fn liveness_hits(server: &wiremock::MockServer) -> usize {
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|request| request.url.path().contains("/eth/v1/validator/liveness/"))
            .count()
    }

    #[test]
    fn proxy_statuses_count_as_unreachable_and_500_does_not() {
        for status in [429_u16, 502, 503, 504] {
            assert!(is_unreachable(&BeaconError::ApiError { status, message: "proxy".into() }));
        }
        assert!(!is_unreachable(&BeaconError::ApiError { status: 500, message: "fault".into() }));
    }

    #[tokio::test]
    async fn agreed_spec_keeps_a_spec_when_genesis_times_out() {
        use wiremock::MockServer;
        let slow = MockServer::start().await;
        let peer = MockServer::start().await;
        mount_spec(&slow, "12000").await;
        mount_genesis_delayed(&slow, Duration::from_millis(300)).await;
        mount_spec_and_genesis(&peer, "6000", "1606824023").await;
        let manager = manager_with_timeout(vec![slow.uri(), peer.uri()], Duration::from_millis(50));
        let err = manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect_err("the timed-out spec must still disagree");
        let message = err.to_string();
        assert!(message.contains("disagree on slot duration"), "{message}");
        assert!(message.contains("12000"), "{message}");
        assert!(message.contains("6000"), "{message}");
    }

    #[tokio::test]
    async fn unvalidated_bn_is_not_used_for_liveness_after_sync_recovers() {
        use wiremock::MockServer;
        let skipped = MockServer::start().await;
        let live = MockServer::start().await;
        mount_spec(&skipped, "12000").await;
        mount_genesis_delayed(&skipped, Duration::from_millis(300)).await;
        mount_synced(&skipped).await;
        mount_liveness(&skipped, 200).await;
        mount_spec_and_genesis(&live, "12000", "1606824023").await;
        mount_liveness(&live, 200).await;
        let manager =
            manager_with_timeout(vec![skipped.uri(), live.uri()], Duration::from_millis(50));
        manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect("the live beacon node completes agreement");
        assert!(!manager.is_admitted(0), "a genesis timeout must leave the node unadmitted");
        manager.check_sync_status().await;
        assert!(!manager.is_admitted(0), "syncing recovery must not admit the node");
        let indices = vec!["1".to_string()];
        manager.post_validator_liveness(1, &indices).await.expect("live node answers");
        manager
            .post_validator_liveness_merged(1, &indices)
            .await
            .expect("merged liveness uses admitted nodes");
        assert_eq!(liveness_hits(&skipped).await, 0, "the unvalidated node must not be queried");
        assert!(liveness_hits(&live).await > 0);
    }

    #[tokio::test]
    async fn skipped_bn_is_admitted_for_liveness_after_identity_matches() {
        use wiremock::MockServer;
        let skipped = MockServer::start().await;
        let live = MockServer::start().await;
        mount_spec(&skipped, "12000").await;
        mount_genesis_delayed(&skipped, Duration::from_millis(300)).await;
        mount_spec_and_genesis(&live, "12000", "1606824023").await;
        mount_liveness(&live, 500).await;
        let manager =
            manager_with_timeout(vec![skipped.uri(), live.uri()], Duration::from_millis(50));
        manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect("the live beacon node completes agreement");
        mount_liveness(&skipped, 200).await;
        let indices = vec!["1".to_string()];
        let blocked = manager.post_validator_liveness(1, &indices).await;
        assert!(blocked.is_err(), "the unadmitted node must not fail over: {blocked:?}");
        assert_eq!(liveness_hits(&skipped).await, 0);

        skipped.reset().await;
        mount_spec_and_genesis(&skipped, "12000", "1606824023").await;
        mount_liveness(&skipped, 200).await;
        manager.admit_skipped_beacon(0).await.expect("identity matches");
        assert!(manager.is_admitted(0));
        manager.post_validator_liveness(1, &indices).await.expect("admitted node answers");
        assert!(liveness_hits(&skipped).await > 0);
    }

    #[tokio::test]
    async fn admit_skipped_beacon_rejects_mismatched_genesis_validators() {
        use wiremock::MockServer;
        let skipped = MockServer::start().await;
        let live = MockServer::start().await;
        mount_status(&skipped, "/eth/v1/config/spec", 503).await;
        mount_spec_and_genesis(&live, "12000", "1606824023").await;
        let manager =
            BnManager::new(BnManagerConfig::new(vec![skipped.uri(), live.uri()])).expect("manager");
        manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect("503 is skipped");
        skipped.reset().await;
        mount_spec(&skipped, "12000").await;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"genesis_time":"1606824023","genesis_validators_root":"0xdef","genesis_fork_version":"0x00000000"}}"#,
            ))
            .mount(&skipped)
            .await;
        let err = manager.admit_skipped_beacon(0).await.expect_err("root mismatch");
        assert!(err.to_string().contains("genesis_validators_root"), "{err}");
        assert!(!manager.is_admitted(0));
    }

    #[tokio::test]
    async fn responding_agreement_skips_proxy_unavailable() {
        use wiremock::MockServer;
        for status in [502_u16, 503, 504, 429] {
            let down = MockServer::start().await;
            let live = MockServer::start().await;
            mount_status(&down, "/eth/v1/config/spec", status).await;
            mount_spec_and_genesis(&live, "12000", "1606824023").await;
            let manager = BnManager::new(BnManagerConfig::new(vec![down.uri(), live.uri()]))
                .expect("manager");
            let agreed = manager
                .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
                .await
                .unwrap_or_else(|err| panic!("status {status} must be skipped, got {err}"));
            assert_eq!(agreed, (12_000, 32, 1_606_824_023));
            assert!(!manager.is_admitted(0));
        }
    }

    #[tokio::test]
    async fn responding_agreement_treats_500_as_boot_fatal() {
        use wiremock::MockServer;
        let down = MockServer::start().await;
        let live = MockServer::start().await;
        mount_status(&down, "/eth/v1/config/spec", 500).await;
        mount_spec_and_genesis(&live, "12000", "1606824023").await;
        let manager =
            BnManager::new(BnManagerConfig::new(vec![down.uri(), live.uri()])).expect("manager");
        let err = manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect_err("500 stays boot-fatal");
        assert!(matches!(err, BeaconError::ApiError { status: 500, .. }), "{err:?}");
    }

    #[tokio::test]
    async fn custom_agreement_treats_503_as_boot_fatal() {
        use wiremock::MockServer;
        let down = MockServer::start().await;
        let live = MockServer::start().await;
        mount_status(&down, "/eth/v1/config/spec", 503).await;
        mount_spec_and_genesis(&live, "12000", "1606824023").await;
        let manager =
            BnManager::new(BnManagerConfig::new(vec![down.uri(), live.uri()])).expect("manager");
        let err = manager
            .agreed_spec_and_genesis(SpecAgreement::All, "0xabc")
            .await
            .expect_err("custom requires every BN");
        assert!(matches!(err, BeaconError::ApiError { status: 503, .. }), "{err:?}");
    }

    async fn mount_genesis_root(server: &wiremock::MockServer, genesis_time: &str, root: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_string(format!(
                r#"{{"data":{{"genesis_time":"{genesis_time}","genesis_validators_root":"{root}","genesis_fork_version":"0x00000000"}}}}"#
            )))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn confirm_genesis_root_checks_every_responder() {
        use wiremock::MockServer;
        let good = MockServer::start().await;
        let wrong = MockServer::start().await;
        mount_genesis_root(&good, "1606824023", "0xabc").await;
        mount_genesis_root(&wrong, "1606824023", "0xdef").await;
        let manager =
            BnManager::new(BnManagerConfig::new(vec![good.uri(), wrong.uri()])).expect("manager");
        manager.confirm_genesis_validators_root("0xabc").await.expect("the good node matches");
        assert!(manager.is_admitted(0));
        assert!(!manager.is_admitted(1), "a later wrong root must not stay admitted");
    }

    #[tokio::test]
    async fn single_wrong_root_node_is_rejected_at_boot() {
        use wiremock::MockServer;
        let server = MockServer::start().await;
        mount_spec(&server, "12000").await;
        mount_genesis_root(&server, "1606824023", "0xdef").await;
        mount_liveness(&server, 200).await;
        let manager = BnManager::new(BnManagerConfig::new(vec![server.uri()])).expect("manager");
        let err = manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect_err("configured root rejects the node");
        assert!(err.to_string().contains("genesis_validators_root"), "{err}");
        assert!(!manager.is_admitted(0));
        let liveness = manager.post_validator_liveness(1, &["1".to_string()]).await;
        assert!(liveness.is_err(), "an unadmitted node is not a liveness source: {liveness:?}");
        assert_eq!(liveness_hits(&server).await, 0);
    }

    #[tokio::test]
    async fn wrong_chain_nodes_stay_unadmitted_after_the_good_node_drops() {
        use wiremock::MockServer;
        let good = MockServer::start().await;
        let wrong_a = MockServer::start().await;
        let wrong_b = MockServer::start().await;
        mount_spec_and_genesis(&good, "12000", "1606824023").await;
        for wrong in [&wrong_a, &wrong_b] {
            mount_spec(wrong, "12000").await;
            mount_genesis_root(wrong, "1606824023", "0xdef").await;
            mount_synced(wrong).await;
            mount_liveness(wrong, 200).await;
        }
        let manager =
            BnManager::new(BnManagerConfig::new(vec![good.uri(), wrong_a.uri(), wrong_b.uri()]))
                .expect("manager");
        manager
            .agreed_spec_and_genesis(SpecAgreement::Responding, "0xabc")
            .await
            .expect("the good node seeds the configured root");
        assert!(manager.is_admitted(0));
        assert!(!manager.is_admitted(1));
        assert!(!manager.is_admitted(2));

        good.reset().await;
        mount_status(&good, "/eth/v1/config/spec", 503).await;
        mount_status(&good, "/eth/v1/beacon/genesis", 503).await;
        manager.check_sync_status().await;
        let err = manager.admit_skipped_beacon(1).await.expect_err("wrong root");
        assert!(err.to_string().contains("genesis_validators_root"), "{err}");
        assert!(!manager.is_admitted(1));
        assert!(!manager.is_admitted(2));
        let liveness = manager.post_validator_liveness(1, &["1".to_string()]).await;
        assert!(liveness.is_err(), "{liveness:?}");
        assert_eq!(liveness_hits(&wrong_a).await, 0);
        assert_eq!(liveness_hits(&wrong_b).await, 0);
    }

    async fn sse_head_server(
        slot: &str,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>, tokio::task::JoinHandle<()>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let accepts = Arc::new(AtomicUsize::new(0));
        let accepts_task = Arc::clone(&accepts);
        let body = format!(
            "event: head\ndata: {{\"slot\":\"{slot}\",\"block\":\"0xabc\",\"state\":\"0xdef\",\"epoch_transition\":false,\"previous_duty_dependent_root\":\"0x11\",\"current_duty_dependent_root\":\"0x22\",\"execution_optimistic\":false}}\n\nevent: chain_reorg\ndata: {{\"slot\":\"{slot}\",\"depth\":\"1\",\"old_head_block\":\"0x01\",\"new_head_block\":\"0x02\",\"old_head_state\":\"0x03\",\"new_head_state\":\"0x04\",\"epoch\":\"1\",\"execution_optimistic\":false}}\n\n"
        );
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                accepts_task.fetch_add(1, Ordering::SeqCst);
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;
                    let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n";
                    let _ = stream.write_all(headers.as_bytes()).await;
                    let chunk = format!("{:x}\r\n{}\r\n", body.len(), body);
                    let _ = stream.write_all(chunk.as_bytes()).await;
                    let _ = stream.flush().await;
                    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                });
            }
        });
        (format!("http://127.0.0.1:{port}"), accepts, handle)
    }

    #[tokio::test]
    async fn sse_does_not_connect_an_unadmitted_bn_until_it_is_admitted() {
        use std::sync::atomic::Ordering;
        use std::sync::{Arc, Mutex};

        let (skipped_url, skipped_hits, skipped_server) = sse_head_server("1").await;
        let (live_url, live_hits, live_server) = sse_head_server("2").await;
        let manager =
            BnManager::new(BnManagerConfig::new(vec![skipped_url, live_url])).expect("manager");
        manager.mark_unadmitted(0);
        let events = Arc::new(Mutex::new(Vec::new()));
        let events_cb = Arc::clone(&events);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = manager.start_sse(
            move |event| {
                events_cb.lock().expect("events").push(event);
            },
            shutdown_rx,
        );

        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if live_hits.load(Ordering::SeqCst) > 0 && !events.lock().expect("events").is_empty() {
                break;
            }
        }
        assert_eq!(
            skipped_hits.load(Ordering::SeqCst),
            0,
            "an unadmitted node must not be connected"
        );
        assert!(live_hits.load(Ordering::SeqCst) > 0, "the admitted node is the stream");
        let delivered = events.lock().expect("events").clone();
        assert!(
            delivered.iter().any(|event| matches!(event, SseEvent::Head(head) if head.slot == "2")),
            "admitted head must be delivered: {delivered:?}"
        );
        assert!(
            delivered.iter().all(|event| match event {
                SseEvent::Head(head) => head.slot != "1",
                SseEvent::ChainReorg(reorg) => reorg.slot != "1",
                SseEvent::Block(_) | SseEvent::FinalizedCheckpoint(_) => true,
            }),
            "unadmitted head and reorg events must be dropped: {delivered:?}"
        );

        manager.admitted[0].store(true, Ordering::Release);
        live_server.abort();
        for _ in 0..80 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            if skipped_hits.load(Ordering::SeqCst) > 0 {
                break;
            }
        }
        assert!(
            skipped_hits.load(Ordering::SeqCst) > 0,
            "the node may be connected after admission"
        );
        shutdown_tx.send(true).expect("shutdown");
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        skipped_server.abort();
    }
}
