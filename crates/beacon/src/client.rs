use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{debug, error, trace, warn, Instrument};

use observability::logging::RedactedUrl;

use eth_types::{ForkName, ForkSchedule, SignedValidatorRegistration, SignedVoluntaryExit};

use crate::http_caps::{read_body_capped, read_body_capped_lossy, ResponseCaps};
use crate::retry::RetryPolicy;
use crate::types::{
    parse_fork_schedule, AttestationDataResponse, AttesterDutiesResponse,
    BeaconCommitteeSubscription, BlockRootResponse, ConfigSpecResponse, DataResponse,
    GenesisResponse, IndexedAttestationError, NodeVersionResponse, NodeVersionV2Response,
    ProduceBlockResponse, ProposerDutiesResponse, ProposerPreparation, SignedContributionAndProof,
    StateForkResponse, SubmitAttestationResult, SyncCommitteeContributionResponse,
    SyncCommitteeDutiesResponse, SyncCommitteeMessage, SyncingResponse, ValidatorLivenessResponse,
    ValidatorsResponse, VersionedAggregateAttestation, VersionedAttestation,
    VersionedSignedAggregateAndProof,
};
use crate::BeaconError;

#[derive(Debug, Deserialize)]
struct AttestationSubmissionError {
    #[serde(default)]
    failures: Vec<IndexedAttestationError>,
}

const DEFAULT_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_RETRIES: u32 = 3;
const DEFAULT_INITIAL_BACKOFF_MS: u64 = 100;

/// Configuration for the beacon node HTTP client.
#[derive(Debug, Clone)]
pub struct BeaconClientConfig {
    pub endpoint: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub initial_backoff: Duration,
    /// Maximum bytes allowed in a JSON response body (H-12).
    pub max_body_bytes: usize,
}

impl BeaconClientConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_retries: DEFAULT_MAX_RETRIES,
            initial_backoff: Duration::from_millis(DEFAULT_INITIAL_BACKOFF_MS),
            max_body_bytes: ResponseCaps::DEFAULT_MAX_BODY_BYTES,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_max_retries(mut self, max_retries: u32) -> Self {
        self.max_retries = max_retries;
        self
    }

    pub fn with_initial_backoff(mut self, initial_backoff: Duration) -> Self {
        self.initial_backoff = initial_backoff;
        self
    }

    /// Set the maximum JSON response body size (H-12 body cap).
    ///
    /// Default: 32 MiB.  Raise this if a beacon node legitimately returns
    /// larger responses (e.g. during initial sync).
    pub fn with_max_body_bytes(mut self, max_body_bytes: usize) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }
}

/// Parse a required `Eth-Consensus-Version` header into a [`ForkName`].
///
/// Absent, non-UTF-8, or unknown values are [`BeaconError::ParseError`] naming
/// the offending value. Responses that carry a versioned body must not proceed
/// with an empty string.
fn required_consensus_version(
    headers: &reqwest::header::HeaderMap,
) -> Result<ForkName, BeaconError> {
    let Some(raw) = headers.get("Eth-Consensus-Version") else {
        return Err(BeaconError::ParseError("missing Eth-Consensus-Version header".to_string()));
    };
    let value = raw.to_str().map_err(|_| {
        BeaconError::ParseError("unparseable Eth-Consensus-Version header".to_string())
    })?;
    ForkName::from_str(value)
        .map_err(|_| BeaconError::ParseError(format!("invalid Eth-Consensus-Version: {value}")))
}

/// Async HTTP client wrapper for beacon node communication.
#[derive(Clone)]
pub struct BeaconClient {
    client: Client,
    config: BeaconClientConfig,
    /// Logs the node-version v1 fallback once per BN (D25).
    node_version_v1_fallback_logged: Arc<AtomicBool>,
}

impl BeaconClient {
    /// Creates a new BeaconClient with the given configuration.
    pub fn new(config: BeaconClientConfig) -> Result<Self, BeaconError> {
        let endpoint = config.endpoint.trim_end_matches('/');
        if endpoint.is_empty() {
            return Err(BeaconError::InvalidUrl("endpoint URL cannot be empty".to_string()));
        }

        if !endpoint.starts_with("http://") && !endpoint.starts_with("https://") {
            return Err(BeaconError::InvalidUrl(format!(
                "endpoint must start with http:// or https://: {}",
                endpoint
            )));
        }

        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| BeaconError::HttpError(e.to_string()))?;

        let config = BeaconClientConfig { endpoint: endpoint.to_string(), ..config };

        Ok(Self {
            client,
            config,
            node_version_v1_fallback_logged: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Returns the configured endpoint URL.
    pub fn endpoint(&self) -> &str {
        &self.config.endpoint
    }

    /// Returns the configured timeout.
    pub fn timeout(&self) -> Duration {
        self.config.timeout
    }

    /// Threshold above which `get_validators` switches from GET to POST
    /// to avoid exceeding URL length limits.
    const POST_VALIDATORS_THRESHOLD: usize = 50;

    /// Inject W3C trace context headers into an outbound request builder.
    ///
    /// Single call site for `telemetry::inject_trace_context` in this crate.
    fn traced(builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let mut headers = reqwest::header::HeaderMap::new();
        telemetry::inject_trace_context(&mut headers);
        builder.headers(headers)
    }

    /// Shared retry/backoff policy derived from this client's config.
    fn retry_policy(&self) -> RetryPolicy {
        RetryPolicy::new(self.config.max_retries, self.config.initial_backoff)
    }

    /// Join the configured endpoint with a path (and optional query string).
    ///
    /// Builds a well-formed absolute URL under the **configured beacon origin**
    /// only. Matches the historical `format!("{}{}", endpoint, path)` invariant
    /// that the request host never changes: absolute or scheme-relative path
    /// inputs that would rewrite scheme/host/port are rejected (`InvalidUrl`)
    /// rather than followed (SSRF guard against `Url::join` absolute-URL takeover).
    ///
    /// Path and query components that contain only unreserved characters remain
    /// byte-identical to the historical construction for normal `/eth/...` paths.
    /// Dynamic segments should be percent-encoded via [`Self::build_path`] before
    /// being passed here.
    fn resolve_url(&self, path: &str) -> Result<String, BeaconError> {
        let endpoint = self.config.endpoint.trim_end_matches('/');
        let origin = url::Url::parse(endpoint).map_err(|e| {
            BeaconError::InvalidUrl(format!("invalid endpoint '{}': {e}", self.config.endpoint))
        })?;

        // Scheme-relative references (`//host/...`) rewrite authority under join.
        // Historical concat could not do that; refuse them explicitly.
        if path.starts_with("//") {
            return Err(BeaconError::InvalidUrl(format!(
                "refusing scheme-relative path that would rewrite origin: {path}"
            )));
        }

        // Join against `endpoint/` so a leading-slash path is treated as a path
        // reference relative to the beacon origin (same host as string concat).
        let base = format!("{}/", endpoint);
        let base_url = url::Url::parse(&base).map_err(|e| {
            BeaconError::InvalidUrl(format!("invalid endpoint '{}': {e}", self.config.endpoint))
        })?;
        let rel = path.trim_start_matches('/');
        let joined = base_url
            .join(rel)
            .map_err(|e| BeaconError::InvalidUrl(format!("failed to join path '{path}': {e}")))?;

        // Pin scheme + host + port to the configured endpoint. `Url::join` replaces
        // the entire base when `rel` is an absolute URL (e.g. path="/http://evil.com/x"
        // → rel="http://evil.com/x"). That is a cross-origin SSRF regression vs concat.
        if !Self::same_origin(&origin, &joined) {
            return Err(BeaconError::InvalidUrl(format!(
                "resolved URL origin differs from configured beacon endpoint \
                 (refusing cross-origin request): {path}"
            )));
        }

        Ok(joined.to_string())
    }

    /// True when `candidate` shares scheme, host, and effective port with `origin`.
    fn same_origin(origin: &url::Url, candidate: &url::Url) -> bool {
        origin.scheme() == candidate.scheme()
            && origin.host() == candidate.host()
            && origin.port_or_known_default() == candidate.port_or_known_default()
    }

    /// Build a path + query string with percent-encoded segments and query values.
    ///
    /// `segments` are joined with `/` (no leading empty segment). Query pairs are
    /// encoded via `query_pairs_mut` (application/x-www-form-urlencoded).
    fn build_path(segments: &[&str], query: &[(&str, &str)]) -> String {
        let mut url = url::Url::parse("http://placeholder.invalid")
            .expect("static placeholder URL must parse");
        {
            let mut segs = url.path_segments_mut().expect("placeholder is a base URL");
            segs.clear();
            for seg in segments {
                segs.push(seg);
            }
        }
        if !query.is_empty() {
            let mut qp = url.query_pairs_mut();
            for (k, v) in query {
                qp.append_pair(k, v);
            }
        }
        let mut out = url.path().to_string();
        if let Some(q) = url.query() {
            out.push('?');
            out.push_str(q);
        }
        out
    }

    /// Performs a GET request with retry logic.
    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, BeaconError> {
        let url = self.resolve_url(path)?;
        self.execute_with_retry("GET", &url, || async {
            Self::traced(self.client.get(&url)).send().await
        })
        .await
    }

    /// Performs a POST request with retry logic.
    pub async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, BeaconError> {
        let url = self.resolve_url(path)?;
        if tracing::enabled!(tracing::Level::TRACE) {
            let body_size = serde_json::to_vec(body).map(|b| b.len()).unwrap_or(0);
            trace!(
                method = "POST",
                endpoint = path,
                body_size_bytes = body_size,
                "HTTP request body"
            );
        }
        self.execute_with_retry("POST", &url, || async {
            Self::traced(self.client.post(&url).json(body)).send().await
        })
        .await
    }

    /// Performs a POST request expecting an empty success response.
    pub async fn post_empty<B: Serialize>(&self, path: &str, body: &B) -> Result<(), BeaconError> {
        self.post_empty_with_headers(path, body, &[]).await
    }

    /// Fetches attester duties for the given epoch and validator indices.
    ///
    /// Returns duties with a dependent root that can be used for cache invalidation.
    /// If the dependent root changes, cached duties should be invalidated.
    pub async fn get_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<AttesterDutiesResponse, BeaconError> {
        let path = format!("/eth/v1/validator/duties/attester/{}", epoch);
        self.post(&path, &validator_indices)
            .instrument(tracing::info_span!("beacon.get_attester_duties", epoch = epoch))
            .await
    }

    /// Resolves public keys to validator data including numeric indices.
    ///
    /// Calls the beacon state validators endpoint with the given public keys
    /// to retrieve their validator indices, status, and other metadata.
    pub async fn get_validators(
        &self,
        pubkeys: &[String],
    ) -> Result<ValidatorsResponse, BeaconError> {
        if pubkeys.len() > Self::POST_VALIDATORS_THRESHOLD {
            let path = "/eth/v1/beacon/states/head/validators";
            let body = serde_json::json!({ "ids": pubkeys });
            self.post(path, &body).instrument(tracing::info_span!("beacon.get_validators")).await
        } else {
            let pairs: Vec<(&str, &str)> = pubkeys.iter().map(|pk| ("id", pk.as_str())).collect();
            let path =
                Self::build_path(&["eth", "v1", "beacon", "states", "head", "validators"], &pairs);
            self.get(&path).instrument(tracing::info_span!("beacon.get_validators")).await
        }
    }

    /// Fetches attestation data for the given slot and committee index.
    ///
    /// The beacon node will return attestation data that validators can use
    /// to create their attestations for the specified slot and committee.
    ///
    /// Returns an error if the slot is in the past or too far in the future,
    /// or if the beacon node is still syncing.
    pub async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataResponse, BeaconError> {
        let slot_s = slot.to_string();
        let ci_s = committee_index.to_string();
        let path = Self::build_path(
            &["eth", "v1", "validator", "attestation_data"],
            &[("slot", &slot_s), ("committee_index", &ci_s)],
        );
        self.get(&path)
            .instrument(tracing::info_span!("beacon.get_attestation_data", slot = slot))
            .await
    }

    /// Fetches the chain configuration specification from the beacon node.
    ///
    /// Returns a map of all configuration parameters as string key-value pairs.
    /// Includes fork versions, fork epochs, slot timing, and other consensus parameters.
    #[tracing::instrument(name = "beacon.get_config_spec", skip_all)]
    pub async fn get_config_spec(&self) -> Result<ConfigSpecResponse, BeaconError> {
        self.get("/eth/v1/config/spec").await
    }

    /// Fetches the config spec and parses fork epoch and version fields into a `ForkSchedule`.
    #[tracing::instrument(name = "beacon.get_fork_schedule", skip_all)]
    pub async fn get_fork_schedule(&self) -> Result<ForkSchedule, BeaconError> {
        let spec = self.get_config_spec().await?;
        parse_fork_schedule(&spec.data)
    }

    /// Fetches genesis information from the beacon node.
    ///
    /// Returns the genesis time, genesis validators root, and genesis fork version.
    #[tracing::instrument(name = "beacon.get_genesis", skip_all)]
    pub async fn get_genesis(&self) -> Result<GenesisResponse, BeaconError> {
        self.get("/eth/v1/beacon/genesis").await
    }

    /// Fetches fork information for the given state.
    ///
    /// Returns the previous and current fork versions along with the fork epoch.
    /// Common state_id values: "head", "finalized", "justified", or a specific slot number.
    #[tracing::instrument(name = "beacon.get_fork", skip_all)]
    pub async fn get_fork(&self, state_id: &str) -> Result<StateForkResponse, BeaconError> {
        let path = Self::build_path(&["eth", "v1", "beacon", "states", state_id, "fork"], &[]);
        self.get(&path).await
    }

    /// Fetches the block root for the given block identifier.
    ///
    /// Common block_id values: "head", "finalized", "justified", or a slot number.
    #[tracing::instrument(name = "beacon.get_block_root", skip_all)]
    pub async fn get_block_root(&self, block_id: &str) -> Result<BlockRootResponse, BeaconError> {
        let path = Self::build_path(&["eth", "v1", "beacon", "blocks", block_id, "root"], &[]);
        self.get(&path).await
    }

    /// Path for proposer duties: v1 pre-Gloas, v2 at Gloas.
    ///
    /// v1 remains `/eth/v1/validator/duties/proposer/{epoch}` (byte-identical
    /// to the historical client). Endpoint availability is independent of
    /// response shape — v1 is kept for the whole pre-Gloas window.
    fn proposer_duties_path(epoch: u64, schedule: &ForkSchedule) -> String {
        let version =
            if ForkName::from_epoch(epoch, schedule) >= ForkName::Gloas { "v2" } else { "v1" };
        format!("/eth/{version}/validator/duties/proposer/{epoch}")
    }

    /// Fetches proposer duties for the given epoch.
    ///
    /// Routes on `ForkName::from_epoch(epoch, schedule)`: v1 for pre-Gloas
    /// epochs, v2 at Gloas. A 404 on v2 at a Gloas epoch is an error, never a
    /// silent downgrade to v1 (D25). A 404 on v1 pre-Gloas is the same error
    /// it is today.
    pub async fn get_proposer_duties(
        &self,
        epoch: u64,
        schedule: &ForkSchedule,
    ) -> Result<ProposerDutiesResponse, BeaconError> {
        let path = Self::proposer_duties_path(epoch, schedule);
        self.get(&path)
            .instrument(tracing::info_span!("beacon.get_proposer_duties", epoch = epoch))
            .await
    }

    /// SSZ content negotiation Accept header for block production.
    /// Prefers SSZ for ~67% bandwidth savings with JSON as fallback.
    /// The full SSZ pipeline (header extraction, block-service SSZ path,
    /// JSON fallback on failure) is in place.
    const SSZ_ACCEPT_HEADER: &'static str = "application/octet-stream;q=1.0,application/json;q=0.9";

    /// Produces a block for the given slot using the v3 endpoint.
    ///
    /// Requests SSZ-encoded response for reduced network latency on large blocks.
    /// Falls back to JSON if the BN does not support SSZ or responds with JSON
    /// despite the SSZ preference.
    ///
    /// Wrapped in a `beacon.produce_block_v3` span (canonical `slot`), mirroring the sibling
    /// `beacon.*` duty-call spans so the proposer-duty BN call is correlatable. `skip_all`
    /// keeps `randao_reveal` and the other args out of the span (no eager formatting).
    #[tracing::instrument(name = "beacon.produce_block_v3", level = "debug", skip_all, fields(slot = slot))]
    pub async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        let slot_s = slot.to_string();
        let factor_s = builder_boost_factor.map(|f| f.to_string());
        let mut query: Vec<(&str, &str)> = vec![("randao_reveal", randao_reveal)];
        if let Some(g) = graffiti {
            query.push(("graffiti", g));
        }
        if let Some(ref f) = factor_s {
            query.push(("builder_boost_factor", f.as_str()));
        }
        let path = Self::build_path(&["eth", "v3", "validator", "blocks", &slot_s], &query);
        let url = self.resolve_url(&path)?;

        let response = self
            .execute_with_retry_raw(
                "GET",
                &url,
                || async {
                    Self::traced(
                        self.client
                            .get(&url)
                            .header(reqwest::header::ACCEPT, Self::SSZ_ACCEPT_HEADER),
                    )
                    .send()
                    .await
                },
                Self::take_success_response,
            )
            .await?;

        let is_blinded = response
            .headers()
            .get("Eth-Execution-Payload-Blinded")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "true")
            .unwrap_or(false);

        let consensus_version =
            required_consensus_version(response.headers())?.as_ref().to_string();

        let execution_payload_value = response
            .headers()
            .get("Eth-Execution-Payload-Value")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        if content_type.starts_with("application/octet-stream") {
            match Self::try_process_ssz_body(
                response,
                slot,
                is_blinded,
                &consensus_version,
                &execution_payload_value,
            )
            .await
            {
                Ok(result) => return Ok(result),
                Err(ssz_err) => {
                    warn!(
                        slot = slot,
                        error = %ssz_err,
                        "SSZ block response processing failed, retrying with JSON"
                    );
                    // Single fallback retry with explicit JSON Accept
                    let fallback_response = self
                        .execute_with_retry_raw(
                            "GET",
                            &url,
                            || async {
                                Self::traced(
                                    self.client
                                        .get(&url)
                                        .header(reqwest::header::ACCEPT, "application/json"),
                                )
                                .send()
                                .await
                            },
                            Self::take_success_response,
                        )
                        .await?;
                    return Self::parse_produce_block_json(
                        fallback_response,
                        self.config.max_body_bytes,
                    )
                    .await;
                }
            }
        }

        Self::parse_produce_block_json(response, self.config.max_body_bytes).await
    }

    /// Attempt to read and validate the SSZ body from an HTTP response.
    async fn try_process_ssz_body(
        response: reqwest::Response,
        slot: u64,
        is_blinded: bool,
        consensus_version: &str,
        execution_payload_value: &Option<String>,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        // H-12 (SSZ path): cap before allocation — read_body_capped streams in chunks
        // and returns BodyTooLarge before allocating more than MAX_SSZ_BLOCK_BYTES.
        // The redundant post-hoc size check is no longer needed.
        const MAX_SSZ_BLOCK_BYTES: usize = 16 * 1024 * 1024;

        let ssz_bytes = read_body_capped(response, MAX_SSZ_BLOCK_BYTES).await?.to_vec();

        if ssz_bytes.is_empty() {
            return Err(BeaconError::ParseError("received empty SSZ body from beacon node".into()));
        }

        debug!(
            slot = slot,
            consensus_version = consensus_version,
            ssz_bytes = ssz_bytes.len(),
            "received SSZ block response"
        );

        Ok(ProduceBlockResponse {
            data: serde_json::Value::Null,
            is_blinded,
            consensus_version: consensus_version.to_string(),
            execution_payload_value: execution_payload_value.clone(),
            is_ssz: true,
            ssz_bytes: Some(ssz_bytes),
        })
    }

    /// Parse a JSON produce-block response (headers + body).
    ///
    /// H-12: extracts headers first (before consuming the body), then reads the
    /// body through `read_body_capped` with the caller-supplied cap.  This
    /// prevents `response.json().await` from buffering an unbounded body before
    /// deserialisation.
    async fn parse_produce_block_json(
        response: reqwest::Response,
        max_body_bytes: usize,
    ) -> Result<ProduceBlockResponse, BeaconError> {
        // Extract all headers before consuming the body (reqwest moves the
        // response when reading the body, so we capture metadata first).
        let is_blinded = response
            .headers()
            .get("Eth-Execution-Payload-Blinded")
            .and_then(|v| v.to_str().ok())
            .map(|v| v == "true")
            .unwrap_or(false);

        let consensus_version =
            required_consensus_version(response.headers())?.as_ref().to_string();

        let execution_payload_value = response
            .headers()
            .get("Eth-Execution-Payload-Value")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());

        // H-12: cap the body before deserialising.
        let bytes = read_body_capped(response, max_body_bytes).await?;
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| BeaconError::ParseError(e.to_string()))?;

        let data = body.get("data").cloned().ok_or_else(|| {
            BeaconError::ParseError("missing 'data' field in produce block response".into())
        })?;

        Ok(ProduceBlockResponse {
            data,
            is_blinded,
            consensus_version,
            execution_payload_value,
            is_ssz: false,
            ssz_bytes: None,
        })
    }

    /// Publishes a signed beacon block to the network.
    pub async fn publish_block<B: Serialize>(
        &self,
        signed_block: &B,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.post_empty_with_headers(
            "/eth/v2/beacon/blocks",
            signed_block,
            &[("Eth-Consensus-Version", consensus_version)],
        )
        .instrument(tracing::info_span!("beacon.publish_block"))
        .await
    }

    /// Publishes a signed blinded beacon block to the network.
    pub async fn publish_blinded_block<B: Serialize>(
        &self,
        signed_blinded_block: &B,
        consensus_version: &str,
    ) -> Result<(), BeaconError> {
        self.post_empty_with_headers(
            "/eth/v1/beacon/blinded_blocks",
            signed_blinded_block,
            &[("Eth-Consensus-Version", consensus_version)],
        )
        .instrument(tracing::info_span!("beacon.publish_blinded_block"))
        .await
    }

    /// Publishes a block as raw SSZ bytes using `Content-Type: application/octet-stream`.
    ///
    /// Routes to the blinded or unblinded endpoint based on `is_blinded`.
    pub async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
    ) -> Result<(), BeaconError> {
        let path =
            if is_blinded { "/eth/v1/beacon/blinded_blocks" } else { "/eth/v2/beacon/blocks" };
        let url = self.resolve_url(path)?;
        let cv = consensus_version.to_string();
        let body = ssz_bytes.to_vec();

        self.execute_with_retry_raw(
            "POST",
            &url,
            || {
                let cv = cv.clone();
                let body = body.clone();
                let url = url.clone();
                async move {
                    Self::traced(
                        self.client
                            .post(&url)
                            .header("Content-Type", "application/octet-stream")
                            .header("Eth-Consensus-Version", &cv)
                            .body(body),
                    )
                    .send()
                    .await
                }
            },
            |response| async move {
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(Self::api_error_from_response(response).await)
                }
            },
        )
        .await
    }

    /// Fetches sync committee duties for the given epoch and validator indices.
    pub async fn post_sync_committee_duties(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<SyncCommitteeDutiesResponse, BeaconError> {
        let path = format!("/eth/v1/validator/duties/sync/{}", epoch);
        self.post(&path, &validator_indices)
            .instrument(tracing::info_span!("beacon.get_sync_committee_duties", epoch = epoch))
            .await
    }

    /// Submits sync committee messages to the beacon node pool.
    pub async fn submit_sync_committee_messages(
        &self,
        messages: &[SyncCommitteeMessage],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/beacon/pool/sync_committees", &messages)
            .instrument(tracing::info_span!("beacon.submit_sync_committee_messages"))
            .await
    }

    /// Fetches a sync committee contribution for the given slot, subcommittee index, and block root.
    #[tracing::instrument(name = "beacon.get_sync_committee_contribution", skip_all, fields(slot = slot))]
    pub async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncCommitteeContributionResponse, BeaconError> {
        let slot_s = slot.to_string();
        let sub_s = subcommittee_index.to_string();
        let path = Self::build_path(
            &["eth", "v1", "validator", "sync_committee_contribution"],
            &[
                ("slot", &slot_s),
                ("subcommittee_index", &sub_s),
                ("beacon_block_root", beacon_block_root),
            ],
        );
        self.get(&path).await
    }

    /// Submits signed contribution and proofs to the beacon node.
    pub async fn submit_contribution_and_proofs(
        &self,
        proofs: &[SignedContributionAndProof],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/validator/contribution_and_proofs", &proofs)
            .instrument(tracing::info_span!("beacon.submit_contribution_and_proofs"))
            .await
    }

    // Aggregation

    /// Fetches an aggregate attestation for the given slot and attestation data root.
    ///
    /// The `committee_index` parameter is required for Electra and later forks.
    /// Pass `None` for pre-Electra requests.
    #[tracing::instrument(name = "beacon.get_aggregate_attestation", skip_all, fields(slot = slot))]
    pub async fn get_aggregate_attestation(
        &self,
        slot: u64,
        attestation_data_root: &str,
        committee_index: Option<u64>,
    ) -> Result<VersionedAggregateAttestation, BeaconError> {
        let slot_s = slot.to_string();
        let ci_s = committee_index.map(|ci| ci.to_string());
        let mut query: Vec<(&str, &str)> =
            vec![("slot", &slot_s), ("attestation_data_root", attestation_data_root)];
        if let Some(ref ci) = ci_s {
            query.push(("committee_index", ci.as_str()));
        }
        let path = Self::build_path(&["eth", "v1", "validator", "aggregate_attestation"], &query);

        if committee_index.is_some() {
            let resp: DataResponse<eth_types::ElectraAttestation> = self.get(&path).await?;
            Ok(VersionedAggregateAttestation::Electra(resp.data))
        } else {
            let resp: DataResponse<eth_types::Attestation> = self.get(&path).await?;
            Ok(VersionedAggregateAttestation::PreElectra(resp.data))
        }
    }

    /// Submits signed aggregate and proofs to the beacon node.
    pub async fn submit_aggregate_and_proofs(
        &self,
        proofs: &VersionedSignedAggregateAndProof,
    ) -> Result<(), BeaconError> {
        let span = tracing::info_span!("beacon.submit_aggregate_and_proofs");
        match proofs {
            VersionedSignedAggregateAndProof::PreElectra(ps) => {
                self.post_empty("/eth/v1/validator/aggregate_and_proofs", ps).instrument(span).await
            }
            VersionedSignedAggregateAndProof::Electra(ps) => {
                self.post_empty_with_headers(
                    "/eth/v2/validator/aggregate_and_proofs",
                    ps,
                    &[("Eth-Consensus-Version", ForkName::Electra.as_ref())],
                )
                .instrument(span)
                .await
            }
            VersionedSignedAggregateAndProof::Fulu(ps) => {
                self.post_empty_with_headers(
                    "/eth/v2/validator/aggregate_and_proofs",
                    ps,
                    &[("Eth-Consensus-Version", ForkName::Fulu.as_ref())],
                )
                .instrument(span)
                .await
            }
        }
    }

    /// Sends proposer preparation data to the beacon node.
    ///
    /// Informs the beacon node of each validator's fee recipient address
    /// so that the execution layer can direct transaction fees appropriately.
    pub async fn prepare_beacon_proposer(
        &self,
        preparations: &[ProposerPreparation],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/validator/prepare_beacon_proposer", &preparations)
            .instrument(tracing::info_span!("beacon.prepare_beacon_proposer"))
            .await
    }

    /// Posts validator indices to check liveness for the given epoch.
    ///
    /// Returns liveness data indicating whether each validator was active
    /// during the specified epoch. Used for doppelganger detection.
    #[tracing::instrument(name = "beacon.post_validator_liveness", skip_all, fields(epoch = epoch))]
    pub async fn post_validator_liveness(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        let path = format!("/eth/v1/validator/liveness/{}", epoch);
        self.post(&path, &validator_indices).await
    }

    /// Single-BN merge is a self-delegation: this node is the only source.
    pub async fn post_validator_liveness_merged(
        &self,
        epoch: u64,
        validator_indices: &[String],
    ) -> Result<ValidatorLivenessResponse, BeaconError> {
        self.post_validator_liveness(epoch, validator_indices).await
    }

    /// Submits a signed voluntary exit to the beacon node pool.
    ///
    /// Once submitted, the exit is irreversible. The beacon node will propagate
    /// the exit through the network and the validator will be exited from the
    /// active validator set after the exit epoch.
    pub async fn submit_voluntary_exit(
        &self,
        signed_exit: &SignedVoluntaryExit,
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/beacon/pool/voluntary_exits", signed_exit)
            .instrument(tracing::info_span!("beacon.submit_voluntary_exit"))
            .await
    }

    /// Subscribes validators to beacon committees for attestation subnet management.
    ///
    /// The beacon node uses these subscriptions to join the appropriate
    /// attestation subnets and prepare for aggregation duties.
    pub async fn submit_beacon_committee_subscriptions(
        &self,
        subscriptions: &[BeaconCommitteeSubscription],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/validator/beacon_committee_subscriptions", &subscriptions)
            .instrument(tracing::info_span!("beacon.submit_beacon_committee_subscriptions"))
            .await
    }

    // Builder

    pub async fn register_validators(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BeaconError> {
        self.post_empty("/eth/v1/validator/register_validator", &registrations)
            .instrument(tracing::info_span!("beacon.register_validators"))
            .await
    }

    /// Fetches the sync status of the beacon node.
    ///
    /// Returns whether the node is syncing, its head slot, sync distance,
    /// and whether the execution layer is offline.
    #[tracing::instrument(name = "beacon.get_node_syncing", skip_all)]
    pub async fn get_node_syncing(&self) -> Result<SyncingResponse, BeaconError> {
        self.get("/eth/v1/node/syncing").await
    }

    /// Fetches the node version string from the beacon node.
    ///
    /// Tries `/eth/v2/node/version` first and, **only on HTTP 404**, falls back
    /// to `/eth/v1/node/version`. This is the only beacon endpoint allowed to
    /// route on a response status code: the payload is informational (logs /
    /// metrics) and no duty or signature depends on it (D25). A 404 on v2 is
    /// logged once per BN; any other v2 error is returned as-is.
    #[tracing::instrument(name = "beacon.get_node_version", skip_all)]
    pub async fn get_node_version(&self) -> Result<String, BeaconError> {
        match self.get::<NodeVersionV2Response>("/eth/v2/node/version").await {
            Ok(response) => Ok(response.data.version_string()),
            Err(BeaconError::ApiError { status: 404, .. }) => {
                if self
                    .node_version_v1_fallback_logged
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    warn!(
                        bn_url = %RedactedUrl(self.endpoint()),
                        "GET /eth/v2/node/version returned 404; falling back to /eth/v1/node/version (informational only — no duty or signature depends on this endpoint)"
                    );
                }
                let response: NodeVersionResponse = self.get("/eth/v1/node/version").await?;
                Ok(response.data.version)
            }
            Err(e) => Err(e),
        }
    }

    /// Submits signed attestations to the beacon node.
    ///
    /// Accepts a versioned attestation payload and submits to the beacon pool.
    /// Returns success if all attestations were accepted, or partial failure
    /// with details about which attestations failed validation.
    ///
    /// Server errors (5xx) will trigger retry logic with exponential backoff.
    pub async fn submit_attestation(
        &self,
        attestations: &VersionedAttestation,
    ) -> Result<SubmitAttestationResult, BeaconError> {
        let url = self.resolve_url("/eth/v2/beacon/pool/attestations")?;

        let span = tracing::info_span!(
            "beacon.submit_attestations",
            http.method = "POST",
            http.url = %RedactedUrl(&url),
            http.status_code = tracing::field::Empty,
        );

        let (consensus_version, attestation_count) = match attestations {
            VersionedAttestation::PreElectra(atts) => (ForkName::Phase0.as_ref(), atts.len()),
            VersionedAttestation::Electra(atts) => (ForkName::Electra.as_ref(), atts.len()),
            VersionedAttestation::Fulu(atts) => (ForkName::Fulu.as_ref(), atts.len()),
        };

        debug!(
            consensus_version = consensus_version,
            attestation_count = attestation_count,
            "Submitting attestations to beacon node"
        );

        self.execute_with_retry_raw(
            "POST",
            &url,
            || {
                let url = url.clone();
                async move {
                    match attestations {
                        VersionedAttestation::PreElectra(atts) => {
                            Self::traced(
                                self.client
                                    .post(&url)
                                    .header("Eth-Consensus-Version", consensus_version)
                                    .json(atts),
                            )
                            .send()
                            .await
                        }
                        VersionedAttestation::Electra(atts) | VersionedAttestation::Fulu(atts) => {
                            Self::traced(
                                self.client
                                    .post(&url)
                                    .header("Eth-Consensus-Version", consensus_version)
                                    .json(atts),
                            )
                            .send()
                            .await
                        }
                    }
                }
            },
            |response| {
                let status = response.status();
                span.record("http.status_code", status.as_u16());
                async move {
                    if status.is_success() {
                        return Ok(SubmitAttestationResult::Success);
                    }

                    // 400 partial-failure: parse per-index failures; never retry.
                    if status.as_u16() == 400 {
                        let body = read_body_capped_lossy(response, 16 * 1024).await;
                        warn!(
                            response_body = %body,
                            "Attestation submission returned 400"
                        );
                        if let Ok(error_response) =
                            serde_json::from_str::<AttestationSubmissionError>(&body)
                        {
                            if error_response.failures.is_empty() {
                                return Err(BeaconError::ApiError { status: 400, message: body });
                            }
                            return Ok(SubmitAttestationResult::PartialFailure {
                                failures: error_response.failures,
                            });
                        }
                        return Err(BeaconError::ApiError { status: 400, message: body });
                    }

                    Err(Self::api_error_from_response(response).await)
                }
            },
        )
        .await
    }

    /// JSON-deserializing request path built on the single retry engine.
    async fn execute_with_retry<F, Fut, T>(
        &self,
        http_method: &str,
        url: &str,
        request_fn: F,
    ) -> Result<T, BeaconError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
        T: DeserializeOwned,
    {
        let endpoint = url.split('?').next().unwrap_or(url).to_string();
        let method = http_method.to_string();
        let url_owned = url.to_string();
        let max_body_bytes = self.config.max_body_bytes;

        self.execute_with_retry_raw(http_method, url, request_fn, move |response| {
            let endpoint = endpoint.clone();
            let method = method.clone();
            let url_owned = url_owned.clone();
            async move {
                let status = response.status();
                if !status.is_success() {
                    return Err(Self::api_error_from_response(response).await);
                }

                // H-12: stream body with configurable cap before allocation.
                let body = read_body_capped(response, max_body_bytes).await?;
                debug!(
                    method = %method,
                    endpoint = %RedactedUrl(&endpoint),
                    bn_url = %RedactedUrl(&url_owned),
                    status_code = status.as_u16(),
                    response_size_bytes = body.len(),
                    "HTTP response received"
                );
                serde_json::from_slice::<T>(&body).map_err(|e| {
                    let preview_end = body.len().min(1024);
                    let preview = std::str::from_utf8(&body[..preview_end]).unwrap_or("<non-utf8>");
                    warn!(
                        error = %e,
                        body_preview = preview,
                        "Failed to parse beacon API response"
                    );
                    BeaconError::ParseError(format!("error decoding response body: {e}"))
                })
            }
        })
        .await
    }

    /// Performs a POST request with retry logic and optional headers, expecting an empty success response.
    async fn post_empty_with_headers<B: Serialize>(
        &self,
        path: &str,
        body: &B,
        headers: &[(&str, &str)],
    ) -> Result<(), BeaconError> {
        let url = self.resolve_url(path)?;

        // Serialize once so each retry reuses the same body bytes.
        let body_bytes = serde_json::to_vec(body).map_err(|e| {
            BeaconError::HttpError(format!("failed to serialize request body: {e}"))
        })?;
        let header_pairs: Vec<(String, String)> =
            headers.iter().map(|(n, v)| ((*n).to_string(), (*v).to_string())).collect();

        self.execute_with_retry_raw(
            "POST",
            &url,
            || {
                let pairs = header_pairs.clone();
                let body_bytes = body_bytes.clone();
                let url = url.clone();
                async move {
                    let mut request = self
                        .client
                        .post(&url)
                        .header(reqwest::header::CONTENT_TYPE, "application/json")
                        .body(body_bytes);
                    for (name, value) in &pairs {
                        request = request.header(name.as_str(), value.as_str());
                    }
                    Self::traced(request).send().await
                }
            },
            |response| async move {
                if response.status().is_success() {
                    Ok(())
                } else {
                    Err(Self::api_error_from_response(response).await)
                }
            },
        )
        .await
    }

    /// Single retry engine for all beacon HTTP paths.
    ///
    /// Auto-retries 429 (honouring `Retry-After`), 5xx, timeouts, and connect/request
    /// transport errors. Every other response — success, other 4xx, odd statuses — is
    /// handed to `on_response` so callers can special-case (e.g. attestation 400
    /// partial-failure) without a second loop.
    async fn execute_with_retry_raw<F, Fut, H, HFut, T>(
        &self,
        http_method: &str,
        url: &str,
        request_fn: F,
        on_response: H,
    ) -> Result<T, BeaconError>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
        H: Fn(reqwest::Response) -> HFut,
        HFut: std::future::Future<Output = Result<T, BeaconError>>,
    {
        let span = tracing::info_span!(
            "beacon.http",
            http.method = %http_method,
            http.url = %RedactedUrl(url),
            http.status_code = tracing::field::Empty,
        );
        let mut last_error = None;
        let endpoint = url.split('?').next().unwrap_or(url);

        let policy = self.retry_policy();
        for attempt in 0..=policy.max_retries {
            if attempt > 0 {
                let backoff = policy.calculate_backoff(attempt - 1);
                debug!(
                    endpoint = %RedactedUrl(endpoint),
                    attempt = attempt,
                    backoff_ms = backoff.as_millis() as u64,
                    bn_url = %RedactedUrl(url),
                    "Retrying HTTP request"
                );
                tokio::time::sleep(backoff).await;
            }

            let request_start = std::time::Instant::now();
            match request_fn().await {
                Ok(response) => {
                    let status = response.status();
                    span.record("http.status_code", status.as_u16());

                    if status.as_u16() == 429 {
                        let delay = RetryPolicy::retry_after_delay(
                            &response,
                            policy.calculate_backoff(attempt),
                        );
                        warn!(attempt = attempt, delay_ms = ?delay.as_millis(), "Rate limited (429), backing off");
                        last_error = Some(BeaconError::ApiError {
                            status: 429,
                            message: "Too Many Requests".to_string(),
                        });
                        tokio::time::sleep(delay).await;
                        continue;
                    }

                    if status.is_server_error() {
                        let message = read_body_capped_lossy(response, 16 * 1024).await;
                        last_error =
                            Some(BeaconError::ApiError { status: status.as_u16(), message });
                        warn!(
                            attempt = attempt,
                            status = status.as_u16(),
                            "Server error, will retry"
                        );
                        continue;
                    }

                    // Success, client errors, and other non-retry statuses → caller.
                    if status.is_success() {
                        let latency_ms = request_start.elapsed().as_millis() as u64;
                        debug!(
                            method = http_method,
                            endpoint = %RedactedUrl(endpoint),
                            bn_url = %RedactedUrl(url),
                            status_code = status.as_u16(),
                            latency_ms = latency_ms,
                            "HTTP response received"
                        );
                    }
                    return on_response(response).await;
                }
                Err(e) => {
                    if e.is_timeout() {
                        last_error = Some(BeaconError::Timeout);
                        warn!(
                            endpoint = %RedactedUrl(endpoint),
                            timeout_ms = self.config.timeout.as_millis() as u64,
                            attempt = attempt,
                            "Request timeout, will retry"
                        );
                        continue;
                    }

                    if e.is_connect() || e.is_request() {
                        last_error = Some(BeaconError::HttpError(e.to_string()));
                        warn!(attempt = attempt, error = %e, "Connection error, will retry");
                        continue;
                    }

                    return Err(BeaconError::HttpError(e.to_string()));
                }
            }
        }

        let err = last_error.unwrap_or_else(|| BeaconError::HttpError("Unknown error".to_string()));
        span.in_scope(|| {
            error!(
                endpoint = %RedactedUrl(endpoint),
                total_attempts = policy.max_retries + 1,
                last_error = %err,
                "Request failed after all retries exhausted"
            )
        });
        Err(err)
    }

    /// Map a non-success response body into `BeaconError::ApiError` (diagnostic cap 16 KiB).
    async fn api_error_from_response(response: reqwest::Response) -> BeaconError {
        let status = response.status().as_u16();
        let message = read_body_capped_lossy(response, 16 * 1024).await;
        BeaconError::ApiError { status, message }
    }

    /// Accept only 2xx responses; convert everything else to `ApiError`.
    async fn take_success_response(
        response: reqwest::Response,
    ) -> Result<reqwest::Response, BeaconError> {
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(Self::api_error_from_response(response).await)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn test_config_default_values() {
        let config = BeaconClientConfig::new("http://localhost:5052");
        assert_eq!(config.endpoint, "http://localhost:5052");
        assert_eq!(config.timeout, Duration::from_secs(30));
        assert_eq!(config.max_retries, 3);
        assert_eq!(config.initial_backoff, Duration::from_millis(100));
    }

    #[test]
    fn test_config_builder_pattern() {
        let config = BeaconClientConfig::new("http://localhost:5052")
            .with_timeout(Duration::from_secs(60))
            .with_max_retries(5)
            .with_initial_backoff(Duration::from_millis(200));

        assert_eq!(config.timeout, Duration::from_secs(60));
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff, Duration::from_millis(200));
    }

    #[test]
    fn test_client_creation_with_valid_url() {
        let config = BeaconClientConfig::new("http://localhost:5052");
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.endpoint(), "http://localhost:5052");
    }

    #[test]
    fn test_client_creation_strips_trailing_slash() {
        let config = BeaconClientConfig::new("http://localhost:5052/");
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.endpoint(), "http://localhost:5052");
    }

    #[test]
    fn test_client_creation_with_https() {
        let config = BeaconClientConfig::new("https://beacon.example.com");
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.endpoint(), "https://beacon.example.com");
    }

    #[test]
    fn test_client_creation_with_empty_url() {
        let config = BeaconClientConfig::new("");
        let result = BeaconClient::new(config);
        assert!(matches!(result, Err(BeaconError::InvalidUrl(_))));
    }

    #[test]
    fn test_client_creation_with_invalid_scheme() {
        let config = BeaconClientConfig::new("ftp://localhost:5052");
        let result = BeaconClient::new(config);
        assert!(matches!(result, Err(BeaconError::InvalidUrl(_))));
    }

    #[test]
    fn test_client_creation_without_scheme() {
        let config = BeaconClientConfig::new("localhost:5052");
        let result = BeaconClient::new(config);
        assert!(matches!(result, Err(BeaconError::InvalidUrl(_))));
    }

    #[test]
    fn test_timeout_accessor() {
        let config =
            BeaconClientConfig::new("http://localhost:5052").with_timeout(Duration::from_secs(60));
        let client = BeaconClient::new(config).unwrap();
        assert_eq!(client.timeout(), Duration::from_secs(60));
    }

    #[test]
    fn test_required_consensus_version_missing() {
        let headers = reqwest::header::HeaderMap::new();
        let err = required_consensus_version(&headers).unwrap_err();
        match err {
            BeaconError::ParseError(msg) => {
                assert!(msg.contains("Eth-Consensus-Version"), "{msg}");
                assert!(msg.contains("missing"), "{msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn test_required_consensus_version_unknown() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers
            .insert("Eth-Consensus-Version", reqwest::header::HeaderValue::from_static("gloas2"));
        let err = required_consensus_version(&headers).unwrap_err();
        match err {
            BeaconError::ParseError(msg) => {
                assert!(msg.contains("gloas2"), "{msg}");
            }
            other => panic!("expected ParseError, got {other:?}"),
        }
    }

    #[test]
    fn test_required_consensus_version_known() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Eth-Consensus-Version", reqwest::header::HeaderValue::from_static("deneb"));
        assert_eq!(required_consensus_version(&headers).unwrap(), ForkName::Deneb);
    }

    fn fulu_gloas_schedule() -> ForkSchedule {
        let mut schedule = ForkSchedule::unscheduled_gloas();
        schedule.fulu_fork_epoch = 500_000;
        schedule.gloas_fork_epoch = 600_000;
        schedule
    }

    #[test]
    fn test_proposer_duties_path_v1_at_fulu_epoch() {
        let schedule = fulu_gloas_schedule();
        assert_eq!(
            BeaconClient::proposer_duties_path(500_000, &schedule),
            "/eth/v1/validator/duties/proposer/500000"
        );
        assert_eq!(
            BeaconClient::proposer_duties_path(599_999, &schedule),
            "/eth/v1/validator/duties/proposer/599999"
        );
    }

    #[test]
    fn test_proposer_duties_path_v2_at_gloas_epoch() {
        let schedule = fulu_gloas_schedule();
        assert_eq!(
            BeaconClient::proposer_duties_path(600_000, &schedule),
            "/eth/v2/validator/duties/proposer/600000"
        );
    }

    #[test]
    fn test_calculate_backoff() {
        let policy = RetryPolicy::new(3, Duration::from_millis(100));

        // With +/-25% jitter, check ranges instead of exact values
        let b0 = policy.calculate_backoff(0).as_millis() as u64;
        assert!((75..=125).contains(&b0), "attempt 0: {b0}ms not in [75,125]");

        let b1 = policy.calculate_backoff(1).as_millis() as u64;
        assert!((150..=250).contains(&b1), "attempt 1: {b1}ms not in [150,250]");

        let b2 = policy.calculate_backoff(2).as_millis() as u64;
        assert!((300..=500).contains(&b2), "attempt 2: {b2}ms not in [300,500]");

        let b3 = policy.calculate_backoff(3).as_millis() as u64;
        assert!((600..=1000).contains(&b3), "attempt 3: {b3}ms not in [600,1000]");
    }

    #[test]
    fn test_calculate_backoff_high_attempt_values_no_panic() {
        let policy = RetryPolicy::new(3, Duration::from_millis(100));

        // These should not panic - they would overflow with the naive implementation
        let _ = policy.calculate_backoff(20);
        let _ = policy.calculate_backoff(31);
        let _ = policy.calculate_backoff(32);
        let _ = policy.calculate_backoff(100);
    }

    #[test]
    fn test_calculate_backoff_capped_at_maximum() {
        let policy = RetryPolicy::new(3, Duration::from_millis(100));

        // Max base backoff at attempt 20: 100ms * 2^20 = 104,857,600ms (~29 hours)
        let max_base_ms: u64 = 100 * (1 << 20);
        let max_low = max_base_ms * 3 / 4; // -25%
        let max_high = max_base_ms * 5 / 4; // +25%

        // All attempts >= 20 should return backoff within +/-25% of the same max base
        for n in [20u32, 31, 32, 100] {
            let ms = policy.calculate_backoff(n).as_millis() as u64;
            assert!(
                (max_low..=max_high).contains(&ms),
                "attempt {n}: {ms}ms not in [{max_low},{max_high}]"
            );
        }
    }

    #[test]
    fn test_calculate_backoff_within_jitter_range() {
        let policy = RetryPolicy::new(3, Duration::from_millis(100));

        // Verify each attempt's backoff is within +/-25% of the expected base
        for _ in 0..100 {
            let b0 = policy.calculate_backoff(0).as_millis() as u64;
            assert!((75..=125).contains(&b0), "attempt 0: {b0}ms not in [75,125]");
        }

        for _ in 0..100 {
            let b1 = policy.calculate_backoff(1).as_millis() as u64;
            assert!((150..=250).contains(&b1), "attempt 1: {b1}ms not in [150,250]");
        }
    }

    // --- RF4-22: URL encoding + traced() ---

    #[test]
    fn test_all_current_urls_unchanged_after_encoding_change() {
        // KAT: existing safe inputs must produce byte-identical paths to the
        // historical format!("{}…") construction (no accidental re-encoding).
        struct Case {
            segments: &'static [&'static str],
            query: &'static [(&'static str, &'static str)],
            expected: &'static str,
        }
        let cases = [
            Case {
                segments: &["eth", "v1", "config", "spec"],
                query: &[],
                expected: "/eth/v1/config/spec",
            },
            Case {
                segments: &["eth", "v1", "beacon", "states", "head", "fork"],
                query: &[],
                expected: "/eth/v1/beacon/states/head/fork",
            },
            Case {
                segments: &["eth", "v1", "beacon", "states", "finalized", "fork"],
                query: &[],
                expected: "/eth/v1/beacon/states/finalized/fork",
            },
            Case {
                segments: &["eth", "v1", "beacon", "blocks", "head", "root"],
                query: &[],
                expected: "/eth/v1/beacon/blocks/head/root",
            },
            Case {
                segments: &["eth", "v1", "validator", "duties", "proposer", "123"],
                query: &[],
                expected: "/eth/v1/validator/duties/proposer/123",
            },
            Case {
                segments: &["eth", "v1", "validator", "attestation_data"],
                query: &[("slot", "1000"), ("committee_index", "1")],
                expected: "/eth/v1/validator/attestation_data?slot=1000&committee_index=1",
            },
            Case {
                segments: &["eth", "v3", "validator", "blocks", "42"],
                query: &[("randao_reveal", "0xabc"), ("builder_boost_factor", "50")],
                expected: "/eth/v3/validator/blocks/42?randao_reveal=0xabc&builder_boost_factor=50",
            },
            Case {
                segments: &["eth", "v1", "validator", "aggregate_attestation"],
                query: &[("slot", "100"), ("attestation_data_root", "0xdeadbeef")],
                expected:
                    "/eth/v1/validator/aggregate_attestation?slot=100&attestation_data_root=0xdeadbeef",
            },
        ];

        for case in &cases {
            let got = BeaconClient::build_path(case.segments, case.query);
            assert_eq!(&got, case.expected, "segments={:?} query={:?}", case.segments, case.query);
        }

        let config = BeaconClientConfig::new("http://localhost:5052");
        let client = BeaconClient::new(config).unwrap();
        let abs = client.resolve_url("/eth/v1/config/spec").unwrap();
        assert_eq!(abs, "http://localhost:5052/eth/v1/config/spec");
    }

    #[test]
    fn test_state_id_with_reserved_characters_is_percent_encoded() {
        // Path segment with `/` and space must be percent-encoded (not split into
        // extra path segments).
        let path = BeaconClient::build_path(
            &["eth", "v1", "beacon", "states", "foo/bar baz", "fork"],
            &[],
        );
        assert_eq!(path, "/eth/v1/beacon/states/foo%2Fbar%20baz/fork");

        // Query values with reserved characters are form-urlencoded.
        let path = BeaconClient::build_path(
            &["eth", "v1", "validator", "sync_committee_contribution"],
            &[("slot", "1"), ("subcommittee_index", "2"), ("beacon_block_root", "0xab&cd=ef")],
        );
        assert!(
            path.contains("beacon_block_root=0xab%26cd%3Def")
                || path.contains("beacon_block_root=0xab%26cd%3def"),
            "reserved query chars must be encoded: {path}"
        );
    }

    /// SSRF regression: absolute / scheme-relative path inputs must not rewrite
    /// the configured beacon origin (`Url::join` absolute-URL takeover).
    #[test]
    fn test_resolve_url_rejects_absolute_url_host_takeover() {
        let client = BeaconClient::new(BeaconClientConfig::new("http://localhost:5052")).unwrap();

        let evil_paths = [
            "http://evil.com/x",
            "/http://evil.com/x",
            "https://evil.com/a?b=1",
            "/https://evil.com/a?b=1",
            "HTTP://evil.com/",
            "//evil.com/steal",
            "/http://127.0.0.1:9/admin",
        ];
        for evil in evil_paths {
            let err = client.resolve_url(evil).expect_err(&format!(
                "expected rejection for absolute/scheme-relative path: {evil}"
            ));
            match err {
                BeaconError::InvalidUrl(msg) => {
                    assert!(
                        msg.contains("origin")
                            || msg.contains("scheme-relative")
                            || msg.contains("refusing")
                            || msg.contains("cross-origin"),
                        "unexpected InvalidUrl message for {evil}: {msg}"
                    );
                    // Must not leak a joined evil absolute URL as a successful request target.
                    assert!(
                        !msg.contains("http://evil.com/x")
                            || msg.contains("refusing")
                            || msg.contains("origin")
                            || msg.contains("cross-origin"),
                        "error should refuse takeover for {evil}: {msg}"
                    );
                }
                other => panic!("expected InvalidUrl for {evil}, got {other:?}"),
            }
        }

        // Legitimate relative paths still resolve on the configured origin.
        assert_eq!(
            client.resolve_url("/eth/v1/config/spec").unwrap(),
            "http://localhost:5052/eth/v1/config/spec"
        );
        assert_eq!(
            client.resolve_url("/eth/v1/beacon/states/head/fork").unwrap(),
            "http://localhost:5052/eth/v1/beacon/states/head/fork"
        );

        // Percent-encoded scheme-like *segment* (via build_path) stays on-host.
        let encoded = BeaconClient::build_path(
            &["eth", "v1", "beacon", "states", "http://evil.com", "fork"],
            &[],
        );
        let abs = client.resolve_url(&encoded).unwrap();
        assert!(
            abs.starts_with("http://localhost:5052/"),
            "encoded segment must stay on configured origin: {abs}"
        );
        assert!(!abs.starts_with("http://evil.com"), "must not takeover origin: {abs}");
    }
}
