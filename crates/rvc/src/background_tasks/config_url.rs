//! Proposer configuration from URL with auto-refresh.
//!
//! Implements Prysm/Teku-compatible JSON schema for proposer configuration
//! fetched from a remote URL. Supports per-epoch refresh.

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn, Instrument};
use validator_store::{DefaultUpdate, RemoteDefaultRelease, ValidatorStore};

/// One successful proposer-config fetch.
///
/// `updates` is `None` when the document has no `proposer_config` object.
/// `Some` includes an empty object. An empty object omits every previously
/// named pubkey. A missing object does not.
#[derive(Debug, Clone, PartialEq)]
pub struct FetchedProposerConfig {
    pub updates: Option<Vec<ValidatorConfigUpdate>>,
    pub default_update: Option<ValidatorConfigUpdate>,
}

/// Literal pubkey key used for `default_config` entries (Prysm/Teku convention).
pub const DEFAULT_PUBKEY: &str = "default";

/// Largest proposer-config body this client will buffer.
///
/// Ten thousand validators are about 2 MiB: a quoted 48-byte pubkey, a fee
/// recipient, and a builder object are a little over 200 bytes, and
/// `10_000 * 217 ≈ 2.1 MiB`. 4 MiB leaves room for `default_config` and
/// longer builder fields.
pub const MAX_PROPOSER_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// DNS, TCP, and TLS. This is not the total request deadline.
const PROPOSER_CONFIG_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total deadline for DNS, connect, TLS, redirects, and the body.
///
/// reqwest 0.12 applies `.timeout()` to the response body as well. There is
/// no client-level read timeout.
const PROPOSER_CONFIG_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Idle gap allowed between body chunks, on top of the total deadline.
const PROPOSER_CONFIG_BODY_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const PROPOSER_CONFIG_MAX_REDIRECTS: usize = 10;
/// Logged remote keys stay this many Unicode scalars, then an ellipsis.
const LOG_KEY_PREFIX_CHARS: usize = 16;

/// Error mapping a URL-fetched proposer config entry into store types.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("invalid fee_recipient hex: {0}")]
    InvalidFeeRecipient(String),
    /// Zero address burns MEV/priority fees; refused like startup ZeroFeeRecipient / keymanager.
    #[error("fee_recipient cannot be the zero address")]
    ZeroFeeRecipient,
    #[error("invalid pubkey hex: {0}")]
    InvalidPubkey(String),
    #[error("invalid gas_limit: {0}")]
    InvalidGasLimit(String),
    #[error("pubkey is the literal \"default\"; use to_default_update")]
    IsDefaultPubkey,
    #[error("to_default_update requires pubkey \"default\"")]
    NotDefaultPubkey,
    /// The same 48-byte key appeared twice, including different hex spellings.
    #[error("duplicate pubkey")]
    DuplicatePubkey,
}

/// Top-level proposer config response from URL endpoint.
///
/// Compatible with both Prysm (`--proposer-settings-url`) and
/// Teku (`--validators-proposer-config`) JSON schemas.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposerConfigResponse {
    /// Absent on a Teku document that carries only `default_config`.
    /// Present, including an empty object, is the per-pubkey map.
    /// An exact duplicate key rejects the document (`DuplicatePubkey`).
    #[serde(default, deserialize_with = "deserialize_proposer_config")]
    pub proposer_config: Option<HashMap<String, ProposerEntry>>,
    #[serde(default)]
    pub default_config: Option<ProposerEntry>,
}

/// Reject an exact duplicate key. Different spellings of one pubkey are
/// rejected later, after both decode to the same `[u8; 48]`.
fn deserialize_proposer_config<'de, D>(
    deserializer: D,
) -> Result<Option<HashMap<String, ProposerEntry>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct ProposerConfigVisitor;

    impl<'de> Visitor<'de> for ProposerConfigVisitor {
        type Value = Option<HashMap<String, ProposerEntry>>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a proposer_config object or null")
        }

        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut out = HashMap::with_capacity(map.size_hint().unwrap_or(0));
            while let Some((key, entry)) = map.next_entry::<String, ProposerEntry>()? {
                if out.contains_key(&key) {
                    return Err(de::Error::custom(duplicate_pubkey_error(&key)));
                }
                out.insert(key, entry);
            }
            Ok(Some(out))
        }
    }

    deserializer.deserialize_any(ProposerConfigVisitor)
}

/// Per-validator proposer configuration entry.
#[derive(Debug, Clone, Deserialize)]
pub struct ProposerEntry {
    pub fee_recipient: Option<String>,
    #[serde(default)]
    pub builder: Option<BuilderEntry>,
}

/// Builder configuration within a proposer entry.
#[derive(Debug, Clone, Deserialize)]
pub struct BuilderEntry {
    pub enabled: Option<bool>,
    pub gas_limit: Option<String>,
}

/// Parsed proposer configuration update for a single validator.
///
/// Distinct from [`validator_store::ValidatorConfigUpdate`] (VD-E3): this type
/// carries the wire/JSON field names (`builder_enabled`, hex strings). Map with
/// [`ValidatorConfigUpdate::to_store_update`] or
/// [`ValidatorConfigUpdate::to_default_update`].
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatorConfigUpdate {
    pub pubkey: String,
    pub fee_recipient: Option<String>,
    pub builder_enabled: Option<bool>,
    pub gas_limit: Option<u64>,
}

impl ValidatorConfigUpdate {
    /// Returns `true` when this entry is the `default_config` sentinel (`"default"`).
    pub fn is_default_entry(&self) -> bool {
        self.pubkey == DEFAULT_PUBKEY
    }

    /// Map a per-validator entry to store types.
    ///
    /// - Absent optional fields become outer `None` (leave alone), never
    ///   `Some(None)` (clear).
    /// - `builder_enabled` renames to `builder_proposals`.
    /// - Malformed hex or the zero fee-recipient address is `Err` (never silent).
    /// - The literal pubkey `"default"` is rejected; use [`Self::to_default_update`].
    pub fn to_store_update(
        &self,
    ) -> Result<([u8; 48], validator_store::ValidatorConfigUpdate), ParseError> {
        if self.is_default_entry() {
            return Err(ParseError::IsDefaultPubkey);
        }
        let pubkey = parse_pubkey_hex(&self.pubkey)?;
        if let Some(gl) = self.gas_limit {
            validator_store::ensure_toml_u64("gas_limit", gl)
                .map_err(|e| ParseError::InvalidGasLimit(e.to_string()))?;
        }
        let fee_recipient = match &self.fee_recipient {
            None => None,
            Some(s) => Some(Some(parse_fee_recipient_hex(s)?)),
        };
        Ok((
            pubkey,
            validator_store::ValidatorConfigUpdate {
                fee_recipient,
                gas_limit: self.gas_limit.map(Some),
                graffiti: None,
                builder_proposals: self.builder_enabled,
                builder_boost_factor: None,
                block_selection_mode: None,
                builders: None,
                min_bid: None,
            },
        ))
    }

    /// Map a `default_config` entry to a store defaults partial update.
    ///
    /// Requires [`Self::is_default_entry`] (`pubkey == "default"`). Call only
    /// for the optional `default_config` value from fetch, not for per-validator
    /// `proposer_config` entries — elevating an arbitrary pubkey to store-wide
    /// defaults is refused with [`ParseError::NotDefaultPubkey`].
    ///
    /// Absent fields become `None` (leave alone). Malformed or zero fee-recipient
    /// hex is `Err`. Builder fields are not part of store defaults and are ignored.
    pub fn to_default_update(&self) -> Result<DefaultUpdate, ParseError> {
        if !self.is_default_entry() {
            return Err(ParseError::NotDefaultPubkey);
        }
        if let Some(gl) = self.gas_limit {
            validator_store::ensure_toml_u64("gas_limit", gl)
                .map_err(|e| ParseError::InvalidGasLimit(e.to_string()))?;
        }
        let fee_recipient = match &self.fee_recipient {
            None => None,
            Some(s) => Some(parse_fee_recipient_hex(s)?),
        };
        Ok(DefaultUpdate { fee_recipient, gas_limit: self.gas_limit, graffiti: None })
    }
}

/// Parse a 20-byte execution address from hex (optional single `0x`/`0X`).
///
/// Rejects the zero address (aligns with startup `ZeroFeeRecipient` and keymanager).
fn parse_fee_recipient_hex(s: &str) -> Result<[u8; 20], ParseError> {
    let hex = strip_hex_prefix(s)?;
    let bytes = hex::decode(hex).map_err(|e| {
        // Avoid embedding raw non-hex characters (may be sensitive) in logs.
        let msg = match e {
            hex::FromHexError::OddLength => "odd number of hex digits".to_owned(),
            hex::FromHexError::InvalidHexCharacter { index, .. } => {
                format!("non-hex character at index {index}")
            }
            hex::FromHexError::InvalidStringLength => "invalid string length".to_owned(),
        };
        ParseError::InvalidFeeRecipient(msg)
    })?;
    let addr: [u8; 20] = bytes.try_into().map_err(|v: Vec<u8>| {
        ParseError::InvalidFeeRecipient(format!("expected 20 bytes, got {}", v.len()))
    })?;
    if addr == [0u8; 20] {
        return Err(ParseError::ZeroFeeRecipient);
    }
    Ok(addr)
}

/// Parse a 48-byte BLS pubkey from hex (optional `0x`/`0X`, case-insensitive).
fn parse_pubkey_hex(s: &str) -> Result<[u8; 48], ParseError> {
    eth_types::canonical::pubkey_hex::parse_pubkey_hex(s)
        .map(|pk| *pk.as_bytes())
        .map_err(|e| ParseError::InvalidPubkey(e.to_string()))
}

/// Strip a single optional `0x`/`0X` prefix; reject doubled prefixes.
fn strip_hex_prefix(s: &str) -> Result<&str, ParseError> {
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        if rest.starts_with("0x") || rest.starts_with("0X") {
            return Err(ParseError::InvalidFeeRecipient("double 0x prefix".to_owned()));
        }
        Ok(rest)
    } else {
        Ok(s)
    }
}

/// Configuration for the proposer config URL refresh task.
#[derive(Debug, Clone)]
pub struct ProposerConfigUrlSettings {
    pub url: String,
    pub refresh_interval: Duration,
    pub token: Option<String>,
    pub insecure: bool,
}

/// Deadlines for one proposer-config client.
///
/// `connect_timeout` covers DNS, TCP, and TLS, not only the TCP handshake.
/// `request_timeout` is the total deadline for DNS, connect, TLS, redirects,
/// and the body (reqwest 0.12 applies it to body reads). `body_idle_timeout`
/// is the extra gap allowed between body chunks, re-armed on every chunk.
#[derive(Debug, Clone, Copy)]
struct FetchLimits {
    connect_timeout: Duration,
    request_timeout: Duration,
    body_idle_timeout: Duration,
}

fn production_limits() -> FetchLimits {
    FetchLimits {
        connect_timeout: PROPOSER_CONFIG_CONNECT_TIMEOUT,
        request_timeout: PROPOSER_CONFIG_REQUEST_TIMEOUT,
        body_idle_timeout: PROPOSER_CONFIG_BODY_IDLE_TIMEOUT,
    }
}

/// Success and failure counters for one refresh task.
///
/// Production clones the process metrics. A test passes its own unregistered
/// counters so exact counts do not share the process-global value.
#[derive(Clone)]
pub(crate) struct RefreshMeters {
    success: metrics::IntCounter,
    failure: metrics::IntCounter,
    #[cfg(test)]
    cancel_apply_join: bool,
}

fn production_meters() -> RefreshMeters {
    RefreshMeters {
        success: crate::metrics::RVC_PROPOSER_CONFIG_REFRESH_SUCCESS_TOTAL.clone(),
        failure: crate::metrics::RVC_PROPOSER_CONFIG_REFRESH_FAILURES_TOTAL.clone(),
        #[cfg(test)]
        cancel_apply_join: false,
    }
}

/// First `LOG_KEY_PREFIX_CHARS` Unicode scalars, then `…` when the text is longer.
///
/// Truncation walks `chars`, so it never splits a scalar. Remote documents are
/// untrusted and can be as large as the body cap. Logs and error strings keep
/// a short prefix and drop the rest.
fn bounded_log_text(raw: &str) -> String {
    let mut chars = raw.chars();
    let prefix: String = chars.by_ref().take(LOG_KEY_PREFIX_CHARS).collect();
    if chars.next().is_some() {
        format!("{prefix}…")
    } else {
        prefix
    }
}

fn bounded_remote_key(raw: &str) -> String {
    bounded_log_text(raw)
}

fn duplicate_pubkey_error(raw: &str) -> String {
    format!("duplicate pubkey {}", bounded_remote_key(raw))
}

fn bounded_parse_error(text: &str) -> String {
    if text.starts_with("duplicate pubkey ") || text.starts_with("duplicate field ") {
        return text.to_string();
    }
    format!("failed to parse proposer config JSON: {}", bounded_log_text(text))
}

/// Reject a repeated key at any object, including struct fields.
///
/// Keys of the `proposer_config` object are pubkeys and use the duplicate-pubkey
/// error. Every other repeated name is a duplicate field. Serde's own error
/// text is truncated; a remote document can echo an attacker string into it.
fn reject_duplicate_json_fields(bytes: &[u8]) -> Result<(), String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let scanned = de.deserialize_any(DuplicateJsonVisitor { keys_are_pubkeys: false });
    match scanned {
        Ok(()) => de.end().map_err(|e| bounded_parse_error(&e.to_string())),
        Err(e) => Err(bounded_parse_error(&e.to_string())),
    }
}

struct DuplicateJsonVisitor {
    keys_are_pubkeys: bool,
}

impl<'de> DeserializeSeed<'de> for DuplicateJsonVisitor {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for DuplicateJsonVisitor {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("json")
    }

    fn visit_bool<E: de::Error>(self, _v: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, _v: i64) -> Result<(), E> {
        Ok(())
    }

    fn visit_u64<E: de::Error>(self, _v: u64) -> Result<(), E> {
        Ok(())
    }

    fn visit_f64<E: de::Error>(self, _v: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, _v: &str) -> Result<(), E> {
        Ok(())
    }

    fn visit_string<E: de::Error>(self, _v: String) -> Result<(), E> {
        Ok(())
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(DuplicateJsonVisitor { keys_are_pubkeys: false })?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                let msg = if self.keys_are_pubkeys {
                    duplicate_pubkey_error(&key)
                } else {
                    format!("duplicate field {}", bounded_log_text(&key))
                };
                return Err(de::Error::custom(msg));
            }
            let child_keys_are_pubkeys = !self.keys_are_pubkeys && key == "proposer_config";
            map.next_value_seed(DuplicateJsonVisitor { keys_are_pubkeys: child_keys_are_pubkeys })?;
        }
        Ok(())
    }
}

/// Follow a redirect only when the next URL has the same scheme, host, and port.
fn same_origin(prev: &reqwest::Url, next: &reqwest::Url) -> bool {
    prev.scheme() == next.scheme()
        && prev.host() == next.host()
        && prev.port_or_known_default() == next.port_or_known_default()
}

/// Same-origin redirects only, in both secure and insecure modes.
///
/// A change of scheme, host, or port is cross-origin. That includes
/// `https://h:8443` → `http://h:8443` and a hop onto loopback. The limit is
/// [`PROPOSER_CONFIG_MAX_REDIRECTS`].
fn proposer_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > PROPOSER_CONFIG_MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        if let Some(prev) = attempt.previous().last() {
            if !same_origin(prev, attempt.url()) {
                return attempt.error("refusing cross-origin redirect");
            }
        }
        attempt.follow()
    })
}

/// HTTP client builder for proposer-config fetches.
///
/// Env and system proxies stay enabled: `no_proxy()` / `proxy()` would turn
/// them off. Tests that must not follow the environment call `no_proxy()`
/// on the builder this returns. There is no application-level retry, no
/// `Referer`, and no content decoding, so `Content-Length` is the wire size.
fn proposer_config_client_builder(insecure: bool, limits: FetchLimits) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .connect_timeout(limits.connect_timeout)
        .timeout(limits.request_timeout)
        .redirect(proposer_redirect_policy())
        .referer(false)
        .https_only(!insecure)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        // Default client policy retries protocol NACKs. This fetch does not.
        .retry(reqwest::retry::never())
}

/// HTTP client for proposer-config fetches.
///
/// Built once per refresh task and cloned per request (`reqwest::Client` is
/// a handle).
fn proposer_config_client(insecure: bool) -> Result<reqwest::Client, String> {
    proposer_config_client_builder(insecure, production_limits())
        .build()
        .map_err(|e| format!("failed to create HTTP client: {e}"))
}

fn report_client_build_failure(err: &str, meters: &RefreshMeters) {
    error!(error = %err, "Failed to create proposer config HTTP client");
    meters.failure.inc();
}

fn body_cap() -> u64 {
    u64::try_from(MAX_PROPOSER_CONFIG_BYTES).expect("4 MiB fits in u64")
}

fn body_cap_exceeded(got: u64) -> String {
    format!("proposer config body exceeds the {MAX_PROPOSER_CONFIG_BYTES} byte cap (got {got})")
}

/// Advertised length from the size hint and the `Content-Length` header.
///
/// The larger of the two wins, so a header above [`MAX_PROPOSER_CONFIG_BYTES`]
/// is rejected even when the hint is absent.
fn advertised_body_len(response: &reqwest::Response) -> Option<u64> {
    let from_hint = response.content_length();
    let from_header = response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.parse::<u64>().ok());
    match (from_hint, from_header) {
        (Some(hint), Some(header)) => Some(hint.max(header)),
        (Some(hint), None) => Some(hint),
        (None, Some(header)) => Some(header),
        (None, None) => None,
    }
}

/// Stream a body up to [`MAX_PROPOSER_CONFIG_BYTES`].
///
/// A `Content-Length` above the cap returns before any body byte is buffered.
/// A chunked body with no length is rejected on the chunk that would pass the cap.
/// Each `chunk()` call is bounded by `idle`. That timer starts when the read
/// starts, not when the request is sent, so a slow header does not consume it.
async fn read_body_capped(response: reqwest::Response, idle: Duration) -> Result<Vec<u8>, String> {
    let cap = body_cap();
    if let Some(advertised) = advertised_body_len(&response) {
        if advertised > cap {
            return Err(body_cap_exceeded(advertised));
        }
    }

    let mut body = Vec::new();
    let mut response = response;
    loop {
        let next = match tokio::time::timeout(idle, response.chunk()).await {
            Err(_elapsed) => return Err("timed out reading proposer config body".to_string()),
            Ok(Ok(chunk)) => chunk,
            Ok(Err(e)) => return Err(map_transport_error(e)),
        };
        match next {
            Some(chunk) => {
                let chunk_len = u64::try_from(chunk.len()).unwrap_or(u64::MAX);
                let already = u64::try_from(body.len()).unwrap_or(u64::MAX);
                let new_total = already.saturating_add(chunk_len);
                if new_total > cap {
                    return Err(body_cap_exceeded(new_total));
                }
                body.extend_from_slice(&chunk);
            }
            None => break,
        }
    }
    Ok(body)
}

/// Transport failure text. Timeouts lead with `timed out`. The URL is dropped
/// so a query string cannot reach a log line.
fn map_transport_error(err: reqwest::Error) -> String {
    if err.is_timeout() {
        return "timed out fetching proposer config".to_string();
    }
    let err = err.without_url();
    let mut detail = err.to_string();
    let mut source = std::error::Error::source(&err);
    while let Some(inner) = source {
        let text = inner.to_string();
        if !detail.contains(&text) {
            detail.push_str(": ");
            detail.push_str(&text);
        }
        source = std::error::Error::source(inner);
    }
    format!("failed to fetch proposer config: {detail}")
}

/// Fetches proposer configuration from the given URL.
///
/// Returns a list of per-validator config updates and an optional default config.
/// Supports Bearer token authentication and HTTPS enforcement.
///
/// The body is capped at [`MAX_PROPOSER_CONFIG_BYTES`]. An exact duplicate JSON
/// key or two spellings of one pubkey (`DuplicatePubkey`) rejects the document.
pub async fn fetch_proposer_config(
    url: &str,
    token: Option<&str>,
    insecure: bool,
) -> Result<FetchedProposerConfig, String> {
    let client = proposer_config_client(insecure)?;
    fetch_proposer_config_with_client(
        &client,
        url,
        token,
        insecure,
        production_limits().body_idle_timeout,
        &production_meters(),
    )
    .await
}

async fn fetch_proposer_config_with_client(
    client: &reqwest::Client,
    url: &str,
    token: Option<&str>,
    insecure: bool,
    body_idle: Duration,
    meters: &RefreshMeters,
) -> Result<FetchedProposerConfig, String> {
    if !insecure && !url.starts_with("https://") {
        return Err(
            "proposer config URL requires HTTPS; use --proposer-config-url-insecure for HTTP"
                .to_string(),
        );
    }

    let mut request = client.get(url);
    if let Some(t) = token {
        request = request.bearer_auth(t);
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(err) => {
            let msg = map_transport_error(err);
            // Counted here so a direct fetch and the refresh loop share one increment.
            if msg.contains("cross-origin redirect") || msg.contains("scheme is not allowed") {
                meters.failure.inc();
            }
            return Err(msg);
        }
    };

    if !response.status().is_success() {
        return Err(format!("proposer config URL returned HTTP {}", response.status()));
    }

    // `MAX_PROPOSER_CONFIG_BYTES`: header first, then the chunk loop.
    let bytes = read_body_capped(response, body_idle).await?;
    reject_duplicate_json_fields(&bytes)?;
    let body: ProposerConfigResponse =
        serde_json::from_slice(&bytes).map_err(|e| bounded_parse_error(&e.to_string()))?;

    if body.proposer_config.is_none() && body.default_config.is_none() {
        return Err(
            "proposer config JSON has neither proposer_config nor default_config".to_string()
        );
    }

    let updates = match &body.proposer_config {
        None => None,
        Some(map) => {
            let mut updates = Vec::new();
            for (pubkey, entry) in map {
                updates.push(entry_to_update(pubkey.clone(), entry).map_err(|e| {
                    format!(
                        "invalid proposer config for pubkey {}: {e}",
                        bounded_remote_key(pubkey)
                    )
                })?);
            }
            Some(updates)
        }
    };

    let default_update = body
        .default_config
        .as_ref()
        .map(|entry| entry_to_update(DEFAULT_PUBKEY.to_string(), entry))
        .transpose()
        .map_err(|e| format!("invalid default_config: {e}"))?;

    // Validate every entry before the caller applies any of them. One bad
    // fee, pubkey, or gas limit rejects the whole fetch: a sibling is not
    // published and an omitted key is not restored. `DuplicatePubkey` covers
    // two spellings of the same 48 bytes (`0xAB…`, `0xab…`, `ab…`).
    if let Some(updates) = &updates {
        let mut seen = HashSet::with_capacity(updates.len());
        for update in updates {
            let (pk, _) = update.to_store_update().map_err(|e| {
                format!(
                    "invalid proposer config for pubkey {}: {e}",
                    bounded_remote_key(&update.pubkey)
                )
            })?;
            if !seen.insert(pk) {
                return Err(duplicate_pubkey_error(&update.pubkey));
            }
        }
    }
    if let Some(update) = &default_update {
        update.to_default_update().map_err(|e| format!("invalid default_config: {e}"))?;
    }

    Ok(FetchedProposerConfig { updates, default_update })
}

/// Build a wire update from a JSON entry.
///
/// Malformed `builder.gas_limit` strings are `Err` (not silent `None`) so a
/// multi-field entry cannot partially apply fee_recipient while dropping gas.
fn entry_to_update(
    pubkey: String,
    entry: &ProposerEntry,
) -> Result<ValidatorConfigUpdate, ParseError> {
    let (builder_enabled, gas_limit) = match &entry.builder {
        Some(b) => {
            let gas_limit = match b.gas_limit.as_deref() {
                None => None,
                Some(g) => {
                    let parsed =
                        g.parse::<u64>().map_err(|e| ParseError::InvalidGasLimit(e.to_string()))?;
                    validator_store::ensure_toml_u64("gas_limit", parsed)
                        .map_err(|e| ParseError::InvalidGasLimit(e.to_string()))?;
                    Some(parsed)
                }
            };
            (b.enabled, gas_limit)
        }
        None => (None, None),
    };

    Ok(ValidatorConfigUpdate {
        pubkey,
        fee_recipient: entry.fee_recipient.clone(),
        builder_enabled,
        gas_limit,
    })
}

/// Pubkeys named by the last successful fetch that included `proposer_config`.
///
/// Call [`Self::apply`] only after a fetch succeeds and every entry validates.
/// A 401, a body that is not JSON, a body with neither `proposer_config` nor
/// `default_config`, or one bad entry must not call it.
///
/// Ownership of each fee recipient, gas limit, and builder flag lives in
/// [`ValidatorStore`]. When the URL starts owning a field, the store snapshots
/// that field's live value under the same lock as the write. A keymanager
/// write of a field the URL owns drops that ownership, even when the written
/// value equals the URL value. A later document owns the field again only by
/// setting a value, and the baseline is the live value at that moment.
/// Omitting a pubkey restores each field the URL still owns. Naming the
/// pubkey but omitting a field releases that field the same way. One
/// successful document is one state write: rows are claimed, omitted pubkeys
/// are released, then defaults are applied and omitted default fields are
/// released. A fetch with no `proposer_config` object applies `default_config`
/// only and does not restore omitted pubkeys.
///
/// `default_config` changes the live defaults. The store does not write it
/// into `[defaults]`. A successful document that omits `default_config`, or
/// omits one of its fields, releases that remote default. A failed fetch does
/// not. No block is signed or published.
#[derive(Default)]
pub struct ProposerConfigApplier {
    seen: HashSet<[u8; 48]>,
}

impl ProposerConfigApplier {
    /// An applier that has not yet seen a successful fetch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one fully validated fetch.
    ///
    /// `updates == None` means the document had no `proposer_config` object.
    /// Every entry is checked before any store write. One bad pubkey, fee, or
    /// gas limit leaves the previous URL values in place and does not restore
    /// omitted keys. Rows are claimed before defaults are released, so a
    /// reader does not observe the local default fee for a row this document
    /// still sets. No block is signed or published.
    pub fn apply(
        &mut self,
        store: &ValidatorStore,
        updates: Option<Vec<ValidatorConfigUpdate>>,
        default_update: Option<ValidatorConfigUpdate>,
    ) {
        let Some(updates) = updates else {
            let Some(update) = default_update else {
                return;
            };
            let default_update = match update.to_default_update() {
                Ok(update) => update,
                Err(e) => {
                    warn!(error = %e, "proposer config rejected; previous values stay");
                    return;
                }
            };
            publish_remote_defaults(store, Some(default_update));
            return;
        };
        let Ok(prepared) = prepare_fetch(&updates, default_update.as_ref()) else {
            return;
        };
        let mut present = HashSet::new();
        for (pk, _) in &prepared.rows {
            present.insert(*pk);
        }
        let missing: Vec<[u8; 48]> =
            self.seen.iter().copied().filter(|pk| !present.contains(pk)).collect();
        if let Err(e) = store.apply_remote_document(prepared.rows, missing, prepared.default_update)
        {
            warn!(error = %e, "proposer config document rejected; previous values stay");
            return;
        }
        self.seen = present;
    }
}

/// Apply `default_config` fields the document sets, then release the ones it omits.
///
/// `None` means the document had no `default_config`. Every remote default is
/// released. An apply error leaves the previous remote defaults in place.
fn publish_remote_defaults(store: &ValidatorStore, update: Option<DefaultUpdate>) {
    let Some(update) = update else {
        store.release_remote_defaults(RemoteDefaultRelease::all());
        return;
    };
    let release = RemoteDefaultRelease::omitted(&update);
    if let Err(e) = store.apply_remote_defaults(update) {
        warn!(error = %e, "proposer config default entry ignored");
        return;
    }
    store.release_remote_defaults(release);
}

struct PreparedFetch {
    default_update: Option<DefaultUpdate>,
    rows: Vec<([u8; 48], validator_store::ValidatorConfigUpdate)>,
}

/// Parse every entry. `Err` means the caller must not write or restore.
fn prepare_fetch(
    updates: &[ValidatorConfigUpdate],
    default_update: Option<&ValidatorConfigUpdate>,
) -> Result<PreparedFetch, ()> {
    let default_update = match default_update {
        None => None,
        Some(update) => match update.to_default_update() {
            Ok(update) => Some(update),
            Err(e) => {
                warn!(error = %e, "proposer config rejected; previous values stay");
                return Err(());
            }
        },
    };
    let mut rows = Vec::with_capacity(updates.len());
    for update in updates {
        if update.is_default_entry() {
            warn_ignored_entry(&update.pubkey, &ParseError::IsDefaultPubkey);
            return Err(());
        }
        match update.to_store_update() {
            Ok((pk, store_update)) => rows.push((pk, store_update)),
            Err(e) => {
                warn_ignored_entry(&update.pubkey, &e);
                return Err(());
            }
        }
    }
    Ok(PreparedFetch { default_update, rows })
}

fn warn_ignored_entry(pubkey: &str, error: &impl std::fmt::Display) {
    let pubkey = bounded_remote_key(pubkey);
    warn!(error = %error, pubkey = %pubkey, "proposer config entry ignored");
}

/// Starts the background proposer config refresh task.
///
/// Fetches proposer config from URL at the configured interval and
/// calls `apply_fn` with the parsed updates. On failure, retains existing
/// config and logs at WARN level.
///
/// The HTTP client is built once. Each fetch, including the initial one, is
/// raced with `shutdown`. Dropping the fetch future stops this task from
/// waiting on it. DNS lookup and a connect already spawned inside the HTTP
/// stack can outlive that drop; those are bounded by the connect timeout
/// and the request deadline, not by the drop itself.
///
/// `apply_fn` runs on the blocking pool because it waits on the store save
/// lock while durable writers hold that lock across `write_toml_atomic`.
/// Shutdown observed before `spawn_blocking` does not start apply and is
/// not a success. An apply that has started is awaited and still runs to
/// completion, including a release of omitted fields. Shutdown does not roll
/// that release back. A cancelled or failed join is not logged or counted
/// as success.
pub async fn start_proposer_config_refresh<A>(
    settings: ProposerConfigUrlSettings,
    shutdown: CancellationToken,
    apply_fn: A,
) where
    A: Fn(FetchedProposerConfig) + Send + Sync + 'static,
{
    let meters = production_meters();
    let client = match proposer_config_client(settings.insecure) {
        Ok(client) => client,
        Err(e) => {
            report_client_build_failure(&e, &meters);
            return;
        }
    };
    let fetch_url = settings.url.clone();
    let fetch_token = settings.token.clone();
    let fetch_insecure = settings.insecure;
    let body_idle = production_limits().body_idle_timeout;
    let fetch_meters = meters.clone();
    start_proposer_config_refresh_with(
        settings,
        shutdown,
        meters,
        move || {
            let client = client.clone();
            let url = fetch_url.clone();
            let token = fetch_token.clone();
            let fetch_meters = fetch_meters.clone();
            async move {
                fetch_proposer_config_with_client(
                    &client,
                    &url,
                    token.as_deref(),
                    fetch_insecure,
                    body_idle,
                    &fetch_meters,
                )
                .await
            }
        },
        apply_fn,
    )
    .await;
}

/// Refresh loop with an injected fetch.
///
/// `fetch_fn` is called for the initial load and every later tick. Shutdown
/// during a fetch drops that future and returns. `apply_fn` is `Send + Sync`
/// and is invoked via `spawn_blocking`.
pub(crate) async fn start_proposer_config_refresh_with<F, Fut, A>(
    settings: ProposerConfigUrlSettings,
    shutdown: CancellationToken,
    meters: RefreshMeters,
    fetch_fn: F,
    apply_fn: A,
) where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<FetchedProposerConfig, String>> + Send,
    A: Fn(FetchedProposerConfig) + Send + Sync + 'static,
{
    let apply_fn = Arc::new(apply_fn);
    if !refresh_interval_is_usable(settings.refresh_interval) {
        error!(
            interval_secs = settings.refresh_interval.as_secs(),
            "proposer config refresh interval must be 1..=86400 seconds"
        );
        meters.failure.inc();
        return;
    }
    if !run_one_fetch(&shutdown, &fetch_fn, &apply_fn, &meters, true).await {
        return;
    }

    let mut interval = tokio::time::interval(settings.refresh_interval);
    // Skip the immediate first tick (we already did the initial fetch).
    interval.tick().await;

    // detached: process-lifetime loop root; the tick is the exported span.
    let loop_span = tracing::info_span!(parent: None, "proposer_config_refresh");
    loop {
        let tick = tracing::info_span!(parent: None, "proposer_config_refresh.tick");
        tick.follows_from(&loop_span);
        let stop = async {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    debug!("Proposer config refresh task shutting down");
                    true
                }
                _ = interval.tick() => {
                    !run_one_fetch(&shutdown, &fetch_fn, &apply_fn, &meters, false).await
                }
            }
        }
        .instrument(tick)
        .await;
        if stop {
            return;
        }
    }
}

/// `true` when the loop should keep refreshing. `false` means shutdown won.
async fn run_one_fetch<F, Fut, A>(
    shutdown: &CancellationToken,
    fetch_fn: &F,
    apply_fn: &Arc<A>,
    meters: &RefreshMeters,
    initial: bool,
) -> bool
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<FetchedProposerConfig, String>> + Send,
    A: Fn(FetchedProposerConfig) + Send + Sync + 'static,
{
    let fetched = tokio::select! {
        biased;
        _ = shutdown.cancelled() => {
            debug!("Proposer config refresh task shutting down");
            return false;
        }
        result = fetch_fn() => result,
    };
    match fetched {
        Ok(fetched) => {
            if shutdown.is_cancelled() {
                debug!("Proposer config refresh task shutting down");
                return false;
            }
            let count = fetched.updates.as_ref().map_or(0, Vec::len);
            let applied = invoke_apply(apply_fn, fetched, meters).await;
            #[cfg(any(test, feature = "test-utils"))]
            note_proposer_refresh_settled();
            if applied.is_err() {
                warn!("proposer config apply did not finish; not counting success");
                meters.failure.inc();
                return true;
            }
            if initial {
                info!(count, "Initial proposer config loaded from URL");
            } else {
                debug!(count, "Proposer config refreshed from URL");
            }
            meters.success.inc();
        }
        Err(e) => {
            if initial {
                warn!(error = %e, "Failed to load initial proposer config from URL");
            } else {
                warn!(
                    error = %e,
                    "Failed to refresh proposer config from URL, retaining existing config"
                );
            }
            if !fetch_error_already_counted(&e) {
                meters.failure.inc();
            }
            #[cfg(any(test, feature = "test-utils"))]
            note_proposer_refresh_settled();
        }
    }
    true
}

#[cfg(any(test, feature = "test-utils"))]
fn proposer_refresh_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[cfg(any(test, feature = "test-utils"))]
static PROPOSER_REFRESH_SETTLED: std::sync::Mutex<Option<std::sync::mpsc::Sender<()>>> =
    std::sync::Mutex::new(None);

/// Serialize refresh tasks in one test binary so they share one settle sender.
#[cfg(any(test, feature = "test-utils"))]
pub async fn testing_lock_proposer_refresh() -> tokio::sync::MutexGuard<'static, ()> {
    proposer_refresh_lock().lock().await
}

/// Install the sender notified after a fetch applies or fails. `None` clears it.
#[cfg(any(test, feature = "test-utils"))]
pub fn testing_set_proposer_refresh_settled(tx: Option<std::sync::mpsc::Sender<()>>) {
    *PROPOSER_REFRESH_SETTLED.lock().expect("proposer refresh settled") = tx;
}

#[cfg(any(test, feature = "test-utils"))]
fn note_proposer_refresh_settled() {
    if let Some(tx) = PROPOSER_REFRESH_SETTLED.lock().expect("proposer refresh settled").as_ref() {
        let _ = tx.send(());
    }
}

fn refresh_interval_is_usable(interval: Duration) -> bool {
    let max = Duration::from_secs(rvc_config::MAX_PROPOSER_CONFIG_REFRESH_INTERVAL_SECS);
    if interval.is_zero() || interval > max {
        return false;
    }
    // `interval()` adds the period onto an `Instant`. A duration that does not
    // fit is refused here instead of panicking inside the timer.
    let now = tokio::time::Instant::now();
    now.checked_add(interval).and_then(|tick| tick.checked_add(interval)).is_some()
}

fn fetch_error_already_counted(err: &str) -> bool {
    err.contains("cross-origin redirect") || err.contains("scheme is not allowed")
}

/// Test double for a join that is aborted before `apply_fn` runs.
#[cfg(test)]
async fn aborted_apply_join_for_test(meters: &RefreshMeters) -> Option<Result<(), ()>> {
    if !meters.cancel_apply_join {
        return None;
    }
    let handle = tokio::spawn(std::future::pending::<()>());
    handle.abort();
    Some(settle_apply_join(handle).await)
}

/// Run `apply_fn` off the async worker.
///
/// File I/O under the store save lock happens on the writer that holds the
/// lock (`write_toml_atomic`, `sync_parent_dir`). This wait must not occupy
/// a Tokio worker.
///
/// The caller awaits the [`JoinHandle`], so shutdown of this task waits for
/// an apply that has already started. `Err` is a cancelled or failed join.
/// A panic is resumed. The caller must not count `Err` as a successful refresh.
async fn invoke_apply<A>(
    apply_fn: &Arc<A>,
    fetched: FetchedProposerConfig,
    #[cfg_attr(not(test), allow(unused_variables))] meters: &RefreshMeters,
) -> Result<(), ()>
where
    A: Fn(FetchedProposerConfig) + Send + Sync + 'static,
{
    #[cfg(test)]
    if let Some(result) = aborted_apply_join_for_test(meters).await {
        return result;
    }
    let apply_fn = Arc::clone(apply_fn);
    settle_apply_join(tokio::task::spawn_blocking(move || apply_fn(fetched))).await
}

/// A panic resumes. Any other join error, including cancellation, is a failure.
async fn settle_apply_join(handle: tokio::task::JoinHandle<()>) -> Result<(), ()> {
    match handle.await {
        Ok(()) => Ok(()),
        Err(err) if err.is_panic() => std::panic::resume_unwind(err.into_panic()),
        Err(_) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_prysm_compatible_json() {
        let json = r#"{
            "proposer_config": {
                "0x98765": {
                    "fee_recipient": "0xabcd",
                    "builder": {
                        "enabled": true,
                        "gas_limit": "30000000"
                    }
                }
            },
            "default_config": {
                "fee_recipient": "0x1234",
                "builder": {
                    "enabled": true,
                    "gas_limit": "30000000"
                }
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        let proposer_config = response.proposer_config.expect("proposer_config");
        assert_eq!(proposer_config.len(), 1);
        assert!(response.default_config.is_some());

        let entry = &proposer_config["0x98765"];
        assert_eq!(entry.fee_recipient.as_deref(), Some("0xabcd"));
        assert_eq!(entry.builder.as_ref().unwrap().enabled, Some(true));
        assert_eq!(entry.builder.as_ref().unwrap().gas_limit.as_deref(), Some("30000000"));
    }

    #[test]
    fn test_parse_teku_compatible_json() {
        let json = r#"{
            "proposer_config": {
                "0x98765": {
                    "fee_recipient": "0xabcd",
                    "builder": {
                        "enabled": true,
                        "gas_limit": "36000000"
                    }
                }
            },
            "default_config": {
                "fee_recipient": "0x1234",
                "builder": {
                    "enabled": true,
                    "gas_limit": "36000000"
                }
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        let proposer_config = response.proposer_config.expect("proposer_config");
        let entry = &proposer_config["0x98765"];
        assert_eq!(entry.builder.as_ref().unwrap().gas_limit.as_deref(), Some("36000000"));
    }

    #[test]
    fn test_entry_to_update_full() {
        let entry = ProposerEntry {
            fee_recipient: Some("0xabcd".to_string()),
            builder: Some(BuilderEntry {
                enabled: Some(true),
                gas_limit: Some("30000000".to_string()),
            }),
        };

        let update = entry_to_update("0x98765".to_string(), &entry).expect("valid entry");
        assert_eq!(update.pubkey, "0x98765");
        assert_eq!(update.fee_recipient.as_deref(), Some("0xabcd"));
        assert_eq!(update.builder_enabled, Some(true));
        assert_eq!(update.gas_limit, Some(30000000));
    }

    #[test]
    fn test_entry_to_update_no_builder() {
        let entry = ProposerEntry { fee_recipient: Some("0x1234".to_string()), builder: None };

        let update = entry_to_update("0xabc".to_string(), &entry).expect("valid entry");
        assert_eq!(update.builder_enabled, None);
        assert_eq!(update.gas_limit, None);
    }

    #[test]
    fn test_entry_to_update_invalid_gas_limit() {
        let entry = ProposerEntry {
            fee_recipient: Some(format!("0x{}", hex::encode([0xaau8; 20]))),
            builder: Some(BuilderEntry {
                enabled: Some(false),
                gas_limit: Some("not_a_number".to_string()),
            }),
        };

        // Fail the whole entry — do not silently drop gas while keeping fee_recipient.
        let err = entry_to_update("0xdef".to_string(), &entry).expect_err("invalid gas");
        assert!(matches!(err, ParseError::InvalidGasLimit(_)));
    }

    #[test]
    fn test_parse_empty_proposer_config() {
        let json = r#"{
            "proposer_config": {},
            "default_config": {
                "fee_recipient": "0x1234"
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        assert!(response.proposer_config.expect("proposer_config").is_empty());
        assert!(response.default_config.is_some());
    }

    #[test]
    fn test_parse_no_default_config() {
        let json = r#"{
            "proposer_config": {
                "0x111": {
                    "fee_recipient": "0x222"
                }
            }
        }"#;

        let response: ProposerConfigResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.proposer_config.expect("proposer_config").len(), 1);
        assert!(response.default_config.is_none());
    }

    #[tokio::test]
    async fn test_fetch_rejects_http_without_insecure() {
        let result = fetch_proposer_config("http://example.com/config", None, false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTPS"));
    }

    #[tokio::test]
    async fn test_fetch_success_with_mock() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        let pubkey = valid_pubkey_hex();
        let fee = valid_fee_recipient_hex();
        let default_fee = fee_hex(0xcc);
        let body = format!(
            r#"{{
            "proposer_config": {{
                "{pubkey}": {{
                    "fee_recipient": "{fee}",
                    "builder": {{ "enabled": true, "gas_limit": "30000000" }}
                }}
            }},
            "default_config": {{
                "fee_recipient": "{default_fee}",
                "builder": {{ "enabled": false }}
            }}
        }}"#
        );

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let fetched = fetch_proposer_config(&mock_server.uri(), None, true).await.unwrap();
        let updates = fetched.updates.expect("proposer_config");
        let default_update = fetched.default_update;

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].pubkey, pubkey);
        assert_eq!(updates[0].fee_recipient.as_deref(), Some(fee.as_str()));
        assert_eq!(updates[0].builder_enabled, Some(true));
        assert_eq!(updates[0].gas_limit, Some(30000000));

        let default = default_update.unwrap();
        assert_eq!(default.fee_recipient.as_deref(), Some(default_fee.as_str()));
        assert_eq!(default.builder_enabled, Some(false));
    }

    #[tokio::test]
    async fn test_fetch_with_bearer_token() {
        use wiremock::matchers::{header, method};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(header("Authorization", "Bearer test-token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"proposer_config":{}}"#))
            .expect(1)
            .mount(&mock_server)
            .await;

        let fetched =
            fetch_proposer_config(&mock_server.uri(), Some("test-token"), true).await.unwrap();

        assert!(fetched.updates.expect("proposer_config").is_empty());
    }

    #[tokio::test]
    async fn test_fetch_http_error_returns_err() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = fetch_proposer_config(&mock_server.uri(), None, true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("HTTP 500"));
    }

    #[tokio::test]
    async fn test_refresh_clean_shutdown() {
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let started_fetch = std::sync::Arc::clone(&started);
        let shutdown = CancellationToken::new();
        let shutdown_clone = shutdown.clone();
        let handle = tokio::spawn(async move {
            start_proposer_config_refresh_with(
                ProposerConfigUrlSettings {
                    url: "http://127.0.0.1/config".to_string(),
                    refresh_interval: Duration::from_secs(3600),
                    token: None,
                    insecure: true,
                },
                shutdown_clone,
                production_meters(),
                move || {
                    started_fetch.notify_one();
                    std::future::pending::<Result<FetchedProposerConfig, String>>()
                },
                |_| {},
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .expect("injected fetch starts");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("refresh task shuts down while the fetch is in flight")
            .expect("refresh task");
    }

    fn valid_pubkey_hex() -> String {
        format!("0x{}", hex::encode([0x11u8; 48]))
    }

    fn valid_fee_recipient_hex() -> String {
        format!("0x{}", hex::encode([0xaau8; 20]))
    }

    #[test]
    fn to_store_update_maps_builder_enabled_to_builder_proposals() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: None,
            builder_enabled: Some(true),
            gas_limit: Some(30_000_000),
        };

        let (pk, store_update) = update.to_store_update().expect("valid entry");
        assert_eq!(pk, [0x11u8; 48]);
        assert_eq!(store_update.builder_proposals, Some(true));
        assert_eq!(store_update.gas_limit, Some(Some(30_000_000)));
    }

    #[test]
    fn to_store_update_rejects_a_malformed_fee_recipient() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some("not-a-hex-address".to_string()),
            builder_enabled: None,
            gas_limit: None,
        };

        // Malformed Some(hex) must be Err — never silently become outer None.
        match update.to_store_update() {
            Err(ParseError::InvalidFeeRecipient(_)) => {}
            Err(other) => panic!("expected InvalidFeeRecipient, got {other:?}"),
            Ok((_, store_update)) => panic!(
                "malformed fee_recipient must be Err, got Ok with fee_recipient={:?}",
                store_update.fee_recipient
            ),
        }
    }

    #[test]
    fn an_absent_fee_recipient_maps_to_outer_none_not_some_none() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: None,
            builder_enabled: Some(false),
            gas_limit: None,
        };

        let (_, store_update) = update.to_store_update().expect("valid entry");
        assert!(store_update.fee_recipient.is_none());
        assert_ne!(store_update.fee_recipient, Some(None));
    }

    #[test]
    fn the_literal_default_pubkey_routes_to_the_defaults_path() {
        let fr = valid_fee_recipient_hex();
        let update = ValidatorConfigUpdate {
            pubkey: DEFAULT_PUBKEY.to_string(),
            fee_recipient: Some(fr.clone()),
            builder_enabled: Some(true),
            gas_limit: Some(36_000_000),
        };

        assert!(update.is_default_entry());
        assert!(matches!(update.to_store_update(), Err(ParseError::IsDefaultPubkey)));

        let default = update.to_default_update().expect("defaults path");
        assert_eq!(default.fee_recipient, Some([0xaau8; 20]));
        assert_eq!(default.gas_limit, Some(36_000_000));
        // Builder is not a store-default field.
        assert!(default.graffiti.is_none());
    }

    #[test]
    fn to_store_update_accepts_fee_recipient_with_and_without_0x_prefix() {
        let with_prefix = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(valid_fee_recipient_hex()),
            builder_enabled: None,
            gas_limit: None,
        };
        let without_prefix = ValidatorConfigUpdate {
            pubkey: hex::encode([0x11u8; 48]),
            fee_recipient: Some(hex::encode([0xaau8; 20])),
            builder_enabled: None,
            gas_limit: None,
        };
        let upper_prefix = ValidatorConfigUpdate {
            pubkey: format!("0X{}", hex::encode([0x11u8; 48])),
            fee_recipient: Some(format!("0X{}", hex::encode([0xaau8; 20]))),
            builder_enabled: None,
            gas_limit: None,
        };

        for update in [with_prefix, without_prefix, upper_prefix] {
            let (pk, store_update) = update.to_store_update().expect("hex accepted");
            assert_eq!(pk, [0x11u8; 48]);
            assert_eq!(store_update.fee_recipient, Some(Some([0xaau8; 20])));
        }
    }

    #[test]
    fn to_default_update_absent_fee_recipient_is_none() {
        let update = ValidatorConfigUpdate {
            pubkey: DEFAULT_PUBKEY.to_string(),
            fee_recipient: None,
            builder_enabled: None,
            gas_limit: Some(30_000_000),
        };
        let default = update.to_default_update().expect("defaults path");
        assert!(default.fee_recipient.is_none());
        assert_eq!(default.gas_limit, Some(30_000_000));
    }

    #[test]
    fn to_default_update_rejects_malformed_fee_recipient() {
        let update = ValidatorConfigUpdate {
            pubkey: DEFAULT_PUBKEY.to_string(),
            fee_recipient: Some("0xgg".to_string()),
            builder_enabled: None,
            gas_limit: None,
        };
        assert!(matches!(update.to_default_update(), Err(ParseError::InvalidFeeRecipient(_))));
    }

    #[test]
    fn to_store_update_rejects_zero_fee_recipient() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(format!("0x{}", hex::encode([0u8; 20]))),
            builder_enabled: Some(true),
            gas_limit: Some(30_000_000),
        };
        // Must not partially apply builder/gas while accepting a burn address.
        assert!(matches!(update.to_store_update(), Err(ParseError::ZeroFeeRecipient)));
    }

    #[test]
    fn to_default_update_rejects_zero_fee_recipient() {
        let update = ValidatorConfigUpdate {
            pubkey: DEFAULT_PUBKEY.to_string(),
            fee_recipient: Some(format!("0x{}", "00".repeat(20))),
            builder_enabled: None,
            gas_limit: Some(30_000_000),
        };
        assert!(matches!(update.to_default_update(), Err(ParseError::ZeroFeeRecipient)));
    }

    #[test]
    fn to_default_update_rejects_non_default_pubkey() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(valid_fee_recipient_hex()),
            builder_enabled: None,
            gas_limit: None,
        };
        assert!(matches!(update.to_default_update(), Err(ParseError::NotDefaultPubkey)));
    }

    #[test]
    fn to_store_update_rejects_malformed_pubkey() {
        let update = ValidatorConfigUpdate {
            pubkey: "0xnot-a-pubkey".to_string(),
            fee_recipient: None,
            builder_enabled: None,
            gas_limit: None,
        };
        assert!(matches!(update.to_store_update(), Err(ParseError::InvalidPubkey(_))));
    }

    #[test]
    fn an_absent_gas_limit_maps_to_outer_none_not_some_none() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(valid_fee_recipient_hex()),
            builder_enabled: None,
            gas_limit: None,
        };
        let (_, store_update) = update.to_store_update().expect("valid entry");
        assert!(store_update.gas_limit.is_none());
        assert_ne!(store_update.gas_limit, Some(None));
    }

    #[test]
    fn to_store_update_rejects_double_0x_fee_recipient_prefix() {
        let update = ValidatorConfigUpdate {
            pubkey: valid_pubkey_hex(),
            fee_recipient: Some(format!("0x0x{}", hex::encode([0xaau8; 20]))),
            builder_enabled: None,
            gas_limit: None,
        };
        assert!(matches!(update.to_store_update(), Err(ParseError::InvalidFeeRecipient(_))));
    }

    #[tokio::test]
    async fn test_fetch_rejects_invalid_gas_limit_entry() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let body = r#"{
            "proposer_config": {
                "0xaaa": {
                    "fee_recipient": "0xbbb",
                    "builder": { "enabled": true, "gas_limit": "not_a_number" }
                }
            }
        }"#;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&mock_server)
            .await;

        let result = fetch_proposer_config(&mock_server.uri(), None, true).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("gas_limit"));
    }

    #[test]
    fn apply_proposer_config_updates_writes_per_validator_and_defaults() {
        use validator_store::ValidatorConfig;

        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        store.add_validator(ValidatorConfig::new(pk)).unwrap();

        let fr = valid_fee_recipient_hex();
        let default_fr = format!("0x{}", hex::encode([0xbbu8; 20]));
        ProposerConfigApplier::new().apply(
            &store,
            Some(vec![ValidatorConfigUpdate {
                pubkey: valid_pubkey_hex(),
                fee_recipient: Some(fr),
                builder_enabled: Some(true),
                gas_limit: Some(36_000_000),
            }]),
            Some(ValidatorConfigUpdate {
                pubkey: DEFAULT_PUBKEY.to_string(),
                fee_recipient: Some(default_fr),
                builder_enabled: None,
                gas_limit: Some(40_000_000),
            }),
        );

        assert_eq!(store.effective_fee_recipient(&pk), [0xaau8; 20]);
        assert!(store.is_builder_enabled(&pk));
        assert_eq!(store.effective_gas_limit(&pk), 36_000_000);
        assert_eq!(store.default_fee_recipient(), [0xbbu8; 20]);
        assert_eq!(store.default_gas_limit(), 40_000_000);
    }

    #[test]
    #[tracing_test::traced_test]
    fn apply_proposer_config_updates_skips_malformed_and_warns() {
        use validator_store::ValidatorConfig;

        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some([0xaau8; 20]);
        store.add_validator(cfg).unwrap();

        ProposerConfigApplier::new().apply(
            &store,
            Some(vec![ValidatorConfigUpdate {
                pubkey: valid_pubkey_hex(),
                fee_recipient: Some("not-hex".to_string()),
                builder_enabled: Some(true),
                gas_limit: None,
            }]),
            None,
        );

        assert_eq!(store.effective_fee_recipient(&pk), [0xaau8; 20]);
        assert!(logs_contain("proposer config entry ignored"));
    }

    /// A refresher `gas_limit` above `i64::MAX` must not go live. TOML cannot
    /// serialize it, so a published value makes every later save fail.
    #[test]
    fn apply_proposer_config_updates_rejects_gas_limit_above_i64_max() {
        use validator_store::ValidatorConfig;

        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        store.add_validator(ValidatorConfig::new(pk)).unwrap();
        let huge = (i64::MAX as u64).saturating_add(1);

        ProposerConfigApplier::new().apply(
            &store,
            Some(vec![ValidatorConfigUpdate {
                pubkey: valid_pubkey_hex(),
                fee_recipient: None,
                builder_enabled: None,
                gas_limit: Some(huge),
            }]),
            Some(ValidatorConfigUpdate {
                pubkey: DEFAULT_PUBKEY.to_string(),
                fee_recipient: None,
                builder_enabled: None,
                gas_limit: Some(huge),
            }),
        );

        assert_eq!(store.effective_gas_limit(&pk), 30_000_000);
        assert_eq!(store.default_gas_limit(), 30_000_000);
    }

    fn row(
        pubkey: &str,
        fee: Option<&str>,
        builder: Option<bool>,
        gas: Option<u64>,
    ) -> ValidatorConfigUpdate {
        ValidatorConfigUpdate {
            pubkey: pubkey.to_string(),
            fee_recipient: fee.map(str::to_string),
            builder_enabled: builder,
            gas_limit: gas,
        }
    }

    fn fee_hex(byte: u8) -> String {
        format!("0x{}", hex::encode([byte; 20]))
    }

    fn tracked_row() -> (ValidatorStore, [u8; 48], ProposerConfigApplier) {
        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        let mut cfg = validator_store::ValidatorConfig::new(pk);
        cfg.fee_recipient = Some([0xaau8; 20]);
        cfg.gas_limit = Some(21_000_000);
        cfg.builder_proposals = false;
        cfg.graffiti = Some([0x47u8; 32]);
        store.add_validator(cfg).unwrap();
        (store, pk, ProposerConfigApplier::new())
    }

    fn assert_url_values(store: &ValidatorStore, pk: &[u8; 48]) {
        assert_eq!(store.effective_fee_recipient(pk), [0xbbu8; 20]);
        assert_eq!(store.effective_gas_limit(pk), 36_000_000);
        assert!(store.is_builder_enabled(pk));
    }

    fn assert_baseline(store: &ValidatorStore, pk: &[u8; 48]) {
        assert_eq!(store.effective_fee_recipient(pk), [0xaau8; 20]);
        assert_eq!(store.effective_gas_limit(pk), 21_000_000);
        assert!(!store.is_builder_enabled(pk));
        assert_eq!(store.get_config(pk).expect("row").graffiti, Some([0x47u8; 32]));
        assert!(store.get_config(pk).expect("row").enabled);
    }

    #[test]
    fn an_omitted_pubkey_restores_the_pre_url_triple_and_leaves_graffiti() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        assert_url_values(&store, &pk);
        applier.apply(&store, Some(Vec::new()), None);
        assert_baseline(&store, &pk);
    }

    #[test]
    fn a_later_url_value_does_not_replace_the_original_snapshot() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xcc)), Some(false), Some(40_000_000))]),
            None,
        );
        assert_eq!(store.effective_fee_recipient(&pk), [0xccu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 40_000_000);
        assert!(!store.is_builder_enabled(&pk));
        applier.apply(&store, Some(Vec::new()), None);
        assert_baseline(&store, &pk);
    }

    #[test]
    fn a_pubkey_named_again_after_reset_snapshots_the_restored_row() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        applier.apply(&store, Some(Vec::new()), None);
        assert_baseline(&store, &pk);
        store
            .update_config(
                &pk,
                validator_store::ValidatorConfigUpdate {
                    fee_recipient: Some(Some([0xeeu8; 20])),
                    gas_limit: Some(Some(22_000_000)),
                    builder_proposals: Some(true),
                    ..validator_store::ValidatorConfigUpdate::default()
                },
            )
            .unwrap();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xdd)), Some(false), Some(41_000_000))]),
            None,
        );
        applier.apply(&store, Some(Vec::new()), None);
        assert_eq!(store.effective_fee_recipient(&pk), [0xeeu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 22_000_000);
        assert!(store.is_builder_enabled(&pk));
    }

    #[test]
    fn a_malformed_fee_on_a_present_pubkey_does_not_restore_the_snapshot() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some("not-hex"), Some(false), Some(1))]),
            None,
        );
        assert_url_values(&store, &pk);
    }

    #[test]
    fn a_gas_limit_above_i64_max_on_a_tracked_pubkey_does_not_restore() {
        let (store, pk, mut applier) = tracked_row();
        let hex_pk = valid_pubkey_hex();
        applier.apply(
            &store,
            Some(vec![row(&hex_pk, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        let huge = (i64::MAX as u64).saturating_add(1);
        applier.apply(&store, Some(vec![row(&hex_pk, None, None, Some(huge))]), None);
        assert_url_values(&store, &pk);
    }

    #[test]
    fn an_unknown_pubkey_is_not_tracked_and_a_later_row_is_not_wiped() {
        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let unknown = [0x99u8; 48];
        let unknown_hex = format!("0x{}", hex::encode(unknown));
        let mut applier = ProposerConfigApplier::new();
        applier.apply(
            &store,
            Some(vec![row(&unknown_hex, Some(&fee_hex(0xbb)), Some(true), Some(36_000_000))]),
            None,
        );
        assert!(!store.has_validator(&unknown));
        let mut cfg = validator_store::ValidatorConfig::new(unknown);
        cfg.fee_recipient = Some([0xddu8; 20]);
        cfg.gas_limit = Some(22_000_000);
        cfg.builder_proposals = true;
        store.add_validator(cfg).unwrap();
        applier.apply(&store, Some(Vec::new()), None);
        assert_eq!(store.effective_fee_recipient(&unknown), [0xddu8; 20]);
        assert_eq!(store.effective_gas_limit(&unknown), 22_000_000);
        assert!(store.is_builder_enabled(&unknown));
    }

    #[test]
    fn a_cleared_fee_and_gas_inherit_the_default_current_at_restore() {
        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let pk = [0x11u8; 48];
        store.add_validator(validator_store::ValidatorConfig::new(pk)).unwrap();
        let mut applier = ProposerConfigApplier::new();
        let default_fee = fee_hex(0xcc);
        applier.apply(
            &store,
            Some(vec![row(
                &valid_pubkey_hex(),
                Some(&fee_hex(0xbb)),
                Some(true),
                Some(36_000_000),
            )]),
            Some(row("default", Some(&default_fee), None, Some(40_000_000))),
        );
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
        // Repeat `default_config` so the restored row inherits the remote
        // default. A document that omits it restores the local defaults.
        applier.apply(
            &store,
            Some(Vec::new()),
            Some(row("default", Some(&default_fee), None, Some(40_000_000))),
        );
        assert_eq!(store.get_config(&pk).expect("row").fee_recipient, None);
        assert_eq!(store.get_config(&pk).expect("row").gas_limit, None);
        assert!(!store.is_builder_enabled(&pk));
        assert_eq!(store.effective_fee_recipient(&pk), [0xccu8; 20]);
        assert_eq!(store.effective_gas_limit(&pk), 40_000_000);
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
    }

    #[test]
    fn an_uppercase_pubkey_is_the_same_tracked_key() {
        let (store, pk, mut applier) = tracked_row();
        applier.apply(
            &store,
            Some(vec![row(
                &valid_pubkey_hex(),
                Some(&fee_hex(0xbb)),
                Some(true),
                Some(36_000_000),
            )]),
            None,
        );
        let upper = format!("0x{}", hex::encode(pk).to_uppercase());
        applier.apply(
            &store,
            Some(vec![row(&upper, Some(&fee_hex(0xcc)), Some(true), Some(36_000_000))]),
            None,
        );
        assert_eq!(store.effective_fee_recipient(&pk), [0xccu8; 20]);
        assert!(store.is_builder_enabled(&pk));
        applier.apply(&store, Some(Vec::new()), None);
        assert_baseline(&store, &pk);
    }

    #[test]
    fn omitting_one_pubkey_leaves_the_other_url_row_in_place() {
        let (store, pk, mut applier) = tracked_row();
        let other = [0x22u8; 48];
        let mut other_cfg = validator_store::ValidatorConfig::new(other);
        other_cfg.fee_recipient = Some([0x11u8; 20]);
        other_cfg.gas_limit = Some(23_000_000);
        other_cfg.builder_proposals = false;
        store.add_validator(other_cfg).unwrap();
        let other_hex = format!("0x{}", hex::encode(other));
        applier.apply(
            &store,
            Some(vec![
                row(&valid_pubkey_hex(), Some(&fee_hex(0xbb)), Some(true), Some(36_000_000)),
                row(&other_hex, Some(&fee_hex(0xdd)), Some(true), Some(37_000_000)),
            ]),
            None,
        );
        applier.apply(
            &store,
            Some(vec![row(&other_hex, Some(&fee_hex(0xee)), Some(true), Some(38_000_000))]),
            None,
        );
        assert_baseline(&store, &pk);
        assert_eq!(store.effective_fee_recipient(&other), [0xeeu8; 20]);
        assert_eq!(store.effective_gas_limit(&other), 38_000_000);
        assert!(store.is_builder_enabled(&other));
    }

    #[test]
    fn a_malformed_default_rejects_the_whole_fetch() {
        let (store, pk, mut applier) = tracked_row();
        applier.apply(
            &store,
            Some(vec![row(
                &valid_pubkey_hex(),
                Some(&fee_hex(0xbb)),
                Some(true),
                Some(36_000_000),
            )]),
            Some(row("default", Some(&fee_hex(0xcc)), None, Some(40_000_000))),
        );
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
        applier.apply(&store, Some(Vec::new()), Some(row("default", Some("not-hex"), None, None)));
        assert_url_values(&store, &pk);
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
        assert_eq!(store.default_gas_limit(), 40_000_000);
    }

    #[test]
    fn one_bad_entry_does_not_apply_a_sibling_or_restore_an_omission() {
        let (store, pk, mut applier) = tracked_row();
        let other = [0x22u8; 48];
        let mut other_cfg = validator_store::ValidatorConfig::new(other);
        other_cfg.fee_recipient = Some([0x11u8; 20]);
        other_cfg.gas_limit = Some(23_000_000);
        other_cfg.builder_proposals = false;
        store.add_validator(other_cfg).unwrap();
        let other_hex = format!("0x{}", hex::encode(other));
        applier.apply(
            &store,
            Some(vec![
                row(&valid_pubkey_hex(), Some(&fee_hex(0xbb)), Some(true), Some(36_000_000)),
                row(&other_hex, Some(&fee_hex(0xdd)), Some(true), Some(37_000_000)),
            ]),
            None,
        );
        applier.apply(
            &store,
            Some(vec![
                row(&valid_pubkey_hex(), Some("not-hex"), Some(false), Some(1)),
                row(&other_hex, Some(&fee_hex(0xee)), Some(false), Some(38_000_000)),
            ]),
            None,
        );
        assert_url_values(&store, &pk);
        assert_eq!(store.effective_fee_recipient(&other), [0xddu8; 20]);
        assert_eq!(store.effective_gas_limit(&other), 37_000_000);
        assert!(store.is_builder_enabled(&other));
    }

    #[test]
    fn a_body_with_neither_proposer_key_deserializes_and_is_not_a_document() {
        let body: ProposerConfigResponse =
            serde_json::from_str(r#"{"status":"ok"}"#).expect("unrelated JSON still parses");
        assert!(body.proposer_config.is_none());
        assert!(body.default_config.is_none());
    }

    #[test]
    fn a_document_with_only_default_config_parses() {
        let fee = valid_fee_recipient_hex();
        let body: ProposerConfigResponse =
            serde_json::from_str(&format!(r#"{{"default_config":{{"fee_recipient":"{fee}"}}}}"#))
                .expect("teku default-only document");
        assert!(body.proposer_config.is_none());
        assert!(body.default_config.is_some());
    }

    #[tokio::test]
    async fn fetch_rejects_a_body_with_neither_key_and_accepts_default_only() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let neither = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"status":"ok"}"#))
            .mount(&neither)
            .await;
        let err = fetch_proposer_config(&neither.uri(), None, true).await.expect_err("neither");
        assert!(err.contains("neither"), "{err}");

        let malformed = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"proposer_config":[]}"#))
            .mount(&malformed)
            .await;
        let err = fetch_proposer_config(&malformed.uri(), None, true).await.expect_err("malformed");
        assert!(err.contains("parse") || err.contains("proposer"), "{err}");

        let only_default = MockServer::start().await;
        let fee = valid_fee_recipient_hex();
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200).set_body_string(format!(
                    r#"{{"default_config":{{"fee_recipient":"{fee}"}}}}"#
                )),
            )
            .mount(&only_default)
            .await;
        let fetched =
            fetch_proposer_config(&only_default.uri(), None, true).await.expect("default");
        assert!(fetched.updates.is_none());
        assert_eq!(
            fetched.default_update.expect("default").fee_recipient.as_deref(),
            Some(fee.as_str())
        );
    }

    #[test]
    fn apply_without_a_document_does_not_release_defaults() {
        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        store
            .apply_remote_defaults(validator_store::DefaultUpdate {
                fee_recipient: Some([0xbbu8; 20]),
                gas_limit: Some(40_000_000),
                ..validator_store::DefaultUpdate::default()
            })
            .unwrap();
        ProposerConfigApplier::new().apply(&store, None, None);
        assert_eq!(store.default_fee_recipient(), [0xbbu8; 20]);
        assert_eq!(store.default_gas_limit(), 40_000_000);
    }

    /// A rejected default update does not release fields the URL still owns.
    #[test]
    fn a_rejected_default_update_does_not_release_owned_defaults() {
        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let graffiti = [0x11u8; 32];
        store
            .apply_remote_defaults(validator_store::DefaultUpdate {
                graffiti: Some(Some(graffiti)),
                ..validator_store::DefaultUpdate::default()
            })
            .unwrap();
        let huge = (i64::MAX as u64).saturating_add(1);
        publish_remote_defaults(
            &store,
            Some(validator_store::DefaultUpdate {
                gas_limit: Some(huge),
                ..validator_store::DefaultUpdate::default()
            }),
        );
        assert_eq!(store.effective_graffiti(&[0u8; 48]), Some(graffiti));
        assert_eq!(store.default_gas_limit(), 30_000_000);
    }

    /// A default-only document that fails validation is not a release.
    #[test]
    fn a_rejected_default_only_document_does_not_release_owned_defaults() {
        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        let graffiti = [0x11u8; 32];
        store
            .apply_remote_defaults(validator_store::DefaultUpdate {
                graffiti: Some(Some(graffiti)),
                ..validator_store::DefaultUpdate::default()
            })
            .unwrap();
        let huge = (i64::MAX as u64).saturating_add(1);
        ProposerConfigApplier::new().apply(
            &store,
            None,
            Some(row("default", None, None, Some(huge))),
        );
        assert_eq!(store.effective_graffiti(&[0u8; 48]), Some(graffiti));
    }

    #[test]
    fn a_default_only_fetch_does_not_restore_a_tracked_pubkey() {
        let (store, pk, mut applier) = tracked_row();
        applier.apply(
            &store,
            Some(vec![row(
                &valid_pubkey_hex(),
                Some(&fee_hex(0xbb)),
                Some(true),
                Some(36_000_000),
            )]),
            None,
        );
        applier.apply(
            &store,
            None,
            Some(row("default", Some(&fee_hex(0xcc)), None, Some(40_000_000))),
        );
        assert_url_values(&store, &pk);
        assert_eq!(store.default_fee_recipient(), [0xccu8; 20]);
        assert_eq!(store.default_gas_limit(), 40_000_000);
    }

    fn empty_fetched() -> FetchedProposerConfig {
        FetchedProposerConfig { updates: Some(Vec::new()), default_update: None }
    }

    fn fee_hex_repeated(byte: &str) -> String {
        format!("0x{}", byte.repeat(20))
    }

    fn pubkey_hex_repeated(byte: &str, prefix: &str) -> String {
        format!("{prefix}{}", byte.repeat(48))
    }

    /// Injected fetch never completes. Virtual time must still observe shutdown.
    #[tokio::test(start_paused = true)]
    async fn refresh_shutdown_cancels_an_in_flight_fetch() {
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let started_fetch = std::sync::Arc::clone(&started);
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            start_proposer_config_refresh_with(
                ProposerConfigUrlSettings {
                    url: "http://127.0.0.1/config".to_string(),
                    refresh_interval: Duration::from_secs(32),
                    token: None,
                    insecure: true,
                },
                shutdown_task,
                production_meters(),
                move || {
                    started_fetch.notify_one();
                    std::future::pending::<Result<FetchedProposerConfig, String>>()
                },
                |_| {},
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .expect("fetch should start");
        shutdown.cancel();

        let joined = tokio::time::timeout(Duration::from_secs(60), handle).await;
        assert!(
            joined.is_ok(),
            "shutdown must cancel an in-flight fetch within 60s of virtual time"
        );
        joined.expect("join").expect("refresh task");
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_shutdown_between_refreshes_does_not_fetch_again() {
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fetches_task = std::sync::Arc::clone(&fetches);
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let started_task = std::sync::Arc::clone(&started);
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            start_proposer_config_refresh_with(
                ProposerConfigUrlSettings {
                    url: "http://127.0.0.1/config".to_string(),
                    refresh_interval: Duration::from_secs(32),
                    token: None,
                    insecure: true,
                },
                shutdown_task,
                production_meters(),
                move || {
                    fetches_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    started_task.notify_one();
                    async { Ok(empty_fetched()) }
                },
                |_| {},
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .expect("initial fetch");
        tokio::time::sleep(Duration::from_millis(1)).await;
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(60), handle)
            .await
            .expect("shutdown between ticks")
            .expect("refresh task");
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_shutdown_cancels_during_the_body() {
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let body_sent = Arc::new(tokio::sync::Notify::new());
        let body_sent_srv = Arc::clone(&body_sent);
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
                .await
                .expect("partial body");
            body_sent_srv.notify_one();
            let _ = sock.read(&mut buf).await;
        });

        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            start_proposer_config_refresh(
                ProposerConfigUrlSettings {
                    url: format!("http://{addr}/config"),
                    refresh_interval: Duration::from_secs(3600),
                    token: None,
                    insecure: true,
                },
                shutdown_task,
                |_| {},
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(5), body_sent.notified())
            .await
            .expect("server sent a chunk and stalled");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("shutdown during the body")
            .expect("refresh task");
    }

    /// Connect 1s, body idle 2s, request 6s.
    ///
    /// Paused time can advance by about the connect timeout while a real
    /// handshake is still queued, so the request deadline has to outlast
    /// that plus a header delay that is itself longer than the body idle
    /// timeout. The three values stay distinct: dropping one moves the
    /// failure onto a different deadline.
    fn isolated_limits() -> FetchLimits {
        FetchLimits {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(6),
            body_idle_timeout: Duration::from_secs(2),
        }
    }

    fn isolated_client(limits: FetchLimits) -> reqwest::Client {
        proposer_config_client_builder(true, limits).no_proxy().build().expect("client")
    }

    fn private_meters() -> RefreshMeters {
        RefreshMeters {
            success: metrics::IntCounter::with_opts(metrics::Opts::new(
                "test_proposer_config_refresh_success",
                "per-test proposer config refresh successes",
            ))
            .expect("success counter"),
            failure: metrics::IntCounter::with_opts(metrics::Opts::new(
                "test_proposer_config_refresh_failure",
                "per-test proposer config refresh failures",
            ))
            .expect("failure counter"),
            cancel_apply_join: false,
        }
    }

    fn install_test_rustls_provider() {
        use std::sync::OnceLock;
        static INSTALLED: OnceLock<()> = OnceLock::new();
        INSTALLED.get_or_init(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Connector that signals entry and then never completes.
    ///
    /// `connect_timeout` is the outermost layer, so this hang ends at the
    /// connect budget. Removing that timeout lets the request deadline win.
    #[derive(Clone)]
    struct HangConnect {
        started: std::sync::Arc<tokio::sync::Notify>,
    }

    #[derive(Clone)]
    struct Hang<S> {
        inner: S,
        started: std::sync::Arc<tokio::sync::Notify>,
    }

    impl<S> tower::Layer<S> for HangConnect {
        type Service = Hang<S>;

        fn layer(&self, inner: S) -> Self::Service {
            Hang { inner, started: std::sync::Arc::clone(&self.started) }
        }
    }

    impl<S, R> tower::Service<R> for Hang<S>
    where
        S: tower::Service<R> + Clone + Send + Sync + 'static,
        S::Future: Send + 'static,
        S::Error: Send + Sync + 'static,
        R: Send + 'static,
    {
        type Response = S::Response;
        type Error = S::Error;
        type Future = std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<S::Response, S::Error>> + Send>,
        >;

        fn poll_ready(
            &mut self,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.inner.poll_ready(cx)
        }

        fn call(&mut self, _req: R) -> Self::Future {
            self.started.notify_one();
            Box::pin(std::future::pending())
        }
    }

    /// Injected connect that never finishes. Proxies are off. Elapsed time is
    /// the 1s connect budget, under the 2s body-idle timeout and the 6s
    /// request deadline.
    #[tokio::test(start_paused = true)]
    async fn fetch_connect_timeout_bounds_a_hung_connector() {
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let limits = isolated_limits();
        let client = proposer_config_client_builder(true, limits)
            .no_proxy()
            .connector_layer(HangConnect { started: std::sync::Arc::clone(&started) })
            .build()
            .expect("client");
        let start = tokio::time::Instant::now();
        let fetch = tokio::spawn(async move {
            fetch_proposer_config_with_client(
                &client,
                "http://127.0.0.1:9/config",
                None,
                true,
                limits.body_idle_timeout,
                &production_meters(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), started.notified())
            .await
            .expect("connector was entered");
        let err = fetch.await.expect("join").expect_err("hung connect");
        let elapsed = start.elapsed();
        assert!(err.starts_with("timed out"), "{err}");
        assert!(
            elapsed >= limits.connect_timeout && elapsed < limits.body_idle_timeout,
            "connect timeout is 1s; removing it lets the request deadline win. elapsed {elapsed:?} err {err}"
        );
    }

    /// Headers after the connect budget and after the body-idle budget, but
    /// inside the request deadline, must succeed. A client-level read timeout
    /// of 10s-from-send (or of the idle budget) would fail this.
    #[tokio::test(start_paused = true)]
    async fn fetch_headers_after_connect_budget_and_before_request_deadline_succeed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let limits = isolated_limits();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accepted = std::sync::Arc::new(tokio::sync::Notify::new());
        let got_request = std::sync::Arc::new(tokio::sync::Notify::new());
        let accepted_srv = std::sync::Arc::clone(&accepted);
        let got_request_srv = std::sync::Arc::clone(&got_request);
        let header_delay = limits.body_idle_timeout + limits.connect_timeout;
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            accepted_srv.notify_one();
            let mut buf = vec![0u8; 2048];
            let mut seen = 0usize;
            loop {
                let n = sock.read(&mut buf[seen..]).await.expect("read");
                if n == 0 {
                    return;
                }
                seen += n;
                if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            got_request_srv.notify_one();
            tokio::time::sleep(header_delay).await;
            let pubkey = pubkey_hex_repeated("ab", "0x");
            let fee = fee_hex_repeated("cd");
            let json =
                format!(r#"{{"proposer_config":{{"{pubkey}":{{"fee_recipient":"{fee}"}}}}}}"#);
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                json.len()
            );
            sock.write_all(head.as_bytes()).await.expect("headers");
            sock.write_all(json.as_bytes()).await.expect("body");
        });

        let client = isolated_client(limits);
        let start = tokio::time::Instant::now();
        let fetch = tokio::spawn(async move {
            fetch_proposer_config_with_client(
                &client,
                &format!("http://{addr}/config"),
                None,
                true,
                limits.body_idle_timeout,
                &production_meters(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), accepted.notified())
            .await
            .expect("server accepted the connection");
        tokio::time::timeout(Duration::from_secs(5), got_request.notified())
            .await
            .expect("server received the request");
        let fetched = fetch.await.expect("join").unwrap_or_else(|err| {
            panic!("headers inside the request deadline after {:?}: {err}", start.elapsed())
        });
        let elapsed = start.elapsed();
        assert_eq!(fetched.updates.expect("proposer_config").len(), 1);
        assert!(
            elapsed > limits.body_idle_timeout && elapsed < limits.request_timeout,
            "headers after the body-idle budget must still beat the request deadline; elapsed {elapsed:?}"
        );
    }

    /// A header wait past the request deadline fails with `timed out`, at the
    /// request deadline, after the server has accepted and read the request.
    #[tokio::test(start_paused = true)]
    async fn fetch_headers_past_the_request_deadline_time_out() {
        use tokio::io::AsyncReadExt;

        let limits = isolated_limits();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accepted = std::sync::Arc::new(tokio::sync::Notify::new());
        let got_request = std::sync::Arc::new(tokio::sync::Notify::new());
        let accepted_srv = std::sync::Arc::clone(&accepted);
        let got_request_srv = std::sync::Arc::clone(&got_request);
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            accepted_srv.notify_one();
            let mut buf = vec![0u8; 2048];
            let mut seen = 0usize;
            loop {
                let n = sock.read(&mut buf[seen..]).await.expect("read");
                if n == 0 {
                    return;
                }
                seen += n;
                if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            got_request_srv.notify_one();
            tokio::time::sleep(limits.request_timeout + Duration::from_millis(500)).await;
        });

        let client = isolated_client(limits);
        let start = tokio::time::Instant::now();
        let fetch = tokio::spawn(async move {
            fetch_proposer_config_with_client(
                &client,
                &format!("http://{addr}/config"),
                None,
                true,
                limits.body_idle_timeout,
                &production_meters(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), accepted.notified())
            .await
            .expect("server accepted the connection");
        tokio::time::timeout(Duration::from_secs(5), got_request.notified())
            .await
            .expect("server received the request");
        let err = fetch.await.expect("join").expect_err("headers past the deadline");
        let elapsed = start.elapsed();
        assert!(err.starts_with("timed out"), "{err}");
        assert!(
            elapsed >= limits.request_timeout && elapsed < limits.request_timeout + Duration::from_secs(1),
            "removing the request deadline lets the 3.5s sleep finish and the fetch succeed; elapsed {elapsed:?} err {err}"
        );
    }

    /// A stall between body chunks fails at the idle timeout, after headers
    /// and the first chunk, and before the request deadline.
    #[tokio::test(start_paused = true)]
    async fn fetch_body_idle_timeout_bounds_a_stall_between_chunks() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let limits = isolated_limits();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let accepted = std::sync::Arc::new(tokio::sync::Notify::new());
        let got_request = std::sync::Arc::new(tokio::sync::Notify::new());
        let accepted_srv = std::sync::Arc::clone(&accepted);
        let got_request_srv = std::sync::Arc::clone(&got_request);
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            accepted_srv.notify_one();
            let mut buf = vec![0u8; 2048];
            let mut seen = 0usize;
            loop {
                let n = sock.read(&mut buf[seen..]).await.expect("read");
                if n == 0 {
                    return;
                }
                seen += n;
                if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            got_request_srv.notify_one();
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
                .await
                .expect("first chunk");
            tokio::time::sleep(limits.request_timeout + Duration::from_secs(1)).await;
        });

        let client = isolated_client(limits);
        let start = tokio::time::Instant::now();
        let fetch = tokio::spawn(async move {
            fetch_proposer_config_with_client(
                &client,
                &format!("http://{addr}/config"),
                None,
                true,
                limits.body_idle_timeout,
                &production_meters(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), accepted.notified())
            .await
            .expect("server accepted the connection");
        tokio::time::timeout(Duration::from_secs(5), got_request.notified())
            .await
            .expect("server received the request");
        let err = fetch.await.expect("join").expect_err("stalled body");
        let elapsed = start.elapsed();
        assert!(err.starts_with("timed out"), "{err}");
        assert!(
            elapsed >= limits.body_idle_timeout
                && elapsed + limits.connect_timeout < limits.request_timeout,
            "removing the body idle timeout lets the request deadline win; elapsed {elapsed:?} err {err}"
        );
    }

    /// Gaps between chunks each stay under the idle timeout, and their sum does not.
    /// A single idle deadline from the first chunk would fail this fetch.
    #[tokio::test(start_paused = true)]
    async fn fetch_body_idle_timeout_rearms_on_each_chunk() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Idle is 2s. Two 1.5s gaps sum past that idle budget and stay inside
        // the request deadline. Paused time can also burn about one connect
        // timeout before the body starts, so the request deadline is loose.
        let limits = FetchLimits {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(30),
            body_idle_timeout: Duration::from_secs(2),
        };
        let body = br#"{"proposer_config":{}}"#;
        let parts: [&[u8]; 3] = [&body[..8], &body[8..18], &body[18..]];
        let gap = Duration::from_millis(1500);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let got_request = std::sync::Arc::new(tokio::sync::Notify::new());
        let got_request_srv = std::sync::Arc::clone(&got_request);
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 2048];
            let mut seen = 0usize;
            loop {
                let n = sock.read(&mut buf[seen..]).await.expect("read");
                if n == 0 {
                    return;
                }
                seen += n;
                if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            got_request_srv.notify_one();
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .expect("headers");
            for (i, part) in parts.iter().enumerate() {
                if i > 0 {
                    tokio::time::sleep(gap).await;
                }
                let chunk = format!("{:x}\r\n", part.len());
                sock.write_all(chunk.as_bytes()).await.expect("chunk size");
                sock.write_all(part).await.expect("chunk");
                sock.write_all(b"\r\n").await.expect("chunk end");
            }
            sock.write_all(b"0\r\n\r\n").await.expect("end");
        });

        let client = isolated_client(limits);
        let start = tokio::time::Instant::now();
        let fetch = tokio::spawn(async move {
            fetch_proposer_config_with_client(
                &client,
                &format!("http://{addr}/config"),
                None,
                true,
                limits.body_idle_timeout,
                &production_meters(),
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(5), got_request.notified())
            .await
            .expect("server received the request");
        let fetched = fetch.await.expect("join").expect("idle timer re-armed");
        let elapsed = start.elapsed();
        assert!(fetched.updates.as_ref().is_some_and(|rows| rows.is_empty()));
        assert!(
            elapsed >= gap + gap && elapsed < limits.request_timeout,
            "two gaps must elapse inside the request deadline; elapsed {elapsed:?}"
        );
    }

    /// `/v1` → `/v2` on the same server is same-origin (scheme, host, and port).
    #[tokio::test]
    async fn fetch_follows_a_same_origin_redirect_and_rejects_a_redirect_loop() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let pubkey = pubkey_hex_repeated("ab", "0x");
        let fee = fee_hex_repeated("cd");
        let body = format!(r#"{{"proposer_config":{{"{pubkey}":{{"fee_recipient":"{fee}"}}}}}}"#);
        Mock::given(method("GET"))
            .and(path("/v2"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/v1"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/v2", server.uri())),
            )
            .expect(1)
            .mount(&server)
            .await;
        let fetched = fetch_proposer_config(&format!("{}/v1", server.uri()), None, true)
            .await
            .expect("one redirect");
        assert_eq!(fetched.updates.expect("proposer_config").len(), 1);

        let looping = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/again", looping.uri())),
            )
            .mount(&looping)
            .await;
        let err = fetch_proposer_config(&looping.uri(), None, true).await.expect_err("loop");
        assert!(err.to_lowercase().contains("redirect"), "{err}");
    }

    #[tokio::test]
    async fn fetch_rejects_a_pubkey_named_twice_in_different_spellings() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let fee = fee_hex_repeated("cd");
        let lower = pubkey_hex_repeated("ab", "0x");
        let upper = pubkey_hex_repeated("AB", "0x");
        let bare = pubkey_hex_repeated("ab", "");
        let entry = format!(r#"{{"fee_recipient":"{fee}"}}"#);

        let server = MockServer::start().await;
        let case_body = format!(r#"{{"proposer_config":{{"{lower}":{entry},"{upper}":{entry}}}}}"#);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(case_body))
            .mount(&server)
            .await;
        let err = fetch_proposer_config(&server.uri(), None, true)
            .await
            .expect_err("case spellings of one pubkey");
        let shown_lower = bounded_remote_key(&lower);
        let shown_upper = bounded_remote_key(&upper);
        assert!(
            err.contains("duplicate pubkey")
                && (err.contains(&shown_lower) || err.contains(&shown_upper)),
            "different spellings must name the truncated key, got {err}"
        );
        assert!(
            !err.contains(&lower) && !err.contains(&upper),
            "full key must not be in the error: {err}"
        );

        let server = MockServer::start().await;
        let prefix_body =
            format!(r#"{{"proposer_config":{{"{lower}":{entry},"{bare}":{entry}}}}}"#);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(prefix_body))
            .mount(&server)
            .await;
        let err = fetch_proposer_config(&server.uri(), None, true)
            .await
            .expect_err("prefix spelling of one pubkey");
        let shown_bare = bounded_remote_key(&bare);
        let shown_prefixed = bounded_remote_key(&lower);
        assert!(
            err.contains("duplicate pubkey")
                && (err.contains(&shown_bare) || err.contains(&shown_prefixed)),
            "{err}"
        );
        assert!(!err.contains(&bare) && !err.contains(&lower), "{err}");
    }

    #[tokio::test]
    async fn fetch_rejects_an_exact_duplicate_key() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let key = pubkey_hex_repeated("11", "0x");
        let fee = fee_hex_repeated("22");
        let entry = format!(r#"{{"fee_recipient":"{fee}"}}"#);
        let body = format!(r#"{{"proposer_config":{{"{key}":{entry},"{key}":{entry}}}}}"#);

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(1)
            .mount(&server)
            .await;

        let err = fetch_proposer_config(&server.uri(), None, true)
            .await
            .expect_err("exact duplicate key");
        assert!(
            err.contains("duplicate pubkey") && err.contains(&bounded_remote_key(&key)),
            "{err}"
        );
        assert!(!err.contains(&key), "full key must not be in the error: {err}");
    }

    async fn assert_fetch_hits_the_body_cap(
        label: &str,
        serve: impl FnOnce(tokio::net::TcpStream) + Send + 'static,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (sock, _) = listener.accept().await.expect("accept");
            serve(sock);
        });
        let url = format!("http://{addr}/config");
        let result =
            tokio::time::timeout(Duration::from_secs(3), fetch_proposer_config(&url, None, true))
                .await;
        match result {
            Ok(Err(err)) => {
                assert!(err.contains("byte cap"), "{label} must hit the body cap, got {err}");
            }
            Ok(Ok(_)) => panic!("{label}: oversized body was accepted"),
            Err(_) => panic!("{label}: fetch was not rejected before the deadline"),
        }
    }

    #[tokio::test]
    async fn fetch_rejects_a_body_over_the_size_cap() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        const OVER: usize = 4 * 1024 * 1024 + 1;

        assert_fetch_hits_the_body_cap("content-length", |sock| {
            tokio::spawn(async move {
                let mut sock = sock;
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {OVER}\r\nConnection: close\r\n\r\n"
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.read(&mut buf).await;
            });
        })
        .await;

        assert_fetch_hits_the_body_cap("chunked", |sock| {
            tokio::spawn(async move {
                let mut sock = sock;
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: application/json\r\n\r\n",
                    )
                    .await;
                let chunk = vec![b'x'; 64 * 1024];
                let mut sent = 0usize;
                while sent <= OVER {
                    let header = format!("{:x}\r\n", chunk.len());
                    if sock.write_all(header.as_bytes()).await.is_err() {
                        return;
                    }
                    if sock.write_all(&chunk).await.is_err() {
                        return;
                    }
                    if sock.write_all(b"\r\n").await.is_err() {
                        return;
                    }
                    sent += chunk.len();
                }
                let _ = sock.write_all(b"0\r\n\r\n").await;
            });
        })
        .await;
    }

    /// A blocking `apply_fn` must not stall the current-thread worker.
    #[test]
    fn refresh_apply_runs_off_the_async_worker() {
        use std::sync::{Arc, Condvar, Mutex};
        use std::time::Duration as StdDuration;

        let entered = Arc::new(tokio::sync::Notify::new());
        let progress = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let shutdown = CancellationToken::new();

        let entered_rt = Arc::clone(&entered);
        let progress_rt = Arc::clone(&progress);
        let release_rt = Arc::clone(&release);
        let shutdown_rt = shutdown.clone();

        let runtime = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let apply_entered = Arc::clone(&entered_rt);
                let apply_release = Arc::clone(&release_rt);
                let sibling_progress = Arc::clone(&progress_rt);
                let sibling_watch = Arc::clone(&entered_rt);
                let shutdown_refresh = shutdown_rt.clone();
                let _ = tokio::time::timeout(Duration::from_secs(8), async move {
                    tokio::spawn(async move {
                        start_proposer_config_refresh_with(
                            ProposerConfigUrlSettings {
                                url: "http://127.0.0.1/config".to_string(),
                                refresh_interval: Duration::from_secs(3600),
                                token: None,
                                insecure: true,
                            },
                            shutdown_refresh,
                            production_meters(),
                            || async { Ok(empty_fetched()) },
                            move |_fetched| {
                                apply_entered.notify_one();
                                let (lock, cvar) = &*apply_release;
                                let mut released = lock.lock().unwrap_or_else(|p| p.into_inner());
                                while !*released {
                                    released =
                                        cvar.wait(released).unwrap_or_else(|p| p.into_inner());
                                }
                            },
                        )
                        .await;
                    });
                    tokio::spawn(async move {
                        if tokio::time::timeout(Duration::from_secs(5), sibling_watch.notified())
                            .await
                            .is_ok()
                        {
                            let (lock, cvar) = &*sibling_progress;
                            *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
                            cvar.notify_one();
                        }
                    });
                    shutdown_rt.cancelled().await;
                })
                .await;
            });
        });

        let (lock, cvar) = &*progress;
        let guard = lock.lock().unwrap_or_else(|p| p.into_inner());
        let (guard, wait) = cvar
            .wait_timeout_while(guard, StdDuration::from_secs(5), |ran| !*ran)
            .unwrap_or_else(|p| p.into_inner());
        let sibling_ran = *guard;
        drop(guard);
        {
            let (lock, cvar) = &*release;
            *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
            cvar.notify_all();
        }
        shutdown.cancel();
        runtime.join().expect("runtime thread");
        assert!(
            sibling_ran && !wait.timed_out(),
            "sibling made no progress while apply_fn blocked"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn refresh_shutdown_cancels_an_in_flight_refresh_fetch() {
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stage = std::sync::Arc::new(tokio::sync::Notify::new());
        let applied = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fetches_task = std::sync::Arc::clone(&fetches);
        let stage_task = std::sync::Arc::clone(&stage);
        let applied_task = std::sync::Arc::clone(&applied);
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            start_proposer_config_refresh_with(
                ProposerConfigUrlSettings {
                    url: "http://127.0.0.1/config".to_string(),
                    refresh_interval: Duration::from_secs(32),
                    token: None,
                    insecure: true,
                },
                shutdown_task,
                production_meters(),
                move || {
                    let n = fetches_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    stage_task.notify_one();
                    async move {
                        if n == 0 {
                            Ok(empty_fetched())
                        } else {
                            std::future::pending().await
                        }
                    }
                },
                move |_| {
                    applied_task.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                },
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(5), stage.notified())
            .await
            .expect("initial fetch");
        tokio::time::sleep(Duration::from_secs(32)).await;
        tokio::time::timeout(Duration::from_secs(5), stage.notified())
            .await
            .expect("refresh fetch started");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(60), handle)
            .await
            .expect("shutdown during the refresh fetch")
            .expect("refresh task");
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert_eq!(applied.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn refresh_shutdown_before_apply_is_not_a_success() {
        let applied = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let applied_task = std::sync::Arc::clone(&applied);
        let shutdown = CancellationToken::new();
        let shutdown_fetch = shutdown.clone();
        let meters = private_meters();
        let handle = tokio::spawn({
            let meters = meters.clone();
            async move {
                start_proposer_config_refresh_with(
                    ProposerConfigUrlSettings {
                        url: "http://127.0.0.1/config".to_string(),
                        refresh_interval: Duration::from_secs(3600),
                        token: None,
                        insecure: true,
                    },
                    shutdown_fetch.clone(),
                    meters,
                    move || {
                        let shutdown_fetch = shutdown_fetch.clone();
                        async move {
                            shutdown_fetch.cancel();
                            Ok(empty_fetched())
                        }
                    },
                    move |_| {
                        applied_task.store(true, std::sync::atomic::Ordering::SeqCst);
                    },
                )
                .await;
            }
        });
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("task ends")
            .expect("join");
        assert!(!applied.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(meters.success.get(), 0);
        assert_eq!(meters.failure.get(), 0);
    }

    #[test]
    fn refresh_shutdown_waits_for_an_apply_already_started() {
        use std::sync::{Arc, Condvar, Mutex};
        use std::time::Duration as StdDuration;

        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let shutdown = CancellationToken::new();
        let meters = private_meters();

        let entered_rt = Arc::clone(&entered);
        let release_rt = Arc::clone(&release);
        let finished_rt = Arc::clone(&finished);
        let shutdown_rt = shutdown.clone();
        let meters_rt = meters.clone();
        let runtime = std::thread::spawn(move || {
            let rt =
                tokio::runtime::Builder::new_current_thread().enable_all().build().expect("rt");
            rt.block_on(async move {
                let apply_entered = Arc::clone(&entered_rt);
                let apply_release = Arc::clone(&release_rt);
                start_proposer_config_refresh_with(
                    ProposerConfigUrlSettings {
                        url: "http://127.0.0.1/config".to_string(),
                        refresh_interval: Duration::from_secs(3600),
                        token: None,
                        insecure: true,
                    },
                    shutdown_rt.clone(),
                    meters_rt,
                    || async { Ok(empty_fetched()) },
                    move |_| {
                        apply_entered.notify_one();
                        let (lock, cvar) = &*apply_release;
                        let mut released = lock.lock().unwrap_or_else(|p| p.into_inner());
                        while !*released {
                            released = cvar.wait(released).unwrap_or_else(|p| p.into_inner());
                        }
                    },
                )
                .await;
                finished_rt.store(true, std::sync::atomic::Ordering::SeqCst);
                shutdown_rt.cancel();
            });
        });

        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("wait");
        rt.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), entered.notified())
                .await
                .expect("apply started");
        });
        shutdown.cancel();
        std::thread::sleep(StdDuration::from_millis(50));
        assert!(
            !finished.load(std::sync::atomic::Ordering::SeqCst),
            "shutdown must wait for the apply that already started"
        );
        {
            let (lock, cvar) = &*release;
            *lock.lock().unwrap_or_else(|p| p.into_inner()) = true;
            cvar.notify_all();
        }
        let joined = rt.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                tokio::task::spawn_blocking(move || runtime.join()),
            )
            .await
        });
        joined.expect("apply-wait test hung").expect("join thread").expect("runtime");
        assert!(finished.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(meters.success.get(), 1);
        assert_eq!(meters.failure.get(), 0);
    }

    #[test]
    #[tracing_test::traced_test]
    fn client_build_failure_is_an_error_and_a_failure_metric() {
        let meters = private_meters();
        report_client_build_failure("tls init failed", &meters);
        assert_eq!(meters.failure.get(), 1);
        assert_eq!(meters.success.get(), 0);
        assert!(logs_contain("Failed to create proposer config HTTP client"));
        assert!(logs_contain("ERROR"));
    }

    #[tokio::test]
    async fn cancelled_apply_join_counts_as_failure_not_success() {
        let mut meters = private_meters();
        meters.cancel_apply_join = true;
        let meters_task = meters.clone();
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            start_proposer_config_refresh_with(
                ProposerConfigUrlSettings {
                    url: "http://127.0.0.1/config".to_string(),
                    refresh_interval: Duration::from_secs(3600),
                    token: None,
                    insecure: true,
                },
                shutdown_task,
                meters_task,
                || async { Ok(empty_fetched()) },
                |_| panic!("a cancelled apply join must not run apply"),
            )
            .await;
        });
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while meters.failure.get() == 0 {
            if tokio::time::Instant::now() >= deadline {
                panic!("cancelled apply join did not count a failure");
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(meters.failure.get(), 1);
        assert_eq!(meters.success.get(), 0);
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle).await.expect("refresh task").unwrap();
    }

    #[test]
    #[tracing_test::traced_test]
    fn ignored_entry_log_truncates_a_long_key() {
        use validator_store::ValidatorConfig;

        let store = ValidatorStore::new([0x01u8; 20], 30_000_000);
        store.add_validator(ValidatorConfig::new([0x11u8; 48])).unwrap();
        let tail = "TAILMARKER99";
        let pubkey = format!("{}{tail}", "ab".repeat(400));
        ProposerConfigApplier::new().apply(
            &store,
            Some(vec![ValidatorConfigUpdate {
                pubkey: pubkey.clone(),
                fee_recipient: Some("not-hex".to_string()),
                builder_enabled: None,
                gas_limit: None,
            }]),
            None,
        );
        assert!(logs_contain("proposer config entry ignored"));
        assert!(logs_contain(&bounded_remote_key(&pubkey)));
        assert!(!logs_contain(tail), "log must not carry the rest of the key");
    }

    #[tokio::test]
    async fn fetch_error_does_not_include_the_query() {
        let err =
            fetch_proposer_config("http://127.0.0.1:1/config?token=super-secret&x=1", None, true)
                .await
                .expect_err("closed port");
        assert!(!err.contains("super-secret"), "{err}");
        assert!(!err.contains("token="), "{err}");
    }

    #[tokio::test]
    async fn refresh_interval_zero_returns_without_panicking() {
        let meters = private_meters();
        tokio::time::timeout(
            Duration::from_secs(2),
            start_proposer_config_refresh_with(
                ProposerConfigUrlSettings {
                    url: "http://127.0.0.1/config".to_string(),
                    refresh_interval: Duration::ZERO,
                    token: None,
                    insecure: true,
                },
                CancellationToken::new(),
                meters.clone(),
                || async { Ok(empty_fetched()) },
                |_| panic!("zero interval must not fetch"),
            ),
        )
        .await
        .expect("zero interval returns");
        assert_eq!(meters.failure.get(), 1);
        assert_eq!(meters.success.get(), 0);
    }

    #[tokio::test]
    async fn fetch_refuses_https_to_http_on_the_same_explicit_port() {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        install_test_rustls_provider();
        let certified = rcgen::generate_simple_self_signed(vec!["h".to_string()]).expect("cert");
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key = PrivateKeyDer::try_from(certified.key_pair.serialize_der()).expect("key");
        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server config");
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let port = addr.port();
        let location = format!("http://h:{port}/config");
        let acceptor_task = acceptor.clone();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = listener.accept().await.expect("accept");
                let mut tls = acceptor_task.accept(tcp).await.expect("handshake");
                let mut buf = [0u8; 2048];
                let _ = tls.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = tls.write_all(resp.as_bytes()).await;
            }
        });

        for insecure in [false, true] {
            let meters = private_meters();
            let client = proposer_config_client_builder(insecure, production_limits())
                .no_proxy()
                .danger_accept_invalid_certs(true)
                .resolve("h", addr)
                .build()
                .expect("client");
            let err = tokio::time::timeout(
                Duration::from_secs(5),
                fetch_proposer_config_with_client(
                    &client,
                    &format!("https://h:{port}/config"),
                    Some("bearer-secret"),
                    insecure,
                    production_limits().body_idle_timeout,
                    &meters,
                ),
            )
            .await
            .expect("redirect decision")
            .expect_err("https to http");
            let err_l = err.to_lowercase();
            if insecure {
                assert!(
                    err_l.contains("cross-origin"),
                    "insecure https->http must be refused as cross-origin, got {err}"
                );
            } else {
                assert!(
                    err_l.contains("cross-origin") || err_l.contains("scheme is not allowed"),
                    "https://h:{port} -> http://h:{port} must be refused, got {err}"
                );
            }
            assert!(!err.contains("bearer-secret"), "{err}");
            assert_eq!(meters.failure.get(), 1, "cross-origin redirect must count one failure");
            assert_eq!(meters.success.get(), 0);
        }
    }

    #[tokio::test]
    async fn fetch_rejects_a_cross_origin_redirect() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dest = MockServer::start().await;
        let src = MockServer::start().await;
        let pubkey = pubkey_hex_repeated("ab", "0x");
        let fee = fee_hex_repeated("cd");
        let body = format!(r#"{{"proposer_config":{{"{pubkey}":{{"fee_recipient":"{fee}"}}}}}}"#);
        Mock::given(method("GET"))
            .and(path("/config"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .expect(0)
            .mount(&dest)
            .await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("{}/config", dest.uri())),
            )
            .expect(1)
            .mount(&src)
            .await;

        let meters = private_meters();
        let client = proposer_config_client_builder(true, production_limits())
            .no_proxy()
            .build()
            .expect("client");
        let err = fetch_proposer_config_with_client(
            &client,
            &format!("{}/start", src.uri()),
            Some("bearer-secret"),
            true,
            production_limits().body_idle_timeout,
            &meters,
        )
        .await
        .expect_err("cross-origin redirect");
        assert!(err.to_lowercase().contains("cross-origin"), "{err}");
        assert!(!err.contains("bearer-secret"), "{err}");
        assert_eq!(meters.failure.get(), 1);
        assert_eq!(meters.success.get(), 0);

        let src_reqs = src.received_requests().await.expect("src recorded");
        let src_auth = src_reqs[0].headers.get("authorization").expect("token on the first hop");
        assert!(src_auth.to_str().unwrap_or("").contains("bearer-secret"));
        let dest_reqs = dest.received_requests().await.expect("dest recorded");
        assert!(dest_reqs.is_empty(), "cross-origin target must not be fetched: {dest_reqs:?}");
    }

    #[tokio::test]
    async fn fetch_rejects_a_cross_origin_redirect_to_loopback() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let addr = *server.address();
        Mock::given(method("GET"))
            .and(path("/admin"))
            .respond_with(ResponseTemplate::new(200).set_body_string("loopback"))
            .expect(0)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/start"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("Location", format!("http://127.0.0.1:{}/admin", addr.port())),
            )
            .expect(1)
            .mount(&server)
            .await;

        let meters = private_meters();
        let client = proposer_config_client_builder(true, production_limits())
            .no_proxy()
            .resolve("remote.test", addr)
            .build()
            .expect("client");
        let err = fetch_proposer_config_with_client(
            &client,
            &format!("http://remote.test:{}/start", addr.port()),
            Some("bearer-secret"),
            true,
            production_limits().body_idle_timeout,
            &meters,
        )
        .await
        .expect_err("redirect to loopback");
        assert!(err.to_lowercase().contains("cross-origin"), "{err}");
        assert!(!err.contains("bearer-secret"), "{err}");
        assert_eq!(meters.failure.get(), 1);
        assert_eq!(meters.success.get(), 0);
    }

    /// Chunks arrive inside the idle budget. The total deadline still fires, and apply does not run.
    #[tokio::test(start_paused = true)]
    async fn fetch_slow_trickle_hits_the_total_deadline_and_applies_nothing() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Mutex;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let limits = FetchLimits {
            connect_timeout: Duration::from_secs(1),
            request_timeout: Duration::from_secs(8),
            body_idle_timeout: Duration::from_secs(2),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let got_request = std::sync::Arc::new(tokio::sync::Notify::new());
        let got_request_srv = std::sync::Arc::clone(&got_request);
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 2048];
            let mut seen = 0usize;
            loop {
                let n = sock.read(&mut buf[seen..]).await.expect("read");
                if n == 0 {
                    return;
                }
                seen += n;
                if buf[..seen].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            got_request_srv.notify_one();
            sock.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .expect("headers");
            let gap = Duration::from_secs(1);
            loop {
                if sock.write_all(b"1\r\nx\r\n").await.is_err() {
                    return;
                }
                tokio::time::sleep(gap).await;
            }
        });

        let client = isolated_client(limits);
        let url = format!("http://{addr}/config");
        let err_slot = std::sync::Arc::new(Mutex::new(String::new()));
        let failed = std::sync::Arc::new(tokio::sync::Notify::new());
        let applied = std::sync::Arc::new(AtomicBool::new(false));
        let err_fetch = std::sync::Arc::clone(&err_slot);
        let failed_fetch = std::sync::Arc::clone(&failed);
        let applied_fn = std::sync::Arc::clone(&applied);
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let handle = tokio::spawn(async move {
            start_proposer_config_refresh_with(
                ProposerConfigUrlSettings {
                    url: url.clone(),
                    refresh_interval: Duration::from_secs(3600),
                    token: None,
                    insecure: true,
                },
                shutdown_task,
                production_meters(),
                move || {
                    let client = client.clone();
                    let url = url.clone();
                    let err_fetch = std::sync::Arc::clone(&err_fetch);
                    let failed_fetch = std::sync::Arc::clone(&failed_fetch);
                    async move {
                        let result = fetch_proposer_config_with_client(
                            &client,
                            &url,
                            None,
                            true,
                            limits.body_idle_timeout,
                            &production_meters(),
                        )
                        .await;
                        if let Err(err) = &result {
                            *err_fetch.lock().expect("err") = err.clone();
                            failed_fetch.notify_one();
                        }
                        result
                    }
                },
                move |_| {
                    applied_fn.store(true, Ordering::SeqCst);
                },
            )
            .await;
        });

        tokio::time::timeout(Duration::from_secs(5), got_request.notified())
            .await
            .expect("server received the request");
        tokio::time::timeout(Duration::from_secs(30), failed.notified())
            .await
            .expect("total deadline");
        let err = err_slot.lock().expect("err").clone();
        assert_eq!(err, "timed out fetching proposer config", "{err}");
        assert!(!applied.load(Ordering::SeqCst), "a timed-out body must not be applied");
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(5), handle).await.expect("refresh task").unwrap();
    }

    #[tokio::test]
    async fn fetch_rejects_a_repeated_serde_field() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let fee = fee_hex_repeated("cd");
        let pubkey = pubkey_hex_repeated("ab", "0x");
        let body = format!(
            r#"{{"proposer_config":{{"{pubkey}":{{"fee_recipient":"{fee}","fee_recipient":"{fee}"}}}}}}"#
        );
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let err = fetch_proposer_config(&server.uri(), None, true)
            .await
            .expect_err("repeated fee_recipient");
        assert!(err.contains("duplicate field"), "{err}");
        assert!(err.contains("fee_recipient"), "{err}");
    }

    #[tokio::test]
    async fn fetch_truncates_a_huge_serde_error() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let marker = "TAILMARKER99";
        let huge = format!("{}{marker}", "A".repeat(64 * 1024));
        let body = format!(r#"{{"proposer_config":{{"k":{{"builder":{{"enabled":"{huge}"}}}}}}}}"#);
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;
        let err = fetch_proposer_config(&server.uri(), None, true).await.expect_err("type error");
        assert!(err.contains('…'), "{err}");
        assert!(!err.contains(marker), "{err}");
        assert!(err.len() < 80, "{err}");
    }

    #[tokio::test]
    async fn failed_fetch_leaves_the_store_unchanged() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use validator_store::ValidatorConfig;
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let store = Arc::new(ValidatorStore::new([0x01u8; 20], 30_000_000));
        let pk = [0x11u8; 48];
        let mut cfg = ValidatorConfig::new(pk);
        cfg.fee_recipient = Some([0xaau8; 20]);
        store.add_validator(cfg).unwrap();
        let before_fee = store.effective_fee_recipient(&pk);

        let server = MockServer::start().await;
        let body = format!(
            r#"{{"proposer_config":{{"{}":{{"fee_recipient":"{}","fee_recipient":"{}"}}}}}}"#,
            valid_pubkey_hex(),
            valid_fee_recipient_hex(),
            valid_fee_recipient_hex(),
        );
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body))
            .mount(&server)
            .await;

        let applied = Arc::new(AtomicBool::new(false));
        let applied_fn = Arc::clone(&applied);
        let store_task = Arc::clone(&store);
        let shutdown = CancellationToken::new();
        let shutdown_task = shutdown.clone();
        let meters = private_meters();
        let meters_task = meters.clone();
        let client = proposer_config_client_builder(true, production_limits())
            .no_proxy()
            .build()
            .expect("client");
        let url = server.uri();
        let handle = tokio::spawn(async move {
            let fetch_meters = meters_task.clone();
            start_proposer_config_refresh_with(
                ProposerConfigUrlSettings {
                    url: url.clone(),
                    refresh_interval: Duration::from_secs(3600),
                    token: None,
                    insecure: true,
                },
                shutdown_task,
                meters_task,
                move || {
                    let client = client.clone();
                    let url = url.clone();
                    let fetch_meters = fetch_meters.clone();
                    async move {
                        fetch_proposer_config_with_client(
                            &client,
                            &url,
                            None,
                            true,
                            production_limits().body_idle_timeout,
                            &fetch_meters,
                        )
                        .await
                    }
                },
                move |fetched| {
                    applied_fn.store(true, Ordering::SeqCst);
                    ProposerConfigApplier::new().apply(
                        &store_task,
                        fetched.updates,
                        fetched.default_update,
                    );
                },
            )
            .await;
        });

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while meters.failure.get() == 0 {
            if tokio::time::Instant::now() >= deadline {
                panic!("failed fetch did not count a failure");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(meters.failure.get(), 1);
        assert_eq!(meters.success.get(), 0);
        assert!(!applied.load(Ordering::SeqCst));
        assert_eq!(store.effective_fee_recipient(&pk), before_fee);
        shutdown.cancel();
        tokio::time::timeout(Duration::from_secs(2), handle).await.expect("refresh task").unwrap();
    }

    #[test]
    fn bounded_log_text_does_not_split_a_scalar() {
        let raw = format!("{}€TAIL", "a".repeat(15));
        let shown = bounded_log_text(&raw);
        assert!(shown.contains('€'), "{shown}");
        assert!(shown.ends_with('…'), "{shown}");
        assert!(!shown.contains("TAIL"), "{shown}");
    }

    #[tokio::test]
    async fn refresh_interval_above_max_returns_without_panicking() {
        let meters = private_meters();
        let too_long =
            Duration::from_secs(rvc_config::MAX_PROPOSER_CONFIG_REFRESH_INTERVAL_SECS + 1);
        tokio::time::timeout(
            Duration::from_secs(2),
            start_proposer_config_refresh_with(
                ProposerConfigUrlSettings {
                    url: "http://127.0.0.1/config".to_string(),
                    refresh_interval: too_long,
                    token: None,
                    insecure: true,
                },
                CancellationToken::new(),
                meters.clone(),
                || async { Ok(empty_fetched()) },
                |_| panic!("over-max interval must not fetch"),
            ),
        )
        .await
        .expect("over-max interval returns");
        assert_eq!(meters.failure.get(), 1);
        assert_eq!(meters.success.get(), 0);
    }

    #[tokio::test]
    async fn fetch_accepts_a_body_at_the_size_cap_and_rejects_one_extra_byte() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let cap = MAX_PROPOSER_CONFIG_BYTES;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 2048];
            let _ = sock.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {cap}\r\nConnection: close\r\n\r\n"
            );
            sock.write_all(head.as_bytes()).await.expect("head");
            let chunk = vec![b'x'; 64 * 1024];
            let mut sent = 0usize;
            while sent < cap {
                let n = (cap - sent).min(chunk.len());
                sock.write_all(&chunk[..n]).await.expect("body");
                sent += n;
            }
        });
        let err = fetch_proposer_config(&format!("http://{addr}/config"), None, true)
            .await
            .expect_err("cap-sized body is not JSON");
        assert!(!err.contains("byte cap"), "exactly 4 MiB must pass the cap, got {err}");

        let over = cap + 1;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let head =
                format!("HTTP/1.1 200 OK\r\nContent-Length: {over}\r\nConnection: close\r\n\r\n");
            let _ = sock.write_all(head.as_bytes()).await;
        });
        let err = fetch_proposer_config(&format!("http://{addr}/config"), None, true)
            .await
            .expect_err("one byte over the cap");
        assert!(err.contains("byte cap"), "{err}");
    }
}
