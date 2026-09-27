use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use observability::logging::{RedactedUrl, TruncatedPubkey};
use serde::{Deserialize, Serialize};
use tracing::{info, warn, Instrument};

use crate::error::{
    map_delete_keystore_item_error, map_delete_remote_key_item_error,
    map_import_keystore_item_error, map_import_remote_key_item_error, map_slashing_export_error,
    map_slashing_protection_error, map_url_validation_error, ApiError,
};
use crate::lifecycle::{DoppelgangerLifecycle, ImportKind};
use crate::traits::{
    ImportKeystoreError, ImportRemoteKeyError, KeystoreManager, Pubkey, QuiesceError,
    RemoteKeyManager, SlashingProtection, ValidatorConfigManager, ValidatorManager,
    VoluntaryExitManager,
};
use crate::types::{
    DeleteKeystoreResult, DeleteKeystoresRequest, DeleteKeystoresResponse, DeleteRemoteKeyResult,
    DeleteRemoteKeyStatus, DeleteRemoteKeysRequest, DeleteRemoteKeysResponse, DeleteStatus,
    FeeRecipientData, FeeRecipientResponse, GasLimitData, GasLimitResponse, GraffitiData,
    GraffitiResponse, ImportKeystoreResult, ImportKeystoresRequest, ImportKeystoresResponse,
    ImportRemoteKeyResult, ImportRemoteKeyStatus, ImportRemoteKeysRequest,
    ImportRemoteKeysResponse, ImportStatus, KeystoreInfo, ListKeystoresResponse,
    ListRemoteKeysResponse, RemoteKeyEntry, SetFeeRecipientRequest, SetGasLimitRequest,
    SetGraffitiRequest, VoluntaryExitQuery, VoluntaryExitResponse,
};
use crate::url_validator;

pub struct AppState {
    pub keystore_manager: Arc<dyn KeystoreManager>,
    pub slashing_protection: Arc<dyn SlashingProtection>,
    pub validator_manager: Arc<dyn ValidatorManager>,
    /// KM-2 / SF-3 lifecycle: window, cancel tokens, state lock, monitor.
    ///
    /// See [`DoppelgangerLifecycle`] for the lock-ordering invariant. Handlers
    /// must not open-code token displacement or enable-task spawning.
    pub doppelganger: Arc<DoppelgangerLifecycle>,
    pub remote_key_manager: Arc<dyn RemoteKeyManager>,
    pub config_manager: Arc<dyn ValidatorConfigManager>,
    pub exit_manager: Option<Arc<dyn VoluntaryExitManager>>,
    pub allow_insecure_remote_signer: bool,
    pub attesting_enabled: Arc<AtomicBool>,
    /// Last time `set_attesting_enabled` was accepted; used for rate limiting.
    pub last_set_attesting_enabled: Mutex<Option<tokio::time::Instant>>,
    /// ISSUE-4.7 / L-7: per-API-token rate limit on `import_keystores`.
    ///
    /// Each entry maps a 32-byte SHA-256 of the bearer token to the timestamps
    /// of recent `import_keystores` invocations within the rolling
    /// [`IMPORT_KEYSTORES_WINDOW_SECS`] window.  Excess attempts return
    /// HTTP 429 with `Retry-After`, preventing thousands of bogus passwords
    /// from CPU-grinding the host on the keystore decrypt path.
    pub import_keystores_rate:
        Mutex<HashMap<[u8; 32], std::collections::VecDeque<tokio::time::Instant>>>,
}

#[derive(Debug, Deserialize)]
pub struct SetAttestingRequest {
    pub enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct SetAttestingResponse {
    pub enabled: bool,
}

pub async fn list_keystores(State(state): State<Arc<AppState>>) -> Json<ListKeystoresResponse> {
    // Per Keymanager API spec, GET /eth/v1/keystores returns only local keys.
    // Remote keys are returned by GET /eth/v1/remotekeys.
    //
    // SEC-1a: `list_keys` is the full local signing registry (boot-loaded
    // keystore-dir / secret-provider keys and API-imported keys), not only
    // keys imported via this API.
    let local_keys = state.keystore_manager.list_keys();

    let data: Vec<KeystoreInfo> = local_keys
        .into_iter()
        .map(|pk| {
            // M-12: expose whether this key has passed the doppelganger window.
            let doppelganger_safe = state.doppelganger.is_doppelganger_safe(&pk);
            KeystoreInfo {
                validating_pubkey: format!("0x{}", hex::encode(pk)),
                derivation_path: None,
                // All local keys are deletable via DELETE /eth/v1/keystores
                // (including boot-loaded keys after SEC-1a). Remote keys are
                // listed on /remotekeys, not here.
                readonly: false,
                doppelganger_safe,
            }
        })
        .collect();

    info!(count = data.len(), "Listed local keystores");

    Json(ListKeystoresResponse { data })
}

pub async fn import_keystores(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<ImportKeystoresRequest>,
) -> Result<Json<ImportKeystoresResponse>, ApiError> {
    let span = tracing::info_span!(
        "keymanager.import_keystores",
        keymanager.count = request.keystores.len(),
    );
    let _guard = span.enter();

    // ISSUE-4.7 / L-7: per-API-token rate limit on the decrypt path.
    // Refused calls return 429 with Retry-After and never reach the
    // CPU-bound keystore decryption loop.
    check_import_keystores_rate(&state, &headers)?;

    info!(count = request.keystores.len(), "Importing keystores");

    if request.keystores.len() != request.passwords.len() {
        return Err(ApiError::BadRequest(
            "keystores and passwords arrays must have the same length".into(),
        ));
    }

    // Import slashing protection FIRST — before any keystores are activated.
    // This prevents a window where signing keys exist without slashing records.
    if let Some(ref slashing_json) = request.slashing_protection {
        if let Err(e) = state.slashing_protection.import_interchange(slashing_json) {
            return Err(map_slashing_protection_error(e, "slashing protection import failed"));
        }
    }

    let mut results = Vec::with_capacity(request.keystores.len());

    for (keystore_json, password) in request.keystores.iter().zip(request.passwords.iter()) {
        match state.keystore_manager.import_keystore(keystore_json, password) {
            Ok(pubkey) => {
                let pubkey_hex = format!("0x{}", hex::encode(pubkey));
                info!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    status = "imported",
                    "Keystore import result"
                );
                // M-12 + KM-2: register disabled validator, start monitoring,
                // displace any prior enable task, and spawn the window task.
                // Owned by [`DoppelgangerLifecycle`] so local and remote imports
                // share one path (ImportKind::Local).
                state.doppelganger.on_import(pubkey, ImportKind::Local);

                results.push(ImportKeystoreResult {
                    status: ImportStatus::Imported,
                    message: String::new(),
                });
            }
            Err(ImportKeystoreError::Duplicate) => {
                info!(status = "duplicate", "Keystore import result");
                results.push(ImportKeystoreResult {
                    status: ImportStatus::Duplicate,
                    message: "key already exists".into(),
                });
            }
            Err(e) => {
                results.push(ImportKeystoreResult {
                    status: ImportStatus::Error,
                    message: map_import_keystore_item_error(e),
                });
            }
        }
    }

    Ok(Json(ImportKeystoresResponse { data: results }))
}

/// Clears [`KeystoreManager::begin_delete_export`] on every exit, including
/// a drain timeout.
struct DeleteExportGuard {
    keys: Arc<dyn KeystoreManager>,
}

impl Drop for DeleteExportGuard {
    fn drop(&mut self) {
        self.keys.end_delete_export();
    }
}

pub async fn delete_keystores(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeleteKeystoresRequest>,
) -> Result<Json<DeleteKeystoresResponse>, ApiError> {
    let span = tracing::info_span!(
        "keymanager.delete_keystores",
        keymanager.count = request.pubkeys.len(),
    );
    // `Instrument` enters the span per poll. A `Span::enter` guard must not
    // be held across the drain await.
    async move { delete_keystores_inner(state, request).await }.instrument(span).await
}

async fn delete_keystores_inner(
    state: Arc<AppState>,
    request: DeleteKeystoresRequest,
) -> Result<Json<DeleteKeystoresResponse>, ApiError> {
    warn!(count = request.pubkeys.len(), "Deleting keystores");

    // Parse all pubkeys. Membership is decided under the import/delete lock
    // (`membership_for_delete`), not a racy `has_key` snapshot. Only that set
    // is disabled, drained, and exported. A key admitted afterwards must not
    // be removed.
    let parsed: Vec<Result<Pubkey, String>> =
        request.pubkeys.iter().map(|s| parse_pubkey(s)).collect();
    let candidates: Vec<Pubkey> = parsed.iter().filter_map(|r| r.as_ref().ok().copied()).collect();
    let existing_keys = state.keystore_manager.membership_for_delete(&candidates);
    state.keystore_manager.begin_delete_export(&existing_keys);
    let _export_guard = DeleteExportGuard { keys: Arc::clone(&state.keystore_manager) };

    // Disable, then drain, then export, then delete. Disable goes through
    // `ValidatorManager::set_validator_enabled` (the keymanager entry), which
    // also cancels a pending enable task so a failed delete cannot be turned
    // back on. `quiesce` `Ok` means the slashable lock was free and the
    // under-lock gate is closed — not that non-slashable duties are idle. A
    // drain timeout aborts before export: nothing is migrated and nothing is
    // deleted.
    for pubkey in &existing_keys {
        state.doppelganger.disable_for_delete(pubkey);
    }
    let mut timed_out: Vec<Pubkey> = Vec::new();
    for pubkey in &existing_keys {
        match state.doppelganger.quiesce_for_delete(pubkey).await {
            Ok(()) => {}
            Err(err) => match err {
                QuiesceError::DrainTimedOut { .. } => {
                    if !timed_out.contains(pubkey) {
                        timed_out.push(*pubkey);
                    }
                }
            },
        }
    }
    if !timed_out.is_empty() {
        return Err(drain_timed_out(&timed_out));
    }

    // Export slashing protection BEFORE any deletions.
    //
    // KM-1 (ADR-008): the export must be atomic and fail-closed.
    // If export_interchange returns Err, we abort the entire DELETE with
    // HTTP 500 BEFORE touching the keystore.  Swallowing the error and
    // returning an empty interchange (the previous behaviour) would allow
    // re-import without any slashing history, creating a double-sign hazard.
    //
    // Atomicity contract: SlashingProtectionAdapter::export_interchange (in
    // keymanager_adapters.rs) delegates to SlashingDb::export, which
    // collects all rows inside a single read path and returns Err on any
    // per-pubkey failure — no partial interchange is ever emitted.
    let slashing_protection = if existing_keys.is_empty() {
        empty_interchange()
    } else {
        state
            .slashing_protection
            .export_interchange(&existing_keys)
            .map_err(map_slashing_export_error)?
    };

    // Now process deletions
    let mut results = Vec::with_capacity(request.pubkeys.len());
    for (i, parse_result) in parsed.iter().enumerate() {
        let pubkey_hex = &request.pubkeys[i];
        match parse_result {
            Ok(pubkey) => {
                // Admitted after the membership snapshot: not in the export.
                // Do not call `delete_keystore` (it would remove the key).
                // The adapter also refuses if this check loses the race.
                if !existing_keys.contains(pubkey) && state.keystore_manager.has_key(pubkey) {
                    results.push(DeleteKeystoreResult {
                        status: DeleteStatus::Error,
                        message: "key appeared after the slashing-protection export; not deleted"
                            .into(),
                    });
                    continue;
                }
                // KM-2 (b)+(Finding 3): keystore removal + token cancel (+
                // remove_validator / cancel_monitoring on success) are one
                // critical section inside DoppelgangerLifecycle::on_delete.
                let delete_result = state.doppelganger.on_delete(pubkey, ImportKind::Local, || {
                    match state.keystore_manager.delete_keystore(pubkey) {
                        Ok(true) => (true, Ok(true)),
                        Ok(false) => (false, Ok(false)),
                        Err(e) => (false, Err(e)),
                    }
                });

                match delete_result {
                    Ok(true) => {
                        warn!(
                            pubkey = %TruncatedPubkey::new(pubkey_hex),
                            status = "deleted",
                            "Keystore delete result"
                        );
                        results.push(DeleteKeystoreResult {
                            status: DeleteStatus::Deleted,
                            message: String::new(),
                        });
                    }
                    Ok(false) => {
                        warn!(
                            pubkey = %TruncatedPubkey::new(pubkey_hex),
                            status = "not_found",
                            "Keystore delete result"
                        );
                        results.push(DeleteKeystoreResult {
                            status: DeleteStatus::NotFound,
                            message: String::new(),
                        });
                    }
                    Err(e) => {
                        // M-8: central mapper sanitizes Backend-class payloads.
                        let message = map_delete_keystore_item_error(&e);
                        results.push(DeleteKeystoreResult { status: DeleteStatus::Error, message });
                    }
                }
            }
            Err(e) => {
                // Pubkey-parse error — the value of `e` here is generated
                // server-side from caller input (parse_pubkey), so it is
                // BadRequest-class and safe to echo as-is.
                warn!(
                    pubkey = %TruncatedPubkey::new(pubkey_hex),
                    status = "error",
                    error = %e,
                    "Keystore delete result"
                );
                results
                    .push(DeleteKeystoreResult { status: DeleteStatus::Error, message: e.clone() });
            }
        }
    }

    Ok(Json(DeleteKeystoresResponse { data: results, slashing_protection }))
}

// --- Remote key handlers ---

pub async fn list_remote_keys(State(state): State<Arc<AppState>>) -> Json<ListRemoteKeysResponse> {
    let keys = state.remote_key_manager.list_remote_keys();
    let data: Vec<RemoteKeyEntry> = keys
        .into_iter()
        .map(|(pk, url)| RemoteKeyEntry {
            pubkey: format!("0x{}", hex::encode(pk)),
            url,
            readonly: false,
        })
        .collect();

    info!(count = data.len(), "Listed remote keys");

    Json(ListRemoteKeysResponse { data })
}

pub async fn import_remote_keys(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ImportRemoteKeysRequest>,
) -> Json<ImportRemoteKeysResponse> {
    let span = tracing::info_span!(
        "keymanager.import_remote_keys",
        keymanager.count = request.remote_keys.len(),
    );
    let _guard = span.enter();

    info!(count = request.remote_keys.len(), "Importing remote keys");

    let mut results = Vec::with_capacity(request.remote_keys.len());

    for key_import in &request.remote_keys {
        match parse_pubkey(&key_import.pubkey) {
            Ok(pubkey) => {
                // ISSUE-4.9 / L-9: re-resolve hostnames at request time and
                // validate against the private/reserved deny-list, defending
                // against DNS-rebinding attacks where the host passes startup
                // validation but resolves to a private IP at import time.
                if let Err(e) = url_validator::validate_remote_signer_url_runtime(
                    &key_import.url,
                    state.allow_insecure_remote_signer,
                )
                .await
                {
                    let message = map_url_validation_error(e);
                    warn!(
                        pubkey = %TruncatedPubkey::new(&key_import.pubkey),
                        status = "error",
                        error = %message,
                        "Remote key import result"
                    );
                    results.push(ImportRemoteKeyResult {
                        status: ImportRemoteKeyStatus::Error,
                        message,
                    });
                    continue;
                }
                match state.remote_key_manager.import_remote_key(pubkey, key_import.url.clone()) {
                    Ok(()) => {
                        // SEC-2b: same enablement gate as local imports via
                        // DoppelgangerLifecycle (ImportKind::Remote skips VM
                        // registration; still starts monitoring + enable task).
                        state.doppelganger.on_import(pubkey, ImportKind::Remote);
                        info!(
                            pubkey = %TruncatedPubkey::new(&key_import.pubkey),
                            url = %RedactedUrl(&key_import.url),
                            status = "imported",
                            "Remote key import result"
                        );
                        results.push(ImportRemoteKeyResult {
                            status: ImportRemoteKeyStatus::Imported,
                            message: String::new(),
                        });
                    }
                    Err(ImportRemoteKeyError::Duplicate) => {
                        info!(
                            pubkey = %TruncatedPubkey::new(&key_import.pubkey),
                            status = "duplicate",
                            "Remote key import result"
                        );
                        results.push(ImportRemoteKeyResult {
                            status: ImportRemoteKeyStatus::Duplicate,
                            message: "key already exists".into(),
                        });
                    }
                    Err(e) => {
                        results.push(ImportRemoteKeyResult {
                            status: ImportRemoteKeyStatus::Error,
                            message: map_import_remote_key_item_error(e),
                        });
                    }
                }
            }
            Err(e) => {
                warn!(
                    pubkey = %TruncatedPubkey::new(&key_import.pubkey),
                    status = "error",
                    error = %e,
                    "Remote key import result"
                );
                results.push(ImportRemoteKeyResult {
                    status: ImportRemoteKeyStatus::Error,
                    message: e,
                });
            }
        }
    }

    Json(ImportRemoteKeysResponse { data: results })
}

pub async fn delete_remote_keys(
    State(state): State<Arc<AppState>>,
    Json(request): Json<DeleteRemoteKeysRequest>,
) -> Json<DeleteRemoteKeysResponse> {
    let span = tracing::info_span!(
        "keymanager.delete_remote_keys",
        keymanager.count = request.pubkeys.len(),
    );
    let _guard = span.enter();

    warn!(count = request.pubkeys.len(), "Deleting remote keys");

    let mut results = Vec::with_capacity(request.pubkeys.len());

    for pubkey_str in &request.pubkeys {
        match parse_pubkey(pubkey_str) {
            Ok(pubkey) => {
                let delete_result =
                    state.doppelganger.on_delete(&pubkey, ImportKind::Remote, || {
                        match state.remote_key_manager.delete_remote_key(&pubkey) {
                            Ok(true) => (true, Ok(true)),
                            Ok(false) => (false, Ok(false)),
                            Err(e) => (false, Err(e)),
                        }
                    });
                match delete_result {
                    Ok(true) => {
                        warn!(
                            pubkey = %TruncatedPubkey::new(pubkey_str),
                            status = "deleted",
                            "Remote key delete result"
                        );
                        results.push(DeleteRemoteKeyResult {
                            status: DeleteRemoteKeyStatus::Deleted,
                            message: String::new(),
                        });
                    }
                    Ok(false) => {
                        warn!(
                            pubkey = %TruncatedPubkey::new(pubkey_str),
                            status = "not_found",
                            "Remote key delete result"
                        );
                        results.push(DeleteRemoteKeyResult {
                            status: DeleteRemoteKeyStatus::NotFound,
                            message: String::new(),
                        });
                    }
                    Err(e) => {
                        // M-8: Backend variant is sanitized by the central mapper.
                        let message = map_delete_remote_key_item_error(&e);
                        results.push(DeleteRemoteKeyResult {
                            status: DeleteRemoteKeyStatus::Error,
                            message,
                        });
                    }
                }
            }
            Err(e) => {
                warn!(
                    pubkey = %TruncatedPubkey::new(pubkey_str),
                    status = "error",
                    error = %e,
                    "Remote key delete result"
                );
                results.push(DeleteRemoteKeyResult {
                    status: DeleteRemoteKeyStatus::Error,
                    message: e,
                });
            }
        }
    }

    Json(DeleteRemoteKeysResponse { data: results })
}

// --- Fee Recipient ---

pub async fn get_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<FeeRecipientResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let addr = state.config_manager.get_fee_recipient(&pubkey)?;
    Ok(Json(FeeRecipientResponse {
        data: FeeRecipientData {
            pubkey: format_pubkey(&pubkey),
            ethaddress: format!("0x{}", hex::encode(addr)),
        },
    }))
}

pub async fn set_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(request): Json<SetFeeRecipientRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let addr = parse_eth_address(&request.ethaddress)?;
    if addr == [0u8; 20] {
        return Err(ApiError::BadRequest("fee recipient cannot be zero address".into()));
    }
    state.config_manager.set_fee_recipient(&pubkey, addr)?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn delete_fee_recipient(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    state.config_manager.delete_fee_recipient(&pubkey)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Gas Limit ---

pub async fn get_gas_limit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<GasLimitResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let gas_limit = state.config_manager.get_gas_limit(&pubkey)?;
    Ok(Json(GasLimitResponse {
        data: GasLimitData { pubkey: format_pubkey(&pubkey), gas_limit: gas_limit.to_string() },
    }))
}

pub async fn set_gas_limit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(request): Json<SetGasLimitRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let limit = request
        .gas_limit
        .parse::<u64>()
        .map_err(|_| ApiError::BadRequest("invalid gas_limit: must be a numeric string".into()))?;
    state.config_manager.set_gas_limit(&pubkey, limit)?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn delete_gas_limit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    state.config_manager.delete_gas_limit(&pubkey)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Graffiti ---

pub async fn get_graffiti(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<Json<GraffitiResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    let graffiti = state.config_manager.get_graffiti(&pubkey)?;
    Ok(Json(GraffitiResponse { data: GraffitiData { pubkey: format_pubkey(&pubkey), graffiti } }))
}

pub async fn set_graffiti(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Json(request): Json<SetGraffitiRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    if request.graffiti.len() > 32 {
        return Err(ApiError::BadRequest("graffiti must be 32 bytes or less".into()));
    }
    state.config_manager.set_graffiti(&pubkey, &request.graffiti)?;
    Ok(StatusCode::ACCEPTED)
}

pub async fn delete_graffiti(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
) -> Result<StatusCode, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;
    state.config_manager.delete_graffiti(&pubkey)?;
    Ok(StatusCode::NO_CONTENT)
}

// --- Voluntary Exit ---

/// Route-level framing for voluntary-exit signing.
///
/// Both intents share one signing path: the signed exit is returned to the
/// caller and is **not** submitted to the beacon chain. Variants only select
/// the log line / operator-facing framing of the two public routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitIntent {
    /// `POST /eth/v1/validator/:pubkey/voluntary_exit` — WARN log.
    ///
    /// Name reflects the eth-spec route framing ("voluntary exit requested");
    /// the API still only signs and returns the message.
    SignAndSubmit,
    /// `POST /rvc/v1/validator/:pubkey/prepare_exit` — INFO log.
    SignOnly,
}

/// Static log message selected by [`ExitIntent`] (pure for unit tests).
pub(crate) fn exit_intent_log_message(intent: ExitIntent) -> &'static str {
    match intent {
        ExitIntent::SignAndSubmit => "Voluntary exit requested — THIS IS IRREVERSIBLE",
        ExitIntent::SignOnly => "Preparing pre-signed voluntary exit (not submitting)",
    }
}

/// Shared body for both exit routes. Does not submit to the beacon chain.
async fn handle_exit(
    State(state): State<Arc<AppState>>,
    Path(pubkey_hex): Path<String>,
    Query(query): Query<VoluntaryExitQuery>,
    intent: ExitIntent,
) -> Result<Json<VoluntaryExitResponse>, ApiError> {
    let pubkey = parse_pubkey(&pubkey_hex).map_err(ApiError::BadRequest)?;

    let epoch = query
        .epoch
        .map(|e| e.parse::<u64>())
        .transpose()
        .map_err(|_| ApiError::BadRequest("invalid epoch".into()))?;

    let exit_manager = state.exit_manager.as_ref().ok_or_else(|| {
        ApiError::Internal("voluntary exit not available: beacon node not configured".into())
    })?;

    let msg = exit_intent_log_message(intent);
    match intent {
        ExitIntent::SignAndSubmit => {
            warn!(pubkey = %pubkey_hex, epoch = ?epoch, "{}", msg);
        }
        ExitIntent::SignOnly => {
            info!(pubkey = %pubkey_hex, epoch = ?epoch, "{}", msg);
        }
    }

    let signed_exit = exit_manager.sign_voluntary_exit(&pubkey, epoch).await?;

    Ok(Json(VoluntaryExitResponse { data: signed_exit }))
}

/// Sign a voluntary exit and return it (does **not** submit to the beacon chain).
///
/// `POST /eth/v1/validator/:pubkey/voluntary_exit`
///
/// Identical signing path and response shape to [`prepare_exit`]; differs only
/// in log level (WARN) and operator-facing framing. Submission of the returned
/// message is a separate operator step.
pub async fn sign_voluntary_exit(
    state: State<Arc<AppState>>,
    path: Path<String>,
    query: Query<VoluntaryExitQuery>,
) -> Result<Json<VoluntaryExitResponse>, ApiError> {
    handle_exit(state, path, query, ExitIntent::SignAndSubmit).await
}

/// Sign a voluntary exit and return it without submitting.
///
/// `POST /rvc/v1/validator/:pubkey/prepare_exit`
///
/// Identical signing path and response shape to [`sign_voluntary_exit`]; differs
/// only in log level (INFO) and operator-facing framing.
pub async fn prepare_exit(
    state: State<Arc<AppState>>,
    path: Path<String>,
    query: Query<VoluntaryExitQuery>,
) -> Result<Json<VoluntaryExitResponse>, ApiError> {
    handle_exit(state, path, query, ExitIntent::SignOnly).await
}

/// HTTP 500. Pubkeys are truncated; the list itself is capped.
fn drain_timed_out(pubkeys: &[Pubkey]) -> ApiError {
    const SHOW: usize = 8;
    let shown: Vec<String> = pubkeys
        .iter()
        .take(SHOW)
        .map(|pk| {
            let hex = format!("0x{}", hex::encode(pk));
            TruncatedPubkey::new(&hex).to_string()
        })
        .collect();
    let mut list = shown.join(", ");
    let rest = pubkeys.len().saturating_sub(shown.len());
    if rest > 0 {
        list.push_str(&format!(", and {rest} more"));
    }
    tracing::error!(
        count = pubkeys.len(),
        pubkeys = %list,
        "DELETE aborted: signing drain timed out; no slashing-protection export and no keystores deleted"
    );
    ApiError::Internal(format!(
        "signing drain timed out; no keystores exported or deleted; timed-out pubkeys: {list}"
    ))
}

fn parse_pubkey(s: &str) -> Result<Pubkey, String> {
    eth_types::canonical::pubkey_hex::parse_pubkey_hex(s)
        .map(|pk| *pk.as_bytes())
        .map_err(|e| e.to_string())
}

fn empty_interchange() -> String {
    serde_json::json!({
        "metadata": {
            "interchange_format_version": "5",
            "genesis_validators_root": "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "data": []
    })
    .to_string()
}

pub(crate) fn parse_eth_address(s: &str) -> Result<[u8; 20], ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| ApiError::BadRequest(format!("invalid hex: {e}")))?;
    let addr: [u8; 20] =
        bytes.try_into().map_err(|_| ApiError::BadRequest("address must be 20 bytes".into()))?;
    Ok(addr)
}

pub(crate) fn format_pubkey(pubkey: &[u8; 48]) -> String {
    format!("0x{}", hex::encode(pubkey))
}

/// Rate-limit window for `set_attesting_enabled`: 1 call per 60 seconds.
const ATTESTING_RATE_LIMIT_SECS: u64 = 60;

/// Rate-limit window for `import_keystores` (ISSUE-4.7 / L-7).
const IMPORT_KEYSTORES_WINDOW_SECS: u64 = 60;
/// Maximum allowed `import_keystores` calls per API token per window.
///
/// Each call may carry multiple keystores; the axum body limit bounds the
/// per-call decrypt cost, so this gates the per-token call rate.
const IMPORT_KEYSTORES_MAX_PER_WINDOW: usize = 10;

/// Compute the SHA-256 digest of a bearer token for use as a rate-limiter key.
///
/// The hashed digest is stored in `AppState::import_keystores_rate` so the raw
/// token value never sits in long-lived memory beyond the request scope.
fn hash_bearer_token(token: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let out = hasher.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}

/// Check the per-token rate limit for `import_keystores`.
///
/// On miss (no Authorization header / no Bearer prefix) the rate limiter is
/// skipped — auth middleware (`bearer_auth`) is what enforces the bearer
/// requirement; this check is layered defense, not a primary auth gate.
fn check_import_keystores_rate(state: &AppState, headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(token) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
    else {
        return Ok(());
    };

    let key = hash_bearer_token(token);
    let now = tokio::time::Instant::now();
    let window = std::time::Duration::from_secs(IMPORT_KEYSTORES_WINDOW_SECS);

    let mut map =
        state.import_keystores_rate.lock().expect("import_keystores rate-limit mutex poisoned");
    let history = map.entry(key).or_default();

    // Drop entries older than the window (rolling-window pruning).
    while let Some(front) = history.front() {
        if now.duration_since(*front) > window {
            history.pop_front();
        } else {
            break;
        }
    }

    if history.len() >= IMPORT_KEYSTORES_MAX_PER_WINDOW {
        // Retry-After: time until the oldest entry leaves the window.
        let oldest = history.front().copied().unwrap_or(now);
        let retry_after_secs = window.saturating_sub(now.duration_since(oldest)).as_secs().max(1);
        return Err(ApiError::RateLimited { retry_after_secs });
    }

    history.push_back(now);
    Ok(())
}

pub async fn set_attesting_enabled(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(request): Json<SetAttestingRequest>,
) -> Result<Json<SetAttestingResponse>, crate::error::ApiError> {
    // ── Rate limiting ────────────────────────────────────────────────────────
    {
        let mut last = state.last_set_attesting_enabled.lock().expect("rate-limit mutex poisoned");
        let now = tokio::time::Instant::now();
        if let Some(prev) = *last {
            let elapsed = now.duration_since(prev).as_secs();
            if elapsed < ATTESTING_RATE_LIMIT_SECS {
                let retry_after = ATTESTING_RATE_LIMIT_SECS - elapsed;
                return Err(crate::error::ApiError::RateLimited { retry_after_secs: retry_after });
            }
        }
        *last = Some(now);
    }

    // ── Audit log ────────────────────────────────────────────────────────────
    let caller_prefix = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.chars().take(8).collect::<String>())
        .unwrap_or_else(|| "<none>".to_string());

    info!(
        caller = %caller_prefix,
        requested = request.enabled,
        "set_attesting_enabled audit"
    );

    // ── Apply the change ─────────────────────────────────────────────────────
    let previous = state.attesting_enabled.swap(request.enabled, Ordering::Relaxed);
    let current = request.enabled;

    if previous && !current {
        warn!("Attestation duties disabled via API");
    } else if !previous && current {
        info!("Attestation duties re-enabled via API");
    }

    metrics::definitions::RVC_ATTESTING_ENABLED.set(if current { 1.0 } else { 0.0 });

    Ok(Json(SetAttestingResponse { enabled: current }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- parse_eth_address tests ---

    #[test]
    fn test_parse_eth_address_valid_with_prefix() {
        let addr = parse_eth_address("0xAbcF8e0d4e9587369b2301D0790347320302cc09").unwrap();
        assert_eq!(addr.len(), 20);
        assert_eq!(hex::encode(addr), "abcf8e0d4e9587369b2301d0790347320302cc09");
    }

    #[test]
    fn test_parse_eth_address_valid_without_prefix() {
        let addr = parse_eth_address("AbcF8e0d4e9587369b2301D0790347320302cc09").unwrap();
        assert_eq!(hex::encode(addr), "abcf8e0d4e9587369b2301d0790347320302cc09");
    }

    #[test]
    fn test_parse_eth_address_invalid_hex() {
        let result = parse_eth_address("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_eth_address_wrong_length() {
        let result = parse_eth_address("0xabcdef");
        assert!(result.is_err());
    }

    // --- format_pubkey tests ---

    #[test]
    fn test_format_pubkey() {
        let mut pubkey = [0u8; 48];
        pubkey[0] = 0x93;
        pubkey[1] = 0x24;
        pubkey[47] = 0x4a;
        let formatted = format_pubkey(&pubkey);
        assert!(formatted.starts_with("0x"));
        assert_eq!(formatted.len(), 98); // 0x + 96 hex chars
        assert_eq!(&formatted[..6], "0x9324");
        assert!(formatted.ends_with("4a"));
    }

    #[test]
    fn test_exit_intent_selects_log_line() {
        assert_eq!(
            exit_intent_log_message(ExitIntent::SignAndSubmit),
            "Voluntary exit requested — THIS IS IRREVERSIBLE"
        );
        assert_eq!(
            exit_intent_log_message(ExitIntent::SignOnly),
            "Preparing pre-signed voluntary exit (not submitting)"
        );
        assert_ne!(
            exit_intent_log_message(ExitIntent::SignAndSubmit),
            exit_intent_log_message(ExitIntent::SignOnly)
        );
    }

    /// RF3-15: keymanager now accepts uppercase `0X` via canonical parse.
    #[test]
    fn test_keymanager_accepts_uppercase_0x_pubkey() {
        let bare = "ab".repeat(48);
        let pk = parse_pubkey(&format!("0X{bare}")).expect("0X-prefixed pubkey must parse");
        assert_eq!(pk, [0xabu8; 48]);
    }

    /// RF3-15: shared case table — bare / 0x / 0X / mixed hex accepted; doubles,
    /// wrong length, and non-hex rejected.
    #[test]
    fn test_parse_pubkey_shared_case_table() {
        let bare = "cd".repeat(48);
        let expected = [0xcdu8; 48];
        for s in [
            bare.clone(),
            format!("0x{bare}"),
            format!("0X{bare}"),
            format!("0x{}", bare.to_uppercase()),
            format!("0X{}", bare.to_uppercase()),
        ] {
            assert_eq!(parse_pubkey(&s).unwrap(), expected, "input={s}");
        }
        assert!(parse_pubkey(&format!("0x0x{bare}")).is_err());
        assert!(parse_pubkey(&format!("0x0X{bare}")).is_err());
        assert!(parse_pubkey(&format!("0X0x{bare}")).is_err());
        assert!(parse_pubkey(&format!("0x{}", "ab".repeat(47))).is_err());
        assert!(parse_pubkey(&format!("0x{}", "zz".repeat(48))).is_err());
    }
}
