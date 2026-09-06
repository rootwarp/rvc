//! Axum handlers for the Web3Signer HTTP API.
//!
//! `GET /upcheck`, `GET /api/v1/eth2/publicKeys`, and the live
//! `POST /api/v1/eth2/sign/{identifier}` sign route.

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::header::ACCEPT;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};

use super::accept_loop::PeerCert;
use super::dispatch::plan_sign;
use super::pubkey::{resolve_identifier, PubkeyError};
use super::request::{SignPayload, SignRequest};
use super::response::{sign_response, HttpSignError};
use super::Web3SignerState;
use crate::audit;
use crate::audit::cn::audit_cn;
use crate::metrics::grpc_sign_type;
use crate::sign_plan::{dispatch_sign, DispatchError, RequestCtx};

use tracing::Instrument;

use observability::logging::fields::{self, Duty};
use observability::logging::{new_request_id, record_display, TruncatedPubkey};

/// `GET /upcheck` — liveness probe (FR-1).
///
/// Returns `200 OK` with the body `OK`. It takes no state and never calls the
/// gate, so orchestration health-checks succeed even while the signing path is
/// busy or erroring.
#[tracing::instrument(skip_all)]
pub(super) async fn upcheck() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

/// `GET /api/v1/eth2/publicKeys` (FR-2).
///
/// Returns `200` with a JSON array of `0x`-prefixed lowercase BLS public keys
/// for every key currently loaded in the backend — the same key set the gRPC
/// `list_public_keys` handler serves (one source of truth, both transports). An
/// empty backend returns `[]` (still `200`, not `404`). No gate call.
#[tracing::instrument(skip_all)]
pub(super) async fn public_keys(State(state): State<Web3SignerState>) -> Json<Vec<String>> {
    let keys =
        state.backend.public_keys().iter().map(|pk| format!("0x{}", hex::encode(pk))).collect();
    Json(keys)
}

/// `POST /api/v1/eth2/sign/{identifier}` (FR-3..FR-24).
///
/// Resolves `{identifier}` to a loaded key (`400`/`404`), decodes the request,
/// computes the signing root via the dispatcher, routes the matching
/// `SigningGate.sign_*` call (the single signing authority — slashing + lock +
/// timeout), and shapes the body per `Accept`. The gate result maps to the exact
/// HTTP status (`200/400/404/412/500`) via [`HttpSignError`].
pub(super) async fn sign(
    State(state): State<Web3SignerState>,
    Path(identifier): Path<String>,
    peer: Option<Extension<PeerCert>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    // Continue the caller's W3C trace: the handler span is parented from the
    // inbound `traceparent` BEFORE it is entered (set_parent is a no-op once the
    // span has started), then the body future is instrumented with it.
    let span = sign_span(&headers);

    // request_id correlates one signing request end to end, including across this
    // :9000 hop — reuse the caller's `x-request-id` if present, else mint one.
    // The reused value is recorded on the span and inherits into the signing
    // audit line, so bound it (non-empty, <= 128 ASCII-graphic chars) to deny an
    // attacker-chosen, header-buffer-sized token polluting the audit log; any
    // value outside that gate is replaced by a fresh minted correlator.
    let request_id = headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_owned)
        .unwrap_or_else(|| new_request_id().to_string());

    let mut response = sign_traced(state, identifier, peer, headers, body, request_id.clone())
        .instrument(span)
        .await;

    // Echo the correlator so the caller can stitch both sides of the trace.
    if let Ok(value) = axum::http::HeaderValue::from_str(&request_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}

/// Build the per-request handler span and continue the caller's trace.
///
/// `set_parent_from_headers` MUST run before the span is entered/started (it is a
/// no-op once started — see `telemetry::propagation`), so the span is created
/// here, parented from the inbound `traceparent`, and returned **unentered**; the
/// caller instruments the body future with it. The correlation fields are
/// declared `Empty` and late-bound by the handler once the payload parses.
fn sign_span(headers: &axum::http::HeaderMap) -> tracing::Span {
    let span = tracing::info_span!(
        "sign",
        otel.kind = "server",
        request_id = tracing::field::Empty,
        slot = tracing::field::Empty,
        duty = tracing::field::Empty,
        pubkey = tracing::field::Empty,
    );
    telemetry::set_parent_from_headers(&span, headers);
    span
}

/// The body of [`sign`], instrumented with the handler span so every event it
/// emits (including the audit line) inherits the span's correlation fields.
/// Split out so [`sign`] can build + parent the span first.
async fn sign_traced(
    state: Web3SignerState,
    identifier: String,
    peer: Option<Extension<PeerCert>>,
    headers: axum::http::HeaderMap,
    body: Bytes,
    request_id: String,
) -> Response {
    // request_id is a span field declared `Empty` in `sign_span`; record it so it
    // lands on the handler span and inherits to the audit line.
    record_display(&tracing::Span::current(), fields::REQUEST_ID, &request_id);

    let accept = headers.get(ACCEPT).and_then(|v| v.to_str().ok());
    // Derive the audit CN from the TLS peer cert (Phase 3). `None` extension
    // (socket-free tests / no-TLS) or no client cert (Prysm / server-TLS-only)
    // both degrade to the configured default (`AUDIT_CN_DEFAULT`).
    //
    // SEC-4: when `client_cn_allow_list` is configured, the CN *is* an
    // authorization gate (same list as gRPC). When unset, missing/default CN
    // still signs (backward compatible).
    let cn = audit_cn(peer.as_ref().and_then(|Extension(p)| p.leaf_der()), &state.audit.default_cn);

    // Audit posture (Issue 4.4): emit exactly one structured entry per request —
    // success at `info`, every rejection at `warn` — carrying only metadata
    // (pubkey identifier, Web3Signer `type`, outcome, peer CN, backend, latency).
    // NEVER the request body, signing root, or signature. `rpc_type` is filled by
    // `sign_inner` once the payload parses, so a pre-parse 400 audits with no
    // `type` rather than a wrong one.
    let started = std::time::Instant::now();
    let mut rpc_type: Option<&'static str> = None;
    let (response, result_label) = if let Err(status) =
        audit::authorize_client_cn(state.client_cn_allow_list.as_deref(), &cn)
    {
        // Reject before any parse / gate / BLS work (mirrors gRPC SEC-4 order).
        let err = HttpSignError::Unauthorized(status.message().to_string());
        let label = err.audit_label();
        (err.into_response(), label)
    } else {
        match sign_inner(&state, &identifier, accept, &cn, body.as_ref(), &mut rpc_type).await {
            Ok(resp) => (resp, "success"),
            Err(e) => {
                let label = e.audit_label();
                (e.into_response(), label)
            }
        }
    };
    let elapsed = started.elapsed();

    // HTTP-path metrics (Issue 4.5): count by `type` × outcome and observe
    // latency on series distinct from the gRPC vecs, scraped on the same `:9101`
    // listener. A pre-parse failure has no `type` → "unknown" (a single bounded
    // bucket, never request-derived, so the label set stays low-cardinality).
    state
        .metrics
        .http_sign_total
        .with_label_values(&[rpc_type.unwrap_or("unknown"), result_label])
        .inc();
    state
        .metrics
        .http_sign_duration_seconds
        .with_label_values(&[] as &[&str])
        .observe(elapsed.as_secs_f64());

    audit::log_audit(&audit::AuditEntry {
        timestamp: audit::now_rfc3339(),
        pubkey_hex: identifier,
        client_cn: cn,
        backend: state.audit.backend_name.clone(),
        result: result_label.to_string(),
        duration_ms: elapsed.as_millis() as u64,
        rpc: rpc_type.map(str::to_string),
    });
    response
}

/// Map a Web3Signer payload to its canonical [`Duty`] category (the span's `duty`
/// field). Several request types collapse onto one duty (e.g. RANDAO_REVEAL is a
/// proposer/block duty); the Web3Signer `type` stays distinct in the audit line.
fn payload_duty(payload: &SignPayload) -> Duty {
    match payload {
        SignPayload::Attestation { .. } | SignPayload::PayloadAttestation { .. } => {
            Duty::Attestation
        }
        SignPayload::BlockV2 { .. }
        | SignPayload::RandaoReveal { .. }
        | SignPayload::ProposerPreferences { .. } => Duty::Block,
        SignPayload::AggregationSlot { .. }
        | SignPayload::AggregateAndProof { .. }
        | SignPayload::AggregateAndProofV2 { .. } => Duty::Aggregate,
        SignPayload::SyncCommitteeMessage { .. } => Duty::SyncCommittee,
        SignPayload::SyncCommitteeContributionAndProof { .. }
        | SignPayload::SyncCommitteeSelectionProof { .. } => Duty::SyncContribution,
        SignPayload::ValidatorRegistration { .. } => Duty::ValidatorRegistration,
        SignPayload::VoluntaryExit { .. } => Duty::VoluntaryExit,
    }
}

/// The `slot` a payload pertains to, when it carries one. Epoch-only types
/// (RANDAO_REVEAL, VOLUNTARY_EXIT) and the slotless VALIDATOR_REGISTRATION have
/// none, so the span's `slot` field stays unset for them.
fn payload_slot(payload: &SignPayload) -> Option<u64> {
    match payload {
        SignPayload::BlockV2 { beacon_block } => Some(beacon_block.block_header.slot),
        SignPayload::Attestation { attestation } => Some(attestation.slot),
        SignPayload::AggregationSlot { aggregation_slot } => Some(aggregation_slot.slot),
        SignPayload::AggregateAndProof { aggregate_and_proof } => {
            Some(aggregate_and_proof.aggregate.data.slot)
        }
        SignPayload::AggregateAndProofV2 { aggregate_and_proof } => {
            Some(aggregate_and_proof.data.aggregate.data.slot)
        }
        SignPayload::SyncCommitteeMessage { sync_committee_message } => {
            Some(sync_committee_message.slot)
        }
        SignPayload::SyncCommitteeContributionAndProof { contribution_and_proof } => {
            Some(contribution_and_proof.contribution.slot)
        }
        SignPayload::SyncCommitteeSelectionProof { sync_aggregator_selection_data } => {
            Some(sync_aggregator_selection_data.slot)
        }
        SignPayload::PayloadAttestation { payload_attestation } => {
            Some(payload_attestation.data.slot)
        }
        SignPayload::ProposerPreferences { proposer_preferences } => {
            Some(proposer_preferences.data.proposal_slot)
        }
        SignPayload::RandaoReveal { .. }
        | SignPayload::ValidatorRegistration { .. }
        | SignPayload::VoluntaryExit { .. } => None,
    }
}

/// The fallible core of [`sign`], split out so every failure renders through the
/// single [`HttpSignError`] → status mapping. `rpc_type` is an out-param set to
/// the Web3Signer `type` as soon as the body parses, so the caller can audit the
/// type even on a post-parse failure (slashing/gate error).
async fn sign_inner(
    state: &Web3SignerState,
    identifier: &str,
    accept: Option<&str>,
    cn: &str,
    body: &[u8],
    rpc_type: &mut Option<&'static str>,
) -> Result<Response, HttpSignError> {
    // 1. Resolve {identifier} to a loaded key: malformed → 400, unloaded → 404.
    //    The pre-check runs before any decode/gate work.
    let pubkey = resolve_identifier(identifier, state.backend.as_ref()).map_err(|e| match e {
        PubkeyError::Malformed => {
            HttpSignError::BadRequest("malformed public key identifier".to_string())
        }
        PubkeyError::NotLoaded => HttpSignError::UnknownKey,
    })?;
    // pubkey is a span field declared `Empty` in `sign_span`; record it truncated
    // (never the full key) so the handler span carries the canonical correlator.
    record_display(&tracing::Span::current(), fields::PUBKEY, TruncatedPubkey::new(identifier));

    // 2. Decode the body. A serde decode failure maps to a FIXED 400 — the
    //    decoder message can echo request bytes / field text and is NEVER
    //    surfaced to the client (SEC-INFO-01).
    let req: SignRequest = serde_json::from_slice(body).map_err(|e| {
        // Named unknown-version identifiers only. Empty / invalid tokens and
        // every other decoder failure stay the fixed SEC-INFO-01 body.
        match web3signer_wire::WireVersionError::from_serde_display(&e.to_string()) {
            Some(web3signer_wire::WireVersionError::Unknown(value)) => {
                HttpSignError::BadRequest(format!("unknown version: {value}"))
            }
            _ => HttpSignError::BadRequest("invalid sign request body".to_string()),
        }
    })?;
    // Record the type for the audit entry now that the payload is known, so a
    // later slashing/gate rejection still audits the correct `type` (Issue 4.4).
    *rpc_type = Some(req.payload.type_name());
    // Record the canonical duty + slot (when the payload carries one) on the span.
    let span = tracing::Span::current();
    record_display(&span, fields::DUTY, payload_duty(&req.payload).as_str());
    if let Some(slot) = payload_slot(&req.payload) {
        record_display(&span, fields::SLOT, slot);
    }

    // 3. Compute the signing root + slashing inputs; enforce the signingRoot /
    //    fork_info policy (the shared SignPlan engine owns the domain).
    //    Builder registration uses state.genesis_fork_version (network config).
    let plan = plan_sign(&req, state.genesis_fork_version)?;

    // 4. Shared dispatcher (same A7 metrics path as gRPC). Gate method selection
    //    is carried on `plan.non_slashable_op` — no second payload→gate match here.
    let pubkey_bytes = pubkey.to_bytes();
    let ctx = RequestCtx {
        client_cn: cn.to_string(),
        pubkey,
        pubkey_bytes,
        rpc_type: http_a7_sign_type(&req.payload),
        genesis_fork_version: state.genesis_fork_version,
    };
    let sig = dispatch_sign(
        Some(state.gate.as_ref()),
        state.backend.as_ref(),
        Some(state.metrics.as_ref()),
        &state.audit.backend_name,
        &ctx,
        &plan,
    )
    .await
    .map_err(dispatch_err_to_http)?;

    // 5. Shape the success body per Accept (FR-17).
    Ok(sign_response(accept, &sig))
}

/// Map Web3Signer payload types onto the bounded A7 `sign_*` type labels so HTTP
/// and gRPC populate the same series with the same vocabulary.
fn http_a7_sign_type(payload: &SignPayload) -> &'static str {
    match payload {
        SignPayload::BlockV2 { .. } => grpc_sign_type::BEACON_BLOCK,
        SignPayload::Attestation { .. } => grpc_sign_type::ATTESTATION_DATA,
        SignPayload::RandaoReveal { .. } => grpc_sign_type::RANDAO_REVEAL,
        SignPayload::AggregationSlot { .. } => grpc_sign_type::AGGREGATION_SLOT,
        SignPayload::AggregateAndProof { .. } | SignPayload::AggregateAndProofV2 { .. } => {
            grpc_sign_type::AGGREGATE_AND_PROOF
        }
        SignPayload::SyncCommitteeMessage { .. } => grpc_sign_type::SYNC_COMMITTEE_MESSAGE,
        SignPayload::SyncCommitteeContributionAndProof { .. } => {
            grpc_sign_type::CONTRIBUTION_AND_PROOF
        }
        SignPayload::SyncCommitteeSelectionProof { .. } => {
            grpc_sign_type::SYNC_AGGREGATOR_SELECTION_DATA
        }
        SignPayload::ValidatorRegistration { .. } => grpc_sign_type::BUILDER_REGISTRATION,
        SignPayload::VoluntaryExit { .. } => grpc_sign_type::VOLUNTARY_EXIT,
        SignPayload::PayloadAttestation { .. } => grpc_sign_type::PAYLOAD_ATTESTATION,
        SignPayload::ProposerPreferences { .. } => grpc_sign_type::PROPOSER_PREFERENCES,
    }
}

fn dispatch_err_to_http(e: DispatchError) -> HttpSignError {
    match e {
        DispatchError::Gate(ge) => HttpSignError::Gate(ge),
        DispatchError::Backend(be) => {
            // HTTP always has a gate in production; backend-only path is the
            // insecure no-DB case. Surface as a gate-shaped internal error.
            tracing::error!(error = %be, "HTTP dispatch backend error");
            HttpSignError::Gate(signer::SigningGateError::SigningFailed(be.to_string()))
        }
        DispatchError::GateRequired => {
            HttpSignError::BadRequest("slashing protection is not configured".to_string())
        }
        DispatchError::PlanMismatch => {
            HttpSignError::BadRequest("internal dispatch mismatch".to_string())
        }
    }
}

#[cfg(test)]
mod tests;
