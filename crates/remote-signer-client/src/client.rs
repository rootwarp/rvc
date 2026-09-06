//! HTTP client and trait impls for Web3Signer remote signing.
//!
//! Depends on [`super::wire`] for request builders and config; does not define
//! any wire types (those live in `web3signer_wire`).

use async_trait::async_trait;
use crypto::{
    InsecureGate, InsecureMode, PublicKey, SignContext, Signature, Signer, SigningError,
    TypedSigner, PUBLIC_KEY_BYTES_LEN,
};
use eth_types::{
    AggregateAndProof, AttestationData, BeaconBlock, BlindedBeaconBlock, ContributionAndProof,
    Epoch, PayloadAttestationData, ProposerPreferences, Root, Slot, ValidatorRegistrationV1,
    VoluntaryExit,
};
use observability::logging::{RedactedUrl, TruncatedPubkey};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use tracing::Instrument;
use web3signer_wire::SignRequest;

use crate::wire::{
    build_aggregate_and_proof_request, build_attestation_request, build_blinded_block_v2_request,
    build_block_v2_request, build_contribution_and_proof_request,
    build_payload_attestation_request, build_proposer_preferences_request,
    build_randao_reveal_request, build_sync_committee_message_request,
    build_sync_selection_proof_request, build_validator_registration_request,
    build_voluntary_exit_request, RemoteSignerConfig,
};

/// Environment variable that must be set to `"true"` to allow plaintext
/// `http://` remote-signer URLs.  `https://` URLs always pass without
/// consulting this variable.
pub const REMOTE_SIGNER_INSECURE_ENV_VAR: &str = "RVC_REMOTE_SIGNER_ALLOW_INSECURE";

/// Gate `url` against the plaintext-URL policy.
///
/// - `https://` URLs pass immediately — no env-var check, no log.
/// - Any other scheme (e.g. `http://`) is evaluated by [`InsecureGate`]:
///   - `mode = Warn` (Phase 2 default): emits an `error!`-level log and
///     returns `Ok(())` so existing deployments are not hard-broken.
///   - `mode = Refuse` (Phase 3, ISSUE-3.13): returns
///     `Err(SigningError::RemoteSignerError(...))` unless the operator has set
///     `RVC_REMOTE_SIGNER_ALLOW_INSECURE=true`.
///
/// The predicate passed to the gate is `|| true`: the scheme check is already
/// done above, so the remaining question is purely "has the operator opted
/// in via the env var?".  Predicate `true` means the gate's combined
/// condition (`env_ok && pred_ok`) becomes `env_ok`, giving clean opt-in
/// semantics.
pub fn check_remote_signer_url(url: &str, mode: InsecureMode) -> Result<(), SigningError> {
    if url.trim_end_matches('/').starts_with("https://") {
        return Ok(());
    }
    InsecureGate::with_predicate(REMOTE_SIGNER_INSECURE_ENV_VAR, mode, || true)
        .check()
        .map_err(|e| SigningError::RemoteSignerError(e.to_string()))
}

pub struct RemoteSigner {
    client: Client,
    url: String,
    pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
}

impl RemoteSigner {
    pub fn new(
        config: RemoteSignerConfig,
        pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    ) -> Result<Self, SigningError> {
        let url = config.url.trim_end_matches('/').to_string();

        // Gate plaintext URLs. Per NFR-10 / ISSUE-3.13 (GA) the gate refuses
        // http:// URLs unless RVC_REMOTE_SIGNER_ALLOW_INSECURE=true is set.
        check_remote_signer_url(&url, InsecureMode::Refuse)?;

        let client = Client::builder()
            .timeout(config.timeout)
            .build()
            .map_err(|e| SigningError::RemoteSignerError(e.to_string()))?;

        Ok(Self { client, url, pubkeys })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Creates a `RemoteSigner` without running the insecure-URL gate check.
    ///
    /// **For tests / fixtures only** (e.g. registering a remote pubkey for
    /// policy resolution without dialing Web3Signer). Production callers must
    /// use [`Self::new`], which enforces the `InsecureMode::Refuse` gate
    /// (ISSUE-3.13 / NFR-10).
    pub fn new_for_tests(
        config: RemoteSignerConfig,
        pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    ) -> Self {
        let url = config.url.trim_end_matches('/').to_string();
        let client =
            Client::builder().timeout(config.timeout).build().expect("test http client build");
        Self { client, url, pubkeys }
    }

    /// Alias kept for in-crate tests that predate [`Self::new_for_tests`].
    #[cfg(test)]
    pub(crate) fn new_unchecked(
        config: RemoteSignerConfig,
        pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    ) -> Self {
        Self::new_for_tests(config, pubkeys)
    }

    /// POST a fully-typed Web3Signer body and re-verify the returned signature
    /// against `signing_root` (SEC-8). Never sends a bare `{signing_root}` body.
    pub async fn sign_request(
        &self,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
        request: &SignRequest,
        signing_root: &Root,
    ) -> Result<Signature, SigningError> {
        self.sign_request_classified(pubkey, request, signing_root, None).await
    }

    async fn sign_request_classified(
        &self,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
        request: &SignRequest,
        signing_root: &Root,
        unsupported_duty: Option<&'static str>,
    ) -> Result<Signature, SigningError> {
        if !self.pubkeys.contains(pubkey) {
            return Err(SigningError::KeyNotFound(hex::encode(pubkey)));
        }

        let identifier = format!("0x{}", hex::encode(pubkey));
        let url = format!("{}/api/v1/eth2/sign/{}", self.url, identifier);

        // Logged URL truncates the pubkey path segment; the real request uses `url`.
        let log_url =
            format!("{}/api/v1/eth2/sign/{}", self.url, TruncatedPubkey::new(&identifier));

        let span = tracing::info_span!(
            "sign.remote",
            http.method = "POST",
            http.url = %RedactedUrl(&log_url),
            http.status_code = tracing::field::Empty,
            signer_type = "remote",
            web3signer_type = request.payload.type_name(),
        );

        async {
            let response = self.client.post(&url).json(request).send().await.map_err(|e| {
                SigningError::RemoteSignerError(format!("HTTP request failed: {e}"))
            })?;

            let status = response.status();
            tracing::Span::current().record("http.status_code", status.as_u16());

            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                return Err(classify_web3signer_http_error(status, &body, unsupported_duty));
            }

            let sign_response: SignResponse = response.json().await.map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid response body: {e}"))
            })?;

            let sig_hex =
                sign_response.signature.strip_prefix("0x").unwrap_or(&sign_response.signature);
            let sig_bytes = hex::decode(sig_hex).map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid signature hex: {e}"))
            })?;

            let signature = Signature::from_bytes(&sig_bytes).map_err(|e| {
                SigningError::RemoteSignerError(format!("invalid BLS signature: {e}"))
            })?;

            let pk = PublicKey::from_bytes(pubkey)
                .map_err(|e| SigningError::RemoteSignerError(format!("invalid public key: {e}")))?;
            if signature.verify(&pk, signing_root).is_err() {
                tracing::error!(
                    pubkey = %TruncatedPubkey::new(&hex::encode(pubkey)),
                    "Remote signer returned invalid signature"
                );
                return Err(SigningError::InvalidRemoteSignature);
            }

            Ok(signature)
        }
        .instrument(span)
        .await
    }
}

#[derive(Deserialize)]
struct SignResponse {
    signature: String,
}

/// Classify a non-success Web3Signer HTTP status.
///
/// HTTP 400 is the generic bad-request code and stays
/// [`SigningError::RemoteSignerError`] (transient; callers may retry). It must
/// never become [`SigningError::UnsupportedDuty`] or
/// [`SigningError::UnsupportedSigningType`] — that would poison a key (4.10).
/// 404/501 for a named duty mean the signer does not support the type.
pub(crate) fn classify_web3signer_http_error(
    status: StatusCode,
    body: &str,
    unsupported_duty: Option<&'static str>,
) -> SigningError {
    if let Some(duty) = unsupported_duty {
        if matches!(status, StatusCode::NOT_FOUND | StatusCode::NOT_IMPLEMENTED) {
            tracing::warn!(
                status = status.as_u16(),
                duty,
                "remote signer does not support duty; dropping"
            );
            return SigningError::UnsupportedDuty { duty };
        }
    }
    SigningError::RemoteSignerError(format!("Web3Signer returned {status}: {body}"))
}

#[async_trait]
impl Signer for RemoteSigner {
    /// Raw-root signing is intentionally unsupported for Web3Signer HTTP
    /// (SEC-8). A bare root cannot produce a type-tagged contract body — use
    /// [`TypedSigner`] methods (or [`RemoteSigner::sign_request`]) instead.
    async fn sign(
        &self,
        _signing_root: &Root,
        pubkey: &[u8; PUBLIC_KEY_BYTES_LEN],
    ) -> Result<Signature, SigningError> {
        if !self.pubkeys.contains(pubkey) {
            return Err(SigningError::KeyNotFound(hex::encode(pubkey)));
        }
        Err(SigningError::UnsupportedSigningType(
            "raw-root signing is not supported for Web3Signer HTTP; \
             use TypedSigner::sign_block / sign_attestation / etc."
                .to_string(),
        ))
    }

    fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        self.pubkeys.clone()
    }
}

#[async_trait]
impl TypedSigner for RemoteSigner {
    async fn sign_block(
        &self,
        block: &BeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_block_v2_request(block, ctx)?;
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_blinded_block(
        &self,
        block: &BlindedBeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_blinded_block_v2_request(block, ctx)?;
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_attestation(
        &self,
        data: &AttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_attestation_request(data, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_aggregate_and_proof(
        &self,
        agg: &AggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_aggregate_and_proof_request(agg, ctx)?;
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_sync_committee_message(
        &self,
        slot: Slot,
        beacon_block_root: Root,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) =
            build_sync_committee_message_request(slot, beacon_block_root, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_sync_aggregator_selection(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_sync_selection_proof_request(slot, subcommittee_index, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_contribution_and_proof(
        &self,
        c: &ContributionAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_contribution_and_proof_request(c, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_builder_registration(
        &self,
        reg: &ValidatorRegistrationV1,
        genesis_fork_version: [u8; 4],
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_validator_registration_request(reg, genesis_fork_version);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_randao_reveal_request(epoch, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_voluntary_exit(
        &self,
        exit: &VoluntaryExit,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_voluntary_exit_request(exit, ctx);
        self.sign_request(&pk, &req, &signing_root).await
    }

    async fn sign_payload_attestation(
        &self,
        data: &PayloadAttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_payload_attestation_request(data, ctx);
        self.sign_request_classified(&pk, &req, &signing_root, Some("payload_attestation")).await
    }

    async fn sign_proposer_preferences(
        &self,
        prefs: &ProposerPreferences,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let pk = ctx.pubkey.to_bytes();
        let (req, signing_root) = build_proposer_preferences_request(prefs, ctx);
        self.sign_request_classified(&pk, &req, &signing_root, Some("proposer_preferences")).await
    }
}

#[cfg(test)]
// RF1-12: unit tests mutate env via unsafe set_var/remove_var.
#[allow(unsafe_code)]
#[path = "client_tests.rs"]
mod tests;
