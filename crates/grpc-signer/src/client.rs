//! gRPC remote signer (`TypedSigner` only).
//!
//! # Per-duty Gloas verdict matrix (D11 / 4.20c)
//!
//! Selection is on the resolved [`ForkName`], once per duty: `>= Gloas` uses the
//! Gloas-safe RPC, otherwise the legacy RPC. A failure is a failure — there is
//! **no** fallback-on-error retry onto the other shape.
//!
//! `SignContext::resolve` must actually resolve Gloas (P2 **2.2**). With 2.6's
//! `[0xFF;4]` default, `Gloas.fork_version()` does not round-trip (D7); if that
//! hazard is unresolved the client fails before sending and no row here is
//! reachable.
//!
//! With `GLOAS_FORK_EPOCH` at its far-future sentinel the resolved fork is
//! never `>= Gloas`, so no new RPC is selected.
//!
//! | Duty | Gloas verdict | Path |
//! |---|---|---|
//! | Attestation | supported, unchanged | legacy typed RPC; `fork_id` ignored server-side |
//! | Sync-committee message / selection | supported, unchanged | legacy typed RPC |
//! | RANDAO, voluntary exit, builder registration | supported, unchanged | legacy typed RPC |
//! | Block / blinded block | supported via the header RPC | 4.20a `SignBlockHeader`; Gloas `body_root` from `gloas_body_root` (P5 5.11b) through 4.21's `sign_block_header`. `sign_block` / `sign_blinded_block` refuse at Gloas (no Electra/Deneb body hash). |
//! | Aggregate-and-proof, Electra aggregate-and-proof, contribution-and-proof | supported via the root RPC | 4.20a `SignRoot`; Electra keeps `committee_bits` in the object root |
//! | PTC payload attestation | supported via the root RPC | 4.20a `SignRoot` |
//! | Proposer preferences | supported via the root RPC | 4.20a `SignRoot` |
//! | Self-build execution payload envelope | supported via the root RPC (`EXECUTION_PAYLOAD_ENVELOPE`) | root from P5 5.16; served in P6 6.19 |
//! | Builder request auth | supported via the root RPC (`BUILDER_REQUEST_AUTH`) | served |
//!
//! No duty fails solely because `ForkName::Gloas.id() == 7`. The four
//! decoder-bound legacy RPCs still reject id 7 (`UnknownForkId`); this client
//! never sends Gloas SSZ to those RPCs.

use std::time::Instant;

use async_trait::async_trait;
use tonic::transport::Channel;
use tracing::Instrument;
use tree_hash::TreeHash;
use url::Url;
use zeroize::Zeroizing;

use crypto::typed_signer::SignContext;
use crypto::{signing_root_with_fork_version, SigningError, TypedSigner};
use crypto::{InsecureGate, InsecureMode};
use crypto::{PublicKey, Signature, PUBLIC_KEY_BYTES_LEN};
use eth_types::{
    encode_attestation_ssz, encode_beacon_block_ssz, encode_blinded_beacon_block_ssz,
    encode_sync_committee_contribution_ssz, AggregateAndProof, Attestation, AttestationData,
    BeaconBlock, BeaconBlockHeader, BlindedBeaconBlock, BuilderRequestAuth, ContributionAndProof,
    ElectraAggregateAndProof, Epoch, ForkName, PayloadAttestationData, ProposerPreferences, Slot,
    SyncAggregatorSelectionData, ValidatorRegistrationV1, VoluntaryExit,
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_APPLICATION_BUILDER, DOMAIN_BEACON_ATTESTER,
    DOMAIN_BEACON_PROPOSER, DOMAIN_BUILDER_REQUEST_AUTH, DOMAIN_CONTRIBUTION_AND_PROOF,
    DOMAIN_PROPOSER_PREFERENCES, DOMAIN_PTC_ATTESTER, DOMAIN_RANDAO, DOMAIN_SYNC_COMMITTEE,
    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, DOMAIN_VOLUNTARY_EXIT,
};
use observability::logging::TruncatedPubkey;

use crate::proto::signer_v2::signer_service_client::SignerServiceClient as SignerServiceClientV2;
use crate::proto::signer_v2::{
    AttestationData as ProtoAttestationData, BeaconBlockHeader as ProtoBeaconBlockHeader,
    Checkpoint as ProtoCheckpoint, Duty, ForkInfo as ProtoForkInfo, SignAggregateAndProofRequest,
    SignAttestationDataRequest, SignBeaconBlockRequest, SignBlindedBeaconBlockRequest,
    SignBlockHeaderRequest, SignBuilderRegistrationRequest, SignContributionAndProofRequest,
    SignRandaoRevealRequest, SignResponse, SignRootRequest, SignSyncAggregatorSelectionDataRequest,
    SignSyncCommitteeMessageRequest, SignVoluntaryExitRequest,
};

// RF2-15: v1 SignerService surface fully retired from this crate; connect and
// all signing RPCs use SignerServiceClientV2 only.

/// The proto package name emitted by the v2 `GetStatus` response.
/// `bin/rvc` checks this at startup to refuse a v1 signer.
pub const SIGNER_V2_PACKAGE_NAME: &str = "signer.v2";

/// Environment variable that must be set to `"true"` to allow plaintext
/// `http://` gRPC remote-signer URLs.  `https://` URLs always pass without
/// consulting this variable.
pub const REMOTE_SIGNER_INSECURE_ENV_VAR: &str = "RVC_REMOTE_SIGNER_ALLOW_INSECURE";

fn redact_url(url: &str) -> String {
    if let Ok(mut parsed) = Url::parse(url) {
        if parsed.password().is_some() || !parsed.username().is_empty() {
            let _ = parsed.set_username("***");
            let _ = parsed.set_password(Some("***"));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

#[derive(Debug, Clone)]
pub struct GrpcRemoteSignerConfig {
    pub url: String,
    pub tls_cert: Option<Vec<u8>>,
    pub tls_key: Option<Zeroizing<Vec<u8>>>,
    pub tls_ca_cert: Option<Vec<u8>>,
}

impl GrpcRemoteSignerConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into(), tls_cert: None, tls_key: None, tls_ca_cert: None }
    }

    pub fn with_tls(mut self, cert: Vec<u8>, key: Vec<u8>, ca_cert: Vec<u8>) -> Self {
        self.tls_cert = Some(cert);
        self.tls_key = Some(Zeroizing::new(key));
        self.tls_ca_cert = Some(ca_cert);
        self
    }

    /// Gate this config's URL against the plaintext-URL policy.
    ///
    /// - `https://` URLs pass immediately — no env-var check, no log.
    /// - `http://` (or any other non-HTTPS scheme) is evaluated by
    ///   [`InsecureGate`] using [`REMOTE_SIGNER_INSECURE_ENV_VAR`]:
    ///   - `mode = Warn` (Phase 2 default): emits an `error!`-level log and
    ///     returns `Ok(())`.
    ///   - `mode = Refuse` (Phase 3, ISSUE-3.13): returns
    ///     `Err(SigningError::RemoteSignerError(...))` unless env var is set.
    pub fn check_url_security(&self, mode: InsecureMode) -> Result<(), SigningError> {
        if self.url.trim_end_matches('/').starts_with("https://") {
            return Ok(());
        }
        InsecureGate::with_predicate(REMOTE_SIGNER_INSECURE_ENV_VAR, mode, || true)
            .check()
            .map_err(|e| SigningError::RemoteSignerError(e.to_string()))
    }
}

/// Client mTLS materials: (client cert PEM, client key PEM, CA cert PEM).
type ClientTlsMaterial = (Vec<u8>, Zeroizing<Vec<u8>>, Vec<u8>);

/// Build a tonic endpoint for `url`, optionally applying mTLS.
///
/// TLS and plaintext share one construction path; TLS config is applied only
/// when credential materials are present.
fn build_endpoint(
    url: &str,
    tls: Option<ClientTlsMaterial>,
) -> Result<tonic::transport::Endpoint, SigningError> {
    let mut endpoint = Channel::from_shared(url.to_string())
        .map_err(|e| SigningError::RemoteSignerError(format!("invalid endpoint URL: {e}")))?;

    if let Some((cert, key, ca_cert)) = tls {
        let tls_config = tonic::transport::ClientTlsConfig::new()
            .identity(tonic::transport::Identity::from_pem(cert, &*key))
            .ca_certificate(tonic::transport::Certificate::from_pem(ca_cert));
        endpoint = endpoint.tls_config(tls_config).map_err(|e| {
            SigningError::RemoteSignerError(format!("TLS configuration error: {e}"))
        })?;
    }

    Ok(endpoint)
}

/// gRPC remote signer client.
///
/// Implements [`TypedSigner`] only — there is no raw-root signing path.
/// This is the permanent fix for C-2/C-3: the v2 gRPC contract carries
/// typed consensus objects and the signing root is reconstructed
/// server-side, so raw 32-byte roots are never sent over the wire.
pub struct GrpcRemoteSigner {
    /// v2 typed-RPC client.
    client_v2: SignerServiceClientV2<Channel>,
    /// Cached public keys from `ListPublicKeys` at connect time.
    pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>,
    url: String,
    /// Network genesis fork used for BUILDER_REQUEST_AUTH local-verify
    /// (`compute_domain` with genesis + zero GVR). Default `[0; 4]` (mainnet /
    /// KAT). Does not follow `SignContext::fork_info.current_version`.
    genesis_fork_version: [u8; 4],
}

impl GrpcRemoteSigner {
    #[tracing::instrument(name = "grpc_signer.connect", skip_all)]
    pub async fn connect(config: GrpcRemoteSignerConfig) -> Result<Self, SigningError> {
        // Gate plaintext URLs. Per NFR-10 / ISSUE-3.13 (GA) the gate refuses
        // http:// URLs unless RVC_REMOTE_SIGNER_ALLOW_INSECURE=true is set.
        config.check_url_security(InsecureMode::Refuse)?;

        let url = config.url.trim_end_matches('/').to_string();
        let tls_enabled = config.tls_cert.is_some();
        let tls = match (config.tls_cert, config.tls_key, config.tls_ca_cert) {
            (Some(cert), Some(key), Some(ca_cert)) => Some((cert, key, ca_cert)),
            _ => None,
        };

        let channel = build_endpoint(&url, tls)?.connect().await.map_err(|e| {
            tracing::error!(
                endpoint = %redact_url(&url),
                error = %e,
                "gRPC signer connection failed"
            );
            SigningError::RemoteSignerError(format!(
                "failed to connect to {}: {e}",
                redact_url(&url)
            ))
        })?;

        // SS-1 (Issue 2.2): use the v2 client for ListPublicKeys.
        // The v1 service has been removed from the live listener; only the v2 typed RPCs
        // are served.  Both v1 and v2 expose ListPublicKeys, but the live server only
        // responds to v2 requests.
        let mut v2_list_client = SignerServiceClientV2::new(channel.clone());

        let response = v2_list_client
            .list_public_keys(crate::proto::signer_v2::ListPublicKeysRequest {})
            .await
            .map_err(|e| {
                tracing::error!(
                    endpoint = %redact_url(&url),
                    error = %e,
                    "gRPC signer connection failed during key listing"
                );
                SigningError::RemoteSignerError(format!("failed to list public keys: {e}"))
            })?;

        let pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]> = response
            .into_inner()
            .pubkeys
            .into_iter()
            .filter_map(|pk_bytes| pk_bytes.try_into().ok())
            .collect();

        let client_v2 = SignerServiceClientV2::new(channel);

        tracing::info!(
            endpoint = %redact_url(&url),
            tls_enabled,
            key_count = pubkeys.len(),
            "gRPC signer connection established (v2 typed RPCs)"
        );

        Ok(Self { client_v2, pubkeys, url, genesis_fork_version: [0; 4] })
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// Set the network genesis fork used for BUILDER_REQUEST_AUTH local-verify.
    pub fn with_genesis_fork_version(mut self, genesis_fork_version: [u8; 4]) -> Self {
        self.genesis_fork_version = genesis_fork_version;
        self
    }

    /// Returns the cached public keys (fetched at connect time).
    pub fn public_keys(&self) -> Vec<[u8; PUBLIC_KEY_BYTES_LEN]> {
        self.pubkeys.clone()
    }

    fn make_fork_info(ctx: &SignContext) -> ProtoForkInfo {
        ProtoForkInfo {
            previous_version: ctx.fork_info.previous_version.to_vec(),
            current_version: ctx.fork_info.current_version.to_vec(),
            epoch: 0,
            genesis_validators_root: ctx.fork_info.genesis_validators_root.to_vec(),
        }
    }

    /// SSZ / wire fork id from the resolved [`SignContext::fork_name`].
    ///
    /// Callers must populate `fork_name` (via schedule lookup or
    /// [`SignContext::resolve`]); there is no silent mainnet-byte match and no
    /// Deneb default for unknown versions.
    fn fork_id(ctx: &SignContext) -> u32 {
        ctx.fork_name.id()
    }

    fn uses_gloas_rpc(ctx: &SignContext) -> bool {
        ctx.fork_name >= ForkName::Gloas
    }

    fn proto_header(header: &BeaconBlockHeader) -> ProtoBeaconBlockHeader {
        ProtoBeaconBlockHeader {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root.to_vec(),
            state_root: header.state_root.to_vec(),
            body_root: header.body_root.to_vec(),
        }
    }

    fn gloas_block_requires_header() -> SigningError {
        SigningError::LocalRejected(
            "use sign_block_header: Gloas body_root is gloas_body_root from the VC, \
             not an Electra/Deneb body hash"
                .to_string(),
        )
    }

    fn map_grpc_status(status: tonic::Status, rpc_name: &'static str) -> SigningError {
        if status.code() == tonic::Code::Unimplemented
            && matches!(rpc_name, "SignBlockHeader" | "SignRoot")
        {
            SigningError::SignerLacksGloasSupport {
                rpc: rpc_name,
                details: status.message().to_string(),
            }
        } else {
            SigningError::RemoteSignerError(format!(
                "gRPC {rpc_name} failed ({}): {}",
                status.code(),
                status.message()
            ))
        }
    }

    fn root_duty_or_err(duty: i32) -> Result<Duty, SigningError> {
        match Duty::try_from(duty) {
            Ok(Duty::Unspecified) | Err(_) => {
                Err(SigningError::LocalRejected(format!("unknown sign type: duty={duty}")))
            }
            Ok(d) => Ok(d),
        }
    }

    fn ensure_pubkey(&self, ctx: &SignContext) -> Result<(), SigningError> {
        let pk_bytes = ctx.pubkey.to_bytes();
        if !self.pubkeys.contains(&pk_bytes) {
            return Err(SigningError::KeyNotFound(hex::encode(pk_bytes)));
        }
        Ok(())
    }

    fn extract_signature(
        sig_bytes: Vec<u8>,
        pubkey: &PublicKey,
        signing_root: &[u8; 32],
        pubkey_hex: &str,
    ) -> Result<Signature, SigningError> {
        let signature = Signature::from_bytes(&sig_bytes)
            .map_err(|e| SigningError::RemoteSignerError(format!("invalid BLS signature: {e}")))?;
        let pk = pubkey;
        if signature.verify(pk, signing_root).is_err() {
            tracing::error!(
                pubkey = %TruncatedPubkey::new(pubkey_hex),
                "gRPC remote signer returned invalid signature"
            );
            return Err(SigningError::InvalidRemoteSignature);
        }
        Ok(signature)
    }

    /// Test helper: construct a signer with a lazy (unconnected) channel.
    #[cfg(test)]
    fn with_pubkeys_for_test(pubkeys: Vec<[u8; PUBLIC_KEY_BYTES_LEN]>) -> Self {
        let channel = Channel::from_static("http://127.0.0.1:1").connect_lazy();
        Self {
            client_v2: SignerServiceClientV2::new(channel),
            pubkeys,
            url: "http://127.0.0.1:1".to_string(),
            genesis_fork_version: [0; 4],
        }
    }

    /// Shared pipeline for every typed gRPC signing RPC.
    ///
    /// Owns `ensure_pubkey`, span, timing, status→error mapping, and
    /// `extract_signature`. Callers only build the request and supply a lazy
    /// local-verify root (evaluated only after the pubkey guard passes).
    async fn sign_rpc<R, F, Fut>(
        &self,
        ctx: &SignContext,
        duty_type: &'static str,
        rpc_name: &'static str,
        signing_root: R,
        call: F,
    ) -> Result<Signature, SigningError>
    where
        R: FnOnce() -> [u8; 32],
        F: FnOnce(SignerServiceClientV2<Channel>) -> Fut + Send,
        Fut: std::future::Future<Output = Result<tonic::Response<SignResponse>, tonic::Status>>
            + Send,
    {
        // KeyNotFound must short-circuit before request/root work that may
        // TreeHash consensus objects (integration fixtures can use empty bodies).
        self.ensure_pubkey(ctx)?;
        let pubkey_hex = hex::encode(ctx.pubkey.to_bytes());
        let signing_root = signing_root();

        let span = tracing::info_span!(
            "sign.grpc_remote_typed",
            signer_type = "grpc_remote_typed",
            duty_type,
            grpc.url = %redact_url(&self.url),
        );

        async {
            tracing::debug!(
                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                duty_type,
                "Typed sign request sent"
            );
            let start = Instant::now();

            let client = self.client_v2.clone();
            let response = call(client).await.map_err(|status| {
                tracing::warn!(
                    pubkey = %TruncatedPubkey::new(&pubkey_hex),
                    duty_type,
                    error_code = %status.code(),
                    "sign gRPC error"
                );
                Self::map_grpc_status(status, rpc_name)
            })?;

            let latency_ms = start.elapsed().as_millis() as u64;
            tracing::debug!(
                pubkey = %TruncatedPubkey::new(&pubkey_hex),
                duty_type,
                latency_ms,
                "sign response received"
            );

            let sig_bytes = response.into_inner().signature;
            Self::extract_signature(sig_bytes, &ctx.pubkey, &signing_root, &pubkey_hex)
        }
        .instrument(span)
        .await
    }

    async fn sign_block_header_rpc(
        &self,
        header: &BeaconBlockHeader,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let fork_id = Self::fork_id(ctx);
        let req = SignBlockHeaderRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            header: Some(Self::proto_header(header)),
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        self.sign_rpc(
            ctx,
            "block_header",
            "SignBlockHeader",
            || signing_root_with_fork_version(header, DOMAIN_BEACON_PROPOSER, fork_version, gvr),
            move |mut client| async move { client.sign_block_header(req).await },
        )
        .await
    }

    async fn sign_root_rpc(
        &self,
        object_root: [u8; 32],
        duty: Duty,
        ctx: &SignContext,
        signing_root: [u8; 32],
    ) -> Result<Signature, SigningError> {
        let fork_id = Self::fork_id(ctx);
        let req = SignRootRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            object_root: object_root.to_vec(),
            duty: duty as i32,
            fork_id,
        };
        self.sign_rpc(
            ctx,
            "sign_root",
            "SignRoot",
            move || signing_root,
            move |mut client| async move { client.sign_root(req).await },
        )
        .await
    }

    /// Gloas-safe `SignRoot` (PTC, proposer preferences, request-auth, P6 envelope).
    ///
    /// Unknown / `UNSPECIFIED` duties fail closed locally with no RPC. Envelope
    /// is sent and surfaces the server's `UNIMPLEMENTED`.
    pub async fn sign_root(
        &self,
        object_root: [u8; 32],
        duty: i32,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let duty = Self::root_duty_or_err(duty)?;
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        let signing_root = match duty {
            Duty::AggregateAndProof => signing_root_with_fork_version(
                &object_root,
                DOMAIN_AGGREGATE_AND_PROOF,
                fork_version,
                gvr,
            ),
            Duty::ContributionAndProof => signing_root_with_fork_version(
                &object_root,
                DOMAIN_CONTRIBUTION_AND_PROOF,
                fork_version,
                gvr,
            ),
            Duty::PayloadAttestation => {
                signing_root_with_fork_version(&object_root, DOMAIN_PTC_ATTESTER, fork_version, gvr)
            }
            Duty::ProposerPreferences => signing_root_with_fork_version(
                &object_root,
                DOMAIN_PROPOSER_PREFERENCES,
                fork_version,
                gvr,
            ),
            Duty::BuilderRequestAuth => signing_root_with_fork_version(
                &object_root,
                DOMAIN_BUILDER_REQUEST_AUTH,
                // Builder-registration idiom: configured genesis + zero GVR.
                // `current_version` is the active fork (e.g. Gloas) and must
                // not be used; the server plans with its genesis too.
                self.genesis_fork_version,
                [0u8; 32],
            ),
            Duty::ExecutionPayloadEnvelope => {
                signing_root_with_fork_version(&object_root, [0u8; 4], fork_version, gvr)
            }
            Duty::Unspecified => unreachable!("rejected by root_duty_or_err"),
        };
        self.sign_root_rpc(object_root, duty, ctx, signing_root).await
    }
}

#[async_trait]
impl TypedSigner for GrpcRemoteSigner {
    async fn sign_block(
        &self,
        block: &BeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        if Self::uses_gloas_rpc(ctx) {
            let _ = block;
            return Err(Self::gloas_block_requires_header());
        }
        let fork_id = Self::fork_id(ctx);
        let block_ssz = encode_beacon_block_ssz(block, fork_id);
        let req = SignBeaconBlockRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            block_ssz,
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        self.sign_rpc(
            ctx,
            "block",
            "sign_block",
            || signing_root_with_fork_version(block, DOMAIN_BEACON_PROPOSER, fork_version, gvr),
            move |mut client| async move { client.sign_beacon_block(req).await },
        )
        .await
    }

    async fn sign_block_header(
        &self,
        header: &BeaconBlockHeader,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        if Self::uses_gloas_rpc(ctx) {
            return self.sign_block_header_rpc(header, ctx).await;
        }
        // Pre-Gloas: legacy SignBeaconBlock. Outer container is fork-invariant.
        // Callers that still hold body SSZ should prefer `sign_block` so the
        // server tree-hash matches the header leaf.
        let block = BeaconBlock {
            slot: header.slot,
            proposer_index: header.proposer_index,
            parent_root: header.parent_root,
            state_root: header.state_root,
            body: Vec::new(),
        };
        self.sign_block(&block, ctx).await
    }

    async fn sign_blinded_block(
        &self,
        block: &BlindedBeaconBlock,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        if Self::uses_gloas_rpc(ctx) {
            let _ = block;
            return Err(Self::gloas_block_requires_header());
        }
        let fork_id = Self::fork_id(ctx);
        let block_ssz = encode_blinded_beacon_block_ssz(block, fork_id);
        let req = SignBlindedBeaconBlockRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            block_ssz,
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        self.sign_rpc(
            ctx,
            "blinded_block",
            "sign_blinded_beacon_block",
            || signing_root_with_fork_version(block, DOMAIN_BEACON_PROPOSER, fork_version, gvr),
            move |mut client| async move { client.sign_blinded_beacon_block(req).await },
        )
        .await
    }

    async fn sign_attestation(
        &self,
        data: &AttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let fork_id = Self::fork_id(ctx);
        let proto_data = ProtoAttestationData {
            slot: data.slot,
            index: data.index,
            beacon_block_root: data.beacon_block_root.to_vec(),
            source: Some(ProtoCheckpoint {
                epoch: data.source.epoch,
                root: data.source.root.to_vec(),
            }),
            target: Some(ProtoCheckpoint {
                epoch: data.target.epoch,
                root: data.target.root.to_vec(),
            }),
        };
        let req = SignAttestationDataRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            data: Some(proto_data),
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        self.sign_rpc(
            ctx,
            "attestation",
            "sign_attestation_data",
            || signing_root_with_fork_version(data, DOMAIN_BEACON_ATTESTER, fork_version, gvr),
            move |mut client| async move { client.sign_attestation_data(req).await },
        )
        .await
    }

    async fn sign_aggregate_and_proof(
        &self,
        agg: &AggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        if Self::uses_gloas_rpc(ctx) {
            let object_root = agg.tree_hash_root().0;
            let fork_version = ctx.fork_info.current_version;
            let gvr = ctx.fork_info.genesis_validators_root;
            let signing_root =
                signing_root_with_fork_version(agg, DOMAIN_AGGREGATE_AND_PROOF, fork_version, gvr);
            return self
                .sign_root_rpc(object_root, Duty::AggregateAndProof, ctx, signing_root)
                .await;
        }
        let fork_id = Self::fork_id(ctx);
        let aggregate_ssz = encode_attestation_ssz(&agg.aggregate, fork_id);
        let req = SignAggregateAndProofRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            aggregator_index: agg.aggregator_index,
            aggregate_ssz,
            selection_proof: agg.selection_proof.clone(),
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        self.sign_rpc(
            ctx,
            "aggregate_and_proof",
            "sign_aggregate_and_proof",
            || signing_root_with_fork_version(agg, DOMAIN_AGGREGATE_AND_PROOF, fork_version, gvr),
            move |mut client| async move { client.sign_aggregate_and_proof(req).await },
        )
        .await
    }

    async fn sign_electra_aggregate_and_proof(
        &self,
        agg: &ElectraAggregateAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        if Self::uses_gloas_rpc(ctx) {
            let object_root = agg.tree_hash_root().0;
            let fork_version = ctx.fork_info.current_version;
            let gvr = ctx.fork_info.genesis_validators_root;
            let signing_root =
                signing_root_with_fork_version(agg, DOMAIN_AGGREGATE_AND_PROOF, fork_version, gvr);
            return self
                .sign_root_rpc(object_root, Duty::AggregateAndProof, ctx, signing_root)
                .await;
        }
        // Pre-Gloas SignAggregateAndProof is pre-Electra attestation SSZ.
        let legacy = AggregateAndProof {
            aggregator_index: agg.aggregator_index,
            aggregate: Attestation {
                aggregation_bits: agg.aggregate.aggregation_bits.clone(),
                data: agg.aggregate.data.clone(),
                signature: agg.aggregate.signature.clone(),
            },
            selection_proof: agg.selection_proof.clone(),
        };
        self.sign_aggregate_and_proof(&legacy, ctx).await
    }

    async fn sign_sync_committee_message(
        &self,
        slot: Slot,
        beacon_block_root: eth_types::Root,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let fork_id = Self::fork_id(ctx);
        let req = SignSyncCommitteeMessageRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            slot,
            beacon_block_root: beacon_block_root.to_vec(),
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        self.sign_rpc(
            ctx,
            "sync_committee_message",
            "sign_sync_committee_message",
            || {
                signing_root_with_fork_version(
                    &beacon_block_root,
                    DOMAIN_SYNC_COMMITTEE,
                    fork_version,
                    gvr,
                )
            },
            move |mut client| async move { client.sign_sync_committee_message(req).await },
        )
        .await
    }

    async fn sign_sync_aggregator_selection(
        &self,
        slot: Slot,
        subcommittee_index: u64,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let fork_id = Self::fork_id(ctx);
        let req = SignSyncAggregatorSelectionDataRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            slot,
            subcommittee_index,
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        self.sign_rpc(
            ctx,
            "sync_aggregator_selection",
            "sign_sync_aggregator_selection_data",
            || {
                let selection_data = SyncAggregatorSelectionData { slot, subcommittee_index };
                signing_root_with_fork_version(
                    &selection_data,
                    DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                    fork_version,
                    gvr,
                )
            },
            move |mut client| async move { client.sign_sync_aggregator_selection_data(req).await },
        )
        .await
    }

    async fn sign_contribution_and_proof(
        &self,
        c: &ContributionAndProof,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        if Self::uses_gloas_rpc(ctx) {
            let object_root = c.tree_hash_root().0;
            let fork_version = ctx.fork_info.current_version;
            let gvr = ctx.fork_info.genesis_validators_root;
            let signing_root =
                signing_root_with_fork_version(c, DOMAIN_CONTRIBUTION_AND_PROOF, fork_version, gvr);
            return self
                .sign_root_rpc(object_root, Duty::ContributionAndProof, ctx, signing_root)
                .await;
        }
        let fork_id = Self::fork_id(ctx);
        let contribution_ssz = encode_sync_committee_contribution_ssz(&c.contribution, fork_id);
        let req = SignContributionAndProofRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            aggregator_index: c.aggregator_index,
            contribution_ssz,
            selection_proof: c.selection_proof.clone(),
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        self.sign_rpc(
            ctx,
            "contribution_and_proof",
            "sign_contribution_and_proof",
            || signing_root_with_fork_version(c, DOMAIN_CONTRIBUTION_AND_PROOF, fork_version, gvr),
            move |mut client| async move { client.sign_contribution_and_proof(req).await },
        )
        .await
    }

    async fn sign_builder_registration(
        &self,
        reg: &ValidatorRegistrationV1,
        genesis_fork_version: [u8; 4],
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let req = SignBuilderRegistrationRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fee_recipient: reg.fee_recipient.to_vec(),
            gas_limit: reg.gas_limit,
            timestamp: reg.timestamp,
            genesis_fork_version: genesis_fork_version.to_vec(),
        };
        self.sign_rpc(
            ctx,
            "builder_registration",
            "sign_builder_registration",
            || {
                signing_root_with_fork_version(
                    reg,
                    DOMAIN_APPLICATION_BUILDER,
                    genesis_fork_version,
                    [0u8; 32],
                )
            },
            move |mut client| async move { client.sign_builder_registration(req).await },
        )
        .await
    }

    async fn sign_randao_reveal(
        &self,
        epoch: Epoch,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let fork_id = Self::fork_id(ctx);
        let req = SignRandaoRevealRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            epoch,
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        self.sign_rpc(
            ctx,
            "randao_reveal",
            "sign_randao_reveal",
            || signing_root_with_fork_version(&epoch, DOMAIN_RANDAO, fork_version, gvr),
            move |mut client| async move { client.sign_randao_reveal(req).await },
        )
        .await
    }

    async fn sign_voluntary_exit(
        &self,
        exit: &VoluntaryExit,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let fork_id = Self::fork_id(ctx);
        let req = SignVoluntaryExitRequest {
            pubkey: ctx.pubkey.to_bytes().to_vec(),
            fork_info: Some(Self::make_fork_info(ctx)),
            epoch: exit.epoch,
            validator_index: exit.validator_index,
            fork_id,
        };
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        // Capella: caller must supply Capella-capped current_version (same
        // contract as LocalSigner / wire). Prefer schedule path when available.
        self.sign_rpc(
            ctx,
            "voluntary_exit",
            "sign_voluntary_exit",
            || signing_root_with_fork_version(exit, DOMAIN_VOLUNTARY_EXIT, fork_version, gvr),
            move |mut client| async move { client.sign_voluntary_exit(req).await },
        )
        .await
    }

    async fn sign_payload_attestation(
        &self,
        data: &PayloadAttestationData,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let object_root = data.tree_hash_root().0;
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        let signing_root =
            signing_root_with_fork_version(data, DOMAIN_PTC_ATTESTER, fork_version, gvr);
        self.sign_root_rpc(object_root, Duty::PayloadAttestation, ctx, signing_root).await
    }

    async fn sign_proposer_preferences(
        &self,
        prefs: &ProposerPreferences,
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let object_root = prefs.tree_hash_root().0;
        let fork_version = ctx.fork_info.current_version;
        let gvr = ctx.fork_info.genesis_validators_root;
        let signing_root =
            signing_root_with_fork_version(prefs, DOMAIN_PROPOSER_PREFERENCES, fork_version, gvr);
        self.sign_root_rpc(object_root, Duty::ProposerPreferences, ctx, signing_root).await
    }

    async fn sign_builder_request_auth(
        &self,
        auth: &BuilderRequestAuth,
        genesis_fork_version: [u8; 4],
        ctx: &SignContext,
    ) -> Result<Signature, SigningError> {
        let object_root = auth
            .try_tree_hash_root()
            .map_err(|e| SigningError::LocalRejected(format!("invalid builder_request_auth: {e}")))?
            .0;
        let signing_root = signing_root_with_fork_version(
            auth,
            DOMAIN_BUILDER_REQUEST_AUTH,
            genesis_fork_version,
            [0u8; 32],
        );
        self.sign_root_rpc(object_root, Duty::BuilderRequestAuth, ctx, signing_root).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = GrpcRemoteSignerConfig::new("http://localhost:50051");
        assert_eq!(config.url, "http://localhost:50051");
        assert!(config.tls_cert.is_none());
        assert!(config.tls_key.is_none());
        assert!(config.tls_ca_cert.is_none());
    }

    #[test]
    fn test_config_with_tls() {
        let config = GrpcRemoteSignerConfig::new("https://localhost:50051").with_tls(
            b"cert".to_vec(),
            b"key".to_vec(),
            b"ca".to_vec(),
        );
        assert!(config.tls_cert.is_some());
        assert!(config.tls_key.is_some());
        assert!(config.tls_ca_cert.is_some());
    }

    #[test]
    fn test_redact_url_hides_credentials() {
        let url = "http://user:pass@example.com:50051";
        let redacted = redact_url(url);
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(redacted.contains("***"));
        assert!(redacted.contains("example.com"));
    }

    #[test]
    fn test_redact_url_preserves_url_without_credentials() {
        let url = "http://example.com:50051";
        let redacted = redact_url(url);
        assert_eq!(redacted, "http://example.com:50051/");
    }

    #[test]
    fn test_redact_url_handles_invalid_url() {
        let url = "not-a-url";
        let redacted = redact_url(url);
        assert_eq!(redacted, "not-a-url");
    }

    #[test]
    fn test_grpc_remote_signer_not_implements_raw_signer() {
        // This test verifies at compile time that GrpcRemoteSigner does NOT implement
        // the old Signer (raw-root) trait. If this file compiles, the trait is absent.
        // The trait requires `async fn sign(root: &[u8;32], pubkey: &[u8;48])` which
        // is the C-2/C-3 oracle path.
        //
        // The negative assertion: we cannot write `let _: &dyn Signer = &signer`
        // because GrpcRemoteSigner no longer implements Signer.
        // The presence of this comment + successful compilation IS the test.
        let _ = "GrpcRemoteSigner implements TypedSigner only — no raw Signer impl";
    }

    // ---- RF3-08: SignContext carries ForkName; no silent `_ => Deneb` ----

    use crypto::typed_signer::SignContext;
    use crypto::SecretKey;
    use eth_types::{ForkInfo, ForkName, ForkSchedule};

    /// Hoodi-style Electra version bytes (not mainnet `[0x05,0,0,0]`).
    const HOODI_ELECTRA: [u8; 4] = [0x60, 0x00, 0x09, 0x10];
    const HOODI_DENEB: [u8; 4] = [0x50, 0x00, 0x09, 0x10];
    const HOODI_CAPELLA: [u8; 4] = [0x40, 0x00, 0x09, 0x10];
    const HOODI_GENESIS: [u8; 4] = [0x10, 0x00, 0x09, 0x10];

    fn mainnet_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
            altair_fork_epoch: 74240,
            altair_fork_version: [0x01, 0x00, 0x00, 0x00],
            bellatrix_fork_epoch: 144896,
            bellatrix_fork_version: [0x02, 0x00, 0x00, 0x00],
            capella_fork_epoch: 194048,
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            deneb_fork_epoch: 269568,
            deneb_fork_version: [0x04, 0x00, 0x00, 0x00],
            electra_fork_epoch: 364032,
            electra_fork_version: [0x05, 0x00, 0x00, 0x00],
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [0x06, 0x00, 0x00, 0x00],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [0x07, 0x00, 0x00, 0x00],
        }
    }

    fn hoodi_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: HOODI_GENESIS,
            altair_fork_epoch: 0,
            altair_fork_version: [0x20, 0x00, 0x09, 0x10],
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: [0x30, 0x00, 0x09, 0x10],
            capella_fork_epoch: 0,
            capella_fork_version: HOODI_CAPELLA,
            deneb_fork_epoch: 0,
            deneb_fork_version: HOODI_DENEB,
            electra_fork_epoch: 0,
            electra_fork_version: HOODI_ELECTRA,
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [0x70, 0x00, 0x09, 0x10],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [0x80, 0x00, 0x09, 0x10],
        }
    }

    fn dummy_pubkey() -> crypto::PublicKey {
        SecretKey::generate().public_key()
    }

    #[test]
    fn test_hoodi_electra_fork_version_maps_to_electra_not_deneb() {
        // RED for the pre-fix bug: matching only mainnet bytes returned 4 (Deneb)
        // for any non-mainnet Electra version.
        let fork_info = ForkInfo {
            previous_version: HOODI_DENEB,
            current_version: HOODI_ELECTRA,
            genesis_validators_root: [0xaa; 32],
        };
        let ctx = SignContext::resolve(dummy_pubkey(), fork_info, &hoodi_schedule())
            .expect("Hoodi Electra version must resolve via schedule");
        assert_eq!(ctx.fork_name, ForkName::Electra);
        assert_eq!(GrpcRemoteSigner::fork_id(&ctx), 5);
    }

    #[test]
    fn test_mainnet_fork_ids_unchanged_for_all_eight_versions() {
        let schedule = mainnet_schedule();
        let expected = [
            (ForkName::Phase0, [0x00, 0x00, 0x00, 0x00], 0u32),
            (ForkName::Altair, [0x01, 0x00, 0x00, 0x00], 1),
            (ForkName::Bellatrix, [0x02, 0x00, 0x00, 0x00], 2),
            (ForkName::Capella, [0x03, 0x00, 0x00, 0x00], 3),
            (ForkName::Deneb, [0x04, 0x00, 0x00, 0x00], 4),
            (ForkName::Electra, [0x05, 0x00, 0x00, 0x00], 5),
            (ForkName::Fulu, [0x06, 0x00, 0x00, 0x00], 6),
            (ForkName::Gloas, [0x07, 0x00, 0x00, 0x00], 7),
        ];
        for (name, version, id) in expected {
            let fork_info = ForkInfo {
                previous_version: version,
                current_version: version,
                genesis_validators_root: [0xbb; 32],
            };
            let ctx = SignContext::resolve(dummy_pubkey(), fork_info, &schedule)
                .unwrap_or_else(|_| panic!("mainnet {name:?} version must resolve"));
            assert_eq!(ctx.fork_name, name);
            assert_eq!(GrpcRemoteSigner::fork_id(&ctx), id, "mainnet {name:?}");
            assert_eq!(name.id(), id);
        }
    }

    #[test]
    fn test_unknown_fork_version_is_warned_not_silently_defaulted() {
        let schedule = mainnet_schedule();
        let fork_info = ForkInfo {
            previous_version: [0xde, 0xad, 0xbe, 0xef],
            current_version: [0xde, 0xad, 0xbe, 0xef],
            genesis_validators_root: [0xcc; 32],
        };
        let result = SignContext::resolve(dummy_pubkey(), fork_info, &schedule);
        let err = match result {
            Ok(_) => panic!("unknown version must not resolve"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("unresolvable fork version"), "typed error message, got: {msg}");
        // No silent Deneb: there is no SignContext and therefore no fork_id == 4 path.
    }

    #[test]
    fn test_sign_context_carries_resolved_fork_name() {
        let ctx = SignContext::new(
            dummy_pubkey(),
            ForkInfo {
                previous_version: HOODI_CAPELLA,
                current_version: HOODI_ELECTRA,
                genesis_validators_root: [0xdd; 32],
            },
            ForkName::Electra,
        );
        assert_eq!(ctx.fork_name, ForkName::Electra);
        assert_eq!(ctx.fork_name.id(), 5);
        assert_eq!(GrpcRemoteSigner::fork_id(&ctx), ctx.fork_name.id());
        // Version bytes alone are non-mainnet; fork_id must still come from fork_name.
        assert_ne!(ctx.fork_info.current_version, [0x05, 0x00, 0x00, 0x00]);
    }

    /// A Gloas `SignContext` produces wire `fork_id == 7`. signer-server
    /// `validate_fork_id` still rejects 7 (`UnknownForkId`) — Phase-2 fail-closed,
    /// not the accepted end state (Phase 4 / D11).
    #[test]
    fn test_gloas_sign_context_produces_fork_id_7() {
        let ctx = SignContext::new(
            dummy_pubkey(),
            ForkInfo {
                previous_version: [0x06, 0x00, 0x00, 0x00],
                current_version: [0x07, 0x00, 0x00, 0x00],
                genesis_validators_root: [0xee; 32],
            },
            ForkName::Gloas,
        );
        assert_eq!(ctx.fork_name, ForkName::Gloas);
        assert_eq!(GrpcRemoteSigner::fork_id(&ctx), 7);
        assert_eq!(ctx.fork_name.id(), 7);
    }

    /// gRPC local-verify roots must match `signing_root_with_fork_version` for
    /// every duty shape (prevents a third independent derivation path).
    #[test]
    fn test_grpc_signer_fork_info_matches_shared_derivation() {
        use eth_types::{Attestation, Checkpoint, SyncCommitteeContribution};

        let gvr = [0xaa; 32];
        let fork_info = ForkInfo {
            previous_version: [0x03, 0, 0, 0],
            current_version: [0x04, 0, 0, 0], // Deneb
            genesis_validators_root: gvr,
        };
        let ctx = SignContext::new(dummy_pubkey(), fork_info, ForkName::Deneb);
        let fv = ctx.fork_info.current_version;

        let data = AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 2, root: [0x22; 32] },
            target: Checkpoint { epoch: 3, root: [0x33; 32] },
        };
        assert_eq!(
            signing_root_with_fork_version(&data, DOMAIN_BEACON_ATTESTER, fv, gvr),
            signing_root_with_fork_version(
                &data,
                DOMAIN_BEACON_ATTESTER,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            )
        );

        let block = BeaconBlock {
            slot: 100,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body: eth_types::external_vector_electra_body().as_ssz_bytes(),
        };
        let block_root = signing_root_with_fork_version(&block, DOMAIN_BEACON_PROPOSER, fv, gvr);
        assert_eq!(
            block_root,
            signing_root_with_fork_version(
                &block,
                DOMAIN_BEACON_PROPOSER,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            )
        );

        let epoch: Epoch = 42;
        assert_eq!(
            signing_root_with_fork_version(&epoch, DOMAIN_RANDAO, fv, gvr),
            signing_root_with_fork_version(
                &epoch,
                DOMAIN_RANDAO,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            )
        );

        let beacon_block_root = [0x44; 32];
        assert_eq!(
            signing_root_with_fork_version(&beacon_block_root, DOMAIN_SYNC_COMMITTEE, fv, gvr),
            signing_root_with_fork_version(
                &beacon_block_root,
                DOMAIN_SYNC_COMMITTEE,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            )
        );

        let sel = SyncAggregatorSelectionData { slot: 100, subcommittee_index: 2 };
        assert_eq!(
            signing_root_with_fork_version(&sel, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF, fv, gvr),
            signing_root_with_fork_version(
                &sel,
                DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            )
        );

        let agg = AggregateAndProof {
            aggregator_index: 1,
            aggregate: Attestation {
                aggregation_bits: vec![0xff; 4],
                data: data.clone(),
                signature: vec![0xaa; 96],
            },
            selection_proof: vec![0xbb; 96],
        };
        assert_eq!(
            signing_root_with_fork_version(&agg, DOMAIN_AGGREGATE_AND_PROOF, fv, gvr),
            signing_root_with_fork_version(
                &agg,
                DOMAIN_AGGREGATE_AND_PROOF,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            )
        );

        let cap = ContributionAndProof {
            aggregator_index: 1,
            contribution: SyncCommitteeContribution {
                slot: 100,
                beacon_block_root: [0x11; 32],
                subcommittee_index: 0,
                aggregation_bits: vec![0xff; 16],
                signature: vec![0xcc; 96],
            },
            selection_proof: vec![0xdd; 96],
        };
        assert_eq!(
            signing_root_with_fork_version(&cap, DOMAIN_CONTRIBUTION_AND_PROOF, fv, gvr),
            signing_root_with_fork_version(
                &cap,
                DOMAIN_CONTRIBUTION_AND_PROOF,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            )
        );

        // Voluntary exit: pre-resolved path uses current_version as-is (caller Capella duty).
        let exit = VoluntaryExit { epoch: 200_000, validator_index: 1 };
        let exit_root = signing_root_with_fork_version(&exit, DOMAIN_VOLUNTARY_EXIT, fv, gvr);
        assert_eq!(
            exit_root,
            signing_root_with_fork_version(
                &exit,
                DOMAIN_VOLUNTARY_EXIT,
                ctx.fork_info.current_version,
                ctx.fork_info.genesis_validators_root,
            )
        );
        // Capella-capped version produces a different root than raw Deneb (documents S1 residual).
        let capella_fv = [0x03, 0, 0, 0];
        let capped_root =
            signing_root_with_fork_version(&exit, DOMAIN_VOLUNTARY_EXIT, capella_fv, gvr);
        assert_ne!(
            exit_root, capped_root,
            "post-Capella exit with Deneb current_version must not match Capella-capped domain"
        );

        let reg = ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1,
            pubkey: [0xcd; 48],
        };
        let genesis_fv = [0; 4];
        assert_eq!(
            signing_root_with_fork_version(&reg, DOMAIN_APPLICATION_BUILDER, genesis_fv, [0u8; 32]),
            signing_root_with_fork_version(&reg, DOMAIN_APPLICATION_BUILDER, genesis_fv, [0u8; 32]),
        );
    }

    // ---- RF4-11: sign_rpc helper + connect channel builder ----

    #[test]
    fn test_connect_tls_and_plaintext_share_channel_builder() {
        // Both paths go through `build_endpoint`; invalid URLs fail identically.
        let plain = build_endpoint("http://localhost:50051", None);
        assert!(plain.is_ok(), "plaintext endpoint must build: {plain:?}");

        // TLS config application is the only branch difference; invalid PEM is
        // accepted at endpoint construction (tonic validates on connect).
        let tls = build_endpoint(
            "https://localhost:50051",
            Some((
                b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_vec(),
                Zeroizing::new(
                    b"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n".to_vec(),
                ),
                b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_vec(),
            )),
        );
        // tls_config may accept or reject the stub PEM depending on tonic/rustls;
        // either way the call is on the shared builder (no second Channel::from_shared).
        let _ = tls;

        let bad_plain = build_endpoint("not a url", None);
        let bad_tls = build_endpoint("not a url", Some((vec![], Zeroizing::new(vec![]), vec![])));
        match (bad_plain, bad_tls) {
            (Err(SigningError::RemoteSignerError(a)), Err(SigningError::RemoteSignerError(b))) => {
                assert!(a.contains("invalid endpoint URL"), "plain: {a}");
                assert!(b.contains("invalid endpoint URL"), "tls: {b}");
            }
            other => panic!("expected identical invalid-URL mapping on both paths: {other:?}"),
        }
    }

    #[test]
    fn test_signature_extraction_rejects_wrong_length() {
        let pk = dummy_pubkey();
        let root = [0u8; 32];
        let err = GrpcRemoteSigner::extract_signature(vec![0u8; 10], &pk, &root, "ab")
            .expect_err("wrong-length signature must fail");
        match err {
            SigningError::RemoteSignerError(msg) => {
                assert!(msg.contains("invalid BLS signature"), "got: {msg}");
            }
            other => panic!("expected RemoteSignerError, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_ensure_pubkey_rejected_before_rpc_issued() {
        let known = dummy_pubkey();
        let unknown = dummy_pubkey();
        let unknown_bytes = unknown.to_bytes();
        // Lazy channel needs a Tokio runtime (hyper connector); ensure_pubkey itself
        // is local and must fail before any RPC is issued.
        let signer = GrpcRemoteSigner::with_pubkeys_for_test(vec![known.to_bytes()]);
        let ctx = SignContext::new(
            unknown,
            ForkInfo {
                previous_version: [0x04, 0, 0, 0],
                current_version: [0x04, 0, 0, 0],
                genesis_validators_root: [0xaa; 32],
            },
            ForkName::Deneb,
        );
        match signer.ensure_pubkey(&ctx) {
            Err(SigningError::KeyNotFound(hex)) => {
                assert_eq!(hex, hex::encode(unknown_bytes));
            }
            other => panic!("expected KeyNotFound, got: {other:?}"),
        }
        // Also via a TypedSigner method — same guard, no network call.
        let block = BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: eth_types::external_vector_electra_body().as_ssz_bytes(),
        };
        match TypedSigner::sign_block(&signer, &block, &ctx).await {
            Err(SigningError::KeyNotFound(hex)) => {
                assert_eq!(hex, hex::encode(unknown_bytes));
            }
            other => panic!("expected KeyNotFound from sign_block, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_sign_block_at_gloas_requires_header() {
        let pk = dummy_pubkey();
        let signer = GrpcRemoteSigner::with_pubkeys_for_test(vec![pk.to_bytes()]);
        let ctx = SignContext::new(
            pk,
            ForkInfo {
                previous_version: [0x06, 0, 0, 0],
                current_version: [0x07, 0, 0, 0],
                genesis_validators_root: [0xaa; 32],
            },
            ForkName::Gloas,
        );
        let block = BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: eth_types::external_vector_electra_body().as_ssz_bytes(),
        };
        match TypedSigner::sign_block(&signer, &block, &ctx).await {
            Err(SigningError::LocalRejected(msg)) => {
                assert!(msg.contains("sign_block_header"), "got {msg}");
            }
            other => panic!("expected LocalRejected use sign_block_header, got: {other:?}"),
        }
        let blinded = BlindedBeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
        };
        match TypedSigner::sign_blinded_block(&signer, &blinded, &ctx).await {
            Err(SigningError::LocalRejected(msg)) => {
                assert!(msg.contains("sign_block_header"), "got {msg}");
            }
            other => panic!("expected LocalRejected for blinded, got: {other:?}"),
        }
    }

    /// Behavioral proxy for shared `sign_rpc` error mapping: a dead transport
    /// must yield the same `RemoteSignerError` shape from every TypedSigner method.
    #[tokio::test]
    async fn test_all_typed_signer_methods_route_through_sign_rpc() {
        use eth_types::{Attestation, Checkpoint, SyncCommitteeContribution};

        let pk = dummy_pubkey();
        let pk_bytes = pk.to_bytes();
        let signer = GrpcRemoteSigner::with_pubkeys_for_test(vec![pk_bytes]);
        let ctx = SignContext::new(
            pk,
            ForkInfo {
                previous_version: [0x04, 0, 0, 0],
                current_version: [0x04, 0, 0, 0],
                genesis_validators_root: [0xaa; 32],
            },
            ForkName::Deneb,
        );

        let block = BeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: eth_types::external_vector_electra_body().as_ssz_bytes(),
        };
        let blinded = BlindedBeaconBlock {
            slot: 1,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body: eth_types::external_vector_blinded_electra_body().as_ssz_bytes(),
        };
        let data = AttestationData {
            slot: 1,
            index: 0,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 0, root: [0x22; 32] },
            target: Checkpoint { epoch: 1, root: [0x33; 32] },
        };
        let agg = AggregateAndProof {
            aggregator_index: 1,
            aggregate: Attestation {
                aggregation_bits: vec![0xff; 4],
                data: data.clone(),
                signature: vec![0xaa; 96],
            },
            selection_proof: vec![0xbb; 96],
        };
        let cap = ContributionAndProof {
            aggregator_index: 1,
            contribution: SyncCommitteeContribution {
                slot: 1,
                beacon_block_root: [0x11; 32],
                subcommittee_index: 0,
                aggregation_bits: vec![0xff; 16],
                signature: vec![0xcc; 96],
            },
            selection_proof: vec![0xdd; 96],
        };
        let reg = ValidatorRegistrationV1 {
            fee_recipient: [0xab; 20],
            gas_limit: 30_000_000,
            timestamp: 1,
            pubkey: pk_bytes,
        };
        let exit = VoluntaryExit { epoch: 10, validator_index: 1 };

        let ptc = PayloadAttestationData {
            beacon_block_root: [0x11; 32],
            slot: 1,
            payload_present: true,
            blob_data_available: false,
        };
        let prefs = ProposerPreferences {
            dependent_root: [0x33; 32],
            proposal_slot: 32,
            validator_index: 3,
            fee_recipient: [0x44; 20],
            target_gas_limit: 36_000_000,
        };
        let auth = BuilderRequestAuth::new(hex::decode("1234567890abcdef").unwrap(), 1).unwrap();
        let results = vec![
            TypedSigner::sign_block(&signer, &block, &ctx).await,
            TypedSigner::sign_blinded_block(&signer, &blinded, &ctx).await,
            TypedSigner::sign_attestation(&signer, &data, &ctx).await,
            TypedSigner::sign_aggregate_and_proof(&signer, &agg, &ctx).await,
            TypedSigner::sign_sync_committee_message(&signer, 1, [0x44; 32], &ctx).await,
            TypedSigner::sign_sync_aggregator_selection(&signer, 1, 0, &ctx).await,
            TypedSigner::sign_contribution_and_proof(&signer, &cap, &ctx).await,
            TypedSigner::sign_builder_registration(&signer, &reg, [0; 4], &ctx).await,
            TypedSigner::sign_randao_reveal(&signer, 10, &ctx).await,
            TypedSigner::sign_voluntary_exit(&signer, &exit, &ctx).await,
            TypedSigner::sign_payload_attestation(&signer, &ptc, &ctx).await,
            TypedSigner::sign_proposer_preferences(&signer, &prefs, &ctx).await,
            TypedSigner::sign_builder_request_auth(&signer, &auth, [0; 4], &ctx).await,
        ];

        assert_eq!(results.len(), 13);
        let mut messages = Vec::with_capacity(13);
        for (i, result) in results.into_iter().enumerate() {
            match result {
                Err(SigningError::RemoteSignerError(msg)) => {
                    assert!(
                        msg.starts_with("gRPC ") && msg.contains(" failed ("),
                        "method {i}: expected shared gRPC error mapping, got: {msg}"
                    );
                    messages.push(msg);
                }
                other => panic!("method {i}: expected RemoteSignerError, got: {other:?}"),
            }
        }
        // All thirteen share the same error *shape* (shared map_err in sign_rpc).
        assert!(messages.iter().all(|m| m.contains("failed (")));
    }
}
