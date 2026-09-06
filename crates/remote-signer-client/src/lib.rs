//! Web3Signer HTTP remote signer client.
//!
//! Split (RF3-11):
//! - `wire` — config + request builders (consumes `web3signer_wire` types)
//! - `client` — HTTP client + `crypto::Signer` / `crypto::TypedSigner` impls
//!
//! Public path is `remote_signer_client::*` (ARCH-6f; was `crypto::remote_signer::*`).

mod client;
mod wire;

pub use client::{check_remote_signer_url, RemoteSigner, REMOTE_SIGNER_INSECURE_ENV_VAR};
pub use wire::{
    build_aggregate_and_proof_request, build_aggregation_slot_request, build_attestation_request,
    build_blinded_block_v2_request, build_block_v2_request, build_contribution_and_proof_request,
    build_payload_attestation_request, build_proposer_preferences_request,
    build_randao_reveal_request, build_sync_committee_message_request,
    build_sync_selection_proof_request, build_validator_registration_request,
    build_voluntary_exit_request, sign_request_to_json, AggregationSlotPayload,
    BeaconBlockEnvelope, RandaoRevealPayload, RemoteSignerConfig, SignRequestJson,
    SyncSelectionPayload, Web3SignerPayload, Web3SignerSignRequest, WireForkInfo, WireForkInfoExt,
};
