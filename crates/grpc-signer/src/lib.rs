pub mod client;

/// Re-export of the shared v2 signer proto bindings (compiled once in `rvc-signer-proto`).
pub mod proto {
    pub use signer_proto::signer_v2;
}

pub use client::{
    GrpcRemoteSigner, GrpcRemoteSignerConfig, REMOTE_SIGNER_INSECURE_ENV_VAR,
    SIGNER_V2_PACKAGE_NAME,
};

// V2 client and server exports
pub use proto::signer_v2::signer_service_client::SignerServiceClient as SignerServiceClientV2;
pub use proto::signer_v2::signer_service_server::{
    SignerService as SignerServiceV2, SignerServiceServer as SignerServiceServerV2,
};

#[cfg(test)]
mod tests {
    // ---- proto v2 compile tests ----
    // These tests verify that SignerService and PeerSignerService request types
    // from signer.v2.proto are reachable from crates/grpc-signer.

    #[test]
    fn test_v2_sign_beacon_block_request_accessible() {
        use crate::proto::signer_v2::{ForkInfo, SignBeaconBlockRequest};
        let req = SignBeaconBlockRequest {
            pubkey: vec![0u8; 48],
            fork_info: Some(ForkInfo {
                previous_version: vec![0u8; 4],
                current_version: vec![4u8; 4],
                epoch: 40000,
                genesis_validators_root: vec![0xaa; 32],
            }),
            block_ssz: vec![0u8; 84],
            fork_id: 4, // Deneb
        };
        assert_eq!(req.pubkey.len(), 48);
        assert_eq!(req.fork_id, 4);
    }

    #[test]
    fn test_v2_sign_blinded_beacon_block_request_accessible() {
        use crate::proto::signer_v2::SignBlindedBeaconBlockRequest;
        let req = SignBlindedBeaconBlockRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            block_ssz: vec![0u8; 84],
            fork_id: 4,
        };
        assert_eq!(req.pubkey.len(), 48);
    }

    #[test]
    fn test_v2_sign_attestation_data_request_accessible() {
        use crate::proto::signer_v2::{AttestationData, Checkpoint, SignAttestationDataRequest};
        let req = SignAttestationDataRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            data: Some(AttestationData {
                slot: 100,
                index: 0,
                beacon_block_root: vec![0u8; 32],
                source: Some(Checkpoint { epoch: 9, root: vec![0u8; 32] }),
                target: Some(Checkpoint { epoch: 10, root: vec![0u8; 32] }),
            }),
            fork_id: 4,
        };
        assert_eq!(req.pubkey.len(), 48);
    }

    #[test]
    fn test_v2_sign_aggregate_and_proof_request_accessible() {
        use crate::proto::signer_v2::SignAggregateAndProofRequest;
        let req = SignAggregateAndProofRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            aggregator_index: 42,
            aggregate_ssz: vec![0u8; 16],
            selection_proof: vec![0u8; 96],
            fork_id: 4,
        };
        assert_eq!(req.aggregator_index, 42);
    }

    #[test]
    fn test_v2_sign_sync_committee_message_request_accessible() {
        use crate::proto::signer_v2::SignSyncCommitteeMessageRequest;
        let req = SignSyncCommitteeMessageRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            slot: 500,
            beacon_block_root: vec![0u8; 32],
            fork_id: 4,
        };
        assert_eq!(req.slot, 500);
    }

    #[test]
    fn test_v2_sign_sync_aggregator_selection_data_request_accessible() {
        use crate::proto::signer_v2::SignSyncAggregatorSelectionDataRequest;
        let req = SignSyncAggregatorSelectionDataRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            slot: 600,
            subcommittee_index: 3,
            fork_id: 4,
        };
        assert_eq!(req.subcommittee_index, 3);
    }

    #[test]
    fn test_v2_sign_contribution_and_proof_request_accessible() {
        use crate::proto::signer_v2::SignContributionAndProofRequest;
        let req = SignContributionAndProofRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            aggregator_index: 7,
            contribution_ssz: vec![0u8; 56],
            selection_proof: vec![0u8; 96],
            fork_id: 4,
        };
        assert_eq!(req.aggregator_index, 7);
    }

    #[test]
    fn test_v2_sign_builder_registration_request_accessible() {
        use crate::proto::signer_v2::SignBuilderRegistrationRequest;
        let req = SignBuilderRegistrationRequest {
            pubkey: vec![0u8; 48],
            fee_recipient: vec![0u8; 20],
            gas_limit: 30_000_000,
            timestamp: 1_700_000_000,
            genesis_fork_version: vec![],
        };
        assert_eq!(req.gas_limit, 30_000_000);
        assert!(req.genesis_fork_version.is_empty());
    }

    #[test]
    fn test_v2_sign_randao_reveal_request_accessible() {
        use crate::proto::signer_v2::SignRandaoRevealRequest;
        let req = SignRandaoRevealRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            epoch: 42,
            fork_id: 4,
        };
        assert_eq!(req.epoch, 42);
    }

    #[test]
    fn test_v2_sign_voluntary_exit_request_accessible() {
        use crate::proto::signer_v2::SignVoluntaryExitRequest;
        let req = SignVoluntaryExitRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            epoch: 200,
            validator_index: 99,
            fork_id: 5,
        };
        assert_eq!(req.validator_index, 99);
    }

    #[test]
    fn test_v2_sign_block_header_request_accessible() {
        use crate::proto::signer_v2::{BeaconBlockHeader, SignBlockHeaderRequest};
        let req = SignBlockHeaderRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            header: Some(BeaconBlockHeader {
                slot: 42,
                proposer_index: 1,
                parent_root: vec![0u8; 32],
                state_root: vec![0u8; 32],
                body_root: vec![0u8; 32],
            }),
            fork_id: 7,
        };
        assert_eq!(req.fork_id, 7);
        assert_eq!(req.header.unwrap().slot, 42);
    }

    #[test]
    fn test_v2_sign_root_request_accessible() {
        use crate::proto::signer_v2::SignRootRequest;
        let req = SignRootRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            object_root: vec![0u8; 32],
            duty: 0,
            fork_id: 7,
        };
        assert_eq!(req.duty, 0);
        assert_eq!(req.fork_id, 7);
    }

    #[test]
    fn test_v2_sign_response_accessible() {
        use crate::proto::signer_v2::SignResponse;
        let resp = SignResponse { signature: vec![0u8; 96] };
        assert_eq!(resp.signature.len(), 96);
    }

    #[test]
    fn test_v2_partial_sign_beacon_block_request_accessible() {
        use crate::proto::signer_v2::PartialSignBeaconBlockRequest;
        let req = PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: vec![0u8; 48],
            fork_info: None,
            block_ssz: vec![0u8; 84],
            fork_id: 4,
        };
        assert_eq!(req.requester_index, 1);
    }

    #[test]
    fn test_v2_partial_sign_attestation_data_request_accessible() {
        use crate::proto::signer_v2::PartialSignAttestationDataRequest;
        let req = PartialSignAttestationDataRequest {
            requester_index: 2,
            pubkey: vec![0u8; 48],
            fork_info: None,
            data: None,
            fork_id: 4,
        };
        assert_eq!(req.requester_index, 2);
    }

    #[test]
    fn test_v2_partial_sign_sync_committee_request_accessible() {
        use crate::proto::signer_v2::PartialSignSyncCommitteeRequest;
        let req = PartialSignSyncCommitteeRequest {
            requester_index: 3,
            pubkey: vec![0u8; 48],
            fork_info: None,
            slot: 700,
            beacon_block_root: vec![0u8; 32],
            fork_id: 4,
        };
        assert_eq!(req.requester_index, 3);
    }

    #[test]
    fn test_v2_partial_sign_response_accessible() {
        use crate::proto::signer_v2::PartialSignResponse;
        let resp = PartialSignResponse { partial_signature: vec![0u8; 96], share_index: 1 };
        assert_eq!(resp.share_index, 1);
    }

    #[test]
    fn test_v2_partial_sign_block_header_request_accessible() {
        use crate::proto::signer_v2::PartialSignBlockHeaderRequest;
        let req = PartialSignBlockHeaderRequest {
            requester_index: 4,
            pubkey: vec![0u8; 48],
            fork_info: None,
            header: None,
            fork_id: 7,
        };
        assert_eq!(req.requester_index, 4);
    }

    #[test]
    fn test_v2_partial_sign_root_request_accessible() {
        use crate::proto::signer_v2::PartialSignRootRequest;
        let req = PartialSignRootRequest {
            requester_index: 5,
            pubkey: vec![0u8; 48],
            fork_info: None,
            object_root: vec![0u8; 32],
            duty: 3,
            fork_id: 7,
        };
        assert_eq!(req.requester_index, 5);
        assert_eq!(req.duty, 3);
    }

    #[test]
    fn test_v2_list_public_keys_request_accessible() {
        use crate::proto::signer_v2::ListPublicKeysRequest;
        let req = ListPublicKeysRequest {};
        let _ = req;
    }

    #[test]
    fn test_v2_get_status_request_accessible() {
        use crate::proto::signer_v2::GetStatusRequest;
        let req = GetStatusRequest {};
        let _ = req;
    }

    #[test]
    fn test_v2_get_status_response_accessible() {
        use crate::proto::signer_v2::GetStatusResponse;
        let resp = GetStatusResponse { ready: true, backend: "local".to_string(), key_count: 3 };
        assert!(resp.ready);
        assert_eq!(resp.key_count, 3);
    }
}
