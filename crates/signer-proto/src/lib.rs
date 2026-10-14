//! Shared generated bindings for `proto/signer.v2.proto`.
//!
//! This is the single `tonic_build` home for the signer v2 contract (RF3-14).
//! Consumers enable additive features:
//! - `server` — generate server stubs (`*_server` modules)
//! - `client` — generate client stubs (`*_client` modules)
//!
//! Message types are always generated. Cargo feature unification turns both
//! stubs on when `rvc-signer-bin` and `rvc-grpc-signer` share a build graph.

#![allow(clippy::all)]
// Generated prost/tonic code is not clippy-clean; keep the allow at the crate root.

/// Generated package `signer.v2`.
pub mod signer_v2 {
    tonic::include_proto!("signer.v2");
}

#[cfg(test)]
mod tests {
    use eth_types::{decode_beacon_block_ssz, ForkName, SszDecodeError};
    use prost::Message;

    use super::signer_v2::{
        BeaconBlockHeader, PartialSignAttestationDataRequest, PartialSignBeaconBlockRequest,
        PartialSignBlockHeaderRequest, PartialSignPayloadAttestationRequest, PartialSignResponse,
        PartialSignRootRequest, PartialSignSyncCommitteeRequest, PayloadAttestationData,
        SignBlockHeaderRequest, SignRootRequest,
    };

    const PROTO: &str = include_str!("../../../proto/signer.v2.proto");

    fn proto_message_fields(src: &str, message: &str) -> Vec<(String, u32)> {
        let header = format!("message {message} {{");
        let start = src.find(&header).unwrap_or_else(|| panic!("missing message {message}"));
        let after = &src[start + header.len()..];
        let end = after.find('}').unwrap_or_else(|| panic!("unclosed message {message}"));
        let mut fields = Vec::new();
        for line in after[..end].lines() {
            let line = line.split("//").next().unwrap().trim().trim_end_matches(';').trim();
            if line.is_empty() {
                continue;
            }
            let (left, right) =
                line.split_once('=').unwrap_or_else(|| panic!("no field number: {line}"));
            let name =
                left.split_whitespace().last().unwrap_or_else(|| panic!("no field name: {line}"));
            let num: u32 =
                right.trim().parse().unwrap_or_else(|_| panic!("bad field number: {line}"));
            fields.push((name.to_string(), num));
        }
        fields
    }

    fn proto_service_rpcs(src: &str, service: &str) -> Vec<String> {
        let header = format!("service {service} {{");
        let start = src.find(&header).unwrap_or_else(|| panic!("missing service {service}"));
        let after = &src[start + header.len()..];
        let end = after.find('}').unwrap_or_else(|| panic!("unclosed service {service}"));
        after[..end]
            .lines()
            .filter_map(|line| {
                let line = line.split("//").next().unwrap().trim();
                let rest = line.strip_prefix("rpc ")?;
                Some(rest.split_whitespace().next()?.to_string())
            })
            .collect()
    }

    fn protobuf_top_level_fields(mut buf: &[u8]) -> Vec<u32> {
        let mut fields = Vec::new();
        while !buf.is_empty() {
            let (key, rest) = decode_varint(buf);
            buf = rest;
            fields.push((key >> 3) as u32);
            let wire_type = key & 7;
            buf = match wire_type {
                0 => decode_varint(buf).1,
                1 => &buf[8..],
                2 => {
                    let (len, rest) = decode_varint(buf);
                    &rest[len as usize..]
                }
                5 => &buf[4..],
                other => panic!("unsupported protobuf wire type {other}"),
            };
        }
        fields
    }

    fn decode_varint(buf: &[u8]) -> (u64, &[u8]) {
        let mut result = 0u64;
        for (i, b) in buf.iter().enumerate() {
            result |= u64::from(*b & 0x7f) << (7 * i);
            if *b & 0x80 == 0 {
                return (result, &buf[i + 1..]);
            }
        }
        panic!("unterminated varint");
    }

    /// Historical PeerSigner field numbers stay frozen; later RPCs are additive
    /// (see `signer_v2_wire_contract` for the mechanical D18/B5 freeze).
    #[test]
    fn test_existing_peer_signer_rpc_field_numbers_unchanged() {
        assert_eq!(
            proto_service_rpcs(PROTO, "PeerSignerService"),
            [
                "PartialSignBeaconBlock",
                "PartialSignAttestationData",
                "PartialSignSyncCommittee",
                "PartialSignPayloadAttestation",
                "PartialSignBlockHeader",
                "PartialSignRoot",
            ]
        );

        assert_eq!(
            proto_message_fields(PROTO, "PartialSignBeaconBlockRequest"),
            [
                ("requester_index".into(), 1),
                ("pubkey".into(), 2),
                ("fork_info".into(), 3),
                ("block_ssz".into(), 4),
                ("fork_id".into(), 5),
            ]
        );
        assert_eq!(
            proto_message_fields(PROTO, "PartialSignAttestationDataRequest"),
            [
                ("requester_index".into(), 1),
                ("pubkey".into(), 2),
                ("fork_info".into(), 3),
                ("data".into(), 4),
                ("fork_id".into(), 5),
            ]
        );
        assert_eq!(
            proto_message_fields(PROTO, "PartialSignSyncCommitteeRequest"),
            [
                ("requester_index".into(), 1),
                ("pubkey".into(), 2),
                ("fork_info".into(), 3),
                ("slot".into(), 4),
                ("beacon_block_root".into(), 5),
                ("fork_id".into(), 6),
            ]
        );
        assert_eq!(
            proto_message_fields(PROTO, "PartialSignResponse"),
            [("partial_signature".into(), 1), ("share_index".into(), 2)]
        );
        assert_eq!(
            proto_message_fields(PROTO, "PayloadAttestationData"),
            [
                ("beacon_block_root".into(), 1),
                ("slot".into(), 2),
                ("payload_present".into(), 3),
                ("blob_data_available".into(), 4),
            ]
        );
        assert_eq!(
            proto_message_fields(PROTO, "PartialSignPayloadAttestationRequest"),
            [
                ("requester_index".into(), 1),
                ("pubkey".into(), 2),
                ("fork_info".into(), 3),
                ("data".into(), 4),
                ("fork_id".into(), 5),
                ("object_root".into(), 6),
            ]
        );
        assert_eq!(
            proto_message_fields(PROTO, "BeaconBlockHeader"),
            [
                ("slot".into(), 1),
                ("proposer_index".into(), 2),
                ("parent_root".into(), 3),
                ("state_root".into(), 4),
                ("body_root".into(), 5),
            ]
        );
        assert_eq!(
            proto_message_fields(PROTO, "SignBlockHeaderRequest"),
            [
                ("pubkey".into(), 1),
                ("fork_info".into(), 2),
                ("header".into(), 3),
                ("fork_id".into(), 4),
            ]
        );
        assert_eq!(
            proto_message_fields(PROTO, "SignRootRequest"),
            [
                ("pubkey".into(), 1),
                ("fork_info".into(), 2),
                ("object_root".into(), 3),
                ("duty".into(), 4),
                ("fork_id".into(), 5),
            ]
        );
        assert_eq!(
            proto_message_fields(PROTO, "PartialSignBlockHeaderRequest"),
            [
                ("requester_index".into(), 1),
                ("pubkey".into(), 2),
                ("fork_info".into(), 3),
                ("header".into(), 4),
                ("fork_id".into(), 5),
            ]
        );
        assert_eq!(
            proto_message_fields(PROTO, "PartialSignRootRequest"),
            [
                ("requester_index".into(), 1),
                ("pubkey".into(), 2),
                ("fork_info".into(), 3),
                ("object_root".into(), 4),
                ("duty".into(), 5),
                ("fork_id".into(), 6),
            ]
        );

        let block = PartialSignBeaconBlockRequest {
            requester_index: 1,
            pubkey: vec![0u8; 48],
            fork_info: None,
            block_ssz: vec![0u8; 4],
            fork_id: 6,
        };
        assert_eq!(protobuf_top_level_fields(&block.encode_to_vec()), [1, 2, 4, 5]);

        let att = PartialSignAttestationDataRequest {
            requester_index: 1,
            pubkey: vec![0u8; 48],
            fork_info: None,
            data: None,
            fork_id: 6,
        };
        assert_eq!(protobuf_top_level_fields(&att.encode_to_vec()), [1, 2, 5]);

        let sync = PartialSignSyncCommitteeRequest {
            requester_index: 1,
            pubkey: vec![0u8; 48],
            fork_info: None,
            slot: 1,
            beacon_block_root: vec![0u8; 32],
            fork_id: 6,
        };
        assert_eq!(protobuf_top_level_fields(&sync.encode_to_vec()), [1, 2, 4, 5, 6]);

        let resp = PartialSignResponse { partial_signature: vec![0u8; 96], share_index: 1 };
        assert_eq!(protobuf_top_level_fields(&resp.encode_to_vec()), [1, 2]);
    }

    /// Gloas `fork_id` is accepted on the new request (object-root / field path).
    /// `validate_fork_id` (the four `decode_*_ssz` helpers) still rejects 7.
    #[test]
    fn test_partial_sign_payload_attestation_accepts_gloas_fork_id() {
        assert_eq!(ForkName::Gloas.id(), 7);
        assert_eq!(ForkName::try_from(7u32), Ok(ForkName::Gloas));

        let req = PartialSignPayloadAttestationRequest {
            requester_index: 1,
            pubkey: vec![0u8; 48],
            fork_info: None,
            data: Some(PayloadAttestationData {
                beacon_block_root: vec![0x11; 32],
                slot: 1,
                payload_present: true,
                blob_data_available: false,
            }),
            fork_id: ForkName::Gloas.id(),
            object_root: vec![],
        };
        assert_eq!(req.fork_id, 7);

        let decoded = PartialSignPayloadAttestationRequest::decode(req.encode_to_vec().as_slice())
            .expect("PartialSignPayloadAttestationRequest with fork_id=7 must encode/decode");
        assert_eq!(decoded.fork_id, ForkName::Gloas.id());
        assert_eq!(decoded.requester_index, 1);
        let data = decoded.data.expect("payload attestation data");
        assert_eq!(data.beacon_block_root, vec![0x11; 32]);
        assert_eq!(data.slot, 1);
        assert!(data.payload_present);
        assert!(!data.blob_data_available);

        let ssz = decode_beacon_block_ssz(&[], 7);
        assert!(
            matches!(ssz, Err(SszDecodeError::UnknownForkId(7))),
            "validate_fork_id(7) via decode_*_ssz must stay UnknownForkId, got {ssz:?}"
        );
    }

    #[cfg(feature = "server")]
    #[test]
    fn test_server_stub_includes_partial_sign_payload_attestation() {
        use tonic::{Request, Response, Status};

        use crate::signer_v2::peer_signer_service_server::PeerSignerService;

        struct Stub;

        #[tonic::async_trait]
        impl PeerSignerService for Stub {
            async fn partial_sign_beacon_block(
                &self,
                _request: Request<PartialSignBeaconBlockRequest>,
            ) -> Result<Response<PartialSignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }

            async fn partial_sign_attestation_data(
                &self,
                _request: Request<PartialSignAttestationDataRequest>,
            ) -> Result<Response<PartialSignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }

            async fn partial_sign_sync_committee(
                &self,
                _request: Request<PartialSignSyncCommitteeRequest>,
            ) -> Result<Response<PartialSignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }

            async fn partial_sign_payload_attestation(
                &self,
                _request: Request<PartialSignPayloadAttestationRequest>,
            ) -> Result<Response<PartialSignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }

            async fn partial_sign_block_header(
                &self,
                _request: Request<PartialSignBlockHeaderRequest>,
            ) -> Result<Response<PartialSignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }

            async fn partial_sign_root(
                &self,
                _request: Request<PartialSignRootRequest>,
            ) -> Result<Response<PartialSignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
        }

        let _ = Stub;
    }

    #[cfg(feature = "client")]
    #[test]
    fn test_client_stub_includes_partial_sign_payload_attestation() {
        use crate::signer_v2::peer_signer_service_client::PeerSignerServiceClient;

        async fn call_rpc<T>(
            client: &mut PeerSignerServiceClient<T>,
            request: PartialSignPayloadAttestationRequest,
        ) -> Result<tonic::Response<PartialSignResponse>, tonic::Status>
        where
            T: tonic::client::GrpcService<tonic::body::BoxBody>,
            T::Error: Into<tonic::codegen::StdError>,
            T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
            <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
        {
            client.partial_sign_payload_attestation(request).await
        }

        let _ = call_rpc::<tonic::transport::Channel>;
    }

    fn proto_enum_values(src: &str, name: &str) -> Vec<(String, u32)> {
        let header = format!("enum {name} {{");
        let start = src.find(&header).unwrap_or_else(|| panic!("missing enum {name}"));
        let after = &src[start + header.len()..];
        let end = after.find('}').unwrap_or_else(|| panic!("unclosed enum {name}"));
        let mut values = Vec::new();
        for line in after[..end].lines() {
            let line = line.split("//").next().unwrap().trim().trim_end_matches(';').trim();
            if line.is_empty() {
                continue;
            }
            let (left, right) =
                line.split_once('=').unwrap_or_else(|| panic!("no enum number: {line}"));
            values.push((
                left.trim().to_string(),
                right.trim().parse().unwrap_or_else(|_| panic!("bad enum number: {line}")),
            ));
        }
        values
    }

    /// Gloas-safe header/root shapes: no SSZ bytes, Gloas fork_id is on the wire,
    /// and Duty 0 / unknown are representable (fail-closed in 4.20b).
    #[test]
    fn test_gloas_safe_header_and_root_shapes() {
        assert_eq!(
            proto_service_rpcs(PROTO, "SignerService")
                .into_iter()
                .filter(|rpc| rpc == "SignBlockHeader" || rpc == "SignRoot")
                .collect::<Vec<_>>(),
            ["SignBlockHeader", "SignRoot"]
        );
        assert_eq!(
            proto_enum_values(PROTO, "Duty"),
            [
                ("UNSPECIFIED".into(), 0),
                ("AGGREGATE_AND_PROOF".into(), 1),
                ("CONTRIBUTION_AND_PROOF".into(), 2),
                ("PAYLOAD_ATTESTATION".into(), 3),
                ("PROPOSER_PREFERENCES".into(), 4),
                ("EXECUTION_PAYLOAD_ENVELOPE".into(), 5),
                ("BUILDER_REQUEST_AUTH".into(), 6),
            ]
        );
        let stripped: String =
            PROTO.lines().map(|l| l.split("//").next().unwrap()).collect::<Vec<_>>().join("\n");
        let enum_pos = stripped.find("enum ").expect("Duty enum");
        assert!(stripped[enum_pos..].starts_with("enum Duty"), "first proto enum must be Duty");

        let header = BeaconBlockHeader {
            slot: 42,
            proposer_index: 7,
            parent_root: vec![0x11; 32],
            state_root: vec![0x22; 32],
            body_root: vec![0x33; 32],
        };
        let header_req = SignBlockHeaderRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            header: Some(header),
            fork_id: ForkName::Gloas.id(),
        };
        let decoded = SignBlockHeaderRequest::decode(header_req.encode_to_vec().as_slice())
            .expect("SignBlockHeaderRequest must encode/decode");
        assert_eq!(decoded.fork_id, 7);
        let decoded_header = decoded.header.expect("header");
        assert_eq!(decoded_header.slot, 42);
        assert_eq!(decoded_header.proposer_index, 7);
        assert_eq!(decoded_header.parent_root, vec![0x11; 32]);
        assert_eq!(decoded_header.state_root, vec![0x22; 32]);
        assert_eq!(decoded_header.body_root, vec![0x33; 32]);

        let unspecified = SignRootRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            object_root: vec![0x44; 32],
            duty: 0,
            fork_id: ForkName::Gloas.id(),
        };
        let decoded = SignRootRequest::decode(unspecified.encode_to_vec().as_slice())
            .expect("UNSPECIFIED duty must encode/decode");
        assert_eq!(decoded.duty, 0);
        assert_eq!(decoded.fork_id, 7);

        let unknown = SignRootRequest {
            pubkey: vec![0u8; 48],
            fork_info: None,
            object_root: vec![0x44; 32],
            duty: 99,
            fork_id: ForkName::Gloas.id(),
        };
        let decoded = SignRootRequest::decode(unknown.encode_to_vec().as_slice())
            .expect("unknown duty must remain representable on the wire");
        assert_eq!(decoded.duty, 99);

        let ssz = decode_beacon_block_ssz(&[], 7);
        assert!(
            matches!(ssz, Err(SszDecodeError::UnknownForkId(7))),
            "validate_fork_id(7) via decode_*_ssz must stay UnknownForkId, got {ssz:?}"
        );
    }

    #[cfg(feature = "server")]
    #[test]
    fn test_server_stub_includes_sign_block_header_and_sign_root_rpc() {
        use tonic::{Request, Response, Status};

        use crate::signer_v2::signer_service_server::SignerService;
        use crate::signer_v2::{
            GetStatusRequest, GetStatusResponse, ListPublicKeysRequest, ListPublicKeysResponse,
            SignAggregateAndProofRequest, SignAttestationDataRequest, SignBeaconBlockRequest,
            SignBlindedBeaconBlockRequest, SignBuilderRegistrationRequest,
            SignContributionAndProofRequest, SignRandaoRevealRequest, SignResponse,
            SignSyncAggregatorSelectionDataRequest, SignSyncCommitteeMessageRequest,
            SignVoluntaryExitRequest,
        };

        struct Stub;

        #[tonic::async_trait]
        impl SignerService for Stub {
            async fn sign_beacon_block(
                &self,
                _request: Request<SignBeaconBlockRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_blinded_beacon_block(
                &self,
                _request: Request<SignBlindedBeaconBlockRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_attestation_data(
                &self,
                _request: Request<SignAttestationDataRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_aggregate_and_proof(
                &self,
                _request: Request<SignAggregateAndProofRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_sync_committee_message(
                &self,
                _request: Request<SignSyncCommitteeMessageRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_sync_aggregator_selection_data(
                &self,
                _request: Request<SignSyncAggregatorSelectionDataRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_contribution_and_proof(
                &self,
                _request: Request<SignContributionAndProofRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_builder_registration(
                &self,
                _request: Request<SignBuilderRegistrationRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_randao_reveal(
                &self,
                _request: Request<SignRandaoRevealRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_voluntary_exit(
                &self,
                _request: Request<SignVoluntaryExitRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_block_header(
                &self,
                _request: Request<SignBlockHeaderRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn sign_root(
                &self,
                _request: Request<SignRootRequest>,
            ) -> Result<Response<SignResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn list_public_keys(
                &self,
                _request: Request<ListPublicKeysRequest>,
            ) -> Result<Response<ListPublicKeysResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
            async fn get_status(
                &self,
                _request: Request<GetStatusRequest>,
            ) -> Result<Response<GetStatusResponse>, Status> {
                Err(Status::unimplemented("test stub"))
            }
        }

        let _ = Stub;
    }

    #[cfg(feature = "client")]
    #[test]
    fn test_client_stub_includes_sign_block_header_and_sign_root_rpc() {
        use crate::signer_v2::signer_service_client::SignerServiceClient;

        async fn call_rpcs<T>(
            client: &mut SignerServiceClient<T>,
            header: SignBlockHeaderRequest,
            root: SignRootRequest,
        ) -> Result<(), tonic::Status>
        where
            T: tonic::client::GrpcService<tonic::body::BoxBody>,
            T::Error: Into<tonic::codegen::StdError>,
            T::ResponseBody: tonic::codegen::Body<Data = tonic::codegen::Bytes> + Send + 'static,
            <T::ResponseBody as tonic::codegen::Body>::Error: Into<tonic::codegen::StdError> + Send,
        {
            let _ = client.sign_block_header(header).await?;
            let _ = client.sign_root(root).await?;
            Ok(())
        }

        let _ = call_rpcs::<tonic::transport::Channel>;
    }
}
