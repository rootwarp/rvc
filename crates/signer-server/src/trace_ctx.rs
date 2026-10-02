//! Crate-private gRPC handler spans for `SignerServiceV2`.
//!
//! The pattern — build the span, attach the inbound parent, then instrument
//! the body future — is the contract. This module stays crate-private: callers
//! share one construction site, and the helper is not a public API.

/// Build the per-RPC handler span and continue the caller's trace.
///
/// Mirrors the HTTP `sign_span` helper: the span is created explicitly,
/// `telemetry::set_parent_from_metadata` runs before the span is entered, and
/// the span is returned **unentered** so the caller can `.instrument(span)`
/// the handler body.
///
/// # Precondition
///
/// Call this before the span is entered or started. `set_parent` attaches a
/// parent only while the span is still being built; once the span has been
/// entered it returns `AlreadyStarted` and the parent is not attached (the
/// span stays its own root). Do not `.enter()` or `.in_scope()` the returned
/// span before handing it to `.instrument`. This function performs the
/// `set_parent_from_metadata` call itself.
///
/// `otel_name` is recorded as `otel.name` and must stay byte-for-byte the
/// historical `signer.v2.*` instrument name. The tracing span name is
/// `grpc.sign`. Correlation fields are the union of every v2 sign handler's
/// `fields(...)` set, declared `tracing::field::Empty` and late-bound with
/// `Span::current().record` after the payload parses. Handlers this change
/// does not convert still carry `#[tracing::instrument]` (TRC-3d); their field
/// names are declared here so one builder is the union.
pub(crate) fn server_span(
    otel_name: &'static str,
    metadata: &tonic::metadata::MetadataMap,
) -> tracing::Span {
    let span = tracing::info_span!(
        "grpc.sign",
        otel.name = otel_name,
        otel.kind = "server",
        pubkey = tracing::field::Empty,
        slot = tracing::field::Empty,
        epoch = tracing::field::Empty,
        source_epoch = tracing::field::Empty,
        target_epoch = tracing::field::Empty,
        validator_index = tracing::field::Empty,
        duty = tracing::field::Empty,
    );
    telemetry::set_parent_from_metadata(&span, metadata);
    span
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const CONVERTED_OTEL_NAMES: &[&str] = &[
        "signer.v2.sign_beacon_block",
        "signer.v2.sign_blinded_beacon_block",
        "signer.v2.sign_randao_reveal",
        "signer.v2.sign_block_header",
        "signer.v2.sign_root",
    ];

    const UNCONVERTED_OTEL_NAMES: &[&str] = &[
        "signer.v2.sign_attestation_data",
        "signer.v2.sign_aggregate_and_proof",
        "signer.v2.sign_sync_committee_message",
        "signer.v2.sign_sync_aggregator_selection_data",
        "signer.v2.sign_contribution_and_proof",
        "signer.v2.sign_builder_registration",
        "signer.v2.sign_voluntary_exit",
    ];

    /// Union of `SignerServiceV2` sign-handler span fields, plus the OTel
    /// overrides this helper records at construction.
    const UNION_FIELDS: &[&str] = &[
        "otel.name",
        "otel.kind",
        "pubkey",
        "slot",
        "epoch",
        "source_epoch",
        "target_epoch",
        "validator_index",
        "duty",
    ];

    #[test]
    fn test_server_span_name_and_union_field_set() {
        let span = server_span("signer.v2.sign_beacon_block", &tonic::metadata::MetadataMap::new());
        let meta = span.metadata().expect("span metadata");
        assert_eq!(meta.name(), "grpc.sign");
        let names: BTreeSet<&str> = meta.fields().iter().map(|field| field.name()).collect();
        assert_eq!(names, BTreeSet::from_iter(UNION_FIELDS.iter().copied()));
    }

    /// The returned span is unentered: parenting from metadata still observes
    /// the call (a span entered inside `server_span` would make `set_parent` a
    /// no-op). No subscriber: must not panic.
    #[test]
    fn test_server_span_unentered_without_subscriber_does_not_panic() {
        let span = server_span("signer.v2.sign_root", &tonic::metadata::MetadataMap::new());
        let _enter = span.enter();
    }

    #[test]
    fn test_first_five_handlers_use_server_span_remaining_seven_keep_instrument() {
        let src = include_str!("service.rs");
        assert_eq!(
            src.matches("#[tracing::instrument").count(),
            UNCONVERTED_OTEL_NAMES.len(),
            "only the seven not-yet-converted handlers may keep #[tracing::instrument]"
        );
        for name in CONVERTED_OTEL_NAMES {
            assert!(
                src.contains(&format!("server_span(\"{name}\"")),
                "{name} must be passed to server_span"
            );
            assert!(
                !src.contains(&format!("name = \"{name}\"")),
                "{name} must not keep #[tracing::instrument]"
            );
        }
        for name in UNCONVERTED_OTEL_NAMES {
            assert!(
                src.contains(&format!("name = \"{name}\"")),
                "{name} must still use #[tracing::instrument] (TRC-3d)"
            );
            assert!(
                !src.contains(&format!("server_span(\"{name}\"")),
                "{name} must not be converted in TRC-3c"
            );
        }
    }
}
