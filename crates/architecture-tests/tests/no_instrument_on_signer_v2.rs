//! TRC-3d: `#[tracing::instrument]` is banned on `SignerServiceV2`.
//!
//! VD-C: an inbound `traceparent` is attached with `set_parent_from_metadata`
//! before the handler span is entered. `#[tracing::instrument]` enters the span
//! as the method starts, so that call cannot parent. Every v2 sign handler
//! builds the span with `trace_ctx::server_span` and instruments the body
//! future.
//!
//! This gate reads `crates/signer-server/src/service.rs` from the workspace
//! tree (same discipline as `no_rvc_prefix.rs`: the tracked source on disk,
//! not a compiled copy and not a baked-in snapshot). Re-adding
//! `#[tracing::instrument]` to any method in `impl SignerServiceV2` fails it.

use std::path::{Path, PathBuf};

/// Historical `signer.v2.*` names from `0ae9a09` (ten) plus the two Gloas RPCs
/// (`sign_block_header`, `sign_root`). `otel.name` stays byte-identical.
const V2_SIGN_OTEL_NAMES: &[&str] = &[
    "signer.v2.sign_beacon_block",
    "signer.v2.sign_blinded_beacon_block",
    "signer.v2.sign_randao_reveal",
    "signer.v2.sign_attestation_data",
    "signer.v2.sign_aggregate_and_proof",
    "signer.v2.sign_sync_committee_message",
    "signer.v2.sign_sync_aggregator_selection_data",
    "signer.v2.sign_contribution_and_proof",
    "signer.v2.sign_builder_registration",
    "signer.v2.sign_voluntary_exit",
    "signer.v2.sign_block_header",
    "signer.v2.sign_root",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().to_path_buf()
}

fn signer_service_source(root: &Path) -> String {
    let path = root.join("crates/signer-server/src/service.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read tracked source {}: {err}", path.display()))
}

/// `impl SignerServiceV2 for SignerServiceImpl` through the brace that closes
/// it. The following banner is `// Unit tests`; the impl's closing `}` is the
/// last column-0 brace before that banner. Slicing this way avoids a brace
/// scan (handler bodies contain `{e}` in format strings).
fn signer_service_v2_impl(src: &str) -> &str {
    let start = src
        .find("impl SignerServiceV2 for SignerServiceImpl {")
        .expect("SignerServiceV2 impl header");
    let tests_at = src[start..]
        .find("\n// Unit tests\n")
        .expect("unit-test banner after SignerServiceV2 impl");
    let region = &src[start..start + tests_at];
    let close_at = region.rfind("\n}\n").expect("column-0 brace closing SignerServiceV2 impl");
    let impl_src = &region[..=close_at + 1];
    assert!(
        impl_src.ends_with('}'),
        "SignerServiceV2 impl slice must end at the impl's closing brace"
    );
    impl_src
}

#[test]
fn no_tracing_instrument_on_signer_service_v2() {
    let src = signer_service_source(&workspace_root());
    assert!(
        src.lines().count() > 500,
        "service.rs walk looks truncated ({} lines)",
        src.lines().count()
    );

    let impl_src = signer_service_v2_impl(&src);
    assert!(
        impl_src.contains("async fn sign_attestation_data"),
        "impl slice missed a SignerServiceV2 method; gate would be vacuous"
    );

    let file_hits = src.matches("tracing::instrument").count();
    assert_eq!(
        file_hits, 0,
        "tracing::instrument must not appear in crates/signer-server/src/service.rs \
         (census git grep -c 'tracing::instrument' == 0). SignerServiceV2 handlers use \
         trace_ctx::server_span + .instrument(span). hits={file_hits}"
    );
    assert!(
        !impl_src.contains("tracing::instrument"),
        "#[tracing::instrument] is banned on SignerServiceV2"
    );

    for name in V2_SIGN_OTEL_NAMES {
        let call = format!("server_span(\"{name}\"");
        assert!(
            impl_src.contains(&call),
            "{name} must be passed to trace_ctx::server_span inside SignerServiceV2"
        );
    }
    assert!(
        impl_src.matches(".instrument(span)").count() >= V2_SIGN_OTEL_NAMES.len(),
        "expected one .instrument(span) per v2 sign handler"
    );
}
