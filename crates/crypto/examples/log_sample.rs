//! Emits a representative `trace`-level log sample using the redaction primitives so the
//! Gate 2 secret-scan (gitleaks) can verify, on the *emitted output*, that no raw secret
//! reaches a logging macro. This is the load-bearing half of Gate 2 (Open Q5: reuse the
//! redaction wrappers as the sample source).
//!
//! CI runs: `cargo run -p rvc-crypto --example log_sample > emitted-trace.log`
//! then gitleaks scans `emitted-trace.log`. Secret-shaped inputs are logged THROUGH
//! `TruncatedRoot` / `TruncatedPubkey` / `RedactedUrl`, so only truncated/redacted forms
//! appear — the full pubkey/root hex and the URL password must be ABSENT from the output.
//!
//! The inputs here are not real secrets, but they are the *shape* of values the wrappers
//! must never emit verbatim (a 96-hex pubkey, a 64-byte-ish root, a `user:pass@` URL).

use observability::logging::{
    fields, new_request_id, record_display, RedactedUrl, TruncatedPubkey, TruncatedRoot,
};

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(std::io::stdout)
        .with_ansi(false)
        .init();

    // Representative (non-secret) inputs shaped like the values the wrappers redact.
    let root: [u8; 32] = std::array::from_fn(|i| i as u8);
    let pubkey_hex = "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
    // T21: a real W3C trace id (16 random bytes → 32 lowercase hex), generated
    // at runtime so this source line stays put and the tree gains no new
    // secret-shaped literal. Invalid all-zero ids are rejected.
    let mut trace_id_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut trace_id_bytes);
    if trace_id_bytes.iter().all(|byte| *byte == 0) {
        trace_id_bytes[0] = 1;
    }
    let trace_id = hex::encode(trace_id_bytes);
    let credentialed_url = "https://user:hunter2pw@beacon.example.com:5052/eth/v1/node/version";

    let req_id = new_request_id();

    let span = tracing::info_span!(
        "sign",
        request_id = tracing::field::Empty,
        slot = 6_400_000_u64,
        duty = %fields::Duty::Attestation.as_str(),
    );
    let _enter = span.enter();
    record_display(&span, fields::REQUEST_ID, req_id);

    tracing::trace!(
        trace_id = %trace_id,
        signing_root = %TruncatedRoot::new(&root),
        head = %TruncatedRoot::new(&root),
        "computed signing root"
    );
    tracing::debug!(pubkey = %TruncatedPubkey::new(pubkey_hex), "resolved validator");
    tracing::info!(bn_url = %RedactedUrl(credentialed_url), "connected to beacon node");
    tracing::info!(slot = 6_400_000_u64, "published attestation");
}
