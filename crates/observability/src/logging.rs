/// Displays a public key hex string as `0x{first10}...{last8}`.
///
/// Implements `Display` for zero-allocation use with tracing's `%` specifier.
/// When tracing level is disabled, `Display::fmt` is never called.
pub struct TruncatedPubkey<'a>(pub &'a str);

impl<'a> TruncatedPubkey<'a> {
    pub fn new(hex: &'a str) -> Self {
        Self(hex)
    }
}

impl std::fmt::Display for TruncatedPubkey<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Defense-in-depth: strip at most one `0x`/`0X` prefix.
        // On `DoubleZeroXPrefix` emit a warning and fall back to the raw input
        // as-is so that the log line is not garbled and no panic occurs.
        // Callers should supply canonical pubkeys; this path indicates a bug upstream.
        let hex = match crate::hex::strip_prefix_strict(self.0) {
            Ok(s) => s,
            Err(crate::hex::HexError::DoubleZeroXPrefix) => {
                tracing::warn!(
                    pubkey = self.0,
                    "TruncatedPubkey: double 0x prefix detected, falling back to raw input"
                );
                return write!(f, "{}", self.0);
            }
        };
        if hex.len() > 18 && hex.is_ascii() {
            write!(f, "0x{}...{}", &hex[..10], &hex[hex.len() - 8..])
        } else {
            write!(f, "0x{hex}")
        }
    }
}

/// Displays a URL with username/password replaced by `***`.
///
/// Uses `url::Url::parse` internally. If parsing fails, displays the raw string.
pub struct RedactedUrl<'a>(pub &'a str);

impl std::fmt::Display for RedactedUrl<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Ok(mut parsed) = url::Url::parse(self.0) {
            if parsed.password().is_some() || !parsed.username().is_empty() {
                let _ = parsed.set_username("***");
                let _ = parsed.set_password(Some("***"));
            }
            write!(f, "{parsed}")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// Displays a 32-byte root / signature / hash as `0x{first10hex}...{last8hex}`.
///
/// Zero-allocation `Display` wrapper for tracing's `%` specifier: the hex is written
/// byte-by-byte directly into the `Formatter` (no `hex::encode` / `format!` / `to_string`),
/// so nothing is heap-allocated and `fmt` only runs when the log level is enabled. This is
/// the sanctioned way to render a block / head / signing root, hash, or signature in a log
/// line (ADR-005); a full root or signature is never logged.
///
/// Wraps a **non-secret** root / signature only — a `Display` impl is never added to a
/// secret type.
///
/// Inputs shorter than 9 bytes render their full lower-hex (`0x{all-bytes}`) instead of
/// slicing out of bounds, and `fmt` never panics.
pub struct TruncatedRoot<'a>(pub &'a [u8]);

impl<'a> TruncatedRoot<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }
}

impl std::fmt::Display for TruncatedRoot<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = self.0;
        f.write_str("0x")?;
        // Short input (< 9 bytes): the 5 leading + 4 trailing slices would overlap, so
        // render the full lower-hex rather than slice out of bounds. Never panics.
        if bytes.len() < 9 {
            for b in bytes {
                write!(f, "{b:02x}")?;
            }
            return Ok(());
        }
        // 5 leading bytes (10 hex chars) + "..." + 4 trailing bytes (8 hex chars).
        // Written byte-by-byte: zero heap allocation, and lazy under `%`.
        for b in &bytes[..5] {
            write!(f, "{b:02x}")?;
        }
        f.write_str("...")?;
        for b in &bytes[bytes.len() - 4..] {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// Canonical structured-field keys and `duty` value strings — the compile-checked,
/// greppable mirror of the field registry in `plan/logging/STANDARD.md`.
///
/// These consts are the single source of truth for field-key spellings so no crate can
/// invent a synonym (`val_idx`, `validator`, `rvc.slot`). They MUST stay in lockstep with
/// the STANDARD.md registry table; Gate 5 (Phase 4/5) diffs emitted field names against
/// them. `network` is intentionally **absent** — it is a resource attribute set once in
/// `telemetry::init`, never a per-event key.
pub mod fields {
    /// Defines the canonical field-key consts **and** a complete `ALL` slice of
    /// them from one list, so `ALL` (and thus `conformance::CANONICAL`) can never
    /// drift from the consts: a new key added to this list automatically joins
    /// `ALL`, making the Gate-5 registry self-maintaining.
    macro_rules! field_keys {
        ($( $(#[$doc:meta])* $name:ident = $value:literal ),+ $(,)?) => {
            $( $(#[$doc])* pub const $name: &str = $value; )+
            /// Every canonical field key, generated from the consts above.
            /// `conformance::CANONICAL` re-exports this as the Gate-5 registry.
            pub const ALL: &[&str] = &[$($name),+];
        };
    }

    field_keys! {
        /// Slot number (`u64`). Lives on the duty / attestation / block / sign span.
        SLOT = "slot",
        /// Epoch number (`u64`). Lives on the duty span.
        EPOCH = "epoch",
        /// Validator index (`u64`).
        VALIDATOR_INDEX = "validator_index",
        /// Truncated public key (`0x{first10}...{last8}`, via `TruncatedPubkey`).
        PUBKEY = "pubkey",
        /// Duty kind string (see [`Duty`]).
        DUTY = "duty",
        /// Correlation id for one signing / API request (including the :9000 hop).
        REQUEST_ID = "request_id",
        /// Committee index (`u64`).
        COMMITTEE_INDEX = "committee_index",
        /// Subcommittee index (`u64`) — sync-committee contribution lines only.
        SUBCOMMITTEE_INDEX = "subcommittee_index",
        /// Redacted beacon-node URL (via `RedactedUrl`).
        BN_URL = "bn_url",
        /// Attested head root (truncated via `TruncatedRoot`).
        HEAD = "head",
        /// Proposed block root (truncated via `TruncatedRoot`).
        BLOCK_ROOT = "block_root",
        /// Time into slot (duration / ms) — operator timing signal.
        TIME_INTO_SLOT = "time_into_slot",
    }

    /// Canonical `duty` value strings.
    ///
    /// `as_str()` returns a `&'static str` so it is `Copy`-cheap and safe to use inside an
    /// eagerly-evaluated `#[instrument(fields(duty = %Duty::….as_str()))]` (research R1).
    /// Spellings are normative — `sync_committee`, not the Prysm/Lodestar variants.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Duty {
        Attestation,
        Block,
        Aggregate,
        SyncCommittee,
        SyncContribution,
        ValidatorRegistration,
        BuilderRequestAuth,
        VoluntaryExit,
    }

    impl Duty {
        /// Returns the normative `&'static str` spelling for this duty.
        pub fn as_str(&self) -> &'static str {
            match self {
                Duty::Attestation => "attestation",
                Duty::Block => "block",
                Duty::Aggregate => "aggregate",
                Duty::SyncCommittee => "sync_committee",
                Duty::SyncContribution => "sync_contribution",
                Duty::ValidatorRegistration => "validator_registration",
                Duty::BuilderRequestAuth => "builder_request_auth",
                Duty::VoluntaryExit => "voluntary_exit",
            }
        }
    }
}

/// Mints a fresh `request_id` (a v4 UUID) for one signing / API request.
///
/// Returns a [`uuid::Uuid`], **not** a pre-built `String`, so callers render it with `%`
/// and pay nothing when the span level is disabled (ADR-002). The id follows a single
/// request end to end, including across the :9000 Web3Signer hop.
pub fn new_request_id() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

/// Returns `true` once per `n` calls, advancing a caller-owned counter — a
/// dependency-light **1-in-`n` log sampler** for the highest-volume `trace`/`debug`
/// loop sites (issue 5.3, P2-1).
///
/// Each hot call site owns its own `static CTR: AtomicU64`; the predicate emits on the
/// 1st call and every `n`-th call thereafter (`old % n == 0`), so the first hit of a
/// fresh run is never silently dropped. `Relaxed` ordering is intentional: sampling is a
/// volume-reduction heuristic, not a correctness barrier, so cross-thread interleaving
/// that merely skews which calls emit is acceptable and the cheapest atomic to pay.
///
/// **Zero-cost-when-disabled (the crux, Gate 4 guards it).** This MUST sit **behind**
/// the level check so a disabled site never bumps the counter nor allocates. Use an
/// explicit [`tracing::enabled!`] guard — the outer check compiles to a cheap level test
/// (free when the level is off), and the sampler runs only when the level is enabled:
///
/// ```ignore
/// use std::sync::atomic::AtomicU64;
/// static CTR: AtomicU64 = AtomicU64::new(0);
/// if tracing::enabled!(tracing::Level::TRACE)
///     && observability::logging::should_log_sampled(&CTR, 16)
/// {
///     tracing::trace!(slot = slot, validator_index = idx, "hot per-validator line");
/// }
/// ```
///
/// Never wrap an `info` milestone in this — the heartbeat must stay complete
/// ([`STANDARD.md` §6]). Sample only designated `trace`/`debug` hot loops, and document
/// each sampled site in `plan/logging/OPERATOR_GUIDE.md` so an operator knows a 1-in-`n`
/// line is sampled, not accidentally dropped.
///
/// `n == 0` is treated as `1` (emit every call) so a mis-supplied rate can never divide
/// by zero or silence a site entirely.
pub fn should_log_sampled(counter: &std::sync::atomic::AtomicU64, n: u64) -> bool {
    let n = n.max(1);
    let old = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    old.is_multiple_of(n)
}

/// Fills a deferred (`field::Empty`) span field with a `Display` value.
///
/// The target field **must** have been declared at span creation (e.g.
/// `request_id = tracing::field::Empty`); recording a field that was **not** declared is a
/// silent no-op — the #1 "vanishing attribute" bug. This helper exists because the `%`/`?`
/// sigils are macro sugar and are **not** available at a `span.record(...)` call site.
///
/// **Secret-safety (STANDARD.md §3):** `val` is rendered verbatim, so it MUST be
/// non-secret — wrap pubkeys in `TruncatedPubkey`, roots/signatures in `TruncatedRoot`, and
/// URLs in `RedactedUrl`; never pass key material, passwords, or mnemonics. The recorded
/// value surfaces only on events emitted **while the span is entered** (or via
/// `#[instrument]` / `.in_scope()`).
pub fn record_display(span: &tracing::Span, key: &'static str, val: impl std::fmt::Display) {
    span.record(key, tracing::field::display(val));
}

/// Fills a deferred (`field::Empty`) span field with a `Debug` value.
///
/// Same contract as [`record_display`], including its secret-safety rule: the field must be
/// declared at span creation or the record is silently dropped, and you must never
/// `?`-format secret-bearing data (e.g. a type that derives `Debug` over key material).
pub fn record_debug(span: &tracing::Span, key: &'static str, val: impl std::fmt::Debug) {
    span.record(key, tracing::field::debug(val));
}

/// Gate 5 (canonical-field-name conformance) advisory helper.
///
/// Given the field keys observed on emitted events, [`conformance::non_canonical_keys`] returns the ones
/// that are neither in the canonical [`fields`] registry nor on the documented advisory
/// allow-list. It is a pure function (no subscriber needed) so it is unit-testable and can
/// drive a captured-subscriber gate — Phase 4 wires it **advisory**, Phase 5 escalates it to
/// **blocking**. `fields` is the single source of truth this diffs against (STANDARD.md).
pub mod conformance {
    use super::fields;

    /// The canonical field-key registry — exactly [`fields::ALL`], which the
    /// `field_keys!` macro generates from the same list as the consts. So a new
    /// canonical key automatically joins this set; it cannot be added to the
    /// registry yet omitted here (the drift is structurally impossible, not
    /// guarded by a test).
    pub const CANONICAL: &[&str] = fields::ALL;

    /// Non-registry keys the STANDARD permits on events, so the advisory diff stays
    /// meaningful rather than noisy. Each carries a one-line rationale:
    pub const ADVISORY_ALLOW: &[&str] = &[
        "count",   // generic cardinality on a milestone/summary event (e.g. validators loaded)
        "error",   // the `err`-once / error-display field on a failure event
        "phase",   // slot-phase label emitted by `timing` / the orchestrator
        "network", // resource attribute (intentionally not a per-event `fields` const)
    ];

    /// Returns the observed keys that are **not** canonical and **not** advisory-allowed,
    /// preserving input order. The OpenTelemetry semantic-convention namespaces `http.*` and
    /// `otel.*` (e.g. `http.status_code`, `otel.kind`, used by `beacon`) are allowed — they
    /// are deliberate OTel conventions, not rs-vc synonyms.
    pub fn non_canonical_keys<'a>(observed: impl IntoIterator<Item = &'a str>) -> Vec<&'a str> {
        // Returns offenders verbatim and in input order (no trim/dedup) so an
        // advisory report names the exact stray keys, including typos/duplicates.
        observed.into_iter().filter(|&k| !is_allowed(k)).collect()
    }

    fn is_allowed(key: &str) -> bool {
        CANONICAL.contains(&key)
            || ADVISORY_ALLOW.contains(&key)
            || key.starts_with("http.")
            || key.starts_with("otel.")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Gate 5 conformance tests ---

    #[test]
    fn non_canonical_keys_all_canonical_is_empty() {
        assert!(conformance::non_canonical_keys(["slot", "epoch"]).is_empty());
    }

    #[test]
    fn non_canonical_keys_flags_synonyms_in_input_order() {
        assert_eq!(
            conformance::non_canonical_keys(["rvc.slot", "val_idx"]),
            vec!["rvc.slot", "val_idx"]
        );
    }

    #[test]
    fn non_canonical_keys_mixed_returns_only_offenders() {
        assert_eq!(
            conformance::non_canonical_keys(["slot", "val_idx", "epoch", "rvc.foo"]),
            vec!["val_idx", "rvc.foo"]
        );
    }

    #[test]
    fn non_canonical_keys_allows_advisory_and_otel_namespaces() {
        assert!(conformance::non_canonical_keys([
            "count",
            "error",
            "phase",
            "network",
            "http.status_code",
            "otel.kind",
        ])
        .is_empty());
    }

    #[test]
    fn canonical_is_exactly_the_generated_field_registry() {
        // CANONICAL is `fields::ALL`, generated by the `field_keys!` macro from
        // the same list as the consts — so a new canonical key cannot be added
        // without joining CANONICAL (drift is structurally impossible). This
        // test pins the wiring + the registry size.
        assert_eq!(conformance::CANONICAL, fields::ALL);
        assert!(conformance::CANONICAL.contains(&fields::SLOT));
        assert!(conformance::CANONICAL.contains(&fields::TIME_INTO_SLOT));
        assert_eq!(conformance::CANONICAL.len(), 12);
    }

    // --- TruncatedPubkey tests ---

    #[test]
    fn test_truncated_pubkey_long_with_prefix() {
        let pubkey = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
        let result = TruncatedPubkey::new(pubkey).to_string();
        assert_eq!(result, "0x93247f2209...611df74a");
    }

    #[test]
    fn test_truncated_pubkey_long_without_prefix() {
        let pubkey = "93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a";
        let result = TruncatedPubkey::new(pubkey).to_string();
        assert_eq!(result, "0x93247f2209...611df74a");
    }

    #[test]
    fn test_truncated_pubkey_short_with_prefix() {
        let result = TruncatedPubkey::new("0xabcdef").to_string();
        assert_eq!(result, "0xabcdef");
    }

    #[test]
    fn test_truncated_pubkey_short_without_prefix() {
        let result = TruncatedPubkey::new("abcdef").to_string();
        assert_eq!(result, "0xabcdef");
    }

    #[test]
    fn test_truncated_pubkey_exactly_18_chars() {
        let result = TruncatedPubkey::new("0x123456789012345678").to_string();
        assert_eq!(result, "0x123456789012345678");
    }

    #[test]
    fn test_truncated_pubkey_19_chars_truncated() {
        let result = TruncatedPubkey::new("0x1234567890123456789").to_string();
        assert_eq!(result, "0x1234567890...23456789");
    }

    #[test]
    fn test_truncated_pubkey_empty() {
        let result = TruncatedPubkey::new("").to_string();
        assert_eq!(result, "0x");
    }

    #[test]
    fn test_truncated_pubkey_non_ascii_falls_back() {
        let input = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74à";
        let result = TruncatedPubkey::new(input).to_string();
        assert_eq!(result, "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74à");
    }

    // -- CQ-2.5: strip_prefix_strict adoption test --

    /// TruncatedPubkey must warn and fall back to the raw input when given a double-0x prefix.
    /// Behavior: no panic, the raw string is emitted as-is, and a warn! log fires.
    #[test]
    #[tracing_test::traced_test]
    fn test_truncated_pubkey_double_0x_prefix_warns_and_falls_back() {
        let pubkey = "0x0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a";
        let result = TruncatedPubkey::new(pubkey).to_string();
        // Must not panic; raw input is emitted as-is
        assert_eq!(result, pubkey, "double-0x input must be returned verbatim");
        assert!(logs_contain("double 0x prefix"), "expected warn log about double prefix");
    }

    // --- RedactedUrl tests ---

    #[test]
    fn test_redacted_url_with_credentials() {
        let url = "http://user:pass@example.com/path";
        let result = RedactedUrl(url).to_string();
        assert!(result.contains("***:***@"));
        assert!(result.contains("example.com/path"));
    }

    #[test]
    fn test_redacted_url_without_credentials() {
        let url = "http://example.com/path";
        let result = RedactedUrl(url).to_string();
        assert_eq!(result, "http://example.com/path");
    }

    #[test]
    fn test_redacted_url_invalid() {
        let url = "not a url";
        let result = RedactedUrl(url).to_string();
        assert_eq!(result, "not a url");
    }

    #[test]
    fn test_redacted_url_username_only() {
        let url = "http://user@example.com/path";
        let result = RedactedUrl(url).to_string();
        assert!(result.contains("***"));
        assert!(!result.contains("user@"));
    }

    // --- TruncatedRoot tests ---

    #[test]
    fn test_truncated_root_32_bytes() {
        let result = TruncatedRoot::new(&[0xab; 32]).to_string();
        assert_eq!(result, "0xababababab...abababab");
        // 0x (2) + 10 leading hex + "..." (3) + 8 trailing hex = 23 chars.
        // NOTE: Issue 1.2's acceptance text "exactly 22" is a miscount of this same
        // breakdown (0x + 10 + ... + 8 = 23); the canonical rendering is 23 chars.
        assert_eq!(result.len(), 23);
    }

    #[test]
    fn test_truncated_root_distinct_bytes() {
        // 0x00,0x01,...,0x1f — first 5 bytes -> 0001020304, last 4 -> 1c1d1e1f.
        let root: [u8; 32] = std::array::from_fn(|i| i as u8);
        assert_eq!(TruncatedRoot::new(&root).to_string(), "0x0001020304...1c1d1e1f");
    }

    /// Redaction (Gate-3 style): the FULL hex of a 32-byte root MUST be absent from a
    /// `trace`-level log line that renders it via `%TruncatedRoot`; only the truncated
    /// form appears.
    #[test]
    #[tracing_test::traced_test]
    fn test_truncated_root_full_hex_absent_at_trace() {
        let root: [u8; 32] = std::array::from_fn(|i| i as u8);
        tracing::trace!(root = %TruncatedRoot::new(&root), "computed signing root");
        let full_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert!(logs_contain("0x0001020304...1c1d1e1f"), "truncated form must be present");
        assert!(!logs_contain(full_hex), "full 32-byte hex must NOT appear");
        // A middle slice that exists only in the full encoding must be absent too.
        assert!(!logs_contain("0a0b0c0d"), "middle bytes must be truncated away");
    }

    #[test]
    fn test_truncated_root_empty_no_panic() {
        assert_eq!(TruncatedRoot::new(&[]).to_string(), "0x");
    }

    #[test]
    fn test_truncated_root_one_byte() {
        assert_eq!(TruncatedRoot::new(&[0xab]).to_string(), "0xab");
    }

    #[test]
    fn test_truncated_root_eight_bytes_full() {
        // 8 bytes (< 9): full lower-hex, not truncated.
        assert_eq!(TruncatedRoot::new(&[0xab; 8]).to_string(), "0xabababababababab");
    }

    #[test]
    fn test_truncated_root_nine_bytes_truncates() {
        // 9 bytes is the threshold: 5 leading + 4 trailing exactly cover it, no overlap.
        let bytes: [u8; 9] = std::array::from_fn(|i| i as u8);
        assert_eq!(TruncatedRoot::new(&bytes).to_string(), "0x0001020304...05060708");
    }

    // --- fields registry + Duty tests ---

    #[test]
    fn test_field_const_values_match_registry() {
        assert_eq!(fields::SLOT, "slot");
        assert_eq!(fields::EPOCH, "epoch");
        assert_eq!(fields::VALIDATOR_INDEX, "validator_index");
        assert_eq!(fields::PUBKEY, "pubkey");
        assert_eq!(fields::DUTY, "duty");
        assert_eq!(fields::REQUEST_ID, "request_id");
        assert_eq!(fields::COMMITTEE_INDEX, "committee_index");
        assert_eq!(fields::SUBCOMMITTEE_INDEX, "subcommittee_index");
        assert_eq!(fields::BN_URL, "bn_url");
        assert_eq!(fields::HEAD, "head");
        assert_eq!(fields::BLOCK_ROOT, "block_root");
        assert_eq!(fields::TIME_INTO_SLOT, "time_into_slot");
    }

    #[test]
    fn test_duty_as_str_pins_all_eight_variants() {
        use fields::Duty;
        assert_eq!(Duty::Attestation.as_str(), "attestation");
        assert_eq!(Duty::Block.as_str(), "block");
        assert_eq!(Duty::Aggregate.as_str(), "aggregate");
        assert_eq!(Duty::SyncCommittee.as_str(), "sync_committee");
        assert_eq!(Duty::SyncContribution.as_str(), "sync_contribution");
        assert_eq!(Duty::ValidatorRegistration.as_str(), "validator_registration");
        assert_eq!(Duty::BuilderRequestAuth.as_str(), "builder_request_auth");
        assert_eq!(Duty::VoluntaryExit.as_str(), "voluntary_exit");
    }

    // --- correlation kit tests ---

    #[test]
    fn test_new_request_id_is_v4_and_unique() {
        let a = new_request_id();
        let b = new_request_id();
        assert_eq!(a.get_version(), Some(uuid::Version::Random));
        assert_ne!(a, b, "two successive request ids must differ");
    }

    /// A field declared `field::Empty` at span creation is filled by `record_display` and
    /// inherits to a child event under a capturing subscriber.
    #[test]
    #[tracing_test::traced_test]
    fn test_record_display_fills_declared_empty_field() {
        let span = tracing::info_span!("req", request_id = tracing::field::Empty);
        let _e = span.enter();
        let id = new_request_id();
        record_display(&span, fields::REQUEST_ID, id);
        tracing::info!("request handled");
        assert!(logs_contain(&id.to_string()), "recorded request_id must appear on the event");
    }

    /// Recording a field that was NOT declared at span creation is a silent no-op — this
    /// documents the foot-gun the helper guards against.
    #[test]
    #[tracing_test::traced_test]
    fn test_record_to_undeclared_field_is_silent_noop() {
        let span = tracing::info_span!("req"); // no fields declared
        let _e = span.enter();
        record_display(&span, "undeclared_key", "sentinel_value_xyz");
        tracing::info!("request handled");
        assert!(
            !logs_contain("sentinel_value_xyz"),
            "an undeclared field must be silently dropped"
        );
    }

    /// `record_debug` behaves identically to `record_display` for a `Debug` value.
    #[test]
    #[tracing_test::traced_test]
    fn test_record_debug_fills_declared_empty_field() {
        let span = tracing::info_span!("op", marker = tracing::field::Empty);
        let _e = span.enter();
        record_debug(&span, "marker", "dbg_sentinel_987");
        tracing::info!("done");
        assert!(logs_contain("dbg_sentinel_987"), "recorded debug value must appear on the event");
    }

    // --- should_log_sampled (1-in-N log sampler, issue 5.3) tests ---

    use std::sync::atomic::{AtomicU64, Ordering};

    /// 1-in-N: over `N` calls the predicate is `true` exactly once, and the first call of
    /// a fresh counter always emits (so a run never silently drops its opening line).
    #[test]
    fn test_should_log_sampled_one_in_n() {
        let ctr = AtomicU64::new(0);
        let n = 16;
        let emitted = (0..n).filter(|_| should_log_sampled(&ctr, n)).count();
        assert_eq!(emitted, 1, "exactly one emit per window of N");
        // Over K full windows the emit count is exactly K.
        let ctr = AtomicU64::new(0);
        let k = 5u64;
        let emitted = (0..(k * n)).filter(|_| should_log_sampled(&ctr, n)).count() as u64;
        assert_eq!(emitted, k, "K windows of N produce exactly K emits");
    }

    /// The very first consultation of a fresh counter emits (`0 % n == 0`).
    #[test]
    fn test_should_log_sampled_first_call_emits() {
        let ctr = AtomicU64::new(0);
        assert!(should_log_sampled(&ctr, 100), "first call must emit");
        // Subsequent calls within the window are suppressed.
        assert!(!should_log_sampled(&ctr, 100));
    }

    /// `n == 1` (and the degenerate `n == 0`, clamped to 1) emit on every call.
    #[test]
    fn test_should_log_sampled_rate_one_and_zero_emit_every_call() {
        let ctr = AtomicU64::new(0);
        assert!((0..50).all(|_| should_log_sampled(&ctr, 1)), "rate 1 emits every call");
        let ctr = AtomicU64::new(0);
        assert!(
            (0..50).all(|_| should_log_sampled(&ctr, 0)),
            "rate 0 clamps to 1, emits every call"
        );
    }

    /// The predicate advances the supplied counter by exactly one per call — so a caller
    /// can reason about the counter directly (this is what the zero-cost-when-disabled
    /// guard test inspects: a DISABLED site must leave the counter untouched).
    #[test]
    fn test_should_log_sampled_advances_counter_by_one() {
        let ctr = AtomicU64::new(0);
        for expected in 0..10u64 {
            assert_eq!(ctr.load(Ordering::Relaxed), expected);
            should_log_sampled(&ctr, 4);
        }
        assert_eq!(ctr.load(Ordering::Relaxed), 10);
    }
}
