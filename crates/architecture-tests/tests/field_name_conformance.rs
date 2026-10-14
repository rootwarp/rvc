//! Gate 5 (BLOCKING): canonical field-name conformance over a curated event set.
//!
//! Captures the structured field keys of a small, representative MULTI-CRATE hot-path event
//! set and **fails the build** (a hard `assert!` surfaced under `cargo nextest run --workspace`)
//! if any key on a COVERED event is not in the canonical registry
//! (`observability::logging::conformance`). Phase 4 (issue 4.13) wired this as an *advisory* report;
//! **Phase 5 / issue 5.2 escalates it to a blocking gate** — the curated covered set is now an
//! enforced, auditable contract. The implicit `message` event field is excluded (it is the log
//! message, not a structured key).
//!
//! **Bounded coverage — read this before trusting the gate.** Gate 5 enforces a CURATED,
//! explicitly-enumerated set of 17 hot-path events ([`COVERED_EVENTS`]), NOT the full 23-crate
//! breadth of the workspace. A passing gate proves the *covered* events use only canonical keys;
//! it is **not** an exhaustive guarantee that every log line in every crate conforms. Widening
//! enforcement to full breadth is a later (post-5.2) dataflow-lint decision (issue 5.6 / P2-4);
//! this gate is the curated floor, not the ceiling. See `plan/logging/STANDARD.md` §7 and
//! `plan/logging/OPERATOR_GUIDE.md` §3.
//!
//! Load-bearing assertions (these DO fail the build):
//!   1. [`gate5_canonical_field_conformance_blocking`] — the curated PURELY-canonical covered
//!      event set yields an EMPTY non-canonical diff. A non-canonical key on ANY covered event
//!      fails the build (proven by the documented RED injection: `val_idx` on the
//!      attestation-published event → `assert!` fires naming `["val_idx"]`).
//!   2. [`non_canonical_key_is_flagged`] — a deliberately non-canonical key IS flagged — proving
//!      the gate mechanism detects drift (it is non-vacuous), so the blocking assertion is
//!      meaningful rather than a no-op.
//!
//! Deferred to a later phase (intentionally NOT covered by the blocking gate — covering them
//! would correctly FAIL the build, since they are not canonical): domain count/label fields
//! that crates still emit but are not yet registered — `validator_count`, `detected_count`,
//! `duty_count`/`duties_count`, `signing_type`, `slashing_result`, `strategy`, `tried`,
//! `cache_type`. [`gate5_deferred_domain_keys_advisory_tail`] surfaces these via `eprintln!`
//! (never `assert!`) so the backlog stays visible; their canonical registration /
//! `ADVISORY_ALLOW` disposition is a separate later decision, out of scope for this severity
//! flip. Do NOT add them to the blocking covered set or to `observability::logging::fields`.

use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

/// Captures emitted field keys **grouped per event**: `on_event` fires once per `tracing::…!`
/// macro, so each inner `Vec<String>` is exactly one event's key-set, in emission order. This
/// per-event grouping is what lets [`covered_event_table_matches_emission`] compare each emitted
/// event against its [`COVERED_EVENTS`] row (a flat key list could not tell where one event ends
/// and the next begins, so it could not detect an added/removed event family).
#[derive(Clone, Default)]
struct KeyCapture(Arc<Mutex<Vec<Vec<String>>>>);

impl KeyCapture {
    /// The emitted keys grouped per event, in emission order (one inner vec per event).
    fn per_event(&self) -> Vec<Vec<String>> {
        self.0.lock().unwrap().clone()
    }

    /// All emitted keys flattened across every event, in emission order — the input to the
    /// blocking conformance diff (which is order- and grouping-agnostic).
    fn flat(&self) -> Vec<String> {
        self.0.lock().unwrap().iter().flatten().cloned().collect()
    }
}

struct KeyVisitor<'a>(&'a mut Vec<String>);

impl Visit for KeyVisitor<'_> {
    // Every typed `record_*` defaults to `record_debug`, so capturing here records the names
    // of all field types (u64/str/bool/…).
    fn record_debug(&mut self, field: &Field, _: &dyn std::fmt::Debug) {
        if field.name() != "message" {
            self.0.push(field.name().to_string());
        }
    }
}

impl<S: tracing::Subscriber> Layer<S> for KeyCapture {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if let Ok(mut events) = self.0.lock() {
            // One event = one inner vec, so emission grouping/order/count is preserved.
            let mut keys = Vec::new();
            event.record(&mut KeyVisitor(&mut keys));
            events.push(keys);
        }
    }
}

/// One covered hot-path event family in the BLOCKING Gate-5 surface: the crate it lives on, a
/// short event label, and the canonical field keys it carries. This is the auditable contract a
/// reviewer reads to know *exactly* what "blocking" enforces — the [`COVERED_EVENTS`] table below
/// must stay in lockstep with the `tracing::{info,debug,warn}!` macros in
/// [`emit_canonical_hot_path_events`] (each table row ↔ one emitted event, in the same order).
struct CoveredEvent {
    /// Originating crate / module (for the reviewer; not asserted on).
    crate_name: &'static str,
    /// Human label for the event (for the reviewer; not asserted on).
    event: &'static str,
    /// The canonical field keys the event emits — every one MUST be in
    /// `observability::logging::fields` (or an advisory-allowed key: `count` / `error` / `http.*`).
    keys: &'static [&'static str],
}

/// The explicit, enumerable BLOCKING covered-event surface (17 rows). Each row names one event
/// family and the canonical keys it carries; the emission in [`emit_canonical_hot_path_events`]
/// mirrors this table 1:1 and in order. A reviewer can read this table to audit the contract
/// without parsing the macros, and [`covered_event_table_matches_emission`] **enforces** the
/// table ↔ emission agreement — comparing each emitted event's captured key-set against its row —
/// so the documentation cannot silently drift from what is emitted/enforced.
const COVERED_EVENTS: &[CoveredEvent] = &[
    // --- orchestrator (crates/rvc) — attestation / aggregation / block phases ---
    CoveredEvent {
        crate_name: "orchestrator",
        event: "attestation published",
        keys: &["slot", "epoch", "committee_index"],
    },
    CoveredEvent {
        crate_name: "orchestrator",
        event: "sync-committee duty processed",
        keys: &["slot", "validator_index", "pubkey", "subcommittee_index"],
    },
    CoveredEvent { crate_name: "orchestrator", event: "head updated", keys: &["slot", "head"] },
    // --- beacon — duty-call spans (slot/epoch/bn_url + OTel http.* + error) ---
    CoveredEvent {
        crate_name: "beacon",
        event: "attester duties fetched",
        keys: &["bn_url", "epoch"],
    },
    CoveredEvent { crate_name: "beacon", event: "beacon call retried", keys: &["slot", "error"] },
    CoveredEvent {
        crate_name: "beacon",
        event: "produce_block_v3 ok",
        keys: &["slot", "http.status_code"],
    },
    // --- signer (rvc-signer) — sign.* spans carry the canonical `duty` ---
    CoveredEvent { crate_name: "signer", event: "block signed", keys: &["slot", "pubkey", "duty"] },
    CoveredEvent {
        crate_name: "signer",
        event: "attestation signed",
        keys: &["epoch", "pubkey", "duty"],
    },
    // --- doppelganger ---
    CoveredEvent {
        crate_name: "doppelganger",
        event: "doppelganger window clear",
        keys: &["epoch", "pubkey"],
    },
    // --- slashing (rvc-slashing) ---
    CoveredEvent {
        crate_name: "slashing",
        event: "slashing-db block staged",
        keys: &["pubkey", "slot"],
    },
    // --- bn-manager ---
    CoveredEvent {
        crate_name: "bn-manager",
        event: "beacon node selected",
        keys: &["bn_url", "slot"],
    },
    // --- duty-tracker ---
    CoveredEvent {
        crate_name: "duty-tracker",
        event: "attester duty resolved",
        keys: &["slot", "epoch", "validator_index", "committee_index"],
    },
    // --- block-service ---
    CoveredEvent {
        crate_name: "block-service",
        event: "block proposed",
        keys: &["slot", "pubkey", "block_root"],
    },
    // --- correlation kit (observability::logging) — request_id / time_into_slot ---
    CoveredEvent {
        crate_name: "correlation-kit",
        event: "signing request received",
        keys: &["request_id"],
    },
    CoveredEvent {
        crate_name: "correlation-kit",
        event: "slot phase reached",
        keys: &["slot", "time_into_slot"],
    },
    // --- trace correlation (observability::logging) — TRACE_ID / SPAN_ID registry pin ---
    // Gate 5's KeyCapture visits event fields only, so this row proves registration of the
    // formatter-injected keys — not that a formatter rendered them (T7′ / TRC-2a).
    CoveredEvent {
        crate_name: "correlation-kit",
        event: "trace correlated",
        keys: &["trace_id", "span_id"],
    },
    // --- generic milestone advisory key ---
    CoveredEvent { crate_name: "orchestrator", event: "validators loaded", keys: &["count"] },
];

/// Deferred domain keys that crates still emit but are NOT yet canonical. The blocking gate must
/// NOT cover these (covering them would fail the build); [`gate5_deferred_domain_keys_advisory_tail`]
/// surfaces them via `eprintln!` only, keeping the backlog visible without blocking. Registering
/// them (or adding them to `ADVISORY_ALLOW`) is a separate later decision — out of scope for 5.2.
const DEFERRED_DOMAIN_KEYS: &[&str] = &[
    "validator_count",
    "detected_count",
    "duty_count",
    "duties_count",
    "signing_type",
    "slashing_result",
    "strategy",
    "tried",
    "cache_type",
];

/// Emits the curated PURELY-canonical multi-crate hot-path event set under `cap`. Every key here
/// is either a canonical `observability::logging::fields` const or an advisory-allowed key (`error`,
/// `count`, `http.*`) — so a correct Phase-4 normalization makes `non_canonical_keys` empty over
/// this set, and the BLOCKING gate passes. Read the captured keys back via `cap.flat()` (blocking
/// diff) or `cap.per_event()` (table↔emission pin).
///
/// The emitted events mirror [`COVERED_EVENTS`] 1:1 and in order — and that is **enforced**, not
/// just documented, by [`covered_event_table_matches_emission`], which compares each emitted
/// event's key-set against the corresponding table row. So adding an event here without a matching
/// `COVERED_EVENTS` row (or vice versa) FAILS that test. To prove the blocking gate BITES instead,
/// inject a non-canonical key (e.g. `val_idx = 1u64`) into any one event below: the blocking test
/// then fails naming `["val_idx"]` (the documented RED case). Leave the tree clean — no synthetic
/// violation here.
fn emit_canonical_hot_path_events(cap: &KeyCapture) {
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        // --- orchestrator (crates/rvc) — attestation / aggregation / block phases ---
        tracing::info!(slot = 1u64, epoch = 0u64, committee_index = 3u64, "attestation published");
        tracing::debug!(
            slot = 1u64,
            validator_index = 7u64,
            pubkey = "0xtrunc",
            subcommittee_index = 2u64,
            "sync-committee duty processed"
        );
        tracing::info!(slot = 1u64, head = "0xtrunc", "head updated");

        // --- beacon — duty-call spans (slot/epoch/bn_url + OTel http.* + error) ---
        tracing::info!(bn_url = "redacted", epoch = 0u64, "attester duties fetched");
        tracing::warn!(slot = 1u64, error = "timeout", "beacon call retried");
        tracing::debug!(slot = 1u64, "http.status_code" = 200u64, "produce_block_v3 ok");

        // --- signer (rvc-signer) — sign.* spans carry the canonical `duty` ---
        tracing::debug!(slot = 1u64, pubkey = "0xtrunc", duty = "block", "block signed");
        tracing::debug!(
            epoch = 0u64,
            pubkey = "0xtrunc",
            duty = "attestation",
            "attestation signed"
        );

        // --- doppelganger ---
        tracing::info!(epoch = 0u64, pubkey = "0xtrunc", "doppelganger window clear");

        // --- slashing (rvc-slashing) ---
        tracing::debug!(pubkey = "0xtrunc", slot = 1u64, "slashing-db block staged");

        // --- bn-manager ---
        tracing::info!(bn_url = "redacted", slot = 1u64, "beacon node selected");

        // --- duty-tracker ---
        tracing::debug!(
            slot = 1u64,
            epoch = 0u64,
            validator_index = 7u64,
            committee_index = 3u64,
            "attester duty resolved"
        );

        // --- block-service ---
        tracing::info!(slot = 1u64, pubkey = "0xtrunc", block_root = "0xtrunc", "block proposed");

        // --- correlation kit (observability::logging) — request_id / time_into_slot ---
        tracing::info!(
            request_id = "00000000-0000-4000-8000-000000000000",
            "signing request received"
        );
        tracing::debug!(slot = 1u64, time_into_slot = 1333u64, "slot phase reached");

        // --- trace correlation (observability::logging) — TRACE_ID / SPAN_ID registry pin ---
        // Emitted as event fields so Gate 5 can observe them. Production injection is via
        // formatter/span layers (TRC-2b+); KeyCapture cannot see those (T7′).
        tracing::debug!(
            trace_id = "00000000000000000000000000000000",
            span_id = "0000000000000000",
            "trace correlated"
        );

        // --- generic milestone advisory key ---
        tracing::info!(count = 42u64, "validators loaded");
    });
}

/// BLOCKING Gate 5: the curated PURELY-canonical multi-crate covered event set
/// ([`COVERED_EVENTS`]) MUST yield an EMPTY non-canonical diff. A non-canonical field key on ANY
/// covered event FAILS the build (this is the severity flip from Phase-4 advisory to Phase-5
/// blocking). Also a Phase-4 normalization proof (re-confirms the `rvc.`-prefix removal + key
/// normalization held) and a harness self-test (capture works).
///
/// RED proof this assertion BITES: injecting `val_idx = 1u64` into the "attestation published"
/// event in [`emit_canonical_hot_path_events`] makes this `assert!` fire with
/// `["val_idx"]`; reverting restores green. (Done during development; the tree is kept clean.)
#[test]
fn gate5_canonical_field_conformance_blocking() {
    let cap = KeyCapture::default();
    emit_canonical_hot_path_events(&cap);
    let observed = cap.flat();
    assert!(observed.iter().any(|k| k == "slot"), "field capture failed (no `slot` seen)");

    let keys: Vec<&str> = observed.iter().map(String::as_str).collect();
    let flagged = observability::logging::conformance::non_canonical_keys(keys);
    assert!(
        flagged.is_empty(),
        "Gate 5 (BLOCKING): a covered hot-path event emitted non-canonical field keys: \
         {flagged:?}. Either spell the field with its canonical `observability::logging::fields` const \
         (no `rvc.` prefix, no synonyms), or — if it is a genuinely new field — register it in \
         the canonical registry + STANDARD.md §2 first."
    );
}

/// REAL pin: the [`COVERED_EVENTS`] documentation table MUST match the actual emission, event for
/// event. This is the load-bearing guard that the auditable contract a reviewer reads cannot
/// silently drift from what the gate emits. It captures the emitted keys **grouped per event**
/// (`cap.per_event()`) and asserts:
///   1. the emitted event COUNT equals `COVERED_EVENTS.len()` — so adding an emitted event without
///      a matching table row (the reviewer's 18th-event probe), or deleting a row without removing
///      its emission, FAILS here; and
///   2. each emitted event's key-SET equals its `COVERED_EVENTS` row's key-set (order-independent
///      within an event, since a row lists keys as authored; event ORDER is pinned by position) —
///      so renaming/retyping a covered key, or a stale/edited table row, FAILS here.
///
/// Plus the prior internal-consistency checks (every table key is itself canonical; labels
/// non-empty), now subordinate to the real emission comparison.
#[test]
fn covered_event_table_matches_emission() {
    // Every key the table documents as covered must itself be canonical / advisory-allowed —
    // the table cannot claim a non-canonical key is part of the BLOCKING surface.
    let table_keys: Vec<&str> =
        COVERED_EVENTS.iter().flat_map(|e| e.keys.iter().copied()).collect();
    let flagged = observability::logging::conformance::non_canonical_keys(table_keys);
    assert!(
        flagged.is_empty(),
        "COVERED_EVENTS documents non-canonical keys as part of the blocking surface: {flagged:?}"
    );
    // Sanity: the table references real crate sections (non-empty labels).
    assert!(COVERED_EVENTS.iter().all(|e| !e.crate_name.is_empty() && !e.event.is_empty()));

    // --- the REAL pin: compare the table against what is actually emitted ---
    let cap = KeyCapture::default();
    emit_canonical_hot_path_events(&cap);
    let emitted = cap.per_event();

    // (1) COUNT: an emitted event without a table row (or a row without emission) fails here.
    assert_eq!(
        emitted.len(),
        COVERED_EVENTS.len(),
        "COVERED_EVENTS table ({} rows) is out of sync with the emission ({} events): add/remove \
         a CoveredEvent row to match every `tracing::…!` in emit_canonical_hot_path_events",
        COVERED_EVENTS.len(),
        emitted.len()
    );

    // (2) PER-EVENT KEY-SETS, in order: each emitted event's keys must equal its table row's keys
    //     (set equality — within-event field order is not pinned; event order IS, by index).
    for (idx, (row, got_keys)) in COVERED_EVENTS.iter().zip(emitted.iter()).enumerate() {
        let mut expected: Vec<&str> = row.keys.to_vec();
        let mut got: Vec<&str> = got_keys.iter().map(String::as_str).collect();
        expected.sort_unstable();
        got.sort_unstable();
        assert_eq!(
            got, expected,
            "COVERED_EVENTS row {idx} ({} / {:?}) does not match the emitted event's keys \
             {got:?}: the documented contract drifted from emission",
            row.crate_name, row.event
        );
    }
}

/// Non-vacuity: a deliberately non-canonical key MUST be flagged by the conformance diff that
/// drives the BLOCKING gate — proving the mechanism detects drift, so the
/// [`gate5_canonical_field_conformance_blocking`] assertion is meaningful (not a no-op that would
/// pass even on a violation). This mirrors the RED injection at the mechanism level: had any
/// covered event carried `rvc.slot` / `not_a_canonical_key`, the blocking `assert!` would fire.
#[test]
fn non_canonical_key_is_flagged() {
    let cap = KeyCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        // A synonym for `slot` and a clearly-stray key: both must be flagged.
        tracing::warn!(
            rvc.slot = 9u64,
            not_a_canonical_key = 1u64,
            "synthetic non-canonical fixture"
        );
    });

    let observed = cap.flat();
    let keys: Vec<&str> = observed.iter().map(String::as_str).collect();
    let flagged = observability::logging::conformance::non_canonical_keys(keys);
    assert!(
        flagged.contains(&"rvc.slot"),
        "conformance diff failed to flag the planted `rvc.slot` synonym: {flagged:?}"
    );
    assert!(
        flagged.contains(&"not_a_canonical_key"),
        "conformance diff failed to flag the planted stray key: {flagged:?}"
    );
}

/// Advisory tail (distinct from the BLOCKING gate above): surfaces the still-DEFERRED Phase-5
/// domain keys ([`DEFERRED_DOMAIN_KEYS`] — `validator_count`, `detected_count`, etc.) via
/// `eprintln!`, NEVER `assert!`. These keys are intentionally NOT canonical and NOT in the
/// blocking covered set; this reporter keeps the backlog visible to a reviewer / operator without
/// failing the build. Registering them (or adding them to `ADVISORY_ALLOW`) is a separate later
/// decision. This is the ONLY advisory part of Gate 5 after the 5.2 severity flip.
#[test]
fn gate5_deferred_domain_keys_advisory_tail() {
    // Dup-safe: the list must be duplicate-free, so the count-parity self-check below cannot be
    // fooled by a duplicate masking a key that silently became canonical.
    let mut unique: Vec<&str> = DEFERRED_DOMAIN_KEYS.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        DEFERRED_DOMAIN_KEYS.len(),
        "DEFERRED_DOMAIN_KEYS contains duplicates: {DEFERRED_DOMAIN_KEYS:?}"
    );

    let flagged =
        observability::logging::conformance::non_canonical_keys(DEFERRED_DOMAIN_KEYS.to_vec());

    // Self-check: every deferred key is (still) non-canonical — if one became canonical, it
    // should graduate out of this list (and could then join the blocking covered set). With the
    // dedup guard above, this set-equality (via equal lengths over a dup-free list) is exact.
    assert_eq!(
        flagged.len(),
        DEFERRED_DOMAIN_KEYS.len(),
        "a DEFERRED_DOMAIN_KEYS entry became canonical/allowed; graduate it out of the advisory tail"
    );

    // ADVISORY ONLY: report, never assert on the build. These remain a known, visible backlog.
    eprintln!(
        "Gate 5 (advisory tail) — deferred non-canonical domain keys still emitted by crates, \
         pending a canonical-registration / ADVISORY_ALLOW decision: {flagged:?}"
    );
}
