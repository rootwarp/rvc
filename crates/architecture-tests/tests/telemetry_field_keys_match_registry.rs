//! ADR-002 cross-crate key pin (T8 / TRC-2e).
//!
//! `telemetry::TRACE_ID_KEY` / `SPAN_ID_KEY` and `observability::logging::fields::TRACE_ID` /
//! `SPAN_ID` are independently spelled string literals. Drift between them would silently
//! break log↔trace joins. This gate keeps the two crates' spellings equal.
//!
//! Dev-dep only (`telemetry.workspace = true` in this crate's `[dev-dependencies]`):
//! production DAG unchanged — see `architecture_no_cycles` `build_edge_map` (:132) and
//! zero-out-edge leaves (:74-82/:326-342).

/// T8: telemetry correlator keys must match the observability field registry.
#[test]
fn telemetry_field_keys_match_registry() {
    assert_eq!(
        telemetry::TRACE_ID_KEY,
        observability::logging::fields::TRACE_ID,
        "TRACE_ID_KEY must equal fields::TRACE_ID (ADR-002 / TRC-2e)"
    );
    assert_eq!(
        telemetry::SPAN_ID_KEY,
        observability::logging::fields::SPAN_ID,
        "SPAN_ID_KEY must equal fields::SPAN_ID (ADR-002 / TRC-2e)"
    );
}
