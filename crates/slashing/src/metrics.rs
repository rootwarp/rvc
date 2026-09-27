//! Slashing-protection Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{define_int_counter, define_int_counter_vec, IntCounter, IntCounterVec};

pub use metrics::definitions::{prune_type, reconcile_outcome, tx_hold_kind};

/// Counter for slashing DB prune operations.
/// Labels: type (attestation, block)
pub static RVC_SLASHING_DB_PRUNE_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_slashing_db_prune_total",
        "Total number of slashing DB records pruned",
        &["type"],
    )
});

/// Attestation source watermarks prune actually raised.
///
/// One increment per pubkey whose stored source floor strictly increased
/// (including a floor that was absent). An equal or higher existing floor is
/// not a raise and does not increment.
pub static RVC_SLASHING_PRUNE_SOURCE_BOUND_RAISED_TOTAL: LazyLock<IntCounter> =
    LazyLock::new(|| {
        define_int_counter(
            "rvc_slashing_prune_source_bound_raised_total",
            "Total attestation source watermarks raised by slashing DB prune",
        )
    });

/// Compensating-delete outcomes for a reserved slashing history row.
///
/// Labels: `kind` — `"block"` | `"attestation"`;
/// `outcome` ∈ {`deleted`, `not_applicable`, `failed`}.
pub static RVC_SLASHING_RECONCILE_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_slashing_reconcile_total",
        "Total slashing reserve compensating-delete outcomes",
        &["kind", "outcome"],
    )
});

/// Interchange rows dropped on import (`WHERE NOT EXISTS` changed 0 rows).
///
/// One increment per dropped attestation or block. The parsed maxima still
/// raise the watermark; there is no audit table.
pub static RVC_SLASHING_IMPORT_CONFLICTS_TOTAL: LazyLock<IntCounter> = LazyLock::new(|| {
    define_int_counter(
        "rvc_slashing_import_conflicts_total",
        "Total interchange import rows dropped because a conflicting record already existed",
    )
});

pub fn init() {
    LazyLock::force(&RVC_SLASHING_DB_PRUNE_TOTAL);
    LazyLock::force(&RVC_SLASHING_RECONCILE_TOTAL);
    LazyLock::force(&RVC_SLASHING_PRUNE_SOURCE_BOUND_RAISED_TOTAL);
    LazyLock::force(&RVC_SLASHING_IMPORT_CONFLICTS_TOTAL);
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }
}
