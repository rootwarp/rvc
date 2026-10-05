//! Slashing-protection Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{
    define_int_counter, define_int_counter_vec, register_metric, Histogram, HistogramOpts,
    IntCounter, IntCounterVec,
};

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

/// Synthetic floors written by interchange export.
///
/// One increment per synthesised attestation or block record. A failed export
/// (unrepresentable floor) increments nothing.
pub static RVC_SLASHING_EXPORT_SYNTHETIC_RECORDS_TOTAL: LazyLock<IntCounter> =
    LazyLock::new(|| {
        define_int_counter(
            "rvc_slashing_export_synthetic_records_total",
            "Total synthetic attestation and block floors written by slashing interchange export",
        )
    });

/// Members drained by one group-commit batch.
///
/// `drain_batch` observes the drained length once per non-empty drain.
/// Mean batch size is `sample_sum / sample_count`. Empty drains are not
/// observed. This does not change reserve, commit, watermark, or PRAGMA
/// behaviour.
pub static RVC_SLASHING_GROUP_COMMIT_BATCH_SIZE: LazyLock<Histogram> = LazyLock::new(|| {
    let histogram = Histogram::with_opts(
        HistogramOpts::new(
            "rvc_slashing_group_commit_batch_size",
            "Number of reserves drained into one slashing group-commit batch",
        )
        .buckets(vec![1.0, 2.0, 4.0, 8.0, 16.0, 25.0, 32.0, 50.0, 64.0, 128.0]),
    )
    .unwrap_or_else(|e| panic!("Failed to create rvc_slashing_group_commit_batch_size: {e}"));
    register_metric("rvc_slashing_group_commit_batch_size", histogram)
});

pub fn init() {
    LazyLock::force(&RVC_SLASHING_DB_PRUNE_TOTAL);
    LazyLock::force(&RVC_SLASHING_RECONCILE_TOTAL);
    LazyLock::force(&RVC_SLASHING_PRUNE_SOURCE_BOUND_RAISED_TOTAL);
    LazyLock::force(&RVC_SLASHING_IMPORT_CONFLICTS_TOTAL);
    LazyLock::force(&RVC_SLASHING_EXPORT_SYNTHETIC_RECORDS_TOTAL);
    LazyLock::force(&RVC_SLASHING_GROUP_COMMIT_BATCH_SIZE);
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }
}
