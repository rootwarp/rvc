//! Duty-tracker Prometheus families (ARCH-6h).

use std::sync::LazyLock;

use metrics::{define_int_counter_vec, IntCounterVec};

/// Counter for duty fetch operations.
pub static RVC_DUTIES_FETCHED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec("rvc_duties_fetched_total", "Total number of duty fetch operations", &[])
});

/// Counter for PTC duty fetch operations (issue 4.6; family delta +1).
pub static RVC_PTC_DUTIES_FETCHED_TOTAL: LazyLock<IntCounterVec> = LazyLock::new(|| {
    define_int_counter_vec(
        "rvc_ptc_duties_fetched_total",
        "Total number of PTC duty fetch operations",
        &[],
    )
});

pub fn init() {
    LazyLock::force(&RVC_DUTIES_FETCHED_TOTAL);
    LazyLock::force(&RVC_PTC_DUTIES_FETCHED_TOTAL);
}

#[cfg(test)]
mod tests {
    #[test]
    fn init_twice_does_not_panic() {
        super::init();
        super::init();
    }
}
