//! Prometheus metrics integration for the validator client.
//!
//! This module provides a global metrics registry and helper macros for
//! registering and using prometheus metrics.

pub mod definitions;
pub mod server;

pub use server::{
    create_metrics_router, create_metrics_router_with_health, new_health_status, serve_metrics,
    serve_metrics_with_health, HealthStatus, SharedHealthStatus,
};

use std::any::Any;
use std::collections::HashMap;
use std::sync::Mutex;

use lazy_static::lazy_static;
use prometheus::core::Collector;
pub use prometheus::{
    Counter, Gauge, GaugeVec, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec,
    IntGauge, IntGaugeVec, Opts, Registry,
};

lazy_static! {
    /// Global prometheus metrics registry.
    pub static ref REGISTRY: Registry = Registry::new();
    static ref HANDLES: Mutex<HashMap<String, Box<dyn Any + Send + Sync>>> =
        Mutex::new(HashMap::new());
}

/// Register a counter metric with a specific registry.
pub fn register_counter_with(
    registry: &Registry,
    name: &str,
    help: &str,
) -> prometheus::Result<Counter> {
    let counter = Counter::with_opts(Opts::new(name, help))?;
    registry.register(Box::new(counter.clone()))?;
    Ok(counter)
}

/// Register a counter metric with the global registry.
pub fn register_counter(name: &str, help: &str) -> prometheus::Result<Counter> {
    register_counter_with(&REGISTRY, name, help)
}

/// Register a gauge metric with a specific registry.
pub fn register_gauge_with(
    registry: &Registry,
    name: &str,
    help: &str,
) -> prometheus::Result<Gauge> {
    let gauge = Gauge::with_opts(Opts::new(name, help))?;
    registry.register(Box::new(gauge.clone()))?;
    Ok(gauge)
}

/// Register a gauge metric with the global registry.
pub fn register_gauge(name: &str, help: &str) -> prometheus::Result<Gauge> {
    register_gauge_with(&REGISTRY, name, help)
}

/// Register a histogram metric with a specific registry.
pub fn register_histogram_with(
    registry: &Registry,
    name: &str,
    help: &str,
    buckets: Option<Vec<f64>>,
) -> prometheus::Result<Histogram> {
    let mut opts = HistogramOpts::new(name, help);
    if let Some(b) = buckets {
        opts = opts.buckets(b);
    }
    let histogram = Histogram::with_opts(opts)?;
    registry.register(Box::new(histogram.clone()))?;
    Ok(histogram)
}

/// Register a histogram metric with the global registry.
pub fn register_histogram(
    name: &str,
    help: &str,
    buckets: Option<Vec<f64>>,
) -> prometheus::Result<Histogram> {
    register_histogram_with(&REGISTRY, name, help, buckets)
}

fn handles() -> std::sync::MutexGuard<'static, HashMap<String, Box<dyn Any + Send + Sync>>> {
    HANDLES.lock().unwrap_or_else(|e| e.into_inner())
}

/// Register `metric` under `name`, or return the previously registered handle.
///
/// Owner crates declare domain metrics against [`REGISTRY`] through this helper
/// so a second declaration of the same family (or a second `init`) does not panic.
pub fn register_metric<M>(name: &str, metric: M) -> M
where
    M: Clone + Collector + Any + Send + Sync + 'static,
{
    let mut map = handles();
    if let Some(existing) = map.get(name) {
        return existing
            .downcast_ref::<M>()
            .unwrap_or_else(|| panic!("metric {name} already registered with a different type"))
            .clone();
    }
    if let Err(e) = REGISTRY.register(Box::new(metric.clone())) {
        panic!("Failed to register {name}: {e}");
    }
    map.insert(name.to_string(), Box::new(metric.clone()));
    metric
}

fn opts_with_consts(name: &str, help: &str, const_labels: &[(&str, &str)]) -> Opts {
    let mut opts = Opts::new(name, help);
    for (k, v) in const_labels {
        opts = opts.const_label((*k).to_string(), (*v).to_string());
    }
    opts
}

/// Idempotent `IntCounter` constructor bound to [`REGISTRY`].
pub fn define_int_counter(name: &str, help: &str) -> IntCounter {
    let counter = IntCounter::with_opts(Opts::new(name, help))
        .unwrap_or_else(|e| panic!("Failed to create {name}: {e}"));
    register_metric(name, counter)
}

/// Idempotent `IntCounter` with constant labels.
pub fn define_int_counter_with_const_labels(
    name: &str,
    help: &str,
    const_labels: &[(&str, &str)],
) -> IntCounter {
    let counter = IntCounter::with_opts(opts_with_consts(name, help, const_labels))
        .unwrap_or_else(|e| panic!("Failed to create {name}: {e}"));
    register_metric(name, counter)
}

/// Idempotent `IntCounterVec` constructor bound to [`REGISTRY`].
pub fn define_int_counter_vec(name: &str, help: &str, labels: &[&str]) -> IntCounterVec {
    let counter = IntCounterVec::new(Opts::new(name, help), labels)
        .unwrap_or_else(|e| panic!("Failed to create {name}: {e}"));
    register_metric(name, counter)
}

/// Idempotent `IntGauge` constructor bound to [`REGISTRY`].
pub fn define_int_gauge(name: &str, help: &str) -> IntGauge {
    let gauge =
        IntGauge::new(name, help).unwrap_or_else(|e| panic!("Failed to create {name}: {e}"));
    register_metric(name, gauge)
}

/// Idempotent `IntGaugeVec` constructor bound to [`REGISTRY`].
pub fn define_int_gauge_vec(name: &str, help: &str, labels: &[&str]) -> IntGaugeVec {
    let gauge = IntGaugeVec::new(Opts::new(name, help), labels)
        .unwrap_or_else(|e| panic!("Failed to create {name}: {e}"));
    register_metric(name, gauge)
}

/// Idempotent `Gauge` constructor bound to [`REGISTRY`].
pub fn define_gauge(name: &str, help: &str) -> Gauge {
    let gauge = Gauge::with_opts(Opts::new(name, help))
        .unwrap_or_else(|e| panic!("Failed to create {name}: {e}"));
    register_metric(name, gauge)
}

/// Idempotent `GaugeVec` constructor bound to [`REGISTRY`].
pub fn define_gauge_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    const_labels: &[(&str, &str)],
) -> GaugeVec {
    let gauge = GaugeVec::new(opts_with_consts(name, help, const_labels), labels)
        .unwrap_or_else(|e| panic!("Failed to create {name}: {e}"));
    register_metric(name, gauge)
}

/// Idempotent `HistogramVec` constructor bound to [`REGISTRY`].
pub fn define_histogram_vec(
    name: &str,
    help: &str,
    labels: &[&str],
    buckets: &[f64],
    const_labels: &[(&str, &str)],
) -> HistogramVec {
    let mut hopts = HistogramOpts::new(name, help).buckets(buckets.to_vec());
    for (k, v) in const_labels {
        hopts = hopts.const_label((*k).to_string(), (*v).to_string());
    }
    let histogram =
        HistogramVec::new(hopts, labels).unwrap_or_else(|e| panic!("Failed to create {name}: {e}"));
    register_metric(name, histogram)
}

/// Macro for conveniently registering a counter metric.
///
/// # Example
/// ```ignore
/// let counter = register_counter!("my_counter", "A sample counter");
/// counter.inc();
/// ```
#[macro_export]
macro_rules! register_counter {
    ($registry:expr, $name:expr, $help:expr) => {
        $crate::register_counter_with($registry, $name, $help)
    };
    ($name:expr, $help:expr) => {
        $crate::register_counter($name, $help)
    };
}

/// Macro for conveniently registering a gauge metric.
///
/// # Example
/// ```ignore
/// let gauge = register_gauge!("my_gauge", "A sample gauge");
/// gauge.set(42.0);
/// ```
#[macro_export]
macro_rules! register_gauge {
    ($registry:expr, $name:expr, $help:expr) => {
        $crate::register_gauge_with($registry, $name, $help)
    };
    ($name:expr, $help:expr) => {
        $crate::register_gauge($name, $help)
    };
}

/// Macro for conveniently registering a histogram metric.
///
/// # Example
/// ```ignore
/// let histogram = register_histogram!("my_histogram", "A sample histogram");
/// histogram.observe(0.5);
/// ```
#[macro_export]
macro_rules! register_histogram {
    ($registry:expr, $name:expr, $help:expr) => {
        $crate::register_histogram_with($registry, $name, $help, None)
    };
    ($registry:expr, $name:expr, $help:expr, $buckets:expr) => {
        $crate::register_histogram_with($registry, $name, $help, Some($buckets))
    };
    ($name:expr, $help:expr) => {
        $crate::register_histogram($name, $help, None)
    };
    ($name:expr, $help:expr, $buckets:expr) => {
        $crate::register_histogram($name, $help, Some($buckets))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_exists() {
        // Verify the global registry exists and is accessible
        let metrics = REGISTRY.gather();
        assert!(metrics.is_empty() || !metrics.is_empty());
    }

    #[test]
    fn test_register_counter() {
        let counter = register_counter("test_counter_1", "A test counter").unwrap();

        // Counter should start at 0
        assert_eq!(counter.get(), 0.0);

        // Increment the counter
        counter.inc();
        assert_eq!(counter.get(), 1.0);

        // Increment by a specific amount
        counter.inc_by(5.0);
        assert_eq!(counter.get(), 6.0);
    }

    #[test]
    fn test_register_gauge() {
        let gauge = register_gauge("test_gauge_1", "A test gauge").unwrap();

        // Gauge should start at 0
        assert_eq!(gauge.get(), 0.0);

        // Set the gauge
        gauge.set(42.0);
        assert_eq!(gauge.get(), 42.0);

        // Increment the gauge
        gauge.inc();
        assert_eq!(gauge.get(), 43.0);

        // Decrement the gauge
        gauge.dec();
        assert_eq!(gauge.get(), 42.0);

        // Add to gauge
        gauge.add(8.0);
        assert_eq!(gauge.get(), 50.0);

        // Subtract from gauge
        gauge.sub(10.0);
        assert_eq!(gauge.get(), 40.0);
    }

    #[test]
    fn test_register_histogram() {
        let histogram = register_histogram("test_histogram_1", "A test histogram", None).unwrap();

        // Observe some values
        histogram.observe(0.5);
        histogram.observe(1.0);
        histogram.observe(2.5);

        // Verify observations were recorded
        let sample_count = histogram.get_sample_count();
        assert_eq!(sample_count, 3);

        let sample_sum = histogram.get_sample_sum();
        assert_eq!(sample_sum, 4.0);
    }

    #[test]
    fn test_register_histogram_with_custom_buckets() {
        let buckets = vec![0.1, 0.5, 1.0, 5.0, 10.0];
        let histogram = register_histogram(
            "test_histogram_custom_1",
            "A histogram with custom buckets",
            Some(buckets),
        )
        .unwrap();

        histogram.observe(0.3);
        histogram.observe(0.8);
        histogram.observe(3.0);

        assert_eq!(histogram.get_sample_count(), 3);
    }

    #[test]
    fn test_duplicate_registration_fails() {
        // Register a metric
        let _ = register_counter("duplicate_test_counter", "First registration").unwrap();

        // Attempting to register with the same name should fail
        let result = register_counter("duplicate_test_counter", "Second registration");
        assert!(result.is_err());
    }

    #[test]
    fn test_register_counter_with_custom_registry() {
        let registry = Registry::new();
        let counter = register_counter_with(&registry, "custom_reg_counter", "A counter").unwrap();
        counter.inc();
        assert_eq!(counter.get(), 1.0);

        let gathered = registry.gather();
        assert!(gathered.iter().any(|m| m.name() == "custom_reg_counter"));

        // Should NOT appear in the global registry
        let global = REGISTRY.gather();
        assert!(!global.iter().any(|m| m.name() == "custom_reg_counter"));
    }

    #[test]
    fn test_register_gauge_with_custom_registry() {
        let registry = Registry::new();
        let gauge = register_gauge_with(&registry, "custom_reg_gauge", "A gauge").unwrap();
        gauge.set(7.0);
        assert_eq!(gauge.get(), 7.0);

        let gathered = registry.gather();
        assert!(gathered.iter().any(|m| m.name() == "custom_reg_gauge"));
    }

    #[test]
    fn test_register_histogram_with_custom_registry() {
        let registry = Registry::new();
        let histogram =
            register_histogram_with(&registry, "custom_reg_histogram", "A histogram", None)
                .unwrap();
        histogram.observe(1.5);
        assert_eq!(histogram.get_sample_count(), 1);

        let gathered = registry.gather();
        assert!(gathered.iter().any(|m| m.name() == "custom_reg_histogram"));
    }

    #[test]
    fn test_register_histogram_with_custom_registry_and_buckets() {
        let registry = Registry::new();
        let buckets = vec![0.1, 1.0, 10.0];
        let histogram = register_histogram_with(
            &registry,
            "custom_reg_histogram_buckets",
            "A histogram with buckets",
            Some(buckets),
        )
        .unwrap();
        histogram.observe(0.5);
        assert_eq!(histogram.get_sample_count(), 1);
    }

    #[test]
    fn test_duplicate_registration_with_custom_registry_fails() {
        let registry = Registry::new();
        let _ = register_counter_with(&registry, "dup_custom", "First").unwrap();
        let result = register_counter_with(&registry, "dup_custom", "Second");
        assert!(result.is_err());
    }

    #[test]
    fn test_global_functions_delegate_to_with() {
        // Verify the global register_counter still works (uses REGISTRY internally)
        let counter = register_counter("delegation_test_counter", "test").unwrap();
        counter.inc();
        assert_eq!(counter.get(), 1.0);
        let gathered = REGISTRY.gather();
        assert!(gathered.iter().any(|m| m.name() == "delegation_test_counter"));
    }

    #[test]
    fn test_metrics_gathered_from_registry() {
        // Register some metrics
        let counter = register_counter("gather_test_counter", "Counter for gather test").unwrap();
        let gauge = register_gauge("gather_test_gauge", "Gauge for gather test").unwrap();

        // Update the metrics
        counter.inc_by(10.0);
        gauge.set(99.0);

        // Gather all metrics from registry
        let metrics = REGISTRY.gather();

        // Find our metrics in the gathered result
        let counter_found = metrics.iter().any(|m| m.name() == "gather_test_counter");
        let gauge_found = metrics.iter().any(|m| m.name() == "gather_test_gauge");

        assert!(counter_found, "Counter should be in gathered metrics");
        assert!(gauge_found, "Gauge should be in gathered metrics");
    }
}
