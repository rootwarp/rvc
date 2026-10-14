//! Per-BN health tracking: EMA latency, sliding window error rate, composite score.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use observability::logging::RedactedUrl;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tracing::{debug, info, warn};

/// Default EMA smoothing factor (alpha). Higher = more weight on recent samples.
const DEFAULT_EMA_ALPHA: f64 = 0.3;

/// Default sliding window size for error rate calculation.
const DEFAULT_WINDOW_SIZE: usize = 100;

/// Default health score threshold below which a BN is considered unhealthy.
const DEFAULT_UNHEALTHY_THRESHOLD: f64 = 0.2;

/// Weight for latency component in composite score.
const W_LATENCY: f64 = 0.4;

/// Weight for error rate component in composite score.
const W_ERROR_RATE: f64 = 0.6;

/// Maximum latency (5s) used for normalization. Latencies above this score 0.
const MAX_LATENCY_MS: f64 = 5000.0;

/// Mixed-fleet selections to skip before re-including an incapable BN.
/// One skip matches "excluded from the next selection"; the following
/// selection re-probes so a recovered peer is not latched out forever.
const CAPABILITY_REPROBE_SKIP: u32 = 1;

/// Per-BN health tracker.
#[derive(Debug)]
pub struct BnHealthTracker {
    endpoint: String,
    latency_ema_ms: Option<f64>,
    ema_alpha: f64,
    outcomes: VecDeque<bool>,
    window_size: usize,
    unhealthy_threshold: f64,
    /// Operations this BN cannot serve (404/405/501 on `/eth/v4`, unrecognised fork).
    /// Sticky until a later success for that same operation — never latched forever.
    incapable: HashSet<String>,
    /// Remaining mixed-fleet skips before a re-probe for each flagged operation.
    reprobe_skips: HashMap<String, AtomicU32>,
}

impl Clone for BnHealthTracker {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint.clone(),
            latency_ema_ms: self.latency_ema_ms,
            ema_alpha: self.ema_alpha,
            outcomes: self.outcomes.clone(),
            window_size: self.window_size,
            unhealthy_threshold: self.unhealthy_threshold,
            incapable: self.incapable.clone(),
            reprobe_skips: self
                .reprobe_skips
                .iter()
                .map(|(k, v)| (k.clone(), AtomicU32::new(v.load(Ordering::Relaxed))))
                .collect(),
        }
    }
}

impl BnHealthTracker {
    pub fn new(endpoint: String) -> Self {
        Self {
            endpoint,
            latency_ema_ms: None,
            ema_alpha: DEFAULT_EMA_ALPHA,
            outcomes: VecDeque::with_capacity(DEFAULT_WINDOW_SIZE),
            window_size: DEFAULT_WINDOW_SIZE,
            unhealthy_threshold: DEFAULT_UNHEALTHY_THRESHOLD,
            incapable: HashSet::new(),
            reprobe_skips: HashMap::new(),
        }
    }

    pub fn record_success(&mut self, latency: Duration) {
        let old_score = self.score();
        let was_healthy = self.is_healthy();
        let ms = latency.as_secs_f64() * 1000.0;
        self.update_latency_ema(ms);
        self.push_outcome(true);
        let new_score = self.score();
        if (new_score - old_score).abs() > 0.01 {
            debug!(
                bn_url = %RedactedUrl(&self.endpoint),
                old_score = format!("{:.3}", old_score),
                new_score = format!("{:.3}", new_score),
                "Health score changed"
            );
        }
        if !was_healthy && self.is_healthy() {
            info!(
                bn_url = %RedactedUrl(&self.endpoint),
                old_status = "unhealthy",
                new_status = "healthy",
                health_score = format!("{:.3}", new_score),
                "BN health transition"
            );
        }
    }

    pub fn record_error(&mut self) {
        let old_score = self.score();
        let was_healthy = self.is_healthy();
        self.push_outcome(false);
        let new_score = self.score();
        if (new_score - old_score).abs() > 0.01 {
            debug!(
                bn_url = %RedactedUrl(&self.endpoint),
                old_score = format!("{:.3}", old_score),
                new_score = format!("{:.3}", new_score),
                "Health score changed"
            );
        }
        if was_healthy && !self.is_healthy() {
            // A BN degrading is a handled-but-degraded event (the manager fails
            // over to healthy peers), so it is `warn`, not `info`.
            warn!(
                bn_url = %RedactedUrl(&self.endpoint),
                old_status = "healthy",
                new_status = "unhealthy",
                health_score = format!("{:.3}", new_score),
                "BN health transition"
            );
        }
    }

    pub fn latency_ema_ms(&self) -> Option<f64> {
        self.latency_ema_ms
    }

    pub fn error_rate(&self) -> f64 {
        if self.outcomes.is_empty() {
            return 0.0;
        }
        let errors = self.outcomes.iter().filter(|&&ok| !ok).count();
        errors as f64 / self.outcomes.len() as f64
    }

    pub fn score(&self) -> f64 {
        let latency_score = match self.latency_ema_ms {
            Some(ms) => (1.0 - (ms / MAX_LATENCY_MS)).max(0.0),
            None => 0.5, // neutral when no data
        };
        let error_score = 1.0 - self.error_rate();
        W_LATENCY * latency_score + W_ERROR_RATE * error_score
    }

    pub fn is_healthy(&self) -> bool {
        self.score() > self.unhealthy_threshold
    }

    /// `true` unless this operation was flagged incapable and has not succeeded since.
    pub fn is_capable(&self, operation: &str) -> bool {
        !self.incapable.contains(operation)
    }

    pub fn mark_incapable(&mut self, operation: &str) {
        self.incapable.insert(operation.to_string());
        self.reprobe_skips.insert(operation.to_string(), AtomicU32::new(CAPABILITY_REPROBE_SKIP));
    }

    pub fn mark_capable(&mut self, operation: &str) {
        self.incapable.remove(operation);
        self.reprobe_skips.remove(operation);
    }

    /// Consume one mixed-fleet skip. `true` means exclude this selection;
    /// `false` while still flagged means this selection is a re-probe.
    pub fn consume_reprobe_skip(&self, operation: &str) -> bool {
        if !self.incapable.contains(operation) {
            return false;
        }
        let Some(skips) = self.reprobe_skips.get(operation) else {
            return false;
        };
        loop {
            let n = skips.load(Ordering::Relaxed);
            if n == 0 {
                return false;
            }
            if skips.compare_exchange_weak(n, n - 1, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
                return true;
            }
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn update_latency_ema(&mut self, ms: f64) {
        self.latency_ema_ms = Some(match self.latency_ema_ms {
            Some(prev) => self.ema_alpha * ms + (1.0 - self.ema_alpha) * prev,
            None => ms,
        });
    }

    fn push_outcome(&mut self, success: bool) {
        if self.outcomes.len() >= self.window_size {
            self.outcomes.pop_front();
        }
        self.outcomes.push_back(success);
    }
}

/// Shared health trackers for all BNs.
///
/// Write-lock acquisitions are counted so selection strategies can assert
/// batched updates (one write per selection round) under test.
#[derive(Clone, Debug)]
pub struct SharedHealthTrackers {
    inner: Arc<RwLock<Vec<BnHealthTracker>>>,
    write_lock_count: Arc<AtomicUsize>,
}

impl SharedHealthTrackers {
    pub async fn read(&self) -> RwLockReadGuard<'_, Vec<BnHealthTracker>> {
        self.inner.read().await
    }

    pub async fn write(&self) -> RwLockWriteGuard<'_, Vec<BnHealthTracker>> {
        self.write_lock_count.fetch_add(1, Ordering::Relaxed);
        self.inner.write().await
    }

    /// Number of write-lock acquisitions since creation or the last reset.
    pub fn write_lock_count(&self) -> usize {
        self.write_lock_count.load(Ordering::Relaxed)
    }

    /// Resets the write-lock counter (test instrumentation).
    pub fn reset_write_lock_count(&self) {
        self.write_lock_count.store(0, Ordering::Relaxed);
    }
}

pub fn new_shared_health_trackers(endpoints: &[String]) -> SharedHealthTrackers {
    let trackers = endpoints.iter().map(|e| BnHealthTracker::new(e.clone())).collect();
    SharedHealthTrackers {
        inner: Arc::new(RwLock::new(trackers)),
        write_lock_count: Arc::new(AtomicUsize::new(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- BnHealthTracker construction --

    #[test]
    fn test_health_tracker_new() {
        let tracker = BnHealthTracker::new("http://localhost:5052".to_string());
        assert_eq!(tracker.endpoint(), "http://localhost:5052");
        assert!(tracker.latency_ema_ms().is_none());
        assert_eq!(tracker.error_rate(), 0.0);
        assert!(tracker.is_healthy());
    }

    // -- Latency EMA --

    #[test]
    fn test_health_tracker_first_latency_sets_ema() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        tracker.record_success(Duration::from_millis(100));
        assert_eq!(tracker.latency_ema_ms(), Some(100.0));
    }

    #[test]
    fn test_health_tracker_ema_smooths_latency() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        tracker.record_success(Duration::from_millis(100));
        tracker.record_success(Duration::from_millis(200));
        // EMA: 0.3 * 200 + 0.7 * 100 = 60 + 70 = 130
        let ema = tracker.latency_ema_ms().unwrap();
        assert!((ema - 130.0).abs() < 0.01, "expected ~130.0, got {ema}");
    }

    #[test]
    fn test_health_tracker_ema_converges_on_repeated() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        for _ in 0..50 {
            tracker.record_success(Duration::from_millis(50));
        }
        let ema = tracker.latency_ema_ms().unwrap();
        assert!((ema - 50.0).abs() < 1.0, "expected ~50.0, got {ema}");
    }

    // -- Error rate --

    #[test]
    fn test_health_tracker_error_rate_all_success() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        for _ in 0..10 {
            tracker.record_success(Duration::from_millis(50));
        }
        assert_eq!(tracker.error_rate(), 0.0);
    }

    #[test]
    fn test_health_tracker_error_rate_all_errors() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        for _ in 0..10 {
            tracker.record_error();
        }
        assert_eq!(tracker.error_rate(), 1.0);
    }

    #[test]
    fn test_health_tracker_error_rate_mixed() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        for _ in 0..8 {
            tracker.record_success(Duration::from_millis(50));
        }
        for _ in 0..2 {
            tracker.record_error();
        }
        assert!((tracker.error_rate() - 0.2).abs() < 0.01);
    }

    #[test]
    fn test_health_tracker_error_rate_sliding_window() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        tracker.window_size = 5;
        // Fill with errors
        for _ in 0..5 {
            tracker.record_error();
        }
        assert_eq!(tracker.error_rate(), 1.0);
        // Now push successes — errors slide out
        for _ in 0..5 {
            tracker.record_success(Duration::from_millis(50));
        }
        assert_eq!(tracker.error_rate(), 0.0);
    }

    // -- Composite score --

    #[test]
    fn test_health_tracker_score_no_data() {
        let tracker = BnHealthTracker::new("http://bn:5052".to_string());
        // No latency (0.5 neutral), no errors (1.0)
        // 0.4 * 0.5 + 0.6 * 1.0 = 0.2 + 0.6 = 0.8
        let score = tracker.score();
        assert!((score - 0.8).abs() < 0.01, "expected ~0.8, got {score}");
    }

    #[test]
    fn test_health_tracker_score_perfect() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        // Very low latency, all successes
        for _ in 0..10 {
            tracker.record_success(Duration::from_millis(10));
        }
        // latency_score = 1 - 10/5000 = 0.998
        // error_score = 1.0
        // score = 0.4 * 0.998 + 0.6 * 1.0 = 0.3992 + 0.6 = 0.9992
        let score = tracker.score();
        assert!(score > 0.99, "expected >0.99, got {score}");
    }

    #[test]
    fn test_health_tracker_score_high_latency() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        for _ in 0..10 {
            tracker.record_success(Duration::from_millis(5000));
        }
        // latency_score = 1 - 5000/5000 = 0.0
        // error_score = 1.0
        // score = 0.4 * 0 + 0.6 * 1.0 = 0.6
        let score = tracker.score();
        assert!((score - 0.6).abs() < 0.01, "expected ~0.6, got {score}");
    }

    #[test]
    fn test_health_tracker_score_all_errors() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        for _ in 0..10 {
            tracker.record_error();
        }
        // No latency (0.5 neutral), all errors (0.0)
        // score = 0.4 * 0.5 + 0.6 * 0.0 = 0.2
        let score = tracker.score();
        assert!((score - 0.2).abs() < 0.01, "expected ~0.2, got {score}");
    }

    // -- is_healthy threshold --

    #[test]
    fn test_health_tracker_unhealthy_below_threshold() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        tracker.unhealthy_threshold = 0.3;
        // All errors → score = 0.2 → below 0.3
        for _ in 0..10 {
            tracker.record_error();
        }
        assert!(!tracker.is_healthy());
    }

    #[test]
    fn test_health_tracker_healthy_above_threshold() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        tracker.unhealthy_threshold = 0.3;
        for _ in 0..10 {
            tracker.record_success(Duration::from_millis(50));
        }
        assert!(tracker.is_healthy());
    }

    #[test]
    fn test_health_tracker_recovery() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        tracker.window_size = 10;
        tracker.unhealthy_threshold = 0.3;
        // Fill with errors → unhealthy
        for _ in 0..10 {
            tracker.record_error();
        }
        assert!(!tracker.is_healthy());
        // Recover with successes
        for _ in 0..10 {
            tracker.record_success(Duration::from_millis(50));
        }
        assert!(tracker.is_healthy());
    }

    /// Issue 2.6: a BN degrading (healthy -> unhealthy) is logged at WARN (a
    /// handled-but-degraded event), and its endpoint is redacted — credentials
    /// must never appear. Driving only errors fires exactly one transition line.
    #[test]
    #[tracing_test::traced_test]
    fn test_health_degradation_logs_warn_with_redacted_bn_url() {
        let mut tracker = BnHealthTracker::new("http://user:secretpw@bn:5052".to_string());
        tracker.unhealthy_threshold = 0.3;
        for _ in 0..10 {
            tracker.record_error();
        }
        assert!(!tracker.is_healthy());

        logs_assert(|lines: &[&str]| {
            let transition = lines
                .iter()
                .find(|l| l.contains("BN health transition"))
                .ok_or_else(|| "no health transition line captured".to_string())?;
            if !transition.contains("WARN") {
                return Err(format!("degradation transition must be WARN: {transition}"));
            }
            if transition.contains("secretpw") {
                return Err(format!("bn_url credentials leaked: {transition}"));
            }
            if !transition.contains("***:***@") {
                return Err(format!("bn_url must be redacted: {transition}"));
            }
            Ok(())
        });
    }

    // -- Per-operation capability --

    #[test]
    fn test_health_tracker_capable_by_default() {
        let tracker = BnHealthTracker::new("http://bn:5052".to_string());
        assert!(tracker.is_capable("produce_block_v4"));
        assert!(tracker.is_capable("get_attester_duties"));
    }

    #[test]
    fn test_health_tracker_mark_incapable_is_sticky_per_operation() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        tracker.mark_incapable("produce_block_v4");
        assert!(!tracker.is_capable("produce_block_v4"));
        assert!(
            tracker.is_capable("get_attester_duties"),
            "capability is per-operation, not a whole-BN latch"
        );
        tracker.record_success(Duration::from_millis(10));
        assert!(
            !tracker.is_capable("produce_block_v4"),
            "latency success without an op must not clear a different operation's flag"
        );
    }

    #[test]
    fn test_health_tracker_mark_capable_clears_flag() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        tracker.mark_incapable("produce_block_v4");
        tracker.mark_capable("produce_block_v4");
        assert!(tracker.is_capable("produce_block_v4"));
        assert!(!tracker.consume_reprobe_skip("produce_block_v4"));
    }

    #[test]
    fn test_health_tracker_reprobe_skip_is_bounded() {
        let mut tracker = BnHealthTracker::new("http://bn:5052".to_string());
        tracker.mark_incapable("produce_block_v4");
        assert!(
            tracker.consume_reprobe_skip("produce_block_v4"),
            "the next selection after a gap must skip the BN"
        );
        assert!(
            !tracker.consume_reprobe_skip("produce_block_v4"),
            "the following selection must re-probe rather than latch forever"
        );
        assert!(!tracker.is_capable("produce_block_v4"));
        assert!(!tracker.consume_reprobe_skip("get_attester_duties"));
    }

    // -- SharedHealthTrackers --

    #[tokio::test]
    async fn test_shared_health_trackers_creation() {
        let endpoints = vec!["http://bn1:5052".to_string(), "http://bn2:5052".to_string()];
        let trackers = new_shared_health_trackers(&endpoints);
        let guard = trackers.read().await;
        assert_eq!(guard.len(), 2);
        assert_eq!(guard[0].endpoint(), "http://bn1:5052");
        assert_eq!(guard[1].endpoint(), "http://bn2:5052");
    }

    #[tokio::test]
    async fn test_shared_health_trackers_record() {
        let endpoints = vec!["http://bn1:5052".to_string()];
        let trackers = new_shared_health_trackers(&endpoints);
        {
            let mut guard = trackers.write().await;
            guard[0].record_success(Duration::from_millis(100));
        }
        let guard = trackers.read().await;
        assert_eq!(guard[0].latency_ema_ms(), Some(100.0));
    }
}
