//! Named, panic-containing task registry for the composition root (ADR-001).
//!
//! Every background future is registered with a static name and a [`ShutdownTier`].
//! A per-task monitor joins the work handle so a panic surfaces immediately as
//! [`ShutdownReason::Failure`] rather than as a silent leak.
//!
//! Task lifecycle metrics (A-A5): exactly two series —
//! `rvc_tasks_running{task}` and `rvc_task_exits_total{task,outcome}`.
//!
//! Shutdown drains tiers in order (Ingress → Orchestrator → Background → Telemetry)
//! under per-tier budgets ([`TierBudget`]). Process metrics land in ARCH-2f.

use std::fmt::Display;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use metrics::definitions::{task_exit_outcome, RVC_TASKS_RUNNING, RVC_TASK_EXITS_TOTAL};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::{error, warn};

/// Drain order. Lower tiers drain first; each tier is fully drained (or its
/// budget expires) before the next begins.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShutdownTier {
    /// Surfaces admitting NEW work: keymanager API, gRPC. Stopped first, so a
    /// keymanager import cannot land during orchestrator teardown.
    Ingress,
    /// Duty orchestrator and liveness loop. In-flight publishes complete here.
    Orchestrator,
    /// Refreshers and monitors, incl. registered bn-manager SSE / sync-status.
    Background,
    /// Metrics HTTP + SIGHUP log reload. Drained last so logging guards owned
    /// by `main` flush after all HTTP work is gone.
    Telemetry,
}

/// Why the process is stopping. Enum shape from Lighthouse; transport is rvc's.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    /// Clean, operator-driven or intentional stop.
    Success(&'static str),
    /// A registered task panicked or otherwise failed fatally.
    Failure(&'static str),
}

impl ShutdownReason {
    /// Human-readable reason string (the static label carried by the variant).
    pub fn message(&self) -> &'static str {
        match self {
            Self::Success(msg) | Self::Failure(msg) => msg,
        }
    }
}

/// Per-tier wall-clock budgets. Defaults sum to A-7's 5 s total process budget:
/// Ingress 2.0 / Orchestrator 2.0 / Background 0.5 / Telemetry 0.5.
///
/// Consumed by [`TaskExecutor::shutdown`]. RA-5: Telemetry stays 0.5 s (abort-drain)
/// until the metrics server is converted to cooperative shutdown (ARCH-2g); that
/// conversion would raise Telemetry to 2.0 s and the process total to 6.5 s.
#[derive(Copy, Clone, Debug)]
pub struct TierBudget([Duration; 4]);

impl Default for TierBudget {
    fn default() -> Self {
        Self([
            Duration::from_millis(2000),
            Duration::from_millis(2000),
            Duration::from_millis(500),
            Duration::from_millis(500),
        ])
    }
}

impl TierBudget {
    /// Build a budget from explicit per-tier durations
    /// (`[Ingress, Orchestrator, Background, Telemetry]`).
    pub const fn new(budgets: [Duration; 4]) -> Self {
        Self(budgets)
    }

    /// Budget for a single tier, indexed by [`ShutdownTier`] discriminant order.
    pub fn for_tier(&self, tier: ShutdownTier) -> Duration {
        self.0[tier as usize]
    }

    /// Sum of all tier budgets (A-7 total process budget when using [`Default`]).
    pub fn total(&self) -> Duration {
        self.0.iter().copied().sum()
    }
}

/// Result of draining every registered task.
pub struct ShutdownOutcome {
    /// Tasks whose monitors joined within their tier budget.
    pub joined: Vec<&'static str>,
    /// Tasks that exceeded their tier budget and were aborted.
    pub aborted: Vec<&'static str>,
}

struct Registered {
    name: &'static str,
    /// Drain order key (Ingress → … → Telemetry).
    tier: ShutdownTier,
    /// Aborts the work task when its tier budget expires.
    work: AbortHandle,
    /// The monitor; joining it proves the work task finished.
    monitor: JoinHandle<()>,
}

/// Composition-root task registry: named spawns, panic containment, joined shutdown.
///
/// Entry points:
/// - [`spawn`](Self::spawn) — root owns a `()` future (`tokio::spawn` inside).
/// - [`register`](Self::register) — primitive; wrap an existing [`JoinHandle`].
/// - [`spawn_result`](Self::spawn_result) / [`register_result`](Self::register_result) —
///   `Result`-returning tasks. `Ok(Err(_))` records outcome `error` and requests
///   failure shutdown. Criticality stays the call site's [`ShutdownTier`].
///
/// `register` wraps Infra `JoinHandle`s at the composition root (DAG). ARCH-3l
/// registers `BnManager::start_sse`'s handle as `"bn.sse"`; a separate
/// `"bn.sse.cancel"` forwarder maps the process token onto `watch<bool>`.
/// DSR-2.1 likewise registers `BnManager::start_sync_monitor` as
/// `"bn.sync_monitor"` (+ `"bn.sync_monitor.cancel"`). `keymanager-api`
/// lifecycle is per-pubkey/C5-owned.
pub struct TaskExecutor {
    token: CancellationToken,
    shutdown_tx: mpsc::Sender<ShutdownReason>,
    registry: Arc<Mutex<Vec<Registered>>>,
    /// Exit classifications (`ok` / `error` / `panic` / `cancelled`) in completion order.
    /// Written by every monitor; read by unit tests (ARCH-2f will also drive metrics).
    exits: Arc<Mutex<Vec<(&'static str, &'static str)>>>,
}

impl TaskExecutor {
    /// Build an executor bound to the process shutdown token.
    ///
    /// Returns the executor and the single `ShutdownReason` receiver, which the
    /// composition root selects on alongside `shutdown_signal()`.
    ///
    /// The reason channel is bounded (`mpsc::channel(8)`); monitors use `try_send`
    /// only so panic reporting can never block (C9 anchor 6).
    pub fn new(token: CancellationToken) -> (Self, mpsc::Receiver<ShutdownReason>) {
        let (shutdown_tx, shutdown_rx) = mpsc::channel(8);
        let executor = Self {
            token,
            shutdown_tx,
            registry: Arc::new(Mutex::new(Vec::new())),
            exits: Arc::new(Mutex::new(Vec::new())),
        };
        (executor, shutdown_rx)
    }

    /// Clone of the process cancellation token for cooperative tasks.
    ///
    /// Identical usage to today's `shutdown.clone()` at `bootstrap/tasks.rs`.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }

    /// Entry point 1 — composition root owns the future.
    ///
    /// Defined as `register(name, tier, tokio::spawn(fut))`; no duplicated monitor.
    pub fn spawn<F>(&self, name: &'static str, tier: ShutdownTier, fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.register(name, tier, tokio::spawn(fut));
    }

    /// Entry point 2 — **the primitive**. Wrap an existing work [`JoinHandle`].
    ///
    /// Generic over `R` because real handles are not all `JoinHandle<()>` —
    /// `BackgroundTasks::metrics_handle` is `JoinHandle<Result<(), std::io::Error>>`.
    ///
    /// # Call-site status (VD-2d)
    ///
    /// ARCH-3l calls `register("bn.sse", Background, start_sse_handle)` at the
    /// call site so `bn-manager` stays Infra. DSR-2.1 registers
    /// `start_sync_monitor` the same way (`"bn.sync_monitor"`).
    /// `keymanager-api` lifecycle is per-pubkey/C5-owned.
    ///
    /// # Monitor / registry split
    ///
    /// The monitor task holds the work `JoinHandle`; the registry holds the work's
    /// `AbortHandle`. Aborting the monitor would not stop the work — `shutdown`
    /// aborts `work`, then joins `monitor`.
    pub fn register<R: Send + 'static>(
        &self,
        name: &'static str,
        tier: ShutdownTier,
        handle: JoinHandle<R>,
    ) {
        let work = handle.abort_handle();
        let tx = self.shutdown_tx.clone();
        let exits = Arc::clone(&self.exits);
        RVC_TASKS_RUNNING.with_label_values(&[name]).inc();
        let monitor = tokio::spawn(async move {
            let outcome = match handle.await {
                Ok(_) => task_exit_outcome::OK,
                Err(e) if e.is_panic() => {
                    let _ = tx.try_send(ShutdownReason::Failure(name));
                    task_exit_outcome::PANIC
                }
                Err(_) => task_exit_outcome::CANCELLED,
            };
            RVC_TASKS_RUNNING.with_label_values(&[name]).dec();
            RVC_TASK_EXITS_TOTAL.with_label_values(&[name, outcome]).inc();
            exits.lock().push((name, outcome));
        });
        self.registry.lock().push(Registered { name, tier, work, monitor });
    }

    /// Feature-disabled case. Registers nothing when `None`.
    ///
    /// Replaces the finished-no-op-handle idiom at `slashing_monitor.rs` so a
    /// disabled feature contributes zero registry entries.
    pub fn register_opt<R: Send + 'static>(
        &self,
        name: &'static str,
        tier: ShutdownTier,
        handle: Option<JoinHandle<R>>,
    ) {
        if let Some(handle) = handle {
            self.register(name, tier, handle);
        }
    }

    /// Wrap a [`JoinHandle`] whose output is `Result<T, E>`.
    ///
    /// `Ok(Ok(_))` records [`task_exit_outcome::OK`]. `Ok(Err(e))` records
    /// [`task_exit_outcome::ERROR`], logs `e`, and `try_send`s
    /// [`ShutdownReason::Failure`]. A panic records [`task_exit_outcome::PANIC`]
    /// and sends `Failure`. An abort records [`task_exit_outcome::CANCELLED`].
    ///
    /// [`register`](Self::register) is unchanged: a `JoinHandle<Result<_, _>>`
    /// passed there still classifies every `Ok` as a clean exit.
    pub fn register_result<T, E>(
        &self,
        name: &'static str,
        tier: ShutdownTier,
        handle: JoinHandle<Result<T, E>>,
    ) where
        T: Send + 'static,
        E: Display + Send + 'static,
    {
        let work = handle.abort_handle();
        let tx = self.shutdown_tx.clone();
        let exits = Arc::clone(&self.exits);
        RVC_TASKS_RUNNING.with_label_values(&[name]).inc();
        let monitor = tokio::spawn(async move {
            let outcome = match handle.await {
                Ok(Ok(_)) => task_exit_outcome::OK,
                Ok(Err(e)) => {
                    let _ = tx.try_send(ShutdownReason::Failure(name));
                    error!(task = name, error = %e, "registered task returned an error");
                    task_exit_outcome::ERROR
                }
                Err(e) if e.is_panic() => {
                    let _ = tx.try_send(ShutdownReason::Failure(name));
                    task_exit_outcome::PANIC
                }
                Err(_) => task_exit_outcome::CANCELLED,
            };
            RVC_TASKS_RUNNING.with_label_values(&[name]).dec();
            RVC_TASK_EXITS_TOTAL.with_label_values(&[name, outcome]).inc();
            exits.lock().push((name, outcome));
        });
        self.registry.lock().push(Registered { name, tier, work, monitor });
    }

    /// [`spawn`](Self::spawn) for a `Result`-returning future.
    ///
    /// Defined as `register_result(name, tier, tokio::spawn(fut))`, so the
    /// `tokio::spawn` stays inside this module.
    pub fn spawn_result<F, T, E>(&self, name: &'static str, tier: ShutdownTier, fut: F)
    where
        F: Future<Output = Result<T, E>> + Send + 'static,
        T: Send + 'static,
        E: Display + Send + 'static,
    {
        self.register_result(name, tier, tokio::spawn(fut));
    }

    /// Cancel the process token once, then drain registered tasks tier by tier.
    ///
    /// Drain order is [`ShutdownTier`] ascending: Ingress → Orchestrator →
    /// Background → Telemetry. Each tier is given `budget.for_tier(tier)` wall
    /// time to join cooperatively; stragglers are `work.abort()`ed, logged at
    /// `warn` with their static name, and recorded in
    /// [`ShutdownOutcome::aborted`].
    ///
    /// Consumes `self` so a double drain cannot compile.
    pub async fn shutdown(self, budget: TierBudget) -> ShutdownOutcome {
        // Exactly once — cooperative tasks across all tiers observe the same cancel.
        self.token.cancel();

        let registered = {
            let mut guard = self.registry.lock();
            std::mem::take(&mut *guard)
        };

        let mut by_tier: [Vec<Registered>; 4] = [Vec::new(), Vec::new(), Vec::new(), Vec::new()];
        for r in registered {
            by_tier[r.tier as usize].push(r);
        }

        let mut joined = Vec::new();
        let mut aborted = Vec::new();

        const TIERS: [ShutdownTier; 4] = [
            ShutdownTier::Ingress,
            ShutdownTier::Orchestrator,
            ShutdownTier::Background,
            ShutdownTier::Telemetry,
        ];

        for tier in TIERS {
            let tasks = std::mem::take(&mut by_tier[tier as usize]);
            if tasks.is_empty() {
                continue;
            }
            Self::drain_tier(tasks, budget.for_tier(tier), &mut joined, &mut aborted).await;
        }

        ShutdownOutcome { joined, aborted }
    }

    /// Join every monitor in `tasks` within `tier_budget`. On expiry, abort
    /// unfinished work (warn + name) and finish joining monitors.
    async fn drain_tier(
        tasks: Vec<Registered>,
        tier_budget: Duration,
        joined: &mut Vec<&'static str>,
        aborted: &mut Vec<&'static str>,
    ) {
        // JoinSet owns the monitors so a tier timeout never drops a JoinHandle
        // (dropping would detach and make stragglers unjoinable).
        let mut join_set = tokio::task::JoinSet::new();
        let mut work_handles = Vec::with_capacity(tasks.len());
        let mut names = Vec::with_capacity(tasks.len());

        for (idx, r) in tasks.into_iter().enumerate() {
            names.push(r.name);
            work_handles.push(r.work);
            let monitor = r.monitor;
            join_set.spawn(async move {
                let _ = monitor.await;
                idx
            });
        }

        let n = names.len();
        let mut finished = vec![false; n];
        let mut was_aborted = vec![false; n];
        let deadline = tokio::time::Instant::now() + tier_budget;
        let mut timed_out = false;

        while finished.iter().any(|&f| !f) {
            if !timed_out {
                let now = tokio::time::Instant::now();
                if now >= deadline {
                    timed_out = true;
                    for (idx, work) in work_handles.iter().enumerate() {
                        if finished[idx] {
                            continue;
                        }
                        if !work.is_finished() {
                            work.abort();
                            warn!(
                                task = names[idx],
                                "tier budget expired; aborting straggler task"
                            );
                            was_aborted[idx] = true;
                            aborted.push(names[idx]);
                        }
                    }
                }
            }

            if timed_out {
                match join_set.join_next().await {
                    Some(Ok(idx)) => {
                        finished[idx] = true;
                        if !was_aborted[idx] {
                            joined.push(names[idx]);
                        }
                    }
                    Some(Err(_)) => {
                        // Wrapper JoinSet task failed; treat remaining as done.
                        break;
                    }
                    None => break,
                }
            } else {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                match tokio::time::timeout(remaining, join_set.join_next()).await {
                    Ok(Some(Ok(idx))) => {
                        finished[idx] = true;
                        joined.push(names[idx]);
                    }
                    Ok(Some(Err(_))) => break,
                    Ok(None) => break,
                    Err(_) => {
                        // Budget exhausted; next loop iteration aborts stragglers.
                    }
                }
            }
        }
    }

    /// Static names of currently registered tasks (ARCH-2g / diagnostics).
    pub fn registered_names(&self) -> Vec<&'static str> {
        self.registry.lock().iter().map(|r| r.name).collect()
    }

    #[cfg(test)]
    fn registry_len(&self) -> usize {
        self.registry.lock().len()
    }

    #[cfg(test)]
    pub(crate) fn registry_entries(&self) -> Vec<(&'static str, ShutdownTier)> {
        self.registry.lock().iter().map(|r| (r.name, r.tier)).collect()
    }

    #[cfg(test)]
    async fn wait_exits(&self, n: usize) {
        loop {
            if self.exits.lock().len() >= n {
                return;
            }
            tokio::task::yield_now().await;
        }
    }

    #[cfg(test)]
    fn recorded_outcomes(&self) -> Vec<(&'static str, &'static str)> {
        self.exits.lock().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::time::Duration;

    fn running_gauge(name: &str) -> i64 {
        RVC_TASKS_RUNNING.with_label_values(&[name]).get()
    }

    fn exit_count(name: &str, outcome: &str) -> u64 {
        RVC_TASK_EXITS_TOTAL.with_label_values(&[name, outcome]).get()
    }

    fn running_series_exists(task: &str) -> bool {
        metrics::REGISTRY
            .gather()
            .iter()
            .filter(|mf| mf.name() == "rvc_tasks_running")
            .flat_map(|mf| mf.get_metric())
            .any(|m| m.get_label().iter().any(|l| l.name() == "task" && l.value() == task))
    }

    fn exits_series_exists(task: &str) -> bool {
        metrics::REGISTRY
            .gather()
            .iter()
            .filter(|mf| mf.name() == "rvc_task_exits_total")
            .flat_map(|mf| mf.get_metric())
            .any(|m| m.get_label().iter().any(|l| l.name() == "task" && l.value() == task))
    }

    #[tokio::test]
    async fn test_panicking_task_reports_failure_reason() {
        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());
        exec.spawn("boom_task", ShutdownTier::Background, async {
            panic!("boom");
        });

        let reason = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("timeout waiting for ShutdownReason")
            .expect("channel closed without reason");

        assert_eq!(reason, ShutdownReason::Failure("boom_task"));
        assert_eq!(reason.message(), "boom_task");
    }

    #[tokio::test]
    async fn test_register_is_generic_over_handle_output() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());

        let io_handle: JoinHandle<Result<(), io::Error>> =
            tokio::spawn(async { Ok::<(), io::Error>(()) });
        exec.register("metrics_like", ShutdownTier::Telemetry, io_handle);

        let unit_handle: JoinHandle<()> = tokio::spawn(async {});
        exec.register("unit_task", ShutdownTier::Background, unit_handle);

        assert_eq!(exec.registry_len(), 2);
        let entries = exec.registry_entries();
        assert_eq!(
            entries,
            vec![
                ("metrics_like", ShutdownTier::Telemetry),
                ("unit_task", ShutdownTier::Background),
            ]
        );

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(2))
            .await
            .expect("handles should finish");
        let outcomes = exec.recorded_outcomes();
        assert!(outcomes.iter().all(|(_, o)| *o == "ok"));
    }

    #[tokio::test]
    async fn test_spawn_is_register_of_tokio_spawn() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());

        exec.spawn("spawned_a", ShutdownTier::Ingress, async {});
        exec.spawn("spawned_b", ShutdownTier::Orchestrator, async {});

        assert_eq!(exec.registry_len(), 2);
        assert_eq!(
            exec.registry_entries(),
            vec![("spawned_a", ShutdownTier::Ingress), ("spawned_b", ShutdownTier::Orchestrator),]
        );

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(2))
            .await
            .expect("spawned tasks should finish");
    }

    #[tokio::test]
    async fn test_register_opt_none_registers_nothing() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        assert_eq!(exec.registry_len(), 0);

        exec.register_opt::<()>("disabled_feature", ShutdownTier::Background, None);
        assert_eq!(exec.registry_len(), 0);
        assert!(exec.recorded_outcomes().is_empty());

        let handle = tokio::spawn(async {});
        exec.register_opt("enabled_feature", ShutdownTier::Background, Some(handle));
        assert_eq!(exec.registry_len(), 1);
        assert_eq!(exec.registry_entries(), vec![("enabled_feature", ShutdownTier::Background)]);
    }

    #[tokio::test]
    async fn test_monitor_try_send_never_blocks_when_channel_full() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        // Leave the receiver unread so the capacity-8 channel fills.

        const FILL: [&str; 8] =
            ["fill_0", "fill_1", "fill_2", "fill_3", "fill_4", "fill_5", "fill_6", "fill_7"];
        for name in FILL {
            exec.spawn(name, ShutdownTier::Background, async {
                panic!("fill channel");
            });
        }

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(8))
            .await
            .expect("fill monitors must complete (try_send, not send().await)");

        exec.spawn("ninth", ShutdownTier::Background, async {
            panic!("ninth");
        });

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(9))
            .await
            .expect("ninth monitor must complete when channel is full — proves try_send");

        let outcomes = exec.recorded_outcomes();
        assert_eq!(outcomes.len(), 9);
        assert!(outcomes.iter().all(|(_, o)| *o == "panic"));
    }

    #[tokio::test]
    async fn test_clean_exit_reports_ok_not_panic() {
        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());

        exec.spawn("clean_task", ShutdownTier::Background, async {
            // normal return
        });

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(1))
            .await
            .expect("clean task should finish");

        assert_eq!(exec.recorded_outcomes(), vec![("clean_task", "ok")]);

        // No Failure reason must be delivered for a clean exit.
        let leftover = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(
            leftover.is_err(),
            "clean exit must not push ShutdownReason::Failure, got {leftover:?}"
        );
    }

    #[test]
    fn test_tier_budget_default_sums_to_five_seconds() {
        let budget = TierBudget::default();
        assert_eq!(budget.total(), Duration::from_secs(5));
        assert_eq!(budget.for_tier(ShutdownTier::Ingress), Duration::from_secs(2));
        assert_eq!(budget.for_tier(ShutdownTier::Orchestrator), Duration::from_secs(2));
        assert_eq!(budget.for_tier(ShutdownTier::Background), Duration::from_millis(500));
        assert_eq!(budget.for_tier(ShutdownTier::Telemetry), Duration::from_millis(500));
    }

    #[test]
    fn test_shutdown_tier_ord_is_drain_order() {
        assert!(ShutdownTier::Ingress < ShutdownTier::Orchestrator);
        assert!(ShutdownTier::Orchestrator < ShutdownTier::Background);
        assert!(ShutdownTier::Background < ShutdownTier::Telemetry);
    }

    /// Drop-guard records task name when the work future is dropped (abort or exit).
    struct ExitOrder {
        name: &'static str,
        order: Arc<Mutex<Vec<&'static str>>>,
    }

    impl Drop for ExitOrder {
        fn drop(&mut self) {
            self.order.lock().push(self.name);
        }
    }

    /// RED-first against a flat `join_all`/abort-everything drain: register in reverse
    /// tier order so registration order ≠ drain order; abort-on-drop records sequence.
    #[tokio::test]
    async fn test_drain_order_is_ingress_before_orchestrator_before_telemetry() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        let order = Arc::new(Mutex::new(Vec::new()));

        // Registration order deliberately reversed vs drain order.
        for (name, tier) in [
            ("telemetry", ShutdownTier::Telemetry),
            ("background", ShutdownTier::Background),
            ("orchestrator", ShutdownTier::Orchestrator),
            ("ingress", ShutdownTier::Ingress),
        ] {
            let order = Arc::clone(&order);
            exec.spawn(name, tier, async move {
                let _guard = ExitOrder { name, order };
                std::future::pending::<()>().await;
            });
        }

        // Short equal budgets so each tier aborts promptly; order is abort order.
        let budget = TierBudget::new([
            Duration::from_millis(40),
            Duration::from_millis(40),
            Duration::from_millis(40),
            Duration::from_millis(40),
        ]);
        let outcome = exec.shutdown(budget).await;

        assert_eq!(
            *order.lock(),
            vec!["ingress", "orchestrator", "background", "telemetry"],
            "work futures must drop in tier drain order, not registration order"
        );
        assert_eq!(outcome.aborted, vec!["ingress", "orchestrator", "background", "telemetry"]);
        assert!(outcome.joined.is_empty());
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_tier_budget_expiry_aborts_and_names_the_task() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        exec.spawn("stuck_forever", ShutdownTier::Background, async {
            std::future::pending::<()>().await;
        });

        let budget = TierBudget::new([
            Duration::from_millis(20),
            Duration::from_millis(20),
            Duration::from_millis(50),
            Duration::from_millis(20),
        ]);
        let outcome = exec.shutdown(budget).await;

        assert_eq!(outcome.aborted, vec!["stuck_forever"]);
        assert!(outcome.joined.is_empty());
        assert!(logs_contain("stuck_forever"), "warn must name the aborted task");
        assert!(
            logs_contain("tier budget expired") || logs_contain("aborting straggler"),
            "warn must explain the abort"
        );
    }

    #[tokio::test]
    async fn test_total_budget_is_the_sum_not_the_max() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());

        for (name, tier) in [
            ("s_ingress", ShutdownTier::Ingress),
            ("s_orchestrator", ShutdownTier::Orchestrator),
            ("s_background", ShutdownTier::Background),
            ("s_telemetry", ShutdownTier::Telemetry),
        ] {
            exec.spawn(name, tier, async {
                std::future::pending::<()>().await;
            });
        }

        let per = Duration::from_millis(80);
        let budget = TierBudget::new([per, per, per, per]);
        let expected_sum = budget.total();
        assert_eq!(expected_sum, per * 4);

        let start = std::time::Instant::now();
        let outcome = exec.shutdown(budget).await;
        let elapsed = start.elapsed();

        assert_eq!(outcome.aborted.len(), 4);
        assert!(outcome.joined.is_empty());

        // Sum, not max: four sequential tier budgets. Allow slack for scheduling.
        assert!(
            elapsed >= expected_sum.saturating_sub(Duration::from_millis(30)),
            "drain wall-clock {elapsed:?} should be ≈ sum {expected_sum:?}, not max {per:?}"
        );
        assert!(
            elapsed < expected_sum + Duration::from_millis(200),
            "drain wall-clock {elapsed:?} exceeded sum {expected_sum:?} + slack"
        );
        // Strictly longer than a single tier (rules out max-of-tiers drain).
        assert!(
            elapsed > per + Duration::from_millis(40),
            "elapsed {elapsed:?} looks like max-tier drain ({per:?}), not sum"
        );
    }

    #[tokio::test]
    async fn test_cooperative_task_joins_well_inside_budget() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        let token = exec.token();
        exec.spawn("cooperative", ShutdownTier::Orchestrator, async move {
            token.cancelled().await;
        });

        let budget = TierBudget::new([
            Duration::from_millis(200),
            Duration::from_millis(200),
            Duration::from_millis(200),
            Duration::from_millis(200),
        ]);
        let start = std::time::Instant::now();
        let outcome = exec.shutdown(budget).await;
        let elapsed = start.elapsed();

        assert_eq!(outcome.joined, vec!["cooperative"]);
        assert!(outcome.aborted.is_empty());
        // Join is not proxied by sleep; cooperative cancel should finish quickly.
        assert!(
            elapsed < Duration::from_millis(150),
            "cooperative join took {elapsed:?}, expected well inside budget"
        );
    }

    #[tokio::test]
    async fn test_running_gauge_returns_to_zero_after_drain() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());

        // Three long-running tasks across tiers so the gauge is observable before drain.
        exec.spawn("gauge_drain_ingress", ShutdownTier::Ingress, async {
            std::future::pending::<()>().await;
        });
        exec.spawn("gauge_drain_orch", ShutdownTier::Orchestrator, async {
            std::future::pending::<()>().await;
        });
        exec.spawn("gauge_drain_telem", ShutdownTier::Telemetry, async {
            std::future::pending::<()>().await;
        });

        // Let the register-side gauge incs become visible.
        tokio::task::yield_now().await;

        let names = ["gauge_drain_ingress", "gauge_drain_orch", "gauge_drain_telem"];
        let sum: i64 = names.iter().map(|n| running_gauge(n)).sum();
        assert_eq!(sum, 3, "gauge must read 3 while tasks are registered and running");

        let outcome = exec.shutdown(TierBudget::default()).await;
        // pending::<()> tasks ignore the token, so they hit tier budget → abort.
        assert_eq!(
            outcome.joined.len() + outcome.aborted.len(),
            3,
            "every registered task must be accounted for in ShutdownOutcome"
        );

        for n in names {
            assert_eq!(
                running_gauge(n),
                0,
                "gauge for {n} must return to 0 after drain (abort path dec)"
            );
            assert!(
                exit_count(n, task_exit_outcome::CANCELLED) >= 1,
                "aborted task {n} must record outcome=cancelled"
            );
        }
    }

    #[tokio::test]
    async fn test_running_gauge_returns_to_zero_after_panic() {
        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());

        exec.spawn("gauge_panic_task", ShutdownTier::Background, async {
            panic!("boom for gauge");
        });

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(1))
            .await
            .expect("panicking task monitor must complete");

        assert_eq!(running_gauge("gauge_panic_task"), 0, "panic path must dec rvc_tasks_running");
        let _ = rx.recv().await;
        let _ = exec.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn test_panic_exit_is_labelled_panic_not_ok() {
        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());
        let before_panic = exit_count("panic_label_task", task_exit_outcome::PANIC);
        let before_ok = exit_count("panic_label_task", task_exit_outcome::OK);

        exec.spawn("panic_label_task", ShutdownTier::Background, async {
            panic!("labelled panic");
        });

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(1))
            .await
            .expect("panic monitor must complete");

        assert_eq!(exit_count("panic_label_task", task_exit_outcome::PANIC), before_panic + 1);
        assert_eq!(
            exit_count("panic_label_task", task_exit_outcome::OK),
            before_ok,
            "panic must not be labelled ok"
        );
        assert_eq!(exec.recorded_outcomes(), vec![("panic_label_task", "panic")]);

        let reason = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout")
            .expect("reason");
        assert_eq!(reason, ShutdownReason::Failure("panic_label_task"));
        let _ = exec.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn test_abort_exit_is_labelled_cancelled() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        let before = exit_count("abort_label_task", task_exit_outcome::CANCELLED);

        exec.spawn("abort_label_task", ShutdownTier::Background, async {
            std::future::pending::<()>().await;
        });
        tokio::task::yield_now().await;
        assert_eq!(running_gauge("abort_label_task"), 1);

        let _ = exec.shutdown(TierBudget::default()).await;

        assert_eq!(running_gauge("abort_label_task"), 0);
        assert_eq!(exit_count("abort_label_task", task_exit_outcome::CANCELLED), before + 1);
    }

    /// RR1-09: `spawn_result` returning `Ok(Err(e))` is outcome `error`, not `ok`.
    ///
    /// `Failure(name)` is sent so the composition root drains and exits 16.
    #[tokio::test]
    #[tracing_test::traced_test]
    async fn spawn_result_task_returning_err_records_error_outcome() {
        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());
        const NAME: &str = "err_outcome_task";
        let before_ok = exit_count(NAME, task_exit_outcome::OK);

        exec.spawn_result(NAME, ShutdownTier::Orchestrator, async {
            Err::<(), _>("orchestrator blew up")
        });

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(1))
            .await
            .expect("error task monitor must complete");

        assert_eq!(
            exit_count(NAME, task_exit_outcome::ERROR),
            1,
            "Ok(Err) must increment rvc_task_exits_total{{outcome=\"error\"}}"
        );
        assert_eq!(
            exit_count(NAME, task_exit_outcome::OK),
            before_ok,
            "Ok(Err) must not be labelled ok"
        );
        assert_eq!(exec.recorded_outcomes(), vec![(NAME, task_exit_outcome::ERROR)]);

        let reason = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for ShutdownReason")
            .expect("channel closed without reason");
        assert_eq!(reason, ShutdownReason::Failure(NAME));
        assert_eq!(running_gauge(NAME), 0, "error path must dec rvc_tasks_running");
        assert!(
            logs_contain("orchestrator blew up"),
            "error log must include the Display of the returned error"
        );

        let outcome = exec.shutdown(TierBudget::default()).await;
        assert!(
            outcome.joined.contains(&NAME) || outcome.aborted.contains(&NAME),
            "Failure must be followed by a drain that accounts for {NAME}: joined={:?} aborted={:?}",
            outcome.joined,
            outcome.aborted,
        );
    }

    #[tokio::test]
    async fn spawn_result_ok_records_ok_and_sends_no_failure() {
        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());
        const NAME: &str = "ok_result_task";

        exec.spawn_result(NAME, ShutdownTier::Background, async { Ok::<(), String>(()) });

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(1))
            .await
            .expect("ok result task should finish");

        assert_eq!(exit_count(NAME, task_exit_outcome::OK), 1);
        assert_eq!(exit_count(NAME, task_exit_outcome::ERROR), 0);
        assert_eq!(exec.recorded_outcomes(), vec![(NAME, task_exit_outcome::OK)]);

        let leftover = tokio::time::timeout(Duration::from_millis(50), rx.recv()).await;
        assert!(leftover.is_err(), "Ok(Ok) must not push ShutdownReason, got {leftover:?}");
        let _ = exec.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn spawn_result_panic_records_panic_and_failure() {
        async fn boom() -> Result<(), String> {
            panic!("spawn_result boom");
        }

        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());
        const NAME: &str = "panic_result_task";

        exec.spawn_result(NAME, ShutdownTier::Background, boom());

        tokio::time::timeout(Duration::from_secs(2), exec.wait_exits(1))
            .await
            .expect("panic result monitor must complete");

        assert_eq!(exit_count(NAME, task_exit_outcome::PANIC), 1);
        assert_eq!(exit_count(NAME, task_exit_outcome::OK), 0);
        assert_eq!(exit_count(NAME, task_exit_outcome::ERROR), 0);
        assert_eq!(exec.recorded_outcomes(), vec![(NAME, task_exit_outcome::PANIC)]);

        let reason = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("timeout waiting for ShutdownReason")
            .expect("channel closed without reason");
        assert_eq!(reason, ShutdownReason::Failure(NAME));
        let _ = exec.shutdown(TierBudget::default()).await;
    }

    #[tokio::test]
    async fn spawn_result_abort_records_cancelled() {
        let (exec, mut rx) = TaskExecutor::new(CancellationToken::new());
        const NAME: &str = "abort_result_task";
        let before_ok = exit_count(NAME, task_exit_outcome::OK);
        let before_error = exit_count(NAME, task_exit_outcome::ERROR);

        exec.spawn_result(NAME, ShutdownTier::Background, async {
            std::future::pending::<Result<(), String>>().await
        });
        tokio::task::yield_now().await;

        let outcome = exec.shutdown(TierBudget::default()).await;

        assert_eq!(exit_count(NAME, task_exit_outcome::CANCELLED), 1);
        assert_eq!(exit_count(NAME, task_exit_outcome::OK), before_ok);
        assert_eq!(exit_count(NAME, task_exit_outcome::ERROR), before_error);
        assert!(
            outcome.joined.contains(&NAME) || outcome.aborted.contains(&NAME),
            "aborted result task must be drained: joined={:?} aborted={:?}",
            outcome.joined,
            outcome.aborted,
        );
        // Drain drops the sender. A queued Failure would still be readable.
        let queued = rx.try_recv();
        assert!(queued.is_err(), "abort must not push ShutdownReason::Failure, got {queued:?}");
    }

    #[tokio::test]
    async fn test_register_opt_none_creates_no_series() {
        let (exec, _rx) = TaskExecutor::new(CancellationToken::new());
        const NAME: &str = "arch2f_opt_none_disabled";

        // Ensure a clean slate for this unique label (other tests use different names).
        assert!(!running_series_exists(NAME), "precondition: no running series for {NAME}");
        assert!(!exits_series_exists(NAME), "precondition: no exits series for {NAME}");

        exec.register_opt::<()>(NAME, ShutdownTier::Background, None);
        assert_eq!(exec.registry_len(), 0);

        assert!(
            !running_series_exists(NAME),
            "register_opt(None) must not create rvc_tasks_running{{task={NAME}}}"
        );
        assert!(
            !exits_series_exists(NAME),
            "register_opt(None) must not create rvc_task_exits_total series for {NAME}"
        );

        let _ = exec.shutdown(TierBudget::default()).await;
    }
}
