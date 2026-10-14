# Research: Runtime Task Model (`TaskExecutor`) and Config Consolidation

> Research track for the architecture-remediation initiative on the rs-vc Cargo workspace.
> Baseline `develop` @ `0ae9a09` (v0.7.0), authored 2026-08-12.
>
> **Authoritative inputs, in precedence order:**
> [`plan/architecture-2026-08-12/prd.md`](../prd.md) (scope, requirement IDs ARCH-P1-1 … ARCH-P1-4,
> constraint register C1–C10, Assumptions A-1 … A-15) →
> [`docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md)
> (the architecture review) → the repository's [`CLAUDE.md`](../../../CLAUDE.md).
>
> **Scope.** Two structural patterns, at implementation-detail level:
> **Track A — `TaskExecutor`** (ARCH-P1-4, evidence PB-A2) and
> **Track B — config consolidation** (ARCH-P1-1 / P1-2 / P1-3, evidence PB-D1).
>
> **This document is not a restatement.** Every in-repo claim below was opened at HEAD with the
> `file:line` shown. Where the review *or the PRD* did not reproduce, the corrected fact is stated
> inline and filed under *Verification Deltas* (**RVD-1 … RVD-6**). RVD-1 and RVD-2 change what
> ARCH-P1-1 and ARCH-P1-4 should be built to do.
>
> **No-ask constraint:** every open question is resolved to a stated default in *Assumptions*
> (RA-1 … RA-11). Nothing is escalated.
>
> **Tooling limitation, stated up front.** This research ran without a shell: no `cargo clippy`,
> `cargo metadata`, `git`, or `wc` was executed. Every count below comes from `Read`/`Grep` over
> the working tree and is reproducible that way (the exact invocations are listed at the end of
> *Sources*). Claims that would require a compile or a lint run to settle are marked
> **[not empirically verified]** / **[static analysis only]** and carry an overturn condition in
> *Assumptions* — RA-8 in particular, which is the execution step for RVD-4. External sources
> **were** fetched and are cited as primary where the fetch succeeded; retrieval failures are
> recorded under *Sources → Dead links*.
>
> **Scope of this document:** research only. It changes no code and deletes nothing.

---

## Verdicts at a glance

Every question in the research brief, answered. No "it depends".

| # | Question | Verdict |
|---|---|---|
| **V1** | Port Lighthouse's `TaskExecutor` wholesale? | **No.** Port 4 of its 9 mechanisms (name, panic→`ShutdownReason`, per-task metric label, join-at-exit). Reject `HandleProvider`/`Weak<Runtime>`, `async_channel` exit-wrapping, rayon variants, `block_on_dangerous`, and the `spawn_blocking` wrappers — the last would put the C9 cancellation-proof signing core behind an executor it must not depend on. |
| **V2** | What is the minimal API? | **Two entry points, not one:** `spawn(name, tier, fut)` for the composition root, and `register(name, tier, JoinHandle)` for library crates that already return handles. `register` is non-negotiable: 4 live production spawns sit inside Infra crates (`bn-manager` ×3, `keymanager-api` ×1) that cannot depend on a bootstrap-layer executor without violating the DAG gate. |
| **V3** | Where does it live? | **`crates/rvc/src/bootstrap/executor.rs`** in Phase 2, promoted to a `rvc-task` crate only if `signer-server` adopts it (out of scope, A-13). Not a new crate now — a new crate costs a `CLASSIFICATION` row, an `ARCHITECTURE.md` regeneration, and a `Base`/`Infra` decision that ARCH-P1-8 has not yet made. |
| **V4** | How is shutdown ordering expressed? | **A `ShutdownTier` enum on registration** (`Ingress` → `Orchestrator` → `Background` → `Telemetry`), drained in order. A-7's 5 s is a **total** budget, split per tier (2.0 / 2.0 / 0.5 / 0.5 s); per-tier 5 s would blow the default k8s 30 s grace period when combined with `BackgroundTasks::shutdown`'s existing 2 s (`bootstrap/tasks.rs:22`). |
| **V5** | Does clippy `disallowed_methods` work for `tokio::spawn`? | **Yes for the free function — but it is the wrong primary gate here.** It cannot be path-scoped, and a per-crate `clippy.toml` *replaces* rather than merges the workspace file, which would silently drop the three Gate-1 secret-key bans (`clippy.toml:25-29`) for that crate. **Primary gate = a `kat_policy`-style path-scoped scanner; clippy is the secondary net, workspace-wide, deferred.** This corrects ARCH-P1-4's acceptance criterion. |
| **V6** | How many raw `tokio::spawn` sites are there, really? | **126 occurrences across 53 files. Only 9 are live production spawns in this initiative's scope** (`crates/rvc/src` + `bin/rvc/src`); 4 more are in Infra crates rvc depends on; 5 are in `signer-server`/`bin/rvc-signer` (out of scope, A-13); 25 are in the untracked orphan trees (dead by PB-E1); the remaining **83** are test or test-support. The PRD's M8 baseline of "≥4 known" is a **floor that misses 5 live sites**, including one in `bin/rvc` the PRD never names. |
| **V7** | Config: macro, figment-style layering, or derive crate? | **None of the three as posed. Adopt the reth `NodeConfig` model: make the clap `Args` group structs *be* the config sections.** Figment cannot reach G5's "one declaration per knob" *in principle* — it layers *values*, so the clap arg declaration must still exist somewhere. A declarative macro solves a problem rvc already solved. reth's model deletes two of the five sites outright. |
| **V8** | Is figment adoptable at all under C3? | **Yes, minus `Env` — and rvc would gain almost nothing.** `Figment::merge` provenance (`Metadata`) is the one real prize, and it can be had for ~40 lines of `ConfigError` context without the dependency. **Recommend: do not add figment.** C3 is honoured trivially by not adopting the library. |
| **V9** | Is `merge_with_cli` a hand-maintained fourth site? | **No — RVD-1, the sharpest correction in this document.** `merge_with_cli` is macro-generated by `merge_cli_fields!` (`config/types.rs:932-940`), which **exhaustively destructures `CliOverrides`** at `:934-936`. Clause (i) of ARCH-P1-1 ("every `CliOverrides` field is consumed in `merge_with_cli`") is **already enforced by rustc**. Building a scanner for it is redundant work. |
| **V10** | Where is the real, ungated drift hole? | **The clap → `CliOverrides` direction, and a second undocumented bypass channel.** `From<StartArgs> for CliOverrides` (`bin/rvc/src/cli.rs:587-685`) destructures `StartArgs` exhaustively but reads the 13 flattened group structs **by field access**, so a new field in `BeaconArgs` compiles silently. Separately, **8 clap args never enter `Config` at all** — they go straight to `RunOptions`/logging init (`cli.rs:738-776`). |
| **V11** | Is the gate RED at HEAD? | **No — GREEN, with a 10-entry declared list.** Hand-running ARCH-P1-1's clause (ii) found **zero** unmapped knob args: 74 group-arg fields − 8 bypass args − 1 duplicate (`no_keymanager`) = **65**, exactly matching `CliOverrides`' 65 fields. The drift hole is real and unguarded but **not yet exploited**. The PRD's "demonstrate RED against a scratch commit" is therefore the correct and only available demonstration. |
| **V12** | Concrete gate design? | **`crates/architecture-tests/tests/config_drift.rs`**, modelled line-for-line on `kat_policy.rs`: no regex crate, workspace-member walk, brace-aware struct extraction, `// config_drift_exempt: <reason>` in-source marker, plus a **shrinking-only `BYPASS` table** for the 8 `RunOptions`/timeout args and an **`ALIASES` table** for the 2 renamed knobs — which exist for *different* reasons: `no_doppelganger_detection` is a 1:1 negated rename (`cli.rs:623`), while `no_keymanager` + `keymanager_enabled` is a 2:1 collapse (`cli.rs:628-634`) and is the sole `−1` in the 74−8−1 arithmetic. It must live in `crates/architecture-tests`, not `bin/rvc`: `bin/rvc/Cargo.toml:12-14` declares no `[lib]`, and Rust has no field reflection, so the `CliOverrides` side must be scanned textually regardless. Full code sketch in B.4. |
| **V13** | Does the `RVC_*` env allow-list gate (ARCH-P1-3) work as a prefix scan? | **No — it must scan `env::var` call sites and `*_ENV` constants, not the `RVC_` prefix.** Measured: **438 `RVC_` hits across 57 files**, overwhelmingly Prometheus metric-name constants (`crates/metrics/src/definitions.rs` alone: 80). Three live env reads carry no `RVC_` prefix at all and a prefix scan misses them: `RUST_LOG`, and `OTEL_EXPORTER_OTLP_ENDPOINT` / `OTEL_TRACES_SAMPLER_ARG` (`config/types.rs:438,447`) — which are config-*else*-env fallbacks, the **opposite** precedence from figment's `Env` layer. And `RVC_LOG_FORMAT` (`crates/telemetry/src/format.rs:53`) is a live **non-security** env knob the rule must grandfather explicitly. **RVD-6.** |
| **V14** | Is there a config defect *already live* at HEAD, beyond the drift risk? | **Yes — nine knobs where clap's default silently clobbers the config file. RVD-4, a new finding.** `metrics_address`, `metrics_port`, `grpc_port`, `grpc_address`, `log_level`, `tracing_exporter`, `keymanager_body_limit`, `slashed_validators_action`, `beacon_max_body_bytes` are each initialised `Some(<clap field with a default_value>)` at `cli.rs:614-682`; `merge_with_cli` runs *after* `load_config` (`cli.rs:780-781`) and its `set` arm assigns on `Some` (`types.rs:942-946`). A TOML `metrics_port = 9090` is reset to 8080 unless `--metrics-port` is also passed. This is a **silently-inert config surface** — PB-B1/PB-B2 family, PRD Problem Statement (b) — not evolvability debt. **[Static analysis only; execution step is RA-8.]** |

---

# Track A — TaskExecutor

## A.1 Lighthouse `task_executor` — the concrete design

Source: `common/task_executor/src/lib.rs` on `stable` [1]. Nine distinct mechanisms; the review
names five. Each is listed with an explicit **adopt / reject** decision for rvc, because "adopt a
lighthouse-style `TaskExecutor`" (review, *Target architecture / Runtime model*) is not a
specification.

| # | Mechanism | Lighthouse shape | rvc decision |
|---|---|---|---|
| L1 | **Named spawns** | `&'static str` name threaded through every entry point: `pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static, name: &'static str)` | **Adopt.** The `&'static str` bound is what makes L3's metric label allocation-free. |
| L2 | **Panic containment** | private `fn spawn_monitor<R: Send>(&self, task_handle: impl Future<Output = Result<R, JoinError>> + Send + 'static, name: &'static str)`; on `join_error.try_into_panic()` sends `ShutdownReason::Failure` on `signal_tx` | **Adopt — this is the single highest-value mechanism for rvc.** Today a panicking background task is silently leaked (A.3, every row with "handle discarded"): the process keeps running with the feature dead and no signal. |
| L3 | **Per-task metrics** | `TASKS_HISTOGRAM`, `BLOCKING_TASKS_HISTOGRAM`, `BLOCK_ON_TASKS_HISTOGRAM` + `ASYNC_TASKS_COUNT`, `BLOCKING_TASKS_COUNT`, `BLOCK_ON_TASKS_COUNT` gauges, labelled by task `name` | **Adopt one gauge + one counter**, not six. rvc needs `rvc_tasks_running{task=…}` and `rvc_task_exits_total{task=…,outcome=…}` to satisfy M8's "every task has a name visible in a metric label". Histograms of task *lifetime* are meaningless for infinite loops, which is what 8 of rvc's 9 live tasks are. |
| L4 | **Exit-signal wrapping** | an `async_channel::Receiver<()>` raced against the task future; on exit the task's result becomes `None`. `spawn_without_exit` opts out. | **Reject.** rvc already has `tokio_util::sync::CancellationToken` threaded to 6 of 9 live tasks (A.3) and to the gRPC server's `serve_with_shutdown` (`bootstrap/run.rs:268-276`). Adding a second, weaker cancellation channel with a new dependency (`async_channel`) is a regression, and racing a future against a signal is exactly the drop-based cancellation PB-A2 is trying to eliminate. **The executor should take the existing `CancellationToken`, not invent an exit channel.** |
| L5 | **`ShutdownReason` + channel** | `pub enum ShutdownReason { Success(&'static str), Failure(&'static str) }` with `pub fn message(&self) -> &'static str`; channel is `futures::channel::mpsc::Sender<ShutdownReason>`; `pub fn shutdown_sender(&self) -> Sender<ShutdownReason>` | **Adopt the enum; change the channel.** rvc has no `futures::channel` usage in the composition root and already models "a subsystem asks the process to stop" with `CancellationToken` (`slashing_monitor.rs:138-139` cancels the token on `ShutdownRequested`). Use `tokio::sync::mpsc::channel::<ShutdownReason>(N)` — **bounded**, per C9's "zero unbounded channels" — with the reason recorded and the token cancelled by the single receiver. |
| L6 | **`spawn_handle`** | `pub fn spawn_handle<R: Send + 'static>(&self, task: impl Future<Output = R> + Send + 'static, name: &'static str) -> Option<JoinHandle<Option<R>>>` | **Reject as-is, replace with `register`.** The doubly-optional return (`Option<JoinHandle<Option<R>>>`) exists because `HandleProvider` may fail to upgrade a `Weak<Runtime>` (L8) — a problem rvc does not have. See V2/A.4. |
| L7 | **`spawn_blocking*` family** | `spawn_blocking`, `spawn_blocking_handle`, `spawn_blocking_with_rayon`, `spawn_blocking_with_rayon_async` | **Reject, and state why in the plan.** `spawn_blocking` in rvc is not background work: `crates/signer/src/core.rs:542` (`tokio::task::spawn_blocking(move \|\| body(session))`) is the C9 cancellation-proof stage→sign→commit core, and `signer-server/src/dvt/peer_service.rs:231,323` carry the `!Send MutexGuard`. Routing those through an executor owned by the composition root would (a) invert the DAG (`signer` is Domain; the executor is in the composition root) and (b) put a metrics/shutdown side-channel inside the one code path that must remain cancellation-proof. **`spawn_blocking` is explicitly out of executor scope and must not be added to any ban list.** |
| L8 | **`HandleProvider`** | `pub enum HandleProvider { Runtime(Weak<Runtime>), Handle(Handle) }` — lets production hold a `Weak<Runtime>` while tests hold a `Handle` | **Reject.** rvc's runtime is created by `#[tokio::main]` in `bin/rvc` and never shut down from inside; there is no `Arc<Runtime>` to weakly reference. This enum is the source of every `Option<…>` in the Lighthouse API and buys rvc nothing. |
| L9 | **`block_on_dangerous`** | `pub fn block_on_dangerous<F: Future>(&self, future: F, name: &'static str) -> Option<F::Output>` | **Reject.** No caller shape in rvc; adding it invites the `Handle::block_on`-inside-async deadlock class. |

**Net:** adopt L1, L2, L3 (slimmed), L5 (re-channelled); reject L4, L6, L7, L8, L9. That is four of
nine — which is what "minimal executor, not a wholesale port" means concretely, and it is consistent
with NG3 ("a spawn/join/metrics utility, not a framework").

## A.2 How rvc spawns tasks today

Three distinct lifecycle idioms coexist, and **none of them is joined**.

**Idiom 1 — spawn and keep the handle in a named struct (1 of 9 sites).**
`bootstrap/tasks.rs:27-30` defines `pub struct BackgroundTasks { pub metrics_handle: JoinHandle<…> }`,
populated at `:87-88` and drained at `:143-152` by `abort()` + `tokio::time::timeout(METRICS_SHUTDOWN_TIMEOUT, …)`
with `METRICS_SHUTDOWN_TIMEOUT = Duration::from_secs(2)` (`:22`). This is the *only* live task with a
bounded drain, and it is drained by **abort**, not by cooperative shutdown — the task never sees a
token. Note that two tests already pin this behaviour
(`test_spawn_background_tasks_all_tasks_cancel_on_shutdown` `:216`,
`test_shutdown_drains_metrics_server_before_returning` `:237`), so the executor migration has an
existing contract to preserve.

**Idiom 2 — spawn with a `CancellationToken`, discard the handle (5 of 9 sites).**
`tasks.rs:103` (monitoring push), `tasks.rs:124` (proposer-config refresh), `enablement.rs:170`
(secret-provider refresh, token passed into `RefreshService::with_denylist` at `:159-165`),
`slashing_monitor.rs:126`, `bin/rvc/src/logging.rs:217` (SIGHUP log-reload). Each *does* stop on
cancel; none can be waited for. The stand-in for a join is
`tokio::time::sleep(Duration::from_millis(100))` at `bootstrap/run.rs:319`.

**Idiom 3 — return a `JoinHandle` in a handle struct that the caller then throws away (2 of 9 sites).**
`liveness_loop.rs:60-65` defines `pub struct LivenessLoopSpawn { pub join: tokio::task::JoinHandle<()>, … }`
— the right shape — and `bootstrap/run.rs:170` destructures it as
`liveness_task: _liveness_loop_handle`, i.e. **bound to an underscore-prefixed name and dropped**.
`slashing_monitor::spawn` returns `JoinHandle<()>` (`:106-113`) and `bootstrap/run.rs:248-253` calls
it in statement position, discarding the return value entirely.

**Idiom 0 (the outlier) — not spawned at all.**
`bootstrap/run.rs:297-313` polls three futures inline in `tokio::select!`: the tonic `grpc_server`
(`:298`), `orchestrator.run()` (`:304`), and `shutdown_signal()` (`:310`). This is PB-A2. Note the
gRPC arm is the *only* one with real graceful shutdown — `serve_with_shutdown` at `:268-276` races
`shutdown_signal()` against `token.cancelled()`. The orchestrator arm has none.

**The ordering that exists today** (`run.rs:315-325`): `log_shutdown_initiated` →
`shutdown_token.cancel()` → `orchestrator_handle.shutdown()` (into a future that no longer exists) →
`sleep(100 ms)` → `background.shutdown().await` (abort + 2 s). Total bounded time ≈ 2.1 s, which is
the budget the executor must fit inside (see A.6).

**A note the PRD does not make.** `slashing_monitor.rs:122-123` returns `tokio::spawn(async {})` — a
*finished no-op handle* — when the feature is disabled. Any executor API must accept that shape
(a registered task that is already complete) rather than treating registration as implying liveness.
`liveness_loop`'s `Option<LivenessLoopSpawn>` (`enablement.rs:44`) is the alternative idiom for the
same "feature disabled" case. The executor should standardise on **`Option`, not a no-op handle**,
so `rvc_tasks_running{task="slashing_monitor"}` is honestly 0 rather than 1-then-0.

## A.3 Full `tokio::spawn` inventory with cleanup story

**Method.** `Grep 'tokio::spawn\('` over `**/*.rs` at HEAD: **126 occurrences across 53 files**.
Partitioned by (a) whether the file is compiled at all and (b) whether the site is inside a
`#[cfg(test)]` module, determined by comparing each hit's line number against the file's
`#[cfg(test)]` line. `spawn_blocking` is counted separately and is **out of scope** (L7).

### Partition summary

| Partition | Sites | Disposition |
|---|---|---|
| **P1 — live production, in scope** (`crates/rvc/src`, `bin/rvc/src`) | **9** | Migrate to the executor (ARCH-P1-4) |
| **P2 — live production, Infra crates rvc depends on** (`bn-manager` ×3, `keymanager-api` ×1) | **4** | `register(...)` the returned handle; do **not** move the spawn |
| **P3 — live production, `signer-server` / `bin/rvc-signer`** | 5 | Out of scope (A-13) |
| **P4 — orphan trees, never compiled** (`crates/rvc-signer/**` 18, `crates/rvc/src/main.rs` 7) | **25** | Deleted by ARCH-P0-1; must not appear in any migration list |
| **P5 — test and test-support** (`#[cfg(test)]` modules, `tests/` dirs) | **83** | Left alone; the reason clippy cannot be the primary gate (A.5) |

Partition arithmetic: 9 + 4 + 5 + 25 + 83 = **126**. ✔

**P3 derivation** (re-verified this attempt, because it is the only partition not directly enumerated
elsewhere in this document): `bin/rvc-signer/src/main.rs:124,205` (both before that file's
`#[cfg(test)]` at `:317`), `crates/signer-server/src/metrics.rs:305` (test module at `:345`),
`crates/signer-server/src/server/mod.rs:129` (test module at `:250`; `:384` and `:423` are inside
it), `crates/signer-server/src/http_api/accept_loop/mod.rs:174` (test module at `:228`) = **5**.

**One P5 caveat worth naming**, because the label is otherwise misleading: `crates/rvc-test-support/src/lib.rs:199`
is **production code in a test-support crate** — it sits before that file's `#[cfg(test)]` at `:272`.
So P5 is 82 genuinely test-only sites plus 1 test-harness helper. It is still out of scope for
ARCH-P1-4 (the harness has no shutdown story to fix), but a clippy-based ban would flag it as a
production violation, which is a small extra argument for the scanner (A.5).

### P1 — the migration list (this is what ARCH-P1-4 must actually convert)

| # | Site | What it runs | Cancellation | Handle | Joined? | Panic → ? |
|---|---|---|---|---|---|---|
| 1 | `bin/rvc/src/logging.rs:217` | SIGHUP log-level reload loop (`spawn_log_reload_handler`, `:206-217`) | `shutdown_token` (param `:209`) | discarded | no | silent leak; log reload dies |
| 2 | `crates/rvc/src/bootstrap/tasks.rs:88` | `serve_metrics_with_health` | **none** (abort-only) | `BackgroundTasks.metrics_handle` (`:29`) | **abort + 2 s** (`:146-150`) | `JoinError` swallowed by `.ok()` at `:148` |
| 3 | `crates/rvc/src/bootstrap/tasks.rs:103` | monitoring push (PB-B2) | `shutdown.clone()` `:97` | discarded | no | silent leak |
| 4 | `crates/rvc/src/bootstrap/tasks.rs:124` | proposer-config URL refresh (PB-B1) | `shutdown.clone()` `:118` | discarded | no | silent leak |
| 5 | `crates/rvc/src/bootstrap/enablement.rs:170` | secret-provider refresh (PB-B3) | inside `RefreshService` (`:164`) | discarded | no | silent leak; key admission stops |
| 6 | `crates/rvc/src/keymanager_adapters/spawn.rs:247` | Keymanager API axum server | **none** | discarded | no | silent leak; key mgmt API dies |
| 7 | `crates/rvc/src/liveness_loop.rs:355` | per-slot doppelganger liveness tick | `cancel` token (`:78`) | `LivenessLoopSpawn.join` (`:62`) | **no** — dropped at `run.rs:170` | silent leak; **keys stay `Pending` forever** |
| 8 | `crates/rvc/src/slashing_monitor.rs:123` | no-op finished handle when `SlashedAction::None` | n/a | discarded | n/a | n/a |
| 9 | `crates/rvc/src/slashing_monitor.rs:126` | slashed-validator epoch check | `shutdown_token` (`:130`) | returned, discarded at `run.rs:248` | no | silent leak; **slashed-validator detection stops** |

Rows 1, 7, 8 and 9 are **not** in the PRD's M8 baseline (`tasks.rs:103,124`, `enablement.rs:170`,
`spawn.rs:247`). Rows 7 and 9 are the two whose silent death has a safety-adjacent consequence, which
makes L2 (panic → `ShutdownReason::Failure`) the highest-value mechanism in A.1 rather than a
nice-to-have. See **RVD-3**.

### P2 — the library-crate sites that force the `register` API

| Site | Signature at HEAD | Why it cannot move |
|---|---|---|
| `crates/bn-manager/src/manager.rs:313` | inside a fn returning `tokio::task::JoinHandle<()>` (`:307`), documented at `:301` as *"The returned `JoinHandle` runs the SSE loop in a background task"* | `bn-manager` is `Layer::Foundation` today (`architecture-tests/src/lib.rs:57-92`); an edge to a composition-root executor is a DAG-gate violation and would also pre-empt ARCH-P1-8's `Base`/`Infra` decision |
| `crates/bn-manager/src/sse.rs:174` | SSE consumer loop | same |
| `crates/bn-manager/src/sync_status.rs:194` | inside a fn returning `tokio::task::JoinHandle<()>` (`:193`) | same |
| `crates/keymanager-api/src/lifecycle.rs:140` | KM-2 monitoring lifecycle (`stop_monitoring`/`cancel_monitoring`, **C5**) | `keymanager-api` depends only on `eth-types`/`metrics`/`observability` — the review calls it *"a model boundary"* (Strength 4). Adding an executor edge would destroy that property for a metrics label. |

These four already return or own handles. The correct integration is **`executor.register(name, tier, handle)`
at the composition root**, which costs zero new crate edges. This is the design constraint that
`spawn(name, fut)`-only APIs (including Lighthouse's) do not express, and it is why V2 specifies two
entry points.

## A.4 Verdict: the minimal executor for rvc

**Provenance note.** The Lighthouse signatures in A.1 were re-fetched and confirmed verbatim at
`raw.githubusercontent.com/sigp/lighthouse/stable/common/task_executor/src/lib.rs` on 2026-08-12 [1].
Two additions to A.1's nine: `spawn_ignoring_error(task: impl Future<Output = Result<(), ()>> + Send + 'static, name)`
and the re-exported `RayonPoolType`. Both are **rejected** for the same reasons as L4/L7 and neither
changes a verdict. The panic path is verbatim:

```rust
if let Err(join_error) = task_handle.await
    && let Ok(_panic) = join_error.try_into_panic()
{
    let _ = shutdown_sender.try_send(ShutdownReason::Failure("Panic (fatal error)"));
}
```

Note what this implies structurally and A.1 did not spell out: `spawn_monitor` means **two tokio tasks
per logical task** — the work, and a monitor that awaits its `JoinHandle`. That is the price of
detecting a panic *when it happens* rather than at join time, and it is the price rvc must pay too,
because rows 7 and 9 of A.3 die silently mid-run and joining only at shutdown would not surface them.
At 13 registered tasks the cost is negligible.

### The API

```rust
// crates/rvc/src/bootstrap/executor.rs

/// Drain order. Lower tiers are drained first; each tier is fully drained
/// (or its budget expires) before the next begins.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ShutdownTier {
    /// Surfaces that admit NEW work: keymanager API, gRPC. Stopped first.
    Ingress,
    /// The duty orchestrator and the liveness loop. In-flight publishes complete here.
    Orchestrator,
    /// Refreshers and monitors: monitoring push, proposer-config, secret provider,
    /// slashing monitor, bn-manager SSE / sync-status.
    Background,
    /// Metrics HTTP + log reload. Drained last so logging guards owned by `main`
    /// flush after all HTTP work is gone (`bootstrap/run.rs:321-322`).
    Telemetry,
}

/// Why the process is stopping. Enum shape adopted from Lighthouse (L5);
/// the transport is rvc's, not `futures::channel`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ShutdownReason {
    Success(&'static str),
    Failure(&'static str),
}

pub struct TaskExecutor {
    token: CancellationToken,                 // the EXISTING token, not a new exit channel (L4 rejected)
    shutdown_tx: mpsc::Sender<ShutdownReason>,// tokio::sync::mpsc::channel(8) — BOUNDED (C9)
    registry: Arc<parking_lot::Mutex<Vec<Registered>>>,
}

struct Registered {
    name: &'static str,
    tier: ShutdownTier,
    /// Aborts the *work* task if its tier budget expires.
    work: tokio::task::AbortHandle,
    /// The monitor task; joining this proves the work task finished.
    monitor: JoinHandle<()>,
}

impl TaskExecutor {
    /// Returns the executor and the single `ShutdownReason` receiver, which the
    /// composition root selects on alongside `shutdown_signal()`.
    pub fn new(token: CancellationToken) -> (Self, mpsc::Receiver<ShutdownReason>);

    /// Hand this to a task instead of an exit channel. Identical to today's
    /// `shutdown.clone()` at `tasks.rs:97`, `:118`.
    pub fn token(&self) -> CancellationToken;

    /// Entry point 1 — for the composition root, which owns the future.
    pub fn spawn<F>(&self, name: &'static str, tier: ShutdownTier, fut: F)
    where F: Future<Output = ()> + Send + 'static;

    /// Entry point 2 — for library crates that already return a handle (A.3 / P2).
    /// Generic over `R` because real handles are not all `JoinHandle<()>`:
    /// `BackgroundTasks::metrics_handle` is `JoinHandle<Result<(), std::io::Error>>`
    /// (`bootstrap/tasks.rs:29`).
    pub fn register<R: Send + 'static>(
        &self, name: &'static str, tier: ShutdownTier, handle: JoinHandle<R>,
    );

    /// Feature-disabled case. Registers nothing when `None`, so
    /// `rvc_tasks_running{task="…"}` is honestly 0 (see A.2, the `slashing_monitor.rs:122-123`
    /// no-op-handle idiom this replaces).
    pub fn register_opt<R: Send + 'static>(
        &self, name: &'static str, tier: ShutdownTier, handle: Option<JoinHandle<R>>,
    );

    /// Cancels the token, then drains tier by tier. Consumes `self`.
    pub async fn shutdown(self, budget: TierBudget) -> ShutdownOutcome;
}

pub struct ShutdownOutcome {
    pub joined: Vec<&'static str>,
    pub aborted: Vec<&'static str>,   // exceeded its tier budget; logged at `warn` with the name (A-7)
}
```

`spawn(name, tier, fut)` is defined as `register(name, tier, tokio::spawn(fut))` — one implementation,
no duplicated monitor logic. `register` is the primitive:

```rust
pub fn register<R: Send + 'static>(&self, name, tier, handle: JoinHandle<R>) {
    let work = handle.abort_handle();
    let tx = self.shutdown_tx.clone();
    metrics::TASKS_RUNNING.with_label_values(&[name]).inc();
    let monitor = tokio::spawn(async move {
        let outcome = match handle.await {
            Ok(_) => "ok",
            Err(e) if e.is_panic() => {
                // L2, the highest-value mechanism: today this is a silent leak.
                let _ = tx.try_send(ShutdownReason::Failure(name));
                "panic"
            }
            Err(_) => "cancelled",
        };
        metrics::TASKS_RUNNING.with_label_values(&[name]).dec();
        metrics::TASK_EXITS_TOTAL.with_label_values(&[name, outcome]).inc();
    });
    self.registry.lock().push(Registered { name, tier, work, monitor });
}
```

Two properties worth stating because they are the reason `register` is not just `spawn` with extra
steps:

1. **The monitor holds the work handle; the registry holds the work's `AbortHandle`.** Aborting the
   monitor would *not* stop the work — so `shutdown` aborts `work`, then joins `monitor`, which then
   observes `Err(is_cancelled)` and records the exit. Getting this backwards is the obvious
   implementation bug and the reason it is written out here.
2. **`try_send` on a bounded channel, never `send().await`.** A full channel means shutdown is
   already in flight; dropping the second reason is correct, and `send().await` inside a monitor
   would make panic reporting itself blockable. This is how the enum survives C9's "zero unbounded
   channels" without Lighthouse's `futures::channel::mpsc`.

### What this is *not*

No `HandleProvider` (L8) — rvc's runtime comes from `#[tokio::main]` in `bin/rvc/src/main.rs` and is
never shut down from inside, so there is no `Weak<Runtime>` to upgrade and therefore no reason for a
single `Option` anywhere in the API. No `block_on_dangerous` (L9). No `spawn_blocking` family (L7):
`crates/signer/src/core.rs:542` is the C9 cancellation-proof stage→sign→commit core and
`crates/signer-server/src/dvt/peer_service.rs:231,323` carry `!Send` guards
(`peer_service.rs:230`: *"spawn_blocking is required because StagedBlock holds a !Send MutexGuard"*).
Those three sites must **not** acquire an edge to a composition-root executor, and must **not** appear
on any ban list — see A.5.

### Where it lives — verdict

**`crates/rvc/src/bootstrap/executor.rs`.** Not a new crate. A new crate costs a `CLASSIFICATION` row
in `crates/architecture-tests/src/lib.rs:57-92`, an `ARCHITECTURE.md` regeneration, and a
`Base`-vs-`Infra` placement decision that ARCH-P1-8 has not yet made — for a ~200-line module with
exactly one consumer. Promote to a `rvc-task` crate only if `signer-server` adopts it, which **A-13
explicitly places out of scope** (PRD `prd.md:1225`: *"Does this initiative own the `signer-server`
composition root? **No***"). Recorded as **RA-3**.

## A.5 Enforcement: does clippy `disallowed_methods` actually work here?

The brief asks to "verify that lint actually works for this case". Three separate questions hide
inside that, and they have three different answers.

### Q1 — Does `disallowed_methods` match a free function like `tokio::spawn`? **Yes.**

The lint "denies the configured methods **and functions** in clippy.toml" [2]. `tokio::spawn` is a
free function at path `tokio::spawn`, and the repo's own config already demonstrates the pattern with
a trait method (`secrecy::ExposeSecret::expose_secret`, `clippy.toml:26`). A row
`{ path = "tokio::spawn", reason = "…" }` will fire. **No blocker here.**

### Q2 — Can the ban be scoped to production code only? **No — and this is decisive.**

`disallowed-methods` is a flat list of paths with no path, module, or target scoping. Two consequences
that are specific to this repo, both read out of `clippy.toml` itself:

| Fact at HEAD | Consequence for a `tokio::spawn` ban |
|---|---|
| CI runs clippy with `--all-targets` (`clippy.toml:22-23` documents the extra `cargo clippy -p rvc-signer-bin --all-targets --features dvt` pass) | `--all-targets` compiles `#[cfg(test)]` modules, integration tests and benches — so the ban fires on **all 83 sites** in A.3/P5, including the `rvc-test-support/src/lib.rs:199` helper that is *not* behind `#[cfg(test)]` and would be reported as a production violation. Every one needs `#[allow(clippy::disallowed_methods)]`. |
| `clippy.toml:21-24` records that feature-gated code is **not** covered by the default workspace clippy run, which is why CI adds a separate `--features dvt` pass | A spawn ban inherits that exact blind spot: any `tokio::spawn` behind a non-default feature is unenforced unless a matching extra pass exists. The gate would silently under-cover precisely the code paths the repo already knows are under-covered. |

The obvious escape — a per-crate `clippy.toml` — **does not work, and is actively dangerous.** Clippy
searches for a config starting at `CLIPPY_CONF_DIR`, else `CARGO_MANIFEST_DIR`, else the current
directory, and *"if the chosen directory does not contain a configuration file, Clippy will walk up
the directory tree, searching each parent directory until it finds one or reaches the filesystem
root"* [3]. **First found wins; there is no merge.** So a `crates/rvc/clippy.toml` adding a spawn ban
would stop the walk-up and silently drop the three Gate-1 secret-key bans at `clippy.toml:25-29` for
that crate — a security-gate regression traded for a hygiene gate.

**Verified as hypothetical, not live:** `Glob '**/{clippy.toml,.clippy.toml}'` at HEAD returns exactly
**one** file, the workspace root `clippy.toml`. The hazard is created by the fix, not present today —
which is precisely why it must be written into the plan before someone reaches for the obvious
solution.

### Q3 — What should the primary gate be? **A path-scoped scanner in `architecture-tests`.**

**Verdict, correcting ARCH-P1-4's acceptance criterion (RVD-2):** the primary enforcement is a
`kat_policy`-style scanner, and clippy is a *secondary, deferred, workspace-wide* net. The scanner
can do what clippy structurally cannot:

- scope to `crates/rvc/src/**` + `bin/rvc/src/**` and skip `#[cfg(test)]` regions, using the same
  line-number-vs-`#[cfg(test)]` partitioning that produced A.3 (9 live sites out of 126 raw hits);
- name the offending file and line in the failure message (NFR-5 / R10), which
  `disallowed_methods`'s generic "use of a disallowed method" cannot;
- carry a shrinking-only allow list seeded with the P2 library sites, in the exact `EXEMPTIONS`
  idiom of `kat_policy.rs:42-163`;
- see feature-gated code, because it reads source text rather than compiling a cfg-selected crate
  graph — closing the `clippy.toml:21-24` blind spot rather than inheriting it.

Sequencing verdict: land the scanner with ARCH-P1-4. Add `{ path = "tokio::spawn" }` to
`clippy.toml` only **after** the executor migration is complete and the 83 test/test-support sites have been
triaged, as a belt-and-braces workspace-wide rule; if that triage is judged not worth the churn,
skip it — the scanner is sufficient. Recorded as **RA-4**.

## A.6 Shutdown ordering

### The tier assignment

Every live task from A.3 (P1) and A.3 (P2), plus the two futures currently polled inline at
`bootstrap/run.rs:297-313`, placed in a tier:

| Tier | Budget | Members | Why here |
|---|---|---|---|
| **1. Ingress** | 2.0 s | gRPC `DutyTrackerServer` (`run.rs:266-276`, today inline); Keymanager API axum server (`keymanager_adapters/spawn.rs:247`) | Stop admitting new work first. A keymanager import racing orchestrator teardown is the mid-import half-applied-state failure in PB-A2; ordering it first removes the race by construction rather than by timeout. |
| **2. Orchestrator** | 2.0 s | `orchestrator.run()` (`run.rs:304`, today inline); liveness loop (`liveness_loop.rs:355`) | The tier where ARCH-P0-4's acceptance criterion lives — an in-flight block publish must **complete**, not be dropped. |
| **3. Background** | 0.5 s | monitoring push (`tasks.rs:103`); proposer-config refresh (`tasks.rs:124`); secret-provider refresh (`enablement.rs:170`); slashing monitor (`slashing_monitor.rs:126`); registered bn-manager SSE (`sse.rs:174`), sync-status (`sync_status.rs:194`), manager SSE loop (`manager.rs:313`); keymanager-api lifecycle (`lifecycle.rs:140`) | All are `select!`-on-token loops that return within one poll of cancellation. 0.5 s is generous. |
| **4. Telemetry** | 0.5 s | metrics HTTP server (`tasks.rs:88`); SIGHUP log-reload (`bin/rvc/src/logging.rs:217`) | Preserves the *existing documented* invariant at `run.rs:321-322`: *"Metrics server drained before returning so logging guards (owned by main) drop last and flush after HTTP work is gone."* |

Total **5.0 s = A-7** (`prd.md:1219`), which is the whole point of splitting it: A-7's 5 s is a
**process** budget, and a naive per-task or per-tier 5 s would multiply it by 4 and blow past the
Kubernetes default 30 s `terminationGracePeriodSeconds` once combined with container-runtime overhead.

### The one budget conflict, and its resolution

Tier 4's 0.5 s is **shorter** than the existing `METRICS_SHUTDOWN_TIMEOUT = Duration::from_secs(2)`
(`bootstrap/tasks.rs:22`). That looks like a regression against two tests that already pin the
behaviour (`test_spawn_background_tasks_all_tasks_cancel_on_shutdown` `tasks.rs:216`,
`test_shutdown_drains_metrics_server_before_returning` `tasks.rs:237`). It is not, for a reason that
must be stated in the plan or an implementer will "fix" it the wrong way:

`BackgroundTasks::shutdown` (`tasks.rs:143-152`) is `abort()` **then** `timeout(2 s, await)`. The 2 s
is a ceiling on joining an *already-aborted* task, not a graceful-drain window — an aborted tokio task
resolves at its next yield point, effectively immediately. The tests assert *drain-before-return*, not
a duration. So 0.5 s satisfies them.

**The conditional that must be carried forward:** if ARCH-P1-4 converts the metrics server from
abort-drain to cooperative shutdown (which it should — the metrics task is the only live task that
never sees a token, A.3 row 2), the Telemetry budget must rise to **2.0 s** and A-7's total to
**6.5 s**. That is a change to a PRD assumption and must be filed as such, not absorbed silently.
Recorded as **RA-5**.

### How ordering is expressed in code

```rust
// bootstrap/run.rs, replacing :297-323
let reason = tokio::select! {
    _ = shutdown_signal()      => ShutdownReason::Success("signal"),
    Some(r) = shutdown_rx.recv() => r,     // a task panicked, or slashing_monitor asked to stop
};
startup::log_shutdown_initiated(reason.message());
let outcome = executor.shutdown(TierBudget::default()).await;   // cancels the token, drains 1→4
for name in &outcome.aborted {
    warn!(task = name, "task exceeded its shutdown budget and was aborted");
}
```

Three things this deletes, each an explicit ARCH-P0-4 acceptance criterion:
`tokio::time::sleep(Duration::from_millis(100))` at `run.rs:319` (the fake join);
`orchestrator_handle.shutdown()` at `:317` signalling a future that no longer exists; and the
three-arm inline `select!` at `:297-313` that drops the orchestrator mid-phase.

One property to preserve that the current code gets right and a rewrite can easily lose: the gRPC arm
is the **only** future today with real graceful shutdown — `serve_with_shutdown` at `:268-276` races
`shutdown_signal()` against `token.cancelled()`. Moving it into Tier 1 must keep the token arm; the
`shutdown_signal()` arm inside it becomes redundant once the executor owns signal handling and should
be dropped, or a second SIGINT during drain will bypass tier ordering.

### Ingress-first vs. Orchestrator-first — the decision, stated

Ingress before Orchestrator is not the only defensible order; draining the orchestrator first would
let an in-flight publish finish sooner. **Verdict: Ingress first.** Rationale: the orchestrator's
in-flight publish is protected by its own 2.0 s tier budget regardless of order, whereas a keymanager
import that lands *during* orchestrator teardown mutates key state with no reader — the exact
half-applied-state failure PB-A2 describes. Ordering removes that class; a budget cannot.
Recorded as **RA-6**.

---

# Track B — Config consolidation

## B.1 Measured duplication at HEAD

### It is five sites, not four — and only one adjacency is ungated

The PRD (PB-D1, `prd.md:296-303`) counts four sites. Opening them found a fifth that the four-site
framing hides, and it is the one that actually leaks:

| # | Site | Location | Size at HEAD | Hand-maintained? |
|---|---|---|---|---|
| 1 | 13 clap `Args` group structs | `bin/rvc/src/cli.rs:195-575` | **74 fields** | yes |
| 2 | **`impl From<StartArgs> for CliOverrides`** | `bin/rvc/src/cli.rs:587-685` | **99 lines**, 65 field initialisers | yes — **this is the fifth site, not counted by the PRD** |
| 3 | `CliOverrides` struct | `crates/rvc/src/config/types.rs:1313-1383` | **65 fields** | yes |
| 4 | `merge_with_cli` field list | `crates/rvc/src/config/types.rs:1211-1291` | **65 arms** | list is hand-written; the *code* is generated |
| 5 | `Config` + `Default` + `ConfigWire` serde shim | `crates/rvc/src/config/types.rs` | **3,187 lines** | yes |

All four PRD figures reproduce (65 / 1,363 / 3,187 / the `:1210` and `:1015` entry points). What
changes the design is the **adjacency** analysis — which of the four seams between those five sites a
compiler already guards:

| # | Adjacency | Guarded by | Verdict |
|---|---|---|---|
| **α** | group `Args` structs → `From<StartArgs>` | rustc, **partially** | The destructure at `cli.rs:589-604` is exhaustive over the **14 group bindings**, so adding a *group* fails to compile. But the 74 group **fields** are read by field access (`beacon.beacon_url`, `keys.keystore_path`, …) at `:607-682`, so **adding a field to `BeaconArgs` compiles silently.** ← the hole |
| β | `From<StartArgs>` → `CliOverrides` | rustc, fully | struct literal at `:606-683` must name all 65 fields |
| γ | `CliOverrides` → `merge_with_cli` | rustc, fully | `merge_cli_fields!` destructures `CliOverrides` exhaustively (`types.rs:934-936`) |
| δ | `merge_with_cli` → `Config` | rustc, fully | `$dst` expands to a real field path |

**Three of the four seams are already compiler-enforced.** The PRD's ARCH-P1-1 clause (i) — "every
`CliOverrides` field is consumed in `merge_with_cli`" — targets seam γ, which rustc has covered since
`merge_cli_fields!` landed. Building a scanner for it is redundant. See **RVD-1**; this is the single
largest correction in this document, and it re-points ARCH-P1-1 at seam **α**, which nothing guards.

### The gate at HEAD is GREEN — the arithmetic

Hand-running ARCH-P1-1 clause (ii) ("every clap argument maps to a `CliOverrides` field"):

```
74   group-arg fields          (7+10+4+4+8+5+9+4+4+5+7+3+4, cli.rs:195-575)
−  8  bypass args              never reach Config at all (below)
−  1  collapse                 no_keymanager + keymanager_enabled → one override (cli.rs:628-634)
= 65  == CliOverrides fields   (types.rs:1313-1383)  ✔
```

**Zero unmapped knobs.** The drift hole at seam α is real and unguarded, but **not yet exploited** —
so ARCH-P1-1's "demonstrate RED against a scratch commit that adds an orphan arg" is not merely the
preferred demonstration, it is the *only available* one. (V11.)

Two different reasons produce the two adjustments, and a reviewer reproducing `74 − 8 − 1` will think
one is a miscount unless both are stated:

- **`no_doppelganger_detection` is not a collapse.** It is the *sole* source of the
  `doppelganger_detection` override (`cli.rs:623-627`, `Some(false)` / `None`) — a 1:1 mapping under
  a negated name. It needs an **alias** entry in the gate, not an exemption.
- **`no_keymanager` + `keymanager_enabled` *is* a collapse.** Two args, one override, tri-state at
  `cli.rs:628-634`. That is the `−1`. It also needs an alias entry — a many-to-one one.

### The 8 bypass args — a second, undocumented channel

These clap args never enter `Config`. They are read directly off `StartArgs` at `cli.rs:738-776` and
routed to `bn_manager::OperationTimeouts` or to logging init. Nothing in the PRD names them:

| Arg | Destination | Line |
|---|---|---|
| `--block-production-timeout` | `timeouts.block_production` | `cli.rs:739-744` |
| `--attestation-timeout` | `timeouts.attestation_fetch` | `:745-750` |
| `--aggregate-timeout` | `timeouts.aggregate_fetch` + `aggregate_submit` | `:751-757` |
| `--duty-fetch-timeout` | `timeouts.duty_fetch` | `:758-763` |
| `--log-format` | `telemetry::LogFormat::resolve` | `:773`, `:785` |
| `--enable-log-reload` | `RunOptions` | `:774` |
| `--strict-permissions` | `RunOptions` | `:775` |
| `--strict-slashing-semantics` | `RunOptions` | `:776` |

Consequence for ARCH-P1-2: **four BN timeouts are operator-settable on the command line but have no
config-file representation at all.** Any "one declaration per knob" collapse must either give them
`Config` fields (raising the knob count from 65 to 69) or codify the bypass as intentional. Default
taken: **give them `Config` fields** — a timeout you cannot set in the config file is exactly the kind
of asymmetry that produced this problem. Recorded as **RA-7**.

### RVD-4 — a live precedence defect at seam β that no type check can catch

Nine `CliOverrides` fields are populated with `Some(...)` **unconditionally**, because their clap
field is non-`Option` with a `default_value`:

| `CliOverrides` field | `From` line | clap default | `Config` default, where pinned by a test |
|---|---|---|---|
| `metrics_address` | `cli.rs:614` | `DEFAULT_METRICS_ADDRESS` = `127.0.0.1` (`:20`, `:287`) | `127.0.0.1` — asserted at `types.rs:1398` |
| `metrics_port` | `:615` | `DEFAULT_METRICS_PORT` = `8080` (`:21`, `:291`) | `8080` — asserted at `types.rs:1397` |
| `grpc_port` | `:616` | `DEFAULT_GRPC_PORT` = `50051` (`:19`, `:295`) | `50051` — asserted at `types.rs:1399` |
| `grpc_address` | `:617` | `DEFAULT_GRPC_ADDRESS` = `127.0.0.1` (`:18`, `:299`) | `"127.0.0.1"` (`types.rs:592`) ✔ |
| `log_level` | `:622` | `"info"` (`:327`) | `"info"` (`types.rs:597`) ✔ |
| `tracing_exporter` | `:641` | `TracingExporter::Otlp` (`:377`) | `Otlp` is `#[default]` (`types.rs:107-108`) ✔ |
| `keymanager_body_limit` | `:652` | `keymanager_api::DEFAULT_BODY_LIMIT` (`:429`) | `default_keymanager_body_limit()` = `10 * 1024 * 1024` (`types.rs:356-358`, via `KeymanagerConfig::default` `:495`); clap's doc comment states "default: 10 MB" (`cli.rs:428`) ✔ (agreement by value, two constants) |
| `slashed_validators_action` | `:658` | `SlashedAction::DisableOnly` (`:471`) | `SlashedAction::default()` (`types.rs:602`), and `DisableOnly` carries `#[default]` (`types.rs:28-29`) ✔ |
| `beacon_max_body_bytes` | `:682` | `beacon::ResponseCaps::DEFAULT_MAX_BODY_BYTES` (`:211`) | `default_beacon_max_body_bytes()` → the **same constant** `ResponseCaps::DEFAULT_MAX_BODY_BYTES` (`types.rs:275-277`, via `:619`) ✔ |

**All nine agree** — checked individually, not assumed. Two notes on the citations: `types.rs:1397-1399`
are `test_default_config` assertions (`types.rs:1392`), not the `Default` impl, cited because they are
what pins those three values in CI; and `keymanager_body_limit` is the one row where agreement rests
on two independently-written constants having the same value rather than on a shared constant — it is
the row most likely to drift, and clause (iv) of the B.4 gate should say so.

The agreement matters because it bounds the blast radius: with all nine matched, the only symptom is
"the config file is ignored for these knobs". Had any row disagreed, that knob's documented `Config`
default would be **unreachable** even with no TOML and no flag — a strictly worse defect. That
possibility is now closed.

The chain: `load_config(config_path)` reads the TOML, **then** `cfg.merge_with_cli(&cli_overrides)`
runs (`cli.rs:780-781`); the `set` arm is `if let Some(v) = $field { $dst = v.clone(); }`
(`types.rs:942-946`). With `--metrics-port` **absent**, `cli_overrides.metrics_port` is
`Some(8080)` — clap's default, indistinguishable from an operator-supplied 8080 — and the `set` arm
overwrites whatever the TOML said.

**Conclusion: a TOML file setting `metrics_port = 9090` is silently reset to 8080 unless the operator
also passes `--metrics-port 9090` on the command line.** The same holds for the other eight rows. The
symptom is confined to "config file ignored" rather than "wrong value" only because the clap and
`Config` defaults happen to agree — which makes it invisible in exactly the way PB-B1/PB-B2 are.

Why no existing test catches it: `test_start_args_convert_to_equivalent_cli_overrides`
(`cli.rs:1018-1216`) passes **every** flag explicitly, so it exercises only the
operator-supplied branch; and `test_start_help_lists_every_flag` (`cli.rs:1005-1015`) only asserts
that a **hand-maintained** `START_FLAGS` const array (ending `cli.rs:1003`) appears in `--help` — it is
one-directional and would pass if a new arg were added and never listed. Neither is a precedence test.

**[Static analysis only — no shell available in this session; not executed.]** Overturn condition:
run `rvc start --config <toml with metrics_port=9090>` and observe the bind port. If it binds 9090,
some later code path re-applies the TOML and this finding is withdrawn; nothing between
`cli.rs:781` and the metrics bind at `bootstrap/tasks.rs:81-88` appeared to do so. Recorded as
**RA-8**, and it belongs in the *problem statement*, not merely in this research file — see B.5.

## B.2 Option evaluation: macro vs figment-style layering vs derive crate

The brief poses three options. **All three are rejected**, and the reason is the same for each: they
attack seams γ and δ, which rustc already guards (B.1), and leave seam α — the only unguarded one —
untouched. The comparison table below scores against what actually has to change.

| Criterion | Opt-1 Declarative macro | Opt-2 figment-style layering (minus `Env`, C3) | Opt-3 Derive crate (`confique`, `twelf`, `config-rs` + derive) | **Opt-4 reth `NodeConfig` model (B.3)** |
|---|---|---|---|---|
| Closes seam α (new group field silently unmapped) | no — macro sits inside `crates/rvc`, cannot see `bin/rvc`'s clap structs | **no** — layers *values*, not declarations | partial — only if the derive also generates the clap args | **yes, by deletion** — the clap struct *is* the config section, so there is no seam |
| Sites remaining afterwards | 4 (macro replaces site 4 only, which is already generated) | 5 + a provider stack | 3 | **2** (group `Args` structs + a thin `Config` assembly) |
| Fixes RVD-4 precedence bug | no | **yes, incidentally** — precedence becomes explicit in the provider order | no | **yes, by construction** — `clap::ArgMatches::value_source` is consultable, and the default lives in exactly one place |
| New dependency | none | `figment` (+ `toml` provider) | one | none |
| C3 compliance | n/a | requires deliberately *not* using the idiomatic `Env` provider | n/a | trivially compliant |
| Compatible with `no .unwrap()` / `thiserror` (CLAUDE.md) | yes | figment errors need a `From` into `ConfigError` | varies | yes |
| Prior art in this repo | **yes** — `merge_cli_fields!` (`types.rs:932-981`) is already this | no | no | partial — `StartArgs` groups already exist |
| Churn on 3,187 lines of `Config` | low | medium | high (re-derive every field) | medium, mechanical |

### Opt-1 — Declarative macro: **reject, because rvc already did it**

`merge_cli_fields!` (`types.rs:932-981`) *is* the declarative-macro answer, scoped to the one seam a
macro can reach from inside `crates/rvc`. It has five handler kinds (`set`, `set_some`, `set_true`,
`csv_opt`, `csv_vec`, `:928-931`) and it works: seam γ has been compiler-enforced since it landed.
Extending it to also emit clap `Arg` definitions is impossible without moving the clap surface into
`crates/rvc`, which inverts the dependency (`bin/rvc` → `rvc`, `bin/rvc/Cargo.toml:34`) and makes the
library crate own the binary's UX. **Verdict: keep `merge_cli_fields!`; do not grow it.** One useful
one-line extension is proposed in B.4.

### Opt-2 — figment-style layering: **reject the library; steal one idea**

C3 forbids the `Env` provider. Honouring it is trivial — do not use that provider — but it removes
most of figment's value proposition, because `Serialized::defaults() → Toml::file() → clap` is a
three-provider stack rvc can express in ~20 lines. What remains is `figment::Metadata`: every merged
value carries its provider's name, so an error can say *"`beacon_url` from `/etc/rvc.toml` is not a
valid URL"* instead of today's `ConfigError::InvalidBeaconUrl("beacon URL cannot be empty")`
(`types.rs:1016-1018`), which names no source. **That is worth having and does not need figment** —
~40 lines adding a `source: ConfigSource` field to `ConfigError` gets the same operator benefit with
no dependency, no `Env`-provider temptation sitting in the API surface, and no serde round-trip
through `figment::value::Value` for the 3,187-line `Config`.

There is a second, sharper reason to keep figment out. **rvc already has two env→config layers that a
figment adoption would legitimise and generalise:** `types.rs:438` reads
`OTEL_EXPORTER_OTLP_ENDPOINT` and `:447` reads `OTEL_TRACES_SAMPLER_ARG` as config-*else*-env
fallbacks. Adding a library whose idiomatic use is an env layer, while forbidding that layer by
policy, is a standing invitation to re-add it. **Verdict: do not add figment (V8).**

### Opt-3 — Derive crate: **reject on the 3,187-line number**

`confique`/`twelf`/`config-rs`+derive all require annotating every `Config` field. `Config` is 3,187
lines with a hand-written `ConfigWire` serde shim and a custom `Deserialize` that special-cases
`logfile` as either a string path or a table (`types.rs:895-920`). That shim would have to be
re-expressed in the derive crate's vocabulary or kept alongside it, and none of them generate clap
args, so seam α survives. High churn, low seam coverage. **Reject.**

### Opt-4 — the recommendation

See B.3. It is the only option that deletes a site rather than adding a generator over it.

## B.3 reth `NodeConfig` / type-state builder — what transfers

### What reth actually does

`reth_node_core::node_config::NodeConfig<ChainSpec>` [4]:

```rust
pub struct NodeConfig<ChainSpec> {
    pub datadir: DatadirArgs,
    pub config: Option<PathBuf>,
    pub chain: Arc<ChainSpec>,
    pub metrics: MetricArgs,
    pub instance: Option<u16>,
    pub network: NetworkArgs,
    pub rpc: RpcServerArgs,
    pub txpool: TxPoolArgs,
    pub builder: PayloadBuilderArgs,
    pub debug: DebugArgs,
    pub db: DatabaseArgs,
    pub dev: DevArgs,
    pub pruning: PruningArgs,
    pub engine: EngineArgs,
    pub era: EraArgs,
    pub static_files: StaticFilesArgs,
    pub storage: StorageArgs,
    pub jit: JitArgs,
}
```

The load-bearing fact: **every non-primitive field is a clap `Args` group struct**, imported from
`reth_node_core::args`. `NodeConfig` itself does **not** derive clap; the CLI command flattens the
same `*Args` structs and hands them over. Alongside it is a `with_*` builder — `with_network`,
`with_rpc`, `with_txpool`, `with_db`, `with_pruning`, `with_metrics`, `with_unused_ports`,
`with_disabled_discovery`, … — used almost entirely by tests and by embedders constructing a node
without a command line.

The consequence for the duplication problem: **reth has no `CliOverrides` and no `merge_with_cli`,
because there is nothing to merge.** The parsed arg group *is* the config section. Defaults live in
one place — the `#[arg(default_value_t = …)]` attribute, reachable programmatically through
`Default for XArgs` for non-CLI construction.

### What transfers to rvc, and what does not

| reth mechanism | Transfers? | Detail |
|---|---|---|
| Config sections **are** clap `Args` group structs | **Yes — this is the whole recommendation** | rvc already has the 13 group structs (`cli.rs:195-575`). Making `Config` hold them collapses sites 1+2+3+4 of B.1 into one. |
| No `CliOverrides` / no merge step | **Yes** | Deletes 65 fields + 99 lines + 65 macro arms. Seam α, β, γ all cease to exist rather than being gated. |
| `with_*` builder | **Partially** | rvc's non-CLI constructors are tests and `Config::from_file`. A `with_*` per section (13 methods) is cheap and replaces ad-hoc test fixtures. |
| Type-state builder (`NodeBuilder<…>` phantom-state chain) | **No — reject** | reth's type-state lives in `NodeBuilder`, not `NodeConfig`, and encodes *component wiring* (types not yet chosen), not config. rvc's `bootstrap` has a fixed component set. Adopting it would be NG3-adjacent framework adoption for zero defect closed. |
| `Arc<ChainSpec>` as a config field | **No** | rvc's equivalent is `Network` (`types.rs`), an enum with genesis lookups (`effective_genesis_time`, `:995`; `effective_genesis_validators_root`, `:1005`). Keep. |

### The three real obstacles, and their resolutions

Stating these matters because "just do what reth does" hides all three.

1. **rvc's `Config` is also the TOML schema; reth's is not.** `Config` has a hand-written
   `ConfigWire` shim and a custom `Deserialize` special-casing `logfile` (`types.rs:895-920`).
   Group `Args` structs would need `#[derive(Deserialize)]` and section names matching the TOML
   layout. **Resolution:** keep `Config` as the deserialisation target and make each of its *sections*
   an `Args` struct — `Config { keymanager: KeymanagerArgs, tracing: TracingArgs, … }`. `Config`
   already has this shape (`self.keymanager.enabled`, `self.tracing.endpoint`,
   `self.secret_provider.gcp.project_id` — see `merge_with_cli`'s `$dst` paths at
   `types.rs:1243-1290`). The section boundaries in `Config` and the clap group boundaries in
   `StartArgs` are **already close to isomorphic**; the collapse is mostly a renaming exercise, not a
   redesign. This is the single most important finding in Track B for effort estimation.
2. **A clap `Args` struct's `default_value` fights a TOML value — RVD-4.** reth has the same tension
   and resolves it because there is no second source to be clobbered. rvc has one. **Resolution:**
   the section structs' fields become `Option<T>` with `#[arg(long)]` and **no** `default_value`;
   defaults move to `impl Default for Config` / per-section `Default`, applied *after* the TOML and
   the CLI have both been folded in. This makes "operator supplied it" and "clap invented it"
   distinguishable — which is exactly the distinction RVD-4 shows is currently lost. `--help` output
   changes (defaults must be moved into doc comments or `default_value_t` retained only where the
   field is genuinely non-optional), which is operator-visible and belongs in the release note.
3. **Two crates own the two halves.** `bin/rvc` declares the args, `crates/rvc` owns `Config`
   (`bin/rvc/Cargo.toml:34` depends on `rvc`). The section structs must live in `crates/rvc` and be
   re-exported for `#[command(flatten)]` in `bin/rvc`. `crates/rvc` therefore gains a `clap`
   dependency it does not have today. **Resolution and cost:** that is the ARCH-P1-2 crate extraction
   (`rvc-config`) in one sentence — a new crate owning the section structs + `Config`, depended on by
   both `crates/rvc` and `bin/rvc`, with `clap` confined to it. Adding `clap` directly to
   `crates/rvc` instead would be cheaper and is acceptable if the extraction slips; recorded as
   **RA-9**.

## B.4 The interim conformance gate — concrete design

### What the gate must check, after RVD-1

ARCH-P1-1 has three clauses. B.1 changes what each should be:

| Clause | As written in the PRD | Verdict |
|---|---|---|
| (i) every `CliOverrides` field is consumed in `merge_with_cli` | build a scanner | **Drop — redundant.** Seam γ is compiler-enforced by `merge_cli_fields!`'s exhaustive destructure (`types.rs:934-936`). A scanner here can only ever be green. **RVD-1.** |
| (ii) every clap argument maps to a `CliOverrides` field | build a scanner | **Keep, and re-aim at seam α.** The failure mode is not "an arg with no override" in the abstract — it is *a new field added to an existing group struct that `From<StartArgs>` never reads* (`cli.rs:607-682`). That is what must be detected. |
| (iii) every `Config` field reachable from a knob has a validation or a no-validation marker | build a scanner | **Descope.** `validate` (`types.rs:1015`) is hand-written and most of the 65 knobs legitimately have nothing to validate; a marker on each would be 65 lines of noise. Replace with: every `CliOverrides` field appears in `validate`'s body **or** on a shrinking-only `UNVALIDATED` list. Same scanner, one extra pass, honest signal. |

Plus one clause the PRD does not have, which B.1 shows is needed: **(iv) the nine unconditional
`Some(...)` initialisers of RVD-4 must not grow.** A shrinking-only `CLAP_DEFAULT_CLOBBERS` list makes
the precedence defect visible in CI and prevents a tenth.

### Placement — verdict, with the reason

**One file: `crates/architecture-tests/tests/config_drift.rs`.** Not split, not typed.

The typed alternative — `clap::CommandFactory` on `Cli::command()`, enumerating every real arg — is
attractive and **fails on two hard facts verified at HEAD**:

1. `bin/rvc/Cargo.toml:12-14` declares `[[bin]] name = "rvc"` and **no `[lib]` target**. Integration
   tests under `bin/rvc/tests/` therefore cannot `use` `cli::Cli`; a typed gate could only be a unit
   test inside `bin/rvc/src/cli.rs`'s `#[cfg(test)]` module — which is exactly where the existing,
   *hand-maintained and therefore non-binding* `test_start_help_lists_every_flag` (`cli.rs:1005`)
   already sits. `crates/architecture-tests` cannot import `bin/rvc` at all.
2. Rust has no field reflection. Even a perfect typed enumeration of clap args cannot enumerate
   `CliOverrides`' 65 fields, so **the `CliOverrides` side must be scanned textually regardless.**
   Splitting the gate across two crates to make half of it typed buys nothing and doubles the places
   a reviewer must look.

A text scanner also matches house style: `kat_policy.rs:23` states the Phase-1 rule explicitly —
*"No external dependency (Phase-1 rule P6): hand-rolled scan, same style as `no_rvc_prefix.rs`."*

### Code sketch

Modelled on `kat_policy.rs` line for line: same `workspace_root()`/member-walk helpers, same
shrinking-only const tables, same brace-aware extraction, same "the scanner itself must not be
vacuous" self-checks.

```rust
//! ARCH-P1-1: config-drift gate.
//!
//! Seam α (`bin/rvc/src/cli.rs` group `Args` structs → `impl From<StartArgs> for CliOverrides`)
//! is the ONE seam in the five-site config pipeline that rustc does not guard: the destructure at
//! `cli.rs:589-604` is exhaustive over the 14 group *bindings*, but the 74 group *fields* are read
//! by field access, so a new field in e.g. `BeaconArgs` compiles silently and is ignored at runtime.
//! Seams β/γ/δ are compiler-enforced (struct literal; `merge_cli_fields!` exhaustive destructure at
//! config/types.rs:934-936; `$dst` field paths) and are NOT re-checked here.
//!
//! No external dependency (Phase-1 rule P6): hand-rolled scan, same style as `kat_policy.rs`.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

const CLI_RS: &str = "bin/rvc/src/cli.rs";
const TYPES_RS: &str = "crates/rvc/src/config/types.rs";

/// Group-struct fields that deliberately never reach `Config`: they are read straight off
/// `StartArgs` at `cli.rs:738-776` into `bn_manager::OperationTimeouts` or `RunOptions`.
///
/// **Shrinking-only.** Entries may be REMOVED (by giving the knob a `Config` field, RA-7),
/// never added. Adding one hides a real drift.
const BYPASS: &[(&str, &str)] = &[
    ("BeaconArgs", "aggregate_timeout"),          // -> timeouts.aggregate_fetch/submit, cli.rs:751
    ("BeaconArgs", "attestation_timeout"),        // -> timeouts.attestation_fetch,      cli.rs:745
    ("BeaconArgs", "block_production_timeout"),   // -> timeouts.block_production,       cli.rs:739
    ("BeaconArgs", "duty_fetch_timeout"),         // -> timeouts.duty_fetch,             cli.rs:758
    ("LoggingArgs", "enable_log_reload"),         // -> RunOptions,                      cli.rs:774
    ("LoggingArgs", "log_format"),                // -> LogFormat::resolve,              cli.rs:773
    ("SlashingArgs", "strict_permissions"),       // -> RunOptions,                      cli.rs:775
    ("SlashingArgs", "strict_slashing_semantics"),// -> RunOptions,                      cli.rs:776
];

/// Group fields whose override name differs from the arg name. Two distinct reasons — see B.1.
const ALIASES: &[(&str, &str, &str)] = &[
    // (struct, field, CliOverrides field)
    ("SafetyArgs", "no_doppelganger_detection", "doppelganger_detection"), // 1:1, negated (cli.rs:623)
    ("KeymanagerArgs", "no_keymanager", "keymanager_enabled"),             // 2:1 collapse (cli.rs:628)
];

/// Clause (iv): `CliOverrides` fields populated with an unconditional `Some(...)` from a clap
/// field carrying a `default_value`, so clap's default clobbers a TOML value (RVD-4).
///
/// **Shrinking-only.** A tenth entry is a new instance of a known live defect.
const CLAP_DEFAULT_CLOBBERS: &[&str] = &[
    "beacon_max_body_bytes", "grpc_address", "grpc_port", "keymanager_body_limit",
    "log_level", "metrics_address", "metrics_port", "slashed_validators_action",
    "tracing_exporter",
];

/// Clause (iii): knobs with nothing to validate. **Shrinking-only.**
const UNVALIDATED: &[&str] = &[/* seeded at ARCH-P1-1 land */];

// --------------------------------------------------------------------------
// Extraction — brace-aware, same technique as kat_policy::extract_tests
// --------------------------------------------------------------------------

/// `pub struct Foo {` … `}` → the field identifiers declared directly inside.
/// Skips doc comments, attributes and nested braces (there are none at HEAD, but
/// depth tracking keeps it honest if a field type gains a closure or an array init).
fn struct_fields(src: &str, struct_name: &str) -> Vec<String> { /* … */ }

/// Every `#[derive(Args)] pub struct XArgs` in cli.rs → its name.
fn arg_group_structs(src: &str) -> Vec<String> { /* … */ }

/// `StartArgs`' `#[command(flatten)] pub <binding>: <XArgs>,` lines → binding ⇄ type.
fn flatten_bindings(src: &str) -> BTreeMap<String, String> { /* binding -> type */ }

/// The body of `impl From<StartArgs> for CliOverrides` (cli.rs:587-685).
fn from_impl_body(src: &str) -> String { /* … */ }

// --------------------------------------------------------------------------
// Gates
// --------------------------------------------------------------------------

#[test]
fn every_group_arg_field_is_read_by_the_from_impl() {
    let root = workspace_root();
    let cli = std::fs::read_to_string(root.join(CLI_RS)).expect("cli.rs");

    let bindings = flatten_bindings(&cli);                 // beacon -> BeaconArgs, …
    assert_eq!(bindings.len(), 13, "expected 13 flattened Args groups; scanner or cli.rs changed");

    let body = from_impl_body(&cli);
    assert!(body.contains("beacon.beacon_url"), "From-impl body extraction broke");

    let bypass: HashSet<(&str, &str)> = BYPASS.iter().copied().collect();
    let mut violations = Vec::new();
    let mut checked = 0usize;

    for (binding, ty) in &bindings {
        for field in struct_fields(&cli, ty) {
            checked += 1;
            if bypass.contains(&(ty.as_str(), field.as_str())) {
                continue;
            }
            // The From impl reads every mapped field as `<binding>.<field>` (cli.rs:607-682).
            if !body.contains(&format!("{binding}.{field}")) {
                violations.push(format!(
                    "{ty}::{field} (--{}) is declared as a clap arg but never read by \
                     `impl From<StartArgs> for CliOverrides`; it is accepted on the command line \
                     and silently ignored. Add a `CliOverrides` field for it, or add it to BYPASS \
                     with the destination it is routed to.",
                    field.replace('_', "-")
                ));
            }
        }
    }

    assert_eq!(checked, 74, "expected 74 group-arg fields at HEAD; got {checked}");
    violations.sort();
    assert!(violations.is_empty(), "ARCH-P1-1 seam α:\n  {}", violations.join("\n  "));
}

#[test]
fn every_cli_override_field_has_a_source_arg() {
    // Reverse direction: an override with no arg is dead weight (and a merge that
    // can never fire). Uses ALIASES for the two negated/collapsed names.
    // … same shape; compares `struct_fields(types_rs, "CliOverrides")` against the
    // union of all group fields, minus BYPASS, plus ALIASES targets.
}

#[test]
fn clap_default_clobbers_do_not_grow() {
    // Clause (iv) / RVD-4. Detect `<field>: Some(<binding>.<field>)` in the From body
    // where the clap declaration for that field carries `default_value`.
    // Anything found that is not on CLAP_DEFAULT_CLOBBERS fails; the list is shrinking-only.
}

#[test]
fn every_knob_is_validated_or_declared_unvalidated() {
    // Clause (iii), descoped: each CliOverrides field name appears in the body of
    // `Config::validate` (types.rs:1015) or on the shrinking-only UNVALIDATED list.
}

#[test]
fn bypass_and_aliases_are_sorted_and_unique() {
    // Verbatim the shape of kat_policy_exemptions_are_sorted_and_unique (kat_policy.rs:462-476).
}

// --------------------------------------------------------------------------
// Non-vacuous matcher unit tests (kat_policy.rs:482-563 idiom)
// --------------------------------------------------------------------------

#[test]
fn struct_fields_extracts_and_skips_attributes() {
    let src = r#"
#[derive(Args, Debug)]
pub struct BeaconArgs {
    /// Beacon node URL
    #[arg(long)]
    pub beacon_url: Option<String>,

    #[arg(long, value_delimiter = ',')]
    pub beacon_nodes: Option<Vec<String>>,
}
"#;
    assert_eq!(struct_fields(src, "BeaconArgs"), vec!["beacon_url", "beacon_nodes"]);
}

#[test]
fn seam_alpha_detector_flags_an_unread_field() {
    // The RED demonstration ARCH-P1-1 requires, run as a unit test rather than
    // against a scratch commit: a synthetic group with one field the From impl ignores.
}
```

### Why this is falsifiable rather than decorative

Three properties, each borrowed from a specific line of `kat_policy.rs`:

- **`assert_eq!(checked, 74, …)`** and `assert_eq!(bindings.len(), 13, …)` are the
  `assert!(files.len() > 100, "scanned only {} files; workspace walk likely broke")`
  (`kat_policy.rs:414`) and `assert!(matched > 20, …)` (`:444`) idiom: a scanner that silently stops
  matching must fail, not pass. Without them, a rename of `StartArgs` turns the gate green forever.
- **Shrinking-only tables with removal-not-addition semantics**, documented in the const's own doc
  comment — `kat_policy.rs:32-41`.
- **Matcher unit tests on synthetic input** — `kat_policy.rs:482-563`. The `seam_alpha_detector_flags_an_unread_field`
  test is what lets ARCH-P1-1 satisfy "demonstrated RED, not asserted" *in the same PR*, without
  merging a knowingly-failing gate (the same standard ARCH-P0-2 sets for D1/D2).

### Lifetime

This gate is **interim by construction**. ARCH-P1-2's reth-model collapse (B.3) deletes seam α
entirely — there is no `From<StartArgs>` to drift from once the group `Args` structs *are* the config
sections. At that point `every_group_arg_field_is_read_by_the_from_impl` and
`every_cli_override_field_has_a_source_arg` are deleted, and only
`clap_default_clobbers_do_not_grow` (whose list should by then be empty, per B.3 obstacle 2) and the
validation clause survive. Say this in the file's module doc, or it will outlive its purpose.

## B.5 Verdict and sequencing

### ARCH-P1-3: the `RVC_*` env allow-list gate must not be a prefix scan

C3 says config consolidation must not adopt figment's `Env` provider, and must instead "codify the
`env = security opt-outs only` rule with an `RVC_*` allow-list scan gate". Taken literally — scan for
the `RVC_` prefix — **the gate does not work.** Measured at HEAD:

- `Grep 'RVC_'` over `crates/**/*.rs`: **438 occurrences across 57 files.** The largest contributors
  are Prometheus metric-name constants, not env vars: `crates/metrics/src/definitions.rs` (80),
  `crates/secret-provider/src/key_source_manager.rs` (32), `crates/secret-provider/src/metrics.rs`
  (21), `crates/secret-provider/src/refresh.rs` (16). A prefix scan is ~95 % false positives.
- Three live env reads carry **no `RVC_` prefix at all** and a prefix scan misses them entirely:
  `RUST_LOG` (`crates/telemetry/src/init.rs:152`), `OTEL_EXPORTER_OTLP_ENDPOINT`
  (`crates/rvc/src/config/types.rs:438`), `OTEL_TRACES_SAMPLER_ARG` (`types.rs:447`). The last two are
  **config-else-env fallbacks on `TracingConfig`** — i.e. an env→config channel that already exists.
  Note the precedence is the *opposite* of figment's idiomatic `Env` layer: config wins, env only
  fills a `None`. That is the defensible shape and the rule should say so.
- `RVC_LOG_FORMAT` (`crates/telemetry/src/format.rs:53`, `LOG_FORMAT_ENV`) is a live **non-security**
  `RVC_*` env knob, with documented CLI-wins precedence (`format.rs:77`, and
  `format.rs:269`: *"CLI --log-format must outrank RVC_LOG_FORMAT"*). The
  "env = security opt-outs only" rule must **grandfather it explicitly** or the gate is red on day one.

**Verdict:** ARCH-P1-3 scans `std::env::var` **call sites** and `*_ENV` / `*_ENV_VAR` string
constants, not the `RVC_` prefix, and classifies each against an explicit allow-list:

| Class | Members at HEAD |
|---|---|
| **Security opt-out** (the sanctioned class) | `RVC_REMOTE_SIGNER_ALLOW_INSECURE` (`crates/crypto/src/remote_signer/client.rs:31`, `crates/grpc-signer/src/client.rs:43`); `RVC_ALLOW_INSECURE` (`crates/rvc/src/config/types.rs:1115`, `crates/signer-server/src/slashing/config.rs:48`); `RVC_ALLOW_NON_WAL_SLASHING_DB` (`crates/slashing/src/db/open.rs:225`); `RVC_SIGNER_ALLOW_INSECURE` (`crates/signer-server/src/insecure_startup.rs:20`); `RVC_METRICS_ALLOW_NON_LOOPBACK` (`crates/rvc/src/bootstrap/tasks.rs:19`) |
| **Grandfathered non-security** (shrinking-only) | `RVC_LOG_FORMAT` (`crates/telemetry/src/format.rs:53`) |
| **Ecosystem-standard, config-wins fallback** (allowed by name, not by prefix) | `RUST_LOG`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_TRACES_SAMPLER_ARG` |
| **Anything else** | fail, naming the file and the variable |

Recorded as **RA-10**. This is the same class of correction as RVD-2: the constraint is right, the
mechanism named for it is not.

### Sequencing verdict for Track B

| Step | What | Depends on | Why in this order |
|---|---|---|---|
| B-1 | Land `config_drift.rs` with clauses (ii), (iii), (iv) — **not** (i) | nothing | ARCH-P1-1 is a precondition on all knob-adding work (G5). Clause (iv) makes RVD-4 visible in CI immediately, before anyone fixes it. |
| B-2 | Fix RVD-4: the nine `Some(clap_default)` initialisers | B-1 (so the list shrinks visibly) | This is a **live operator-facing defect**, not evolvability debt. It is the same family as PB-B1/PB-B2 — a config surface accepted and discarded — and on the evidence it belongs in the PRD's Problem Statement section (b), not in P1. Cheapest correct fix: make the nine clap fields `Option<T>` and move the defaults to `Config::default()`. |
| B-3 | ARCH-P1-3 env allow-list gate, scanning call sites | independent | Small, and it must land before ARCH-P1-2 so the collapse cannot quietly add an env layer. |
| B-4 | ARCH-P1-2 reth-model collapse | B-1, B-2, B-3 | Deletes seams α/β/γ and sites 2+3+4 of B.1. Two of the four gates from B-1 are deleted with it. |

**The one sequencing claim worth arguing with:** B-2 before B-4. The collapse fixes RVD-4 by
construction, so doing B-2 first is arguably wasted work. It is not, for two reasons: B-4 is a large,
multi-PR change that may slip past this initiative, and B-2 is a ~30-line change closing a defect
that silently ignores an operator's config file today. Shipping the defect fix behind a refactor is
the pattern that produced PB-B1. Recorded as **RA-11**.

### Track B verdict in one line

Gate seam α now with a `kat_policy`-style scanner and fix the nine clobbered knobs; then collapse to
the reth `NodeConfig` model, which deletes the duplication instead of generating it. Do not adopt
figment, a derive crate, or a new macro.

---

## Assumptions (no-ask defaults)

Every open question in this research is resolved to a stated default here. Nothing is escalated
(no-ask constraint, PRD `prd.md:21-22`). Each row carries the condition that would overturn it.

| ID | Question | Default taken | Overturn condition |
|---|---|---|---|
| **RA-1** | Executor metric shape and cardinality | Two series: `rvc_tasks_running{task}` (gauge) and `rvc_task_exits_total{task,outcome}` (counter, `outcome ∈ {ok, panic, cancelled}`). No lifetime histogram — 8 of the 9 live P1 tasks are infinite loops, for which a lifetime histogram is meaningless. Cardinality ≈ 13 tasks × 3 outcomes = 39 series. | A task set large enough for 13 label values to matter, or a need for per-task latency (which belongs on the work, not the task) |
| **RA-2** | `ShutdownReason` channel capacity | `tokio::sync::mpsc::channel(8)`, `try_send` only. Bounded per C9. A full channel means shutdown is already in flight; dropping the second reason is correct. | A design in which more than 8 distinct shutdown reasons can race |
| **RA-3** | Does the executor become its own crate? | **No.** `crates/rvc/src/bootstrap/executor.rs`. Promotion to `rvc-task` only if `signer-server` adopts it — explicitly out of scope per PRD **A-13** (`prd.md:1225`). | ARCH-P1-8's `Base`/`Infra` split landing first and creating an obvious home |
| **RA-4** | Primary enforcement for the raw-`tokio::spawn` ban | **Scanner in `architecture-tests`, path-scoped and test-aware.** clippy `disallowed-methods` is a deferred, optional, workspace-wide secondary net added only after the 83 test/test-support sites are triaged. | A clippy release adding path/target scoping to `disallowed-methods` |
| **RA-5** | Telemetry-tier shutdown budget vs `METRICS_SHUTDOWN_TIMEOUT` | **0.5 s**, because `BackgroundTasks::shutdown` is `abort()`-then-join (`tasks.rs:143-152`) and the two existing tests assert drain-before-return, not a duration. **If** the executor converts the metrics server to cooperative shutdown, Telemetry rises to 2.0 s and PRD **A-7** rises from 5 s to 6.5 s — a PRD amendment, not a silent absorption. | The conversion in the previous sentence |
| **RA-6** | Tier order: Ingress before Orchestrator | **Ingress first.** An in-flight publish is protected by its own tier budget regardless of order; a keymanager import landing during orchestrator teardown is a state-corruption class that only ordering removes. | Measurement showing publishes routinely exceed the Orchestrator budget because Ingress consumed it |
| **RA-7** | The four BN timeout args with no config-file representation | **Give them `Config` fields** in ARCH-P1-2 (65 → 69 knobs) and shrink `BYPASS` accordingly. | A decision that BN timeouts are deliberately CLI-only, which must then be documented on the args |
| **RA-8** | Is RVD-4 (clap defaults clobber TOML) real? | **Assumed real**, from a complete static read of the chain `cli.rs:780-781` → `types.rs:942-946` → the nine `Some(...)` initialisers. **Not executed — no shell in this session.** | `rvc start --config <toml with metrics_port = 9090>` binding 9090. Phase 0 must run this before B-2 is scheduled. |
| **RA-9** | Where the shared config section structs live | **A new `rvc-config` crate** (ARCH-P1-2), so `clap` is confined to it. Acceptable fallback if the extraction slips: add `clap` directly to `crates/rvc`. | The `Base`/`Infra` classification making a new crate expensive |
| **RA-10** | Shape of the ARCH-P1-3 env gate | **Scan `std::env::var` call sites and `*_ENV`/`*_ENV_VAR` constants**, classified against a four-class allow-list. **Not** an `RVC_` prefix scan (438 hits, ~95 % metric names; misses `RUST_LOG` and the two `OTEL_*` reads). `RVC_LOG_FORMAT` is grandfathered on a shrinking-only non-security list. | A decision to rename metric constants off the `RVC_` prefix, which would make a prefix scan viable but is far more churn |
| **RA-11** | Fix RVD-4 before or after the ARCH-P1-2 collapse? | **Before.** ~30 lines closing a live defect; the collapse is multi-PR and may slip. | The collapse being scheduled inside the same phase with high confidence |

## Verification deltas

Facts asserted by the architecture review or the PRD that did **not** reproduce at HEAD (`0ae9a09`),
with the corrected fact and what it changes downstream. Ordered by impact.

### RVD-1 — ARCH-P1-1 clause (i) is already enforced by rustc

**Claimed** (PRD `prd.md:734`): the gate must assert *"every `CliOverrides` field
(`config/types.rs:1313-1383`, 65 today) is consumed in `merge_with_cli` (`:1210`)"*, implying
`merge_with_cli` is a hand-maintained fourth site.

**At HEAD:** `merge_with_cli` is generated by `merge_cli_fields!` (`types.rs:932-981`), whose first
arm **exhaustively destructures `CliOverrides`** at `:934-936`:

```rust
let CliOverrides {
    $($field,)*
} = $cli;
```

The macro's own doc comment states the property (`types.rs:925-926`: *"Exhaustively destructures
`CliOverrides` so a new override field that is not listed fails to compile"*), and `merge_with_cli`
repeats it (`:1207-1209`). An unlisted field is a `missing field in pattern` compile error.

**Changes:** clause (i) is **dropped** from ARCH-P1-1 as redundant. The gate is re-aimed at seam α
(`bin/rvc/src/cli.rs` group fields → `From<StartArgs>`), the one seam of four that nothing guards.
This is the difference between a gate that can only ever be green and one that can catch the defect
class the requirement exists for.

### RVD-2 — clippy `disallowed_methods` is the wrong *primary* gate for raw `tokio::spawn`

**Claimed** (research brief, and implied by ARCH-P1-4's acceptance criterion): enforce with clippy
`disallowed-methods` on raw `tokio::spawn`.

**At HEAD:** the lint does match free functions [2], so the mechanism works in the narrow sense. But
it cannot be scoped: CI runs `--all-targets` (`clippy.toml:22-23`), so the ban fires on all **83**
test/test-support sites; `clippy.toml:21-24` records that feature-gated code is outside the default workspace
run; and a per-crate `clippy.toml` **replaces** rather than merges the root file [3], which would
silently drop the three Gate-1 secret-key bans at `clippy.toml:25-29`. Only one `clippy.toml` exists
in the repo (`Glob '**/{clippy.toml,.clippy.toml}'` → 1 hit), so the last hazard is created by the
fix, not present today.

**Changes:** ARCH-P1-4's acceptance criterion becomes "a path-scoped `architecture-tests` scanner
fails on a new raw `tokio::spawn` under `crates/rvc/src/**` or `bin/rvc/src/**`", with clippy as an
optional deferred secondary.

### RVD-3 — the raw-spawn baseline is 9 live sites, not "≥4 known"

**Claimed** (PRD metric M8): four known sites — `tasks.rs:103`, `tasks.rs:124`,
`enablement.rs:170`, `spawn.rs:247`.

**At HEAD:** 126 raw `tokio::spawn(` occurrences across 53 files, partitioning to **9** live
production sites in scope (A.3/P1) + 4 in Infra crates (P2) + 5 in `signer-server` / `bin/rvc-signer`
(P3, out of scope per A-13) + 25 in the untracked orphan trees (P4, deleted by ARCH-P0-1) + 83
test/test-support (P5) = 126. The five
sites the PRD does not name: `bin/rvc/src/logging.rs:217`, `bootstrap/tasks.rs:88`,
`liveness_loop.rs:355`, `slashing_monitor.rs:123`, `slashing_monitor.rs:126`.

**Changes:** M8's baseline. Two of the unnamed sites have safety-adjacent silent-death consequences —
`liveness_loop.rs:355` (keys stay `Pending` forever) and `slashing_monitor.rs:126` (slashed-validator
detection stops) — which is what promotes Lighthouse's panic→`ShutdownReason::Failure` mechanism (L2)
from nice-to-have to the highest-value mechanism in the port.

### RVD-4 — a live config-precedence defect: nine knobs where clap's default clobbers the TOML

**Not claimed anywhere.** New finding; see B.1 for the full chain and table.

Nine `CliOverrides` fields are populated with an unconditional `Some(...)` from a clap field carrying
`default_value` (`cli.rs:614,615,616,617,622,641,652,658,682`). `merge_with_cli` runs after
`load_config` (`cli.rs:780-781`) and its `set` arm assigns on `Some` (`types.rs:942-946`), so a TOML
`metrics_port = 9090` is reset to clap's 8080 whenever `--metrics-port` is absent. Neither existing
test can catch it: `test_start_args_convert_to_equivalent_cli_overrides` (`cli.rs:1018`) passes every
flag explicitly, and `test_start_help_lists_every_flag` (`cli.rs:1005`) checks a hand-maintained list
against `--help`.

**Changes:** this is a *silently-inert config surface* — PRD Problem Statement section (b), the
PB-B1/PB-B2 family — not evolvability debt. It should be added there and given a P0/P1 requirement,
and clause (iv) of the B.4 gate makes it non-growing in the meantime. **[Static analysis only; RA-8
carries the execution step.]**

### RVD-5 — the config pipeline is five hand-maintained sites, not four

**Claimed** (PRD PB-D1 table, `prd.md:296-303`): four sites — clap args, `CliOverrides`, `Config`,
`merge_with_cli` + `validate`.

**At HEAD:** `impl From<StartArgs> for CliOverrides` (`bin/rvc/src/cli.rs:587-685`, 99 lines, 65 field
initialisers) is a fifth, entirely hand-written site — and it is where seam α lives. The four-site
framing counts the *generated* site (`merge_with_cli`) and omits the hand-written one, which inverts
the priority: the plan would gate what rustc already covers and leave uncovered what it does not.

**Changes:** ARCH-P1-1's target; ARCH-P1-2's scope (the collapse must delete site 2, which is the
largest single win — 99 lines and one whole seam).

### RVD-6 — C3's `RVC_*` prefix-scan mechanism does not survive contact with the tree

**Claimed** (constraint **C3**): codify "env = security opt-outs only" with an *"`RVC_*` allow-list
scan gate"*.

**At HEAD:** `RVC_` appears **438 times across 57 files**, overwhelmingly as Prometheus metric-name
constants (`crates/metrics/src/definitions.rs` alone has 80). Meanwhile three live env reads carry no
`RVC_` prefix — `RUST_LOG` (`telemetry/src/init.rs:152`), `OTEL_EXPORTER_OTLP_ENDPOINT`
(`config/types.rs:438`), `OTEL_TRACES_SAMPLER_ARG` (`types.rs:447`) — and one `RVC_*` var is a live
**non-security** knob (`RVC_LOG_FORMAT`, `telemetry/src/format.rs:53`).

**Changes:** the constraint stands; its named mechanism does not. ARCH-P1-3 scans `env::var` call
sites and `*_ENV` constants against a four-class allow-list (B.5, RA-10). Worth noting for C3's own
sake: `types.rs:438,447` are config-*else*-env fallbacks — config wins — which is the **opposite**
precedence from figment's `Env` provider, and is the shape the codified rule should permit.

## Sources

### External

[1] [Lighthouse `common/task_executor/src/lib.rs` (`stable`)](https://raw.githubusercontent.com/sigp/lighthouse/stable/common/task_executor/src/lib.rs) — Sigma Prime, fetched 2026-08-12. **Primary source.** Every signature in A.1 and the panic→`ShutdownReason::Failure` snippet in A.4 are quoted from this fetch: `TaskExecutor::new(handle, exit: async_channel::Receiver<()>, signal_tx: Sender<ShutdownReason>)`, `spawn`, `spawn_ignoring_error`, `spawn_without_exit`, `spawn_handle -> Option<JoinHandle<Option<R>>>`, the four `spawn_blocking*` variants, `block_on_dangerous`, `exit`, `shutdown_sender`; `enum ShutdownReason { Success(&'static str), Failure(&'static str) }`; `enum HandleProvider { Runtime(Weak<Runtime>), Handle(Handle) }`; metrics `TASKS_HISTOGRAM`, `ASYNC_TASKS_COUNT`, `BLOCKING_TASKS_HISTOGRAM`, `BLOCKING_TASKS_COUNT`, `BLOCK_ON_TASKS_HISTOGRAM`, `BLOCK_ON_TASKS_COUNT`.

[2] [`rust-clippy/clippy_lints/src/disallowed_methods.rs`](https://github.com/rust-lang/rust-clippy/blob/master/clippy_lints/src/disallowed_methods.rs) — rust-lang, master. Source of the claim that the lint *"denies the configured methods **and functions** in clippy.toml"*, i.e. free functions such as `tokio::spawn` are matchable. **Retrieved via search-result summary, not a direct fetch** — direct `github.com` fetches DNS-failed throughout this session (see *Dead links*). Confidence: high (the lint's real-world use to ban `std::process::exit` corroborates it), but flagged as second-hand. Mirror: [`clippy_config::conf::defaults::disallowed_methods`](https://doc.rust-lang.org/stable/nightly-rustc/clippy_config/conf/defaults/fn.disallowed_methods.html).

[3] [Clippy Configuration — *The Clippy Book*](https://doc.rust-lang.org/clippy/configuration.html) — rust-lang, fetched 2026-08-12. **Primary source, quoted verbatim** in A.5: config is *"searched for starting in the first defined directory according to the following priority order: 1. `CLIPPY_CONF_DIR` … 2. `CARGO_MANIFEST_DIR` … 3. the current directory. If the chosen directory does not contain a configuration file, Clippy will walk up the directory tree, searching each parent directory until it finds one or reaches the filesystem root."* This is the basis for "first found wins, no merge".

[4] [reth `reth_node_core::node_config` source](https://reth.rs/docs/src/reth_node_core/node_config.rs.html) — Paradigm, fetched 2026-08-12. **Primary source.** `NodeConfig<ChainSpec>`'s 18 fields quoted verbatim in B.3; the `with_*` builder list; the fact that all non-primitive fields are clap `Args` group structs and that `NodeConfig` itself does not derive clap.

[5] [`RpcServerArgs` in `reth::args`](https://paradigmxyz.github.io/reth/docs/reth/args/struct.RpcServerArgs.html) — Paradigm. Corroborates that the group structs in [4] are ordinary clap `Args` derives usable via `#[command(flatten)]`.

**Dead links / retrieval failures, recorded per house convention.** `github.com/sigp/lighthouse/blob/…`
and `rust-lang.github.io/rust-clippy/master/index.html#disallowed_methods` both failed with
`getaddrinfo ENOTFOUND` during this session; `raw.githubusercontent.com` failed once and succeeded on
retry (DNS was intermittent, not blocked). **`https://docs.rs/task_executor/` was checked and
deliberately NOT used**: it resolves to an unrelated crate (`task_executor` 0.3.3, exporting
`Executor`/`Spawner`/`GroupBuilder`), not Lighthouse's unpublished workspace member. Citing it would
have been a fabricated source.

### In-repo (all opened at `develop` @ `0ae9a09`)

| Claim | Location |
|---|---|
| Inline three-arm `select!`; token cancelled after the future is dropped; `sleep(100 ms)` as a join | `crates/rvc/src/bootstrap/run.rs:297-323` |
| gRPC `serve_with_shutdown` — the only real graceful shutdown today | `crates/rvc/src/bootstrap/run.rs:266-276` |
| Metrics drained last so logging guards flush after HTTP work | `crates/rvc/src/bootstrap/run.rs:321-322` |
| `BackgroundTasks` struct, `metrics_handle: JoinHandle<Result<(), std::io::Error>>` | `crates/rvc/src/bootstrap/tasks.rs:27-30` |
| `METRICS_SHUTDOWN_TIMEOUT = 2 s`; abort-then-join drain | `crates/rvc/src/bootstrap/tasks.rs:22`, `:143-152` |
| The 3 production spawns in `spawn_background_tasks` | `crates/rvc/src/bootstrap/tasks.rs:88`, `:103`, `:124` |
| Secret-provider refresh spawn | `crates/rvc/src/bootstrap/enablement.rs:170` |
| Keymanager API spawn, handle discarded, no token | `crates/rvc/src/keymanager_adapters/spawn.rs:233-251` |
| `LivenessLoopSpawn { join }` returned and dropped | `crates/rvc/src/liveness_loop.rs:324`, `:355`; dropped at `bootstrap/run.rs:170` |
| Slashing-monitor no-op handle + real spawn | `crates/rvc/src/slashing_monitor.rs:106-130` |
| SIGHUP log-reload spawn | `bin/rvc/src/logging.rs:206-217` |
| P2 library spawns that force `register` | `crates/bn-manager/src/manager.rs:313`, `sse.rs:174`, `sync_status.rs:194`; `crates/keymanager-api/src/lifecycle.rs:140` |
| `spawn_blocking` sites that must stay out of executor scope (C9) | `crates/signer/src/core.rs:542`; `crates/signer-server/src/dvt/peer_service.rs:230-231`, `:322-323` |
| Gate-1 `disallowed-methods` list; `--all-targets` / feature-gate notes | `clippy.toml:21-29` |
| Scanner idioms modelled in B.4 | `crates/architecture-tests/tests/kat_policy.rs:23`, `:32-41`, `:169-226`, `:297-359`, `:410-476`, `:482-563` |
| 13 clap `Args` group structs, 74 fields | `bin/rvc/src/cli.rs:195-575` |
| `impl From<StartArgs> for CliOverrides` — exhaustive over groups, field-access over fields | `bin/rvc/src/cli.rs:587-685` (destructure `:589-604`; initialisers `:606-683`) |
| The 8 bypass args | `bin/rvc/src/cli.rs:738-776` |
| `load_config` then `merge_with_cli` | `bin/rvc/src/cli.rs:780-781` |
| Hand-maintained `START_FLAGS` + one-directional help test | `bin/rvc/src/cli.rs:1003`, `:1005-1015` |
| All-flags-present conversion test (cannot see RVD-4) | `bin/rvc/src/cli.rs:1018-1216` |
| `bin/rvc` has `[[bin]]` and no `[lib]` | `bin/rvc/Cargo.toml:12-14` |
| `merge_cli_fields!` — exhaustive destructure, five handler kinds, `set` arm | `crates/rvc/src/config/types.rs:923-981` (destructure `:934-936`; `set` `:942-946`) |
| `merge_with_cli` 65 arms | `crates/rvc/src/config/types.rs:1211-1291` |
| `CliOverrides` 65 fields | `crates/rvc/src/config/types.rs:1313-1383` |
| `Config::validate` entry point | `crates/rvc/src/config/types.rs:1015` |
| Custom `Deserialize` special-casing `logfile` | `crates/rvc/src/config/types.rs:895-920` |
| `impl Default for Config` — the six RVD-4 defaults not pinned by `test_default_config` | `crates/rvc/src/config/types.rs:579`, `:592`, `:597`, `:602`, `:619`; helpers `:275-277`, `:356-358`, `:495`; `#[default]` variants `:28-29`, `:107-108` |
| P3 spawn sites (out of scope, A-13) | `bin/rvc-signer/src/main.rs:124`, `:205`; `crates/signer-server/src/metrics.rs:305`, `server/mod.rs:129`, `http_api/accept_loop/mod.rs:174` |
| Production spawn in a test-support crate | `crates/rvc-test-support/src/lib.rs:199` (before `#[cfg(test)]` at `:272`) |
| Env reads: `OTEL_*` config-else-env fallbacks | `crates/rvc/src/config/types.rs:438`, `:447` |
| Env reads: security opt-outs | `crates/crypto/src/remote_signer/client.rs:31`; `crates/grpc-signer/src/client.rs:43`; `crates/rvc/src/config/types.rs:1115`; `crates/slashing/src/db/open.rs:225`; `crates/signer-server/src/insecure_startup.rs:20`; `crates/rvc/src/bootstrap/tasks.rs:19` |
| `RVC_LOG_FORMAT` — live non-security env knob, CLI-wins | `crates/telemetry/src/format.rs:53`, `:77`, `:269` |
| Layer classification table (bn-manager / keymanager-api placement) | `crates/architecture-tests/src/lib.rs:57-92` |

### Counts, and how to reproduce them

| Count | Command | Result |
|---|---|---|
| Raw spawn occurrences | `Grep 'tokio::spawn\(' --glob '**/*.rs' --output_mode count` | 126 across 53 files |
| Spawn partition | per-file counts above, split by each file's `#[cfg(test)]` line | P1 9 + P2 4 + P3 5 + P4 25 + P5 83 = **126** ✔ |
| `RVC_` occurrences | `Grep 'RVC_' --glob 'crates/**/*.rs' --output_mode count` | 438 across 57 files |
| clippy config files | `Glob '**/{clippy.toml,.clippy.toml}'` | 1 (workspace root) |
| Group-arg fields | field count per `Args` struct, `cli.rs:195-575` | 7+10+4+4+8+5+9+4+4+5+7+3+4 = **74** |
| Knob arithmetic | 74 − 8 (BYPASS) − 1 (`no_keymanager` collapse) | **65** = `CliOverrides` fields ✔ |
