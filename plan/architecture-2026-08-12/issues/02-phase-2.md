# Phase 2: Task Topology — an executor, a spawnable orchestrator, a real shutdown

> **Sprint-ready issue breakdown for Phase 2** of the rs-vc architecture-remediation initiative.
> Baseline **`develop` @ `0ae9a09`** (v0.7.0), authored 2026-08-12.
>
> **Authoritative inputs, in precedence order:**
> [`../project-plan.md`](../project-plan.md) §7 *Phase 2* (scope, work packages 2A–2D, gates) →
> [`../architecture.md`](../architecture.md) (ADR-001, ADR-002, §5.1 `TaskExecutor` interface, §6 G-4,
> §7.1–7.3) → [`../prd.md`](../prd.md) (ARCH-P1-4, ARCH-P0-4, M8, M10, NFR-2/3) →
> [`../research/`](../research/) →
> [`../../../docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md).
> Where the architecture and the review conflict the architecture wins; where **this file's
> verification against HEAD** contradicts either, the verified fact wins and is recorded as a
> `VD-2*` delta in §4 with its `file:line`.
>
> **Every `file:line` below was opened at `0ae9a09` while writing this document.** Six claims carried
> down from the upstream documents did **not** reproduce; all six are recorded in §3 and two of them
> change this phase's scope (VD-2d removes `crates/bn-manager/` from the diff entirely; VD-2e adds
> `crates/keymanager-api/src/server.rs`, which no upstream scope list names). Two more are internal
> contradictions in the architecture itself, resolved here rather than deferred: VD-2a (six sites vs.
> six impls plus the trait) and VD-2f (a G-4 allow-list seeded entirely outside G-4's own scan path).
>
> **No-ask constraint:** every open question is resolved to a stated default in §8 *Assumptions*.
> Nothing is escalated.
>
> **Scope:** planning only. This file changes no source file and deletes nothing. The orphan trees
> (`crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`, `crates/rvc/src/commands/`)
> are **never cited, edited or migrated** by any issue here — they are Phase 0's archive-then-delete
> work (C10), and `crates/rvc/src/main.rs:1608`'s `#[allow(clippy::arc_with_non_send_sync)]` is
> explicitly **out of** ARCH-2b's removal list.

---

## 1. Phase Overview

**Goal.** Every task in the rvc process is named, tiered, metered, panic-contained and **joined**
through a two-entry-point `TaskExecutor`; the duty orchestrator is `tokio::spawn`ed and joined
instead of being polled inline and dropped mid-phase; and a SIGTERM lets an in-flight block publish
finish instead of vanishing with the dropped future.

| | |
|---|---|
| **Requirements** | ARCH-P1-4 (`TaskExecutor`), ARCH-P0-4 (spawnable/joinable orchestrator + real shutdown) |
| **ADRs** | ADR-001 (executor), ADR-002 (`?Send` removal + supertrait) |
| **Gate** | **G-4** `raw_spawn.rs` — lands **with** the migration, RED demonstrated locally (project-plan §1.1) |
| **Metrics closed** | **M8 = 0** raw spawns outside the executor allow-list; **M10** in-flight publish completes on signal |
| **Issue count** | **11** (ARCH-2a … ARCH-2k) |
| **Total points** | **21** |
| **Duration, 1 dev** | **11–19 working days** (see the reconciliation note below) |
| **Duration, 2 devs** | **9–17 working days** — Stream A is a 17-point chain and Stream B only 4 points, so the second developer buys ~1.15×, not 2× |
| **Depends on** | **Phase 0 only** — hard, not cosmetic |
| **Blocks** | Phase 3 (testability only: ADR-004's harness needs a spawnable orchestrator) |

**Estimate reconciliation, stated rather than smoothed.** The project plan sizes Phase 2 at
**8–13 d**; this decomposition totals 21 points ≈ **11–19 d** at the house rate (1 pt ≈ 0.5–1 day,
covering coding + tests + review + integration). The mid-points are 10.5 d vs 15 d. The gap is not
padding — it is three verified facts the plan's sizing did not have:

- **VD-2e** adds a cross-crate edit (`crates/keymanager-api/src/server.rs`) that ARCH-P0-4 item 3
  requires and that no upstream scope list names (+2 pts, ARCH-2j).
- **VD-2c** makes G-4 a path-aware scanner rather than a line-number comparison; the specified
  algorithm is RED-after-a-correct-migration on five files (+1 pt inside ARCH-2k).
- **VD-2a** makes ADR-002's mechanical edit 7 sites + 4 allows, not 6 sites + 3 allows.

Partially offsetting: **VD-2d** removes all three `crates/bn-manager/` sites from this phase's diff
(−1 to −2 pts). Net honest range is 11–19 d and the phase is *still* not on Phase 3's critical path
for anything but ARCH-2b/2c.

### Entry criteria

- [x] **Phase 0 is complete and merged.** Specifically: the four orphan paths no longer exist, so
      ADR-001's migration list and G-4's scanner never have to reason about the **25** raw
      `tokio::spawn` sites inside them (project-plan §7 Phase 2 *Entry criteria*, C10). Verified at
      HEAD as still present — e.g. `crates/rvc/src/main.rs:1495`, `:1773`, `:1826`, `:1902`, `:1921`,
      `:1944`, `:2060` — which is exactly why this is a hard gate: a G-4 scanner written today over
      `crates/rvc/src/**` reports 7 extra hits it must never learn to ignore.
- [x] The **`arch-gates` CI job** (`cargo nextest run -p rvc-architecture-tests`, project-plan A-P1)
      exists, so G-4's RED/GREEN is a fast signal instead of a coverage-job side effect.
- [x] Working tree green on all §2 standing invariants: `cargo fmt --all -- --check`,
      `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings`,
      `cargo build --workspace`, `cargo nextest run --workspace`.
- [x] **File-ownership agreed with any concurrent `plan/tracing-2026-08-06/` work** (project-plan
      RP2). Phase 2 owns `crates/rvc/src/bootstrap/run.rs`'s task lifecycle for its duration.

### Exit criteria — the milestone, as a checklist

- [x] **M8 = 0.** `raw_spawn.rs` (G-4) is green: zero raw `tokio::spawn` under `crates/rvc/src/**` +
      `bin/rvc/src/**` outside `bootstrap/executor.rs` and the shrinking-only allow-list, and the
      gate's RED is demonstrated on synthetic input in the same PR.
- [x] **M10.** A test that signals shutdown while a block publish is in flight asserts the publish
      **completes** — with an explicit `tokio::time::timeout`, so the pre-fix behaviour fails loudly
      instead of hanging. *(ARCH-2h: `tests/in_flight_publish_on_shutdown.rs`)*
- [x] `handle.shutdown()` → the orchestrator loop observes the watch change → returns `Ok(())` → the
      join completes within the 5 s budget (A-7); the assertion is on the **join**, not on a sleep.
      *(ARCH-2h: `test_orchestrator_handle_shutdown_is_joined_within_budget`)*
- [x] The **`LocalSet`/`spawn_local` scaffold at `crates/rvc/tests/sync_independent_of_attesting.rs:269-273`
      is deleted** and the orchestrator future is driven by a bare `tokio::spawn`. That compile is the
      regression pin for spawnability. The scaffold must not reappear (project-plan RP6).
- [x] `rg 'process::exit' crates/rvc/src` returns **no hit inside an `async fn`** (today:
      `bootstrap/run.rs:83`). The named exit codes EXIT_* 10/11/13/14 are preserved and asserted for
      the keystore-lock path (NFR-3).
- [x] No `tokio::time::sleep` stands in for a join in `bootstrap/run.rs` (today: `:319`).
      *(ARCH-2h: sleep deleted; drain is `executor.shutdown(TierBudget::default())`)*
- [x] Every registered task has a name visible in a metric label (`rvc_tasks_running{task}`), and a
      panicking task produces a reasoned shutdown (`ShutdownReason::Failure`) rather than a silent
      leak.
- [x] ADR-002's **probe verdict is recorded either way** — removal, or a named blocking type plus the
      alternative taken (A-6). Phase 2 cannot stall on it. *(ARCH-2a: clean — see `probe-adr002-verdict.md`)*
- [x] `rg 'arc_with_non_send_sync' crates/rvc/src bin/` returns nothing outside the orphan trees
      (VD-2b: **four** tracked sites, not three).
- [x] All §2 standing invariants green; no new `unbounded_channel` anywhere in the diff (C9 anchor 6).

**KAT-first policy (CLAUDE.md).** No issue in this phase adds, renames or moves a test matching
`.*(tree_hash|signing_root|_root)$`; the phase touches task lifecycle and shutdown only, never a
signing root or a container `hash_tree_root`. **The KAT policy is therefore not triggered by any
issue here, and `crates/architecture-tests/tests/kat_policy.rs`'s `EXEMPTIONS` list must not change.**
Stated rather than skipped, because ARCH-2c edits a test file and ARCH-2b edits mock impls — neither
introduces a root-named test, and a reviewer should be able to confirm that by name-pattern alone.
The one KAT-adjacent obligation is *stylistic*: G-4's scanner in ARCH-2k is written in the
`kat_policy.rs` house idiom (hand-rolled scan, shrinking-only const table, non-vacuity assertion,
matcher unit tests on synthetic input).

---

## 2. Assumptions verified against HEAD (`0ae9a09`)

Each row was opened and read while writing this file. "Confirmed" means the cited line contains what
the upstream document says it contains.

| # | Claim (source) | Status | Evidence at HEAD |
|---|---|---|---|
| V1 | `#[async_trait(?Send)]` on `BeaconBlockClient` is the root of the `!Send` orchestrator (ADR-002) | **Confirmed** | `crates/block-service/src/traits.rs:13` attribute, `:14` `pub trait BeaconBlockClient {` — **no supertraits declared** |
| V2 | The single production impl wraps an already-`Send + Sync` handle (ADR-002) | **Confirmed** | `crates/rvc/src/beacon_adapter.rs:18-19` `impl BeaconBlockClient for BeaconBlockAdapter` |
| V3 | The orchestrator is polled **inline** in a three-arm `select!` and its future is dropped on signal (ADR-001 *Consequences*) | **Confirmed** | `crates/rvc/src/bootstrap/run.rs:297-313` — arms `grpc_server` `:298`, `orchestrator.run()` `:304`, `shutdown_signal()` `:310` |
| V4 | `shutdown_token.cancel()` / `orchestrator_handle.shutdown()` fire **into a dropped future**, followed by a fake join | **Confirmed** | `run.rs:316-317` then `tokio::time::sleep(Duration::from_millis(100)).await` at `:319`; `background.shutdown()` at `:323` |
| V5 | An in-async `std::process::exit` on the keystore-lock path (ARCH-P0-4 item 4) | **Confirmed** | `run.rs:81-84` — `Err(e) if e.is_keystore_locked() => { std::process::exit(e.exit_code()); }` inside `async fn` |
| V6 | The gRPC arm carries a redundant `shutdown_signal()` alongside the token (§5.1 note) | **Confirmed** | `run.rs:268-276` — `serve_with_shutdown` selects `shutdown_signal()` **and** `token.cancelled()` |
| V7 | `OrchestratorHandle::shutdown()` exists and is a `watch::Sender<bool>` send — the machinery is real, only the join is missing | **Confirmed** | `crates/rvc/src/orchestrator/coordinator/mod.rs:68-81`; channel created at `:266` |
| V8 | 9 live in-scope production spawn sites in `crates/rvc/src` + `bin/rvc/src` (ADR-001) | **Confirmed, exactly 9** | `bootstrap/tasks.rs:88`, `:103`, `:124`; `bootstrap/enablement.rs:170`; `keymanager_adapters/spawn.rs:247`; `liveness_loop.rs:355`; `slashing_monitor.rs:123`, `:126`; `bin/rvc/src/logging.rs:217`. Every other `crates/rvc/src` hit is inside an orphan tree (`main.rs:1495…2060`) or a `#[cfg(test)]` region (`config/builder.rs:1122,1125,1166,1169` behind `:700`; `background_tasks/config_url.rs:401` behind `:174`; `background_tasks/monitoring.rs:442` behind `:241`; `bootstrap/keys.rs:473` behind `:194`) |
| V9 | `BackgroundTasks.metrics_handle` is `JoinHandle<Result<(), std::io::Error>>` — so `register` must be generic over `R` (§5.1) | **Confirmed** | `bootstrap/tasks.rs:29`; abort-then-2 s-timeout drain at `:145-151`, `JoinError` swallowed by `.ok()` at `:148` |
| V10 | The metrics server is the only live task that never sees a token (RA-5) | **Confirmed** | `tasks.rs:87-88` spawns `serve_metrics_with_health` with no `shutdown` argument; `:97` and `:118` clone the token for the other two |
| V11 | `slashing_monitor.rs:122-123` returns a **finished no-op handle** when the feature is disabled (`register_opt`'s reason for existing) | **Confirmed** | `slashing_monitor.rs:122-124` `if action == SlashedAction::None { return tokio::spawn(async {}); }`; the live handle at `:126` is returned and then **discarded** at `run.rs:248-253` |
| V12 | The liveness-loop handle is returned and dropped (keys stay `Pending` forever on panic) | **Confirmed** | `liveness_loop.rs:355-358` returns `LivenessLoopSpawn { join, .. }` (field at `:62`); destructured as `liveness_task: _liveness_loop_handle` and dropped at `run.rs:170` |
| V13 | The secret-provider refresh spawn discards its handle (PB-B3) | **Confirmed** | `bootstrap/enablement.rs:170-192` — bare `tokio::spawn`, result unbound |
| V14 | The Keymanager API server spawn discards its handle and has no token (Ingress tier) | **Confirmed** | `keymanager_adapters/spawn.rs:247-251` — bare `tokio::spawn`, `spawn_keymanager_api` returns `Result<(), _>` |
| V15 | The SIGHUP log-reload loop is token-scoped but its handle is discarded | **Confirmed** | `bin/rvc/src/logging.rs:206-217` — `spawn_log_reload_handler` returns `()`; the loop selects on `shutdown_token.cancelled()` at `:229` |
| V16 | The `LocalSet`/`spawn_local` scaffold exists and its comment names `?Send` as the reason | **Confirmed** | `crates/rvc/tests/sync_independent_of_attesting.rs:248-250` (comment), `:269` `LocalSet::new()`, `:273` `spawn_local`, `:281-282` `handle.shutdown(); let _ = run_task.await;` |
| V17 | clippy `disallowed-methods` cannot be adopted per-crate without dropping the three Gate-1 secret-key bans (G-4 *Why a scanner*) | **Confirmed** | `clippy.toml:25-29` — exactly three entries (`expose_secret`, `SecretKey::raw_bytes`, `SecretKey::to_bytes`); `clippy.toml:21-24` documents the feature-gated blind spot |
| V18 | The G-4 house idiom (no external dep, shrinking-only table, non-vacuity, synthetic matcher tests) exists to copy | **Confirmed** | `crates/architecture-tests/tests/kat_policy.rs` — rule note `:23`, shrinking-only `EXEMPTIONS` doc `:32-41`, non-vacuity `assert!(files.len() > 100, …)` `:414` and `assert!(matched > 20, …)` `:444`, synthetic matcher tests `:482-563` |
| V19 | `spawn_blocking` must never enter G-4's ban list (C9 anchor 7) | **Confirmed as a live hazard** | `crates/signer/src/core.rs:542` is the cancellation-proof core; `crates/signer-server/src/dvt/peer_service.rs:231,323` carry `!Send` guards. G-4 is path-scoped to `crates/rvc/src/**` + `bin/rvc/src/**`, which does not contain either — the ban list is the only way to reach them, so the prohibition is on the *list*, not the *path* |

---

## 3. Verification deltas found while writing this file

Six upstream claims did not reproduce. Each states the corrected fact and the issue that carries it.

| ID | Claim as written upstream | Status at HEAD | Corrected fact carried forward | Lands in |
|---|---|---|---|---|
| **VD-2a** | ADR-002: *"Remove `#[async_trait(?Send)]` at **all six sites** (trait declaration plus five impls)"* — and, one paragraph earlier, *"`rg 'impl BeaconBlockClient for'` returns **six impls**, one production"* | **Internally contradictory; the correct count is 7** | `rg 'impl BeaconBlockClient for'` returns **six** impls — `beacon_adapter.rs:19`, `coordinator/tests/mod.rs:128`, `:181`, `block-service/src/service/tests/mocks.rs:416`, `rvc/tests/common/pipeline_fixture.rs:160`, `rvc/tests/sync_independent_of_attesting.rs:120` — each preceded by its own `#[async_trait(?Send)]`, **plus** the trait declaration at `block-service/src/traits.rs:13`. That is **7 attribute sites**, in **5 files across 2 crates**. The seventh `?Send` string in the workspace is prose in a doc comment (`sync_independent_of_attesting.rs:249`) and is deleted by ARCH-2c, not ARCH-2b | **ARCH-2b** (edit list), **ARCH-2a** (probe `sed` list) |
| **VD-2b** | ADR-002 / project-plan §5: *"delete the **three** stale `#[allow(clippy::arc_with_non_send_sync)]` (`bootstrap/services.rs:186`, `config/builder.rs:3`, `orchestrator/coordinator/tests/mod.rs:6`)"*; architecture §7.2 sets the proof obligation *"no `#[allow(clippy::arc_with_non_send_sync)]` remains under `crates/rvc/src/` outside the orphan trees"* | **Understated — four tracked sites; the §7.2 obligation is unsatisfiable with the three-item list** | A fourth tracked site exists: **`crates/rvc/src/orchestrator/sync_committee.rs:327-329`** — `#[cfg(test)] #[allow(clippy::arc_with_non_send_sync)] mod tests`. The three named sites are real (`bootstrap/services.rs:186` production, `config/builder.rs:3` crate-file-level `#![allow]`, `coordinator/tests/mod.rs:6` file-level `#![allow]`). The fifth hit, `crates/rvc/src/main.rs:1608`, is **inside an orphan tree and must not be touched** (C10). ARCH-2b's list is therefore **four**, and §7.2's obligation is only then met | **ARCH-2b** |
| **VD-2c** | G-4 spec: *"skipping `#[cfg(test)]` regions by **comparing each hit's line number against the file's `#[cfg(test)]` line**"* | **The specified algorithm is RED after a correct migration** | Five in-scope hits live in files that contain **no `#[cfg(test)]` attribute at all**: `crates/rvc/src/orchestrator/coordinator/tests/core.rs:202` and `tests/spans.rs:124,193,409,479`. Their test-gating is **external** — `#[cfg(test)] mod tests;` at `coordinator/mod.rs:704` — and `rg 'cfg\(test\)' crates/rvc/src/orchestrator/coordinator` returns that one line only. A file-local line-number comparison finds no marker and classifies all five as production, so G-4 reports **14** violations where the truth is 9→0. The scanner needs a **path rule** (`**/src/**/tests/**` and `**/src/**/tests.rs` are test regions) *in addition to* the line-number rule, and a matcher unit test pinning exactly this shape | **ARCH-2k** |
| **VD-2d** | ADR-001: *"four **live production** spawns sit inside Infra crates"*; §5.1 rows P2-1…P2-4 record *"Handle today: **returned**"*; the phase brief calls `register` *"non-negotiable for four Infra sites"* | **Three of the four have zero production callers; the fourth's handle is discarded** | (i) `bn-manager/src/manager.rs:313` is inside `BnManager::start_sse` (`:303-316`) — `rg 'start_sse'` returns the definition and **no call site anywhere**, production or test, in `crates/rvc`/`bin/rvc`. (ii) `bn-manager/src/sync_status.rs:194` is inside `start_sync_monitor` (`:188-207`), whose only callers are `sync_status.rs:674`, `:706` (own `#[cfg(test)]`), `manager.rs:290` (the `BnManager` wrapper at `:284`) and `bn-manager/tests/manager_strategies.rs:1041` — **all tests**. (iii) `bn-manager/src/sse.rs:174` is the H-11 callback-dispatch task spawned **inside** `subscribe_events`, an `async fn` returning `()` (`:154`); its handle is **discarded, not returned**, and it is reachable only via `start_sse`, so it is not live either. (iv) `keymanager-api/src/lifecycle.rs:140` **is** live, but its handle is likewise discarded and it is a **per-pubkey, per-import** task whose cancellation lives in a `cancel_tokens` map (`:125-128`) — a `&'static str`-named registry entry per imported key is the wrong shape. **Consequence: `crates/bn-manager/` leaves this phase's diff entirely, and `register` has zero live *Infra-crate* call sites at HEAD.** `register` is not dead code: ARCH-2g uses it at **four in-crate sites** that already return a `JoinHandle` (P1-2 metrics server, P1-6 keymanager server, P1-7 liveness loop, P1-9 slashing monitor). What does not happen in this phase is the **four-row `P2-*` cross-crate migration** ADR-001 schedules; ADR-001's DAG argument for `register`'s shape still stands, and Phase 3's ADR-013 is where P2-1/P2-2 become live — see **A-2.4** | **ARCH-2d** (interface), **ARCH-2g** (four in-crate callers), **ARCH-2k** (VD-2f) |
| **VD-2f** | G-4 spec (architecture §6): the scanner is *"path-scoped to `crates/rvc/src/**` + `bin/rvc/src/**`"* **and** *"a shrinking-only allow list is **seeded with the four Infra library sites** reached via `register` (`bn-manager/src/manager.rs:313`, `sse.rs:174`, `sync_status.rs:194`, `keymanager-api/src/lifecycle.rs:140`)"* | **Internally inconsistent — the seeded list is vacuous** | All four seeded entries live under `crates/bn-manager/` and `crates/keymanager-api/`, which are **outside the declared scan path**. No entry can ever match a scanned line, so seeding them freezes four permanently-unreachable rows into a table the house idiom declares **shrinking-only** — the exact non-vacuity failure `kat_policy.rs:414`/`:444` exists to prevent, and a future reader would have no way to tell an obsolete row from a load-bearing one. **Corrected: the allow-list is empty at HEAD.** The four sites are recorded in the scanner's header comment as *out of scan scope by path, not by exemption*, each with its VD-2d reason. Widening the path scope to Infra crates (which Phase 3's ADR-013 may want) is then an explicit amendment decision, not a silent addition | **ARCH-2k** |
| **VD-2e** | ARCH-P0-4 item 3: *"Give the Keymanager API server a cancellation token and a bounded join (`keymanager_adapters/spawn.rs:247-251`; axum `with_graceful_shutdown`)"*, and the project plan's Phase-2 scope list, which names only `keymanager_adapters/spawn.rs:247` | **Not satisfiable inside `crates/rvc` — a second crate must change** | `KeymanagerApiServer::run` is `pub async fn run(self) -> Result<(), std::io::Error>` at `crates/keymanager-api/src/server.rs:158` and calls **bare `axum::serve(listener, router).await`** at `:162`. There is **no `with_graceful_shutdown` anywhere in `crates/keymanager-api/src`**. The token cannot be threaded from `spawn.rs:247` alone: `run`'s signature must gain the token (or a `run_with_shutdown`) inside `crates/keymanager-api`. That file appears in **no** upstream scope list. `keymanager-api` depends only on `eth-types`/`metrics`/`observability`, so taking a `tokio_util::sync::CancellationToken` adds **no new workspace edge** — no DAG-gate impact | **ARCH-2j** (own issue, own points) |

---

## 4. Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|---|---|---|---|---|---|
| **ARCH-2a** | ADR-002 spawnability probe — the verdict is the deliverable | **1** | spike | — | A |
| **ARCH-2b** | Remove `?Send` at 7 sites, add the `Send + Sync` supertrait, delete 4 stale allows | **2** | chore | ARCH-2a | A |
| **ARCH-2c** | Delete the `LocalSet`/`spawn_local` scaffold — the spawnability regression pin | **1** | chore | ARCH-2b | A |
| **ARCH-2d** | `TaskExecutor` core: `register` primitive, `spawn`, `register_opt`, panic-containing monitor | **3** | feature | — | A |
| **ARCH-2e** | Tiered drain, `TierBudget`, `ShutdownOutcome`, `ShutdownReason` escalation | **2** | feature | ARCH-2d | A |
| **ARCH-2f** | Two task metric series and nothing else | **1** | feature | ARCH-2d | A |
| **ARCH-2g** | Migrate the 9 in-scope production spawn sites onto the executor | **3** | chore | ARCH-2d, ARCH-2e, ARCH-2f, **ARCH-2j** (cross-stream: row P1-6 registers the handle 2j returns) | A |
| **ARCH-2h** | Spawn and join the orchestrator; retire the inline `select!` and the 100 ms sleep (**M10**) | **3** | feature | ARCH-2b, ARCH-2e, ARCH-2g | A |
| **ARCH-2i** | Remove the in-async `process::exit`; preserve and assert EXIT_* 10/11/13/14 | **1** | bug | — | A |
| **ARCH-2j** | Keymanager API graceful shutdown (**VD-2e**: `crates/keymanager-api/src/server.rs`) | **2** | feature | — | B |
| **ARCH-2k** | **G-4** `raw_spawn.rs` — path-aware scanner, allow-list, synthetic RED (**M8**) | **2** | chore | ARCH-2g (to land), not to build | B |
| | **Total** | **21** | | | |

**Binding intra-phase order** (safety / falsifiability, not preference):

| Order | Reason |
|---|---|
| **ARCH-2a first, always** | The compile was never run by any research track (ADR-002 *Consequences*). The verdict — removal or a named blocking type — is the deliverable either way (A-6, project-plan §8). |
| ARCH-2b → ARCH-2c | The scaffold cannot be deleted until the future is `Send`. |
| ARCH-2d → 2e → 2f → 2g | Build the primitive, then the drain, then the metrics, then convert call sites. Converting first means rewriting the call sites twice. |
| ARCH-2g → ARCH-2k **lands** | G-4 is one of the three gates that cannot precede its change (project-plan §1.1). It is **built** in parallel and **merged with or after** the migration, with RED reproduced locally against the pre-migration tree and the output pasted into the PR. `develop` is never red. |
| ARCH-2h last of the behavioural set | It needs a `Send` orchestrator (2b), a drain (2e) and migrated tasks (2g) to join against. |

---

## 5. Stream / file ownership (2 developers)

Disjoint file sets, drawn so no two issues in flight open the same file.

| Stream | Owns | Issues |
|---|---|---|
| **A** | `crates/rvc/src/bootstrap/**` (`run.rs`, `tasks.rs`, `enablement.rs`, `services.rs`, new `executor.rs`), `crates/rvc/src/keymanager_adapters/spawn.rs`, `liveness_loop.rs`, `slashing_monitor.rs`, `config/builder.rs`, `orchestrator/coordinator/**`, `orchestrator/sync_committee.rs` (one line), `crates/block-service/src/traits.rs` + `service/tests/mocks.rs`, `bin/rvc/src/logging.rs`, `crates/rvc/tests/**` | 2a, 2b, 2c, 2d, 2e, 2f, 2g, 2h, 2i |
| **B** | `crates/architecture-tests/tests/raw_spawn.rs` *(new)*, `crates/keymanager-api/src/server.rs` | 2j, 2k |

**Sequencing across the split.** Stream B can **build** both of its issues from day one — 2k's scanner
and matcher unit tests need only the pre-migration tree (that tree *is* the RED evidence), and 2j is
a self-contained cross-crate signature change. B's 2k **merges with or after** A's 2g; B's 2j merges
whenever it is green, and A's 2g then registers the returned handle at `spawn.rs:247`. Because
Stream A is a genuine chain (2a→2b→2c and 2d→2e→2f→2g→2h), the second developer shortens the phase
by roughly the 4 points in Stream B — **~1.15×, not 2×**. If only one developer is available, do
**ARCH-2a first anyway**: a failed probe changes the shape of 2b/2c/2h and of Phase 3's harness
(project-plan RP6), and discovering that on day 9 is the expensive outcome.

**Cross-phase rebase notes (not conflicts).**

- `crates/rvc/src/orchestrator/sync_committee.rs` — ARCH-2b removes **one line** (`:328`). Phase 3
  owns this file substantively (ADR-003/ADR-013). One-line, top-of-test-module change: rebase, do not
  coordinate.
- `crates/block-service/src/service/tests/mocks.rs:415` — ARCH-2b removes one attribute; Phase 3's
  G-8 work rewrites the seven `with_get_block_root` stubs in the same file. Land 2b first (it is in
  the earlier phase) and let Phase 3 rebase.
- `crates/rvc/src/bootstrap/run.rs` — touched by Phase 0 (16a deprecation `warn!` near `:263-276`)
  and Phase 7 (healthz removal). Phase 0 is a **prerequisite**, so its edit is already in; Phase 7 is
  five phases away. ARCH-2h must **preserve** the healthz `DutyTrackerServer` arm and its deprecation
  `warn!` — deleting it here would silently reset C8's deprecation clock.
- `plan/tracing-2026-08-06/` — project-plan RP2. That plan's Phase 2/3 do not touch `run.rs`'s
  `select!`; agree ownership at kickoff regardless.

---

## 6. Issues

### ARCH-2a — ADR-002 spawnability probe: the verdict is the deliverable

- **Points:** 1 · **Type:** spike · **Priority:** P0 · **Scope:** 0.5–1 day
- **Blocked by:** — · **Blocks:** ARCH-2b, ARCH-2c, ARCH-2h
- **Stream:** A · **Requirement:** ARCH-P0-4 item 1 (ADR-002) · **Constraints:** C9 (anchor 2), C10

**Context.** ADR-002's exhaustive static audit found no `!Send` blocker: `BeaconBlockAdapter` wraps
`Arc<dyn BeaconNodeClient>`, already `Send + Sync` (`crates/bn-manager/src/traits.rs:178-188`); a
field-by-field audit of `DutyOrchestrator`'s eighteen fields (`coordinator/mod.rs:204-235`) found
exactly one failing field, `block_service: BlockService<SignerService, B>`; and the two `.await`ed
locks at `duty_management.rs:162`, `:191` are `tokio::sync::RwLock`, whose guards are `Send`. But
**the compile was never run** — no research track had a shell. The verdict is "no blocker found by
exhaustive audit," not "the build passed." One day of probe removes an assumption the rest of the
phase and Phase 3's harness both rest on.

**Files to touch.** None in the working tree. A throwaway `git worktree` only. The recorded verdict
lands as `plan/architecture-2026-08-12/probe-adr002-verdict.md` and is quoted in the ARCH-2b PR body.

**Implementation approach.**
1. `git worktree add ../rvc-probe-adr002 develop` — never probe in the working tree.
2. Delete the `#[async_trait(?Send)]` attribute at the **seven** sites of VD-2a (not six):
   `crates/block-service/src/traits.rs:13`, `crates/rvc/src/beacon_adapter.rs:18`,
   `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:127` and `:180`,
   `crates/block-service/src/service/tests/mocks.rs:415`,
   `crates/rvc/tests/common/pipeline_fixture.rs:159`,
   `crates/rvc/tests/sync_independent_of_attesting.rs:119`.
3. Add the supertrait: `pub trait BeaconBlockClient: Send + Sync` at `traits.rs:14`.
4. `cargo check --workspace --all-targets --all-features` — **`--all-targets` is not optional**: four
   of the seven sites are in test targets, so a default `cargo check` proves nothing about them.
5. Record the verdict. **If it fails**, the failing diagnostic **names a concrete type**, and that
   name — plus the alternative taken — *is* the closure of ARCH-P0-4 item 1 (A-6). Look first in
   `crates/block-service/src/service/**` and in `MockBeaconClient`'s method bodies after
   `mocks.rs:439`, which hold `std::sync::Mutex<Vec<…>>` call logs; a body that locks and *then*
   awaits is the classic instance.
6. `git worktree remove` — the probe leaves no trace.

**TDD test plan.** This is a spike, so the "RED test" is the probe itself: the pre-change tree
**already fails** the target property, and `crates/rvc/tests/sync_independent_of_attesting.rs:248-250`
is the checked-in comment asserting so (*"`DutyOrchestrator::run()` is `!Send` because
`BeaconBlockClient` uses `#[async_trait(?Send)]`"*). No test is added or changed by this issue.

**Acceptance criteria.**
- [x] `cargo check --workspace --all-targets --all-features` was run on a worktree with all seven
      attributes removed and the supertrait added, and its **full output** is recorded.
- [x] The verdict file states one of: (a) *clean — proceed with ARCH-2b*, or (b) *blocked by
      `<fully-qualified type>` at `<file:line>`, alternative taken: `<Route B / owned handle / …>`*.
- [x] The working tree is byte-identical before and after (`git status --porcelain` empty).
- [x] **No file under `crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs` or
      `crates/rvc/src/commands/` is opened, `sed`ed or listed** (C10).

**Done:** verdict at [`../probe-adr002-verdict.md`](../probe-adr002-verdict.md) — **clean, proceed with ARCH-2b**. HEAD delta: 8th `?Send` site at `proposal_under_duty_stall.rs:368` (include in ARCH-2b).

**Risk.** Project-plan R3, downgraded to Low × Low by the audit but **not discharged** until this
runs. If it fails, project-plan RP6 applies: Phase 3's harness keeps the `LocalSet` scaffold at a
stated cost, ARCH-2c is cancelled, and ARCH-2h's join is written against the inline future.

---

### ARCH-2b — Remove `?Send` at seven sites, add the supertrait, delete four stale allows

- **Points:** 2 · **Type:** chore · **Priority:** P0 · **Scope:** 1–2 days
- **Blocked by:** ARCH-2a · **Blocks:** ARCH-2c, ARCH-2h
- **Stream:** A · **Requirement:** ARCH-P0-4 item 1 (ADR-002) · **Constraints:** C9 (anchor 2 — by
  *not* touching it), C10

**Context.** `BeaconBlockClient` is the **only** service trait in the workspace without
`: Send + Sync`; eight peers declare it (`SlotClock`, `BeaconNodeClient`, `AttestationSubmitter`,
`Signer`, `ValidatorSigner`, `SigningEnablement`, `RegistrationSigner`, `BuilderBeaconClient`). The
anomaly is its absence. ADR-002 rejects *Route B* — adding `+ Send + Sync` at the seven
`B: BeaconBlockClient` bound sites (`coordinator/mod.rs:125`, `:154`, `:208`, `:241`;
`block_proposal/mod.rs:53`; `block-service/src/service/mod.rs:27`, `:36`) — because it re-creates the
enforced-by-discipline seam this initiative exists to remove. The supertrait is one line and
satisfies every bound automatically.

**Files to touch** (VD-2a and VD-2b corrections applied — **7** attributes, **4** allows):

| File | Line | Change |
|---|---|---|
| `crates/block-service/src/traits.rs` | 13, 14 | Delete `#[async_trait(?Send)]`; `pub trait BeaconBlockClient: Send + Sync` |
| `crates/rvc/src/beacon_adapter.rs` | 18 | Delete attribute (the one production impl) |
| `crates/rvc/src/orchestrator/coordinator/tests/mod.rs` | 127, 180 | Delete both attributes (`MockBlockBeacon`, `BadProposerBlockBeacon`) |
| `crates/block-service/src/service/tests/mocks.rs` | 415 | Delete attribute (`MockBeaconClient`) |
| `crates/rvc/tests/common/pipeline_fixture.rs` | 159 | Delete attribute (`NoopBlockBeacon`) |
| `crates/rvc/tests/sync_independent_of_attesting.rs` | 119 | Delete attribute (`NoopBlockBeacon`) |
| `crates/rvc/src/bootstrap/services.rs` | 186 | Delete `#[allow(clippy::arc_with_non_send_sync)]` (production) |
| `crates/rvc/src/config/builder.rs` | 3 | Delete the crate-file-level `#![allow(...)]` |
| `crates/rvc/src/orchestrator/coordinator/tests/mod.rs` | 6 | Delete the file-level `#![allow(...)]` |
| `crates/rvc/src/orchestrator/sync_committee.rs` | 328 | **VD-2b — the fourth site the upstream list misses.** Delete the allow above `#[cfg(test)] mod tests` |
| ~~`crates/rvc/src/main.rs`~~ | ~~1608~~ | **DO NOT TOUCH** — orphan tree, no git object behind it, C10 |

**Implementation approach.** Apply exactly the probe's diff from ARCH-2a, then delete the four
allows in the same PR (they are adjacent to the change and would otherwise mask a regression of
precisely the bug class being fixed). Do **not** touch `crates/signer/src/core.rs` or
`crates/slashing/src/stage.rs` — ADR-002 has **no dependency on ADR-005**, and the `!Send` staging
guard never enters the orchestrator's future (refuted by `core.rs:36-41`, `:284-287`, `:542`, `:930`).
The `?Send` prose in `sync_independent_of_attesting.rs:248-250` stays for now; ARCH-2c deletes it
together with the scaffold it explains.

**TDD test plan.**
- **RED (first):** in `crates/rvc/src/orchestrator/coordinator/tests/mod.rs`, add
  `fn test_duty_orchestrator_run_future_is_send()` — a **compile-time** assertion, not a runtime one:
  ```rust
  fn assert_send<T: Send>(_: &T) {}
  // RED before the supertrait: `future cannot be sent between threads safely`.
  let fut = orchestrator.run();
  assert_send(&fut);
  ```
  It asserts that `DutyOrchestrator::run()`'s future is `Send`. Before the change it fails to
  compile with a diagnostic naming `dyn Future ... + !Send`; after, it compiles and passes trivially.
  Compile-failure is the correct RED here because a runtime assertion cannot observe `!Send`.
- **GREEN:** the seven attribute removals + the supertrait.
- **REFACTOR:** delete the four allows; confirm clippy does not re-raise
  `clippy::arc_with_non_send_sync` at any of them — if it does, one is still load-bearing, and the
  `Arc::new` plus its type goes in the PR body rather than the allow going back in.

**Acceptance criteria.**
- [x] `rg 'async_trait\(\?Send\)' --glob '**/*.rs'` returns **only** the prose hit at
      `crates/rvc/tests/sync_independent_of_attesting.rs:249` (deleted by ARCH-2c) — zero attributes.
- [x] `crates/block-service/src/traits.rs:14` reads `pub trait BeaconBlockClient: Send + Sync`.
- [x] `rg 'arc_with_non_send_sync' crates/rvc/src bin/` returns nothing outside `crates/rvc/src/main.rs`
      (which no longer exists after Phase 0) — satisfying architecture §7.2's secondary obligation,
      which the three-item list could not (VD-2b).
- [x] `test_duty_orchestrator_run_future_is_send` compiles and passes.
- [x] No bound site gained `+ Send + Sync` (Route B was rejected):
      `rg 'B: BeaconBlockClient \+ Send'` returns nothing.
- [x] `git diff --stat` shows **no** change under `crates/signer/` or `crates/slashing/`.
- [x] All §2 standing invariants green; the diff is net-negative in lines.

**Done:** ADR-002 applied — 8 attribute sites (`?Send` → default `#[async_trait]`), `BeaconBlockClient: Send + Sync`, 4 stale `arc_with_non_send_sync` allows removed (VD-2b), compile-time Send pin `test_duty_orchestrator_run_future_is_send`. LocalSet scaffold left for ARCH-2c.

---

### ARCH-2c — Delete the `LocalSet`/`spawn_local` scaffold: the spawnability regression pin

- **Points:** 1 · **Type:** chore · **Priority:** P0 · **Scope:** 0.5–1 day
- **Blocked by:** ARCH-2b · **Blocks:** Phase 3's harness (testability)
- **Stream:** A · **Requirement:** ARCH-P0-4 (acceptance addition) · **Constraints:** C9

**Context.** `crates/rvc/tests/sync_independent_of_attesting.rs:269-273` wraps the orchestrator in a
`tokio::task::LocalSet` and drives it with `spawn_local`, with a comment at `:248-250` naming
`#[async_trait(?Send)]` as the reason. Deleting it and driving the future with a bare `tokio::spawn`
is **the sharpest available proof of spawnability** — it converts an existing workaround into the
regression pin, so a future re-introduction of `?Send` breaks a checked-in test rather than silently
re-disabling this phase's outcome.

**Files to touch.** `crates/rvc/tests/sync_independent_of_attesting.rs` (`:119` attribute already
gone via ARCH-2b; `:240-290` body and `:248-250` comment).

**Implementation approach.** Replace `local.run_until(async move { … }).await` with a direct
`tokio::spawn(async move { orchestrator.run().await })`, keeping the existing
`tokio::time::timeout(Duration::from_secs(5), submitted_rx)` and the
`handle.shutdown(); let _ = run_task.await;` sequence at `:281-282` **unchanged** — that pair is
already the join shape ARCH-2h generalises. Delete the `?Send`/`LocalSet` explanation at `:248-250`
and replace it with one sentence stating that the bare `tokio::spawn` **is** the ADR-002 regression
pin, so a future reader does not "simplify" it back.

**TDD test plan.** The RED is structural and already checked in: `test_sync_runs_with_attesting_disabled`
**does not compile** with a bare `tokio::spawn` before ARCH-2b (`future is not Send`). Run it in that
order once, locally, and paste the diagnostic in the PR — that is the "demonstrated, not asserted"
standard (ADR-012). No new test is added; an existing test is strengthened.

**Acceptance criteria.**
- [x] `rg 'LocalSet|spawn_local' crates/rvc/` returns **nothing**.
- [x] `test_sync_runs_with_attesting_disabled` drives `orchestrator.run()` through a bare
      `tokio::spawn` and passes under `cargo nextest run -p rvc`.
- [x] The assertion semantics are unchanged — the test still fails if a sync-committee message is not
      submitted within 5 s (it is a behaviour test, not a spawnability test; spawnability is proved
      by its **compilation**).
- [x] A comment at the spawn site states it is the ADR-002 regression pin and must not be reverted to
      a `LocalSet` (project-plan RP6: *"the scaffold must not be re-introduced as a permanent
      fixture"*).
- [x] `git grep -n 'async_trait(?Send)' -- '*.rs'` returns **zero** hits (historical plan/docs prose
      still names the removed attribute; no remaining code or test comments).

**Done:** Deleted `LocalSet`/`spawn_local` scaffold in `sync_independent_of_attesting.rs` (both tests)
and `proposal_under_duty_stall.rs` `drive_orchestrator`; bare `tokio::spawn` is the ADR-002
regression pin. Kept timeout + `handle.shutdown` + join. Zero `LocalSet|spawn_local` under
`crates/rvc/`; zero `async_trait(?Send)` in `**/*.rs`.

---

### ARCH-2d — `TaskExecutor` core: the `register` primitive, `spawn`, `register_opt`, panic-containing monitor

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Scope:** 2 days
- **Blocked by:** — · **Blocks:** ARCH-2e, ARCH-2f, ARCH-2g
- **Stream:** A · **Requirement:** ARCH-P1-4 (ADR-001) · **Constraints:** C9 (anchors 6, 7), NG3

**Context.** rvc has three spawn idioms and **none of them joins**. A panicking background task today
is a silent leak: the process keeps running with the feature dead and no signal — including
`liveness_loop.rs:355` (keys stay `Pending` forever) and `slashing_monitor.rs:126` (slashed-validator
detection stops). ADR-001 adopts **four of Lighthouse's nine** `task_executor` mechanisms: named
spawns (`&'static str`, so the metric label is allocation-free), panic containment →
`ShutdownReason::Failure`, per-task metrics, and the `ShutdownReason` enum. It rejects
`HandleProvider`/`Weak<Runtime>`, `async_channel` exit-wrapping, the rayon variants,
`block_on_dangerous`, `spawn_handle` and the whole `spawn_blocking` family. This is a **utility, not
a framework** (NG3).

**Files to touch.** `crates/rvc/src/bootstrap/executor.rs` *(new — a **module**, not a crate)*;
`crates/rvc/src/bootstrap/mod.rs` (one `pub mod executor;`).

**Implementation approach.** Implement architecture §5.1 verbatim: `ShutdownTier`
(`Ingress < Orchestrator < Background < Telemetry`, `PartialOrd + Ord` so the drain order is the enum
order), `ShutdownReason::{Success, Failure}(&'static str)`, `TierBudget([Duration; 4])`, `Registered
{ name, tier, work: AbortHandle, monitor: JoinHandle<()> }`, and
`TaskExecutor::new(token) -> (Self, mpsc::Receiver<ShutdownReason>)`.

Three properties that are easy to invert and produce a silently broken executor:

1. **The monitor holds the work `JoinHandle`; the registry holds the work's `AbortHandle`.** Aborting
   the monitor would not stop the work. `shutdown` aborts `work`, then joins `monitor`, which observes
   `Err(e)` and records `e.is_cancelled()` vs `e.is_panic()`.
2. **The monitor uses `try_send`, never `send().await`** on the `mpsc::channel(8)`. A full channel
   means shutdown is already in flight, so dropping the second reason is correct; awaiting inside a
   monitor would make panic reporting itself blockable. **`channel(8)`, never `unbounded_channel`**
   (C9 anchor 6).
3. **`register` is the primitive; `spawn` is defined as `register(name, tier, tokio::spawn(fut))`** —
   no duplicated monitor logic. `register` is generic over `R: Send + 'static` because real handles
   are not all `JoinHandle<()>`: `BackgroundTasks::metrics_handle` is
   `JoinHandle<Result<(), std::io::Error>>` (`bootstrap/tasks.rs:29`, verified V9).

`register_opt(name, tier, Option<JoinHandle<R>>)` registers **nothing** on `None`, replacing the
finished-no-op-handle idiom at `slashing_monitor.rs:122-123` so `rvc_tasks_running{task}` is honestly
0 when a feature is disabled.

**On `register`'s call sites — read VD-2d before writing the doc comment.** ADR-001 justifies
`register` by four Infra sites that "cannot depend on a composition-root executor without violating
the DAG gate." That justification stands and `register` **is** built here, but the claim that the
four are *live* does not reproduce: `bn-manager`'s `start_sse` and `start_sync_monitor` have **no
production caller at HEAD**, `sse.rs:174`'s handle is discarded rather than returned, and
`keymanager-api/src/lifecycle.rs:140` is per-pubkey and C5-owned. **`register` therefore ships with
zero live *Infra-crate* call sites** — but it is not dead code: ARCH-2g uses it at four in-crate
sites that already return a `JoinHandle` (P1-2, P1-6, P1-7, P1-9). Its doc comment must state both
halves and name Phase 3 (ADR-013, which wires SSE into production) as where the Infra rows become
live. Do not invent an Infra caller to justify the generic signature, and do not delete it.

**TDD test plan** (all in `#[cfg(test)] mod tests` at the bottom of `executor.rs`):
- **RED first:** `test_panicking_task_reports_failure_reason` — register a task whose body is
  `panic!("boom")`, then assert the `ShutdownReason` receiver yields
  `ShutdownReason::Failure("<task name>")` within a `timeout`. Fails today because no such type
  exists; fails against a naive implementation that only joins at shutdown, because the reason must
  arrive **when the panic happens**, not at drain.
- `test_register_is_generic_over_handle_output` — register a `JoinHandle<Result<(), io::Error>>`
  (mirroring `metrics_handle`) and a `JoinHandle<()>` in the same registry.
- `test_spawn_is_register_of_tokio_spawn` — asserts one registry entry per `spawn`, and that its
  recorded `name`/`tier` round-trip.
- `test_register_opt_none_registers_nothing` — registry length unchanged, no `rvc_tasks_running`
  series created.
- `test_monitor_try_send_never_blocks_when_channel_full` — fill the `channel(8)`, panic a ninth task,
  assert the monitor completes within a `timeout` (proves `try_send`, not `send().await`).
- `test_clean_exit_reports_ok_not_panic` — a task returning normally records `outcome = ok`.

**Acceptance criteria.**
- [x] `crates/rvc/src/bootstrap/executor.rs` exists and matches architecture §5.1's signatures
      (`new`, `token`, `spawn`, `register`, `register_opt`, `shutdown`, `ShutdownOutcome`).
- [x] **No new crate** was created (`cargo metadata` member count unchanged from Phase 0's 28) —
      ADR-001 rejected `rvc-task` for now.
- [x] `spawn` is literally implemented as `register(name, tier, tokio::spawn(fut))`; there is exactly
      one monitor implementation.
- [x] The shutdown-reason channel is `mpsc::channel(8)` and the monitor uses `try_send`;
      `rg 'unbounded_channel' crates/rvc/src/bootstrap/` returns nothing (C9 anchor 6).
- [x] The executor takes the **existing** `CancellationToken` (no second exit channel) — `token()`
      returns a clone usable exactly like today's `shutdown.clone()` at `tasks.rs:97`, `:118`.
- [x] `spawn_blocking` appears nowhere in `executor.rs` and no API wraps it (C9 anchor 7).
- [x] All six unit tests above pass; the panic test is written with a `timeout`.
- [x] Public items carry `///` docs; `register`'s doc states VD-2d's zero-live-call-sites fact and
      names Phase 3 as where it becomes live.

---

### ARCH-2e — Tiered drain, `TierBudget`, `ShutdownOutcome`, `ShutdownReason` escalation

- **Points:** 2 · **Type:** feature · **Priority:** P0 · **Scope:** 1–2 days
- **Blocked by:** ARCH-2d · **Blocks:** ARCH-2g, ARCH-2h
- **Stream:** A · **Requirement:** ARCH-P1-4 (ADR-001), ARCH-P0-4 (the join half) · **Constraints:** C9

**Context.** A-7's 5 s grace period is a **total process budget**, not a per-task one; ADR-001 splits
it Ingress 2.0 / Orchestrator 2.0 / Background 0.5 / Telemetry 0.5. Tier order is a correctness
property, not cosmetics: **Ingress stops first** so a keymanager import cannot land during
orchestrator teardown, and **Telemetry drains last** so logging guards owned by `main` flush after
all HTTP work is gone (`bootstrap/run.rs:321-322`, verified V4).

**Files to touch.** `crates/rvc/src/bootstrap/executor.rs` (extends ARCH-2d).

**Implementation approach.** `shutdown(self, budget: TierBudget) -> ShutdownOutcome`: cancel the
token once, then for each tier in ascending order, `tokio::time::timeout(tier_budget, join_all(monitors))`;
on expiry, `work.abort()` every straggler in that tier, `warn!` with the task **name**, and record it
in `ShutdownOutcome.aborted`. Joined tasks land in `ShutdownOutcome.joined`. Consumes `self` so a
double drain cannot compile.

**Carry RA-5 forward explicitly — it is a PRD amendment, not a silent absorption.** The metrics
server is the only live task that never sees a token (verified V10: `tasks.rs:87-88` takes no
`shutdown`). If ARCH-2g converts it to cooperative shutdown — and it should — the Telemetry budget
rises 0.5 → 2.0 s and A-7's total 5 s → **6.5 s**. If that conversion happens, this issue's PR body
states the new total and links the PRD amendment; if it does not, Telemetry stays abort-drain at
0.5 s, exactly matching today's `METRICS_SHUTDOWN_TIMEOUT` semantics (2 s abort-then-await at
`tasks.rs:145-151`) and the budget is noted as **tighter than today**, which is a deliberate choice
and must be stated rather than discovered.

**TDD test plan.**
- **RED first:** `test_drain_order_is_ingress_before_orchestrator_before_telemetry` — register one
  task per tier, each pushing its name onto a shared `Arc<Mutex<Vec<&'static str>>>` on exit; assert
  the recorded order is exactly `[ingress, orchestrator, background, telemetry]`. Fails against a
  `join_all`-everything implementation, which is the natural wrong first draft.
- `test_tier_budget_expiry_aborts_and_names_the_task` — a task that ignores the token and sleeps
  forever is aborted at its tier budget, appears in `ShutdownOutcome.aborted`, and its **name**
  appears in the emitted `warn` (assert via a capturing subscriber, not by eyeball).
- `test_total_budget_is_the_sum_not_the_max` — four straggler tasks, one per tier; assert wall-clock
  drain ≈ the sum of the four budgets, and that no single tier consumes another's.
- `test_cooperative_task_joins_well_inside_budget` — a token-observing task exits and is in
  `joined`, not `aborted`.
- `test_shutdown_consumes_executor` — compile-level: a second `shutdown` call does not compile
  (documented in a `compile_fail` doctest or asserted by inspection in review).

**Acceptance criteria.**
- [x] `TierBudget::default()` is `[2.0, 2.0, 0.5, 0.5]` seconds, summing to A-7's 5 s, with the sum
      asserted by a unit test so a future edit to one tier cannot silently change the total.
- [x] Drain is strictly tier-ordered; each tier is fully drained or its budget expires before the
      next begins.
- [x] Every abort emits `warn` with the task name; `ShutdownOutcome { joined, aborted }` is returned
      and logged by the caller.
- [x] The token is cancelled exactly **once**, at the top of `shutdown`.
- [x] RA-5's decision is recorded in the PR body: either Telemetry stayed 0.5 s (abort-drain) or it
      rose to 2.0 s with the total restated as 6.5 s.
- [x] No test uses `sleep` as a proxy for a join.



---

### ARCH-2f — Two task metric series and nothing else

- **Points:** 1 · **Type:** feature · **Priority:** P1 · **Scope:** 0.5–1 day
- **Blocked by:** ARCH-2d · **Blocks:** ARCH-2g
- **Stream:** A · **Requirement:** ARCH-P1-4 ("every task has a name visible in a metric label"),
  NFR-7 · **Constraints:** NFR-1, NFR-5

**Context.** A-A5 caps the executor's observability at **two series**, against Lighthouse's six.
Eight of the nine live in-scope tasks are infinite loops, for which a task-lifetime histogram is
meaningless — it would record "still running" forever and cost cardinality for nothing.

**Files to touch.** `crates/rvc/src/bootstrap/executor.rs`; the metrics registration site under
`crates/metrics/` **only if** the repo's existing pattern requires central registration (check
`crates/metrics/src/` for the idiom before adding a new one — extend, never invent a second
registry).

**Implementation approach.** `rvc_tasks_running{task}` (gauge: `inc` at register, `dec` in the
monitor on any exit) and `rvc_task_exits_total{task, outcome}` (counter,
`outcome ∈ {ok, panic, cancelled}`). Labels are `&'static str`, so the label set is allocation-free
and bounded by the registered task list. **No lifetime histogram. No per-tier series. No third
metric.** Adding one later is a decision; adding it here is scope creep on a phase whose exit
criteria are two numbers.

**TDD test plan.**
- **RED first:** `test_running_gauge_returns_to_zero_after_drain` — register three tasks across
  tiers, assert the gauge reads 3, drain, assert it reads **0**. Fails against the obvious
  implementation that increments at register and decrements only on the `ok` path (a panicked or
  aborted task leaks the gauge — exactly the silent-leak class this phase exists to end).
- `test_panic_exit_is_labelled_panic_not_ok` and `test_abort_exit_is_labelled_cancelled`.
- `test_register_opt_none_creates_no_series` — the disabled-feature honesty property
  (`slashing_monitor.rs:122-123`'s idiom is what this replaces).

**Acceptance criteria.**
- [x] Exactly two series exist; `rg 'rvc_task' crates/` shows no third.
- [x] Every registered task's name appears as a label value in `rvc_tasks_running`.
- [x] The gauge returns to 0 after a full drain, including for panicked and aborted tasks.
- [x] `outcome` takes exactly the three documented values.
- [x] No measurable cost on the per-slot deadline path at default `info` (NFR-1) — the executor is
      touched at register and at exit only, never per slot; state this in the PR rather than
      re-running the Phase-0 M1/M2 harness for a metric that cannot be on that path.

---

### ARCH-2g — Migrate the nine in-scope production spawn sites onto the executor

- **Points:** 3 · **Type:** chore · **Priority:** P0 · **Scope:** 2 days
- **Blocked by:** ARCH-2d, ARCH-2e, ARCH-2f · **Blocks:** ARCH-2h, ARCH-2k (to land)
- **Stream:** A · **Requirement:** ARCH-P1-4 · **Constraints:** C9 (anchors 6, 7), C10, NFR-2

**Context.** This is the whole of ARCH-P1-4's conversion work. Architecture §5.1's migration table
lists 13 rows (9 `P1-*` + 4 `P2-*`); **VD-2d removes all four `P2-*` rows from this phase** — three
have no production caller at HEAD and the fourth is per-pubkey and C5-owned — so this issue is
**nine sites, one crate pair, zero cross-crate edits**. That is what keeps it at 3 points.

**Files to touch** (each row verified at HEAD, V8/V11–V15):

| # | Site | Task | Tier | Entry point | Note |
|---|---|---|---|---|---|
| P1-1 | `bin/rvc/src/logging.rs:217` | SIGHUP log-reload loop | Telemetry | `spawn` | Already token-scoped (`:229`); handle currently discarded. `spawn_log_reload_handler` must take `&TaskExecutor` |
| P1-2 | `crates/rvc/src/bootstrap/tasks.rs:88` | `serve_metrics_with_health` | Telemetry | `register` | The only live task with **no token** (V10). Converting it to cooperative shutdown triggers RA-5 — see ARCH-2e |
| P1-3 | `bootstrap/tasks.rs:103` | monitoring push (PB-B2) | Background | `spawn` | Token cloned at `:97` |
| P1-4 | `bootstrap/tasks.rs:124` | proposer-config URL refresh (PB-B1) | Background | `spawn` | Token cloned at `:118` |
| P1-5 | `bootstrap/enablement.rs:170` | secret-provider refresh (PB-B3) | Background | `spawn` | Token lives inside `RefreshService` (`:164`). Panic today = **key admission stops** |
| P1-6 | `keymanager_adapters/spawn.rs:247` | Keymanager API axum server | **Ingress** | `register` | Registers the handle **returned by ARCH-2j**; no token today |
| P1-7 | `liveness_loop.rs:355` | per-slot doppelganger liveness tick | Orchestrator | `register` | Handle exists (`LivenessLoopSpawn.join`, `:62`) and is dropped at `run.rs:170`. Panic today = **keys stay `Pending` forever** |
| P1-8 | `slashing_monitor.rs:123` | finished no-op handle when disabled | — | `register_opt(None)` | Change `spawn_with_interval` to return `Option<JoinHandle<()>>` |
| P1-9 | `slashing_monitor.rs:126` | slashed-validator epoch check | Background | `register` | Returned and discarded at `run.rs:248-253`. Panic today = **detection stops** |

**Implementation approach.** Thread `&TaskExecutor` from the composition root (`bootstrap/run.rs`)
into `spawn_background_tasks`, `spawn_keymanager_api`, `spawn_liveness_loop`, `slashing_monitor::spawn`
and `spawn_log_reload_handler`. Prefer `register` wherever a function already returns a `JoinHandle`
(P1-2, P1-6, P1-7, P1-9) — that keeps the library function's signature and only changes what the
root does with the result. Use `spawn` where the future is constructed at the root. **Delete
`BackgroundTasks::shutdown`'s bespoke abort-then-2 s-timeout (`tasks.rs:143-152`)** — it is a private
one-task drain that the tiered drain subsumes; leaving both means two shutdown paths and the one you
did not update wins. `BackgroundTasks` may reduce to nothing, in which case delete the struct.

**Sites that must NOT change** — each is a real trap:
- The **83 test/test-support** raw spawns, including `crates/rvc-test-support/src/lib.rs:199`
  (production code in a test-support crate) and the five under
  `crates/rvc/src/orchestrator/coordinator/tests/` (VD-2c).
- The **5 `signer-server`/`bin/rvc-signer`** sites — out of scope by A-13.
- **Every `spawn_blocking`**, everywhere (C9 anchor 7).
- **Anything under the orphan trees** — they no longer exist after Phase 0; if a hit appears there,
  Phase 0 is incomplete and this issue stops (C10).

**TDD test plan.**
- **RED first:** `test_every_background_task_is_registered_by_name` in
  `crates/rvc/tests/` — boot the bootstrap path with a test config that enables monitoring push,
  proposer-config refresh, keymanager API and the slashing monitor, then assert the executor's
  registry contains **exactly** the expected `&'static str` name set. Fails today (no registry) and
  fails against a partial migration, which is the realistic regression.
- `test_panicking_background_task_triggers_reasoned_shutdown` — inject a panicking task at
  Background tier and assert the process receives `ShutdownReason::Failure` rather than continuing
  with the feature dead (this is ARCH-P1-4's named acceptance criterion). Use a `timeout`.
- `test_disabled_slashing_monitor_registers_no_task` — `SlashedAction::None` ⇒ no
  `rvc_tasks_running{task="slashing_monitor"}` series at all (P1-8, the `register_opt` reason).
- Existing tests for each migrated task stay green unchanged — a changed assertion in any of them is
  a behavioural regression, not a migration.

**Acceptance criteria.**
- [x] All nine sites route through `TaskExecutor`; `rg 'tokio::spawn' crates/rvc/src bin/rvc/src`
      returns hits **only** inside `bootstrap/executor.rs` and `#[cfg(test)]`/`tests/` regions.
- [x] Each site's tier matches the table above, and the tier choice is defensible from the drain
      semantics (Ingress admits new work; Telemetry flushes last).
- [x] `BackgroundTasks::shutdown`'s private drain is deleted; there is exactly **one** shutdown path.
- [x] `rg 'spawn_blocking' crates/rvc/src bin/rvc/src` is unchanged by this diff.
- [x] No new channel of any kind; `rg 'unbounded_channel'` unchanged workspace-wide (C9 anchor 6,
      NFR-2).
- [x] The three tests above pass; every pre-existing test for the nine tasks passes **unmodified**.
- [x] `cargo nextest run --workspace` green; `cargo build --workspace` green.

**Status:** Done (ARCH-2g, branch `feature/p2-2g-migrate-spawns-to-executor`). G-4 `ALLOW_LIST` emptied (M8 = 0 / ARCH-2k acceptance).

---

### ARCH-2h — Spawn and join the orchestrator; retire the inline `select!` and the 100 ms sleep (M10)

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Scope:** 2 days
- **Blocked by:** ARCH-2b, ARCH-2e, ARCH-2g · **Blocks:** — (Phase 3 depends on ARCH-2c, not on this)
- **Stream:** A · **Requirement:** ARCH-P0-4 items 2 and 4 (the sleep), **M10** · **Constraints:**
  C8, C9 (anchor 6), NFR-3

**Context — the defect, stated precisely.** `bootstrap/run.rs:297-313` polls three futures inline.
When the `shutdown_signal()` arm at `:310` completes, `select!` **drops the other two futures**,
including `orchestrator.run()` — mid-phase, mid-publish. The code then calls
`shutdown_token.cancel()` and `orchestrator_handle.shutdown()` at `:316-317` **into a future that no
longer exists**, and `tokio::time::sleep(Duration::from_millis(100))` at `:319` stands in for the
join that never happens. The watch/`wait_for` machinery is real and correct
(`OrchestratorHandle::shutdown` at `coordinator/mod.rs:78-80`, channel at `:266`, `wait_for` at
`:628`) — it is simply never reachable, because the listener is dropped before the signal is sent.
That is M10's "in-flight publish dropped on signal, **by construction**."

**Files to touch.** `crates/rvc/src/bootstrap/run.rs:293-326`; a new integration test under
`crates/rvc/tests/`.

**Implementation approach.**
1. `let orchestrator_task = executor.spawn("duty_orchestrator", ShutdownTier::Orchestrator, async move { orchestrator.run().await })`
   — now legal because of ARCH-2b.
2. `executor.register("grpc_healthz", ShutdownTier::Ingress, tokio::spawn(grpc_server))` for the
   tonic server currently polled inline at `:298`. **Keep** its `serve_with_shutdown` token arm
   (`:268-276`) and **drop its redundant `shutdown_signal()` arm** (`:272`) — once the executor owns
   signal handling, a second SIGINT arriving during drain would otherwise bypass tier ordering and
   kill Ingress out of turn.
3. Replace the three-arm `select!` with a two-arm wait on `shutdown_signal()` **or** the executor's
   `ShutdownReason` receiver — so a panicking task (ARCH-2g) and an operator signal enter the same
   path.
4. `executor.shutdown(TierBudget::default()).await` replaces `:316-319` and `background.shutdown()`
   at `:323`. Log the returned `ShutdownOutcome`.
5. **Delete `tokio::time::sleep(Duration::from_millis(100))` at `:319`.** Its removal is an exit
   criterion, not a cleanup.

**C8 — do not collaterally delete the healthz server.** `run.rs:263-276`'s `DutyTrackerServer` is
scheduled for removal in **Phase 7** (ARCH-P1-16b), after Phase 0's deprecation `warn!` has shipped
for at least one release. It is tempting to delete it here while restructuring the `select!`;
**doing so resets C8's deprecation clock and breaks the operator-visible contract.** This issue
*re-homes* it (inline arm → Ingress-tier registration) and changes nothing an operator can observe.

**TDD test plan.**
- **RED first — the M10 test:** `test_in_flight_publish_completes_on_shutdown_signal` in
  `crates/rvc/tests/`. A mock BN whose `publish_block` blocks on a barrier for ~1 s; drive a slot to
  the publish, fire the shutdown signal, release the barrier, and assert (a) the publish was
  **observed by the BN mock**, and (b) the process's shutdown future resolves afterwards. **Wrap the
  whole body in `tokio::time::timeout(Duration::from_secs(10), …)`** — the pre-fix behaviour on some
  interleavings is a hang, not a failure, and an untimed test would wedge CI instead of going RED.
  Today it fails: the publish future is dropped by `select!` and the mock never records it.
- `test_orchestrator_handle_shutdown_is_joined_within_budget` — assert `handle.shutdown()` → the loop
  observes the watch change → returns `Ok(())` → the **join** completes inside 5 s. Assert on
  `ShutdownOutcome.joined.contains("duty_orchestrator")`, not on elapsed time.
- `test_second_sigint_during_drain_does_not_bypass_tier_order` — fire the signal twice; assert the
  recorded drain order is still Ingress→Orchestrator→Background→Telemetry (this is the redundant-arm
  removal's regression pin).
- `test_healthz_grpc_still_serves_and_still_warns` — the deprecation `warn!` from Phase 0's 0F is
  still emitted and the endpoint still responds (C8).

**Acceptance criteria.**
- [x] **M10:** a publish in flight at signal time **completes**; the test asserts it with a timeout.
- [x] `handle.shutdown()` → `Ok(())` → join within the budget, asserted via `ShutdownOutcome`.
- [x] `rg 'tokio::time::sleep' crates/rvc/src/bootstrap/run.rs` returns nothing that stands in for a
      join.
- [x] The orchestrator is `tokio::spawn`ed (via `executor.spawn`) and its handle is held, not
      dropped.
- [x] The gRPC server keeps its token arm and loses its `shutdown_signal()` arm; the healthz endpoint
      and its deprecation `warn!` are **unchanged** in observable behaviour (C8).
- [x] A panicking registered task and an operator SIGTERM converge on the same shutdown path.
- [x] `cargo nextest run --workspace` green. *(verified: rvc bootstrap + in_flight + raw_spawn)*

**Done:** On top of ARCH-2g (`be03347`). Spawn/join orchestrator via `TaskExecutor`
(`duty_orchestrator` Orchestrator tier); `grpc_healthz` registered Ingress with token-only
shutdown (C8 deprecation warn preserved); wait on `shutdown_signal` OR `ShutdownReason` OR token
cancel; `executor.shutdown(TierBudget::default())` replaces 100 ms sleep. Binary passes
`shutdown_rx` into `run` so panicking tasks drain the process. M10 + join-budget tests in
`crates/rvc/tests/in_flight_publish_on_shutdown.rs`. Did **not** reintroduce raw `tokio::spawn`
for the nine 2g-migrated sites; G-4 `ALLOW_LIST` remains empty.

---

### ARCH-2i — Remove the in-async `process::exit`; preserve and assert EXIT_* 10/11/13/14

- **Points:** 1 · **Type:** bug · **Priority:** P0 · **Scope:** 0.5–1 day
- **Blocked by:** — (independent; can land any time in the phase) · **Blocks:** —
- **Stream:** A · **Requirement:** ARCH-P0-4 item 4 · **Constraints:** **NFR-3** (fail-closed startup
  preserved)

**Context.** `bootstrap/run.rs:81-84` calls `std::process::exit(e.exit_code())` from inside an
`async fn` on the keystore-lock-contention path. That kills the runtime with tasks mid-flight, no
drain, no destructor — the exact failure mode this phase exists to remove, and the one place where
it is *deliberate* ("Match prior binary: hard-exit on lock contention with the startup code"). The
behaviour must be preserved; only the mechanism changes.

**Files to touch.** `crates/rvc/src/bootstrap/run.rs:81-91`; the `BootstrapError` definition (an
`exit_code()`-carrying variant) under `crates/rvc/src/bootstrap/`; `bin/rvc/src/main.rs` (the
top-level `main` that maps the error to a process exit code — the **only** legitimate
`process::exit` site, because it is not `async`).

**Implementation approach.** Replace the in-async exit with `return Err(BootstrapError::…)` carrying
the exit code, and map it to `std::process::exit(code)` in the synchronous `main` after the runtime
has been dropped. Note this happens **before** any task is spawned (`:72` is step 1–2d, the
executor does not exist yet), so no drain is required or possible — say so in a code comment, because
the next reader will ask.

**TDD test plan.**
- **RED first:** `test_keystore_lock_contention_returns_exit_code_not_process_exit` — acquire the
  keystore lock in the test process, run the bootstrap path, and assert it **returns**
  `Err(e)` with `e.exit_code() == <EXIT_KEYSTORE_LOCKED>`. Today this test **cannot pass by
  construction**: `process::exit` terminates the test binary, so the RED is a killed test runner,
  which is itself the demonstration. Run it once before the fix and paste the output.
- `test_exit_codes_are_unchanged` — pin EXIT_* 10/11/13/14 to their current numeric values in a table
  test, so a future refactor cannot renumber them silently (NFR-3).

**Acceptance criteria.**
- [x] `rg 'process::exit' crates/rvc/src` returns no hit inside an `async fn`.
- [x] The only remaining `process::exit` in the binary path is in the synchronous `main`.
- [x] Exit codes 10/11/13/14 are preserved and asserted; the keystore-lock path still exits with the
      same code an operator's tooling sees today (NFR-3).
- [x] The fail-closed startup gates (SEC-9 fork gate, GVR chain-swap gate, keystore fd-lock) behave
      identically — no gate becomes a warning.
- [x] A comment at the new `return Err(...)` states why no drain is needed at that point.

---

### ARCH-2j — Keymanager API graceful shutdown (VD-2e: the cross-crate half nobody scoped)

- **Points:** 2 · **Type:** feature · **Priority:** P0 · **Scope:** 1–2 days
- **Blocked by:** — · **Blocks:** ARCH-2g row P1-6 (which registers the handle this issue makes
  joinable)
- **Stream:** **B** · **Requirement:** ARCH-P0-4 item 3 · **Constraints:** C5 (adjacent — read
  below), C9

**Context — VD-2e.** ARCH-P0-4 item 3 says "give the Keymanager API server a cancellation token and
a bounded join (`keymanager_adapters/spawn.rs:247-251`; axum `with_graceful_shutdown`)", and every
upstream scope list names only the `crates/rvc` half. **That is not satisfiable inside `crates/rvc`.**
`KeymanagerApiServer::run` is `pub async fn run(self) -> Result<(), std::io::Error>`
(`crates/keymanager-api/src/server.rs:158`) and calls bare `axum::serve(listener, router).await` at
`:162`; `rg 'with_graceful_shutdown' crates/keymanager-api/src` returns **nothing**. The token has to
enter the API crate. `keymanager-api` depends only on `eth-types`/`metrics`/`observability`, and
`tokio_util` is already a workspace dependency, so this adds **no new workspace crate edge** and has
no DAG-gate impact.

**Files to touch.** `crates/keymanager-api/src/server.rs:158-163`;
`crates/keymanager-api/Cargo.toml` (only if `tokio-util` is not already a dependency);
`crates/rvc/src/keymanager_adapters/spawn.rs:233-254` (pass the token, return the handle).

**Implementation approach.** Add
`pub async fn run_with_shutdown(self, token: CancellationToken) -> Result<(), std::io::Error>`
wrapping `axum::serve(listener, router).with_graceful_shutdown(async move { token.cancelled().await })`,
and define `run(self)` as `run_with_shutdown(self, CancellationToken::new())` so no existing caller
or test breaks. Change `spawn_keymanager_api` to take the token and **return the `JoinHandle`**
instead of discarding it (`spawn.rs:247`), so ARCH-2g can `register` it at Ingress tier.

**C5 boundary — do not cross it.** `crates/keymanager-api/src/lifecycle.rs:140` spawns the per-pubkey
KM-2 enable task, and its cancel token lives in the `cancel_tokens` map at `:125-128`. That machinery
implements the `stop_monitoring` (graceful removal, machine stays `Pending`) vs `cancel_monitoring`
(abort, `ForwardWindowMachine::cancel`) contract — and **G-6, the gate that protects it, does not
exist until Phase 7** (VD-6). This issue touches `server.rs` only. **Do not** register, join, retime
or otherwise alter `lifecycle.rs`'s spawn or its cancellation; an unguarded change to it is exactly
the failure C5 exists to prevent. State this in the PR description so a reviewer does not suggest it.

**TDD test plan.**
- **RED first:** `test_keymanager_server_stops_on_token_cancel` in `crates/keymanager-api/`'s test
  module — start the server on port 0, confirm a request succeeds, cancel the token, and assert
  `run_with_shutdown` **returns** within a `tokio::time::timeout(Duration::from_secs(2), …)`. Today
  there is no token and `axum::serve` never returns, so the RED is a timeout expiry — assert on the
  timeout's `Ok`, not on a sleep.
- `test_in_flight_request_completes_during_graceful_shutdown` — a handler that blocks ~500 ms;
  cancel mid-request; assert the client receives a full response (this is `with_graceful_shutdown`'s
  actual contract and the thing that distinguishes it from `abort`).
- `test_run_without_token_is_unchanged` — the pre-existing `run()` behaviour is preserved for any
  caller that does not pass a token.
- `test_spawn_keymanager_api_returns_a_joinable_handle` in `crates/rvc/src/keymanager_adapters/tests/spawn.rs`
  — the handle is returned rather than discarded.

**Acceptance criteria.**
- [x] `crates/keymanager-api/src/server.rs` uses `with_graceful_shutdown` driven by a
      `CancellationToken`; `run()` still exists and is unchanged for existing callers.
- [x] `spawn_keymanager_api` returns `JoinHandle<()>` (or `Option<JoinHandle<()>>` for the disabled
      case, feeding `register_opt`) instead of discarding it.
- [x] Cancelling the token stops the server within 2 s **and** lets an in-flight request finish.
- [x] `git diff --stat` shows **no** change to `crates/keymanager-api/src/lifecycle.rs` (C5).
- [x] `cargo metadata` shows no new workspace crate edge; `ARCHITECTURE.md` regenerates byte-identically.
- [x] All existing keymanager API tests pass unmodified.

---

### ARCH-2k — G-4 `raw_spawn.rs`: a path-aware scanner, a seeded allow-list, a synthetic RED (M8)

- **Points:** 2 · **Type:** chore · **Priority:** P0 · **Scope:** 1–2 days
- **Blocked by:** nothing to **build**; must **land** with or after ARCH-2g · **Blocks:** —
- **Stream:** **B** · **Requirement:** ARCH-P1-4's gate half, **M8** · **Constraints:** **C9**
  (anchors 1, 7), NFR-5, R10

**Context.** G-4 is a **path-scoped scanner in `architecture-tests`**, not clippy
`disallowed-methods`. The lint does match free functions, but it cannot be path-scoped; CI runs
`--all-targets`, so it would fire on all 83 test/test-support sites including
`crates/rvc-test-support/src/lib.rs:199` (production code in a test-support crate); feature-gated
code is outside the default workspace run (`clippy.toml:21-24`); and the obvious escape — a per-crate
`clippy.toml` — **replaces rather than merges** the workspace file, silently dropping the three
Gate-1 secret-key bans at `clippy.toml:25-29` (verified V17: exactly three entries). That hazard is
*created by the naive fix*, which is why it is written down.

**VD-2c — the specified algorithm does not work, and the failure is invisible until the migration is
done.** G-4's spec says to skip `#[cfg(test)]` regions "by comparing each hit's line number against
the file's `#[cfg(test)]` line." Five in-scope hits live in files with **no `#[cfg(test)]` attribute
at all** — `crates/rvc/src/orchestrator/coordinator/tests/core.rs:202` and `tests/spans.rs:124,193,409,479`
— because their gating is external (`#[cfg(test)] mod tests;` at `coordinator/mod.rs:704`;
`rg 'cfg\(test\)' crates/rvc/src/orchestrator/coordinator` returns that one line only). A file-local
comparison finds no marker and reports all five as production, so a **correctly migrated** tree goes
RED with 5 violations. The scanner needs a **path rule in addition to** the line rule.

**Files to touch.** `crates/architecture-tests/tests/raw_spawn.rs` *(new)*. Nothing else — the gate
is a new file per property (A-14); the harness is **extended, never replaced** (NG2, C9 anchor 1).

**Implementation approach — the four house properties from `kat_policy.rs` (V18), each mandatory.**
1. **No external dependency** — a hand-rolled walk (`kat_policy.rs:23`'s "Phase-1 rule P6").
2. **Shrinking-only const tables** whose doc comment says entries may be *removed, never added*
   (`kat_policy.rs:32-41`).
3. **Non-vacuity assertions** — `assert!(files_scanned > N, "scanned only {} files; workspace walk likely broke")`
   in the `:414`/`:444` idiom, so a scanner that silently stops matching **fails** rather than passes.
4. **Matcher unit tests on synthetic input** (`kat_policy.rs:482-563`) — this is how the gate
   demonstrates RED in the same PR without merging a knowingly-failing test.

Scope: `crates/rvc/src/**` + `bin/rvc/src/**`. Test-region exclusion is the **union** of (a) the
line-number rule against a file-local `#[cfg(test)]` and (b) a **path rule**: any file under a
`src/**/tests/` directory, or named `tests.rs`, is a test region in full. Allowed production sites:
`crates/rvc/src/bootstrap/executor.rs` only.

**The allow-list is EMPTY at HEAD (VD-2f) — do not seed it.** G-4's spec says to seed it with the
four Infra `register` sites, but all four live under `crates/bn-manager/` and
`crates/keymanager-api/`, **outside the declared scan path** (`crates/rvc/src/**` + `bin/rvc/src/**`).
A seeded row that can never match is dead weight in a table the house idiom declares shrinking-only,
and a later reader cannot distinguish it from a load-bearing exemption. Declare
`const ALLOW_LIST: [(&str, &str); 0] = [];` with the shrinking-only doc comment, and record the four
sites in the **file header comment** as *out of scan scope by path, not by exemption*, with these
reasons:

| Out-of-scope site (header comment, not allow-list) | Reason |
|---|---|
| `crates/bn-manager/src/manager.rs:313` (`start_sse`) | Infra crate; cannot depend on the composition-root executor without violating the DAG gate. **No production caller at HEAD**; becomes live in Phase 3 (ADR-013), which registers the returned handle |
| `crates/bn-manager/src/sse.rs:174` | Same, plus: nested inside `subscribe_events`, whose handle is **discarded**. Making it registrable requires an API change owned by Phase 3 |
| `crates/bn-manager/src/sync_status.rs:194` (`start_sync_monitor`) | Same; **no production caller at HEAD** |
| `crates/keymanager-api/src/lifecycle.rs:140` | Live, but **per-pubkey/per-import**: a `&'static str`-named registry entry per key is the wrong shape, and its cancellation is the C5 `stop_monitoring`/`cancel_monitoring` contract, unguarded until **G-6 lands in Phase 7** |

**`spawn_blocking` is explicitly NOT scanned and must never be added to the ban list** (C9 anchor 7).
`crates/signer/src/core.rs:542` *is* the cancellation-proof core and
`crates/signer-server/src/dvt/peer_service.rs:231,323` carry `!Send` guards; a ban that catches them
is a C9 regression wearing a hygiene costume. Add a unit test that **asserts the ban list does not
contain `spawn_blocking`**, so the prohibition is mechanical rather than a comment.

**TDD test plan.**
- **RED first (synthetic, in-PR):** `test_matcher_flags_a_raw_spawn_in_a_production_path` — feed the
  matcher a synthetic `("crates/rvc/src/bootstrap/tasks.rs", "    tokio::spawn(foo());")` and assert
  it is reported, with the **path named in the failure message** (NFR-5/R10: a gate that says only
  "violation found" gets disabled).
- **The VD-2c pin:** `test_matcher_excludes_src_tests_directory_without_a_cfg_test_line` — feed
  `("crates/rvc/src/orchestrator/coordinator/tests/spans.rs", "tokio::spawn(...)")` with **no**
  `#[cfg(test)]` anywhere in the synthetic content, and assert it is **not** reported. This is the
  test that would have caught the specified algorithm.
- `test_matcher_excludes_after_a_file_local_cfg_test_line` — the ordinary case
  (`config/builder.rs:1122` behind `:700`).
- `test_matcher_never_flags_spawn_blocking` and `test_ban_list_excludes_spawn_blocking` (C9 anchor 7).
- `test_allow_list_is_empty_at_head` (VD-2f) — pins the corrected fact and makes any future addition
  a deliberate, reviewed act rather than a quiet seed; the shrinking-only convention is carried by
  the const's doc comment.
- **Non-vacuity:** `test_scan_visited_a_plausible_number_of_files` in the `kat_policy.rs:414` idiom.
- **Local RED demonstration (not merged):** run the finished scanner against the **pre-ARCH-2g**
  tree, confirm it reports exactly the 9 sites of V8 by path, and paste that output into the PR. This
  is project-plan §1.1's compensating discipline for a gate that cannot precede its change:
  *demonstrated, not asserted*, and `develop` is never red.

**Acceptance criteria.**
- [x] `crates/architecture-tests/tests/raw_spawn.rs` exists, uses no new dependency, and runs under
      the Phase-0 `arch-gates` job.
- [x] **M8 = 0**: the gate is green on `develop` after ARCH-2g lands. *(ALLOW_LIST emptied with ARCH-2g)*
- [x] Every failure message names the offending `path:line` (NFR-5, R10).
- [x] **The allow-list is empty** (VD-2f), documented as shrinking-only, with the four out-of-path
      Infra sites and their reasons in the file header comment — not as exemption rows.
- [x] `spawn_blocking` is neither scanned nor bannable, and a test asserts it.
- [x] The VD-2c exclusion test passes and is commented with the reason
      (`coordinator/mod.rs:704`'s external `#[cfg(test)] mod tests;`).
- [x] A non-vacuity assertion fails the test if the workspace walk visits implausibly few files.
- [x] The pre-migration RED output (9 named sites) is in the PR body; no knowingly-failing test was
      merged.
- [x] CI runtime does not regress materially (NFR-5) — scanner-style only, no compile-heavy approach.

---

## 7. Constraint coverage (C1–C10)

Every constraint is either carried forward by a named issue or rejected with a stated reason.
Silence on any row would be a defect, so the not-applicable rows say *why* rather than being omitted.

| # | Constraint | Status in Phase 2 | Where |
|---|---|---|---|
| **C1** | Retain-on-ambiguity vs lock-shortening; the naive stage→release→sign→re-check cannot retain a released row | **N/A — and deliberately so.** No issue here opens `crates/slashing/` or `crates/signer/`. ADR-002 has **no** dependency on ADR-005: the `!Send` staging guard is confined to a `spawn_blocking` thread (`crates/signer/src/core.rs:36-41`), its sign is `Handle::block_on` not `.await` (`:284-287`), and `core.rs:930` wraps `sign_slashable` in a bare `tokio::spawn` inside a **green unit test**. A planner who reads C1 next to `stage.rs:57-63` and serialises this phase behind Phase 5 loses ~4 weeks for no safety benefit. ARCH-2b's acceptance criteria include an empty `git diff --stat` over both crates, so the independence is *enforced*, not merely asserted | ARCH-2b (acceptance) |
| **C2** | Audit-log emission inside the slashing mutex (`crates/slashing/src/scoped.rs:70-75`, `:102-107`) can deadlock via a DB-touching subscriber | **N/A — owned by Phase 1 (ADR-006 / G-7, work package 1A), which is a prerequisite of Phase 5, not of this phase.** Named here only because ARCH-2f adds metrics and ARCH-2e adds `warn!` emissions: **neither is emitted while any lock is held**, and neither touches `crates/slashing/`. The executor's monitor uses `try_send` on a bounded channel precisely so no emission path can block | ARCH-2d (`try_send`), ARCH-2e |
| **C3** | figment's `Env` provider is forbidden; env = security opt-outs only | **N/A — no config work in this phase.** One adjacency worth naming: `RVC_METRICS_ALLOW_NON_LOOPBACK` (`bootstrap/tasks.rs:19`) sits in the file ARCH-2g edits. It is a **security opt-out**, exactly the sanctioned class, and ARCH-2g must not move, rename or widen it — the migration changes how the metrics task is spawned, never how its bind is gated | ARCH-2g (do-not-touch note) |
| **C4** | Keystore-less key admission through `KeyChangeNotifier` | **N/A — Phase 1 (ADR-007).** Adjacency: ARCH-2g migrates the secret-provider refresh spawn at `bootstrap/enablement.rs:170`, which Phase 1 also rebuilds. ARCH-2g changes only the **spawn wrapper**, never the `RefreshService::run<F>` callback body (`crates/secret-provider/src/refresh.rs:179-181`, a synchronous `F: Fn(SecretKey)`), so the two phases' diffs on that file do not overlap semantically | ARCH-2g |
| **C5** | KM-2 `stop_monitoring` (graceful, machine stays `Pending`) vs `cancel_monitoring` (abort) must survive | **Live here, and the reason for a stated default.** VD-2d found that `keymanager-api/src/lifecycle.rs:140` is the **only** live "Infra register site", and its cancellation is the C5 machinery (`cancel_tokens` map at `:125-128`). **G-6, the gate that protects the contract, does not exist until Phase 7** (VD-6). Default (**A-2.4**): do **not** register it, do **not** alter its cancellation; record it in G-4's header comment as out of scan scope with the reason (VD-2f — it is outside the scan path, so it needs no exemption row). ARCH-2j asserts an empty diff on `lifecycle.rs` | ARCH-2k (header comment), ARCH-2j (acceptance) |
| **C6** | Cold-cache pre-proposal fetch must be a bounded short-deadline fetch, never a silent skip | **N/A — Phase 3 (ADR-004).** No issue here changes slot ordering, duty fetching or the pre-proposal path. One forward obligation is created: ARCH-2h's spawned orchestrator is what makes Phase 3's cold-cache tests drivable without a `LocalSet`, so ARCH-2c is a *precondition* on C6's testability rather than a participant in it | — (ARCH-2c enables) |
| **C7** | SSE drops are normal: bounded `mpsc(64)`, drop-on-overflow (H-11), timer stays authoritative | **Carried forward as a prohibition.** `crates/bn-manager/src/sse.rs:171-178` is the H-11 bounded dispatch channel; VD-2d/VD-2f put its spawn **outside G-4's scan path**, documented in the scanner header rather than exempted. ARCH-2k must **not** treat that site as a defect to migrate, and no issue here adds an `error!` or a failure metric on the SSE path. `crates/bn-manager/` leaves this phase's diff entirely | ARCH-2k (header row 2) |
| **C8** | Healthz removal is operator-visible; needs a deprecation release first | **Live, as a do-not-delete.** ARCH-2h restructures the `select!` that contains the healthz `DutyTrackerServer` arm (`run.rs:263-276`, `:298`). Deleting it while "cleaning up" would **reset the deprecation clock started by Phase 0's 0F** and break k8s probes without notice. ARCH-2h re-homes it (inline arm → Ingress-tier registration) with zero observable change, and carries a test that the deprecation `warn!` still fires. Removal stays in Phase 7 (ARCH-P1-16b) | ARCH-2h |
| **C9** | Keep-list: architecture-tests harness · cancellation-proof core · KAT-first · env rule · single signing gate · zero unbounded channels · `spawn_blocking` excluded | **Live on four anchors.** *Anchor 1:* ARCH-2k **extends** the harness with a new file, never replaces it (NG2, A-14). *Anchor 2:* untouched — see C1. *Anchor 3 (KAT):* no `*_root`/`*tree_hash*`/`*signing_root*` test is added or renamed by any issue; `EXEMPTIONS` must not change (§1). *Anchor 6:* the executor's only new channel is `mpsc::channel(8)` with `try_send`; ARCH-2g and ARCH-2k assert `unbounded_channel` is unchanged workspace-wide. *Anchor 7:* `spawn_blocking` is never scanned and a unit test asserts it cannot enter the ban list. *Anchor 5 (single signing gate):* not reachable from this phase — no issue opens `config/builder.rs:394` or `CompositeSigner` | ARCH-2d, ARCH-2g, ARCH-2k |
| **C10** | Archive-before-delete for the untracked trees; `rm` is unrecoverable because **no git object exists** behind them | **Live as a hard prohibition, with a specific trap.** `crates/rvc/src/main.rs:1608` carries a fifth `#[allow(clippy::arc_with_non_send_sync)]` that looks exactly like ARCH-2b's four targets. **It must not be edited**: that tree was never tracked in git (no commit, no blob, no reflog entry), so any edit is unrecoverable and would corrupt Phase 0's archive-then-delete input. Likewise the **25** raw `tokio::spawn` sites in the orphan trees never enter ARCH-2g's list or G-4's scope. Phase 0 completing is this phase's hard entry criterion precisely so both traps have already evaporated | ARCH-2b (explicit exclusion row), ARCH-2g, entry criteria |

---

## 8. Assumptions (no-ask resolutions)

Per the no-ask constraint, **every open question is resolved to a stated default here. Nothing is
escalated.** The PRD's A-1…A-15, the architecture's A-A1…A-A11 and the project plan's A-P1…A-P12
remain in force and are **not repeated**; below are the ones this issue breakdown creates, prefixed
`A-2`.

| # | Open question | Stated default | Overturned by |
|---|---|---|---|
| **A-2.1** | ADR-002 says "six `?Send` sites" in one sentence and "six impls **plus** the trait declaration" in another (VD-2a). Which count binds? | **Seven.** The edit list is enumerated by `file:line` in ARCH-2b so the ambiguity cannot survive into execution: 1 trait declaration + 6 impls, in 5 files across 2 crates. A "six-site" PR is incomplete by construction and will not compile | A site turning out to be dead code that Phase 0 or Phase 3 deletes first — in which case the count drops and the enumeration, not the number, is authoritative |
| **A-2.2** | The upstream allow-removal list has three entries but architecture §7.2 demands *no* allow remains under `crates/rvc/src/` (VD-2b) | **Four**, adding `orchestrator/sync_committee.rs:328`. The three-item list cannot satisfy its own proof obligation. `crates/rvc/src/main.rs:1608` is excluded by C10, not by oversight | Clippy proving one of the four is still load-bearing after the supertrait lands — in which case the diagnostic names the `Arc::new` and its type, and that goes in the PR body |
| **A-2.3** | G-4's specified `#[cfg(test)]`-line comparison misclassifies five files (VD-2c). Fix the gate, or annotate the five files? | **Fix the gate** with a path rule, pinned by a matcher unit test. Annotating source files to satisfy a scanner inverts the relationship — the gate exists to describe the codebase, not the reverse — and `#[cfg(test)] mod tests;` in a parent module is idiomatic Rust that the repo uses elsewhere | A decision to flatten `coordinator/tests/` back into `mod.rs`, which is out of scope here (Phase 3 owns that file) |
| **A-2.4** | VD-2d: three of the four Infra `register` sites have no production caller and the fourth is per-pubkey and C5-owned. Drop `register`? Migrate anyway? | **Build `register` as specified; migrate none of the four `P2-*` rows in this phase.** `register` is exercised by four **in-crate** callers via ARCH-2g (P1-2, P1-6, P1-7, P1-9), so it is neither dead nor speculative; what it lacks is a live *Infra-crate* caller. All four Infra sites are documented in G-4's file header as out of scan scope by path (VD-2f), not as allow-list rows. ADR-001's DAG argument for `register`'s shape stands independently of today's callers, it costs zero crate edges, and Phase 3 (ADR-013) makes rows 1–2 live. Consequence: `crates/bn-manager/` is **not** in this phase's diff | Phase 3 landing ADR-013 before this phase, which would make rows 1–2 live and move their registration here |
| **A-2.10** | VD-2f: G-4's spec seeds an allow-list with four sites that its own path scope excludes. Widen the path, or empty the list? | **Empty the list; keep the path scope.** Widening to `crates/**` would drag the 83 test/test-support sites and the `signer-server` sites (A-13, out of scope) into the gate and re-create the reason clippy was rejected. The four Infra sites are recorded in the scanner header with reasons, and `test_allow_list_is_empty_at_head` makes any future addition a reviewed act | Phase 3 needing G-4 to cover `bn-manager` once ADR-013 wires SSE — which is an explicit amendment to the gate's path scope, taken in Phase 3, not here |
| **A-2.5** | VD-2e: ARCH-P0-4 item 3 needs a `crates/keymanager-api` edit that no scope list names. In scope? | **Yes — ARCH-2j, its own issue, its own 2 points, its own stream.** The requirement is not satisfiable otherwise, and the crate takes `tokio_util` without a new workspace edge. Hiding it inside ARCH-2g would make a cross-crate change invisible in the phase summary | A maintainer preferring the Keymanager API be aborted rather than gracefully drained — which would satisfy "bounded join" but not "in-flight request completes", and would contradict ARCH-P0-4's own wording |
| **A-2.6** | RA-5: does the metrics server become cooperative, raising the total budget 5 s → 6.5 s? | **Convert it** (it is the only live task that never sees a token, V10) and **state the new total in the ARCH-2e PR body as a PRD amendment**, never as a silent absorption. If the conversion turns out to need a `serve_metrics_with_health` signature change beyond ARCH-2g's budget, Telemetry stays abort-drain at 0.5 s and the PR records that the budget is *tighter* than today's 2 s `METRICS_SHUTDOWN_TIMEOUT` | An in-flight metrics scrape measured to routinely exceed 0.5 s, which forces the conversion |
| **A-2.7** | This decomposition totals 21 pts ≈ 11–19 d against the project plan's 8–13 d envelope | **Report the honest number and its three causes** (VD-2c, VD-2e, VD-2a add; VD-2d subtracts) rather than trimming issues to fit. Every issue is ≤ 3 points and independently revertible, so the phase can be cut at a boundary if the calendar binds: **ARCH-2i and ARCH-2j are the deferrable pair** — both are self-contained, neither blocks ARCH-2h, and deferring them costs 3 points and two ARCH-P0-4 sub-items, which would have to be recorded as an open requirement rather than quietly dropped | Execution showing the mechanical issues (2b, 2c, 2f, 2i) land at the 0.5 d/pt end, which pulls the range to ≈ 11–14 d |
| **A-2.8** | Does Phase 2 need the Phase-0 M1/M2 baselines? | **No.** Phase 0 is this phase's dependency for the **orphan deletion and the `arch-gates` job**, not for measurement: the M1/M2 instruments gate Phase 3 (ADR-004), and nothing here is on the per-slot deadline path. NFR-1 is discharged by argument (the executor is touched at register and at exit only), stated in ARCH-2f, rather than by a benchmark run | A shutdown-path change measurably affecting steady-state slot latency, which would be a defect in its own right |
| **A-2.9** | Where does the ADR-002 probe verdict live? | **`plan/architecture-2026-08-12/probe-adr002-verdict.md`**, quoted in the ARCH-2b PR body. A verdict recorded only in a PR comment is unfindable by the Phase-3 developer who needs it if the probe failed (RP6) | A maintainer preferring the PR body alone, which is acceptable only if the PR is linked from this phase file |

