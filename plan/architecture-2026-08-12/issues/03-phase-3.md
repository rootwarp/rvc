# Phase 3 Issues — Slot Ordering: split the context, then propose first

> **Authoritative inputs, in precedence order:**
> [`../project-plan.md`](../project-plan.md) §7 *Phase 3* (scope, work packages 3A–3D, entry/exit
> gates) → [`../architecture.md`](../architecture.md) (ADR-003, ADR-004, ADR-013; gate **G-8**;
> §5 interfaces; §7.1 anchors 3 and 6) → [`../prd.md`](../prd.md) (ARCH-P0-8, ARCH-P0-3, ARCH-P1-12,
> ARCH-P1-13; A-4, A-5, A-10, A-11) → [`../research/`](../research/) →
> [`../../../docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md).
> Where the architecture and the PRD conflict the architecture wins; where the project plan sets a
> binding internal order (3A **before** 3B) that order is reproduced here as issue dependencies.
>
> **Baseline:** `develop` @ `0ae9a09` (v0.7.0), authored 2026-08-12. **Every `file:line` in this
> document was re-opened against HEAD while writing it** — not copied from the upstream documents.
> Six claims did not reproduce as written; they are recorded in §3 as `VD-3x` and the corrected fact
> is what the issues are built on. Two of them change scope (**VD-31**, **VD-32**), one changes an
> acceptance criterion (**VD-35**), one changes a path (**VD-34**).
>
> **What this file adds over its inputs:** the four work packages become fourteen 1–3-point issues
> with a stated RED test each; the `SlotContext` split is decomposed into a field split, a walk-back
> and a gate so the binding 3A→3B order becomes a dependency graph rather than a sentence; and three
> compile-level traps that the prose instruction "move the duty fetches into the wait window" does
> not survive are named with their signatures (`wait_for(&mut self)`, the sync `Fn(SseEvent)`
> callback, the `Arc<dyn BeaconNodeClient>` trait object).
>
> **No-ask constraint:** every open question is resolved to a stated default in §2 *Assumptions*.
> Nothing is escalated; `AskUserQuestion` was never called.
>
> **Scope:** planning only. This file changes no source file and deletes nothing. **C10 (archive
> before delete) belongs to Phase 0 and no issue here deletes a tree.** `docs/prd.md`,
> `docs/architecture.md` and `docs/project-plan.md` belong to the older Test Audit Remediation
> initiative and are untouched (NG8).

---

## 1. Phase Overview

**Goal.** Reach the t=0 proposal decision first and within a bounded budget, and stop discarding both
sync-committee reward components every slot — by **splitting the field, not repairing the query**
(ADR-003), then reordering the slot loop (ADR-004), then adding head-event triggering as a strictly
optional latency win (ADR-013).

| | |
|---|---|
| **Requirements** | ARCH-P0-8, ARCH-P0-3, ARCH-P1-12, ARCH-P1-13 |
| **ADRs / gates** | ADR-003, ADR-004, ADR-013; gate **G-8** (`mock_fidelity.rs`) |
| **Issues / points** | **14 issues · 30 points** (no issue > 3 pts) |
| **Duration, 1 dev** | **15–23 working days** (30 pts) — derivation below |
| **Duration, 2 devs** | **15–21 working days** = Stream A's 21 pts at the same rate; the gain is the 9 points Stream B absorbs (~4–6 d) |
| **Depends on** | Phase 0 (M1/M2 baselines — an *entry* criterion), Phase 2 (testability only) |

**Estimate derivation, reconstructible rather than asserted.** The project plan sizes this phase at
**11–17 d**. Two verified findings add work the plan could not have priced:

| Addition | Evidence | Cost |
|---|---|---|
| **ADR-013 is a new registered Background task plus a bridge, not a trigger arm** — `BnManager::start_sse` has **zero call sites** in the workspace, so no SSE subscriber runs in production today | `crates/bn-manager/src/manager.rs:303`; `rg 'start_sse'` returns only the definition and unrelated test-server helpers (VD-31) | **+3–4 d** (ARCH-3l, 3 pts, plus the bridge half of 3m) |
| **The wait window cannot host the duty fetches without an enabling refactor** — `wait_for(&mut self)` takes `&mut self`, so `select!`-ing it against `self.duty_management.fetch_epoch_duties(..)` cannot borrow-check | `coordinator/mod.rs:628`, field at `:224` (owned, not `Arc`), and the existing work-around comment at `:550` (VD-32) | **+1–2 d** (ARCH-3h, 2 pts) |

11–17 d **+ 4–6 d = 15–23 d single-dev**, which is also what 30 points yields at the house rate of
~0.5–1 d/point (15–30 d) with the mass concentrated in 2-pointers. Both derivations are shown so
neither has to be taken on trust. **The two-developer figure uses one derivation only** — Stream A's
21 points at the same 0.5–1 d/point rate = **15–21 d** — so it is not obtained by subtracting a gain
from the single-dev range.

**Parallelism is poor here, and saying so is the honest answer.** The project plan's internal order
(3A **before** 3B) is binding, and Stream A carries 21 of 30 points on one chain: 15–23 d → 15–21 d,
a gain of ~4–6 d at the fast end and ~2 d at the slow end — not ~1.6×. If the second developer is available, the higher-value assignment is
**Phase 4 or Phase 5 in parallel with the whole of Phase 3** (project plan §9); Stream B below exists
so that a second developer *inside* this phase has 9 points of genuinely disjoint work rather than
idle time.

### Entry criteria

- [ ] **Phase 0 complete, and M1/M2 baselines exist as files in `plan/architecture-2026-08-12/`.**
      Hard, not cosmetic: ARCH-3k asserts against them, and without them ADR-004's targets are
      unfalsifiable (project plan D10; PRD *Success Metrics* — M1 and M2 have **no** instrument at
      HEAD, and the two `benches/` files are logging-latency benches, VD-P2).
- [ ] **Phase 2 complete — for testability, not for compilation.** ARCH-3k drives a spawned
      orchestrator; the alternative is the `LocalSet`/`spawn_local` scaffold at
      `crates/rvc/tests/sync_independent_of_attesting.rs:269-273` that ADR-002 deletes. Re-introducing
      it here would undo 2C, so it is forbidden rather than merely discouraged.
- [ ] Phase 2's `TaskExecutor` exposes `register` (architecture §5.1) — **ARCH-3l registers the SSE
      subscriber through it**; without `register` the new task would be a fresh G-4 violation on the
      day G-4 goes green.
- [ ] Green on all project-plan §2 commands at the phase's base commit, including
      `cargo nextest run --workspace` (**not** `cargo test --workspace`, which deadlocks in this repo).

### Exit criteria

The eleven-box checklist is §8. It is a literal superset of the project plan's Phase 3 milestone and
of the PRD acceptance criteria for all four requirements; nothing is paraphrased away.


## 2. Assumptions, Verified Against HEAD

Every open question is resolved to a stated default (no-ask constraint). Each row names the
`file:line` **re-opened while writing this file**, not the upstream citation.

| ID | Assumption / default | Verified at HEAD | Falsifier |
|---|---|---|---|
| **A-3.1** | `SlotContext::capture` queries the **current** slot's root at t=0, and every non-200 collapses to `head_root = None` | `orchestrator/slot_context.rs:41` (`let block_id = slot.to_string();`), `:42-58` (both the parse-error and the transport-error arms yield `None`). Struct has exactly three fields — `slot`, `epoch`, `head_root` (`:19-29`) | ARCH-3a's wiremock pin returning a usable 200 root |
| **A-3.2** | A spec-conformant BN 404s that query (A-10, "assume yes") | Not verifiable from this repo — **that is precisely what ARCH-3a exists to pin**, and it is the phase's first task (A-A1). Default: assume 404; cost of being wrong is one test, not a wrong fix | ARCH-3a |
| **A-3.3** | `ctx.head_root` has a **third** consumer that feeds `expected_parent_root`, so "make `capture` succeed" arms a dropped proposal | `block_proposal/mod.rs:104` passes `ctx.head_root` as the 4th argument of `propose_block`, whose parameter is `expected_parent_root: Option<Root>` (`block-service/src/service/mod.rs:89-95`), constructed into `BlockResponseValidator` at `:97-101` and compared at `validation.rs:63-67` → `ParentRootMismatch` | — (re-verified; VD-Q1-6 stands) |
| **A-3.4** | H-4's parent-root check is **shipped and inert** today | `validation.rs:64` — `if let Some(expected) = self.expected_parent_root`; the only production caller passes `ctx.head_root`, which is `None` on every slot where the BN 404s | ARCH-3a |
| **A-3.5** | Both sync-committee reward components are lost, not just messages | messages skip at `orchestrator/sync_committee.rs:65-74`, contributions skip **independently** at `:148-157`; both `return` on `None` after a `warn!` | — (VD-Q1-1 confirmed) |
| **A-3.6** | The H-5 cross-phase property is pinned by an existing test that must stay green | `test_messages_and_contributions_share_head_root`, `sync_committee.rs:558` | — |
| **A-3.7** | **That test is on the KAT `EXEMPTIONS` list**, so it may not be renamed | `crates/architecture-tests/tests/kat_policy.rs:125-128` — `("crates/rvc/src/orchestrator/sync_committee.rs", "test_messages_and_contributions_share_head_root")`. `EXEMPTIONS` is **shrinking-only** (`:16`), so a rename (= remove + add) is forbidden. **Default: keep the name byte-identical** | — |
| **A-3.8** | The KAT scanner matches on a **suffix**, so new tests avoid it by not *ending* in `_root` | `kat_policy.rs:232-234`: `name.ends_with("tree_hash") \|\| name.ends_with("signing_root") \|\| name.ends_with("_root")`. So `test_capture_parent_root_walks_back_over_skips` is out of scope; `test_capture_uses_parent_root` is in scope. **Default: name every new test so it does not end in those suffixes**, and add nothing to `EXEMPTIONS` (C9 anchor 3) | — |
| **A-3.9** | Both `fetch_epoch_duties` calls run on **every** slot; only the epoch-boundary prep is guarded | `coordinator/mod.rs:376-383` unconditional; the `// === Epoch boundary:` comment sits at `:375` *above* them; `if current_slot % SLOTS_PER_EPOCH == 0` begins at `:386` (VD-1 confirmed) | — |
| **A-3.10** | All three duty fetches are cache-guarded, so 6 × 10 s is a **tail** risk, not a per-slot constant | `duty_management.rs:66`, `:86`, `:106` (`if !…is_cached`); `duty_fetch` default is **10 s** (`bn-manager/src/traits.rs:216`, pinned at `:514`) | — |
| **A-3.11** | Cold cache = first slot after boot **and every slot after a `key_gen` bump** | `coordinator/mod.rs:373` → `apply_key_gen_cache_invalidation` at `:606-612`, which calls `duty_tracker.clear_cache()` — i.e. it clears *all* duty caches, so the very next `maybe_propose_block` has no cached proposer duty (C6 is real, not hypothetical) | — |
| **A-3.12** | The wait-window pattern to extend already exists | `coordinator/mod.rs:541-594`: builder registration raced against `wait_for(time_until_next_slot)` in a `tokio::select!` at `:582-589`, with the plain-wait `else if` branch at `:590-594` | — |
| **A-3.13** | wiremock is already available to `crates/rvc` — ARCH-3a costs no dependency work | `crates/rvc/Cargo.toml:75` `wiremock.workspace = true` under `[dev-dependencies]` | — |
| **A-3.14** | ADR-013's channel is the **only** new concurrency primitive, and it is bounded by construction | Default: `tokio::sync::watch<Option<HeadEvent>>` (latest-wins, no growth, drop-is-normal — the exact C7 semantics). See **VD-33**: the ADR's "adds no channel" claim is not achievable | — |
| **A-3.15** | ARCH-P1-13 takes the project plan's **first** branch (1–2 d): the residual reproduces and `broadcast_inner` is reusable | Residual documented at `crates/rvc/src/liveness_loop.rs:17-24`; `post_validator_liveness` routes through `query_first` (`bn-manager/src/manager.rs:1289`); fan-out primitive `broadcast_inner` at `:757`. **No new primitive is required**, so the phase estimate is not revised on this item | ARCH-3n's first task |
| **A-3.16** | Pre-proposal budget: **1,000 ms p99 warm / 2,000 ms cold**, cold-cache fetch deadline **500 ms** (A-5) | Carried unchanged from the PRD; Phase 0's baseline may tighten them | Phase-0 baseline |
| **A-3.17** | Walk-back depth is **four** attempts (`slot-1 … slot-4`) then `"head"` as a warn-logged, counted terminal (A-4) | Carried from ADR-003; four slots ≈ 48 s of mainnet skips, beyond which a `"head"` parent is the honest answer | Observed terminal-counter rate in ARCH-3d |
| **A-3.18** | This phase deletes nothing and archives nothing | **C10 is Phase 0's obligation** (ARCH-P0-1); no issue here removes a file. The orphan-tree invariant has already expired by the time Phase 3 starts (Phase 0's delete commit) | — |


## 3. Verification Deltas Found While Writing This File

Six claims in the authoritative inputs did not reproduce as written. Where an input is wrong it is
said so plainly and the corrected fact is what the issues below are built on.

| ID | Claim as written upstream | Status at HEAD | Corrected fact carried forward | Lands in |
|---|---|---|---|---|
| **VD-31** | Architecture §5.1 P2-2 and ADR-013 treat the SSE subscriber as a **live** task ("registered bn-manager SSE", "rvc's SSE stream is a bounded `mpsc(64)` … falls back to polling on failover"), making ARCH-P1-12 an additive trigger arm | **Scope-changing — no SSE subscriber runs in production at HEAD** | `BnManager::start_sse` (`crates/bn-manager/src/manager.rs:303-316`) has **zero call sites in the workspace**: `rg 'start_sse'` returns the definition plus test-server helpers named `start_sse_server` in `sse.rs` and `tests/sse_oversize_h11.rs` only. `subscribe_events` (`sse.rs:154`) is likewise reached only from tests. Two consequences: (i) ARCH-P1-12 must **start** the subscriber as a new production task — registered on Phase 2's executor at tier `Background`, not raw-spawned — before it can add a trigger; (ii) **two** of Phase 2's Infra `register` rows are vacuous until this phase wires them, not one: architecture §5.1 and `:142` / `:1038-1039` name both `bn-manager/src/manager.rs:313` (the outer spawn inside `start_sse`, the function with no callers) **and** `sse.rs:174` (the inner callback-dispatch task, reached only *through* it). Neither runs today, so Phase 2 should record both as "register-on-wiring" rather than migrations of live sites | ARCH-3l (and a note back to Phase 2) |
| **VD-32** | Project plan 3B / PRD ARCH-P0-3: "move both `fetch_epoch_duties` calls and the epoch-boundary prep **into the phase-3 → next-slot wait window**" | **Does not compile as stated** | `wait_for` is `async fn wait_for(&mut self, duration: Duration)` (`coordinator/mod.rs:628`) — it needs `&mut self` for `self.shutdown_rx.changed()` at `:632`. `duty_management` is an **owned** field, not an `Arc` (`:224`, `pub(crate) duty_management: DutyManagementService`), so `select!`-ing `self.wait_for(..)` against `self.duty_management.fetch_epoch_duties(..)` is a simultaneous `&mut self` + `&self` borrow. The existing builder-registration window works only because it **clones the service out of `self` first** — the comment at `:550` says exactly that. **Resolution: a `&self` wait variant driven by a cloned `watch::Receiver`** (`watch::Receiver` is `Clone`; `check_shutdown` is already `&self` at `:614`), delivered as its own issue | ARCH-3h |
| **VD-33** | Architecture §7.1 anchor 6: "**ADR-013 adds no channel** — it consumes the existing bounded `mpsc(64)` SSE stream" | **Not achievable as stated** | The `mpsc(64)` is *internal* to `subscribe_events` (`sse.rs:171-182`): its consumer task invokes the caller's callback, whose type is `F: Fn(SseEvent) + Send + Sync + 'static` (`sse.rs:159`) — a **synchronous** closure that cannot `.await`. Getting an event to the orchestrator's `select!` therefore requires a bridge, and it must be non-blocking on the SSE side. **Default (A-3.14): `tokio::sync::watch<Option<HeadEvent>>`** — bounded by construction (one slot, latest-wins), no `unbounded_channel`, `send` is non-blocking, and losing an intermediate value *is* the C7 semantics rather than a violation of them. C9 anchor 6 is honoured in substance; the ADR's literal wording is not, and the PR must say so | ARCH-3l, ARCH-3m |
| **VD-34** | PRD ARCH-P1-13 and project plan 3D cite `crates/doppelganger/.../liveness_loop.rs:19-24` | **Wrong crate** | The file is `crates/rvc/src/liveness_loop.rs`; the documented multi-BN residual is its module doc at `:17-24` ("Liveness uses bn-manager `query_first` … there is **no cross-BN OR-merge of `is_live`**"). `crates/doppelganger/src/` contains no `liveness_loop.rs`. This matters for stream ownership: the file is in `crates/rvc`, so it must be named explicitly in the file-ownership map or Stream B silently collides with Stream A's crate | ARCH-3n, §5 |
| **VD-35** | PRD/architecture: "with duty fetches stubbed to hang for the full **6 × 10 s**, the proposal still happens" | **Understated by up to 2 fetches** | `fetch_epoch_duties` ends with `maybe_prefetch_next_sync_period` (`duty_management.rs:132`, body `:149-190`), which issues a **fourth** BN fetch (`sync_duty_prefetch`, `:177-180`) under the same 10 s `duty_fetch` timeout whenever the epoch is within `PREFETCH_LOOKAHEAD` of a period boundary, and — because the period is marked done only on success (`:158-170`) — **retries every slot while it keeps failing**. With both `fetch_epoch_duties` calls that is up to **8 × 10 s = 80 s**, not 60 s, in the lookahead window. **The milestone stays worded as the plan states it (60 s — it is the authoritative exit criterion); ARCH-3k additionally parameterises its stall test to 80 s** so the larger envelope is covered rather than discovered in production | ARCH-3k |
| **VD-37** | Implicit in this file's own first draft, and in any reading of ADR-003 that treats the H-5 pin as untouchable: *"if the split makes `test_messages_and_contributions_share_head_root` fail, the split is wrong"* | **Too strong — the test needs one mandatory, legitimate edit** | The test at `sync_committee.rs:557-602` builds the context as a **struct literal**: `let ctx = SlotContext { slot: 0, epoch: 0, head_root: Some(r_captured) };` (`:582`). Adding a fourth field therefore **breaks compilation**, and adding `parent_root: None` is a required edit — not a regression and not a rename. Its call-count assertion, however, **survives untouched**: it asserts `get_block_root_call_count == 0` (`:589-594`) while invoking `maybe_produce_sync_messages` / `maybe_produce_sync_contributions` **directly** (`:585-586`), not through the coordinator loop — so neither the t=0 parent capture nor the phase-2 head capture runs inside it, and the counter stays 0 after 3c/3d. **Three separable obligations, and conflating them is what pushes a developer toward reverting the split or exempting the test:** (i) the H-5 *property* (phases 2 and 3 read one captured head root) is inviolable; (ii) the struct-literal update is mandatory; (iii) the **name** stays byte-identical (A-3.7) | ARCH-3c, ARCH-3f |
| **VD-36** | Architecture G-8: "**all seven** `with_get_block_root` stubs … return `Ok(...)` for any `block_id`" | **Six of seven; the seventh is an error stub** | Confirmed seven call sites (`slot_context.rs:70`, `:77`, `sync_committee.rs:388`, `aggregation.rs:609`, `coordinator/tests/mod.rs:253`, `tests/common/pipeline_fixture.rs:243`, `tests/sync_independent_of_attesting.rs:87`), but `slot_context.rs:77-79` returns `Err(BeaconError::HttpError(..))` unconditionally — it is not an `Ok`-for-anything stub, and G-8's predicate must not flag it. It is *also* not spec-honest (a 404 is not a transport error), so it is corrected by ARCH-3f for a different reason. **G-8's scanner therefore has two clauses, not one**: no unconditional `Ok`, and no error-for-everything stub standing in for a 404. The handler signature is `impl Fn(String) -> Result<BlockRootResponse, BeaconError>` (`bn-manager/src/mock.rs:150-156`) — it receives the `block_id` **by value**, which is what makes a slot-aware stub cheap to write | ARCH-3b, ARCH-3f, ARCH-3g |


## 4. Phase Summary

**14 issues · 30 points · no issue above 3 points.**

| Issue | Title | Pts | Type | Blocked by | Stream | Scope | Requirement |
|---|---|---|---|---|---|---|---|
| **ARCH-3a** | Pin BN `get_block_root(<current slot>)` behaviour (probe) | 1 | spike | — | **A** | 0.5–1 d | ARCH-P0-8 |
| **ARCH-3b** | Spec-honest `with_get_block_root` mock primitive | 2 | chore | — | **B** | 1–1.5 d | ARCH-P0-8 (G-8) |
| **ARCH-3c** | Split `SlotContext` → `parent_root` + `head_root` | 3 | feature | 3a | **A** | 2 d | ARCH-P0-8 |
| **ARCH-3d** | Walk back over skipped slots + counted terminal | 2 | feature | 3c | **A** | 1–1.5 d | ARCH-P0-8 (A-4) |
| **ARCH-3e** | Activate H-4 + sync-skip counter + doc corrections | 2 | feature | 3c, 3d | **A** | 1–1.5 d | ARCH-P0-8 |
| **ARCH-3f** | Correct all seven `with_get_block_root` stubs | 2 | chore | 3b, 3c | **A** | 1–1.5 d | ARCH-P0-8 (G-8) |
| **ARCH-3g** | G-8 mock-fidelity gate (`mock_fidelity.rs`) | 2 | chore | 3f | **A** | 1–1.5 d | ARCH-P0-8 (G-8) |
| **ARCH-3h** | Make the next-slot wait window able to host work | 2 | chore | — | **A** | 1–1.5 d | ARCH-P0-3 |
| **ARCH-3i** | Proposal-first: move both fetches + epoch prep into the window | 3 | feature | 3d, 3h | **A** | 2 d | ARCH-P0-3 |
| **ARCH-3j** | Bounded 500 ms cold-cache pre-proposal fetch (C6) | 2 | feature | 3i | **A** | 1–1.5 d | ARCH-P0-3 |
| **ARCH-3k** | M1/M2 acceptance runs + behaviour-contract pin | 2 | chore | 3f, 3j | **A** | 1–1.5 d | ARCH-P0-3 (M1/M2) |
| **ARCH-3l** | Wire the SSE subscriber + bounded head-event bridge | 3 | feature | — | **B** | 2 d | ARCH-P1-12 |
| **ARCH-3m** | Head-event attestation trigger, timer authoritative | 2 | feature | 3i, 3l | **B** | 1–1.5 d | ARCH-P1-12 |
| **ARCH-3n** | OR-merge doppelganger liveness across healthy BNs | 2 | feature | — | **B** | 1–1.5 d | ARCH-P1-13 |
| | **Total** | **30** | | | A = 21 · B = 9 | | |

**Dependency graph**, as an edge list so it cannot drift from the *Blocked by* column. The project
plan's binding internal order (3A **before** 3B) is the `3d → 3i` edge.

```text
3a → 3c → {3d, 3f}
3d → {3e, 3i}
3b → 3f → 3g
3h → 3i → 3j → 3k
3f → 3k                (the acceptance harness needs spec-honest mocks)
3l → 3m                (3m also needs 3i's head_events seam)
3n                     (independent)
```


## 5. Stream Model, File Ownership and Merge Hotspots

Two streams, chosen so each owns **disjoint files**. Stream A is the slot-loop and block-path spine
(the binding 3A→3B chain); Stream B is the BN-facing infrastructure that touches none of it.

### File ownership map

| Directory / file | Owner | Notes |
|---|---|---|
| `crates/rvc/src/orchestrator/slot_context.rs` | **A** | 3c, 3d, 3f |
| `crates/rvc/src/orchestrator/coordinator/mod.rs` | **A** | 3c, 3h, 3i, 3j — **and the `head_events` seam for 3m** (see hotspots) |
| `crates/rvc/src/orchestrator/coordinator/tests/mod.rs` | **A** | 3f |
| `crates/rvc/src/orchestrator/{block_proposal/mod.rs, sync_committee.rs, aggregation.rs, duty_management.rs}` | **A** | 3c, 3e, 3f, 3i, 3j |
| `crates/block-service/src/{service/mod.rs, validation.rs}` | **A** | 3c (call-site types), 3e (doc + H-4 test) |
| `crates/rvc/tests/{bn_block_root_contract.rs*, proposal_first_budget.rs*, common/pipeline_fixture.rs, sync_independent_of_attesting.rs}` | **A** | `*` = new file |
| `crates/architecture-tests/tests/mock_fidelity.rs` *(new)* | **A** | 3g — assigned to A, not B, so the gate rides its own change's PR (§1.1) |
| `crates/bn-manager/src/mock.rs` | **B** | 3b only; A consumes the helper, never edits the file |
| `crates/bn-manager/src/{sse.rs, manager.rs}` | **B** | 3l, 3n |
| `crates/rvc/src/orchestrator/head_events.rs` *(new)* | **B** | 3m — the whole trigger lives here |
| `crates/rvc/src/liveness_loop.rs` | **B** | 3n (**VD-34**: this file is in `crates/rvc`, not `crates/doppelganger`) |
| `crates/rvc/src/bootstrap/tasks.rs` | **B** | 3l's `register` call. Phase 2 owns this file but has landed by the time Phase 3 starts |

### Merge conflict hotspots

Every file touched by both streams, with a strategy — "be careful" is not a strategy.

| File | Touched by | Strategy | Merge order |
|---|---|---|---|
| `crates/rvc/src/orchestrator/coordinator/mod.rs` | A (3c/3h/3i/3j) · B (3m needs a trigger point) | **Scaffold-first.** ARCH-3i introduces the phase-2 wait as **one** call — `self.wait_for_attestation_or_head(current_slot, &head_gate)` — delegating to the new Stream-B-owned `orchestrator/head_events.rs`. In the scaffold the gate is a no-op that just waits the timer, so 3i is behaviour-neutral. 3m then edits **only** `head_events.rs` | 3i (scaffold) → 3l → 3m |
| `crates/bn-manager/src/mock.rs` | B (3b defines) · A (3f consumes) | **New primitive, not an edit.** 3b adds a builder method; 3f only *calls* it from orchestrator files. A never edits `mock.rs` | 3b → 3f |
| `crates/rvc/src/orchestrator/sync_committee.rs` | A only (3c, 3e, 3f) | Single owner. **Hard rule from A-3.7: `test_messages_and_contributions_share_head_root` (`:558`) keeps its exact name** — it is on the shrinking-only `EXEMPTIONS` list (`kat_policy.rs:125-128`) and a rename is an addition | — |
| `crates/rvc/src/bootstrap/tasks.rs` | B only (3l) | Single owner within this phase; verify Phase 2's executor `register` signature before starting 3l | after Phase 2 |

### Execution plan

Day-slots are the **slow end** of each issue's scope line, so Stream A totals 21 d = the upper bound
in §1. At the fast end the same sequence closes on day 15.

| Day | Stream A (21 pts — the critical path) | Stream B (9 pts, 2nd dev, optional) |
|---|---|---|
| 1 | 3a probe (1 pt) | 3b mock primitive (2 pts) |
| 2–3 | 3c field split (3 pts) | 3b cont. |
| 4 | 3c cont. | 3l SSE wiring (3 pts) |
| 5–6 | 3d walk-back (2 pts) | 3l cont. |
| 7–8 | 3e H-4 + counter (2 pts) | 3n OR-merge (2 pts) |
| 9–10 | 3f stubs (2 pts) | 3n cont. |
| 11–12 | 3g G-8 gate (2 pts, rides 3f's PR) | *(idle, or Phase 4/5 — see §1)* |
| 13–14 | 3h wait-window refactor (2 pts) | |
| 15–16 | 3i proposal-first (3 pts) | |
| 17 | 3i cont. | 3m trigger (2 pts — 3i's seam has landed) |
| 18–19 | 3j cold cache (2 pts) | 3m cont. |
| 20–21 | 3k M1/M2 acceptance (2 pts) | |


---

## 6. Issues

### ARCH-3a — Pin the BN's `get_block_root(<current slot>)` behaviour (gating probe)

**Points:** 1 · **Type:** spike · **Priority:** P0 · **Blocked by:** — · **Blocks:** 3c ·
**Stream:** A · **Scope:** 0.5–1 day · **Requirement:** ARCH-P0-8 · **Constraints:** C9 (anchor 3)

**Context.** ARCH-P0-8 is *"resolve the question empirically, **then** fix"*, and A-A1 makes the
probe the first task of the work package. The whole phase's ordering (3A before 3B) rests on the
assumption that a spec-conformant BN answers `404 Block not found` for a slot whose block does not
yet exist. If it instead returns a usable 200, the ADR-003 finding is withdrawn and issues 3c–3f
collapse to "keep the pin, downgrade the finding" — which is why this costs one day at the front
rather than a rewrite at the back.

**Files.**
- `crates/rvc/tests/bn_block_root_contract.rs` *(new)* — wiremock is already a dev-dependency
  (`crates/rvc/Cargo.toml:75`), so there is no dependency work.

**Implementation approach.** Stand up a wiremock BN that mirrors the beacon-API contract for
`GET /eth/v1/beacon/blocks/{block_id}/root`: `404` with the standard error body for a slot-qualified
id with no block, `200` for `"head"`. Drive the **real** `BeaconClient`/`BnManager` HTTP path (not
`MockBeaconNodeClient`) so the assertion is about HTTP behaviour, and then drive
`SlotContext::capture` through it to show what today's code does with that response
(`slot_context.rs:42-58` → `head_root = None`). Record the observed status code and body in the
issue and in the PR description — the *measurement* is half the deliverable.

**TDD test plan (RED first).**
1. **RED — `test_capture_yields_no_context_when_bn_404s_current_slot`**: asserts
   `SlotContext::capture(...).head_root.is_none()` against the 404-ing wiremock **and** that a
   subsequent sync-committee message phase produces **zero** messages. This is red against the
   *intent* (messages should be produced) and green against HEAD's behaviour — so it is written as
   the documentation of the defect and is **inverted by 3c**, with the inversion called out in the
   test's doc comment so a reviewer cannot mistake it for a regression.
2. **GREEN pin — `test_bn_returns_404_for_slot_qualified_id_with_no_block`**: asserts the HTTP status
   the mock is configured with is what the client surfaces as `BeaconError`, i.e. the transport layer
   does not silently rewrite it.
3. If the probe instead observes a usable 200, **stop and record**: 3c–3f are re-scoped to "keep the
   pin, correct the doc comments, downgrade the finding" and the phase estimate drops by ~7 points.

**KAT-first note (C9 anchor 3).** Neither test name may end in `_root`, `tree_hash` or
`signing_root` — the scanner is a **suffix** match (`kat_policy.rs:232-234`). Both names above end in
`_block` / `_none` / `_404s_current_slot`; they assert HTTP behaviour, not a spec-defined root, so
they must stay out of the scanner's scope and **nothing is added to `EXEMPTIONS`**.

**Acceptance criteria.**
- [x] A wiremock test exists that asserts a **specific documented BN behaviour** for
      `get_block_root(<current slot>)` — not a self-consistency tautology.
- [x] The observed status code and response body are recorded in the PR description and in
      `plan/architecture-2026-08-12/` (one short note file), so the phase's premise is auditable.
- [x] The test drives the real HTTP client, not `MockBeaconNodeClient`.
- [x] No new test name ends in `_root` / `tree_hash` / `signing_root`; `EXEMPTIONS` unchanged.
- [x] The decision — proceed with 3c–3f, or re-scope — is written into the issue before it closes.

---


### ARCH-3b — Spec-honest `with_get_block_root` mock primitive in `bn-manager`

**Points:** 2 · **Type:** chore · **Priority:** P0 · **Blocked by:** — · **Blocks:** 3f ·
**Stream:** B · **Scope:** 1–1.5 days · **Requirement:** ARCH-P0-8 (G-8 precondition) ·
**Constraints:** C9 (anchor 3)

**Context.** G-8 forbids `Ok`-for-anything stubs, and six of the seven call sites are exactly that
(**VD-36**). Fixing seven sites by hand-writing seven slot-aware closures would produce seven subtly
different notions of "spec-honest" and would leave the eighth author to invent an eighth. The
primitive belongs in the mock, next to the builder it replaces
(`crates/bn-manager/src/mock.rs:150-156`).

**Files.**
- `crates/bn-manager/src/mock.rs` — add the builder + its unit tests. **Stream B owns this file;
  Stream A only calls the new method** (hotspot table, §5).

**Implementation approach.** Add a second builder alongside the existing one:

```rust
/// Spec-honest block-root stub: `block_id` values that name a slot at or after
/// `head_slot` answer `404` the way a conformant BN does (beacon-APIs
/// `blocks/{block_id}/root`); `"head"`, `"finalized"` and slots <= head resolve
/// to `root_for(slot)`. Skipped slots named in `skipped` also 404.
pub fn with_slot_aware_block_root(
    self,
    head_slot: Slot,
    skipped: &[Slot],
    root_for: impl Fn(Option<Slot>) -> String + Send + Sync + 'static,
) -> Self
```

The handler receives `block_id: String` **by value** (`mock.rs:152`), so parsing is a plain
`block_id.parse::<Slot>()` with the string literals handled first. The 404 must be surfaced as the
same `BeaconError` variant the real client produces for a 404 — take that from ARCH-3a's recorded
observation rather than guessing; if 3a has not landed yet, use `BeaconError::HttpError` with the
status embedded and open a follow-up to tighten it (this is the only ordering coupling between the
streams, and it is soft).

Keep the existing `with_get_block_root` builder — it is legitimate for tests that genuinely need a
fixed answer for a non-slot id — but make G-8 (3g) require that any *slot-qualified* id routed
through it does not unconditionally succeed.

**TDD test plan (RED first).**
1. **RED — `test_slot_aware_stub_404s_a_slot_at_head`**: build the stub with `head_slot = 100`, call
   `get_block_root("100")`, assert `Err`. Red before the builder exists (does not compile → write the
   builder), and it is the exact behaviour the seven sites are missing.
2. `test_slot_aware_stub_resolves_a_past_slot`: `get_block_root("99")` → `Ok`.
3. `test_slot_aware_stub_404s_a_skipped_slot`: `skipped = [99]` → `Err` for `"99"`, `Ok` for `"98"`.
   This is the fixture ARCH-3d's walk-back is tested against, so it must exist here.
4. `test_slot_aware_stub_resolves_head_literal`: `"head"` → `Ok`, distinct root from any slot id
   (this is what keeps the L-5 fix's regression test meaningful).

**KAT-first note.** All four names avoid the `_root` / `tree_hash` / `signing_root` **suffix**
(A-3.8). `test_slot_aware_stub_404s_a_slot_at_head` is safe; a name like
`test_slot_aware_stub_returns_root` would not be.

**Acceptance criteria.**
- [x] `with_slot_aware_block_root` exists, is documented with `///`, and names the beacon-API
      behaviour it emulates.
- [x] Slot ids `>= head_slot` and slots listed as skipped return the BN's 404 error variant; past
      non-skipped slots and `"head"` return distinct roots.
- [x] Four unit tests above are green; no test name carries a scanner suffix; `EXEMPTIONS` unchanged.
- [x] No existing call site changes in this issue (it is additive) — `cargo nextest run --workspace`
      is green with zero test-behaviour changes elsewhere.

---


### ARCH-3c — Split `SlotContext` into `parent_root` (t=0) and `head_root` (phase 2)

**Points:** 3 · **Type:** feature · **Priority:** P0 · **Blocked by:** 3a · **Blocks:** 3d, 3e, 3f,
3i · **Stream:** A · **Scope:** 2 days · **Requirement:** ARCH-P0-8 (ADR-003) ·
**Constraints:** C6 (sequencing), C9 (anchor 3)

**Context — this is the issue the review's framing gets wrong.** ADR-003's decision is **split the
field, do not repair the query**. Making `capture` succeed at t=0 would activate the shipped-but-inert
H-4 parent-root check with **slot N's own root** in `expected_parent_root` — a block proposed *for*
slot N can never have slot N's own root as its parent — so a valid block would be rejected with
`ParentRootMismatch` precisely on the degraded slots where proposals are already at risk. The chain
is verified at HEAD: `block_proposal/mod.rs:104` → `service/mod.rs:89-95` (`expected_parent_root`) →
`:97-101` (`BlockResponseValidator`) → `validation.rs:63-67` (A-3.3, A-3.4).

**Files.**
- `crates/rvc/src/orchestrator/slot_context.rs` — struct (`:19-29`), `capture` (`:31-60`), doc
  comments (`:8-9`, `:24`, `:26-28`, `:34-39`).
- `crates/rvc/src/orchestrator/coordinator/mod.rs:402` — the single `capture` call; add the phase-2
  head capture just before the attestation/sync phase (`:412-489`).
- `crates/rvc/src/orchestrator/block_proposal/mod.rs:104` — pass `ctx.parent_root`, **not**
  `ctx.head_root`.
- `crates/rvc/src/orchestrator/sync_committee.rs:65-74`, `:148-157` — keep reading `ctx.head_root`
  (unchanged semantics, now populated at phase 2).

**Implementation approach.**
1. `SlotContext { slot, epoch, parent_root: Option<Root>, head_root: Option<Root> }`.
2. Split `capture` into two constructors: `capture_parent(beacon, slot, epoch)` at t=0 querying
   `get_block_root(slot - 1)` (the walk-back arrives in 3d — here it is the single `slot-1` attempt,
   deliberately, to keep this issue at 3 points), and `capture_head(&mut self, beacon)` at phase 2
   querying the slot-qualified current slot, storing into `head_root`.
3. **Phase 3 reuses phase 2's `head_root`; it does not re-capture.** Re-capturing breaks H-5 and its
   existing regression test.
4. Correct the three misleading doc comments rather than editing around them: `slot_context.rs:24`
   ("Head block root at slot start" — now two fields with two different chain positions),
   `:26-28` (`None` is the **normal** path for the t=0 query, not an exception), and the module doc
   `:1-9`. `block-service/src/validation.rs:9` ("`parent_root` matches the expected head root") is
   corrected in 3e together with the H-4 test that gives it teeth.

**TDD test plan (RED first).**
1. **RED — `test_sync_messages_are_produced_when_bn_404s_the_current_slot`** (in
   `sync_committee.rs` tests, driven through the coordinator's phase-2 capture): with a BN that 404s
   slot N and answers slot N-1 and `"head"`, assert **messages are produced**. Red at HEAD (today
   `head_root` is `None` and `:65-74` returns early), green once phase-2 capture exists.
2. **RED — `test_proposal_passes_previous_slot_as_expected_parent`**: assert the value handed to
   `propose_block`'s 4th argument equals the **slot N-1** root, not slot N's. Red at HEAD (`:104`
   passes `ctx.head_root`).
3. **`test_messages_and_contributions_share_head_root` (`sync_committee.rs:557-602`) — three
   separable obligations, per VD-37. Do not conflate them:**
   - **The H-5 property is inviolable**: phases 2 and 3 must still read *one* captured head root.
   - **One mandatory edit**: the test builds `SlotContext` as a **struct literal** at `:582`, so the
     fourth field breaks compilation. Add `parent_root: None` — legitimate, not a regression.
   - **The name stays byte-identical**: it is on the shrinking-only `EXEMPTIONS` list at
     `kat_policy.rs:125-128`, so a rename is an addition (A-3.7, C9 anchor 3).
   - Its `get_block_root_call_count == 0` assertion (`:589-594`) **should survive unchanged**,
     because the test calls `maybe_produce_sync_messages` / `maybe_produce_sync_contributions`
     **directly** (`:585-586`) rather than through the coordinator, so neither capture runs inside
     it. **If that counter does move, the correct response is to check whether a sync phase started
     fetching for itself — not to adjust the number reflexively, and never to revert the split or
     exempt the test.**
4. `test_capture_parent_leaves_head_unset_until_phase_two`: the t=0 context has
   `head_root == None` by construction, so a future consumer cannot accidentally read a head root
   that was never captured.

**KAT-first note.** New test names must not end in `_root` (A-3.8) — hence
`..._as_expected_parent` and `..._404s_the_current_slot`. `EXEMPTIONS` neither grows nor shrinks in
this issue.

**Acceptance criteria.**
- [x] `SlotContext` has four fields; `parent_root` is captured at t=0 from `slot - 1`, `head_root` at
      phase 2 from the slot-qualified current slot, and phase 3 **reuses** phase 2's value.
- [x] `block_proposal/mod.rs:104` passes `parent_root`; no production caller passes a head root into
      `expected_parent_root`.
- [x] With a 404-on-current-slot BN, sync-committee **messages** are produced (contributions in 3e's
      criteria; the code path is already shared).
- [x] `test_messages_and_contributions_share_head_root` is green and **byte-identically named**, with
      its struct literal at `:582` updated for the new field (VD-37) and its call-count assertion
      unchanged.
- [x] Both captures stay **slot-qualified**; the literal `"head"` block_id is not reintroduced (the
      L-5 fix is preserved; `"head"` appears only as 3d's terminal fallback).
- [x] The three misleading doc comments are corrected, not deleted.
- [x] `cargo nextest run --workspace` green; `EXEMPTIONS` unchanged.

---


### ARCH-3d — Walk back over skipped slots, with a counted terminal fallback

**Points:** 2 · **Type:** feature · **Priority:** P0 · **Blocked by:** 3c · **Blocks:** 3e, 3i ·
**Stream:** A · **Scope:** 1–1.5 days · **Requirement:** ARCH-P0-8 (A-4) · **Constraints:** C9

**Context.** The walk-back is **required for correctness, not polish**. `slot - 1` is itself a 404
whenever the previous slot was skipped, and giving up at the first 404 leaves `parent_root = None` on
every post-skip slot — re-disabling H-4 exactly where a wrong-ancestor block is most likely
(ADR-003 *Consequences*). Skips are not rare on a degraded network, and they cluster.

**Files.**
- `crates/rvc/src/orchestrator/slot_context.rs` — `capture_parent`.
- `crates/metrics/src/definitions.rs` (or the crate-local registration site, whichever Phase 6 has
  not yet moved) — one counter.

**Implementation approach.** Attempt `slot-1`, `slot-2`, `slot-3`, `slot-4` in order (A-3.17), taking
the first `200`. On four consecutive misses fall back to the literal `"head"` block_id as a
**terminal last resort**, `warn!`-logged with the slot and the attempt count, and increment
`rvc_slot_context_parent_fallback_total{reason="walk_back_exhausted"}`. A transport error (as opposed
to a 404) should **stop** the walk rather than consume attempts on a BN that is down — record the
distinction using the error variant ARCH-3a observed, and if the two are indistinguishable at the
client layer, state that in the code comment and treat everything as a miss (the conservative
choice: at worst four cheap queries).

Budget note for 3i/3j: four sequential BN round trips at t=0 is now part of the pre-proposal path, so
this issue's fallback must be **bounded by the same pre-proposal deadline** ARCH-3i introduces — it
is not permitted to grow the t=0 critical path without a ceiling.

**TDD test plan (RED first).**
1. **RED — `test_capture_parent_walks_back_over_a_skipped_slot`**: using 3b's
   `with_slot_aware_block_root(head_slot = N, skipped = [N-1], ..)`, assert `parent_root ==
   root_of(N-2)`. Red after 3c (which tries `slot-1` only, so this yields `None`).
2. `test_capture_parent_walks_back_over_three_consecutive_skips` → `root_of(N-4)`.
3. `test_capture_parent_falls_back_to_head_after_four_misses`: all of `N-1..N-4` skipped → the
   `"head"` root is used, the counter increments by exactly 1, and a `warn!` is emitted
   (`tracing-test` is already a dev-dependency of `crates/rvc`).
4. `test_capture_parent_stops_walking_on_transport_error`: at most one query is issued when the BN is
   unreachable (assert on the mock's call count).

**KAT-first note.** `..._walks_back_over_a_skipped_slot`, `..._falls_back_to_head_after_four_misses`
— none ends in a scanner suffix (A-3.8).

**Acceptance criteria.**
- [x] Up to four slot-qualified attempts (`slot-1 … slot-4`), first success wins.
- [x] Terminal `"head"` fallback is `warn!`-logged **and** counted with a dedicated metric, so its
      real-world frequency is observable rather than assumed.
- [x] A transport-level failure does not consume all four attempts.
- [ ] The walk-back is inside whatever pre-proposal deadline 3i establishes (cross-checked in 3k).
- [x] `EXEMPTIONS` unchanged; workspace green.

---


### ARCH-3e — Activate H-4: wrong-ancestor rejection test + sync-skip counter + doc corrections

**Points:** 2 · **Type:** feature · **Priority:** P0 · **Blocked by:** 3c, 3d · **Blocks:** — ·
**Stream:** A · **Scope:** 1–1.5 days · **Requirement:** ARCH-P0-8 · **Constraints:** C9 (anchor 3)

**Context.** H-4's parent-root check has shipped inert: `validation.rs:63-70` only fires when
`expected_parent_root` is `Some`, and the only production caller supplied a value that is `None` on
every 404-ing slot. After 3c/3d it is `Some` on essentially every slot — so **for the first time the
check can reject a block**, and it needs the test it never had. Architecture §7.2 requires that test
to be **RED before the fix**. It also requires the residual failure to stay observable: if
`head_root` is ever `None` at phase 2, the sync path still skips, and that must be counted rather
than merely logged.

**Files.**
- `crates/block-service/src/validation.rs` — doc comment at `:9`; new tests in the existing
  `#[cfg(test)] mod tests` (`:73+`).
- `crates/block-service/src/service/mod.rs` — doc comment at `:75-77` if it still says "head".
- `crates/rvc/src/orchestrator/sync_committee.rs:65-74`, `:148-157` — add the counter next to the two
  existing `warn!`s.
- metric registration site (see 3d).

**Implementation approach.** Two independent pieces, deliberately in one issue because they are the
two halves of "the failure is now visible either way":

1. **H-4 activation proof.** A `BlockResponseValidator` with `expected_parent_root =
   Some(root_of(N-1))` rejects a block whose `parent_root` is a different (wrong-ancestor) root with
   `ParentRootMismatch`, and accepts the correct one — asserted through the **service** entry point
   (`propose_block`), not only the struct, so the wiring is what is proven. Also assert the negative
   direction that motivated the split: a block whose parent is `root_of(N-1)` is **accepted**, where
   the naive "make capture succeed" fix would have rejected it.
2. **Sync-skip counter.** `rvc_sync_committee_skipped_total{phase="messages"|"contributions",
   reason="no_head_root"}` incremented at both skip sites. Two label values, because 3c must not be
   allowed to fix messages and leave contributions silently broken (A-3.5).

Correct `validation.rs:9` from *"`parent_root` matches the expected **head** root"* to the parent
semantics — the doc comment is what let the conflation survive review in the first place.

**TDD test plan (RED first).**
1. **RED — `test_propose_block_rejects_a_wrong_ancestor_parent`**: build the service with a BN
   returning a block whose `parent_root` is an unrelated value; assert
   `Err(BlockServiceError::ParentRootMismatch { .. })` **and** that the signer was never called.
   Demonstrably red before 3c (the check is inert: `expected_parent_root` is `None`, so the block is
   accepted) — reproduce that locally with the pre-3c tree and paste the output into the PR, per the
   repo's "demonstrated, not asserted" standard.
2. `test_propose_block_accepts_the_previous_slot_parent` — the anti-regression for the dropped-
   proposal bug the naive fix would have armed.
3. **RED — `test_sync_skip_counter_increments_for_messages_and_contributions`**: force
   `head_root = None` at phase 2 and assert **both** label values increment by 1.

**KAT-first note (C9 anchor 3).** These assert HTTP/validation behaviour, not spec-defined roots, so
they must stay out of the scanner: no name ends in `_root`. Note the near-miss —
`test_propose_block_rejects_a_wrong_ancestor_parent_root` **would** be scanned and would then demand
a KAT anchor it cannot have. `EXEMPTIONS` must not grow.

**Acceptance criteria.**
- [x] H-4 gains a test it never had: a wrong-ancestor block is rejected with `ParentRootMismatch`,
      **RED demonstrated against the pre-fix tree** with the output in the PR.
- [x] A correct previous-slot parent is accepted (the dropped-proposal anti-regression).
- [x] No signer call occurs on a validation rejection.
- [x] A counter exists for "sync messages/contributions skipped: no head root", with **both** phases
      labelled.
- [x] `validation.rs:9` and any sibling doc comment no longer say "head root" for a parent.
- [x] No new test name enters the KAT scanner's suffix scope; `EXEMPTIONS` unchanged.

---


### ARCH-3f — Correct all seven `with_get_block_root` stubs

**Points:** 2 · **Type:** chore · **Priority:** P0 · **Blocked by:** 3b, 3c · **Blocks:** 3g, 3k ·
**Stream:** A · **Scope:** 1–1.5 days · **Requirement:** ARCH-P0-8 (G-8) · **Constraints:** C9

**Context.** Six stubs return `Ok(...)` for **any** `block_id`, and the one at
`crates/rvc/tests/sync_independent_of_attesting.rs:87-91` is *single-handedly why CI is green* on the
ADR-003 defect — it is the only test that drives the real composition through `capture`. Fixing one
call site leaves five loaded guns, which is why this is a sweep and why 3g makes it permanent.

**Files — all seven call sites, verified at HEAD:**

| # | Site | Today |
|---|---|---|
| 1 | `crates/rvc/src/orchestrator/slot_context.rs:70-73` | `Ok`; routes `"head"` vs anything-else |
| 2 | `crates/rvc/src/orchestrator/slot_context.rs:77-79` | **`Err(HttpError)` for everything** — not an `Ok` stub, but not spec-honest either (**VD-36**) |
| 3 | `crates/rvc/src/orchestrator/sync_committee.rs:388-391` | `Ok`, counts calls |
| 4 | `crates/rvc/src/orchestrator/aggregation.rs:609-613` | `Ok`, fixed root |
| 5 | `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:253-257` | `Ok`, fixed root |
| 6 | `crates/rvc/tests/common/pipeline_fixture.rs:243-245` | `Ok`, fixed root |
| 7 | `crates/rvc/tests/sync_independent_of_attesting.rs:87-91` | `Ok`, fixed root — **the load-bearing one** |

**Implementation approach.** Replace each with `with_slot_aware_block_root` (ARCH-3b), configured
with the fixture's notion of the current slot. Sites 1 and 3 intentionally distinguish `"head"` from
slot ids and must keep doing so (site 1 *is* the L-5 regression test; site 3 counts calls to prove
H-5's single capture) — the helper preserves both. Site 2 keeps an error-returning variant but for a
transport error only, and gains a sibling that 404s, because 3d's
`test_capture_parent_stops_walking_on_transport_error` needs the distinction.

Expect **test failures to appear** as the honest mocks land — that is the deliverable, not an
accident. Each newly-failing test is either (a) a genuine defect the stub was hiding, fixed here or
carried to 3e/3i with a named issue, or (b) a fixture that needs its `head_slot` set correctly.
Enumerate them in the PR description; "silently adjusted" is not acceptable.

**TDD test plan (RED first).**
1. **RED — flip site 7 first, alone.** `sync_independent_of_attesting.rs` must fail after 3b's helper
   replaces its stub and before 3c has landed in the same branch; capture that output. This is the
   single sharpest proof that the CI-green story was mock-driven.
2. Then flip 1–6 and run `cargo nextest run --workspace`; every failure is triaged in writing.
3. No new test is added by this issue — it changes fixtures only. Its regression pin **is** 3g.

**Acceptance criteria.**
- [x] All seven call sites use a spec-honest stub; no stub returns `Ok` for a slot-qualified id that
      cannot have a block, and no stub returns an error for *every* id.
- [x] Sites 1 and 3 still distinguish `"head"` from slot-qualified ids (L-5 and H-5 pins intact).
- [x] `test_messages_and_contributions_share_head_root` still green, name unchanged (A-3.7); if its
      `get_block_root` call count moved, the cause is diagnosed in the PR rather than the number
      silently updated (VD-37).
- [x] Every test that changed status is listed in the PR with a one-line disposition.
- [x] `cargo nextest run --workspace` green at the end of the issue.

---


### ARCH-3g — G-8 mock-fidelity gate (`mock_fidelity.rs`)

**Points:** 2 · **Type:** chore · **Priority:** P0 · **Blocked by:** 3f · **Blocks:** — ·
**Stream:** A · **Scope:** 1–1.5 days · **Requirement:** ARCH-P0-8 (gate G-8) · **Constraints:** C9
(anchor 1 — new file in the existing scanner idiom, no existing gate file modified)

**Context and landing rule.** Per project plan §1.1, G-8 is one of the three gates that **cannot**
precede its change: it is RED at HEAD (six `Ok`-for-anything stubs). Its landing rule is *"with
ADR-003, after the seven stubs are corrected"* — so this issue's commit **rides in ARCH-3f's PR,
after 3f's commit**, and RED is demonstrated locally against the pre-3f tree with the output pasted
into the PR. It is assigned to **Stream A** (not B) precisely so that gate and change share one PR
and one author; putting the gate in the other stream would create a cross-stream PR for no benefit.

**Files.**
- `crates/architecture-tests/tests/mock_fidelity.rs` *(new)*.
- Nothing else. `kat_policy.rs`, `orphan_dirs.rs` and the other gate files are not touched (C9
  anchor 1).

**Implementation approach.** A source scanner in the existing `architecture-tests` idiom (brace-aware
body extraction, same technique `kat_policy.rs` already uses). Walk every `.rs` file under
`crates/**`, find each `with_get_block_root(` call, extract the closure body, and fail on **two**
clauses (**VD-36** — the architecture states one):

- **(i)** the body has no branch on the `block_id` argument *and* returns `Ok(` — an
  unconditional-success stub;
- **(ii)** the body returns `Err(` on every path — an error-for-everything stub standing in for a
  404, which is equally dishonest about BN behaviour.

Failure messages name **file, line and call site** (NFR-5, R10) and state the remedy: *"use
`MockBeaconNodeClient::with_slot_aware_block_root`"*. **Non-vacuity** is mandatory — the gate must
assert it actually found call sites (`assert!(sites >= 7)` at the time of writing, or an exact
equality if the count is stable after 3f), or a future rename of the builder silently turns the gate
into a no-op. Include the `mock.rs` builder definition itself in the exclusion list, by exact path,
with a comment.

**TDD test plan (RED first).**
1. **RED — local demonstration**: `git stash` the 3f fixture changes (or check out the pre-3f tree),
   run `cargo nextest run -p rvc-architecture-tests`, and capture the six failures naming the six
   `Ok`-for-anything sites plus the one error-for-everything site. Paste into the PR. Never merge a
   knowingly-failing test (ADR-012).
2. `test_scanner_flags_a_synthetic_unconditional_ok_stub`: an inline synthetic source string is
   flagged — the gate's own unit test, so it is falsifiable without editing the workspace.
3. `test_scanner_accepts_a_synthetic_slot_aware_stub`: the honest form is not flagged (no false
   positive on the very pattern 3f introduces).
4. `test_scanner_is_non_vacuous`: the walk finds at least the known number of call sites.

**Acceptance criteria.**
- [x] `mock_fidelity.rs` exists, runs under the Phase-0 `arch-gates` CI job, and is green on
      `develop` after 3f.
- [x] Both clauses implemented; the error-for-everything case is covered (**VD-36**).
- [x] RED demonstrated locally against the pre-3f tree, output in the PR.
- [x] Each failure names file + line and the concrete remedy.
- [x] Non-vacuity assertion present; the `mock.rs` definition is excluded by exact path with a reason.
- [x] No existing gate file modified.

---


### ARCH-3h — Make the phase-3 → next-slot wait window able to host work

**Points:** 2 · **Type:** chore · **Priority:** P0 · **Blocked by:** — · **Blocks:** 3i ·
**Stream:** A · **Scope:** 1–1.5 days · **Requirement:** ARCH-P0-3 (enabler) · **Constraints:** C9
(anchor 6 — no new channels)

**Context — VD-32, and the reason this is its own issue.** "Move the duty fetches into the wait
window" does not compile. `wait_for` is `async fn wait_for(&mut self, duration: Duration)`
(`coordinator/mod.rs:628`) and needs `&mut self` only for `self.shutdown_rx.changed()` at `:632`.
`duty_management` is an **owned** field (`:224`), not an `Arc`. `select!`-ing the two therefore asks
for `&mut self` and `&self` simultaneously. The existing builder-registration window sidesteps this
by cloning the service out of `self` first — the comment at `:550` says so verbatim: *"Clone
builder_service before borrowing self for wait_for"*. Discovering this inside ARCH-3i would turn a
3-point issue into a 5-point one mid-flight; it is separated so the borrow work is done, reviewed and
green before any behaviour moves.

**Files.**
- `crates/rvc/src/orchestrator/coordinator/mod.rs` — `wait_for` (`:623-640`), `check_shutdown`
  (`:614-621`), the two wait branches (`:549-594`).

**Implementation approach.**
1. Add `async fn wait_for_shared(&self, duration: Duration) -> WaitOutcome` that clones
   `self.shutdown_rx` (a `watch::Receiver` is `Clone`) into a local `mut rx` and runs the same
   `select!`; `check_shutdown` is already `&self`. Keep `wait_for(&mut self, ..)` as a thin delegate
   so the ~8 existing call sites are untouched in this issue (smallest reviewable diff), and mark it
   for removal once 3i has migrated its callers.
2. Generalise the `:541-594` block into **one** structure with a single wait: a
   `post_duty_work: impl Future<Output = ()>` raced against `wait_for_shared(time_until_next_slot)`
   via `tokio::select!`, collapsing the `if should_register` / `else if` duplication at `:590-594`.
   Builder registration becomes the *first* occupant of that window, unchanged in behaviour.
3. **No new channel, no new task, no `spawn`** — the window is a `select!` over futures owned by the
   loop, so G-4 and C9 anchor 6 are untouched.

**TDD test plan (RED first).**
1. **RED — `test_post_duty_window_runs_hosted_work_before_the_next_slot`**: register a trivial future
   that sets a flag; assert the flag is set when the next slot begins. Red before the refactor (there
   is no hosting seam), green after.
2. `test_post_duty_window_abandons_hosted_work_when_the_slot_arrives_first`: a hosted future that
   never completes must not delay the next slot — preserving the abandon semantics documented at
   `:542-544`.
3. `test_shutdown_during_the_post_duty_window_still_returns` — the `WaitOutcome::Shutdown` path must
   survive the receiver-cloning change; assert the loop returns `Ok(())` promptly.
4. Existing builder-registration tests stay green with **no** change to their assertions (the
   behaviour-neutrality proof for this refactor).

**Acceptance criteria.**
- [x] A `&self` wait variant exists and compiles alongside concurrent use of `self.duty_management`
      (demonstrated by test 1, which borrows both).
- [x] The two wait branches at `:549-594` collapse into one hosting structure; builder registration
      is now a hosted future with unchanged behaviour.
- [x] Shutdown still short-circuits the window; named exit paths unchanged.
- [x] No new channel, task or `tokio::spawn`; G-4 stays green.
- [x] Workspace green with no assertion changes to existing coordinator tests.

---


### ARCH-3i — Proposal-first: move both duty fetches and the epoch-boundary prep into the window

**Points:** 3 · **Type:** feature · **Priority:** P0 · **Blocked by:** 3d, 3h · **Blocks:** 3j, 3m ·
**Stream:** A · **Scope:** 2 days · **Requirement:** ARCH-P0-3 (ADR-004) · **Constraints:** C6
(binding), C7, C9

**Context.** The binding order from the project plan is **3A before 3B**, i.e. this issue may not
land before 3c/3d: reordering first removes the accidental masking and makes the sync-committee
reward loss deterministic on every slot in every BN-health regime. PRD ARCH-P0-3 enumerates exactly
four things that must move or be bounded, and all four are verified at HEAD:

| Currently at | Work | Required disposition |
|---|---|---|
| `coordinator/mod.rs:376-379` | `fetch_epoch_duties(current_epoch)` — **runs every slot** (A-3.9) | Move into the post-duty window; keep an epoch-boundary / dependent-root trigger |
| `:380-383` | `fetch_epoch_duties(current_epoch + 1)` — lookahead, also every slot | Same |
| `:386-397` | circuit-breaker reset + `on_epoch_boundary` | Move into the window |
| `:402` | `SlotContext::capture` — a **third** pre-proposal BN round trip | After 3c/3d this is the `parent_root` capture; it must be **bounded by the pre-proposal deadline**, never an unbounded gate |

**Files.**
- `crates/rvc/src/orchestrator/coordinator/mod.rs:365-410` (the reorder), `:541-594` (the window from
  3h).
- `crates/rvc/src/orchestrator/duty_management.rs` — the epoch-boundary trigger predicate, if it
  belongs next to `fetch_epoch_duties`.

**Implementation approach.**
1. New per-slot order: key-gen invalidation (`:373`) → **bounded** `parent_root` capture →
   `maybe_propose_block` → phase 2 → phase 3 → **post-duty window**: `fetch_epoch_duties(e)`,
   `fetch_epoch_duties(e+1)`, epoch-boundary prep, builder registration.
2. The pre-proposal deadline is an **aggregate** budget (A-5: 1,000 ms warm), enforced with a single
   `tokio::time::timeout` around the capture + cold-cache fallback, not per-request timeouts that can
   sum past the slot's 1/3 point.
3. Keep an **epoch-boundary / dependent-root-change trigger** so duties for the imminent epoch are
   not fetched a slot too late; the existing `current_slot % SLOTS_PER_EPOCH == 0` guard at `:386`
   moves with the prep it guards.
4. **Scaffold for Stream B (hotspot table, §5):** replace the phase-2 wait
   (`self.wait_for(time_until_attestation)`, `:427`) with
   `self.wait_for_attestation_or_head(current_slot, &self.head_gate)` delegating to a new
   `orchestrator/head_events.rs`. In this issue the gate is a **no-op that waits the timer** — zero
   behaviour change, one review, and ARCH-3m then edits only `head_events.rs`.
5. `maybe_propose_block` and the duty set it reads are **unchanged**: which duties are performed must
   not change, only when the work around them runs.

**TDD test plan (RED first).**
1. **RED — `test_proposal_is_attempted_before_any_epoch_duty_fetch`**: a BN mock recording call order
   asserts `produceBlock`-path entry precedes the first `get_attester_duties`. Red at HEAD
   (`:376-383` run first, unconditionally, every slot).
2. **RED — `test_proposal_still_happens_when_duty_fetches_stall`**: duty-fetch endpoints hang; assert
   `maybe_propose_block` is entered and a block is produced. (The full stall envelope is 3k's job;
   here a single stalled fetch suffices to prove the dependency is gone.)
3. `test_epoch_boundary_prep_runs_in_the_post_duty_window`: assert `on_epoch_boundary` is observed
   after phase 3 and before the next slot, and only on boundary slots.
4. `test_duties_performed_are_unchanged_by_the_reorder` — the behaviour-contract pin (§7.2): same
   fixture, same set of produced duties, only ordering differs.
5. Existing `sync_independent_of_attesting.rs` stays green **driven by a bare `tokio::spawn`** — no
   `LocalSet` scaffold may be reintroduced (Phase 2 entry criterion).

**Acceptance criteria.**
- [x] All four enumerated items are moved or bounded; nothing else moves.
- [x] `maybe_propose_block` is entered before any epoch duty fetch on every slot.
- [x] An aggregate pre-proposal deadline exists and covers the `parent_root` capture including 3d's
      walk-back.
- [x] An epoch-boundary / dependent-root trigger still fetches duties in time; no epoch's duties are
      fetched later than today relative to their first use.
- [x] The `head_events` seam exists as a behaviour-neutral no-op (Stream B's scaffold).
- [x] Behaviour-contract test shows **which** duties are performed is unchanged and only **when**
      changed.
- [x] No new `unbounded_channel`; no new raw `tokio::spawn` (G-4 green).

---


### ARCH-3j — Bounded 500 ms cold-cache pre-proposal duty fetch (C6)

**Points:** 2 · **Type:** feature · **Priority:** P0 · **Blocked by:** 3i · **Blocks:** 3k ·
**Stream:** A · **Scope:** 1–1.5 days · **Requirement:** ARCH-P0-3 · **Constraints:** **C6
(binding)**

**Context — C6, carried forward in full.** Proposal-first creates a new miss mode: if the loop
proposes before fetching duties, then on a slot with an empty proposer-duty cache it has nothing to
propose *from*. That is not hypothetical — it is guaranteed on the first slot after boot and on
**every slot after a `key_gen`-driven invalidation**, because `apply_key_gen_cache_invalidation`
(`coordinator/mod.rs:373` → `:606-612`) calls `duty_tracker.clear_cache()`, which clears all duty
caches (A-3.11). ADR-004 rejects *"propose only if a cached duty exists"* by name: it converts a key
import into a guaranteed missed proposal on the following slot. The required behaviour is a
**bounded, short-deadline** pre-proposal duty fetch — **not a silent skip**.

**Files.**
- `crates/rvc/src/orchestrator/coordinator/mod.rs` — the pre-proposal path from 3i.
- `crates/rvc/src/orchestrator/duty_management.rs` — a proposer-duties-only fetch entry point with a
  caller-supplied deadline (the existing `fetch_epoch_duties` fetches all three duty types under the
  10 s `duty_fetch` timeout — `:66`, `:86`, `:106`, `traits.rs:216` — and is the wrong tool here).
- metric registration site.

**Implementation approach.**
1. Detect cold cache explicitly: *no cached proposer duty for `current_epoch`*, via the existing
   `is_proposer_epoch_cached` predicate (`duty_management.rs:86` uses it already). Do **not** infer
   coldness from a boot flag — the `key_gen` case has no flag.
2. On cold cache, run a **proposer-duties-only** fetch under a hard `timeout(500 ms)` (A-3.16),
   inside the aggregate pre-proposal budget from 3i, then proceed to the proposal decision with
   whatever was learned. On timeout: proceed anyway, `warn!` once, and count it.
3. Two metrics, both labelled: `rvc_pre_proposal_cold_fetch_total{outcome="hit"|"miss"|"timeout"}`
   and a duration histogram, so M2's cold-cache p99 (≤ 2,000 ms) is measurable from the process
   itself rather than only from the harness. Plus a distinct log line, per the PRD.
4. The 500 ms deadline is a **constant with a named default**, not a literal buried in the loop, so
   Phase 4's config consolidation has one declaration to move.

**TDD test plan (RED first).**
1. **RED — `test_cold_cache_slot_still_proposes_when_a_duty_exists`**: empty duty cache, BN serving
   proposer duties with 100 ms latency; assert the block **is** proposed. Red against a naive
   proposal-first implementation that reads only the cache (which is why this test must be written
   before 3j's code and run against 3i's tree, where it fails).
2. **RED — `test_slot_after_key_gen_bump_still_proposes`**: send on `key_gen_tx`, let the loop
   invalidate at `:373`, assert the *very next* slot proposes. This is the case a boot-flag
   implementation silently fails.
3. `test_cold_fetch_gives_up_at_the_bounded_deadline`: BN latency 5 s; assert the pre-proposal path
   returns within ~500 ms (+ tolerance), the timeout counter increments, and the loop still reaches
   `maybe_propose_block`.
4. `test_warm_cache_slot_issues_no_pre_proposal_duty_fetch`: assert **zero** BN duty calls before the
   proposal on a warm slot — the guard against re-introducing the cost 3i just removed (A-3.10:
   warm cache = zero round trips today).

**Acceptance criteria.**
- [x] Cold cache triggers a bounded proposer-duty fetch; the proposal check is **never** silently
      skipped (C6).
- [x] Both cold-cache origins are covered: first slot after boot **and** the slot after a `key_gen`
      bump.
- [x] The fetch has its own metric **and** its own log line (PRD wording).
- [x] The deadline is a named constant with a stated default of 500 ms.
- [x] A warm slot issues no pre-proposal duty fetch.
- [x] The cold path stays inside 3i's aggregate pre-proposal budget.

---


### ARCH-3k — M1/M2 acceptance harness runs and the behaviour-contract pin

**Points:** 2 · **Type:** chore · **Priority:** P0 · **Blocked by:** 3f, 3j · **Blocks:** — ·
**Stream:** A · **Scope:** 1–1.5 days · **Requirement:** ARCH-P0-3 (M1, M2) · **Constraints:** C6,
C9 (anchor 3)

**Context.** M1 and M2 are the phase's milestone, and their **instrument is a Phase-0 deliverable**
(the latency-injecting BN harness and the slot-phase-0 start-offset measurement — project plan 0D).
This issue does not build an instrument; it **runs** it against the reordered loop and pins the
numbers. Two traps: ADR-004's own acceptance tests must **not** use an `Ok`-for-anything
`get_block_root` stub (hence the `3f` dependency — otherwise the new ordering bakes in the very
assumption ADR-003 removed), and the stall envelope is larger than the documents say (**VD-35**).

**Files.**
- `crates/rvc/tests/proposal_first_budget.rs` *(new)* — the three-scenario budget test.
- `plan/architecture-2026-08-12/` — the recorded post-change numbers, alongside Phase 0's baselines.

**Implementation approach.**
1. Three scenarios, per ADR-004: **warm**; **cold post-boot**; **cold immediately after a `key_gen`
   bump**. Each asserts entry to `maybe_propose_block` within the configured budget of slot start
   (1,000 ms warm / 2,000 ms cold, A-3.16), measured with the Phase-0 offset instrument so the test
   and the metric cannot disagree.
2. **M1 stall test parameterised to 80 s, not 60 s.** The milestone stays worded as the plan states
   it (60 s is the authoritative exit criterion), but the true worst case is up to **8 × 10 s**:
   `fetch_epoch_duties` runs twice per slot, and each call ends in
   `maybe_prefetch_next_sync_period` (`duty_management.rs:132`, `:149-190`), which issues a **fourth**
   BN fetch under the same 10 s `duty_fetch` timeout inside the period-boundary lookahead window and
   retries every slot until it succeeds (`:158-170`). Run the stall test at both 60 s and 80 s; the
   80 s case is the one that would have surprised production.
3. Record the numbers **as a file in this directory**, not only in a CI log — same discipline Phase 0
   used for the baselines, so M2 before/after is a diff rather than an anecdote.
4. The harness drives a **spawned** orchestrator (Phase 2's ADR-002); reintroducing `LocalSet` is
   forbidden.

**TDD test plan (RED first).**
1. **RED — `test_proposal_survives_a_full_duty_fetch_stall`**: all duty endpoints hang; assert the
   block is proposed. Red against the pre-3i tree (100 % miss by construction, PB-A1), green after.
   Run at 60 s and at 80 s.
2. `test_phase_zero_offset_within_budget_warm` / `..._cold_after_boot` / `..._cold_after_key_gen`:
   p99 over N simulated slots within budget.
3. `test_acceptance_harness_uses_a_slot_aware_block_root_stub` — a guard on the harness itself, so a
   future edit cannot reintroduce an `Ok`-for-anything mock here (G-8 covers the workspace; this
   makes the intent local and explicit).

**KAT-first note.** `..._uses_a_slot_aware_block_root_stub` ends in `_stub`, not `_root` — safe under
the suffix matcher (A-3.8). Watch this one: dropping the trailing word would put an HTTP-behaviour
test into the KAT scanner's scope.

**Acceptance criteria.**
- [x] **M1 = 0 missed proposals** with duty fetches stalled the full 60 s — and the 80 s envelope
      (**VD-35**) additionally covered.
- [x] **M2 p99 ≤ 1,000 ms warm / ≤ 2,000 ms cold**, all three scenarios, measured with Phase 0's
      instrument.
- [x] The cold-cache scenarios **propose** when a duty exists (the test fails if the check is
      skipped) — C6.
- [x] Post-change numbers recorded as a file in `plan/architecture-2026-08-12/`, next to the
      baselines.
- [x] The harness uses spec-honest block-root stubs and a bare `tokio::spawn`ed orchestrator.
- [x] Behaviour-contract test from 3i still green.

---


### ARCH-3l — Wire the SSE subscriber and a bounded head-event bridge

**Points:** 3 · **Type:** feature · **Priority:** P1 · **Blocked by:** — (Phase 2's executor) ·
**Blocks:** 3m · **Stream:** B · **Scope:** 2 days · **Requirement:** ARCH-P1-12 (ADR-013) ·
**Constraints:** **C7 (binding)**, C9 (anchors 6 and 7)

**Context — VD-31, the scope correction.** ADR-013 reads as though the SSE stream is live and only a
trigger arm is missing. It is not: `BnManager::start_sse` (`crates/bn-manager/src/manager.rs:303-316`)
has **zero call sites in the workspace**, and `subscribe_events` (`sse.rs:154`) is reached only from
tests. Nothing subscribes in production. So ARCH-P1-12 is *first* a wiring job — a new long-lived
task — and only *then* a trigger. Two knock-on facts the PR must state:

- **Phase 2's P2-2 `register` row (`sse.rs:174`) is vacuous until this issue lands.** The task it
  describes does not run. This issue is where the registration becomes real.
- **VD-33: ADR-013's "adds no channel" is not achievable.** The `mpsc(64)` lives *inside*
  `subscribe_events` (`sse.rs:171-182`), and the caller's callback is
  `F: Fn(SseEvent) + Send + Sync + 'static` (`:159`) — **synchronous**, so it cannot `.await` a send
  into the orchestrator. A bridge is required.

**Files.**
- `crates/rvc/src/bootstrap/tasks.rs` — start + `register` the subscriber (Background tier).
- `crates/rvc/src/orchestrator/head_events.rs` *(new, Stream B owned)* — the bridge type.
- `crates/bn-manager/src/{manager.rs, sse.rs}` — only if `start_sse` needs a cancellation-token
  variant to match the executor's contract; prefer adapting at the call site.

**Implementation approach.**
1. **Bridge = `tokio::sync::watch<Option<HeadEvent>>`** (A-3.14). Justification to be written into
   the code, not left to a reviewer: a `watch` is bounded by construction (single slot), `send` is
   non-blocking and callable from a sync closure, and **losing an intermediate value is exactly C7's
   semantics** — head events are advisory, the newest one is the only one worth having. C9 anchor 6
   ("zero unbounded channels") is honoured in substance; the ADR's literal "no channel" wording is
   not, and the PR says so rather than quietly diverging.
2. `HeadEventGate { rx: watch::Receiver<Option<HeadEvent>> }` in `head_events.rs`, with
   `async fn wait_for_head_or(&self, slot: Slot, timer: Duration) -> TriggerReason` — the method
   ARCH-3i's scaffold already calls. In this issue it may still behave as timer-only; 3m implements
   the race.
3. Register with Phase 2's `TaskExecutor` at tier **`Background`**, named (`"bn.sse"`), with the
   cancellation token — **never a raw `tokio::spawn`** (G-4 would go red the moment it is enabled).
   `start_sse` returns a `JoinHandle`; adapt it to the executor's `register` primitive, since
   `bn-manager` is Infra and must not depend on the executor (DAG gate).
4. **Failover and drops are expected path** (C7): the existing `warn!`-on-full behaviour at
   `sse.rs:292` (`tx.try_send`) and the polling fallback at `:208-214` stay as they are. Add
   `rvc_sse_events_dropped_total{expected="true"}` — a counter **labelled as expected**, never an
   error metric, never an alert.
5. If the SSE endpoint is unconfigured or disabled, `register_opt` so `rvc_tasks_running` stays
   honest (architecture §5.1).

**TDD test plan (RED first).**
1. **RED — `test_head_event_subscriber_is_started_at_bootstrap`**: assert a task named `"bn.sse"` is
   registered with the executor after bootstrap. Red at HEAD — nothing starts it (**VD-31**), which
   is the whole point of the issue.
2. `test_head_event_bridge_publishes_the_latest_event`: feed two events through the callback; the
   `watch` holds the newer one and neither `send` blocks.
3. `test_bridge_send_never_blocks_the_sse_callback`: the callback is sync — assert it returns
   promptly with no receiver alive (the `watch` no-receiver case must not panic or error-log).
4. `test_sse_task_stops_on_cancellation_within_its_tier_budget`: cancellation token → task joins
   inside the Background budget.
5. `test_sse_drop_counter_is_labelled_expected`: no `error!`, no failure metric on drop or failover.

**Acceptance criteria.**
- [x] An SSE subscriber runs in production, started at bootstrap and **registered** with Phase 2's
      executor at tier `Background` with a name — no raw `tokio::spawn`; G-4 green.
- [x] A bounded bridge exists; no `unbounded_channel` anywhere in the path (C9 anchor 6), and the
      divergence from ADR-013's "no channel" wording is stated in the PR with the C7 reasoning.
- [x] Drops and failover produce **no** `error!` and **no** failure metric; the drop counter is
      labelled expected-path (C7).
- [x] The task shuts down within its tier budget on cancellation.
- [x] Feature-disabled / unconfigured case uses `register_opt`, so the running-task gauge is honest.
- [x] A note is filed back to Phase 2 recording that **both** vacuous `register` rows became real
      here — `manager.rs:313` (outer spawn) and `sse.rs:174` (inner dispatch task).

---


### ARCH-3m — Head-event attestation trigger, timer authoritative (C7)

**Points:** 2 · **Type:** feature · **Priority:** P1 · **Blocked by:** 3i (seam), 3l (bridge) ·
**Blocks:** — · **Stream:** B · **Scope:** 1–1.5 days · **Requirement:** ARCH-P1-12 (ADR-013) ·
**Constraints:** **C7 (binding)**, C9 (anchor 6)

**Context.** Every surveyed reference client attests at "1/3 slot **or** head event, whichever
first"; rvc is purely timer-driven. Lighthouse treats head events strictly as a latency optimisation
— a missed event costs latency, never a duty. C7 is the whole design: the SSE stream is lossy by
policy (bounded `mpsc(64)`, drop-on-overflow at `sse.rs:292`, polling fallback at `:208-214`), so
making it load-bearing would convert an expected drop into a missed duty. The 1/3-slot timer stays
authoritative and this change is **purely additive** — which is also what makes it independently
revertible (NFR-4): its worst-case regression is latency, never a duty.

**Files.**
- `crates/rvc/src/orchestrator/head_events.rs` — **the only file this issue edits.** The trigger
  point in `coordinator/mod.rs` was scaffolded by ARCH-3i as
  `wait_for_attestation_or_head(current_slot, &self.head_gate)`, replacing the phase-2 wait at
  `coordinator/mod.rs:427` (§5 hotspot table; merge order 3i → 3l → 3m).

**Implementation approach.**
1. Implement the race: `tokio::select!` over the 1/3-slot timer (`time_until_attestation`, unchanged
   arithmetic) and `head_gate.rx.changed()`. Whichever fires first proceeds to phase 2. **The timer
   arm alone is sufficient for correctness** — if the bridge is empty forever, behaviour is exactly
   today's.
2. **Duplicate suppression is required**: record the slot for which the attestation phase has already
   been entered and ignore any further event for that slot, so an early event cannot produce a second
   attestation.
3. Ignore events for a slot other than `current_slot` (a reorg or a lagging BN must not pull phase 2
   forward for the wrong slot).
4. Emit a labelled trigger counter `rvc_attestation_trigger_total{source="timer"|"head_event"}` so
   the optimisation's real hit rate is measurable — and so a silent regression to timer-only is
   visible rather than invisible.
5. **No `error!` on drop or failover, no failure metric, no alert** — the drop counter from 3l stays
   labelled expected.

**TDD test plan (RED first).**
1. **RED — `test_early_head_event_triggers_the_attestation_sooner`**: deliver a head event at t=1 s
   with a 4 s timer; assert the attestation phase is entered at ~1 s. Red against 3i's no-op gate
   (timer-only), which is the correct RED baseline.
2. **The C7 acceptance test — `test_dropping_every_head_event_still_attests_on_the_timer`**: a bridge
   that discards every event; assert **every** attestation still happens, on the timer, for N slots.
   This is the criterion that makes "events are an optimisation" enforceable rather than aspirational.
3. `test_early_head_event_does_not_produce_a_duplicate_attestation`: event **and** timer both fire;
   exactly one attestation per slot.
4. `test_head_event_for_another_slot_is_ignored`.
5. `test_no_error_log_or_failure_metric_on_drop_or_failover` — assert with `tracing-test` that no
   `error!` is emitted and the failure counters are untouched (C7 by construction, not by convention).

**Acceptance criteria.**
- [x] Attestations trigger on "1/3-slot timer **or** head event, whichever first"; the timer remains
      authoritative.
- [x] Dropping **every** SSE event still yields every attestation on the timer.
- [x] An early event fires the attestation sooner, with **no duplicate**.
- [x] Events for other slots are ignored.
- [x] No `error!`, no failure metric on drop or failover; the drop counter is labelled expected.
- [x] Trigger source is counted with a label, so the optimisation is measurable.
- [x] The change touches only `head_events.rs` (no cross-stream conflict) and is revertible in one
      commit.

---


### ARCH-3n — OR-merge doppelganger liveness across healthy BNs

**Points:** 2 · **Type:** feature · **Priority:** P1 · **Blocked by:** — · **Blocks:** — ·
**Stream:** B · **Scope:** 1–1.5 days · **Requirement:** ARCH-P1-13 · **Constraints:** C9 (the
doppelganger gate must not weaken), C5 (untouched — see below)

**Context — `[review-carried]`, and the branch is now decided.** The project plan sizes this as a
three-way branch pending in-issue verification (A-11, A-P12). **The verification is done and the
first branch applies (A-3.15): the residual reproduces and the fan-out primitive is reusable.**

- The residual is documented at `crates/rvc/src/liveness_loop.rs:17-24` — *"Liveness uses bn-manager
  `query_first` … there is **no cross-BN OR-merge of `is_live`**. A lagging or wrong primary that
  answers all-not-live suppresses secondaries that might report live activity."* (**VD-34**: the file
  is in `crates/rvc/src/`, **not** `crates/doppelganger/` as the PRD and project plan cite.)
- `post_validator_liveness` routes through `query_first` (`bn-manager/src/manager.rs:1289-1292`).
- `broadcast_inner` (`:757-780`) is the existing fan-out primitive, returning a `BroadcastResult<T>`
  over all clients with per-attempt spans.

So this is **1–2 days**, not the 3–4-day "new primitive" branch, and the phase estimate is not
revised on this item.

**The one wiring trap, named.** `LivenessObservationLoop` holds `beacon: Arc<dyn BeaconNodeClient>`
(`liveness_loop.rs:70`). An **inherent** method on `BnManager` is therefore unreachable through the
trait object. Add the merged call as a **role-trait method** instead, so `BnManager` implements the
merge and `BeaconClient` (a single BN) implements it as a trivial self-delegation — the passthrough
macro at `manager.rs:1298-1301` gives a compile error until the method is listed, which is the
desired forcing function. Changing the loop's field type to a concrete `Arc<BnManager>` is the
rejected alternative: it would couple the doppelganger loop to the multi-BN implementation and break
its single-BN tests.

**Files.**
- `crates/bn-manager/src/manager.rs` — merged liveness method + passthrough list entry.
- `crates/rvc/src/liveness_loop.rs` — call the merged method; **rewrite the `:17-24` residual note**
  (the PRD requires the note be removed or rewritten, not left contradicting the code).

**Implementation approach.** Fan out `post_validator_liveness` over all healthy BNs via
`broadcast_inner`; merge per validator index with a logical **OR on `is_live`** — any BN reporting
live wins. Errors and non-responses contribute **nothing** (they must not be read as "not live"), and
if *every* BN fails the call returns `Err` so the loop's existing fail-closed behaviour
(`liveness_loop.rs:24`, "loop still fail-closes on errors/incomplete samples") is preserved
unchanged. **C5 is not touched here**: this issue changes how liveness is *observed*, not the
`stop_monitoring` / `cancel_monitoring` teardown contract, which stays entirely with Phase 7's
ADR-015 and gate G-6.

**TDD test plan (RED first).**
1. **RED — `test_merged_liveness_reports_live_when_any_bn_says_live_fail_safe`**: BN A returns
   `is_live = false`, BN B returns `is_live = true` for the same index; assert the merged verdict is
   **live-detected**. The fail-safe direction is stated in the test name, as ARCH-P1-13 requires. Red
   at HEAD — `query_first` takes A's answer and stops.
2. `test_merged_liveness_ignores_a_failing_bn`: A errors, B says not-live → verdict not-live (an
   error is not evidence of liveness *or* of safety).
3. `test_merged_liveness_errors_when_every_bn_fails` → the loop's fail-closed path still fires.
4. `test_single_bn_client_merged_liveness_delegates_to_itself` — the `BeaconClient` impl.

**Acceptance criteria.**
- [x] One BN reporting "live" and another "not live" yields a **live-detected** merged verdict, with
      the fail-safe direction explicit in the test name.
- [x] Errors contribute nothing; all-fail still returns `Err` and the loop still fail-closes.
- [x] The merged call is reachable through `Arc<dyn BeaconNodeClient>` (role-trait method, passthrough
      list updated).
- [x] The documented residual at `liveness_loop.rs:17-24` is rewritten to describe the new behaviour.
- [x] No change to `stop_monitoring` / `cancel_monitoring` semantics (C5 remains Phase 7's).
- [x] Existing doppelganger tests green; no new unbounded channel or raw spawn.

---


---

## 7. Constraint Coverage Map (C1–C10)

Every constraint gets a disposition. A blank is a defect, so non-applicable constraints carry a
one-line reason rather than silence.

| ID | Disposition in Phase 3 | Where |
|---|---|---|
| **C1** — retain-on-ambiguity vs lock shortening | **Not applicable.** No issue here touches `crates/slashing/` or `crates/signer/src/core.rs`; the slashing critical section is Phase 5 (ADR-005). Phase 3 changes *when* the loop reaches the signer, never the staging protocol. If any issue here finds itself editing `stage.rs`, it is out of scope and stops | — |
| **C2** — audit-log emission inside the mutex | **Not applicable / already discharged upstream.** Phase 1's ARCH-P0-9 moves emission outside the mutex (`slashing/src/scoped.rs:69-75`, `:102-107`); Phase 3 adds no logging inside any lock. The new metrics (3d, 3e, 3j, 3l, 3m) are all emitted from the orchestrator task, holding no DB guard | — |
| **C3** — figment `Env` provider forbidden | **Not applicable.** Phase 3 introduces exactly one new configurable value (3j's 500 ms deadline) and declares it as a **named constant with a stated default**, read from `Config`, never from an env var. Phase 4 owns config consolidation and G-3 | 3j |
| **C4** — keystore-less key admission | **Not applicable.** Key admission is Phase 1 (ARCH-P0-5 / ADR-007). Phase 3 only *observes* the resulting `key_gen` notification: `apply_key_gen_cache_invalidation` (`coordinator/mod.rs:606-612`) is read, not changed — and C4's raw-`SecretKey` admission is precisely what makes 3j's post-`key_gen` cold-cache case reachable in production | 3j (consumer) |
| **C5** — KM-2 teardown contract | **Explicitly out of scope, and said so in the issue.** ARCH-3n changes liveness *observation* only; `stop_monitoring` vs `cancel_monitoring` (graceful removal vs abort) stays with Phase 7's ADR-015 behind gate G-6 | 3n |
| **C6** — cold-cache pre-proposal fetch | **Binding, owned by a dedicated issue.** Bounded 500 ms proposer-duty fetch covering both cold origins (boot **and** post-`key_gen`); "propose only if cached" rejected by name; acceptance test fails if the check is skipped | **3j**, asserted in 3k |
| **C7** — SSE drops are normal | **Binding.** Timer stays authoritative; drop counter labelled expected; no `error!`, no failure metric, no alert on drop or failover; the drop-every-event test is an acceptance criterion, not a nice-to-have | **3l**, **3m** |
| **C8** — healthz removal is operator-visible | **Not applicable.** Healthz deprecation is Phase 0 (16a) and its removal Phase 7 (16b); Phase 3 removes no operator-visible surface. The new metrics are additive | — |
| **C9** — preserve the keep-list | **Live, per anchor:** anchor 1 (3g is a **new** file in the scanner idiom; no existing gate file modified). Anchor 3 (**KAT-first**: the matcher is a *suffix* test, `kat_policy.rs:232-234`; every new test name avoids `_root`/`tree_hash`/`signing_root`, and `test_messages_and_contributions_share_head_root` keeps its exact name because it is on the shrinking-only `EXEMPTIONS` list at `:125-128` — **`EXEMPTIONS` neither grows nor is renamed in this phase**). Anchor 5 (single signing gate — untouched; no issue adds a signing surface). Anchor 6 (**zero unbounded channels**: 3h adds none, 3l adds a bounded `watch`; the divergence from ADR-013's "no channel" wording is recorded as **VD-33**). Anchor 7 (`spawn_blocking` is never scanned or added to a ban list here) | 3b–3g, 3h, 3l, 3m |
| **C10** — archive before delete for untracked trees | **Not applicable to this phase, and deliberately restated so it is not forgotten.** The four untracked trees (`crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`, `crates/rvc/src/commands/`) have **no git object behind them**, so `rm` is unrecoverable; Phase 0's ARCH-P0-1 archives to a named branch **and** tarball, verifies by restore-and-diff, then deletes. **No issue in Phase 3 deletes any file**, and by the time this phase starts G-1 enforces the absence mechanically | — |


## 8. Exit Criteria Checklist

A literal superset of the project plan's Phase 3 milestone and of the PRD acceptance criteria for
ARCH-P0-8, ARCH-P0-3, ARCH-P1-12 and ARCH-P1-13. Nothing here is a paraphrase; each box names the
issue that discharges it.

- [ ] **M1 = 0 missed proposals** with duty fetches stalled the full **60 s** — plus the verified
      **80 s** envelope (**VD-35**). *(3k)*
- [ ] **M2 p99 ≤ 1,000 ms warm cache / ≤ 2,000 ms cold cache**, measured with Phase 0's instrument
      across all three scenarios (warm; cold post-boot; cold after a `key_gen` bump). *(3k)*
- [ ] With a 404-on-current-slot BN, sync-committee **messages *and* contributions** are produced.
      *(3c, 3e)*
- [ ] A metric counts any remaining **"skipped: no head root"**, labelled for both messages and
      contributions. *(3e)*
- [ ] **H-4 gains a test it never had** — a wrong-ancestor block is rejected with
      `ParentRootMismatch` — and it is **RED before the fix**, demonstrated locally with the output in
      the PR. *(3e)*
- [ ] **H-5's existing test stays green** and byte-identically named:
      `test_messages_and_contributions_share_head_root` (`sync_committee.rs:558`, on the
      shrinking-only `EXEMPTIONS` list at `kat_policy.rs:125-128`). *(3c, 3f)*
- [ ] `maybe_propose_block` is **entered within budget** in three scenarios, and the **cold-cache path
      does propose when a duty exists** — the test fails if the check is skipped (C6). *(3j, 3k)*
- [ ] **Dropping every SSE event still yields every attestation on the timer.** *(3m)*
- [ ] **An early head event fires the attestation sooner, with no duplicate.** *(3m)*
- [ ] **No `error!` and no failure metric on SSE drop or failover**; the drop counter is labelled
      expected-path. *(3l, 3m)*
- [ ] **Behaviour-contract tests show *which* duties are performed is unchanged and only *when*
      changed.** *(3i)*

Plus the phase-local gates and the standing invariants:

- [ ] **G-8 green** on `develop`, RED demonstrated against the pre-3f tree, running under the Phase-0
      `arch-gates` job; no `with_get_block_root` stub returns `Ok` unconditionally for a
      slot-qualified id, and none returns an error for every id (**VD-36**). *(3f, 3g)*
- [ ] **ARCH-P1-13:** one BN "not live" + one "live" merges to **live-detected**; the documented
      residual at `crates/rvc/src/liveness_loop.rs:17-24` is rewritten. *(3n)*
- [ ] `EXEMPTIONS` unchanged — nothing added, nothing renamed (C9 anchor 3).
- [ ] No new `unbounded_channel`; no new raw `tokio::spawn` (G-4 stays green); `spawn_blocking` not
      added to any ban list (C9 anchors 6, 7).
- [ ] Project-plan §2 green build: `cargo fmt --all -- --check`,
      `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings`,
      `cargo build --workspace`, `cargo nextest run --workspace`.
- [ ] Each issue is separately revertible (NFR-4); ARCH-3m in particular reverts in one commit
      touching one file.
- [ ] Post-change M1/M2 numbers are recorded **as files in `plan/architecture-2026-08-12/`**, next to
      Phase 0's baselines.

