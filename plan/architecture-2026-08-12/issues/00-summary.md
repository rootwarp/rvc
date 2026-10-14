# Architecture Remediation — Cross-Phase Issue Summary

> Engineering-lead roll-up across the eight phase breakdowns of the rs-vc architecture-remediation
> initiative (baseline `develop` @ `0ae9a09`, v0.7.0). Each phase file is self-contained; this
> summary is the planning index — total scope, point totals, the **PRD requirement → issue** coverage
> table, the **C1–C10 constraint** coverage table, the calendars for one and two developers, and the
> execution order.
>
> Authoritative inputs: the eight phase files plus [`../prd.md`](../prd.md),
> [`../project-plan.md`](../project-plan.md), [`../architecture.md`](../architecture.md).
>
> Phase files: [Phase 0](00-phase-0.md) · [Phase 1](01-phase-1.md) · [Phase 2](02-phase-2.md) ·
> [Phase 3](03-phase-3.md) · [Phase 4](04-phase-4.md) · [Phase 5](05-phase-5.md) ·
> [Phase 6](06-phase-6.md) · [Phase 7](07-phase-7.md)
>
> **Headline:** **99 issues · 216 points · 8 phases.** **1 dev: 116–179 working days
> (≈ 23–36 weeks). 2 devs: 71–107 working days (≈ 14–21 weeks) — ~1.6×.** **No PRD requirement is without a
> covering issue**; four carry *partial* coverage and one of those four (ARCH-P2-5's second clause)
> is genuinely unowned — see *Requirement Coverage*.

---

## Estimation Approach

- **Point scale:** 1 (trivial) / 2 (small) / 3 (medium). **Target: every issue completable in 1–2
  days.** **No issue in any phase exceeds 3 points** — the 5-point band is unused by construction,
  and anything that sized larger was split (ADR-005's redesign became eight issues; ADR-008's
  collapse became nine).
- **Day-rate is a range, not a constant: ~1 pt ≈ 0.5–1.0 working day**, and it differs per phase
  (Phase 1 pins 0.5–0.75 d/pt in its A-1.1; Phase 5 runs the full 0.5–1.0 because ADR-005's proof
  surfaces carry real variance). **The calendars below are the sum of the phase files' own stated
  durations — do not recompute them as 216 × a global rate**, which produces a third number that
  belongs to nobody.
- **Points cover** coding + tests + review + integration for that change. Review *turnaround* and CI
  cycles are not modelled (project-plan §5: add ~10–15 %).
- **Grounded against HEAD.** Every phase file re-verified its claims by opening the cited
  `file:line`. **59 verification deltas** were found across the eight phases (counted, not asserted:
  `rg '^\| \*\*VD-' plan/architecture-2026-08-12/issues` → 9 · 7 · 6 · 7 · 8 · 7 · 8 · 7 for Phases
  0–7), of which **22 changed the work** rather than documenting it (5 · 2 · 2 · 3 · 2 · 2 · 3 · 3,
  each phase file's own count in its §*Verification deltas*). They
  are the reason the estimator's total exceeds the project plan's; see the gap column below.
- **Two streams (A/B)** are available for two developers, drawn so each owns disjoint files. The
  default plan is **single-stream** (project-plan A-P9); the stream column is an overlay, not a
  requirement.
- **Gate-before-change is the sequencing thesis** (project-plan §1.1): no behavioural change ships
  before the artefact that would detect its regression exists. Three gates (G-1, G-4, G-7/G-8)
  structurally cannot precede their change and land in the same PR *after* it, with RED demonstrated
  locally.

---

## Phase Table

| File | Phase | PRD requirements covered | Issues | Points | Plan est. (1 dev) | This estimate (1 dev) | Gap driver |
|------|-------|--------------------------|-------:|-------:|-------------------|-----------------------|------------|
| [00-phase-0.md](00-phase-0.md) | **0 — Ground truth**: archive, gate, measure, start the clock | P0-1, P0-2, P2-5 *(scan half)*, P2-6, P2-7, P2-9, P1-16a; M1/M2 instruments; `arch-gates` job | 13 | 21 | 7–11 d | **13–19 d** | **VD-E8** — D2 is a module-graph walker, all three harnesses are new builds, VD-E3 turns "tail hygiene" into a gate |
| [01-phase-1.md](01-phase-1.md) | **1 — Runtime honesty**: inert surfaces, one admission path, the live hazard | P0-9, P0-5, P0-7, P0-6, P1-1; ADR-009 *(no PRD ID)* | 13 | 28 | 13–19 d | **14–21 d** | **VD-E2** — ADR-006's "`scoped.rs` only" bound is unsatisfiable on the success path; four `crates/signer` call sites must change |
| [02-phase-2.md](02-phase-2.md) | **2 — Task topology**: an executor, a spawnable orchestrator, a real shutdown | P1-4, P0-4 | 11 | 21 | 8–13 d | **11–19 d** | 7 `?Send` sites (not 6), a 4th stale allow, G-4's path rule (VD-2c), **VD-2e**'s cross-crate keymanager edit |
| [03-phase-3.md](03-phase-3.md) | **3 — Slot ordering**: split the context, then propose first | P0-8, P0-3, P1-12, P1-13 | 14 | 30 | 11–17 d | **15–23 d** | **VD-32** (the wait-window move does not compile — needs an enabler), **VD-33** (ADR-013 needs a bridge), **VD-31** (no SSE subscriber runs in production) |
| [04-phase-4.md](04-phase-4.md) | **4 — Config consolidation**: gate the env rule, then collapse | P1-3, P1-2 (+ P1-1 retirement) | 12 | 29 | 11–16 d | **15–21 d** | **VD-4.1** — a *sixth* hand-maintained site (the `ConfigWire` flat/nested shim, 31 legacy keys) that ADR-008 cannot simply delete |
| [05-phase-5.md](05-phase-5.md) | **5 — Slashing critical section**: measure, fold, then reserve-and-reconcile | P1-15a, P1-6, P1-5, P2-2, P2-1 | 15 | 39 | 18–26 d | **20–39 d** | Three proof surfaces are switchover **gates**, not follow-ups; **VD-5.1** splits the fold; **VD-5.2** makes M3's window a decision |
| [06-phase-6.md](06-phase-6.md) | **6 — Layer taxonomy & seam cleanup**: Base/Infra with teeth | P1-8, P1-9, P1-10, P2-3 | 8 | 19 | 9–14 d | **10–15 d** | **VD-6-3** adds a decoupling prerequisite; **VD-6-6** — the metrics-conformance gate ARCH-P2-3 is accepted against does not exist |
| [07-phase-7.md](07-phase-7.md) | **7 — Fork & scale readiness** | P1-11, P1-14, P1-7, P1-15b, P1-16b, P2-4, P2-8 | 13 | 29 | 14–20 d | **18–22 d** | **VD-7C** — the `Wire*` deletion trigger is unsatisfied at HEAD, so a spike + a conditional branch; **VD-7D** — DVT registration breaks an existing enumeration test |
| | **Total** | **9 P0 · 16 P1 · 9 P2** | **99** | **216** | **91–136 d** | **116–179 d** | **+25 / +43 d** |

**The gap is stated, not retrofitted.** It is +27 % / +32 % on the project plan's envelope, and every
phase names its own driver above rather than absorbing it by shrinking points. Two phases moved for
reasons the upstream documents could not have known: Phase 0 (the estimator opened the files the plan
assumed) and Phase 5 (the proof surfaces became exit gates rather than follow-ups). Nothing in the
gap is buffer.

---

## Calendar — one developer

Phases run in the dependency order below; the figures are each phase file's own stated single-dev
duration.

| Phase | Days | Cumulative |
|---|---|---|
| 0 — Ground truth | 13–19 | 13–19 |
| 1 — Runtime honesty | 14–21 | 27–40 |
| 2 — Task topology | 11–19 | 38–59 |
| 3 — Slot ordering | 15–23 | 53–82 |
| 4 — Config consolidation | 15–21 | 68–103 |
| 5 — Slashing critical section | 20–39 | 88–142 |
| 6 — Layer taxonomy | 10–15 | 98–157 |
| 7 — Fork & scale readiness | 18–22 | **116–179** |

**Single developer, all eight phases: 116–179 working days ≈ 23–36 calendar weeks.**

- **The `ARCH-P0-*` commitment closes at the end of Phase 3**: Phases 0–3 = **53–82 d ≈ 11–17
  weeks**. (Phases 1 and 3 also carry P1 items — P1-1, P1-12, P1-13 — that travel with them for
  sequencing reasons.)
- **P0 + P1 closes at the end of Phase 7** (P1-11/14/7/15b/16b live there).
- Assumes no hard-fork window intersecting the plan (A-P10) and one release per phase boundary
  (A-P11 — required for C8's deprecation window; **ARCH-P1-16b in Phase 7 is blocked by a
  release count, not by effort**).

---

## Calendar — two developers

**Model (stated once, because the answer depends on it).** Stream B is dedicated to the two phases
that hang off the critical path — **Phase 5 (39 pts) then Phase 6 (19 pts)** — which is where the
entire speed-up comes from (project-plan §10). **Consequence: Stream A absorbs the B-stream issues of
Phases 2, 3 and 4** (P2/ARCH-2j, 2k; P3/ARCH-3l, 3m, 3n; P4/ARCH-4a, 4b, 4c, 4k, 4l), so those
phases are costed at or near their single-dev figure, not their in-phase 2-dev figure.

| Link (Stream A critical path) | Adjusted days | Note |
|---|---|---|
| Phase 0 (A = 13 pts; B takes the M1/M2 instruments + healthz warn + doc tail) | 8–13 | The 1a → 1b → 2a → 2b → 3 chain is one person's PR sequence (A-E1) |
| Phase 1 minus 1A-cluster (A = 22 pts) | 11–17 | B does ARCH-1a/1b/1c (6 pts, 3–5 d) then **departs to Phase 5's 5A** |
| Phase 2 (A absorbs 2j/2k) | 11–19 | B is on Phase 5 |
| Phase 3 (A absorbs 3l/3m/3n) | 15–23 | B is on Phase 5 |
| Phase 4 (A absorbs 4a/4b/4c/4k/4l) | 15–21 | B is on Phase 5 tail → Phase 6 |
| Phase 7 — **both streams**, so the phase's own 2-dev figure applies | 11–14 | A's half is 13 pts (≈ 8–10 d); B's half is 16 pts (≈ 10–12 d), so **B binds** |
| **Two-stream critical path** | **71–107 d ≈ 14–21 weeks** | 116/71 ≈ **1.63×**, 179/107 ≈ **1.67×** |

**~1.6× is corroboration, not coincidence.** The project plan derives the same multiplier
independently (§9/§10) from a different set of per-phase numbers. Two derivations landing on the same
ratio is the strongest available check on this arithmetic.

**Stream B's load fits inside that window**: Phase 1's 6 pts (3–5 d) + Phase 5 as a solo phase
(20–39 d) + Phase 6 as a solo phase (10–15 d) + Phase 7's B half (16 pts, ≈ 10–12 d) ≈ **43–71 d**
against Stream A's 71–107 d. B has float; A does not.

**The number this is *not*.** Summing the eight phase files' in-phase 2-dev figures gives **83–130
d** — that figure **double-books Stream B**, because it assumes a dedicated second developer inside
every phase *and* Phase 5/6 running in parallel. It is recorded here only so nobody re-derives it and
believes it.

**Why the speed-up is sub-linear.** Stream A is a genuine dependency chain — `G-2 → ADR-009 →
ADR-008`, `ADR-002 → ADR-004's harness`, `ADR-003 → ADR-004`, `M1/M2 → ADR-004`, `0F → 7E` — and none
of those links dissolve by adding people. A third developer buys almost nothing.

---

## Issue Index

**ID convention (read this before using the table).** Phases 0 and 1 number their issues
`ARCH-1a`, `ARCH-2a`, `ARCH-3` … locally, while Phases 2–7 use phase-scoped numbering
(`ARCH-2a` = Phase 2). **The bare IDs therefore collide across phases** — `ARCH-2a` and `ARCH-2b`
exist in Phases 0, 1 **and** 2; `ARCH-7a/7b/7c` in Phases 0 and 7; `ARCH-1a/1b` and `ARCH-3` in 0 and
1; `4a/4b`, `5a/5b`, `6a/6b` in Phase 1 versus Phases 4/5/6. The `P<n>/` prefix below is a **display
convention for this index only — it is not a rename**, and the phase files are unchanged.
**Recommended pre-board-import action:** renumber Phase 0 to an `ARCH-0*` series and Phase 1 to a
phase-scoped series, then drop the prefix. Do not import into a tracker before that, or two issues
will collapse onto one key.

Scope is each phase file's stated per-issue figure where it gives one (Phases 1, 3, 5); elsewhere it
is derived from points at that phase's own rate (1 pt = 0.5–1 d, 2 pts = 1–1.5 d, 3 pts = 1.5–2.5 d)
and marked *(d)*.

| Issue | Title | Pts | Scope | Stream | Blocked by |
|-------|-------|----:|-------|--------|------------|
| **P0/ARCH-1a** | Archive the four orphan trees (branch + tarball) and verify by restore-and-diff | 2 | 1–1.5 d *(d)* | A | — |
| **P0/ARCH-1b** | Delete the four orphan trees in a separate commit referencing the archive ref | 1 | 0.5–1 d *(d)* | A | P0/ARCH-1a |
| **P0/ARCH-2a** | G-1 detector **D1** — every `crates/*`/`bin/*` dir with a `Cargo.toml` is a member | 1 | 0.5–1 d *(d)* | A | P0/ARCH-1b |
| **P0/ARCH-2b** | G-1 detector **D2** — no uncompiled `.rs` under a member's `src/` | 3 | 1.5–2.5 d *(d)* | A | P0/ARCH-1b |
| **P0/ARCH-3** | Delete `crates/sync-service` (member, alias, `CLASSIFICATION`, `DOMAIN_PACKAGES`, regenerate) | 1 | 0.5–1 d *(d)* | A | P0/ARCH-2a |
| **P0/ARCH-4** | Add the `arch-gates` CI job | 1 | 0.5–1 d *(d)* | A | — |
| **P0/ARCH-5** | `cargo machete` in CI + remove `bin/rvc`'s unused workspace deps | 2 | 1–1.5 d *(d)* | A | P0/ARCH-4 |
| **P0/ARCH-6** | Docs-freshness scan with a one-entry shrinking-only exemption list | 2 | 1–1.5 d *(d)* | A | P0/ARCH-4 |
| **P0/ARCH-7a** | M2 instrument — slot-phase-0 start-offset histogram | 2 | 1–1.5 d *(d)* | B | — |
| **P0/ARCH-7b** | M1 harness — latency-injecting BN mock + missed-proposal measurement | 3 | 1.5–2.5 d *(d)* | B | P0/ARCH-7a |
| **P0/ARCH-7c** | Record the M1/M2 baselines as files in `plan/architecture-2026-08-12/` | 1 | 0.5–1 d *(d)* | B | P0/ARCH-7b |
| **P0/ARCH-8** | Healthz deprecation notice + probe-migration check (**no removal**) | 1 | 0.5–1 d *(d)* | B | — |
| **P0/ARCH-9** | Stale doc comments + the `signer-registry` shipped-fix TODO | 1 | 0.5–1 d *(d)* | B | — |
| **P1/ARCH-1a** | `PendingAudit` hand-off in `scoped.rs` + thread-bounded RED deadlock harness | 2 | 1–1.5 d | B | — |
| **P1/ARCH-1b** | Migrate the four `crates/signer` stage call sites; deadlock test goes GREEN | 2 | 1–1.5 d | B | P1/ARCH-1a |
| **P1/ARCH-1c** | **G-7** `audit_log_scope.rs` scanner (both paths) + synthetic RED | 2 | 1–1.5 d | B | P1/ARCH-1a |
| **P1/ARCH-2a** | Relocate the secret-provider refresh spawn (**VD-E1** prerequisite) | 2 | 1–1.5 d | A | — |
| **P1/ARCH-2b** | `KeyAdmissionService` seam: `AdmissionSource`/`Outcome`/`Error` + `admit` | 3 | 1.5–2 d | A | P1/ARCH-2a |
| **P1/ARCH-2c** | Switch both admission callers; liveness-sampling test proves the key leaves `Pending` | 3 | 1.5–2 d | A | P1/ARCH-2b |
| **P1/ARCH-3** | Live validator counts in the monitoring push (total loaded vs. active/enabled) | 2 | 1–1.5 d | A | — *(soft: P1/ARCH-2c)* |
| **P1/ARCH-4a** | `ValidatorStore::apply_default_update` + `config_url` → store mapping (**VD-E3/E4**) | 2 | 1–1.5 d | A | — |
| **P1/ARCH-4b** | Wire the proposer-config apply callback; wiremock rotation + negative tests | 2 | 1–1.5 d | A | P1/ARCH-4a |
| **P1/ARCH-5a** | **G-2** `config_drift.rs` clause (ii): seam-α scanner, non-vacuity, synthetic RED | 3 | 1.5–2 d | A | — |
| **P1/ARCH-5b** | **G-2** clauses (iii) `UNVALIDATED` + (iv) `CLAP_DEFAULT_CLOBBERS` | 2 | 1–1.5 d | A | P1/ARCH-5a |
| **P1/ARCH-6a** | **Spike:** run the ADR-009 precedence probe and record the verdict | 1 | 0.5 d | A | — |
| **P1/ARCH-6b** | ADR-009 fix: nine clap fields → `Option<T>`; `CLOBBERS` → empty | 2 | 1–1.5 d | A | P1/ARCH-5b, P1/ARCH-6a |
| **P2/ARCH-2a** | ADR-002 spawnability probe — the verdict is the deliverable | 1 | 0.5–1 d *(d)* | A | — |
| **P2/ARCH-2b** | Remove `?Send` at 7 sites, add the `Send + Sync` supertrait, delete 4 stale allows | 2 | 1–1.5 d *(d)* | A | P2/ARCH-2a |
| **P2/ARCH-2c** | Delete the `LocalSet`/`spawn_local` scaffold — the spawnability regression pin | 1 | 0.5–1 d *(d)* | A | P2/ARCH-2b |
| **P2/ARCH-2d** | `TaskExecutor` core: `register` primitive, `spawn`, `register_opt`, panic monitor | 3 | 1.5–2.5 d *(d)* | A | — |
| **P2/ARCH-2e** | Tiered drain, `TierBudget`, `ShutdownOutcome`, `ShutdownReason` escalation | 2 | 1–1.5 d *(d)* | A | P2/ARCH-2d |
| **P2/ARCH-2f** | Two task metric series and nothing else | 1 | 0.5–1 d *(d)* | A | P2/ARCH-2d |
| **P2/ARCH-2g** | Migrate the 9 in-scope production spawn sites onto the executor | 3 | 1.5–2.5 d *(d)* | A | P2/ARCH-2d, 2e, 2f, **P2/ARCH-2j** *(cross-stream)* |
| **P2/ARCH-2h** | Spawn and join the orchestrator; retire the inline `select!` and the sleep (**M10**) | 3 | 1.5–2.5 d *(d)* | A | P2/ARCH-2b, 2e, 2g |
| **P2/ARCH-2i** | Remove the in-async `process::exit`; preserve and assert EXIT_* 10/11/13/14 | 1 | 0.5–1 d *(d)* | A | — |
| **P2/ARCH-2j** | Keymanager API graceful shutdown (**VD-2e**: cross-crate, `keymanager-api/src/server.rs`) | 2 | 1–1.5 d *(d)* | B | — |
| **P2/ARCH-2k** | **G-4** `raw_spawn.rs` — path-aware scanner, allow-list, synthetic RED (**M8**) | 2 | 1–1.5 d *(d)* | B | P2/ARCH-2g *(to land, not to build)* |
| **P3/ARCH-3a** | **Spike:** pin BN `get_block_root(<current slot>)` behaviour | 1 | 0.5–1 d | A | — |
| **P3/ARCH-3b** | Spec-honest `with_get_block_root` mock primitive | 2 | 1–1.5 d | B | — |
| **P3/ARCH-3c** | Split `SlotContext` → `parent_root` + `head_root` | 3 | 2 d | A | P3/ARCH-3a |
| **P3/ARCH-3d** | Walk back over skipped slots + counted terminal | 2 | 1–1.5 d | A | P3/ARCH-3c |
| **P3/ARCH-3e** | Activate H-4 + sync-skip counter + doc corrections | 2 | 1–1.5 d | A | P3/ARCH-3c, 3d |
| **P3/ARCH-3f** | Correct all seven `with_get_block_root` stubs | 2 | 1–1.5 d | A | P3/ARCH-3b, 3c |
| **P3/ARCH-3g** | **G-8** mock-fidelity gate (`mock_fidelity.rs`) | 2 | 1–1.5 d | A | P3/ARCH-3f |
| **P3/ARCH-3h** | Make the next-slot wait window able to host work (**VD-32** enabler) | 2 | 1–1.5 d | A | — |
| **P3/ARCH-3i** | Proposal-first: move both fetches + epoch prep into the window | 3 | 2 d | A | P3/ARCH-3d, 3h |
| **P3/ARCH-3j** | Bounded 500 ms cold-cache pre-proposal fetch (**C6**) | 2 | 1–1.5 d | A | P3/ARCH-3i |
| **P3/ARCH-3k** | M1/M2 acceptance runs + behaviour-contract pin | 2 | 1–1.5 d | A | P3/ARCH-3f, 3j |
| **P3/ARCH-3l** | Wire the SSE subscriber + bounded head-event bridge (**VD-31/33**) | 3 | 2 d | B | — |
| **P3/ARCH-3m** | Head-event attestation trigger, timer authoritative | 2 | 1–1.5 d | B | P3/ARCH-3i, 3l |
| **P3/ARCH-3n** | OR-merge doppelganger liveness across healthy BNs | 2 | 1–1.5 d | B | — |
| **P4/ARCH-4a** | **G-3** scanner core: `env::var` call sites + `*_ENV` constants, non-vacuity | 3 | 1.5–2.5 d *(d)* | B | — |
| **P4/ARCH-4b** | **G-3** four-class allow-list + `DYNAMIC_READS` table + RED matcher tests | 3 | 1.5–2.5 d *(d)* | B | P4/ARCH-4a |
| **P4/ARCH-4c** | Wire G-3 into `arch-gates`; source-scoped figment-absence assertion | 1 | 0.5–1 d *(d)* | B | P4/ARCH-4b |
| **P4/ARCH-4d** | Freeze the TOML wire surface: corpus + round-trip parity harness *(binding: before 4f–4h)* | 3 | 1.5–2.5 d *(d)* | A | — |
| **P4/ARCH-4e** | `rvc-config` scaffold: `ConfigSource`, `ConfigError` provenance, `Config::load` | 2 | 1–1.5 d *(d)* | A | — |
| **P4/ARCH-4f** | Migrate the 4 clean sections (tracing, keymanager, grpc_signer, monitoring) | 3 | 1.5–2.5 d *(d)* | A | P4/ARCH-4c, 4d, 4e |
| **P4/ARCH-4g** | Migrate the 4 partial sections with field aliases | 3 | 1.5–2.5 d *(d)* | A | P4/ARCH-4f |
| **P4/ARCH-4h** | Create the 5 missing sections for the 28 bare knobs | 3 | 1.5–2.5 d *(d)* | A | P4/ARCH-4g |
| **P4/ARCH-4i** | Delete `CliOverrides` + `From<StartArgs>` + `merge_with_cli`; `Config::load(file, cli)` | 3 | 1.5–2.5 d *(d)* | A | P4/ARCH-4f, 4g, 4h |
| **P4/ARCH-4j** | Promote the 4 BN timeout knobs to `Config` (65 → 69) | 2 | 1–1.5 d *(d)* | A | P4/ARCH-4i |
| **P4/ARCH-4k** | Retire G-2 clauses (i)/(ii) with seam α; assert (iv) empty, keep (iii) | 2 | 1–1.5 d *(d)* | B | P4/ARCH-4i, 4j |
| **P4/ARCH-4l** | Operator release note: `--help` change, TOML spelling, flat keys deprecated | 1 | 0.5–1 d *(d)* | B | P4/ARCH-4i, 4j |
| **P5/ARCH-5a** | Load harness: latency-injecting BLS backend + concurrent `signer-server` driver | 3 | 1.5–3 d | B | — *(entry E1)* |
| **P5/ARCH-5b** | **Spike:** M3 baseline run + tx-hold observation-window decision (**VD-5.2**) | 2 | 1–2 d | B | P5/ARCH-5a |
| **P5/ARCH-5c** | Fold `sign_nonslashable` ×2 and unify `DEFAULT_SIGN_TIMEOUT` | 3 | 1.5–3 d | B | — |
| **P5/ARCH-5d** | Fold the four slashable `body` closures into one `core.rs` staging consumer | 3 | 1.5–3 d | B | P5/ARCH-5c |
| **P5/ARCH-5e** | `reserve_block` / `reserve_attestation` + `CommittedReservation` (additive) | 3 | 1.5–3 d | A | — *(entry E3)* |
| **P5/ARCH-5f** | `reconcile_unsigned`: compensating delete, `inserted` guard, watermark-safety proof | 3 | 1.5–3 d | A | P5/ARCH-5e |
| **P5/ARCH-5g** | `PubkeyScopedDb::reserve_*` wrappers + commit-failure inject re-pointed | 2 | 1–2 d | A | P5/ARCH-5e, 5f |
| **P5/ARCH-5h** | **Proof surface 3** — concurrency proptest over interleaved reservations | 3 | 1.5–3 d | A | P5/ARCH-5f, 5g |
| **P5/ARCH-5i** | `SlashableSignSession::reserve_then_sign` — additive, no production caller | 2 | 1–2 d | B | P5/ARCH-5b, 5d, 5g |
| **P5/ARCH-5j** | **Proof surface 1** — the 14-cell error-class × policy matrix | 3 | 1.5–3 d | B | P5/ARCH-5i |
| **P5/ARCH-5k** | **Proof surface 2** — crash / cancellation injection at every await point | 3 | 1.5–3 d | B | P5/ARCH-5i |
| **P5/ARCH-5l** | **Switchover** — flip the call site, delete `stage_then_sign`, add the `stage_*` scanner | 3 | 1.5–3 d | B | P5/ARCH-5h, 5j, 5k |
| **P5/ARCH-5m** | M3 post-change run, rollback plan, honest VC-path ceiling record | 2 | 1–2 d | B | P5/ARCH-5l |
| **P5/ARCH-5n** | `ValidatorLockMap` eviction with a bounded map | 2 | 1–2 d | A *(slack)* | — |
| **P5/ARCH-5o** | Type the internal slashing records (rescoped by **VD-5.5**) | 2 | 1–2 d | A | P5/ARCH-5l |
| **P6/ARCH-6a** | `Layer::Base`/`Infra` split: 28 deliberate rows + `DOMAIN_PACKAGES` lock-step + doc regen | 3 | 1.5–2.5 d *(d)* | A | — *(Phase 0)* |
| **P6/ARCH-6b** | **G-5a** `layer_edges`: a `Base` package may depend only on `Base`, with synthetic RED | 2 | 1–1.5 d *(d)* | A | P6/ARCH-6a |
| **P6/ARCH-6c** | **G-5b** `layer_edges`: no `Infra` → `Domain` edge, with a mandatory synthetic RED | 2 | 1–1.5 d *(d)* | A | P6/ARCH-6a |
| **P6/ARCH-6d** | One `ProduceBlockResponse`: delete the twin and the adapter's field copy | 3 | 1.5–2.5 d *(d)* | B | — |
| **P6/ARCH-6e** | Decouple `CompositeSigner` from the concrete `RemoteSigner` (**VD-6-3** prerequisite) | 2 | 1–1.5 d *(d)* | B | — |
| **P6/ARCH-6f** | Extract `remote-signer-client`; `crypto` becomes `Base`-eligible | 3 | 1.5–2.5 d *(d)* | B | P6/ARCH-6a, 6e |
| **P6/ARCH-6g** | Move `is_aggregator` from `crypto` to `eth-types` | 1 | 0.5–1 d *(d)* | B | P6/ARCH-6f |
| **P6/ARCH-6h** | Decentralize `metrics::definitions` + build the missing conformance assertion | 3 | 1.5–2.5 d *(d)* | A | P6/ARCH-6a |
| **P7/ARCH-7a** | **G-6**: KM-2 teardown gate (`km2_lifecycle.rs`) | 3 | 1.5–2.5 d *(d)* | A | — |
| **P7/ARCH-7b** | Delete the unwired legacy doppelganger surface (**VD-7A**) | 2 | 1–1.5 d *(d)* | A | P7/ARCH-7a |
| **P7/ARCH-7c** | Retire `DoppelgangerGate` from the opt-out path | 2 | 1–1.5 d *(d)* | A | P7/ARCH-7a, 7b |
| **P7/ARCH-7d** | Remove the healthz-only tonic server and its `select!` arm | 2 | 1–1.5 d *(d)* | A | **C8 release window** (P0/ARCH-8) |
| **P7/ARCH-7e** | Dispose `grpc_address` / `grpc_port` by startup rejection | 2 | 1–1.5 d *(d)* | A | P7/ARCH-7d |
| **P7/ARCH-7f** | **Spike:** can the `Wire*` twins be collapsed at HEAD? (**VD-7C**) | 2 | 1–1.5 d *(d)* | B | — |
| **P7/ARCH-7g** | Write `docs/forks.md` (add-a-fork checklist) | 2 | 1–1.5 d *(d)* | B | — |
| **P7/ARCH-7h** | Collapse the `Wire*` twins **or** record the deferral | 3 | 1.5–2.5 d *(d)* | B | P7/ARCH-7f, 7g |
| **P7/ARCH-7i** | Register the DVT signing surface in `signer-registry` (**VD-7B/7D**) | 3 | 1.5–2.5 d *(d)* | B | — |
| **P7/ARCH-7j** | Enumeration gate under `--features dvt` + new CI step (**VD-P6**) | 2 | 1–1.5 d *(d)* | B | P7/ARCH-7i |
| **P7/ARCH-7k** | Honour `BnRole` in `broadcast_inner` (closes **M7 = 0**) | 2 | 1–1.5 d *(d)* | A | — |
| **P7/ARCH-7l** | Prune the KAT `EXEMPTIONS` list (removals only) | 1 | 0.5–1 d *(d)* | B | P7/ARCH-7h |
| **P7/ARCH-7m** | 200-key / 200 ms scale validation run, checked in | 3 | 1.5–2.5 d *(d)* | B | **Phase 5** (P5/ARCH-5a harness) |

**Spikes (5):** P1/ARCH-6a (ADR-009 precedence probe), P2/ARCH-2a (ADR-002 spawnability), P3/ARCH-3a
(BN 404 pin), P5/ARCH-5b (M3 observation window), P7/ARCH-7f (`Wire*` collapse feasibility).
**Each is the first task of its own work package** (A-A1). In every case the *verdict* is the
deliverable, so no downstream issue can stall on it.

---

## Requirement Coverage

Every requirement ID in `prd.md` — **9 P0 · 16 P1 · 9 P2 = 34** — with the issue(s) that close it.
**No requirement has zero issues.** Five rows are marked **PARTIAL** — four P2 rows plus ARCH-P1-1,
whose clause set shrank by design; read those, not the checkmarks.

| Requirement | Closed by | Phase | Status |
|---|---|---|---|
| **ARCH-P0-1** Archive-then-delete the untracked shadow trees | P0/ARCH-1a, P0/ARCH-1b | 0 | ✅ (C10's three-step sequence, split across two issues by design) |
| **ARCH-P0-2** Orphan-directory gate (D1 + D2) | P0/ARCH-2a, P0/ARCH-2b | 0 | ✅ |
| **ARCH-P0-3** Proposal-first slot ordering, bounded pre-proposal budget | P3/ARCH-3h, 3i, 3j, 3k | 3 | ✅ |
| **ARCH-P0-4** Spawnable, joinable orchestrator + real graceful shutdown | P2/ARCH-2a, 2b, 2c *(item 1)*, 2h *(item 2)*, 2j *(item 3)*, 2i + 2h *(item 4)*, 2e *(join)* | 2 | ✅ all four items owned |
| **ARCH-P0-5** One runtime key-admission path | P1/ARCH-2a, 2b, 2c | 1 | ✅ (sized as a **build**, per VD-5) |
| **ARCH-P0-6** Proposer-config URL updates applied, or the knob rejected | P1/ARCH-4a, 4b | 1 | ✅ (apply, per A-2/A-1.5) |
| **ARCH-P0-7** Monitoring push reports live validator counts | P1/ARCH-3 | 1 | ✅ |
| **ARCH-P0-8** Resolve the t=0 `SlotContext` question empirically, then fix | P3/ARCH-3a, 3b, 3c, 3d, 3e, 3f, 3g | 3 | ✅ (grew into the phase's largest cluster) |
| **ARCH-P0-9** Move audit-log emission outside the slashing DB mutex | P1/ARCH-1a, 1b, 1c | 1 | ✅ both paths; `stage.rs` byte-unchanged (A-12) |
| **ARCH-P1-1** Config-drift gate | P1/ARCH-5a, 5b (land) · P4/ARCH-4k (retire clauses i/ii with seam α) | 1, 4 | ⚠️ **PARTIAL by design — the clause set shrank.** Clause (i) is **dropped** (rustc already enforces it: `merge_cli_fields!` destructures exhaustively, `types.rs:934-936` — RVD-1); clause (iii) is **descoped** to validation coverage; clause (iv) is **new** and owns ADR-009. Phase 4's ARCH-4k then **retires (i)/(ii) with seam α**. The gate is *interim by construction* (ADR-008), and it delivers G5's real obligation — it is green **before** and **through** the collapse. Recorded rather than shown as a bare ✅ |
| **ARCH-P1-2** Extract `rvc-config`: one declaration per knob | P4/ARCH-4d, 4e, 4f, 4g, 4h, 4i, 4j, 4l | 4 | ✅ (reth `NodeConfig` model; figment rejected outright) |
| **ARCH-P1-3** `RVC_*` environment-variable allow-list gate | P4/ARCH-4a, 4b, 4c | 4 | ✅ (call-site scan, not a prefix scan — ADR-010) |
| **ARCH-P1-4** `TaskExecutor`: named, metered, panic-contained, joined spawns | P2/ARCH-2d, 2e, 2f, 2g, 2k | 2 | ✅ |
| **ARCH-P1-5** Slashing-DB critical-section redesign | P5/ARCH-5e, 5f, 5g, 5h, 5i, 5j, 5k, 5l | 5 | ✅ (three proof surfaces are switchover gates) |
| **ARCH-P1-6** Fold the non-slashable path + timeout constant into `core.rs` | P5/ARCH-5c, 5d | 5 | ✅ (split by VD-5.1: PRD-literal vs. expansive reading) |
| **ARCH-P1-7** Classify the DVT signing surface | P7/ARCH-7i, 7j | 7 | ✅ (targets `crates/signer-server/`, per VD-7B) |
| **ARCH-P1-8** `Base`/`Infra` layer split with two new gates | P6/ARCH-6a, 6b, 6c | 6 | ✅ (G-5a read as "Base may depend only on Base", VD-P5) |
| **ARCH-P1-9** One `ProduceBlockResponse` | P6/ARCH-6d | 6 | ✅ |
| **ARCH-P1-10** Extract the remote-signer HTTP client out of `crypto` | P6/ARCH-6e, 6f, 6g | 6 | ✅ (6e exists only because of VD-6-3) |
| **ARCH-P1-11** Retire the legacy doppelganger mechanism, carrying KM-2 | P7/ARCH-7a *(gate first)*, 7b, 7c | 7 | ✅ |
| **ARCH-P1-12** Head-event attestation triggering, timer authoritative | P3/ARCH-3l, 3m | 3 | ✅ |
| **ARCH-P1-13** OR-merge doppelganger liveness across healthy BNs | P3/ARCH-3n | 3 | ✅ (verification is the issue's first task — A-11) |
| **ARCH-P1-14** Delete the `Wire*` twins, write `docs/forks.md` | P7/ARCH-7f, 7g, 7h (+ 7l) | 7 | ✅ **conditional**: VD-7C shows the deletion trigger is unsatisfied at HEAD, so 7h is "collapse **or** record the deferral" |
| **ARCH-P1-15** Scale validation at the target validator count | **15a:** P5/ARCH-5a, 5b, 5m · **15b:** P7/ARCH-7m | 5, 7 | ✅ (split by D8: harness build ≠ validation run) |
| **ARCH-P1-16** Remove the healthz-only tonic server, with a migration path | **16a:** P0/ARCH-8 · **16b:** P7/ARCH-7d, 7e | 0, 7 | ✅ (split by D2; the gap between them is a **release count**, not effort) |
| **ARCH-P2-1** Evict `ValidatorLockMap` entries | P5/ARCH-5n | 5 | ✅ |
| **ARCH-P2-2** Type the slashing storage layer | P5/ARCH-5o | 5 | ⚠️ **PARTIAL** — see below |
| **ARCH-P2-3** Decentralize `metrics::definitions` | P6/ARCH-6h | 6 | ✅ (6h also **builds** the acceptance gate, which VD-6-6 shows does not exist) |
| **ARCH-P2-4** Prune the KAT `EXEMPTIONS` entries that are KAT-anchored | P7/ARCH-7l | 7 | ✅ removals only |
| **ARCH-P2-5** Docs-freshness scan **+ retire the mis-titled `docs/architecture.md`** | P0/ARCH-6 *(scan half only)* | 0 | ⚠️ **PARTIAL — second clause has no issue in any phase** |
| **ARCH-P2-6** `cargo-machete`/`cargo-udeps` in CI; remove `bin/rvc`'s unused deps | P0/ARCH-5 | 0 | ⚠️ **PARTIAL** — `cargo machete` only |
| **ARCH-P2-7** Delete `crates/sync-service` | P0/ARCH-3 | 0 | ✅ (four edit sites, not three — VD-E9) |
| **ARCH-P2-8** Honour `BnRole`/tier in `broadcast_inner`, + pre-slot BN health re-check | P7/ARCH-7k | 7 | ⚠️ **PARTIAL** — broadcast half only |
| **ARCH-P2-9** Fix stale doc comments and the `signer-registry` TODO | P0/ARCH-9 | 0 | ✅ |

### The partials, in order of how much they should worry you

(ARCH-P1-1's reduction is stated in its row above and is not repeated here — it is a *deliberate*
shrink with a reason per clause, not an unowned gap.)

1. **ARCH-P2-5 — the only clause in the PRD with no owning issue anywhere.** P0/ARCH-6 builds the
   docs-freshness scan; *"retire the mis-titled `docs/architecture.md`"* is **deferred by NG8**,
   which forbids touching that file. Phase 0's **VD-E3** shows the scan is RED on precisely that file
   (dead paths to `crates/propagator/`, `coordinator.rs`, `service.rs`, `db.rs`, `sync-service`), and
   resolves it with a **one-entry, shrinking-only exemption list** whose removal trigger *is* the
   deferred move. So the requirement is *mechanised* but not *closed*: someone must schedule the move
   in a future initiative, or the exemption entry becomes permanent. **This is the one row a reviewer
   should challenge.**
2. **ARCH-P2-2 — the PRD's own acceptance criterion is unsatisfiable.** *"No `String` pubkey or root
   comparison remains in `slashing/src/types.rs`"* cannot hold: EIP-3076 mandates `String` in the
   interchange types (`types.rs:53-70`). P5/ARCH-5o closes a **rescoped** criterion (type the
   *internal* records; the interchange boundary keeps its strings). The requirement text should be
   amended rather than the issue stretched.
3. **ARCH-P2-6 — `cargo-udeps` dropped with a stated reason** (A-E3: it needs a nightly toolchain;
   CI pins stable everywhere and `rust-version = "1.92"`). `cargo machete` satisfies the written
   acceptance criterion ("CI fails on an unused declared dependency"); the deeper analysis does not
   ship.
4. **ARCH-P2-8 — the pre-slot BN health re-check is descoped** (A-7.9: the project plan itself marks
   it "optional", and it is a slot-loop change that would move the M2 offset Phase 3 was judged
   against — NFR-1). The broadcast half alone **does** satisfy the PRD's written acceptance criterion,
   so this is the weakest of the four.

### Issues that close something other than a PRD requirement

Recorded so the coverage table does not look incomplete in the other direction.

| Issue | Closes |
|---|---|
| P0/ARCH-4 | `arch-gates` CI job — project-plan **A-P1 / VD-P7**; no PRD ID |
| P0/ARCH-7a, 7b, 7c | Success metrics **M1**, **M2** and their baselines (departure D10); no PRD ID |
| P1/ARCH-6a, 6b | **ADR-009** clap-default-clobbers-TOML — architecture-only, no PRD ID (A-P5) |
| P2/ARCH-2k | **M8** (raw spawns = 0) — the gate half of P1-4 |
| P2/ARCH-2h | **M10** (in-flight publish survives SIGTERM) |
| P3/ARCH-3b, 3g | **G-8** mock-fidelity gate — an enabler ARCH-P0-8 does not name |
| P3/ARCH-3h | **VD-32** enabler — the wait-window move does not compile without it |
| P5/ARCH-5c | Also **M9** (one duplicated seam removed) |
| P6/ARCH-6e | **VD-6-3** enabler — without it ADR-011's extraction defeats its own `Base` decision |

### Goals not fully delivered by any requirement (stated, not hidden)

- **G6** (*"slashable signing scales to the target validator count"*) is **not** reached on the VC
  path by Phase 5. `orchestrator/attestation.rs:171-192` is a sequential `await` loop, so 200 keys ×
  200 ms = 40 s with a completely free DB. Phase 5 closes the **`signer-server`** ceiling and
  P5/ARCH-5m **records VC-path attestation concurrency as a separate, unscheduled requirement**.
  Claiming G6 at the end of Phase 5 would be false.
- **M7 = 0** (zero inert config surfaces) is reached only at the **end of Phase 7** — Phase 1 closes
  four of five (M7 → 1); the fifth (`BnRole` broadcast, P7/ARCH-7k) and the healthz knobs
  (P7/ARCH-7e) close last.

---

## Constraint Coverage (C1–C10)

Every constraint, with the issues that **close** it, the issues that **honour it by abstention** (a
well-meaning future edit is how these break), and the phase that owns it. Silence on a constraint is
a defect, so nothing here is omitted.

| # | Constraint | Owned by (closes) | Honoured by abstention (the trap) |
|---|---|---|---|
| **C1** | Retain-on-ambiguity is a safety property; lock-shortening must not break it | **P5/ARCH-5e, 5f** (reserve + compensating delete), **5h, 5j, 5k** (the three proof surfaces), **5l** (switchover gated on all three) | P0/ARCH-9 barred from `stage.rs`/`core.rs` doc comments · P4/ARCH-4b allow-lists `RVC_ALLOW_NON_WAL_SLASHING_DB` **without reading or altering the code around it** · P7/ARCH-7i documents the DVT stage→sign→commit shape but changes no ordering · P7/ARCH-7m forbidden from landing group commit (A-A9) |
| **C2** | Audit-log emission must move outside the mutex | **P1/ARCH-1a** (`PendingAudit`, both `scoped.rs:75` and `:106`), **1b** (the four `crates/signer` call sites — VD-E2), **1c** (G-7 `audit_log_scope.rs`) | P5/ARCH-5g's `reserve_*` wrappers must keep G-7 green — emission is structurally outside the lock because `reserve_*` releases before returning · Phases 3/4/6/7 open `scoped.rs` in no issue |
| **C3** | The figment `Env` provider layer is forbidden | **P4/ARCH-4a, 4b, 4c** (G-3 `env_allowlist`, four classes + `DYNAMIC_READS`), **4e–4j** (collapse takes **no figment dependency** — C3 honoured by not taking it) | P0/ARCH-4 adds no `RVC_*` var to CI · P2/ARCH-2g must not move, rename or widen `RVC_METRICS_ALLOW_NON_LOOPBACK` · P3/ARCH-3j's 500 ms deadline is a `Config` constant, never an env read · P7/ARCH-7e must not replace a removed knob with an env override |
| **C4** | Keystore-less key admission must be a first-class mode | **P1/ARCH-2b** (`AdmissionSource::RawSecret` as an enum variant, not an error path), **2c** (both callers) | P2/ARCH-2g changes only the spawn wrapper, never the `Fn(SecretKey)` callback body · P5/ARCH-5n's eviction is driven by an internal bound, **not** by hooking the admission/removal path · P6/ARCH-6e does not touch `add_dynamic_local_key` or the denylist · P7/ARCH-7b/7c must not reintroduce a keystore-file assumption |
| **C5** | The KM-2 teardown contract must survive **and gain a gate** | **P7/ARCH-7a** (G-6 `km2_lifecycle.rs`, lands **before** the retirement), **7b, 7c** (retirement preserving `stop_monitoring` ≠ `cancel_monitoring`) | P0/ARCH-9 **explicitly barred** from `doppelganger/src/traits.rs:79-88` — a doc-comment pass is exactly how the trait default silently collapses · P1's A-1.4 **defers `KeyAdmissionService::withdraw` to Phase 7**, because shipping the contract's new implementation before G-6 exists is the failure §1.1 prevents · P3/ARCH-3n changes liveness *observation* only · P4/ARCH-4f moves the `KeymanagerArgs` struct but no lifecycle code |
| **C6** | Cold-cache pre-proposal fetch, not a silent skip | **P3/ARCH-3j** (bounded 500 ms, both cold origins: boot **and** post-`key_gen`), asserted in **3k** | P0/ARCH-7b must baseline M1 in **both** warm and cold conditions, or 3j's budget has nothing to be judged against · P2/ARCH-2c's spawnable orchestrator is what makes 3j testable without a `LocalSet` |
| **C7** | SSE drops are normal, not errors | **P3/ARCH-3l** (bounded bridge, drop-on-overflow), **3m** (timer stays authoritative; drop counter labelled expected; drop-every-event test is an acceptance criterion) | P0/ARCH-7a's histogram must not be labelled as if a dropped head event were an error · P6/ARCH-6h must not add an `error!`-level or failure-classed metric for an expected-path drop · P7/ARCH-7k touches the publish fan-out, not the SSE consumer |
| **C8** | Healthz removal is operator-visible | **P0/ARCH-8** (deprecation `warn!` + release note naming `/livez` **and** `/readyz` — VD-E2 — + a probe-migration check; **starts the clock**), **P7/ARCH-7d** (removal, ≥1 release later), **P7/ARCH-7e** (knobs **disposed**, never left inert — that would recreate PB-B1 inside the change meant to end it) | Phase 1's milestone is *4 of 5* inert surfaces precisely because C8 forbids closing the fifth early · P4/ARCH-4l instructed **not** to announce a deprecation window for the flat TOML keys |
| **C9** | The keep-list — seven anchors, different owners (below) | see sub-table | see sub-table |
| **C10** | Archive before deleting untracked trees | **P0/ARCH-1a** (branch **and** tarball, restore-and-diff, recorded manifest hash; VD-E5's gitleaks fallback) → **P0/ARCH-1b** (delete, separate commit) | The **orphan-tree invariant** binds every issue until Phase 0's delete lands: P2/ARCH-2b must not touch `main.rs:1608`'s allow, and the 25 orphan `tokio::spawn` sites must never enter ADR-001's migration list · P4 records that every deletion in it is *tracked*, so no archive step is invented |

### C9's seven anchors

| # | Anchor | Owner issues | Artefact that turns red |
|---|---|---|---|
| 1 | The `architecture-tests` harness and its gate suite | P0/ARCH-3 (member removal), P6/ARCH-6a (28 layer rows), P7/ARCH-7b/7l (row + exemption changes) | Generated `ARCHITECTURE.md` regenerates **byte-identically** |
| 2 | The cancellation-proof stage→sign→commit core | **Phase 5 only** — P5/ARCH-5h, 5j, 5k, 5l | Error-class × policy matrix + crash/cancellation injection + concurrency proptest. **EIP-3076 vectors are necessary and insufficient** (VD-S3) |
| 3 | KAT-first policy for signing roots and container HTRs | P3 (ADR-003 tests must **not** carry a `_root` suffix), P6/ARCH-6f (signing-root KATs stay green), P7/ARCH-7h (**re-anchor**, not re-run), P7/ARCH-7l (`EXEMPTIONS` shrinks only) | `kat_policy.rs`; `EXEMPTIONS` is shrinking-only. Flagged as a live false-positive risk in P0/ARCH-7b and P4/ARCH-4d/4h |
| 4 | "env = security opt-outs only" | P4/ARCH-4a, 4b | G-3 `env_allowlist.rs` |
| 5 | A single unbypassable signing gate | P5/ARCH-5l (no new signing surface; `reserve_*` is a DB call), P7/ARCH-7i, 7j (DVT registered + enumerated under `--features dvt`) | Single wiring site `config/builder.rs:394` + the `CompositeSigner` grep gate + the **new** dvt CI step (VD-P6) |
| 6 | Zero unbounded channels | P2/ARCH-2d, 2e (executor `mpsc(8)`, `try_send`), P3/ARCH-3l (consumes the existing bounded `mpsc(64)`) | Channel review in the PR; no new `unbounded_channel`. Phase 1's stated position is stronger: **no new channel at all** (which is why ADR-006's queue design was rejected — VD-E7) |
| 7 | `spawn_blocking` excluded from executor scope | P2/ARCH-2k (G-4's ban list), P5/ARCH-5l (`spawn_blocking` **stays** even though the `!Send` guard no longer requires it) | G-4 must never gain `signer/src/core.rs:542` or `signer-server/src/dvt/peer_service.rs:231,323` |

---

## Execution Order

### Single developer (the default plan)

```text
Phase 0 ─▶ Phase 1 ─▶ Phase 2 ─▶ Phase 3 ─▶ Phase 4 ─▶ Phase 5 ─▶ Phase 6 ─▶ Phase 7
  13–19     14–21      11–19      15–23      15–21      20–39      10–15      18–22
```

1. **Phase 0 — ground truth.** `1a → 1b → 2a → 2b → 3 → 7a → 7b → 7c → 4 → 5 → 6 → 8 → 9`, with
   **ARCH-8 pulled earlier if the release closing this phase is imminent** (C8's clock is measured in
   releases, not days). **PR grouping is binding:** 1b + 2a + 2b land in **one PR in that commit
   order**, detectors after the deletion, so `develop` is never red.
2. **Phase 1 — runtime honesty.** `1a → 1b → 1c` first even single-stream (the cheapest removal of a
   live availability hazard), then `6a` (spike) → `5a → 5b → 6b` (gate visible in CI **before** the
   defect is fixed), then `2a → 2b → 2c`, then `3`, then `4a → 4b`.
3. **Phase 2 — task topology.** `2a` (probe) always first; `2b → 2c`; `2d → 2e → 2f → 2g`; `2h` last
   of the behavioural set; `2k` **lands with or after** `2g`.
4. **Phase 3 — slot ordering.** **`3a → 3c → 3d` before `3i`** — binding: landing proposal-first
   first removes the accidental masking and makes a known reward loss deterministic on every slot.
5. **Phase 4 — config.** **`4a` (G-3) before `4b`**-onward collapse; **`4d` (the TOML parity harness)
   before `4f/4g/4h`**; `4i` deletes the four sites only once the sections exist.
6. **Phase 5 — the lock.** `5a → 5b` (measure) → `5c → 5d` (fold, so the migration rewrites one
   consumer) → `5e → 5f → 5g` → the three proof surfaces → **`5l` switchover** → `5m` → `5o`.
7. **Phase 6 — taxonomy.** `6a` first (the rows), then the two gates; `6e` before `6f`.
8. **Phase 7 — readiness.** **`7a` (G-6) before `7b`** — gate the contract before retiring the
   mechanism that holds it. `7d` only ≥1 release after P0/ARCH-8.

### Two developers (overlay; see the calendar section for the model)

| Window | Stream A (critical path) | Stream B |
|---|---|---|
| W0 | **Phase 0** Stream A chain (1a → 1b → 2a → 2b → 3 → 4 → 5 → 6) | Phase 0 Stream B (7a → 7b → 7c, 8, 9) |
| W1 | **Phase 1** minus the 1A cluster (2a→2b→2c, 3, 4a→4b, 5a→5b, 6a→6b) | **P1/ARCH-1a → 1b → 1c**, then **departs to P5/ARCH-5a** |
| W2 | **Phase 2** (all of it, including 2j/2k) | **Phase 5** 5b → 5c → 5d |
| W3 | **Phase 3** (all of it, including 3l/3m/3n) | **Phase 5** 5e–5l |
| W4 | **Phase 4** (all of it, including 4a–4c/4k/4l) | **Phase 5** tail (5m, 5n, 5o) → **Phase 6** |
| W5 | **Phase 7** A half: 7a → 7b → 7c, 7d → 7e, 7k | **Phase 7** B half: 7f → 7g → 7h → 7l, 7i → 7j, 7m |

**`ARCHITECTURE.md` / `CLASSIFICATION` collision protocol** (agreed once at the W3 kickoff): the file
is **generated — never hand-merge it**. On conflict take either side, regenerate, commit. Any stream
adding a **production** crate edge lands the `Cargo.toml` change *and* the regeneration in the same
commit; whoever rebases second regenerates again.

**Anti-patterns, forbidden explicitly:** never run P5/ARCH-5c concurrently with 5d; never run a
Phase-6 `CLASSIFICATION` edit concurrently with a Phase-7 row change; never parallelise Phase 0's
`1a → 1b → 2a → 2b` chain (it is one PR sequence, not four issues).

### Cross-phase dependency map

```text
Phase 0 ─┬─▶ Phase 1 ──┬─▶ Phase 4
         │             ├─▶ Phase 5 ──┬─▶ Phase 7
         ├─▶ Phase 2 ──▶ Phase 3     │
         ├─▶ Phase 6 ────────────────┘
         └┄┄▶ Phase 7   (C8: ≥1 release between P0/ARCH-8 and P7/ARCH-7d — a calendar edge, not effort)

Phase 2 ┄┄▶ Phase 3   (testability only: the harness needs a spawnable orchestrator)
Phase 2 ✗  Phase 5    (NOT a dependency — the !Send guard never enters the orchestrator future, VD-Q2-2)
```

---

## Risk Flags

| Flag | Issues | Why |
|---|---|---|
| **Highest-consequence change in the initiative** | P5/ARCH-5e → 5l | A mistake here is a signature on the wire with no slashing record. C1 rejects the naive design **by name**; the three proof surfaces are switchover **gates**. The M-1 prior-art warning (`phantom_row_m1.rs`) is quoted in the issue so a reviewer can neither reject nor approve on sight |
| **Widest estimate spread (20–39 d)** | Phase 5 | The variance is in the proof surfaces, not the redesign. Not padded — the phase names its cut line (5o) explicitly |
| **Conditional scope** | P7/ARCH-7f → 7h | VD-7C: both `ethereum_ssz` 0.8.3 and 0.9.1 are pinned at HEAD, so the `Wire*` deletion trigger is unsatisfied. The spike decides; 7h is "collapse **or** record the deferral" |
| **Branch-not-buffer estimates** | P3/ARCH-3n, P5/ARCH-5o | Both are `[review-carried, unverified at HEAD]`; verification is the **first task inside the issue** (A-11), and a failed verification drops the issue rather than inflating it |
| **Calendar-bound, not effort-bound** | P7/ARCH-7d, 7e | Blocked by a release count (C8). If releases do not fall at phase boundaries, **7E slips out of the plan** rather than shipping early (RP3) |
| **Cross-plan collision** | P5/ARCH-5e onward | A-12: the tracing initiative's prospective byte-identical pin on `crates/slashing/src/stage.rs`. Verified **not wired in CI at HEAD**; Phase 5's entry criterion is that it is **lifted or re-pinned, never discovered** |
| **Gate green on day one** | P6/ARCH-6c (G-5b) | VD-P4: no Foundation member declares a Domain dependency, so the gate is vacuously green. The **synthetic RED demo is the work**, not a formality |
| **Estimate gap vs. the project plan** | all phases | +25/+43 d. Stated per phase above with its driver. Nothing absorbed |

---

## Standing Invariant

**At every merge, in every phase** (`CLAUDE.md` + NFR-6):

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings
cargo build --workspace
cargo nextest run --workspace     # NEVER `cargo test --workspace` — it deadlocks in this workspace
```

Plus, on every issue:

- **TDD** RED → GREEN → REFACTOR; every gate has a **named** RED demonstration, reproduced locally
  against the pre-change tree with the output pasted into the PR — never by merging a knowingly
  failing test.
- `thiserror` in libraries, `anyhow` in binaries; **no `.unwrap()` in production code**; `///` on
  public API.
- **KAT-first policy:** any new or renamed `*_root` / `*tree_hash*` / `*signing_root*` test is
  KAT-anchored or carries `// kat_exempt: <reason>`; `EXEMPTIONS` is **shrinking-only**. Two inverse
  obligations: ADR-003's new tests (Phase 3) and P0/ARCH-7b's harness tests must **avoid** a `_root`
  suffix — they assert HTTP behaviour and latency, not spec-defined roots — and P7/ARCH-7h must
  **re-anchor** every touched container-root test, not merely re-run it.
- **NFR-1:** no latency regression on the per-slot deadline path at default `info`, measured against
  Phase 0's M1/M2 baselines.
- **NFR-4:** each phase separately revertible; no PR whose revert requires reverting another.
- **Orphan-tree invariant, with a stated expiry:** until Phase 0's delete commit lands, never cite,
  edit or migrate `crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`,
  `crates/rvc/src/commands/`. It expires when G-1 enforces it mechanically.
- Each issue merges **ff-only** after review.

---

## Housekeeping notes for whoever consumes this directory

1. **Issue-ID collisions must be resolved before tracker import.** See the ID convention note above.
   The `P<n>/` prefix here is display-only.
2. **`00-phase-0.md` may be invisible to the dev-run discovery globs.** *Attributed, not verified
   here:* the dev-run convention documented for the default `plan/issues/` path discovers phase files
   with `0[1-9]*.md` and `[1-9]*.md` — a rule written to skip `00-summary.md`, which also skips
   anything else starting `00`. No consumer of *this* directory was inspected, so the claim is a
   caution, not a finding. **If that pipeline is pointed here, Phase 0's file is not discovered** and
   the fix is a rename (e.g. `08-phase-0.md`, or renumbering the series `01`…`08`). **The rename has
   a cost:** it breaks this summary's phase-file link table, the per-phase cross-references between
   files, and any external references — so it is a coordinated edit, not a `mv`. Flagged, not fixed.
3. This directory is `plan/architecture-2026-08-12/issues/`, not the default `plan/issues/`; any
   tooling pointed at the default path will find nothing.
