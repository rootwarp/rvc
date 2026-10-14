# Research Overview: Architecture Remediation for rs-vc

> Index over a three-track investigation supporting
> [`plan/architecture-2026-08-12/prd.md`](../prd.md), baseline `develop` @ `0ae9a09`.
> **Verdicts only** — methodology and evidence live in the linked track docs.
>
> **Standing caveat:** all three tracks ran **without a shell** — no `cargo`, `git`, wiremock or
> `rvc start` was executed; every verdict rests on static analysis at HEAD plus external primary
> sources. The two unexecuted probes (Q2's compile check, RVD-4's TOML-clobber check) are specified
> verbatim and must be the first task of their requirements.

## Track Docs

| Track | Doc | Scope | State |
|---|---|---|---|
| Empirical verification | [`empirical-verification.md`](./empirical-verification.md) | Q1 `SlotContext` t=0; Q2 `?Send` | Complete |
| Slashing critical section | [`slashing-critical-section.md`](./slashing-critical-section.md) | ARCH-P1-5, C1/C2, EIP-3076 | Complete |
| Runtime & config patterns | [`runtime-and-config-patterns.md`](./runtime-and-config-patterns.md) | ARCH-P1-4; ARCH-P1-1/2/3 | Complete |

---

## Track 1 — Empirical verification

- **Q1 (Weakness 8): REAL and understated. Re-rank MEDIUM → HIGH.** A spec-conformant BN 404s the
  not-yet-produced current slot; `head_root = None` every slot; **both** sync phases skip (messages
  *and* contributions). Worst when the BN is **healthiest** (duty fetches are cache-guarded, so
  `capture` fires at t≈0+ε).
- **VD-Q1-6 — the finding that rewrites the fix:** a **third** consumer, `block_proposal/mod.rs:104`,
  feeds `head_root` into `expected_parent_root`. Today the H-4 check is inert; "just make `capture`
  succeed" **arms a dropped-proposal bug** (`ParentRootMismatch`). The field must be **split** into
  `parent_root` (t=0) and `head_root` (phase 2, reused at phase 3 — H-5 preserved).
- **Q2: YES, removable — but not a one-line fix.** Six `?Send` sites **plus** a `Send + Sync`
  supertrait on `BeaconBlockClient`. **Corollary (VD-Q2-2): the `!Send` slashing guard is *not* a
  cause** — it is confined to `spawn_blocking`, so ARCH-P0-4 is independent of the C1 redesign.

## Track 2 — Slashing critical section

- **V1 Tentative-commit-then-reconcile**, scoped to `RetainStagedRow`, sign lifted out of the DB
  transaction — what Lighthouse and Web3Signer both already do (V5). **V7** retain-on-ambiguity
  provably survives; **VD-S6** watermarks are import-only, so a compensating delete cannot re-open a
  slot — this is what makes reconcile safe.
- **V6/VD-S2 the mutex is not the VC-path wall** — `attestation.rs:171-192` is a sequential await
  loop; 200 keys × 200 ms = 40 s with a free DB.
- **V8** the hold-duration metric exists; **no bench or load harness does**. **V10/VD-S3** the 38
  in-tree EIP-3076 vectors are blind to the reordering. **V11** ARCH-P0-9 still lands first.
  **V12** the next wall is fsync. **V13** 10–15 days.
- **Gap:** §2–§8 and Sources are TODO; citations `[1]`–`[7]` behind V2/V5/V6/V12/V13 resolve to
  nothing and A-S1…A-S9 are absent. Directionally usable; external claims not yet verifiable.

## Track 3 — Runtime & config patterns

- **V1–V4 `TaskExecutor`:** port 4 of Lighthouse's 9 mechanisms; **two** entry points (`spawn` +
  `register`, the latter non-negotiable for 4 Infra-crate spawns); lives at `bootstrap/executor.rs`,
  not a new crate; `spawn_blocking` stays **out** of scope (C9); `ShutdownTier` order Ingress →
  Orchestrator → Background → Telemetry, A-7's 5 s a **total** budget (2.0/2.0/0.5/0.5).
- **V5/RVD-2** clippy `disallowed-methods` is the wrong *primary* gate (a per-crate `clippy.toml`
  **replaces** the workspace file, silently dropping the secret-key bans). **V6/RVD-3** 9 live
  production spawns, not "≥4".
- **V7/V8 config:** adopt the **reth `NodeConfig` model** — clap `Args` groups *are* the config
  sections; reject figment (even minus `Env`), a derive crate and a new macro. **V9/RVD-1** clause
  (i) of ARCH-P1-1 is already enforced by rustc (`merge_cli_fields!` destructures exhaustively).
  **V10–V12** the real ungated seam is clap → `CliOverrides`, plus 8 undocumented bypass args; the
  gate is GREEN today. **V13/RVD-6** the `RVC_*` prefix scan fails (438 hits, mostly metric names;
  misses `RUST_LOG`). **V14/RVD-4 new live defect:** nine knobs where a clap default clobbers the TOML.

---

## Consolidated: question → verdict → plan impact

| Q | Verdict | Changes in the plan |
|---|---|---|
| Q1 `SlotContext` t=0 | Real, HIGH | ARCH-P0-8 ships; assert **contributions** too; split `parent_root`/`head_root`; fix the 7 `Ok`-for-anything stubs |
| Q1 sequencing | P0-3 worsens P0-8 | **ARCH-P0-8 before ARCH-P0-3**, same phase (nowhere in the PRD) |
| Q2 `?Send` removable | Yes, +supertrait | ARCH-P0-4 item 1 reworded (6 sites + supertrait); R3 → Low×Low; A-6 → finding |
| Q2 vs slashing guard | Refuted | ARCH-P0-4 has **no** dependency on C1 |
| Which slashing redesign | Tentative-commit | Amend admissible list to `{tentative-commit}`; sign leaves the transaction |
| WAL / per-pubkey / sharded DB | WAL already on, no help; sharding rejected | Delete from `prd.md:792-793` and NG5; record as rejected-with-reason |
| Retain-on-ambiguity survives? | Yes, provably | C1 satisfied: identical on 3 of 4 error classes, stricter on the 4th; compensating delete fails safe |
| EIP-3076 vectors sufficient? | No | ARCH-P1-5 criterion += error-class×policy matrix, crash injection, concurrency proptest |
| Where is the wall? | Not the VC path | **G6 unreachable from ARCH-P1-5 alone**; retarget ARCH-P1-15 at `signer-server` or add a concurrency requirement |
| Next wall after the fix | fsync | Group commit admissible **only if measured** — not a day-one design |
| Baseline / harness available? | Metric yes, harness no | ARCH-P1-15 must **build** the load harness; it cannot assume one |
| C2 ordering | P0-9 first | Unchanged; `stage.rs`-untouched scope still satisfiable |
| `TaskExecutor` shape | 4 of 9 mechanisms | `spawn` + `register` at `bootstrap/executor.rs`; no new crate; `spawn_blocking` excluded |
| Shutdown budget | Total, not per-tier | A-7 stays 5 s split per tier; rises to 6.5 s only if metrics shutdown goes cooperative |
| Raw-spawn ban gate | Scanner, not clippy | ARCH-P1-4 criterion rewritten; M8 baseline 9, not ≥4 |
| Config mechanism | reth `NodeConfig` | ARCH-P1-2's "macro-based or figment-style" superseded; C3 honoured by not adopting figment |
| ARCH-P1-1 clause (i) | Redundant | Drop it; gate clauses (ii)–(iv) only |
| Config drift gate shape | Scanner | `architecture-tests/tests/config_drift.rs`, `kat_policy` style, `BYPASS` + `ALIASES` tables |
| Clap defaults vs TOML | Live defect | New Problem-Statement (b) item; ~30-line fix **before** the ARCH-P1-2 collapse |
| `RVC_*` env gate | Prefix scan fails | ARCH-P1-3 scans `env::var` call sites/`*_ENV` constants; grandfather `RVC_LOG_FORMAT` |

## Decisions forced by research (vs the review's Phases 0–5)

1. **Phase 1 → split `SlotContext`, don't repair the query.** The naive "make capture succeed"
   reading is a missed-block bug. Add the mock-fidelity scan.
2. **Phase 1 ordering:** ARCH-P0-8 lands before the Phase 2 slot reordering.
3. **Phase 2 → the `?Send` fix is a supertrait plus seven annotation sites** (not six), and Phase 2
   is **not** serialized behind Phase 4 on `!Send` grounds. **Compile-verified after the fact** — the
   research track carried the caveat *"no shell tool this session — no build ran"*, so the team lead
   ran the experiment in a scratch copy of the tracked tree: dropping `?Send` at
   `crates/block-service/src/traits.rs:13`, adding `: Send + Sync` to `BeaconBlockClient`, and
   dropping `?Send` at `crates/rvc/src/beacon_adapter.rs:18` gives a clean
   `cargo check -p rvc-block-service --lib` **and** `cargo check -p rvc --lib`. No non-`Send` type
   blocks it. The site count is `rg 'async_trait\(\?Send\)'` → 8 hits, of which one
   (`crates/rvc/tests/sync_independent_of_attesting.rs:249`) is prose in a doc comment, leaving
   **seven** real annotations — one trait declaration, one production impl, five test mocks. This
   matches Phase 2's estimate and supersedes this track's "six impls".
4. **Phase 4 → "or per-pubkey connections" is removed** as an option.
5. **Phase 4 → "proptest against the EIP-3076 vectors" is insufficient**: three new proof surfaces.
6. **Phase 4 alone does not deliver G6** — the sequential attestation loop is the VC-path ceiling.
7. **Phase 3 → gate clause (i) is dropped**, the env gate's mechanism is replaced, and the nine
   clobbered knobs become a P0-class defect fix ahead of the collapse.
8. **Phase 3 → the collapse is reth-shaped.** ARCH-P1-2's stated mechanism is superseded: figment
   layers *values* and cannot reach one-declaration-per-knob.
9. **Phase 2 → the raw-spawn ban is a scanner**, not clippy `disallowed-methods`; the executor is
   4 of 9 Lighthouse mechanisms at `bootstrap/executor.rs`.
10. **Phase 5 → the recommended slashing ordering was already shipped here, and reverted as a bug
    (VD-S9).** `crates/signer/tests/phantom_row_m1.rs:1-10` documents **M-1**: committing the row
    before calling the signer left a phantom row on signing failure, so *the next legitimate sign
    was rejected as a DoubleVote*. The current stage→sign→commit design **is** that bug's fix and its
    regression test is still green. ADR-005 is admissible only because it adds the compensating
    delete M-1 lacked, on exactly M-1's failure class — **the compensation is not an optimization,
    it is the entire reason the ordering is admissible**, and shipping the reorder without it
    re-opens M-1. M-1's failure mode was **liveness, not safety** (a phantom row refuses a legitimate
    signature; it never permits a double-sign), which is why the fail-safe direction of the
    compensating delete is the correct one. Carried into `architecture.md` ADR-005 and enforced in
    `issues/05-phase-5.md` (acceptance item **X4**: `phantom_row_m1.rs` stays green, unchanged, and
    is quoted in the switchover PR).
