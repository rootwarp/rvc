# Research: Slashing-DB Critical-Section Redesign (ARCH-P1-5)

> Research track for the architecture-remediation initiative on the rs-vc Cargo workspace,
> baseline `develop` @ `0ae9a09` (v0.7.0), authored 2026-08-12.
>
> **Authoritative inputs, in precedence order:**
> [`plan/architecture-2026-08-12/prd.md`](../prd.md) (requirement **ARCH-P1-5**, constraints
> **C1**, **C2**, **C9**, assumption **A-12**, risk **R1**) →
> [`docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md)
> (Weakness 5, Target Architecture "Signing/slashing placement", Phase 4) →
> the repository's [`CLAUDE.md`](../../../CLAUDE.md) (TDD cycle, KAT-first policy, `thiserror`/`anyhow`,
> no `.unwrap()` in production code).
>
> **This document is not a restatement of the review or the PRD.** Every in-repo claim was opened at
> HEAD and is cited `file:line`. Where the review or the PRD did not reproduce, or reproduced but
> licensed a wrong conclusion, the corrected fact is stated here and filed under
> *Verification Deltas* (VD-S1 … VD-S9). External claims carry a URL.
>
> **No-ask constraint:** every open question is resolved to a stated default in *Assumptions*
> (A-S1 … A-S9). Nothing is escalated.
>
> **Scope:** research and recommendation only. It changes no code, deletes nothing, and does not
> modify `crates/slashing/` or `crates/signer/`.

---

## Verdict Summary

Every question in the research brief, answered. Detail and evidence follow in §1–§8.

| # | Question | Verdict |
|---|---|---|
| **V1** | Which redesign? | **Tentative-commit-then-reconcile**, scoped to the `RetainStagedRow` policy, with the DB critical section reduced to a short write transaction and the BLS sign lifted out of `spawn_blocking`. This is what **both** surveyed reference implementations already do. |
| **V2** | Does SQLite WAL help? | **No.** WAL is already enabled and *hard-fails* at open (`crates/slashing/src/db/open.rs:217-238`). WAL gives reader/writer concurrency, but *"since there is only one WAL file, there can only be one writer at a time"* [1]. While a write transaction is open across a 200 ms sign, every other writer is blocked regardless of WAL. |
| **V3** | Per-pubkey connections / sharded DB? | **Reject.** Against one DB file they buy **zero** concurrency (V2). Lighthouse deliberately pins `POOL_SIZE = 1` **plus** `locking_mode=EXCLUSIVE` [2]. Sharding into per-pubkey *files* would break the single-file EIP-3076 export/import, GVR pinning (`db/mod.rs:150`), backup (`db/migrations.rs:115-116`) and integrity-check story. **The PRD's admissible-design list should be amended to drop this option** (VD-S1). |
| **V4** | Finer-grained transactions alone? | **Necessary but not the design.** The transaction is already minimal in *work*; it is long in *wall-clock* only because it spans the sign. Removing the sign from the transaction **is** tentative-commit. |
| **V5** | What do the references do? | **Lighthouse:** one connection, `TransactionBehavior::Exclusive`, check+insert+**COMMIT**, then sign outside [2]. **Web3Signer:** `jdbi.inTransaction(READ_COMMITTED)` + `pg_advisory_xact_lock(lockType, validatorId)`, insert, commit, **then** the caller signs [3][4]. **Dirk:** per-account locker, protection written as part of signing [5][6]. Nobody holds a DB lock across the sign. |
| **V6** | Where is the wall, quantitatively? | Current: **≈20 slashable signs** per 4,001 ms attestation window at 200 ms remote latency. **But on the VC path the mutex is not the binding constraint** — `crates/rvc/src/orchestrator/attestation.rs:171-192` awaits each duty **sequentially**, so 200 keys cost 40 s with a *free* DB. **ARCH-P1-5 alone buys the VC nothing** (VD-S2). The mutex is the real wall on the `signer-server` / `SigningGate` path, where requests genuinely arrive concurrently. |
| **V7** | Does retain-on-ambiguity survive (C1)? | **Yes, provably, case by case.** Under `RetainStagedRow` the current design commits on success, on timeout and on ambiguous error — 3 of 4 error classes. Commit-before-sign is **behaviourally identical** on those three and *more conservative* on the fourth (unambiguous-no-signature), where a best-effort compensating delete replaces a rollback. Every failure of the compensating delete fails **safe**. §6.1. |
| **V8** | Is a baseline metric available? | **Yes.** `rvc_signer_slashing_tx_hold_duration_ms{kind}` is observed at `crates/signer/src/core.rs:219` and regression-pinned by `crates/signer/tests/tx_hold_metric.rs`. **No benchmark or load harness exists** — ARCH-P1-15 must build one. |
| **V9** | Do EIP-3076 conformance vectors exist in-tree? | **Yes — 38 official vectors**, `crates/slashing/tests/conformance/*.json` + runner `crates/slashing/tests/conformance.rs`, already driving the production `stage_* → commit()/discard()` path (`conformance.rs:8-21`). |
| **V10** | Are they sufficient to prove the new ordering? | **No.** EIP-3076 is **silent on ordering and durability** [7] and the vectors are single-threaded rule-engine fixtures. They can only prove the *rule engine* is unchanged. Retain-on-ambiguity needs a **separate error-class × policy matrix test**, a **crash/cancellation-injection test**, and a **concurrency proptest**. **The PRD's ARCH-P1-5 acceptance criterion is under-specified as written** (VD-S3). §6.1–§6.2. |
| **V11** | Ordering vs C2 (audit-log deadlock)? | Tentative-commit **dissolves** C2 on the sign path (no guard is held across anything a subscriber could observe), but ARCH-P0-9 must still land **first** — it is the cheap independent fix for a live hazard, and its `stage.rs`-untouched scope (A-12/R9) remains satisfiable. §7. |
| **V12** | Secondary wall after the fix? | **fsync.** `synchronous=EXTRA` + `fullfsync=ON` (`db/open.rs:240-246`) makes each commit a durable write. At 200 keys this is 200 serialized fsyncs per window. Mitigation if measured to bind: **group commit** (batch N pending checks into one transaction, one fsync, then release all N to sign) — which preserves commit-before-sign exactly. §5. |
| **V13** | Effort | **10–15 engineering days** for the redesign + proof harness, excluding the ARCH-P1-15 load harness. §5. |

## 1. Current ordering, precisely

All of §1 was read at HEAD. This is the level of detail the redesign has to preserve; the review's
one-paragraph summary and the PRD's PB-C1 both compress away the parts that make C1 hard.

### 1.1 What is held, and for how long

There are **four** nested serialization points, not one. Naming them separately matters, because a
redesign that shortens #3 while leaving #1 and #4 in place changes nothing measurable (V6).

| # | Serializer | Acquired at | Released at | Scope |
|---|---|---|---|---|
| 1 | **Orchestrator sequential loop** (VC path only) | — | — | one duty at a time, *global*, `crates/rvc/src/orchestrator/attestation.rs:171-192` |
| 2 | **Per-pubkey async lock** `ValidatorLockMap` | `crates/signer/src/core.rs:505` (`req.locks.lock(&pubkey_bytes).await`) | end of `sign_slashable` | per pubkey |
| 3 | **`parking_lot::Mutex<Connection>`** — the one this requirement is about | `crates/slashing/src/stage.rs:355` (block) / `:436` (attestation), `self.conn.lock()` | `StagedBlock::commit` / `discard` / `Drop` (`stage.rs:166-219`, `:248-300`) | **global, one per `SlashingDb`** (`crates/slashing/src/db/mod.rs:59`, `conn: Mutex<Connection>`) |
| 4 | **SQLite `BEGIN IMMEDIATE` write lock** | `stage.rs:357` / `:438` | the `COMMIT` in `commit()` (`:190`, `:273`) or `ROLLBACK` | the DB **file** — one writer, process-wide *and* cross-process |
| 5 | **A tokio blocking-pool thread** | `core.rs:542` `spawn_blocking` | when `body` returns | one thread per in-flight slashable sign |

The mutex (#3) and the SQLite write lock (#4) are acquired **one line apart** and released together,
so they are effectively one lock with two enforcement layers — #3 within the process, #4 against any
second process. Both are held across the sign.

The sign itself is `crates/signer/src/core.rs:284-287`:

```rust
let sign_result = self.handle.block_on(tokio::time::timeout(
    self.sign_timeout,
    self.signer.sign(&self.signing_root, &self.pubkey_bytes),
));
```

— a `Handle::block_on` on the blocking thread, precisely because the staged guard is `!Send`
(`stage.rs:57-63`, `core.rs:36-41`). So the hold duration equals the **full remote-signer round trip**,
bounded only by `sign_timeout`.

**Work done inside the critical section** (this is small, and that is the point — the section is long
in wall-clock, not in work):

1. `BEGIN IMMEDIATE` (`stage.rs:357`).
2. `read_watermark` ×1 for blocks, ×2 for attestations (`stage.rs:367`, `:445-446`).
3. `check_block` / `check_attestation` against `TargetedSql*History` (`stage.rs:369-372`, `:448-458`).
4. *(sign — 200 ms)*
5. One `INSERT` (skipped on `is_resign` / `is_duplicate`) then `COMMIT` (`stage.rs:176-190`, `:258-273`).

Note the GVR check is deliberately **outside** the mutex — `pinned_gvr()` is consulted before
`self.conn.lock()` to avoid a nested-lock deadlock (`stage.rs:341-351`, comment "M-6: GVR check before
acquiring the main mutex"). That is a precedent worth citing in the redesign: the codebase already
moves work out of the critical section when correctness allows.

### 1.2 The error-class → commit/discard decision table

This table **is** the safety property C1 protects. It is assembled from `core.rs:290-343` (the match
on `sign_result`), `:346-376` (`finish_timeout`), `:379-409` (`finish_ambiguous_error`) and
`:412-450` (`retain_staged_row`).

| Outcome of `stage()` / `sign()` | `DiscardStagedRow` (in-process backends) | `RetainStagedRow` (remote / unknown) | Code |
|---|---|---|---|
| `stage()` returns `Err` (EIP-3076 violation or SQL I/O) | rolled back inside `stage_*` before the guard is handed out; `SlashingBlocked` | same | `stage.rs:375-381`, `:461-467`; `core.rs:266-276` |
| Sign **succeeded** | **COMMIT** | **COMMIT** | `core.rs:295-313` |
| Sign **timed out** (`tokio::time::timeout` elapsed) | **ROLLBACK** | **COMMIT**, error still `SigningFailed("signer timed out")` | `core.rs:292`, `:351-375` |
| **Ambiguous** signer error (`RemoteSignerError`, `InvalidRemoteSignature`, transport/HTTP) | **ROLLBACK** | **COMMIT**, error `SigningFailed(<msg>)` | `core.rs:342`, `:385-408` |
| **Unambiguous no-signature** (`KeyNotFound`, `LocalRejected`, `UnsupportedSigningType`) | **ROLLBACK** | **ROLLBACK** — policy is *not* consulted | `core.rs:316-338` |
| `commit_row()` itself fails | `CommitFailed { signing_root, source }` | same, and on the retain path too (`core.rs:420-432`) | `core.rs:300-312`, `:420-432` |
| Blocking task **panics** | guard `Drop` → ROLLBACK | same | `stage.rs:204-219`, `core.rs:542-550` |

Two properties of this table that a redesign must reproduce exactly:

- **Retain-on-ambiguity is per-policy, not global.** `TimeoutPolicy` has **no `Default`**
  (`core.rs:63-97`) — every call site must choose. `TimeoutPolicySource::ResolveUnderLock`
  (`core.rs:104-110`) re-evaluates the policy *twice*: once under the per-pubkey lock (`core.rs:518-524`)
  and again immediately before the sign (`core.rs:280-282`), merged fail-closed by
  `fail_closed_max` (`core.rs:114-121`) so `Retain` always wins. That is SEC-1: a concurrent
  keymanager remote-import must not leave a sign snapshotted as in-process.
- **`RetainStagedRow` never rolls back on any outcome where the remote may hold a signature.** The
  only rollback under `Retain` is the unambiguous-no-signature class, where no remote I/O produced a
  signature (`core.rs:316`, guarded by `e.is_unambiguous_no_signature()`).

### 1.3 Why cancellation cannot desynchronize signature and record

Three independent mechanisms, all verified:

1. **The whole triple runs on one blocking thread.** `sign_slashable` calls
   `tokio::task::spawn_blocking(move || body(session))` (`core.rs:542`). Dropping the *caller's*
   future does not cancel a `spawn_blocking` task — it runs to completion. So the stage→sign→commit
   sequence cannot be interrupted between the sign and the commit.
2. **The `!Send` guard makes the unsafe shape uncompilable.** `StagedBlock`/`StagedAttestation` own a
   `parking_lot::MutexGuard`, which is `!Send` (`stage.rs:57-63`). A guard therefore cannot cross a
   real `.await`; the compiler rejects any refactor that would let a runtime cancel between stage and
   commit. This is a *type-level* guarantee, not a convention.
3. **`Drop` is the backstop.** Any unwind (panic, early return, `?`) issues `ROLLBACK`
   (`stage.rs:204-219`, `:284-300`), so the failure mode is "no record and no signature", never
   "signature without record".

`core.rs:500-504` states the residual explicitly and correctly:

> *"CANCELLATION NOTE: if the caller drops this future at the `spawn_blocking(...).await` below, this
> guard is released while the blocking task keeps running. The authoritative double-sign serializer is
> the SQLite `BEGIN IMMEDIATE` lock held by the staged guard."*

i.e. the per-pubkey lock (#2) is a *performance/TOCTOU* device; the **authority** is #4. Any redesign
that shortens #4 must therefore re-establish where the double-sign authority lives — this is the
single most load-bearing sentence in the current design and it is easy to miss.

### 1.4 Verification deltas against the review and the PRD

**VD-S1 — "per-pubkey connections" is not an admissible design.** The PRD (`prd.md:792-793`) and the
review (Target Architecture, "Signing/slashing placement") both list *per-pubkey connections* as an
admissible alternative to tentative-commit. Against a single SQLite file this is **inert**: SQLite
permits exactly one writer at a time even in WAL mode [1], and `BEGIN IMMEDIATE` (`stage.rs:357`)
takes that writer lock at stage time. A second connection's `BEGIN IMMEDIATE` would return
`SQLITE_BUSY` / block for the entire sign — identical wall, worse failure mode. Lighthouse pins
`POOL_SIZE = 1` *and* `locking_mode=EXCLUSIVE` for exactly this reason [2]. **Carry forward:** amend
ARCH-P1-5's admissible list to `{tentative-commit-then-reconcile}` plus, if measurement demands it,
`{group commit}` — and record per-pubkey/sharded connections as **rejected with reason**, so a future
implementer does not re-open it. Details in §4.2.

**VD-S2 — the ~200 ms / ~20-signs wall does not bind the VC path.** The review (Weakness 5) and the
PRD (PB-C1) both frame the mutex as "a hard ceiling on validators-per-instance". At HEAD the VC's
attestation phase is a **sequential await loop** —
`crates/rvc/src/orchestrator/attestation.rs:171-192`, `for duty in duties { self.process_attestation_duty(duty).await; }`
— with no `join_all`, `FuturesUnordered` or `spawn` anywhere in
`crates/rvc/src/orchestrator/` (verified by grep; the same sequential shape appears at
`aggregation.rs:96` and `sync_committee.rs:78,162,304`). With a *zero-cost* slashing DB, 200 keys at
200 ms remote latency still take **40 s**, ten slots. **Carry forward:** ARCH-P1-5's success metric
(M3, `prd.md:993`) is measurable and real, but the *user-visible* outcome it promises — "slashable
signing scales to the target validator count" (G6) — is **not reachable from ARCH-P1-5 alone on the
VC path**. Either ARCH-P1-15's load profile must target the `signer-server` path (where the mutex
genuinely binds), or a companion requirement must make the attestation loop concurrent. §2.

**VD-S3 — the ARCH-P1-5 acceptance criterion "passes the EIP-3076 conformance vectors" cannot prove
the property it is asked to prove.** EIP-3076 specifies *conditions on what may be signed* and an
interchange file format; it says nothing about when a record must be persisted relative to signature
release, nothing about fsync, and nothing about crash-safety [7]. The 38 in-tree vectors
(`crates/slashing/tests/conformance/`) are single-threaded, single-outcome fixtures. They will pass
identically before and after the reordering — which is the *point* (they pin the rule engine) but
also means they are **blind to the change under test**. §6.2 specifies what must be added.

**VD-S4 — `stage.rs:32-48`'s justification #2 is misleading and should not be carried into the new
design's rationale.** The doc comment argues the hold is acceptable partly because *"The SQLite WAL
writer lock is coarse-grained anyway; there is at most one writer at a time regardless."* That is a
true statement about SQLite used to justify a false conclusion: single-writer means a *committed*
write serializes for its own duration, not that it is free to hold the writer lock open across an
unbounded network call. The correct reading is the opposite — because there is only one writer,
holding it across a 200 ms sign is maximally expensive.

**VD-S5 — the review's "the code documents the hazard itself" for C2 reproduces, with a scope
correction.** `scoped.rs:70-75` is the block path; the identical hazard is repeated for attestations
at `scoped.rs:103-107`. Any ARCH-P0-9 acceptance criterion written against `:70-75` alone leaves half
the surface. (The PRD does say "and the corresponding `stage_attestation` path at `:88+`",
`prd.md:705` — this delta is recorded against the *review*, not the PRD.)

**VD-S6 — the signing path does not raise watermarks, which is what makes a compensating delete
safe.** `crates/slashing/tests/conformance.rs:18-21` states: *"production signing does not auto-raise
watermarks after each sign — that remains history-table driven on the complete path."* Watermarks are
raised only by interchange `import` (`conformance.rs:31-34`, `db/interchange.rs`). Therefore a
compensating delete of a history row **cannot lower a watermark** and cannot re-open a slot that a
minified import had closed. Without this fact, tentative-commit's reconcile step would be
unacceptable; with it, the blast radius is exactly one history row. This fact appears in neither the
review nor the PRD.

## 2. Quantifying the wall

> **Note on delta numbering.** **VD-S1 … VD-S6** are recorded in §1.4. Verification during §2–§6
> raised **three more** — **VD-S7** (§2.1, the attestation window is 3,999 ms), **VD-S8** (§2.3,
> "ten slots" should read "ten attestation windows") and **VD-S9** (§6.2.4, *this reordering was
> previously shipped and reverted as M-1*). **VD-S9 is the substantive one** and is cross-referenced
> from §4.1.1.

The point of this section is to separate two numbers that the review and the PRD merge: the
**mutex's throughput ceiling** (real, and what ARCH-P1-5 removes) and the **VC's actual per-slot
cost** (also real, and what ARCH-P1-5 does *not* touch). They differ by a factor that decides
whether ARCH-P1-5 is worth Phase 4.

### 2.1 The deadline budget

All constants read at HEAD:

| Quantity | Value | Source |
|---|---|---|
| Slot duration (mainnet) | 12,000 ms | `eth_types::SECONDS_PER_SLOT`, re-exported `crates/timing/src/lib.rs:14` |
| Attestation deadline (bps) | 3333 | `ATTESTATION_DUE_BPS`, `crates/timing/src/lib.rs:27` |
| **Attestation deadline (ms)** | **3,999 ms** | `due_ms(3333, 12000) = 3333 * 12000 / 10000`, `crates/timing/src/lib.rs:35-46` (doctest asserts `3999`) |
| Aggregate deadline | 8,000 ms | `AGGREGATE_DUE_BPS = 6667`, `crates/timing/src/lib.rs:33` |
| Per-sign timeout (default) | **4,000 ms** | `DEFAULT_SIGN_TIMEOUT`, `crates/signer/src/gate.rs:115` and `crates/signer/src/lib.rs:169` |

> **Verification delta VD-S7 — the attestation window is 3,999 ms, not 4,001 ms.** V6 and the review
> both quote a ~4,001 ms window. At HEAD the constant is a basis-points computation that floors to
> **3,999 ms**, deliberately (`timing/src/lib.rs:23-27`: *"the spec 1/3 mark (not the legacy
> `12000 / 3 = 4000 ms`)"*), regression-pinned in `crates/timing/tests/timing_m11.rs:44-59` and
> changed from 4,000 ms in v0.5.0 (`docs/releases/v0.5.0.md:72`). The 2 ms discrepancy does **not**
> change any conclusion — 3,999/200 = 19.995 still rounds to ≈20 — so V6's headline stands. Use
> 3,999 ms in any acceptance criterion or load profile that names the number, because 3,999 is what
> the scheduler will actually enforce.

### 2.2 The mutex ceiling (V6, first half — confirmed)

The serialized cost of one slashable sign is the whole stage→sign→commit window (§1.1), which is
sign-dominated: the `BEGIN IMMEDIATE`, one or two watermark reads, the rule check and one INSERT are
all microsecond-scale local SQLite work, while the sign is a network round trip.

```
signs_per_attestation_window = floor(3_999 ms / hold_ms)
```

| Remote-signer latency | Hold ≈ | Slashable signs per attestation window |
|---|---|---|
| 5 ms (local BLS) | ~5 ms | ~799 |
| 50 ms (same-DC Web3Signer) | ~50 ms | ~79 |
| **200 ms (the PRD's A-9 assumption)** | **~200 ms** | **19** (19.995 → 19 complete) |
| 500 ms (cross-region / HSM) | ~500 ms | 7 |

So at 200 ms the *global* ceiling is **≈20 slashable signs per attestation window**, against a
target of 200 keys. V6's headline number reproduces.

**The tail case is worse than the throughput case, and it is documented in-tree.** The per-sign
timeout is 4,000 ms (`gate.rs:115`) — *longer than the entire 3,999 ms attestation window*.
A single wedged remote signer therefore holds the global mutex past the deadline for **every**
validator, not just its own. `crates/signer/src/gate.rs:74-83` says this in as many words:

> *"A wedged signer would hold this write lock indefinitely, causing a signing blackout for ALL
> validators (they queue behind the same lock). The gate therefore wraps the sign call in a
> `tokio::time::timeout`."*

The timeout bounds the blackout; it does not prevent one. **This is the strongest argument for
ARCH-P1-5** and it is stronger than the throughput argument, because it is a correctness-adjacent
availability property that binds at *any* key count, not only above 100. It is worth carrying into
ARCH-P1-5's motivation explicitly — the PRD currently motivates the requirement on throughput alone
(`prd.md:788-789`).

### 2.3 What actually binds on the VC path (V6, second half — confirmed, with a correction)

The ceiling in §2.2 is a *contention* ceiling: it only bites when signs arrive concurrently. On the
VC path they do not.

`crates/rvc/src/orchestrator/attestation.rs:171-192`:

```rust
for duty in duties {
    let result = self.process_attestation_duty(duty).await;
    ...
    results.push(result);
}
```

No `join_all`, no `FuturesUnordered`, no `tokio::spawn` — each duty is fully awaited before the next
begins. The same sequential shape recurs at `aggregation.rs:96` and `sync_committee.rs:78,162,304`
(§1.4, VD-S2). The consequence is exact and unflattering:

| | Per-slot cost, 200 keys @ 200 ms |
|---|---|
| At HEAD (sequential loop, mutex held across sign) | 200 × 200 ms = **40,000 ms** |
| With a **zero-cost** slashing DB (mutex removed entirely) | 200 × 200 ms = **40,000 ms** |
| Deadline | 3,999 ms |

**The mutex is uncontended on this path**, because the caller never offers it a second concurrent
request. Removing contention from a lock that has none saves nothing. ARCH-P1-5 in isolation moves
the VC's 200-key attestation phase from 40 s to 40 s.

> **Verification delta VD-S8 — "40 s, ten slots" should read "ten attestation windows" (≈3.3 slots).**
> §1.4's VD-S2 states 40 s is "ten slots". At 12,000 ms per slot, 40,000 ms is **3.33 slots**; it is
> **10.0 attestation *windows*** (40,000 / 3,999 = 10.003). The "ten" is a count of missed deadlines,
> not of slots. The conclusion is unchanged and if anything understated: the phase overruns its
> deadline by 10×, and overruns the *slot itself* by 3.3×, so duties for slot *n* are still being
> signed during slot *n+3*. Prefer "≈10× the attestation deadline" in any acceptance criterion.

**Carry-forward (unchanged from VD-S2):** ARCH-P1-5's success metric M3 (`prd.md:993`) is real and
measurable, but goal **G6** (`prd.md:419`, "slashable signing scales to the target validator count")
is **not reachable from ARCH-P1-5 alone on the VC path**. Either ARCH-P1-15's load profile targets
the `signer-server` path, or a companion requirement makes the orchestrator loop concurrent — and if
the loop is made concurrent *first*, ARCH-P1-5 becomes the immediate next bottleneck. That ordering
dependency is not currently recorded in the PRD's phase table (`prd.md:1183-1184`).

### 2.4 Where the mutex genuinely binds: `signer-server` / `SigningGate`

The `signer-server` crate exposes signing over HTTP (`crates/signer-server/src/http_api/`) and gRPC
(`crates/signer-server/src/server/grpc.rs`) with a per-connection accept loop
(`http_api/accept_loop/`). Requests there arrive from *external* VCs, genuinely concurrently, with no
sequential loop upstream to throttle them — one shared `SigningGate` across transports
(`crates/signer-server/src/gate_shared_across_transports.rs`). Every slashable request funnels into
the same `SlashingDb` mutex. This is the deployment where the §2.2 ceiling and the §2.2 blackout are
both live, and it is the one ARCH-P1-15's load profile should target.

### 2.5 What is not measured today (V8)

`rvc_signer_slashing_tx_hold_duration_ms{kind}` is observed at `crates/signer/src/core.rs:219` and
regression-pinned by `crates/signer/tests/tx_hold_metric.rs` (file exists at HEAD). It measures the
right thing — `tx_start` is taken before `stage()` (`core.rs:265`) and elapsed after the sign
resolves (`core.rs:288`), so it spans the true hold, and it is recorded on **every** exit path
including `SlashingBlocked` (`core.rs:273`), commit failure (`:307`, `:427`) and both retain paths.

What does **not** exist at HEAD is any way to *drive* it: there is no benchmark, no load harness, and
no multi-key soak. `M3`'s Phase-0 baseline (`prd.md:993`, `:1002`) therefore cannot be captured with
what is in the tree — **ARCH-P1-15 must build the harness before Phase 0 can close**, which is a
sequencing constraint the PRD's phase table places in the wrong order (harness in Phase 5,
`prd.md:1184`; baseline required as a Phase-0 entry criterion, `prd.md:1179`). Flagged as A-S9.

## 3. Does SQLite WAL help? (verdict: no)

### 3.1 WAL is already on, and it is mandatory

WAL is not an available lever — it is spent. `configure_pragmas` (`crates/slashing/src/db/open.rs:217-248`)
sets `journal_mode=wal` via `pragma_update_and_check` and **hard-fails the open** if the result is
not `"wal"` (`:221-233`, `SlashingError::JournalMode`), unless the operator sets
`RVC_ALLOW_NON_WAL_SLASHING_DB=true`, which downgrades to a loud `tracing::error!`
(`:225-238`). So every production `SlashingDb` is already a WAL database. There is no
"turn on WAL" work item.

### 3.2 WAL gives reader/writer concurrency, never writer/writer

The SQLite documentation is explicit, and the verdict table's quotation is verbatim [1]:

> *"Because writers do nothing that would interfere with the actions of readers, writers and readers
> can run at the same time. **However, since there is only one WAL file, there can only be one writer
> at a time.**"*

and

> *"WAL provides more concurrency as readers do not block writers and a writer does not block readers.
> Reading and writing can proceed concurrently."*

Both sentences are about the **reader/writer** axis. The rvc critical section is a **writer**
occupying the single writer slot: `stage_block` and `stage_attestation` open the transaction with
`BEGIN IMMEDIATE` (`crates/slashing/src/stage.rs:357`, `:438`), which acquires the write lock
*immediately* rather than deferring it to first write — precisely so the EIP-3076 check and the
subsequent INSERT are one atomic unit. While that transaction is open across a 200 ms sign, the
single writer slot is occupied and **every** other writer waits, in WAL or out of it.

**Conclusion (V2 — confirmed).** WAL is orthogonal to the wall. It was chosen for durability and for
reader concurrency, and it delivers both; it cannot deliver writer concurrency because SQLite has
exactly one writer slot per database file.

### 3.3 What WAL *does* buy, which is worth keeping

Not nothing, and the redesign must not regress it:

- **Readers never block behind the sign.** `PRAGMA integrity_check` (`crates/slashing/src/db/mod.rs:256-259`),
  interchange `export`, and watermark reads are readers. Under WAL they proceed against the last
  committed snapshot while a sign is in flight. Under rollback-journal mode they would serialize
  behind the writer too, turning a 200 ms sign into a 200 ms stall for the metrics/export path.
- **Crash atomicity for the commit** — the property `synchronous=EXTRA` (`open.rs:241`) builds on.

### 3.4 Two gaps this section surfaced (not in the review or the PRD)

Both are cheap, both matter to the redesign, and neither is currently a requirement.

- **No `busy_timeout` is set.** A repo-wide grep of `crates/slashing/src` finds no `busy_timeout`
  pragma at HEAD. SQLite's default busy timeout is 0, so a *second process* attempting
  `BEGIN IMMEDIATE` against the same file gets an immediate `SQLITE_BUSY` error rather than waiting.
  In-process this is invisible (the `parking_lot::Mutex` at `db/mod.rs:59` serializes first and
  blocks properly), which is exactly why it has gone unnoticed. **After tentative-commit the hold
  window shrinks to microseconds and this stays benign; but any design that adds a second connection
  makes it a live error path** (§4.2).
- **No `locking_mode=EXCLUSIVE`.** Lighthouse sets it deliberately, with the comment *"put the
  database into exclusive locking mode, so that threads are forced to serialise all DB access (to
  prevent slashable data being checked and signed in parallel)"* [2]. rvc does not, so nothing at the
  SQLite layer prevents a **second rvc process** from opening the same slashing DB. Today the
  cross-process hazard is contained by `BEGIN IMMEDIATE` (§1.3's "authoritative double-sign
  serializer"). **This is a keep-list item for ARCH-P1-5**: whatever replaces the long transaction
  must still be safe against a second process, and adopting `locking_mode=EXCLUSIVE` — as
  Lighthouse does — is the cheapest way to make that explicit rather than emergent. Recorded as
  A-S6.

## 4. Candidate redesigns evaluated

Four candidates, scored against the properties the current design actually provides (§1) rather than
against the wall alone. A candidate that removes the wall and loses a row of this table has not
satisfied ARCH-P1-5 — that is what C1 means (`prd.md:1014-1029`).

| Property | HEAD | (a) Tentative-commit | (b) Per-pubkey conns / shards | (c) Finer-grained txns |
|---|---|---|---|---|
| DB lock held across the sign | **Yes** (200 ms) | **No** (µs + fsync) | **Yes** — unchanged | No, but see §4.3 |
| Concurrency gain vs HEAD | — | Real | **Zero** (one writer slot) | Real, but it *is* (a) |
| Double-sign authority | `BEGIN IMMEDIATE` held across sign | the **committed row** | unchanged | committed row |
| Retain-on-ambiguity (C1) | 3 of 4 classes commit | **preserved**, §6.1 | preserved | preserved |
| Unambiguous-no-signature | ROLLBACK | commit + compensating delete | ROLLBACK | commit + delete |
| Single-file EIP-3076 export/import | Yes | Yes | **Broken** if sharded to files | Yes |
| Cross-process safety | `BEGIN IMMEDIATE` | committed row + §3.4 | degraded (`SQLITE_BUSY`) | committed row |
| `!Send` type-level guarantee (§1.3) | Load-bearing | **weakened** (a real cost) | unchanged | weakened |
| C2 (audit-log-in-mutex) | live hazard | **dissolved** on sign path | unchanged | dissolved |
| Precedent in reference clients | none | **all three** (§4.4) | Lighthouse rejects it | — |

The verdict is (a). §4.1 states it precisely, including the part the PRD does not: where double-sign
authority moves to, and what is given up.

### 4.1 (a) Tentative-commit-then-reconcile

**Recommended (V1).** The name is slightly misleading and it is worth being precise: the commit is
not "tentative" in the database sense. It is a *real, durable* commit that happens **before** the
sign, and the "reconcile" is a narrow compensating delete on exactly one error class.

#### 4.1.1 The new ordering

```text
HEAD:      lock ─ BEGIN IMMEDIATE ─ check ─┤ 200 ms SIGN ├─ INSERT ─ COMMIT ─ unlock
                  └──────────────── mutex held ~200 ms ─────────────────────┘

Proposed:  lock ─ BEGIN IMMEDIATE ─ check ─ INSERT ─ COMMIT ─ unlock ─┤ 200 ms SIGN ├─ [compensate?]
                  └── mutex held ~µs + one fsync ──┘
```

> **Read VD-S9 (§6.2.4) before accepting this section.** This ordering — commit, then sign — was
> **previously shipped in rvc and reverted as bug M-1**, and its regression test is still in the tree
> (`crates/signer/tests/phantom_row_m1.rs:1-10`). The recommendation is not a re-introduction of that
> bug, and the difference is threefold: M-1 had **no compensation on any failure class**, so routine
> `KeyNotFound` failures left phantom rows; §4.1.1 step 4 adds a compensating delete on exactly that
> class; and §5.1 scopes the new ordering to `RetainStagedRow`, leaving the in-process/gate path on
> M-1's ordering untouched. Retention on the *ambiguous* classes — which M-1 treated as a defect — is
> now the deliberate safety property C1 protects, a requirement that changed with the `TimeoutPolicy`
> work (`core.rs:63-97`). **State this in the design doc**: a reviewer who remembers M-1 will
> otherwise reject the change on sight, and correctly so.

Concretely, against the code at HEAD:

1. `stage_*` (`stage.rs:341-381`, `:428-467`) is extended to perform the INSERT and `COMMIT` that
   currently live in `StagedBlock::commit` (`stage.rs:166-193`) / `StagedAttestation::commit`
   (`:248-276`), and to **return no guard** — instead a small `Send` receipt (pubkey, slot or
   source/target epochs, signing-root hex, and whether the row was newly inserted vs. an idempotent
   re-sign, i.e. today's `is_resign` / `is_duplicate` flags).
2. The `parking_lot::MutexGuard` is released at the end of that call. Nothing `!Send` survives it.
3. The BLS sign runs **outside** any lock. Because the receipt is `Send`, the sign no longer needs
   `Handle::block_on` on a blocking thread (`core.rs:284-287`, `:542`) — it becomes an ordinary
   `.await`, which is the "BLS sign lifted out of `spawn_blocking`" half of V1.
4. On the **unambiguous-no-signature** class only (`KeyNotFound`, `LocalRejected`,
   `UnsupportedSigningType` — `crates/crypto/src/error.rs:39-44`), a best-effort compensating
   `DELETE` removes the row the receipt names, in its own short transaction. Every other outcome
   does nothing, because the row is already where it needs to be.

#### 4.1.2 Where double-sign authority relocates — the question §1.3 forces

This is the part the PRD does not address and the single thing an implementer can get wrong.

At HEAD, `core.rs:500-504` names the authority explicitly: *"The authoritative double-sign serializer
is the SQLite `BEGIN IMMEDIATE` lock held by the staged guard."* Tentative-commit **removes that
lock from the sign window**, so the authority must move. It moves to the **committed row itself**:

- Under the new ordering, a second concurrent request for the same `(pubkey, slot)` or
  `(pubkey, source, target)` no longer *blocks* on a lock — it runs `check_block` /
  `check_attestation` (`stage.rs:369-372`, `:448-458`) against a row that is **already durably
  committed**, and is rejected with `SlashableBlock` / `SlashableAttestation`.
- This is strictly *stronger* than the lock in one respect and equal in the rest. The lock only
  serialized attempts that overlapped in time; the committed row rejects conflicting attempts
  **forever**, including after a crash and restart, and including from a second process.
- The window in which two racing requests can both pass `check_*` is now bounded by the duration of
  the short write transaction (µs) instead of by the sign (200 ms) — and inside that window
  `BEGIN IMMEDIATE` still serializes them, exactly as it does today. **The atomicity of
  check+INSERT+COMMIT is the invariant to protect**; it is preserved verbatim.

Two consequences to write into the design doc:

- **The per-pubkey `ValidatorLockMap` (§1.1 #2) stops being load-bearing for correctness** — it was
  already documented as a "performance/TOCTOU device" (`core.rs:500-504`). Keep it (it avoids
  queueing redundant work for one key) but the cancellation note must be rewritten, because its
  current text points at a lock that will no longer span the sign.
- **The `!Send` type-level guarantee weakens, and that is a genuine cost.** Today
  `parking_lot::MutexGuard` being `!Send` (`stage.rs:57-63`) makes the dangerous refactor
  *uncompilable* — a guard cannot cross an `.await`. After the change there is no guard to hold, so
  the compiler stops enforcing anything, and "check now, insert later" becomes expressible again.
  **Mitigation:** make the receipt type carry the invariant instead — a `#[must_use]` receipt that
  can only be produced by a function that has already committed, with no public constructor. That
  converts a type-level guarantee into a weaker API-level one; the difference must be covered by the
  §6.2 tests rather than by the compiler. Do not let this trade-off go unrecorded — it is the
  strongest argument *against* the recommendation.

#### 4.1.3 Why this is not the design C1 rejects

C1 rejects *"stage → release → sign → re-check-and-commit"* (`prd.md:1022-1023`) because it "cannot
retain a released row". The distinction is exact and worth stating so a reviewer does not
pattern-match the two:

| | Rejected design | Tentative-commit |
|---|---|---|
| State of the row while signing | **staged, uncommitted** (or discarded) | **committed, durable** |
| On timeout / ambiguous error | nothing to retain — row is gone | **nothing to do** — already retained |
| Second check after the sign | required (`re-check`) | **none** |
| Failure mode | signature may exist with no record | record may exist with no signature |

The rejected design's hazard is *record loss*; tentative-commit's residual is *a spare record*. Those
are not symmetric: a spare record costs one wasted slot, a lost record costs the stake.

#### 4.1.4 What it costs

- Hold duration drops from ≈200 ms to the local work plus **one fsync** (§5, V12).
- One new failure mode: the compensating delete can fail. It fails **safe** (§6.1).
- Metric continuity: `rvc_signer_slashing_tx_hold_duration_ms` (`core.rs:219`) currently spans
  `tx_start` at `core.rs:265` to after the sign at `:288`. After the change it must be re-scoped to
  the *transaction*, not the sign — otherwise M3 records a spurious ~100× improvement that is
  measuring a redefinition rather than a fix. **This is an acceptance-criterion-level trap**
  (recorded as A-S4) and `crates/signer/tests/tx_hold_metric.rs` must be updated deliberately, not
  incidentally.

### 4.2 (b) Per-pubkey connections / sharded DB

**Reject (V3).** This is the option the PRD lists as admissible (`prd.md:793`, `:1024`) and it should
be struck (VD-S1). It splits into two sub-variants, both of which fail, for different reasons.

#### 4.2.1 Multiple connections, one database file — buys exactly zero

Replacing `conn: Mutex<Connection>` (`crates/slashing/src/db/mod.rs:59`) with a pool keyed by pubkey
removes the *`parking_lot`* serializer (§1.1 #3) but leaves the *SQLite* one (§1.1 #4) untouched.
Per §3.2 and [1] there is one writer slot per file, and `BEGIN IMMEDIATE` (`stage.rs:357`, `:438`)
takes it at stage time and holds it across the sign. So connection *k* stages and signs; connections
1…*n* all issue `BEGIN IMMEDIATE` and receive **`SQLITE_BUSY` immediately**, because no
`busy_timeout` is configured (§3.4).

The result is not "the same wall": it is **worse**. Today contenders block politely on a fair
`parking_lot::Mutex` and proceed in turn. After the change they fail fast with an I/O error that
`stage_*` surfaces as a `SlashingError`, which `core.rs:271-275` converts to
`SigningGateError::SlashingBlocked` — a *refusal to sign* where HEAD merely *queues*. Adding a
`busy_timeout` restores the queueing and lands back at the original wall with more moving parts.

Lighthouse reached this conclusion and encoded it: `pub const POOL_SIZE: u32 = 1;` plus
`conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?` with the comment *"put the database into
exclusive locking mode, so that threads are forced to serialise all DB access (to prevent slashable
data being checked and signed in parallel)"* [2]. A production client that shipped this exact idea
deliberately went the **opposite** direction.

#### 4.2.2 Sharding into per-pubkey database *files* — breaks four working properties

This variant does buy real writer concurrency (one writer slot per file), which is why it is
tempting. It is still a reject, because each of the following is a working property at HEAD that has
no cheap replacement:

| Property broken | Evidence at HEAD |
|---|---|
| **Single-file EIP-3076 interchange** — `import`/`export` are defined over one file for all validators; sharding forces an N-file fan-in/fan-out with its own atomicity story, and the interchange metadata (`interchange_format_version`, `genesis_validators_root`) is per-file | `crates/slashing/src/db/interchange.rs`; conformance runner assumes one `SlashingDb` (`tests/conformance.rs:175`, `:320`) |
| **GVR pinning** — one pinned genesis-validators-root per DB, cached in a `OnceLock` and checked before the mutex (M-6) | `db/mod.rs:150` (`pinned_gvr`), `stage.rs:341-351`; N files means N pins that can silently diverge |
| **Backup before migration** — one atomic `<path>.bak.<UNIX_TS>` snapshot | `db/migrations.rs:89-135`; N-file backup is not atomic across files |
| **Integrity check** — one `PRAGMA integrity_check` answers "is the slashing DB sound?" | `db/mod.rs:256-259`; with shards, a partial-corruption answer is meaningless |

Add the operational cost: file-descriptor pressure and per-file WAL/SHM sidecars at 200+ keys (the
sidecar chmod loop at `open.rs:190-205` runs per file), and a migration path from one file to N with
no rollback.

**Carry-forward.** Amend ARCH-P1-5 (`prd.md:788-793`) and C1 (`prd.md:1024`) so the admissible list
reads `{tentative-commit-then-reconcile}`, with `{group commit}` (§5) as a measured add-on, and
record per-pubkey connections and per-pubkey files as **rejected, with the reasons above**, so this
is not re-opened in Phase 4 by someone reading only the PRD.

### 4.3 (c) WAL-mode + finer-grained transactions

**Necessary but not a distinct design (V4).** WAL is already on and is orthogonal (§3), so this
candidate reduces to "make the transaction finer-grained". The trap is that the transaction is
**already minimal in work** — §1.1 enumerates it: one `BEGIN IMMEDIATE`, one or two watermark reads,
one in-memory rule check, one INSERT, one `COMMIT`. There is no fat to trim. Every microsecond of
*work* in that transaction is load-bearing.

What makes it long is the **one non-database statement wedged into the middle of it**: the sign. So:

> "Finer-grained transactions" applied honestly to this code has exactly one degree of freedom —
> take the sign out of the transaction. Doing that **is** tentative-commit (§4.1). There is no
> intermediate option.

The only genuinely distinct variant is **splitting the transaction in two** — `BEGIN; check; COMMIT`
then later `BEGIN; INSERT; COMMIT` — and that is precisely the *"stage → release → sign →
re-check-and-commit"* shape C1 rejects by name (`prd.md:1022-1023`), because between the two
transactions there is no row to retain when the sign comes back ambiguous. It also re-opens the
TOCTOU that `BEGIN IMMEDIATE` closes.

**Conclusion:** keep this candidate in the design record only as the reasoning above — it is where a
reviewer's intuition will go first, and the explanation of why it collapses into (a) or into the
rejected design is the useful artefact, not the option itself.

### 4.4 (d) What the reference implementations do

Three independent production clients, three different storage engines, three different concurrency
primitives — and **one shared ordering**: the slashing record is durably written **before** the
signature is produced, and no lock spans the sign. All three were read at source (V5 — confirmed).

| | Storage | Serializer | Serializer scope | Record written… | Lock held across sign? |
|---|---|---|---|---|---|
| **Lighthouse** [2] | SQLite, one file | `POOL_SIZE = 1`, `locking_mode=EXCLUSIVE`, `TransactionBehavior::Exclusive` | whole DB | inside the txn, **committed before return** | **No** |
| **Web3Signer** [3][4] | PostgreSQL | `pg_advisory_xact_lock(lockType, validatorId)` inside `READ_COMMITTED` txn | per (validator, lock type) | inside the txn, committed on return | **No** |
| **Dirk** [5][6] | per-account key/value store | in-process locker keyed by 48-byte pubkey | per pubkey | inside the rules check, **before `APPROVED`** | **No** |
| **rvc @ HEAD** | SQLite, one file | `parking_lot::Mutex` + `BEGIN IMMEDIATE` | whole DB | **after** the sign | **Yes** |

#### Lighthouse

`check_and_insert_block_signing_root` opens
`conn.transaction_with_behavior(TransactionBehavior::Exclusive)`, runs the check-and-insert, and then
`txn.commit()?; Ok(safe)` — the commit is inside the DB layer, before the function returns [2]. The
caller then signs, in that order:

```rust
// lighthouse_validator_store/src/lib.rs, sign_abstract_block
let slashing_status = ... self.slashing_protection.check_and_insert_block_proposal(
    &validator_pubkey, &block.block_header(), domain_hash,
) ...;
match slashing_status {
    Ok(Safe::Valid) => {
        let signature = signing_method.get_signature(...).await?;
```

The `.await` on the signature happens after the transaction has committed and the exclusive
transaction has ended. Attestations follow the same shape via `check_and_insert_attestations`, which
returns a vector of per-attestation `Safe`/`NotSafe` results that gate a subsequent batch of signs.
Note the direct relevance to §5: Lighthouse **batches** the attestation check-and-insert for all
validators into one transaction, which is exactly the group-commit mitigation (V12).

#### Web3Signer

`DbSlashingProtection.maySignAttestation` / `maySignBlock` are the whole protection surface, and they
return a **boolean** — the signature is produced by a different component afterwards [3]:

```java
return jdbi.inTransaction(READ_COMMITTED, handle -> {
  lockForValidator(handle, LockType.ATTESTATION, validatorId);
  // watermark / conflict / surround checks, then insert
  return true;
});
```

with the lock being a PostgreSQL transaction-scoped advisory lock [4]:

```java
handle.execute("SELECT pg_advisory_xact_lock(?, ?)", lockType.lockOrdinal(), validatorId)
```

`LockType` is `BLOCK(0)` / `ATTESTATION(1)`, so the lock is per (validator, message-type) — far finer
than rvc's global mutex — and because it is `_xact_` scoped it is released by the commit, i.e.
**before** the caller signs. Web3Signer is also the strongest available evidence for V3: a
multi-writer engine was chosen *and* the lock was still narrowed to the validator, because
global serialization was not acceptable at scale.

#### Dirk

Dirk splits the two halves across services. `services/ruler/golang/runner.go` `RunRules` takes a
per-pubkey lock:

```go
for i := range rulesData {
    var lockKey [48]byte
    copy(lockKey[:], rulesData[i].PubKey)
    s.locker.Lock(lockKey)
    defer s.locker.Unlock(lockKey)
}
```

The rule implementation persists the new protection state before returning: `OnSignBeaconAttestation`
fetches prior state via `fetchSignBeaconAttestationState`, validates, then calls
`storeSignBeaconAttestationState(ctx, metadata.PubKey, state)` → `s.store.Store(ctx, key, state.Encode())`
**before** returning its result [6]. The `defer`red unlocks fire when `RunRules` returns. Only then
does the signer act (`services/signer/standard/signbeaconattestation.go`) [5]:

```go
results := s.ruler.RunRules(ctx, credentials, ruler.ActionSignBeaconAttestation, rulesData)
// case rules.APPROVED: // Nothing to do.
signature, err := signRoot(ctx, account, signingRoot[:])
```

**Refinement to V5's wording:** the verdict table says Dirk writes protection "as part of signing".
More precisely, Dirk writes it as part of **rule evaluation, which completes and unlocks before
signing**. The distinction strengthens rather than weakens the verdict.

**Note what Dirk does *not* do:** there is no compensating delete. If `signRoot` fails after
`OnSignBeaconAttestation` stored the state, the state stays. Dirk is therefore permanently in
rvc's `RetainStagedRow` posture for **all four** error classes — more conservative than even the
design proposed in §4.1, which compensates on the unambiguous class. That is direct production
precedent that retain-on-ambiguity survives commit-before-sign (V7, §6.1).

## 5. Recommendation

**Adopt tentative-commit-then-reconcile (§4.1), scoped to the `RetainStagedRow` policy, with the
critical section reduced to a short write transaction and the BLS sign lifted out of
`spawn_blocking`.** Amend the PRD's admissible list per §4.2. Land ARCH-P0-9 first (§7).

### 5.1 Scope it to `RetainStagedRow` — do not convert both policies

`DiscardStagedRow` exists for **in-process** backends, where "the backend cannot complete a durable
slashable sign after the client future is dropped (pure in-process BLS)" (`core.rs:87-91`). For those
backends the sign is sub-millisecond, so:

- the wall does not exist (§2.2: ~799 signs/window at 5 ms), and
- discard-on-timeout is *sound* precisely because no signature can escape.

Converting the discard path to commit-then-delete would make in-process signs **less** accurate for
no throughput gain, and would put a compensating delete on the hot path that has no failure to
compensate. **Keep `DiscardStagedRow` on the current stage→sign→commit ordering.** The two policies
already diverge structurally in `core.rs:346-450`; this makes the divergence explicit at the
*ordering* level rather than only at the commit/rollback level. Recorded as A-S2.

This also shrinks the blast radius of the riskiest change in the initiative (R1): the new ordering
only ever runs on paths whose policy resolved to `Retain`, and `fail_closed_max` (`core.rs:114-121`)
already guarantees that resolution is conservative.

### 5.2 The secondary wall is fsync (V12 — confirmed)

Once the sign leaves the transaction, the transaction's cost is dominated by making it durable.
`configure_pragmas` sets `synchronous=EXTRA` (`open.rs:241`) and, on macOS, `fullfsync=ON`
(`open.rs:244-245`) — the latter because *"macOS's `fsync(2)` does not guarantee this without
F_FULLFSYNC"* (`open.rs:215-216`). `EXTRA` is `FULL` plus a directory fsync. So **every commit is at
least one real device-level flush**, and at 200 keys that is 200 serialized flushes per attestation
window.

Order-of-magnitude (author's estimate, **not measured** — no harness exists, §2.5):

| Storage | Plausible fsync | 200 serialized commits | vs 3,999 ms window |
|---|---|---|---|
| Enterprise NVMe w/ PLP | ~0.05–0.2 ms | 10–40 ms | fine |
| Consumer NVMe / SSD | ~0.5–2 ms | 100–400 ms | fine |
| macOS `F_FULLFSYNC` | ~1–10 ms | 200 ms–2 s | **marginal** |
| Network / virtualized disk | ~5–20 ms | 1–4 s | **binds** |

The honest conclusion: on good hardware fsync will *not* bind, and on macOS or network storage it
may. **Measure before mitigating** — this is exactly what ARCH-P1-15's harness is for, and it is a
second reason the harness must precede the redesign, not follow it.

**Do not "fix" this by weakening the pragmas.** `synchronous=EXTRA` + `fullfsync=ON` is the property
that makes the committed row a *durable* double-sign authority (§4.1.2). Lowering it to `NORMAL`
would convert a crash into a lost record — the one failure class the whole design exists to prevent.

**Mitigation, if measured to bind: group commit.** Batch N pending checks into one transaction, one
`COMMIT`, one fsync, then release all N to sign concurrently:

```text
collect N requests ─ BEGIN IMMEDIATE ─ check₁…checkₙ ─ INSERT₁…INSERTₙ ─ COMMIT (1 fsync) ─ unlock
                                                                          └─ sign₁…signₙ in parallel
```

This preserves commit-before-sign exactly, and it has direct precedent: Lighthouse's
`check_and_insert_attestations` already takes a *slice* of attestations and returns a vector of
per-attestation results from one exclusive transaction [2]. The cost is latency-vs-throughput tuning
(a batching window) and a more complex partial-failure story — one slashable request in a batch must
reject only itself. **Design it as a follow-on, gated on measurement; do not build it speculatively.**

### 5.3 Sequencing

1. **ARCH-P0-9** — move audit-log emission out of the mutex, both call sites (§7, VD-S5).
2. **ARCH-P1-15's harness** — build it *early*, not in Phase 5. Capture the M3 baseline against the
   `signer-server` path (§2.4), where the mutex actually binds.
3. **Proof harness first (TDD/RED)** — the §6.2 tests, written against the *current* ordering, where
   the error-class matrix must already pass. They are the switchover gate.
4. **The reordering itself**, scoped to `RetainStagedRow` (§5.1).
5. **Re-measure**; only then consider group commit (§5.2).
6. **Companion work** for G6 on the VC path (§2.3) — the sequential orchestrator loop.

### 5.4 Effort (V13)

**10–15 engineering days**, excluding the ARCH-P1-15 load harness. This is an **author's estimate
based on the enumerated work below, not a measured or cited figure** — treat it as a planning input,
not evidence.

| Work item | Days |
|---|---|
| Reorder `stage_*` to insert+commit; define the `Send` receipt type; delete/repoint the guard API | 2–3 |
| Compensating delete + its own short transaction + failure logging | 1 |
| Lift the sign out of `spawn_blocking`; rewrite the cancellation note; keep `ValidatorLockMap` | 2 |
| Re-scope `rvc_signer_slashing_tx_hold_duration_ms` + update `tx_hold_metric.rs` (A-S4) | 0.5 |
| Error-class × policy matrix test (§6.2) | 2 |
| Crash/cancellation-injection test (§6.2) | 2–3 |
| Concurrency proptest (§6.2) | 1.5–2 |
| Docs: `stage.rs:32-48` rationale rewrite (VD-S4), ARCHITECTURE.md, C1 amendment | 1 |

The table sums to **12–14.5 days**, which sits inside V13's 10–15 band; the band's lower end assumes
the receipt-type refactor is smaller than estimated, not that any row is skipped.

**Excluded from the estimate**, on the same basis as the ARCH-P1-15 harness: the `!Send` mitigation
(§4.1.2) if it turns out to require an API shape that touches every call site, and resolution of the
A-12/R9 cross-plan pin on `stage.rs` (§7.3), which is a negotiation rather than engineering work.
Either can push the total past 15 days. **If both bind, re-estimate rather than compressing the test
families in §6.2.3** — they are the switchover gate, and cutting them is the one economy that
converts a schedule risk into a safety risk.

## 6. Migration-safety argument

The safety claim has two halves, and they need different kinds of proof:

1. **The rule engine is unchanged.** EIP-3076 verdicts for any given history must be bit-identical
   before and after. This is provable with the existing 38 conformance vectors, which is exactly what
   they are for — and exactly the limit of what they can do (§6.2).
2. **The ordering is safe.** No signature may exist without its record; retain-on-ambiguity must hold
   on every error class; a crash at any point must leave a state that fails closed. **None of this is
   testable with the conformance vectors** and it needs three new test families (§6.2).

The invariant to hold in mind throughout, stated as the asymmetry it is:

> **A record without a signature is a wasted slot. A signature without a record is a slashing.**
> Every design decision below resolves ties toward the first.

### 6.1 How to prove retain-on-ambiguity survives

**Verdict V7 — confirmed, case by case.** The argument is a four-row case analysis over the error
classes established in §1.2, restricted to `RetainStagedRow` (§5.1). It is not an appeal to
intuition: each row is decided by what is *durably in the database* at the moment the sign resolves.

#### 6.1.1 The four error classes, before and after

| Error class | Source | HEAD (`Retain`) | Tentative-commit | Observable difference |
|---|---|---|---|---|
| **Sign succeeded** | `core.rs:295-313` | row staged → `commit_row()` → **row present** | row **already committed** → no action | **None.** Row present, signature returned. |
| **Timeout** (`tokio::time::timeout` elapsed) | `core.rs:292`, `:346-375` | `retain_staged_row` → **COMMIT** → row present; returns `SigningFailed("signer timed out")` | row **already committed** → no action; same error | **None.** |
| **Ambiguous signer error** (`RemoteSignerError`, `InvalidRemoteSignature`, transport/HTTP) | `core.rs:342`, `:379-408` | `retain_staged_row` → **COMMIT** → row present; returns `SigningFailed(msg)` | row **already committed** → no action; same error | **None.** |
| **Unambiguous no-signature** (`KeyNotFound`, `LocalRejected`, `UnsupportedSigningType`) | `core.rs:316-338`, `crypto/src/error.rs:39-44` | `discard_row()` → **ROLLBACK** → row absent | row committed → **compensating DELETE** → row absent *if the delete succeeds*; row **present** if it fails | Only on delete failure: a spare row instead of no row — **strictly more conservative**. |

Three of the four classes are **behaviourally identical, not merely equivalent**: under `Retain` the
current design *already commits* on success, timeout and ambiguous error. Tentative-commit simply
performs that same commit earlier. There is no state in which HEAD retains a row and the new design
does not.

**The commit-failure row deserves separate mention.** At HEAD, `commit_row()` can fail on all three
of those classes and yields `CommitFailed { signing_root, source }` (`core.rs:300-312`, `:420-432`)
*after* the sign has already been attempted — i.e. a signature may exist on the wire and the record
may have failed to persist. **Tentative-commit eliminates this window entirely**: if the commit
fails, it fails *before* the sign is attempted, so no signature can exist. This is a real safety
*improvement*, and it is the strongest under-sold argument for V1. It should be an explicit
acceptance criterion, not a side effect.

#### 6.1.2 Why the compensating delete is bounded — the VD-S6 dependency

The fourth row is only acceptable because deleting a history row is a **local, non-cascading**
operation in this schema. That rests on one fact, and if the fact were false the whole design would
fail:

> **The signing path never raises watermarks.** `crates/slashing/tests/conformance.rs:18-21`:
> *"production signing does not auto-raise watermarks after each sign — that remains history-table
> driven on the complete path."* Watermarks are raised only by interchange `import`
> (`conformance.rs:31-34`, `crates/slashing/src/db/interchange.rs`); the test harness raises them
> itself precisely *because* production does not (`conformance.rs:307-317`).

Consequences, in order:

1. Committing the row before the sign **cannot** raise a watermark, so it cannot retroactively close
   slots or epochs beyond the row itself.
2. Deleting the row **cannot lower a watermark**, so it cannot *re-open* a slot that a minified
   import had closed. The floor established by `import` is untouched by both operations.
3. The blast radius of the compensating delete is therefore **exactly one row in `blocks` or
   `attestations`** — the one the receipt names, identified by the same `(pubkey, slot, gvr)` /
   `(pubkey, source_epoch, target_epoch, gvr)` key the INSERT used (`stage.rs:176-187`, `:258-270`).

**Make this dependency a test, not a comment.** A regression that started raising watermarks on the
signing path would silently make the compensating delete unsound. Recorded as A-S7 and as the fourth
item in §6.2.

#### 6.1.3 What happens when the compensating delete fails — the "fails safe" mechanism

V7 claims every failure of the compensating delete fails safe. Spelled out rather than asserted:

- **The delete never runs before the sign resolves**, so it cannot race the sign.
- **If the delete fails** (SQL I/O error, disk full, mutex poisoned, process killed between the sign
  failure and the delete), the row **stays committed**. The validator's state is then: no signature
  was produced (this is the *unambiguous* class — by construction no signature can exist,
  `crypto/src/error.rs:37-38`: *"True when no remote signature can have been produced"*), and a
  history row exists for that slot/epoch pair.
- **The cost of that state** is that a *future legitimate* sign at the same `(pubkey, slot)` with a
  **different** signing root will be rejected as slashable — one lost proposal or attestation, an
  inactivity penalty on the order of one duty. A same-root re-sign is **still permitted**, because
  the resign path (`is_resign` / `is_duplicate`, `stage.rs:175`, `:257`) is an EIP-3076-sanctioned
  path and is what a retry after `KeyNotFound` → key re-import would actually do.
- **The cost is never a slashing**, because a slashing requires two *conflicting signatures*, and
  this failure mode produces zero signatures.

So the failure ladder is: delete succeeds → identical to HEAD; delete fails → one wasted duty. The
design has no branch that produces a signature without a record. That is the whole of V7.

**Operational requirement:** the delete failure must be loud — `error!` with pubkey, slot/epochs and
signing root, plus a counter (e.g. `rvc_signer_slashing_compensate_failed_total`) so operators can
see accumulating spare rows rather than discovering them as unexplained missed duties. Recorded as
A-S5.

#### 6.1.4 The one property that genuinely weakens

Stated plainly so it is not lost among the reassurances: **the `!Send` compiler guarantee**
(§1.3 #2, `stage.rs:57-63`). At HEAD, a refactor that let a runtime cancel between check and record
**does not compile**. After the change it compiles, and only tests stand between the codebase and
that bug. §4.1.2 proposes a `#[must_use]`, no-public-constructor receipt as partial replacement;
§6.2's cancellation-injection family is the rest. This is the residual risk of V1 and it belongs in
the PRD's R1 mitigation text, which currently cites only the conformance vectors (`prd.md:1192`).

### 6.2 Do EIP-3076 conformance vectors exist in-tree, and are they sufficient?

**Exist: yes (V9). Sufficient: no (V10).**

#### 6.2.1 What exists

**38 official vectors**, one JSON file each in `crates/slashing/tests/conformance/` (count verified
by glob at HEAD), from the `eth-clients/slashing-protection-interchange-tests` repository
(`crates/slashing/tests/conformance.rs:1-4`). The runner declares them with a
`conformance_test!` macro (`conformance.rs:393-411`) invoked 38 times (`:418-473`), each generating
**two** tests — `complete` and `minimal_conservative` — for **76 test functions total**.

Their quality is high and should be preserved verbatim:

- They drive the **production** decision path, not a shadow implementation: *"Every block/attestation
  verdict comes from the production `stage_* → commit()/discard()` path"* (`conformance.rs:8-21`),
  via `stage_and_commit_block` / `stage_and_commit_attestation` (`conformance.rs:41`).
- They cover both EIP-3076 strategies (full history and minified/watermark), including the
  strategy-divergent fixtures (`*_iff_minified`, `*_fail_iff_imported`), resign cases, surround
  votes, and `source > target` edge cases.

#### 6.2.2 Why they cannot prove the new ordering

Three independent reasons, each sufficient on its own:

1. **EIP-3076 does not specify ordering or durability.** Verified directly against the spec [7]: it
   defines *conditions on what may be signed* (the five refusal rules) and the interchange file
   format. It says nothing about when a record must be persisted relative to signature release,
   nothing about fsync, nothing about crash-safety, nothing about concurrency. A spec that is silent
   on a property cannot have vectors that test it.
2. **There is no signer in the loop.** The runner calls `stage_and_commit_block(&db, …)` — it takes a
   `&SlashingDb` and never a `Signer`. **No sign is ever attempted, so no sign can ever fail**, and
   the entire §1.2 error-class table — the thing C1 protects — is unreachable from these fixtures.
   This is the decisive reason.
3. **They are single-threaded and single-outcome.** Each runner constructs a fresh
   `SlashingDb::open_in_memory()` (`conformance.rs:175`, `:320`) and walks steps sequentially. No
   concurrency, no cancellation, no crash.

**They will pass identically before and after the reordering.** That is exactly their value — they
pin the rule engine against regression, which is half the safety claim (§6, item 1) — and exactly
their limit: they are **blind to the change under test**. Using "passes the EIP-3076 conformance
vectors" as ARCH-P1-5's proof of ordering safety (`prd.md:796-797`) would be a green test for an
untested property (VD-S3). Keep the criterion, but **as a non-regression gate**, and add the
following.

#### 6.2.3 What must be added

**(A) Error-class × policy matrix test.** The direct proof of C1/V7. A parameterized test over
`{sign OK, timeout, ambiguous error, unambiguous no-signature, commit failure}` ×
`{DiscardStagedRow, RetainStagedRow}` asserting, for each cell, the **post-conditions**: row present
or absent, error variant returned, and — new — that no signature was returned when a row is absent.
The existing test doubles make this cheap: a stalling `Signer` (`gate_sign_timeout.rs:9-10`), an
empty `CompositeSigner` for `KeyNotFound` (`phantom_row_m1.rs:62`), and the `fail_next_commits`
inject (`stage.rs:50-55`) for the commit-failure row. **Write it against HEAD first**, where it must
already pass — that is the RED/GREEN discipline CLAUDE.md requires, and it makes the matrix a true
switchover gate rather than a post-hoc rationalization.

**(B) Crash / cancellation-injection test.** For each injection point — after `COMMIT` and before the
sign; during the sign; after a failed sign and before the compensating delete; during the delete —
assert the surviving state is one of `{no row, no signature}` or `{row, signature}` or
`{row, no signature}`, and **never** `{no row, signature}`. Process-kill variants need a file-backed
DB and a subprocess; future-drop variants are in-process. This family replaces what the `!Send`
compiler guarantee used to provide for free (§6.1.4), so it is not optional.

**(C) Concurrency proptest.** N concurrent slashable signs over an interleaved set of pubkeys, slots
and epochs, with randomized signer outcomes and latencies, asserting the global invariant: *for every
signature returned, a committed row exists that authorizes it, and no two returned signatures
conflict under EIP-3076.* This is the family that would catch a mistake in §4.1.2's relocation of
double-sign authority, and it is the only one that exercises the property ARCH-P1-5 exists to
enable — genuine concurrency.

**(D) Watermark-invariant test.** Assert that a full stage→sign→commit cycle leaves
`get_block_watermark` / `get_attestation_watermark` **unchanged**. This pins VD-S6, the fact the
compensating delete's soundness rests on (§6.1.2). It is three lines and it protects the load-bearing
assumption.

#### 6.2.4 Existing tests that already cover part of this — and one that is a warning

| Test | Covers | Under the new ordering |
|---|---|---|
| `crates/signer/tests/gate_sign_timeout.rs` | timeout → ROLLBACK, no phantom row, `SigningFailed("signer timed out")` | **Unaffected** — the gate uses `DiscardStagedRow`, which §5.1 leaves on the current ordering |
| `crates/signer/tests/phantom_row_m1.rs` | `KeyNotFound` → no committed row | **Becomes the compensating-delete test** — see below |
| `crates/signer/tests/commit_failed_path.rs` | `CommitFailed` surfacing | Must be re-pointed: commit failure now precedes the sign (§6.1.1) |
| `crates/signer/tests/gate_per_validator_lock.rs` | per-pubkey lock behaviour | Re-validate: the lock stops being correctness-load-bearing (§4.1.2) |
| `crates/signer/tests/tx_hold_metric.rs` | M3 metric emission | Must be re-scoped deliberately (A-S4) |

> **Verification delta VD-S9 — this exact reordering was once reverted as a bug (M-1), and the
> regression test is still in the tree.** `crates/signer/tests/phantom_row_m1.rs:1-10` documents:
> *"Before the fix, `SignerService::sign_attestation` and `sign_block` called `check_and_record_*`
> (which committed the row immediately) and only then called `signer.sign`. A signing failure left a
> committed row in the DB, causing the next legitimate sign attempt to look like a DoubleVote. After
> the fix, these methods use the stage + commit-on-success pattern."*
>
> **ARCH-P1-5 proposes moving back to commit-before-sign.** This is not a contradiction, but it is a
> fact that must be stated in the design doc, because a reviewer who remembers M-1 will otherwise
> reject the change on sight. The difference is precise:
>
> - **M-1's bug** was commit-before-sign with **no compensation on any failure class**, so *every*
>   signer failure — including the routine `KeyNotFound` — left a phantom row.
> - **The proposal** is commit-before-sign **plus** a compensating delete on the unambiguous
>   no-signature class (§4.1.1 step 4), **plus** scoping to `RetainStagedRow` (§5.1) so the
>   in-process/gate path keeps M-1's ordering unchanged.
> - Retention on the *ambiguous* classes, which M-1 treated as a bug, is now the **deliberate safety
>   property** C1 protects. The intervening `TimeoutPolicy` work (`core.rs:63-97`) is what changed
>   the requirement.
>
> **Usefully, `phantom_row_m1.rs` becomes the highest-value test in the suite**: it injects exactly
> the unambiguous class (`KeyNotFound`, empty `CompositeSigner` at `:62`) and asserts the row is
> absent afterwards (`:79`). Under the new ordering it passes **only if the compensating delete
> works**. Do not rewrite or relax it — re-point its doc comment and keep the assertion identical.

### 6.3 Switchover plan and rollback

#### 6.3.1 Ordered switchover

The ordering matters more than usual here, because steps 1–3 are all **provably no-ops** on
behaviour, which means any test that changes colour during them is a real finding.

| Step | Action | Gate before proceeding |
|---|---|---|
| 0 | Land **ARCH-P0-9** (audit-log out of the mutex, both call sites — §7) | Existing suite green; C2 closed |
| 1 | Build the **§6.2 (A)–(D)** test families against **HEAD's** ordering | All four pass **unchanged** on `0ae9a09`. If (A) does not pass at HEAD, the §1.2 table is wrong and everything downstream is void |
| 2 | Build the **ARCH-P1-15 harness**; capture the M3 baseline on the `signer-server` path (§2.4) | A number exists for p99 hold duration |
| 3 | Introduce the `Send` receipt type **alongside** the guard API; no call-site behaviour change | 76 conformance tests + (A)–(D) green |
| 4 | **Flip the ordering**, `RetainStagedRow` paths only (§5.1) | (A)–(D) green; `phantom_row_m1.rs` green **without modification to its assertions**; 76 conformance tests green |
| 5 | Lift the sign out of `spawn_blocking`; re-scope the M3 metric (A-S4) | Full suite; re-measure M3 |
| 6 | Re-measure; decide on group commit (§5.2) **only if fsync is shown to bind** | Measured, not assumed |

**Step 4 is the only step that changes behaviour.** Everything before it is additive and everything
after is mechanical. That is deliberate: it makes the bisect target a single commit.

#### 6.3.2 Rollback

- **Before step 4:** revert is trivial — steps 1–3 add tests and an unused type.
- **At step 4:** the change is one ordering decision inside `stage_*` plus the compensating delete.
  Keep it a **single revertible commit**, and do not mix it with the `spawn_blocking` lift (step 5),
  which touches many call sites and would make the revert large. This is the main reason steps 4 and
  5 are separated.
- **Do not add a runtime feature flag or env toggle to switch orderings.** Two live orderings over a
  slashing database means two sets of crash-safety semantics and a state that can be written by one
  and read by the other. The revert path is `git revert`, not a config knob. Note also that the repo
  restricts env vars to security opt-outs (C3, `prd.md:1041-1047`) — an ordering toggle would violate
  that rule. Recorded as A-S8.

#### 6.3.3 Data compatibility

There is **no schema change and no migration**. The rows written are byte-identical — same tables,
same columns, same `AUDIT_ORIGIN` value (`stage.rs:85`), same INSERT statements (`stage.rs:176-187`,
`:258-270`). Only the *time* at which the INSERT commits changes. Consequently:

- A database written by the new code is readable by the old code and vice versa.
- EIP-3076 export/import is unaffected; interchange output is unchanged.
- **Downgrade is safe**, which is what makes step 4's revert genuinely available in production rather
  than only in theory. Worth stating explicitly in the release notes, because operators will ask.

The one residual: a database from the new code may contain a **spare row** from a failed compensating
delete (§6.1.3). Old code reads it as an ordinary history row and refuses a conflicting sign — the
conservative outcome. No corruption, no incompatibility.

## 7. Interaction with C2 (audit-log deadlock) and the other constraints

### 7.1 C2 — tentative-commit dissolves it on the sign path (V11 — confirmed)

**The hazard at HEAD.** `PubkeyScopedDb::stage_block` calls `self.db.stage_block(...)` at
`scoped.rs:68`, which returns a `StagedBlock` **owning the connection mutex**, and then calls
`audit_log(&self.client_cn, pubkey_hex, outcome)` at `:75` — *while that guard is alive*. The code
documents its own hazard (`scoped.rs:70-75`):

> *"NOTE: audit_log fires at STAGE time (before commit), while the returned StagedBlock still holds
> the parking_lot::MutexGuard on the DB connection. A tracing subscriber that attempts to read the DB
> would deadlock because parking_lot mutexes are non-reentrant."*

`parking_lot::Mutex` is non-reentrant, so a subscriber that reads the slashing DB on that event
deadlocks the signing path **permanently** — and the process keeps reporting healthy.

**Why tentative-commit dissolves it.** After §4.1, `stage_block` returns a plain `Send` receipt and
holds **no lock**. The `audit_log` call at `:75` then executes with nothing held that a subscriber
could contend for: a DB-reading subscriber takes the mutex, gets it, and returns. The deadlock class
is *structurally* eliminated on the sign path, not merely avoided by convention.

Two riders:

- **This does not make ARCH-P0-9 redundant.** ARCH-P0-9 is a P0 fix for a hazard that is live *today*
  and triggerable by an ordinary observability change (`prd.md:708-711`); ARCH-P1-5 is a Phase-4
  change with the initiative's highest risk (R1). Waiting for P1-5 means carrying a
  signing-wedges-permanently landmine through four phases. **Land P0-9 first** — the PRD's phase
  ordering is right (`prd.md:1183`).
- **P0-9's scope constraint remains satisfiable.** Its acceptance criteria require
  `git diff <base> -- crates/slashing/src/stage.rs` to be **empty** (`prd.md:721-725`), which is the
  mechanism by which it sidesteps the tracing plan's prospective byte-identical pin on that file
  (A-12/R9). Nothing in §4.1 changes that: P0-9 restructures `scoped.rs` only — capture the outcome,
  release/hand off, then emit — and every line it needs is in `scoped.rs:62-108`. Confirmed reachable
  without touching `stage.rs`.

**VD-S5 restated (scope correction against the review).** The block path is `scoped.rs:70-75`; the
**identical** hazard is repeated for attestations at `scoped.rs:103-107` (*"same timing caveat as
stage_block — fires at STAGE time while the StagedAttestation guard holds the DB mutex"*). An
acceptance criterion written against `:70-75` alone leaves half the surface unfixed. The PRD already
says "and the corresponding `stage_attestation` path at `:88+`" (`prd.md:704`) — the delta is against
the *review*, not the PRD. The P0-9 scan criterion (`prd.md:717-718`) covers both by construction,
which is the right shape.

### 7.2 C9 — the keep-list

Two of the six keep-list entries (`prd.md:1110-1121`) are touched by this design.

| Keep-list entry | Effect of §4.1 |
|---|---|
| **"The cancellation-proof stage→sign→commit core"** — anchored at `crates/signer/src/core.rs` and `crates/slashing/src/stage.rs:24-30` | **This is the entry ARCH-P1-5 necessarily modifies.** The property must be *preserved*; the *mechanism* changes from `!Send` guard + `spawn_blocking` to a durable committed row + `Send` receipt (§4.1.2). Note the anchor `stage.rs:24-30` is a **doc comment** describing the guard protocol — it must be rewritten, along with `:32-48` (VD-S4). **Flag for the PRD:** C9 as written could be read as forbidding exactly what ARCH-P1-5 requires. Add "property, not mechanism" to that row, or ARCH-P1-5 and C9 are in formal conflict. |
| **"A single unbypassable signing gate"** | **Unaffected.** §4.1 changes ordering *inside* the existing gate; no new signing surface, no new entry point. ARCH-P1-5's own criterion (`prd.md:805`) already says this and it is satisfiable as written. |

The other four — `architecture-tests` harness, KAT-first policy, "env = security opt-outs only", zero
unbounded channels — are untouched. Note that A-S8 (§6.3.2, no ordering feature flag) is what keeps
the third of those true.

### 7.3 A-12 / R9 — the cross-plan pin on `stage.rs`

ARCH-P1-5 **cannot** avoid `stage.rs`: §4.1's whole change is in `stage_block` / `stage_attestation`
and the `StagedBlock` / `StagedAttestation` types. The tracing plan's prospective byte-identical pin
on that file (R9, `prd.md:1200`) is therefore a **hard blocker for ARCH-P1-5**, not a soft one — even
though it is only a soft constraint for ARCH-P0-9, which was deliberately scoped around it.

The PRD records that the pin is **not wired in CI at HEAD** (`rg 'stage.rs|TRC-1e|byte-identical' .github`
→ no matches), so it is prospective rather than enforced. The phase table already requires "A-12 pin
must be resolved first" for Phase 4 (`prd.md:1183`). **Carry-forward:** resolve A-12 explicitly
*before* step 3 of §6.3.1, not before step 4 — the receipt type lands in `stage.rs` too.

### 7.4 C1 — restated as the acceptance shape

C1 (`prd.md:1014-1029`) binds ARCH-P1-5 and is satisfied by §6.1, with two amendments already argued:
strike per-pubkey connections from the admissible list (§4.2, VD-S1), and replace "validation against
the EIP-3076 conformance vectors is a gate on the switchover" with "the EIP-3076 vectors are a
**non-regression** gate; the §6.2 (A)–(D) families are the **ordering** gate" (§6.2, VD-S3).

## 8. Open questions resolved to defaults (Assumptions)

Per the no-ask constraint, every open question raised by this research is resolved here to a stated
default. Each is a **decision an implementer may act on**, not a question to re-open; each names the
condition that would justify revisiting it.

#### A-S1 — Remote-signer latency is 200 ms; the deadline is 3,999 ms

All arithmetic in §2 uses 200 ms per remote sign (the PRD's A-9 assumption) and the HEAD-verified
3,999 ms attestation deadline (`crates/timing/src/lib.rs:27`, VD-S7), on a 12,000 ms mainnet slot.
*Revisit if:* the ARCH-P1-15 harness measures a materially different p50/p99, or a non-12 s slot
configuration becomes a target — the basis-points model (`timing/src/lib.rs:35-46`) already handles
the latter, so only the derived numbers change, not the conclusions.

#### A-S2 — The new ordering applies to `RetainStagedRow` only

`DiscardStagedRow` paths keep the current stage→sign→commit ordering (§5.1). *Rationale:* in-process
signs are sub-millisecond, so there is no wall to remove, and discard-on-timeout is sound there by
construction (`core.rs:87-91`). *Revisit if:* a future in-process backend acquires unbounded latency
(e.g. an HSM behind the "local" interface) — in which case its policy should become `Retain` anyway,
via `fail_closed_max` (`core.rs:114-121`), and it inherits the new ordering automatically.

#### A-S3 — Reconciliation is a synchronous, inline, best-effort delete — no background GC

The compensating delete runs immediately after the failed sign, in its own short write transaction,
on the same task. **No background sweeper, no retry loop, no persisted work queue.** *Rationale:* a
sweeper would need its own durable state and could race a legitimate re-sign; and per §6.1.3 the
consequence of one missed delete is one wasted duty, which does not justify that machinery. A single
inline retry is acceptable; anything more is not. *Revisit if:* the A-S5 counter shows delete
failures are not vanishingly rare in practice.

#### A-S4 — `rvc_signer_slashing_tx_hold_duration_ms` is re-scoped to the transaction, deliberately

At HEAD the metric spans `tx_start` (`core.rs:265`) through post-sign (`core.rs:288`) — i.e. it
measures stage+sign+commit. After the reordering it must measure the **write transaction only**, and
`crates/signer/tests/tx_hold_metric.rs` must be updated in the same commit with a comment stating the
redefinition. *Rationale:* otherwise M3 records a ~100× "improvement" that is a change of definition,
not of behaviour — a self-congratulatory metric is worse than none. **Recommendation:** keep a
*separate* end-to-end sign-latency metric so the pre/post comparison remains honest, and state in the
PRD's M3 row (`prd.md:993`) which of the two the target applies to.

#### A-S5 — Compensating-delete failure is loud and counted

`error!` with pubkey (via `TruncatedPubkey`), slot or source/target epochs, and signing root, plus a
new counter (`rvc_signer_slashing_compensate_failed_total` or similar). *Rationale:* the failure is
silent by nature — it manifests days later as an unexplained missed duty (§6.1.3). *Revisit:* the
metric name is a suggestion; the requirement that it be counted is not.

#### A-S6 — Adopt `locking_mode=EXCLUSIVE`, matching Lighthouse

Add the pragma in `configure_pragmas` (`open.rs:217-248`) as part of ARCH-P1-5, so cross-process
exclusion is **explicit** rather than an emergent consequence of `BEGIN IMMEDIATE` held across the
sign — a consequence the redesign removes (§3.4). *Caveat — verify this first, it is not a formality:*
`locking_mode=EXCLUSIVE` interacts with WAL (SQLite keeps the shm/WAL files locked for the
connection's lifetime), so confirm it does not break the sidecar-permissions path
(`open.rs:190-205`), the backup path (`db/migrations.rs:89-135`) or **in-memory test DBs — which is
the sharp edge**: `open_in_memory` has **391 occurrences across 61 files** at HEAD, including all 76
conformance tests (`conformance.rs:175`, `:320`). `configure_pragmas` runs on that path too
(`open.rs:266`), so a pragma that misbehaves on `:memory:` would take the entire suite down at once.
Prototype the pragma against `open_in_memory` **before** committing to A-S6. If it does not hold,
the fallback default is: document the cross-process contract in `stage.rs` and add a startup check,
rather than silently relying on emergence.

#### A-S7 — The signing path must never raise watermarks; this becomes a test

VD-S6 is treated as an **invariant**, pinned by test (D) in §6.2.3, not as an observation. *Rationale:*
the compensating delete's soundness depends on it entirely (§6.1.2). *Revisit:* never silently — a
change that makes signing raise watermarks invalidates §4.1 and must re-open this document.

#### A-S8 — No runtime toggle between orderings

Rollback is `git revert` of the single step-4 commit (§6.3.2), not a feature flag or env var.
*Rationale:* two live orderings over one slashing database means two crash-safety semantics; and an
env toggle would violate C3's "env = security opt-outs only" rule (`prd.md:1041-1047`). A
compile-time `cfg` for tests is acceptable; a production-reachable switch is not.

#### A-S9 — The ARCH-P1-15 harness is built early, and targets the `signer-server` path

The PRD requires M3's baseline as a Phase-0 entry criterion (`prd.md:1002`, `:1179`) but schedules
the harness in Phase 5 (`prd.md:1184`). That is unsatisfiable: no benchmark or load harness exists at
HEAD (§2.5). **Default resolution:** move the harness earlier — before §6.3.1 step 2 — and point its
load profile at `signer-server`, where signs genuinely arrive concurrently (§2.4), *not* at the VC
orchestrator, whose sequential loop would flatten the profile and produce a meaningless baseline
(§2.3). *Revisit if:* the orchestrator loop is made concurrent first, in which case the VC path
becomes a valid second profile.

## Sources

External sources are numbered to match the citations in the *Verdict Summary*. All were fetched and
read on 2026-08-12; every quotation below was taken from the fetched page, not from memory. Source
type is noted because reliability differs.

[1] [SQLite — Write-Ahead Logging](https://sqlite.org/wal.html) — SQLite Consortium, official
documentation (primary). Source of the single-writer property underpinning **V2** and **V3**. Quoted
verbatim in §3.2: *"Because writers do nothing that would interfere with the actions of readers,
writers and readers can run at the same time. However, since there is only one WAL file, there can
only be one writer at a time."* and *"WAL provides more concurrency as readers do not block writers
and a writer does not block readers."* The verdict table's quotation was checked against the page and
is exact.

[2] [Lighthouse — `validator_client/slashing_protection/src/slashing_database.rs`](https://github.com/sigp/lighthouse/blob/stable/validator_client/slashing_protection/src/slashing_database.rs)
— Sigma Prime, `stable` branch (primary, source code; read via `raw.githubusercontent.com`). Source
of `pub const POOL_SIZE: u32 = 1;`, `conn.pragma_update(None, "locking_mode", "EXCLUSIVE")?` with the
comment *"put the database into exclusive locking mode, so that threads are forced to serialise all
DB access (to prevent slashable data being checked and signed in parallel)"*,
`transaction_with_behavior(TransactionBehavior::Exclusive)` in `check_and_insert_block_signing_root`
/ `check_and_insert_attestations`, and `txn.commit()?; Ok(safe)` — the commit-before-return that
makes **V3** and **V5** hold. The batched `check_and_insert_attestations` signature is also the
precedent for group commit (**V12**, §5.2).

[2a] [Lighthouse — `validator_client/lighthouse_validator_store/src/lib.rs`](https://github.com/sigp/lighthouse/blob/stable/validator_client/lighthouse_validator_store/src/lib.rs)
— Sigma Prime, `stable` branch (primary, source code). The **caller-side ordering** for **V5**:
`sign_abstract_block` calls `check_and_insert_block_proposal`, matches `Ok(Safe::Valid)`, and only
then `let signature = signing_method.get_signature(...).await?`. Cited under [2] in the verdict
table; listed separately here because it is a different file and it carries the load-bearing
ordering claim. *Note:* `validator_client/validator_store/src/lib.rs` holds only the trait and the
`Slashable(NotSafe)` error variant — a first fetch of that path did not contain the implementation.

[2b] [Lighthouse Book — Slashing Protection](https://lighthouse-book.sigmaprime.io/validator_slashing_protection.html)
— Sigma Prime, official documentation (secondary). Corroborates the single-file + exclusive-lock
deployment model: *"Lighthouse's slashing protection database is an SQLite database located at
`$datadir/validators/slashing_protection.sqlite` which is locked exclusively when the validator
client is running."*

[3] [Web3Signer — `DbSlashingProtection.java`](https://github.com/Consensys/web3signer/blob/master/slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbSlashingProtection.java)
— Consensys, `master` branch, Apache-2.0 (primary, source code). Source for **V5**:
`maySignAttestation` / `maySignBlock` wrap their checks in
`jdbi.inTransaction(READ_COMMITTED, handle -> { lockForValidator(handle, LockType.ATTESTATION, validatorId); … return true; })`
and return a **boolean** — the transaction commits and the advisory lock is released before the
caller signs.

[4] [Web3Signer — `DbLocker.java`](https://github.com/Consensys/web3signer/blob/master/slashing-protection/src/main/java/tech/pegasys/web3signer/slashingprotection/DbLocker.java)
— Consensys, `master` branch, Apache-2.0 (primary, source code). The lock primitive quoted in §4.4:
`handle.execute("SELECT pg_advisory_xact_lock(?, ?)", lockType.lockOrdinal(), validatorId)`, with
`LockType` = `BLOCK(0)` / `ATTESTATION(1)`. Confirms the lock is per (validator, message-type) and
transaction-scoped — i.e. released by the commit, before signing.

[5] [Dirk — `services/signer/standard/signbeaconattestation.go`](https://github.com/attestantio/dirk/blob/master/services/signer/standard/signbeaconattestation.go)
— Attestant, `master` branch (primary, source code). The ordering for **V5**:
`results := s.ruler.RunRules(ctx, credentials, ruler.ActionSignBeaconAttestation, rulesData)` →
`case rules.APPROVED:` → `signature, err := signRoot(ctx, account, signingRoot[:])`.

[6] [Dirk — `services/ruler/golang/runner.go`](https://github.com/attestantio/dirk/blob/master/services/ruler/golang/runner.go)
and [`rules/standard/signbeaconattestation.go`](https://github.com/attestantio/dirk/blob/master/rules/standard/signbeaconattestation.go)
— Attestant, `master` branch (primary, source code). `RunRules` locks per 48-byte public key
(`s.locker.Lock(lockKey)` with `defer s.locker.Unlock(lockKey)`), and
`OnSignBeaconAttestation` persists the new protection state via
`storeSignBeaconAttestationState(...)` → `s.store.Store(ctx, key, state.Encode())` **before**
returning its result. Together with [5] this establishes that Dirk writes protection state and
releases its lock before signing, and never compensates on sign failure (§4.4).

[7] [EIP-3076: Slashing Protection Interchange Format](https://eips.ethereum.org/EIPS/eip-3076)
— Ethereum Improvement Proposals, official specification (primary). Read to establish an **absence**,
which is the basis of **V10**: the EIP specifies the interchange file format and five refusal
conditions (block conflict, block slot floor, attestation conflict, source-epoch floor, target-epoch
floor) and says **nothing** about the order in which a record must be persisted relative to signature
release, nothing about fsync or durability, nothing about crash-safety, and nothing about
concurrency.

[8] [`eth-clients/slashing-protection-interchange-tests`](https://github.com/eth-clients/slashing-protection-interchange-tests)
— Ethereum client teams (primary, test vectors). The upstream origin of the 38 in-tree vectors, as
named by `crates/slashing/tests/conformance.rs:1-4`. Listed for provenance; the vectors themselves
were read in-tree, not fetched.

### In-repo evidence

Every `file:line` citation in this document was opened at `develop` @ `0ae9a09` on 2026-08-12. The
load-bearing ones, for convenience:

| Claim | Location |
|---|---|
| Global connection mutex | `crates/slashing/src/db/mod.rs:59` |
| `BEGIN IMMEDIATE` at stage time | `crates/slashing/src/stage.rs:357`, `:438` |
| INSERT + `COMMIT` in the guard | `crates/slashing/src/stage.rs:166-193`, `:248-276` |
| `Drop` → ROLLBACK backstop | `crates/slashing/src/stage.rs:204-219`, `:284-300` |
| `!Send` guard rationale | `crates/slashing/src/stage.rs:57-63` |
| Misleading WAL justification (VD-S4) | `crates/slashing/src/stage.rs:32-48` |
| WAL hard-fail + durability pragmas | `crates/slashing/src/db/open.rs:217-248` |
| GVR pinning | `crates/slashing/src/db/mod.rs:150`; check before mutex `stage.rs:341-351` |
| Backup before migration | `crates/slashing/src/db/migrations.rs:89-135` |
| `PRAGMA integrity_check` | `crates/slashing/src/db/mod.rs:256-259` |
| Audit-log inside the mutex (C2) | `crates/slashing/src/scoped.rs:70-75` **and** `:103-107` (VD-S5) |
| Error-class decision table | `crates/signer/src/core.rs:290-343`, `:346-375`, `:379-408`, `:412-450` |
| `TimeoutPolicy`, no `Default` | `crates/signer/src/core.rs:63-97`; fail-closed merge `:114-121` |
| SEC-1 double policy resolution | `crates/signer/src/core.rs:280-282`, `:518-524` |
| Unambiguous-no-signature classes | `crates/crypto/src/error.rs:37-44` |
| Cancellation note / lock authority | `crates/signer/src/core.rs:500-505`, `:542` |
| Sign inside `block_on` | `crates/signer/src/core.rs:284-287` |
| M3 metric emission | `crates/signer/src/core.rs:219`; test `crates/signer/tests/tx_hold_metric.rs` |
| Blackout hazard documented | `crates/signer/src/gate.rs:74-83`; timeout const `:115`, `lib.rs:169` |
| Attestation deadline (VD-S7) | `crates/timing/src/lib.rs:23-46`; pinned `crates/timing/tests/timing_m11.rs:44-59` |
| Sequential duty loop (VD-S2) | `crates/rvc/src/orchestrator/attestation.rs:171-192` |
| 38 vectors + runner | `crates/slashing/tests/conformance/*.json`; `crates/slashing/tests/conformance.rs:393-473` |
| Signing never raises watermarks (VD-S6) | `crates/slashing/tests/conformance.rs:18-21` |
| M-1 history (VD-S9) | `crates/signer/tests/phantom_row_m1.rs:1-10`, `:59-79` |
