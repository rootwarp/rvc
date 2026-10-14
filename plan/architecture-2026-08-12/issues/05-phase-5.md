# Phase 5 — Slashing Critical Section: measure, fold, then reserve-and-reconcile

> Sprint-ready issue breakdown for **Phase 5** of the rs-vc architecture-remediation initiative.
> Baseline **`develop` @ `0ae9a09`** (v0.7.0), authored 2026-08-12. Every `file:line` below was
> re-opened against HEAD while writing this document; where an authoritative input did not
> reproduce, the corrected fact is carried forward in *§3 Verification Deltas* and used in the
> issue bodies rather than smoothed away.
>
> **Authoritative inputs, in precedence order:**
> [`../project-plan.md`](../project-plan.md) §7 *Phase 5* (scope, work packages 5A–5E, entry/exit
> gates) → [`../architecture.md`](../architecture.md) **ADR-005** (`:334-418`), **§5.3** the
> tentative-commit API and the error-class × policy contract (`:1193-1269`) →
> [`../prd.md`](../prd.md) (**ARCH-P1-15a**, **ARCH-P1-6** `:807`, **ARCH-P1-5** `:783`,
> **ARCH-P2-2** `:954`, **ARCH-P2-1** `:953`; constraints **C1** `:1016`, **C2** `:1033`) →
> [`../research/slashing-critical-section.md`](../research/slashing-critical-section.md) →
> [`../../../docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md)
> → the repository's [`CLAUDE.md`](../../../CLAUDE.md) (TDD RED→GREEN→REFACTOR, KAT-first policy,
> `thiserror`/`anyhow`, no `.unwrap()` in production code — binding on every issue below).
>
> **What this document adds over its inputs.** It is not a restatement. It adds: (a) **seven
> verification deltas** found by opening the code this phase edits, two of which change the phase's
> shape — the plan's own justification for "fold before redesign" is false under the PRD-literal
> reading of ARCH-P1-6 (**VD-5.1**), and the M3 exit criterion is **unmeetable by construction**
> unless the tx-hold observation window is deliberately redefined (**VD-5.2**); (b) the discovery
> that `core.rs` already carries a `StagedRow` trait (`crates/signer/src/core.rs:127-150`) and a
> `stage_then_sign` seam, which is the actual migration surface and which none of the upstream
> documents name; (c) a counted decision to **retain** `stage_*` rather than replace it, forced by
> 63 counted test call sites; (d) a two-stream split on genuinely disjoint crate boundaries.
>
> **No-ask constraint:** every open question is resolved to a stated default in *§2 Assumptions*.
> Nothing is escalated. **Scope:** planning only — this document changes no source file and deletes
> nothing.

## 1. Phase Overview

**Goal.** Remove the hold-across-the-sign wall without weakening retain-on-ambiguity — the
highest-risk change in the initiative, and the one whose failure mode is *a signature on the wire
with no slashing record*. Order is binding: **measure (M3 baseline) → fold (one staging consumer) →
reserve-and-reconcile (the switchover, gated on three proof surfaces)**.

| | |
|---|---|
| **Issue count** | **15** (`ARCH-5a` … `ARCH-5o`) |
| **Total points** | **39** (Stream A 15 · Stream B 24) |
| **Duration, 1 dev** | **20–39 working days** at the house rate (1 pt ≈ 0.5–1 d). This is a counted range, not a narrowed one. The plan's §6 envelope of **18–26 d** holds at the faster end of the rate; at the slower end it holds only if `ARCH-5n` + `ARCH-5o` (4 pts) are dropped — which is exactly the cut line the plan itself names (5D/5E, project-plan `:598-599`). Recorded, not absorbed. |
| **Duration, 2 devs** | **12–24 working days.** Critical path is **Stream B (24 pts)**; Stream A (15 pts) finishes early and its dev absorbs `ARCH-5n`/`ARCH-5o`. Speed-up ≈ **1.6×** — the same figure the plan claims for the whole initiative, and here it is real because the two streams own disjoint crates. |
| **Requirements closed** | ARCH-P1-15a (harness + baseline), ARCH-P1-6, **ARCH-P1-5**, ARCH-P2-2 (rescoped, VD-5.5), ARCH-P2-1 |
| **ADRs implemented** | **ADR-005** (owns ARCH-P1-5); ADR-006 is a *prerequisite*, landed in Phase 1 |
| **Constraints** | **C1 binding**, **C2 prerequisite**, **C9** anchors 2/5/7 — see §4 |

### 1.1 Entry criteria (all three are hard; none is cosmetic)

- [ ] **E1 — Phase 1's ARCH-P0-9 (ADR-006/G-7) has landed.** Audit-log emission is outside the
      slashing mutex on **both** paths (`crates/slashing/src/scoped.rs:75` block, `:106`
      attestation — both verified present at HEAD). **C2.** Bundling it here would carry a live
      availability landmine through the initiative's highest-risk diff.
- [ ] **E2 — The M3 baseline is captured and recorded as a file in
      `plan/architecture-2026-08-12/`** — delivered by `ARCH-5a` + `ARCH-5b`, which are *inside*
      this phase precisely because a measurement instrument that does not exist cannot be a
      follow-up (project-plan §1.1, architecture Design Principle 8). **`ARCH-5b` gates every
      issue from `ARCH-5i` onward.**
- [ ] **E3 — A-12 is resolved explicitly, never discovered.** The tracing initiative's
      byte-identical pin on `crates/slashing/src/stage.rs` is *prospective*: re-verified here —
      `rg 'stage\.rs|TRC-1e|byte-identical' .github` returns nothing, and
      `plan/tracing-2026-08-06/` is untracked (`git status` shows it as `??`). **Default taken:
      proceed and re-pin to the post-redesign hash**, recorded in `plan/tracing-2026-08-06/`. The
      resolution is written into `ARCH-5e`'s description before its first commit.
- [ ] **E4 — Green on all §2 standing-invariant commands** of the project plan, notably
      `cargo nextest run --workspace` (**not** `cargo test --workspace`, which deadlocks in this
      repo — project-plan `:129-135`).

### 1.2 Exit criteria — the milestone, as a checklist

- [ ] **X1 — The §5.3 outcome table reproduces cell by cell.** A remote-signer **timeout** and an
      **ambiguous** signer error each leave the row **retained** under `RetainStagedRow`; the
      **unambiguous-no-signature** class is *stricter* than today (a failed compensating delete
      **retains**). All 14 cells asserted by `ARCH-5j`.
- [ ] **X2 — Three proof surfaces green BEFORE the switchover, not after** — `ARCH-5j`
      (error-class × policy matrix), `ARCH-5k` (crash/cancellation injection at every await
      point), `ARCH-5h` (concurrency proptest over interleaved reservations). All three land and
      pass against the additive `reserve_then_sign` entry point (`ARCH-5i`) while production still
      runs `stage_then_sign`, so `ARCH-5l`'s switchover is a flip of four call sites against
      already-green proofs — never a knowingly-failing merge (ADR-012 / project-plan `:93-96`).
- [ ] **X3 — The EIP-3076 conformance vectors are re-run and green, and are recorded as
      *necessary and insufficient*.** They are single-threaded rule-engine fixtures that pass
      identically before and after (VD-S3); running them is table stakes.
- [ ] **X4 — `crates/signer/tests/phantom_row_m1.rs` stays green across the change**, and the
      switchover PR quotes its header (`:1-10`) — the M-1 prior-art warning.
- [ ] **X5 — No new signing surface.** `reserve_*` is a DB call. The single unbypassable wiring
      site (`crates/rvc/src/config/builder.rs:394`) and the `CompositeSigner` grep gate stay green
      (**C9 anchor 5**), and a new scanner asserts **no production caller outside
      `crates/slashing/` uses `stage_block`/`stage_attestation`** (`ARCH-5l`).
- [ ] **X6 — M3 p99 within the per-sign budget on the `signer-server` profile**, recorded against
      `ARCH-5b`'s baseline, **under both metric definitions** (VD-5.2) so the comparison is
      falsifiable.
- [ ] **X7 — Rollback plan written** (`ARCH-5m`): reverting to the guard-holding design is safe in
      the slashing direction (the old design retains strictly *less*, never more) but must re-run
      the three proof surfaces, not just the vectors.
- [ ] **X8 — The VC-path ceiling is recorded honestly as out of scope (A-A8).**
      `crates/rvc/src/orchestrator/attestation.rs:171-192` is a sequential `for duty in duties {
      … .await }` loop — re-verified at HEAD, no `join_all` / `FuturesUnordered` / `spawn` — so
      200 keys × 200 ms = 40 s = ten slots **with a completely free DB**. Claiming G6 here would
      be false. `ARCH-5m` files VC-path attestation concurrency as a separate, unscheduled
      requirement.
- [ ] **X9 — `spawn_blocking` still wraps the sequence** (`crates/signer/src/core.rs:542`) even
      though the `!Send` guard no longer requires it (**C9 anchor 7**); G-4's ban list must never
      gain that line.

## 2. Assumptions, verified against HEAD (`0ae9a09`)

Per the no-ask constraint, every open question is resolved to a stated default. Each row was
re-opened in the working tree while writing this file; `file:line` is what the file says at HEAD,
not what an upstream document says about it.

| ID | Question | **Default taken** | Verified at HEAD | What would overturn it |
|---|---|---|---|---|
| **A-5.1** | ADR-005 says the redesign is *"scoped to the `RetainStagedRow` policy"* (architecture `:350`), and project-plan 5C says the compensating delete applies to *"the unambiguous-no-signature class **only**"* (`:597`). But §5.3's table puts `reconcile_unsigned` on **three** `DiscardStagedRow` rows (timeout, ambiguous, unambiguous) and **one** `RetainStagedRow` row. Which governs? | **§5.3's table governs.** The architecture states the table *"**is** the C1 safety property"* (`:1252`). Implement all 14 cells: under `Discard`, every non-success class reconciles; under `Retain`, only the unambiguous class does. ADR-005's "scoped to Retain" is read as *risk* scoping (the retain semantics are what must be preserved), not as an implementation bound. | Contract assembled from `crates/signer/src/core.rs:290-343` (dispatch), `:346-376` (`finish_timeout`), `:379-409` (`finish_ambiguous_error`), `:412-450` (`retain_staged_row`) — all four reproduce exactly as the architecture cites them | A reviewer ruling that `DiscardStagedRow` must keep a true ROLLBACK, which would require `reserve_*` to *not* commit under Discard — i.e. two staging designs, not one |
| **A-5.2** | Does `reserve_*` **replace** `stage_*`, as project-plan 5C's *"a `CommittedReservation` … replaces the RAII guard"* (`:597`) and architecture §5.3's *"removes the lifetime and the guard from the caller's hands entirely"* (`:1209`) both read? | **No — `reserve_*` is added alongside; `stage_*` is retained and demoted.** Replacement is a test migration neither document counts. Deletion is deferred out of this phase; safety is bought instead by a **production-caller scanner** (`ARCH-5l`, X5). | **Counted precisely** — `rg 'stage_block\(\|stage_attestation\(' crates/slashing/tests` = **63 call sites across 6 files**: `tests/stage.rs` **39**, `tests/pubkey_scope_cross_cn.rs` **8**, `tests/migration_v3_cases.rs` **5**, `tests/reader_skeleton.rs` **5**, `tests/gvr_recheck_m6.rs` **4**, `tests/common/mod.rs` **2**. Plus **2 production wrappers** in `crates/slashing/src/scoped.rs` (`:62`, `:88`). *(A broader `stage_block\|stage_attestation\|check_and_record_` grep returns much larger per-file numbers, but `check_and_record_*` is a **different** API and doc-comment mentions are not call sites — the 63 above is the migration surface.)* | A measured demonstration that the migration is <2 pts, or a decision to accept two staging APIs permanently (rejected — see X5) |
| **A-5.3** | ARCH-P1-6's PRD title is *"Fold the **non-slashable** path and timeout constant"* (`prd.md:807`), but the plan justifies its position with *"the migration rewrites one staging consumer instead of two"* (`:596`). The non-slashable helpers touch **no** staging consumer. | **Take the expansive reading and split it in two.** `ARCH-5c` delivers the PRD-literal fold (two `sign_nonslashable` helpers + the duplicated timeout constant). `ARCH-5d` delivers the fold the *plan's ordering rationale actually requires* — the four slashable `body` closures collapse into one `core.rs` helper, so the switchover flips one site. Both are pre-switchover. | Both `sign_nonslashable` helpers document in-source that they do **not** touch the DB: `crates/signer/src/gate.rs:405-411` and `crates/signer/src/lib.rs:440-446` (*"does **NOT** call any of `PubkeyScopedDb`, `stage_block`, `stage_attestation`, or `commit`"*). The four slashable closures are `gate.rs:278-293`, `gate.rs:~364`, `lib.rs:~594-620`, `lib.rs:~674+` | A ruling that ARCH-P1-6 is PRD-literal only — in which case `ARCH-5d` becomes an ARCH-P1-5 sub-issue and the phase's point total is unchanged (see VD-5.1) |
| **A-5.4** | Where does the M3 load profile run? | **`signer-server`, not the VC.** `crates/signer-server/tests/` (helpers exist at `tests/helpers.rs`; real end-to-end drivers at `tests/sign_attestation_v2.rs`, `tests/sign_beacon_block_v2.rs`). Requests genuinely arrive concurrently there, so the mutex binds. 200 keys / 200 ms injected latency (A-9). | The VC path cannot show the effect: `crates/rvc/src/orchestrator/attestation.rs:171-192` is a sequential await loop (verified) | A companion requirement making the VC attestation loop concurrent — explicitly *not* scheduled (X8) |
| **A-5.5** | `SigningGate` is `TimeoutPolicySource::Fixed(TimeoutPolicy::DiscardStagedRow)` (`gate.rs:274`, `:360`) — so the load profile exercises the **Discard** branch, the one that gains reconcile on *every* failure class. Is that acceptable? | **Yes, and it is stated as a conscious liveness trade.** Under Discard, a *failed* compensating delete leaves a retained row — M-1's liveness failure mode (a phantom row refuses a legitimate sign; it never permits a double-sign). Accepted in the fail-safe direction, but **metered and logged at `error!`**, never silent (`ARCH-5f`, `ARCH-5l`). | `crates/signer/src/gate.rs:274`, `:360`; M-1's failure class documented at `crates/signer/tests/phantom_row_m1.rs:1-10` | Measured reconcile-failure rate above zero in the load run — which would promote group commit / a retry from "admissible if measured" (A-A9) to scheduled |
| **A-5.6** | ARCH-P2-2 is marked `[review-carried, unverified at HEAD]` (`prd.md:954`). Does it reproduce? | **Partly — and its acceptance criterion as written is unsatisfiable.** Rescoped: type the **internal** records only. See **VD-5.5**. | `crates/slashing/src/types.rs` opened in full (404 lines) | Nothing — the EIP-3076 string mandate is in-source at `types.rs:53-54`, `:62-63` |
| **A-5.7** | Does `ARCH-5o` (ARCH-P2-2) run concurrently with the redesign? | **No.** Project-plan 5D is explicit: *"After 5C, never concurrent with it"* (`:598`). It lands after `ARCH-5l`'s switchover, and it is the phase's declared cut line together with `ARCH-5n`. | project-plan `:598-599` | — |
| **A-5.8** | Is `crates/slashing/src/db/mod.rs`'s `.expect("infallible")` in production code, contra `CLAUDE.md`? | **Yes — and it is in `ARCH-5o`'s scope, not a separate issue.** | `crates/slashing/src/db/mod.rs:53-55`: `pubkey.parse::<observability::pubkey::CanonicalPubkey>().expect("infallible").to_string()` — reproduces exactly at `:54` | — |
| **A-5.9** | Group commit (batching N checks into one transaction/fsync)? | **Not day one (A-A9).** Admissible **only if** `ARCH-5m`'s post-change run measures fsync to bind (`synchronous=EXTRA` + `fullfsync=ON`, `crates/slashing/src/db/open.rs:240-246`). If it does, it is a new requirement, not scope creep absorbed here — and it preserves commit-before-sign exactly. | `db/open.rs:240-246` | A measured p99 still above budget with the mutex gone |
| **A-5.10** | Do Phase 5's new tests fall under the KAT-first policy? | **Only by name.** The scanner matches test **names** ending `tree_hash` / `signing_root` / `_root` (`crates/architecture-tests/tests/kat_policy.rs`). Phase 5's proof surfaces assert *slashing-DB state and error classes*, not spec-defined roots. **Default: no new test in this phase may be named `*_root`.** If one must be, it carries `// kat_exempt: <reason>`; `EXEMPTIONS` is shrinking-only and gains **nothing** here. | `kat_policy.rs:12-17`, `:42`, `:273-276`, `:397`, `:466-471` | A proof surface that genuinely needs to assert a signing-root value — then KAT-anchor it |

---

## 3. Verification Deltas found while estimating this phase

Seven claims in the authoritative inputs did not reproduce as written. Two change the phase's shape.

| ID | Claim as written upstream | Status at HEAD | Corrected fact carried forward | Lands in |
|---|---|---|---|---|
| **VD-5.1** | project-plan 5B (`:596`): *"folding first means ADR-005's reserve/reconcile migration rewrites **one** staging consumer instead of two"* — given as the reason ARCH-P1-6 precedes ARCH-P1-5 | **False under the PRD-literal reading of ARCH-P1-6** | The thing ARCH-P1-6 folds — `sign_nonslashable` — states in-source that it touches **no** staging API (`gate.rs:405-411`, `lib.rs:440-446`), and the "duplicated timeout constant" is two `const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(4)` declarations (`gate.rs:115`, `lib.rs:169`) that no staging code reads. Folding it rewrites **zero** staging consumers. The rationale is only true of the **four slashable `body` closures** — which the PRD title does not mention. **Resolution (A-5.3):** keep the ordering, but make it true by splitting: `ARCH-5c` = PRD-literal fold, `ARCH-5d` = the four-closure fold that actually shrinks the switchover from 4 sites to 1 | `ARCH-5c`, `ARCH-5d` |
| **VD-5.2** | project-plan exit criterion (`:624`) and PRD M3 (`:993`): *"M3 p99 within the per-sign budget"*, measured by `rvc_signer_slashing_tx_hold_duration_ms` | **Unmeetable by construction unless the observation window is deliberately redefined** | The metric is **not** a DB-lock-hold metric. `tx_start` is taken *before* `stage()` (`core.rs:265`) and `tx_hold_ms` is computed *after* the sign returns (`:288`), then observed on every branch (`:297`, `:307`, `:318`, `:354`, `:427`, `:433`). It therefore measures **stage-start → sign-return**, which under ADR-005 still contains the whole sign — so before/after would be **identical** and the exit criterion unfalsifiable. **Resolution:** `ARCH-5b` takes the decision explicitly — keep the existing series for comparability **and** add a second, reserve-transaction-only series; record X6 under **both** definitions | `ARCH-5b`, `ARCH-5l`, `ARCH-5m` |
| **VD-5.3** | architecture §5.3 (`:1239`): *"`SignerError::is_unambiguous_no_signature`, `signer/src/core.rs:316`"* | **Wrong type; line is the call site** | `core.rs:316` is `Ok(Err(e)) if e.is_unambiguous_no_signature()` where `e: crypto::SigningError` (bound by `Signer::sign`, imported at `core.rs:46`). It is **not** on `SignerError` (`crates/signer/src/error.rs`), which is the VC-facing error. An implementer who greps `SignerError` for it will not find it | `ARCH-5f`, `ARCH-5i` |
| **VD-5.4** | Implicit in ADR-005 and §5.3: the migration surface is `stage_*` → `reserve_*` at the DB | **Understated — the real seam is already abstracted in `core.rs`, and no input names it** | `crates/signer/src/core.rs:124-150` declares `pub trait StagedRow { fn commit_row(self) -> Result<(), SlashingError>; fn discard_row(self); }` with impls for `StagedBlock<'_>`/`StagedAttestation<'_>`, and `SlashableSignSession::stage_then_sign<S: StagedRow, F: FnOnce() -> Result<S, SlashingError>>` (`:260-344`) is generic over it. **Consequence — and a trap:** the naive migration is "impl `StagedRow` for a reservation, `commit_row` = no-op, `discard_row` = reconcile", which **silently loses the compensating delete's failure signal** because `discard_row` returns `()`. The new entry point must be a *sibling* method with its own outcome type, not a new `StagedRow` impl | `ARCH-5i` |
| **VD-5.5** | ARCH-P2-2 acceptance (`prd.md:954`): *"**No `String` pubkey or root comparison remains in `slashing/src/types.rs`**"* | **Unsatisfiable as written** | `types.rs` holds **two** internal records (`SignedAttestation:16-21`, `SignedBlock:24-29`, both `pubkey: String` + `signing_root: Option<String>`) and **five** EIP-3076 interchange DTOs whose `String` fields are **mandated by the spec and documented in-source**: `InterchangeBlock:53-60` (*"Note: slot is serialized as string per EIP-3076 specification"*), `InterchangeAttestation:62-70`, `ValidatorRecord:47-51`, `InterchangeMetadata:39-43`, `InterchangeFormat:32-36`. Removing `String` from those breaks the wire format. **Rescoped criterion:** newtypes on `SignedAttestation`/`SignedBlock` and the `db/mod.rs:54` `.expect` only; the `Interchange*` DTOs stay `String` **by mandate**, recorded in a doc comment so the next reader does not re-open it | `ARCH-5o` |
| **VD-5.6** | project-plan 5E (`:599`) / ARCH-P2-1 (`prd.md:953`): *"Evict `ValidatorLockMap` entries on key removal / by LRU bound"* — implying a call-site change | **Reproduces, and is smaller than implied** | `crates/signer/src/locks.rs` is 56 lines: one field `locks: parking_lot::Mutex<HashMap<[u8; 48], Arc<tokio::sync::Mutex<()>>>>` (`:22`), `get` (`:33-39`), `lock` (`:46-48`). There is **no** `remove`, no bound, no eviction — unbounded growth confirmed. A size-bounded sweep can live **entirely inside `locks.rs`** with no caller change, because "held" is observable as `Arc::strong_count(&entry) > 1`. That is what keeps this issue at 2 pts and lets it float between streams | `ARCH-5n` |
| **VD-5.7** | Implicit in "re-run the EIP-3076 vectors": the conformance harness is inert w.r.t. the reorder | **It is not — one runner has a commit-ordered hook** | `crates/slashing/tests/conformance.rs:17-19`: *"After a successful stage commit the harness raises the corresponding watermark so later steps see the post-sign high-water mark"* — the `minimal_conservative` runner. It reaches the staging API through two shared helpers, `stage_and_commit_block` (`tests/common/mod.rs:17-24`) and `stage_and_commit_attestation` (`:32-40`) — **so `conformance.rs` itself contains zero `stage_*` call sites, and a future migration is 2 helper edits, not 11.** Under ADR-005 the commit moves *before* the sign, so re-pointing those helpers at `reserve_*` would raise a watermark for a sign that may then be reconciled away. **Mitigation:** A-5.2 keeps `stage_*`, so both files are untouched this phase — but the hazard and the two exact helper lines are written into `ARCH-5h` so a later `stage_*` deletion does not walk into it | `ARCH-5h` |

## 4. Constraint disposition (C1–C10) — every item addressed, none silent

| C | Constraint | Disposition in Phase 5 | Owning issues |
|---|---|---|---|
| **C1** | Retain-on-ambiguity vs lock-shortening. *"Stage → release → sign → re-check-and-commit" cannot retain a released row and is rejected outright* (`prd.md:1021-1024`) | **Binding, and the phase's whole point.** The design taken is tentative-commit-then-reconcile: the row is **committed before** the sign, so a timeout or ambiguous error needs no action at all to retain it — retention becomes the *default* rather than a step that can be skipped. The naive design is rejected by name in `ARCH-5e`'s description so it cannot be re-proposed. Validated against the 14-cell matrix (`ARCH-5j`) **and** crash injection (`ARCH-5k`) **and** a concurrency proptest (`ARCH-5h`) — EIP-3076 vectors are necessary and insufficient (VD-S3, X3) | `ARCH-5e`, `ARCH-5f`, `ARCH-5h`, `ARCH-5j`, `ARCH-5k`, `ARCH-5l` |
| **C2** | Audit-log emission inside the mutex (`scoped.rs:70-75`; parking_lot is non-reentrant) | **Prerequisite, discharged in Phase 1** (entry criterion E1). Phase 5 must not regress it: `ARCH-5g` adds `PubkeyScopedDb::reserve_*` wrappers, and their audit emission is **structurally** outside the lock because `reserve_*` releases the mutex before returning. G-7 (`audit_log_scope.rs`) must stay green over the new wrappers | `ARCH-5g` |
| **C3** | figment `Env` provider forbidden | **Not applicable.** Phase 5 adds no configuration surface and no dependency. Stated rather than omitted; if any issue below grows a knob, it belongs to Phase 4's declaration model, not here | — |
| **C4** | Keystore-less key admission | **Not applicable** — Phase 1 (ADR-007). Phase 5 touches no admission path. Noted because `ValidatorLockMap` eviction (`ARCH-5n`) is adjacent to key *removal*: the eviction must be driven by an internal bound, **not** by hooking the admission/removal path, so the two phases stay independently revertible (NFR-4) | `ARCH-5n` (as a bound) |
| **C5** | KM-2 `stop_monitoring` / `cancel_monitoring` teardown contract | **Not applicable** — Phase 7 (ADR-015, G-6). No Phase 5 issue touches `keymanager-api` | — |
| **C6** | Cold-cache pre-proposal fetch | **Not applicable** — Phase 3 (ADR-004). Recorded because Phase 5 shortens the *sign* path and could be mistaken for a proposal-deadline fix; it is not, and X8 states the VC-path ceiling honestly | — |
| **C7** | SSE drops are normal | **Not applicable** — Phase 3 (ADR-013) | — |
| **C8** | Healthz removal is operator-visible | **Not applicable** — Phase 0 (16a) / Phase 7 (16b) | — |
| **C9** | Preserve the keep-list | **Three anchors are live here.** **Anchor 2** (cancellation-proof stage→sign→commit core) is the one this phase *can* regress and is guarded by X2's three proof surfaces. **Anchor 5** (single unbypassable signing gate) — `reserve_*` is a DB call, not a signing surface; the single wiring site + `CompositeSigner` grep gate stay green (X5). **Anchor 7** (`spawn_blocking` excluded from executor scope) — `core.rs:542` **stays** `spawn_blocking` even though the `!Send` guard no longer requires it; G-4's ban list must never gain it (X9). Anchors 1/3/4/6 are untouched: no `CLASSIFICATION` row moves, `EXEMPTIONS` gains nothing (A-5.10), no env var is added, no channel is created | `ARCH-5h`, `ARCH-5j`, `ARCH-5k`, `ARCH-5l` |
| **C10** | Archive-before-delete for untracked trees | **Not applicable — and deliberately so.** The four orphan paths have no git object behind them, so `rm` is unrecoverable; **deleting them is Phase 0's ARCH-P0-1 (archive → verify → delete), not this phase's work, and is out of scope for this planning document.** Phase 5's only relevance: `crates/rvc-signer/src/{service.rs,dvt/peer_service.rs}` show up in a `stage_block` grep with 4 hits. Those are in an **untracked orphan tree** — Phase 5 must never cite, edit or migrate them, and `ARCH-5l`'s production-caller scanner must be path-scoped to exclude them (they will already be gone if Phase 0 has landed; the scanner must not depend on that) | `ARCH-5l` |

---

## 5. Rejected alternatives — carried forward so no one re-opens them

The phase goal requires per-pubkey connections and sharding to be **rejected with reason**, not
merely omitted. This register belongs to the phase, and `ARCH-5e` cites it in its description.

| Alternative | Verdict | Reason, with evidence |
|---|---|---|
| **Stage → release → sign → re-check-and-commit** | **Rejected by name (C1)** | It cannot retain a released row, so an ambiguous remote sign silently becomes a rolled-back row — a signature that may exist on the wire with **no** slashing record. The single highest-consequence mistake available in this initiative (`prd.md:1021-1024`) |
| **Per-pubkey connections** | **Rejected (VD-S1)** — the PRD and the review both list it as admissible and it is not | Against **one SQLite file** it buys **zero** concurrency: SQLite permits one writer at a time even in WAL mode, and `BEGIN IMMEDIATE` (`crates/slashing/src/stage.rs:357`, `:438`) takes that writer lock at stage time, so a second connection's `BEGIN IMMEDIATE` returns `SQLITE_BUSY` or blocks for the whole sign — identical wall clock, worse failure mode. Lighthouse pins `POOL_SIZE = 1` *and* `locking_mode=EXCLUSIVE` for exactly this reason |
| **Sharding into per-pubkey DB files** | **Rejected** | Breaks single-file EIP-3076 export/import (`crates/slashing/src/db/interchange.rs`), GVR pinning (`db/mod.rs`, cached `genesis_validators_root`), backup, and the integrity check |
| **Enabling / relying on WAL** | **Rejected as a non-fix** | WAL is **already enabled and hard-fails at open** (`crates/slashing/src/db/open.rs:217-238`). It gives reader/writer concurrency, not writer/writer |
| **Migrating off SQLite to Postgres** | **Out of scope (NG5)** | — |
| **Group commit as a day-one design** | **Deferred (A-5.9 / A-A9)** | Admissible only if `ARCH-5m` measures fsync to bind (`synchronous=EXTRA` + `fullfsync=ON`, `db/open.rs:240-246`). It preserves commit-before-sign exactly, so it remains available |
| **Removing `spawn_blocking` now that the guard is `Send`** | **Rejected (C9 anchor 7)** | It is what makes the sequence uncancellable. Moving it is a separate decision ADR-005 does not take |
| **Deleting `stage_*` in this phase** | **Deferred (A-5.2)** | **63** counted test call sites across 6 files in `crates/slashing/tests/`, plus 2 production wrappers in `scoped.rs`; the safety it would buy is bought instead by `ARCH-5l`'s production-caller scanner at a fraction of the cost |
| **Deleting `stage_then_sign` in this phase** | **Deferred, symmetrically** | It has **6 exercising unit tests inside `crates/signer/src/core.rs`** (`:677`, `:756`, `:799`, `:852`, `:898`, `:946`) that would all need migrating. Retiring the old staging API is **one follow-up project** — `stage_*` + `stage_then_sign` + `StagedRow` together — not a tail bolted onto the switchover PR. `ARCH-5l` proves *no production caller remains*, which is the property that matters |
| **Reusing the `StagedRow` trait for reservations** | **Rejected (VD-5.4)** | `discard_row(self)` returns `()`, so a failed compensating delete would have no error surface — exactly the signal A-5.5 requires to be metered |

---

## 6. Phase Summary

**Point scale** 1 / 2 / 3 / 5; **no issue in this phase exceeds 3** — every 5-point candidate
(ARCH-P1-5 above all) was split. 1 pt ≈ 0.5–1 working day, covering coding + tests + review +
integration.

| Issue | Title | Pts | Type | Blocked by | Stream | Scope |
|---|---|---|---|---|---|---|
| **ARCH-5a** | Load harness: latency-injecting BLS backend + concurrent `signer-server` driver | 3 | chore | — (E1) | **B** | 1.5–3 d |
| **ARCH-5b** | M3 baseline run + the tx-hold observation-window decision (VD-5.2) | 2 | spike | 5a | **B** | 1–2 d |
| **ARCH-5c** | Fold `sign_nonslashable` ×2 and unify `DEFAULT_SIGN_TIMEOUT` (ARCH-P1-6, PRD-literal) | 3 | chore | — | **B** | 1.5–3 d |
| **ARCH-5d** | Fold the four slashable `body` closures into one `core.rs` staging consumer | 3 | chore | 5c | **B** | 1.5–3 d |
| **ARCH-5e** | `reserve_block` / `reserve_attestation` + `CommittedReservation` (additive) | 3 | feature | — (E3) | **A** | 1.5–3 d |
| **ARCH-5f** | `reconcile_unsigned`: compensating delete, `inserted` guard, watermark-safety proof | 3 | feature | 5e | **A** | 1.5–3 d |
| **ARCH-5g** | `PubkeyScopedDb::reserve_*` wrappers + commit-failure inject re-pointed | 2 | feature | 5e, 5f | **A** | 1–2 d |
| **ARCH-5h** | **Proof surface 3** — concurrency proptest over interleaved reservations | 3 | feature | 5f, 5g | **A** | 1.5–3 d |
| **ARCH-5i** | `SlashableSignSession::reserve_then_sign` — additive, no production caller | 2 | feature | 5b, 5d, 5g | **B** | 1–2 d |
| **ARCH-5j** | **Proof surface 1** — the 14-cell error-class × policy matrix | 3 | feature | 5i | **B** | 1.5–3 d |
| **ARCH-5k** | **Proof surface 2** — crash / cancellation injection at every await point | 3 | feature | 5i | **B** | 1.5–3 d |
| **ARCH-5l** | **Switchover** — flip the production call site, delete `stage_then_sign`, add the `stage_*` production-caller scanner | 3 | feature | 5h, 5j, 5k | **B** | 1.5–3 d |
| **ARCH-5m** | M3 post-change run, rollback plan, honest VC-path ceiling record | 2 | chore | 5l | **B** | 1–2 d |
| **ARCH-5n** | `ValidatorLockMap` eviction with a bounded map (ARCH-P2-1) | 2 | chore | — | **A** (slack) | 1–2 d |
| **ARCH-5o** | Type the internal slashing records (ARCH-P2-2, rescoped by VD-5.5) | 2 | chore | 5l | **A** | 1–2 d |
| | **Total** | **39** | | | **A 15 · B 24** | |

### 6.1 Stream model and file ownership

Two streams, chosen so each **owns a disjoint set of files**. This is a strict improvement on the
plan's 5A–5E packaging, which put the load harness, the fold and the redesign all in the signer
crate and therefore could not be parallelised at all.

| Path | Owner | Notes |
|---|---|---|
| `crates/slashing/src/{stage.rs, scoped.rs, db/mod.rs, types.rs}` | **A** | `stage.rs` is the A-12 re-pin surface (E3) |
| `crates/slashing/tests/**` | **A** | `conformance.rs` is **untouched** this phase (A-5.2 / VD-5.7) |
| `crates/signer/src/{core.rs, lib.rs, gate.rs}` | **B** | The entire fold + switchover chain |
| `crates/signer/tests/**` | **B** | Proof surfaces 1 and 2 |
| `crates/signer-server/tests/**` | **B** | The load profile (A-5.4) |
| `crates/signer/src/locks.rs` | **A (slack)** | Sole toucher is `ARCH-5n`; assigning it to A keeps B off the file entirely, so the "disjoint" property survives the rebalance |
| `plan/architecture-2026-08-12/measurements/` *(new)* | **B** | M3 baseline + post-change records |
| `crates/architecture-tests/tests/stage_api_scope.rs` *(new)* | **B** | `ARCH-5l`'s production-caller scanner |
| `crates/metrics/src/definitions.rs` | **shared — the one exception** | Touched by `ARCH-5f` (Stream A: `rvc_slashing_reconcile_total`) and `ARCH-5l` (Stream B: the reserve-only tx-hold series). **Strategy — strict ordering, not "be careful":** `ARCH-5f` merges first and lands *both* additions as one appended, comment-delimited `// ── ADR-005 (Phase 5) ──` block; `ARCH-5l` then only wires the second series up, editing no definition. Chosen because 5f strictly precedes 5l on the dependency graph, so the ordering costs nothing |

**The one cross-stream handoff** is `ARCH-5g → ARCH-5i`: Stream B cannot write the additive
`reserve_then_sign` until Stream A's `reserve_*` + `reconcile_unsigned` + scoped wrappers exist.
Stream A reaches that point at 8 pts; Stream B has 11 pts of independent work (`5a`,`5b`,`5c`,`5d`)
to fill it, so **the handoff introduces no idle time in either direction**.

### 6.2 Execution plan (single-stream default — the house baseline)

| Day | Issue |
|---|---|
| 1–3 | ARCH-5a Load harness |
| 4–5 | ARCH-5b M3 baseline + observation-window decision |
| 6–8 | ARCH-5c Fold `sign_nonslashable` + timeout constant |
| 9–11 | ARCH-5d Fold the four slashable closures |
| 12–14 | ARCH-5e `reserve_*` + `CommittedReservation` |
| 15–17 | ARCH-5f `reconcile_unsigned` |
| 18–19 | ARCH-5g `PubkeyScopedDb::reserve_*` |
| 20–21 | ARCH-5i `reserve_then_sign` (additive) |
| 22–24 | ARCH-5j Proof surface 1 — matrix |
| 25–27 | ARCH-5k Proof surface 2 — crash injection |
| 28–30 | ARCH-5h Proof surface 3 — concurrency proptest |
| 31–33 | **ARCH-5l Switchover** |
| 34–35 | ARCH-5m M3 post-change + rollback plan |
| 36–37 | ARCH-5n `ValidatorLockMap` eviction *(cut line)* |
| 38–39 | ARCH-5o Type internal slashing records *(cut line)* |

Days are at the **slow** end of the rate (1 pt ≈ 1 d). At the fast end the same order completes in
20 d. Cutting `ARCH-5n` + `ARCH-5o` removes 4 d from either end and costs **no exit criterion** —
X1–X9 all belong to `5a`–`5m`.

### 6.3 Dependency map

```text
                                   ── Stream B ──
ARCH-5a ──▶ ARCH-5b ──┐
ARCH-5c ──▶ ARCH-5d ──┤
                      ├──▶ ARCH-5i ──┬──▶ ARCH-5j ──┐
                      │              └──▶ ARCH-5k ──┤
                                   ── Stream A ──   ├──▶ ARCH-5l ──▶ ARCH-5m
ARCH-5e ──▶ ARCH-5f ──▶ ARCH-5g ──┬──────────┘      │        │
                                  └──▶ ARCH-5h ─────┘        └──▶ ARCH-5o
ARCH-5n  (independent — absorbs slack in either stream)
```

`ARCH-5l` is the phase's single **switchover gate**: three proof surfaces (`5h`, `5j`, `5k`) and the
recorded baseline (`5b`) all converge on it. Nothing after it is safety-critical.

### 6.4 Risk flags

| Risk | Issues | Mitigation |
|---|---|---|
| **R1 — retain-on-ambiguity broken subtly, green tests.** The highest-consequence risk in the initiative | 5e, 5f, 5i, 5l | C1's by-name rejection in `ARCH-5e`'s body; three proof surfaces as **switchover gates**, not follow-ups (X2); `5c`/`5d` shrinking the diff before it is written |
| **R9 / A-12 — cross-plan pin on `stage.rs`** | 5e | Entry criterion E3; resolved before the first commit, never discovered. **RP2:** if the tracing plan lands TRC-1e mid-flight this becomes a hard cross-plan dependency and `ARCH-5e` blocks until the pin is re-scoped |
| **Reconcile-failure liveness regression on the Discard path** (A-5.5) | 5f, 5l | Metered + `error!`-logged; measured in `ARCH-5m`'s run. If non-zero in production, it promotes A-5.9 |
| **M3 shows no improvement because the metric window still contains the sign** (VD-5.2) | 5b, 5m | The observation-window decision is an explicit deliverable of `ARCH-5b`, taken **before** the redesign |
| **`ARCH-5d` is larger than 3 pts** because the four closures differ in error type and audit CN | 5d | Named in the issue; if the probe shows >3 pts it splits `5d1` (gate pair) / `5d2` (SignerService pair) along the error-type boundary |

## 7. Issues

---

### ARCH-5a — Load harness: latency-injecting BLS backend + concurrent `signer-server` driver

- **Points:** 3 · **Type:** chore · **Priority:** P0 · **Stream:** B · **Scope:** 1.5–3 days
- **Blocked by:** none (phase entry E1) · **Blocks:** ARCH-5b
- **Requirements:** **ARCH-P1-15a** (the harness-build half, split out by the plan's departure D8)
- **Constraints:** C9 anchor 5 (adds no signing surface)

**Context.** The hold-duration metric exists — `RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS`, observed
at `crates/signer/src/core.rs:219`, regression-pinned by `crates/signer/tests/tx_hold_metric.rs` —
but **nothing drives it under load**. The plan's VD-P2 warns that a planner checking
`git ls-files '*/benches/*'` will find two files (`crates/signer/benches/sign_path.rs`,
`crates/rvc/benches/per_slot.rs`) and size this down: both are **logging-latency** benches under
three subscriber regimes, and both say so in their own headers. Neither measures sign throughput.
**This is a new build.**

**Profile target is `signer-server`, not the VC (A-5.4/A-A8).** `SigningGate` is reached over
gRPC/HTTP where requests genuinely arrive concurrently, so the global
`parking_lot::Mutex<Connection>` (`crates/slashing/src/stage.rs:355`, `:436`) actually binds. The
VC path cannot show the effect — `crates/rvc/src/orchestrator/attestation.rs:171-192` is a
sequential `for duty in duties { … .await }` loop.

**Files to touch**
- `crates/signer-server/tests/load_profile.rs` *(new)* — the driver.
- `crates/signer-server/tests/helpers.rs` — extend with a load-fixture constructor; do **not**
  change existing helper signatures (7 `sign_*_v2.rs` suites depend on them).
- `crates/signer/src/lib.rs` — **read-only reference**: `SignerService` already exposes a
  `sign_backend` override (`:319`) and `SigningGate::new_with_raw_signer` exists (`gate.rs:174`),
  so the latency injector needs **no production change**. If a production seam turns out to be
  missing, that finding is the deliverable and the issue stops — it does not grow a production edit.

**Implementation approach**
1. `SlowSigner`: a `crypto::Signer` impl wrapping `LocalSigner` with a configurable
   `tokio::time::sleep` before returning (default **200 ms**, A-9). It must sleep on the *async*
   side so it is observed through `Handle::block_on(timeout(...))` at `core.rs:284-287` exactly as
   a remote signer would be.
2. Fixture: **200 keys** (A-9), one `SlashingDb` (temp file, real `open` path so WAL +
   `synchronous=EXTRA` are live — `crates/slashing/src/db/open.rs:217-246`), one `SigningGate`.
3. Driver: issue 200 concurrent `sign_attestation` calls (distinct pubkeys, one attestation each)
   and record per-call wall clock plus the `RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS` histogram.
4. Emit a machine-readable summary (p50/p95/p99, max, total wall) to stdout **and** a file path
   given by an env-free CLI arg, so `ARCH-5b` can commit it verbatim.
5. Gate it behind `#[ignore]` so `cargo nextest run --workspace` stays fast (NFR-5); CI does not
   run it. Document the exact invocation in the file header.

**TDD test plan**
- **RED first:** `test_load_profile_reports_p99_above_serialized_floor` — asserts the harness
  observes a p99 **≥ 200 keys × 200 ms / concurrency-actually-achieved**, i.e. that it *detects*
  full serialization. Written before the driver exists, it fails to compile; then fails on an
  empty summary; then passes. This is the harness's own non-vacuity check: a harness that measures
  a free DB is worthless as a baseline.
- `test_slow_signer_delays_are_observed_through_the_blocking_bridge` — 1 key, 200 ms injected,
  asserts the recorded hold is ≥ 200 ms. Proves the injector is not bypassed by `spawn_blocking`.
- **KAT note (A-5.10):** no test in this issue may be named `*_root`; none needs to be.

**Acceptance criteria**
- [x] A single command runs the 200-key / 200 ms profile against `signer-server` and prints
      p50/p95/p99/max for both wall-clock latency and the tx-hold histogram.
- [x] The harness is `#[ignore]`d and does not lengthen `cargo nextest run --workspace`.
- [x] The non-vacuity test proves the harness detects serialization (RED demonstrated on an
      artificially free DB).
- [x] No production file under `crates/signer/src/` or `crates/signer-server/src/` is modified;
      `git diff --stat` in the PR shows tests-only.
- [x] Header documents: key count, injected latency, DB pragmas in force, and that the profile
      targets `signer-server` **because the VC path's wall is its sequential loop, not the mutex**
      (X8).

---

### ARCH-5b — M3 baseline run + the tx-hold observation-window decision

- **Points:** 2 · **Type:** spike · **Priority:** P0 · **Stream:** B · **Scope:** 1–2 days
- **Blocked by:** ARCH-5a · **Blocks:** ARCH-5i (and therefore the whole switchover chain)
- **Requirements:** **ARCH-P1-15a** (the baseline half) · Success metric **M3**
- **Constraints:** — (measurement only)

**Context — this issue exists because of VD-5.2, and it is the phase's least obvious dependency.**
The exit criterion "M3 p99 within the per-sign budget" is **unmeetable by construction** unless
someone decides, before the redesign, what M3 measures. At HEAD the metric is **not** a lock-hold
metric: `tx_start` is taken before `stage()` (`crates/signer/src/core.rs:265`) and `tx_hold_ms` is
computed **after** the sign returns (`:288`), then observed on every terminal branch (`:297`,
`:307`, `:318`, `:354`, `:427`, `:433`). Under ADR-005 the sign is still inside that window, so a
naive before/after would show **no change at all** and the milestone would be unfalsifiable.

**Files to touch**
- `plan/architecture-2026-08-12/measurements/m3-baseline-0ae9a09.md` *(new)* — the recorded run.
  Recorded **in this plan directory**, not only in a run log (project-plan 0D's convention).
- `plan/architecture-2026-08-12/measurements/README.md` *(new)* — one paragraph: what each file is,
  how to reproduce it, which commit it was taken at.
- No source file. The metric *change* itself is `ARCH-5l`'s work; this issue takes and records the
  **decision**.

**Implementation approach**
1. Run `ARCH-5a`'s profile three times at `0ae9a09` + Phase 1's ADR-006 commit; record all three
   and the median, never a single run.
2. Take the observation-window decision explicitly. **Default (recommended, and the one written
   here unless the run contradicts it):**
   - **Keep** `rvc_signer_slashing_tx_hold_duration_ms` with its current window
     (stage-start → sign-return) so before/after is comparable and
     `crates/signer/tests/tx_hold_metric.rs` — which asserts observation on **both** the
     commit and the discard cycle — keeps passing unchanged.
   - **Add** a second series measuring the reserve transaction only (mutex acquire → COMMIT),
     which is the quantity ADR-005 actually shrinks.
   - Record X6 under **both** definitions. Reporting only the redefined one would make the
     milestone look met by a definition change.
3. Derive and write down the **per-sign budget** the exit criterion refers to: 200 keys inside one
   attestation window (A-9). State the arithmetic; do not assert a number.
4. Record the *observed* concurrency achieved, so `ARCH-5m` compares like with like.

**TDD test plan**
- This is a measurement spike; its RED is the **absence** of a recorded file. The check-in gate is
  a one-line assertion in `ARCH-5m`: the post-change document must cite this file's commit hash.
- If the harness's numbers are not reproducible across three runs (>20 % spread on p99), that is
  the finding: the issue's deliverable becomes a named source of variance and `ARCH-5a` is
  reopened rather than the baseline being averaged into meaninglessness.

**Acceptance criteria**
- [x] `plan/architecture-2026-08-12/measurements/m3-baseline-0ae9a09.md` exists, is non-empty, and
      records three runs + median for p50/p95/p99/max, the achieved concurrency, the DB pragmas,
      and the exact harness invocation.
- [x] The observation-window decision is **stated with its consequence for
      `tx_hold_metric.rs`** — which of the two series each of that file's assertions binds to.
- [x] The per-sign budget is derived from A-9 with the arithmetic shown, not asserted.
- [x] Phase entry criterion **E2 is now satisfiable**; the file is linked from the phase's PR.

---

### ARCH-5c — Fold `sign_nonslashable` ×2 and unify `DEFAULT_SIGN_TIMEOUT`

- **Points:** 3 · **Type:** chore · **Priority:** P1 · **Stream:** B · **Scope:** 1.5–3 days
- **Blocked by:** none · **Blocks:** ARCH-5d
- **Requirements:** **ARCH-P1-6** (PRD-literal reading, `prd.md:807-815`) · **M9** (removes one
  duplicated seam: "non-slashable path ×2")
- **Constraints:** C9 anchor 5

**Context.** `SignerService` (`crates/signer/src/lib.rs:169`) and `SigningGate`
(`crates/signer/src/gate.rs:115`) must differ only in **policy inputs**, not in duplicated code
paths or duplicated timeout constants. Verified at HEAD, and the duplication is exact:

- `const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(4);` appears **twice** —
  `gate.rs:115` and `lib.rs:169`. Same value, two declarations.
- Two `async fn sign_nonslashable` bodies with the same 2-step flow and the same doc block
  (including the same "No-lock invariant" and "TOCTOU note" paragraphs):
  `gate.rs:426-479` and `lib.rs:461-515`.

**This is not a copy-paste dedup — the two differ in four load-bearing ways**, and any estimate
that misses them is low:

| | `SigningGate::sign_nonslashable` | `SignerService::sign_nonslashable` |
|---|---|---|
| Return | `Result<Vec<u8>, SigningGateError>` | `Result<Signature, SignerError>` |
| Gate call | `if !self.gate_decision(pubkey) { … }` (bool, fail-closed) `gate.rs:436` | `self.ensure_signing_enabled(pubkey)?` (Result) `lib.rs:468` |
| Backend field | `self.signer` `gate.rs:447` | `self.sign_backend` `lib.rs:483` |
| `KeyNotFound` | mapped explicitly `gate.rs:461-468` | folded into `e.into()` `lib.rs:512` |
| Extra work | — | `debug!` "Signing non-slashable duty" + `start.elapsed()` timing `lib.rs:472-478`, `:497-503` |

**VD-5.1 must be recorded in this issue's description**: the plan justifies ARCH-P1-6's position
before the redesign with *"rewrites one staging consumer instead of two"* — but both helpers
document in-source that they touch **no** staging API (`gate.rs:405-411`, `lib.rs:440-446`). That
rationale belongs to `ARCH-5d`, not here. This issue is scheduled first for a different and honest
reason: it is the cheapest way to establish the "one core, two policy inputs" shape that `ARCH-5d`
then extends to the slashable path.

**Files to touch**
- `crates/signer/src/core.rs` — new `pub async fn sign_nonslashable_core(...)` returning a neutral
  outcome; `pub const DEFAULT_SIGN_TIMEOUT`.
- `crates/signer/src/gate.rs` — delete the local const (`:115`) and the local helper (`:426-479`);
  7 call sites re-point.
- `crates/signer/src/lib.rs` — delete the local const (`:169`) and the local helper (`:461-515`);
  re-point call sites; keep the `debug!`/timing in the `SignerService` wrapper (it is VC-specific
  operator output, not core behaviour).

**Implementation approach**
1. Core signature returns a **neutral outcome**, not either error type — e.g.
   `Result<Signature, NonSlashableFailure>` where
   `NonSlashableFailure { TimedOut { after: Duration }, KeyNotFound, Backend(SigningError), Blocked }`.
   Each wrapper maps it to its own error type. This is what keeps the fold honest instead of
   forcing one error type on the other crate boundary.
2. Enablement stays at the **wrapper**: the core takes a `&dyn SigningEnablement` and calls it, so
   the "same gate point as slashable paths" property (`gate.rs:435`, `lib.rs:467`) is preserved and
   testable once rather than twice.
3. `DEFAULT_SIGN_TIMEOUT` moves to `core.rs` and is re-exported; both former sites reference it.
4. **Do not touch** the `!Send` staging path, `spawn_blocking`, or any `stage_*` call — the
   no-lock invariant doc block moves verbatim onto the core helper, including its
   *"**If a future variant of this helper needs to write to the slashing DB, it MUST add the
   per-pubkey lock and the staging/commit/discard pattern**"* warning.

**TDD test plan**
- **RED first:** `test_one_default_sign_timeout_declaration` in `crates/signer/tests/` — a
  source-text assertion that `rg -c 'const DEFAULT_SIGN_TIMEOUT' crates/signer/src` returns `1`.
  It fails today (returns 2) and is the mechanical proof the constant is unified. This is the
  workspace grep gate ARCH-P1-6's acceptance criteria call for.
- `test_nonslashable_path_behaves_identically_through_both_entry_points` — a table-driven test
  running the same four outcomes (success, timeout, `KeyNotFound`, generic backend error) through
  `SigningGate::sign_sync_committee_message` and `SignerService`'s equivalent, asserting the same
  classification on both. RED before the fold (the two paths' `KeyNotFound` handling differs
  observably), green after.
- Existing coverage that must stay green unchanged: `lib.rs:3031` (hung backend times out),
  `lib.rs:3061-3085` (non-slashable must not block on the validator lock), `lib.rs:3132-3135`
  (non-slashable writes **no** slashing rows) — the last is the strongest regression pin here.

**Acceptance criteria**
- [x] Exactly **one** `DEFAULT_SIGN_TIMEOUT` declaration in `crates/signer/src`, asserted by a test.
- [x] Exactly **one** non-slashable flow implementation; both entry points delegate.
- [x] A test asserts identical behaviour through both entry points across four outcome classes.
- [x] `lib.rs:3132-3135`'s "non-slashable must not write block/attestation rows" assertions stay
      green **verbatim**.
- [x] The no-lock invariant doc block survives on the folded helper (it is the guard rail that
      stops a future contributor adding DB writes to a lock-free path).
- [x] `cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings` green (CI Gate 1,
      `ci.yml:47`).

---

### ARCH-5d — Fold the four slashable `body` closures into one `core.rs` staging consumer

- **Points:** 3 · **Type:** chore · **Priority:** P0 · **Stream:** B · **Scope:** 1.5–3 days
- **Blocked by:** ARCH-5c · **Blocks:** ARCH-5i
- **Requirements:** **ARCH-P1-6** (expansive reading, A-5.3) · **M9**
- **Constraints:** **C9 anchor 2** (must not weaken the cancellation-proof core), C9 anchor 7

**Context — this is the issue that makes the plan's ordering rationale true (VD-5.1).** There are
**four** production closures passed as `body` to `sign_slashable`, each of which constructs a
`PubkeyScopedDb` and calls `session.stage_then_sign(|| scoped.stage_*(…))`:

| # | `session.stage_then_sign` call site | Enclosing method | Policy | Audit CN |
|---|---|---|---|---|
| 1 | `crates/signer/src/gate.rs:280` | `SigningGate::sign_block` (`:241`) | `Fixed(DiscardStagedRow)` `:274` | caller's mTLS CN `:262` |
| 2 | `crates/signer/src/gate.rs:366` | `SigningGate::sign_attestation` | `Fixed(DiscardStagedRow)` `:360` | caller's mTLS CN |
| 3 | `crates/signer/src/lib.rs:620` | `SignerService::sign_attestation` (`:542`) | `ResolveUnderLock` via `timeout_policy_source(pubkey)` `:591` | `"local-vc"` |
| 4 | `crates/signer/src/lib.rs:722` | `SignerService::sign_block` | `ResolveUnderLock` | `"local-vc"` |

All four verified by `rg -n 'stage_then_sign' crates/signer/src`, which returns **13** occurrences:
these 4 production call sites, the declaration (`core.rs:260`), 2 doc references (`core.rs:238`,
`:479`), and **6 exercising unit tests inside `core.rs`'s own `#[cfg(test)] mod tests`**
(`:677`, `:756`, `:799`, `:852`, `:898`, `:946`). Those 6 are why `stage_then_sign`'s **deletion**
is deferred out of this phase (§5) — this issue removes its *production* callers, not the method.

Folding these to **one** is what turns `ARCH-5l`'s switchover from four edits into one. Without
this issue, the highest-risk change in the initiative is applied four times in four slightly
different contexts — which is precisely how R1 (retain-on-ambiguity broken subtly, green tests)
materialises.

**Files to touch**
- `crates/signer/src/core.rs` — add the single staging consumer.
- `crates/signer/src/gate.rs` — sites 1 and 2 lose their closures.
- `crates/signer/src/lib.rs` — sites 3 and 4 lose their closures.

**Implementation approach**
1. Extend `SignSlashableRequest` with the data the closures currently capture: `slashing_db:
   Arc<SlashingDb>`, `client_cn: String`, `gvr: Root`, and a `SlashableKind` enum
   (`Block { slot }` | `Attestation { source_epoch, target_epoch }`). The four call sites then
   pass **data**, not behaviour.
2. `sign_slashable` builds the `PubkeyScopedDb` **inside** `spawn_blocking` (it must — the guard is
   `!Send`) and dispatches on `SlashableKind`. The rejection `error!` log the closures currently
   emit moves into the core with the kind as a field, so the two log lines become one with a
   `duty` label.
3. **Do not change the signature of `stage_then_sign`, and do not touch the four `finish_*`
   methods.** This issue is a *caller* collapse; the semantics it must preserve are exactly the
   14 cells of §5.3's "today" column. If a semantic difference is discovered between the gate and
   VC closures, that difference is the finding and the issue reports it rather than harmonising it
   silently.
4. Watch out: site 1 clones `pubkey_hex` **twice** (`gate.rs:249`, `:263`) because the closure is
   `move`. After the fold there is one owner; the clone count must drop, not stay.

**TDD test plan**
- **RED first:** `test_single_production_stage_then_sign_call_site` — a source-text assertion,
  **scoped to production code** so `core.rs`'s six in-file unit tests do not contaminate it:
  `rg -n 'session\.stage_then_sign' crates/signer/src/gate.rs crates/signer/src/lib.rs` returns
  **0**, and the sole production caller lives in `core.rs` outside `#[cfg(test)]`. It returns
  **4** today (`gate.rs:280`, `gate.rs:366`, `lib.rs:620`, `lib.rs:722`). Mechanical, unfoolable,
  and it is the pin `ARCH-5l` relies on when it asserts the switchover touched one place. A naive
  `rg -c 'stage_then_sign' crates/signer/src` returns 13 and would assert nothing.
- `test_gate_and_service_produce_identical_slashing_rows_for_the_same_duty` — sign the same
  attestation through `SigningGate` and `SignerService` against two fresh DBs and assert the
  committed rows are identical **except** `client_cn`. RED if the fold accidentally unifies the CN.
- Regression pins that must stay green untouched: `crates/signer/tests/phantom_row_m1.rs`,
  `crates/signer/tests/commit_failed_path.rs`, `crates/signer/tests/tx_hold_metric.rs`.
- **KAT note (A-5.10):** none of these may be named `*_root`.

**Acceptance criteria**
- [x] Exactly **one** *production* `session.stage_then_sign(...)` call site (in `core.rs`, outside
      `#[cfg(test)]`), asserted by a test; `gate.rs` and `lib.rs` contain none.
- [x] The four public entry points (`SigningGate::{sign_block, sign_attestation}`,
      `SignerService::{sign_block, sign_attestation}`) keep their signatures and their error types.
- [x] `client_cn` is still per-caller on the gate path and `"local-vc"` on the VC path, asserted.
- [x] `TimeoutPolicySource::ResolveUnderLock`'s **double resolution** is untouched — the
      `fail_closed_max` merge at `core.rs:280-282` is not moved, reordered, or made conditional
      (SEC-1).
- [x] `spawn_blocking` still wraps the sequence (`core.rs:542`) — **C9 anchor 7** (X9).
- [x] `phantom_row_m1.rs`, `commit_failed_path.rs`, `tx_hold_metric.rs` green with **zero** edits.
- [x] **If the fold measures beyond 3 points**, split at the error-type boundary: `ARCH-5d1`
      (gate pair) / `ARCH-5d2` (SignerService pair). Recorded up front, not discovered.

---

### ARCH-5e — `reserve_block` / `reserve_attestation` + `CommittedReservation`

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Stream:** A · **Scope:** 1.5–3 days
- **Blocked by:** none (phase entry **E3** must be resolved before the first commit) ·
  **Blocks:** ARCH-5f, ARCH-5g
- **Requirements:** **ARCH-P1-5** (ADR-005) · Interface spec **architecture §5.3** (`:1212-1250`)
- **Constraints:** **C1 (binding)**, C9 anchor 2, C10 (the orphan-tree exclusion note)

**Context.** At HEAD the API hands the caller an RAII guard that **owns the connection mutex** for
the whole sign. Verified: `stage_block` at `crates/slashing/src/stage.rs:334-400` takes
`let guard = self.conn.lock();` (`:355`), issues `BEGIN IMMEDIATE` (`:357`), runs the rule check,
and returns a `StagedBlock` **holding that guard** (`:388-399`) — the INSERT happens later, in
`commit()`. `stage_attestation` is the same shape at `:415-...`, `guard` at `:436`, `BEGIN
IMMEDIATE` at `:438`. The module's own rationale (`:32-48`) licenses this with *"the SQLite WAL
writer lock is coarse-grained anyway"* — a true statement used for a false conclusion: because
there is exactly **one** writer, holding it across a 200 ms sign is *maximally* expensive (VD-S4).

**The M-1 prior-art warning is mandatory reading and must be quoted in this issue's PR
description.** `crates/signer/tests/phantom_row_m1.rs:1-10` documents that this repo **already
shipped commit-before-sign and reverted it as a bug**. The delta between that reverted design and
this one is precisely the compensating delete (`ARCH-5f`) — so **the compensating delete is not an
optimisation, it is the entire reason this ordering is admissible**, and shipping the reorder
without it re-opens M-1. Note that M-1's failure mode was **liveness, not safety** (a phantom row
refuses a legitimate sign; it never permits a double-sign), which is why the fail-safe direction of
the compensating delete is the correct one.

**Rejected alternatives — cite §5 of this document in the PR description**, in particular
stage→release→sign→re-check (C1, by name), **per-pubkey connections** (VD-S1: zero concurrency
against one SQLite file), sharding, WAL (already on, `db/open.rs:217-238`), Postgres (NG5), and
group commit as a day-one design (A-5.9).

**Files to touch**
- `crates/slashing/src/stage.rs` — add `reserve_block` / `reserve_attestation` **alongside**
  `stage_block` / `stage_attestation` (A-5.2). **E3's A-12 re-pin is recorded before the first
  commit on this file.**
- `crates/slashing/src/lib.rs` — export `CommittedReservation`, `ReservationKind`.
- `crates/slashing/tests/reserve.rs` *(new)*.

**Implementation approach — the signature is fixed by architecture §5.3, not open**
```rust
pub struct CommittedReservation {
    pub pubkey_hex: String,
    pub kind: ReservationKind,        // Block { slot } | Attestation { source, target }
    pub signing_root_hex: Option<String>,
    pub inserted: bool,               // false for an idempotent re-sign / duplicate
}
pub fn reserve_block(&self, pubkey_hex: &str, slot: Slot,
                     signing_root_hex: Option<String>, gvr: &Root)
    -> Result<CommittedReservation, SlashingError>;
```
1. **One short write transaction:** `BEGIN IMMEDIATE` → watermark reads → rule check → **INSERT** →
   `COMMIT`. The mutex is acquired and released **inside** the call; **no guard escapes**, so
   `CommittedReservation` is `Send`.
2. **Keep the M-6 GVR pre-check before the mutex** (`stage.rs:341-351`, `:423-432`) — `pinned_gvr()`
   may itself briefly acquire the mutex, so moving it inside is a nested-lock deadlock. Reuse the
   existing code path verbatim.
3. **Keep the error-funnelling closure** (`stage.rs:360-381`): every error between `BEGIN
   IMMEDIATE` and return must pass through exactly one `ROLLBACK`, or the connection is left in a
   "transaction within transaction" state. Extend it to cover the INSERT, which now lives inside.
4. **`inserted` distinguishes a fresh INSERT from a `Resign`/duplicate.** The verdict is already
   available: `matches!(outcome, BlockVerdict::Resign)` (`stage.rs:395`). `inserted = false` on a
   resign, and `ARCH-5f`'s delete is then a documented no-op — deleting a row an *earlier* sign
   legitimately owns would be a safety regression, not a liveness one.
5. **Error surface — the trap.** Because INSERT+COMMIT now happens at reserve time, a commit
   failure and a rule violation both come back as `Err(SlashingError)`. They must remain
   **distinguishable**, or `SigningGateError::CommitFailed` collapses into `SlashingBlocked` and
   `crates/signer/tests/commit_failed_path.rs` (plus `lib.rs:1562`, `:1619`) loses its meaning.
   Default: a dedicated `SlashingError` variant for reserve-time commit failure, classified by the
   signer in `ARCH-5i`.
6. **Do not** change `stage_*`, `commit()`, `discard()`, or `Drop`. `crates/slashing/tests/stage.rs`
   (82 call sites) and `gvr_recheck_m6.rs` (35) must compile and pass with **zero** edits.

**TDD test plan**
- **RED first:** `test_reserve_block_releases_the_connection_mutex_before_returning` in
  `crates/slashing/tests/reserve.rs` — reserve on thread A, then assert a second thread can
  complete a `reserve_block` for a **different** pubkey within a short bound (e.g. 50 ms) while A
  still holds its `CommittedReservation`. Under `stage_block` this deadlocks/blocks; it is the
  single clearest RED for the whole phase. Write it **with a timeout**, not a bare join.
- `test_committed_reservation_is_send` — a compile-time assertion
  (`fn assert_send<T: Send>() {}; assert_send::<CommittedReservation>();`). It fails to compile if
  a guard leaks into the struct, which is the mistake this design exists to prevent.
- `test_reserve_block_rule_violation_leaves_no_row` — a `DoubleBlockProposal` must return `Err`
  **and** leave the history table exactly as it was (the transaction rolled back).
- `test_reserve_block_resign_reports_not_inserted` — same signing root twice ⇒ second call
  `inserted == false`.
- `test_reserve_rejects_genesis_root_mismatch_without_touching_the_mutex` — the M-6 path.
- `test_reserve_commit_failure_is_distinguishable_from_a_rule_violation` — arm
  `fail_next_commits(1)` and assert the error variant differs from a slashing verdict.
- **KAT note (A-5.10):** none of these may be named `*_root` — note
  `test_reserve_rejects_genesis_root_mismatch_without_touching_the_mutex` is deliberately suffixed
  to stay outside the scanner's `.*_root$` pattern.

**Acceptance criteria**
- [x] `reserve_block` / `reserve_attestation` exist, commit inside one short write transaction, and
      return a `Send` `CommittedReservation`; no `MutexGuard` escapes.
- [x] Two different pubkeys can hold reservations concurrently — asserted with a timeout.
- [x] The M-6 GVR pre-check runs **before** the mutex, unchanged.
- [x] All error paths between `BEGIN IMMEDIATE` and return funnel through exactly one `ROLLBACK`.
- [x] `inserted` is `false` on a resign/duplicate and `true` on a fresh INSERT.
- [x] Reserve-time commit failure is a distinct error from a rule violation.
- [x] `stage_*` and its **63** counted test call sites (6 files, A-5.2) are **byte-unchanged**;
      `cargo nextest run -p rvc-slashing` green with no test edits.
- [x] The PR description quotes `phantom_row_m1.rs:1-10` and links §5's rejected-alternatives table.
- [x] **E3's A-12 resolution is recorded in `plan/tracing-2026-08-06/` before this PR merges** —
      lifted or re-pinned, never discovered.

---

### ARCH-5f — `reconcile_unsigned`: compensating delete, `inserted` guard, watermark-safety proof

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Stream:** A · **Scope:** 1.5–3 days
- **Blocked by:** ARCH-5e · **Blocks:** ARCH-5g, ARCH-5h
- **Requirements:** **ARCH-P1-5** (ADR-005) · architecture §5.3 (`:1238-1249`)
- **Constraints:** **C1 (binding)**, C9 anchor 2

**Context — this issue *is* the reason ADR-005's ordering is admissible.** M-1 committed
unconditionally and had **no compensation on any failure class**, so a phantom row survived forever
and permanently over-constrained the pubkey. Everything ADR-005 adds over the reverted design is in
this issue. An implementation that ships `ARCH-5e` without `ARCH-5f` **re-opens M-1** and must not
be merged; the two are separate issues only because they are separately testable, not separately
shippable.

**What makes reconcile safe is a fact stated in neither the review nor the PRD (VD-S6), and it is
re-verified here:** the signing path does **not** raise watermarks — they are raised only by
interchange import. `crates/slashing/tests/conformance.rs:18-21` states it in-source: *"production
signing does not auto-raise watermarks after each sign — that remains history-table driven on the
complete path."* Therefore a compensating delete of a history row **cannot lower a watermark and
cannot re-open a slot a minified import had closed**. Blast radius is exactly one history row, and
every failure of the delete fails **safe** (the retained row over-constrains future signing, never
permits a sign).

**The liveness trade must be conscious, not discovered (A-5.5).** `SigningGate` is
`Fixed(DiscardStagedRow)` (`crates/signer/src/gate.rs:274`, `:360`) — the exact path the load
profile targets. Today its timeout/ambiguous classes ROLLBACK; after the change they reconcile, and
a **failed** delete retains — which is M-1's liveness failure mode. Accepted in the fail-safe
direction, but it must be **metered and logged at `error!`**, never silent.

**Files to touch**
- `crates/slashing/src/stage.rs` — `reconcile_unsigned`.
- `crates/slashing/src/lib.rs` — export `ReconcileOutcome`.
- `crates/metrics/src/definitions.rs` — **the phase's one shared file** (§6.1). Land the whole
  Phase-5 block here, in one appended `// ── ADR-005 (Phase 5) ──` section: the counter
  `rvc_slashing_reconcile_total{kind, outcome}` (`outcome ∈ {deleted, not_applicable, failed}`)
  **and** the reserve-only tx-hold series `ARCH-5l` will wire up. Two series total — the executor's
  two-series discipline (A-A5) is the house norm. Landing both here is the merge-conflict strategy,
  not a scope creep: `ARCH-5l` then edits no definition.
- `crates/slashing/tests/reserve.rs` — extend.

**Implementation approach**
```rust
pub enum ReconcileOutcome { Deleted, NotApplicable, Failed(SlashingError) }
pub fn reconcile_unsigned(&self, reservation: &CommittedReservation) -> ReconcileOutcome;
```
1. **Returns an outcome, never a `Result`** — the caller must not be able to `?` it and abort a
   signing path on a compensation failure. Failing safe means *continuing* with the row retained.
2. **No-op when `!reservation.inserted`** → `NotApplicable`. Deleting a row an earlier legitimate
   sign owns would be a **safety** regression, not a liveness one — this guard is the sharpest edge
   in the issue.
3. Delete is **targeted**: `(pubkey, kind-discriminant, signing_root)` must all match, so a
   concurrently-inserted different row for the same slot/epoch pair cannot be removed. Run it in
   its own short `BEGIN IMMEDIATE` transaction; assert `changes() <= 1`.
4. **Never touch the watermark tables.** Add a `debug_assert` and a test proving watermarks are
   byte-identical before and after — VD-S6 is a *fact about today's code*, and this issue is what
   keeps it true tomorrow.
5. Emit the counter and, on `Failed`, an `error!` naming pubkey (truncated,
   `observability::logging::TruncatedPubkey` — the house idiom) and kind. Emission is **outside**
   the mutex by construction (**C2** / G-7).

**TDD test plan**
- **RED first:** `test_reconcile_deletes_exactly_the_reserved_row` — reserve two blocks for the
  same pubkey at different slots, reconcile one, assert the **other** survives and the history
  table has exactly one row. Fails to compile before `reconcile_unsigned` exists; then fails on a
  naive `DELETE … WHERE pubkey = ?`; then passes.
- `test_reconcile_is_a_noop_for_a_resign_reservation` — `inserted == false` ⇒ `NotApplicable` and
  the row survives. This is the safety-critical guard.
- `test_reconcile_never_changes_watermarks` — snapshot both watermark tables before and after a
  reserve + reconcile cycle; assert equality. Directly pins VD-S6.
- `test_reconcile_after_a_minified_import_cannot_reopen_a_closed_slot` — import a minified
  interchange (watermark-only), reserve above it, reconcile, then assert a sign **at or below** the
  watermark is still refused. This is the criterion that would catch a delete that accidentally
  lowered a floor.
- `test_reconcile_failure_reports_failed_and_retains_the_row` — inject a failing DB and assert
  `Failed(_)` **and** the row still present. The fail-safe direction, asserted rather than assumed.
- **KAT note (A-5.10):** none named `*_root`.

**Acceptance criteria**
- [x] `reconcile_unsigned` returns `ReconcileOutcome`, never `Result`; no caller can `?` it.
- [x] `NotApplicable` on `!inserted`, asserted.
- [x] The delete is targeted on `(pubkey, kind, signing_root)` and affects at most one row.
- [x] Watermarks are provably unchanged across reserve + reconcile.
- [x] A minified-import floor cannot be re-opened by a reconcile.
- [x] A failed delete yields `Failed(_)`, **retains** the row, increments
      `rvc_slashing_reconcile_total{outcome="failed"}`, and logs at `error!`.
- [x] The liveness trade (A-5.5) is written into the module docs: *under `DiscardStagedRow` a
      failed compensating delete leaves a phantom row — M-1's liveness mode, accepted because the
      alternative direction permits a double-sign.*
- [x] G-7 (`audit_log_scope.rs`) green — no emission inside a scope holding the DB mutex.

---

### ARCH-5g — `PubkeyScopedDb::reserve_*` wrappers + commit-failure inject re-pointed

- **Points:** 2 · **Type:** feature · **Priority:** P0 · **Stream:** A · **Scope:** 1–2 days
- **Blocked by:** ARCH-5e, ARCH-5f · **Blocks:** ARCH-5h, ARCH-5i *(the cross-stream handoff)*
- **Requirements:** **ARCH-P1-5** · **C2** (must not regress Phase 1's ADR-006)
- **Constraints:** **C2**, C9 anchor 2

**Context.** The signer never calls `SlashingDb::stage_*` directly — it goes through
`PubkeyScopedDb`, which pins the audit CN and the GVR. Verified at HEAD:
`crates/slashing/src/scoped.rs:41-49` (`new(db, client_cn, gvr)`), `:62` (`stage_block`),
`:88` (`stage_attestation`), with `audit_log(...)` at `:75` and `:106`. Phase 1's ADR-006 moved
those two emissions out of the mutex; **this issue must not put them back**, and the new wrappers
must be structurally clean rather than carefully clean: `reserve_*` releases the mutex *before*
returning, so an emission after it is outside the lock by construction.

The test-inject also has to move. `SlashingDb::fail_next_commits` (`crates/slashing/src/db/mod.rs:97`)
is **snapshotted onto the staged guard at stage time** via `take_injected_commit_failure`
(`stage.rs:387`, `:469`) and consumed by `commit()`. With INSERT+COMMIT inside `reserve_*`, the
snapshot point and the consumption point become the same call. Downstream consumers:
`crates/signer/tests/commit_failed_path.rs:25`, `:65` and `crates/signer/src/lib.rs:1562`, `:1619`.

**Files to touch**
- `crates/slashing/src/scoped.rs` — `reserve_block`, `reserve_attestation`, `reconcile_unsigned`
  pass-through.
- `crates/slashing/src/stage.rs` / `db/mod.rs` — inject consumption inside `reserve_*`.
- `crates/slashing/tests/reserve.rs` — extend.

**Implementation approach**
1. Wrappers mirror `scoped.rs:62-80` / `:88-110` exactly in shape: normalise, delegate, then emit
   the audit event with `self.client_cn`. The audit **outcome** label changes meaning and must be
   re-documented: `"staged"` correlated with *"a row will exist if the sign succeeds"*; it now
   correlates with *"a row exists"*. **Replace** the doc note at `scoped.rs:70-74` for the reserve
   path — do not edit around it (ADR-006's own rule).
2. `reconcile_unsigned` gets a scoped pass-through so the compensation is auditable with the same
   CN; emit `outcome = "reconciled" | "reconcile_failed"`.
3. Move the inject: `take_injected_commit_failure()` is consumed inside `reserve_*` immediately
   before the INSERT, and forces the reserve to fail with the reserve-time commit-failure variant
   from `ARCH-5e`. `fail_next_commits`'s public signature does not change.

**TDD test plan**
- **RED first:** `test_scoped_reserve_emits_audit_outside_the_connection_mutex` — install a
  subscriber that acquires the slashing DB mutex on every event, then drive a scoped
  `reserve_block`. **Write it with a `tokio::time::timeout`**, because the failure mode is a
  deadlock, not an assertion failure. Green today only because Phase 1 fixed the stage path; RED if
  the new wrapper regresses it.
- `test_fail_next_commits_fails_the_reserve_not_a_later_call` — arm the inject, call `reserve_*`,
  assert it returns the commit-failure variant and **no row exists**.
- `test_scoped_reserve_pins_client_cn_and_gvr` — a wrong GVR is rejected; the committed row carries
  the scoped CN.
- **KAT note (A-5.10):** none named `*_root`.

**Acceptance criteria**
- [x] `PubkeyScopedDb::{reserve_block, reserve_attestation, reconcile_unsigned}` exist and delegate.
- [x] **G-7 green** over the new wrappers; a DB-reading subscriber completes a full reserve → sign
      cycle within the test timeout.
- [x] The `scoped.rs:70-74` ordering note is **replaced** for the reserve path with an accurate
      one, not amended.
- [x] `fail_next_commits` fails the reserve; `commit_failed_path.rs` and `lib.rs:1562`/`:1619`
      still express a real path (they may be re-pointed in `ARCH-5l`, not here).
- [x] Existing `scoped.rs` tests (`:249`, `:272`) pass **unchanged**.

---

### ARCH-5h — Proof surface 3: concurrency proptest over interleaved reservations

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Stream:** A · **Scope:** 1.5–3 days
- **Blocked by:** ARCH-5f, ARCH-5g · **Blocks:** ARCH-5l *(switchover gate)*
- **Requirements:** **ARCH-P1-5** · exit criterion **X2**
- **Constraints:** **C1**, C9 anchor 2

**Context.** The EIP-3076 conformance vectors are **necessary and insufficient** (VD-S3): they are
single-threaded rule-engine fixtures that pass identically before and after the reorder. What the
reorder actually risks is an *interleaving* — two reservations for the same pubkey racing across
the newly-opened window between COMMIT and the sign. Under the old design that window did not
exist (the mutex spanned it); under the new one it does, and the per-pubkey `ValidatorLockMap`
lock is only a performance/TOCTOU device. `crates/signer/src/core.rs:500-504` is explicit about
where authority lives: *"The authoritative double-sign serializer is the SQLite `BEGIN IMMEDIATE`
lock held by the staged guard."* **That sentence becomes false when the guard stops spanning the
sign, and this issue is what re-establishes the property at the DB layer instead.**

**VD-5.7 hazard, recorded here so a later `stage_*` deletion does not walk into it:**
`crates/slashing/tests/conformance.rs:17-19` documents that the `minimal_conservative` runner
raises a watermark **after a successful stage commit**. It reaches the staging API through exactly
two shared helpers — `stage_and_commit_block` (`crates/slashing/tests/common/mod.rs:17-24`) and
`stage_and_commit_attestation` (`:32-40`) — so `conformance.rs` itself holds **zero** `stage_*`
call sites and the future migration is **two helper edits**. Because A-5.2 keeps `stage_*`, both
files are untouched this phase. If `stage_*` is ever deleted, those two helpers must be re-pointed
at `reserve_*` **and** taught that a reconciled reservation must not leave a raised watermark
behind.

**Files to touch**
- `crates/slashing/tests/reserve_concurrency.rs` *(new)*.
- `crates/slashing/Cargo.toml` — `proptest` as a **dev-dependency only**.
- `crates/slashing/tests/conformance.rs` — **not touched** (assert this in the PR:
  `git diff --stat` shows no change to it).

**Implementation approach**
1. Model: a sequence of operations over K pubkeys × N slots/epochs, each op being
   `Reserve(pubkey, kind)` or `Reconcile(handle)`, executed from T threads against **one**
   `SlashingDb`.
2. **The invariant, stated as a property, not a scenario:** for every pubkey, the set of committed
   history rows at the end is a valid EIP-3076 history — no two distinct signing roots for the same
   `(pubkey, slot)`; no surrounding/surrounded attestation pair — **regardless of interleaving**.
   Reuse the production rule engine (`crates/slashing/src/rules.rs`) as the oracle so the property
   cannot drift from the checker.
3. A second property: **reconcile never widens the accepted set.** After any interleaving, replaying
   the same op sequence *without* reconciles must accept a **subset** of what the reconciled run
   accepts — i.e. reconcile only ever restores liveness, never permits a sign the strict run
   refused.
4. Bound it: 64 cases, 8 threads, `proptest` shrinking on. Runtime must stay under ~30 s so it can
   live in the normal `nextest` run rather than behind `#[ignore]` — a switchover gate that CI does
   not execute is not a gate.
5. Deterministic seed recorded in the file header, plus a `PROPTEST_CASES` override documented.

**TDD test plan**
- **RED first:** `prop_interleaved_reservations_preserve_eip3076_history` run against a
  **deliberately broken** reserve (one that skips the rule check inside the transaction, on a
  scratch branch) must **fail and shrink to a two-op counterexample**. Paste that shrunk
  counterexample into the PR. A proptest that has never been seen to fail is not evidence.
- `prop_reconcile_never_widens_the_accepted_set`.
- `test_two_threads_reserving_the_same_slot_produce_exactly_one_row` — the deterministic
  companion, so a proptest flake is distinguishable from a real regression.
- **KAT note (A-5.10):** none named `*_root`.

**Acceptance criteria**
- [x] Both properties are implemented against the production rule engine as oracle.
- [x] The RED demonstration — a shrunk counterexample from a deliberately broken reserve — is
      pasted into the PR (ADR-012 "demonstrated, not asserted").
- [x] Runs inside `cargo nextest run --workspace` in under ~30 s; not `#[ignore]`d.
- [x] `crates/slashing/tests/conformance.rs` is **unchanged**, and VD-5.7's hazard is recorded in
      the new file's header for whoever deletes `stage_*`.
- [x] `proptest` is a dev-dependency only; no production dependency is added.

---

### ARCH-5i — `SlashableSignSession::reserve_then_sign` (additive, no production caller)

- **Points:** 2 · **Type:** feature · **Priority:** P0 · **Stream:** B · **Scope:** 1–2 days
- **Blocked by:** ARCH-5b *(E2)*, ARCH-5d, ARCH-5g · **Blocks:** ARCH-5j, ARCH-5k
- **Requirements:** **ARCH-P1-5** · exit criterion **X2**
- **Constraints:** **C1 (binding)**, C9 anchors 2 and 7

**Context — this issue is what makes "three proof surfaces green *before* the switchover"
mechanically possible** instead of a slogan. The matrix (`ARCH-5j`) and the crash injection
(`ARCH-5k`) must exercise the *new* semantics, but the switchover must not merge before they are
green. The resolution is an **additive sibling method** on `SlashableSignSession`, exercised only
by tests, with production still on `stage_then_sign`. `ARCH-5l` then flips one call site against
already-green proofs — never a knowingly-failing merge (project-plan `:93-96`).

**VD-5.4 is the trap this issue must avoid.** `core.rs:124-150` already declares
`pub trait StagedRow { fn commit_row(self) -> Result<(), SlashingError>; fn discard_row(self); }`
and `stage_then_sign<S: StagedRow, F>` is generic over it (`:260-344`). The tempting migration is
"impl `StagedRow` for a reservation wrapper: `commit_row` = no-op, `discard_row` = reconcile."
**Reject it:** `discard_row(self)` returns `()`, so a failed compensating delete would have **no
error surface** — exactly the signal A-5.5 requires to be metered. `reserve_then_sign` is a
sibling method with its own control flow, not a new `StagedRow` impl.

**Files to touch**
- `crates/signer/src/core.rs` — `SlashableSignSession::reserve_then_sign`; classification of the
  reserve-time commit-failure variant introduced by `ARCH-5e`.
- `crates/signer/src/error.rs` — doc table at `:77-80` gains the new-design column (docs only;
  variants unchanged).

**Implementation approach**
1. Shape, mirroring `stage_then_sign` (`:260-344`) so the diff is reviewable side by side:
   ```rust
   pub fn reserve_then_sign<F>(mut self, reserve: F) -> Result<Vec<u8>, SigningGateError>
   where F: FnOnce() -> Result<CommittedReservation, SlashingError>;
   ```
2. **Ordering, exactly:** `reserve()` → hooks (`on_stage_safe`/`on_stage_blocked`) → **SEC-1
   policy re-resolution** → `handle.block_on(timeout(sign))` → dispatch on §5.3's table.
3. **The SEC-1 subtlety that must be argued, not assumed.** Today the re-resolution at `:280-282`
   happens while the row is still **uncommitted**; after the change it happens while the row is
   already **committed**. A `Discard → Retain` upgrade in that window therefore means "retain a row
   that already exists" — i.e. simply **do not reconcile**. That is still the fail-closed
   direction, but the argument belongs in the code comment and in a test (`ARCH-5j`), not in a
   reviewer's head. The `fail_closed_max` merge itself is unchanged.
4. **Dispatch (§5.3, all 14 cells):**
   - sign succeeded → nothing to do; the row is already committed.
   - `commit_row()`-equivalent failure → **cannot occur here**; a reserve failure is returned
     *before* any sign is attempted, and must map to `CommitFailed` (not `SlashingBlocked`) when
     the underlying `SlashingError` is the reserve-time commit-failure variant. This is the
     classification `ARCH-5e` step 5 exists to enable.
   - timeout → `Discard`: `reconcile_unsigned`; `Retain`: **no action**, return
     `SigningFailed("signer timed out")` with history retained.
   - ambiguous (`Ok(Err(e))`, not `e.is_unambiguous_no_signature()`) → same split.
   - unambiguous-no-signature (`e.is_unambiguous_no_signature()` — **on `crypto::SigningError`,
     not `SignerError`; VD-5.3**) → `reconcile_unsigned` under **both** policies; a `Failed`
     outcome is logged at `error!` and the call still returns its original error (fail-safe).
   - blocking-task panic → the row stays committed and the sign is never released. Same as today.
5. **`on_tx_hold_ms` observation** follows `ARCH-5b`'s decision: the existing series keeps its
   window (so `tx_hold_metric.rs` is untouched); the new reserve-only series is observed at reserve
   return.
6. `stage_then_sign` stays. No production caller changes. `spawn_blocking` stays (**C9 anchor 7**).

**TDD test plan**
- **RED first:** `test_reserve_then_sign_commits_before_the_sign_is_attempted` — a signer backend
  that, when invoked, **queries the DB from another thread** and asserts the row is already
  present. It cannot pass under `stage_then_sign` (the row does not exist yet and the mutex is
  held), so it is RED against the pre-change semantics and green against the new method. The
  sharpest single-test statement of what ADR-005 changes.
- `test_reserve_failure_returns_commit_failed_not_slashing_blocked` — pins the classification.
- `test_policy_upgrade_between_reserve_and_sign_retains_the_row` — SEC-1 (`ResolveUnderLock`
  flipping `Discard → Retain`), asserting **no** reconcile call is made.
- **KAT note (A-5.10):** none named `*_root`.

**Acceptance criteria**
- [x] `reserve_then_sign` exists and is exercised **only** by tests; `rg 'reserve_then_sign'
      crates/signer/src` shows the declaration and no production caller.
- [x] It is **not** implemented as a `StagedRow` impl (VD-5.4); the compensation outcome is
      observable.
- [x] `is_unambiguous_no_signature` is called on `crypto::SigningError` (VD-5.3), and the code
      comment says so.
- [x] SEC-1's double resolution is preserved around the **reserve** point, with the
      already-committed-row argument written in a comment.
- [x] `stage_then_sign` and all four `finish_*` helpers are unchanged;
      `phantom_row_m1.rs`/`commit_failed_path.rs`/`tx_hold_metric.rs` green with zero edits.
- [x] `spawn_blocking` still wraps the sequence (X9).

---

### ARCH-5j — Proof surface 1: the 14-cell error-class × policy matrix

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Stream:** B · **Scope:** 1.5–3 days
- **Blocked by:** ARCH-5i · **Blocks:** ARCH-5l *(switchover gate)*
- **Requirements:** **ARCH-P1-5** · exit criteria **X1**, **X2**
- **Constraints:** **C1 (binding — this issue *is* C1's proof)**

**Context.** Architecture §5.3's table *"**is** the C1 safety property"* (`:1252`), assembled from
`crates/signer/src/core.rs:290-343`, `:346-376`, `:379-409`, `:412-450` — all four ranges verified
at HEAD. This issue asserts it **cell by cell**, which is the only exit criterion that can catch
R1 (retain-on-ambiguity broken subtly, green tests). Per A-5.1, the table governs over ADR-005's
narrower "scoped to `RetainStagedRow`" sentence.

**The matrix to reproduce (7 outcome classes × 2 policies = 14 cells):**

| Outcome | `DiscardStagedRow` | `RetainStagedRow` |
|---|---|---|
| Rule violation / SQL error at reserve | error before any row | same |
| Sign **succeeded** | row already committed | row already committed |
| Sign **timed out** | `reconcile_unsigned` | **no action — row retained (identical to today)** |
| **Ambiguous** signer error | `reconcile_unsigned` | **no action — row retained (identical to today)** |
| **Unambiguous no-signature** | `reconcile_unsigned` | `reconcile_unsigned` — **stricter than today: a failed delete retains** |
| Reserve-time commit failure | `CommitFailed`, **no sign attempted** | same |
| Blocking task panics | row committed, sign never released | same |

**Files to touch**
- `crates/signer/tests/retain_on_ambiguity_matrix.rs` *(new)*.
- `crates/signer/tests/common/` — extend with backends that produce each error class on demand.

**Implementation approach**
1. **Table-driven, one `#[test]` per cell** — not one test with 14 assertions. A single failing
   cell must name itself in the failure output; that is what makes the criterion "reproduces cell
   by cell" checkable in a CI log.
2. Backends: `SucceedingSigner`, `HangingSigner` (exceeds `sign_timeout`),
   `AmbiguousErrorSigner` (a transport/remote error class), `KeyNotFoundSigner`,
   `LocalRejectedSigner`, `UnsupportedSigningTypeSigner`, `PanickingSigner`. The last three are the
   `is_unambiguous_no_signature` set — **verify the classification against
   `crypto::SigningError`'s own method (VD-5.3)** rather than re-listing variants in the test, or
   the test and the production classifier can drift apart.
3. Each cell asserts **three** things, always: (a) the returned `SigningGateError` variant,
   (b) the **DB state** (row present / absent, and its signing root), (c) the
   `rvc_slashing_reconcile_total` label that was incremented. Asserting only (a) is how a
   retain-on-ambiguity break ships green.
4. Add the **"today" half** as a second table run against `stage_then_sign`, so the file proves the
   two designs agree on the cells that must be identical and differ **only** where §5.3 says they
   differ. That comparison is the actual C1 argument.

**TDD test plan**
- **RED first:** `test_retain_matrix_ambiguous_error_retain_policy_keeps_the_row` — written against
  `reserve_then_sign` before its dispatch is complete, it fails because the naive implementation
  reconciles on every non-success class. It is the cell that, if wrong, produces *a signature on
  the wire with no slashing record* — the phase's stated worst outcome. Write it first, by name.
- Then the remaining 13 cells.
- Then the "today" comparison run.
- **KAT note (A-5.10):** these tests sign real attestations and blocks and therefore compute
  signing roots. **No test name here may end in `_root`** or it enters `kat_policy.rs`'s scanner for
  no benefit; name them for the *outcome class*, not the artefact. `EXEMPTIONS` gains nothing.

**Acceptance criteria**
- [x] All 14 cells asserted, one `#[test]` per cell, each named for its (class, policy) pair.
- [x] Every cell asserts error variant **and** DB state **and** reconcile-metric label.
- [x] A parallel "today" run over `stage_then_sign` shows agreement everywhere §5.3 says
      "identical" and difference only where it says "stricter".
- [x] The unambiguous class under `Retain` is demonstrably **stricter**: with reconcile forced to
      fail, the row **remains**.
- [x] No test name matches `.*_root$`; `kat_policy.rs` green with an unchanged `EXEMPTIONS`.
- [x] Runs in the normal `nextest` workspace run.

---

### ARCH-5k — Proof surface 2: crash / cancellation injection at every await point

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Stream:** B · **Scope:** 1.5–3 days
- **Blocked by:** ARCH-5i · **Blocks:** ARCH-5l *(switchover gate)*
- **Requirements:** **ARCH-P1-5** · exit criterion **X2**
- **Constraints:** **C1**, **C9 anchor 2** (the cancellation-proof core is *the* anchor this issue
  guards), C9 anchor 7

**Context.** The old design's crash-safety argument was structural: the guard's `Drop` issued
`ROLLBACK` (`crates/slashing/src/stage.rs:30`), so **any** unwind left the DB pristine. The new
design has no such guard — the row is committed and the compensation is an explicit call that a
panic or a dropped future can skip. **The safety claim therefore moves from "the type system does
it" to "every abandonment leaves a retained row", and that claim needs a test at every point where
abandonment is possible.**

The abandonment points, enumerated from HEAD:
1. `req.locks.lock(&pubkey_bytes).await` (`core.rs:505`) — caller drops before the blocking task
   starts. The cancellation note at `:501-504` says the guard is released while the blocking task
   keeps running.
2. `spawn_blocking(...).await` (`core.rs:542`) — caller drops the future mid-sign. `spawn_blocking`
   is **not** cancelled by the drop; this is exactly why C9 anchor 7 keeps it (X9).
3. `handle.block_on(timeout(sign))` (`core.rs:284-287`) — the sign panics on the blocking thread.
4. Process kill between COMMIT and the compensation call — the case with no in-process analogue.

**Files to touch**
- `crates/signer/tests/reserve_cancellation.rs` *(new)*.
- `crates/signer/tests/common/` — a re-openable DB fixture (temp path, reopened after "crash").

**Implementation approach**
1. Points 1–3 are in-process: drop the future with `tokio::time::timeout` / an explicit `drop`, or
   panic inside the backend, then **reopen the DB** and assert state.
2. Point 4 is simulated by **abandoning the reservation without calling reconcile** and reopening
   the DB from the same path — a durable-state assertion, not a process fork.
3. **The single invariant every case asserts:** *after any abandonment, the reserved row is
   present and a conflicting sign is refused.* Never "the DB is pristine" — that is the old
   design's invariant and asserting it here would be wrong.
4. A companion assertion for the fail-safe direction: after abandonment, an **identical re-sign**
   (same signing root) is still permitted — the EIP-3076 `Resign` path — so the fail-safe posture
   does not brick the validator for the duty it was actually performing.
5. Reuse the existing `spawn_blocking`-crossing proof idiom: `core.rs:930` already wraps
   `sign_slashable` in a bare `tokio::spawn` inside a green unit test — compile-checked proof the
   future is `Send`. Keep an equivalent for `reserve_then_sign`.

**TDD test plan**
- **RED first:** `test_dropped_future_mid_sign_leaves_the_reserved_row_present` — drop the caller's
  future while the backend sleeps, reopen the DB, assert the row **exists** and a conflicting slot
  is refused. Against the pre-change design this fails (the guard's `Drop` rolls back, so the row
  is absent) — a clean RED that documents the intended semantic change rather than hiding it.
- `test_panic_in_the_sign_backend_leaves_the_reserved_row_present`.
- `test_cancellation_before_the_blocking_task_starts_leaves_no_row` — the one case where **no** row
  should exist, because the reserve never ran. Distinguishes "abandoned after commit" from
  "abandoned before commit".
- `test_abandoned_reservation_still_permits_an_identical_resign`.
- `test_reserve_then_sign_future_is_send` — compile-time, mirroring `core.rs:930`.
- **KAT note (A-5.10):** none named `*_root`.

**Acceptance criteria**
- [x] All four abandonment points have a test; each reopens the DB and asserts durable state.
- [x] The invariant asserted is **"the row is retained and a conflicting sign is refused"**, never
      "the DB is pristine".
- [x] An identical re-sign after abandonment is still permitted (fail-safe without bricking).
- [x] Cancellation *before* the reserve leaves no row — the two cases are distinguished.
- [x] `spawn_blocking` is still what makes the sequence uncancellable (X9); no test asserts a
      behaviour that would only hold without it.
- [x] The RED for the first test is reproduced locally against the pre-change tree and pasted into
      the PR (ADR-012).

---

### ARCH-5l — Switchover: flip the production call site, retire `stage_then_sign`, gate `stage_*`

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Stream:** B · **Scope:** 1.5–3 days
- **Blocked by:** ARCH-5h, ARCH-5j, ARCH-5k *(all three proof surfaces)* · **Blocks:** ARCH-5m,
  ARCH-5o
- **Requirements:** **ARCH-P1-5** (closes it) · exit criteria **X1, X2, X4, X5, X9**
- **Constraints:** **C1 (binding)**, C9 anchors 2/5/7, **C10** (orphan-tree path exclusion)

**Context.** Everything before this issue was additive. This is the one commit that changes what
production does. It is small **by design**: `ARCH-5d` collapsed four staging consumers to one, so
the flip is a single call site. If this issue's diff touches more than one `stage_then_sign` call,
`ARCH-5d` did not land correctly and this issue stops.

**Scope correction, taken here rather than discovered.** An earlier framing had this issue *delete*
`stage_then_sign` and the `StagedRow` trait. It does not. `rg -n 'stage_then_sign'
crates/signer/src` shows **6 exercising unit tests inside `core.rs`'s own `#[cfg(test)] mod tests`**
(`:677`, `:756`, `:799`, `:852`, `:898`, `:946`) that would all need migrating — unbudgeted work
inside the phase's single highest-risk PR, and work whose failure mode is "the switchover PR grew
and nobody reviewed the interesting part". **This issue flips the production caller and proves that
no production caller remains.** Retiring the old staging API — `stage_*` + `stage_then_sign` +
`StagedRow` together — is one deferred follow-up project, symmetric with A-5.2 (§5).

**Files to touch**
- `crates/signer/src/core.rs` — the single production staging consumer calls `reserve_then_sign`.
  `stage_then_sign` and `StagedRow` (`:124-150`) **remain**, exercised only by the 6 in-file unit
  tests, and gain `#[deprecated(note = "superseded by reserve_then_sign (ADR-005); retained only
  for the pre/post comparison tests")]` so the retirement is visible in every build.
- `crates/signer/src/lib.rs`, `crates/signer/src/gate.rs` — no behavioural change expected; verify.
- `crates/architecture-tests/tests/stage_api_scope.rs` *(new)* — the production-caller scanner.
- `crates/signer/tests/commit_failed_path.rs` — re-point to the reserve-time failure if `ARCH-5g`
  left it expressing the old shape.
- `crates/metrics/src/definitions.rs` — the reserve-only tx-hold series from `ARCH-5b`'s decision,
  if `ARCH-5f` has not already added the file's Phase-5 block (see §6.1's ordering note).

**Implementation approach**
1. Flip the single production call site. Mark the old path deprecated; **do not delete it** (scope
   correction above). What stops the two designs coexisting *in production* is step 2's scanner,
   not deletion.
2. **The `stage_*` bypass scanner (X5).** Two staging APIs now exist in `crates/slashing`
   (A-5.2 retained `stage_*` because **63** counted test call sites make deletion a separate
   project). What makes that safe is a gate, not a convention — the repo's own Design Principle 2.
   New file in the existing `architecture-tests` idiom (hand-rolled scan, non-vacuity assertion,
   failure message naming the path):
   - **Assert:** no file under `crates/*/src/` or `bin/*/src/` **outside `crates/slashing/src/`**
     contains `stage_block(` or `stage_attestation(`.
   - **Path-scoped exclusions, deliberate:** `crates/slashing/src/**` (the owner, 2 wrappers at
     `scoped.rs:62`/`:88`), `**/tests/**` and `#[cfg(test)]` bodies (63 call sites, A-5.2), and
     — **C10** — the untracked orphan trees
     `crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`,
     `crates/rvc/src/commands/`. A `stage_block` grep hits `crates/rvc-signer/src/service.rs` and
     `crates/rvc-signer/src/dvt/peer_service.rs` today; those are **orphans Phase 0 deletes**, and
     the scanner must not depend on Phase 0 having landed, nor may this phase cite, edit or migrate
     them.
   - **Non-vacuity:** assert the scan visits > 0 files and that a synthetic in-memory input
     containing `scoped.stage_block(` is reported. A scanner green on an empty file list is
     unfalsifiable (the same trap G-5b carries in Phase 6).
   - Runs in the `arch-gates` CI job Phase 0 adds (A-P1 / VD-P7), not in `coverage`.
3. Re-verify the single unbypassable wiring site (`crates/rvc/src/config/builder.rs:394`) and the
   `CompositeSigner` grep gate are untouched — **C9 anchor 5**. `reserve_*` is a DB call and adds
   no signing surface.
4. Update the `SigningGateError::SigningFailed` doc table (`crates/signer/src/error.rs:77-80`) to
   the new design. It is the operator-facing statement of what "SigningFailed" implies about
   history; leaving it stale is the same class of defect ADR-006 rejected at `scoped.rs:70-74`.

**TDD test plan**
- **RED first:** `test_no_production_caller_uses_stage_block_outside_slashing` in
  `crates/architecture-tests/tests/stage_api_scope.rs`. **Demonstrate RED locally** against the
  pre-flip tree (where `core.rs`'s consumer still calls `scoped.stage_block`) and paste the output
  into the PR — never merge a knowingly-failing test (ADR-012, project-plan `:93-96`).
- `test_stage_api_scanner_reports_a_synthetic_violation` — non-vacuity.
- `test_no_production_caller_uses_stage_then_sign` — `rg -n 'session\.stage_then_sign'` finds hits
  **only** inside `core.rs`'s `#[cfg(test)]` block. Scoped this way deliberately: a bare
  `rg -c 'stage_then_sign' crates/signer/src` would return 7 after this PR and assert nothing.
- **The three proof surfaces must be green on this PR's HEAD before merge** — `ARCH-5h`,
  `ARCH-5j`, `ARCH-5k`. State it in the PR checklist, not just in this document.
- `phantom_row_m1.rs` green (**X4**) — and the PR quotes its header, because a reviewer who has not
  read M-1 cannot review this change.
- **KAT note (A-5.10):** no new test named `*_root`.

**Acceptance criteria**
- [x] Exactly **one** production call site changed; `stage_then_sign` / `StagedRow` **retained and
      `#[deprecated]`**, with no production caller (asserted). Their deletion — together with
      `stage_*` and the 6 `core.rs` unit tests that exercise them — is filed as a follow-up.
- [x] `crates/signer/tests/phantom_row_m1.rs` green, **unchanged**, and quoted in the PR (X4).
- [x] The three proof surfaces are green on this commit (X2); the PR links their runs.
- [x] EIP-3076 conformance vectors green, and the PR records them as *necessary and insufficient*
      (X3).
- [x] `stage_api_scope.rs` lands, is RED-demonstrated locally, has a non-vacuity assertion,
      excludes the orphan trees (**C10**), and runs in the `arch-gates` job.
- [x] Single wiring site + `CompositeSigner` grep gate green (**C9 anchor 5**, X5).
- [x] `spawn_blocking` retained at `core.rs:542` (**C9 anchor 7**, X9).
- [x] `SigningGateError::SigningFailed`'s doc table reflects the new design.
- [x] This PR is **independently revertible** (NFR-4): reverting it restores `stage_then_sign` and
      leaves `reserve_*` unused but present.

---

### ARCH-5m — M3 post-change run, rollback plan, honest VC-path ceiling record

- **Points:** 2 · **Type:** chore · **Priority:** P0 · **Stream:** B · **Scope:** 1–2 days
- **Blocked by:** ARCH-5l · **Blocks:** none
- **Requirements:** **ARCH-P1-15a** (closes it) · **M3** · exit criteria **X6, X7, X8**
- **Constraints:** C9 anchor 2 (the rollback argument)

**Context.** The phase's milestone is not "the code changed" — it is *"M3 recorded before and
after; hold-duration p99 within the per-sign budget on the `signer-server` profile"*
(project-plan `:290`). This issue closes the measurement loop `ARCH-5a`/`ARCH-5b` opened, and it
is where the phase's **honest scope limit** is written down rather than buried.

**Files to touch**
- `plan/architecture-2026-08-12/measurements/m3-post-adr005.md` *(new)*.
- `plan/architecture-2026-08-12/measurements/README.md` — index the second file.
- No source file.

**Implementation approach**
1. Re-run `ARCH-5a`'s profile, same parameters, three runs + median. Report p50/p95/p99/max under
   **both** metric definitions (VD-5.2 / `ARCH-5b`) side by side with the baseline, and cite the
   baseline file's commit hash.
2. **Judge X6 against the derived budget, not against "it got faster."** If p99 is still above
   budget, the finding is the deliverable and it names the next wall: fsync
   (`synchronous=EXTRA` + `fullfsync=ON`, `crates/slashing/src/db/open.rs:240-246`) makes 200
   serialized durable writes per window. Group commit then moves from "admissible if measured"
   (A-5.9 / A-A9) to a **new requirement** — recorded, not absorbed into this phase.
3. Report the observed **reconcile failure count** from `rvc_slashing_reconcile_total{outcome="failed"}`
   (A-5.5). Non-zero under load is a finding, not noise.
4. **Rollback plan (X7).** Write, do not gesture at: reverting `ARCH-5l` is safe *in the slashing
   direction* because the old design retains strictly **less**, never more — so no signature can
   become unrecorded by rolling back. But the revert **must re-run all three proof surfaces**, not
   only the EIP-3076 vectors, because the vectors pass identically under both designs (VD-S3).
   Name the revert commit shape (single PR, NFR-4) and the DB-compatibility statement: the schema
   is unchanged, so no data migration is involved in either direction.
5. **The honest scope limit (X8), stated in the document and in the phase's release note:**
   *ARCH-P1-5 alone does not deliver G6 on the VC path.* Re-verified at HEAD:
   `crates/rvc/src/orchestrator/attestation.rs:171-192` is a sequential
   `for duty in duties { self.process_attestation_duty(duty).await; }` with no `join_all`,
   `FuturesUnordered` or `spawn` anywhere under `crates/rvc/src/orchestrator/`. 200 keys × 200 ms
   = **40 s — ten slots — with a completely free DB.** File **VC-path attestation concurrency as a
   separate, unscheduled requirement.** Claiming G6 here would be false.

**TDD test plan**
- Measurement + documentation; its RED is the absence of the post-change file, and `ARCH-5l`'s
  PR checklist blocks the phase from being declared complete without it.
- One mechanical check: the post-change document must cite the baseline document's commit hash, so
  the two numbers cannot be from different trees.

**Acceptance criteria**
- [x] `m3-post-adr005.md` records three runs + median under **both** metric definitions, alongside
      the baseline, citing its commit hash (X6).
- [x] X6 is judged against the derived per-sign budget with the arithmetic shown; if unmet, fsync
      is named as the next wall and group commit is filed as a new requirement.
- [x] Reconcile failure count under load is reported.
- [x] The rollback plan is written, including *"re-run all three proof surfaces, not just the
      vectors"* and the no-migration statement (X7).
- [x] **VC-path attestation concurrency is filed as a separate, unscheduled requirement**, with
      the 40 s arithmetic and the `attestation.rs:171-192` citation. G6 is **not** claimed (X8).

---

### ARCH-5n — `ValidatorLockMap` eviction with a bounded map

- **Points:** 2 · **Type:** chore · **Priority:** P2 · **Stream:** A *(slack — sole owner of
  `crates/signer/src/locks.rs`)* · **Scope:** 1–2 days
- **Blocked by:** none · **Blocks:** none
- **Requirements:** **ARCH-P2-1** (`prd.md:953`)
- **Constraints:** **C4** (as a *bound*: must not hook the key-admission path — see below)

**Context — reproduces at HEAD, and is smaller than the requirement's phrasing implies (VD-5.6).**
`crates/signer/src/locks.rs` is **56 lines**: one field
`locks: parking_lot::Mutex<HashMap<[u8; 48], Arc<tokio::sync::Mutex<()>>>>` (`:22`), `get`
(`:33-39`), `lock` (`:46-48`), `Default` (`:51-55`). There is **no** `remove`, no bound, no
eviction. Every pubkey ever signed for leaves a permanent entry — unbounded growth across key
churn.

**The requirement says "on key removal / by LRU bound". Take the bound, not the hook** — and the
reason is a constraint, not a preference: hooking key removal would couple this issue to Phase 1's
`KeyAdmissionService` (**C4**) and to the keymanager adapters, making two phases jointly
revertible and violating NFR-4. A size bound lives **entirely inside `locks.rs`**, needs no caller
change, and keeps this issue at 2 points and this file single-owner.

**Files to touch**
- `crates/signer/src/locks.rs` — the whole issue.
- `crates/signer/tests/validator_lock_map.rs` *(new)*.

**Implementation approach**
1. Add a capacity (default generous — e.g. 4× the supported key count, documented as a rationale,
   not a magic number) and an opportunistic sweep on insert when `len() > capacity`.
2. **"No lock evicted while held" is directly observable and must be enforced, not hoped for:** an
   entry is held iff `Arc::strong_count(&entry) > 1` (the map holds one). Sweep only entries with
   `strong_count == 1`. This is why the bound is safe without any coordination with callers.
3. Sweep under the existing short-held `parking_lot` map lock. **Never `.await` inside it** — the
   map lock's whole design property (`locks.rs:14-17`) is that it is released before the async
   lock is acquired.
4. If the sweep cannot free anything (all entries held), grow rather than block. Log once at
   `warn!` with the count; never stall a sign to enforce a hygiene bound.
5. No public signature changes: `get` and `lock` keep their shapes so `core.rs:505`, `gate.rs` and
   `lib.rs` are untouched.

**TDD test plan**
- **RED first:** `test_lock_map_size_is_bounded_under_key_churn` — churn N ≫ capacity distinct
  pubkeys through `lock()`, each guard dropped, then assert `len() <= capacity`. Fails at HEAD
  (the map grows monotonically); this is the whole requirement in one assertion.
- `test_no_held_lock_is_evicted` — hold a guard for pubkey P, churn past capacity, then assert the
  **same** `Arc` is still returned for P (`Arc::ptr_eq`). Returning a *different* mutex for a held
  pubkey would silently destroy the per-validator serialization — the one way this issue can cause
  a slashing-adjacent bug.
- `test_sweep_never_blocks_when_every_entry_is_held`.
- **KAT note (A-5.10):** none named `*_root`.

**Acceptance criteria**
- [x] The map is bounded under churn, asserted by a test.
- [x] No held lock is ever evicted — asserted via `Arc::ptr_eq`, not via timing.
- [x] No `.await` inside the map lock; no public signature change; no caller edited.
- [x] The capacity default carries a written rationale.
- [x] **No hook into key admission or removal** (C4 / NFR-4): `git diff --stat` touches only
      `crates/signer/src/locks.rs` and the new test file.

---

### ARCH-5o — Type the internal slashing records (ARCH-P2-2, rescoped by VD-5.5)

- **Points:** 2 · **Type:** chore · **Priority:** P2 · **Stream:** A · **Scope:** 1–2 days
- **Blocked by:** ARCH-5l *(project-plan `:598`: "After 5C, **never concurrent with it**")* ·
  **Blocks:** none
- **Requirements:** **ARCH-P2-2** (`prd.md:954`) — **acceptance criterion rescoped, see below**
- **Constraints:** C9 anchor 3 (KAT-first, by not tripping it)

**Context — the requirement is marked `[review-carried, unverified at HEAD]`; it is now verified,
and its acceptance criterion is unsatisfiable as written (VD-5.5).** `crates/slashing/src/types.rs`
(404 lines) holds two categories:

- **Internal records — in scope.** `SignedAttestation` (`:16-21`) and `SignedBlock` (`:24-29`),
  both `pubkey: String` + `signing_root: Option<String>`. These are ours; they can be newtypes.
- **EIP-3076 interchange DTOs — out of scope by spec mandate.** `InterchangeFormat` (`:32-36`),
  `InterchangeMetadata` (`:39-43`), `ValidatorRecord` (`:47-51`), `InterchangeBlock` (`:55-60`),
  `InterchangeAttestation` (`:65-70`). Their `String` fields are the **wire format**, and the file
  says so in-source: *"Note: slot is serialized as string per EIP-3076 specification"* (`:53-54`,
  and again at `:62-63`). Removing `String` from these breaks import/export.

So the PRD's *"No `String` pubkey or root comparison remains in `slashing/src/types.rs`"* cannot be
met. **Rescoped criterion, carried forward:** newtypes on the two internal records; the
`Interchange*` DTOs stay `String` **by mandate**, with a module-level doc comment saying why, so
the next reader does not re-open this.

Also in scope, per **A-5.8**: `crates/slashing/src/db/mod.rs:53-55` —
`pubkey.parse::<observability::pubkey::CanonicalPubkey>().expect("infallible").to_string()` — an
`.expect` in production code, contrary to `CLAUDE.md`. The canonical type it parses into
(`observability::pubkey::CanonicalPubkey`) is **the newtype this issue should adopt** rather than
inventing a second one; the workspace already declares it the single source of truth for pubkey
normalisation (`db/mod.rs:50-52`).

**Files to touch**
- `crates/slashing/src/types.rs` — the two internal records.
- `crates/slashing/src/db/mod.rs` — `normalize_pubkey`, `.expect` removal.
- Conversion boundaries in `crates/slashing/src/db/{records.rs, interchange.rs}` — the DTO↔record
  edges, which is where the `String` boundary now lives explicitly.

**Implementation approach**
1. Adopt `observability::pubkey::CanonicalPubkey` for `pubkey`; introduce a root newtype for
   `signing_root` (or reuse `eth_types::Root` with a hex-boundary helper — decide in-issue, and
   record the decision).
2. `normalize_pubkey` returns `Result<CanonicalPubkey, SlashingError>`; the `.expect("infallible")`
   is deleted. If the parse genuinely cannot fail for the callers, the correct expression of that
   is a type that cannot be constructed wrongly — not an `.expect`.
3. Conversions live at the interchange boundary, so the DTO layer keeps its `String` fields and the
   internal layer keeps its types. Add the doc comment recording VD-5.5.
4. **Landing after `ARCH-5l` is not a preference** — typing `types.rs` mid-redesign would collide
   with both the A-12 `stage.rs` pin and the three proof surfaces.

**TDD test plan**
- **RED first:** `test_no_expect_in_slashing_production_code` — a source-text assertion that
  `crates/slashing/src/**` (excluding `#[cfg(test)]`) contains no `.expect(`. Fails today on
  `db/mod.rs:54`. Cheap, mechanical, and it is the `CLAUDE.md` rule made executable in this crate.
- `test_signed_block_rejects_a_malformed_pubkey_at_construction` — the newtype's point: the error
  moves from a runtime `.expect` to a construction-time `Result`.
- `test_interchange_dtos_still_serialize_strings` — the six existing round-trip tests in
  `types.rs:117-402` must pass **unchanged**; add one asserting `InterchangeBlock.slot` is still
  emitted as a JSON string. This is the guard against an over-eager typing pass breaking the wire
  format.
- Full EIP-3076 conformance suite green (`crates/slashing/tests/conformance.rs`, 38 official
  vectors) — the real acceptance gate.
- **KAT note (A-5.10):** none named `*_root`.

**Acceptance criteria**
- [x] `SignedAttestation` / `SignedBlock` carry canonical newtypes, not `String`.
- [x] `.expect("infallible")` is gone from `crates/slashing/src/db/mod.rs`; no new `.expect` in
      production code (`CLAUDE.md`), asserted by a test.
- [x] The `Interchange*` DTOs are **unchanged** and a module doc comment records **why**
      (EIP-3076 string mandate, VD-5.5) — so the PRD's literal criterion is closed with a stated
      correction rather than left failing.
- [x] All 38 EIP-3076 conformance vectors green.
- [x] The existing `types.rs` round-trip tests pass with **zero** edits.
- [x] Landed **after** `ARCH-5l`; `git log` shows no overlap with the switchover PR.

---

## 8. What this phase deliberately does **not** do

Recorded so a reader does not mistake omission for oversight.

- **Does not claim G6.** The VC-path ceiling is a sequential await loop, not the mutex (X8, A-5.4).
- **Does not delete `stage_*`, `stage_then_sign` or `StagedRow`** (A-5.2, §5) — 63 counted
  `stage_*` test call sites plus 6 `core.rs` unit tests on `stage_then_sign`; retiring the old
  staging API is one deferred follow-up project. Safety is bought by `ARCH-5l`'s production-caller
  scanner instead.
- **Does not touch `crates/slashing/tests/conformance.rs`** (VD-5.7) — the commit-ordered watermark
  hook is a trap for a later `stage_*` deletion, and is documented for that reader.
- **Does not adopt per-pubkey connections, sharding, WAL changes, Postgres, or day-one group
  commit** — each rejected with reason in §5.
- **Does not remove `spawn_blocking`** even though the `!Send` guard no longer requires it
  (C9 anchor 7, X9).
- **Does not delete, edit, cite or migrate the untracked orphan trees.** `crates/rvc-signer/`
  carries `stage_block` hits that would otherwise land in `ARCH-5l`'s scanner; they are excluded by
  path. Archiving and deleting them is Phase 0's **ARCH-P0-1** (archive → verify → delete, C10) and
  is out of scope here.
- **Does not touch `docs/prd.md`, `docs/architecture.md` or `docs/project-plan.md`** — they belong
  to the older Test Audit Remediation initiative (NG8).
