# Phase 0 — Ground Truth: archive, gate, measure, start the clock

> **Sprint-ready issue breakdown for Phase 0** of the rs-vc architecture-remediation initiative.
> Baseline **`develop` @ `0ae9a09` (v0.7.0)**, authored 2026-08-12.
>
> **Authoritative inputs, in precedence order:**
> [`../project-plan.md`](../project-plan.md) §7 *Phase 0* (scope, work packages 0A–0G, entry/exit
> gates) → [`../architecture.md`](../architecture.md) (**ADR-012**, gate **G-1** §6) →
> [`../prd.md`](../prd.md) (ARCH-P0-1, P0-2, P2-5, P2-6, P2-7, P2-9, P1-16a; metrics M1/M2/M6) →
> [`../research/`](../research/) → [`../../../docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md).
>
> **Every `file:line` below was re-verified against HEAD while writing this document** — none is
> copied forward on trust. Claims that did **not** reproduce, or that reproduced but are stated
> imprecisely upstream, are recorded as **verification deltas (VD-E1…VD-E8)** in §3 and are carried
> into the acceptance criteria of the issue that consumes them. Five of the nine change work:
> **VD-E3** (the docs-freshness scan cannot land green as specified), **VD-E4** (the `CliOverrides`
> acceptance criterion is false as written), **VD-E5** (the archive tarball lands inside the
> gitleaks scan path), **VD-E9** (`sync-service` appears in **two** tables in
> `architecture-tests/src/lib.rs`, not one), and **VD-E8** (Phase 0 is under-sized upstream —
> stated, not retrofitted).
>
> **No-ask constraint:** every open question is resolved to a stated default in *§2 Assumptions*.
> Nothing is escalated.
>
> **Scope:** planning only. This document changes no source file, deletes nothing, and executes none
> of the sequences it estimates — **deleting the orphan trees is ARCH-1b's work, not this
> document's**. `docs/prd.md`, `docs/architecture.md` and `docs/project-plan.md` belong to the older
> Test Audit Remediation initiative and are not touched (NG8); ARCH-6 below is explicitly designed
> around that prohibition rather than through it.

## Phase Overview

- **Goal.** Make the repository's contents honest and the recurrence mechanically impossible:
  archive-verify-delete ≈26,270 **unrecoverable** untracked lines (C10), land the two orphan
  detectors, delete the tracked `sync-service` shell, build the M1/M2 measurement instruments every
  behavioural phase is judged against, add an `arch-gates` CI job, and start the healthz deprecation
  clock — a release-count dependency no amount of effort shortens (C8).
- **Issue count:** **13 issues** (ARCH-1a … ARCH-9), **21 points**.
- **Estimated duration:** **1 developer: 13–19 working days.** **2 developers: 8–13 working days**
  (Stream A is the critical path at 13 pts; Stream B is 8 pts and fully disjoint). *This exceeds the
  project plan's 7–11 d estimate — see **VD-E8**, which states the gap rather than absorbing it.*
- **Point scale:** 1 / 2 / 3 (nothing above 3 in this phase; ~1 pt ≈ 0.5–1 working day, covering
  coding + tests + review + integration).
- **Milestone (M6 = 0).** No untracked `.rs` source under `crates/`/`bin/`; a verified archive ref
  with a recorded manifest hash; D1+D2 preventing recurrence with `members = 28 = directory count`
  (verified 31 → 29 → 28); M1/M2 baselines recorded as files in `plan/architecture-2026-08-12/`.

**Entry criteria.**

- [ ] Working tree at `develop` @ `0ae9a09`; all §2 standing-invariant commands green
      (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings`,
      `cargo build --workspace`, `cargo nextest run --workspace`).
- [ ] All four orphan paths still present — **they are the RED evidence** for ARCH-2a/2b and must not
      be removed by any hand outside ARCH-1b.
- [ ] Write access to `.github/workflows/ci.yml` and permission to push a non-PR branch
      (`archive/untracked-orphans-2026-08-12`); confirmed that pushing that branch does **not**
      trigger CI (`ci.yml:3-6` triggers only on `pull_request` to `main`/`develop`).
- [ ] No concurrent work in `crates/rvc/src/main.rs`, `crates/rvc/src/commands/`,
      `crates/rvc-signer/`, `crates/rvc-keygen/` (the orphan-tree invariant, project-plan §2).

**Exit criteria — the milestone, as a checklist.**

- [ ] Archive ref `archive/untracked-orphans-2026-08-12` exists **and** a tarball exists at the path
      recorded in ARCH-1a; a scripted restore-and-diff yields **zero** differences; the manifest
      hash is recorded in the issue body and in `plan/architecture-2026-08-12/archive/MANIFEST.md`.
- [ ] None of the four orphan paths exists in the working tree.
- [ ] `rg 'struct CliOverrides' crates bin` returns exactly **one** hit
      (`crates/rvc/src/config/types.rs:1313`), down from two — **path-scoped**, per **VD-E4**.
- [ ] `cargo build --workspace` and `cargo nextest run --workspace` are **unchanged** by the
      deletion; any change is itself the finding (architecture §7.2).
- [ ] D1 and D2 each fail against a scratch re-add and pass on `develop`; each names the offending
      path; neither failure message recommends "add it to `[workspace] members`" (**VD-P1**).
- [ ] **`{crates,bin}/*/Cargo.toml` = 28 directories = 28 `cargo metadata` members**, asserted as an
      exact equality (verified at HEAD: 31 → 29 after ARCH-1b → 28 after ARCH-3; VD-P8 reproduced).
- [ ] `ARCHITECTURE.md` regenerates **byte-identically** after ARCH-3 (C9 anchor 1).
- [ ] `arch-gates` CI job exists and runs `cargo nextest run -p rvc-architecture-tests` on every PR.
- [ ] `cargo machete` is a CI step and passes; `bin/rvc`'s unused workspace deps are removed.
- [ ] The docs-freshness scan is green with a **one-entry, shrinking-only** exemption list whose sole
      member is `docs/architecture.md`, carrying a written NG8 reason (**VD-E3**).
- [ ] **M1 and M2 baselines exist as files** at
      `plan/architecture-2026-08-12/measurements/m1-missed-proposals.md` and
      `.../m2-slot-phase0-offset.md`, each naming the harness commit, the injected latency profile
      and the raw sample set.
- [ ] The healthz deprecation `warn!` ships in the release closing this phase, naming `/livez` and
      `/readyz` concretely (**VD-E2**) — **no removal** (C8).
- [ ] **M6 = 0**, under the scoped definition in **VD-E6** (untracked `.rs` under `crates/`/`bin/`).

## Assumptions verified against HEAD

Per the no-ask constraint, every open question is resolved to a stated default. The PRD's A-1…A-15,
the architecture's A-A1…A-A11 and the plan's A-P1…A-P12 remain in force and are **not** repeated;
these are the ones this *estimate* creates or had to re-resolve, each with the HEAD evidence I
checked myself.

| # | Question this breakdown had to answer | Stated default | HEAD evidence (verified here) | Overturned by |
|---|---|---|---|---|
| **A-E1** | The task asks for two streams; project-plan §9 W0 says Phase 0 is **single-stream** ("0A/0B are one PR sequence and 0D is the same person's harness"). Which governs? | **Both, at issue granularity.** Streams are assigned per *issue*, not per work package. **ARCH-1a → 1b → 2a → 2b → 3 are locked to Stream A in that order** (one PR sequence; §9's objection survives intact). The genuinely disjoint work — the M1/M2 instruments, the healthz warn, the doc-comment tail — becomes Stream B. The 2-dev figure is stated separately and never blended | The A/B file sets are disjoint: Stream A never opens `crates/rvc/src/{orchestrator,bootstrap}/**`, `crates/metrics/`, `crates/rvc/tests/`, `crates/signer-registry/`; Stream B never opens root `Cargo.toml`, `crates/architecture-tests/**`, `.github/workflows/ci.yml`, `bin/rvc/Cargo.toml` | Single staffing, in which case run Stream A first and Stream B second; nothing in B blocks A |
| **A-E2** | Two Phase-0 issues edit `.github/workflows/ci.yml` (ARCH-4 `arch-gates`, ARCH-5 `cargo machete`). §9's regeneration protocol covers `ARCHITECTURE.md` only — **it does not cover `ci.yml`** | **Both are Stream A, and ARCH-4 lands before ARCH-5.** `ci.yml` is hand-maintained YAML with no generator, so there is no take-either-side-and-regenerate escape hatch. ARCH-5 appends its step to the `check` job; ARCH-4 adds a new top-level job — different regions, but the same file, so strict order rather than concurrency | `ci.yml` has exactly three jobs: `check:13`, `secret-scan:59`, `coverage:129`; the only workspace test execution is `cargo llvm-cov nextest --workspace` at `:166` | A maintainer merging both edits in one PR, which is also acceptable and strictly safer |
| **A-E3** | Where does `cargo machete` vs `cargo-udeps` land? The plan says "`cargo-machete`/`cargo-udeps`" | **`cargo machete` only.** `cargo-udeps` requires a nightly toolchain; `ci.yml:19-22` and `:79-80` pin `dtolnay/rust-toolchain@stable`, and `rust-version = "1.92"` is declared at root `Cargo.toml:15`. Adding a nightly toolchain to CI for one hygiene check is out of proportion to the finding | `ci.yml` installs **stable** in all three jobs; no nightly anywhere | A maintainer wanting `udeps`' deeper analysis, which then needs a second toolchain install and its own job |
| **A-E4** | What does D2 do about `#[path = "…"]` module declarations and `#[cfg(...)] mod`? | **Resolve `#[path]`; ignore `cfg` predicates.** A file is "compiled" if *some* ancestor module source declares it, regardless of whether the `cfg` is active under default features. Without `#[path]` resolution D2 has **exactly one** false positive at HEAD | `crates/crypto/src/remote_signer/client.rs:325` is the workspace's **only** `#[path = "client_tests.rs"]`; `rg '#\[path\|include!\(' '{crates,bin}/**/src/**/*.rs'` returns that one hit and nothing else | A second `#[path]` site appearing, which the same resolver already handles |
| **A-E5** | Does ARCH-1b also remove `autobins = false` from `crates/rvc/Cargo.toml:3`? | **No — leave line 3 unchanged.** Removing it enlarges the delete diff and changes build semantics in the same commit that removes 26k lines; leaving it is inert once `src/main.rs` is gone, and **D2 is precisely what makes leaving it safe** (a future `src/main.rs` under `autobins = false` is exactly the orphan D2 catches) | `crates/rvc/Cargo.toml:3` = `autobins = false`; `crates/rvc/src/lib.rs:3-15` declares 13 modules and **no `mod commands;`** and no bin target — so `main.rs` + `commands/` are genuinely uncompiled | A follow-up hygiene issue after D2 is green; it is not a Phase-0 dependency |
| **A-E6** | M2's instrument: new metric, or read the existing span? | **New histogram metric**, `rvc_slot_phase_block_start_offset_ms`, recorded at slot-loop entry to `maybe_propose_block`. The existing `slot.phase.block` span measures the phase's **duration**, not its **offset from slot start** — it cannot answer M2 | `info_span!(parent: &slot_span, "slot.phase.block")` at `coordinator/mod.rs:404`, wrapping `maybe_propose_block(...)` at `:405`; slot span `slot.process` opens at `:368` | A `timing`-crate deadline helper already exposing the offset, which would reduce ARCH-7a to wiring |
| **A-E7** | What exactly does "no untracked source" mean for M6 = 0? | **Untracked `.rs` files under `crates/**` and `bin/**`.** The tree legitimately carries untracked `.md` (`plan/`, `docs/prd.md`, `docs/project-plan.md`, `docs/issues/`, `AUDIT-*.md`) that Phase 0 neither owns nor may delete (NG8) | Working tree at baseline shows untracked `.md` trees outside `crates/`/`bin/` that survive Phase 0 by design | A repo-wide untracked-file policy, which is a different initiative |
| **A-E8** | Where do the M1/M2 baseline numbers live? | **`plan/architecture-2026-08-12/measurements/m1-missed-proposals.md` and `.../m2-slot-phase0-offset.md`**, each recording harness commit, injected latency profile, warm/cold cache condition, sample count, and raw percentiles | The plan requires "recorded as files in `plan/architecture-2026-08-12/`" but names no path; the milestone is otherwise unverifiable | A maintainer preferring a single `measurements/00-baselines.md`; the *existence and content* are what M6/NFR-1 need, not the split |
| **A-E9** | M1's baseline is expected to be ~100 % missed proposals. Is that a failure of Phase 0? | **No — recording a bad number is the deliverable.** ARCH-7b builds the instrument and records the pre-fix baseline; **fixing M1 is Phase 3 (ADR-004)**. An issue that "makes M1 pass" in Phase 0 is out of scope and would pre-empt ADR-004 | PRD M1 baseline: "expected 100 % miss with a stalled fetch, **by construction of PB-A1**" — the ordering at `coordinator/mod.rs:376-383` (both `fetch_epoch_duties` calls) precedes `:405` | Nothing; a green M1 at baseline would itself be the finding and would be recorded as such |

## Verification deltas found while estimating

Nine deltas, prefixed **VD-E**. Each was found by checking HEAD, not by reading the review. Five
change work (E3, E4, E5, E8, E9); three tighten an acceptance criterion (E2, E6, E7); one adds
evidence to an existing delta (E1).

| ID | Claim as written upstream | Status at HEAD | Corrected fact carried forward | Consumed by |
|---|---|---|---|---|
| **VD-E1** | VD-P1 (plan §4): *both* orphans collide by **package** name — `rvc-signer-bin` and `rvc-keygen` | **Confirmed, and understated again** | Verified: `crates/rvc-signer/Cargo.toml:2` = `rvc-signer-bin` = `bin/rvc-signer/Cargo.toml:2`; `crates/rvc-keygen/Cargo.toml:2` = `rvc-keygen` = `bin/rvc-keygen/Cargo.toml:2`. **New:** the **bin-target** names collide too — `crates/rvc-signer/Cargo.toml:13` = `rvc-signer` = `bin/rvc-signer/Cargo.toml:13`, and `crates/rvc-keygen/Cargo.toml:13` = `rvc-keygen` = `bin/rvc-keygen/Cargo.toml:13`. **The sharpest trap is a third name:** the package **`rvc-signer` is `crates/signer/`** (`crates/signer/Cargo.toml:2`), a live Domain member — *not* the orphan directory `crates/rvc-signer/`. A `cargo`- or grep-driven deletion keyed on the name `rvc-signer` destroys the wrong crate | ARCH-1a, ARCH-1b, ARCH-2a |
| **VD-E2** | VD-P3 / A-P3: the healthz replacement is *"`/health` (`server.rs:57-64`) and `readyz_handler` (`:145`)"* | **Correct but undercounted, and mis-paired for k8s** | `create_metrics_router_with_health` registers **four** routes at `crates/metrics/src/server.rs:59-64`: `/metrics`, `/health`, **`/livez` (`:62`)**, `/readyz` (`:63`). The k8s-relevant pair is **`/livez` (liveness) + `/readyz` (readiness)** — naming only `/health` in the deprecation note would send operators to the endpoint that maps to *neither* probe kind | ARCH-8 |
| **VD-E3** | ARCH-P2-5 / plan 0G: *"docs-freshness scan (paths mentioned in `docs/` must exist)"*, listed as tail hygiene | **Unsatisfiable as specified — it is RED on a file NG8 forbids editing** | `docs/architecture.md` cites **dead paths**: `crates/propagator/src/lib.rs` (`:384`, `:558` — the crate no longer exists, folded in `a2fc33d`), `crates/rvc/src/orchestrator/coordinator.rs` (`:254`, `:371`, … — now `coordinator/mod.rs`), `crates/block-service/src/service.rs` (`:34`, `:372-374`, … — now `service/mod.rs`), `crates/slashing/src/db.rs` (`:386`, `:400` — now `db/mod.rs`), and `crates/sync-service/src/lib.rs` (`:148`, `:375`), which **ARCH-3 deletes in this very phase**. NG8 forbids touching `docs/architecture.md`. **Resolution:** the scan ships with a documented **shrinking-only** exemption list, `kat_policy`-fashion, whose sole entry is `docs/architecture.md` with the NG8 reason and ARCH-P2-5's proposed move as the removal trigger. **Verified cheap:** among the other tracked docs (`docs/releases/*.md`, `keygen-guide.md`, `running-guide.md`, `keymanager-api.md`, `web3signer-http-api.md`, `validators-config.md`) a scan for `crates/…\.rs` paths returns **zero** matches, so the exemption list is exactly one entry, not a bulk waiver | ARCH-6 |
| **VD-E4** | PRD:494 / plan:352 / architecture:717: *"`rg 'struct CliOverrides'` returns exactly **one** hit"* after deletion | **False as written** | `rg 'struct CliOverrides'` at HEAD returns **six** hits: two in source (`crates/rvc/src/config/types.rs:1313`, `crates/rvc-signer/src/config.rs:132`) and **four in the planning documents themselves** (`prd.md:376`, `:494`, `project-plan.md:352`, `architecture.md:717`) — the criterion is self-defeating because stating it creates hits. **Corrected acceptance criterion: `rg 'struct CliOverrides' crates bin` → exactly 1**, path-scoped. This corrects PRD:494, project-plan:352 and architecture:717 | ARCH-1b |
| **VD-E5** | A-1 / ADR-012: archive to a branch **and** a tarball at `plan/architecture-2026-08-12/archive/untracked-orphans-2026-08-12.tar.gz` | **The tarball path is inside a fail-closed secret-scan** | `ci.yml:76-77` runs `gitleaks detect --no-git --source . --config .gitleaks.toml --exit-code 1` over the **whole working tree**, and `.gitleaks.toml:32-37` allow-lists **only** `target/` and `tests/` by path (deliberately no value regexes). A ~23.5k-line archive of **keygen/signer** code committed under `plan/…/archive/` is therefore scanned by Gate 2a, on the PR that adds it. **Default:** attempt the in-repo tarball; if Gate 2a reports a finding, move the tarball to a named out-of-repo location, record that path **and** the manifest hash in the issue body, and **do not** widen `.gitleaks.toml` — weakening a fail-closed security gate to store dead code is the wrong trade. The archive **branch** is unaffected (`ci.yml:3-6` triggers on `pull_request` only) | ARCH-1a |
| **VD-E6** | Milestone: *"no untracked source in the tree"* | **True only when scoped** | The tree legitimately carries untracked non-source files that Phase 0 must not delete — `plan/**`, `docs/prd.md`, `docs/project-plan.md`, `docs/issues/**` (NG8), `AUDIT-*.md`. M6 must read: **untracked `.rs` files under `crates/**` and `bin/**` = 0** (A-E7). D1/D2 enforce exactly that scope and nothing wider | Exit criteria, ARCH-2a, ARCH-2b |
| **VD-E7** | A-P1's overturn condition: gates inside `check` *"would need a `protoc`-free build path"* | **The stated reason does not hold; the decision still does** | `ci.yml:35-38` already installs `protoc` in the `check` job (as do `secret-scan:93-97` and `coverage:153-157`), so `protoc` is not what blocks it. The real reason to keep a separate `arch-gates` job stands on **NFR-5 / R10** grounds: `check` currently runs no tests at all, and folding a test run into it couples gate signal to the fmt/clippy/audit critical path. **A-P1's default is unchanged; its justification is corrected** | ARCH-4 |
| **VD-E9** | ARCH-P2-7 / plan 0C: delete `sync-service` = *"`members`, the alias at `Cargo.toml:33`, and the `CLASSIFICATION` row at `lib.rs:71`"* — **three** edit sites | **Incomplete — there is a fourth** | `crates/architecture-tests/src/lib.rs:375-384` declares `pub const DOMAIN_PACKAGES` which **also** lists `"rvc-sync-service"` (**`:382`**), and its doc comment at `:373-374` states that the unit test **`domain_packages_match_classification` enforces lock-step with `CLASSIFICATION`**. Removing only the `:71` row therefore fails that pre-existing test. Two consequences: ARCH-3 edits `lib.rs` in **two** places, and it gets a **free RED demonstration** — the existing `domain_packages_match_classification` test is the detector, so no new gate is needed to prove the edit is complete | ARCH-3 |
| **VD-E8** | Plan §6: Phase 0 = **7–11 d** (1 dev) | **Under-sized; stated, not retrofitted** | Counted items give **21 points ≈ 13–19 d**. Three drivers the upstream sizing does not carry: (i) **D2 is a module-graph walker**, not a directory comparison — it must parse `mod` declarations transitively from each member's roots and resolve `#[path]` (A-E4), where D1 reuses existing helpers (`load_cargo_metadata()` `lib.rs:146`, `workspace_root()` `:131`, `package_count()` `:102`) and is genuinely ~1 pt; (ii) **all three measurement harnesses are new builds** (VD-P2, re-confirmed: `crates/rvc/benches/per_slot.rs:1-16` and `crates/signer/benches/sign_path.rs` are logging-latency benches, explicitly *"NOT run under `nextest`/CI"*), and M1 needs a latency-injecting BN mock plus a deterministic slot clock; (iii) **VD-E3** converts "tail hygiene" into a gate with an exemption mechanism. Per house rule the gap is recorded, **not** absorbed by shrinking points | Phase Overview |

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream | Requirements |
|---|---|---|---|---|---|---|
| **ARCH-1a** | Archive the four orphan trees (branch + tarball) and verify by restore-and-diff | 2 | chore | — | **A** | ARCH-P0-1 (1,2) |
| **ARCH-1b** | Delete the four orphan trees in a separate commit referencing the archive ref | 1 | chore | ARCH-1a | **A** | ARCH-P0-1 (3) |
| **ARCH-2a** | G-1 detector **D1** — every `crates/*`/`bin/*` dir with a `Cargo.toml` is a member | 1 | chore | ARCH-1b | **A** | ARCH-P0-2 |
| **ARCH-2b** | G-1 detector **D2** — no uncompiled `.rs` under a member's `src/` | 3 | chore | ARCH-1b | **A** | ARCH-P0-2 |
| **ARCH-3** | Delete `crates/sync-service` (member, alias, `CLASSIFICATION` row, regenerate) | 1 | chore | ARCH-2a | **A** | ARCH-P2-7 |
| **ARCH-4** | Add the `arch-gates` CI job | 1 | chore | — | **A** | A-P1 / VD-P7 |
| **ARCH-5** | `cargo machete` in CI + remove `bin/rvc`'s unused workspace deps | 2 | chore | ARCH-4 | **A** | ARCH-P2-6 |
| **ARCH-6** | Docs-freshness scan with a one-entry shrinking-only exemption list | 2 | chore | ARCH-4 | **A** | ARCH-P2-5 |
| **ARCH-7a** | M2 instrument — slot-phase-0 start-offset histogram | 2 | feature | — | **B** | M2 (D10) |
| **ARCH-7b** | M1 harness — latency-injecting BN mock + missed-proposal measurement | 3 | feature | ARCH-7a | **B** | M1 (D10) |
| **ARCH-7c** | Record the M1/M2 baselines as files in `plan/architecture-2026-08-12/` | 1 | chore | ARCH-7b | **B** | M1, M2 (D10) |
| **ARCH-8** | Healthz deprecation notice + probe-migration check (**no removal**) | 1 | chore | — | **B** | ARCH-P1-16a |
| **ARCH-9** | Stale doc comments + the `signer-registry` shipped-fix TODO | 1 | chore | — | **B** | ARCH-P2-9 |
| | **Total** | **21** | | | **A: 13 · B: 8** | |

**ID convention.** IDs follow `ARCH-<n><letter>`; a **bare number means an unsplit issue**
(ARCH-3, 4, 5, 6, 8, 9) and **letters mark a split** — ARCH-1a/1b is C10's archive-then-delete
sequence, ARCH-2a/2b is G-1's two required detectors, ARCH-7a/7b/7c is the M2 instrument, the M1
harness and the baseline record. No number is reused across streams.

**Phase execution plan (2 developers, day-slots at ~1 pt/day).**

| Day | Stream A | Stream B |
|---|---|---|
| 1–2 | ARCH-1a (archive + verify) | ARCH-7a (M2 histogram) |
| 3 | ARCH-1b (delete) — *PR opens here* | ARCH-7a cont. |
| 4 | ARCH-2a (D1) — *same PR, after the delete commit* | ARCH-7b (M1 harness) |
| 5–7 | ARCH-2b (D2) — *same PR* | ARCH-7b cont. |
| 8 | ARCH-3 (`sync-service`) | ARCH-7c (record baselines) |
| 9 | ARCH-4 (`arch-gates`) | ARCH-8 (healthz deprecation) |
| 10–11 | ARCH-5 (`cargo machete` + deps) | ARCH-9 (doc-comment tail) |
| 12–13 | ARCH-6 (docs-freshness scan) | — (float / review support) |

Single-developer order: **1a → 1b → 2a → 2b → 3 → 7a → 7b → 7c → 4 → 5 → 6 → 8 → 9**, with **ARCH-8
pulled earlier if the release closing this phase is imminent** — C8's clock is measured in releases,
so shipping the `warn!` late costs a whole release cycle at the Phase-7 end.

**PR grouping (binding, from ADR-012).** ARCH-1b, ARCH-2a and ARCH-2b land in **one PR, in that
commit order** — the detectors after the deletion — so `develop` is never red and RED is
demonstrated locally against the pre-deletion tree with the output pasted into the PR. ARCH-1a is a
separate, earlier PR (or a direct branch push plus the tarball PR), because the archive must be
verified *before* anything is deleted. Every other issue is its own PR.

## Stream & file ownership

Streams are assigned per **issue**, not per work package, so that project-plan §9's "W0 is
single-stream" objection survives intact: **the 1a → 1b → 2a → 2b → 3 chain is one person's PR
sequence** and is not parallelised (A-E1).

| Path / area | Owner | Issues |
|---|---|---|
| `crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`, `crates/rvc/src/commands/` | **A** | 1a (read/archive), 1b (delete) — **no other issue may open these** |
| `plan/architecture-2026-08-12/archive/` *(new)* | **A** | 1a |
| `crates/architecture-tests/tests/*.rs` *(new files)*, `crates/architecture-tests/src/lib.rs` | **A** | 2a, 2b, 3, 6 |
| root `Cargo.toml`, `crates/sync-service/`, `ARCHITECTURE.md` *(generated)* | **A** | 3 |
| `.github/workflows/ci.yml` | **A** | 4 **then** 5 — strict order, no generator, no merge escape hatch (A-E2) |
| `bin/rvc/Cargo.toml` | **A** | 5 |
| `crates/rvc/src/orchestrator/coordinator/mod.rs`, `crates/metrics/src/**` | **B** | 7a |
| `crates/rvc/tests/**`, `crates/rvc/Cargo.toml` *(dev-deps)* | **B** | 7b |
| `plan/architecture-2026-08-12/measurements/` *(new)* | **B** | 7c |
| `crates/rvc/src/bootstrap/run.rs`, `docs/releases/UNRELEASED.md` | **B** | 8 |
| `crates/signer-registry/src/**` + scattered `///` comments | **B** | 9 |

**Disjointness check.** Stream A's only touch inside `crates/rvc/src/` is the **deletion** of
`main.rs` and `commands/` — files Stream B never opens (B works in `orchestrator/coordinator/mod.rs`,
`bootstrap/run.rs`, `tests/`). Stream A does **not** edit `crates/rvc/Cargo.toml` (A-E5 leaves
`autobins = false` in place), so B owns that manifest outright. No file appears in both columns.

**Merge-conflict hotspots.**

| File | Touched by | Strategy |
|---|---|---|
| `.github/workflows/ci.yml` | ARCH-4 (new job), ARCH-5 (step in `check`) | **Strict ordering**, both Stream A: 4 merges first, 5 rebases. Different regions, but hand-maintained YAML has no regeneration protocol (A-E2) |
| `ARCHITECTURE.md` | ARCH-3 only in this phase | Generated — never hand-merged. ARCH-3 lands the `Cargo.toml` + `CLASSIFICATION` edit **and** the regeneration in the same commit (§9 protocol) |
| `crates/architecture-tests/src/lib.rs` | ARCH-3 (`CLASSIFICATION` row) and possibly ARCH-2b (a shared file-walk helper) | 2b adds any helper as a **new** `pub fn` at end of file; 3 deletes one line at `:71`. Sequence 2b → 3 if both need it |

## Constraint discharge (C1–C10)

Silence on any constraint is a defect, so every one is discharged here — owned, or explicitly
deferred with its owning phase and reason.

| # | Constraint | Phase 0 disposition |
|---|---|---|
| **C1** | Retain-on-ambiguity vs lock-shortening | **Not owned — Phase 5 (ADR-005).** Phase 0 touches neither `crates/slashing/src/stage.rs` nor `crates/signer/src/core.rs`. Actively protected here: ARCH-9's doc-comment sweep **must not** edit `stage.rs` or `core.rs` comments, since Phase 1's 1A depends on `git diff -- crates/slashing/src/stage.rs` being **empty** |
| **C2** | Audit-log emission inside the mutex | **Not owned — Phase 1 (ADR-006, G-7).** Same protection as C1: ARCH-9 does not open `crates/slashing/src/scoped.rs` |
| **C3** | figment `Env` provider forbidden | **Not owned — Phase 4 (ADR-010, G-3).** Phase 0 adds no config surface and no env var. Positive obligation here: ARCH-4's `arch-gates` job introduces **no** `RVC_*` environment variable into CI, so G-3's future allow-list stays as small as it is today |
| **C4** | Keystore-less key admission | **Not owned — Phase 1 (ADR-007).** No admission-path file is opened |
| **C5** | KM-2 `stop_monitoring` vs `cancel_monitoring` teardown | **Not owned — Phase 7 (G-6 then ADR-015).** Phase 0 must not "tidy" the `cancel_monitoring → stop_monitoring` trait default at `crates/doppelganger/src/traits.rs:79-88` — **ARCH-9 is explicitly barred from that file**, because the trait default is the exact trap G-6 exists to gate and a doc-comment pass is how it would silently collapse |
| **C6** | Cold-cache pre-proposal fetch | **Not owned — Phase 3 (ADR-004).** But Phase 0 **enables** it: ARCH-7b must measure M1 in **both** warm and cold cache conditions (post-boot and post-`key_gen`-invalidation, `coordinator/mod.rs:373`), or Phase 3's 500 ms cold-cache budget has no baseline to be judged against |
| **C7** | SSE drops are normal | **Not owned — Phase 3 (ADR-013).** ARCH-7a's histogram must not be labelled or documented in a way that implies a dropped head event is an error condition |
| **C8** | Healthz removal is operator-visible | **Owned — ARCH-8.** Deprecation `warn!` + release note naming `/livez` and `/readyz` (VD-E2) + a probe-migration check. **No removal in this phase** (that is ARCH-P1-16b, Phase 7, ≥1 release later) |
| **C9** | Preserve the keep-list | **Owned in part — anchor 1.** ARCH-3 removes a `CLASSIFICATION` row and a workspace member; the proof it did not damage the harness is `ARCHITECTURE.md` regenerating **byte-identically**. ARCH-2a/2b/6 **add new gate files** in the existing scanner idiom and modify no existing gate. Anchors 2–7 are untouched by this phase: no signing path, no env rule, no channel, no spawn migration, and `spawn_blocking` is never scanned |
| **C10** | Archive before delete (untracked trees) | **Owned — ARCH-1a → ARCH-1b, and the reason this is two issues.** No git object exists behind the four trees, so `rm` is unrecoverable. Archive to a named branch **and** a tarball, verify by independent restore-and-diff (file count + per-file hash), record the manifest hash, **then** delete in a separate commit. **VD-E5** adds the gitleaks-path fallback so the tarball half cannot quietly be dropped |

## KAT-first policy applicability

Phase 0 contains **no signing-root or container `hash_tree_root` work** — no issue opens
`crates/signer/`, `crates/crypto/`, `crates/eth-types/` or `crates/slashing/`'s root logic — so the
KAT-anchoring obligation is discharged by scope rather than by anchoring. Two obligations remain,
and both are real:

1. **Name-scan collision (ARCH-7b).** CI enforces a name-pattern scan
   (`.*(tree_hash|signing_root|_root)$`) in `crates/architecture-tests/tests/kat_policy.rs`. The M1
   harness necessarily deals with block roots — `SlotContext::capture` calls `get_block_root`
   (`coordinator/mod.rs:402`) — so a natural test name like `test_capture_returns_parent_root` would
   **trip the gate**. **Requirement:** ARCH-7b's tests are named for what they assert
   (`..._offset_ms`, `..._miss_rate`, `..._under_stalled_duty_fetch`) and **must not** end in
   `_root`. This mirrors the inverse obligation the plan already places on ADR-003.
2. **`EXEMPTIONS` is shrinking-only.** No Phase-0 issue may add an entry to `kat_policy.rs`'s
   `EXEMPTIONS` list. If ARCH-7b cannot avoid a `_root`-suffixed name, it carries a documented
   `// kat_exempt: <reason>` marker in the test body instead — never a list addition.

## Issues

---

### ARCH-1a — Archive the four orphan trees (branch + tarball) and verify by restore-and-diff

- **Points:** 2 · **Scope:** 1–2 days · **Type:** chore · **Priority:** P0 · **Stream:** A
- **Blocked by:** — · **Blocks:** ARCH-1b (and therefore all of ARCH-2a/2b/3)
- **Requirements:** ARCH-P0-1 steps (1) and (2) · **ADR:** ADR-012 · **Constraints:** **C10 (binding)**

**Context.** `crates/rvc-signer/` (19,750 LOC), `crates/rvc-keygen/` (3,749), `crates/rvc/src/main.rs`
(2,771 lines) and `crates/rvc/src/commands/` (5 files) are **untracked and have never been tracked**:
`git log --all` over all four paths returns nothing — no commit, no blob, no reflog entry. `rm` is
therefore **unrecoverable**, which is a materially different risk class from every other deletion in
this initiative (`crates/sync-service`, the healthz server, the `Wire*` twins are all restorable from
history). This issue exists so that ARCH-1b is a reversible action.

**Implementation approach.**

1. **Archive as content, not as workspace members.** Create branch
   `archive/untracked-orphans-2026-08-12` from `develop` @ `0ae9a09`, `git add -f` the four paths
   verbatim, commit. **Do not** add either crate to `[workspace] members` — both are duplicate-package
   hard errors (**VD-P1**, re-verified as **VD-E1**): `crates/rvc-signer/Cargo.toml:2` = `rvc-signer-bin`
   = `bin/rvc-signer/Cargo.toml:2`, and `crates/rvc-keygen/Cargo.toml:2` = `rvc-keygen` =
   `bin/rvc-keygen/Cargo.toml:2`. Their **bin-target** names collide as well (`:13` in all four
   manifests). Expect the archive branch to be non-building by design; state that in the commit message.
2. **Do not touch the content.** Not a single byte, including
   `crates/rvc/src/main.rs:1608`'s `#[allow(clippy::arc_with_non_send_sync)]` — editing an
   unrecoverable tree is the one action C10 forbids outright, and ADR-002 has a downstream
   dependency on that line *not* having been touched. No content comparison against `bin/` is
   performed here (A-15): the archive is what makes that question answerable later.
3. **Tarball.** Produce `plan/architecture-2026-08-12/archive/untracked-orphans-2026-08-12.tar.gz`
   containing the same four paths, plus `plan/architecture-2026-08-12/archive/MANIFEST.md` recording
   the file count, the per-file SHA-256 list and the tarball's own SHA-256. Both branch *and*
   tarball, never either (A-1: a branch can be pruned, a tarball can be lost).
4. **Verify independently.** Restore the archive (branch *and* tarball, separately) into a scratch
   directory outside the repo and compare against the working tree: **file count equal** and **every
   per-file hash equal**. Zero differences is the pass condition. Record the resulting manifest hash
   in the issue body.
5. **Guard the naming trap (VD-E1).** The package named `rvc-signer` is **`crates/signer/`**
   (`crates/signer/Cargo.toml:2`), a live Domain member — *not* the orphan directory
   `crates/rvc-signer/`. Likewise `bin/rvc/src/commands/` is **live** (6 files) while
   `crates/rvc/src/commands/` is the orphan (5 files; the orphan lacks `signed_exit.rs`). Every
   command in this issue and in ARCH-1b addresses paths **literally**; nothing is driven by package
   name or by a `commands/` glob.

**Exact files to touch.**

- Read-only: `crates/rvc-signer/**`, `crates/rvc-keygen/**`, `crates/rvc/src/main.rs`,
  `crates/rvc/src/commands/**`.
- New: `plan/architecture-2026-08-12/archive/untracked-orphans-2026-08-12.tar.gz`,
  `plan/architecture-2026-08-12/archive/MANIFEST.md`,
  `plan/architecture-2026-08-12/archive/verify-archive.sh` (the restore-and-diff script, checked in
  so the verification is repeatable rather than a one-off shell session).
- New branch: `archive/untracked-orphans-2026-08-12` (not merged, not deleted).

**TDD test plan.** The deliverable here is a *verification procedure*, so the RED test is the
verification script run against a deliberately corrupted archive.

- **RED first:** `verify-archive.sh` run against an archive with **one file removed** must exit
  non-zero and print the missing path. Then run it against a tarball with **one byte flipped** in a
  single file: it must exit non-zero and print that file's path with expected/actual hashes. Only
  after both failures reproduce is the script trusted to certify the real archive.
- **GREEN:** the same script against the real branch and the real tarball exits zero with
  `files=<N> differences=0`.

**Risks.**

- **Gitleaks (VD-E5, named risk).** `ci.yml:76-77` runs `gitleaks detect --no-git --source .` over
  the whole tree, fail-closed, and `.gitleaks.toml:32-37` allow-lists only `target/` and `tests/`.
  A ~23.5k-line keygen/signer archive under `plan/…/archive/` is inside that scan. **Fallback, in
  order:** (i) if Gate 2a is clean, keep the in-repo tarball; (ii) if it reports a finding, move the
  tarball to a named out-of-repo location (recorded in the issue body and in `MANIFEST.md`) and keep
  `MANIFEST.md` in-repo; (iii) **never** widen `.gitleaks.toml` — weakening a fail-closed security
  gate to store dead code is the wrong trade. The archive **branch** is unaffected: `ci.yml:3-6`
  triggers on `pull_request` to `main`/`develop` only.
- Repository size: a ~23.5k-line compressed archive is small in absolute terms; no LFS needed.

**Acceptance criteria.**

- [ ] Branch `archive/untracked-orphans-2026-08-12` exists and contains all four paths verbatim;
      `git show --stat` on its tip lists files from all four trees.
- [ ] `plan/architecture-2026-08-12/archive/MANIFEST.md` records file count, per-file SHA-256 and the
      tarball SHA-256; the same manifest hash is pasted into the issue body.
- [ ] `verify-archive.sh` exits **non-zero** on a corrupted archive (both the missing-file and the
      flipped-byte cases) — output pasted into the PR.
- [ ] `verify-archive.sh` exits **zero** against branch and tarball with `differences=0`.
- [ ] Neither orphan crate was added to `[workspace] members` anywhere (`git diff` on root
      `Cargo.toml` is **empty** in this issue).
- [ ] No byte of the four trees changed (`verify-archive.sh` against the working tree is the proof).
- [ ] The gitleaks disposition is recorded in the issue body: in-repo tarball retained, **or** the
      out-of-repo path named — with `.gitleaks.toml` **unchanged** either way.

---

### ARCH-1b — Delete the four orphan trees in a separate commit referencing the archive ref

- **Points:** 1 · **Scope:** 0.5 day · **Type:** chore · **Priority:** P0 · **Stream:** A
- **Blocked by:** ARCH-1a · **Blocks:** ARCH-2a, ARCH-2b
- **Requirements:** ARCH-P0-1 step (3) · **ADR:** ADR-012 · **Constraints:** **C10**, C9 (anchor 1)

**Context.** With a verified archive in hand the deletion becomes reversible and mechanical. Its
value is that it closes the grep-ambiguity failure mode: today `struct CliOverrides` matches two
definitions, one live and one dead, so a reviewer or an agent can edit the wrong copy and silently
lose a security fix (the orphan `rvc-keygen` lacks `fs_util.rs` and still carries 14 inline
`0o600`/`set_permissions` sites where the member has 12 factored through it).

**Implementation approach.**

1. One commit, deleting exactly four paths, with the archive ref and manifest hash in the commit
   message: `crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`,
   `crates/rvc/src/commands/`. Nothing else — in particular **not** `bin/rvc/src/commands/`, which is
   live (VD-E1).
2. **Leave `crates/rvc/Cargo.toml:3` (`autobins = false`) unchanged** (A-E5). Removing it would
   change build semantics inside the same commit that removes 26k lines, and D2 is what makes
   leaving it safe: a future `src/main.rs` under `autobins = false` is exactly the orphan D2 catches.
3. The build must be **unaffected** — nothing compiled these trees (`crates/rvc/src/lib.rs:3-15`
   declares 13 modules and no `mod commands;`; `crates/rvc/Cargo.toml` declares no `[[bin]]`). Any
   build or test delta is itself the finding and is investigated before the PR proceeds.
4. This commit is the **first** commit of the shared PR with ARCH-2a and ARCH-2b, in that order.

**Exact files to touch.** Deletions only: `crates/rvc-signer/**`, `crates/rvc-keygen/**`,
`crates/rvc/src/main.rs`, `crates/rvc/src/commands/**`.

**TDD test plan.** The regression detector for this deletion **is** ARCH-2a/2b, landing immediately
after it in the same PR — that is the ADR-012 landing rule, and it is why this issue writes no test
of its own. Its pre-conditions are assertions run by hand and pasted into the PR:

- **Before:** `rg 'struct CliOverrides' crates bin` → **2** hits
  (`crates/rvc/src/config/types.rs:1313`, `crates/rvc-signer/src/config.rs:132`).
- **After:** → **1** hit. Note the **path scope is load-bearing** (**VD-E4**): unscoped,
  `rg 'struct CliOverrides'` also matches four planning documents, so the criterion as written in
  PRD:494 / project-plan:352 / architecture:717 can never be satisfied. Use the scoped form.

**Acceptance criteria.**

- [ ] None of the four paths exists in the working tree; `git status` shows no untracked `.rs` under
      `crates/` or `bin/` (VD-E6's scoped M6 = 0).
- [ ] `bin/rvc/src/commands/` is **untouched** (6 files present) and `crates/signer/` is untouched.
- [ ] `rg 'struct CliOverrides' crates bin` returns exactly **1** hit at
      `crates/rvc/src/config/types.rs:1313`.
- [ ] `cargo build --workspace` and `cargo nextest run --workspace` produce **the same** result as on
      the parent commit — pasted into the PR as before/after summaries.
- [ ] `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings` green.
- [ ] The commit message names the archive branch **and** the manifest hash.
- [ ] `crates/rvc/Cargo.toml` is **unchanged** in this commit.

---

### ARCH-2a — G-1 detector D1: every `crates/*`/`bin/*` dir with a `Cargo.toml` is a workspace member

- **Points:** 1 · **Scope:** 0.5–1 day · **Type:** chore · **Priority:** P0 · **Stream:** A
- **Blocked by:** ARCH-1b (same PR, immediately after) · **Blocks:** ARCH-3
- **Requirements:** ARCH-P0-2 (D1) · **ADR:** ADR-012 · **Gate:** **G-1** · **Constraints:** C9 (anchor 1)

**Context.** The architecture gates read `cargo metadata`, so a non-member directory is invisible to
every one of them — which is how 23.5k lines of shadow code survived a fully-gated repo. D1 closes
that hole for whole directories. It is cheap because the scanner primitives already exist.

**Implementation approach.**

- New file `crates/architecture-tests/tests/orphan_dirs.rs`, in the existing scanner idiom.
- Reuse, do not rebuild: `workspace_root()` (`crates/architecture-tests/src/lib.rs:131`),
  `load_cargo_metadata()` (`:146`), `WorkspaceGraph::package_count()` (`:102`).
- Enumerate `{crates,bin}/*/Cargo.toml` from the filesystem; map each to its manifest path; compare
  against the `manifest_path` set from `cargo metadata --no-deps`.
- **Non-vacuity is two assertions, not one.** The relational check alone (`dirs == members`) is green
  and useless if the filesystem walk returns empty — `0 == 0` passes. So assert **both**: (a) the
  directory count equals the member count, **and** (b) the count equals the **absolute pin `28`**, per
  the architecture's G-1 spec ("assert the member count equals the workspace's — 29 at HEAD, 28 after
  ARCH-P2-7's removal"). **Consequence, carried forward:** the pin makes
  `crates/architecture-tests/tests/orphan_dirs.rs` a **third edit site for ARCH-3** (29 → 28) — the
  same class of miss as VD-E9, and it is listed in ARCH-3's files below. Land the pin as `29` in this
  issue and let ARCH-3's RED be the failing pin.
- **Verified reachable (VD-P8, reproduced here):** `{crates,bin}/*/Cargo.toml` matches
  **31** paths at HEAD; ARCH-1b removes the two orphans → **29**, exactly the member count in root
  `Cargo.toml:2`; ARCH-3 removes `sync-service` → **28 = 28**. There is no intentionally-excluded
  manifest and no nested manifest, so **D1 needs no exclusion list** and asserts a hard equality
  rather than a `>=` bound.
- **Failure message (binding, VD-P1/VD-E1):** name the offending path and say *"either add it to
  `[workspace] members` **or** delete it"* — and **never** recommend adding it unconditionally,
  because for the two historical orphans that remedy does not compile (duplicate package names). The
  message should note that a same-named package elsewhere in the tree is the likely cause.

**TDD test plan.**

- **RED (demonstrated locally, pasted into the PR):** run `test_every_crate_dir_is_a_workspace_member`
  against the **pre-deletion** tree (`git stash` the delete, or check out the parent commit). It must
  fail naming **both** `crates/rvc-signer` and `crates/rvc-keygen`, and report `31 != 29`.
- **RED (permanent, in CI):** `test_d1_rejects_an_unregistered_manifest` — a unit test that feeds the
  comparison function a synthetic directory set containing `crates/scratch-orphan` plus the real
  member list, and asserts the returned error names `crates/scratch-orphan`. This keeps D1 falsifiable
  after the tree is clean, without a scratch commit.
- **GREEN:** on `develop` after ARCH-1b, the test passes with `29 == 29`; after ARCH-3, `28 == 28`.

**Acceptance criteria.**

- [ ] `crates/architecture-tests/tests/orphan_dirs.rs` exists and contains D1.
- [ ] D1 fails against the pre-deletion tree naming both orphan directories — output in the PR.
- [ ] D1 passes on `develop` after ARCH-1b, asserting **both** the exact equality of directory count
      and member count **and** the absolute pin (`29` at this issue's merge, `28` after ARCH-3).
- [ ] A synthetic empty-directory-set input makes D1 **fail**, proving the equality cannot pass
      vacuously.
- [ ] `test_d1_rejects_an_unregistered_manifest` passes (synthetic RED, permanent).
- [ ] The failure message names the offending path and does **not** unconditionally recommend
      `[workspace] members`.
- [ ] The test runs in the `arch-gates` job (ARCH-4) as well as under `cargo nextest run --workspace`.

---

### ARCH-2b — G-1 detector D2: no uncompiled `.rs` under a member crate's `src/`

- **Points:** 3 · **Scope:** 2 days · **Type:** chore · **Priority:** P0 · **Stream:** A
- **Blocked by:** ARCH-1b (same PR, after ARCH-2a) · **Blocks:** —
- **Requirements:** ARCH-P0-2 (D2) · **ADR:** ADR-012 · **Gate:** **G-1** · **Constraints:** C9 (anchor 1)

**Context.** D1 catches orphan *directories*; only D2 catches an orphan *inside* a member —
`crates/rvc/src/main.rs` (2,771 lines) and `crates/rvc/src/commands/` (5 files) lived inside the
member crate `rvc`, uncompiled, because `crates/rvc/Cargo.toml:3` sets `autobins = false` and
`crates/rvc/src/lib.rs` never declares `mod commands;`. Half the ≈26,270 lines are invisible to D1.
**This is the phase's only 3-point issue**: unlike D1 it has no existing primitive to reuse — it
needs a transitive module-graph walk (see VD-E8).

**Implementation approach.**

1. For each `cargo metadata` member, compute its **compilation roots**: `src/lib.rs`; `src/main.rs`
   *only if* `autobins` is not `false` **or** an explicit `[[bin]] path` points at it; every
   `[[bin]]`/`[[example]]`/`[[bench]]`/`[[test]]` `path` inside `src/`; and `src/bin/*.rs` when
   `autobins` is not disabled.
2. From each root, walk `mod <name>;` declarations transitively, resolving `<name>.rs` and
   `<name>/mod.rs`, and **resolving `#[path = "…"]`** (A-E4). Ignore `cfg` predicates entirely — a
   file declared behind `#[cfg(feature = "gcp-secret")]` or `#[cfg(test)]` is *declared*, therefore
   not an orphan.
3. The orphan set is `{all .rs under src/} − {reachable from a root}`. Fail naming each path.
4. **Documented-marker escape hatch:** a file carrying `// orphan_exempt: <reason>` on its first
   non-empty line is skipped, and the exemption list — like `kat_policy`'s `EXEMPTIONS` — is
   **shrinking-only**. At HEAD, after ARCH-1b, the expected exemption count is **zero**.
5. **Known false-positive source, verified:** the workspace's **only** `#[path]` attribute is
   `crates/crypto/src/remote_signer/client.rs:325` → `client_tests.rs`. A resolver that ignores
   `#[path]` reports exactly that one false positive; the acceptance criteria pin it.
6. **Non-vacuity:** assert the walker visited a non-trivial file count (e.g. `>= 300` `.rs` files
   across members) — a walker that silently visits nothing is green and useless.

**TDD test plan.**

- **RED (demonstrated locally, pasted into the PR):** `test_no_uncompiled_source_under_member_src`
  against the **pre-deletion** tree must fail naming `crates/rvc/src/main.rs` **and all five**
  `crates/rvc/src/commands/*.rs` files — six paths, not one.
- **RED (permanent, in CI):** `test_d2_rejects_a_module_no_root_declares` — feeds the reachability
  function a synthetic root set and a synthetic file list containing `src/ghost.rs`, asserting the
  error names `ghost.rs`.
- **RED for the resolver:** `test_d2_resolves_path_attribute_modules` — asserts that
  `crates/crypto/src/remote_signer/client_tests.rs` is **reachable** (this test fails first if
  `#[path]` handling is omitted, which is exactly the bug this issue must not ship).
- **GREEN:** on `develop` after ARCH-1b, zero orphans, zero exemptions, `visited >= 300`.

**Acceptance criteria.**

- [ ] D2 fails against the pre-deletion tree naming all **six** in-member orphan files — output in
      the PR.
- [ ] D2 passes on `develop` after ARCH-1b with **zero** exemptions.
- [ ] `crates/crypto/src/remote_signer/client_tests.rs` is **not** reported (the `#[path]` case is
      covered by its own test).
- [ ] `#[cfg(...)]`-gated and `#[cfg(test)]` modules are **not** reported.
- [ ] The non-vacuity assertion on visited file count is present and passes.
- [ ] A scratch commit adding `crates/rvc/src/ghost.rs` (undeclared) fails the gate and names the path.
- [ ] The `orphan_exempt` list is documented as shrinking-only and is empty at merge.

---

### ARCH-3 — Delete `crates/sync-service` (member, alias, `CLASSIFICATION` row, regenerate)

- **Points:** 1 · **Scope:** 0.5 day · **Type:** chore · **Priority:** P2 · **Stream:** A
- **Blocked by:** ARCH-2a · **Blocks:** ARCH-6 (removes two of its dead-path citations)
- **Requirements:** ARCH-P2-7 · **Constraints:** **C9 (anchor 1)**; **C10 does not apply**

**Context.** `crates/sync-service` **is** a real workspace member (root `Cargo.toml:2`) — the review
resolved a conflict between two subsystem maps in favour of that reading, and it reproduces at HEAD —
but it is a 45-line shell with zero consumers. Because it is **tracked**, this is an ordinary,
recoverable delete and C10's archive ritual does **not** apply; saying so explicitly is what stops
someone from cargo-culting ARCH-1a's ceremony onto it. It is bundled into Phase 0 (D11) so that
G-1's member-count equality is pinned **once** (29 → 28) rather than twice.

**Exact files to touch.**

- Delete `crates/sync-service/**`.
- Root `Cargo.toml`: remove `"crates/sync-service"` from `members` (`:2`) and the
  `sync-service = { path = "crates/sync-service", package = "rvc-sync-service" }` alias (**`:33`**,
  verified).
- `crates/architecture-tests/src/lib.rs`, **two** sites (**VD-E9** — the upstream documents name only
  the first):
  1. the `CLASSIFICATION` row `("rvc-sync-service", Layer::Domain, "sync-service", "sync committees")`
     at **`:71`** (verified; the table spans `:57-92` and holds **29** rows — 3 Binary,
     1 Orchestrator, 8 Domain, 15 Foundation, 2 Meta);
  2. `pub const DOMAIN_PACKAGES` at **`:375-384`**, which lists `"rvc-sync-service"` at **`:382`** and
     whose doc comment (`:373-374`) states that **`domain_packages_match_classification` enforces
     lock-step with `CLASSIFICATION`**. Editing only site 1 fails that existing test.
- `crates/architecture-tests/tests/orphan_dirs.rs`: update D1's **absolute pin 29 → 28** (site 3 —
  introduced by ARCH-2a's non-vacuity floor, and the reason ARCH-3 must run after it).
- Regenerate `ARCHITECTURE.md` **in the same commit** (§9's protocol for generated files).

**Implementation approach.** Confirm zero consumers first: `rg 'sync-service|sync_service|rvc-sync-service'`
over `{crates,bin}/**/Cargo.toml` must return only the root alias and the crate's own manifest. Then
delete, edit **both** `lib.rs` sites, regenerate via the existing `generate-architecture-md` binary
(`crates/architecture-tests/Cargo.toml:19`), and let the byte-match gate prove nothing else moved.
`DOMAIN_EDGE_ALLOWLIST` (`:391-399`) contains no `sync-service` entry and needs no edit — verified.

**TDD test plan.** This issue needs **no new test**: the repo already ships its detector (VD-E9).

- **RED first (free, pre-existing):** remove the `CLASSIFICATION` row at `:71` **only**, leaving
  `DOMAIN_PACKAGES:382` intact, and run `cargo nextest run -p rvc-architecture-tests`.
  `domain_packages_match_classification` must fail naming `rvc-sync-service` — this is the proof that
  site 2 exists and that the edit is incomplete without it.
- **RED, second form:** delete the `CLASSIFICATION` row **without** deleting the member and run the
  generator check; it must fail with *"CLASSIFICATION lists package(s) absent from cargo metadata"*
  (`crates/architecture-tests/src/lib.rs:235`), proving the classification gate is live before it is
  relied on as the safety net for the real edit.
- **GREEN:** with member, alias, row and directory all removed, `ARCHITECTURE.md` regenerates
  **byte-identically** to the committed file and `architecture_doc_matches_graph.rs` passes.
- **Regression:** ARCH-2a's D1 now asserts `28 == 28`.

**Acceptance criteria.**

- [ ] `crates/sync-service/` is gone; root `Cargo.toml` `members` has 28 entries; the `:33` alias is
      removed.
- [ ] The `CLASSIFICATION` table has **28** rows and no `rvc-sync-service` entry, **and**
      `DOMAIN_PACKAGES` has **7** entries with no `rvc-sync-service` (VD-E9).
- [ ] `domain_packages_match_classification` passes, and its RED form (site 1 only) was demonstrated
      and pasted into the PR.
- [ ] `ARCHITECTURE.md` regenerates byte-identically (`architecture_doc_matches_graph.rs` green) —
      C9 anchor 1's proof that the harness was not damaged.
- [ ] `cargo build --workspace` and `cargo nextest run --workspace` green.
- [ ] D1 (ARCH-2a) asserts and passes `28 directories == 28 members`, **and** its absolute pin reads
      `28` (the failing `29` pin is this issue's third RED, pasted into the PR).
- [ ] The commit message states that this delete is **tracked and recoverable**, so C10 does not apply.

---

### ARCH-4 — Add the `arch-gates` CI job

- **Points:** 1 · **Scope:** 0.5 day · **Type:** chore · **Priority:** P0 · **Stream:** A
- **Blocked by:** — · **Blocks:** ARCH-5 (`ci.yml` ordering, A-E2), ARCH-6
- **Requirements:** A-P1 / VD-P7 (plan-introduced; no PRD ID) · **Constraints:** C3 (negative), C9 (anchor 1)

**Context.** Eight new gates land across this initiative, and at HEAD **CI has nowhere prompt to run
them**: `ci.yml` has exactly three jobs — `check:13` (fmt / clippy / clippy-dvt / audit),
`secret-scan:59`, `coverage:129` — and the only place a `#[test]` executes is
`cargo llvm-cov nextest --workspace` at **`:166`**, under coverage instrumentation. Without this job
every gate failure arrives late and attributed to coverage tooling (NFR-5, R10). This issue is
deliberately **first among the CI edits** so ARCH-2a/2b's detectors have a fast home from day one.

**Implementation approach.**

- Add a fourth top-level job `arch-gates` to `.github/workflows/ci.yml` running
  `cargo nextest run -p rvc-architecture-tests`.
- Mirror the existing job scaffolding: `actions/checkout@v4`, `dtolnay/rust-toolchain@stable`, the
  cargo cache with its own key, `arduino/setup-protoc@v3` (**`protoc` is required** — `signer-proto`
  is in the build graph; note **VD-E7**: `protoc` is *not* what argues against folding these into
  `check`, since `check` already installs it at `:35-38`), plus `taiki-e/install-action@nextest`.
- **No `RVC_*` environment variable may be introduced** in this job (C3, negative obligation): the
  Phase-4 env allow-list should stay as small as it is today.
- Keep the job scanner-scoped: one package, no `--workspace`, so it stays fast (NFR-5).

**Exact files to touch.** `.github/workflows/ci.yml` (new job only; existing jobs untouched).

**TDD test plan.**

- **RED:** on a scratch branch, introduce a deliberately failing assertion in an existing
  architecture test (e.g. flip a `CLASSIFICATION` blurb so the byte-match gate fails), open a draft
  PR, and confirm **`arch-gates` fails while `check` still passes** — that divergence is the proof
  the job actually adds signal rather than duplicating `check`.
- **GREEN:** revert the scratch change; `arch-gates` passes on `develop` and reports a wall-clock
  runtime, recorded in the PR (the NFR-5 budget baseline for the seven gates still to come).

**Acceptance criteria.**

- [ ] `ci.yml` has four jobs; `arch-gates` runs `cargo nextest run -p rvc-architecture-tests`.
- [ ] The RED demonstration (arch-gates red, check green) is pasted into the PR.
- [ ] Job wall-clock runtime is recorded in the PR as the NFR-5 baseline.
- [ ] The three existing jobs are byte-unchanged in this PR.
- [ ] No `RVC_*` env var is added anywhere in `ci.yml`.

---

### ARCH-5 — `cargo machete` in CI + remove `bin/rvc`'s unused workspace deps

- **Points:** 2 · **Scope:** 1 day · **Type:** chore · **Priority:** P2 · **Stream:** A
- **Blocked by:** ARCH-4 (strict `ci.yml` ordering, A-E2) · **Blocks:** —
- **Requirements:** ARCH-P2-6 · **Assumption:** **A-E3** (`machete` only, not `udeps`)
- **Constraints:** **none** — this issue has no C1–C10 surface (no signing path, no env var, no
  channel, no spawn, no classification row); stated rather than left silent

**Context.** `bin/rvc` declares 24 production dependencies (`bin/rvc/Cargo.toml:21-54`), several of
which no source file uses. Unused declared deps inflate the build graph and — worse for this
initiative — make `cargo metadata`-derived edges lie about the real architecture, which is the same
class of dishonesty Phase 0 exists to end.

**Implementation approach.**

1. **Verify before removing (PRD A-11).** A path-qualified scan of `bin/rvc/src/**` for each declared
   alias gives **eight candidates with no `::`-qualified use at HEAD**: `builder`, `doppelganger`,
   `grpc-signer`, `observability`, `parking_lot`, `secret-provider`, `timing`, `tonic`. The review
   says "~6"; **the count is a candidate list, not a verdict** — a dep can be used via a macro, a
   re-export, or a feature edge (`gcp-secret` at `:19` pulls `rvc/gcp-secret` and `dep:rustls`).
   `cargo machete` plus a clean `cargo build --workspace` is the arbiter, not the grep.
2. Remove only what both the scan and `cargo machete` agree on; keep anything whose removal breaks
   the build or a feature, and record the reason inline.
3. Add a `cargo machete` step to the **existing `check` job** (it is a fast, non-test check and
   belongs beside fmt/clippy/audit), installed via `taiki-e/install-action@v2`.
4. **`cargo-udeps` is explicitly not adopted** (A-E3): it needs nightly, and all three CI jobs pin
   `dtolnay/rust-toolchain@stable` with `rust-version = "1.92"` at root `Cargo.toml:15`.
5. Note the duplicate declarations at `bin/rvc/Cargo.toml:57-64`: `eth-types`, `hex` and `serde_json`
   appear in **both** `[dependencies]` and `[dev-dependencies]`. Decide deliberately — machete may or
   may not flag them — and record the decision rather than letting the tool's default stand silently.

**Exact files to touch.** `bin/rvc/Cargo.toml`, `.github/workflows/ci.yml` (a step inside `check`),
possibly `Cargo.lock`.

**TDD test plan.**

- **RED:** add the `cargo machete` step **before** removing any dependency and push. The step must
  **fail**, listing the unused deps — that output is the verified count and replaces the review's
  "~6" estimate with a number. Paste it into the PR.
- **GREEN:** remove the confirmed-unused deps; `cargo machete` passes; `cargo build --workspace`,
  `cargo build --workspace --all-features` and `cargo nextest run --workspace` are green.
- **Regression:** re-adding an unused dep in a scratch commit fails CI.

**Acceptance criteria.**

- [ ] `cargo machete`'s RED output (the authoritative unused-dep list) is pasted into the PR.
- [ ] Every removed dep is listed in the PR body; every *retained* candidate from the eight has a
      one-line reason.
- [ ] `cargo machete` is a step in `check` and passes.
- [ ] `cargo build --workspace`, `--all-features`, and `cargo nextest run --workspace` green.
- [ ] `cargo-udeps` is **not** added, and the nightly-toolchain reason is recorded (A-E3).
- [ ] ARCH-4's `arch-gates` job is untouched by this PR (A-E2's ordering held).

---

### ARCH-6 — Docs-freshness scan with a one-entry, shrinking-only exemption list

- **Points:** 2 · **Scope:** 1 day · **Type:** chore · **Priority:** P2 · **Stream:** A
- **Blocked by:** ARCH-4 only · **Blocks:** —
- *(Not blocked by ARCH-3, contrary to first reading: the two `sync-service` citations ARCH-3
  invalidates are at `docs/architecture.md:148` and `:375` — inside the one file this gate exempts —
  and every other tracked doc has zero `crates/…` paths. ARCH-6 is green regardless of ARCH-3.)*
- **Requirements:** ARCH-P2-5 (**scan only** — the plan does *not* move `docs/architecture.md`, NG8)
- **Constraints:** **NG8**, C9 (anchor 1)

**Context.** `docs/architecture.md` is not an architecture document — it is a stale test-audit
remediation plan whose paths have rotted. A scan is the durable fix; moving the file is out of scope
(NG8). **This issue is the phase's one genuine specification problem (VD-E3):** as written, the gate
cannot land green, because the only tracked doc that cites source paths is precisely the one this
initiative may not edit.

**Verified scope (why this is 2 points and not 3).**

- `docs/architecture.md` cites dead paths: `crates/propagator/src/lib.rs` (`:384`, `:558` — the crate
  no longer exists; folded in `a2fc33d`), `crates/rvc/src/orchestrator/coordinator.rs`
  (`:254`, `:371`, `:379`, `:396`, … — now `coordinator/mod.rs`), `crates/block-service/src/service.rs`
  (`:34`, `:372-374`, … — now `service/mod.rs`), `crates/slashing/src/db.rs` (`:386`, `:400` — now
  `db/mod.rs`), and `crates/sync-service/src/lib.rs` (`:148`, `:375`) which **ARCH-3 deletes**.
- **Every other tracked doc is clean:** a scan of `docs/releases/*.md`, `keygen-guide.md`,
  `running-guide.md`, `keymanager-api.md`, `web3signer-http-api.md` and `validators-config.md` for
  `crates/…\.rs` / `bin/…\.rs` paths returns **zero** matches. The exemption list is therefore
  **exactly one entry**, not a bulk waiver — which is what keeps this gate meaningful.
- `docs/prd.md`, `docs/project-plan.md` and `docs/issues/**` also cite dead paths but are **untracked**
  at baseline and belong to the older initiative; scanning `git ls-files docs` skips them without a
  special case.

**Implementation approach.**

- New `crates/architecture-tests/tests/docs_freshness.rs` in the scanner idiom.
- Input set: **tracked** markdown under `docs/` (`git ls-files 'docs/**/*.md'`), so the older
  initiative's untracked working files are out of scope by construction rather than by name.
- Extract backticked path-like tokens matching `(crates|bin|plan|docs)/…` and assert each resolves on
  disk (file **or** directory). Ignore URLs, fenced code blocks and inline `mermaid`.
- `STALE_DOC_EXEMPTIONS: &[(&str, &str)] = &[("docs/architecture.md", "NG8: owned by the Test Audit
  Remediation initiative; ARCH-P2-5 proposes moving it to plan/test-architecture-audit.md — remove
  this entry when that move lands")]`, documented as **shrinking-only**, `kat_policy`-fashion.
- Non-vacuity: assert the scan resolved at least N (>0) real paths from **non-exempt** docs, so a
  regex that matches nothing cannot pass.

**TDD test plan.**

- **RED first:** `test_docs_reference_only_existing_paths` with an **empty** exemption list must fail
  naming `docs/architecture.md` and at least the `crates/propagator/src/lib.rs` citation. Paste the
  output into the PR — it is the evidence that justifies the one exemption.
- **RED, permanent:** `test_docs_freshness_rejects_a_dead_path` — feeds the checker a synthetic doc
  body citing `crates/does-not-exist/src/lib.rs` and asserts the error names it. Keeps the gate
  falsifiable without a scratch commit.
- **GREEN:** with the one-entry exemption list, the gate passes on `develop` after ARCH-3.

**Acceptance criteria.**

- [ ] Gate exists, runs in `arch-gates`, and passes on `develop`.
- [ ] The exemption list has **exactly one** entry, with a written NG8 reason and a named removal
      trigger; it is documented as shrinking-only.
- [ ] `docs/architecture.md` is **not modified** by this issue (NG8) — `git diff` on it is empty.
- [ ] The empty-exemption RED output is pasted into the PR.
- [ ] The synthetic dead-path test passes.
- [ ] The non-vacuity assertion (paths resolved from non-exempt docs > 0) is present.

---

### ARCH-7a — M2 instrument: slot-phase-0 start-offset histogram

- **Points:** 2 · **Scope:** 1 day · **Type:** feature · **Priority:** P0 · **Stream:** B
- **Blocked by:** — · **Blocks:** ARCH-7b, ARCH-7c
- **Requirements:** **M2** (PRD *Success Metrics*; plan D10) · **Constraints:** C6, C7 (both forward-looking)

**Context.** M2 is *"p99 offset from slot start to entry of `maybe_propose_block`"*, and **no
instrument exists at HEAD**. The nearest thing is the `slot.phase.block` span
(`crates/rvc/src/orchestrator/coordinator/mod.rs:404`), which measures the phase's **duration**, not
its **offset from slot start** — it cannot answer M2 (A-E6). Phase 3 (ADR-004) is judged against this
number, so building it is a Phase-0 *entry* obligation for that phase, not a follow-up. **Do not fix
the ordering here** — this issue only measures it.

**Implementation approach.**

- Add a histogram `rvc_slot_phase_block_start_offset_ms` in `crates/metrics/src/definitions.rs`
  (the existing — and per the review, over-centralised — definitions module; Phase 6 decentralises
  it, so follow today's pattern rather than inventing a second one now).
- Record it in `coordinator/mod.rs` immediately before `maybe_propose_block` at `:405`, computed as
  `now − slot_start`, where `slot_start` comes from the existing `timing` slot clock. The measurement
  point sits **after** the two unconditional `fetch_epoch_duties` calls (`:376-383`) and the
  epoch-boundary block (`:386-397`) — which is exactly what makes the baseline large and the number
  meaningful.
- Add a `cache` label with values `warm` / `cold`, where cold = first slot after boot **or** the slot
  after a `key_gen` invalidation (`apply_key_gen_cache_invalidation`, `:373`). Without this label the
  cold-cache half of C6's Phase-3 budget (500 ms) has no baseline (C6 discharge).
- Buckets must span the full 12 s slot (the baseline is expected to be *bad*, potentially tens of
  seconds under stall) — a histogram clipped at 1 s would silently record the target instead of the
  truth.
- **C7:** neither the metric name, the label set nor the doc comment may imply that a dropped SSE
  head event is an error.

**Exact files to touch.** `crates/metrics/src/definitions.rs`,
`crates/rvc/src/orchestrator/coordinator/mod.rs` (measurement point only — **no reordering**).

**TDD test plan.**

- **RED first:** `test_slot_phase_block_start_offset_is_recorded_each_slot` — drive one slot through
  the existing coordinator test harness (`crates/rvc/src/orchestrator/coordinator/tests/`) and assert
  the histogram's sample count is 1 and the observed value is `>= 0`. It fails first because the
  metric does not exist.
- **Second RED:** `test_offset_reflects_pre_proposal_work` — with a mock BN delaying duty fetches by
  a known `D`, assert the recorded offset is `>= D`. This is the assertion that makes the instrument
  *credible*: it proves the metric captures the ordering defect rather than a constant.
- **Third:** `test_offset_labels_cold_after_key_gen_invalidation` — assert `cache="cold"` on the slot
  following a `key_gen` bump.
- **KAT note:** none of these tests may be named with a `_root` suffix (see the KAT section);
  `_offset_ms` naming is required.

**Acceptance criteria.**

- [ ] `rvc_slot_phase_block_start_offset_ms` is defined, documented, and exposed on `/metrics`.
- [ ] One sample per slot, labelled `warm`/`cold`, with cold covering post-boot **and**
      post-`key_gen`-invalidation slots.
- [ ] Buckets span ≥ 12 s; the recorded p99 is not clipped by the top bucket at baseline.
- [ ] `test_offset_reflects_pre_proposal_work` passes with an injected delay.
- [ ] **No reordering of the slot loop** — `git diff` shows only the added measurement, and the two
      `fetch_epoch_duties` calls at `:376-383` are untouched (that is ADR-004's work, Phase 3).
- [ ] No test name ends in `_root`; `kat_policy.rs` `EXEMPTIONS` is unchanged.

---

### ARCH-7b — M1 harness: latency-injecting BN mock + missed-proposal measurement

- **Points:** 3 · **Scope:** 2 days · **Type:** feature · **Priority:** P0 · **Stream:** B
- **Blocked by:** ARCH-7a · **Blocks:** ARCH-7c
- **Requirements:** **M1** (PRD *Success Metrics*; plan D10) · **Constraints:** **C6** (enabling), C7

**Context.** M1 is *"missed-proposal rate under injected BN latency (6 × 10 s duty-fetch stall, warm
and cold cache)"*. It **does not exist** and, per **VD-P2** (re-confirmed here), cannot be adapted
from the two existing benches: `crates/rvc/benches/per_slot.rs:1-16` and
`crates/signer/benches/sign_path.rs` are *logging-latency* benches under three subscriber regimes,
whose own headers say they are **"NOT run under `nextest`/CI"**. This is a new build — the largest
single reason Phase 0 is under-sized upstream (VD-E8).

**Implementation approach.**

1. New integration test `crates/rvc/tests/proposal_under_duty_stall.rs`, alongside the existing
   `crates/rvc/tests/` suite (11 files; `sync_independent_of_attesting.rs` is the closest structural
   model).
2. A BN mock with **per-endpoint latency injection** — a configurable delay applied to the duty
   endpoints only, so `get_block_root` / proposal submission stay fast and the measured miss is
   unambiguously attributable to the pre-proposal ordering.
3. A deterministic slot clock (`timing`'s basis-point deadline model) so the run is reproducible and
   not wall-clock flaky.
4. Measure across ≥ 32 slots per condition: **stall ∈ {0 s, 10 s, 60 s} × cache ∈ {warm, cold}**,
   recording missed-proposal count and the ARCH-7a offset histogram for the same run.
5. **Forward-compatibility constraint (RP6).** The orchestrator is `!Send` until Phase 2 removes
   `?Send` from `BeaconBlockClient` (`crates/block-service/src/traits.rs:13`), so this harness must
   drive it via the same `LocalSet`/`spawn_local` scaffold used at
   `crates/rvc/tests/sync_independent_of_attesting.rs:269-273`. **Isolate that in a single
   `drive_orchestrator()` helper**, because ADR-002 deletes the scaffold in Phase 2 and the swap to a
   bare `tokio::spawn` must be a one-function change, not a rewrite of the harness Phase 3 depends on.
6. **Scope discipline (A-E9):** the deliverable is the instrument plus a *bad* baseline (~100 % miss
   with a stalled fetch, by construction). Nothing in this issue may reorder the slot loop.

**Exact files to touch.** `crates/rvc/tests/proposal_under_duty_stall.rs` *(new)*,
`crates/rvc/Cargo.toml` (dev-dependencies only, if the mock needs `wiremock`).

**TDD test plan.**

- **RED first:** `test_proposal_is_missed_when_duty_fetch_stalls` with a 60 s injected stall must
  **fail the assertion `missed == 0`** — the failure *is* the M1 baseline finding, and it is recorded
  rather than fixed. Convert it immediately into a recording form
  (`test_records_missed_proposal_rate_under_stall`, asserting only that a rate was measured and
  written) so the suite is green on `develop` while the number lives in ARCH-7c's file. **Do not
  merge a knowingly-failing test** (ADR-012's standard); the RED output goes in the PR.
- **Control:** `test_no_missed_proposal_without_stall` — with 0 s injection, `missed == 0`. This is
  what proves the harness measures the ordering defect and not itself.
- **Cold cache (C6):** `test_cold_cache_slot_is_measured_separately` — the post-`key_gen`-invalidation
  slot is attributed to the `cold` condition.
- **KAT note:** the harness handles block roots via `get_block_root`; **no test or helper may be
  named with a `_root` suffix** (`kat_policy.rs`'s name scan). Use `..._miss_rate`,
  `..._under_stalled_duty_fetch`. If a `_root` name is unavoidable, add `// kat_exempt: <reason>` —
  never an `EXEMPTIONS` entry.

**Acceptance criteria.**

- [ ] The harness runs under `cargo nextest run --workspace` and is deterministic (10 consecutive
      runs, same verdict) — flakiness here would poison every Phase-3 judgement.
- [ ] Latency injection is per-endpoint and configurable; duty endpoints only.
- [ ] Both cache conditions (warm, post-boot cold, post-`key_gen` cold) are measured.
- [ ] The zero-stall control asserts `missed == 0`.
- [ ] `drive_orchestrator()` is the **single** site containing `LocalSet`/`spawn_local`, with a
      comment naming ADR-002 as its removal trigger.
- [ ] The RED baseline output (~100 % miss at 60 s stall) is pasted into the PR and handed to ARCH-7c.
- [ ] The slot loop is **not** reordered; no test name ends in `_root`.

---

### ARCH-7c — Record the M1/M2 baselines as files in `plan/architecture-2026-08-12/`

- **Points:** 1 · **Scope:** 0.5 day · **Type:** chore · **Priority:** P0 · **Stream:** B
- **Blocked by:** ARCH-7b · **Blocks:** *(Phase 3's entry criteria)*
- **Requirements:** **M1**, **M2** (plan D10) · **Constraints:** NFR-1 (supplies its baseline)

**Context.** The milestone requires the numbers to exist as **files in this plan directory**, not in
a CI log that expires. Phases 3 and 5 are judged against them, and NFR-1 ("no latency regression on
the per-slot deadline path") is unfalsifiable without them. The plan mandates the recording but names
no path — resolved by **A-E8**.

**Exact files to touch (new).**

- `plan/architecture-2026-08-12/measurements/m1-missed-proposals.md`
- `plan/architecture-2026-08-12/measurements/m2-slot-phase0-offset.md`
- `plan/architecture-2026-08-12/measurements/README.md` (how to re-run, one command per metric)

**Implementation approach.** Each file records: the harness commit SHA; the exact command; hardware
and toolchain; injected-latency profile; cache condition; sample count; **raw percentiles p50/p90/p99
plus min/max** (not just p99 — a single percentile hides bimodality between warm and cold); and a
one-paragraph interpretation stating what the number means and which requirement it gates. M1's file
must state explicitly that ~100 % miss under stall is **expected at baseline** and is ADR-004's
target (A-E9), so a later reader does not mistake it for a Phase-0 failure.

**TDD test plan.** No production code; the "test" is reproducibility.

- **RED:** hand `measurements/README.md` to a second person (or run in a clean clone) and re-run both
  measurements. If the numbers do not land within a stated tolerance band, the README is incomplete —
  fix the README, not the number.
- **GREEN:** two independent runs agree within the stated tolerance, and both are recorded.

**Acceptance criteria.**

- [ ] Both files exist, are non-empty, and are committed to `plan/architecture-2026-08-12/`.
- [ ] Each records harness commit, command, environment, latency profile, cache condition, sample
      count and p50/p90/p99/min/max.
- [ ] M1's file states that the bad baseline is expected and names ADR-004 (Phase 3) as its owner.
- [ ] M2's file records **separate** warm and cold p99 values, so Phase 3's 1,000 ms / 2,000 ms
      targets (A-5) are each individually falsifiable.
- [ ] A second, independent run reproduces both within the stated tolerance.

---

### ARCH-8 — Healthz deprecation notice + probe-migration check (no removal)

- **Points:** 1 · **Scope:** 0.5 day · **Type:** chore · **Priority:** P1 · **Stream:** B
- **Blocked by:** — · **Blocks:** ARCH-P1-16b (Phase 7), by **≥ 1 release**
- **Requirements:** ARCH-P1-16a · **ADR:** ADR-014 · **Constraints:** **C8 (binding)**

**Context.** The healthz-only tonic server occupies a top-level `select!` arm and serves nothing but
a health check — but removing it is **operator-visible**: a k8s liveness/readiness probe or an
external monitor may target the gRPC endpoint. C8 requires one release of deprecation warning first.
**This is the one dependency in the initiative measured in *releases*, not days** — which is exactly
why a half-day issue sits in Phase 0 rather than travelling with the removal in Phase 7. Shipping it
late costs a whole release cycle at the far end.

**Verified detail.**

- The server is constructed at `crates/rvc/src/bootstrap/run.rs:260-276`: address at `:260-262`,
  `DutyTrackerService::new()` at `:263`, `info!(addr = %grpc_addr, "Starting gRPC server")` at `:265`,
  `DutyTrackerServer` registered at `:267`, `serve_with_shutdown` at `:268-276`.
- **Replacement, verified and corrected (VD-E2):** `crates/metrics/src/server.rs:58-65`
  (`create_metrics_router_with_health`) registers **four** routes — `/metrics` (`:60`), `/health`
  (`:61`), **`/livez` (`:62`)** and **`/readyz` (`:63`)** — served by `serve_metrics_with_health`
  (`:96-110`). The k8s-relevant pair is **`/livez` + `/readyz`**; VD-P3 named only `/health`, which
  maps to neither probe kind. The deprecation note must name `/livez` and `/readyz` explicitly.

**Implementation approach.**

1. A startup `warn!` emitted next to the existing `info!` at `run.rs:265`, stating: the gRPC healthz
   endpoint is deprecated; it will be removed in a future release (ARCH-P1-16b); migrate liveness
   probes to `/livez` and readiness probes to `/readyz` on the metrics server; the metrics port knob
   is the one to point them at.
2. A release note in `docs/releases/UNRELEASED.md` with the same content plus a copy-pasteable k8s
   probe snippet.
3. A **probe-migration check**: a short operator-facing checklist in the release note — *does any
   probe, monitor or load balancer target the gRPC port?* — since **VD-A3 remains unverified and is
   unverifiable from inside this repo**; the deprecation window *is* the discovery mechanism, and the
   note should say so rather than implying the question was answered.
4. **No removal, no knob change.** `grpc_address` / `grpc_port` keep working exactly as today;
   disposing of them is ARCH-P1-16b's job (Phase 7).

**Exact files to touch.** `crates/rvc/src/bootstrap/run.rs` (one `warn!`),
`docs/releases/UNRELEASED.md`.

**TDD test plan.**

- **RED first:** `test_startup_warns_that_grpc_healthz_is_deprecated` — a captured-subscriber test
  asserting a `WARN` event is emitted during bootstrap whose message names **both** `/livez` and
  `/readyz`. It fails first because no such event exists.
- **Guard:** `test_grpc_healthz_still_serves_after_deprecation_warning` — the endpoint still answers.
  A deprecation that silently disables the thing it deprecates is the failure mode C8 exists to
  prevent; assert against it now, while the code is fresh.

**Acceptance criteria.**

- [ ] A `WARN` is emitted at startup naming the deprecation, `/livez` and `/readyz`.
- [ ] The gRPC healthz endpoint **still works** — asserted by test, not by inspection.
- [ ] `docs/releases/UNRELEASED.md` carries the note, the endpoint pair and the probe-migration
      checklist, and states that no probe dependency has been verified from inside the repo (VD-A3).
- [ ] `grpc_address` / `grpc_port` behaviour is unchanged.
- [ ] The note ships in the release that closes Phase 0 — **this is what starts C8's clock**, and the
      release date is recorded in the issue so Phase 7's `≥ 1 release` precondition is auditable.

---

### ARCH-9 — Stale doc comments + the `signer-registry` shipped-fix TODO

- **Points:** 1 · **Scope:** 0.5 day · **Type:** chore · **Priority:** P2 · **Stream:** B
- **Blocked by:** ARCH-3 (invalidates the `sync-service` references) · **Blocks:** —
- **Requirements:** ARCH-P2-9 · **Constraints:** **C1, C2, C5 (all negative — files this issue may not open)**

**Context.** Comment rot is how a repo starts lying at a smaller scale than a shadow tree. This is
the tail item, deliberately last, and it is **fenced**: a doc-comment sweep is precisely the kind of
"harmless" change that can collapse a load-bearing distinction, so the files it must not touch are
enumerated before the ones it must.

**Do-not-open list (binding).**

| File | Why |
|---|---|
| `crates/slashing/src/stage.rs` | **C1.** Phase 1's 1A requires `git diff -- crates/slashing/src/stage.rs` to be **empty**; Phase 5 re-pins it (A-12) |
| `crates/slashing/src/scoped.rs` | **C2.** The misleading note at `:70-74` is ADR-006's to replace, deliberately, as part of moving audit-log emission out of the mutex — fixing the comment now would remove the marker Phase 1 navigates by |
| `crates/signer/src/core.rs` | **C1.** The cancellation-proof core is C9 anchor 2; no cosmetic diff |
| `crates/doppelganger/src/traits.rs` | **C5.** The `cancel_monitoring → stop_monitoring` trait default at `:79-88` is the exact trap G-6 exists to gate. A "clarifying" comment edit here is how the distinction gets collapsed. Phase 7 owns it |

**In-scope work, verified.**

1. **`crates/signer-registry/src/lib.rs:145-146`** — `// TODO(SS-2/SS-3, Phase 4): reclassify
   aggregate as non-slashable once the SignAggregateAndProof path is fixed to not stage attestation
   slashing records.`, sitting above the `SignAggregateAndProof` entry (`:147-153`, currently
   `MessageKind::Aggregate` / `GateRouting::Gated`).
   **First task is verification (PRD A-11):** does the `SignAggregateAndProof` path still stage an
   attestation slashing record? Three outcomes, decided in advance so the issue cannot stall:
   - *Fix has shipped* → the TODO is stale; **delete the TODO only**, and file the reclassification
     (`Gated` → `NonSlashable`) as a **follow-up for Phase 5/7**. **Phase 0 changes no signing
     classification** — that is a behaviour change on a signing surface and would touch C9 anchor 5.
   - *Fix has not shipped* → the TODO is live and **stays**, but must be disambiguated (below).
   - *Undeterminable in half a day* → record the finding, disambiguate the reference, stop.
   **Disambiguation is required either way:** "Phase 4" in that comment refers to a *different*
   initiative's phase numbering and now collides with **this** plan's Phase 4 (config consolidation).
   Rewrite it to name the owning initiative explicitly.
2. **`crates/eth-types/src/sync_committee.rs:134`** — `/// both \`sync-service\` and the orchestrator
   (F99 / RF3-20)`. ARCH-3 deletes that crate, so this doc comment becomes false the moment ARCH-3
   lands. Update it to name the orchestrator alone. **This is the dependency edge on ARCH-3.**
3. **`crates/rvc/src/orchestrator/sync_committee.rs:840`** — `// Ported from the deleted
   \`sync-service\` twin suite`. Note the direction: this comment is **stale today** (it claims a
   deletion that has not happened) and **becomes accurate** after ARCH-3. **No edit required** —
   record the finding rather than churning the line.

**TDD test plan.** Comment-only changes have no runtime behaviour, so the guard is mechanical:

- **RED (already available):** ARCH-6's docs-freshness scan covers `docs/`, not source comments. Run
  `rg 'sync-service' crates bin --glob '*.rs'` **after** ARCH-3 lands: the pre-fix output is the RED
  evidence and must list `crates/eth-types/src/sync_committee.rs:134`. Post-fix it must list only
  `crates/rvc/src/orchestrator/sync_committee.rs:840` (accurate) and nothing in
  `crates/architecture-tests/src/lib.rs` (removed by ARCH-3, both sites — VD-E9).
- **GREEN:** `cargo doc --workspace --no-deps` builds without new warnings; `cargo nextest run
  --workspace` unchanged.

**Acceptance criteria.**

- [ ] The `signer-registry` TODO's premise is **verified** and the verdict recorded in the issue body.
- [ ] The TODO is either deleted (fix shipped) or retained with the initiative-disambiguated
      reference; **no `GateRouting` / `MessageKind` value is changed in this phase**.
- [ ] `crates/eth-types/src/sync_committee.rs:134` no longer references `sync-service`.
- [ ] The `sync_committee.rs:840` finding is recorded, and the line is **not** edited.
- [ ] `git diff` touches **none** of the four do-not-open files.
- [ ] `cargo nextest run --workspace` and `cargo doc --workspace --no-deps` are clean.

---

## Points roll-up and the estimate gap

| Stream | Issues | Points | Implied days (0.5–1 d/pt) |
|---|---|---|---|
| **A** — archive/delete/gates/CI/workspace | 1a, 1b, 2a, 2b, 3, 4, 5, 6 | **13** | 8–13 |
| **B** — measurement, deprecation clock, doc tail | 7a, 7b, 7c, 8, 9 | **8** | 5–8 |
| **Total** | **13 issues** | **21** | **13–19 (1 dev)** · **8–13 (2 dev)** |

**Against the project plan's 7–11 d: this breakdown is 13–19 d, a gap of ~6–8 days.** Per house rule
the gap is **stated, not retrofitted downward** (**VD-E8**). Its three drivers are counted, not
asserted: **ARCH-2b** is a transitive module-graph walker with `#[path]` resolution (3 pts) where the
plan's "two detectors" phrasing implies symmetry with the ~1-pt D1; **ARCH-7a + 7b** are new builds
totalling 5 pts because no reusable harness exists (VD-P2, re-confirmed); and **ARCH-6** is a gate
with an exemption mechanism rather than tail hygiene (VD-E3). If the phase must be compressed, the
only safe cut is **deferring ARCH-9 (1 pt)** — every other issue is either a milestone component, a
dependency of a later phase's entry criteria, or the release-clock start (ARCH-8), which is the one
item whose deferral cannot be recovered by effort.
