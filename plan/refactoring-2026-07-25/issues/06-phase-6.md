# Phase 6: Structure, tests & docs (Themes G remainder + H)

> The last phase of `plan/refactoring-2026-07-25/refactoring-plan.md`. Deliberately last: file splits and test relocation
> create merge conflicts with every earlier phase, so every issue here assumes Phases 1–5 have landed.
> Nothing in this phase changes production behaviour except **RF6-06** (blob-commitment error contract)
> and **RF6-31** (PubkeyMap key type + a duty-index lookup that stops being quadratic).
>
> Authoritative inputs: [`../refactoring-plan.md`](../refactoring-plan.md) §3 Themes G/H, §4 Phase 6,
> §6 Validation Strategy; [`../refactoring-findings.json`](../refactoring-findings.json) F5, F6, F8,
> F10, F11, F17, F23, F33, F46, F60, F65, F67, F80, F81, F83, F86, F87, F95, F103, F109, F112, F113,
> F121–F123, F129.
> All file:line references re-verified against HEAD `develop` (`a7f8cdf`) on 2026-07-25.

## Phase Overview

- **Goal:** navigable files (no god-file above ~40% test lines), one mock per concept, SSZ container
  definitions that cannot drift from their encoders, and an ARCHITECTURE.md that regenerates instead of
  rotting.
- **Issue count:** 32 issues, 78 points.
- **Estimated duration:** ~43–66 days single-stream; ~22–34 days with 2 developers on the two streams
  below (Stream A 42 pts, Stream B 36 pts). Points-to-days follows the template: 1 pt ≈ 0.5–1 day,
  2 pts ≈ 1–1.5 days, 3 pts ≈ 1.5–2 days, including coding, tests, and review.
- **Entry criteria:** Phases 1–5 merged to `develop`; workspace green on the standing invariant
  (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo nextest run --workspace`, `cargo test -p architecture-tests`).
- **Exit criteria (phase gate):**
  - [ ] `coordinator.rs`, `beacon/client.rs`, `bn-manager/manager.rs`, `keymanager-api/handlers.rs`,
        `block-service/service.rs`, `rvc-signer/http_api/routes.rs` each **< 40% test lines**
        (line-count report attached to the phase-closing PR).
  - [ ] **Test-count proof:** for every relocation PR, `cargo nextest list --workspace | wc -l` recorded
        before and after; the diff is 0, or every non-zero delta is itemised in the PR body
        (`ported` / `merged-duplicate` / `deleted-with-dead-code`). No test deleted without a ported
        equivalent.
  - [ ] eth-types: `EXTERNAL_*_ROOT_HEX` KATs byte-identical before and after G1/G2; zero
        `impl_ssz_container!` invocations remain that restate a field list written elsewhere.
  - [ ] `cargo test -p architecture-tests` green **including** the new `doc == generated` test;
        ARCHITECTURE.md crate count matches `cargo metadata`.
  - [ ] Workspace green on the standing invariant.

## Assumptions (verified against HEAD, 2026-07-25)

- **A1 — SEC-6 typed-SSZ bodies have LANDED, not in flight.** `git log -- crates/eth-types/src/block_body.rs`
  shows `8538afe` (spike) → `f9b5962` (typed Electra body + decode) → `5505748` (typed body leaf for
  proposal roots) → `2493c3a` (Deneb + blinded coverage), i.e. SEC-6a–d from
  `plan/security-2026-07-18/issues/00-summary.md:50-53` are complete on `develop`. **G1/G2 therefore
  rebase on landed work rather than serialising behind an in-flight branch.** The plan's "coordinate with
  SEC-6" note is still honoured as a *KAT* obligation (RF6-01/02/03/04 must leave
  `EXTERNAL_ELECTRA_BODY_ROOT_HEX`, `EXTERNAL_DENEB_BODY_ROOT_HEX`,
  `EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX`, `EXTERNAL_DENEB_BLOCK_ROOT_HEX` and their block-level
  siblings unchanged), not as a scheduling constraint.
- **A2 — every `impl_ssz_container!` struct carries the identical derive line and *no* serde
  attributes.** All 30 macro'd structs in `block_body.rs` are
  `#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]`; `grep serde crates/eth-types/src/block_body.rs`
  returns nothing. G1's macro needs no arbitrary-attribute passthrough, which removes the
  silent-breakage risk (a lost `TreeHash` derive fails to compile; a lost serde attr would not).
- **A3 — `block_body`'s twin types have zero external importers.** `grep -rn "block_body::" crates bin`
  outside `crates/eth-types/` returns **0 hits**. Downstream code reaches the module only through the
  `lib.rs:34-55` re-export list, which exports the *body/payload* types and the decode/KAT helpers —
  **not** the eight twins (`Checkpoint`, `AttestationData`, `BeaconBlockHeader`, `DepositData`,
  `VoluntaryExit`, `SignedVoluntaryExit`, `Attestation`, `AttestationElectra`). G3's blast radius is
  therefore internal to eth-types.
- **A4 — `bin/rvc` has no lib target; `bin/rvc-signer` does.** `bin/rvc/Cargo.toml` declares only
  `[[bin]]`, so `bin/rvc/tests/*` genuinely cannot reach `main.rs` (F17). `bin/rvc-signer/Cargo.toml:13`
  declares `[lib] name = "rvc_signer_bin"`, so `bin/rvc-signer/tests/*` *can* import the crate — but only
  its `pub` surface.
- **A5 — test-module proportions at HEAD** (production ends / file total / test share):

  | File | prod ends | total | test share |
  |---|---:|---:|---:|
  | `crates/rvc/src/orchestrator/coordinator.rs` | 743 | 5711 | 87% (80 tests, 124 wiremock refs) |
  | `crates/beacon/src/client.rs` | 1311 | 5357 | 76% (127 tests, wiremock) |
  | `crates/keymanager-api/src/handlers.rs` | 979 | 4181 | 77% (101 tests, no wiremock) |
  | `crates/block-service/src/service.rs` | 567 | 3567 | 84% (90 tests, 3 beacon mocks) |
  | `crates/bn-manager/src/manager.rs` | 1401 | 3716 | 62% (93 tests, wiremock) |
  | `crates/rvc/src/keymanager_adapters.rs` | 1074 | 3028 | 64% (82 tests) |
  | `bin/rvc-signer/src/http_api/routes.rs` | 331 | 1881 | 82% (57 tests) |
  | `bin/rvc-signer/src/http_api/tls.rs` | 435 | 1097 | 60% (29 tests) |

- **A6 — `crates/slashing/src/db.rs` is NOT in scope here.** The plan assigns its split and test move to
  **E2 (Phase 4)**. Phase 6 inherits it already split.

### Stale citations found while grounding (report these upstream)

- **F81** says `impl_ssz_container!` is invoked **24×**; HEAD has **30** (SEC-6 added the Deneb and
  blinded body variants). Points for RF6-01/02 are sized against 30.
- **F121** says `coordinator.rs` is **4,081 lines**; HEAD is **5,711**. The REVIEW.md target ("under
  2,000 lines") is measured against production lines, of which there are 743 at HEAD — the *test* module
  is what makes the file unreadable, which is why RF6-09 precedes every coordinator production split.
- **Crate count is a three-way disagreement:** `ARCHITECTURE.md:3` says 23 crates (3 bin + 20 lib),
  F109 says 26, and `Cargo.toml` `members` has **25**. RF6-23's generator must take `cargo metadata` as
  the baseline, and the number is a moving target within this programme: C1 (+observability),
  C4 (+signer-proto), C5 (+web3signer-wire) in Phase 3, F2 (+signer-server) in Phase 5, RF6-14
  (+rvc-test-support) and RF6-24 (−propagator) here. That is precisely the argument for generating it.

## The H1 relocation rule (read before touching any test module)

Moving an inline `#[cfg(test)]` module to a crate-level `tests/` directory converts it from a *child
module with full private access* into an *external crate consumer*. That is only a pure move when the
suite already runs against the crate's public surface. The rule, applied per file:

> **In-source submodule directory** (`src/<thing>/tests/*.rs`, `#[cfg(test)] mod tests;`) when the suite
> touches non-`pub` items — this is a pure move, `git diff -M` shows renames, and no visibility changes.
> **Crate-level `tests/`** only when the suite compiles unchanged against the public surface.
> **Never widen `pub` visibility to enable a relocation.** If a handful of unit tests block a
> crate-level move, leave *those* inline and move the rest.

Grounded per target:

| Target | Non-`pub` items the tests touch | Decision |
|---|---|---|
| `beacon/client.rs` | `calculate_backoff` (11 refs), `retry_after_delay` | crate-level `tests/client_http.rs` for the wiremock suite; leave the backoff/parse unit tests inline |
| `bn-manager/manager.rs` | `primary_endpoint` (2), `is_better_block` (11) | crate-level `tests/manager_strategies.rs` for the wiremock suite; leave those 13 inline |
| `keymanager-api/handlers.rs` | none — suite drives `KeymanagerServer::router()` (`server.rs:75`, `pub`) | crate-level `tests/` with one shared `TestApp` harness |
| `rvc/orchestrator/coordinator.rs` | constructs orchestrator internals; `process_slot` is `pub` but the fixtures are not | **in-source** `src/orchestrator/coordinator/tests/*.rs` (F5's own recommendation) |
| `block-service/service.rs` | mocks + `propose_block_with_mode` (`pub(crate)` after E8a's rider) | **in-source** `src/service/tests/*.rs` |
| `rvc-signer/http_api/routes.rs`, `tls.rs` | `pub(crate)` `test_support` + the router builder | **in-source** `src/http_api/routes/tests/*.rs`, `tls/tests.rs` (crate-level would require promoting `test_support` to `pub`) |

`crates/beacon/tests/body_cap_h12.rs:8` was checked as the reference for the crate-level pattern — it
imports only `beacon::{BeaconClient, BeaconClientConfig, BeaconError}`, confirming F60's claim for the
wiremock subset.

**Verification plan shared by every pure-move issue** (RF6-07/08/09/10/11/12/13/18/26/28/32 and the move
commits of the others), so it is not restated per issue: *the relocated suite is its own oracle — it must
pass unmodified.* Each PR records `cargo nextest list -p <crate> | wc -l` before and after, shows
`git diff -M` rendering the change as renames, and states the delta as 0 or itemises it. Any behavioural
delta means the move was not pure and the PR is re-scoped, not patched.

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|-------|-------|----:|------|------------|--------|
| RF6-01 | `ssz_container!` single-field-list macro + 24 sub-containers | 3 | chore | — | A |
| RF6-02 | `ssz_container!` for `ExecutionPayload(Header)` + the 4 body variants | 2 | chore | RF6-01 | A |
| RF6-03 | `impl_container_tree_hash!` + 8 types in aggregation/attestation/sync_committee | 3 | chore | — | A |
| RF6-04 | `BeaconBlock`/`BlindedBeaconBlock` onto the TreeHash macro | 2 | chore | RF6-03 | A |
| RF6-05 | Dual-SSZ exposure mitigation: `Wire*` twins + twin table | 2 | chore | RF6-02 | A |
| RF6-06 | `extract_blob_kzg_commitments` on typed decoders, `Result` contract | 3 | bugfix | RF6-02 | A |
| RF6-07 | beacon `client.rs` wiremock suite → `tests/client_http.rs` | 3 | chore | — | A |
| RF6-08 | bn-manager `manager.rs` wiremock suite → `tests/manager_strategies.rs` | 2 | chore | — | A |
| RF6-09 | coordinator test module → `src/orchestrator/coordinator/tests/` | 3 | chore | — | B |
| RF6-10 | block-service test module split + one capturing beacon mock | 3 | chore | — | B |
| RF6-11 | keymanager-api router tests → `tests/` with shared `TestApp` | 3 | chore | — | A |
| RF6-12 | rvc-signer `routes.rs`/`tls.rs` suites → submodule test files | 3 | chore | — | A |
| RF6-13 | Rename opaque rvc-signer test modules and issue-ID test files | 1 | chore | RF6-12 | A |
| RF6-14 | `rvc-test-support` dev-only crate (rcgen PKI + mTLS harness) | 3 | chore | — | A |
| RF6-15 | `create_test_keystore` behind crypto `test-utils`; delete 4 copies | 2 | chore | — | A |
| RF6-16 | signer `tests/common/mod.rs` fixture; consolidate 13 gate test files | 2 | chore | — | A |
| RF6-17 | duty-tracker: wiremock unit tests → in-memory `BeaconNodeClient` mock | 3 | chore | — | A |
| RF6-18 | bin/rvc tier suites → `crates/rvc/tests` + `crates/bn-manager/tests`; prune | 3 | chore | RF6-08 | B |
| RF6-19 | bin/rvc `main.rs` test module: telemetry tests out, vacuous test deleted | 2 | chore | — | B |
| RF6-20 | Real CLI-level tests (`assert_cmd`/`CARGO_BIN_EXE`) for flags + exit codes | 2 | feature | RF6-18 | B |
| RF6-21 | Mock-fidelity reconciliation with the test-audit track | 1 | chore | RF6-10 | B |
| RF6-22 | KAT-first policy: CI-enforced ban on self-consistency-only root tests | 2 | chore | — | A |
| RF6-23 | ARCHITECTURE.md generated from `cargo metadata` + `doc == generated` test | 3 | feature | — | A |
| RF6-24 | Fold propagator into bn-manager `submit` module; delete the crate | 2 | chore | RF6-08 | B |
| RF6-25 | Break `block-service → builder`; add no-domain→domain FORBIDDEN rule | 2 | chore | RF6-10, RF6-24 | B |
| RF6-26 | `keymanager_adapters/` module dir + shared `KeyChangeNotifier` | 3 | chore | — | B |
| RF6-27 | coordinator `wait_for`/`phase_deadline` helpers + epoch-boundary extraction | 3 | chore | RF6-09 | B |
| RF6-28 | Relocate block-proposal methods to `orchestrator/block_proposal.rs` | 3 | chore | RF6-27 | B |
| RF6-29 | aggregation: `produce_one_aggregate`/`submit_versioned`/`timed()` | 3 | chore | RF6-09 | B |
| RF6-30 | attestation: inner-`Result` fn + collapse Fulu/Electra arms | 2 | chore | — | B |
| RF6-31 | `PubkeyMap` re-key to `[u8;48]` + shared pubkey→index registry (+ perf test) | 3 | perf | RF6-28 | B |
| RF6-32 | Module renames: `duty_tracker`→`grpc_health`; `background_tasks/` | 1 | chore | RF6-26 | B |

**Total: 32 issues, 78 points. Stream A 42 pts (17 issues), Stream B 36 pts (15 issues).**

## Execution Plan

**Stream A — eth-types + the crates Stream B never opens.** `crates/eth-types`, `crates/beacon`,
`crates/bn-manager` (tests only), `crates/keymanager-api`, `bin/rvc-signer`, `crates/crypto`,
`crates/signer`, `crates/duty-tracker`, `crates/architecture-tests`, `ARCHITECTURE.md`, and the new
`rvc-test-support` crate.

**Stream B — `crates/rvc` and everything that edits it.** The coordinator/aggregation/attestation/
adapters splits, `crates/block-service`, `bin/rvc`, plus **both H6 topology issues** — the propagator
fold rewrites `crates/rvc/src/orchestrator/{attestation,coordinator,error}.rs` and `config/builder.rs`,
and the `CircuitBreakerState` move rewrites `coordinator.rs` and `crates/rvc/tests/`, so they are
Stream-B work despite being "architecture" issues.

Files touched by both streams: none. `crates/bn-manager` is the only shared crate — Stream A edits
`manager.rs`'s test module (RF6-08), Stream B adds a *new* `src/submit.rs` (RF6-24) and does not open
`manager.rs`; RF6-24 is nonetheless sequenced after RF6-08 so the crate has one owner at a time.

## Dependency Map

```text
Stream A
  RF6-01 ──▶ RF6-02 ──┬──▶ RF6-05
                      └──▶ RF6-06
  RF6-03 ──▶ RF6-04
  RF6-07    RF6-08(→B: RF6-18, RF6-24)    RF6-11    RF6-12 ──▶ RF6-13
  RF6-14    RF6-15    RF6-16    RF6-17    RF6-22    RF6-23

Stream B  (the critical path)
  RF6-09 ──▶ RF6-27 ──▶ RF6-28 ──▶ RF6-31
     ├──▶ RF6-29
  RF6-10 ──┬──▶ RF6-21
           └──▶ RF6-25 ◀── RF6-24 ◀── (RF6-08)
  RF6-26 ──▶ RF6-32
  RF6-18 ──▶ RF6-20        RF6-19        RF6-30
```

**Critical path:** `RF6-09 → RF6-27 → RF6-28 → RF6-31` (12 pts, ~6–8 days). All four rewrite
`crates/rvc/src/orchestrator/coordinator.rs`; relocating the tests first (RF6-09) drops the file from
5,711 to ~750 lines, which is what makes the three production splits reviewable. This is a hard
issue-ID dependency, not a courtesy note.

## Phase Risk Flags

- **Cross-track collision with `docs/issues/` (test audit).** Its issues **3.10** and **4.1** make
  *additive edits to `coordinator.rs`* (both list it under "Shared File Edits"). Land those before
  RF6-09 or rebase them onto the relocated files — they will conflict.
- **Wasted work if test-audit 2.3/2.4 land after Phase 2.** Those two issues (5 pts) add capture structs
  to `crates/sync-service/src/lib.rs:328`, which **B1 deletes** in Phase 2. Sequence 2.3/2.4 before
  Phase 2 or drop them; RF6-21 assumes they are already resolved one way or the other.
- **`git diff -M` rename detection is the review tool for every H1 issue.** A relocation PR whose diff
  does not render as renames + a `mod` declaration is not a pure move and must be re-scoped.
- **RF6-06 is the only genuine behaviour change in the phase** (malformed body stops looking like an
  empty commitment list). It changes a *signing-adjacent* fingerprint path — release-note it.
- **RF6-31 changes a hot-path data structure.** The perf assertion must be a complexity assertion
  (bounded lookups), not a wall-clock threshold, or it will flake in CI.

---

## Issues

### Issue RF6-01: `ssz_container!` single-field-list macro + 24 sub-containers

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** A
- **Plan item:** G1 · **Findings:** F81
- **Blocked by:** — · **Blocks:** RF6-02

**Files:** `crates/eth-types/src/block_body.rs:104-170` (the macro), and the 24 struct/invocation pairs
between `:250` (`Eth1Data`) and `:603` (`ExecutionRequests`) **excluding** `ExecutionPayload` (`:451`/`:470`)
and `ExecutionPayloadHeader` (`:492`/`:511`), which RF6-02 takes.

**What / why:** `impl_ssz_container!($ty { field: type, … })` restates a field list that was already
written in the struct immediately above it — 30 times. The macro's own doc comment (`:106-107`) concedes
the hazard: "Field order is merkleization- and serialization-sensitive — keep in sync with the struct
definition." Adding or reordering a field in the struct and forgetting the macro call compiles cleanly
and produces a wrong SSZ encoding that only a KAT exercising that field can catch. This issue makes the
divergence unrepresentable by having one macro emit both the struct and the `Encode`/`Decode` impls.

**Implementation sketch:**
1. Add `macro_rules! ssz_container` taking `$(#[$meta:meta])* pub struct $ty { $(pub $field: $ftype,)* }`
   and expanding to the struct definition plus the existing `Encode`/`Decode` bodies verbatim. Per
   **A2**, all 30 structs share `#[derive(Debug, Clone, PartialEq, Eq, TreeHash)]` and carry no serde
   attributes, so a single `$(#[$meta])*` passthrough on the struct covers every case; do not build
   per-field attribute support that nothing needs.
2. Convert the 24 sub-containers one commit at a time (or in typed batches: primitives → attestation
   family → deposit/exit family → request family). Keep the old `impl_ssz_container!` in place until the
   last invocation is gone, then delete it.
3. Leave `Uint256` (`:178`, a newtype with hand-written impls) alone — it is not a container.

**Acceptance criteria:**
- [x] `ssz_container!` defines struct + `Encode` + `Decode` from one field list; the 24 targets use it.
- [x] No field name or type appears twice for any converted container (`rg` proof in the PR).
- [x] Every `EXTERNAL_*_ROOT_HEX` assertion in `block_body.rs`'s test module passes **unchanged** — the
      hex constants are not edited in this PR (grep-diff proof: `git diff` touches no `EXTERNAL_` line).
- [x] Round-trip tests (`test_*_ssz_round_trip`) and sub-container root tests
      (`test_subcontainer_roots_match_external_vector_components`, `block_body.rs:1160`) green.
- [x] `cargo nextest list -p rvc-eth-types | wc -l` unchanged.
- [x] `cargo fmt`/`clippy -D warnings`/`cargo nextest run --workspace` green.

**Test/verification plan:** No new tests — the existing external-vector KATs are the oracle, and their
value is that they were computed by a reference client. Add one *negative* compile-fail check only if
`trybuild` is already a dev-dependency; otherwise skip it (not worth a new dependency).

**Risks:** A `macro_rules!` that emits a struct cannot easily support generic parameters or lifetimes —
none of the 30 targets have any (verified). If one turns out to need `#[serde(...)]` later, the
passthrough already handles struct-level attributes; per-field attributes would need a follow-up.

---

### Issue RF6-02: `ssz_container!` for `ExecutionPayload(Header)` + the 4 body variants

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** A
- **Plan item:** G1 · **Findings:** F81
- **Blocked by:** RF6-01 · **Blocks:** RF6-05, RF6-06

**Files:** `crates/eth-types/src/block_body.rs` — `ExecutionPayload` `:451`/`:470` (17 fields twice),
`ExecutionPayloadHeader` `:492`/`:511`, `BeaconBlockBodyElectra` `:613`/`:629` (13 fields twice),
`BlindedBeaconBlockBodyElectra` `:659`/`:675`, `BeaconBlockBodyDeneb` `:713`/`:728`,
`BlindedBeaconBlockBodyDeneb` `:758`/`:773`.

**What / why:** The six containers whose field order actually determines a signed block root. Split from
RF6-01 so the mechanical bulk lands separately from the six that the block-root KATs pin — a reviewer
should be able to read this diff field-by-field against the consensus-spec containers.

**Implementation sketch:** Convert each pair to `ssz_container!`, deleting the duplicated list. Keep the
hand-written `from_ssz_bytes`/`as_ssz_bytes` inherent wrappers (`:645-655` etc.) — they are the
`BodySszError` boundary, not part of the macro's job. Land as one PR with the six diffs adjacent so the
field lists can be diffed against each other (Electra vs Deneb differ only by `execution_requests`;
blinded differs only by `execution_payload` → `execution_payload_header`).

**Acceptance criteria:**
- [x] All six use `ssz_container!`; `impl_ssz_container!` and its doc-comment warning are **deleted**
      from the file (this is the last consumer).
- [x] `EXTERNAL_ELECTRA_BODY_ROOT_HEX`, `EXTERNAL_DENEB_BODY_ROOT_HEX`,
      `EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX` and the four `EXTERNAL_*_BLOCK_ROOT_HEX` constants are
      untouched and their assertions pass (`test_beacon_block_body_electra_htr_matches_external_vector`
      `:1099`, `test_deneb_body_htr_matches_external_vector` `:1215`,
      `test_blinded_deneb_body_htr_matches_external_vector` `:1227`, and siblings).
- [x] `crates/crypto/tests/typed_signer_local_golden.rs` (golden signing roots over
      `external_vector_electra_body()`) green — this is the cross-crate proof that block roots did not move.
- [x] Test count unchanged; workspace green.

**Risks:** The blinded/full pairs are easy to transpose during a copy-heavy edit. Mitigation: the
`test_full_and_blinded_bodies_have_distinct_roots`-style assertions (`:1240-1243`) already fail loudly on
a transposition; confirm one is present for both fork pairs before starting, and add it if not.

---

### Issue RF6-03: `impl_container_tree_hash!` + 8 types in aggregation/attestation/sync_committee

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** A
- **Plan item:** G2 · **Findings:** F83
- **Blocked by:** — · **Blocks:** RF6-04

**Files:** `crates/eth-types/src/aggregation.rs:37` (`Attestation`), `:74` (`AggregateAndProof`),
`:126` (`ElectraAttestation`), `:163` (`ElectraAggregateAndProof`) and their `try_tree_hash_root` pairs at
`:23`,`:65`,`:111`,`:154`; `crates/eth-types/src/attestation.rs:18` (`SingleAttestation`);
`crates/eth-types/src/sync_committee.rs:43` (`SyncCommitteeContribution`), `:73`
(`SyncAggregatorSelectionData`), `:103` (`ContributionAndProof`).

**What / why:** Eight types hand-implement `TreeHash` with the identical scaffold — `tree_hash_type() ->
Container`, `tree_hash_packed_encoding() -> unreachable!()`, `tree_hash_packing_factor() -> 1`, then a
`MerkleHasher::with_leaves(N)` body writing each leaf with `.expect("valid leaf")` — plus a near-identical
`try_tree_hash_root`/panicking-`tree_hash_root` pairing. ~200 lines in which the only real content is the
ordered leaf list. F122 (AUDIT-2026-05-30 theme 2) records that a wrong Electra field order once shipped
with a green test asserting the bug; concentrating the leaf order in one visible list per type is the
structural half of the fix (RF6-22 is the policy half).

**Implementation sketch:**
1. Add `impl_container_tree_hash!(Ty, N, [ leaf_expr, … ])` in a new
   `crates/eth-types/src/tree_hash_utils.rs` sibling (the `TreeHashError` type already lives there),
   emitting both `try_tree_hash_root() -> Result<Hash256, TreeHashError>` and the `TreeHash` impl whose
   `tree_hash_root` unwraps it with the existing panic message.
2. Leaf expressions stay explicit closures over `&self` so bitlist/`Vec<u8>` helpers
   (`bitlist_tree_hash_root`, `vec_u8_tree_hash_root`) remain visible at each call site — the leaf order
   must stay reviewable, not disappear into a derive.
3. Convert the eight types; delete the scaffold.

**Acceptance criteria:**
- [x] All eight use the macro; no `impl TreeHash for` remains in `aggregation.rs`, `attestation.rs`,
      `sync_committee.rs`.
- [x] Every leaf order is byte-identical to the pre-change implementation, proven by the existing root
      tests — including the ones the test-audit track adds (`docs/issues/phase-3-coverage-correctness.md`
      issue **3.14**, "Add TreeHash tests for sync committee types"). If 3.14 has not landed, say so in the
      PR and treat its absence as a coverage gap, not a blocker.
- [x] `crates/eth-types/src/block_body.rs`'s `Uint256` `TreeHash` (`:190`) is untouched (not a container).
- [x] Test count unchanged; workspace green.

**Risks:** `MerkleHasher::with_leaves(N)` takes a literal leaf count that must match the closure list
length. Make the macro derive `N` from the list length rather than accepting it as a parameter, so the
two cannot disagree.

---

### Issue RF6-04: `BeaconBlock`/`BlindedBeaconBlock` onto the TreeHash macro

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** A
- **Plan item:** G2 · **Findings:** F83
- **Blocked by:** RF6-03 · **Blocks:** —

**Files:** `crates/eth-types/src/block.rs:458` (`impl TreeHash for BeaconBlock`), `:520`
(`BlindedBeaconBlock`), plus the four root entry points `:430` `try_tree_hash_root`, `:438`
`try_tree_hash_root_for_layout`, `:493`, `:500`.

**What / why:** Split from RF6-03 because these two are shaped differently: their body leaf is not a
field root but a `body_tree_hash_root_for_layout(&self.body, layout)` call over raw SSZ bytes, so they
carry a `BodyForkLayout` parameter the other eight do not. Forcing them into RF6-03's macro shape is
where a subtle root change would hide.

**Implementation sketch:** Extend `impl_container_tree_hash!` with a layout-parameterised variant (or
generate only the `TreeHash` scaffold and keep the two `try_tree_hash_root_for_layout` bodies
hand-written — pick whichever leaves the leaf list more readable and say which in the PR). The
non-layout `try_tree_hash_root` delegates to the layout form with the default, exactly as today.

**Acceptance criteria:**
- [x] Both types' 5-leaf order (`slot`, `proposer_index`, `parent_root`, `state_root`, `body_root`) is
      stated once each.
- [x] `EXTERNAL_ELECTRA_BLOCK_ROOT_HEX`, `EXTERNAL_DENEB_BLOCK_ROOT_HEX`,
      `EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX` assertions pass unchanged.
- [x] `crates/crypto/src/remote_signer.rs:298,313` (which call `body_tree_hash_root` /
      `blinded_body_tree_hash_root` on the signing path) compile and their tests pass.
- [x] Test count unchanged; workspace green.

**Risks:** Low. If the layout variant makes the macro contorted, keeping these two hand-written and
closing this issue with "evaluated, rejected, here's why" is an acceptable outcome — record it.

---

### Issue RF6-05: Dual-SSZ exposure mitigation — `Wire*` twins + twin table

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** A
- **Plan item:** G3 · **Findings:** F80
- **Blocked by:** RF6-02 · **Blocks:** —

**Files:** `crates/eth-types/src/block_body.rs` — `Checkpoint:259`, `AttestationData:266`,
`BeaconBlockHeader:282`, `Attestation:340`, `DepositData:388`, `VoluntaryExit:412`,
`SignedVoluntaryExit:419`, `AttestationElectra:374`; module docs at `:1-100`;
`crates/eth-types/src/lib.rs:9,34-55`.

**What / why:** Because `ssz_types 0.10` implements `Encode`/`Decode` only against `ethereum_ssz 0.8`
while the workspace pins `ssz 0.9`, `block_body.rs` redefines eight types that already exist at the crate
root with the same names and different field types. `rvc_eth_types::Checkpoint` and
`rvc_eth_types::block_body::Checkpoint` are distinct types with identical names. Full unification is
**deliberately deferred** (plan §5, blocked on upstream version alignment); this issue removes the
ambiguity without waiting.

**Per A3 the blast radius is internal:** zero files outside `crates/eth-types/` reference `block_body::`,
and `lib.rs`'s re-export list does not include the eight twins. So the rename is confined to one crate.

**Implementation sketch:**
1. Rename the eight to `Wire*` (`WireCheckpoint`, `WireAttestationData`, …). Prefer the rename over
   `pub(crate)`: several are reachable as *fields* of the publicly re-exported body types
   (`BeaconBlockBodyElectra.attestations: VariableList<AttestationElectra, …>`), so `pub(crate)` would
   make a `pub` struct expose a private type.
2. Add a module-level twin table to `block_body.rs`'s docs: each `Wire*` name, its crate-root counterpart,
   the reason both exist (the ssz version split), and the deletion trigger ("delete when `ssz_types`
   compiles against `ethereum_ssz 0.9`; see plan §5").
3. Add a one-line pointer from `lib.rs`'s module docs.

**Acceptance criteria:**
- [x] No type name is defined twice in the `rvc_eth_types` public namespace
      (`cargo doc` search, or an `rg` over `pub struct` names, attached to the PR).
- [x] The twin table names all eight pairs and states the deletion trigger.
- [x] No downstream crate changed (`git diff --stat` touches only `crates/eth-types/`) — if it does, A3
      was wrong and the issue is re-scoped to 3 points.
- [x] Workspace green.

**Risks:** None material. Naming bikeshed is the main cost — `Wire*` is chosen because these are the
encode/decode-facing forms; state it once in the twin table and move on.

---

### Issue RF6-06: `extract_blob_kzg_commitments` on typed decoders, `Result` contract

- **Points:** 3 · **Days:** 1.5–2 · **Type:** bugfix · **Stream:** A
- **Plan item:** G4 · **Findings:** F87
- **Blocked by:** RF6-02 · **Blocks:** —

**Files:** `crates/eth-types/src/block.rs:23` (`DENEB_BODY_FIXED_LEN`), `:27` (`KZG_COMMIT_OFFSET_POS`),
`:30`, `:36`, `:86-137` (the hand parser), `:333` (`BlockContents::…`), `:349`/`:410`
(`kzg_commitment_root`), `:419` (blob count); consumers `crates/eth-types/tests/block_and_blobs_l3.rs`.

**What / why:** `extract_blob_kzg_commitments` re-implements Deneb/Electra body layout by hand — the
392-byte fixed portion, the offset at byte 388, the next-offset bound for Electra — even though SEC-6
landed `decode_beacon_block_body_deneb`/`_electra` (`block_body.rs:805-830`) which already understand
exactly that layout. The constants are now maintained in two places. Worse, **every** failure mode
(truncated body, bad offset, misalignment, over-limit count) returns `vec![]`, indistinguishable from a
legitimately empty commitment list — so `BlockContents::kzg_commitment_root` silently produces the
empty-list fingerprint for a corrupt body. The proposal path already pays for a full typed decode in
`try_tree_hash_root`, so the manual parser saves nothing there.

**Implementation sketch:**
1. **RED:** add a test asserting a truncated/misaligned body yields `Err(BodySszError::…)` and not
   `Ok(vec![])`, and that a genuinely empty commitment list yields `Ok(vec![])`. It fails today.
2. Reimplement as `fn extract_blob_kzg_commitments(body: &[u8], layout: BodyForkLayout) ->
   Result<Vec<[u8; 48]>, BodySszError>` dispatching on `layout` to the typed decoder and returning
   `body.blob_kzg_commitments`.
3. Delete `DENEB_BODY_FIXED_LEN`, `KZG_COMMIT_OFFSET_POS`, `KZG_COMMITMENT_BYTES`,
   `MAX_BLOB_COMMITMENTS_PER_BLOCK` from `block.rs` (the typed containers own those limits now).
4. Propagate: `kzg_commitment_root` and the blob-count accessor become `Result`-returning, or log-and-
   propagate at the one call site each. Decide and document — do **not** re-swallow the error.
5. Port the ~12 existing unit tests at `block.rs:878-1015` to the new signature; the ones that assert
   `vec![]` for malformed input flip to asserting `Err` — that flip **is** the fix and each must be
   reviewed individually, not bulk-edited.

**Acceptance criteria:**
- [x] Signature returns `Result`; malformed body is distinguishable from empty list at every caller.
- [x] The four duplicated offset/limit constants are gone from `block.rs`.
- [x] `crates/eth-types/tests/block_and_blobs_l3.rs` (commitment-substitution detection) still passes —
      the fingerprint value for well-formed input is unchanged.
- [x] Release note drafted: "a corrupt block body now surfaces an error where it previously produced the
      empty-commitment fingerprint."
- [x] Test count: +2 or more (new error-vs-empty cases), each itemised.

**Test/verification plan:** Two oracles pull in opposite directions and both must hold. (a) *Unchanged for
well-formed input:* `crates/eth-types/tests/block_and_blobs_l3.rs`'s commitment-substitution and
determinism assertions must pass with their existing expected values — the fingerprint for a valid body
does not move. (b) *Changed for malformed input:* each of the ~12 unit tests at `block.rs:878-1015` that
currently asserts `vec![]` is reviewed **individually** and flipped to assert a specific `BodySszError`
variant; a bulk find-replace here would hide the case where the hand parser and the typed decoder
disagree about *which* input is malformed. List the 12 with their old and new expectations in the PR.
Add one round-trip test proving a well-formed Electra body's commitments survive the decoder path
identically to the old offset path.

**Risks:** The typed decoder is stricter than the hand parser (it validates the whole body, not just the
commitment region). A body that the hand parser accepted may now error. That is the intended direction
(fail-closed), but it can surface on the proposal path — confirm `block-service`'s propose tests still
pass and note any behaviour delta explicitly.

---

### Issue RF6-07: beacon `client.rs` wiremock suite → `tests/client_http.rs`

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** A
- **Plan item:** H1 · **Findings:** F60
- **Blocked by:** — · **Blocks:** —

**Files:** `crates/beacon/src/client.rs:1312-5357` (the `#[cfg(test)] mod tests`, 127 tests, 159 wiremock
references); new `crates/beacon/tests/client_http.rs`; pattern reference
`crates/beacon/tests/body_cap_h12.rs`.

**What / why:** 76% of a 5,357-line file is an inline test module dominated by `wiremock::MockServer`
integration tests. CLAUDE.md's own convention puts unit tests at the bottom of the file and integration
tests in `tests/` — spinning up an HTTP mock server is squarely the latter. The 38 endpoint methods a
reader actually needs are buried.

**Relocation decision (per the H1 rule):** **crate-level `tests/client_http.rs`** for the wiremock suite,
which drives only the public `BeaconClient` surface. **Leave inline** the unit tests that reach private
items: the 11 `calculate_backoff` tests (`client.rs:1294`, private method) and any `retry_after_delay`
(`:1283`) tests. Do not widen visibility to move them.

**Implementation sketch:**
1. Record `cargo nextest list -p beacon | wc -l` (the baseline).
2. Classify the 127 tests into `wiremock` vs `unit` — a single `rg -n "MockServer::start" ` pass over the
   module gives the split; attach the classification to the PR.
3. `git mv`-style move the wiremock bodies plus their shared helpers into `tests/client_http.rs`,
   adjusting only `use` lines. If a helper is used by both halves, duplicate it into the new file rather
   than making it `pub` (a ~20-line test helper is not worth a visibility change).
4. Re-record the test count.

**Acceptance criteria:**
- [x] `client.rs` is **< 40% test lines** (target: ~1,300 production + a small unit module).
- [x] `crates/beacon/tests/client_http.rs` imports only `beacon::`'s public surface — no `pub` was added
      to `client.rs` in this PR (`git diff` proof: no line matching `^\+.*\bpub\b` in `src/`).
- [x] Test count before == after; any delta itemised.
- [x] `git diff -M` renders the move as renames.
- [x] Workspace green.

**Test/verification plan:** The relocated suite is its own verification — it must pass unmodified. E4
(Phase 4, beacon retry engine) already used this suite as its oracle, so any behaviour delta here would
mean the move was not pure.

**Risks:** Per-test `MockServer` startup in a separate integration binary is slower to link than an
inline module. If wall-clock regresses noticeably, split into two integration files by endpoint family
rather than reverting.

---

### Issue RF6-08: bn-manager `manager.rs` wiremock suite → `tests/manager_strategies.rs`

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** A
- **Plan item:** H1 · **Findings:** F60
- **Blocked by:** — · **Blocks:** RF6-18, RF6-24

**Files:** `crates/bn-manager/src/manager.rs:1402-3716` (93 tests, 109 wiremock references); new
`crates/bn-manager/tests/manager_strategies.rs`; pattern reference `crates/bn-manager/tests/body_cap.rs`.

**What / why:** Same shape as RF6-07 at 62% test lines. The strategy engine (`query_first`/`query_best`/
`broadcast`/`fallback_unsynced`) is what a reader needs and it is buried under 2,300 lines of mocks.

**Relocation decision:** crate-level `tests/manager_strategies.rs` for the wiremock suite. **Leave
inline** the 13 tests that reach private items: `primary_endpoint` (`:224`, 2 refs) and `is_better_block`
(`:792`, 11 refs).

**Acceptance criteria:**
- [x] `manager.rs` < 40% test lines; relocated file imports only the public surface; no `pub` added.
- [x] Test count before == after (baseline recorded with `cargo nextest list -p bn-manager | wc -l`).
- [x] `git diff -M` renders as renames. Workspace green.

**Risks:** E5 (Phase 4) introduced the shared configurable mock in `bn-manager`'s `test-utils` feature;
the relocated suite must consume it rather than re-declaring mocks. Confirm at step 1.

---

### Issue RF6-09: coordinator test module → `src/orchestrator/coordinator/tests/`

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** B
- **Plan item:** H1 · **Findings:** F5, F121
- **Blocked by:** — · **Blocks:** RF6-27, RF6-29 (and transitively RF6-28, RF6-31)

**Files:** `crates/rvc/src/orchestrator/coordinator.rs:744-5711` — one flat `#[cfg(test)] mod tests`
spanning 4,967 lines, 80 tests, 124 wiremock references, mixing timeout, fork-transition, tracing-span,
slashing-integration, circuit-breaker and sync-gating topics, each with its own mock scaffolding.

**What / why:** The file is 87% tests. Every later coordinator change (RF6-27/28/31, and F1's bootstrap
work if it needs a follow-up) is unreviewable until this lands — that is why it heads the critical path.

**Relocation decision:** **in-source submodule directory**, per F5's own recommendation:
`src/orchestrator/coordinator.rs` → `src/orchestrator/coordinator/mod.rs` +
`src/orchestrator/coordinator/tests/{timeouts,fork_transition,tracing,slashing,circuit_breaker,sync_gating,mod}.rs`.
`process_slot` is `pub` (`:706`) but the fixtures construct orchestrator internals, so a crate-level move
would require widening visibility — which the H1 rule forbids. The submodule form is a pure move.

**Implementation sketch:**
1. Record the baseline test count (`cargo nextest list -p rvc | wc -l`).
2. `coordinator.rs` → `coordinator/mod.rs` (production only, ~743 lines), `#[cfg(test)] mod tests;`.
3. `tests/mod.rs` holds the shared mock scaffolding (deduplicated where the six topics had near-copies —
   **any dedup must be a separate commit** so the first commit is a provable pure move).
4. Split the 80 tests into the six topic files by the boundaries F5 names.
5. Replace the struct-level `#[allow(dead_code)]` at `:98` with per-field annotations or field removal —
   it currently hides genuinely unused fields, and it is in the production half this issue is isolating.

**Acceptance criteria:**
- [x] `coordinator/mod.rs` is production-only and **< 800 lines**; no topic test file exceeds ~900 lines.
- [x] Commit 1 is a pure move (`git diff -M` = renames + `mod` declaration); mock dedup, if any, is
      commit 2 with its own justification.
- [x] Test count before == after.
- [x] The struct-level `#[allow(dead_code)]` is gone (per-field or fields deleted).
- [x] Workspace green, including `crates/rvc/tests/sync_independent_of_attesting.rs`.

**Risks:** **Cross-track conflict** — test-audit issues **3.10** and **4.1** both list `coordinator.rs`
under "Shared File Edits". Land them first or rebase; coordinate at kickoff. This is the single most
likely merge-conflict source in the phase.

---

### Issue RF6-10: block-service test module split + one capturing beacon mock

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** B
- **Plan item:** H1 + H2 · **Findings:** F95, F113
- **Blocked by:** — · **Blocks:** RF6-21, RF6-25

**Files:** `crates/block-service/src/service.rs:568-3567` (90 tests, 85% of the file) — an 11-method
`ValidatorSigner` mock at `:606-776` (mostly stubs for duties block-service never signs) and **three**
`BeaconBlockClient` mocks that differ only in what they capture: `MockBeaconClient:778`,
`CapturingBeacon:1403`, `BoostCapturingBeacon:2097`.

**What / why:** Production ends at line 565. Reviewing it means scrolling past 3,000 lines of fixtures,
and drift between the three beacon mocks is already visible (F95).

**Relocation decision:** **in-source** `src/service/tests/{mocks,propose,ssz,boost}.rs` — the tests use
`propose_block_with_mode` (11 refs), which E8a's rider demoted to `pub(crate)`.

**Implementation sketch:**
1. Baseline test count; move to `service/mod.rs` + `service/tests/` (commit 1, pure move).
2. Commit 2: merge the three beacon mocks into one configurable capturing mock. It must retain the
   full-argument capture that test-audit issues **2.1/2.2** installed (`CapturedProduceCall`,
   `CapturedPublishCall`, `CapturedSignBlockCall`) — merging must not regress fidelity. If 2.1/2.2 have
   not landed, merge the mocks as-is and let RF6-21 reconcile.
3. Commit 3: replace the 11-method `ValidatorSigner` stub with the shared one from `signer`'s
   `test-utils` feature (introduced by RF6-16); if RF6-16 has not landed, leave the local stub and note
   the follow-up rather than blocking.

**Acceptance criteria:**
- [x] `service/mod.rs` < 40% test lines (production ~565 lines, no inline test module).
- [x] Exactly one beacon mock in the crate (`rg "impl BeaconBlockClient for" -c` = 1).
- [x] Every assertion that was content-based stays content-based (no capture field dropped).
- [x] Test count before == after; pure-move commit separated from the merge commits.
- [x] Workspace green.

**Risks:** Merging three mocks is where a silently weakened assertion hides. Require the reviewer to diff
the three old mocks' captured fields against the merged one's field-by-field, and say so in the PR
template.

---

### Issue RF6-11: keymanager-api router tests → `tests/` with a shared `TestApp`

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** A
- **Plan item:** H1 · **Findings:** F69
- **Blocked by:** — · **Blocks:** —

**Files:** `crates/keymanager-api/src/handlers.rs:980-4181` (101 tests, 77% of the file); public entry
point `crates/keymanager-api/src/server.rs:75` `pub fn router(&self) -> Router`; new
`crates/keymanager-api/tests/{common/mod.rs, keystores.rs, remotekeys.rs, exits.rs, auth.rs}`.

**What / why:** 4,181 lines of which 3,201 are tests, and F5 (Phase 5) already restructured this file's
production half — leaving it at 77% tests defeats that work.

**Relocation decision:** **crate-level `tests/`**. Verified: the inline suite references **none** of the
file's private helpers (`escape_log_control_chars:801`, `sanitize_internal:815`, `sanitize_item_err:824`,
`parse_pubkey:831`, `zero-gvr helper:842`, `hash_bearer_token:880`, `check_import_keystores_rate:895`)
— it drives the router. This is the cleanest crate-level move in the phase.

**Implementation sketch:**
1. Baseline test count.
2. `tests/common/mod.rs` gets one `TestApp` harness: build `KeymanagerServer` with the trait doubles,
   call `.router()`, expose `TestApp::request(...)` over `tower::ServiceExt::oneshot`. Today each test
   rebuilds this.
3. Split the 101 tests by endpoint family into the four files.
4. If a handful of tests genuinely unit-test a private helper (e.g. `escape_log_control_chars`), leave
   exactly those inline — do not make the helper `pub`.

**Acceptance criteria:**
- [x] `handlers.rs` < 40% test lines; the four `tests/` files import only `keymanager_api`'s public surface.
- [x] One `TestApp` harness; no test rebuilds the router by hand.
- [x] No `pub` added to `handlers.rs`.
- [x] Test count before == after. Workspace green.

**Risks:** F5 (Phase 5) and SEC-1 both rewrote `handlers.rs`; start from HEAD-of-Phase-5, not from the
line numbers in this document, and re-derive the 980 boundary.

---

### Issue RF6-12: rvc-signer `routes.rs`/`tls.rs` suites → submodule test files

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** A
- **Plan item:** H1 · **Findings:** F33
- **Blocked by:** — · **Blocks:** RF6-13

**Files:** `bin/rvc-signer/src/http_api/routes.rs:332-1881` (1,549 test lines = 82%, 57 tests);
`bin/rvc-signer/src/http_api/tls.rs:436-1097` (661 test lines = 60%, 29 tests).

**What / why:** `routes.rs`'s production code is a 330-line island at the top of a 1.9k-line file. The
tests are router-level integration tests (`tower::oneshot` over the full `Router` with a real gate and an
in-memory slashing DB), not unit tests — the "tests at the bottom" convention has scaled past its limit.

**Relocation decision:** **in-source submodule test files** —
`src/http_api/routes/tests/{sign,errors,auth}.rs` and `src/http_api/tls/tests.rs`. The suites use the
`pub(crate)` `test_support` module and the router builder; `bin/rvc-signer` *does* have a lib target
(`[lib] name = "rvc_signer_bin"`, `Cargo.toml:13`) so a crate-level move is mechanically possible, but it
would require promoting `test_support` to `pub` — which the H1 rule forbids. Revisit only if Phase 5's F2
(`crates/signer-server` promotion) exposed a deliberate public test surface; if it did, say so in the PR
and take the crate-level route instead.

**Acceptance criteria:**
- [x] `routes.rs` and `tls.rs` each < 40% test lines.
- [x] No `pub(crate)` → `pub` promotion in this PR.
- [x] Test count before == after (`cargo nextest list -p rvc-signer-bin | wc -l`).
- [x] `git diff -M` renders as renames. Workspace green.

**Risks:** Phase 5's F2 moved this composition root into the lib and split `tls/` into
`tls_config.rs` + `accept_loop.rs`. Re-derive the file layout from HEAD-of-Phase-5 before starting; the
`:436` boundary in `tls.rs` will have moved.

---

### Issue RF6-13: Rename opaque rvc-signer test modules and issue-ID test files

- **Points:** 1 · **Days:** 0.5–1 · **Type:** chore · **Stream:** A
- **Plan item:** H1 · **Findings:** F33
- **Blocked by:** RF6-12 · **Blocks:** —

**Files:** `bin/rvc-signer/src/integration_polish.rs` (706 lines: CLI/TOML precedence, metrics wiring,
hot-reload, binary-spawning); `bin/rvc-signer/src/cross_transport.rs` (151 lines); the issue-ID-keyed
files in `bin/rvc-signer/tests/`: `tonic_limits_m10.rs`, `insecure_flag_h9.rs`, `dvt_sni_pinning_l1.rs`,
`audit_cn_m4.rs`, `audit_log_m5.rs`, `hot_reload_l6.rs`, `m4_enumeration.rs`, `v1_raw_root_bypass.rs`.

**What / why:** Names keyed to audit-issue IDs become opaque once the audit context fades; a reader
cannot tell what `m4_enumeration.rs` covers. `integration_polish.rs` conveys nothing at all.

**Implementation sketch:** `git mv` to behaviour names (`config_precedence.rs` + `cli_startup.rs` for
`integration_polish.rs`; `gate_shared_across_transports.rs` for `cross_transport.rs`;
`grpc_message_limits.rs`, `insecure_flag_refused.rs`, `dvt_sni_pinning.rs`, `client_cn_allowlist.rs`,
`audit_log.rs`, `hot_reload.rs`, `key_enumeration.rs`, `v1_raw_root_bypass.rs` → `raw_root_rejected.rs`).
**Keep the original issue ID in each file's `//!` doc comment** — the traceability is the point of the
old names and must not be lost. Relocate `integration_polish.rs`'s binary-spawning cases to
`tests/cli_startup.rs` using `CARGO_BIN_EXE` (`env!("CARGO_BIN_EXE_rvc-signer")`).

**Acceptance criteria:**
- [x] No test file or `cfg(test)` module name references an audit issue ID; every renamed file's `//!`
      doc comment states the original ID.
- [x] Binary-spawning tests use `CARGO_BIN_EXE`, not a shelled `cargo build` (this is F2's acceptance
      criterion too — verify it held).
- [x] Test count unchanged. Workspace green.

**Risks:** None. Purely nominal.

---

### Issue RF6-14: `rvc-test-support` dev-only crate (rcgen PKI + mTLS harness)

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** A
- **Plan item:** H2 · **Findings:** F113
- **Blocked by:** — · **Blocks:** —

**Files:** duplicated fixtures at `crates/grpc-signer/tests/integration.rs:190` and
`bin/rvc-signer/tests/dvt_sni_pinning_l1.rs:75` (rcgen PKI + `start_mtls_server`); new crate
`crates/rvc-test-support/` (`publish = false`); `crates/architecture-tests/tests/architecture_no_cycles.rs`
(`ZERO_OUT_EDGE_IF_PRESENT` list at `:58`).

**What / why:** The rcgen-based mTLS PKI harness exists twice with no shared home. The workspace already
has the precedent for a dev-only pinned crate: `rvc-signer-registry` is pinned in
`ZERO_OUT_EDGE_IF_PRESENT` per ADR-010 (`architecture_no_cycles.rs:54`).

**Implementation sketch:** New crate exporting `TestPki::new()` (CA + server + client certs),
`start_mtls_server(...)`, and SNI-pinning helpers. Add it to `Cargo.toml` `members` and to
`ZERO_OUT_EDGE_IF_PRESENT` (it must have zero workspace-internal out-edges — it depends only on `rcgen`,
`rustls`, `tokio`). Repoint both consumers via `[dev-dependencies]`; delete the copies.

**Acceptance criteria:**
- [x] `crates/rvc-test-support` exists with `publish = false` and zero workspace-internal dependencies.
- [x] It appears in `ZERO_OUT_EDGE_IF_PRESENT`; `cargo test -p architecture-tests` green.
- [x] `rg "rcgen::" --type rust` outside the new crate returns 0 hits.
- [x] It appears **only** in `[dev-dependencies]` — never a runtime dep of a binary (grep proof).
- [x] Test count unchanged; the two relocated suites pass unmodified.

**Risks:** RF6-23's generated ARCHITECTURE.md must account for the new crate. Sequence the two so the
generator runs after this lands, or accept one regeneration.

---

### Issue RF6-15: `create_test_keystore` behind crypto `test-utils`; delete 4 copies

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** A
- **Plan item:** H2 · **Findings:** F113, F110
- **Blocked by:** — · **Blocks:** —

**Files:** four copies with slightly different signatures at `bin/rvc-signer/src/commands/split_key.rs:172`,
`bin/rvc-signer/src/integration_polish.rs:37`, `bin/rvc-signer/src/backend/basic.rs:178`,
`bin/rvc-signer/src/reload.rs:254`; `crates/crypto/Cargo.toml:40-41` (`test-utils = []` — declared and
**empty**, verified at HEAD).

**What / why:** The natural home already exists and gates nothing. Phase 3's C7 standardised the feature
name to `test-utils`; this issue puts something behind it.

**Implementation sketch:** Add `#[cfg(feature = "test-utils")] pub mod test_utils` to `crypto` with one
`create_test_keystore(password, secret_key) -> (PathBuf, Keystore)` covering the union of the four
signatures (add optional parameters rather than four variants). Add
`crypto = { workspace = true, features = ["test-utils"] }` to the consumers' `[dev-dependencies]`; delete
the copies. If RF6-13 renamed `integration_polish.rs`, coordinate ordering.

**Acceptance criteria:**
- [x] One `create_test_keystore` in the workspace (`rg "fn create_test_keystore" -c` = 1).
- [x] `crypto`'s `test-utils` feature is non-empty and enabled only in `[dev-dependencies]`.
- [x] Test count unchanged; workspace green with and without the feature
      (`cargo check -p rvc-crypto` and `cargo check -p rvc-crypto --features test-utils`).

**Risks:** Low.

---

### Issue RF6-16: signer `tests/common/mod.rs` fixture; consolidate 13 gate test files

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** A
- **Plan item:** H2 · **Findings:** F46
- **Blocked by:** — · **Blocks:** (soft) RF6-10

**Files:** `crates/signer/tests/` — 18 files, of which `gate_attestation_happy_path.rs:19`,
`gate_block_doppelganger_blocked.rs:17`, `gate_attestation_doppelganger_blocked.rs`,
`gate_sync_doppelganger_blocked.rs`, `gate_unknown_pubkey_fails_closed.rs`, `gate_per_validator_lock.rs`,
`gate_sign_timeout.rs`, `gate_aggregate_no_slashing_db.rs`, `log_sampling_disabled.rs`,
`log_sampling_volume.rs` each define their own `AlwaysAllowed`/`AlwaysDenied` `SigningEnablement` and a
near-identical `make_gate*`/`make_signer_with_key` builder; `crates/signer/Cargo.toml:9-13` already ships
`AlwaysEnabled`/`always_enabled()` behind the `test-helpers` feature (`lib.rs:152-169`) that its own
tests never use.

**What / why:** Thirteen copies of the same fixture, while the crate's own helper sits unused. Several
files hold a single test each, paying separate link/compile cost as their own integration binary.

**Implementation sketch:**
1. `tests/common/mod.rs` with the enablement mocks and a `gate_fixture()` builder
   (`KeyManager → LocalSigner → CompositeSigner → SigningGate`), pointed at the crate's existing
   `test-helpers` items (renamed `test-utils` by C7 in Phase 3 — use whichever name HEAD has and say so).
2. Merge the three single-test `gate_*_doppelganger_blocked.rs` files into `gate_doppelganger.rs` and the
   two `log_sampling_*.rs` into `log_sampling.rs`.
3. Also export a stub `ValidatorSigner` behind the feature, so `block-service` (RF6-10) and `builder` stop
   re-stubbing 11 methods each.

**Acceptance criteria:**
- [x] One `AlwaysAllowed`/`AlwaysDenied` definition in `crates/signer` (`rg -c` = 1 each).
- [x] Integration-test binary count drops by ≥ 3; **test count unchanged**.
- [x] The `test-helpers`/`test-utils` items are actually consumed (the dead-helper condition F46 flags is
      resolved, not preserved).
- [x] Workspace green.

**Risks:** `tests/common/mod.rs` is compiled into every integration binary in the crate; keep it small.

---

### Issue RF6-17: duty-tracker wiremock unit tests → in-memory `BeaconNodeClient` mock

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** A
- **Plan item:** H2 · **Findings:** F103
- **Blocked by:** — · **Blocks:** —

**Files:** `crates/duty-tracker/src/tracker.rs:488-1506` (39 tests; `setup_mock_beacon` at `:500-507`
spins a `wiremock::MockServer` + a real `beacon::BeaconClient` for every one); `crates/duty-tracker/Cargo.toml`
(`beacon` and `wiremock` exist as dev-dependencies **only** for this).

**What / why:** The unit under test is pure cache logic behind `Arc<dyn BeaconNodeClient>`. The HTTP layer
adds per-test startup cost and couples duty-tracker's suite to the beacon crate's URL scheme — a URL
change in `beacon` breaks `duty-tracker`'s tests.

**Implementation sketch:** Consume the single configurable mock that **E5 (Phase 4)** exported from
`bn-manager`'s `test-utils` feature; only 3 of its ~25 methods need real bodies
(`get_attester_duties`, `get_proposer_duties`, `get_sync_committee_duties`), the rest error by default.
Rewrite the 39 tests to feed typed `AttesterDutiesResponse`/`ProposerDutiesResponse` values. **Keep 1–2
wiremock round-trips** as explicit `tests/beacon_roundtrip.rs` integration coverage of the beacon+tracker
pair — do not delete the HTTP path entirely. Drop `beacon`/`wiremock` dev-deps if nothing else needs them.

**Acceptance criteria:**
- [x] ≤ 2 wiremock tests remain, in `tests/`, documented as deliberate integration coverage.
- [x] No test in `tracker.rs` constructs a `MockServer`.
- [x] Test count before == after (rewrites, not deletions — each of the 39 has a named successor; attach
      the mapping table to the PR).
- [x] `cargo tree -p duty-tracker -e dev` no longer lists `wiremock` (or the retained dep is justified).
- [x] Workspace green.

**Test/verification plan:** This is a *rewrite*, not a move, so the pure-move oracle does not apply and a
test-count match alone would not prove coverage was preserved. Build a 39-row successor table (old test
name → new test name → what it now drives) and attach it to the PR; a row without a successor is a
deletion and needs the same written justification RF6-18 requires. Verify the rewrite did not weaken
assertions by checking that each new test still asserts on cache *contents*, not just call counts — the
wiremock path made responses explicit, and an in-memory mock makes it easy to accidentally assert less.
Keep the 1–2 retained wiremock tests as the proof that the beacon URL contract itself is still exercised.

**Risks:** If E5's shared mock has not landed, this issue is blocked, not re-scoped — flag it at kickoff
rather than hand-rolling a fourth mock.

---

### Issue RF6-18: bin/rvc tier suites → `crates/rvc/tests` + `crates/bn-manager/tests`; prune

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** B
- **Plan item:** H3 · **Findings:** F17
- **Blocked by:** RF6-08 · **Blocks:** RF6-20

**Files:** `bin/rvc/tests/tier2_safety.rs` (924 lines), `tier3_operations.rs` (978),
`tier4_advanced.rs` (940), `integration_test.rs` (298) — 3,140 lines that import only `rvc::config`,
`rvc::slashing_monitor`, `rvc::startup`, `bn_manager`, `builder`. Tautological cases named by F17:
`tier3_operations.rs:52-55` (`empty_proposer_nodes_returns_none` builds a `Config` with an empty vec and
asserts the vec is empty) and `:37-49` (`proposer_pool_separate_from_main_pool` asserts two hand-set
config fields differ).

**What / why:** `bin/rvc` has **no lib target** (verified: `Cargo.toml` declares only `[[bin]]`), so these
tests cannot reach a single line of `main.rs`. They live one crate away from the code they cover and
force a binary rebuild to run.

**Implementation sketch:**
1. Baseline test count for `bin/rvc` and the receiving crates.
2. Move by *target crate*, not by tier file: everything importing `rvc::` → `crates/rvc/tests/`;
   everything importing `bn_manager::`/`builder::` → those crates' `tests/`. Group into behaviour-named
   files, not `tierN_*` names.
3. Prune the tautological cases in a **separate commit** with a one-line justification each — this is the
   one place in the phase where deleting a test is allowed, and each deletion must be argued, not batched.
4. Leave `bin/rvc/tests/` holding only `metrics_bind_l10.rs` and whatever RF6-20 adds.

**Acceptance criteria:**
- [x] No file in `bin/rvc/tests/` imports `rvc::`, `bn_manager::`, or `builder::` except through the
      spawned binary.
- [x] Move commit is a pure move (test count unchanged); prune commit lists each deleted test with its
      reason (target: the ~4 F17 names, plus any others found — the count is a finding, not a quota).
- [x] Aggregate workspace test count == baseline − (pruned count), and the pruned list is enumerated.
- [x] Workspace green.

**Risks:** Some tier tests may exercise `builder`+`rvc` together and belong in neither crate alone. Put
those in `crates/rvc/tests/` (the crate higher in the dependency graph) rather than duplicating.

---

### Issue RF6-19: bin/rvc `main.rs` test module — telemetry tests out, vacuous test deleted

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** B
- **Plan item:** H3 · **Findings:** F23
- **Blocked by:** — · **Blocks:** —

**Files:** `bin/rvc/src/main.rs:2097-2712` (615-line `#[cfg(test)]` module): RUST_LOG parity tests
`:2672-2711` and `init_tracing` tests `:2325-2350` call only `telemetry::` functions (the comment at
`:2668` concedes they "mirror the rvc-signer parity tests" — a third copy);
`test_init_logging_none_config_returns_none` `:2295-2302` constructs a local `None` and asserts it
`is_none()`; a `SharedBuf` `MakeWriter` test double defined **verbatim twice** at `:2518-2534` and
`:2608-2624`. Destination: `crates/telemetry/tests/`.

**What / why:** After Phase 5's F1 shrinks `main.rs` to CLI-parse-plus-one-call, a 615-line test module
testing another crate is the largest remaining thing in the file.

**Implementation sketch:** Move the telemetry-behaviour tests to `crates/telemetry` as the single home for
both binaries' parity guarantees (and note the rvc-signer copy for a follow-up — do not fix it here).
Delete the vacuous test with its own commit message quoting its own comment ("verified by code review").
Define `SharedBuf` once at test-module scope. Keep only tests that exercise binary-local code: clap
parsing, `build_tracing_config`, `apply_fork_compatibility_result`.

**Acceptance criteria:**
- [x] `main.rs`'s test module holds only binary-local tests; no `telemetry::`-only test remains.
- [x] `SharedBuf` defined once. The vacuous test is deleted with a written justification.
- [x] Test count: baseline − 1 (the vacuous test), all other movements accounted as ports.
- [x] Workspace green.

**Risks:** Re-derive line numbers from HEAD-of-Phase-5 — F1 rewrote `main.rs` wholesale.

---

### Issue RF6-20: Real CLI-level tests (`assert_cmd`/`CARGO_BIN_EXE`) for flags + exit codes

- **Points:** 2 · **Days:** 1–1.5 · **Type:** feature · **Stream:** B
- **Plan item:** H3 · **Findings:** F17
- **Blocked by:** RF6-18 · **Blocks:** —

**Files:** new `bin/rvc/tests/cli.rs`; the startup path in `bin/rvc/src/main.rs` (post-F1).

**What / why:** F17's real finding is not just misplacement — it is that the startup path has **zero**
automated coverage, because the only tests near it cannot reach it. Phase 5's F1 acceptance criteria
already pull forward a startup smoke test; this issue completes the set (flag parsing, `--help`, bad-flag
exit codes, config-file precedence, clean shutdown).

**Implementation sketch:** `assert_cmd`/`escargot` or plain `env!("CARGO_BIN_EXE_rvc")` + `std::process`.
Cover: `--help` exits 0; an unknown flag exits non-zero with a usage message on stderr; an explicit
`--tracing-sample-rate 0.01` survives an env override (F3's Phase-5 behaviour, asserted end-to-end here);
a missing slashing DB refuses to start (fail-closed, per Phase 1); SIGTERM produces a clean exit. Keep
these few and fast — a binary-spawning suite is the slowest thing in CI.

**Acceptance criteria:**
- [x] ≥ 5 CLI-level cases, all spawning the real binary; none shells out to `cargo build`.
- [x] The suite runs in < 30s on a warm target dir (state the measured number in the PR).
- [x] Test count: +N, itemised (these are genuinely new).
- [x] Workspace green.

**Test/verification plan:** These tests *are* the deliverable, so verify they can fail. For each case,
demonstrate the negative in the PR: temporarily break the behaviour (reject a valid flag, remove the
fail-closed slashing-DB check) and paste the failing output, then revert. A CLI test that passes against
a deliberately broken binary is asserting nothing — which is exactly the F17 pattern this issue exists to
end. Also confirm coverage does not overlap Phase 5's F1 startup smoke test: extend it rather than
duplicating it, and say which cases came from where.

**Risks:** Binary-spawning tests are the classic CI flake source. Give every spawn an explicit timeout and
assert on exit status plus a stable substring, never on full stderr text.

---

### Issue RF6-21: Mock-fidelity reconciliation with the test-audit track

- **Points:** 1 · **Days:** 0.5–1 · **Type:** chore · **Stream:** B
- **Plan item:** H4 · **Findings:** F123
- **Blocked by:** RF6-10 · **Blocks:** —

**Files:** `crates/block-service/src/service/tests/mocks.rs` (post-RF6-10);
`docs/issues/phase-2-mock-fidelity.md` issues 2.1–2.4.

**What / why:** **This issue deliberately does not do the mock-fidelity work** — the test-audit track owns
it: issues **2.1/2.2** (block-service capture structs + assertions, 5 pts) and **2.3/2.4** (sync-service,
5 pts). Two things need reconciling instead:

1. **The sync-service half is obsolete.** F123 cites `crates/sync-service/src/lib.rs:328`, but **B1
   (Phase 2)** deletes `SyncService`/`SyncSigner`/`SyncBeaconClient` outright — the mocks those issues
   would fix no longer exist. Confirm and close 2.3/2.4 as superseded.
2. **The block-service half must survive RF6-10's mock merge.** Verify the merged capturing mock still
   captures `CapturedProduceCall{slot, randao_reveal, graffiti, builder_boost_factor}`,
   `CapturedPublishCall{consensus_version, slot, proposer_index, signature_bytes}` and
   `CapturedSignBlockCall{block_root, slot, pubkey, fork_schedule, genesis_validators_root}`, and that
   assertions are on content, not call counts.

**Acceptance criteria:**
- [x] A written reconciliation in the PR: 2.1/2.2 status, 2.3/2.4 marked superseded-by-B1 (or done).
- [x] `rg "assert_eq!\(.*\.len\(\), [0-9]" crates/block-service` reviewed — every count-only assertion is
      either justified or upgraded to a content assertion.
- [x] No mock in `block-service` discards an argument it previously captured.
- [x] Workspace green.

**Risks (flag at programme level, not in this issue):** if test-audit 2.3/2.4 are scheduled *after*
Phase 2, 5 points are spent on code B1 deletes. Sequence 2.3/2.4 before Phase 2 or drop them.

---

### Issue RF6-22: KAT-first policy — CI-enforced ban on self-consistency-only root tests

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** A
- **Plan item:** H5 · **Findings:** F122
- **Blocked by:** — · **Blocks:** —

**Files:** `CLAUDE.md` (Testing section), `ARCHITECTURE.md` (conventions), new
`crates/architecture-tests/tests/kat_policy.rs`.

**What / why:** F122 records three bugs (C-1, C-2, H-9) that each shipped with a **green test asserting
the bug** — `test_electra_attestation_tree_hash_spec_field_order` enforced the wrong field order, and
`compute_block_root == tree_hash_root` is tautological self-consistency. A prose convention would not
have caught any of them, so this issue makes the policy falsifiable rather than documentary.

**Implementation sketch:**
1. Document the rule: every signing-root and container-root test must assert against a vector sourced from
   a reference client or the official consensus-spec tests; self-consistency assertions
   (`a.tree_hash_root() == compute_x(a)`) are never the sole coverage for a spec-defined value.
2. Add a source-scanning test in `architecture-tests` (the crate already scans sources — see
   `no_rvc_prefix.rs`, 184 lines, and `field_name_conformance.rs`, 426 lines): for every test function
   whose name matches `.*(tree_hash|signing_root|_root)$`, require the body to reference a
   `EXTERNAL_*`/`KAT_*`/`SPEC_*` constant or a `#[allow(kat_exempt)]`-style documented exemption marker.
   Seed the exemption list with today's violations so the gate starts green and cannot grow.
3. Add the review-checklist line.

**Acceptance criteria:**
- [x] `cargo test -p architecture-tests kat_policy` green, with an exemption list that is enumerated and
      **shrinking-only** (a comment states that entries may be removed, never added).
- [x] The rule appears in CLAUDE.md's Testing section.
- [x] Workspace green.

**Test/verification plan:** The gate is only as good as its seed, so step 2's discovery pass is the real
work and must be evidenced: enumerate every workspace test matching the name pattern, classify each as
`has-KAT` / `exempt-with-reason`, and attach the table to the PR. Then prove the gate bites by adding a
throwaway self-consistency root test in a scratch commit, showing the failure, and reverting it. Finally,
confirm the seeded exemptions shrink rather than grow: test-audit issue **3.4** ("Rewrite tautological
block root test") removes one of them, so cross-reference it.

**Why 2 points, not 1:** the scanner is new code alongside `field_name_conformance.rs` (426 lines) and
`no_rvc_prefix.rs` (184), and seeding the exemption list is a workspace-wide discovery pass, not a
one-file edit. The prose-only version of this policy would be 1 point and would not have caught F122's
three bugs.

**Risks:** A name-pattern scanner will have false positives. Keep the pattern narrow and the exemption
mechanism explicit; a noisy gate gets disabled.

---

### Issue RF6-23: ARCHITECTURE.md generated from `cargo metadata` + `doc == generated` test

- **Points:** 3 · **Days:** 1.5–2 · **Type:** feature · **Stream:** A
- **Plan item:** H6 · **Findings:** F109
- **Blocked by:** — · **Blocks:** —

**Files:** `ARCHITECTURE.md:3` (crate count), `:100-135`+ (the mermaid graph);
`crates/architecture-tests/src/` (new generator), new
`crates/architecture-tests/tests/architecture_doc_matches_graph.rs`.

**What / why:** The doc says 23 crates; `Cargo.toml` `members` has **25**; F109 counted 26. The mermaid
graph omits real production edges — `signer→doppelganger` is enforced as `REQUIRED_EDGE` by
`architecture_no_cycles.rs:62` while the doc contradicts it; `doppelganger→slashing`,
`block-service→builder`, `beacon→crypto`, `bn-manager→crypto`, `keymanager-api→metrics` are all missing.
The suite validates acyclicity, forbidden edges, one required edge and three zero-out sinks — it never
validates the documented graph, so the doc keeps rotting. And the count is about to move again (C1, C4,
C5 in Phase 3; F2 in Phase 5; RF6-14 `+1` and RF6-24 `−1` here).

**Implementation sketch:**
1. Generator in `architecture-tests/src/`: parse `cargo metadata --no-deps`, emit the mermaid block and
   the crate-count sentence between stable `<!-- BEGIN GENERATED -->` / `<!-- END GENERATED -->` markers.
   Node grouping (Red orchestrator / Yellow domain / Green foundation, `ARCHITECTURE.md:176-178`) comes
   from a small checked-in classification table — the layer model is a human judgement, the edges are not.
2. Test asserts the generated block equals the in-file block; on mismatch, print the diff and the exact
   regeneration command.
3. Add a `just`/`cargo xtask`-style regeneration entry point and document it in the file's header.
4. Record in ARCHITECTURE.md the two conventions the plan asks for: the shutdown idiom and the
   fail-closed convention (Phase 1's slashing-DB and enablement defaults).

**Acceptance criteria:**
- [x] The crate count and the mermaid graph are generated; the count matches `cargo metadata` exactly.
- [x] The doc no longer contradicts `REQUIRED_EDGE` (`signer→doppelganger` present) and shows every real
      production edge.
- [x] `cargo test -p architecture-tests` fails on a hand-edit inside the generated markers (prove it by
      hand-editing in the PR and pasting the failure).
- [x] Fail-closed and shutdown-idiom conventions recorded.
- [x] Workspace green.

**Test/verification plan:** The gate must be shown to bite, since a generator whose test silently passes
on stale input is worse than no generator. In the PR: (1) hand-edit one edge inside the generated markers,
paste the test failure and the printed regeneration command; (2) revert. (3) Prove the generator tracks
reality by running it before and after RF6-24 (which deletes a crate) and showing the diff is exactly the
propagator node and its two edges. (4) Cross-check the generated edge set against the existing
`FORBIDDEN`/`REQUIRED_EDGE`/`ZERO_OUT_EDGE_IF_PRESENT` tables — the doc contradicting
`REQUIRED_EDGE: ("rvc-signer", "rvc-doppelganger")` is the specific rot F109 found, so assert they agree.

**Risks:** Sequencing — if RF6-14/RF6-24 land after this, one regeneration is needed. That is the point of
the generator; land RF6-23 early and let the others regenerate.

---

### Issue RF6-24: Fold propagator into bn-manager `submit` module; delete the crate

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** B
- **Plan item:** H6 · **Findings:** F67, F112
- **Blocked by:** RF6-08 · **Blocks:** RF6-25

**Files:** `crates/propagator/src/lib.rs` (646 lines incl. tests; `AttestationSubmitter` `:27`,
`Propagator::propagate` `:90`, `extract_attestation_context` `:104`); consumers
`crates/rvc/src/config/builder.rs:28`, `crates/rvc/src/orchestrator/attestation.rs:14`,
`crates/rvc/src/orchestrator/coordinator.rs:21`, `crates/rvc/src/orchestrator/error.rs:8`,
`crates/rvc/tests/sync_independent_of_attesting.rs:47`; new `crates/bn-manager/src/submit.rs`.

**What / why:** A 695-LOC crate exposing one method for one of four submission types — aggregates and sync
messages bypass it entirely (`orchestrator/aggregation.rs:382,430`), so the "message propagation" layer
with its `RVC_ATTESTATIONS_TOTAL` accounting exists for exactly one path. It costs a crate boundary, its
own error enum, and a Cargo.toml to decorate `bn-manager`'s submit path. The plan (§5) explicitly chose
the fold-in direction over extending it.

**Implementation sketch:** Move the ~120 production lines into `crates/bn-manager/src/submit.rs`, keeping
`AttestationSubmitter` public for DI. Re-point the five consumers. `PropagatorError` folds into
`bn_manager`'s error type — and `OrchestratorError`'s propagator variant (`orchestrator/error.rs:8`)
follows. Delete `extract_attestation_context`'s committee-index computation, which is discarded at
`lib.rs:104`. Remove the crate from `Cargo.toml` `members`.

**Acceptance criteria:**
- [x] `crates/propagator/` is deleted; `cargo metadata` shows one fewer member.
- [x] `bn-manager`'s `submit` module carries the propagator's tests (test count unchanged).
- [x] The `PROP → BNM` / `PROP → METRICS` edges disappear from the generated graph (RF6-23's test
      catches this automatically if RF6-23 landed first).
- [x] Workspace green including `crates/rvc/tests/sync_independent_of_attesting.rs`.

**Risks:** Touches `coordinator.rs` — sequence against RF6-27/28/31 within Stream B. Adding a *new*
bn-manager module does not conflict with RF6-08's `manager.rs` test move, but do them in order anyway.

---

### Issue RF6-25: Break `block-service → builder`; add no-domain→domain FORBIDDEN rule

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** B
- **Plan item:** H6 · **Findings:** F112
- **Blocked by:** RF6-10, RF6-24 · **Blocks:** —

**Files:** `crates/block-service/src/service.rs:3` (`use builder::CircuitBreakerState;` — the crate's
**only** use of `builder`), `:34`, `:51`, `:61`, and the test constructions at `:2136`+;
`crates/builder/src/circuit_breaker.rs:11`; also `crates/rvc/src/orchestrator/coordinator.rs:13,110,163,181,215`
and `crates/rvc/tests/sync_independent_of_attesting.rs:40,368` (both import it from `builder` too);
`crates/architecture-tests/tests/architecture_no_cycles.rs:45` (`FORBIDDEN`).

**What / why:** `block-service` pulls in the whole MEV-registration crate — and its `bn-manager`
subtree — for one struct, creating a domain→domain edge the ARCHITECTURE.md layer model says should not
exist. Note the citation is incomplete: **`crates/rvc` imports `CircuitBreakerState` from `builder` too**,
so the move is not confined to `block-service`.

**Implementation sketch:** Pick one of: (a) move `CircuitBreakerState` to a small shared home — a
`service_util` module in `signer` or a tiny shared crate; `eth-types` is the wrong home semantically
despite having no deps; or (b) have `block-service` define its own state and `builder` convert. Prefer
(a): three consumers argue for a shared home, and (b) would duplicate the state machine. Then add
`("rvc-block-service", "rvc-builder")` — and the general no-domain→domain rule the plan asks for — to
`FORBIDDEN`, so the edge cannot come back.

**Acceptance criteria:**
- [x] `crates/block-service/Cargo.toml` has no `builder` dependency.
- [x] The no-domain→domain rule is in `FORBIDDEN` and `cargo test -p architecture-tests` green.
- [x] `crates/rvc` and `crates/block-service` import `CircuitBreakerState` from the same new home.
- [x] Circuit-breaker behaviour unchanged (existing block-service and coordinator circuit-breaker tests
      pass unmodified).
- [x] Test count unchanged; workspace green.

**Risks:** Encoding "no domain→domain" as a general rule may trip legitimate existing edges. Enumerate the
current domain→domain edges from `cargo metadata` **before** writing the rule, and either fix or
explicitly grandfather each with a comment — do not weaken the rule to fit.

---

### Issue RF6-26: `keymanager_adapters/` module dir + shared `KeyChangeNotifier`

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** B
- **Plan item:** H7 · **Findings:** F6
- **Blocked by:** — · **Blocks:** RF6-32

**Files:** `crates/rvc/src/keymanager_adapters.rs` (3,028 lines; production ends ~1,074, then ~1,950 lines
of tests, 82 tests) holding eight adapters — `KeystoreManagerAdapter:50`, `SlashingProtectionAdapter`,
`ValidatorManagerAdapter`, `DoppelgangerMonitorAdapter`, `ForwardWindowMonitor`,
`RemoteKeyManagerAdapter:754`, `ValidatorConfigManagerAdapter`, `VoluntaryExitManagerAdapter:982` — plus
`scan_and_rearm_gate` and `wall_clock_epoch`. `KeystoreManagerAdapter` and `RemoteKeyManagerAdapter`
duplicate identical `with_pubkey_map` + `notify_key_change` members (`:73-93` vs `:775-789`).

**What / why:** Eight unrelated adapters and two free functions in one file. Phase 1's A4 already made the
notifier a **required** constructor parameter of both key adapters — this issue gives that shared concept
a type and the file a structure.

**Implementation sketch:** Convert to `keymanager_adapters/` with one file per adapter
(`keystore.rs`, `remote_keys.rs`, `slashing.rs`, `validator.rs`, `doppelganger.rs`, `voluntary_exit.rs`,
`config.rs`, `mod.rs`) and colocated tests. Extract `KeyChangeNotifier { pubkey_map, key_gen_tx }` used by
both key adapters (this is the type A4's required-parameter change was reaching for). Route the file's
`format!("0x{}", hex::encode(...))` sites through the canonical pubkey helper C6 (Phase 3) installed —
the crate had 58 such occurrences at survey time; fix the ones in this file and count what remains.

**Acceptance criteria:**
- [x] No file in `keymanager_adapters/` exceeds ~600 lines; each adapter's tests sit beside it.
- [x] One `KeyChangeNotifier`; neither key adapter defines its own `notify_key_change`.
- [x] Zero `format!("0x{}", hex::encode(` in `keymanager_adapters/` (`rg -c` = 0); the remaining
      workspace count is stated in the PR.
- [x] Move commits are pure moves; the notifier extraction is its own commit.
- [x] Test count unchanged; workspace green.

**Risks:** SEC-1/SEC-1b and Phase-5 F5 both rewrote this file. Re-derive boundaries from HEAD-of-Phase-5.

---

### Issue RF6-27: coordinator `wait_for`/`phase_deadline` helpers + epoch-boundary extraction

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** B
- **Plan item:** H7 · **Findings:** F5, F121
- **Blocked by:** RF6-09 · **Blocks:** RF6-28

**Files:** `crates/rvc/src/orchestrator/coordinator.rs` (post-RF6-09, production-only) —
`run()` at `:299-585` with four near-identical `tokio::select! { sleep / shutdown_rx.changed() }` blocks
each followed by `check_shutdown()` (`:299`, `:402`, `:498`, `:565`), the bps-in-milliseconds deadline
computation duplicated at `:419-433` and `:478-485`, and the epoch-boundary summary at `:352-365` that
loops 32 slots **twice** just to count duties; destination for the latter:
`crates/rvc/src/orchestrator/duty_management.rs`.

**What / why:** A 285-line `run()` loop that inlines epoch-boundary work, three phase blocks, deadline
math, and the builder-registration select. Extracting `wait_for(duration) -> Continue | Shutdown` and
`phase_deadline(bps)` removes the four/two duplications and makes the slot loop readable in one screen.

**Implementation sketch:**
1. `fn wait_for(&self, d: Duration) -> WaitOutcome` wrapping the select + `check_shutdown`; replace all
   four sites. The enum (not a bool) so the caller must handle shutdown explicitly.
2. `fn phase_deadline(bps: u64) -> Duration` for the two copies.
3. Move the epoch-boundary summary into `DutyManagementService`, and while moving it, collapse the
   double 32-slot loop into one pass (a behaviour-preserving fix, but assert the summary output is
   identical before/after with a test).
4. Keep `run()`'s ordering and log lines byte-identical — the tracing-span tests relocated by RF6-09 are
   the oracle.

**Acceptance criteria:**
- [x] One `select!`-plus-`check_shutdown` implementation (`rg -c "shutdown_rx.changed()"` in the file = 1).
- [x] One deadline computation.
- [x] The epoch-boundary block lives in `duty_management.rs` and iterates the slot range once.
- [x] Log lines and their ordering unchanged (tracing-span tests pass unmodified).
- [x] Test count unchanged; workspace green.

**Risks:** The four select blocks may differ in a subtle way (a different metric increment, a different
log level). Diff them explicitly before unifying and record any real difference as a parameter rather
than flattening it away.

---

### Issue RF6-28: Relocate block-proposal methods to `orchestrator/block_proposal.rs`

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** B
- **Plan item:** H7 · **Findings:** F121
- **Blocked by:** RF6-27 · **Blocks:** RF6-31

**Files:** `crates/rvc/src/orchestrator/coordinator/mod.rs` (post-RF6-09/27); new
`crates/rvc/src/orchestrator/block_proposal.rs`; the relocated tests in
`coordinator/tests/` follow their subject.

**Scope decision (read this before estimating differently):** this issue is a **mechanical relocation of
the block-proposal methods into a sibling module — no new trait, no new seam, no dependency inversion.**
The plan writes "(optional) BlockProposalService" and F121 asks for a full service extraction; a genuine
service extraction with its own injected seam is **not** a 2-day job and is explicitly **out of scope
here**. If the relocated module later justifies a trait boundary, that is a separate, separately-sized
issue. Recording the ambiguity as resolved is part of this issue's output.

**What / why:** F121 (REVIEW.md) names block-proposal extraction as the next decomposition step and
targets `coordinator.rs` under 2,000 lines. After RF6-09 the file is ~750 production lines, so the line
target is already met — the remaining value is *cohesion*: the coordinator should own the slot loop, not
the proposal pipeline.

**Implementation sketch:** Move the proposal methods and their helpers into `block_proposal.rs` as an
`impl DutyOrchestrator` block (a second `impl` block on the same type — this keeps it a pure move; no
field plumbing, no constructor change). Move the corresponding tests from
`coordinator/tests/` to `block_proposal/tests.rs`. State in the module doc what a future service
extraction would need (which fields it would take, which seam it would inject).

**Acceptance criteria:**
- [x] `coordinator/mod.rs` contains the slot loop and phase dispatch only; proposal methods live in
      `block_proposal.rs`.
- [x] `git diff -M` renders as a move; no signature, field, or constructor changed.
- [x] The module doc records the go/no-go note for a future `BlockProposalService`.
- [x] Test count unchanged; workspace green.

**Risks:** If the proposal methods turn out to be entangled with the slot loop's state such that a second
`impl` block does not compile cleanly, stop and convert this issue into the 1-point decision issue it
almost was: emit the entanglement list plus a sized follow-up, and close.

---

### Issue RF6-29: aggregation — `produce_one_aggregate`/`submit_versioned`/`timed()`

- **Points:** 3 · **Days:** 1.5–2 · **Type:** chore · **Stream:** B
- **Plan item:** H7 · **Findings:** F8
- **Blocked by:** RF6-09 · **Blocks:** —

**Files:** `crates/rvc/src/orchestrator/aggregation.rs:46-459` (`maybe_produce_aggregations`, one
415-line function) — the Electra branch `:246-305` and pre-Electra branch `:306-365` are structurally
identical (build `AggregateAndProof`, `try_tree_hash_root` guard, sign, push) differing only in types and
log strings; the two submit blocks `:368-410` and `:412-458` are ~45-line clones differing only in the
`VersionedSignedAggregateAndProof` wrapper. The `timeout → warn → RVC_AGGREGATIONS_TOTAL[FAILED].inc() →
continue` idiom repeats **8 times** here and 5 more in `duty_management.rs`
(`fetch_epoch_duties:65-117`, `check_reorg:208-274`).

**What / why:** One function containing two mirrored fork branches and eight copies of the same
timeout-handling idiom — the shape that made the Electra rollout expensive and will make Fulu expensive
again.

**Implementation sketch:**
1. `produce_one_aggregate(duty) -> Option<Aggregate>` plus a `sign_and_wrap` helper generic over the
   proof type (both branches share the `TreeHash` + signing shape).
2. `submit_versioned(versioned, label)` for the two submit clones.
3. A crate-local `timed(op_name, timeout, fut)` combinator that logs and increments the failure metric
   uniformly; use it here (8 sites) **and** in `duty_management.rs` (5 sites) so the idiom has one home.
4. Metric labels and log messages must not change — Phase 1's A7 scrape test and the aggregation metrics
   are the oracle.

**Acceptance criteria:**
- [x] `maybe_produce_aggregations` under ~120 lines; no mirrored fork branch remains.
- [x] One `timed(...)` combinator, used at all 13 sites (`rg -c` proof for both files).
- [x] `RVC_AGGREGATIONS_TOTAL` label values and log messages byte-identical (grep-diff in the PR).
- [x] Test count unchanged; the aggregator-determinism tests (test-audit issue 3.10) pass.
- [x] Workspace green.

**Risks:** Generic-over-proof-type may fight the two `VersionedSignedAggregateAndProof` variants. If the
generic gets contorted, keep two small explicit functions and still extract `timed()` + `submit_versioned`
— most of the value is in those two.

---

### Issue RF6-30: attestation — inner-`Result` fn + collapse Fulu/Electra arms

- **Points:** 2 · **Days:** 1–1.5 · **Type:** chore · **Stream:** B
- **Plan item:** H7 · **Findings:** F11
- **Blocked by:** — · **Blocks:** —

**Files:** `crates/rvc/src/orchestrator/attestation.rs:224-554` (`process_attestation_duty`, 330 lines
repeating `return AttestationResult { validator_index, slot, success: false, error: Some(...) }` **twelve
times**); `:466-510` (versioned-attestation construction duplicating the index-zeroing clone for the Fulu
and Electra branches, which differ only in the enum constructor).

**What / why:** Twelve hand-copied three-field constructions with the happy path buried between them.

**Implementation sketch:** Refactor the body into an inner `async fn attest(...) -> Result<(), String>`
using `?`, and build the `AttestationResult` once at the call site from the `Result`. Collapse the
Fulu/Electra arms into one block that builds the shared `SingleAttestation` and then selects the
constructor.

**Acceptance criteria:**
- [x] Exactly one `AttestationResult { … success: false … }` construction in the file.
- [x] Every error string is preserved verbatim (they are user-visible in logs — grep-diff proof).
- [x] One index-zeroing block covering both forks.
- [x] Test count unchanged; the attestation-data validation tests
      (`crates/rvc/tests/attestation_data_validation_m2.rs`) pass unmodified.
- [x] Workspace green.

**Risks:** Some of the twelve returns may carry side effects (a metric increment, a log) before returning.
Enumerate them first; side effects move into the inner function, not into the `?` boundary.

---

### Issue RF6-31: `PubkeyMap` re-key to `[u8;48]` + shared pubkey→index registry

- **Points:** 3 · **Days:** 1.5–2 · **Type:** perf · **Stream:** B
- **Plan item:** H7 · **Findings:** F10
- **Blocked by:** RF6-28 · **Blocks:** —

**Files:** `crates/rvc/src/orchestrator/coordinator.rs:37` (`PubkeyMap = Arc<RwLock<HashMap<String,
PublicKey>>>`), `orchestrator/utils.rs:79-108` (`find_pubkey`'s case-insensitive O(n) fallback),
`utils.rs:198-227` (`get_duties_for_slot` clones the whole map and re-normalizes every key, called twice
per slot), `orchestrator/duty_management.rs:287-312` (`prepare_proposers` resolves each validator's index
by scanning 64 slots × all duties **per validator per epoch**), `:357-359`
(`submit_committee_subscriptions`'s per-duty linear `.find` with normalize on both sides),
`liveness_loop.rs:46` (`IndexToPubkeyHex`, an existing pubkey→index map), `config/builder.rs:500-508`
(`build_pubkey_map`), `bin/rvc/src/main.rs` (`validator_index_map`).

**What / why:** All production insertion sites already produce canonical `0x`-lowercase keys, yet the map
is keyed by `String` and every read path pays for it: a linear case-insensitive fallback, a full-map clone
plus re-normalization twice per slot, and — worst — `prepare_proposers` at **O(validators × 64 × duties)**
even though a pubkey→index map already exists in the liveness loop and in `main.rs`. This is the one
performance item in the phase, and it scales with validator count.

**Implementation sketch:**
1. **RED:** a complexity test for `prepare_proposers` — instrument a counting duty-cache double and assert
   the lookup count is O(validators), not O(validators × 64 × duties). Assert on **counts, not
   wall-clock**, so it cannot flake.
2. Re-key `PubkeyMap` to `[u8; 48]` (or the `CanonicalPubkey` newtype C6 installed in Phase 3 — prefer it
   if it exists at HEAD) and normalize duty pubkeys **once** at `DutyTracker` ingestion.
3. Delete `find_pubkey`'s linear fallback — with a typed key it is unreachable. Its removal is the
   behaviour-visible part: a non-canonical pubkey that previously matched case-insensitively now misses.
   Confirm no production path can supply one (all insertion sites are canonical) and add a test asserting
   ingestion canonicalizes.
4. Promote the liveness loop's `IndexToPubkeyHex` into a small shared pubkey→index registry; use it in
   `prepare_proposers` and `submit_committee_subscriptions` instead of the nested scans; retire
   `main.rs`'s `validator_index_map` copy.
5. `get_duties_for_slot` borrows rather than cloning the map.

**Acceptance criteria:**
- [x] `PubkeyMap` is keyed by a fixed-size/typed key; no `String` normalization on any per-slot path.
- [x] `prepare_proposers` performs O(validators) index lookups (count-based test, not timing).
- [x] One pubkey→index registry in the workspace; `IndexToPubkeyHex` and `validator_index_map` are gone
      or delegate to it.
- [x] `find_pubkey`'s linear fallback deleted; a canonicalization-at-ingestion test exists.
- [x] Test count unchanged plus the new perf/canonicalization tests, itemised.
- [x] Workspace green.

**Test/verification plan:** The perf assertion must be **count-based, never wall-clock** — instrument the
duty-cache double with an access counter and assert `lookups <= validators + k`, so the test states the
complexity claim directly and cannot flake on a loaded CI box. Write it RED first against the current
implementation and paste the observed count (it should be roughly `validators × 64 × duties`); the
before/after numbers are the evidence that F10's claim was real. Separately, guard the one behavioural
change: before deleting `find_pubkey`'s case-insensitive fallback, enumerate every insertion site
(`config/builder.rs:500-508`, both keymanager adapters, duty ingestion) and show each produces a canonical
key; add an ingestion-canonicalization test so a future non-canonical source fails loudly instead of
silently missing.

**Risks:** Touches 8 files across `crates/rvc` and `bin/rvc` including `coordinator.rs` — hence the
RF6-28 dependency. The `find_pubkey` fallback deletion is the only place a real behaviour change hides;
treat step 3 as the review focus.

---

### Issue RF6-32: Module renames — `duty_tracker`→`grpc_health`; `background_tasks/`

- **Points:** 1 · **Days:** 0.5–1 · **Type:** chore · **Stream:** B
- **Plan item:** H7 · **Findings:** F12
- **Blocked by:** RF6-26 · **Blocks:** —

**Files:** `crates/rvc/src/lib.rs:8` (`pub mod duty_tracker;`) and `:19` (`pub mod duty_tracker` inside
`proto`) — the crate-local module collides in name with the workspace's real `crates/duty-tracker`;
`crates/rvc/src/monitoring.rs` (377 lines), `crates/rvc/src/config_url.rs` (409 lines) → new
`crates/rvc/src/background_tasks/`.

**What / why:** `rvc::duty_tracker` is the gRPC health/duty-tracker *server*, not the duty cache — the
name collision with `crates/duty-tracker` makes both harder to search for. `monitoring` and `config_url`
are background tasks with no other home.

**Implementation sketch:** `git mv` + rename the module; keep `DutyTrackerServer`'s re-export
(`lib.rs:24`) and the `proto::duty_tracker` module (generated from the `.proto` package name — do **not**
rename that one, it must match the wire package). Group `monitoring.rs` and `config_url.rs` under
`background_tasks/`.

**Acceptance criteria:**
- [x] `rvc::duty_tracker` no longer exists; `rvc::grpc_health` does; `proto::duty_tracker` unchanged
      (wire package name preserved).
- [x] `monitoring` and `config_url` live under `background_tasks/`; consumers updated.
- [x] Pure rename (`git diff -M`); test count unchanged; workspace green.

**Risks:** The public re-export `DutyTrackerServer` is part of the crate's API — keep the re-export path
stable even though the module moved.

---

## Cross-Phase & External Dependencies

| Dependency | Affects | Note |
|---|---|---|
| Phases 1–5 landed | all | file splits conflict with every earlier phase |
| **SEC-6a–d (LANDED, `2493c3a`)** | RF6-01/02/03/04 | rebase, not serialize; KAT obligation only |
| E2 (Phase 4) | — | slashing `db.rs` split + test move is Phase 4's, not here |
| E5 (Phase 4) shared bn-manager mock | RF6-17, RF6-08 | hard blocker for RF6-17 |
| E8a rider (Phase 4) | RF6-10 | `propose_block_with_mode` demoted to `pub(crate)` |
| C6/C7 (Phase 3) | RF6-15, RF6-16, RF6-26 | canonical pubkey helper; `test-utils` feature naming |
| F1/F2/F5 (Phase 5) | RF6-11, RF6-12, RF6-19, RF6-26 | re-derive line numbers from HEAD-of-Phase-5 |
| B1 (Phase 2) | RF6-21 | deletes the sync-service mocks F123 cites |
| `docs/issues/` 2.1–2.4 | RF6-10, RF6-21 | owns mock fidelity; do not duplicate |
| `docs/issues/` 3.10, 4.1 | RF6-09 | additive `coordinator.rs` edits — conflict risk |
| `docs/issues/` 3.14 | RF6-03 | adds the sync-committee TreeHash tests G2 wants as its oracle |
| `docs/issues/` 3.4 | RF6-22 | rewrites the tautological block-root test the KAT policy bans |
