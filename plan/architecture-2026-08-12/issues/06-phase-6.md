# Phase 6 — Layer Taxonomy & Seam Cleanup

> Sprint-ready issue breakdown for **Phase 6** of the rs-vc architecture-remediation initiative.
> Baseline **`develop` @ `0ae9a09`** (v0.7.0), authored **2026-08-12**. Every `file:line` below was
> re-opened against HEAD while writing this file; where a `file:line` is cited without a delta note it
> reproduced exactly.
>
> **Authoritative inputs, in precedence order:**
> [`../project-plan.md`](../project-plan.md) §6/§7 *Phase 6* (scope, gates, entry/exit) →
> [`../architecture.md`](../architecture.md) (**ADR-011**, gate specs **G-5a/G-5b** §6, VD-3, VD-A1,
> VD-P4, VD-P5) → [`../prd.md`](../prd.md) (**ARCH-P1-8, ARCH-P1-9, ARCH-P1-10, ARCH-P2-3**;
> constraints C1–C10) → [`../research/`](../research/) →
> [`../../../docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md)
> → the repository's [`CLAUDE.md`](../../../CLAUDE.md) (TDD RED→GREEN→REFACTOR, **KAT-first policy**,
> `thiserror`/`anyhow`, no `.unwrap()` in production, `cargo nextest run --workspace`).
>
> **What this file adds over its inputs.** It is not a restatement. Eight new verification deltas
> (`VD-6-1 … VD-6-8`, §*Assumptions*), three of which materially change the work: the
> `CompositeSigner`-holds-a-concrete-`RemoteSigner` blocker that would have defeated ADR-011's own
> `crypto`-into-`Base` decision (**VD-6-3**, forcing ARCH-6e to exist), the fact that the
> "metrics-conformance gate" ARCH-P2-3 is accepted against **does not exist at HEAD** (**VD-6-6**),
> and the discovery that the reqwest extraction has **one** production consumer rather than the five
> its `rg` hit list suggests (**VD-6-8**, which also proves `SIGNER_SERVER_ALLOWED_EDGES` needs no
> row).
> It also supplies the artefact both the review and the plan lack and which is the only thing that
> makes ARCH-P1-8 estimable rather than aspirational: a **draft 28-row `Base`/`Infra`/`Domain` table
> with a one-line reason per row**, derived from the checked-in `CLASSIFICATION`, not from the
> review's prose (which omits two members and misclassifies `timing` — VD-A1, VD-3).
>
> **No-ask constraint:** every open question is resolved to a stated default in *§Assumptions*.
> Nothing is escalated. `AskUserQuestion` is never called.
>
> **Scope:** planning only. This document changes no source file and deletes nothing. `docs/prd.md`,
> `docs/architecture.md` and `docs/project-plan.md` belong to the older Test Audit Remediation
> initiative and are untouched (NG8). Deleting the untracked orphan trees is **Phase 0**'s work
> (ARCH-P0-1), not this phase's — see **C10** in *§Constraint Coverage*.

---

## Phase Overview

- **Goal.** Make the layer rules bite: a `Base` layer that cannot reach outside itself, an `Infra`
  layer that cannot reach into `Domain`, and the duplicated seams that force every fork-driven change
  to be made twice removed.
- **Requirements covered.** ARCH-P1-8, ARCH-P1-9, ARCH-P1-10, ARCH-P2-3. ADR-011; gates **G-5a**,
  **G-5b**.
- **Issue count / points.** **8 issues, 19 points.** No issue exceeds 3 points.
- **Duration, 1 developer.** **10–15 working days.** This sits at/just above the plan's 9–14 d band
  (`project-plan.md:277`) and the reason is named rather than padded: the plan sized Phase 6 *below* a
  naive reading because G-5b needs no edge removals (VD-P4 — re-confirmed here), but it did not know
  about **VD-6-3**, which adds ARCH-6e (2 pts) as a hard prerequisite of the `crypto` extraction.
- **Duration, 2 developers.** **6–8 working days** on the critical path (two disjoint-file streams,
  A/B — see *§Phase Execution Plan*).
- **Depends on phases.** **Phase 0 only.** Parallel-safe with Phases 1–5 (disjoint files), subject to
  the plan's `ARCHITECTURE.md` collision protocol (`project-plan.md:824-825`).

### Entry criteria

- [ ] Phase 0 complete: `crates/sync-service/` deleted, so the workspace member count is **28** and
      the split does not classify a crate that is about to be deleted (`project-plan.md:669-670`).
- [ ] Phase 0's `arch-gates` CI job exists (`cargo nextest run -p rvc-architecture-tests`, A-P1 /
      VD-P7) — otherwise every gate in this phase lands in the slow `coverage` job.
- [ ] The four untracked orphan trees are gone (Phase 0, ARCH-P0-1). Until then the orphan-tree
      invariant (`project-plan.md:151-157`) forbids citing or editing them; note in particular that
      `crates/rvc-signer/Cargo.toml:35` is the *only* Foundation→Domain hit VD-P4 found, and it is
      inside an orphan — so **G-5b's greenness is contingent on Phase 0 having landed.**
- [ ] Green on all §2 standing commands: `cargo fmt --all -- --check`,
      `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings`,
      `cargo build --workspace`, `cargo nextest run --workspace`.

### Exit criteria (matches the plan's Phase-6 milestone, `project-plan.md:672-679` and `:291`)

- [ ] **All 28 members carry a deliberate `Base`/`Infra`/`Domain`(/`Binary`/`Orchestrator`/`Meta`) row
      with a stated reason** in `crates/architecture-tests/src/lib.rs`'s `CLASSIFICATION`, sourced from
      the checked-in table and not from the review's prose (VD-A1).
- [ ] **`rvc-timing` is reclassified `Domain` → `Base`** deliberately, with its reason recorded, and
      `DOMAIN_PACKAGES` is updated in lock-step so `domain_packages_match_classification` stays green
      (VD-3 discharged; A-P2's G-5a reading is what makes it eligible).
- [ ] **`ARCHITECTURE.md` regenerates byte-identically** — read precisely (**VD-6-7**): after
      `make architecture-doc`, `cargo nextest run -p rvc-architecture-tests` is green because the
      checked-in generated block equals the generator's output. It does **not** mean the diff to
      `ARCHITECTURE.md` is empty; the generated body provably changes (see VD-6-7).
- [ ] **G-5a and G-5b are each RED against a scratch violating edge** — mandatory for G-5b, which is
      otherwise vacuously green (VD-P4, R10). RED reproduced locally and the output pasted into the PR
      (ADR-012's "demonstrated, not asserted" standard).
- [ ] **`crypto` passes G-5a** — its only remaining workspace out-edges are `observability`,
      `eth-types`, `web3signer-wire`, all `Base` — **with signing-root KATs green**
      (`crates/crypto/tests/signing_root_kat.rs`).
- [ ] **M9 drops by one duplicated seam**: `rg 'struct ProduceBlockResponse'` returns exactly **one**
      hit, and `crates/rvc/src/beacon_adapter.rs:33-40`'s six-field copy is gone.
- [ ] `metrics` carries no domain-named metric definition, and the exposed metric-name set is proven
      unchanged by a **new** name-stability assertion (VD-6-6: the gate ARCH-P2-3 is accepted against
      does not exist at HEAD).
- [ ] The existing DAG / forbidden-edge / required-edge gates
      (`crates/architecture-tests/tests/architecture_no_cycles.rs`) stay green, with
      `ZERO_OUT_EDGE_IF_PRESENT` (`:72-79`) **retained unchanged**.
- [ ] All §2 standing commands green.

---

## Assumptions verified against HEAD (`0ae9a09`)

Every row below was checked by opening the named file at the named line while writing this document.
Eight are **new deltas** found here (`VD-6-*`); the rest are re-verifications of upstream claims, and
where an upstream claim did not reproduce it is corrected, not smoothed.

### Re-verified upstream claims (reproduced exactly)

| # | Claim | Verified at HEAD |
|---|---|---|
| RV-1 | `CLASSIFICATION` has 29 rows across 5 layers | `crates/architecture-tests/src/lib.rs:57-92`. Binary 3 (`:59-61`), Orchestrator 1 (`:63`), Domain 8 (`:65-72`), Foundation 15 (`:74-88`), Meta 2 (`:90-91`). ✓ |
| RV-2 | `rvc-timing` is `Domain`, not Foundation (VD-3) | `("rvc-timing", Layer::Domain, "timing", "slot clock")` at `lib.rs:72`, inside the Domain block. The review's "pure leaves" list is wrong. ✓ |
| RV-3 | VD-A1: the review omits `rvc-signer-registry` and `rvc-grpc-signer` and does not place `rvc-slashing` / `rvc-validator-store` | All four are present in the Foundation block: `lib.rs:84`, `:78`, `:85`, `:87`. ✓ |
| RV-4 | VD-P5: `crypto` declares three workspace deps the extraction does not remove | `crates/crypto/Cargo.toml:19` `observability`, `:24` `eth-types`, `:26` `web3signer-wire`. Under the literal G-5a wording `crypto` can never be `Base`. ✓ **A-P2's reading ("Base may depend only on Base") is adopted.** |
| RV-5 | VD-P5: `rvc-timing`'s only workspace out-edge is `eth-types` | `crates/timing/Cargo.toml:13`. Sole workspace dependency; `thiserror` (`:14`) and `tracing` (`:15`) are external. ✓ Base-eligible under A-P2. |
| RV-6 | The existing zero-out-edge pin is a hand-listed six | `ZERO_OUT_EDGE_IF_PRESENT` = `rvc-eth-types`, `rvc-signer-registry`, `rvc-telemetry`, `rvc-observability`, `rvc-signer-proto`, `rvc-test-support` at `crates/architecture-tests/tests/architecture_no_cycles.rs:72-79`. **Retained unchanged** (plan `:654`). ✓ |
| RV-7 | VD-P4: G-5b is green at HEAD | No tracked Foundation member declares a Domain dependency. Spot-checked the two most likely: `crates/slashing/Cargo.toml:19-28` (`observability`, `eth-types`, `metrics` — no Domain) and `crates/validator-store/Cargo.toml:13-14` (`observability`, `eth-types`). ✓ **Contingent on Phase 0**: the one hit VD-P4 found is `crates/rvc-signer/Cargo.toml:35`, inside an untracked orphan. |
| RV-8 | ADR-011 lists `rvc-metrics` among the pure leaves | `architecture.md:643-644`. Confirmed structurally: `crates/metrics/Cargo.toml:12-18` declares **zero** workspace dependencies. ✓ |

### New verification deltas found while writing this file

| ID | Claim as written upstream | Status at HEAD | Corrected fact carried forward | Lands in |
|---|---|---|---|---|
| **VD-6-1** | Plan 6B / A-8: *"`bn-manager` sanctioned as the types facade"* for `ProduceBlockResponse` | **`bn-manager` does not define the type — it re-exports `beacon`'s** | The two definitions are `crates/beacon/src/types.rs:132` and `crates/block-service/src/traits.rs:50`; `crates/bn-manager/src/lib.rs:34-43` is a `pub use beacon::{… ProduceBlockResponse …}` whose own comment (`:32-33`) reads *"so downstream crates don't need to depend on `beacon` directly."* **That rationale does not bind `block-service`, which already depends on `beacon` in production** (`crates/block-service/Cargo.toml:14`, used at `service/mod.rs:306,323,341,576-577`). **Default taken (A-6-1): the survivor is `beacon::ProduceBlockResponse`, imported through `bn_manager`'s existing re-export where a crate already depends on `bn-manager`, and directly where it already depends on `beacon`.** Consequence: **ARCH-P1-9 costs zero new crate edges**; routing it through `bn-manager` instead would *add* `block-service → bn-manager`, an edge that does not exist today | ARCH-6d |
| **VD-6-2** | Implicit in ARCH-P1-9: "unify the type" | **The two structs are field-identical; the only delta is the `impl`'s error type** | `beacon/src/types.rs:132-141` and `block-service/src/traits.rs:50-59` declare the **same six fields in the same order with the same doc comments** (`data`, `is_blinded`, `consensus_version`, `execution_payload_value`, `is_ssz`, `ssz_bytes`). The divergence is `parse_full_block`/`parse_blinded_block` returning `Result<_, BeaconError>` (`types.rs:145,151`, `BeaconError::ParseError`) vs `Result<_, BlockServiceError>` (`traits.rs:62,67`, `BlockServiceError::Parse`). **That error-type reconciliation is the entire design decision in ARCH-P1-9** and must be taken explicitly, not discovered at compile time | ARCH-6d |
| **VD-6-3** | ADR-011: *"Slim `rvc-crypto` into `Base` by extracting `remote_signer/` (the reqwest client) into an Infra crate"* | **Blocked as stated — the extraction as written makes `crypto` depend on the new Infra crate** | `CompositeSigner` holds a **concrete** `remote: RwLock<HashMap<[u8; 48], Arc<RemoteSigner>>>` (`crates/crypto/src/composite_signer.rs:21`) and `add_remote_key(&self, pubkey, signer: RemoteSigner)` takes it **by value** (`:81`). Moving `remote_signer/` out therefore forces `crypto → remote-signer-client` (Infra), and `crypto` can never be `Base`. **The field is only ever used through `Signer::sign`** (`:173-184`), and the crate already contains the exact precedent for the fix one line above: `grpc_remote: RwLock<HashMap<…, Arc<dyn TypedSigner + Send + Sync>>>` (`:20`). **Consequence: a decoupling issue (ARCH-6e) must land before the extraction (ARCH-6f).** Neither the review, the PRD, the architecture nor the plan names this | ARCH-6e → ARCH-6f |
| **VD-6-4** | ADR-011: *"moving `is_aggregator`/duty selection to `eth-types`"* — cost unstated | **Cheaper than it looks: the dependency and the precedent already exist** | `is_aggregator` is `crates/crypto/src/aggregation_signing.rs:12`, re-exported at `crypto/src/lib.rs:50` and `signer/src/lib.rs:23`; **no production code imports it from `crypto`** — both call sites go through `signer` (`crates/rvc/src/orchestrator/duty_management.rs:12`, `aggregation.rs:15`). `eth-types` **already declares `sha2` specifically for the sibling predicate `is_sync_committee_aggregator`** (`crates/eth-types/Cargo.toml:28-30`, comment: *"External only — keeps the zero workspace-internal out-edge pin for rvc-eth-types"*). So the move is precedent-matching, adds **no** dependency, and cannot disturb `rvc-eth-types`'s zero-out-edge pin | ARCH-6g |
| **VD-6-5** | ADR-011: extract *"the reqwest client"* out of `crypto` | **Removability verified, plus one bonus finding** | `reqwest` appears at **exactly one site** in `crates/crypto/src` — `remote_signer/client.rs:12` (`use reqwest::Client;`). The extraction therefore genuinely drops `crypto`'s `reqwest` line (`Cargo.toml:29`). **Bonus:** `url` (`crypto/Cargo.toml:39`) has **no** use anywhere in `crates/crypto/src` (the only `Url` hits are `observability::logging::RedactedUrl`, `remote_signer/client.rs:11`) — it appears to be already-dead and is a `cargo-machete` candidate that Phase 0's 0G should catch; ARCH-6f drops it opportunistically with `cargo machete` as the proof | ARCH-6f |
| **VD-6-6** | PRD ARCH-P2-3 acceptance: *"the metrics-conformance gate still passes"* | **That gate does not exist at HEAD** | `crates/metrics/tests/` does not exist (no files). `crates/architecture-tests/tests/` holds seven gates, none about metrics; `field_name_conformance.rs:1-9` is the **log-field** Gate 5 over a curated 16-event set, not a metrics gate. **Consequence:** ARCH-P2-3 has **no regression detector** for the one failure mode decentralization actually causes — a metric silently renamed or dropped out of an operator dashboard. **Default taken (A-6-4): ARCH-6h must build a metric-name-stability assertion** (pin the exposed name set, shrinking-and-growing only by explicit edit) as part of the issue, not as follow-on work. Second correction: PRD's *"`metrics` has no reverse dependency on domain crates"* is **already true as a Cargo edge** — `crates/metrics/Cargo.toml:12-18` has zero workspace deps — so the real work is lexical (24 domain-named `pub static ref` definitions at `crates/metrics/src/definitions.rs`), and the acceptance criterion must be lexical too or it is vacuous | ARCH-6h |
| **VD-6-8** | This file's own first draft (and the plan's ADR-011 framing) treated *"extract `remote_signer/`"* as rewiring **five** external consumer crates | **Only one production consumer exists; the other four are false positives** | Opening each `rg 'RemoteSigner\|remote_signer'` hit by shape rather than by identifier: `crates/signer-server/src/backend/signer_adapter.rs:14,15,50,63-64` and `crates/signer/src/core.rs:26,72,706` mention only the **error variant** `SigningError::RemoteSignerError`, never the type; `crates/rvc/src/bootstrap/keys.rs:11,39,133-180` uses `grpc_signer::GrpcRemoteSigner`, a **different type from a different crate**; `crates/signer/src/lib.rs:3300-3301` (`crypto::RemoteSigner::new_for_tests`) is inside `#[cfg(test)] mod tests` (`:923-924`), so `signer` needs only a **dev-dependency**, which `build_edge_map`'s `kind == null` filter (`architecture_no_cycles.rs:110`) excludes from every production-edge gate. **The sole production consumer is `crates/rvc/src/keymanager_adapters/remote_keys.rs:8,84-88.`** Two consequences: ARCH-6f's blast radius is one production crate, not five; and **`SIGNER_SERVER_ALLOWED_EDGES` (`architecture_no_cycles.rs:93-102`) needs no new row**, because `rvc-signer-server` takes no edge — a table the file itself warns against widening (`:90-92`) is therefore left byte-unchanged | ARCH-6f |
| **VD-6-7** | Plan/PRD milestone: *"`ARCHITECTURE.md` regenerates byte-identically"* | **True as a gate statement, false as a diff statement — and the naive reading produces a defect** | The generated body (`crates/architecture-tests/src/lib.rs:255-300`, markers at `ARCHITECTURE.md:3` / `:181`) emits **no layer names**: node lines carry only `label`/`blurb` (`:264-268`), edge lines (`:272-281`), then `style <id> <hex>` lines where the layer contributes **only a colour** (`:285-289`), then a hardcoded legend containing the literal word *"Foundation"* (`:298` → `ARCHITECTURE.md:179`). Therefore: (a) if `Layer::Base` and `Layer::Infra` both keep Foundation's `fill:#51cf66,color:#fff`, the style lines are unchanged; (b) **`rvc-timing` moving `Domain` → `Base` flips its style line from `fill:#ffd43b,color:#333` to green regardless**, so the generated body *does* change; (c) updating the legend changes it again. **The exit criterion is "after `make architecture-doc`, `architecture_doc_matches_graph` is green", never "the diff is empty."** A naive implementer reading it the other way will skip the legend update or hand-edit the file. Additionally `ARCHITECTURE.md:698` (*"Binary → Orchestrator → Domain → Foundation"*) sits **outside** the generated region and names the retired layer — no gate catches it; it is a required hand edit | ARCH-6a |

### Stated defaults (no-ask resolutions)

| ID | Open question | Default taken | Rationale / authority |
|---|---|---|---|
| **A-6-1** | Which crate owns the surviving `ProduceBlockResponse`? | **`beacon`** (definition stays at `crates/beacon/src/types.rs:132`); `bn-manager`'s re-export (`lib.rs:37`) remains the facade for crates that depend on `bn-manager`; `block-service` re-exports from `beacon`, which it already depends on | VD-6-1. Departs from A-8's letter, honours its intent (no crate is forced to take a new `beacon` edge), and costs zero new edges |
| **A-6-2** | `parse_full_block` / `parse_blinded_block` error type after unification | Keep `BeaconError` on the inherent impl; `block-service` converts at its boundary via the existing `BlockServiceError::Beacon`/`Parse` mapping (an explicit `From<BeaconError> for BlockServiceError`, ~10 lines) | VD-6-2. Preserves `beacon`'s API for its other consumers; the conversion already exists in spirit at `crates/rvc/src/beacon_adapter.rs:31` |
| **A-6-3** | Is `rvc-metrics` `Base` or `Infra`? It has zero workspace out-edges (Base-eligible) but binds an axum listener (`crates/metrics/src/server.rs`) | **`Base`** | ADR-011's Context explicitly enumerates `rvc-metrics` among the pure leaves (`architecture.md:643-644`), and the ADRs are authoritative and not re-opened (`project-plan.md:14`). The structural rule (zero out-edges) is the tiebreak. **The tension is real and is recorded in the row's reason**, not hidden |
| **A-6-4** | ARCH-P2-3's missing acceptance artefact | ARCH-6h **builds** a metric-name-stability assertion; the PRD criterion is re-read as lexical (no domain-named definition in `crates/metrics/src/definitions.rs`), not as a Cargo-edge claim | VD-6-6; architecture Design Principle 2 (*"a discipline without a gate is a defect waiting for a rename"*) |
| **A-6-5** | Do `Layer::Base` and `Layer::Infra` get distinct mermaid colours? | **Yes** — `Base` keeps Foundation's green `fill:#51cf66,color:#fff`; `Infra` takes a distinct shade. The legend at `lib.rs:294-299` is updated to name both, and `ARCHITECTURE.md` is regenerated and committed in the same PR | VD-6-7. A split that is invisible in the generated diagram is a rename, not a taxonomy. The cost is one regeneration, which is required anyway because of `rvc-timing` |
| **A-6-6** | New crate name / alias for the extracted reqwest client | Package `rvc-remote-signer-client`, workspace alias `remote-signer-client` (matching the repo's `package = "rvc-…"` + unprefixed-alias convention, e.g. `Cargo.toml:26` `timing = { path = "crates/timing", package = "rvc-timing" }`), classified **`Infra`** | Plan `:655`; convention verified in the root `Cargo.toml` |
| **A-6-7** | Member count after the phase | **28 at ARCH-6a; 29 after ARCH-6f adds `remote-signer-client`** | The milestone's "28 members" is the ARCH-6a state. ARCH-6f owns the 29th `CLASSIFICATION` row and its own regeneration — stated so nobody reads a growing member count as a G-1 regression |
| **A-6-9** | Where does ARCH-6d's "exactly one `ProduceBlockResponse`" assertion live, given that `crates/architecture-tests/tests/` is Stream A's directory? | **A `#[test]` in `crates/block-service/src/traits.rs`'s `#[cfg(test)]` module** | Keeps the two streams file-disjoint for the whole phase. Promoting it into `architecture-tests` is reasonable follow-on work once the streams rejoin, but is not required to close ARCH-P1-9 |
| **A-6-8** | Does G-5a *define* Base membership? | **No.** G-5a is a **necessary constraint on** `Base`, not a definition of it. `rvc-slashing` (`Cargo.toml:19-22`: `observability`, `eth-types`, `metrics` — all Base) and `rvc-validator-store` (`:13-14`: `observability`, `eth-types`) are **structurally Base-eligible and are deliberately placed `Infra`** because they own I/O (SQLite; TOML persistence) | Prevents a future reviewer "fixing" the table by promoting every structurally-eligible crate into `Base` |

### Draft 28-row taxonomy (ARCH-6a's starting artefact — every row has a reason)

State: **after Phase 0** (`sync-service` deleted → 28 members), **before** ARCH-6f's new crate.
Sourced from `crates/architecture-tests/src/lib.rs:57-92`, **not** from the review's prose.

| # | Package | HEAD layer (`lib.rs:`) | Phase-6 layer | Reason |
|---|---|---|---|---|
| 1 | `rvc-bin` | Binary `:59` | **Binary** | Unchanged — CLI entry point |
| 2 | `rvc-keygen` | Binary `:60` | **Binary** | Unchanged — key generation binary |
| 3 | `rvc-signer-bin` | Binary `:61` | **Binary** | Unchanged — gRPC signing server binary |
| 4 | `rvc` | Orchestrator `:63` | **Orchestrator** | Unchanged — composition root |
| 5 | `rvc-block-service` | Domain `:65` | **Domain** | Duty logic: block proposal |
| 6 | `rvc-builder` | Domain `:66` | **Domain** | Duty logic: MEV registration |
| 7 | `rvc-doppelganger` | Domain `:67` | **Domain** | Duty-safety policy: duplicate detection |
| 8 | `rvc-duty-tracker` | Domain `:68` | **Domain** | Duty cache |
| 9 | `rvc-signer` | Domain `:69` | **Domain** | Safe-signing choke point (C9 anchor 2/5) |
| 10 | `rvc-signer-server` | Domain `:70` | **Domain** | Remote-signing library over the domain signing stack |
| — | ~~`rvc-sync-service`~~ | Domain `:71` | **deleted in Phase 0** | ARCH-P2-7 / D11 — not classified here |
| 11 | `rvc-timing` | Domain `:72` | **Base** ⚠ **reclassified** | Pure slot arithmetic; sole workspace out-edge is `eth-types` (`crates/timing/Cargo.toml:13`), itself `Base`. No I/O, no duty policy. Discharges VD-3 deliberately (A-P2). **Requires the matching `DOMAIN_PACKAGES` edit** |
| 12 | `beacon` | Foundation `:74` | **Infra** | Beacon-API HTTP client — network I/O |
| 13 | `rvc-bn-manager` | Foundation `:75` | **Infra** | Multi-BN pool, failover, SSE — network I/O |
| 14 | `rvc-crypto` | Foundation `:76` | **Base** (after ARCH-6f) | BLS + EIP-2333 + keystore only once `remote_signer/` leaves; out-edges then `observability`/`eth-types`/`web3signer-wire`, all Base. **Blocked on ARCH-6e+6f — until then it is `Infra` and G-5a must not assert it** |
| 15 | `rvc-eth-types` | Foundation `:77` | **Base** | Consensus types + SSZ; zero workspace out-edges, already pinned (`architecture_no_cycles.rs:73`) |
| 16 | `rvc-grpc-signer` | Foundation `:78` | **Infra** | tonic/gRPC client — network I/O. *(One of the two members the review's enumeration omits — VD-A1)* |
| 17 | `rvc-keymanager-api` | Foundation `:79` | **Infra** | Key-management REST surface — network I/O |
| 18 | `rvc-metrics` | Foundation `:80` | **Base** | Zero workspace out-edges (`crates/metrics/Cargo.toml:12-18`); ADR-011 enumerates it as a pure leaf. **Tension recorded (A-6-3):** it binds an axum listener in `server.rs`, so it is the one `Base` row whose reason is authority-based rather than purely structural |
| 19 | `rvc-observability` | Foundation `:81` | **Base** | Logging-field registry + redaction helpers; zero out-edges, already pinned (`:76`) |
| 20 | `rvc-secret-provider` | Foundation `:82` | **Infra** | Cloud KMS clients — network I/O |
| 21 | `rvc-signer-proto` | Foundation `:83` | **Base** | Generated protobuf types only; zero out-edges, already pinned (`:77`) |
| 22 | `rvc-signer-registry` | Foundation `:84` | **Base** | Const sign-type table, no runtime out-edges; already pinned (`:74`). *(The other member the review omits — VD-A1)* |
| 23 | `rvc-slashing` | Foundation `:85` | **Infra** | EIP-3076 SQLite store — filesystem/DB I/O. **Structurally Base-eligible** (out-edges `observability`/`eth-types`/`metrics`, `Cargo.toml:19-22`) **and deliberately not Base** (A-6-8) |
| 24 | `rvc-telemetry` | Foundation `:86` | **Base** | OTel/subscriber construction; zero out-edges, already pinned (`:75`) |
| 25 | `rvc-validator-store` | Foundation `:87` | **Infra** | Persists validator config to disk (`toml`/`tempfile`, `Cargo.toml:18,20`). Structurally Base-eligible; deliberately `Infra` (A-6-8) |
| 26 | `rvc-web3signer-wire` | Foundation `:88` | **Base** | Pure serde wire types; sole out-edge `eth-types` (`Cargo.toml:14`), itself Base |
| 27 | `rvc-architecture-tests` | Meta `:90` | **Meta** | Unchanged — dev-only gate harness (C9 anchor 1) |
| 28 | `rvc-test-support` | Meta `:91` | **Meta** | Unchanged — dev-only PKI/mTLS harness; already zero-out-edge pinned (`:78`) |
| +1 | `rvc-remote-signer-client` | *(new, ARCH-6f)* | **Infra** | Web3Signer HTTP client; reqwest — network I/O. Out-edges `crypto`(Base)/`eth-types`/`web3signer-wire`/`observability`: Infra→Base only, so G-5b holds and no cycle is created (`crypto` no longer depends on it) |

**Roll-up:** Base **9**, Infra **7**, Domain **6**, Orchestrator 1, Binary 3, Meta 2 = **28**.
(Foundation 15 + `rvc-timing` = 16 → 9 Base + 7 Infra. After ARCH-6f: Infra 8, total 29.)

---

## Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|---|---|---|---|---|---|
| **ARCH-6a** | `Layer::Base`/`Layer::Infra` split: 28 deliberate rows + `DOMAIN_PACKAGES` lock-step + doc regeneration | **3** | chore | — (Phase 0) | **A** |
| **ARCH-6b** | **G-5a** `layer_edges`: "a `Base` package may depend only on `Base`", with a synthetic RED | **2** | feature | ARCH-6a | **A** |
| **ARCH-6c** | **G-5b** `layer_edges`: no `Infra` → `Domain` edge, with a mandatory synthetic RED | **2** | feature | ARCH-6a | **A** |
| **ARCH-6d** | One `ProduceBlockResponse`: delete `block-service`'s twin and the adapter's field copy | **3** | chore | — | **B** |
| **ARCH-6e** | Decouple `CompositeSigner` from the concrete `RemoteSigner` (prerequisite of the extraction) | **2** | chore | — | **B** |
| **ARCH-6f** | Extract `remote-signer-client`; `crypto` becomes `Base`-eligible | **3** | chore | ARCH-6a, ARCH-6e | **B** |
| **ARCH-6g** | Move `is_aggregator` from `crypto` to `eth-types` | **1** | chore | ARCH-6f | **B** |
| **ARCH-6h** | Decentralize `metrics::definitions` + build the missing metric-name-stability assertion | **3** | chore | ARCH-6a | **A** |
| | **Total** | **19** | | | |

**Priority.** ARCH-6a/6b/6c/6f are **P1** (they own ARCH-P1-8 and ARCH-P1-10). ARCH-6d/6e/6g are
**P1** (ARCH-P1-9 and its enabler). ARCH-6h is **P2** (ARCH-P2-3) and is the phase's cut line if the
sprint must shrink — it is the only issue whose removal leaves every exit criterion but the last one
intact.

**G-5a's staging trap, stated once so no issue re-discovers it.** ARCH-6b lands the gate with
`crypto` still classified `Infra`; ARCH-6f flips `crypto` to `Base` **and** is the moment G-5a first
asserts anything about it. Landing 6b after 6f instead would be equally valid but delays the RED
demo; landing 6b *asserting* `crypto` before 6f is a knowingly-red merge and is forbidden
(`project-plan.md:93-96`).

## Phase Execution Plan

**Streams are disjoint by file.** Stream A owns `crates/architecture-tests/`, `crates/metrics/`,
`ARCHITECTURE.md`. Stream B owns `crates/beacon/`, `crates/block-service/`,
`crates/rvc/src/beacon_adapter.rs`, `crates/crypto/`, `crates/eth-types/`, and the new crate.

**The one real collision, and its protocol.** ARCH-6f creates a crate, which touches the root
`Cargo.toml` member list **and** `CLASSIFICATION` — Stream A's files. Resolution: ARCH-6f is
**blocked by ARCH-6a** (already in the table above) and carries the single-row addition plus its own
`make architecture-doc` regeneration. Stream A must not be mid-flight on `CLASSIFICATION` when 6f
merges; in practice A is on 6b/6c/6h by then, which do not touch the table. This is the plan's
`ARCHITECTURE.md` collision protocol (`project-plan.md:824-825`) applied concretely.

### Single developer (10–15 days)

| Day | Issue |
|---|---|
| 1–2 | ARCH-6a (3 pts) |
| 3 | ARCH-6b (2 pts) |
| 4 | ARCH-6c (2 pts) |
| 5–6 | ARCH-6d (3 pts) |
| 7 | ARCH-6e (2 pts) |
| 8–9 | ARCH-6f (3 pts) |
| 10 | ARCH-6g (1 pt) |
| 11–12 | ARCH-6h (3 pts) |
| 13–15 | Buffer: review turnaround, CI cycles, `arch-gates` first-run debugging (plan §5: +10–15 %) |

### Two developers (6–8 days on the critical path)

| Day | Stream A (`architecture-tests`, `metrics`, `ARCHITECTURE.md`) | Stream B (`beacon`, `block-service`, `crypto`, `eth-types`) |
|---|---|---|
| 1–2 | ARCH-6a (3) | ARCH-6d (3) |
| 3 | ARCH-6b (2) | ARCH-6e (2) |
| 4 | ARCH-6c (2) | ARCH-6f (3) — unblocked by 6a landing on day 2 |
| 5 | ARCH-6h (3) | ARCH-6f cont. |
| 6 | ARCH-6h cont. | ARCH-6g (1) |
| 7–8 | Integration: full `cargo nextest run --workspace`, both RED demos re-run, `ARCHITECTURE.md` regenerated once with 29 rows | |

**Sync point:** end of day 6 — both streams converge on one `make architecture-doc` regeneration
covering `rvc-timing`'s recolour, the legend change and `remote-signer-client`'s new row, then the
phase's single `ARCHITECTURE.md` commit is verified against `architecture_doc_matches_graph`.

---

## Issues

### ARCH-6a — `Layer::Base` / `Layer::Infra` split: 28 deliberate rows, `DOMAIN_PACKAGES` in lock-step, doc regenerated

- **Points:** 3 · **Scope:** 2 days · **Type:** chore · **Priority:** P1 · **Stream:** A
- **Blocked by:** — (Phase 0) · **Blocks:** ARCH-6b, ARCH-6c, ARCH-6f, ARCH-6h
- **Requirements:** ARCH-P1-8 (ADR-011). **Constraints:** **C9** anchor 1.

**Context.** `Layer::Foundation` (`crates/architecture-tests/src/lib.rs:74-88`) is a grab-bag: pure
leaves sit beside network and I/O services, so the no-Domain-dependency rule binds narrowly and
nothing structurally forbids a Foundation→Domain edge (ADR-011). This issue is the **re-labelling
only** — no gate, no edge change, no crate boundary moves (NG1). Start from the **table**, not the
review's prose: the review omits `rvc-signer-registry` (`:84`) and `rvc-grpc-signer` (`:78`), does not
place `rvc-slashing` (`:85`) or `rvc-validator-store` (`:87`) (VD-A1), and misclassifies `rvc-timing`
as a Foundation leaf when it sits in the **Domain** block at `:72` (VD-3). The draft 28-row table with
a per-row reason is in *§Assumptions* above and is this issue's starting artefact.

**Files to touch.**

- `crates/architecture-tests/src/lib.rs` — `Layer` enum `:28-39`; `mermaid_style` `:42-50`;
  `CLASSIFICATION` `:57-92`; `DOMAIN_PACKAGES` `:375-384`; the legend string `:294-299` (the
  `"Foundation crates"` line is `:298`).
- `ARCHITECTURE.md` — regenerated block (`:3`–`:181`) via `make architecture-doc`; **plus one hand
  edit outside the generated region**: `:698` reads *"Binary → Orchestrator → Domain → Foundation"*
  and names a retired layer. No gate catches it (VD-6-7).
- **Not touched:** `crates/architecture-tests/tests/architecture_no_cycles.rs` — `ZERO_OUT_EDGE_IF_PRESENT`
  (`:72-79`) is **retained unchanged** (plan `:654`).

**Implementation approach.**

1. Replace `Layer::Foundation` with `Layer::Base` and `Layer::Infra`. Per **A-6-5**, `Base` keeps
   `fill:#51cf66,color:#fff`; `Infra` takes a distinct shade, and the legend at `:294-299` names
   both.
2. Apply the 28-row table from *§Assumptions*. **Every row carries its reason as a code comment** —
   the exit criterion is "deliberate", and a row without a stated reason does not satisfy it.
3. `rvc-timing`: `Layer::Domain` → `Layer::Base` at `:72` **and** remove `"rvc-timing"` from
   `DOMAIN_PACKAGES` (`:383`). These are two edits enforced as one by the existing unit test
   `domain_packages_match_classification` (`:437-447`) — which is exactly why it is the RED test.
   **Verified non-consequence, record it in the PR:** `rvc-timing` is depended on only by
   `crates/rvc/Cargo.toml:43` (Orchestrator) and `bin/rvc/Cargo.toml:39` (Binary) — **no Domain
   crate depends on it** — so shrinking `DOMAIN_PACKAGES` cannot weaken the domain→domain rule or
   require a `DOMAIN_EDGE_ALLOWLIST` (`:391-399`) entry.
4. `rvc-crypto` stays **`Infra`** in this issue. It only becomes `Base` in ARCH-6f, after the
   extraction actually removes the reqwest edge (VD-6-3). Do not pre-flip it.
5. `make architecture-doc`, commit the regenerated `ARCHITECTURE.md`, hand-fix `:698`.

**TDD test plan.**

- **RED (first):** in `crates/architecture-tests/src/lib.rs`, change **only** `:72` to
  `Layer::Base`, leaving `DOMAIN_PACKAGES` untouched, and run
  `cargo test -p rvc-architecture-tests domain_packages_match_classification`. It **must fail** with
  *"DOMAIN_PACKAGES must match CLASSIFICATION Layer::Domain entries"* (`:447`). This proves the
  lock-step invariant is live before relying on it. Paste the failure into the PR.
- **RED (second):** after applying the full table but **before** regenerating, run
  `cargo test -p rvc-architecture-tests --test architecture_doc_matches_graph`. It **must fail** —
  `rvc-timing`'s style line changed colour and the legend changed. This is the demonstration that
  VD-6-7's reading is the correct one; a green result here would mean the split is invisible in the
  generated diagram and is a rename, not a taxonomy.
- **GREEN:** `make architecture-doc`; both tests green; `cargo nextest run -p rvc-architecture-tests`
  green (all seven existing gates).
- **New non-vacuity test:** `every_classification_row_has_a_reason` — assert
  `CLASSIFICATION.len() == cargo metadata member count` and that no blurb is empty. Cheap, and it is
  what stops a future member being added with a copy-pasted row.
- **KAT policy:** not applicable — no test in this issue matches
  `.*(tree_hash|signing_root|_root)$`. Confirm with
  `rg -n '(tree_hash|signing_root|_root)\s*\(' crates/architecture-tests/src/lib.rs` before opening
  the PR.

**Acceptance criteria.**

- [x] `Layer` has `Base` and `Infra` variants; `Foundation` is gone from the enum and from all uses.
- [x] `CLASSIFICATION` has **28** rows, each with a non-empty reason comment, matching the draft table
      (or departing from it with a written reason in the PR).
- [x] `rvc-timing` is `Layer::Base` **and** absent from `DOMAIN_PACKAGES`;
      `domain_packages_match_classification` green; the "no Domain consumer" check is recorded in the
      PR body.
- [x] `rvc-crypto` is still `Infra` (it flips in ARCH-6f).
- [x] `make architecture-doc` produces no further diff and
      `cargo test -p rvc-architecture-tests --test architecture_doc_matches_graph` is green — the
      exit criterion read as VD-6-7 specifies, **not** "the file is unchanged".
- [x] `ARCHITECTURE.md:698`'s hand-written layer chain names `Base`/`Infra`.
- [x] `ZERO_OUT_EDGE_IF_PRESENT` (`architecture_no_cycles.rs:72-79`) is byte-unchanged:
      `git diff <base> -- crates/architecture-tests/tests/architecture_no_cycles.rs` is empty.
- [x] `cargo nextest run --workspace` green; §2 standing commands green.

---

### ARCH-6b — G-5a `layer_edges`: a `Base` package may depend only on `Base`

- **Points:** 2 · **Scope:** 1 day · **Type:** feature · **Priority:** P1 · **Stream:** A
- **Blocked by:** ARCH-6a · **Blocks:** —
- **Requirements:** ARCH-P1-8 (gate G-5a, `architecture.md:1462-1464`). **Constraints:** **C9**
  anchor 1 (extend the harness, never replace it).

**Context — the definition correction is the issue.** G-5a as specified reads *"No `Layer::Base`
package may declare a production workspace dependency on any other workspace package"*
(`architecture.md:1462-1464`). **That is unsatisfiable for ADR-011's own decision** (VD-P5,
re-verified here as RV-4): `crates/crypto/Cargo.toml` declares `observability` (`:19`), `eth-types`
(`:24`) and `web3signer-wire` (`:26`), and the `remote_signer/` extraction removes **none** of them.
Under the literal rule `crypto` can never be `Base`. **This issue implements A-P2's reading: "a `Base`
package may depend only on other `Base` packages."** The existing hand-listed six-crate pin
`ZERO_OUT_EDGE_IF_PRESENT` (`architecture_no_cycles.rs:72-79`) is **retained unchanged** for the true
leaves — so the workspace keeps both rules: strict zero-out-edge for six named leaves, and
Base-may-only-reach-Base for the layer.

Also carry **A-6-8** into the gate's doc comment: G-5a is a **necessary constraint on** `Base`, not a
definition of it. `rvc-slashing` (`Cargo.toml:19-22`) and `rvc-validator-store` (`:13-14`) both pass
G-5a today and are deliberately `Infra`. Without this note the first reviewer to run the gate will
"fix" the table by promoting them.

**Files to touch.** `crates/architecture-tests/tests/layer_edges.rs` *(new)*; `src/lib.rs` only if a
`base_packages()` / `infra_packages()` helper is added beside `DOMAIN_PACKAGES` (`:375-384`) — reuse
`classification_map()` and `load_workspace_graph()` rather than re-parsing `cargo metadata`.

**Implementation approach.** Hand-rolled scan in the existing harness idiom (no new dependency,
Phase-1 rule P6 as in `no_rvc_prefix.rs:11`): for every package whose `CLASSIFICATION` layer is
`Base`, every workspace-internal **production** edge (`build_edge_map`'s `kind == null` filter,
`architecture_no_cycles.rs:110`) must point at a package that is also `Base`. Failure message names
**both** packages and both layers, e.g. `G-5a: Base package 'rvc-crypto' depends on 'rvc-slashing'
(Infra); a Base package may depend only on Base packages`.

**TDD test plan.**

- **RED (first, and the deliverable):** `g5a_is_red_against_a_scratch_violating_edge` — build a
  synthetic `WorkspaceGraph` in which a `Base` package carries an edge to an `Infra` package, run the
  predicate, and assert it reports the violation naming both packages. A gate that has never been
  seen red is unfalsifiable (R10). Reproduce the same RED against the real tree by temporarily adding
  `slashing.workspace = true` to `crates/timing/Cargo.toml` in a scratch worktree, paste the output
  into the PR, and discard the worktree.
- **RED (second, expected-green-later):** run G-5a on the real graph with `crypto` still `Infra`
  (ARCH-6a's state) — it must be **green**, proving the phase does not merge a knowingly-red gate.
- **Non-vacuity:** `g5a_scans_a_nonempty_base_set` — assert the `Base` set has ≥ 8 members and that
  at least one of them (`rvc-crypto` after 6f, `rvc-web3signer-wire` before) actually has out-edges
  to inspect. Without this the gate passes trivially if the layer predicate silently matches nothing.
- **KAT policy:** not applicable — no `*_root`/`*tree_hash*`/`*signing_root*` test names here.

**Acceptance criteria.**

- [x] `layer_edges.rs` exists and implements G-5a as "Base may depend only on Base" (A-P2), with the
      literal zero-out-edge wording explicitly rejected in the file's `//!` header **naming VD-P5 and
      `crates/crypto/Cargo.toml:19-26` as the reason**.
- [x] The failure message names both packages **and** both layers.
- [x] The synthetic RED test exists and passes (i.e. it proves the gate fires); the real-tree RED
      output is pasted in the PR.
- [x] The non-vacuity assertion exists.
- [x] `ZERO_OUT_EDGE_IF_PRESENT` is still byte-unchanged and still enforced.
- [x] G-5a is green on `develop` with `crypto` classified `Infra`.
- [x] `cargo nextest run -p rvc-architecture-tests` green in the Phase-0 `arch-gates` job.

---

### ARCH-6c — G-5b `layer_edges`: no `Infra` → `Domain` edge (green at HEAD, so the RED demo *is* the work)

- **Points:** 2 · **Scope:** 1 day · **Type:** feature · **Priority:** P1 · **Stream:** A
- **Blocked by:** ARCH-6a · **Blocks:** —
- **Requirements:** ARCH-P1-8 (gate G-5b, `architecture.md:1465-1466`). **Constraints:** **C9**
  anchor 1.

**Context — this gate is green on day one, and that is the risk.** VD-P4 established, and RV-7
re-confirms, that **no tracked Foundation member declares a Domain dependency**: spot-checked
`crates/slashing/Cargo.toml:19-28` (`observability`, `eth-types`, `metrics`) and
`crates/validator-store/Cargo.toml:13-14` (`observability`, `eth-types`), the two most likely
offenders. So **Phase 6 carries no hidden edge-removal work** — but a gate that is green the day it
lands and has never been seen red is indistinguishable from a gate that scans nothing (R10). The
synthetic RED demonstration is therefore not a formality; it is this issue's entire deliverable.

**One contingency, stated because it is easy to trip over.** The single Foundation→Domain hit VD-P4
found in the whole tree is `crates/rvc-signer/Cargo.toml:35`, **inside an untracked orphan tree**.
It is invisible to `cargo metadata` (non-member) and is deleted by Phase 0. If this issue is ever run
before Phase 0 lands, that path is still on disk and must **not** be cited, edited or migrated
(orphan-tree invariant, `project-plan.md:151-157`); it also cannot be revived, because
`crates/rvc-signer/Cargo.toml:2` declares the package name `rvc-signer-bin`, colliding with
`bin/rvc-signer` (VD-P1). See **C10** in *§Constraint Coverage*.

**Files to touch.** `crates/architecture-tests/tests/layer_edges.rs` (the same new file as ARCH-6b —
one file, two gate functions; sequence 6b then 6c to avoid a self-collision inside Stream A).

**Implementation approach.** For every `Layer::Infra` package, assert no production workspace edge
targets a `Layer::Domain` package. Reuse `DOMAIN_PACKAGES` (`src/lib.rs:375-384`) as the Domain
source of truth — it is already kept in lock-step with `CLASSIFICATION` by
`domain_packages_match_classification` (`:437-447`), so G-5b inherits that guarantee for free rather
than introducing a second, driftable list. Failure message names both packages, per
`architecture.md:1465-1466`.

**TDD test plan.**

- **RED (first, mandatory):** `g5b_is_red_against_a_scratch_infra_to_domain_edge` — synthetic graph
  with an `Infra` package depending on a `Domain` package; assert the violation is reported naming
  both. Then reproduce against the real tree in a scratch worktree by adding
  `signer.workspace = true` to `crates/beacon/Cargo.toml`; paste the failure output into the PR;
  discard the worktree. **A PR without this output does not satisfy the exit criterion**
  (`project-plan.md:676-677`).
- **Non-vacuity:** `g5b_scans_a_nonempty_infra_set_with_real_out_edges` — assert the `Infra` set is
  non-empty (7 members after ARCH-6a, 8 after ARCH-6f) and that at least one has production
  out-edges. This is the assertion that distinguishes "green because compliant" from "green because
  the predicate matched nothing".
- **GREEN:** G-5b passes on `develop`.
- **KAT policy:** not applicable.

**Acceptance criteria.**

- [x] G-5b implemented in `layer_edges.rs`; failure message names both packages.
- [x] Synthetic RED test present and passing; **real-tree RED output pasted in the PR**.
- [x] Non-vacuity assertion present, asserting a non-empty `Infra` set with real out-edges.
- [x] G-5b consumes `DOMAIN_PACKAGES` rather than a second hand-maintained Domain list.
- [x] The file header records VD-P4 — *"green at HEAD; the RED demo is why this gate is trustworthy"* —
      so a future reader does not mistake it for dead code.
- [x] G-5b green on `develop`; `cargo nextest run -p rvc-architecture-tests` green.

### ARCH-6d — One `ProduceBlockResponse`: delete the twin and the adapter's field copy

- **Points:** 3 · **Scope:** 2 days · **Type:** chore · **Priority:** P1 · **Stream:** B
- **Blocked by:** — · **Blocks:** —
- **Requirements:** ARCH-P1-9 (ADR-011). **Constraints:** **C9** anchor 1 (no new crate edge ⇒ no
  `ARCHITECTURE.md` change).

**Context — two verified facts that change how this is built.**

1. **VD-6-1:** the plan's *"`bn-manager` sanctioned as the types facade (A-8)"* is a re-export, not a
   definition. The two **definitions** are `crates/beacon/src/types.rs:132` and
   `crates/block-service/src/traits.rs:50`; `crates/bn-manager/src/lib.rs:34-43` re-exports `beacon`'s
   with the comment *"so downstream crates don't need to depend on `beacon` directly"* (`:32-33`).
   **That rationale does not bind `block-service`, which already takes a production `beacon`
   dependency** (`crates/block-service/Cargo.toml:14`, used at `service/mod.rs:306,323,341,576-577`
   for `beacon::ssz_deser`). **A-6-1: the survivor is `beacon::ProduceBlockResponse`** — zero new
   crate edges. Routing through `bn-manager` would *add* `block-service → bn-manager`, which does not
   exist today.
2. **VD-6-2:** the structs are **field-identical** — same six fields, same order, same doc comments
   (`types.rs:132-141` vs `traits.rs:50-59`). The **only** divergence is the inherent impl's error
   type: `Result<_, BeaconError>` with `BeaconError::ParseError` (`types.rs:145,151`) vs
   `Result<_, BlockServiceError>` with `BlockServiceError::Parse` (`traits.rs:62,67`). **That
   reconciliation is the whole design decision** and A-6-2 takes it explicitly: keep `BeaconError` on
   the inherent impl and convert at `block-service`'s boundary.

`crates/rvc/src/beacon_adapter.rs:33-40` is the seam this deletes: a six-field struct-literal copy
from one identical type to the other, executed on **every block proposal**.

**Files to touch.**

- `crates/block-service/src/traits.rs` — delete `struct ProduceBlockResponse` (`:50-59`) and its impl
  (`:61-71`); re-export `beacon::ProduceBlockResponse`. `traits.rs:21`'s signature is unchanged in
  shape.
- `crates/block-service/src/lib.rs:14` — `pub use` now re-exports the `beacon` type.
- `crates/block-service/src/service/mod.rs:11,294,400,491` — import path only.
- `crates/block-service/src/error.rs` (or wherever `BlockServiceError` lives) — add
  `impl From<BeaconError> for BlockServiceError` (~10 lines, A-6-2).
- `crates/rvc/src/beacon_adapter.rs:33-40` — **delete the field copy**; return the response directly.
- Test-side import updates: `block-service/src/service/tests/{mocks.rs:241,256,278,313,342,423,
  mod.rs:10}`, `service/tests/propose.rs:671,999,1022,1119`,
  `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:17,189`,
  `crates/rvc/tests/common/pipeline_fixture.rs:20`,
  `crates/rvc/tests/sync_independent_of_attesting.rs:32`.

**⚠ Cross-phase file collision — flag it in the PR.** `crates/rvc/src/beacon_adapter.rs` is **also**
in Phase 2's scope (`project-plan.md:436`, ADR-002 removes `#[async_trait(?Send)]` at `:18`). This
issue must **not** touch the `?Send` attribute, the trait bounds, or `traits.rs:13` — it changes only
the body at `:33-40` and the import at `:10`. If Phase 2 is in flight, whichever lands second rebases;
the two edits are on disjoint lines. This collision is not in the plan's §9 table
(`project-plan.md:824-825` lists W3/W4 only) and is recorded here.

**Implementation approach.** Delete-and-re-export, not copy-and-adapt. `parse_full_block` /
`parse_blinded_block` call sites inside `block-service` gain a `?`-through `From<BeaconError>` rather
than a changed signature, so the diff stays inside the two parse call chains.

**TDD test plan.**

- **RED (first):** `only_one_produce_block_response_definition_exists` — a scanner-style test in the
  `architecture-tests` idiom asserting `rg 'struct ProduceBlockResponse'` over `crates/**/src`
  yields **exactly one** path, and that path is `crates/beacon/src/types.rs`. Run it before the
  change: it must fail reporting **two** paths. This is M9's measurement, made executable rather than
  asserted. **Placement (A-6-9, decided, not deferred):** a `#[test]` in
  `crates/block-service/src/traits.rs`'s `#[cfg(test)]` module — `crates/architecture-tests/tests/` is
  Stream A's directory and using it here would break stream disjointness for one assertion.
- **GREEN-side regression pin (not a RED — stated plainly):**
  `beacon_adapter_preserves_all_six_fields_for_an_ssz_response` — assert `is_ssz = true` and
  `ssz_bytes = Some(...)` survive the adapter hop. The current field copy already does this
  correctly, so the test passes before and after; its value is pinning that the *deletion* of the copy
  loses nothing. Calling it a RED would be dishonest — RED #1 carries this issue.
- **Regression:** the three existing `beacon_adapter` wiremock tests (`:98`, `:130`, `:155`) must pass
  **unmodified**; they assert `execution_payload_value` and `consensus_version` survive the hop.
- **KAT policy:** not applicable — no test here matches `.*(tree_hash|signing_root|_root)$`, and none
  should be *named* into that pattern (these assert HTTP/field plumbing, not spec-defined roots — the
  same inverse obligation ADR-003 carries, `project-plan.md:144-146`). Verify with
  `rg -n 'fn test_.*(tree_hash|signing_root|_root)\b' crates/block-service crates/beacon` before the
  PR.

**Acceptance criteria.**

- [x] `rg 'struct ProduceBlockResponse' crates/**/src` returns **exactly one** hit
      (`crates/beacon/src/types.rs:132`). **M9 drops by one.**
- [x] `crates/rvc/src/beacon_adapter.rs` contains no `ProduceBlockResponse { … }` struct literal.
- [x] `impl From<BeaconError> for BlockServiceError` exists; no `parse_*` call site uses
      `.map_err(|e| …to_string())` to launder the error.
- [x] **No new workspace edge**: `git diff <base> -- '**/Cargo.toml'` is empty, and
      `cargo test -p rvc-architecture-tests --test architecture_doc_matches_graph` is green **without
      regenerating** `ARCHITECTURE.md`.
- [x] `crates/rvc/src/beacon_adapter.rs:18`'s `#[async_trait(?Send)]` and `traits.rs:13` are
      **byte-unchanged** (Phase 2 owns them): `git diff <base> -- crates/block-service/src/traits.rs`
      shows only the struct/impl deletion and the re-export.
- [x] The three existing adapter wiremock tests pass unmodified.
- [x] §2 standing commands green.

---

### ARCH-6e — Decouple `CompositeSigner` from the concrete `RemoteSigner`

- **Points:** 2 · **Scope:** 1 day · **Type:** chore · **Priority:** P1 · **Stream:** B
- **Blocked by:** — · **Blocks:** ARCH-6f
- **Requirements:** ARCH-P1-10 (ADR-011) — **enabler, not the deliverable**. **Constraints:** **C9**
  anchor 5 (single unbypassable signing gate).

**Context — this issue exists because of VD-6-3, and without it ARCH-6f cannot achieve its goal.**
ADR-011 says *"slim `rvc-crypto` into `Base` by extracting `remote_signer/` (the reqwest client) into
an Infra crate"* (`architecture.md:652-654`). Executed literally that **fails**: `CompositeSigner`
holds a **concrete** `remote: RwLock<HashMap<[u8; PUBLIC_KEY_BYTES_LEN], Arc<RemoteSigner>>>`
(`crates/crypto/src/composite_signer.rs:21`) and `add_remote_key(&self, pubkey, signer: RemoteSigner)`
takes it **by value** (`:81`). Moving `remote_signer/` out therefore creates
`crypto → remote-signer-client` (Infra) and `crypto` can never be `Base` — defeating ADR-011's own
decision. Neither the review, the PRD, the architecture nor the plan names this.

**The fix is already present in the same struct, one line above.** The field is used **only** through
the `Signer` trait (`:172-184`: `signer.sign(signing_root, pubkey).await`), and the sibling gRPC field
is already a trait object: `grpc_remote: RwLock<HashMap<…, Arc<dyn TypedSigner + Send + Sync>>>`
(`:20`). Making `remote` symmetric is the whole change.

**Files to touch.**

- `crates/crypto/src/composite_signer.rs` — field `:21`; `add_remote_key` signature `:81`; the lookup
  at `:172-184` (body unchanged); in-crate tests `:265-268, :304-307, :337-340, :399-404`.
- `crates/rvc/src/keymanager_adapters/remote_keys.rs:88` — the **only production call site**.
- `crates/signer/src/lib.rs:3304` — test call site.
- **Not touched:** `crates/crypto/src/remote_signer/**` (that is ARCH-6f), `crypto/Cargo.toml`.

**Implementation approach.** Change the field to
`RwLock<HashMap<[u8; PUBLIC_KEY_BYTES_LEN], Arc<dyn Signer + Send + Sync>>>` and
`add_remote_key(&self, pubkey: [u8; PUBLIC_KEY_BYTES_LEN], signer: Arc<dyn Signer + Send + Sync>)`,
mirroring `add_grpc_remote_signer` (`:39-52`). Callers wrap in `Arc::new(...)`. This issue moves **no
files and adds/removes no dependency** — that is what makes it safely separable and independently
revertible (NFR-4).

**C9 anchor 5 — must be discharged, not assumed.** The keep-list names *"single unbypassable signing
gate — single wiring site (`config/builder.rs:394`) + `CompositeSigner` grep gate"*
(`project-plan.md:168`). **Verification delta worth recording:** `rg 'CompositeSigner'
crates/architecture-tests` returns **one** hit and it is a synthetic input string inside
`tests/no_crypto_logging_paths.rs:103` (`"use crypto::{logging::TruncatedPubkey, CompositeSigner};"`)
— i.e. there is no standalone `CompositeSigner` grep gate at HEAD; the real constraint is that
`crypto::CompositeSigner` must remain importable at exactly that path. This issue keeps
`CompositeSigner` in `crypto` and changes only a parameter type, so the path and the wiring site are
untouched — and the acceptance criteria assert it.

**TDD test plan.**

- **RED (first):** `composite_signer_accepts_any_signer_impl_for_a_remote_key` — define a minimal
  in-test `struct FakeRemote` implementing `Signer` (returning a fixed signature), register it via
  `composite.add_remote_key(pk, Arc::new(FakeRemote))`, and assert `composite.sign(root, &pk)`
  dispatches to it. Against HEAD this **fails to compile** (`add_remote_key` demands a concrete
  `RemoteSigner`) — that compile error is the RED, and it is the sharpest available proof that the
  coupling exists. Paste it into the PR.
- **GREEN:** the test compiles and passes; the four existing in-crate remote-key tests
  (`:265, :304, :337, :399`) pass with only an `Arc::new` wrap.
- **Regression:** `crates/crypto/tests/signing_root_kat.rs` green — no signing behaviour changes.
- **KAT policy:** **applies by proximity.** No test is added or renamed into
  `.*(tree_hash|signing_root|_root)$` here; `signing_root_kat.rs` is re-run unmodified, which is
  sufficient because nothing it covers changes. If any test in this diff acquires such a name it must
  be KAT-anchored or carry `// kat_exempt: <reason>`; `EXEMPTIONS` is shrinking-only.

**Acceptance criteria.**

- [x] `CompositeSigner.remote` is `Arc<dyn Signer + Send + Sync>`; `crypto` contains no field or
      parameter typed as the concrete `RemoteSigner` outside `remote_signer/` itself.
- [x] `rg 'RemoteSigner' crates/crypto/src --glob '!remote_signer/**'` returns only doc/comment hits
      (`insecure.rs:8`) and `SigningError::RemoteSignerError` (`error.rs`) — no type usage.
- [x] The `FakeRemote` dispatch test exists and passes; its pre-change compile failure is in the PR.
- [x] `crypto::CompositeSigner` is still importable at that exact path;
      `crates/architecture-tests/tests/no_crypto_logging_paths.rs` green; the single wiring site
      `crates/rvc/src/config/builder.rs:394` is **byte-unchanged**.
- [x] `git diff <base> -- crates/crypto/Cargo.toml` is empty (no dependency moves in this issue).
- [x] `crates/crypto/tests/signing_root_kat.rs` green.
- [x] §2 standing commands green, including
      `cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings`.

---

### ARCH-6f — Extract `remote-signer-client`; `crypto` becomes a `Base` package

- **Points:** 3 · **Scope:** 2 days · **Type:** chore · **Priority:** P1 · **Stream:** B
- **Blocked by:** ARCH-6a (owns `CLASSIFICATION`), ARCH-6e (VD-6-3) · **Blocks:** ARCH-6g
- **Requirements:** ARCH-P1-10 (ADR-011). **Constraints:** **C9** anchors 1, 3, 5. **NG1** — this is
  *the one crate boundary this initiative moves*.

**Context.** `crypto` today is *"BLS, signing, Web3Signer"* (`architecture-tests/src/lib.rs:76`): a
pure-cryptography crate carrying a reqwest HTTP client. ADR-011 slims it to BLS + EIP-2333 + keystore
so it can be `Base`. **Verified removability (VD-6-5):** `reqwest` appears at **exactly one site** in
`crates/crypto/src` — `remote_signer/client.rs:12` — so `crypto/Cargo.toml:29` genuinely drops.
**Bonus finding:** `url` (`crypto/Cargo.toml:39`) has **no** use anywhere in `crates/crypto/src`; the
only `Url` hits are `observability::logging::RedactedUrl` (`client.rs:11`, `client_tests.rs:4`). It
appears already-dead and is dropped here with `cargo machete` as the proof (Phase 0's 0G otherwise
catches it).

**After the extraction `crypto`'s workspace out-edges are `observability` (`Cargo.toml:19`),
`eth-types` (`:24`), `web3signer-wire` (`:26`) — all `Base` — so it passes G-5a under A-P2's reading.**
That closure is what VD-P5 established and what makes ADR-011's decision satisfiable at all.

**Files to touch.**

- **New crate** `crates/remote-signer-client/` (package `rvc-remote-signer-client`, alias
  `remote-signer-client` — A-6-6), receiving `crates/crypto/src/remote_signer/{mod.rs, client.rs,
  wire.rs, client_tests.rs}` verbatim and `crates/crypto/tests/remote_signer_h10.rs`.
- Root `Cargo.toml` — `[workspace] members` + the alias line (convention: `Cargo.toml:26`).
- `crates/crypto/Cargo.toml` — drop `reqwest` (`:29`) and `url` (`:39`); drop `wiremock`
  (`:56`) if no remaining dev test needs it.
- `crates/crypto/src/lib.rs` — remove the `remote_signer` module and its re-exports.
- **Exactly one production consumer (VD-6-8 — the `rg` hit list is four-fifths false positives):**
  `crates/rvc/src/keymanager_adapters/remote_keys.rs:8` (`use crypto::{CompositeSigner, PublicKey,
  RemoteSigner, RemoteSignerConfig}`) and `:84-88`, plus `crates/rvc/Cargo.toml` gaining the new
  production edge (`rvc` is Orchestrator → Infra: allowed, no allow-list involved).
- **One dev-dependency:** `crates/signer/Cargo.toml` `[dev-dependencies]`, for
  `crates/signer/src/lib.rs:3300-3301`, which sits inside `#[cfg(test)] mod tests` (`:923-924`).
  Dev edges are invisible to every production-edge gate (`architecture_no_cycles.rs:110`).
- **Explicitly NOT consumers — do not add edges for these:** `crates/signer-server/src/backend/
  signer_adapter.rs:14,15,50,63-64` and `crates/signer/src/core.rs:26,72,706` reference only the
  **error variant** `SigningError::RemoteSignerError`; `crates/rvc/src/bootstrap/keys.rs:11,39` uses
  `grpc_signer::GrpcRemoteSigner`, a different type from a different crate; all
  `crates/grpc-signer/**` hits are its own type.
- **`SIGNER_SERVER_ALLOWED_EDGES` (`architecture_no_cycles.rs:93-102`) stays byte-unchanged.** It was
  checked deliberately: `rvc-signer-server` takes **no** edge to the new crate (VD-6-8), so the table
  the file warns against widening (`:90-92`) needs no row. **If a later refactor makes signer-server a
  real consumer, adding that row is the only sanctioned edit to that file in Phase 6, with the reason
  in the PR — and `ZERO_OUT_EDGE_IF_PRESENT` (`:72-79`) stays byte-unchanged regardless.**
- `crates/architecture-tests/src/lib.rs` — **one** `CLASSIFICATION` row (`rvc-remote-signer-client`,
  `Infra`) + `make architecture-doc`. **This is the Stream A/B collision; ARCH-6a must have landed.**
- **Not touched:** `crates/rvc-signer/`, `crates/rvc-keygen/` — untracked orphans, Phase 0's
  (**C10**). `crates/rvc-signer/src/backend/signer_adapter.rs` appears in the `rg` output and is
  **not** in this issue's list.

**Implementation approach.** `git mv` the four files so history follows them, then fix imports. The
new crate's out-edges are `crypto` (for `Signer`/`SigningError`/BLS types), `eth-types`,
`web3signer-wire`, `observability` — **`Infra → Base` only**, so G-5b holds and no cycle exists
(`crypto` no longer depends on it, courtesy of ARCH-6e). `crypto::remote_signer::*`'s stability note
(`mod.rs:7`) is retired: the public path becomes `remote_signer_client::*` and that rename is
operator-invisible but API-visible — note it in the release note.

**TDD test plan.**

- **RED (first, the gating probe — run before any file moves):** `crypto_declares_no_http_client` —
  a scanner-style test asserting no file under `crates/crypto/src` mentions `reqwest`. Against HEAD it
  **must fail**, naming `crates/crypto/src/remote_signer/client.rs:12`; after the move it must return
  nothing. Paste the pre-change failure into the PR. *(This is the executable form of the requirement:
  `reqwest` is an **external** crate, so `cargo metadata`-based gates such as G-5a cannot see it — the
  scan is the only detector.)*
- **RED (second):** with `crypto` flipped to `Layer::Base` **before** the move, ARCH-6b's G-5a must be
  green (its out-edges were already all-Base — RV-4) while the reqwest scan is red. That asymmetry is
  the point of VD-P5 and should be shown, not explained: G-5a alone does not catch an external HTTP
  dependency, which is why ARCH-P1-10 is a separate requirement from ARCH-P1-8.
- **GREEN:** all moved tests pass in their new home; `cargo build --workspace` and
  `cargo nextest run --workspace` green; G-5a green with `crypto` as `Base`.
- **KAT policy — flagged, and check before moving:** `crates/crypto/tests/signing_root_kat.rs` **stays
  in `crypto` and must be green unchanged** (ADR-011: *"KAT-anchored signing-root tests stay green —
  no signing behaviour change"*). Verified: `crates/crypto/tests/remote_signer_h10.rs` contains **no**
  identifier matching `signing_root` / `tree_hash` / `_root`, so moving it does not enter the KAT
  scanner's scope. **Re-run `rg -n '(tree_hash|signing_root|_root)' crates/crypto/tests/remote_signer_h10.rs
  crates/crypto/src/remote_signer` immediately before the move** — if any moved test name matches
  `.*(tree_hash|signing_root|_root)$` it needs a KAT constant or a documented
  `// kat_exempt: <reason>`; `EXEMPTIONS` is shrinking-only, never additive.

**Acceptance criteria.**

- [x] `crates/remote-signer-client/` exists; `rg 'reqwest' crates/crypto` returns nothing;
      `crypto/Cargo.toml` no longer lists `reqwest` or `url`, and `cargo machete` (or `cargo udeps`)
      confirms no unused dependency remains.
- [ ] `rvc-crypto` is `Layer::Base` in `CLASSIFICATION` and **G-5a is green over it**; the new crate
      is `Layer::Infra` and **G-5b is green over it**.
- [ ] `crypto`'s remaining workspace out-edges are exactly `observability`, `eth-types`,
      `web3signer-wire`.
- [x] The one production consumer (`remote_keys.rs`) compiles with the new import path;
      `crates/signer` carries the new crate only as a **dev-dependency**; `cargo build --workspace`
      green.
- [x] `crates/architecture-tests/tests/architecture_no_cycles.rs` is **byte-unchanged**, including
      `SIGNER_SERVER_ALLOWED_EDGES` (`:93-102`) — verified unnecessary, not merely skipped (VD-6-8).
- [x] **Signing-root KATs green:** `cargo test -p rvc-crypto --test signing_root_kat` passes with the
      file byte-unchanged. No new `EXEMPTIONS` entry (shrinking-only).
- [ ] Member count is **29** with `ARCHITECTURE.md` regenerated and
      `architecture_doc_matches_graph` green; `ZERO_OUT_EDGE_IF_PRESENT` still byte-unchanged.
- [x] Single wiring site `crates/rvc/src/config/builder.rs:394` byte-unchanged; C9 anchor 5 intact.
- [x] Release note records the `crypto::remote_signer::*` → `remote_signer_client::*` path change.
- [x] §2 standing commands green, including the `--features dvt` clippy run.

---

### ARCH-6g — Move `is_aggregator` from `crypto` to `eth-types`

- **Points:** 1 · **Scope:** 0.5 day · **Type:** chore · **Priority:** P1 · **Stream:** B
- **Blocked by:** ARCH-6f · **Blocks:** —
- **Requirements:** ARCH-P1-10 (ADR-011's *"moving `is_aggregator`/duty selection to `eth-types`"*).
  **Constraints:** **C9** anchor 3 (KAT-first).

**Context — cheaper than it looks, for a verified reason (VD-6-4).** `is_aggregator` is
`crates/crypto/src/aggregation_signing.rs:12`, re-exported at `crypto/src/lib.rs:50` and
`signer/src/lib.rs:23`. **No production code imports it from `crypto`** — both production call sites
go through `signer`: `crates/rvc/src/orchestrator/duty_management.rs:12,396` and
`aggregation.rs:15,198`. And `eth-types` **already declares `sha2`** for the sibling predicate
`is_sync_committee_aggregator` (`crates/eth-types/Cargo.toml:28-30`, whose comment reads *"External
only — keeps the zero workspace-internal out-edge pin for rvc-eth-types"*). So the move is
precedent-matching, adds no dependency, and provably cannot disturb `rvc-eth-types`'s zero-out-edge
pin (`architecture_no_cycles.rs:73`).

**Files to touch.** `crates/crypto/src/aggregation_signing.rs` (move the function **and its whole
test module `:22-128`**); `crates/eth-types/src/` (new sibling module beside
`is_sync_committee_aggregator`); `crates/crypto/src/lib.rs:50` (drop the re-export);
`crates/signer/src/lib.rs:23` (`pub use crypto::is_aggregator` → `pub use eth_types::is_aggregator`,
preserving `signer::is_aggregator` so **no orchestrator call site changes**).

**Implementation approach.** Preserve `signer::is_aggregator` as the public path so
`duty_management.rs` and `aggregation.rs` are byte-unchanged. Move the tests **with** the function —
in particular `test_is_aggregator_little_endian_golden_digest` (`aggregation_signing.rs:91`), which
pins the little-endian `bytes_to_uint64(sha256(proof)[0:8])` contract against literal bytes
independent of the function (`:96`). Losing or weakening it in the move is the failure mode.

**TDD test plan.**

- **RED (first):** `signer_reexports_is_aggregator_from_eth_types` — assert
  `eth_types::is_aggregator(1, &[0x00; 96])` is `true`. Against HEAD it **fails to compile**
  (`eth_types::is_aggregator` does not exist); that compile error is the RED.
- **Move-fidelity pin:** the golden-digest test must be present in the new location and pass
  **unmodified**; `git log --follow` shows the move.
- **Regression:** `crates/signer/src/lib.rs:2203-2205`
  (`test_is_aggregator_reexported`) passes unmodified — it is the existing pin on the public path.
- **Zero-out-edge pin:** `cargo test -p rvc-architecture-tests` — `rvc-eth-types` must still be in
  `ZERO_OUT_EDGE_IF_PRESENT` and still satisfy it (`sha2` is external, so the pin is unaffected).
- **KAT policy — flagged.** `test_is_aggregator_little_endian_golden_digest` does **not** match
  `.*(tree_hash|signing_root|_root)$`, so the scanner does not apply; it is nevertheless a
  known-answer test and must move intact. `crates/crypto/tests/signing_root_kat.rs:28` explicitly
  records *"`is_aggregator` tests are intentionally untouched (function survives RF2-08)"* — after
  this move that comment is stale and must be corrected, not left to mislead the next reader.

**Acceptance criteria.**

- [x] `is_aggregator` lives in `eth-types`; `rg 'fn is_aggregator' crates` returns one definition.
- [x] `signer::is_aggregator` still resolves; `crates/rvc/src/orchestrator/duty_management.rs` and
      `aggregation.rs` are **byte-unchanged**.
- [x] All ten `test_is_aggregator_*` tests, including the golden-digest KAT, exist in the new location
      and pass unmodified.
- [x] `crates/eth-types/Cargo.toml` gains **no** dependency; `rvc-eth-types` still satisfies
      `ZERO_OUT_EDGE_IF_PRESENT`.
- [x] `cargo machete -p rvc-crypto` re-run and clean: removing `is_aggregator` may strand `sha2`
      (`crypto/Cargo.toml:34`). ARCH-6f's `cargo machete` pass lands **before** this issue, so nothing
      else catches it.
- [x] `crates/crypto/tests/signing_root_kat.rs:28`'s now-stale note is corrected; the file otherwise
      green.
- [x] §2 standing commands green.

### ARCH-6h — Decentralize `metrics::definitions`, and build the acceptance gate that does not exist

- **Points:** 3 · **Scope:** 2 days · **Type:** chore · **Priority:** P2 · **Stream:** A
- **Blocked by:** ARCH-6a (layer rows must be correct first — plan `:667`) · **Blocks:** —
- **Requirements:** ARCH-P2-3. **Constraints:** **C9** anchor 1.

**Context — two corrections to the requirement as written (VD-6-6).**

1. PRD ARCH-P2-3's acceptance criterion *"the metrics-conformance gate still passes"* **names a gate
   that does not exist at HEAD.** `crates/metrics/tests/` does not exist; the seven gates under
   `crates/architecture-tests/tests/` contain no metrics gate, and `field_name_conformance.rs:1-9` is
   the **log-field** Gate 5 over a curated 16-event set. So the requirement currently has **no
   regression detector for the exact failure mode decentralization causes**: a metric silently
   renamed, dropped, or double-registered out of an operator dashboard. **A-6-4: building that
   assertion is part of this issue**, per architecture Design Principle 2.
2. The other criterion — *"`metrics` has no reverse dependency on domain crates"* — is **already true
   as a Cargo edge**: `crates/metrics/Cargo.toml:12-18` declares **zero** workspace dependencies
   (which is also why A-6-3 places it in `Base`). The real coupling is **lexical**: 24
   `pub static ref RVC_*` definitions in `crates/metrics/src/definitions.rs` name domain concepts
   (`RVC_ATTESTATIONS_TOTAL:15`, `RVC_DUTIES_FETCHED_TOTAL:28`, `RVC_SIGNING_DURATION_SECONDS:41`,
   `RVC_SLASHING_PROTECTION_CHECKS_TOTAL:55`, `RVC_ORCHESTRATOR_SLOTS_PROCESSED_TOTAL:68`, …). The
   acceptance criterion must be lexical or it is vacuous.

**Files to touch.**

- `crates/metrics/src/definitions.rs` — the 24 `lazy_static!` blocks; `crates/metrics/src/lib.rs:6`
  (`pub mod definitions`).
- The owning crates that already consume them (verified consumer set, orphan trees excluded):
  `crates/slashing/src/db/watermarks.rs`, `crates/signer/src/{lib.rs, core.rs}`,
  `crates/rvc/src/{slashing_monitor.rs, orchestrator/{duty_management.rs, coordinator/mod.rs,
  block_proposal/mod.rs, attestation.rs, aggregation.rs}, bootstrap/services.rs,
  background_tasks/{monitoring.rs, config_url.rs}}`, `crates/keymanager-api/src/handlers.rs`,
  `crates/duty-tracker/src/tracker.rs`, `crates/bn-manager/src/submit.rs`, `bin/rvc/src/cli.rs`,
  `bin/rvc/src/commands/slashing.rs`; plus the tests `crates/signer/tests/tx_hold_metric.rs`.
- `crates/metrics/tests/metric_name_stability.rs` *(new)*.
- **Not touched:** `crates/rvc/src/main.rs`, `crates/rvc/src/commands/slashing.rs` — untracked orphans
  deleted by Phase 0 (**C10**). If they still exist, this issue must not start.

**Implementation approach.** `metrics` keeps `REGISTRY` and the registration helper; each owning crate
declares its own metrics against the shared registry, so `metrics` retains only cross-cutting
primitives. Registration stays lazy-on-first-use so no ordering change is introduced. Move
metric-by-metric, not big-bang: the diff is 24 small moves, each independently verifiable against the
name-stability pin.

**⚠ Prometheus double-registration is the live hazard.** Today each `lazy_static!` block calls
`REGISTRY.register(...).expect("Failed to register …")` (e.g. `definitions.rs:22-23`) — a **panic** on
duplicate registration. Moving a definition while a stale re-export still forces the old block is a
startup panic, not a compile error. The name-stability test is what catches it before an operator
does.

**TDD test plan.**

- **RED (first, and it is the missing artefact):**
  `metric_name_set_is_unchanged` in `crates/metrics/tests/metric_name_stability.rs` — force
  registration of every definition, gather `REGISTRY`, collect the sorted set of metric family names,
  and assert it equals a checked-in `EXPECTED_METRIC_NAMES` constant of **24** entries. Write the
  constant **from the pre-change tree**, then delete one definition and watch it fail naming the
  missing metric. Paste that RED into the PR. The list is edit-only: a rename or removal must be a
  deliberate diff to the constant with an operator-facing note.
- **RED (second):** `no_domain_named_definition_remains_in_metrics` — a scanner-style assertion (the
  `no_rvc_prefix.rs` hand-rolled idiom, no new dependency) that `crates/metrics/src/definitions.rs`
  declares no `pub static ref` whose name matches a domain vocabulary list
  (`ATTESTATION|DUTY|DUTIES|SIGNING|SLASHING|ORCHESTRATOR|PROPOS|AGGREGAT|SYNC_COMMITTEE|BEACON`).
  Red at HEAD over all 24; green when the file holds only cross-cutting primitives. This is the
  lexical restatement of the PRD criterion (correction 2 above).
- **Regression:** `crates/signer/tests/tx_hold_metric.rs` green unmodified — it pins the hold-duration
  metric ADR-005/Phase 5 measures against, so a rename here would silently invalidate M3.
- **Double-registration guard:** a test that forces every metric twice in one process and asserts no
  panic.
- **KAT policy:** not applicable — no metric test matches `.*(tree_hash|signing_root|_root)$`. Do not
  name one into the pattern.

**Acceptance criteria.**

- [x] `crates/metrics/src/definitions.rs` contains no domain-named `pub static ref`; each domain metric
      is declared by its owning crate.
- [x] `crates/metrics/tests/metric_name_stability.rs` exists, pins **24** names, and its RED (one
      metric removed) is pasted in the PR. **This is the "metrics-conformance gate" ARCH-P2-3 is
      accepted against — it did not exist before this issue (VD-6-6).**
- [x] The domain-vocabulary scanner exists and is green.
- [x] `crates/metrics/Cargo.toml` still declares **zero** workspace dependencies (so `rvc-metrics`
      remains `Base`-eligible under A-6-3 and G-5a stays green over it).
- [x] `crates/signer/tests/tx_hold_metric.rs` green unmodified; the double-registration guard passes.
- [x] The `/metrics` endpoint's exposed name set is byte-identical before and after — no operator
      dashboard breaks.
- [x] §2 standing commands green.

---

## Constraint Coverage (C1–C10)

Every constraint is addressed explicitly: carried forward, or rejected with a stated reason. Silence
on any item would be a defect, but padding an inapplicable constraint into false relevance would be
worse — so the inapplicable ones are dismissed in one honest line each.

| ID | Constraint | Disposition in Phase 6 |
|---|---|---|
| **C1** | Retain-on-ambiguity vs lock-shortening; the redesign must be tentative-commit-then-reconcile, not a plain lock-scope shrink | **Not applicable — rejected for this phase with reason.** No issue here touches `crates/slashing/src/{stage.rs, core.rs}` or the signer's staging path; ADR-005 is **Phase 5**'s, and the plan makes Phases 5 and 6 explicitly parallel-safe on disjoint files (`project-plan.md:681-682`). One live interaction is worth naming: **ARCH-6a classifies `rvc-slashing` as `Infra`** (row 23), a label change only — no file under `crates/slashing/src/` is edited by any issue in this phase, so C1's safety property cannot be reached from here. |
| **C2** | Audit-log emission inside the mutex (`scoped.rs:70-75`) must move outside the lock | **Not applicable — owned by Phase 1** (ADR-006 / ARCH-P0-9 / G-7, `project-plan.md:391`). No Phase-6 issue edits `crates/slashing/src/scoped.rs`. Carried forward only as a non-regression: ARCH-6h moves metric *definitions*, never emission sites, so it cannot introduce a new in-lock emission. |
| **C3** | figment's `Env` provider is FORBIDDEN; "env = security opt-outs only", codified by an `RVC_*` allow-list gate | **Not applicable — owned by Phase 4** (ADR-008/ADR-010, G-3). No Phase-6 issue adds a dependency with an env layer or reads an environment variable. One adjacency, checked: ARCH-6f moves `REMOTE_SIGNER_INSECURE_ENV_VAR` (`crypto/src/remote_signer/mod.rs:12`) into the new crate **unchanged** — it is a security opt-out, exactly the permitted class, and the move must not alter its name or semantics. |
| **C4** | Keystore-less key admission — raw `SecretKey` with no keystore file and no denylist row | **Not applicable — owned by Phase 1** (ADR-007 / `KeyAdmissionService`). ARCH-6e changes `CompositeSigner::add_remote_key`'s parameter type; it does **not** touch `add_dynamic_local_key`, the denylist, or any admission path. Recorded as a non-regression in ARCH-6e's acceptance criteria via the unchanged wiring site. |
| **C5** | KM-2 teardown contract: `stop_monitoring` (graceful) vs `cancel_monitoring` (abort) must survive in whichever mechanism remains | **Not applicable — owned by Phase 7** (G-6 then ADR-015; VD-6 records that the gate does not exist at HEAD). No Phase-6 issue touches `crates/keymanager-api/` or `crates/doppelganger/`. ARCH-6a classifies `rvc-keymanager-api` as `Infra` (row 17) — a label only. |
| **C6** | Cold-cache pre-proposal fetch must be a bounded short-deadline fetch, never a silent skip | **Not applicable — owned by Phase 3** (ADR-004). No Phase-6 issue touches the slot loop. ARCH-6d edits `crates/rvc/src/beacon_adapter.rs:33-40` only, which is on the block-production hop, not the ordering decision — and it *removes* a per-proposal six-field copy, so its only latency effect is favourable (NFR-1 unaffected). |
| **C7** | SSE drops are normal: bounded `mpsc(64)`, drop-on-overflow, the 1/3-slot timer stays authoritative | **Not applicable — owned by Phase 3** (ADR-013). No Phase-6 issue touches `crates/bn-manager/src/sse.rs` or any channel. ARCH-6a classifies `rvc-bn-manager` as `Infra` (row 13) — a label only. Carried forward as a non-regression: ARCH-6h must not add an `error!`-level or failure-classed metric for an expected-path SSE drop. |
| **C8** | Healthz removal is operator-visible; needs a deprecation window and a probe-migration check | **Not applicable — split across Phase 0 (16a deprecation) and Phase 7 (16b removal).** No Phase-6 issue touches `crates/rvc/src/bootstrap/run.rs:263-276`. **One adjacency that must not be missed:** ARCH-6h changes where metrics are *declared*, and `crates/metrics/src/server.rs` is the crate that serves the `/health` + `/readyz` endpoints VD-P3 named as healthz's concrete replacement (`:57-64`, `:134`, `:145`). ARCH-6h must leave `server.rs` **byte-unchanged** — asserted by its `/metrics` name-set criterion plus `git diff <base> -- crates/metrics/src/server.rs` being empty. |
| **C9** | Preserve the keep-list: architecture-tests harness; cancellation-proof stage→sign→commit; KAT-first policy; "env = security opt-outs only"; single unbypassable signing gate; zero unbounded channels; `spawn_blocking` excluded from executor scope | **Binding — this phase can regress anchors 1, 3 and 5** (`project-plan.md:162-171`). **Anchor 1** (harness): every new gate is a **new file** in the existing hand-rolled idiom (`layer_edges.rs`, `metric_name_stability.rs`); no existing gate file is modified except `CLASSIFICATION`/`DOMAIN_PACKAGES`, and `ZERO_OUT_EDGE_IF_PRESENT` is asserted byte-unchanged in ARCH-6a, 6b and 6f. Byte-matched `ARCHITECTURE.md` regeneration is an exit criterion, read per VD-6-7. **Anchor 3** (KAT-first): flagged in ARCH-6e, 6f and 6g; `crates/crypto/tests/signing_root_kat.rs` green with the file byte-unchanged; **`EXEMPTIONS` shrinks only — no additive entry is permitted anywhere in this phase**; no new test is named into `.*(tree_hash\|signing_root\|_root)$`. **Anchor 5** (single signing gate): ARCH-6e/6f keep `CompositeSigner` in `crypto` at the path `no_crypto_logging_paths.rs:103` depends on and assert `crates/rvc/src/config/builder.rs:394` byte-unchanged. **Anchors 2, 4, 6, 7 are out of reach**: no issue edits the signer core, reads an env var, creates a channel, or adds a `spawn_blocking` site. |
| **C10** | Archive-before-delete for the untracked trees — `rm` is unrecoverable because no git object exists behind them | **Binding as an out-of-scope guard.** `crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`, `crates/rvc/src/commands/` are **never cited, edited, migrated or deleted by any issue in this phase**; their archive-verify-delete sequence is **Phase 0's ARCH-P0-1** and is an entry criterion here. Three concrete traps this phase would otherwise walk into, all excluded by name: (i) `crates/rvc-signer/Cargo.toml:35` is the **only** Foundation→Domain edge in the tree and it is inside an orphan — ARCH-6c must not "fix" it, and G-5b never sees it because non-members are outside `cargo metadata`; (ii) `crates/rvc-signer/src/backend/signer_adapter.rs` appears in ARCH-6f's `rg` output and is **excluded from its file list**, unlike the tracked `crates/signer-server/src/backend/signer_adapter.rs`; (iii) `crates/rvc/src/main.rs` and `crates/rvc/src/commands/slashing.rs` appear in ARCH-6h's consumer grep and are **excluded**. Neither orphan can be revived by adding it to `[workspace] members` — **both** collide by package name (VD-P1: `rvc-signer-bin` and `rvc-keygen`). |

---

## Risks carried by this phase

| ID | Risk | Mitigation in this file |
|---|---|---|
| **RP5** | `CLASSIFICATION` / `ARCHITECTURE.md` collision with another stream touching the member list | ARCH-6f is `Blocked by` ARCH-6a; one regeneration at the day-6 sync point; Phase 4's `rvc-config` and Phase 6's `remote-signer-client` are the two crate additions in the initiative and both are named in `project-plan.md:825` |
| **R10** | A gate green on day one (G-5b) is treated as noise | Synthetic **and** real-tree RED demos are acceptance criteria in ARCH-6c, plus a non-vacuity assertion on the `Infra` set |
| **New — VD-6-3** | The `crypto`-into-`Base` extraction is attempted without ARCH-6e and silently re-couples `crypto` to an `Infra` crate | ARCH-6e is a separate, blocking issue with a compile-error RED; ARCH-6f's acceptance asserts `crypto`'s exact remaining out-edge set |
| **New — VD-6-7** | "Regenerates byte-identically" is read as "do not touch `ARCHITECTURE.md`", so the legend and `:698` are left naming a retired layer, or the file is hand-edited to force a clean diff | The reading is corrected in the exit criteria, in ARCH-6a's second RED, and in the acceptance criterion wording ("no *further* diff after `make architecture-doc`") |
| **New — VD-6-6** | ARCH-P2-3 is closed against a gate that does not exist, so a renamed metric ships | ARCH-6h **builds** the name-stability pin as part of the issue, with its own RED |
| **Cross-phase** | `crates/rvc/src/beacon_adapter.rs` is edited by both ARCH-6d and Phase 2's ADR-002 | Flagged in ARCH-6d; the edits are on disjoint lines (`:33-40` body vs `:18` attribute); whichever lands second rebases |
