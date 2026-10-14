# Phase 7 — Fork & Scale Readiness

> Sprint-ready issue breakdown for **Phase 7** of the rs-vc architecture-remediation initiative.
> Baseline **`develop` @ `0ae9a09` (v0.7.0)**, authored 2026-08-12. Every `file:line` below was
> re-opened against this working tree while writing; nothing is copied forward on trust.
>
> **Authoritative inputs, in precedence order:**
> [`../project-plan.md`](../project-plan.md) §7 *Phase 7* and §8 (binding intra-phase order) →
> [`../architecture.md`](../architecture.md) (ADR-014, ADR-015, ADR-011 dependents; gate **G-6**) →
> [`../prd.md`](../prd.md) (ARCH-P1-7, P1-11, P1-14, P1-15b, P1-16b, P2-4, P2-8) →
> [`../research/`](../research/) →
> [`../../../docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md)
> §*Migration plan* Phase 5 (`:211`) and §*Fork handling* (`:191`).
>
> **What this file adds over its inputs.** Seven verification deltas found while estimating
> (§3), three of which change an issue's shape rather than its wording:
> **VD-7A** — the "legacy doppelganger mechanism" ADR-015 retires is **already unwired from
> production**; what is live is a *different* legacy object on the opt-out path, which splits 7B in
> two and moves the risk;
> **VD-7C** — the `Wire*` deletion is gated on a **dependency-version trigger that is not satisfied at
> HEAD** (`ethereum_ssz` 0.8.3 *and* 0.9.1 are both pinned in `Cargo.lock`), so it cannot be
> scheduled as ordinary work and becomes spike → conditional collapse → recorded deferral;
> **VD-7D** — registering the DVT surface **breaks two existing assertions** in the enumeration gate
> (`all_entries_use_v2_service_path`, the `EXPECTED = 10` count floor), so ARCH-P1-7 is a registry
> *model* change, not an append.
> Plus interface-level detail the upstream documents do not carry: the exact CI invocation for a dvt
> **test** run, the `DoppelgangerMonitor` implementor table G-6 must classify against, the counted
> `grpc_*` disposal footprint including the `#[serde(default)]` trap, and the role-vs-tier narrowing
> of ARCH-P2-8.
>
> **No-ask constraint:** every open question is resolved to a stated default in §2 *Assumptions*.
> Nothing is escalated.
>
> **Scope:** planning only. This document changes no source file and deletes nothing. It writes only
> to `plan/architecture-2026-08-12/issues/07-phase-7.md`. `docs/prd.md`, `docs/architecture.md` and
> `docs/project-plan.md` belong to the older Test Audit Remediation initiative and are untouched
> (project-plan NG8).

---

## 1. Phase Overview

**Goal.** Be ready for the next hard fork and for deployments above the current supported key count,
and close the two removals that were deliberately deferred behind a gate (G-6) and a deprecation
window (C8).

| | |
|---|---|
| **Issues** | 13 (`ARCH-7a` … `ARCH-7m`) |
| **Points** | **29** (1 / 2 / 3 scale; no issue exceeds 3) |
| **Duration, 1 developer** | **18–22 working days** — see the departure note below |
| **Duration, 2 developers** | **11–14 working days** (critical path = Stream B, 16 pts) |
| **Requirements** | ARCH-P1-7, ARCH-P1-11, ARCH-P1-14, ARCH-P1-15b, ARCH-P1-16b, ARCH-P2-4, ARCH-P2-8 |
| **ADRs / gates** | ADR-015, ADR-014, ADR-011 (dependents); gate **G-6** + 1 new CI check |
| **Depends on phases** | **1** (ADR-007 rebuilt the admission path), **5** (7m reuses 5A's harness), **6** (ADR-011 owns P1-14's seam work), and **0** for the C8 deprecation clock |

**Departure from the project plan's sizing, stated rather than absorbed.** `project-plan.md:278`
sizes Phase 7 at **14–20 d**. This breakdown lands at **18–22 d** for one developer. The delta is one
item and one item only: **VD-7C**. The plan's 7C reads *"Delete the `Wire*` twins"* as executable
work; at HEAD the documented deletion trigger (`crates/eth-types/src/block_body.rs:41-43`) is **not
satisfied**, and discharging it costs a spike plus a conditional collapse instead of a delete. Every
other package sizes at or below the plan's implied budget — two of them (7B's dead-code half, P2-4)
size **below** it because of VD-7A and VD-7G.

### Entry criteria

- [ ] **Phase 6 complete** — `CLASSIFICATION` stable at 28 rows, `ARCHITECTURE.md` regenerating
      byte-identically. `ARCH-7a`/`7j`/`7l` all add or read gate files in `crates/architecture-tests`.
- [ ] **Phase 5 complete** — the M3 load harness built at 5A exists and has produced a pre/post
      number; `ARCH-7m` reuses it and does not build one.
- [ ] **Phase 1 complete** — ADR-007's `KeyAdmissionService` has landed, so the admission path
      `ARCH-7b`/`7c` touch is the rebuilt one, not the HEAD one (C4 was discharged there).
- [ ] **Phase 0's healthz deprecation (`0F` / ARCH-P1-16a) shipped in a release that is now at least
      one release old** — a *calendar* precondition on `ARCH-7d`/`7e` only (C8). If it is not, 7d/7e
      slip; the rest of the phase does not.
- [ ] Working tree green on all §2 standing commands of the project plan
      (`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings`,
      `cargo build --workspace`, `cargo nextest run --workspace`).

### Exit criteria (the milestone, as a checklist)

- [ ] **One SSZ stack per container** — one struct per container in `crates/eth-types`, *or*, if
      `ARCH-7f`'s verdict is "unsatisfiable", a **recorded, trigger-bearing deferral** in
      `docs/forks.md` plus a CI reminder. A silent skip fails this criterion.
- [ ] **Every touched container-root test re-anchored**, not merely re-run — each asserts against
      `EXTERNAL_ELECTRA_BODY_ROOT_HEX` / `EXTERNAL_ELECTRA_BLOCK_ROOT_HEX` /
      `EXTERNAL_BLINDED_ELECTRA_*` / `EXTERNAL_DENEB_*` (`block_body.rs:794-825`), and
      `kat_policy`'s `EXEMPTIONS` has not grown (C9 anchor 3, `CLAUDE.md` KAT-first policy).
- [ ] **`docs/forks.md` exists and every path in it resolves** under Phase 0's docs-freshness scan.
- [ ] **One doppelganger mechanism behind G-6** — `crates/architecture-tests/tests/km2_lifecycle.rs`
      is green, and RED against a scratch collapse of `stop_monitoring`/`cancel_monitoring`;
      `rg 'LegacySlashingHistoryReader'` returns nothing; `rg 'DoppelgangerService'` returns nothing
      in `crates/` or `bin/`; the DELETE path still calls `remove_validator` + `cancel_monitoring`.
- [ ] **The `signer-registry` enumeration gate passes under `--features dvt`** as a **new CI step**
      (`cargo nextest run -p rvc-signer-server --features dvt`), and a test asserts a DVT partial
      signature cannot be produced outside the registered contract.
- [x] **Healthz removed with its knobs disposed** — no `DutyTrackerServer`, no gRPC `select!` arm, and
      a TOML carrying `grpc_port` / `grpc_address` is **rejected at startup** with a message naming
      `/health` and `/readyz` (never accepted-and-ignored — that is PB-B1's failure mode inside the
      change meant to end it).
      *Closure note (2026-09-06): ARCH-7d removed the listener (`32e8a44`); ARCH-7e rejects leftover keys.*
- [ ] **A documented 200-key / 200 ms run is checked into `plan/architecture-2026-08-12/`** — zero
      missed attestation deadlines, `rvc_signer_slashing_tx_hold_duration_ms` p99 recorded, and the
      scope stated honestly (this validates the `signer-server` path — A-A8).
- [x] **M7 = 0** — `BnRole` broadcast routing is honoured or the surface is rejected (`ARCH-7k`); with
      the four closed in Phase 1 and healthz's two knobs disposed in `ARCH-7e`, no inert config
      surface remains.
      *Closure note (2026-09-06): ARCH-7k (`e14afba`) honours `BnRole`; ARCH-7e rejects `grpc_*` keys.*
- [ ] **M5 reached, in M5's own enumeration** (`prd.md:995`): `ARCH-7a` lands the **7th** of the +7
      gates (KM-2 teardown), and `ARCH-7j` lands the **third and last** of the +3 CI checks
      (`--features dvt` enumeration run); the other two (docs-freshness, unused-deps) landed in
      Phase 0 (`project-plan.md:344`, work package 0G). See **VD-7F** for why "+7" is not the total gate count of the initiative.
- [ ] All five standing green-build commands pass; `cargo nextest run --workspace` (**not**
      `cargo test --workspace`, which deadlocks in this repo — project-plan §2).

---

## 2. Assumptions, verified against HEAD (`0ae9a09`)

Every row below was checked by opening the cited file at the cited lines. **No open question is
escalated**; each is resolved to a stated default (project-plan §12 convention).

| ID | Assumption / decision | Evidence at HEAD | Default taken |
|---|---|---|---|
| **A-7.1** | The KM-2 contract is held by a trait *default*, and the default is the trap. | `crates/keymanager-api/src/traits.rs:80` declares `fn stop_monitoring`; `:86-88` defines `fn cancel_monitoring(&self, pubkey: &Pubkey) { self.stop_monitoring(pubkey); }`. Doc at `:73-79` states `stop_monitoring` "**Must not** tear down forward-window enablement state". | G-6 is written as a **classification**, not a ban: inheriting the default is *correct* for time-based implementors and *fatal* for machine-backed ones (A-7.2). |
| **A-7.2** | There are exactly **four** `impl DoppelgangerMonitor for` sites in the workspace outside the orphan trees. | `crates/rvc/src/keymanager_adapters/doppelganger.rs:123` (`DoppelgangerMonitorAdapter`, log-only), `:181` (`ForwardWindowMonitor`, machine-backed — overrides `cancel_monitoring` at `:216-233`), `crates/keymanager-api/src/gate.rs:63` (`DoppelgangerGate`, time-based, inherits the default), `crates/keymanager-api/src/server.rs:274` (`StubDoppelganger`, test-only). | G-6's classification input is this table; `crates/keymanager-api/src/lifecycle.rs:356` already records in a comment that the inherited default on `DoppelgangerGate` is "safe". |
| **A-7.3** | The `DoppelgangerGate` branch is reached **exactly** on the doppelganger opt-out path, where the window is `Duration::ZERO`. | `keymanager_adapters/spawn.rs:91-101` selects `ForwardWindowMonitor` iff `forward_window_machine.is_some()`, else `DoppelgangerGate`; `:165-169` sets the window to `ZERO` iff `!config.doppelganger_detection`; `bootstrap/enablement.rs:365-368` (detection on ⇒ machine `is_some`) and `:403` (opt-out ⇒ `is_none`) pin the equivalence; `gate.rs:139-146` (`test_zero_window_is_immediately_safe`). | `ARCH-7c` replaces the branch with an explicitly-named always-safe monitor. **Behaviour-preserving by construction**, and the equivalence is re-pinned by 7c's RED test rather than assumed. |
| **A-7.4** | `crates/signer/src/dvt/peer_service.rs` — the path the PRD and architecture cite — **does not exist**. | `Glob crates/*/src/dvt/peer_service.rs` returns `crates/signer-server/src/dvt/peer_service.rs` and `crates/rvc-signer/src/dvt/peer_service.rs` (the latter is an orphan Phase 0 deletes). | All ARCH-P1-7 work targets **`crates/signer-server/`**; see **VD-7B**. |
| **A-7.5** | The DVT partial-sign path is **slashing-protected but gate-unclassified** — it is not an ungated signing hole. | `signer-server/src/dvt/peer_service.rs:227` `PubkeyScopedDb::new`, `:232-234` `stage_block`, `:236` `partial_sign_with_share`, `:240-242` `commit()`, `:246` `discard()`; identical shape for attestations at `:319`, `:325`, `:328`, `:333`, `:338`. `SigningGate` is never called. | ARCH-P1-7 is discharged via the PRD's **second** option — "formally register it in `signer-registry` with its own enforcement contract" — not by routing share-signing through a `SigningGate` built for full BLS keys. Stated as a decision in `ARCH-7i`, not discovered at compile time. |
| **A-7.6** | `--features dvt` cannot be applied to a workspace test run. | `dvt` is declared only on `bin/rvc-signer/Cargo.toml:19` (`dvt = ["signer-server/dvt"]`) and `crates/signer-server/Cargo.toml:20`. `.github/workflows/ci.yml:166` is the only place a `#[test]` executes (`cargo llvm-cov nextest --workspace`, default features); `:46-47` is **clippy only**, scoped `-p rvc-signer-bin`. | The new CI step is **`cargo nextest run -p rvc-signer-server --features dvt`**, added to the `arch-gates` job Phase 0 created (A-P1), not to `coverage`. |
| **A-7.7** | Removing a `ConfigWire` field makes an existing operator TOML key **silently ignored**, not rejected. | `crates/rvc/src/config/types.rs:628-630`: `#[derive(Debug, Default, Deserialize)] #[serde(default)] struct ConfigWire` — there is **no** `deny_unknown_fields`. | `ARCH-7e` disposes the knobs by **explicit startup rejection** (a named `ConfigError` listing the removed keys and the replacement probes), not by deletion. Required, not preferred: `prd.md:997` defines M7's target as "each either applied or **rejected at startup**". |
| **A-7.8** | ARCH-P2-8's "`BnRole`/tier" phrasing is **narrowed to role only**. | `crates/bn-manager/src/manager.rs:737-738` documents `broadcast` as "to all BNs (**regardless of sync status**)"; `:764` iterates `self.clients` unfiltered; `:746` reports `tried = self.clients.len()`. `synced_indices(role, min_tier)` at `:328` already implements role → tier → score with an `All`-role fallback documented at `:318-327`. | `ARCH-7k` filters by **role** and reuses the `All`-fallback, with a **permissive tier floor**. Tier-filtering a publish fan-out would reduce the number of BNs an already-signed attestation reaches — a safety regression dressed as a fix. The narrowing is recorded in the issue, not silently applied. |
| **A-7.9** | The pre-slot BN health re-check bundled into ARCH-P2-8 is **descoped from this phase**. | `project-plan.md:715` itself marks it "optional"; it is a slot-loop change in `crates/rvc/src/orchestrator/`, which Phase 3 owns, and it would move the M2 slot-phase-0 offset that Phase 0 baselined and Phase 3 was judged against (NFR-1). | Rejected here with reason; recorded as follow-on work. ARCH-P2-8's acceptance criterion (`prd.md:960`) is satisfied by the broadcast half alone. |
| **A-7.10** | `docs/forks.md` lands **regardless** of the `Wire*` verdict. | `prd.md:912-923` states two deliverables under one ID; the review (`:191`) likewise. The dispatch-site enumeration has no dependency on the SSZ stack question. | `ARCH-7g` is unblocked by `ARCH-7f` and ships in either branch; it is also where a deferral verdict is **recorded** (`ARCH-7h`). |
| **A-7.11** | The scale-validation artefact path is fixed now, so 7m has somewhere to write. | `project-plan.md:714` requires the numbers "checked into `plan/architecture-2026-08-12/`"; `prd.md:934` "checked into the plan directory, not just observed". | **`plan/architecture-2026-08-12/measurements/m3-scale-200keys-200ms.md`**, alongside Phase 0's M1/M2 files. Creating it is `ARCH-7m`'s deliverable — **not** this planning task's. |
| **A-7.12** | One release ships per phase boundary, so C8's window has in fact elapsed by the time Phase 7 starts. | project-plan A-P11 / §6a. | Carried unchanged. If it has not, 7d/7e slip alone (they are the only C8-bound issues) — the phase is not blocked. |

---

## 3. Verification deltas found while estimating

Seven deltas, prefixed `VD-7`. Three change an issue's shape (**VD-7A**, **VD-7C**, **VD-7D**); one
removes scope (**VD-7G**); one corrects a path every upstream document repeats (**VD-7B**).

| ID | Claim as written upstream | Status at HEAD | Corrected fact carried forward | Lands in |
|---|---|---|---|---|
| **VD-7A** | ADR-015 / `prd.md:867` / review `:189`: *"Retire the legacy time-based `DoppelgangerGate`/`DoppelgangerService` **once** `ForwardWindowMachine` covers its consumers"* — framed as retiring a live mechanism with live consumers. | **Half of it is already unwired; the other half is live for a different reason.** | `DoppelgangerService::new` is called **only** from its own `#[cfg(test)]` module (`crates/doppelganger/src/service.rs:388`…`:1032`) and `crates/doppelganger/tests/clock_m7.rs:52`. `SlashingDbReaderAdapter` — the workspace's only `impl LegacySlashingHistoryReader` (`crates/rvc/src/doppelganger_adapter.rs:97`) — is constructed only at `:115`, `:125`, `:137`, all inside its own test module. `crates/rvc/src/liveness_loop.rs:15` states it outright: *"the backward one-shot `DoppelgangerService` is not wired"*. **So that half is a dead-but-public API deletion with no behavioural risk** (2 pts, `ARCH-7b`). What *is* live is `DoppelgangerGate`, reached at `keymanager_adapters/spawn.rs:99` **only on the doppelganger opt-out path** (A-7.3) — a different object with a different risk profile, and the one that actually needs a behaviour-preservation test (`ARCH-7c`). Retiring them as one issue would attach the dead half's zero risk to the live half's real one. | `ARCH-7b`, `ARCH-7c` |
| **VD-7B** | `prd.md:822`, `architecture.md` §7.1 anchor 5, `project-plan.md:701`: the DVT bypass is at **`crates/signer/src/dvt/peer_service.rs:227-230`**. | **The path does not exist.** | The file is **`crates/signer-server/src/dvt/peer_service.rs`** (package `rvc-signer-server`, `Cargo.toml:2`). The upstream is internally inconsistent about this: architecture §7.1 anchor **7** already cites the correct `signer-server/src/dvt/peer_service.rs:231,323` for the `spawn_blocking` exclusion — the same file the anchor-5 row misnames. Both `:231` and `:323` re-verified as `tokio::task::spawn_blocking` (C9 anchor 7 stands, unchanged). | `ARCH-7i`, `ARCH-7j` |
| **VD-7C** | `prd.md:916` / review `:191` / `project-plan.md:711`: *"Execute the already-documented `Wire*` twin deletion"* — scheduled as ordinary work. | **The documented trigger is not satisfied at HEAD, and satisfying it as written is a workspace-wide dependency upgrade.** | `crates/eth-types/src/block_body.rs:41-43` states the trigger: *"remove the `Wire*` twins when `ssz_types` compiles against `ethereum_ssz` 0.9 (or workspace `ssz` aligns with the stack `ssz_types` implements)"*. At HEAD the root `Cargo.toml` pins `ssz = ethereum_ssz 0.9` (`:88`), `ssz08 = ethereum_ssz 0.8.3` (`:93`), `ssz_types = 0.10.1` (`:98`), `tree_hash = 0.9` (`:99`), and `Cargo.lock` carries **both** `ethereum_ssz 0.8.3` (`:1526-1527`) and `0.9.1` (`:1541-1542`). The root manifest's own comment (`:95-97`) says `ssz_types` 0.11+ "pin tree_hash ≥ 0.10" and warns against jumping without a **workspace-wide `tree_hash` upgrade** — which would touch every `TreeHash` derive, including every KAT-anchored signing-root test. **A third path exists that the trigger text does not consider** and that needs no dependency change: the two `Encode`/`Decode` trait sets come from two *different* crates, so both can be implemented on **one** struct — `crate::Checkpoint` already derives 0.9 `Encode, Decode` + `TreeHash` (`lib.rs:119-125`) while `WireCheckpoint` gets 0.8 impls from the hand-written `ssz_container!` macro (`block_body.rs:127-218`, `:302`); both `TreeHash` derives come from the same `tree_hash_derive` 0.9. The verdict is a **compile**, so the work is spike → conditional collapse → recorded deferral, never a scheduled delete. Scope relief: the `Wire*` types are used **only inside `block_body.rs`** (40 occurrences; zero elsewhere in `crates/` or `bin/`), so no downstream consumer breaks. | `ARCH-7f`, `ARCH-7g`, `ARCH-7h` |
| **VD-7D** | `prd.md:826`: *"The `signer-registry` enumeration gate runs with `--features dvt` in CI and passes"* — reads as adding entries plus a flag. | **Adding DVT entries makes the gate fail on two assertions that have nothing to do with gating.** | `crates/signer-server/tests/signing_path_enumeration.rs:104-115` (`all_entries_use_v2_service_path`) asserts **every** entry's `service` equals `"signer.v2.SignerService"` (`:105`); `:122-130` asserts `REGISTERED_METHODS.len() == EXPECTED` with `EXPECTED: usize = 10` (`:124`). The DVT peer service is a different gRPC service, so registration breaks both — and `rvc-signer-registry` has **no `dvt` feature** (only `bin/rvc-signer` and `crates/signer-server` declare one), so unconditional entries would change the count for the default-features run too. ARCH-P1-7 is therefore a registry **model** change: a `dvt` feature on `rvc-signer-registry` chained from `signer-server/dvt`, `#[cfg(feature = "dvt")]` entries, a feature-conditional count, a two-name service allow-list, and a new enforcement variant — with the strict M4 invariants (`:74-96`, `:143-173`) *strengthened*, never relaxed (C9 anchor 5). | `ARCH-7i`, `ARCH-7j` |
| **VD-7E** | `project-plan.md:713` / `prd.md:945`: *"dispose of `grpc_address`/`grpc_port` — removed or repointed"*, as a two-site edit. | **Correct in intent; the footprint is 8 production sites plus 6 test/doc sites, and the obvious implementation recreates the defect it forbids.** | Counted at HEAD: `bin/rvc/src/cli.rs:296,300` (clap fields) and `:616,617` (two of the nine `CLAP_DEFAULT_CLOBBERS` entries that Phase 1's 1F converts to `Option<T>` — `research/runtime-and-config-patterns.md:841-845`); `crates/rvc/src/config/types.rs:178,180` (`Config`), `:591,592` (defaults), `:640,641` (`ConfigWire`), `:842,843` (merge), `:1045-1046` (`InvalidPort` validation); plus `crates/rvc/tests/config_backward_compat.rs:28,29,202`, `bin/rvc/tests/cli.rs:240,254,255,265`, `bin/rvc/tests/integration_test.rs:123,124`, `config.example.toml:81,82`, `docs/running-guide.md:186`. Because `ConfigWire` is `#[serde(default)]` with no `deny_unknown_fields` (`types.rs:628-630`), plain field deletion = **silently ignored operator input** = PB-B1 (A-7.7). Second-order: removing two clap fields moves G-2 clause (ii)'s **counted** arithmetic (74 fields / 65 merge arms at HEAD), so 7e must update the gate's numbers in whatever post-Phase-4 form G-2 has. | `ARCH-7e` |
| **VD-7F** | `project-plan.md:729` exit criterion: *"**M5 = +7 gates / +3 CI checks** reached"*. | **True in M5's own enumeration, but "+7" is not the initiative's gate count — do not read it as one.** | `prd.md:995` enumerates the +7 as: orphan-dir D1, uncompiled-source D2, config-drift (G-2), `RVC_*` allow-list (G-3), Base zero-out-edge (G-5a), Infra→Domain (G-5b), KM-2 teardown (G-6). It **omits** G-4 (`raw_spawn`, Phase 2), G-7 (`audit_log_scope`, Phase 1) and G-8 (`mock_fidelity`, Phase 3), all of which also land in this initiative and are counted as new gates by `project-plan.md:82-92`. Phase 7's contribution to M5 is therefore exactly **one gate (G-6) and one CI check (the dvt run)**; the exit criterion is written that way in §1 rather than restating a number that does not reconcile with the gate table. | §1 exit criteria, `ARCH-7a`, `ARCH-7j` |
| **VD-7G** | `prd.md:956` / `project-plan.md:715`: prune the `EXEMPTIONS` entries "that are in fact KAT-anchored" — unsized. | **Sized, and the prune is mostly one detector gap.** | `crates/architecture-tests/tests/kat_policy.rs:42-163` holds **57** entries. **Seven** of them (`:92-104`) live in `crates/crypto/tests/signing_root_kat.rs` and are named `kat_*` — i.e. they are already KAT tests, listed as exempt only because `body_has_kat_constant` (`:238`) scans the **test body** for an `EXTERNAL_*`/`KAT_*`/`SPEC_*` token and these reference file-level constants. Four more (`crates/eth-types/src/{aggregation.rs,builder.rs,sync_committee.rs,tree_hash_utils.rs}`, entries at `:106-122`) are field-sensitivity tests in the crate `ARCH-7h` touches. **Ten** entries are `bin/rvc-keygen/*` (`:43-52`) — the *tracked* tree, so Phase 0's orphan deletion does not affect them (a plausible mis-read worth stating). Removals only; `EXEMPTIONS` never grows (`CLAUDE.md`, `kat_policy.rs:16-17`). | `ARCH-7l` |

---

## 4. Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|---|---|---|---|---|---|
| **ARCH-7a** | G-6: KM-2 teardown gate (`km2_lifecycle.rs`) | 3 | chore (gate) | — | A |
| **ARCH-7b** | Delete the unwired legacy doppelganger surface | 2 | chore | 7a | A |
| **ARCH-7c** | Retire `DoppelgangerGate` from the opt-out path | 2 | feature | 7a, 7b | A |
| **ARCH-7d** | Remove the healthz-only tonic server and its `select!` arm | 2 | chore | C8 window (Phase 0 `0F`) | A |
| **ARCH-7e** | Dispose `grpc_address` / `grpc_port` by startup rejection | 2 | feature | 7d | A |
| **ARCH-7k** | Honour `BnRole` in `broadcast_inner` (closes M7) | 2 | feature | — | A |
| **ARCH-7f** | **Spike:** can the `Wire*` twins be collapsed at HEAD? | 2 | spike | — | B |
| **ARCH-7g** | Write `docs/forks.md` (add-a-fork checklist) | 2 | chore | — | B |
| **ARCH-7h** | Collapse the `Wire*` twins **or** record the deferral | 3 | feature | 7f, 7g | B |
| **ARCH-7i** | Register the DVT signing surface in `signer-registry` | 3 | feature | — | B |
| **ARCH-7j** | Enumeration gate under `--features dvt` + new CI step | 2 | chore (gate) | 7i | B |
| **ARCH-7l** | Prune the KAT `EXEMPTIONS` list (removals only) | 1 | chore | 7h | B |
| **ARCH-7m** | 200-key / 200 ms scale validation run, checked in | 3 | chore | Phase 5 (5A harness) | B |
| | **Total** | **29** | | | **A 13 · B 16** |

**Points ↔ days.** House convention is ~1 pt ≈ 0.5–1 working day (coding + tests + review +
integration). 29 pts ⇒ **14.5–29 d**; the realistic band for this mix is **18–22 d** because five of
the thirteen issues are gate/CI work whose cost is dominated by RED-demonstration and CI-cycle
turnaround rather than by lines written. Two-developer critical path = Stream B (16 pts) plus the one
sync point ⇒ **11–14 d**.

### Binding intra-phase order

| Order | Reason | Authority |
|---|---|---|
| **7a → 7b → 7c** | Gate the contract **before** retiring any mechanism that holds it. 7a is the phase's first issue and is a hard gate on both retirement issues. | `project-plan.md:788`; `architecture.md:1555`; C5 |
| **7d → 7e** | The knobs cannot be rejected while the server that reads them still binds. | ADR-014 |
| **7f → 7h**, **7g → 7h** | The collapse is conditional on the spike's verdict, and `docs/forks.md` is where a deferral verdict is *recorded*. | VD-7C, A-7.10 |
| **7i → 7j** | The registry model must exist before a CI step can assert against it. | VD-7D |
| **7h → 7l** | Pruning `EXEMPTIONS` after the container-root tests are re-anchored, so the prune reflects the final state and shrinks once. **The dependency is conditional:** under 7h's *Branch 2* (deferral) nothing in `crates/eth-types` changes, so it goes vacuous and 7l becomes immediately runnable — which frees Stream B earlier in the two-developer overlay. | VD-7G, C9 anchor 3 |

### Execution plan — single developer (default)

| Day | Issue |
|---|---|
| 1–3 | ARCH-7a (3) |
| 4–5 | ARCH-7b (2) |
| 6–7 | ARCH-7c (2) |
| 8–9 | ARCH-7f (2) |
| 10–11 | ARCH-7g (2) |
| 12–14 | ARCH-7h (3) |
| 15–17 | ARCH-7i (3) |
| 18–19 | ARCH-7j (2) |
| 20 | ARCH-7l (1) |
| 21–22 | ARCH-7d (2) |
| 23–24 | ARCH-7e (2) |
| 25–26 | ARCH-7k (2) |
| 27–29 | ARCH-7m (3) |

Day-slots above are drawn at **1 pt = 1 day**, i.e. the **pessimistic** end of the 0.5–1 d/pt range
(29 d). The estimate of record is **18–22 d**: five of the thirteen issues (7a, 7f, 7g, 7j, 7l) are
gate, spike or docs work that habitually lands inside its point budget, and the table is laid out at
the slow end so a slipped issue does not silently consume another's slot. 7d/7e are placed late so a
slipped C8 release does not idle the developer.

---

## 5. Stream & File Ownership

**Two streams, disjoint file sets.** No file below is opened by both.

| Directory / file | Owner | Issues |
|---|---|---|
| `crates/keymanager-api/**` | **A** | 7a, 7c |
| `crates/doppelganger/**` | **A** | 7a, 7b |
| `crates/rvc/src/keymanager_adapters/**` | **A** | 7a, 7c |
| `crates/rvc/src/doppelganger_adapter.rs`, `liveness_loop.rs` | **A** | 7b |
| `crates/rvc/src/bootstrap/run.rs`, `crates/rvc/src/config/types.rs` | **A** | 7d, 7e |
| `bin/rvc/src/cli.rs`, `bin/rvc/tests/**`, `config.example.toml`, `docs/running-guide.md` | **A** | 7e |
| `crates/bn-manager/**` | **A** | 7k |
| `crates/architecture-tests/tests/km2_lifecycle.rs` *(new)* | **A** | 7a (creates), 7b (adds the `LegacySlashingHistoryReader` grep assertion), 7c (updates the classification tables) |
| `crates/eth-types/**` | **B** | 7f, 7h |
| `crates/crypto/tests/signing_root_kat.rs` | **B** | 7l (may add `// kat_exempt:` markers) |
| `docs/forks.md` *(new)* | **B** | 7g, 7h |
| `crates/signer-server/**`, `crates/signer-registry/**` | **B** | 7i, 7j |
| `crates/architecture-tests/tests/kat_policy.rs` | **B** | 7l |
| `.github/workflows/ci.yml` | **B** | 7j |
| `plan/architecture-2026-08-12/measurements/` *(new)* | **B** | 7m |

**Departure from `project-plan.md` §9's global cut, stated rather than switched silently.** §9 draws
the workspace-wide line at *`crates/rvc/` + `bin/rvc/` (A)* vs *`crates/slashing/` + `crates/signer/`
+ `Cargo.toml`s/`architecture-tests` (B)*. That cut does not partition Phase 7: this phase contains
**no** `crates/slashing` or `crates/signer` work at all, and it touches `architecture-tests` from
**both** halves (`km2_lifecycle.rs` is inseparable from the `keymanager-api`/`doppelganger` work,
`kat_policy.rs` is inseparable from the `eth-types` work). The phase-local cut above is
**fork-readiness surfaces (B) vs lifecycle-and-operability surfaces (A)**, and it is genuinely
disjoint at file granularity — including inside `architecture-tests`, where the two streams add/edit
different files and neither touches `src/lib.rs`'s `CLASSIFICATION` (Phase 6 pinned it at 28 rows).

**Merge-conflict hotspots.** One directory, and every collision inside it is *within* a stream rather
than across streams — which is what makes the cut disjoint. `crates/architecture-tests` is opened by
**7a, 7b and 7c** (all Stream A, all on the **new** file `km2_lifecycle.rs`) and by **7l** (Stream B,
the **existing** `kat_policy.rs`). Strategy: *new file* (pattern 1) for the Stream-A trio, so they
cannot collide with Stream B at all; within Stream A they are strictly ordered 7a → 7b → 7c, so the
file has one writer at a time. 7l is removals-only inside a single `const` array. Neither stream
touches `crates/architecture-tests/src/lib.rs` (Phase 6 pinned `CLASSIFICATION` at 28 rows). No
scaffold issue is needed.

**Sync point.** One, at the end of the phase: 7j's new CI step and 7l's `EXEMPTIONS` shrink both
change `arch-gates`/CI behaviour, and 7e changes the config surface that 7k's broadcast-topic tests
read indirectly. Both streams converge for one integration run of the five standing commands plus
`cargo nextest run -p rvc-signer-server --features dvt` before the phase is declared done.

---

## 6. Issues

### ARCH-7a — G-6: KM-2 teardown gate (`km2_lifecycle.rs`)

- **Points:** 3 · **Scope:** 2 days · **Type:** chore (gate) · **Priority:** P0
- **Stream:** A · **Blocked by:** — · **Blocks:** ARCH-7b, ARCH-7c
- **Requirements:** ARCH-P1-11 (gate half) · **ADR:** ADR-015 · **Gate:** G-6
- **Constraints:** **C5 (binding)**, C9 anchor 1

**Context.** The review states the KM-2 teardown contract is one *"the keymanager-api gate currently
owns"* (review `:189`). **There is no such gate** (VD-6): `rg 'KM-2|lifecycle|stop_monitoring'
crates/architecture-tests` returns nothing — re-verified at HEAD. The contract lives in a trait
default (`crates/keymanager-api/src/traits.rs:86-88`), a doc table
(`crates/rvc/src/keymanager_adapters/doppelganger.rs:140-144`), a runtime log line (`:209-213`) and
unit tests (`keymanager_adapters/tests/misc_adapters.rs:112-122`). C5 is therefore **two**
obligations — preserve *and* gate — and this issue is the second one. It lands **first in the phase**
because the gate must exist before the mechanisms that hold the contract are touched.

**The trap this gate exists to catch.** `traits.rs:86-88` gives `cancel_monitoring` a **default body
that calls `stop_monitoring`**. An implementor that does not override it silently gets
`stop_monitoring` semantics. For `ForwardWindowMonitor` that would mean a DELETE no longer resets the
forward window, so a re-import is admitted on a stale window. For `DoppelgangerGate` the same default
is **correct** (`lifecycle.rs:356` says so in a comment). **The gate is therefore a classification,
not a ban** — a gate that simply forbade the default would be wrong, and one that ignored it would be
vacuous.

**Files to touch.**

- `crates/architecture-tests/tests/km2_lifecycle.rs` — **new**, the only new file. Scanner idiom, same
  brace-aware extraction technique as `kat_policy.rs:297` / `architecture.md` §7.1 anchor 1
  ("every gate in §6 is a **new file** in the existing scanner idiom; no existing gate file is
  modified").
- No production file is modified by this issue.

**Implementation approach.**

1. Two `const` classification tables in the gate file, in the repo's existing `CLASSIFICATION` /
   `EXEMPTIONS` idiom:
   - `MUST_OVERRIDE_CANCEL: &[(&str, &str)]` — `(file, impl type)` for machine-backed monitors.
     Seeded with `("crates/rvc/src/keymanager_adapters/doppelganger.rs", "ForwardWindowMonitor")`.
   - `DEFAULT_IS_SAFE: &[(&str, &str, &str)]` — `(file, impl type, reason)` for implementors where
     inheriting the default is correct. Seeded with `DoppelgangerGate`
     (`crates/keymanager-api/src/gate.rs:63`, reason: *"time-based; both methods mean prune-pending —
     lifecycle.rs:356"*), `DoppelgangerMonitorAdapter` (`doppelganger.rs:123`, reason: *"log-only, no
     teardown state"*) and `StubDoppelganger` (`crates/keymanager-api/src/server.rs:274`, reason:
     *"test double"*).
2. **Non-vacuity assertion (the load-bearing clause):** walk every workspace `.rs` file for
   `impl DoppelgangerMonitor for <T>` and assert each hit appears in **exactly one** table. A new
   implementor fails CI until someone classifies it. Without this the gate is unfalsifiable — it
   would only ever check two names someone remembered to add.
3. Assert `MUST_OVERRIDE_CANCEL` impls textually declare `fn cancel_monitoring`.
4. Assert the trait still declares **both** `fn stop_monitoring` and `fn cancel_monitoring`
   (`traits.rs:80`, `:86`) — this is the "collapse the two methods" detector ADR-015 names as the
   exact failure C5 exists to prevent.
5. Assert the DELETE path still calls `cancel_monitoring`: scan the keymanager delete handler for a
   `cancel_monitoring` call site paired with `remove_validator`.
6. Wire into the `arch-gates` CI job Phase 0 added (A-P1) — no new job.

**TDD test plan.**

- **RED first — `km2_gate_is_red_when_cancel_override_is_removed`.** Before writing the gate, take a
  scratch copy of the tree, delete `ForwardWindowMonitor::cancel_monitoring`
  (`doppelganger.rs:216-233`) so it inherits the default, and run the new gate. It must fail naming
  `doppelganger.rs` and `ForwardWindowMonitor`. Paste the output into the PR — RED is *demonstrated
  locally against a scratch tree*, never merged (ADR-012, `project-plan.md:93-96`).
- Second RED: a scratch `impl DoppelgangerMonitor for Foo` in a test fixture must fail the
  non-vacuity clause with "unclassified implementor".
- Third RED: a scratch edit deleting `fn cancel_monitoring` from `traits.rs` must fail the
  collapse detector.
- GREEN: all three revert; gate passes on `develop`.
- The **behavioural** half of the contract is not this gate's job and must stay where it is — confirm
  `misc_adapters.rs:112-122` still asserts `stop_monitoring` ⇒ `ForwardWindowStatus::Pending` and
  `cancel_monitoring` ⇒ `Unmonitored`, unchanged.

**KAT policy.** Not applicable — no test here matches `.*(tree_hash|signing_root|_root)$`. Name the
tests `km2_*` so they do not enter `kat_policy`'s scanner scope for no benefit (the inverse
obligation the architecture places on ADR-003, applied here by analogy).

**Acceptance criteria.**

- [x] `crates/architecture-tests/tests/km2_lifecycle.rs` exists and runs in the `arch-gates` job.
- [x] Every `impl DoppelgangerMonitor for` site in the workspace is in exactly one classification
      table; an unclassified new implementor fails with the file and type named.
- [x] Removing `ForwardWindowMonitor`'s `cancel_monitoring` override turns the gate RED (output
      pasted in the PR).
- [x] Collapsing `stop_monitoring`/`cancel_monitoring` on the trait turns the gate RED.
- [x] The gate is green on `develop` with **no production file modified** by this issue.
- [x] `rg 'KM-2|km2' crates/architecture-tests` now returns hits — the VD-6 finding is closed.

---

### ARCH-7b — Delete the unwired legacy doppelganger surface

- **Points:** 2 · **Scope:** 1 day · **Type:** chore · **Priority:** P1
- **Stream:** A · **Blocked by:** ARCH-7a · **Blocks:** ARCH-7c
- **Requirements:** ARCH-P1-11 (the `LegacySlashingHistoryReader` half) · **ADR:** ADR-015
- **Constraints:** C5 (must not disturb), C9 anchor 1

**Context — and the correction that sizes it (VD-7A).** ADR-015 and the review describe retiring a
*live* legacy mechanism. Verified at HEAD: **`DoppelgangerService` has no production caller.**
`DoppelgangerService::new` appears only inside its own `#[cfg(test)]` module
(`crates/doppelganger/src/service.rs:388` … `:1032`) and `crates/doppelganger/tests/clock_m7.rs:52`.
`SlashingDbReaderAdapter` — the workspace's only `impl LegacySlashingHistoryReader`
(`crates/rvc/src/doppelganger_adapter.rs:97-106`) — is constructed only at `:115`, `:125`, `:137`,
all inside its own test module. `crates/rvc/src/liveness_loop.rs:15` states it in a module doc:
*"the backward one-shot `DoppelgangerService` is not wired"*. This half is therefore a **dead-but-
public API deletion with no behavioural risk**, which is why it is 2 points and not 5.

The trait being deleted is the actual foot-gun: `crates/doppelganger/src/traits.rs:75-80`
(`LegacySlashingHistoryReader`), whose own doc at `:68-74` says using the wrong reader for the
forward-window machine *"would bypass chain-identity checks"* — protected today by naming discipline
alone, because it is `pub` and re-exported at `crates/doppelganger/src/lib.rs:23`.

**Files to touch.**

- `crates/doppelganger/src/service.rs` — delete (the whole file: struct `:31`, impl `:39`, ~1,000
  lines of which the great majority is its own test module).
- `crates/doppelganger/src/traits.rs:68-80` — delete `LegacySlashingHistoryReader`.
- `crates/doppelganger/src/lib.rs:21,23` — drop the `pub use service::{DoppelgangerService,
  DEFAULT_MONITORING_EPOCHS}` and the `LegacySlashingHistoryReader` re-export. **Check
  `DEFAULT_MONITORING_EPOCHS` for other consumers before removing it** — it is exported alongside but
  is a separate symbol.
- `crates/doppelganger/tests/clock_m7.rs` — retarget or delete. Its module doc (`:6`) says the clock
  test exists to prove `DoppelgangerService` "embeds the same clock (no parallel formula)"; with the
  service gone the correct move is to **keep the `MonotonicEpochClock` assertions and drop the
  service arm**, not to delete the file.
- `crates/rvc/src/doppelganger_adapter.rs:82-106` + its tests `:112-140` — delete
  `SlashingDbReaderAdapter`. **Keep `BeaconLivenessAdapter`** (`:28-79`) — it implements
  `LivenessChecker`, which the surviving forward-window path uses.
- Doc-reference cleanups: `crates/doppelganger/src/state.rs:37`, `epoch_clock.rs:50`,
  `restart_skip.rs:4`, `service.rs:23` (moved), `traits.rs:68`, `liveness_loop.rs:15`,
  `tests/forward_window_satisfaction.rs:394` all name `DoppelgangerService` in doc comments; rustdoc
  intra-doc links to a deleted item are a **`cargo doc` warning**, and stale prose is exactly
  ARCH-P2-9's category.
- `ARCHITECTURE.md:556` describes `DoppelgangerService` as a live mechanism — regenerate/update.

**Implementation approach.** Delete in one commit; the compiler is the completeness check. Do **not**
touch `ForwardWindowMachine`, `SigningEnablement` or the `spawn.rs` monitor selection — that is
`ARCH-7c`, deliberately separated so a revert of either does not require reverting the other (NFR-4).
`crates/rvc/src/main.rs:1401` also references the service, but that file **no longer exists** after
Phase 0 (the orphan-tree invariant, `project-plan.md:151-157`) — it must not appear in this issue's
file list.

**TDD test plan.**

- **RED first — `no_legacy_slashing_history_reader_symbol`.** Add a one-line grep assertion (in the
  same PR, in `km2_lifecycle.rs` from 7a) that `rg 'LegacySlashingHistoryReader'` over `crates/` and
  `bin/` returns zero hits. It is RED at HEAD (10 hits across `traits.rs`, `service.rs`,
  `lib.rs`, `doppelganger_adapter.rs`, `clock_m7.rs`) and turns GREEN with the deletion. This is the
  PRD's own acceptance signal (`prd.md:884`) made mechanical rather than manual.
- No new behavioural test: **there is no behaviour to preserve**. The proof is that
  `cargo nextest run --workspace` shows the same pass count minus exactly the deleted tests, and
  `cargo build --workspace` is unaffected outside `crates/doppelganger` and `crates/rvc`.
- Regression pin that must stay green untouched: `crates/doppelganger/tests/forward_window_satisfaction.rs`.

**KAT policy.** Not applicable. Note `kat_policy.rs`'s `EXEMPTIONS` has **no** entry in
`crates/doppelganger` (verified over `:42-163`), so no exemption bookkeeping is needed here.

**Acceptance criteria.**

- [x] `rg 'LegacySlashingHistoryReader'` returns nothing under `crates/` and `bin/`.
- [x] `rg 'DoppelgangerService'` returns nothing under `crates/` and `bin/` (doc comments included).
- [x] `BeaconLivenessAdapter` survives and its test at `doppelganger_adapter.rs:147` still passes.
- [x] `crates/doppelganger/tests/clock_m7.rs` still asserts the `MonotonicEpochClock` formula.
- [x] `cargo doc --workspace` produces no new broken intra-doc link warnings.
- [x] `ARCHITECTURE.md` regenerates byte-identically after the classification-neutral edit (C9
      anchor 1) — this deletes **types**, not a workspace member, so the member count stays 28.
- [x] G-6 (7a) still green.

---

### ARCH-7c — Retire `DoppelgangerGate` from the opt-out path

- **Points:** 2 · **Scope:** 1–1.5 days · **Type:** feature · **Priority:** P1
- **Stream:** A · **Blocked by:** ARCH-7a, ARCH-7b · **Blocks:** —
- **Requirements:** ARCH-P1-11 (the "four mechanisms → one plus the store-level flag" half)
- **ADR:** ADR-015 · **Constraints:** **C5 (binding)**, C9 anchor 5 (adjacent — do not weaken)

**Context.** This is the half of ARCH-P1-11 that is genuinely live (VD-7A). The time-based
`DoppelgangerGate` (`crates/keymanager-api/src/gate.rs:45`) is selected at
`crates/rvc/src/keymanager_adapters/spawn.rs:99` — and, verified, **only** there:
`select_and_rearm_doppelganger_monitor` (`spawn.rs:85-109`) picks `ForwardWindowMonitor` iff
`forward_window_machine.is_some()` and falls back to `DoppelgangerGate` otherwise, while
`bootstrap/enablement.rs:365-368` / `:403` pin `is_some()` ⟺ `config.doppelganger_detection`. On that
opt-out path `spawn.rs:165-169` sets the window to `Duration::ZERO`, and
`gate.rs:139-146` (`test_zero_window_is_immediately_safe`) proves a zero-window gate reports every key
safe immediately.

**So the live legacy mechanism is a time-based gate configured to do nothing.** Replacing it with an
explicitly-named always-safe monitor is behaviour-preserving *by construction* — but the equivalence
must be **pinned by a test**, not asserted in a commit message, because it is the whole safety
argument.

**Files to touch.**

- `crates/rvc/src/keymanager_adapters/spawn.rs:85-109` (selection), `:55-56`
  (`DoppelgangerMonitorKind::TimeBasedGate` variant), `:171-179` (call site and its comment).
- `crates/rvc/src/keymanager_adapters/doppelganger.rs` — the always-safe monitor. **Reuse, do not
  invent:** `DoppelgangerMonitorAdapter` (`:110-135`) is already a log-only `DoppelgangerMonitor`
  returning `is_doppelganger_safe == true` (`:132-134`). Rename it to state its role
  (`DoppelgangerDisabledMonitor`) rather than adding a fourth type.
- `crates/keymanager-api/src/gate.rs` — delete `DoppelgangerGate` and its module (the file's own
  tests at `:93-160` go with it).
- `crates/keymanager-api/src/lifecycle.rs:249,294-295,356` — the lifecycle tests construct
  `DoppelgangerGate`; retarget them onto the surviving monitor. **`:356`'s comment ("cancel_monitoring
  on DoppelgangerGate defaults to stop_monitoring → safe") is load-bearing for G-6's classification
  table — when the type goes, its `DEFAULT_IS_SAFE` row in `km2_lifecycle.rs` goes with it.**
- `crates/keymanager-api/tests/{post_import_doppelganger_m12.rs:19,194,254,300,
  km2_cancel_token_race.rs:20,68,77}` and `crates/rvc/src/keymanager_adapters/tests/denylist.rs:78,90,
  104,118` — all construct `DoppelgangerGate` as a test double. Retarget each; **`km2_cancel_token_race.rs`
  is the KM-2 race regression test and must keep asserting the same property** with the new double.
- `crates/rvc/src/keymanager_adapters/doppelganger.rs:18` — `scan_and_rearm_gate`'s doc says "after
  the `DoppelgangerGate` is created"; the re-arm call at `spawn.rs:104-106` runs for **both** monitor
  variants and is guarded by `!doppelganger_window.is_zero()`, so on the opt-out path it never fires
  today. Keep that guard semantics exactly.

**Implementation approach.** Replace the `else` arm at `spawn.rs:98-101` with the renamed always-safe
monitor and keep `DoppelgangerMonitorKind` as a two-variant enum (rename `TimeBasedGate` →
`Disabled`) so the existing selection assertion at
`keymanager_adapters/tests/spawn.rs:171` keeps its meaning. Delete `gate.rs` last, once every
constructor is retargeted — the compiler then proves completeness. Update G-6's classification table
in the same PR (remove the `DoppelgangerGate` row, add the renamed type). **Do not** collapse
`stop_monitoring` and `cancel_monitoring` while "simplifying" the surviving implementors — that is
the exact failure C5 exists to prevent, and 7a's gate now fails CI if anyone tries.

**TDD test plan.**

- **RED first — `test_doppelganger_optout_monitor_reports_every_key_safe`** in
  `crates/rvc/src/keymanager_adapters/tests/spawn.rs`. Build the keymanager API with
  `forward_window_machine: None`, assert the selected monitor reports `is_doppelganger_safe == true`
  for a freshly `start_monitoring`-ed key **and** for an unknown key, and assert
  `monitor_kind == DoppelgangerMonitorKind::Disabled`. Written **against the new enum variant name**,
  so it fails to compile before the change — the sharpest available RED for a rename-and-replace.
- Second test — `test_doppelganger_optout_rearm_is_not_invoked_on_zero_window`: assert the re-arm
  scan does not run when the window is zero (pins `spawn.rs:104`'s guard through the change).
- Preserve, do not rewrite: `keymanager_adapters/tests/spawn.rs:171`
  ("`forward_window_machine` must select ForwardWindow monitor") and
  `crates/keymanager-api/tests/km2_cancel_token_race.rs`.
- GREEN: `cargo nextest run -p rvc-keymanager-api -p rvc` plus the workspace run.

**KAT policy.** Not applicable.

**Acceptance criteria.**

- [x] `rg 'DoppelgangerGate'` returns nothing under `crates/` and `bin/`.
- [x] Exactly **two** production `impl DoppelgangerMonitor for` sites remain
      (`ForwardWindowMonitor`, `DoppelgangerDisabledMonitor`) — four mechanisms are now one plus the
      store-level flag, per ADR-015.
- [x] G-6's non-vacuity clause is green with its tables updated in the same PR.
- [x] The opt-out path's observable behaviour is unchanged: every key signing-enabled immediately, no
      re-arm scan, `handles.forward_window_machine.is_none()` (`enablement.rs:403`) still holds.
- [x] The DELETE path still calls `remove_validator` + `cancel_monitoring`; `misc_adapters.rs:112-122`
      unchanged and green.
- [x] No new `.unwrap()` in production code (`CLAUDE.md`).

---

### ARCH-7d — Remove the healthz-only tonic server and its `select!` arm

- **Points:** 2 · **Scope:** 1 day · **Type:** chore · **Priority:** P1
- **Stream:** A · **Blocked by:** C8 deprecation window (Phase 0 `0F` shipped ≥ 1 release ago)
- **Blocks:** ARCH-7e · **Requirements:** ARCH-P1-16b · **ADR:** ADR-014
- **Constraints:** **C8 (binding)**

**Context.** `crates/rvc/src/bootstrap/run.rs:260-276` builds a `DutyTrackerService` and serves
`DutyTrackerServer` on `{grpc_address}:{grpc_port}`, occupying a top-level `select!` arm at `:298`.
Its only content is a healthz endpoint. Removal is **operator-visible**: k8s liveness/readiness or
monitoring may target the gRPC endpoint — and, stated honestly, **VD-A3 stands: nobody has verified
that any probe does.** The deprecation window shipped in Phase 0 (`0F`) *is* the discovery mechanism,
not a courtesy, which is why this issue may not be pulled earlier.

The replacement is concrete, not a category (VD-P3, re-verified): `crates/metrics/src/server.rs`
exposes `/health` (`:57-64`, handler `:134`) and `readyz_handler` (`:145`) via
`serve_metrics_with_health` (`:96-106`).

**Files to touch.**

- `crates/rvc/src/bootstrap/run.rs` — `:21`, `:24` (imports), `:260-276` (addr parse, service, server
  builder, `serve_with_shutdown`), `:296-313` (drop the gRPC arm from the `select!`; **arm order is
  commented as preserved at `:296`, so the comment must be corrected, not left describing three
  arms**).
- `crates/rvc/src/grpc_health/` — delete the module (`mod.rs:5`, `service.rs:7,9,16,33` including its
  test at `:33`).
- `crates/rvc/src/lib.rs:23` — drop `pub use proto::duty_tracker::duty_tracker_server::DutyTrackerServer`.
- The `duty_tracker` proto and its build-script entry — **check before deleting**: the existing
  single-proto architecture gate (`prd.md:995` baseline list) may assert on the proto set, and
  `cargo-machete`/`cargo-udeps` (added to CI in Phase 0, ARCH-P2-6) will flag `tonic`/`prost` if they
  become unused in `crates/rvc`. Resolve both in this PR rather than leaving CI red for the next one.
- Release notes — name `/health` and `/readyz` as the replacement pair.

**Out of scope, deliberately:** the `grpc_address`/`grpc_port` knobs. They are `ARCH-7e`, so that a
revert of the knob disposal does not revert the server removal (NFR-4).

**Implementation approach.** Delete the arm first and confirm the `select!` still compiles with two
arms; then delete the module; then the re-export; then the proto. Note the shutdown path at
`:316-319` is **Phase 2's** territory (ADR-001/ADR-002 replaced the `sleep` with a join) — this issue
must not re-open it; it only removes one arm.

**TDD test plan.**

- **RED first — `test_no_grpc_listener_on_startup`.** A bootstrap test that starts the client with a
  config naming a free `grpc_port` and asserts **nothing is listening** on that port after startup
  (a `TcpStream::connect` that must fail). RED at HEAD (the server binds), GREEN after removal. This
  is stronger than asserting the symbol is gone, because it tests the operator-visible fact.
- Second test: assert the metrics server still answers `/health` and `/readyz` — the replacement must
  be proven live in the same PR that removes the old probe, or the deprecation note is a promise
  rather than a fact.
- Preserve: `bin/rvc/tests/integration_test.rs` and `bin/rvc/tests/cli.rs` currently start the client
  with `grpc_address`/`grpc_port` set (`:123-124`, `:254-255`); they must still pass here — they stop
  passing in `ARCH-7e`, which is exactly why the two issues are separate.

**KAT policy.** Not applicable.

**Acceptance criteria.**

- [x] `rg 'DutyTrackerServer|DutyTrackerService|grpc_health'` returns nothing under `crates/`, `bin/`.
- [ ] The top-level `select!` in `run.rs` has two arms and its arm-order comment matches.
      *Closure note (2026-09-05): stale vs HEAD. Phase 2 (ARCH-2h) already re-homed tonic to
      `executor.spawn("grpc_healthz", ShutdownTier::Ingress, …)`; the remaining `select!` is the
      three-arm drain trigger (signal / `shutdown_rx` / token) and must not be collapsed (Phase 2
      shutdown / `EXIT_*`). Equivalent work: delete the Ingress spawn — done.*
- [x] No listener binds the configured gRPC port at startup (test-asserted).
- [x] `/health` and `/readyz` answer on the metrics server (test-asserted).
- [x] The release note names the replacement probe pair and links the probe-migration check written
      in Phase 0 (`0F`).
- [x] `cargo-machete` / `cargo-udeps` green — no dependency orphaned by the deletion.
- [x] Named exit codes and shutdown behaviour unchanged (Phase 2's `EXIT_*` assertions still green).

---

### ARCH-7e — Dispose `grpc_address` / `grpc_port` by startup rejection

- **Points:** 2 · **Scope:** 1–1.5 days · **Type:** feature · **Priority:** P1
- **Stream:** A · **Blocked by:** ARCH-7d · **Blocks:** —
- **Requirements:** ARCH-P1-16b (disposal half), **M7 → 0** contribution · **ADR:** ADR-014
- **Constraints:** **C8 (binding)**, C3 (adjacent — no env layer is introduced)

**Context.** ADR-014 rejects *"leaving the knobs in place after removing the server"* explicitly:
that recreates PB-B1's failure mode — a config surface that accepts input and does nothing — **inside
the change that exists to eliminate it** (`architecture.md:774-776`).

**The obvious implementation does exactly that (VD-7E).** `ConfigWire` is declared
`#[derive(Debug, Default, Deserialize)] #[serde(default)]` at `crates/rvc/src/config/types.rs:628-630`
with **no `deny_unknown_fields`**. Simply deleting the `grpc_port` / `grpc_address` fields at `:640-641`
makes every existing operator TOML that sets them parse **silently**, ignoring the keys — precisely
PB-B1. `prd.md:997` settles the choice rather than leaving it to taste: M7's target is "each either
applied or **rejected at startup**".

**Files to touch (counted footprint — 8 production sites, 6 test/doc sites).**

| File | Lines | What |
|---|---|---|
| `bin/rvc/src/cli.rs` | `:296`, `:300` | clap fields — delete |
| `bin/rvc/src/cli.rs` | `:616`, `:617` | `CliOverrides` initialisers — delete (Phase 1's 1F converted these to `Option<T>`; they leave together) |
| `crates/rvc/src/config/types.rs` | `:178`, `:180` | `Config` fields — delete |
| `crates/rvc/src/config/types.rs` | `:591`, `:592` | `Config::default()` — delete |
| `crates/rvc/src/config/types.rs` | `:640`, `:641` | `ConfigWire` — **keep, repurposed as rejection sentinels** |
| `crates/rvc/src/config/types.rs` | `:842`, `:843` | merge arms — delete |
| `crates/rvc/src/config/types.rs` | `:1045-1046` | `InvalidPort` validation — replace with the rejection |
| `crates/rvc/tests/config_backward_compat.rs` | `:28`, `:29`, `:202` | retarget to assert **rejection** |
| `bin/rvc/tests/cli.rs` | `:240`, `:254`, `:255`, `:265` | remove from the fixture TOML |
| `bin/rvc/tests/integration_test.rs` | `:123`, `:124` | remove from the fixture TOML |
| `config.example.toml` | `:81`, `:82` | delete + a migration comment |
| `docs/running-guide.md` | `:186` | delete + point at `/health`, `/readyz` |

**Implementation approach.** Keep `grpc_port` / `grpc_address` in `ConfigWire` as
`Option<toml::Value>`-style **sentinels**, and have `Config::validate` (or the wire→`Config`
conversion) return a new `ConfigError::RemovedKey { key, replacement }` naming the key, the release
that removed it, and the `/health` + `/readyz` replacement. Delete them from `Config`, the defaults,
the merge and the clap surface. The `--grpc-address` / `--grpc-port` **CLI flags** are removed
outright: clap already errors on an unknown flag, so no sentinel is needed there.

**Second-order obligation the upstream does not state (VD-7E).** Removing two clap fields moves G-2
clause (ii)'s **counted** arithmetic (74 fields / 13 groups / `BYPASS` 8 / `74 − 8 − 1 = 65` merge
arms at HEAD, `project-plan.md:395`). Phase 4's ADR-008 collapse has by now replaced `CliOverrides`
with the reth `NodeConfig` model, so the numbers live in whatever form G-2 then asserts — **this issue
must update them there.** A gate whose arithmetic silently stops matching is a gate that has been
turned off. `CLAP_DEFAULT_CLOBBERS` itself is already empty (Phase 1's 1F) and must **stay** empty —
it is shrinking-only, and these two knobs were 2 of its 9 seed entries
(`research/runtime-and-config-patterns.md:841-845`).

**TDD test plan.**

- **RED first — `test_removed_grpc_keys_are_rejected_at_startup`** in
  `crates/rvc/tests/config_backward_compat.rs`. Feed a TOML containing `grpc_port = 50051` and assert
  startup returns `ConfigError::RemovedKey` whose message contains `grpc_port`, `/health` and
  `/readyz`. RED at HEAD (the key is accepted and used), and — importantly — **also RED against the
  naive delete-the-field implementation**, which returns `Ok`. That second property is what makes
  this test the right RED: it fails the wrong fix, not just the missing fix.
- `test_config_without_grpc_keys_starts_clean` — no warning, no error.
- `test_unknown_grpc_cli_flag_is_rejected` — `--grpc-port 1` exits non-zero from clap.
- Preserve: the rest of `config_backward_compat.rs`'s round-trip parity assertions (Phase 4's ADR-008
  proof surface) stay green.

**KAT policy.** Not applicable.

**Acceptance criteria.**

- [x] `rg 'grpc_port|grpc_address'` under `crates/` and `bin/` returns only the rejection sentinel and
      its tests.
- [x] A TOML setting either key **fails startup** with a message naming the key and the `/health` +
      `/readyz` replacement — never accepted-and-ignored.
- [x] `config.example.toml` and `docs/running-guide.md` no longer advertise the knobs; the
      docs-freshness scan (Phase 0, ARCH-P2-5) is green.
- [x] G-2's counted arithmetic is updated in its post-Phase-4 form and the gate is green;
      `CLAP_DEFAULT_CLOBBERS` is still empty.
- [x] **M7 = 0** — with Phase 1's four surfaces and `ARCH-7k`, no inert config surface remains
      (`prd.md:997`).
- [x] No new `.unwrap()`; `thiserror` used for the new error variant (library crate — `CLAUDE.md`).

---

### ARCH-7k — Honour `BnRole` in `broadcast_inner` (closes M7)

- **Points:** 2 · **Scope:** 1–1.5 days · **Type:** feature · **Priority:** P2
- **Stream:** A · **Blocked by:** — · **Blocks:** —
- **Requirements:** ARCH-P2-8 (broadcast half) · **Constraints:** C9 (no anchor regressed)

**Context.** `crates/bn-manager/src/manager.rs:757-781`'s `broadcast_inner` iterates
`self.clients` (`:764`) with **no role filter**, and `broadcast` reports `tried = self.clients.len()`
(`:746`) — the unfiltered count. `self.roles: Vec<HashSet<BnRole>>` exists (`:86`, populated at
`:137-159`, defaulting to `{All}` at `:143`) and is honoured on the *query* path:
`synced_indices(role, min_tier)` at `:328` implements role → tier → health-score with a documented
`All`-role fallback (`:318-327`), used by `query_first` (`:242`). So the config surface is real,
parsed, stored — and ignored by fan-out. That is PB-B4, the fifth inert surface, and closing it is
what makes **M7 = 0**.

**The narrowing this issue takes, with its reason (A-7.8).** ARCH-P2-8 says "honour `BnRole`/tier".
**Role: yes. Tier: no.** `broadcast` is documented at `:737-738` as sending "to all BNs (**regardless
of sync status**)" — deliberately, because a fan-out publish of an *already-signed* message should
reach as many beacon nodes as possible; a lagging BN still gossips. Tier-filtering a publish would
reduce propagation and could lose an attestation on a partially-degraded fleet — a safety regression
dressed as a fix. This issue therefore filters by **role only**, passing the most permissive tier
floor into `synced_indices`, and records the narrowing in the code comment so a later reader does not
"complete" it.

**Files to touch.** `crates/bn-manager/src/manager.rs:737-755` (`broadcast` — add the role parameter
and fix the `tried` field), `:757-781` (`broadcast_inner` — filter), the `broadcast` call sites in
`crates/bn-manager/src/` (publish paths), and `crates/bn-manager/src/traits.rs:254-276` if the
default-roles doc needs updating. `crates/bn-manager/src/mock.rs` for the test double.

**Implementation approach.** Thread a `BnRole` argument into `broadcast`/`broadcast_inner`; select
indices via the existing `synced_indices(role, <permissive tier>)` so the `All`-fallback semantics
(`:324-326`) are shared rather than duplicated; build the future list from the selected indices only;
set the `tried` span field to the **filtered** count. If the role filter selects zero BNs, the
existing `All`-role fallback fires — and if that is also empty, fall back to *every* client with a
`warn!`, never to publishing nowhere.

**TDD test plan.**

- **RED first — `test_broadcast_reaches_only_the_matching_role_tier`.** Three mock BNs with roles
  `{Attestation}`, `{Block}`, `{All}`; broadcast an attestation publish; assert the `{Block}`-only BN
  received **zero** calls and the other two received one each, and that the recorded `tried` is `2`,
  not `3`. RED at HEAD (all three are called, `tried = 3`).
- `test_broadcast_is_not_tier_filtered` — a BN below the healthy tier still receives the publish.
  This is the guard on the narrowing: it fails if a later change "completes" ARCH-P2-8 by adding a
  tier filter.
- `test_broadcast_falls_back_to_all_role_when_no_bn_matches` — pins the `:324-326` fallback.
- Preserve: `query_first`'s existing role/tier tests must be untouched and green.

**KAT policy.** Not applicable.

**Acceptance criteria.**

- [x] A role-scoped broadcast reaches only the intended tier of nodes and `tried` reflects the
      **filtered** count (`prd.md:960`'s literal criterion).
- [x] Broadcast is **not** tier-filtered, and a test enforces that.
- [x] The `All`-role fallback is preserved and tested; an empty selection never means "publish to
      nobody" (fail-closed `NoEligibleBn`; never off-role last-resort).
- [x] **M7 = 0** is now reachable — this is the fifth and last inert surface (`prd.md:997`).
- [x] The pre-slot BN health re-check is **explicitly out of scope** (A-7.9) and recorded as follow-on
      work in the PR description, not silently dropped.
- [x] Zero new unbounded channels; no `tokio::spawn` added (C9 anchors 6 and 7 untouched).

---

### ARCH-7f — Spike: can the `Wire*` twins be collapsed at HEAD?

- **Points:** 2 · **Scope:** 1–1.5 days (**time-boxed — the verdict is the deliverable**) · **Type:** spike
- **Priority:** P1 · **Stream:** B · **Blocked by:** — · **Blocks:** ARCH-7h
- **Requirements:** ARCH-P1-14 (feasibility half) · **ADR:** ADR-011 (dependents)
- **Constraints:** C9 anchor 3 (KAT-first)

**Context — VD-7C.** Every upstream document schedules the `Wire*` deletion as executable work
(`prd.md:916`, review `:191`, `project-plan.md:711`). The code says otherwise.
`crates/eth-types/src/block_body.rs:41-43` states the trigger: *"remove the `Wire*` twins when
`ssz_types` compiles against `ethereum_ssz` 0.9 (or workspace `ssz` aligns with the stack `ssz_types`
implements)"*. At HEAD: root `Cargo.toml` pins `ssz = ethereum_ssz 0.9` (`:88`), `ssz08 =
ethereum_ssz 0.8.3` (`:93`), `ssz_types = 0.10.1` (`:98`), `tree_hash = 0.9` (`:99`); `Cargo.lock`
carries **both** `ethereum_ssz 0.8.3` (`:1526`) and `0.9.1` (`:1541`). The root manifest's own comment
(`:95-97`) warns that `ssz_types` 0.11+ pins `tree_hash ≥ 0.10`, i.e. the literal trigger implies a
**workspace-wide `tree_hash` upgrade** touching every `TreeHash` derive — including every KAT-anchored
signing-root test. That is not a phase-7-sized change, and scheduling the delete without resolving
this is how a plan acquires an item that cannot land.

**Three candidate paths, to be settled by a compile, not an argument.**

| Path | Description | Cost signal |
|---|---|---|
| **A** | Upgrade `ssz_types` to a release implementing `Encode`/`Decode` against `ethereum_ssz` 0.9 | Requires `tree_hash ≥ 0.10` workspace-wide (`Cargo.toml:95-97`); count the `TreeHash` derive sites and the KAT tests affected |
| **B** | Align the workspace on `ethereum_ssz` 0.8 (drop the 0.9 alias) | Count `ssz_derive` 0.9 derive sites that must change; check `web3signer-wire` and `signer-proto` |
| **C** *(default hypothesis)* | **Keep one struct per container and implement both trait sets on it.** The two `Encode`/`Decode` traits come from two *different* crates, so implementing both on one type is legal Rust — no coherence conflict. `crate::Checkpoint` already derives 0.9 `Encode, Decode` + `TreeHash` (`lib.rs:119-125`); `WireCheckpoint` (`block_body.rs:302`) gets its 0.8 impls from the hand-written `ssz_container!` macro (`:127-218`), and **both** `TreeHash` derives come from the same `tree_hash_derive` 0.9 | **Zero dependency change.** Cost = extending `ssz_container!` into a macro that decorates an existing struct, applied to 8 types |

**Scope relief already established:** the `Wire*` types are referenced **only inside
`block_body.rs`** (40 occurrences; zero elsewhere in `crates/` or `bin/`, excluding the orphan
`crates/rvc-signer/` that Phase 0 deleted). No downstream consumer breaks under any path.

**Files to touch.** **None in `develop`.** The spike runs in a throwaway worktree (the pattern
`project-plan.md:446` uses for ADR-002's probe). Its output is a written verdict appended to
`ARCH-7g`'s `docs/forks.md` and the `ARCH-7h` issue.

**Method.**

1. Try **Path C** on **one** container first — `WireCheckpoint` → `crate::Checkpoint` — and run
   `cargo check -p rvc-eth-types`. This is the cheapest possible falsifier; if the two `Encode`
   impls conflict, Path C dies in ten minutes.
2. If Path C holds for `Checkpoint`, verify the hard case: a type used as a `ssz_types::VariableList`
   element (`WireAttestationElectra`, `block_body.rs:394`, used at `:572`) — the element bound is
   where a coherence or trait-bound problem would actually surface.
3. Only if Path C fails, cost Paths A and B by **counting** (derive sites, KAT tests, lockfile deltas)
   — do not attempt either migration inside the time box.
4. Record the verdict with the `cargo check` output pasted in.

**TDD test plan.** The compile **is** the test, exactly as ADR-002's `?Send` probe (`architecture.md`
§7.2). Before touching anything, run the existing anchor and record the baseline: `cargo nextest run
-p rvc-eth-types` with `crates/eth-types/src/block.rs:671-738` asserting `body_tree_hash_root` /
`blinded_body_tree_hash_root` against `EXTERNAL_ELECTRA_BODY_ROOT_HEX`,
`EXTERNAL_ELECTRA_BLOCK_ROOT_HEX`, `EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX`,
`EXTERNAL_DENEB_BODY_ROOT_HEX`, `EXTERNAL_DENEB_BLOCK_ROOT_HEX` (constants at `block_body.rs:794-825`).
A Path-C prototype that changes any of those roots has produced the exact field-order bug the KAT
policy exists to catch, and the spike ends there.

**Acceptance criteria.**

- [x] A written verdict naming **one** path as chosen or all three as blocked, with `cargo check` /
      `cargo nextest` output pasted in.
- [x] If Path C: a working single-container prototype and the `VariableList`-element case verified.
- [ ] If blocked: the **specific** blocking fact (compiler error, or the counted `tree_hash` upgrade
      surface) recorded, so `ARCH-7h`'s deferral carries a trigger a future reader can re-test.
- [x] The six `EXTERNAL_*` root assertions in `block.rs:671-738` are unchanged in the prototype.
- [x] **No product-code commit lands on `develop` from this issue.** (Verdict measurement only; prototype reverted.)

---

### ARCH-7g — Write `docs/forks.md` (add-a-fork checklist)

- **Points:** 2 · **Scope:** 1 day · **Type:** chore · **Priority:** P1
- **Stream:** B · **Blocked by:** — · **Blocks:** ARCH-7h
- **Requirements:** ARCH-P1-14 (docs half) · **Constraints:** C9 anchor 3

**Context.** `prd.md:912-923` and the review (`:191`) pair the `Wire*` deletion with a new
`docs/forks.md` enumerating the verified `ForkName` / `ForkSchedule` / `body_layout` dispatch sites.
The two are **independent** (A-7.10): the checklist has no dependency on the SSZ-stack question, and
it is also where `ARCH-7h`'s deferral verdict is recorded if the collapse cannot land. Writing it
first means the fork-readiness deliverable ships even in the pessimistic branch.

**Files to touch.** `docs/forks.md` *(new)*. No source file.

**Implementation approach.** Enumerate, with `file:line`, every dispatch site — the review counts
"~8 files". Verify each by opening it; the docs-freshness scan Phase 0 added (ARCH-P2-5) will fail on
any path that does not exist, so a copied-from-the-review list is not acceptable. Sections:

1. **Dispatch sites** — `ForkName` / `ForkSchedule` / `body_layout` (`crates/eth-types/src/fork.rs`,
   `block.rs:282,350` `kzg_commitment_root(layout)`, `block_body.rs`'s per-fork bodies
   `BeaconBlockBodyElectra` `:566` / `BlindedBeaconBlockBodyElectra` `:598` / the Deneb pair, and the
   SEC-9 fail-closed startup gate).
2. **The KAT obligation** — each new container root needs an `EXTERNAL_*`/`KAT_*`/`SPEC_*` anchor per
   `CLAUDE.md`; name the existing constants (`block_body.rs:794-825`) as the pattern to copy.
3. **The dual-SSZ status** — the current stack, the deletion trigger verbatim
   (`block_body.rs:41-43`), and **`ARCH-7f`'s verdict**, so the next fork engineer inherits the
   finding instead of rediscovering it.
4. **The per-fork checklist itself** — body variant, `body_layout` arm, root KAT, `ForkSchedule`
   entry, startup gate, conformance fixtures.

**TDD test plan.**

- **RED first — the docs-freshness scan.** Before writing prose, add `docs/forks.md` containing a
  deliberately **dead** path and run Phase 0's scan; it must fail naming the path. That demonstrates
  the doc is actually covered by a gate rather than merely committed. Then write the real content and
  watch it go green.
- Every `file:line` in the finished doc is opened during review; the scan checks path existence, a
  human checks the line still says what the doc claims.

**KAT policy.** No test is added, so the scanner is not engaged — but §2 of the doc **states** the
obligation for future fork work, which is the point.

**Acceptance criteria.**

- [x] `docs/forks.md` exists; every path in it resolves under the docs-freshness scan.
- [x] Every dispatch site listed was opened and verified, with `file:line`.
- [x] The KAT-anchoring obligation for new container roots is stated with the existing `EXTERNAL_*`
      constants named as the pattern.
- [x] `ARCH-7f`'s verdict is recorded in the doc.
- [x] The scan is RED against a scratch dead path (output in the PR).

---

### ARCH-7h — Collapse the `Wire*` twins, or record the deferral

- **Points:** 3 · **Scope:** 2 days · **Type:** feature · **Priority:** P1
- **Stream:** B · **Blocked by:** ARCH-7f, ARCH-7g · **Blocks:** ARCH-7l
- **Requirements:** ARCH-P1-14 (execution half), **M9** contribution · **ADR:** ADR-011 (dependents)
- **Constraints:** **C9 anchor 3 (binding)**, C9 anchor 1

**Context.** Eight `Wire*` twins exist because the crate-root types use `ssz` 0.9 while
`ssz_types` 0.10.1 implements `Encode`/`Decode` against `ethereum_ssz` 0.8 only
(`block_body.rs:22-39`): `WireCheckpoint` `:302`, `WireAttestationData` `:310`,
`WireBeaconBlockHeader` `:321`, `WireAttestation` `:368`, `WireAttestationElectra` `:394`,
`WireDepositData` `:404`, `WireVoluntaryExit` `:422`, `WireSignedVoluntaryExit` `:430`. The dual stack
doubles per-container fork work and **reintroduces the field-order bug class the KAT-first policy
exists to catch** — the same class that "shipped green tests for wrong tree-hash / field-order bugs
(F122)" per `CLAUDE.md`. This is the one item in the initiative with an **external calendar trigger**
(A-P10): if a body-changing fork is announced, it is pulled to the head of the queue regardless of
phase order.

**This issue has two branches and both are deliverables.**

**Branch 1 — `ARCH-7f` chose a path.** Collapse the eight twins onto the crate-root types.

- Files: `crates/eth-types/src/block_body.rs` (the eight `ssz_container!` invocations and their ~40
  internal references), `crates/eth-types/src/lib.rs` (the crate-root counterparts at `:119-125` and
  following), `crates/eth-types/src/{aggregation.rs, builder.rs, sync_committee.rs}` if their
  containers are among the collapsed set.
- Approach: one container per commit, `EXTERNAL_*` roots re-run after each. Start with
  `WireCheckpoint` (a leaf) and finish with `WireAttestationElectra` (a `VariableList` element, the
  hard case). Never collapse two containers in one commit — a root that moves must be attributable.

**Branch 2 — `ARCH-7f` found it blocked.** The deliverable is a **recorded, trigger-bearing
deferral**, not a skipped issue:

- The blocking fact and the re-test procedure written into `docs/forks.md` §3.
- The `block_body.rs:41-43` trigger comment updated with the verdict, its date and the baseline
  commit, so it is not re-litigated from scratch next year.
- A CI reminder: extend the docs-freshness or `arch-gates` job with an assertion that fails if
  `Cargo.lock` ever stops containing two `ethereum_ssz` entries — i.e. **the day the trigger becomes
  satisfiable, CI says so.** A deferral with no detector is a forgotten item.
- **M9 does not drop by the `Wire*` entry** in this branch; say so in the PR rather than letting the
  metric quietly read as met.

**TDD test plan (Branch 1 — the KAT-first obligation, and this is the point of the issue).**

- **RED first — `electra_body_root_matches_external_vector_after_collapse`.** Before collapsing
  anything, add/confirm the assertion that `body_tree_hash_root` (`block_body.rs:735`) equals
  `EXTERNAL_ELECTRA_BODY_ROOT_HEX` (`:794`) and that `blinded_body_tree_hash_root` (`:746`) equals
  `EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX` (`:807`) — the existing anchors live at
  `block.rs:671-738`. Then make a **deliberate one-field-order swap** in a scratch commit and confirm
  the assertion fails. That is the RED: it proves the anchor detects the exact bug class the collapse
  risks, *before* the collapse. Re-running a green test proves nothing.
- Every touched container root test is **re-anchored, not merely re-run** — each must assert against
  an `EXTERNAL_*` / `KAT_*` / `SPEC_*` constant (`architecture.md` §7.1 anchor 3, `CLAUDE.md`). Four
  candidates are currently on the exemption list and live in this crate:
  `aggregation.rs` (2 entries, `kat_policy.rs:106-113`), `builder.rs` (`:114-117`),
  `sync_committee.rs` (`:118-121`), `tree_hash_utils.rs` (`:122`) — if the collapse touches them,
  they must be **re-anchored and removed from `EXEMPTIONS`**, feeding `ARCH-7l`.
- `EXEMPTIONS` must not grow. Any newly-named `*_root` test needs a KAT constant in its body or a
  `// kat_exempt: <reason>` marker (`kat_policy.rs:12-17`, `:238`, `:275`).
- SSZ round-trip: encode/decode each collapsed container and assert byte-equality with the pre-change
  encoding, per fork variant.

**Acceptance criteria.**

- [x] **Branch 1:** `rg 'Wire(Checkpoint|AttestationData|BeaconBlockHeader|Attestation|AttestationElectra|DepositData|VoluntaryExit|SignedVoluntaryExit)'`
      returns nothing; one struct per container; all six `EXTERNAL_*` root assertions green and
      **unchanged in value**; SSZ round-trips byte-identical; `EXEMPTIONS` has not grown.
- [ ] **Branch 2:** the trigger, the blocking fact, the re-test procedure and the date are in
      `docs/forks.md`; the `block_body.rs` comment is updated; a CI detector fires when the trigger
      becomes satisfiable; the PR states plainly that M9's `Wire*` entry is **not** closed.
- [x] Either branch: `cargo nextest run -p rvc-eth-types` and the workspace run green;
      `ARCHITECTURE.md` regenerates byte-identically (C9 anchor 1 — no crate boundary moved).
- [x] Either branch: `docs/forks.md` §3 tells the next fork engineer what is true.

---

### ARCH-7i — Register the DVT signing surface in `signer-registry`

- **Points:** 3 · **Scope:** 2 days · **Type:** feature · **Priority:** P1
- **Stream:** B · **Blocked by:** — · **Blocks:** ARCH-7j
- **Requirements:** ARCH-P1-7 · **Constraints:** **C9 anchor 5 (binding)**, C9 anchor 7

**Context.** "Every signing surface is classified" is false under `--features dvt`. Verified at HEAD
(and note **VD-7B**: the file is `crates/signer-server/`, not `crates/signer/` as every upstream
document writes it): `partial_sign_beacon_block` computes a signing root at
`peer_service.rs:215-218` and calls `partial_sign_with_share` at `:236`; `partial_sign_attestation_data`
does the same at `:309-311` / `:328`. **`SigningGate` is never invoked on either path.**

**What is *not* true, and matters for how this is fixed (A-7.5):** these paths are **not
slashing-unprotected**. Both run a full `PubkeyScopedDb` stage → sign → commit
(`:227`, `:232-234`, `:240-242`, `:246`; attestation at `:319`, `:325`, `:333`, `:338`), inside
`spawn_blocking` because the staged guard is `!Send` (`:230-231`, `:322-323` — these two sites are
C9 anchor 7's named exclusions and **must never enter G-4's ban list**). They are *gate-unclassified*,
not ungated. Routing share-signing through a `SigningGate` built for full BLS keys via
`CompositeSigner` would be an architectural mismatch, so this issue takes the PRD's **second**
option (`prd.md:822-824`): *"formally register it in `signer-registry` with its own enforcement
contract"* — stated as a decision, not discovered at compile time.

**The part the upstream misses (VD-7D).** Registration is not an append. Two existing assertions
break:

- `signing_path_enumeration.rs:104-115` asserts **every** entry's `service` equals
  `"signer.v2.SignerService"` (`:105`).
- `:122-130` asserts `REGISTERED_METHODS.len() == EXPECTED` with `EXPECTED: usize = 10` (`:124`).

And `rvc-signer-registry` has **no `dvt` feature** — only `bin/rvc-signer/Cargo.toml:19` and
`crates/signer-server/Cargo.toml:20` declare one — so unconditional entries would change the count
for the default-features run too.

**Files to touch.**

- `crates/signer-registry/Cargo.toml` — add a `dvt` feature.
- `crates/signer-registry/src/lib.rs` — `#[cfg(feature = "dvt")]` entries for the two DVT methods; a
  new enforcement variant on `GateRouting` (or a sibling field) meaning *"slashing-scoped share
  signing, not `SigningGate`-routed"*; a new `SLASHING_STAGE_METHODS` canonical list
  (`stage_block`, `stage_attestation`) analogous to `SIGNING_GATE_METHODS`; a `service` string for
  the DVT service.
- `crates/signer-server/Cargo.toml:20` — chain `signer-registry/dvt` into the existing `dvt` feature.
- `crates/signer-server/src/dvt/peer_service.rs` — doc comments naming the registry entry each
  handler satisfies (the linkage a reader can check).

**The C9-anchor-5 guard rail — non-negotiable.** A new enforcement variant is a hole unless it is
fenced. The registry model must make all of the following true, and `ARCH-7j` asserts them:

1. The new variant may appear **only** on entries whose `service` is the DVT service — never on
   `signer.v2.SignerService`.
2. An entry carrying it **must** name a member of `SLASHING_STAGE_METHODS`; `None` is a hard failure,
   exactly as `gate_method: None` is today (`:155-161`).
3. `no_slashable_method_is_marked_non_slashable` (`:74-96`) keeps its exact current strength — the
   DVT entries are slashable kinds and may **not** be `NonSlashable`.

**TDD test plan.**

- **RED first — `dvt_partial_sign_methods_are_registered`** in
  `crates/signer-server/tests/signing_path_enumeration.rs`, `#[cfg(feature = "dvt")]`. Assert both DVT
  methods appear in `REGISTERED_METHODS` with the slashing-scoped variant and a named stage method.
  RED at HEAD under `cargo nextest run -p rvc-signer-server --features dvt` (they are absent).
- **RED — `dvt_enforcement_variant_is_rejected_on_the_v2_service`:** a scratch entry putting the new
  variant on `signer.v2.SignerService` must fail. This is the loophole test; without it the change
  meant to strengthen M4 weakens it.
- **RED — `dvt_partial_signature_requires_a_committed_slashing_row`:** a handler-level test that a
  partial signature cannot be produced when staging fails — `prd.md:827`'s literal criterion ("a DVT
  partial signature cannot be produced outside the registered contract"), driven through the real
  `stage_* → commit()/discard()` path, not a stub.
- Update `EXPECTED` to be feature-conditional (10 default / 12 with `dvt`) **in the same commit** as
  the entries, and state the number in the failure message so the next person knows which run they
  are looking at.
- Preserve verbatim: `:74-96`, `:143-173`, `:180-194`, `:199-213`.

**KAT policy.** Applies **indirectly and must be watched**: do not name any new test with a
`_root` / `_tree_hash` / `_signing_root` suffix. These tests assert *registration and enforcement*,
not spec-defined roots — the same inverse obligation the architecture places on ADR-003
(`architecture.md` §7.1 anchor 3). A `_root`-suffixed name here would pull an unrelated test into
`kat_policy`'s scope for no benefit.

**Acceptance criteria.**

- [x] Both DVT partial-sign methods appear in `REGISTERED_METHODS` under `--features dvt` with an
      explicit enforcement contract naming their stage method.
- [x] The new variant cannot appear on `signer.v2.SignerService` (test-asserted).
- [x] A DVT partial signature cannot be produced without a committed slashing row (test-asserted
      through the real path).
- [x] Default-features `cargo nextest run --workspace` is unaffected — count still 10, service
      allow-list still effectively single-valued.
- [x] `crates/signer/src/gate.rs`'s single wiring site (`config/builder.rs:394`) and the
      `CompositeSigner` grep gate are **untouched and green** (C9 anchor 5).
- [x] G-4's ban list has **not** gained `signer-server/src/dvt/peer_service.rs:231` or `:323`
      (C9 anchor 7).

---

### ARCH-7j — Enumeration gate under `--features dvt` + the new CI step

- **Points:** 2 · **Scope:** 1 day · **Type:** chore (gate/CI) · **Priority:** P1
- **Stream:** B · **Blocked by:** ARCH-7i · **Blocks:** —
- **Requirements:** ARCH-P1-7 (CI half), **M5** (+1 of the 3 CI checks)
- **Constraints:** C9 anchor 5, NFR-5 (CI runtime)

**Context — VD-P6, re-verified and sharpened.** `architecture.md` §7.1 anchor 5 and `prd.md:826`
phrase this as *"the enumeration gate is **run with `--features dvt`** in CI"* — a flag on an existing
run. **There is no such run.** `.github/workflows/ci.yml:46-47` is `cargo clippy -p rvc-signer-bin
--all-targets --features dvt` — **clippy only**, one package. The only place a `#[test]` executes is
`:166`, `cargo llvm-cov nextest --workspace`, default features. This is a **new CI step**.

**And the obvious invocation does not work (A-7.6).** `dvt` is declared only on `bin/rvc-signer`
(`Cargo.toml:19`) and `crates/signer-server` (`:20`); a virtual-workspace `--workspace --features dvt`
does not resolve. The step is:

```
cargo nextest run -p rvc-signer-server --features dvt
```

**Files to touch.** `.github/workflows/ci.yml` — add the step to the **`arch-gates` job Phase 0
created** (A-P1 / VD-P7), not to `coverage`. Putting a gate in `coverage` couples gate failures to
`llvm-cov` instrumentation and to the slowest job (NFR-5, R10) — the exact anti-pattern Phase 0 added
`arch-gates` to avoid. Optionally also
`crates/signer-server/tests/signing_path_enumeration.rs` for the guard-rail assertions from 7i.

**Implementation approach.** One step, `protoc` already installed in the job. Assert in the PR that
the step actually **runs** the DVT tests (the `#[cfg(feature = "dvt")]` tests appear in the nextest
output) — a feature-gated test suite that silently compiles to nothing is a gate that passes
vacuously, and that is the failure mode here.

**TDD test plan.**

- **RED first — remove one DVT entry from `REGISTERED_METHODS` in a scratch commit and run the new
  step.** It must fail, naming the missing method. Paste the output. Then confirm the **same** scratch
  commit leaves the default-features run green — that contrast is the whole argument for the step's
  existence, and it is what `clippy --features dvt` cannot show.
- Second RED: a scratch DVT handler added without a registry entry must fail the count floor.
- Assert non-vacuity explicitly: capture the nextest summary line showing the dvt-gated test names.

**KAT policy.** Not applicable.

**Acceptance criteria.**

- [x] `cargo nextest run -p rvc-signer-server --features dvt` runs in the `arch-gates` job and passes.
- [x] The step's output demonstrably includes the `#[cfg(feature = "dvt")]` tests (non-vacuity).
- [x] Removing a registry entry turns the step RED while the default run stays green (output in PR).
- [x] The existing `cargo clippy -p rvc-signer-bin --all-targets --features dvt` step (`:46-47`) is
      **kept** — it is Gate 1 secret-sink coverage and is not what this replaces.
- [x] CI wall-clock increase recorded in the PR (NFR-5).
- [x] **M5:** the third and last of the +3 CI checks is landed (`prd.md:995`); with G-6 from
      `ARCH-7a` as the 7th gate, M5's enumerated target is reached.

---

### ARCH-7l — Prune the KAT `EXEMPTIONS` list (removals only)

- **Points:** 1 · **Scope:** 0.5 days · **Type:** chore · **Priority:** P2
- **Stream:** B · **Blocked by:** ARCH-7h *(conditionally — see below)* · **Blocks:** —
- **Requirements:** ARCH-P2-4 · **Constraints:** **C9 anchor 3 (binding)**

**Dependency is conditional.** 7l runs after 7h only so the list shrinks **once**, against the final
state of `crates/eth-types`' container-root tests. Under 7h's **Branch 2** (the deferral) no
`eth-types` test changes, the dependency is vacuous, and 7l can start immediately — worth stating
because it is what frees Stream B early in the two-developer overlay.

**Context — VD-7G.** `crates/architecture-tests/tests/kat_policy.rs:42-163` holds **57** entries.
Seven of them (`:92-104`) live in `crates/crypto/tests/signing_root_kat.rs` and are named `kat_*` —
they *are* KAT tests, listed as exempt only because `body_has_kat_constant` (`:238`) scans the **test
body** for an `EXTERNAL_*` / `KAT_*` / `SPEC_*` token and these reference file-level constants. Four
more (`:106-122`) are `crates/eth-types` field-sensitivity tests in the crate `ARCH-7h` touches — this
issue runs **after** 7h so the list shrinks once against the final state. Ten entries are
`bin/rvc-keygen/*` (`:43-52`): those live in the **tracked** `bin/` tree and are unaffected by Phase
0's orphan deletion — a plausible mis-read, stated so nobody "prunes" them expecting the files to be
gone.

**Files to touch.** `crates/architecture-tests/tests/kat_policy.rs` (the `EXEMPTIONS` array only) and,
where a test genuinely is KAT-anchored but the detector cannot see it, the test itself — a
`// kat_exempt: <reason>` marker or a body-local reference to the constant.

**Implementation approach.** For each candidate, choose exactly one of: (a) the test references its
KAT constant in-body → remove the exemption; (b) the test is legitimately non-KAT (a truncation,
logging or field-sensitivity assertion) → add `// kat_exempt: <reason>` in the body and remove the
exemption; (c) neither → **leave the entry**. Do **not** weaken the detector to make entries
disappear — the detector's strictness is the asset. `EXEMPTIONS` is shrinking-only
(`kat_policy.rs:16-17`, `CLAUDE.md`); the `kat_policy_exemptions_are_sorted_and_unique` test (`:463`)
keeps the array sorted through the edit.

**TDD test plan.**

- **RED first — `kat_policy_exemptions_count_is_at_most_N`.** Before pruning, add an assertion that
  `EXEMPTIONS.len() <= 57` and confirm it passes; then set the bound to the post-prune number and
  watch it fail until the removals land. A ratchet turns "the list shrinks" from a review promise
  into a gate, and prevents a future PR from re-adding entries under the shrinking-only rule.
- After each removal, `cargo nextest run -p rvc-architecture-tests` must stay green — a removal that
  turns `kat_policy` RED means the test was *not* in fact KAT-anchored and the entry must be restored
  (or the test fixed, which is a different issue).

**KAT policy.** This issue **is** the KAT policy. C9 anchor 3 is directly at stake: the list must end
strictly shorter than 57 and never longer.

**Acceptance criteria.**

- [x] `EXEMPTIONS` is strictly shorter than 57 entries; each removal is justified in the PR by
      category (a)/(b) above.
- [x] The seven `signing_root_kat.rs` entries (`:92-104`) are individually adjudicated — removed or
      justified in writing; "left as-is" without a reason is not acceptable.
- [x] `kat_policy` and `kat_policy_exemptions_are_sorted_and_unique` (`:463`) are green.
- [x] A `EXEMPTIONS.len()` ratchet assertion exists so the list cannot grow.
- [x] The detector at `:238` / `:275` is **unchanged** — no entry was retired by weakening the scan.

---

### ARCH-7m — 200-key / 200 ms scale validation run, checked in

- **Points:** 3 · **Scope:** 2 days · **Type:** chore · **Priority:** P1
- **Stream:** B · **Blocked by:** Phase 5 (`P1-15a` harness) · **Blocks:** —
- **Requirements:** ARCH-P1-15b, **M3** · **Constraints:** C9 anchor 2 (must not be disturbed)

**Context.** `project-plan.md` D8 split ARCH-P1-15: the load-harness **build** and the M3 baseline are
Phase 5's *entry* criterion (`P1-15a`); only the validation **run** is here. This issue therefore
**builds no harness** — if 5A's harness does not exist, this issue is blocked, not re-scoped.
(VD-P2 is why: the two `benches/` files that exist — `crates/signer/benches/sign_path.rs`,
`crates/rvc/benches/per_slot.rs` — are logging-latency benches, explicitly not run under
`nextest`/CI, and measure neither sign throughput nor slot-phase offsets.)

The instrument exists: `rvc_signer_slashing_tx_hold_duration_ms{kind=block|attestation}`, observed at
`crates/signer/src/core.rs:219`, regression-tested by `crates/signer/tests/tx_hold_metric.rs`
(`prd.md:993`).

**Scope stated honestly (A-A8).** This validates the **`signer-server`** profile. The VC path's wall
is a sequential `await` loop, not the mutex (VD-S2), so a green run here does **not** license a claim
about the VC path at 200 keys. The write-up must say so in its own words.

**Files to touch.** `plan/architecture-2026-08-12/measurements/m3-scale-200keys-200ms.md` *(new,
A-7.11)*, and the harness's parameter file/fixture in Phase 5's location. No production source.

**Implementation approach.** Run 5A's harness at **200 keys / 200 ms injected remote-signer latency**
(A-9), against the post-ADR-005 tree, and record: p50/p95/p99/max hold duration per kind; missed
attestation deadlines (target **0**); throughput per attestation window; the p99 against the per-sign
budget implied by 200 keys in one window; and the **pre-redesign** number from Phase 5's baseline for
comparison. Record the environment (host, cores, disk, `synchronous`/`fullfsync` settings from
`slashing/src/db/open.rs:240-246`) — an unreproducible number is not a measurement.

**If fsync dominates (R1's tail):** record it and stop. Group commit is admissible **only if measured
to bind** (A-A9) and is explicit **follow-on work, not absorbed here**. Writing "we also added group
commit" into this issue would put an unreviewed change to the commit-before-sign ordering inside a
measurement task.

**TDD test plan.** Measurement, not TDD — but the analogue applies and is not optional:

- **RED first — run the harness at 200 keys with the injected latency raised until deadlines are
  missed**, and confirm the harness *reports* the misses. A harness that cannot show failure cannot
  demonstrate success. Record that calibration run alongside the real one.
- Confirm `tx_hold_metric.rs` is green before and after — the metric being measured must still be the
  metric that is pinned.
- **Do not touch** the C9 anchor-2 proof surfaces (error-class × policy matrix, crash/cancellation
  injection, concurrency proptest). They gate Phase 5's switchover; this issue reads their world, it
  does not edit it.

**KAT policy.** Not applicable.

**Acceptance criteria.**

- [x] `plan/architecture-2026-08-12/measurements/m3-scale-200keys-200ms.md` exists and is checked in —
      "documented" means **a file in this directory**, not a run log or a PR comment
      (`prd.md:934`, `project-plan.md:714`).
- [x] Zero missed attestation deadlines at 200 keys / 200 ms.
- [x] `rvc_signer_slashing_tx_hold_duration_ms` p99 recorded per kind and compared against the
      Phase-5 pre-redesign baseline; no single hold exceeds the remote-signer timeout.
- [x] The environment is recorded in enough detail to reproduce.
- [x] The write-up states that this validates the `signer-server` path (A-A8), and names the VC path
      as unvalidated at this count.
- [x] The calibration (deliberately-failing) run is recorded alongside the passing one.
- [x] If fsync binds, it is recorded as follow-on work — **no group-commit change lands here**.

---

## 7. Constraint Coverage Matrix (C1–C10)

Every constraint gets a row. Silence on any is a defect, so the five this phase does not touch carry
an explicit no-regression statement rather than being omitted.

| # | Constraint | Status in Phase 7 | Where |
|---|---|---|---|
| **C1** | Retain-on-ambiguity vs lock-shortening | **Not touched.** Phase 7 contains no `crates/slashing` or `crates/signer` change. `ARCH-7i` documents the DVT `stage → sign → commit` shape but modifies **no** ordering; `ARCH-7m` measures the redesign, and its acceptance explicitly forbids landing group commit (A-A9). No-regression check: C9 anchor 2's three proof surfaces are untouched by every issue here. | 7i (read-only), 7m |
| **C2** | Audit-log emission inside the mutex | **Not touched — discharged in Phase 1** (ADR-006 / G-7, both paths `scoped.rs:69-75` and `:102-107`). No issue here opens `crates/slashing/src/scoped.rs`. G-7 must remain green at the phase's exit run. | — |
| **C3** | figment `Env` provider is FORBIDDEN | **Not touched — carried.** `ARCH-7e` removes two config knobs and introduces **no** env var and no provider layer; the `RVC_*` allow-list gate (G-3, Phase 4) must be green at exit, and 7e must not add an allow-list entry. Recorded as an explicit non-action because a "removed the knob, added an env override" shortcut is exactly what C3 forbids. | 7e |
| **C4** | Keystore-less key admission | **Not touched — discharged in Phase 1** (ADR-007's `AdmissionSource::{Keystore, RawSecret}`). `ARCH-7b`/`7c` operate on the doppelganger monitor selection **downstream** of admission and must not reintroduce a keystore-file assumption: 7c's always-safe monitor takes no keystore path, and the re-arm scan's zero-window guard (`spawn.rs:104`) is preserved unchanged. | 7b, 7c |
| **C5** | KM-2 teardown contract | **Binding and central.** Two obligations: **gate** it (`ARCH-7a`, G-6 — the gate the review assumed existed, VD-6) and **preserve** it (`ARCH-7b`, `ARCH-7c` — `stop_monitoring` leaves `ForwardWindowStatus::Pending`, `cancel_monitoring` calls `ForwardWindowMachine::cancel`, DELETE still calls `remove_validator` + `cancel_monitoring`). The gate lands **first**, and the trait default at `traits.rs:86-88` is treated as the trap it is via a classification table, not a blanket ban. | **7a**, 7b, 7c |
| **C6** | Cold-cache pre-proposal fetch | **Not touched — Phase 3's territory** (ADR-004's bounded 500 ms fetch). No issue here opens `crates/rvc/src/orchestrator/`. This is also why `ARCH-7k` **rejects** the pre-slot BN health re-check bundled into ARCH-P2-8 (A-7.9): it is a slot-loop change that would move the M2 offset Phase 3 was judged against. | 7k (by exclusion) |
| **C7** | SSE drops are normal | **Not touched — Phase 3's ADR-013.** `ARCH-7k`'s broadcast change touches the *publish* fan-out in `bn-manager`, not the SSE consumer (`crates/bn-manager/src/sse.rs`), adds no channel, and leaves the 1/3-slot timer authoritative. No `error!` or failure metric is introduced on any expected-path event. | 7k |
| **C8** | Healthz removal is operator-visible | **Binding.** `ARCH-7d` removes the server only **after** Phase 0's `0F` deprecation has shipped ≥ 1 release (an entry criterion, and the only calendar dependency in the phase); the replacement is named concretely (`/health`, `/readyz` — `crates/metrics/src/server.rs:57-64`, `:145`, VD-P3) and proven live in the same PR; the probe-migration check written in Phase 0 is linked. `ARCH-7e` disposes the knobs by **startup rejection**, because `ConfigWire`'s `#[serde(default)]` (`types.rs:628-630`) would otherwise make deletion equal silent acceptance — PB-B1 inside the fix for PB-B1. VD-A3 stands and is stated: no probe inventory exists; the window is the discovery mechanism. | **7d**, **7e** |
| **C9** | Preserve the keep-list | **Anchor 1** (`architecture-tests` harness): 7a adds a **new** gate file and modifies no existing one; 7l shrinks a shrinking-only table; `ARCHITECTURE.md` must regenerate byte-identically (7b/7h delete types, not members — the count stays 28). **Anchor 3** (KAT-first): 7h re-anchors every touched container root against `EXTERNAL_*` (`block_body.rs:794-825`) and 7l shrinks `EXEMPTIONS`; new tests in 7a/7i avoid `_root` suffixes. **Anchor 5** (single unbypassable signing gate): 7i adds an enforcement variant that is *fenced* — DVT service only, stage method mandatory, `no_slashable_method_is_marked_non_slashable` unchanged — and 7j proves it under `--features dvt`; the `config/builder.rs:394` wiring site and the `CompositeSigner` grep gate are untouched. **Anchor 6** (zero unbounded channels): no issue adds a channel. **Anchor 7** (`spawn_blocking` out of executor scope): 7i documents `peer_service.rs:231,323` and its acceptance forbids adding them to G-4's ban list. **Anchor 2** and **anchor 4** are not touched (see C1, C3). | 7a, 7b, 7h, 7i, 7j, 7l |
| **C10** | Archive-before-delete for untracked trees | **Expired, and that expiry is load-bearing here.** The constraint's own scope ends when Phase 0's delete commit lands (`project-plan.md:151-157`), after which G-1 enforces it mechanically. Consequence for this phase, stated so it cannot be mis-read: the orphan trees' contents are **out of scope and must not appear in any issue's file list** — specifically `crates/rvc/src/main.rs:14,21,1401,1862,1866` (its `DutyTrackerService` and `DoppelgangerService` references, which `ARCH-7b`/`7d` must **not** cite) and `crates/rvc-signer/` (its own `dvt` feature at `Cargo.toml:23` and `src/dvt/peer_service.rs`, which `ARCH-7i`/`7j` must **not** target — see VD-7B). Every deletion in this phase is of **tracked** code and is recoverable by `git revert`; C10's archive-then-delete procedure does not apply to any of them. | 7b, 7d, 7i, 7j |
