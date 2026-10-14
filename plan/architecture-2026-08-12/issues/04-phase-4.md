# Phase 4 Issues — Config Consolidation: gate the env rule, then collapse

> **Authoritative inputs, in precedence order:**
> [`../project-plan.md`](../project-plan.md) §7 *Phase 4* (scope, gates, entry/exit) →
> [`../architecture.md`](../architecture.md) (**ADR-008**, **ADR-009**, **ADR-010**; gate **G-3**;
> interface §5.4) → [`../prd.md`](../prd.md) (**ARCH-P1-2**, **ARCH-P1-3**, **M4**, **R8**) →
> [`../research/`](../research/) → [`../../../docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md).
>
> **Baseline:** `develop` @ `0ae9a09` (v0.7.0). Authored 2026-08-12. Every `file:line` below was
> re-opened against HEAD while writing this file; where a cited fact did not reproduce it is recorded
> in §3 *Verification Deltas* and the **corrected** fact is what the issues carry.
>
> **What this file adds over its inputs.** Eight verification deltas (§3), two of which change scope:
> ADR-008 counts **five** hand-maintained sites per knob — there is a **sixth**, the `ConfigWire`
> flat/nested TOML compatibility shim (`crates/rvc/src/config/types.rs:628-711`, 31 flat legacy keys,
> documented **flat-wins** precedence at `:626-627`), which **cannot be deleted** without breaking
> every operator TOML written against the old spelling (**VD-4.1**); and ADR-008's "already
> near-isomorphic, mostly a renaming exercise" sizing fact is **partial and now quantified** — 37 of
> the 65 `merge_with_cli` arms are dotted `self.<section>.<field>` (`:1243-1290`) but **28 are bare
> `self.<field>`** (`:1214-1241`), and five of the thirteen clap groups have no section at either the
> `Config` or the TOML layer (**VD-4.2**). Also: the milestone's `rg 'figment'`-empty check is **false
> at HEAD and would still be false after a perfect execution** (**VD-4.3**), and the five sanctioned
> security opt-out env vars all reach the runtime through **one indirect, unclassifiable call site**
> (`crates/crypto/src/insecure.rs:168`) that a literal-argument scanner cannot see (**VD-4.5**).
>
> **No-ask constraint:** every open question is resolved to a stated default in §2 *Assumptions*.
> Nothing is escalated. Following the convention set in
> [`../../tracing-2026-08-06/project-plan.md`](../../tracing-2026-08-06/project-plan.md).
>
> **Scope:** planning only. This file changes no source, deletes nothing, and touches no path outside
> `plan/architecture-2026-08-12/`. `docs/prd.md`, `docs/architecture.md` and `docs/project-plan.md`
> belong to the older Test Audit Remediation initiative and are **not** inputs here (NG8).

---

## 1. Phase Overview

**Goal.** One declaration per operator knob, with the "env = security opt-outs only" discipline
converted from convention into a **gate that lands first**, so the collapse cannot quietly erode it.

**Maps to.** PRD **ARCH-P1-3** (env allow-list gate) and **ARCH-P1-2** (extract `rvc-config`, one
declaration per knob). ADR-010 (owns and *replaces the mechanism of* ARCH-P1-3), ADR-008 (owns and
*supersedes the mechanism of* ARCH-P1-2), ADR-009 (inherited from Phase 1). Gate **G-3**; gate
**G-2** is inherited from Phase 1 and is **retired in part** here.

| | |
|---|---|
| **Issues** | 12 (`ARCH-4a` … `ARCH-4l`) |
| **Points** | **29** (scale 1/2/3/5; no issue exceeds 3) |
| **Duration, 1 dev** | **15–21 working days** — *revised upward from the plan's 11–16 d; driver named in §1.1* |
| **Duration, 2 devs** | **11–16 working days** (critical path ≈ 22 pts; Stream B is only 9 of 29 pts and finishes early) |
| **Streams** | **A** = config code (`crates/rvc-config/`, `bin/rvc/src/cli.rs`, `crates/rvc/src/config/`) · **B** = gates, CI and operator docs (`crates/architecture-tests/tests/`, `.github/workflows/ci.yml`, release notes) — disjoint file sets |
| **Depends on** | **Phase 1** only (G-2 green, ADR-009 landed). Nothing from Phases 0/2/3 is required beyond Phase 0's `arch-gates` CI job. |

### 1.1 Estimate reconciliation — moved on evidence, not padded

The project plan sizes this phase **11–16 d** for one developer. The issue-level roll-up is **29
points**, and the honest band is **15–21 d**. **Both endpoints are counted, not asserted** — the house
rule is that ranges are derived from counted items (project-plan §5):

- **Floor 15 d** = 29 points × the scale's optimistic 0.5 d/point.
- **Ceiling 21 d** = the sum of the twelve per-issue `Scope:` lines (2 + 2 + 0.5 + 2 + 1.5 + 2 + 2 + 2
  + 2 + 1 + 1 + 0.5 = **18.5 d**) plus the plan's own "~10–15 % for review turnaround" (§5) ≈ 21 d.
- The same arithmetic on the **critical path** (22 pts / 14 d of scope, §4.2) gives the two-developer
  band **11–16 d**.

The entire delta against the plan's 11–16 d is attributable to two issues the plan's sizing did not
price, both created by **VD-4.1/VD-4.2**:

- **ARCH-4d** (3 pts) — freezing the current TOML wire surface as a corpus *before* anything moves.
  The plan assumes the round-trip parity test is an acceptance criterion of the collapse; it must be
  a **prior artefact**, because it is the only thing that can detect a silently relocated knob.
- **ARCH-4h** (3 pts) — creating **five** TOML sections that do not exist today (`beacon`, `server`,
  `network`, `safety`, `slashing`) for the 28 bare top-level knobs, each with an alias preserving the
  current flat spelling.

ADR-008's sizing note ("mostly a renaming exercise") is **correct for 4 of the 13 clap groups** and
**wrong for the other 9**. That is the whole of the movement; nothing else in this phase is buffered.

### 1.2 Internal ordering — binding, not advisory

Two orderings are load-bearing and are marked *binding* the way the project plan marks 3A→3B and
5B→5C:

1. **`ARCH-4a`/`4b`/`4c` (G-3) land before `ARCH-4f`** — ADR-010's *Consequences*, project-plan §1.1
   ("G-3 before ADR-008"). Otherwise the migration can introduce an env layer and the gate ratifies
   it afterwards.
2. **`ARCH-4d` lands before any section struct moves (`4f`, `4g`, `4h`)** — the parity corpus is the
   RED artefact for **R8** ("a knob is silently dropped"). A parity test written *after* the
   migration tests the migration against itself.

### 1.3 Entry criteria

- [ ] **Phase 1 complete.** Specifically: **G-2 is green in CI** (`config_drift.rs` present, all four
      clauses) and **ADR-009 has landed** — the nine clap fields at `bin/rvc/src/cli.rs:614, :615,
      :616, :617, :622, :641, :652, :658, :682` are `Option<T>` and `CLAP_DEFAULT_CLOBBERS` is empty.
      *(All nine reproduce at HEAD — VD-4.6. If Phase 1 slipped, this phase does **not** absorb the
      fix; it blocks, per project-plan §7 Phase 4 entry.)*
- [ ] **Phase 0's `arch-gates` CI job exists** (`cargo nextest run -p rvc-architecture-tests`), so
      G-3 lands in a fast job rather than inside `coverage` (A-P1 / VD-P7).
- [ ] **Phase 0's orphan deletion has landed.** G-3's hit count must be measured against a tree with
      no `crates/rvc-signer/` and no `crates/rvc/src/main.rs` — both contain live `env::var` reads
      (`crates/rvc-signer/src/main.rs:1122, :1213`; `crates/rvc/src/main.rs:992, :997`) that would
      otherwise inflate the allow-list. See VD-4.5.
- [ ] Working tree green on all project-plan §2 commands, including `cargo nextest run --workspace`
      (**not** `cargo test --workspace`).

### 1.4 Exit criteria — checklist matching the plan's milestone (M4)

- [ ] **M4 = 1 declaration per knob.** `rg 'struct CliOverrides' crates/ bin/` returns **nothing**;
      `impl From<StartArgs> for CliOverrides` and `merge_with_cli` no longer exist.
- [ ] `rg 'figment' crates/ bin/ Cargo.toml Cargo.lock` returns nothing — **source-scoped, per
      VD-4.3**; the unscoped grep is false at HEAD and after, because this planning directory
      discusses figment by name.
- [ ] **G-3 is green and RED-demonstrated** against a scratch unsanctioned `env::var`, naming the
      file and the variable; its four class tables carry a reason string per entry; class 2 is
      annotated shrinking-only.
- [ ] **A TOML `metrics_port = 9090` binds 9090** — inherited from ADR-009 and now a *structural*
      property (section fields are `Option<T>` with no `default_value`), asserted by an executable
      test rather than by inspection.
- [ ] **Round-trip parity over every existing knob** — all 65 knobs, plus the 4 promoted BN timeouts
      (69), in **both** TOML spellings, produce a `Config` equal to the pre-migration `Config`
      (`ARCH-4d`'s corpus, re-run unchanged after `ARCH-4i`).
- [ ] `Config::validate`'s coverage clause (G-2 iii) still green through the migration; G-2 clauses
      (i)/(ii) are **deleted with seam α**, clause (iv)'s list is empty and asserted empty.
- [ ] A `ConfigError` names its provenance layer (`Default` / `File(path)` / `Cli`).
- [ ] Knob count **65 → 69**; G-2's `BYPASS` table shrinks **8 → 4** (VD-4.8 — not to zero).
- [ ] Release note published covering the `--help` change and the TOML section spelling, with the
      flat legacy keys documented as **deprecated but still accepted**.
- [ ] All project-plan §2 green-build commands pass.

---

## 2. Assumptions, Verified Against HEAD

Every open question is resolved to a stated default. `file:line` re-checked at `0ae9a09`.

| ID | Question | Stated default | Evidence at HEAD |
|---|---|---|---|
| **A-4.1** | Where do the shared section structs live? | **A new `rvc-config` crate** (ADR-008 / A-A3). Fallback if extraction slips: add `clap` to `crates/rvc` directly — taken only if `ARCH-4e` exceeds its 2 points. | `bin/rvc/Cargo.toml:12-14` declares a `[[bin]]` and **no `[lib]`**, so nothing outside can `use cli::Cli` (architecture §6, G-2 *Placement is forced*) — the structs cannot simply stay in `bin/rvc`. |
| **A-4.2** | What layer does `rvc-config` get in `CLASSIFICATION`? | **`Domain`**, not `Foundation`/`Base` — it must name domain types. Recorded here so Phase 6's ADR-011 inherits the row rather than discovering it. | `Config` fields reference `validator_store::BlockSelectionMode` (`crates/rvc/src/config/types.rs:250`), `Network` (`:182`), `SlashedAction` (`:206`), `BroadcastTopic` (`:238`), `TracingExporter`, `BnRole` (`:300`). A `Base`-classified crate may depend only on `Base` (VD-P5) — `rvc-config` cannot. |
| **A-4.3** | Do the flat legacy TOML keys survive? | **Yes — retained as `#[serde(alias = …)]`, deprecated in docs, not removed.** Removal is explicitly **out of scope for this phase** and is not scheduled anywhere in this initiative. | `ConfigWire`'s own doc: *"when both spellings set the same logical field, the **flat** key wins (operators with existing files keep working without edits)"* — `crates/rvc/src/config/types.rs:626-627`. The repo has already paid for one compat migration and chose compatibility; reversing that silently is an operator break, not a refactor. |
| **A-4.4** | ADR-008 says "the clap `Args` group struct **is** the config section." What happens where a TOML section already exists with a *different* shape? | **The existing TOML section wins; the clap group is reshaped to match it.** A deliberate refinement of ADR-008, taken because the alternative renames operator-visible TOML tables. Applies to `logfile`↔`LoggingArgs`, `proposer_config`↔`ProposerArgs`, `builder_limits`↔`BuilderArgs`, and `secret_provider`↔`KeysArgs`. | Eight sections exist in `Config` (`:213`, `:216`, `:219`, `:222`, `:225`, `:228`, `:231`, `:200`) against thirteen clap groups (`bin/rvc/src/cli.rs:195-575`); the shapes differ in four cases and are absent in five (VD-4.2). |
| **A-4.5** | `secret_provider` is a `Config` section with **no** clap group — its five knobs sit inside `KeysArgs`. Which side moves? | **Keep `SecretProviderConfig` as its own section struct**; `KeysArgs` gains `#[command(flatten)] secret_provider: SecretProviderArgs`. Nested flattening is a clap-supported shape and preserves both surfaces. | `merge_with_cli:1258-1262` routes five knobs to `self.secret_provider.*`; the same five are declared on `KeysArgs` (`cli.rs:233-281`) and read via `keys.*` at `cli.rs:645-649`. |
| **A-4.6** | G-3's non-vacuity thresholds | **`assert!(files.len() > 100)` and `assert!(call_sites >= 20)`**, mirroring the house idiom exactly rather than inventing numbers. | `crates/architecture-tests/tests/kat_policy.rs:414` (`> 100` files) and `:444` (`> 20` matches) — architecture §6 makes this idiom binding on every new gate. |
| **A-4.7** | G-3's class-3 (ecosystem-standard) precedence direction | **config-else-env: config wins, env only fills a `None`.** The rule text must say so, or a later refactor "harmonises" it into an env-wins layer. | `crates/rvc/src/config/types.rs:438` (`self.endpoint.clone().or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())`) and `:447` (`None => match std::env::var("OTEL_TRACES_SAMPLER_ARG")`). Both are `or_else`/`None =>` shapes — env is the fallback, never the override. |
| **A-4.8** | Does the collapse move the two `OTEL_*` reads? | **Yes — they move into `rvc-config` with `TracingArgs`, keeping the `or_else` shape byte-for-byte in behaviour.** They are the two reads most at risk of being "simplified" into an env layer during the move. | `types.rs:438`, `:447`; C3. |
| **A-4.9** | Is any signing root or container `hash_tree_root` touched? | **No.** The KAT-first policy is **not** triggered by any issue here. One **naming trap** applies and is flagged on `ARCH-4d`/`ARCH-4h`. | `CLAUDE.md` KAT-first policy; the name-pattern scan `.*(tree_hash\|signing_root\|_root)$` in `crates/architecture-tests/tests/kat_policy.rs`. The knob `genesis_validators_root` (`types.rs:188`, `cli.rs` `NetworkArgs`) means a test named `…_genesis_validators_root` would **match the scan** and demand a KAT anchor it cannot have. Round-trip tests must not end in `_root` — the same inverse obligation ADR-003 carries. |
| **A-4.10** | Does this phase delete anything untracked? | **No.** C10 does not apply. Every file this phase deletes (`CliOverrides`, `From<StartArgs>`, `merge_with_cli`) is tracked and recoverable by `git revert`. | Project-plan §3 D1; C10 is scoped to Phase 0's orphan trees. |
| **A-4.11** | Where does G-3 run? | **The `arch-gates` job** created in Phase 0, not `coverage`. | `.github/workflows/ci.yml` has three jobs at HEAD (`check:13`, `secret-scan:59`, `coverage:129`); the only `#[test]` execution is under `cargo llvm-cov` at `:166` (VD-P7). |
| **A-4.12** | Are the four promoted BN timeouts given `Config` defaults matching today's behaviour? | **Yes — the defaults are taken from `bn_manager::OperationTimeouts::default()`, not re-invented**, and a test asserts the promoted `Config` defaults equal that struct field-for-field. | `bin/rvc/src/cli.rs:738` constructs `OperationTimeouts::default()` and overrides only when the flag is `Some`; `:739-762`. |

---

## 3. Verification Deltas Found While Writing This File

Eight deltas. **VD-4.1 and VD-4.2 change scope** (they are the whole of §1.1's estimate movement);
**VD-4.3 corrects a milestone that is unsatisfiable as written**; **VD-4.5 corrects a gate design that
would miss the most security-relevant read in the repository**.

| ID | Claim as written upstream | Status at HEAD | Corrected fact carried forward | Lands in |
|---|---|---|---|---|
| **VD-4.1** | ADR-008 *Context*: a knob exists in **five** hand-maintained shapes — clap groups, `From<StartArgs>`, `CliOverrides`, `merge_with_cli`, `Config`+`Default`+`ConfigWire`. | **Undercounted, and the missing one is undeletable** | There is a **sixth** site the ADR folds into "(5) `Config` + `Default` + `ConfigWire`" and then proposes to delete: the **wire-compat shim**. `ConfigWire` (`crates/rvc/src/config/types.rs:628-711`) carries **31 flat legacy keys** (`:680-710`) that duplicate the 7 nested tables (`:664-677`), reconciled by `From<ConfigWire> for Config` (`:713-…`) with **flat-wins** precedence documented at `:626-627`, plus a hand-written `Deserialize` that special-cases `logfile` as *either* a string path *or* a table (`:888-920`). ADR-008's target shape (`Config { metrics: MetricsArgs, … }` deserialised straight from nested tables) **silently stops accepting all 31 flat keys**. This is not a code seam — it is an operator-file break, strictly worse than R8. **Carried forward as A-4.3 (aliases retained) and as the whole of `ARCH-4d`.** | `ARCH-4d`, `ARCH-4g`, `ARCH-4h` |
| **VD-4.2** | ADR-008 *Consequences*: *"the section boundaries already visible in `merge_with_cli`'s `$dst` paths … are already close to isomorphic with the clap group boundaries. That is the single most important fact for effort estimation."* | **Partially true; now quantified** | Counted arm-by-arm at `types.rs:1211-1291`: **65 arms total — 28 are bare `self.<field>`** (`:1214-1241`, the block the file itself labels `// top-level`) and **37 are dotted** across **8** sections (`keymanager` 8, `tracing` 5, `secret_provider` 5, `grpc_signer` 4, `builder_limits` 2, `proposer_config` 5, `monitoring` 3, `logfile` 5). Against **13** clap groups that gives: **4 clean** (`Tracing`, `Keymanager`, `GrpcSigner`, `Monitoring`), **4 partial** (`Logging`⊃`logfile`, `Proposer`⊃`proposer_config`, `Builder`⊃`builder_limits`, `Keys`⊃`secret_provider`), and **5 with no section at all** (`Beacon`, `Server`, `Network`, `Safety`, `Slashing`). The renaming-exercise claim holds for **4 of 13**; the other 9 need a section created or reshaped, and 5 of those need a **new TOML table** that has never existed. | §1.1, `ARCH-4f/4g/4h` |
| **VD-4.3** | Project-plan §6 milestone M4 and Phase 4 exit criteria: *"`rg 'figment'` returns nothing."* | **False at HEAD; would remain false after a flawless execution** | `figment` appears **46 times across 6 files** — and **every one is a planning or research document**: `plan/architecture-2026-08-12/architecture.md` (7), `project-plan.md` (6), `prd.md` (6), `research/runtime-and-config-patterns.md` (19), `research/00-overview.md` (3), `docs/research/architecture-review-2026-08-11.md` (5). **Zero occurrences in `crates/`, `bin/`, `Cargo.toml` or `Cargo.lock`.** Corrected criterion: `rg 'figment' crates/ bin/ Cargo.toml Cargo.lock` → empty. Note the consequence: this is a **regression guard, not a change** — C3 is honoured *by construction* because the dependency is never taken (ADR-008), and the assertion exists so a later contributor cannot add it. | `ARCH-4c`, §1.4 |
| **VD-4.4** | ADR-010 / architecture §6 G-3: `RVC_LOG_FORMAT` at `crates/telemetry/src/format.rs:53`. | **Line cited is the constant, not the read** | `:53` is `pub const LOG_FORMAT_ENV: &str = "RVC_LOG_FORMAT";`. The **read** is `std::env::var(LOG_FORMAT_ENV)` at **`:89`**; `:196` is a test helper. The distinction matters because it is exactly the two-shape problem the gate must handle: the scanner sees a *constant declaration* at one line and a *non-literal call site* at another, and must join them. Both shapes are in ADR-010's design ("call sites **and** `*_ENV`/`*_ENV_VAR` constants") — this delta pins the line numbers the gate's own fixtures should use. | `ARCH-4a`, `ARCH-4b` |
| **VD-4.5** | ADR-010 *Decision*: the gate *"scans `std::env::var` call sites … and classifies each against a four-class allow-list."* | **The sanctioned class is unreachable by a literal-argument scan** | All five class-1 security opt-outs reach the runtime through **one indirect call site**: `let env_ok = std::env::var(self.env_var).as_deref() == Ok("true");` — `crates/crypto/src/insecure.rs:168`, where `env_var` is a struct field. A scanner reading the argument gets `self.env_var` and can classify **nothing**. The names live elsewhere: constants `REMOTE_SIGNER_INSECURE_ENV_VAR = "RVC_REMOTE_SIGNER_ALLOW_INSECURE"` (`crates/crypto/src/remote_signer/client.rs:31`), `INSECURE_ENV_VAR = "RVC_SIGNER_ALLOW_INSECURE"` (`crates/signer-server/src/insecure_startup.rs:20`), `METRICS_ALLOW_NON_LOOPBACK_ENV = "RVC_METRICS_ALLOW_NON_LOOPBACK"` (`crates/rvc/src/bootstrap/tasks.rs:19`); and as inline literals `"RVC_ALLOW_INSECURE"` (`crates/rvc/src/config/types.rs:1115`, `crates/signer-server/src/slashing/config.rs:48`) and `"RVC_ALLOW_NON_WAL_SLASHING_DB"` (`crates/slashing/src/db/open.rs:225`). **Corrected rule: a call site whose argument is not a string literal FAILS unless it appears on an explicit `DYNAMIC_READS` table naming the constants that flow into it.** Silently skipping it is the failure mode that makes the gate worthless. | `ARCH-4b` |
| **VD-4.6** | ADR-009: nine `CliOverrides` fields populated with an unconditional `Some(...)`. | **Reproduces exactly — confirming, not correcting** | `bin/rvc/src/cli.rs:614` `metrics_address`, `:615` `metrics_port`, `:616` `grpc_port`, `:617` `grpc_address`, `:622` `log_level`, `:641` `tracing_exporter`, `:652` `keymanager_body_limit`, `:658` `slashed_validators_action`, `:682` `beacon_max_body_bytes`. Nine, no more, no fewer. Recorded because Phase 4's entry criterion is that they are **already fixed**; if they are still `Some(...)` when this phase starts, Phase 1 has not landed and this phase blocks rather than absorbing the fix. | §1.3 entry |
| **VD-4.7** | ADR-008's counted items: 13 groups / 74 fields; `CliOverrides` 65 fields; `From<StartArgs>` 99 lines. | **All three reproduce** | 13 group structs between `bin/rvc/src/cli.rs:195` (`BeaconArgs`) and `:575` (end of `SlashingArgs`), with `StartArgs` itself the 14th container at `:148-191`. `CliOverrides` fields counted line-by-line at `types.rs:1314-1382` = **65 exactly**. `impl From<StartArgs> for CliOverrides` spans `:587-685` = **99 lines**. The `74 − 8 − 1 = 65` arithmetic is therefore sound. | all Stream-A issues |
| **VD-4.8** | ADR-008 *Consequences* / G-2: promoting the four BN timeouts *"shrink[s] the gate's `BYPASS` table accordingly"* (8 entries). | **Shrinks 8 → 4, not to 0** | The 8 are: four BN timeouts consumed at `cli.rs:739-762` (`block_production_timeout`, `attestation_timeout`, `aggregate_timeout`, `duty_fetch_timeout`) **plus four run/logging args read directly at `:773-776`** (`log_format`, `enable_log_reload`, `strict_permissions`, `strict_slashing_semantics`). Only the first four gain `Config` fields. Note also that `log_level` at `:772` is **not** a bypass — it is read directly *and* also flows through `CliOverrides` (`:622`); and `config` is destructured `config: _` at `:590`, so it never enters the count. | `ARCH-4j`, `ARCH-4k` |

---

## 4. Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream |
|---|---|---|---|---|---|
| **ARCH-4a** | G-3 scanner core: `env::var` call sites + `*_ENV` constants, `#[cfg(test)]` partition, non-vacuity | 3 | chore (gate) | — | **B** |
| **ARCH-4b** | G-3 four-class allow-list + `DYNAMIC_READS` table + RED synthetic matcher tests | 3 | chore (gate) | 4a | **B** |
| **ARCH-4c** | Wire G-3 into `arch-gates`; source-scoped figment-absence assertion | 1 | chore (CI) | 4b | **B** |
| **ARCH-4d** | **Freeze the TOML wire surface: corpus + round-trip parity harness** *(binding: before 4f/4g/4h)* | 3 | test | — | **A** |
| **ARCH-4e** | `rvc-config` crate scaffold: `ConfigSource`, `ConfigError` provenance, `Config::load` signature | 2 | feature | — | **A** |
| **ARCH-4f** | Migrate the **4 clean** sections (tracing, keymanager, grpc_signer, monitoring) | 3 | feature | 4c, 4d, 4e | **A** |
| **ARCH-4g** | Migrate the **4 partial** sections (logfile, proposer_config, builder_limits, secret_provider) with field aliases | 3 | feature | 4f | **A** |
| **ARCH-4h** | Create the **5 missing** sections (beacon, server, network, safety, slashing) for the 28 bare knobs | 3 | feature | 4g | **A** |
| **ARCH-4i** | Delete `CliOverrides` + `From<StartArgs>` + `merge_with_cli`; `Config::load(file, cli)` | 3 | chore | 4f, 4g, 4h | **A** |
| **ARCH-4j** | Promote the 4 BN timeout knobs to `Config` (65 → 69) | 2 | feature | 4i | **A** |
| **ARCH-4k** | Retire G-2 clauses (i)/(ii) with seam α; assert (iv) empty, keep (iii) | 2 | chore (gate) | 4i, 4j | **B** |
| **ARCH-4l** | Operator release note: `--help` change, TOML section spelling, flat keys deprecated | 1 | docs | 4i, 4j | **B** |
| | **Total** | **29** | | | |

### 4.1 Stream model & file ownership

| Path | Owner | Note |
|---|---|---|
| `crates/architecture-tests/tests/env_allowlist.rs` *(new)* | **B** | G-3; new file, no conflict |
| `crates/architecture-tests/tests/config_drift.rs` | **B** | inherited from Phase 1; `ARCH-4k` edits it |
| `.github/workflows/ci.yml` | **B** | one-line addition to the Phase-0 `arch-gates` job |
| `crates/rvc-config/**` *(new crate)* | **A** | the phase's main new surface |
| `bin/rvc/src/cli.rs` | **A** | the 13 group structs move out; `From<StartArgs>` deleted |
| `crates/rvc/src/config/types.rs` | **A** | `CliOverrides`, `merge_with_cli`, `ConfigWire` |
| `crates/rvc/tests/config_wire_parity.rs` + `crates/rvc/tests/fixtures/config/` | **A** | the parity corpus; **Stream B never writes here** — `ARCH-4l` hands its examples to `ARCH-4j` |
| **`Cargo.toml` (root `[workspace] members`)** | **A** | ⚠️ **hotspot** — see below |
| **`crates/architecture-tests/src/lib.rs` (`CLASSIFICATION`)** | **A** | ⚠️ **hotspot** — see below |

**Merge-conflict hotspots.** Two files are touched by this phase *and* by Phases 0 and 6, all of
which edit the workspace member list and the layer table:

| File | Also touched by | Strategy | Merge order |
|---|---|---|---|
| root `Cargo.toml` `[workspace] members` | Phase 0 (removes 3 entries: 2 orphans + `sync-service`) | Phase 4 **adds one row** (`crates/rvc-config`); Phase 0's removals land first and are a strict prerequisite (§1.3). Member count moves **28 → 29**. | Phase 0 → `ARCH-4e` |
| `crates/architecture-tests/src/lib.rs` `CLASSIFICATION` | Phase 0 (28 rows), Phase 6 (ADR-011 relabels all rows) | `ARCH-4e` **appends one `Domain` row** for `rvc-config` (A-4.2) and touches no other row; Phase 6 rebases onto 29 rows. Whichever lands second re-runs the byte-match on generated `ARCHITECTURE.md` (C9 anchor 1). | `ARCH-4e` → Phase 6 |

**Why this phase parallelises poorly, stated rather than hidden.** Stream B is 9 of 29 points and its
first three issues (7 pts) gate Stream A's `ARCH-4f`. Stream A's remaining 18 points are a strict
chain (`4f → 4g → 4h → 4i → 4j`) because each step changes the same two files. The second developer
buys ≈ 1.3×, not the ≈ 1.6× the plan achieves elsewhere; the honest use of a second developer here is
to take Stream B and then move to Phase 5 or 6.

### 4.2 Execution plan

Both tables allocate each issue **exactly its stated `Scope:`** — they sum to 18.5 d and 14 d
respectively, and no slot is over-packed. Half-day issues (`ARCH-4c`, `ARCH-4l`) share a day with a
neighbour, marked am/pm. Review turnaround is **not** in these tables; it is the §1.1 ceiling.

**Single stream (one developer) — 18.5 d of scope, finishing day 19:**

| Day | Issue | Scope | Cum. |
|---|---|---|---|
| 1–2 | `ARCH-4a` G-3 scanner core | 2.0 | 2.0 |
| 3–4 | `ARCH-4b` classes + `DYNAMIC_READS` | 2.0 | 4.0 |
| 5 (am) | `ARCH-4c` CI wiring | 0.5 | 4.5 |
| 5 (pm)–7 (am) | `ARCH-4d` wire-surface freeze *(binding gate on everything below)* | 2.0 | 6.5 |
| 7 (pm)–8 | `ARCH-4e` `rvc-config` scaffold | 1.5 | 8.0 |
| 9–10 | `ARCH-4f` 4 clean sections | 2.0 | 10.0 |
| 11–12 | `ARCH-4g` 4 partial sections | 2.0 | 12.0 |
| 13–14 | `ARCH-4h` missing sections | 2.0 | 14.0 |
| 15–16 | `ARCH-4i` the deletion — **M4** | 2.0 | 16.0 |
| 17 | `ARCH-4j` BN timeouts | 1.0 | 17.0 |
| 18 | `ARCH-4k` G-2 retirement | 1.0 | 18.0 |
| 19 (am) | `ARCH-4l` release note | 0.5 | 18.5 |

**Two streams — critical path 14 d:**

| Day | Stream A | Stream B |
|---|---|---|
| 1–2 | `ARCH-4d` (freeze) | `ARCH-4a` |
| 3–4 (am) | `ARCH-4e` (scaffold) | `ARCH-4b` |
| 4 (pm) | *(reviews 4a/4b)* | `ARCH-4c` — **sync point: G-3 green before `4f`** |
| 5–6 | `ARCH-4f` | *(reviews 4d corpus; drafts `ARCH-4l`)* |
| 7–8 | `ARCH-4g` | *(idle — see the note below)* |
| 9–10 | `ARCH-4h` | |
| 11–12 | `ARCH-4i` — **M4** | |
| 13 | `ARCH-4j` | |
| 14 | *(reviews 4k)* | `ARCH-4k` + `ARCH-4l` (am/pm) — **sync point: parity corpus re-run unchanged** |

Stream B is idle from day 7 to day 13. That is not a scheduling error to be hidden by padding — it is
the §4.1 finding restated on a calendar: **this phase does not have 2 developers' worth of parallel
work.** The second developer should take Phase 5 or 6 after day 6 and return for `ARCH-4k`/`4l`.

---

## 5. Issues

### ARCH-4a — G-3 scanner core: `env::var` call sites, `*_ENV` constants, `#[cfg(test)]` partition

- **Points:** 3 · **Type:** chore (gate) · **Priority:** P0 · **Scope:** 2 days
- **Blocked by:** — · **Blocks:** `ARCH-4b` · **Stream:** B
- **Requirements:** ARCH-P1-3 · **ADR:** ADR-010 · **Gate:** G-3 · **Constraints:** **C3**, **C9 (anchor 4)**

**Context.** "env = security opt-outs only" is a real discipline — it is even given a validator,
`Config::validate_insecure_env_var` at `crates/rvc/src/config/types.rs:1114` — and it is **enforced by
nothing**. C3 names the mechanism as an "`RVC_*` allow-list scan". ADR-010 rejects that on
measurement (438 `RVC_` hits across 57 files, ~95 % Prometheus metric-name constants; misses
`RUST_LOG` and both `OTEL_*`; red day one on `RVC_LOG_FORMAT`) and replaces it with a **call-site +
constant** scan. This issue builds the extraction half only; classification is `ARCH-4b`.

**Files.**

- `crates/architecture-tests/tests/env_allowlist.rs` *(new — one gate per file, A-14)*

**Approach.**

1. Walk the workspace exactly as `kat_policy.rs` does — hand-rolled, **no new dependency** (house
   idiom (a), `kat_policy.rs:23` "Phase-1 rule P6").
2. Extract two shapes into one `EnvRead { file, line, shape }` record:
   - **literal call site** — `std::env::var("LITERAL")` / `env::var("LITERAL")`;
   - **non-literal call site** — `env::var(<anything else>)`, recorded as
     `Shape::Dynamic { expr }`. It must be *captured*, never skipped (VD-4.5).
   - **constant declaration** — `const <NAME>_ENV: &str = "…"` / `<NAME>_ENV_VAR`, so the name behind
     a dynamic read is discoverable.
   Also scan `env::set_var` / `remove_var` **only** to exclude them from the read set — they appear
   ~20 times in test scaffolding and are not reads.
3. **Partition on `#[cfg(test)]`** using the same line-number comparison G-4 uses: a hit whose line
   number is greater than the file's first `#[cfg(test)]` line is a test read. Without this the gate
   is red on day one for the wrong reason — verified test-side reads at
   `crates/signer-server/src/server/slashing.rs:167, :217, :246, :293`,
   `crates/signer-server/src/server/mod.rs:339, :369, :370, :410, :411`,
   `crates/telemetry/src/init.rs:278, :492`, `crates/rvc/src/bootstrap/tasks.rs:169`,
   `crates/crypto/src/insecure.rs:263-326` (synthetic `UTEST_*` vars).
4. **Non-vacuity** per A-4.6: `assert!(files.len() > 100, …)` and `assert!(production_reads >= 8, …)`
   with a message that says the workspace walk likely broke. A scanner that silently stops matching
   must **fail**, not pass.
5. Every failure message names **file, line and variable** (NFR-5 / R10) — a gate that says only
   "violation found" gets disabled.

**TDD test plan.**

- **RED first:** `dynamic_env_read_is_captured_not_skipped` — feed the scanner a synthetic source
  string containing `let ok = std::env::var(self.env_var).as_deref() == Ok("true");` and assert the
  extractor yields exactly one record with `Shape::Dynamic`. Against a naive literal-only regex this
  returns **zero records** and the test fails. This is the RED demonstration, and it is a
  matcher-unit-test on synthetic input — house idiom (d), `kat_policy.rs:482-563` — which is how a
  gate demonstrates RED in the same PR without merging a knowingly-failing test.
- `cfg_test_region_reads_are_partitioned_out` — synthetic file with one read above and one below a
  `#[cfg(test)]` line; assert 1 production read, 1 test read.
- `env_constant_declaration_is_extracted` — asserts `pub const LOG_FORMAT_ENV: &str = "RVC_LOG_FORMAT";`
  yields a constant record binding `LOG_FORMAT_ENV → "RVC_LOG_FORMAT"` (the real one, VD-4.4,
  `crates/telemetry/src/format.rs:53`).
- `set_var_is_not_a_read` — `env::set_var`/`remove_var` produce no `EnvRead`.
- `scanner_is_non_vacuous_over_the_real_workspace` — the two `assert!` thresholds.

**Acceptance criteria.**

- [x] `crates/architecture-tests/tests/env_allowlist.rs` exists and compiles with **no new dependency**.
- [x] The extractor returns all three shapes; a dynamic call site is a record, never a skip.
- [x] `#[cfg(test)]` regions are partitioned out by line number, matching G-4's idiom.
- [x] Both non-vacuity assertions present with explanatory messages.
- [x] Every emitted diagnostic names file, line and variable (or, for a dynamic read, the expression).
- [x] The five matcher unit tests above pass; `dynamic_env_read_is_captured_not_skipped` was
      demonstrated RED against a literal-only matcher and the output is pasted into the PR.
- [x] Module doc states the mechanism and **why the `RVC_` prefix scan was rejected**, citing the 438/57
      measurement — so no one "simplifies" it back.

---

### ARCH-4b — G-3 four-class allow-list, `DYNAMIC_READS` table, and the RED demonstration

- **Points:** 3 · **Type:** chore (gate) · **Priority:** P0 · **Scope:** 2 days
- **Blocked by:** `ARCH-4a` · **Blocks:** `ARCH-4c`, `ARCH-4f` · **Stream:** B
- **Requirements:** ARCH-P1-3 · **ADR:** ADR-010 · **Gate:** G-3 · **Constraints:** **C3**, **C9 (anchor 4)**

**Context.** The classification half. ADR-010's four classes, plus the correction from **VD-4.5**: the
five sanctioned security opt-outs are *unreachable* by a literal scan because they all funnel through
`std::env::var(self.env_var)` at `crates/crypto/src/insecure.rs:168`. If the gate skips what it
cannot classify, the single most security-relevant read in the repository is the one read it never
checks — the gate would be worse than useless, because it would look green.

**Files.**

- `crates/architecture-tests/tests/env_allowlist.rs`

**Approach — the five tables, each entry carrying a required reason string** (mirroring the KAT
`EXEMPTIONS` convention, `kat_policy.rs:32-41`):

| Table | Entries at HEAD | Shrinking-only? |
|---|---|---|
| `SECURITY_OPT_OUT` (class 1) | `RVC_REMOTE_SIGNER_ALLOW_INSECURE`, `RVC_SIGNER_ALLOW_INSECURE`, `RVC_ALLOW_INSECURE`, `RVC_ALLOW_NON_WAL_SLASHING_DB`, `RVC_METRICS_ALLOW_NON_LOOPBACK` | no — this is the *sanctioned* class |
| `GRANDFATHERED` (class 2) | `RVC_LOG_FORMAT` | **yes** — removal only, never addition |
| `ECOSYSTEM_CONFIG_WINS` (class 3) | `RUST_LOG`, `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_TRACES_SAMPLER_ARG` | no, but see the precedence rule below |
| `DYNAMIC_READS` **(new — VD-4.5)** | one entry: `crates/crypto/src/insecure.rs:168`, naming the constants that flow in | **yes** |
| — anything else | **fail**, naming file and variable | — |

1. Class-1 names are reached via constants (`crates/crypto/src/remote_signer/client.rs:31`,
   `crates/signer-server/src/insecure_startup.rs:20`, `crates/rvc/src/bootstrap/tasks.rs:19`) and
   inline literals (`crates/rvc/src/config/types.rs:1115`,
   `crates/signer-server/src/slashing/config.rs:48`, `crates/slashing/src/db/open.rs:225`). The gate
   must accept both routes.
2. **`DYNAMIC_READS` is an explicit, shrinking-only allow-list, not a skip.** Each entry names the
   file:line of the dynamic call site **and** the set of constants/literals that reach it, so a new
   dynamic read anywhere else fails. This is the correction that makes the gate honest.
3. **Class 3's precedence rule is written into the table's doc comment, in words** (A-4.7): these are
   **config-else-env** — config wins, env only fills a `None` (`types.rs:438` `or_else`, `:447`
   `None =>`). This is the **opposite** of figment's idiomatic `Env` layer, and the comment exists so
   a later refactor cannot "harmonise" it in the wrong direction. **This sentence is the textual
   discharge of C3.**
4. Class 2 is annotated shrinking-only with the same wording as `kat_policy.rs`'s `EXEMPTIONS`.
5. Note in the module doc that the hit set is measured **post-Phase-0**: the orphan trees carried
   their own reads (`crates/rvc-signer/src/main.rs:1122, :1213`; `crates/rvc/src/main.rs:992, :997`)
   and must not be allow-listed.

**TDD test plan.**

- **RED first:** `unsanctioned_env_read_fails_naming_file_and_variable` — synthetic input
  `std::env::var("RVC_TOTALLY_NEW_KNOB")` in a non-test region; assert the classifier returns a
  failure whose message contains **both** the file path and `RVC_TOTALLY_NEW_KNOB`. Fails before the
  classifier exists. This doubles as the gate's permanent RED demonstration.
- `dynamic_read_not_on_the_table_fails` — a second synthetic `env::var(other.var_name)` at a file:line
  absent from `DYNAMIC_READS` must **fail**, proving the table is an allow-list rather than a blanket
  exemption for the dynamic shape.
- `all_five_security_opt_outs_classify_via_constant_and_literal` — both routes resolve to class 1.
- `real_workspace_is_green` — the full scan over HEAD passes with the tables as seeded.
- `grandfathered_table_is_documented_shrinking_only` — a doc/const-order assertion mirroring
  `kat_policy.rs`.

**Acceptance criteria.**

- [x] Four classes implemented; anything unmatched fails, naming file and variable.
- [x] `DYNAMIC_READS` exists, contains exactly one entry (`crates/crypto/src/insecure.rs:168`) with a
      reason string and the in-flowing constant names; a dynamic read elsewhere fails.
- [x] Class-3 doc comment states **config-else-env** explicitly and cites `types.rs:438`, `:447`.
- [x] Class 2 annotated shrinking-only; contains exactly `RVC_LOG_FORMAT`.
- [x] `cargo nextest run -p rvc-architecture-tests` green on `develop`.
- [x] RED output for `unsanctioned_env_read_fails_naming_file_and_variable` pasted into the PR.
- [x] **C3 discharged in text**: the gate file states that adopting a figment-style `Env` layer would
      violate this gate, and that ADR-008 avoids it by not taking the dependency at all.

---

### ARCH-4c — Wire G-3 into `arch-gates`; source-scoped figment-absence assertion

- **Points:** 1 · **Type:** chore (CI) · **Priority:** P1 · **Scope:** 0.5 days
- **Blocked by:** `ARCH-4b` · **Blocks:** `ARCH-4f` *(sync point: G-3 green before the collapse)* · **Stream:** B
- **Requirements:** ARCH-P1-3 · **Constraints:** **C3**

**Context.** A gate that is not run promptly is a gate that gets reverted. Phase 0 adds the
`arch-gates` job precisely so new gates do not land inside the slow `coverage` job (VD-P7; at HEAD
`.github/workflows/ci.yml` has three jobs — `check:13`, `secret-scan:59`, `coverage:129` — and the
only place a `#[test]` runs is under `cargo llvm-cov` at `:166`). This issue also lands the corrected
figment check from **VD-4.3**.

**Files.**

- `.github/workflows/ci.yml` *(Phase-0 `arch-gates` job — confirm `env_allowlist` is included; the job
  runs `-p rvc-architecture-tests`, so no per-test wiring should be needed. **Verify, don't assume.**)*
- `crates/architecture-tests/tests/env_allowlist.rs` *(the figment assertion lives here, beside the
  env rule it protects)*

**Approach.**

1. Confirm `cargo nextest run -p rvc-architecture-tests` in `arch-gates` picks up the new test file;
   if the job enumerates tests explicitly, add it.
2. Add `figment_dependency_is_absent_from_source` asserting `figment` appears **zero** times under
   `crates/`, `bin/`, root `Cargo.toml` and `Cargo.lock`. **The scan must be source-scoped**: at HEAD
   an unscoped `rg 'figment'` returns **46 hits across 6 files, all of them planning documents** —
   including this directory (`architecture.md` 7, `project-plan.md` 6, `prd.md` 6,
   `research/runtime-and-config-patterns.md` 19, `research/00-overview.md` 3) and
   `docs/research/architecture-review-2026-08-11.md` (5). The milestone as written in the project
   plan is therefore **unsatisfiable**; the corrected form is a **regression guard that is already
   green** (VD-4.3).
3. The assertion's message must say *why*: "ADR-008 rejects figment outright; C3 forbids an env
   layer, and this repo honours it by not taking the dependency."

**TDD test plan.**

- **RED first:** `figment_dependency_is_absent_from_source` — demonstrate RED by adding
  `figment = "0.10"` to a scratch `crates/rvc/Cargo.toml` in a throwaway worktree; the test must fail
  and name the manifest. Paste the output; revert the scratch change.
- `figment_scan_ignores_plan_documents` — a synthetic-input test proving the scoping: a path under
  `plan/` containing the word does **not** trip the gate. Without this, someone "fixes" the scope
  later and the gate goes permanently red on documentation.

**Acceptance criteria.**

- [x] `arch-gates` runs `env_allowlist.rs`; a red gate fails CI in the fast job, not in `coverage`.
- [x] `figment_dependency_is_absent_from_source` green at HEAD, RED-demonstrated against a scratch
      manifest, and scoped to `crates/ bin/ Cargo.toml Cargo.lock`.
- [x] The project plan's M4 wording is annotated in this file's §3 as VD-4.3 (done) — **no edit is
      made to `project-plan.md`** (output confinement).

---

### ARCH-4d — Freeze the TOML wire surface: corpus + round-trip parity harness

- **Points:** 3 · **Type:** test · **Priority:** **P0** · **Scope:** 2 days
- **Blocked by:** — · **Blocks:** `ARCH-4f`, `ARCH-4g`, `ARCH-4h`, `ARCH-4i` **(binding)** · **Stream:** A
- **Requirements:** ARCH-P1-2, **R8** · **ADR:** ADR-008 · **Constraints:** **C9** (no anchor regressed)

**Context — this is the issue VD-4.1 created, and the phase's most important one.** ADR-008 counts
five hand-maintained sites and proposes deleting them. It folds a **sixth** into item (5) and does not
price it: the **wire-compat shim**. `ConfigWire` (`crates/rvc/src/config/types.rs:628-711`) accepts
**31 flat legacy keys** (`:680-710`) *alongside* 7 nested tables (`:664-677`), reconciled by
`From<ConfigWire> for Config` (`:713`) with **flat-wins** precedence, documented in the struct's own
doc comment at `:626-627`: *"when both spellings set the same logical field, the flat key wins
(operators with existing files keep working without edits)"*. On top of that sits a hand-written
`Deserialize` that accepts `logfile` as **either a string path or a table** (`:888-920`).

ADR-008's target shape — `Config { metrics: MetricsArgs, … }` deserialised from nested tables —
**silently stops accepting all 31 flat keys and the flat `logfile` string**. That is not a code seam
regressing; it is every existing operator config file breaking, with no error, by falling back to
defaults. R8 ("a knob is silently dropped") understates it.

The only artefact that can detect this is a parity corpus captured **before** anything moves. Written
afterwards, it tests the migration against itself.

**Files.**

- `crates/rvc/tests/config_wire_parity.rs` *(new)*
- `crates/rvc/tests/fixtures/config/*.toml` *(new — the corpus)*

**Approach.**

1. **Build the corpus** — at minimum five TOML fixtures:
   - `flat_legacy_full.toml` — every one of the 31 flat legacy keys at `:680-710` set to a
     non-default value.
   - `nested_full.toml` — the same knobs via the 7 nested tables at `:664-677`.
   - `collision.toml` — both spellings set to *different* values, pinning **flat-wins** (`:626-627`).
   - `logfile_flat_string.toml` and `logfile_table.toml` — the dual shape at `:898-911`.
   - `top_level_28.toml` — the 28 bare top-level knobs (`merge_with_cli:1214-1241`), which are the
     ones `ARCH-4h` will have to give a section.
2. **Assert on the resulting `Config`, not on the TOML.** Serialise the parsed `Config` to a stable
   debug/serde form and snapshot it. The snapshot is the contract: `ARCH-4f/g/h/i` must leave every
   snapshot byte-identical.
3. **Cover the CLI axis too**, since `ARCH-4i` deletes the merge step: for a representative subset,
   parse a `StartArgs` and assert `defaults < file < CLI`, including the ADR-009 falsifier (a TOML
   `metrics_port = 9090` with no `--metrics-port` yields `9090`).
4. **Coverage assertion.** A test that iterates the 65 `CliOverrides` field names (they are the
   canonical knob list at `types.rs:1314-1382`) and asserts each appears in at least one fixture.
   Without it the corpus silently under-covers and the parity claim is hollow.

**TDD test plan.**

- **RED first:** `every_knob_appears_in_the_parity_corpus` — assert all 65 knob names are covered by
  the fixture set. It fails immediately (empty corpus) and stays the forcing function while fixtures
  are written. This is the test that makes "round-trip parity over **every** existing knob" (the
  plan's exit criterion) checkable rather than asserted.
- `flat_legacy_keys_still_parse` — 31 keys → expected `Config`.
- `flat_key_wins_over_nested_table` — the `collision.toml` fixture; pins `:626-627`.
- `logfile_accepts_string_or_table` — both fixtures.
- `toml_metrics_port_9090_survives_absent_cli_flag` — the ADR-009 falsifier as a structural test.

> **KAT-first note (A-4.9).** No signing root or container `hash_tree_root` is touched. **But** the
> knob `genesis_validators_root` (`types.rs:188`) is in the corpus, and the KAT name-pattern scan in
> `crates/architecture-tests/tests/kat_policy.rs` matches any test name ending in `_root`. **Test
> names in this issue must not end in `_root`** — use e.g.
> `genesis_validators_root_parses_from_flat_key`, never `…_genesis_validators_root`. The same inverse
> obligation ADR-003 carries in Phase 3.

**Acceptance criteria.**

- [x] Corpus exists with at least the five fixture classes above.
- [x] `every_knob_appears_in_the_parity_corpus` covers all **65** knob names and is green.
- [x] Snapshots of the parsed `Config` are committed and are the contract for `ARCH-4f`…`4i`.
- [x] Flat-wins precedence, the dual `logfile` shape, and `defaults < file < CLI` each have a test.
- [x] No test name ends in `_root`; `kat_policy.rs` stays green with **no new `EXEMPTIONS` entry**
      (the list is shrinking-only).
- [x] The PR description states, in one sentence, that this harness is the **binding prerequisite**
      for every later Stream-A issue in this phase.

---

### ARCH-4e — `rvc-config` crate scaffold: `ConfigSource`, `ConfigError` provenance, `Config::load`

- **Points:** 2 · **Type:** feature · **Priority:** P1 · **Scope:** 1–1.5 days
- **Blocked by:** — · **Blocks:** `ARCH-4f` · **Stream:** A
- **Requirements:** ARCH-P1-2 · **ADR:** ADR-008 (interface §5.4) · **Constraints:** **C3**, **C9 (anchor 1)**

**Context.** The section structs must be visible to **both** `bin/rvc` (which `#[command(flatten)]`s
them) and `crates/rvc` (which holds `Config`). They cannot stay in `bin/rvc`: `bin/rvc/Cargo.toml:12-14`
declares a `[[bin]]` and **no `[lib]`**, so nothing outside can `use` them (this is the same forced
placement that dictates G-2's textual scanning, architecture §6). Hence a new crate (A-4.1).

**Files.**

- `crates/rvc-config/Cargo.toml`, `crates/rvc-config/src/lib.rs`,
  `crates/rvc-config/src/error.rs`, `crates/rvc-config/src/sections/mod.rs` *(all new)*
- root `Cargo.toml` — `[workspace] members` **(hotspot; see §4.1)**
- `crates/architecture-tests/src/lib.rs` — one appended `CLASSIFICATION` row **(hotspot)**

**Approach.**

1. New crate `rvc-config`, package name `rvc-config`. **Check the package name against every existing
   manifest before creating it** — this workspace has already been bitten twice by duplicate package
   names (VD-P1: both orphan trees collide, `rvc-signer-bin` and `rvc-keygen`). Cheap to check, a hard
   error to discover late.
2. `ConfigSource { Default, File(PathBuf), Cli }` and
   `ConfigError::Invalid { field, message, source_layer }` with `thiserror` (`CLAUDE.md`: `thiserror`
   in libraries). This is the **one idea worth taking from figment** — `Metadata`-style provenance —
   at ~40 lines and **no dependency** (architecture §5.4:1310-1324). C3 is honoured by construction.
3. Declare the signature `pub fn load(file: Option<&Path>, cli: StartArgs) -> Result<Config, ConfigError>`
   and leave it delegating to the existing path for now. **No behaviour changes in this issue** — it
   is a scaffold, and keeping it inert is what makes it independently revertible (NFR-4).
4. Append **one** `CLASSIFICATION` row: `rvc-config` → **`Domain`** (A-4.2), with a reason string
   naming `validator_store::BlockSelectionMode` (`types.rs:250`) as the dependency that forbids a
   `Base` classification under G-5a's corrected reading (VD-P5). Touch no other row — Phase 6 owns the
   relabelling.
5. Regenerate `ARCHITECTURE.md` and confirm the byte-match gate is green with the new member
   (C9 anchor 1). Member count moves **28 → 29**; if Phase 0's exact-equality assertion in G-1's D1
   detector is written as `members == dirs`, it stays true (one member, one directory) — **verify
   this rather than assume it**, since D1 was specified as a hard equality (VD-P8).

**TDD test plan.**

- **RED first:** `config_error_names_its_provenance_layer` — construct a `ConfigError::Invalid` for a
  value that came from a file and assert the rendered `Display` contains both the field name and the
  file path. Fails before `ConfigSource`/`ConfigError` exist. This is the phase exit criterion "a
  `ConfigError` names the provenance layer" made executable on day one rather than at the end.
- `architecture_md_regenerates_byte_identically` — the existing harness test, re-run with 29 members.
- `rvc_config_package_name_is_unique_in_the_workspace` — a one-line guard against the VD-P1 class of
  error.

**Acceptance criteria.**

- [x] `crates/rvc-config` exists, builds, and is a workspace member; **29 members**, one new
      `CLASSIFICATION` row (`Domain`, with reason).
- [x] `ConfigSource` and `ConfigError` implemented with `thiserror`. The crate's dependency set is
      **exactly `clap`, `serde`, `toml`, `thiserror`** — all already workspace dependencies. **No
      config-framework dependency is added, and specifically not figment**: provenance is the ~40
      lines of `ConfigError` context, which is the one idea worth taking from it (architecture
      §5.4:1310-1324). Any addition beyond those four is a C3 discussion, not a detail.
- [x] `Config::load` signature exists per architecture §5.4; behaviour unchanged (scaffold).
- [x] `ARCHITECTURE.md` regenerates byte-identically; DAG / forbidden-edge / required-edge gates green.
- [x] `ARCH-4d`'s parity snapshots unchanged (this issue must not move a single value).
- [x] Public items carry `///` docs (`CLAUDE.md`).

---

### ARCH-4f — Migrate the 4 clean sections: tracing, keymanager, grpc_signer, monitoring

- **Points:** 3 · **Type:** feature · **Priority:** P1 · **Scope:** 2 days
- **Blocked by:** `ARCH-4c` *(G-3 must be green first — binding)*, `ARCH-4d`, `ARCH-4e` · **Blocks:** `ARCH-4g` · **Stream:** A
- **Requirements:** ARCH-P1-2 · **ADR:** ADR-008 · **Constraints:** **C3**

**Context.** These four are the cases where ADR-008's "mostly a renaming exercise" is **true** — the
clap group, the `Config` section and the TOML table already agree (VD-4.2). Doing them first proves
the mechanism on the cheap cases before `ARCH-4g`/`4h` apply it where aliases and new tables are
needed. The ordering is chosen by **compat difficulty, not count**.

| Clap group (`cli.rs`) | `Config` section | `merge_with_cli` arms | Alias work |
|---|---|---|---|
| `TracingArgs` `:371-391` | `tracing` `types.rs:216` | `:1252-1256` (5) | none |
| `KeymanagerArgs` `:395-431` | `keymanager` `:219` | `:1243-1250` (8) | none |
| `GrpcSignerArgs` `:435-451` | `grpc_signer` `:222` | `:1264-1267` (4) | none |
| `MonitoringArgs` `:539-551` | `monitoring` `:228` | `:1282-1284` (3) | none |

That is **20 of the 65 knobs**.

**Files.**

- `crates/rvc-config/src/sections/{tracing.rs, keymanager.rs, grpc_signer.rs, monitoring.rs}` *(new)*
- `bin/rvc/src/cli.rs` — the four group structs move out; `StartArgs` re-imports them
- `crates/rvc/src/config/types.rs` — the four section types re-exported from `rvc-config`

**Approach.**

1. Each section struct gains `#[derive(clap::Args, serde::Deserialize, serde::Serialize)]` with
   `#[serde(default, deny_unknown_fields)]`, exactly as architecture §5.4:1279-1292.
2. **Fields become `Option<T>` with no `default_value`**; defaults move to a `Default` impl / a
   `resolved()` method applied **after** TOML and CLI are folded. This is the mechanism that makes
   ADR-009 true by construction — "operator supplied it" and "clap invented it" stay distinguishable.
   Two of the nine ADR-009 fields live here (`tracing_exporter` `cli.rs:641`,
   `keymanager_body_limit` `:652`) and must **not** regain a `default_value`.
3. Field **names** change from the flat CLI spelling to the section-relative spelling
   (`tracing_endpoint` → `tracing.endpoint`) — this already matches the `$dst` paths at `:1252-1256`,
   which is why these four are cheap. The **flat legacy TOML keys** for these sections
   (`tracing_endpoint`, `keymanager_address`, …, at `ConfigWire:688-701`) get
   `#[serde(alias = "tracing_endpoint")]` so existing files keep parsing (A-4.3).
4. `#[arg(long = "…")]` strings are preserved **verbatim** — the CLI flag surface must not change.
5. Keep the two `OTEL_*` `or_else` reads intact when `TracingConfig` moves (A-4.8, `types.rs:438`,
   `:447`). **Do not "simplify" them into a layered env lookup** — that is precisely the C3 violation
   G-3 now catches, and it would be caught, which is the point of the ordering.

**TDD test plan.**

- **RED first:** `tracing_section_flat_alias_still_parses` — a TOML with the flat key
  `tracing_endpoint = "http://x"` (no `[tracing]` table) must produce the same `Config` as the nested
  spelling. Written against the moved struct *before* the alias is added, it fails with an unknown-key
  or default-value error, then goes green once `#[serde(alias)]` is in place.
- `ARCH-4d`'s **entire** snapshot suite re-run unchanged — this is the regression contract, not a new
  test.
- `otel_env_fallback_is_still_config_else_env` — with `Config.tracing.endpoint = Some(..)` set **and**
  `OTEL_EXPORTER_OTLP_ENDPOINT` set to something else, config wins. Pins A-4.7 through the move.
- `clap_long_flags_unchanged_for_migrated_sections` — assert the 20 `--flag` strings are byte-identical
  to the pre-move set.

**Acceptance criteria.**

- [x] The four group structs live in `rvc-config`; `bin/rvc` `#[command(flatten)]`s them.
- [x] All 20 fields are `Option<T>` with **no** `default_value`; defaults live in one place.
- [x] Flat legacy TOML keys for these sections parse via `#[serde(alias)]`.
- [x] Every `--flag` string is unchanged; `--help` differs only in where defaults are documented.
- [x] `ARCH-4d`'s snapshots byte-identical.
- [x] **G-3 green** through the change (the OTEL reads moved crates — the gate must still classify
      them, which is a real re-check, not a formality).
- [x] `merge_with_cli` still compiles (it is deleted in `ARCH-4i`, not here) — this issue is
      independently revertible.

---

### ARCH-4g — Migrate the 4 partial sections: logfile, proposer_config, builder_limits, secret_provider

- **Points:** 3 · **Type:** feature · **Priority:** P1 · **Scope:** 2 days
- **Blocked by:** `ARCH-4f` · **Blocks:** `ARCH-4h` · **Stream:** A
- **Requirements:** ARCH-P1-2 · **ADR:** ADR-008 · **Constraints:** **C3**

**Context.** Four cases where a `Config` section **already exists but does not match the clap group**
(VD-4.2). ADR-008 says "the clap group **is** the section"; taken literally here it would rename
operator-visible TOML tables. **A-4.4 resolves this: the existing TOML section wins and the clap group
is reshaped to match it.** Recording that decision is the point of this issue — it is a deliberate
refinement of ADR-008, not a drift from it.

| Clap group | Existing `Config` section | Mismatch | Resolution |
|---|---|---|---|
| `LoggingArgs` `cli.rs:325-367` | `logfile` `types.rs:213` (5 arms, `:1286-1290`) | `LoggingArgs` also owns `log_level` (bare, `:1229`) and `log_format`/`enable_log_reload` (G-2 `BYPASS`, read at `cli.rs:773-774`) | `[logfile]` keeps its name and shape; `log_level` moves to the new `[logging]`-adjacent handling in `ARCH-4h`; the two bypass args stay CLI-only |
| `ProposerArgs` `:507-535` | `proposer_config` `:225` (5 arms, `:1276-1280`) | `proposer_nodes` and `broadcast` are bare top-level (`:1235-1236`) | `[proposer_config]` unchanged; the two bare knobs keep their top-level TOML spelling via alias |
| `BuilderArgs` `:483-503` | `builder_limits` `:231` (2 arms, `:1269-1274`) | `block_selection_mode`, `validator_registration_batch_size`, `validator_registration_batch_delay` are bare (`:1237-1239`) | `[builder_limits]` unchanged; three bare knobs aliased |
| `KeysArgs` `:233-281` | `secret_provider` `:200` (5 arms, `:1258-1262`) — **a section with no clap group at all** | five knobs are declared on `KeysArgs` and read as `keys.*` (`cli.rs:645-649`) | **A-4.5:** `SecretProviderArgs` becomes its own struct; `KeysArgs` gains `#[command(flatten)] secret_provider: SecretProviderArgs` |

That is **23 of the 65 knobs** (17 dotted + 6 bare that belong to these groups).

**Files.**

- `crates/rvc-config/src/sections/{logfile.rs, proposer_config.rs, builder_limits.rs, secret_provider.rs, keys.rs}` *(new — `keys.rs` is created **here**, because `KeysArgs` must exist to flatten `SecretProviderArgs`; `ARCH-4h` extends it with five more knobs)*
- `bin/rvc/src/cli.rs` · `crates/rvc/src/config/types.rs`

**Approach.**

1. Same mechanics as `ARCH-4f` (`Option<T>`, no `default_value`, `#[serde(default, deny_unknown_fields)]`).
2. **Nested `#[command(flatten)]` for `KeysArgs → SecretProviderArgs`** — verify clap accepts the
   nesting on the *first* commit of this issue; if it does not, the stated fallback is to keep
   `SecretProviderArgs` as a sibling group and map it in `Config::load`. Take the decision explicitly
   rather than discovering it at compile time.
3. Every bare knob belonging to these groups (`proposer_nodes`, `broadcast`, `block_selection_mode`,
   `validator_registration_batch_size`, `validator_registration_batch_delay`, `log_level`) keeps its
   **top-level** TOML spelling via `#[serde(alias)]` even if it moves into a section struct in Rust.
   The Rust shape may change; **the TOML shape may not**.
4. `logfile`'s string-or-table `Deserialize` (`types.rs:888-920`) must survive verbatim. It is the
   most fragile single piece of the wire surface and has no test outside `ARCH-4d`'s corpus.

**TDD test plan.**

- **RED first:** `secret_provider_knobs_reachable_from_both_cli_and_nested_table` — assert
  `--gcp-project-id X` and `[secret_provider.gcp] project_id = "X"` produce the same `Config`. Fails
  before the flatten is wired.
- `logfile_string_or_table_survives_the_move` — re-runs `ARCH-4d`'s two logfile fixtures against the
  new struct.
- `bare_knobs_of_partial_groups_keep_top_level_toml_spelling` — `proposer_nodes`, `broadcast`,
  `block_selection_mode`, `validator_registration_batch_size`, `validator_registration_batch_delay`,
  `log_level` all parse from top level.
- `ARCH-4d` snapshot suite re-run unchanged.

**Acceptance criteria.**

- [x] Four sections migrated; **A-4.4's decision (existing TOML section wins) is recorded in the
      module doc of each**, so the next reader does not "correct" it back to ADR-008's literal wording.
- [x] `KeysArgs` flattens `SecretProviderArgs`, or the fallback is taken and documented.
- [x] All 23 knobs reachable from both CLI and TOML; flat/top-level spellings preserved by alias.
- [x] `logfile` still accepts a string **or** a table.
- [x] `ARCH-4d` snapshots byte-identical; G-2 and G-3 green.

---

### ARCH-4h — Create the 5 missing sections for the bare top-level knobs (and finish `[keys]`)

- **Points:** 3 · **Type:** feature · **Priority:** P1 · **Scope:** 2 days
- **Blocked by:** `ARCH-4g` · **Blocks:** `ARCH-4i` · **Stream:** A
- **Requirements:** ARCH-P1-2 · **ADR:** ADR-008 · **Constraints:** **C3**

**Context — the other half of VD-4.2, and the second driver of §1.1's estimate movement.** Five clap
groups have **no corresponding section anywhere** — not in `Config`, not in the TOML: `BeaconArgs`
(`cli.rs:195-229`), `ServerArgs` (`:285-301`), `NetworkArgs` (`:305-321`), `SafetyArgs` (`:455-479`),
`SlashingArgs` (`:555-575`). Their knobs are bare top-level fields on `Config` (`types.rs:143-209`)
and bare arms in `merge_with_cli` (`:1214-1241`, the block the source itself labels `// top-level`).

Adopting "the clap group is the section" means **inventing five TOML tables that have never
existed** — `[beacon]`, `[server]`, `[network]`, `[safety]`, `[slashing]` — and relocating 22 keys
into them. Every existing operator file writes those keys at top level.

**The knob arithmetic closes exactly**, which is how this issue's scope is bounded rather than
asserted: `ARCH-4f` 20 + `ARCH-4g` 23 + `ARCH-4h` 22 = **65** = `CliOverrides`' field count.

**Section count, stated precisely so the two issues do not both claim `[keys]`.** `KeysArgs` is a
**partial** group under VD-4.2 (it contains the existing `secret_provider` section), so **`ARCH-4g`
creates the `[keys]` struct**; this issue **creates five new sections** (`[beacon]`, `[server]`,
`[network]`, `[safety]`, `[slashing]`) and **adds five remaining bare knobs to the `[keys]` struct
`ARCH-4g` already created**. Five new sections, six rows below.

| Section | Bare knobs it absorbs | `merge_with_cli` |
|---|---|---|
| `[beacon]` *(new)* | `beacon_url`, `beacon_nodes`, `beacon_max_body_bytes` | `:1214`, `:1215`, `:1241` |
| `[keys]` *(created by `ARCH-4g`; extended here)* | `keystore_path`, `password_file`, `key_decrypt_threads`, `disable_keystore_locking`, `validators_config` | `:1216`, `:1217`, `:1231`, `:1234`, `:1240` |
| `[server]` *(new)* | `metrics_address`, `metrics_port`, `grpc_port`, `grpc_address` | `:1221`–`:1224` |
| `[network]` *(new)* | `network`, `genesis_time`, `genesis_validators_root`, `graffiti` | `:1225`–`:1228` |
| `[safety]` *(new)* | `allow_unsupported_fork`, `doppelganger_detection`, `disable_attesting`, `slashed_validators_action` | `:1220`, `:1230`, `:1232`, `:1233` |
| `[slashing]` *(new)* | `slashing_db_path`, `init_slashing_db` → `allow_fresh_db` | `:1218`, `:1219` |

**Files.**

- `crates/rvc-config/src/sections/{beacon.rs, keys.rs, server.rs, network.rs, safety.rs, slashing.rs}` *(new)*
- `bin/rvc/src/cli.rs` · `crates/rvc/src/config/types.rs`

**Approach.**

1. **Every relocated key gets a top-level `#[serde(alias)]`** so the current flat spelling continues
   to parse. This is the non-negotiable part: without it, `ARCH-4d`'s `top_level_28.toml` fixture goes
   red, which is exactly what that fixture exists to catch.
2. Serde's `alias` is field-scoped, not path-scoped, so a top-level key cannot alias into a nested
   table directly. **Stated default:** keep a thin, *much smaller* `ConfigWire` whose only remaining
   job is the flat→section lift for these 22 keys plus the 31 legacy keys of `ARCH-4g`'s sections —
   i.e. **the sixth site shrinks but does not disappear** (VD-4.1). If a `#[serde(flatten)]`-based
   shape removes it entirely, take that; either way the *decision must be explicit in the PR*, because
   "delete `ConfigWire`" is what ADR-008 implies and it is wrong.
3. Four of the nine ADR-009 fields land here (`metrics_address`, `metrics_port`, `grpc_port`,
   `grpc_address` — `cli.rs:614-617`) and one more (`beacon_max_body_bytes`, `:682`); none may regain
   a `default_value`.
4. **Two TOML-only knobs have no CLI flag and no `CliOverrides` entry and must not be lost**:
   `bn_sync_tolerances` (`types.rs:242`, `ConfigWire:655`) and `beacon_nodes_config`
   (`types.rs:246`, `ConfigWire:656`). They are invisible to the 65-knob arithmetic precisely because
   that arithmetic is derived from `CliOverrides`. Assign them to `[beacon]` and add corpus coverage.

**TDD test plan.**

- **RED first:** `top_level_flat_keys_still_parse_after_sectioning` — parse
  `ARCH-4d`'s `top_level_28.toml` (flat spelling) and assert the resulting `Config` equals the
  committed snapshot. Run it **immediately after** creating the section structs and **before** adding
  the aliases: it fails, and that failure is the demonstration that the naive ADR-008 reading breaks
  operator files. Paste the RED output into the PR — it is the evidence for VD-4.1.
- `new_section_spelling_also_parses` — the same knobs under `[beacon]`, `[server]`, … .
- `toml_only_knobs_survive` — `bn_sync_tolerances` and `beacon_nodes_config` round-trip.
- `every_one_of_the_65_knobs_has_exactly_one_declaration` — count declarations per knob across
  `rvc-config`; assert 1. This is **M4 made executable**.

> **KAT-first note (A-4.9).** `[network]` owns `genesis_validators_root`. Test names must not end in
> `_root` — `kat_policy.rs`'s scan matches `.*_root$` and would demand a KAT anchor that does not
> exist for a config knob. No `EXEMPTIONS` entry may be added (shrinking-only).

**Acceptance criteria.**

- [x] **Five** new section structs (`[beacon]`, `[server]`, `[network]`, `[safety]`, `[slashing]`)
      plus five knobs added to `ARCH-4g`'s `[keys]`; all 22 bare knobs relocated.
- [x] **Flat top-level spelling still parses for every relocated key**, proven by
      `top_level_flat_keys_still_parse_after_sectioning` against `ARCH-4d`'s snapshot.
- [x] The fate of `ConfigWire` is decided explicitly in the PR (shrunk vs removed) with the reason.
- [x] `bn_sync_tolerances` and `beacon_nodes_config` covered.
- [x] `every_one_of_the_65_knobs_has_exactly_one_declaration` green.
- [x] No test name ends in `_root`; `kat_policy.rs` green with no new exemption.
- [x] `ARCH-4d` snapshots byte-identical; G-2, G-3 green.

---

### ARCH-4i — Delete `CliOverrides`, `From<StartArgs>` and `merge_with_cli`; `Config::load(file, cli)`

- **Points:** 3 · **Type:** chore · **Priority:** **P0** · **Scope:** 2 days
- **Blocked by:** `ARCH-4f`, `ARCH-4g`, `ARCH-4h` · **Blocks:** `ARCH-4j`, `ARCH-4k`, `ARCH-4l` · **Stream:** A
- **Requirements:** ARCH-P1-2, **M4** · **ADR:** ADR-008, ADR-009 · **Constraints:** **C3**

**Context.** The milestone itself. After `4f`/`4g`/`4h` every knob has a section-struct declaration,
so the three duplicating sites are dead weight and can be deleted **rather than generated over**:
`CliOverrides` (65 fields, `crates/rvc/src/config/types.rs:1313-1383`), `impl From<StartArgs> for
CliOverrides` (99 lines, `bin/rvc/src/cli.rs:587-685`), and `merge_with_cli` (65 arms, `types.rs:1210-1292`)
together with the `merge_cli_fields!` macro (`:932-981`) that drives it.

**Files.**

- `crates/rvc/src/config/types.rs` — delete `CliOverrides`, `merge_with_cli`, `merge_cli_fields!`
- `bin/rvc/src/cli.rs` — delete `From<StartArgs> for CliOverrides` and the `flag()` helper (`:579-585`,
  which exists only to feed it); replace `cli_overrides`/`merge_with_cli` at `:778-781` with
  `Config::load(config_path.as_deref(), args)`
- `crates/rvc-config/src/lib.rs` — implement `load`

**Approach.**

1. Implement `Config::load` with **explicit, testable precedence: defaults < file < CLI**
   (architecture §5.4:1311). Each layer records its `ConfigSource` so `ConfigError` can name it.
2. Delete the three sites plus the `flag()` helper. Note `CliOverrides` derives only
   `Debug, Default` (`types.rs:1312`) — nothing else depends on it structurally.
3. **Existing tests that will break, named now so they are not discovered as surprises:**
   `test_start_args_convert_to_equivalent_cli_overrides` (`cli.rs:1018-1216`) tests the deleted
   conversion and should be **replaced** by a `Config::load` precedence test, not deleted silently;
   `test_start_help_lists_every_flag` (`cli.rs:1005-1015`) checks a hand-maintained `START_FLAGS`
   array against `--help` and must be updated for the new group placement. Both are named in ADR-009
   as the tests that *failed to catch* the precedence defect — replacing them with real precedence
   coverage is part of the value here.
4. Update `crates/rvc/src/config/` call sites and any re-exports; `bin/rvc` retains only
   `#[command(flatten)]` fields.

**TDD test plan.**

- **RED first:** `config_load_applies_defaults_then_file_then_cli` — assert all three layers on one
  knob: no file/no flag → default; file only → file value; file + flag → flag value. Written against
  the not-yet-existing `Config::load`, it fails to compile, which is the RED state for a deletion
  issue.
- `toml_metrics_port_9090_binds_9090` — the ADR-009 falsifier, now structural. Also a **runtime**
  check: start with `--config <toml with metrics_port = 9090>` and assert the bound port, mirroring
  the existing `bin/rvc/tests/metrics_bind_l10.rs` harness shape.
- `cli_overrides_type_no_longer_exists` — a compile-fail/grep assertion; the executable form of
  **M4 = 1**.
- `ARCH-4d`'s **entire** snapshot suite, unchanged. If any snapshot moves, a knob was dropped — that is
  R8 firing, and the corpus is the only place it fires.

**Acceptance criteria.**

- [x] `rg 'struct CliOverrides' crates/ bin/` → **nothing**; `From<StartArgs>`, `merge_with_cli` and
      `merge_cli_fields!` deleted.
- [x] `Config::load(file, cli)` implements defaults < file < CLI; errors name the provenance layer.
- [x] A TOML `metrics_port = 9090` binds **9090** at runtime.
- [x] `test_start_args_convert_to_equivalent_cli_overrides` **replaced** by real precedence coverage;
      `test_start_help_lists_every_flag` updated, not weakened.
- [x] `ARCH-4d` snapshots byte-identical — every one of the 65 knobs round-trips.
- [x] G-2 clause (iii) still green; G-3 green; all §2 green-build commands pass.
- [x] **Independently revertible** (NFR-4): this PR's revert restores a working binary without
      requiring `ARCH-4j`…`4l` to be reverted.

---

### ARCH-4j — Promote the four BN timeout knobs to `Config` (65 → 69)

- **Points:** 2 · **Type:** feature · **Priority:** P2 · **Scope:** 1 day
- **Blocked by:** `ARCH-4i` · **Blocks:** `ARCH-4k` · **Stream:** A
- **Requirements:** ARCH-P1-2 · **ADR:** ADR-008 (*Consequences*)

**Context.** Four operator-facing flags have **no config-file representation at all** —
`--block-production-timeout`, `--attestation-timeout`, `--aggregate-timeout`, `--duty-fetch-timeout` —
because they are routed straight into `bn_manager::OperationTimeouts` at `bin/rvc/src/cli.rs:738-763`
and never touch `Config`. They are half of G-2's `BYPASS` table for exactly that reason. Giving them
`Config` fields raises the knob count **65 → 69** and shrinks `BYPASS` **8 → 4** (VD-4.8 — *not* to
zero; the other four are `log_format`, `enable_log_reload`, `strict_permissions`,
`strict_slashing_semantics`, read directly at `cli.rs:773-776` and staying CLI-only).

**Files.**

- `crates/rvc-config/src/sections/beacon.rs` *(the four timeouts belong to `BeaconArgs`, `cli.rs:195-229`)*
- `bin/rvc/src/cli.rs:738-763` — the `if let Some(secs)` ladder becomes a fold from `Config`
- `crates/rvc/src/config/types.rs` — `OperationTimeouts` construction

**Approach.**

1. Add the four to `[beacon]` as `Option<u64>` seconds.
2. **Defaults come from `bn_manager::OperationTimeouts::default()`, not from new literals** (A-4.12) —
   `cli.rs:738` constructs exactly that and overrides only when `Some`. Re-inventing the numbers is
   how a "no behaviour change" refactor changes behaviour.
3. Preserve the four `secs == 0` rejections at `:740`, `:746`, `:752`, `:759`. Move them into
   `Config::validate` so they apply to TOML-supplied values too — today a `0` from a config file is
   impossible only because a config file cannot supply one.
4. Note the one-to-two mapping at `:755-756`: `--aggregate-timeout` sets **both**
   `aggregate_fetch` and `aggregate_submit`. Preserve it.

**TDD test plan.**

- **RED first:** `beacon_timeouts_are_settable_from_toml` — a TOML setting all four; assert the
  resulting `OperationTimeouts`. Fails today because the knobs do not exist in `Config` at all.
- `promoted_timeout_defaults_equal_operation_timeouts_default` — field-for-field equality with
  `OperationTimeouts::default()`.
- `zero_timeout_rejected_from_toml_as_well_as_cli` — four cases.
- `aggregate_timeout_sets_both_fetch_and_submit`.

**Acceptance criteria.**

- [x] Four knobs settable from TOML **and** CLI, CLI winning; knob count **69**.
- [x] Defaults derived from `OperationTimeouts::default()`; no new literal constants.
- [x] `secs == 0` rejected from both sources with the existing message text.
- [x] `--aggregate-timeout`'s dual assignment preserved.
- [x] `ARCH-4d` corpus extended with the four new knobs; snapshots updated **in this PR only**, with
      the four additions visible in the diff and nothing else changed.
- [ ] **`ARCH-4l`'s draft example TOMLs are landed as corpus fixtures here** (Stream A owns
      `crates/rvc/tests/fixtures/config/`), so the release note's examples are proven to parse before
      the note ships and cannot rot afterwards. *(No 4l drafts existed; 4l will land examples.)*

---

### ARCH-4k — Retire G-2 clauses (i)/(ii) with seam α; assert clause (iv) empty; keep (iii)

- **Points:** 2 · **Type:** chore (gate) · **Priority:** P1 · **Scope:** 1 day
- **Blocked by:** `ARCH-4i`, `ARCH-4j` · **Blocks:** — · **Stream:** B
- **Requirements:** ARCH-P1-1 (retirement), ARCH-P1-2 · **ADR:** ADR-008, ADR-009 · **Gate:** G-2

**Context.** G-2 is **interim by construction** — architecture §6 requires that lifetime statement in
the gate's own module doc. Its clauses (i) and (ii) exist to guard **seam α** (group `Args` fields →
`From<StartArgs>`, read by field access at `cli.rs:607-682`). `ARCH-4i` deletes seam α, so those
clauses become unfalsifiable — a gate that can only ever be green, which is the R10 failure mode the
whole gate taxonomy exists to avoid. They must be **deleted, not left green**.

**Files.**

- `crates/architecture-tests/tests/config_drift.rs` *(from Phase 1)*

**Approach.**

1. **Delete clauses (i) and (ii)** together with the `BYPASS` (8) and `ALIASES` (2) tables and the
   non-vacuity assertions `assert_eq!(bindings.len(), 13)` / `assert_eq!(checked, 74)`, which are
   statements about a structure that no longer exists.
2. **Keep clause (iii)** — every knob appears in `Config::validate`'s body (`types.rs:1015`) or on the
   shrinking-only `UNVALIDATED` list. Re-aim it from `CliOverrides` field names (deleted) to the
   section-struct field paths. This is the only clause that survives with real content.
3. **Keep clause (iv)** — `CLAP_DEFAULT_CLOBBERS`, and **assert it is empty**. It should already be
   empty from Phase 1's ADR-009 fix; after `ARCH-4f`/`4h` it is empty *structurally* because no
   section field carries a `default_value`. Convert the clause into a scan asserting **no
   `clap::Args` field in `rvc-config` has both a `default_value` and a non-`Option` type** — that is
   the property, expressed once, that makes a tenth instance impossible rather than merely absent.
4. Update the module doc's lifetime statement: record that the interim clauses were retired here, and
   by which issue. A reader in six months must be able to see that the gate shrank *deliberately*.
5. **If `BYPASS` is merely reduced 8 → 4 rather than deleted** (it is attached to clause (ii)),
   preserve the four surviving CLI-only args as an explicit documented list somewhere — they are the
   only args with no config representation, and losing that fact is a small regression in honesty.

**TDD test plan.**

- **RED first:** `no_clap_field_has_both_a_default_value_and_a_non_option_type` — a synthetic-input
  matcher test fed a struct source with `#[arg(long, default_value = "8080")] pub port: u16`; assert
  it is flagged. This is clause (iv)'s replacement and its permanent RED demonstration.
- `clause_iii_covers_every_section_field` — re-aimed coverage assertion, non-vacuous.
- `retired_clauses_are_absent` — assert the file no longer defines `BYPASS`/`ALIASES`, so the
  retirement cannot be half-done.

**Acceptance criteria.**

- [x] Clauses (i)/(ii) and their tables deleted; the file's module doc records the retirement and its
      cause (seam α no longer exists).
- [x] Clause (iii) re-aimed at section-struct field paths, still non-vacuous.
- [x] Clause (iv) reformulated as the structural `default_value` + non-`Option` scan, RED-demonstrated
      on synthetic input; `CLAP_DEFAULT_CLOBBERS` empty.
- [x] The four surviving CLI-only args are documented.
- [x] `arch-gates` green.

---

### ARCH-4l — Operator release note: `--help` change, TOML section spelling, flat keys deprecated

- **Points:** 1 · **Type:** docs · **Priority:** P2 · **Scope:** 0.5 days
- **Blocked by:** `ARCH-4i`, `ARCH-4j` · **Blocks:** — · **Stream:** B
- **Requirements:** ARCH-P1-2 · **ADR:** ADR-008 (*Consequences*: "operator-visible, belongs in the release note")

**Context.** Two operator-visible changes ship in this phase and neither is a bug fix, so neither is
self-announcing:

1. **`--help` output changes.** Section fields become `Option<T>` with no `default_value`, so clap
   stops printing `[default: 8080]` and the default moves into the doc comment
   (architecture §5.4:1282-1291). Nothing behaves differently; the *documentation surface* does.
2. **The TOML gains section tables** (`[beacon]`, `[server]`, `[network]`, `[safety]`, `[slashing]`,
   plus the reshaped existing ones). **The flat spelling still works and is not being removed**
   (A-4.3) — but operators reading a new example file need to know both are valid and which wins.

**Files.**

- The repository's release-note location for the release closing this phase. **This planning file does
  not choose that path** — output confinement forbids writing outside
  `plan/architecture-2026-08-12/`; the issue's first task is to locate the convention used by the
  v0.7.0 release and follow it.

**Approach.**

1. Document the `--help` diff at a level an operator can diff against: defaults are unchanged, only
   their presentation moved.
2. Give a before/after example TOML showing flat and sectioned spelling for the same config, and state
   the **flat-wins** collision rule that has been in force since before this change
   (`types.rs:626-627`) and is preserved.
3. State explicitly that **no knob was removed, renamed or given a new default** — and point at the
   parity corpus (`crates/rvc/tests/config_wire_parity.rs`) as the evidence, so the claim is
   falsifiable rather than reassuring.
4. Note the four BN timeouts are now settable from the config file (new capability, `ARCH-4j`).
5. **Do not** announce a deprecation *window* for the flat keys. No removal is scheduled anywhere in
   this initiative (A-4.3), and announcing a window this phase cannot honour is the C8 mistake in a
   different costume.

**TDD test plan.** Documentation issue — no unit test, and **it writes no code**. The example TOMLs
must not be allowed to rot, but the parity corpus (`crates/rvc/tests/fixtures/config/`) is a
**Stream A** path and this is a Stream B issue: the streams own disjoint files. **Resolution:** this
issue drafts the examples and hands them to `ARCH-4j`, whose acceptance criteria include adding them
to the corpus. `ARCH-4l` therefore ships the note only, and its examples are already proven to parse
before it merges.

**Acceptance criteria.**

- [x] Release note exists at the repo's conventional location, covering all four points above.
- [x] Every example TOML in the note was landed as a corpus fixture by `ARCH-4j` and parses — this
      issue **cites** that fixture, it does not add it.
- [x] No deprecation window is announced for the flat legacy keys.
- [x] The note states that no knob was removed, renamed or re-defaulted, and cites the parity harness.
- [x] No file outside the release-note path is modified (stream disjointness).

---

## 6. Constraint Coverage (C1–C10)

Silence on any constraint is a defect, so every row is stated — including the ones that do not apply.

| ID | Applies? | How this phase discharges it |
|---|---|---|
| **C1** — retain-on-ambiguity vs lock shortening | **No** | Slashing-DB critical section is Phase 5. No issue here touches `crates/slashing/` or `crates/signer/`. Explicitly out of scope; `ARCH-4b` allow-lists `RVC_ALLOW_NON_WAL_SLASHING_DB` (`crates/slashing/src/db/open.rs:225`) as class 1 **without reading or altering the code around it**. |
| **C2** — audit-log emission inside the mutex | **No** | Owned by Phase 1 (ARCH-P0-9 / ADR-006, `crates/slashing/src/scoped.rs:69-75`, `:102-107`). Untouched here. |
| **C3** — figment `Env` provider **forbidden** | **Yes — the live constraint of this phase** | Discharged **three ways, not one**. (1) *By construction*: ADR-008 rejects figment outright, so the dependency is never taken — `ARCH-4e` implements provenance in ~40 lines of `ConfigError` instead. (2) *By gate*: `ARCH-4b` lands G-3 **before** the collapse, so an env layer introduced during migration fails CI; its class-3 doc comment states the **config-else-env** direction explicitly (`types.rs:438`, `:447`) so a later refactor cannot "harmonise" it the wrong way. (3) *By regression guard*: `ARCH-4c`'s source-scoped figment-absence assertion — corrected per VD-4.3, since the unscoped grep is false at HEAD. |
| **C4** — keystore-less key admission | **No** | Phase 1 (ARCH-P0-5 / ADR-007, `crates/rvc/src/keymanager_adapters/notifier.rs`). No overlap. |
| **C5** — KM-2 teardown contract | **No** | Phase 7 (ADR-015 / G-6). `KeymanagerArgs` moves crates in `ARCH-4f`, but only the **arg struct** — no lifecycle code, no `stop_monitoring`/`cancel_monitoring` call site is touched. Flagged so the Phase-7 owner knows the arg struct relocated. |
| **C6** — cold-cache pre-proposal fetch | **No** | Phase 3 (ADR-004). |
| **C7** — SSE drops are normal | **No** | Phase 3 (ADR-013). |
| **C8** — healthz removal is operator-visible | **No, but adjacent** | Healthz is Phase 0 (deprecation) / Phase 7 (removal). `ARCH-4l` writes a release note in the same release, and is explicitly instructed **not** to announce a deprecation window for the flat TOML keys — the C8 lesson applied to a different surface. |
| **C9** — preserve the keep-list | **Yes — anchors 1 and 4** | **Anchor 4** ("env = security opt-outs only") is not merely preserved, it is **converted from convention into a gate** by `ARCH-4a`/`4b` — this phase is where anchor 4 acquires its artefact. **Anchor 1** (architecture-tests harness): `ARCH-4e` appends exactly one `CLASSIFICATION` row and re-runs the byte-match on generated `ARCHITECTURE.md`; the harness is extended, never replaced (NG2). Anchors 2, 3, 5, 6, 7 are untouched — no signing path, no channel, no `spawn_blocking`, no `CompositeSigner` wiring site is in any file this phase edits. |
| **C10** — archive-before-delete for untracked trees | **No** | Every deletion in this phase (`CliOverrides`, `From<StartArgs>`, `merge_with_cli`, `merge_cli_fields!`, G-2 clauses i/ii) is **tracked** and recoverable by `git revert`. The unrecoverable-deletion hazard is confined to Phase 0's four untracked orphan paths, which are **already gone** before this phase starts (§1.3 entry criterion). No archive step is required here, and none is invented. |

---

## 7. KAT-First Policy Applicability

Per `CLAUDE.md`, any test covering a **signing root** or container `hash_tree_root` must be
KAT-anchored or carry a documented `// kat_exempt: <reason>`, and CI enforces a name-pattern scan
(`.*(tree_hash|signing_root|_root)$`) in `crates/architecture-tests/tests/kat_policy.rs` whose
`EXEMPTIONS` list is **shrinking-only**.

**No issue in this phase touches a signing root or a container `hash_tree_root`.** The policy is
therefore not triggered on its merits. **One naming trap applies** and is flagged on the two issues
that meet it:

- **`ARCH-4d`** and **`ARCH-4h`** both handle the config knob `genesis_validators_root`
  (`crates/rvc/src/config/types.rs:188`, `ConfigWire:644`, `NetworkArgs` at `bin/rvc/src/cli.rs:305-321`).
  A round-trip test named `…_genesis_validators_root` **ends in `_root`** and would match the scan,
  demanding a known-answer vector that cannot exist for a string config value.
- **The trap is live, not hypothetical.** `kat_policy.rs:39` names *"name-pattern false positives
  (genesis_root, dependent_root, logging, wire paths, …)"* as a known category, and the `EXEMPTIONS`
  table already carries ten such rows — `test_holesky_genesis_root` (`:47`),
  `test_mainnet_genesis_root` (`:49`), `test_get_proposer_duties_with_dependent_root` (`:53`) and
  siblings. A config round-trip test named after `genesis_validators_root` would be the eleventh, on a
  list that is allowed to shrink only.
- **Rule for both issues:** name such tests so they do **not** end in `_root` — e.g.
  `genesis_validators_root_parses_from_flat_key`. **No `EXEMPTIONS` entry may be added**; the list
  shrinks only, and a config test is not the exceptional case that justifies a removal-only list
  growing.
- This is the same inverse obligation ADR-003 carries in Phase 3 (its new tests assert HTTP behaviour,
  not spec-defined roots, and must avoid the `_root` suffix). Recorded here so the two phases apply it
  consistently.
