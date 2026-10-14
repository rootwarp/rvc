# Phase 1 Issues — Runtime Honesty: inert surfaces, one admission path, the live hazard

> Self-contained issue breakdown for **Phase 1** of the rs-vc architecture-remediation initiative.
> A code-writer should be able to execute this phase from this file alone.
>
> **Authoritative inputs, in precedence order:**
> [`../project-plan.md`](../project-plan.md) *§Phase 1* (scope, work packages 1A–1F, entry/exit gates)
> → [`../architecture.md`](../architecture.md) (ADR-006, ADR-007, ADR-009; §5.2 `KeyAdmissionService`;
> §6 G-2, G-7; §7.1 anchors 2/3/5) → [`../prd.md`](../prd.md) (ARCH-P0-5/6/7/9, ARCH-P1-1; C2, C4, C9)
> → [`../research/`](../research/) → [`../../../docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md).
> Where the architecture and the PRD conflict the architecture wins; where this file records a
> **verification delta** against HEAD, the corrected fact wins over both.
>
> **Baseline:** `develop` @ `0ae9a09` (v0.7.0), 2026-08-12. Every `file:line` below was re-verified
> against that commit by reading the file, not carried over from an upstream document. Seven claims did
> **not** reproduce as written; they are recorded in *§3 Verification deltas* and the corrected fact is
> carried into the affected issue. **VD-E2 changes this phase's scope** and **VD-E1 adds an issue**.
>
> **No-ask constraint:** every open question is resolved to a stated default in *§2 Assumptions*.
> Nothing is escalated.
>
> **Scope of this document:** planning only. It changes no source file and deletes nothing. The four
> untracked orphan trees (`crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`,
> `crates/rvc/src/commands/`) are never cited, edited or migrated by any issue here — Phase 0's
> archive-verify-delete sequence (ARCH-P0-1, **C10**) owns them, and that deletion is *not* this phase's
> work. `docs/prd.md`, `docs/architecture.md` and `docs/project-plan.md` belong to the older Test Audit
> Remediation initiative and are untouched (NG8).

---

## 1. Phase Overview

**Goal.** No shipped config surface accepts operator input and discards it; a key admitted from a cloud
secret manager actually gets duties and can leave `Pending` (a **build**, not a rewiring — VD-5); and no
observability change can wedge signing (**C2**, both `scoped.rs` paths, with `stage.rs` byte-unchanged so
A-12 is sidestepped).

**Milestone (the thing a stakeholder can evaluate).** 4 of 5 inert surfaces closed (**M7 → 1**); a
provider-refreshed key reaches `PubkeyMap` / `ValidatorStore` / `key_gen_tx` and is sampled by the
liveness loop; a DB-reading tracing subscriber completes a full stage→sign→commit; **G-2** green with
`CLAP_DEFAULT_CLOBBERS` shrunk to empty.

| | |
|---|---|
| **Issue count** | **13 issues, 28 points** |
| **Duration, 1 developer** | **14–21 working days** (at 0.5–0.75 d/pt — see A-1.1) |
| **Duration, 2 developers** | **11–17 working days** — Stream A's chain (22 pts). Stream B's 6 pts finish in 3–5 d and it departs to Phase 5's entry work (5A, the M3 load harness) per project-plan §9 |
| **Depends on phases** | **0** (hard, not cosmetic — see entry criteria) |
| **PRD requirements delivered** | ARCH-P0-9 (+G-7), ARCH-P0-5, ARCH-P0-7, ARCH-P0-6, ARCH-P1-1 (+G-2) |
| **ADRs implemented** | ADR-006, ADR-007, ADR-009 (architecture-only; no PRD ID — A-P5), ADR-014's sibling PB-B2 |
| **Constraints in force** | **C2** (is ARCH-P0-9), **C4** (binding on ARCH-2b/2c), **C3** (indirect, ARCH-5b/6b), **C9** anchors 2/3/5/6, **C10** (Phase 0's, restated as a prohibition here), **C5** (deferred, see A-1.4) |

**Why the duration exceeds the project plan's 13–19 d envelope by ~2 d.** The plan sized work package
1A as *"`scoped.rs` only"*. **VD-E2** shows that bound is unsatisfiable on the success path: four
production call sites in `crates/signer/` must change too. The decomposition below is honest about
that rather than absorbing it silently. Everything else lands inside the plan's envelope.

### Entry criteria

- [ ] **Phase 0 complete.** Specifically: the four orphan paths no longer exist, G-1 (`orphan_dirs`) is
      green, and the `arch-gates` CI job (A-P1 / VD-P7) exists and runs
      `cargo nextest run -p rvc-architecture-tests`. Two issues here (**ARCH-1c**, **ARCH-5a/5b**) add
      gate files that land in the slowest job otherwise.
- [ ] `git rev-parse HEAD` is `0ae9a09` or a descendant carrying Phase 0; working tree clean.
- [ ] Standing invariants green on the untouched tree: `cargo fmt --all -- --check`,
      `cargo clippy --workspace --all-targets -- -D warnings`,
      `cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings`,
      `cargo build --workspace`, `cargo nextest run --workspace`.
      **Never `cargo test --workspace`** — it deadlocks in this workspace (NFR-6).
- [ ] **A-12 resolution recorded — verified here, not assumed (VD-E6).** `.github/workflows/ci.yml` at
      HEAD contains **no** occurrence of `stage.rs` and none of `slashing`; the tracing initiative's
      *prospective* byte-identical pin on `crates/slashing/src/stage.rs` is **not wired in CI**. ARCH-1a/1b
      are nonetheless scoped so `stage.rs` is byte-unchanged, so the phase is unaffected either way. The
      note is filed now because Phase 5 cannot proceed without resolving it (A-P8).

### Exit criteria (the phase is complete when all hold)

- [ ] **The live hazard is gone.** A test installs a tracing subscriber that acquires the slashing DB
      lock on every event and drives a full stage→sign→commit; it **completes**. The test is bounded by a
      **thread-based** timeout (`std::thread` + `Receiver::recv_timeout`), never `tokio::time::timeout` —
      a blocking `parking_lot` lock is not cancellable by a future, so the async form hangs the run
      instead of failing it (ARCH-1a).
- [ ] **G-7 (`audit_log_scope.rs`) is green over both paths** — block and attestation — and was
      RED-demonstrated locally against the pre-change tree with output pasted into the PR (ARCH-1c).
- [ ] **`git diff <base> -- crates/slashing/src/stage.rs` is empty** for every PR in this phase.
- [ ] **A provider-refreshed key is fully admitted:** it appears in `PubkeyMap` **and** `ValidatorStore`,
      bumps `key_gen_tx`, is registered with the forward-window machine, is **sampled by the liveness
      loop**, and can leave `Pending` (ARCH-2c).
- [ ] **A raw `SecretKey` is admitted with no keystore file and no filesystem write** (C4), and the
      denylist re-check currently at `bootstrap/enablement.rs:174-183` is preserved and separately tested.
- [ ] **Existing keymanager adapter tests are green, unmodified** — the no-behaviour-change proof for the
      import path (architecture §7.2, ADR-007 row).
- [ ] **Monitoring push reports live counts:** the two tuple elements mean different things (total loaded
      vs. active/enabled), and the pushed values change after a keymanager import **and** after a delete
      (ARCH-3).
- [ ] **A rotated fee recipient reaches the next block proposal**, a `default_config` entry updates the
      store's defaults, and a malformed/unauthorised fetch leaves the previous values intact and logs at
      `warn` (ARCH-4a/4b).
- [ ] **G-2 (`config_drift.rs`) green**, RED-demonstrated on synthetic input, with
      `assert_eq!(bindings.len(), 13)` and `assert_eq!(checked, 74)` non-vacuity assertions present.
- [ ] **`CLAP_DEFAULT_CLOBBERS` has shrunk to empty**, *and* the clause-(iv) scanner still flags a
      synthetic reintroduction — an empty shrinking-only list is otherwise indistinguishable from a dead
      gate (ARCH-6b).
- [ ] **M7 → 1.** Four of five inert surfaces closed; `BnRole` broadcast routing (ARCH-P2-8) remains for
      Phase 7 and is explicitly out of scope here.
- [ ] **No C9 regression.** Specifically: no new unbounded channel and no new channel at all
      (anchor 6); `crates/signer/src/core.rs:542`'s `spawn_blocking` untouched (anchor 7); the single
      wiring site `crates/rvc/src/config/builder.rs:394` unchanged and no new signing surface introduced
      (anchor 5); no new or renamed `*_root` / `*tree_hash*` / `*signing_root*` test without a KAT anchor
      or a `// kat_exempt:` reason, and `EXEMPTIONS` has not grown (anchor 3).
- [ ] Standing invariants green (the five commands above).

---

## 2. Facts verified against HEAD (`0ae9a09`)

Re-checked by reading the named file at the named lines. **Confirmed exactly** unless a delta row in §3
says otherwise.

| # | Claim (upstream source) | Status | Evidence at HEAD |
|---|---|---|---|
| F1 | Both audit-log hazards exist, not just the block one (VD-S5) | ✅ **Confirmed** | `crates/slashing/src/scoped.rs:68` stages, `:75` calls `audit_log` while `result` still owns the guard; attestation stages at `:95-101`, `audit_log` at `:106`. **Citation correction:** the architecture writes the attestation note as `:103-107`; at HEAD the misleading `NOTE` comment is `:103-105` and the call is `:106`. The block-path note is `:70-74`, call at `:75` — as written |
| F2 | `KeyChangeNotifier` is 61 lines, two fields, five methods — *not* the atomic multi-store updater the review describes (VD-5/R6) | ✅ **Confirmed** | `crates/rvc/src/keymanager_adapters/notifier.rs` is 61 lines; struct `:29-32` = `pubkey_map`, `key_gen_tx`; surface `new:36`, `pubkey_map:41`, `notify:46`, `insert_and_notify:51`, `remove_and_notify:57`. It touches no composite signer, no `ValidatorStore`, no denylist, no doppelganger. (The file also carries an unrelated `pubkey_hex` helper at `:16-23` — not part of the struct) |
| F3 | "Register the refreshed keys with doppelganger" is a **no-op fix** — it already happens (VD-2) | ✅ **Confirmed** | `crates/rvc/src/bootstrap/enablement.rs:185-188` calls `machine.register_for_import(&pk, epoch_clock.current_epoch())`; `:189` calls `signer_for_refresh.add_local_key(sk)`. What the closure never touches is `PubkeyMap`, `ValidatorStore`, `key_gen_tx` |
| F4 | The denylist re-check (DELETE-races-refresh guard) must be preserved | ✅ **Confirmed** | `enablement.rs:174-183` — `denylist_for_callback.contains(&pk_bytes)` → `info!` → early `return` |
| F5 | The liveness loop is constructed with the `PubkeyMap` precisely so it can re-resolve indices, so a key absent from the map is **never sampled** — starvation, not absent registration | ✅ **Confirmed** | `enablement.rs:139-150` — `spawn_liveness_loop(..., Some(Arc::clone(&keys.pubkey_map)), ...)`; doc rationale `:135-138` |
| F6 | `RefreshService::run` takes a **synchronous, non-`async`** `Fn(SecretKey)` callback (VD-A2 / A-A2) | ✅ **Confirmed** | `crates/secret-provider/src/refresh.rs:179-181` — `pub async fn run<F>(mut self, on_new_key: F) where F: Fn(SecretKey)`; invoked at `:188` inside the select loop |
| F7 | Monitoring push reports a **boot-time constant** | ✅ **Confirmed, and worse than stated** | `crates/rvc/src/bootstrap/tasks.rs:106` — `move \|\| (validator_count as u32, validator_count as u32)` — a `usize` captured by value (param `:79`), computed **once** at `run.rs:223` as `pubkey_map.read().len()`. Both tuple elements are the *same* number, so "active" is a tautology of "total" as well as being frozen |
| F8 | The proposer-config apply callback logs and discards, including `_default` by name | ✅ **Confirmed** | `tasks.rs:124-137` — `move \|updates, _default\| { for update in &updates { info!(...) } }`. Nothing is written anywhere |
| F9 | Nine `CliOverrides` fields are populated with an unconditional `Some(<clap field with a default_value>)` (ADR-009) | ✅ **Confirmed, all nine, exact lines** | `bin/rvc/src/cli.rs:614` `metrics_address`, `:615` `metrics_port`, `:616` `grpc_port`, `:617` `grpc_address`, `:622` `log_level`, `:641` `tracing_exporter`, `:652` `keymanager_body_limit`, `:658` `slashed_validators_action`, `:682` `beacon_max_body_bytes` |
| F10 | The `set` arm overwrites unconditionally, which is what makes F9 a live defect | ✅ **Confirmed** | `crates/rvc/src/config/types.rs:942-946` — `(@arm set, ...) => { if let Some(v) = $field { $dst = v.clone(); } }` |
| F11 | Clause (i) of ARCH-P1-1 is already enforced by rustc — `merge_cli_fields!` destructures `CliOverrides` exhaustively | ✅ **Confirmed** | `types.rs:932-936` — `let CliOverrides { $($field,)* } = $cli;`; the macro's own doc says so at `:925-926` |
| F12 | Seam α is real: **13** flattened group `Args` structs, read by *field access* in `From<StartArgs>` | ✅ **Confirmed** | 13 groups: `BeaconArgs:195`, `KeysArgs:233`, `ServerArgs:285`, `NetworkArgs:305`, `LoggingArgs:325`, `TracingArgs:371`, `KeymanagerArgs:395`, `GrpcSignerArgs:435`, `SafetyArgs:455`, `BuilderArgs:483`, `ProposerArgs:507`, `MonitoringArgs:539`, `SlashingArgs:555` (`StartArgs:148` is the 14th `#[derive(Args)]` but is the container, not a group). The destructure at `:589-604` binds exactly those 13 plus `config: _`, so a new **group** fails to compile while a new **field** does not |
| F13 | The two `ALIASES` entries exist and have opposite shapes | ✅ **Confirmed** | 1:1 negated rename `no_doppelganger_detection` → `doppelganger_detection` at `cli.rs:623-627`; 2:1 collapse `no_keymanager` + `keymanager_enabled` → `keymanager_enabled` at `:628-634` (the sole `−1` in `74 − 8 − 1 = 65`) |
| F14 | `crates/architecture-tests/tests/` is the gate directory and every gate is a standalone file | ✅ **Confirmed** | 7 files at HEAD: `architecture_doc_matches_graph.rs`, `architecture_no_cycles.rs`, `field_name_conformance.rs`, `kat_policy.rs`, `no_crypto_logging_paths.rs`, `no_rvc_prefix.rs`, `signer_proto_compiled_once.rs`. Both new gates in this phase are **new files**; neither touches `src/lib.rs` (C9 anchor 1) |
| F15 | `ValidatorStore` already has a per-validator update path | ✅ **Confirmed** | `crates/validator-store/src/store.rs:285` `update_config(&self, pubkey: &[u8;48], update: ValidatorConfigUpdate)`, applied under one write guard at `:306-309`; `add_validator:265`, `set_enabled:273`, `effective_fee_recipient:202`, `list_enabled_pubkeys:247` |

---

## 3. Verification deltas found while estimating

Seven claims in the upstream documents did not reproduce as written, or reproduce but omit a fact that
changes the work. Each corrected fact is carried into the named issue. **These are the reason this file
is not an excerpt of the review.**

| ID | Claim as written upstream | Status at HEAD | Corrected fact carried forward | Lands in |
|---|---|---|---|---|
| **VD-E1** | Implicit in ADR-007 §5.2 and project-plan 1B: `KeyAdmissionService` (which needs `validator_store` **and** `key_gen_tx`) simply replaces the closure body at `enablement.rs:172-190` | **Unsatisfiable at that site — neither dependency is in scope yet** | `wire_signing_enablement` is called at `crates/rvc/src/bootstrap/run.rs:127-135`. `build_services` — which *produces* `validator_store` — is called at `:138-146`, i.e. **after** it. `key_gen_tx` is not created until `:190`. So the refresh closure cannot construct or hold a `KeyAdmissionService` where it lives today. Neither the architecture nor the project plan names this; the ADR's "call-site replacement" paragraph reads as a drop-in. **Resolution (A-1.2):** relocate the refresh-service spawn out of `wire_signing_enablement` into `run.rs` after `:190`. This is a prerequisite issue, not a detail of another one | **ARCH-2a** (new issue) |
| **VD-E2** | ADR-006 *Consequences* + PRD ARCH-P0-9 + project-plan 1A: *"Scope is **hard-bounded to `scoped.rs`**"*; restructure so the outcome "is emitted **after** the guard is released" | **Correct in intent; the file bound is impossible on the success path** | `PubkeyScopedDb::stage_block` (`scoped.rs:62-77`) **returns** `StagedBlock<'db>`, which owns the `MutexGuard` (architecture §5.3, `stage.rs:57-63`). On `Ok` the guard is moved to the caller — there is no point inside `stage_block` where the mutex is free. Only the `Err` path is fixable in-file. Four **production** call sites must therefore change: `crates/signer/src/lib.rs:721-724` (block, VC path) and `:619-622` (attestation, VC path); `crates/signer/src/gate.rs:279-282` (block) and `:365-368` (attestation). **What is preserved:** the constraint that actually discharges A-12 is `stage.rs` **byte-unchanged**, and it still holds. **What is preserved in §9's stream cut:** `crates/signer/` is Stream **B** territory in both W1 and W2, and Stream A never opens it — so extending 1A into `crates/signer/` costs zero cross-stream overlap. This is a scope correction, not a re-planning | **ARCH-1a, ARCH-1b** (1A splits in three) |
| **VD-E3** | PRD ARCH-P0-6 / project-plan 1D read as if the fetched update can be handed to `ValidatorStore` | **Two different types share the name `ValidatorConfigUpdate`** | `crates/validator-store/src/config.rs:31-38` — `{ fee_recipient: Option<Option<[u8;20]>>, gas_limit: Option<Option<u64>>, graffiti, builder_proposals: Option<bool>, builder_boost_factor, block_selection_mode }`, **no `pubkey`, no `enabled`**. `crates/rvc/src/background_tasks/config_url.rs:41-46` — `{ pubkey: String, fee_recipient: Option<String>, builder_enabled: Option<bool>, gas_limit: Option<u64> }`. So the apply path needs an explicit mapping including hex→`[u8;20]` / hex→`[u8;48]` parsing (fallible), and `builder_enabled` → `builder_proposals` (a rename across the seam). An undocumented **M9 duplicated-seam** row nobody counted | **ARCH-4a** |
| **VD-E4** | PRD ARCH-P0-6: *"write fetched updates … and the `_default` currently discarded by name … to `ValidatorStore`"* | **No public API exists to write the defaults** | `ValidatorStore`'s defaults are mutated in exactly two places, both unusable here: `reload_config` (`store.rs:395-419`, reads from the config **file**, `state.defaults = new_defaults` at `:416`) and crate-private `state.write().defaults.…` inside its own tests (`:605`, `:1417-1418`). There is no `set_defaults` / `apply_default_update` on the public surface. Applying the `default_config` entry (parsed at `config_url.rs:98-99` under the literal pubkey `"default"`) therefore requires a **new public method on a different crate** — treated as free by the PRD | **ARCH-4a** |
| **VD-E5** | project-plan §Phase 1 *Dependencies*: *"Internally: 1B → 1C"*; work package 1C: *"Depends on 1B: with a live `PubkeyMap` the count is a free win"* | **A milestone dependency, not a structural one** | `spawn_background_tasks` is called at `run.rs:279`, where `pubkey_map` (bound at `:160`, read at `:223`) and `validator_store` (bound at `:176`) are both already in scope. ARCH-3 is therefore independently implementable, mergeable and testable — against a **keymanager import**, which already updates `PubkeyMap` today via `insert_and_notify`. The coupling is only that the *provider-refresh* case starts being counted once ARCH-2c lands. Recorded so a scheduler does not serialise 2 pts behind 8 | **ARCH-3** |
| **VD-E6** | project-plan Phase 1 *Entry criteria*: A-12's pin is *"verified not wired in CI at HEAD"* — asserted, not shown | ✅ **Verified here** | `.github/workflows/ci.yml` contains **no** occurrence of `stage.rs` and **no** occurrence of `slashing`. The tracing initiative's byte-identical pin is genuinely not wired. The entry criterion is discharged by this row |
| **VD-E7** | ADR-006 offers "capture the outcome as a value and emit after the guard is released **or handed off**", implying a deferral seam may already exist | **`audit_log` has no deferral seam** | `crates/slashing/src/audit.rs:22-30` is a thin `tracing::info!(target: "slashing.audit", …)` wrapper — three `&str` args, no state, no queue. Deferring *inside* `audit_log` would mean introducing a queue plus a drainer task in `crates/slashing/`, which adds a channel — **rejected against C9 anchor 6** ("zero unbounded channels"; the phase's stated position is *no new channel at all*). Hence the `PendingAudit` hand-off design in ARCH-1a | **ARCH-1a** |

**A trap that is not a delta but will cost a day if missed.** The RED demonstration for ARCH-1a must be
bounded by a **thread-based** timeout. `tokio::time::timeout` cannot rescue it: the deadlock is a
blocking `parking_lot::Mutex::lock` inside a `tracing` subscriber, which is not an await point and
therefore not cancellable by a future — the test would hang the whole `nextest` run rather than fail.
Run the stage→sign→commit on a `std::thread`, signal completion over a `std::sync::mpsc::channel`, and
assert with `recv_timeout`. ADR-006 says "with a timeout" without saying which kind.

---

## 4. Assumptions — no-ask resolutions

Per the no-ask constraint, every open question is resolved to a stated default here. Nothing is
escalated. The PRD's `A-*`, the architecture's `A-A*` and the project plan's `A-P*` remain in force and
are **not** repeated; below are the ones this estimate creates, prefixed `A-1`.

| ID | Question | Default taken | Why, and what it would cost to reverse |
|---|---|---|---|
| **A-1.1** | Points-to-days calibration | **1 pt ≈ 0.5–0.75 working days.** 28 pts → 14–21 d | The house range is 0.5–1.0 d/pt, which would read as 14–28 d and blow past the project plan's 13–19 d envelope for no reason. The narrower rate is what reconciles this decomposition with §6 of the plan; the ~2 d overshoot at the top is VD-E2's, and is stated rather than hidden. Reversal is arithmetic only |
| **A-1.2** | Where does the secret-provider refresh spawn live, given VD-E1? | **Relocate it out of `wire_signing_enablement` into `run.rs`, after `key_gen_tx` is created at `:190`** | The alternative — create `key_gen_tx` earlier and thread `validator_store` down into `wire_signing_enablement` — inverts the bootstrap's construction order (`build_services` consumes `&enablement`, `run.rs:141`) and grows a 6-parameter function to 8. Relocation keeps `enablement.rs` about enablement. **Verified non-issue:** `RefreshService::run` sleeps `self.interval` before its first fetch (`refresh.rs:184-186`), so moving the spawn a few dozen lines later changes no startup timing and no first-refresh deadline |
| **A-1.3** | Is `KeyAdmissionService::admit` synchronous or async? | **Synchronous**, exactly as ADR-007 / §5.2 decide (A-A2) | Forced by F6: `F: Fn(SecretKey)` is a non-`async` bound. Every store `admit` touches (`PubkeyMap` behind `RwLock`, `ValidatorStore` behind `RwLock`, `watch::Sender`) is synchronously updatable, so this costs nothing. **The issue must state this decision, not discover it at compile time.** Reversal means changing `RefreshService`'s public bound — a `crates/secret-provider` API break |
| **A-1.4** | Does `KeyAdmissionService::withdraw` (§5.2) land in this phase? | **No — deferred to Phase 7, with ADR-015 and G-6** | `withdraw` is specified to call `cancel_monitoring` (not `stop_monitoring`) — i.e. it encodes **C5**'s teardown contract. **G-6 (`km2_lifecycle.rs`) does not exist at HEAD** (VD-6) and lands in Phase 7 *before* the retirement. Shipping the contract's new implementation here, ungated, is exactly the failure mode project-plan §1.1 exists to prevent ("no behavioural change ships before the artefact that would detect its regression exists"). Nothing in this phase's milestone needs it: the DELETE path already works through the keymanager adapters' `remove_and_notify`, and ARCH-3's delete-visibility criterion is satisfied by that existing path. **Cost of reversal: none — it is additive later.** ARCH-2b must therefore *not* collapse `stop_monitoring` and `cancel_monitoring`, and must not add a doppelganger-teardown call of either kind |
| **A-1.5** | Does the proposer-config apply path **apply** or **reject at startup**? | **Apply** (PRD A-2's default, restated) | Rejecting a knob that has shipped and is presumably in use is operator-hostile; "accept and ignore" is the one option ruled out by ARCH-P0-6. The fallback (a named `ConfigError` at startup) stays documented in ARCH-4b's notes so a reviewer can see it was considered |
| **A-1.6** | What do the two monitoring tuple elements mean (A-3)? | **`(total_loaded, active_enabled)`** — `pubkey_map.read().len()` and `validator_store.list_enabled_pubkeys().len()` | These are the only two live sources at the call site (`store.rs:247` exists; F15). Today both are the same frozen number, so any operator dashboard reading them as distinct is already wrong. Named in ARCH-3's acceptance so the distinction is asserted, not assumed |
| **A-1.7** | Does ARCH-6a's probe result change the plan? | **The gate (ARCH-5b) lands regardless; only ARCH-6b is conditional** | ADR-009's finding is static-analysis only (A-A4). If `rvc start --config <toml with metrics_port = 9090>` binds **9090**, the defect is withdrawn, ARCH-6b's code change is cancelled, and `CLAP_DEFAULT_CLOBBERS` ships as a **documented-empty** list guarding against future reintroduction — the phase still exits green. If it binds **8080**, ARCH-6b proceeds as written. Either verdict is recorded in the issue |
| **A-1.8** | Where does the stage→sign→commit deadlock test live? | **`crates/signer/tests/audit_subscriber_deadlock.rs`** (new integration test) | The full path is owned by `crates/signer`, not `crates/slashing`; a unit test inside `scoped.rs` cannot drive a sign. Placing it in `crates/signer/tests/` also keeps it inside Stream B's file ownership. Name carries no `_root` / `_tree_hash` / `_signing_root` suffix, so it does not enter `kat_policy`'s scanner scope (C9 anchor 3) |
| **A-1.9** | Is `BnRole` broadcast routing (PB-B4 / ARCH-P2-8) in scope? | **No** | The milestone is explicitly *4 of 5* inert surfaces (**M7 → 1**). Pulling the fifth in would make the phase's own exit number wrong |
| **A-1.10** | Do the two streams collide in `crates/architecture-tests/`? | **No** | Each adds one **new** file (`audit_log_scope.rs` vs `config_drift.rs`); neither modifies `src/lib.rs`, the `CLASSIFICATION` table, or any existing gate. This is conflict-avoidance pattern 1 (new file), and it also satisfies C9 anchor 1 |

---

## 5. Phase Summary

| Issue | Title | Pts | Type | Blocked by | Stream | Scope |
|---|---|--:|---|---|---|---|
| **ARCH-1a** | `PendingAudit` hand-off in `scoped.rs` + thread-bounded RED deadlock harness | 2 | fix | — | **B** | 1–1.5 d |
| **ARCH-1b** | Migrate the four `crates/signer` stage call sites; deadlock test goes GREEN | 2 | fix | ARCH-1a | **B** | 1–1.5 d |
| **ARCH-1c** | **G-7** `audit_log_scope.rs` scanner (both paths) + synthetic RED | 2 | chore | ARCH-1a | **B** | 1–1.5 d |
| **ARCH-2a** | Relocate the secret-provider refresh spawn so `validator_store` + `key_gen_tx` are in scope (**VD-E1**) | 2 | refactor | — | **A** | 1–1.5 d |
| **ARCH-2b** | `KeyAdmissionService` seam: `AdmissionSource` / `AdmissionOutcome` / `AdmissionError` + `admit` | 3 | feature | ARCH-2a | **A** | 1.5–2 d |
| **ARCH-2c** | Switch both admission callers to `admit`; liveness-sampling test proves the key leaves `Pending` | 3 | feature | ARCH-2b | **A** | 1.5–2 d |
| **ARCH-3** | Live validator counts in the monitoring push (total loaded vs. active/enabled) | 2 | fix | — *(soft: ARCH-2c)* | **A** | 1–1.5 d |
| **ARCH-4a** | `ValidatorStore::apply_default_update` + the `config_url` → `validator-store` update mapping (**VD-E3/E4**) | 2 | feature | — | **A** | 1–1.5 d |
| **ARCH-4b** | Wire the proposer-config apply callback; wiremock rotation + negative tests | 2 | fix | ARCH-4a | **A** | 1–1.5 d |
| **ARCH-5a** | **G-2** `config_drift.rs` clause (ii): seam-α scanner, `BYPASS`/`ALIASES`, non-vacuity, synthetic RED | 3 | chore | — | **A** | 1.5–2 d |
| **ARCH-5b** | **G-2** clauses (iii) `UNVALIDATED` + (iv) `CLAP_DEFAULT_CLOBBERS` (9 entries, shrinking-only) | 2 | chore | ARCH-5a | **A** | 1–1.5 d |
| **ARCH-6a** | **Spike:** run the ADR-009 precedence probe and record the verdict | 1 | spike | — | **A** | 0.5 d |
| **ARCH-6b** | ADR-009 fix: nine clap fields → `Option<T>`, defaults to `Config::default()`; `CLOBBERS` → empty | 2 | fix | ARCH-5b, ARCH-6a | **A** | 1–1.5 d |

**Total: 13 issues, 28 points.**

### Intra-phase dependency map

```text
Stream B (departs to Phase 5 / 5A when done):
  ARCH-1a ──┬──▶ ARCH-1b        (one PR: RED → API → call sites → gate)
            └──▶ ARCH-1c

Stream A:
  ARCH-2a ──▶ ARCH-2b ──▶ ARCH-2c ┄┄(soft, milestone-only — VD-E5)┄┄▶ ARCH-3
  ARCH-4a ──▶ ARCH-4b
  ARCH-5a ──▶ ARCH-5b ──┐
  ARCH-6a ──────────────┴──▶ ARCH-6b
```

`ARCH-3`, `ARCH-4a`, `ARCH-5a` and `ARCH-6a` have **no** blockers and can start on day 1 of Stream A.

### Stream & file ownership (disjoint by construction)

| Stream | Owns | Issues | Pts |
|---|---|---|--:|
| **A** | `crates/rvc/src/**`, `bin/rvc/src/cli.rs`, `crates/validator-store/src/**`, `crates/architecture-tests/tests/config_drift.rs` *(new)* | ARCH-2a/2b/2c, 3, 4a/4b, 5a/5b, 6a/6b | 22 |
| **B** | `crates/slashing/src/{scoped.rs,audit.rs}`, `crates/signer/src/{lib.rs,gate.rs}`, `crates/signer/tests/audit_subscriber_deadlock.rs` *(new)*, `crates/architecture-tests/tests/audit_log_scope.rs` *(new)* | ARCH-1a/1b/1c | 6 |

Matches project-plan §9's cut (`crates/rvc/src` + `bin/rvc` = A; `crates/slashing` + `crates/signer` +
`architecture-tests` = B) with one correction it forces: because of **VD-E2**, Stream B's Phase-1 work
extends into `crates/signer/{lib.rs,gate.rs}` — still Stream-B-owned territory, still zero overlap with
Stream A, and the same developer picks those files up again in W2 for Phase 5.

**Files nobody may touch in this phase:** `crates/slashing/src/stage.rs` (byte-unchanged pin — A-12),
`crates/rvc/src/config/builder.rs:394` (single signing-gate wiring site — C9 anchor 5),
`crates/signer/src/core.rs:542` (`spawn_blocking`, C9 anchor 7),
`crates/architecture-tests/src/lib.rs` (`CLASSIFICATION`, C9 anchor 1), and the four orphan paths (C10).

### Execution plan — single developer (14–21 d)

ARCH-1a/1b/1c go first even single-stream: project-plan §9 says so explicitly ("**If only one developer
is available, do 1A first anyway** — it is the cheapest removal of a live availability hazard").

| Day | Issue | Note |
|---|---|---|
| 1–3 | ARCH-1a → ARCH-1b → ARCH-1c | One PR, four commits. Live hazard closed first |
| 4 | ARCH-6a (spike) | Cheap, and its verdict sizes ARCH-6b. Run it early |
| 5–6 | ARCH-5a | Gate before change (§1.1) |
| 7 | ARCH-5b | `CLAP_DEFAULT_CLOBBERS` visible in CI **before** ARCH-6b fixes it |
| 8–9 | ARCH-6b | `CLOBBERS` shrinks to empty |
| 10 | ARCH-2a | VD-E1 prerequisite |
| 11–12 | ARCH-2b | |
| 13–15 | ARCH-2c | The phase's largest risk (R6) |
| 16 | ARCH-3 | Free win once `PubkeyMap` is live for provider keys too |
| 17–18 | ARCH-4a | New `ValidatorStore` API — separate crate, separate PR |
| 19–21 | ARCH-4b | Wiremock rotation + negative tests |

### Execution plan — two developers (11–17 d)

| Window | Stream A | Stream B |
|---|---|---|
| d1–d3 | ARCH-6a, ARCH-5a | ARCH-1a → ARCH-1b → ARCH-1c |
| d4–d6 | ARCH-5b → ARCH-6b | **departs to Phase 5 entry (5A — M3 load harness)** |
| d7–d12 | ARCH-2a → ARCH-2b → ARCH-2c | 5A continues |
| d13–d17 | ARCH-3, ARCH-4a → ARCH-4b | 5A continues |

The speedup is sub-linear (~1.3× here) and that is expected: Stream A is a genuine dependency chain, and
the 2× only appears at the *initiative* level, where Phase 5 comes off the critical path (plan §9).

---

## 6. Issues

### ARCH-1a — `PendingAudit` hand-off in `scoped.rs` + thread-bounded RED deadlock harness

- **Points:** 2 · **Type:** fix · **Priority:** P0 · **Stream:** B · **Blocked by:** — · **Scope:** 1–1.5 days
- **Requirements:** ARCH-P0-9 (ADR-006) · **Constraints:** **C2** (is the requirement), **C9** anchors 2, 3, 6
- **Merges as one PR with ARCH-1b and ARCH-1c** (project-plan §1.1: G-7 cannot precede its change, so
  change + gate land together with RED demonstrated locally and pasted into the PR).

**Context.** `crates/slashing/src/scoped.rs:75` calls `audit_log(&self.client_cn, pubkey_hex, outcome)`
while the `StagedBlock` returned by `:68` still owns the connection `MutexGuard`; the attestation path
repeats it at `:106`. The code documents the hazard against itself at `:70-74` and `:103-105`: a tracing
subscriber that reads the DB deadlocks, because `parking_lot` mutexes are non-reentrant. An operator who
adds an ordinary audit subscriber stops **all** signing, permanently, with no timeout, while the process
continues to report healthy.

**VD-E2 — read this before starting.** ADR-006's "hard-bounded to `scoped.rs`" cannot be met on the
success path: `stage_block` *returns* the guard, so no in-file point exists where the mutex is free.
Only the `Err` path is fixable in-file. This issue therefore changes the **return type**; ARCH-1b
changes the four callers. The constraint that actually matters — `git diff <base> --
crates/slashing/src/stage.rs` empty — is untouched.

**Files to touch.**
- `crates/slashing/src/scoped.rs` — both methods, both `NOTE` blocks, the new type.
- `crates/slashing/src/lib.rs` — **one line**: `pub use scoped::PendingAudit;` next to `:21`. Verified
  necessary, not assumed: every module in this crate is **private** (`mod audit;` `:6`, `mod scoped;`
  `:12`, `mod stage;` `:13` — none is `pub mod`) and the public surface is an explicit `pub use` list at
  `:16-23`. Without that line `PendingAudit` is unnameable from `crates/signer`. Do **not** add a module
  and do **not** make any existing `mod` public.
- `crates/signer/tests/audit_subscriber_deadlock.rs` *(new)* — the RED harness (A-1.8).
- **Not** `crates/slashing/src/stage.rs`. **Not** `crates/slashing/src/audit.rs` (VD-E7 — `audit_log`
  stays a thin `tracing::info!` wrapper; no queue, no drainer, no new channel).

**Implementation approach.**

```rust
/// Captured audit outcome whose emission is deferred until the staged guard is gone.
/// `#[must_use]` is the enforcement: a caller that forgets to emit gets a warning,
/// and `-D warnings` in CI turns that into a failure.
#[must_use = "the slashing audit record must be emitted after the staged guard is released"]
pub struct PendingAudit { client_cn: String, pubkey_hex: String, outcome: &'static str }

impl PendingAudit {
    /// Emit the record. Call ONLY after `commit()` / `discard()` has released the mutex.
    pub fn emit(self) { audit_log(&self.client_cn, &self.pubkey_hex, self.outcome); }
}

// Err path: no guard was ever created, so emit "rejected" immediately, in-file.
// Ok path: hand the record to the caller alongside the guard.
pub fn stage_block<'db>(&'db self, pubkey_hex: &str, slot: Slot, signing_root_hex: Option<String>)
    -> Result<(StagedBlock<'db>, PendingAudit), SlashingError>;
pub fn stage_attestation<'db>(&'db self, pubkey_hex: &str, source_epoch: Epoch, target_epoch: Epoch,
                              signing_root_hex: Option<String>)
    -> Result<(StagedAttestation<'db>, PendingAudit), SlashingError>;
```

**Replace** the `:70-74` and `:103-105` `NOTE` blocks with the new ordering guarantee — ADR-006 says
replace, not edit around. The new documented contract: `"rejected"` is emitted synchronously with the
rejection; `"staged"` is emitted after the caller releases the guard, so it now correlates with
commit/discard rather than preceding it. That re-ordering is an **accepted consequence** of ADR-006, not
a defect — say so in the doc comment.

**Alternatives rejected (record them in the PR description, not just here).**
1. *Defer inside `audit_log`.* Needs a queue + drainer in `crates/slashing` → a new channel → **C9
   anchor 6**. Rejected (VD-E7).
2. *`Drop`-based emission on a wrapper struct.* Relies on field drop order for correctness and fires
   during panic unwind; `commit()` consumes the guard so the wrapper cannot own both cleanly. Too clever
   for a safety-adjacent file.
3. *Make the mutex reentrant, or document "do not write such a subscriber".* Both rejected by ADR-006 —
   the first changes the lock's safety characteristics for an observability convenience, the second is
   the enforced-by-discipline pattern G-7 exists to end.

**TDD test plan.**
- **RED (write first, must fail before any fix):**
  `crates/signer/tests/audit_subscriber_deadlock.rs::db_reading_subscriber_completes_a_full_stage_sign_commit`.
  It installs a `tracing` subscriber whose `on_event` acquires the same slashing DB lock, then drives a
  full stage → sign → commit on a `std::thread`, signalling completion over
  `std::sync::mpsc::channel`. The assertion is `rx.recv_timeout(Duration::from_secs(5)).is_ok()`.
  **Against HEAD it times out** (that is RED); after ARCH-1b it passes.
  **Do not use `tokio::time::timeout`** — the blocking `parking_lot` lock is not an await point, so the
  future is uncancellable and the test hangs the `nextest` run instead of failing it.
- **GREEN, in this issue:** `stage_block_rejection_emits_audit_without_holding_the_guard` — a double
  proposal returns `Err` and the `"rejected"` event is captured by a `tracing_test`-style subscriber
  (mirror the existing `audit_log_truncates_pubkey` idiom at `audit.rs:52-60`).
- **GREEN, in this issue:** `pending_audit_is_must_use` — a compile-fail/`trybuild`-style check is
  optional; if not taken, assert instead that `PendingAudit` carries `#[must_use]` by relying on
  `-D warnings` in CI and say so in the PR.
- **Regression, unmodified:** all eight existing `scoped.rs` unit tests (`:126-290`) must stay green
  after mechanical call-shape updates only.
- **KAT-first (C9 anchor 3):** the new test names carry **no** `_root` / `_tree_hash` / `_signing_root`
  suffix, so they do not enter `kat_policy`'s scanner scope. The harness does construct a signing-root
  value (`hex::encode(signing_root)` as at `signer/src/lib.rs:724`); if any assertion pins that literal,
  reuse an existing `KAT_*`/`EXTERNAL_*` constant or carry `// kat_exempt: <reason>`. `EXEMPTIONS` must
  not grow.

**Acceptance criteria.**
- [x] `PendingAudit` exists, is `#[must_use]`, and is the only way a `"staged"` event is emitted.
- [x] `scoped.rs` contains **no** `audit_log` call on the `Ok` path of either method.
- [x] The `Err` path of both methods emits `"rejected"` and no guard exists at that point.
- [x] The `:70-74` and `:103-105` `NOTE` blocks are **replaced** by the new ordering guarantee, which
      states explicitly that `"staged"` now correlates with commit/discard.
- [x] The RED test exists, is thread-bounded, and its failing output against the pre-change tree is
      pasted into the PR.
- [x] `git diff <base> -- crates/slashing/src/stage.rs` is **empty**.
- [x] No new channel of any kind in `crates/slashing`.
- [x] `EXEMPTIONS` in `kat_policy.rs` has not grown.

---

### ARCH-1b — Migrate the four `crates/signer` stage call sites; deadlock test goes GREEN

- **Points:** 2 · **Type:** fix · **Priority:** P0 · **Stream:** B · **Blocked by:** ARCH-1a · **Scope:** 1–1.5 days
- **Requirements:** ARCH-P0-9 · **Constraints:** **C2**, **C9** anchors 2, 5, 7

**Context.** VD-E2: four production call sites consume `PubkeyScopedDb::stage_*` and must now bind the
`PendingAudit` and emit it after the guard is released.

**Files to touch — exactly these four sites, and nothing else in `crates/signer`.**

| Site | Path | What it is |
|---|---|---|
| 1 | `crates/signer/src/lib.rs:721-724` | VC block path, `PubkeyScopedDb::new(db, AUDIT_CN_VC, gvr)` at `:721`, `.stage_block(...)` at `:724` |
| 2 | `crates/signer/src/lib.rs:619-622` | VC attestation path, `:619` / `.stage_attestation(...)` at `:622` |
| 3 | `crates/signer/src/gate.rs:279-282` | `SigningGate` block path |
| 4 | `crates/signer/src/gate.rs:365-368` | `SigningGate` attestation path |

**Implementation approach.** At each site the shape becomes:

```rust
let (staged, audit) = scoped.stage_block(&pubkey_hex_clone, slot, Some(hex::encode(signing_root)))?;
// ... sign ...
staged.commit()?;   // or staged.discard();  -- the guard is released HERE
audit.emit();       // ... and only now does the subscriber run
```

Emit **on both branches** — after `commit()` *and* after `discard()` — so a discarded sign is still
audited. Do **not** move the `emit()` before the commit/discard; do **not** hoist it out of the
`spawn_blocking` closure into async context (that would change which thread emits and is not required).

**Hard prohibitions for this issue.**
- `crates/signer/src/core.rs`'s **production** code (`:1-565`) is not modified — in particular the
  `spawn_blocking` at `core.rs:542` is untouched (**C9** anchor 7) — and no new signing surface is
  introduced (**C9** anchor 5 — `crates/rvc/src/config/builder.rs:394` stays the single wiring site).
  Its `#[cfg(test)] mod tests` (from `:566`) **does** change, mechanically — see the six call-shape
  updates budgeted in the test plan. Writing this bound as "`core.rs` is byte-unchanged" would be
  **unsatisfiable**, because the test module lives in the same file; that is the same class of
  file-level bound VD-E2 corrects, so it is spelled out rather than inherited.
- `crates/slashing/src/stage.rs` stays byte-unchanged.
- The retain-on-ambiguity semantics (**C1**) are **not** in scope: this issue changes *when an audit
  event is emitted*, never *whether a row is committed*. Any diff that alters a `commit()`/`discard()`
  decision is out of scope and must be rejected in review.

**TDD test plan.**
- **RED → GREEN:** ARCH-1a's `db_reading_subscriber_completes_a_full_stage_sign_commit` flips to
  passing. This is the issue's primary proof.
- **New:** `discarded_sign_still_emits_a_staged_audit_event` — drive a stage then `discard()`, assert the
  event fires exactly once.
- **New:** `audit_event_fires_after_the_guard_is_released` — a subscriber records
  `db.try_lock().is_some()` at event time and asserts it is `true`. This is what makes the fix
  *behavioural* rather than merely structural, and it is the assertion G-7 cannot make.
- **Regression, unmodified:** the 38 in-tree EIP-3076 conformance vectors
  (`crates/slashing/tests/conformance/*.json`, runner `conformance.rs:8-21`) stay green — necessary but
  **not sufficient** proof here (architecture §7.1 anchor 2); the three tests above are the sufficient
  part for this change class.
- **Regression:** the existing `crates/signer/src/core.rs` test module (`:566-960`) constructs
  `PubkeyScopedDb` and calls `stage_block` at `:678`, `:757`, `:800`, `:853`, `:899`, `:947` — six
  **test** sites that need the same mechanical shape update. Budgeted here; they are test-only and
  outside the production migration list.

**Acceptance criteria.**
- [x] All four production sites bind and emit `PendingAudit`, on both the commit and discard branches.
- [x] `db_reading_subscriber_completes_a_full_stage_sign_commit` passes within its 5 s thread timeout.
- [x] `audit_event_fires_after_the_guard_is_released` asserts the lock is free at emission time.
- [x] `rg 'audit_log' crates/` shows call sites only in `crates/slashing/src/audit.rs` (definition),
      `scoped.rs` (the `Err` path), and `PendingAudit::emit`.
- [x] `crates/slashing/src/stage.rs` is byte-unchanged, and `crates/signer/src/core.rs`'s **production**
      code (`:1-565`) is unchanged — only its `#[cfg(test)]` module's six call shapes are updated.
- [x] All 38 EIP-3076 conformance vectors green.
- [x] `cargo clippy -p rvc-signer-bin --all-targets --features dvt -- -D warnings` green (Gate 1) — the
      DVT surface consumes `SigningGate` and is outside the default workspace run (`clippy.toml:21-24`).

---

### ARCH-1c — G-7 `audit_log_scope.rs` scanner + synthetic RED

- **Points:** 2 · **Type:** chore · **Priority:** P0 · **Stream:** B · **Blocked by:** ARCH-1a · **Scope:** 1–1.5 days
- **Requirements:** ARCH-P0-9 (the gate half), architecture §6 G-7 · **Constraints:** **C2**, **C9** anchor 1

**Context.** ADR-006's second half: a scanner asserting **no `audit_log` call site is lexically inside a
scope holding a staged guard**, over *both* paths. Without it, the next refactor re-introduces the
landmine and CI says nothing — the exact enforced-by-discipline failure the gate exists to end.

**Files to touch.**
- `crates/architecture-tests/tests/audit_log_scope.rs` *(new file — F14; C9 anchor 1 forbids modifying
  `src/lib.rs` or any existing gate)*.

**Implementation approach.** Brace-aware scope tracking, the same technique `kat_policy.rs` already uses
for brace-aware extraction — read it first and mirror its idiom rather than inventing a second one. The
scan: for every file under `crates/slashing/src/**` and `crates/signer/src/**`, find each `audit_log(`
call; walk **backwards** through enclosing brace scopes; fail if any binding still live at that point was
produced by a `stage_block(` / `stage_attestation(` call. Report file, line and the offending binding.

**Non-vacuity — mandatory.** A scanner that finds nothing to scan is green forever. Assert:
`assert!(scanned_files >= 2)` and `assert!(stage_call_sites_found >= 6)` (2 in `scoped.rs`, 4 in
`crates/signer` — VD-E2), so a rename or a file move turns the gate red rather than silent.

**TDD test plan.**
- **RED (demonstrated locally, pasted into the PR — never merged red):** run the scanner against the
  pre-ARCH-1a tree; it must name `crates/slashing/src/scoped.rs:75` **and** `:106`. Capturing both is the
  point — the review's citation covers only the first (VD-S5).
- **GREEN:** `no_audit_log_call_is_inside_a_staged_guard_scope` passes on the post-ARCH-1b tree.
- **Synthetic RED, permanent:** `scanner_flags_a_synthetic_in_scope_audit_call` feeds the matcher an
  in-memory source fixture containing `let s = db.stage_block(..); audit_log(..); drop(s);` and asserts
  it is flagged. This is what keeps the gate falsifiable after the real defect is gone.
- **Synthetic GREEN:** `scanner_accepts_emission_after_the_guard_is_consumed` — the `PendingAudit` shape
  must not be flagged.

**Acceptance criteria.**
- [x] `crates/architecture-tests/tests/audit_log_scope.rs` exists; no existing gate file and no
      `architecture-tests/src/lib.rs` line is modified.
- [x] The gate names file **and** line for each violation.
- [x] Both non-vacuity assertions present.
- [x] Both synthetic fixtures (RED and GREEN) present.
- [x] `cargo nextest run -p rvc-architecture-tests` green in the `arch-gates` CI job (Phase 0's A-P1).
- [x] The pre-change RED output, naming both `:75` and `:106`, is pasted into the PR.

---

### ARCH-2a — Relocate the secret-provider refresh spawn (VD-E1 prerequisite)

- **Points:** 2 · **Type:** refactor · **Priority:** P0 · **Stream:** A · **Blocked by:** — · **Scope:** 1–1.5 days
- **Requirements:** ARCH-P0-5 (enabling half) · **Constraints:** **C4** (prepares it), **C9** anchor 6

**Context — this issue exists because of VD-E1 and appears in no upstream document.** ADR-007 §5.2 says
the closure body at `bootstrap/enablement.rs:172-190` "collapses to
`admissions.admit(sk, AdmissionSource::RawSecret)`". It cannot, at that location: `KeyAdmissionService`
needs `validator_store` and `key_gen_tx`, and at HEAD `wire_signing_enablement` is called at
`run.rs:127-135` — **before** `build_services` produces `validator_store` (`:138-146`) and **before**
`key_gen_tx` is created (`:190`). Attempting ARCH-2b without this issue ends in a compile error and an
ad-hoc redesign under time pressure.

**Files to touch.**
- `crates/rvc/src/bootstrap/enablement.rs` — remove the refresh block (`:152-194`) and its now-unused
  locals; `EnablementHandles` keeps its six fields.
- `crates/rvc/src/bootstrap/run.rs` — re-site the block after `key_gen_tx` (`:190`); un-discard
  `local_pubkeys: _` (`:159`) and `secret_providers: _` (`:161`) from the `LoadedKeys` destructure, which
  `RefreshService::with_denylist` needs (`enablement.rs:159-165`).
- **Not** `crates/secret-provider/**` — its public surface is unchanged by this issue.

**Implementation approach.** Move, do not rewrite: extract the block into a private
`fn spawn_secret_provider_refresh(...) -> Option<JoinHandle<()>>` in `run.rs` (or a small sibling module)
that takes `&Config`, the providers, `local_pubkeys`, `denylist`, `composite_signer`,
`forward_window_machine`, `epoch_clock` and `shutdown`. Keep the callback body **byte-identical** for
now — ARCH-2b/2c replace it. This issue is a pure relocation so its diff is reviewable as such and so a
regression can be bisected to "the move" or "the service", never both.

**Verified non-issue, state it in the PR:** `RefreshService::run` sleeps `self.interval` before its first
fetch (`crates/secret-provider/src/refresh.rs:184-186`), so relocating the spawn later in `run()` changes
no startup timing and no first-refresh deadline (A-1.2).

**Watch out for.** The `tokio::spawn` at `enablement.rs:170` moves with the block and stays a raw spawn —
**do not** migrate it to a `TaskExecutor`; ADR-001 is Phase 2 and G-4's migration list is derived there.
Moving the site is fine; changing its mechanism is scope creep into another phase.

**TDD test plan.**
- **RED:** `secret_provider_refresh_is_spawned_after_key_gen_channel_exists` — a bootstrap-level test (or,
  if wiring a full `run()` is impractical, a `#[test]` over the extracted function's signature) asserting
  the refresh spawner accepts a `watch::Sender<u64>` and an `Arc<ValidatorStore>`. Against HEAD it does
  not compile / does not exist. Keep it minimal; its job is to pin the ordering, not to test refresh.
- **Regression:** existing `enablement.rs` tests and `crates/rvc/tests/**` bootstrap tests green,
  unmodified.
- **Behaviour parity:** a test with `refresh_interval = 0` or no providers asserts **no** task is
  spawned — preserving the `refresh_interval > 0 && !secret_providers.is_empty()` guard at
  `enablement.rs:155`.

**Acceptance criteria.**
- [x] `rg 'RefreshService' crates/rvc/src/bootstrap/enablement.rs` returns nothing.
- [x] The refresh spawn site in `run.rs` is lexically **after** the `key_gen_tx` creation and has
      `validator_store` in scope.
- [x] The callback body is byte-identical to `enablement.rs:172-190` at HEAD (diff-checkable).
- [x] The `refresh_interval > 0 && !secret_providers.is_empty()` guard is preserved and tested.
- [x] `local_pubkeys` and `secret_providers` are no longer discarded in `run.rs`'s destructure.
- [x] No new channel; the relocated `tokio::spawn` is not converted to anything else.
- [x] Standing invariants green.

---

### ARCH-2b — `KeyAdmissionService`: the seam and `admit`

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Stream:** A · **Blocked by:** ARCH-2a · **Scope:** 1.5–2 days
- **Requirements:** ARCH-P0-5 (ADR-007, architecture §5.2) · **Constraints:** **C4** (binding), **C5** (by abstention — A-1.4), **C9** anchors 5, 6

**Context.** The review describes a component that does not exist. Verified (F2): `KeyChangeNotifier` is
61 lines with two fields — `PubkeyMap` and `key_gen_tx` — and touches neither the composite signer, nor
`ValidatorStore`, nor the denylist, nor doppelganger. **This is a build, not a rewiring** (VD-5/R6, and
the plan's stated reason Phase 1 exceeds the review's "1–2 weeks"). Equally verified (F3): the review's
stated defect — "register the refreshed keys with doppelganger" — is a **no-op**; `enablement.rs:187`
already does it. The real defect is the three stores the provider path never reaches: `PubkeyMap`,
`ValidatorStore`, `key_gen_tx`; and the *mechanism* of the "stuck `Pending`" symptom is **starvation**
(F5), because the liveness loop samples from `PubkeyMap` only.

**Files to touch.**
- `crates/rvc/src/key_admission.rs` *(new module)* — the seam. Register it in `crates/rvc/src/lib.rs`.
- `crates/rvc/src/keymanager_adapters/notifier.rs` — **unchanged in behaviour**; `KeyChangeNotifier`
  becomes an internal collaborator of the admission service. Do not delete it, do not widen it.
- **Not** `crates/rvc/src/bootstrap/**` (ARCH-2c switches the callers).

**Implementation approach — the seam, per architecture §5.2.**

```rust
pub enum AdmissionSource { Keystore { keystore_path: PathBuf }, RawSecret }
pub enum AdmissionOutcome {
    Admitted { pubkey: [u8; 48], key_gen: u64 },
    SkippedDenylisted { pubkey: [u8; 48] },   // NOT an error
    AlreadyPresent { pubkey: [u8; 48] },      // idempotent no-op
}
#[derive(Debug, thiserror::Error)]
pub enum AdmissionError { /* thiserror per CLAUDE.md — this is a library seam, no anyhow */ }

pub struct KeyAdmissionService { notifier, composite_signer, validator_store, denylist,
                                 machine: Option<Arc<ForwardWindowMachine>>, epoch_clock }

impl KeyAdmissionService {
    pub fn admit(&self, secret: SecretKey, source: AdmissionSource)
        -> Result<AdmissionOutcome, AdmissionError>;
}
```

`admit` performs, **in this order**: denylist re-check → composite signer (`add_local_key`) →
`PubkeyMap` → `ValidatorStore` (`add_validator`, F15) → doppelganger `register_for_import` →
`key_gen_tx` bump. The generation bump is **last** so no orchestrator wake observes a half-populated
key set.

**`admit` is synchronous — a decision, not a discovery (A-1.3).** F6: the only provider-side caller is
`RefreshService::run<F> … where F: Fn(SecretKey)`, a non-`async` bound. Every store touched is
`parking_lot`/`watch`-guarded and synchronously updatable, so this costs nothing. **Write this rationale
into the `admit` doc comment**, with the rejected alternative (changing `RefreshService`'s bound to an
async callback — a `crates/secret-provider` API break).

**C4 is binding.** `AdmissionSource::RawSecret` is a **first-class mode**, not an error path: no keystore
file, no filesystem write, no denylist row required. Two designs are explicitly rejected — writing a
synthetic keystore to disk (invents a secret-at-rest artefact for a key whose entire point is that it
lives in a cloud secret manager) and failing admission when no keystore is present.

**C5 is honoured by abstention (A-1.4).** `withdraw` is **not** built here. It encodes the
`stop_monitoring` vs `cancel_monitoring` contract, and **G-6 does not exist at HEAD** (VD-6) — it lands in
Phase 7 before ADR-015's retirement. This issue must not collapse the two methods, must not add a
teardown call of either kind, and must leave the keymanager adapters' existing DELETE path alone.

**TDD test plan.**
- **RED (write first):** `admit_raw_secret_reaches_pubkey_map_validator_store_and_bumps_key_gen` —
  construct the service over in-memory stores, call `admit(sk, AdmissionSource::RawSecret)`, assert the
  pubkey is in `PubkeyMap`, that `validator_store.has_validator(&pk)` is true, and that `key_gen_rx`
  observed a bump. Fails at HEAD because the type does not exist.
- `admit_denylisted_key_returns_skipped_and_touches_no_store` — the DELETE-races-refresh guard
  (`enablement.rs:174-183`, F4), tested directly and asserted to be `SkippedDenylisted`, **not** an `Err`.
- `admit_is_idempotent_and_returns_already_present` — second call for the same pubkey does not double-bump
  `key_gen_tx`.
- `admit_raw_secret_writes_nothing_to_the_filesystem` — **C4**'s direct test: run with a `tempdir` as CWD
  and assert it is empty afterwards.
- `admit_with_disabled_doppelganger_succeeds` — `machine: None` is a supported configuration
  (`enablement.rs:139-150` makes the machine optional).
- `key_gen_is_bumped_last` — a `watch` receiver that snapshots `PubkeyMap` on change observes the key
  already present.
- **Compile-level:** the service is usable from a `Fn(SecretKey)` closure (A-1.3) — a test that stores
  `admit` behind `impl Fn(SecretKey)` is the cheapest proof.

**Acceptance criteria.**
- [x] `KeyAdmissionService`, `AdmissionSource`, `AdmissionOutcome`, `AdmissionError` exist as specified;
      errors use `thiserror`, not `anyhow` (CLAUDE.md, library seam).
- [x] `admit` is synchronous and callable from an `Fn(SecretKey)` closure; the doc comment records why.
- [x] All six store updates happen in the stated order, with the `key_gen_tx` bump last.
- [x] `RawSecret` admission performs **no** filesystem write (asserted).
- [x] Denylist skip returns `SkippedDenylisted`, not an error, and mutates nothing.
- [x] `KeyChangeNotifier` is retained unchanged and is an internal collaborator.
- [x] **No `withdraw`**, no `stop_monitoring`/`cancel_monitoring` call, no change to the DELETE path
      (A-1.4 / C5).
- [x] `///` docs on every public item (CLAUDE.md); no `.unwrap()` in the module.
- [x] No new channel (C9 anchor 6); no new signing surface (C9 anchor 5).

---

### ARCH-2c — Switch both admission callers; prove the key leaves `Pending`

- **Points:** 3 · **Type:** feature · **Priority:** P0 · **Stream:** A · **Blocked by:** ARCH-2b · **Scope:** 1.5–2 days
- **Requirements:** ARCH-P0-5 · **Constraints:** **C4**, **C5** (abstention), **C9** anchor 5

**Context.** ARCH-2b built the choke point; this issue makes it the **only** admission path and proves
the outcome the requirement is actually about — that a provider-refreshed key stops starving.

**Files to touch.**
- `crates/rvc/src/bootstrap/run.rs` — construct the `KeyAdmissionService` and pass it to the relocated
  refresh spawner; the closure body collapses to `admissions.admit(sk, AdmissionSource::RawSecret)`.
- `crates/rvc/src/keymanager_adapters/` — the import adapters call
  `admit(sk, AdmissionSource::Keystore { keystore_path })`. **Their observable behaviour must not
  change**; existing adapter tests are the proof and must stay green **unmodified**.
- `crates/rvc/tests/` — the liveness-sampling integration test.

**Implementation approach.** Replace, do not wrap. After this issue, `rg 'add_local_key' crates/rvc/src`
should show the composite-signer call only inside `KeyAdmissionService::admit` (plus boot-time key
loading, which is a different path and stays). The denylist re-check moves **into** `admit` — verify it
is not left duplicated at the call site, and that its behaviour (log at `info` with a
`TruncatedPubkey`, then skip) is preserved exactly (F4).

**The acceptance that matters is not "it registers".** F3: registration already happens. The proof
obligation (architecture §7.2, ADR-007 row) is: `PubkeyMap` + `ValidatorStore` + `key_gen_tx` **plus** a
liveness-sampling test showing the key can leave `Pending`. Without the last one, the issue closes the
symptom's *description* and not the defect.

**TDD test plan.**
- **RED (the phase's headline test):**
  `crates/rvc/tests/provider_refreshed_key_is_sampled_by_the_liveness_loop.rs::a_provider_refreshed_key_leaves_pending`
  — drive one refresh tick delivering a new `SecretKey`, run the liveness loop against a mock BN that
  reports the validator as not-live for the forward window, and assert the key transitions out of
  `Pending`. Against HEAD it stays `Pending` forever, because the key never enters `PubkeyMap` and the
  loop samples only from there (F5). **This is the starvation defect, tested directly.**
- `refresh_admits_through_the_service_only` — a scan/unit assertion that the refresh closure body is a
  single `admit` call.
- `keymanager_import_admits_through_the_service` — same for the import path.
- **Regression, unmodified:** every existing keymanager adapter test. If one needs editing, that is a
  behaviour change and the design is wrong — stop and re-read ADR-007.
- `delete_then_refresh_race_skips_the_denylisted_key` — the guard at `enablement.rs:174-183`, now living
  in `admit`, still fires from the real refresh path.

**Acceptance criteria.**
- [x] Both callers go through `KeyAdmissionService::admit`; no second admission path exists.
- [x] A provider-refreshed key appears in `PubkeyMap` **and** `ValidatorStore`, bumps `key_gen_tx`, is
      registered with the forward-window machine, is **sampled by the liveness loop**, and leaves
      `Pending`.
- [x] A raw `SecretKey` is admitted with no keystore file and no filesystem write (C4).
- [x] The DELETE-races-refresh denylist guard is preserved and separately tested.
- [x] Existing keymanager adapter tests green, **unmodified**.
- [x] `crates/rvc/src/config/builder.rs:394` unchanged; no new signing surface (C9 anchor 5).
- [x] No `withdraw`, no teardown-contract change (A-1.4 / C5).

---

### ARCH-3 — Live validator counts in the monitoring push

- **Points:** 2 · **Type:** fix · **Priority:** P1 · **Stream:** A · **Blocked by:** — *(soft: ARCH-2c — see VD-E5)* · **Scope:** 1–1.5 days
- **Requirements:** ARCH-P0-7 (PB-B2; ADR-014's sibling) · **Constraints:** **C9** anchor 6

**Context.** `crates/rvc/src/bootstrap/tasks.rs:106` passes
`move || (validator_count as u32, validator_count as u32)` to the monitoring push. Verified (F7) this is
worse than the PRD states in **two** ways: the value is a `usize` captured **by value** (param `:79`),
computed once at `run.rs:223` as `pubkey_map.read().len()` and frozen for the process lifetime; **and**
both tuple elements are the same number, so "active" is a tautology of "total" even before the freezing
is considered. An operator watching a monitoring dashboard sees a constant regardless of imports,
deletes or enablement.

**VD-E5 — this issue is not blocked by ARCH-2c.** `spawn_background_tasks` is called at `run.rs:279`,
where `pubkey_map` (`:160`/`:223`) and `validator_store` (`:176`) are both in scope. The project plan's
"1B → 1C" is a **milestone** coupling (provider-refreshed keys only start being counted once ARCH-2c
lands), not a compile or merge dependency. Implement and test it against a **keymanager import**, which
already updates `PubkeyMap` today.

**Files to touch.**
- `crates/rvc/src/bootstrap/tasks.rs` — the `spawn_background_tasks` signature (`:75-80`) and the
  monitoring closure (`:103-107`). Its two existing tests call it with `0` (`:227`, `:245`) and need the
  new argument shape.
- `crates/rvc/src/bootstrap/run.rs:279` — the call site; `:223`'s `let validator_count = …` becomes
  unnecessary for this purpose (it is still used by `startup::log_orchestrator_started` at `:293`, which
  is a genuine boot-time log and stays).

**Implementation approach.** Replace the `validator_count: usize` parameter with the two live handles —
`pubkey_map: PubkeyMap` and `validator_store: Arc<ValidatorStore>` — and build the closure as

```rust
move || {
    let total   = pubkey_map.read().len() as u32;                       // keys loaded
    let active  = validator_store.list_enabled_pubkeys().len() as u32;  // signing-enabled
    (total, active)
}
```

`list_enabled_pubkeys` exists at `crates/validator-store/src/store.rs:247` (F15) — no new
`ValidatorStore` API is needed here (unlike ARCH-4a). **A-1.6** fixes the semantics: element 0 = total
loaded, element 1 = active/enabled. Record that mapping in the closure's doc comment, because the two
were indistinguishable before and any downstream dashboard reading them as distinct is currently wrong.

**Watch out for.** Do not take both locks in a nested scope — read `PubkeyMap` and drop the guard before
touching `ValidatorStore`. `ValidatorStore`'s own doc (`store.rs:100-107`) records that opposite-order
multi-lock acquisition previously caused deadlocks there; adding a *cross-store* nesting from a periodic
background task is the same footgun with a longer fuse.

**TDD test plan.**
- **RED:** `monitoring_count_reflects_a_keymanager_import` — snapshot the closure's output, import a key
  through the existing keymanager adapter, call it again, assert the total increased. At HEAD the value
  is frozen, so it fails.
- **RED:** `monitoring_count_reflects_a_delete` — the mirror case through `remove_and_notify`.
- **RED:** `total_and_active_are_distinct_when_a_validator_is_disabled` — load two validators, call
  `set_enabled(&pk, false)` (`store.rs:273`) on one, assert `(2, 1)`. At HEAD this returns `(2, 2)` and is
  the sharpest single proof the tautology is gone.
- **Regression:** `tasks.rs`'s two existing tests (`:227`, `:245`) green after the signature change.
- **Behaviour parity:** with no monitoring endpoint configured, no task is spawned (guard at `:91`).

**Acceptance criteria.**
- [x] `spawn_background_tasks` no longer takes a `usize` count; the closure reads live state on each call.
- [x] The two tuple elements mean different things and the closure's doc comment says which is which.
- [x] Import, delete and disable each change the pushed values (three tests).
- [x] No nested `PubkeyMap` + `ValidatorStore` lock scope.
- [x] `run.rs:293`'s boot-time `log_orchestrator_started` count is unchanged (it is legitimately
      boot-time).
- [x] No new channel; no new task.

---

### ARCH-4a — `ValidatorStore` default-update API + the `config_url` → store mapping

- **Points:** 2 · **Type:** feature · **Priority:** P1 · **Stream:** A · **Blocked by:** — · **Scope:** 1–1.5 days
- **Requirements:** ARCH-P0-6 (PB-B1) · **Constraints:** **C9** anchor 1 (no `architecture-tests` change; note this issue adds **no** production crate edge — `crates/rvc` already depends on `validator-store`, so no `ARCHITECTURE.md` regeneration is due)

**Context.** ARCH-P0-6 says the apply callback must write fetched updates "and the `_default` currently
discarded by name" to `ValidatorStore`. Two verified obstacles the PRD treats as free:

- **VD-E3 — two different types share the name `ValidatorConfigUpdate`.**
  `crates/validator-store/src/config.rs:31-38` has `{ fee_recipient: Option<Option<[u8;20]>>, gas_limit:
  Option<Option<u64>>, graffiti, builder_proposals: Option<bool>, builder_boost_factor,
  block_selection_mode }` — **no `pubkey` field**. `crates/rvc/src/background_tasks/config_url.rs:41-46`
  has `{ pubkey: String, fee_recipient: Option<String>, builder_enabled: Option<bool>, gas_limit:
  Option<u64> }`. The mapping is therefore fallible (hex parsing) and involves a field rename
  (`builder_enabled` → `builder_proposals`).
- **VD-E4 — there is no public way to write the store's defaults.** They are set only by
  `reload_config` from the config *file* (`store.rs:395-419`, assignment at `:416`) and by crate-private
  test writes (`:605`, `:1417-1418`). The `default_config` entry is parsed at `config_url.rs:98-99` under
  the literal pubkey `"default"`.

**Files to touch.**
- `crates/validator-store/src/store.rs` — new `pub fn apply_default_update(&self, update: DefaultUpdate)`
  applying `fee_recipient` / `gas_limit` / `graffiti` under **one** write guard, mirroring
  `update_config`'s single-guard discipline (`:306-309`) and `reload_config`'s atomic-transition comment
  (`:412-416`).
- `crates/validator-store/src/config.rs` — `DefaultUpdate` (a partial-update sibling of
  `ValidatorDefaults`, `:93-98`).
- `crates/rvc/src/background_tasks/config_url.rs` — a `to_store_update` conversion returning
  `Result<([u8;48], validator_store::ValidatorConfigUpdate), ParseError>`, plus a `default` variant. Do
  **not** rename either existing type in this issue — the collision is recorded as an M9 row for Phase 6
  (ARCH-P1-9's territory), and renaming here would widen the diff into another phase's scope.

**Implementation approach.** Pure, side-effect-free mapping functions with their own unit tests, plus one
new store method. Deliberately separated from the wiring (ARCH-4b) so the fallible parsing is reviewed on
its own, and because `crates/validator-store` is a different crate and therefore a cleanly revertible PR
(NFR-4).

Parsing rules to decide **explicitly** (they are the whole risk surface):
- `fee_recipient: Option<String>` → `[u8;20]`: accept with or without `0x`, case-insensitive; a malformed
  value is an `Err`, never a silent default. `Some(bad)` must not become `None`.
- `pubkey: String` → `[u8;48]`: same rules; the literal `"default"` is routed to the defaults path and is
  **not** a parse failure.
- `gas_limit` is already `u64` on both sides (parsed at `config_url.rs:106`); no work.
- `builder_enabled` → `builder_proposals`, a straight rename across the seam.
- `ValidatorConfigUpdate`'s `Option<Option<T>>` shape means "field absent" vs "field explicitly cleared".
  A proposer-config entry that omits `fee_recipient` maps to the **outer `None`** (leave alone), never to
  `Some(None)` (clear it). Getting this backwards silently resets every fee recipient to the default —
  name it in the PR description and pin it with a test.

**TDD test plan.**
- **RED:** `apply_default_update_changes_the_store_defaults` — call the new method, assert
  `default_fee_recipient()` (`store.rs:176`) returns the new value. Does not compile at HEAD (VD-E4).
- `to_store_update_maps_builder_enabled_to_builder_proposals`.
- `to_store_update_rejects_a_malformed_fee_recipient` — asserts `Err`, and asserts the value did **not**
  silently become `None`.
- `an_absent_fee_recipient_maps_to_outer_none_not_some_none` — the field-clearing trap above.
- `the_literal_default_pubkey_routes_to_the_defaults_path` — pins `config_url.rs:99`'s `"default"`
  convention.
- `apply_default_update_is_a_single_write_guard` — assert via a concurrent reader that no intermediate
  state (new fee recipient + old gas limit) is observable.
- **Regression:** `crates/validator-store`'s existing test suite green, unmodified.

**Acceptance criteria.**
- [x] `ValidatorStore::apply_default_update` exists, is `///`-documented, and applies under one write
      guard.
- [x] A total mapping exists from `config_url::ValidatorConfigUpdate` to
      `([u8;48], validator_store::ValidatorConfigUpdate)`, with parse failures surfaced as `Err`.
- [x] Absent fields map to the outer `None`; the clearing semantics are tested.
- [x] Neither existing `ValidatorConfigUpdate` type is renamed (the M9 collision is deferred, not fixed).
- [x] No `.unwrap()`; `thiserror` for the new error type (library crate).
- [x] No new workspace dependency edge, so no `ARCHITECTURE.md` regeneration is due.

---

### ARCH-4b — Wire the proposer-config apply callback; rotation and negative tests

- **Points:** 2 · **Type:** fix · **Priority:** P1 · **Stream:** A · **Blocked by:** ARCH-4a · **Scope:** 1–1.5 days
- **Requirements:** ARCH-P0-6 · **Constraints:** **C9** anchor 6

**Context.** F8: `tasks.rs:124-137` passes `move |updates, _default| { for update in &updates { info!(…) } }`
— it logs each update and writes nothing, discarding the default entry by name. The URL is fetched, the
HTTPS check runs, the metrics increment (`config_url.rs:134`, `:162`), and the result is thrown away.
This is the canonical inert surface (PB-B1) and the pattern the PRD names as having produced this whole
requirement class.

**Files to touch.**
- `crates/rvc/src/bootstrap/tasks.rs` — **only** the callback body at `:124-137`. This issue **consumes**
  the `validator_store: Arc<ValidatorStore>` parameter that **ARCH-3 introduces**; it does not add a
  signature change of its own. If ARCH-3 has not landed, add the parameter here instead and say so —
  but do not let both PRs claim the same edit.
- `crates/rvc/src/bootstrap/run.rs:279` — no change if ARCH-3 landed first (the store is already passed).
- `crates/rvc/tests/` — the wiremock-backed rotation test.

**Merge-conflict note (intra-stream).** ARCH-3 and ARCH-4b both edit `spawn_background_tasks`'s signature
and adjacent closures (`:103-107` vs `:124-137`). They are in the **same** stream, so this is a sequencing
note, not a cross-stream hazard: land **ARCH-3 first**, which introduces `validator_store` into the
signature, and ARCH-4b then only edits its own closure body.

**Implementation approach (A-1.5 — apply, do not reject).** The callback becomes:

```rust
move |updates, default_update| {
    if let Some(d) = default_update {
        match d.to_default_update() {
            Ok(u)  => validator_store.apply_default_update(u),
            Err(e) => warn!(error = %e, "proposer config default entry ignored"),
        }
    }
    for update in updates {
        match update.to_store_update() {
            Ok((pk, u)) => validator_store.update_config(&pk, u),
            Err(e)      => warn!(error = %e, "proposer config entry ignored"),
        }
    }
}
```

A malformed entry is skipped at `warn` and **leaves the previous value intact** — never a partial write,
never a panic, never a silent reset. That is a stated acceptance criterion of ARCH-P0-6, not a nicety.

**Do not** widen scope into `crates/rvc/src/config/**`: the *startup-rejection* fallback (a named
`ConfigError` + exit code if the operator sets `proposer_config.url` and the plan chose reject-instead)
is **not** taken — A-1.5 chose apply. Record the fallback in the PR description so a reviewer can see it
was considered and why it lost.

**TDD test plan.**
- **RED (the requirement's own acceptance test):**
  `crates/rvc/tests/proposer_config_url_rotation.rs::a_rotated_fee_recipient_reaches_the_store` — a
  wiremock server serves a proposer config with fee recipient A, then B; drive one refresh tick after
  each; assert `validator_store.effective_fee_recipient(&pk)` (`store.rs:202`) returns B. Fails at HEAD.
- **RED:** `a_rotated_fee_recipient_reaches_the_next_block_proposal` — the PRD's second criterion; assert
  the proposal path reads the new value. If a full proposal harness is impractical inside this issue's
  budget, the acceptable substitute is asserting through the same accessor the proposal path uses, with
  the accessor named in the test comment — **state which was done**, do not leave it ambiguous.
- **RED:** `a_default_config_entry_updates_the_store_defaults` — the `_default` that is discarded by name
  today.
- **Negative:** `a_malformed_fee_recipient_leaves_the_previous_value_intact_and_warns`.
- **Negative:** `an_http_401_leaves_all_previous_values_intact` — exercises the existing failure branch
  (`config_url.rs:136-139`, `:164`+) and asserts the failure metric increments.
- **Regression:** `config_url.rs`'s existing parse tests (incl. `test_parse_no_default_config:290`) green,
  unmodified.

**Acceptance criteria.**
- [x] The apply callback writes to `ValidatorStore`; `rg '_default' crates/rvc/src/bootstrap/tasks.rs`
      returns nothing.
- [x] A rotated fee recipient is observable through `effective_fee_recipient` and reaches the next
      proposal.
- [x] The `default_config` entry updates the store's defaults.
- [x] A malformed entry warns and leaves the previous value intact (positively asserted, not just
      "no panic").
- [x] A failed fetch changes nothing and increments the existing failure metric.
- [x] No new channel, no new task; the existing refresh task's shape is unchanged.
- [x] **M7 accounting:** with ARCH-2c, ARCH-3 and this issue landed, three of the four verified inert
      surfaces are closed; the fourth (healthz `grpc_address`/`grpc_port`) is Phase 0's deprecation note
      plus Phase 7's removal, giving **M7 → 1**.

---

### ARCH-5a — G-2 `config_drift.rs`, clause (ii): the seam-α scanner

- **Points:** 3 · **Type:** chore · **Priority:** P1 · **Stream:** A · **Blocked by:** — · **Scope:** 1.5–2 days
- **Requirements:** ARCH-P1-1 (moved into this phase by **D6**) · **Constraints:** **C3** (prepares it), **C9** anchor 1

**Context.** Of the five config-declaration sites, **four seams** connect them and **three are already
compiler-enforced**. Verified (F11): `merge_cli_fields!` exhaustively destructures `CliOverrides`
(`types.rs:932-936`), so **clause (i) of ARCH-P1-1 is dropped, not forgotten** — a scanner for it can only
ever be green. Verified (F12): the one unguarded seam is **α** — the 13 group `Args` structs are read by
*field access* in `impl From<StartArgs> for CliOverrides` (`cli.rs:587-685`), while the destructure at
`:589-604` is exhaustive only over the 13 **group bindings**. Adding a field to `BeaconArgs` compiles
silently and is ignored at runtime.

**Files to touch.**
- `crates/architecture-tests/tests/config_drift.rs` *(new file — F14)*. Nothing else. In particular
  `bin/rvc/src/cli.rs` is **not** edited by this issue.

**Placement is forced, not preferred.** `bin/rvc/Cargo.toml:12-14` declares a `[[bin]]` and **no
`[lib]`**, so nothing outside can `use cli::Cli`; and Rust has no field reflection, so the `CliOverrides`
side must be scanned textually regardless. A typed `clap::CommandFactory` gate could only live as a unit
test inside `cli.rs` — exactly where the existing, hand-maintained and therefore non-binding
`test_start_help_lists_every_flag` (`cli.rs:1005-1015`) already sits.

**Implementation approach.** Textual scan in the `kat_policy.rs` idiom. For each of the 13 group structs,
enumerate its fields; assert each appears as `<binding>.<field>` in `From<StartArgs>`'s body, unless it is
on a shrinking-only table. **Both tables must carry a required reason string per entry**, mirroring the
KAT `EXEMPTIONS` convention.

**`BYPASS` — 8 entries, all verified at HEAD by reading `cli.rs:738-776`** (the architecture gives the
count and a line range but not the names; here they are, so a reviewer can check the table rather than
trust it):

| # | Field | Read at | Destination |
|---|---|---|---|
| 1 | `beacon.block_production_timeout` | `cli.rs:739` | `bn_manager::OperationTimeouts.block_production` (`:743`) |
| 2 | `beacon.attestation_timeout` | `:745` | `…attestation_fetch` (`:749`) |
| 3 | `beacon.aggregate_timeout` | `:751` | `…aggregate_fetch` + `…aggregate_submit` (`:755-756`) |
| 4 | `beacon.duty_fetch_timeout` | `:758` | `…duty_fetch` (`:762`) |
| 5 | `logging.log_format` | `:773` | `telemetry::LogFormat::resolve` (`:785`) |
| 6 | `logging.enable_log_reload` | `:774` | run options / logging init |
| 7 | `slashing.strict_permissions` | `:775` | run options |
| 8 | `slashing.strict_slashing_semantics` | `:776` | run options |

Entries 1–4 shrink when ADR-008 (Phase 4) gives the BN timeouts `Config` fields.

**`ALIASES` — 2 entries, opposite shapes (F13):** `no_doppelganger_detection` → `doppelganger_detection`,
a **1:1 negated rename** (`cli.rs:623-627`); `no_keymanager` + `keymanager_enabled` →
`keymanager_enabled`, a **2:1 collapse** (`:628-634`) and the sole `−1` in the arithmetic
**`74 − 8 − 1 = 65`**, which matches `CliOverrides`' 65 fields (`types.rs:1313`) exactly.

**Non-vacuity — mandatory.** `assert_eq!(bindings.len(), 13)` and `assert_eq!(checked, 74)`, so a rename
of `StartArgs` or a group cannot turn the gate green forever.

**Lifetime — state it in the file's module doc.** This gate is **interim by construction**: ADR-008's
collapse (Phase 4) deletes seam α, at which point clauses (i)/(ii) are deleted with it and only (iii) and
(iv) survive.

**TDD test plan.**
- **The gate is GREEN at HEAD** — the hole is real and unguarded but not yet exploited — so a
  demonstration against the live tree is impossible. The **only** available RED is a synthetic-input
  matcher unit test, and it is therefore mandatory:
  `seam_alpha_detector_flags_an_unread_field` feeds the matcher an in-memory fixture with a `BeaconArgs`
  field absent from `From<StartArgs>` and asserts it is flagged by name.
- `seam_alpha_detector_accepts_a_bypassed_field` — a `BYPASS` entry is not flagged.
- `seam_alpha_detector_accepts_an_aliased_field` — both alias shapes, including the 2:1 collapse.
- `every_bypass_and_alias_entry_carries_a_reason` — the tables cannot silently absorb a new field.
- `field_arithmetic_holds` — `74 − 8 − 1 == 65 == CliOverrides field count`, so a drift in any of the
  three numbers fails loudly rather than being reconciled by hand.
- **GREEN:** the gate passes against HEAD.

**Acceptance criteria.**
- [x] `crates/architecture-tests/tests/config_drift.rs` exists; no existing gate file and no
      `architecture-tests/src/lib.rs` line is modified.
- [x] Clause (ii) implemented; **clause (i) is explicitly documented as dropped with its rustc-enforcement
      reason** in the module doc (a reader who does not know this will read it as an oversight).
- [x] `BYPASS` has exactly 8 entries, each with a reason; `ALIASES` has exactly 2.
- [x] Both non-vacuity assertions present.
- [x] Four synthetic matcher tests present, including the mandatory RED.
- [x] The module doc states the gate's interim lifetime and what ADR-008 deletes.
- [x] Green in the `arch-gates` CI job.

---

### ARCH-5b — G-2 clauses (iii) `UNVALIDATED` and (iv) `CLAP_DEFAULT_CLOBBERS`

- **Points:** 2 · **Type:** chore · **Priority:** P0 · **Stream:** A · **Blocked by:** ARCH-5a · **Scope:** 1–1.5 days
- **Requirements:** ARCH-P1-1 (clause iii), **ADR-009** (clause iv) · **Constraints:** **C3** (indirect)

**Context.** Clause (iv) is **new** and is the reason ADR-009 is in this phase at all: it makes a live,
operator-facing precedence defect **visible in CI before anyone fixes it**, so a tenth instance cannot
appear while the fix is in flight. Clause (iii) is the descoped version of ARCH-P1-1's third clause — not
"every `Config` field has a validation or a marker" (65 lines of noise), but: every `CliOverrides` field
appears in `Config::validate`'s body (`types.rs:1015`, verified) or on a shrinking-only `UNVALIDATED`
list.

**Files to touch.** `crates/architecture-tests/tests/config_drift.rs` only (extends ARCH-5a's file).

**Implementation approach.** `CLAP_DEFAULT_CLOBBERS` is seeded with exactly the nine fields verified in
F9 — `metrics_address` (`cli.rs:614`), `metrics_port` (`:615`), `grpc_port` (`:616`), `grpc_address`
(`:617`), `log_level` (`:622`), `tracing_exporter` (`:641`), `keymanager_body_limit` (`:652`),
`slashed_validators_action` (`:658`), `beacon_max_body_bytes` (`:682`) — each with a reason string. The
detector flags any `Self { … <field>: Some(<binding>.<field>) … }` where the clap field is non-`Option`
with a `default_value`. **Shrinking-only:** a tenth entry fails the gate; removing one is the expected
direction of travel.

Why this is a real defect and not a style nit, restated for the PR: `load_config` reads the TOML and
**then** `merge_with_cli` runs (`cli.rs:780-781`), whose `set` arm is
`if let Some(v) = $field { $dst = v.clone(); }` (`types.rs:942-946`, F10). With `--metrics-port` absent,
`cli_overrides.metrics_port` is `Some(8080)` — clap's default, indistinguishable from an operator-supplied
8080 — and it overwrites the file. **A TOML `metrics_port = 9090` is silently reset to 8080.** All nine
clap defaults agree with their `Config` defaults, which is the only reason the symptom is "config file
ignored" rather than "documented default unreachable", and is exactly what makes it invisible.

**No existing test catches it**, and saying which ones *look* like they might is worth a sentence in the
module doc: `test_start_args_convert_to_equivalent_cli_overrides` (`cli.rs:1018-1216`) passes every flag
explicitly, and `test_start_help_lists_every_flag` (`:1005-1015`) compares a hand-maintained
`START_FLAGS` array against `--help`. Neither is a precedence test.

**TDD test plan.**
- **RED (synthetic, mandatory):** `clap_default_clobber_detector_flags_a_tenth_instance` — feed the
  matcher a fixture with a new `Some(server.some_new_flag)` and assert it is flagged.
- **GREEN:** `clap_default_clobbers_list_matches_the_source` — the nine seeded entries are exactly what
  the detector finds at HEAD; if the source and the list disagree in either direction, fail.
- `every_clobber_entry_carries_a_reason`.
- `unvalidated_list_is_shrinking_only` + `every_cli_override_field_is_validated_or_listed`.
- **GREEN:** the whole gate passes against HEAD, with the nine-entry list.

**Acceptance criteria.**
- [x] `CLAP_DEFAULT_CLOBBERS` contains exactly the nine verified fields, each with a reason.
- [x] A synthetic tenth instance is flagged (the mandatory RED).
- [x] `UNVALIDATED` exists, is shrinking-only, and every `CliOverrides` field is validated or listed.
- [x] The module doc names the two existing tests that *look* like precedence tests and are not.
- [x] Green in the `arch-gates` CI job, **before** ARCH-6b lands.

---

### ARCH-6a — Spike: run the ADR-009 precedence probe and record the verdict

- **Points:** 1 · **Type:** spike · **Priority:** P0 · **Stream:** A · **Blocked by:** — · **Scope:** 0.5 day

**Context.** ADR-009's *Consequences* are explicit: **this finding is static-analysis only — no shell was
available to any research track** (A-A4). It is a *Problem Statement* item, not a P1 item, until someone
runs it. Executing it is the cheapest de-risking available in this phase and it sizes ARCH-6b.

**The probe.**
1. Write a minimal TOML containing `metrics_port = 9090` (and nothing else that matters).
2. `cargo run -p rvc -- start --config <that file>` with `--metrics-port` **absent**.
3. Observe the bound port — the startup log at `crates/rvc/src/bootstrap/tasks.rs:86`
   (`info!(addr = …, port = metrics_port, "Starting metrics server")`) reports it directly; confirm with
   `ss -ltn` / `lsof -i` if the process gets far enough to bind.

**Verdicts (A-1.7).**
- **Binds 8080** → the defect reproduces. ARCH-6b proceeds as written.
- **Binds 9090** → some later path re-applies the TOML; the finding is **withdrawn**. Record *where* the
  re-application happens (nothing between `cli.rs:781` and the metrics bind at `tasks.rs:81-88` appeared
  to do so on inspection). ARCH-6b's code change is cancelled; `CLAP_DEFAULT_CLOBBERS` still ships from
  ARCH-5b as a **documented-empty** guard against future reintroduction, and the phase still exits green.

**Files to touch.** None in `crates/` or `bin/`. The verdict — including the exact command, the observed
port and the date — is written into this phase's PR description **and** appended to
`plan/architecture-2026-08-12/` as a short probe record, so a later reader can see it was executed rather
than assumed. Do not edit any source file in this issue.

**Acceptance criteria.**
- [x] The probe command and its literal output are recorded.
- [x] A verdict is stated: *defect reproduces* or *finding withdrawn (+ where the TOML is re-applied)*.
- [x] ARCH-6b is confirmed or cancelled on the basis of the verdict, in writing.

**ARCH-6a result (2026-08-12):** defect reproduces (`metrics_port=8080` with TOML `9090`, no flag).
Record: [`../measurements/arch-6a-adr009-precedence-probe.md`](../measurements/arch-6a-adr009-precedence-probe.md).
**ARCH-6b confirmed** (proceeds as written). Security review findings 1–3 on the pre-existing clobber class: **wontfix** for this spike — tracked for ARCH-6b.

---

### ARCH-6b — ADR-009 precedence fix: nine clap fields become `Option<T>`

- **Points:** 2 · **Type:** fix · **Priority:** P0 · **Stream:** A · **Blocked by:** ARCH-5b, ARCH-6a · **Scope:** 1–1.5 days
- **Requirements:** **ADR-009** (architecture-only; no PRD requirement ID — A-P5) · **Constraints:** **C3** (indirect)

**Context.** The fix for the defect ARCH-5b made visible. It lands **after** the gate, deliberately: the
project plan's defining sequencing rule (§1.1) is that no behavioural change ships before the artefact
that would detect its regression exists.

**Files to touch.**
- `bin/rvc/src/cli.rs` — the nine clap field declarations inside their group structs (drop
  `default_value`, make the field `Option<T>`), and the nine `Some(...)` wrappers at `:614`, `:615`,
  `:616`, `:617`, `:622`, `:641`, `:652`, `:658`, `:682` (which become plain moves).
- `crates/rvc/src/config/types.rs` — `Config::default()` gains the nine defaults, if any is not already
  there. **Verify each against the clap default before moving it**: ADR-009 records that all nine
  currently agree, which is precisely why the bug is invisible — a transcription slip here converts a
  silent precedence bug into a silent *default* change, which is worse.
- **Not** `merge_with_cli` (`types.rs:1210`): its `set` arm (`:942-946`) is already correct once the
  `Option` is honest.

**Implementation approach.** ~30 lines, mechanical. Do **not** reach for
`clap::ArgMatches::value_source` as the primary fix — it keeps the two-source ambiguity alive in the
type system where `Option<T>` removes it. It stays available as a fallback for any field that must remain
non-optional for `--help` ergonomics; if that fallback is used anywhere, name the field and the reason.

**Operator-visible consequence to record in the release note.** `--help` output changes: the defaults move
out of clap's `default_value` and into doc comments / `Config::default()`, so the `[default: …]`
annotations disappear for those nine flags. That is expected, and the two existing tests that touch
`--help` (`test_start_help_lists_every_flag`, `cli.rs:1005-1015`) must be checked, not assumed green.

**TDD test plan.**
- **RED (write first, and it is the test the repo has never had):**
  `bin/rvc/src/cli.rs`'s test module gains
  `a_toml_metrics_port_survives_when_the_flag_is_absent` — build `StartArgs` with the flag absent,
  convert to `CliOverrides`, load a `Config` from a TOML with `metrics_port = 9090`, call
  `merge_with_cli`, assert `cfg.metrics_port == 9090`. **At HEAD this returns 8080.**
- Repeat for at least three more of the nine (`grpc_port`, `keymanager_body_limit`,
  `beacon_max_body_bytes`) so the fix is proven as a class, not as one field.
- `an_explicit_flag_still_wins_over_the_toml` — the precedence that must **not** change: with
  `--metrics-port 7000` and a TOML `9090`, the result is 7000.
- **Non-vacuity at empty (this is the subtle one):** after the fix, `CLAP_DEFAULT_CLOBBERS` is empty. An
  empty shrinking-only list is indistinguishable from a dead gate, so ARCH-5b's
  `clap_default_clobber_detector_flags_a_tenth_instance` must still pass with the list empty. Re-run it
  and say so in the PR.
- **Regression:** `test_start_args_convert_to_equivalent_cli_overrides` (`cli.rs:1018-1216`) and
  `test_start_help_lists_every_flag` (`:1005-1015`) green — updating the latter's `START_FLAGS`
  expectations if `--help` text changed is in scope; changing what flags exist is not.

**Acceptance criteria.**
- [x] The nine clap fields are `Option<T>` with no `default_value`; the nine `Some(...)` wrappers are gone.
- [x] Each of the nine defaults is present in `Config::default()` and **equals** the clap default it
      replaced (verified field by field, not assumed).
- [x] A TOML value survives when the flag is absent, for at least four of the nine.
- [x] An explicit flag still beats the TOML.
- [x] **`CLAP_DEFAULT_CLOBBERS` is empty, and the detector still flags a synthetic reintroduction.**
- [x] `--help` changes are recorded in the release note; both existing `--help`/conversion tests green.
- [x] `rg 'value_source' bin/rvc/src` is empty, or every hit names its field and reason.

---

## 7. Constraint coverage (C1–C10)

Silence on any constraint is a defect, so every one is either carried forward with its owning issue or
rejected with a stated reason.

| ID | Status in Phase 1 | Where, and what enforces it |
|---|---|---|
| **C1** — retain-on-ambiguity vs lock shortening | **Explicitly out of scope, and actively fenced** | Phase 5 (ADR-005) owns it. ARCH-1a/1b change *when an audit event is emitted*, never *whether a row is committed*: `crates/slashing/src/stage.rs` is byte-unchanged, `crates/signer/src/core.rs` is untouched, and any diff altering a `commit()`/`discard()` decision is an explicit review-rejection criterion in ARCH-1b. Landing ADR-006 first strictly **shrinks** ADR-005's diff, which is why it is here |
| **C2** — audit-log emission inside the mutex | **Carried — it is this phase's headline** | ARCH-1a (the `PendingAudit` hand-off, **both** paths: `scoped.rs:75` and `:106` — VD-S5), ARCH-1b (the four `crates/signer` call sites — **VD-E2**), ARCH-1c (G-7). Proof is behavioural (`audit_event_fires_after_the_guard_is_released`) plus structural (G-7), not one or the other |
| **C3** — figment `Env` provider forbidden | **Carried, and trivially satisfied: this phase adds no config dependency at all** | ARCH-5a/5b/6b touch only `cli.rs`, `types.rs` and a new gate file. No `figment`, no new env read, no `Env` layer. The codified rule is **G-3**, which lands in Phase 4 **before** ADR-008's collapse — this phase's job is only to not create work for it. Note ADR-010 already replaced C3's stated mechanism: the `RVC_*` prefix scan fails on measurement (438 hits / 57 files, ~95 % metric names, and it misses `RUST_LOG`), so G-3 scans `std::env::var` **call sites** instead |
| **C4** — keystore-less key admission | **Carried, binding on ARCH-2b/2c** | `AdmissionSource::RawSecret` is a first-class enum variant, not an error path. Directly tested by `admit_raw_secret_writes_nothing_to_the_filesystem`. Both rejected shortcuts — writing a synthetic keystore to disk, and failing admission when no keystore is present — are named in ARCH-2b so they cannot be re-invented in review |
| **C5** — KM-2 teardown contract | **Carried by abstention, with a stated reason (A-1.4)** | `KeyAdmissionService::withdraw` is **deferred to Phase 7**, where **G-6** lands *before* ADR-015's retirement. G-6 does not exist at HEAD (VD-6), so shipping the contract's new implementation here would violate project-plan §1.1's sequencing thesis. ARCH-2b is explicitly forbidden from collapsing `stop_monitoring` / `cancel_monitoring` or adding a teardown call of either kind; the existing DELETE path is untouched |
| **C6** — cold-cache pre-proposal fetch | **Not applicable to this phase — Phase 3 (ADR-004) owns it** | No issue here touches `orchestrator/coordinator/mod.rs`, `slot_context.rs` or duty fetching. Stated so the omission is visible as a decision |
| **C7** — SSE drops are normal | **Not applicable — Phase 3 (ADR-013) owns it** | No issue here touches `crates/bn-manager/src/sse.rs` or the head-event path, and this phase adds **no channel of any kind** |
| **C8** — healthz removal is operator-visible | **Not applicable here by design (D2's split)** | The deprecation notice is Phase 0 (0F / ARCH-P1-16a), the removal is Phase 7 (16b), because C8 requires one release of warning — a **calendar** dependency. Consequently the healthz `grpc_address`/`grpc_port` surface is the **fifth** inert surface and is why this phase's milestone is *4 of 5* (**M7 → 1**), not 5 of 5 |
| **C9** — preserve the keep-list | **Carried, per anchor** | **1** `architecture-tests` harness: both gates are **new files**; `src/lib.rs`, `CLASSIFICATION` and every existing gate are untouched, and no production crate edge is added, so no `ARCHITECTURE.md` regeneration is due (A-1.10). **2** cancellation-proof core: `stage.rs` byte-unchanged, `core.rs` untouched, 38 EIP-3076 vectors green (necessary, not sufficient — §7.1 anchor 2). **3** KAT-first: no new test carries a `_root`/`_tree_hash`/`_signing_root` suffix; the one exposure (ARCH-1a's harness constructs a signing-root value) is flagged there with the KAT-constant-or-`kat_exempt` rule, and `EXEMPTIONS` must not grow. **4** env rule: no new env read anywhere in the phase. **5** single signing gate: `config/builder.rs:394` unchanged; no new signing surface; Gate 1's `--features dvt` clippy run is an ARCH-1b acceptance criterion because `SigningGate` is on the DVT surface. **6** zero unbounded channels: **no new channel at all** — this is why the "defer inside `audit_log`" design was rejected (VD-E7). **7** `spawn_blocking` out of scope: `signer/src/core.rs:542` untouched, and G-4's ban list is Phase 2's, not built here |
| **C10** — archive-before-delete for untracked trees | **Not this phase's work, and restated as a prohibition** | The four untracked paths (`crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`, `crates/rvc/src/commands/`) have **no git object behind them** — `git log --all` returns nothing, so `rm` is unrecoverable, unlike every other deletion in this initiative. Phase 0's ARCH-P0-1 owns the archive → verify → delete sequence (branch `archive/untracked-orphans-2026-08-12` **and** a tarball, restore-and-diff verified, manifest hash recorded). **No issue in this phase may cite, edit, migrate or delete any of those paths**, and the phase's entry criterion requires they are already gone. Two specific traps that would otherwise reach this phase: `crates/rvc-signer/src/config.rs:132` holds a **second `CliOverrides`**, which would corrupt ARCH-5a's field arithmetic and `rg` counts; and the orphan trees hold 25 raw `tokio::spawn` sites that must never enter any migration list |

