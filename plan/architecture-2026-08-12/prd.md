# PRD: Architecture Remediation for rs-vc

> Requirements document for the architecture-remediation initiative on the rs-vc Cargo workspace
> (29 members, verified in root `Cargo.toml:2`), baseline `develop` @ `0ae9a09` (v0.7.0),
> authored 2026-08-12.
>
> **Authoritative inputs, in precedence order:**
> [`docs/research/architecture-review-2026-08-11.md`](../../docs/research/architecture-review-2026-08-11.md)
> (the architecture review; the source of every weakness ranking and the Target Architecture) →
> the repository's [`CLAUDE.md`](../../CLAUDE.md) (TDD cycle, KAT-first policy, error-handling and
> style conventions — binding on every requirement below) → prior plan documents
> [`../tracing-2026-08-06/`](../tracing-2026-08-06/) and [`../security-2026-07-18/`](../security-2026-07-18/)
> (structural model, and one live cross-plan constraint recorded in *Assumptions* A-12).
>
> **This PRD is not a restatement of the review.** Every factual claim carried forward was
> re-verified against HEAD with the `file:line` shown. Where the review did not reproduce, this
> document carries the **corrected** fact in the Problem Statement and files the correction under
> *Verification Deltas* (VD-1 … VD-7). Claims that could not be checked cheaply are marked
> **[review-carried, unverified at HEAD]** rather than being dressed up with a citation.
>
> **No-ask constraint:** every open question is resolved to a stated default in *Assumptions*.
> Nothing is escalated.
>
> **Scope of this document:** requirements only. It does not decompose into phases-with-issues
> (that is the project plan's job) and it changes no code. Deleting anything is explicitly out of
> scope for the planning work that produced this file.

---

## Overview

This initiative is a **targeted correction of runtime-model defects, inert features, and
change-amplifiers** in rs-vc. It is **not** a rewrite and not a re-layering.

The review's verdict is unambiguous and this PRD adopts it as a premise: *"the architecture is
fundamentally sound and unusually well-governed — the problems are runtime-model defects, hygiene
debt, and change-amplifiers, not layering rot."* That verdict is load-bearing, because it sets the
burden of proof: any requirement below that would change the crate DAG, the signing choke point, or
the gate suite must justify itself against a specific verified defect, and none of them do. The
29-package classification table (`crates/architecture-tests/src/lib.rs:57-92`, one row per
workspace member), the byte-matched
generated `ARCHITECTURE.md`, the KAT-first policy, and the single unbypassable signing gate are
inputs to this work, not targets of it.

**What this initiative is:**

| # | Change | Why it is in scope |
|---|---|---|
| 1 | Make the shipped-but-inert features either work or be rejected | Three config surfaces accept operator input and discard it (verified below) |
| 2 | Fix the slot loop's ordering and the orchestrator's task lifecycle | Directly reward-affecting; verified at `coordinator/mod.rs:375-405` and `bootstrap/run.rs:297-317` |
| 3 | Retire ≈26,270 verified lines of untracked shadow code (19,750 + 3,749 + 2,771, plus `crates/rvc/src/commands/`), **archive-first** | It is invisible to every CI gate *and* unrecoverable by `git` — see ARCH-P0-1 |
| 4 | Close the config-drift hole with a gate, then collapse the four copies | 65 knobs × 4 hand-maintained sites × 0 gates |
| 5 | Remove the scaling wall in slashing-DB serialization, under the safety constraints in C1/C2 | Required before >100-key deployments |

**What this initiative is not:** see *Non-Goals*. In particular the slashing-protection placement,
the `signer`→`doppelganger` required edge, the `architecture-tests` harness, and the sequential
single-loop orchestrator shape are all **preserved by requirement**, not merely left alone.

---

## Problem Statement

**Evidence convention.** Every `file:line` below was opened at HEAD (`0ae9a09`) while writing this
document. Anything not opened is tagged **[review-carried, unverified at HEAD]**. Where the review's
description of a mechanism was wrong, the corrected mechanism is stated here and the delta is filed
in *Verification Deltas*.

---

### (a) Correctness / reward defects

#### PB-A1 — Slot-critical proposal work runs behind unbounded non-critical work

**Verified, and worse than the review states.** At `crates/rvc/src/orchestrator/coordinator/mod.rs`
the per-slot body is ordered:

| Line | Work | Bounded? |
|---|---|---|
| `:373` | `apply_key_gen_cache_invalidation()` | yes |
| `:376-379` | `fetch_epoch_duties(current_epoch)` — **every slot**, despite the `// === Epoch boundary:` comment at `:375` | up to 6 × 10 s BN timeouts (`orchestrator/duty_management.rs:61-133`) **[review-carried, unverified at HEAD]** |
| `:380-383` | `fetch_epoch_duties(current_epoch + 1)` — **every slot** | same |
| `:386-397` | epoch-boundary prep: circuit-breaker reset + `on_epoch_boundary` (proposer preparation, committee subscriptions) | not bounded in the loop |
| `:402` | `SlotContext::capture` — a further BN round trip (`get_block_root`) | not bounded in the loop |
| `:405` | `maybe_propose_block` — **the t=0 duty** | — |

Three refinements the review's "duty fetches and epoch-boundary prep run before `maybe_propose_block`"
understates (VD-1):

1. **Both** epoch fetches run on *every* slot, not only at the boundary. The `// === Epoch boundary`
   comment at `:375` labels them as boundary work; the `if current_slot % SLOTS_PER_EPOCH == 0`
   guard begins at `:386`, *after* them. So the worst case is not confined to slot 0 of an epoch —
   it is every slot.
2. `SlotContext::capture` at `:402` is a **third** pre-proposal BN round trip, unmentioned in the
   review's critical-path list. Any acceptance criterion that only moves duty fetches leaves it in
   place.
3. The proposal is therefore gated on *at least* three BN interactions with no aggregate deadline.

**Consequence.** Direct validator-economic loss: a late or missed block proposal costs the whole
proposal reward (~an order of magnitude more than an attestation) and is unrecoverable. Every
surveyed reference client proposes at slot start and fetches duties with lookahead off the hot path.

#### PB-A2 — Graceful shutdown is dead code; the orchestrator cannot be joined

**Verified at `crates/rvc/src/bootstrap/run.rs`.** The orchestrator future is polled *inline* in a
top-level `select!` (`:297-313`, three arms: gRPC server `:298`, `orchestrator.run()` `:304`,
`shutdown_signal()` `:310`). A signal therefore **drops** the orchestrator future mid-phase. Only
*after* the `select!` returns does `:316-317` run `shutdown_token.cancel()` and
`orchestrator_handle.shutdown()` — i.e. the shutdown watch channel is signalled to a future that no
longer exists. `:319` then sleeps a fixed `100 ms` in lieu of a join.

Supporting facts, each verified:

- **Root cause:** `#[async_trait(?Send)]` on `BeaconBlockClient` (`crates/block-service/src/traits.rs:13-14`)
  makes the orchestrator future `!Send` and therefore un-`tokio::spawn`-able.
- **`std::process::exit` inside async:** `crates/rvc/src/bootstrap/run.rs:83`, in the
  keystore-locked error arm — bypasses every `Drop`, including logging-guard flushes.
- **Fire-and-forget Keymanager API:** `crates/rvc/src/keymanager_adapters/spawn.rs:247-251` spawns
  the server, discards the `JoinHandle`, and passes no cancellation token.

**Consequence.** Safety survives — the slashing core is cancellation-proof by construction
(`crates/signer/src/core.rs`, and `crates/slashing/src/stage.rs:24-30` documents the
stage/commit/discard/Drop-rollback contract). What does not survive is *work*: a signed block can be
dropped between signature and publication (reward loss, no slashing risk), and a mid-import kill can
leave key-state mutations half-applied. Operator-visible symptom: SIGTERM during a proposal slot
loses the block, and container orchestrators that SIGKILL after a short grace period will hit this
routinely.

#### PB-A3 — `SlotContext` at t=0 may systematically drop sync-committee duties

**Mechanism verified; the empirical question is open.** `SlotContext::capture`
(`crates/rvc/src/orchestrator/slot_context.rs:40-60`) queries `get_block_root(&slot.to_string())` —
the **current** slot's root — at slot start, before the block for that slot can exist. On any BN
error it returns `head_root = None` (`:50-57`) and the loop continues. The consumer,
`crates/rvc/src/orchestrator/sync_committee.rs:65-74`, then **returns early**:

```
None => { warn!(slot, "Skipping sync committee messages: head_root unavailable in slot context"); return; }
```

The `// H-5` comment at `:62-64` states this is deliberate — skip rather than re-fetch a potentially
drifted root. That is a correct *TOCTOU* decision and a possibly-wrong *availability* decision: if
the BN 404s a not-yet-produced slot (the Beacon API's specified behaviour), sync-committee messages
are skipped **every slot**, silently, for every validator in the sync committee — a standing
reward loss with no error-level signal.

**Consequence.** Sync-committee rewards are a material share of a validator's income during a
committee period. This is the highest-priority *empirical* question in the initiative: it is either
a systematic reward defect or a non-issue, and the code as written cannot tell you which.

---

### (b) Silently-inert shipped features

The shared failure mode: **a config surface accepts operator input and does nothing with it.** The
operator sees a startup log line confirming the feature is on, and has no signal that it is inert.

#### PB-B1 — Proposer-config URL refresh discards every fetched update

**Verified, `crates/rvc/src/bootstrap/tasks.rs:110-138`.** The task is spawned with a real settings
struct (URL, refresh interval, token, TLS-insecure flag) and logs
`"Starting proposer config URL refresh task"` at `:119-123`. The apply callback passed at `:127-136`
is, in full, a `for` loop that `info!`s each update:

```rust
move |updates, _default| {
    for update in &updates {
        info!(pubkey = %update.pubkey, fee_recipient = ?update.fee_recipient,
              builder_enabled = ?update.builder_enabled, "Proposer config update from URL");
    }
}
```

`_default` is discarded by name. Nothing is written to `ValidatorStore`.

**Consequence.** An operator who rotates a fee recipient via the proposer-config URL — the standard
way to change where block rewards are paid — will see a log line saying the new value was received
and will keep proposing to the **old** fee recipient indefinitely. This is a direct, silent,
unbounded loss of MEV/tip revenue to the wrong address. It is the single most operationally
dishonest surface in the codebase.

#### PB-B2 — Monitoring push reports a boot-time validator count forever

**Verified, `crates/rvc/src/bootstrap/tasks.rs:103-107`.** The count provider is a closure over a
value captured at bootstrap:

```rust
move || (validator_count as u32, validator_count as u32)
```

Both tuple elements are the same boot-time constant, so the "total" and "active" figures are
identical *and* frozen. Keymanager imports and deletes never move them.

**Consequence.** Remote monitoring (the standard beaconcha.in-style push endpoint) misreports the
fleet after any runtime key change. Alerting keyed on validator count cannot detect a key-loading
failure — the failure mode the metric exists to catch.

#### PB-B3 — Secret-provider-refreshed keys are admitted to signing but starved of duties

**Verified, and the review's mechanism is wrong (VD-2).** `crates/rvc/src/bootstrap/enablement.rs:170-192`
is the refresh callback. It does **three** things: denylist re-check (`:174-183`),
`machine.register_for_import(&pk, ...)` (`:185-188`), and `signer_for_refresh.add_local_key(sk)`
(`:189`).

The review states these keys are "never scheduled for duties **or enabled by doppelganger**" and
implies no doppelganger registration happens. It does happen, at `:187`. The real defect is
**starvation, not absence**:

| Store | Updated on keymanager import | Updated on secret-provider refresh |
|---|---|---|
| `CompositeSigner` | yes | **yes** (`enablement.rs:189`) |
| `ForwardWindowMachine` | yes | **yes** (`enablement.rs:187`) |
| `PubkeyMap` | yes (`keymanager_adapters/notifier.rs:51-54`) | **no** |
| `ValidatorStore` | yes | **no** |
| `key_gen_tx` generation counter | yes (`notifier.rs:46-48`) | **no** |

Because the liveness loop is constructed with `Some(Arc::clone(&keys.pubkey_map))` so it can
"re-resolve indices after keymanager import" (`enablement.rs:137-145`), and the refresh path never
inserts into `pubkey_map`, a refresh-admitted key is **registered with the forward-window machine
and then never sampled** — so it cannot advance out of `Pending`. It also gets no duties (the
orchestrator matches duties against `PubkeyMap`) and never invalidates the duty cache.

**Consequence, and why the corrected mechanism matters.** The key is loaded into the signer but can
never be enabled and never receives a duty: an operator using cloud secret management (GCP Secret
Manager) to add validators sees "Secret provider refresh task started" and believes the key is
active. It earns nothing. The fix implied by the review ("register with doppelganger") is a no-op —
the acceptance criterion must be written against `PubkeyMap` / `ValidatorStore` / `key_gen_tx`.

#### PB-B4 — Broadcast configuration implies routing that does not happen

**Verified.** `BroadcastStrategy::broadcast_inner` (`crates/bn-manager/src/manager.rs:757-771`)
iterates **`self.clients`** unconditionally — `for (i, client) in self.clients.iter().enumerate()`
at `:764` — with no `BnRole` or tier predicate anywhere in the fan-out, and the two callers
(`broadcast` `:739-753`, `broadcast_with_result` `:843-857`) each log `tried = self.clients.len()`,
i.e. all of them. `BnRole` is a real, heavily-used concept elsewhere in the crate (99 occurrences
across `lib.rs`/`types.rs`/`traits.rs`/`manager.rs`, 34 in `manager.rs` alone) — it is simply not
consulted on the broadcast path. The operator-facing config surface is real and logged at startup
(`crates/rvc/src/bootstrap/run.rs:282-291`, `effective_broadcast_topics()`).

Same failure family as PB-B1/PB-B2 — a config surface implying routing that does not happen — but
sized lower (P2) because the consequence is unintended redundancy and wasted BN load, not lost
revenue or a wrong destination address.

---

### (c) Scaling walls

#### PB-C1 — One global SQLite mutex is held across every slashable sign

**Verified, `crates/slashing/src/stage.rs`.** The module documentation states the design in its own
words at `:32-48` — *"The mutex is held for the entire stage → (signer call) → commit window. This
means concurrent sign requests for different (pubkey, slot) pairs from the same client are serialised
behind this lock."* — and the mechanism at `:24-30`: `stage_*` issues `BEGIN IMMEDIATE`, runs the
violation check, and returns a guard **owning the `parking_lot::MutexGuard<'db, Connection>`**;
`commit` INSERTs + COMMITs then releases; `Drop` rolls back. `:57-63` pins the `!Send` consequence.

Note for the redesign: `:32-48` is *design intent in a doc comment*; the acceptance criterion for any
change must be written against the guard-returning code and the EIP-3076 conformance vectors, not
against the comment.

The doc's own justification (`:43-44`) is *"Signer calls are fast (sub-millisecond BLS on a local
key, or bounded by the network timeout for a remote signer)"* — which concedes the failure case:
with a remote signer at ~200 ms, roughly 20 signs fill an attestation window, and the deployment
cannot meet deadlines at hundreds of keys.

**Consequence.** A hard ceiling on validators-per-instance with a remote signer, reached silently
(as missed attestation deadlines, not as an error). Web3Signer solves the same problem with
database-level locking on Postgres; rvc's single-connection SQLite design needs sharding, per-pubkey
connections, or a shorter hold window first. See **C1** — this is not a plain lock-scope shrink.

#### PB-C2 — Audit logs are emitted while that mutex is held

**Verified, `crates/slashing/src/scoped.rs:68-76`.** `audit_log(&self.client_cn, pubkey_hex, outcome)`
fires at `:75`, *after* `self.db.stage_block(...)` at `:68` has returned a guard still holding the
connection mutex. The code documents the hazard itself at `:70-74`: *"A tracing subscriber that
attempts to read the DB would deadlock because parking_lot mutexes are non-reentrant."*

**Consequence.** Two distinct problems. (i) **A live availability landmine today**: a well-meaning
operator or developer who adds an audit subscriber that reads the slashing DB wedges *all* signing,
permanently, with no timeout — the process stops signing and keeps running. (ii) **A hard constraint
on PB-C1's fix**: emission must move outside the lock before or with any critical-section redesign.
The comment also concedes a correctness wart — a `"staged"` audit event may precede a rolled-back
sign.

#### PB-C3 — `ValidatorLockMap` never evicts

Per-pubkey lock entries accumulate under key churn (`crates/signer/src/locks.rs`).
**[review-carried, unverified at HEAD]** — an unbounded-growth defect, not a correctness one; sized
P2.

---

### (d) Evolvability taxes

#### PB-D1 — Every operator knob exists in four hand-maintained shapes, with zero gates

**Verified, exactly.**

| Site | Location | Size at HEAD |
|---|---|---|
| 1. clap arg definitions | `bin/rvc/src/cli.rs` | **1,363** lines |
| 2. `CliOverrides` struct | `crates/rvc/src/config/types.rs:1313-1383` | **65** fields (69 lines − 4 doc-comment lines) |
| 3. `Config` fields + defaults | `crates/rvc/src/config/types.rs` | **3,187** lines |
| 4. `merge_with_cli` + `validate` | `crates/rvc/src/config/types.rs:1210`, `:1015` | — |

All four review figures reproduce to the digit. Two crates are involved (`bin/rvc` declares the
args; `crates/rvc` owns the override struct, the config, the merge and the validation), and there is
**no gate** connecting them — while crate edges, signing-root KATs, log fields, proto compilation
and the generated `ARCHITECTURE.md` all have gates. A knob added to clap and forgotten in
`merge_with_cli` is accepted on the command line and silently ignored, and nothing in CI notices.

**Consequence.** This is the mechanism that produced the shadow trees in PB-E1: a second copy of
`CliOverrides` exists in the orphan tree (`crates/rvc-signer/src/config.rs:132`) and greps for the
type return two hits, one of which is dead. It is also the reason config work is the largest
per-feature tax in the repo — and by requirement (ARCH-P1-1) it must be gated *before* any further
feature adds knobs.

#### PB-D2 — Duplicated seams that can drift

**[review-carried, partially verified]** Twin `ProduceBlockResponse` structs
(`crates/beacon/src/types.rs:132` vs `crates/block-service/src/traits.rs:50` — the latter file
verified to exist and to declare the `?Send` trait at `:13`); duplicated non-slashable path and
timeout constants between `SignerService` (`crates/signer/src/lib.rs:169`) and `SigningGate`
(`crates/signer/src/gate.rs:115`); dual-SSZ `Wire*` twins in `crates/eth-types/src/block_body.rs`
doubling per-container fork work; DVT `PeerSignerService` bypassing `SigningGate`
(`crates/signer/src/dvt/peer_service.rs:227-230`) and so escaping the `signer-registry` enumeration
gate under the `dvt` feature.

**Consequence.** Each is a place where a fork-driven or policy-driven change must be made twice, and
where making it once compiles cleanly. The `Wire*` twins specifically reintroduce the field-order
bug class that the KAT-first policy in `CLAUDE.md` exists to catch.

#### PB-D3 — `LegacySlashingHistoryReader` is a public, GVR-blind foot-gun

`crates/doppelganger/src/traits.rs:68-75` is a *public* trait whose own doc comment says misuse for
the forward-window machine *"would bypass chain-identity checks."* **[review-carried, unverified at
HEAD]** It is protected today by naming discipline alone — no gate. Retiring the legacy
doppelganger service removes it; see **C5** for what must survive that retirement.

#### PB-D4 — The layer taxonomy is too coarse to bite

**Verified, `crates/architecture-tests/src/lib.rs:57-92`.** `Layer::Foundation` (`:73-88`) contains
pure leaves (`eth-types`, `observability`, `metrics`, `signer-proto`, `web3signer-wire`) *beside*
network and I/O services (`beacon` — "HTTP client"; `bn-manager` — "multi-BN"; `crypto` — "BLS,
signing, **Web3Signer**"; `secret-provider` — "cloud key mgmt"; `keymanager-api` — "key mgmt REST").
Because they share one layer, the no-Domain-dependency rule binds narrowly and nothing structurally
forbids a foundation→domain edge.

One correction to the review's Target Architecture (VD-3): it lists `timing` among the pure leaves to
move into a new `Base` layer. At HEAD `rvc-timing` is classified **`Layer::Domain`**
(`lib.rs:72`), not Foundation. A `Base`/`Infra` split must reclassify it deliberately, not
incidentally.

---

### (e) Hygiene and unrecoverable-risk debt

#### PB-E1 — ≈26,270 lines of untracked shadow code, invisible to every gate and **unrecoverable by git**

This is the review's #1 finding, and the provenance is materially different from — and worse than —
what the review describes (VD-4). The review calls the trees a *"stale pre-refactor snapshot,"*
implying a refactor left them behind. The verified provenance:

| Fact | Status |
|---|---|
| `git log --all` over `crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`, `crates/rvc/src/commands/` returns **nothing** — no commit, no blob, no reflog entry | **They were never tracked in git at all.** The tracked `bin/` copies were added fresh; the untracked originals were never removed. |
| mtimes: orphan trees 2026-07-26 12:40 vs tracked counterparts 2026-07-28 00:48 | Orphans are ≈2 days **older** — staleness confirmed |
| `bin/rvc-keygen/src/fs_util.rs` exists **only** in the tracked tree; the orphan lacks it and still carries 14 inline `0o600`/`set_permissions` sites where the member has 12 factored through `fs_util.rs` | Decisive content proof the orphan is pre-extraction, and that the orphan **lacks a security fix** |
| `crates/rvc-signer/Cargo.toml:2` declares `name = "rvc-signer-bin"` — verified — which is the **same package name** as the tracked `bin/rvc-signer/Cargo.toml:2` | Adding the orphan to `[workspace] members` is a duplicate-package **hard error**. It cannot be revived as-is. |
| LOC: `crates/rvc-signer` 19,750; `crates/rvc-keygen` 3,749; `crates/rvc/src/main.rs` **2,771** (verified) | ≈26,270 lines plus `crates/rvc/src/commands/` |
| Neither orphan crate appears in `Cargo.toml:2` `members` | Verified — invisible to `cargo metadata`, therefore to every architecture gate |
| `crates/rvc/Cargo.toml:3` sets `autobins = false` | Verified — `crates/rvc/src/main.rs` is never compiled |

**Consequences, three of them, and the third is the one that changes the plan:**

1. **Silent loss of work and false reviews.** Greps return two hits for security-relevant types —
   demonstrated: `struct CliOverrides` matches both `crates/rvc-signer/src/config.rs:132` (dead) and
   `crates/rvc/src/config/types.rs:1313` (live). An edit to the wrong copy compiles nowhere, passes
   nothing, and is invisible. The keygen orphan's missing `fs_util.rs` is a live example of a
   security fix that exists in only one of the two copies.
2. **Every gate is defeated by construction.** The architecture tests read `cargo metadata`;
   non-members are outside the DAG check, the classification table, the KAT scan, and the log-field
   conformance scan.
3. **Deletion is irreversible.** With no git object behind them, `rm` is *unrecoverable* — unlike
   every other deletion in this initiative (`crates/sync-service`, the healthz server, the `Wire*`
   twins are all tracked and restorable from history). This is not a normal hygiene delete. See
   **C10** and **ARCH-P0-1**: the requirement is *archive-then-delete*, to a named location, with
   archive verification as an exit criterion.

#### PB-E2 — Dead and mis-titled supporting assets

- **`crates/sync-service`** is a workspace member (verified, `Cargo.toml:2`; aliased at
  `Cargo.toml:33` as `package = "rvc-sync-service"`; classified `Layer::Domain` at
  `architecture-tests/src/lib.rs:71`) but is a 45-line shell with zero consumers
  **[45-line/zero-consumer claim review-carried, unverified at HEAD]**. Unlike PB-E1 it *is* tracked,
  so its deletion is ordinary and recoverable.
- **Healthz-only tonic server**: `crates/rvc/src/bootstrap/run.rs:263-276` builds a
  `DutyTrackerService` and serves `DutyTrackerServer` on the configured gRPC address, occupying a
  top-level `select!` arm at `:298`. Removing it is **operator-visible** — see **C8**.
- **`docs/architecture.md`** is a stale test-audit remediation plan, not an architecture document;
  the generated root `ARCHITECTURE.md` is the real one. Paths referenced in `docs/` are not checked
  for existence. **[review-carried, unverified at HEAD]**
- **`bin/rvc` declares ~6 unused workspace dependencies**; no `cargo-machete`/`udeps` in CI.
  **[review-carried, unverified at HEAD]**
- **KAT `EXEMPTIONS` overstates the exemption surface**: entries in the shrinking-only list in
  `crates/architecture-tests/tests/kat_policy.rs` are in fact KAT-anchored — a name-based-detector
  weakness. **[review-carried, unverified at HEAD]**

---

## Goals

| # | Goal | Closes |
|---|---|---|
| G1 | **No shipped config surface is inert.** Every operator-settable knob either changes behaviour or is rejected at startup with a named error. | W4, W7 |
| G2 | **Slot-critical work is first and bounded.** The t=0 proposal decision is reached with a bounded pre-proposal budget; all non-critical work moves into the phase-3→next-slot wait window. | W2 |
| G3 | **Every spawned task is named, owned, cancellable, and joined**, and shutdown lets in-flight publishes complete. | W3 |
| G4 | **No source tree in the repo is invisible to the gate suite** — and no unrecoverable tree is deleted without a verified archive. | W1 |
| G5 | **One declaration per operator knob**, with a CI gate that fails on drift, landed *before* the collapse. | W6 |
| G6 | **Slashable signing scales to the target validator count** with a remote signer, without weakening the retain-on-ambiguity property or the single signing gate. | W5 |
| G7 | **Every governance discipline currently enforced by discipline alone gets a gate** — orphan directories, `RVC_*` env allow-list, config drift, KM-2 teardown, docs freshness. | W1, W6, W9, W10 |
| G8 | **Fork work halves.** One SSZ stack, one `ProduceBlockResponse`, an enumerated add-a-fork checklist. | W9 |

## Non-Goals

Stated as exclusions because each is a plausible over-reach that the review's verdict rules out.

| # | Non-goal | Why |
|---|---|---|
| NG1 | **Rewriting or re-cutting the crate DAG.** | The 29-crate granularity is validated against reth/lighthouse layouts and CI-enforced. The `Base`/`Infra` split (ARCH-P1-8) *re-labels* existing crates and adds gates; it moves no crate boundaries except the one extraction in ARCH-P1-10. |
| NG2 | **Replacing or re-implementing `crates/architecture-tests`.** | The review finds it *ahead* of ecosystem tooling (rust_arkitect, cargo-archtest). Every gate requirement below **extends** it, in its existing scanner style. |
| NG3 | **Adopting an actor framework** (or an actor-per-validator model). | Explicitly rejected by the review: the sequential single-loop shape is adequate once ordering is fixed. `TaskExecutor` (ARCH-P1-4) is a spawn/join/metrics utility, not a framework. |
| NG4 | **Changing where slashing protection lives.** | rvc already matches the industry consensus (Web3Signer, Dirk): protection at the signer choke point, with a VC-side gate as defence in depth. PB-C1 changes *how the lock is held*, never *where the check runs*. |
| NG5 | **Migrating the slashing store off SQLite** (e.g. to Postgres) as part of this initiative. | In-scope alternatives are sharding, per-pubkey connections, or a shorter hold window. A store migration is a separate initiative with its own EIP-3076 interchange and operational story. |
| NG6 | **Adding new validator-facing features or protocol support.** | Every requirement here is corrective. ARCH-P1-1's gate is an explicit *precondition* on future knob-adding feature work. |
| NG7 | **Any code change from this planning work.** | This PRD and its downstream plan documents produce no diffs, delete nothing, and touch no source file. |
| NG8 | **Touching `docs/prd.md`, `docs/architecture.md`, `docs/project-plan.md`.** | Those belong to the older Test Audit Remediation initiative. ARCH-P2-5 *proposes* moving `docs/architecture.md`; it does not do it here. |

---

## Target Users & Stakeholders

| Stakeholder | What they get | Which goals |
|---|---|---|
| **Node operators (primary)** | Config surfaces that do what they say; no silent fee-recipient loss; proposals that land under BN stress; a shutdown that does not eat a block | G1, G2, G3 |
| **Staking-service operators running >100 keys with a remote signer** | A removed scaling ceiling and a measured hold-duration budget instead of an undiagnosed miss rate | G6 |
| **rs-vc maintainers / contributors** | One place per knob; one copy per type; gates that catch the class of mistake instead of reviewers catching instances | G5, G7, G8 |
| **Security reviewers / auditors** | No shadow tree to review by accident; no GVR-blind public trait guarded by naming; audit logging that cannot wedge signing | G4, G7 |
| **SRE / platform teams** | An explicit probe-migration path before the healthz endpoint disappears (C8); a live validator count in monitoring push | G1, G3 |

---

## Requirements

**Reading the tables.** Every requirement has a stable ID, the review weakness it closes, the
problem-statement item it is evidenced by, and a **testable** acceptance criterion — one that names
the artefact (a test, a gate, a metric, a file) that turns red if the requirement is unmet. IDs are
stable across downstream plan documents; do not renumber.

**Standing constraints on every requirement** (from `CLAUDE.md` and the constraint register):
TDD RED→GREEN→REFACTOR; `thiserror` in libraries / `anyhow` in binaries; no `.unwrap()` in
production code; `cargo fmt` + `cargo clippy` clean; and any new or renamed `*_root` /
`*tree_hash*` / `*signing_root*` test is KAT-anchored or carries a `// kat_exempt: <reason>`.
No requirement may regress the keep-list in **C9**.

### P0 — Correctness, safety, reward-affecting, unrecoverable-risk hygiene

#### ARCH-P0-1 — Archive-then-delete the untracked shadow trees

| | |
|---|---|
| **Closes** | Weakness 1 (HIGH) |
| **Evidence** | PB-E1 |
| **Constraints** | **C10** (binding) |

The four untracked trees — `crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`,
`crates/rvc/src/commands/` — must be removed from the working tree. Because **no git object exists
behind them**, removal is irreversible; the requirement is therefore a three-step sequence, and an
issue that says only "delete the orphan trees" does not satisfy it.

1. **Archive.** Commit the four trees verbatim to a **named** throwaway branch
   (default: `archive/untracked-orphans-2026-08-12`, see A-1) **and** produce a tarball at a named
   path recorded in the issue. Note that the archive branch cannot simply add the trees to the
   workspace: `crates/rvc-signer/Cargo.toml:2` declares `rvc-signer-bin`, colliding with
   `bin/rvc-signer/Cargo.toml:2`. Archive as content, not as workspace members.
2. **Verify the archive.** Independent restore-and-compare: check out the archive into a scratch
   directory and assert a byte-level match (file count + per-file hash) against the working tree
   before deletion. Record the resulting manifest hash in the issue.
3. **Delete**, in a separate commit from (1), referencing the archive ref.

**Acceptance criteria.**
- `git ls-files` shows the archive ref containing all four trees; a scripted restore-and-diff
  produces zero differences; the manifest hash is recorded in the issue body.
- After deletion, none of the four paths exists in the working tree.
- `rg 'struct CliOverrides'` returns exactly **one** hit (`crates/rvc/src/config/types.rs:1313`),
  down from two.
- `cargo build --workspace` and `cargo nextest run --workspace` are green (they must be unaffected —
  nothing compiled these trees).

#### ARCH-P0-2 — Orphan-directory gate

| | |
|---|---|
| **Closes** | Weakness 1 (recurrence prevention) |
| **Evidence** | PB-E1 |

A new test in `crates/architecture-tests` asserting that **every** directory under `crates/*` and
`bin/*` containing a `Cargo.toml` is a workspace member per `cargo metadata`, and that no `.rs` file
under a member crate's `src/` is excluded from compilation by an `autobins = false` / missing-`mod`
combination without a documented marker.

Two distinct detectors are required, because they catch different orphans:

| Detector | Catches |
|---|---|
| **D1 — orphan directory:** every `crates/*` / `bin/*` dir with a `Cargo.toml` is a `cargo metadata` member | `crates/rvc-signer/`, `crates/rvc-keygen/` |
| **D2 — uncompiled source:** no `.rs` file under a member crate's `src/` is excluded from compilation by an `autobins = false` / missing-`mod` combination without a documented marker | `crates/rvc/src/main.rs`, `crates/rvc/src/commands/` |

**Landing order (this is a hard instruction, not a preference).** Both detectors **land in the same
PR as ARCH-P0-1's deletion commit**, after it, so `develop` is never red. The RED state is
demonstrated *locally* — run each detector against the pre-deletion tree and paste the failure
output into the PR — never by merging a knowingly-failing gate. This is the "demonstrated, not
asserted" standard applied without breaking CI for the interval between the two requirements.

**Acceptance criteria.**
- D1 and D2 each demonstrably fail against the pre-deletion tree (output recorded in the PR) and
  pass after it, within one PR.
- Re-adding an unregistered `crates/foo/Cargo.toml` in a scratch commit fails CI (D1).
- Adding an uncompiled `.rs` file under a member's `src/` in a scratch commit fails CI (D2).
- Each detector names the offending path in its failure message (NFR-5, R10).
- `develop` is green at every commit boundary.

#### ARCH-P0-3 — Proposal-first slot ordering with a bounded pre-proposal budget

| | |
|---|---|
| **Closes** | Weakness 2 (HIGH) |
| **Evidence** | PB-A1 |
| **Constraints** | **C6** (binding), **C7** (if head-event triggering lands with it) |

The t=0 proposal path must be reached before non-critical per-slot work. Because PB-A1 found the
critical path is longer than the review states, the requirement **enumerates what must move**:

| Currently at | Work | Required disposition |
|---|---|---|
| `coordinator/mod.rs:376-379` | `fetch_epoch_duties(current_epoch)` — runs every slot | Move into the phase-3→next-slot wait window; keep an epoch-boundary/dependent-root-change trigger |
| `:380-383` | `fetch_epoch_duties(current_epoch + 1)` — runs every slot | Same (this is the lookahead fetch) |
| `:386-397` | circuit-breaker reset + `on_epoch_boundary` | Move into the wait window (the existing builder-registration race there is the pattern to extend) |
| `:402` | `SlotContext::capture` BN round trip | Must not gate the proposal decision: either move after the proposal, or bound it with the same pre-proposal deadline |

**Cold-cache handling (C6).** Proposal-first must not silently skip the proposal check when no
cached proposer duty exists — which is the case on the first slot after boot and on every slot
immediately after a `key_gen`-driven cache invalidation (`coordinator/mod.rs:373`). The required
behaviour is a **bounded, short-deadline** pre-proposal duty fetch as fallback, with its own metric
and log line.

**Acceptance criteria.**
- A behaviour test with a mock BN injecting per-request latency shows `maybe_propose_block` is
  entered within a configured budget (default 1,000 ms, see A-5) of slot start, in three scenarios:
  warm cache; cold cache post-boot; cold cache immediately after a `key_gen` bump.
- A test asserts the cold-cache path performs the bounded fetch and **does** propose when a duty
  exists — i.e. it fails if the implementation skips the check.
- With duty fetches stubbed to hang for the full 6 × 10 s, the proposal still happens.
- Existing orchestrator behaviour-contract tests remain green; no change to which duties are
  performed, only when.

#### ARCH-P0-4 — Spawnable, joinable orchestrator and a real graceful shutdown

| | |
|---|---|
| **Closes** | Weakness 3 (HIGH) |
| **Evidence** | PB-A2 |
| **Constraints** | **C9** (no regression to the cancellation-proof signing core) |

Four coupled changes:

1. Remove `#[async_trait(?Send)]` from `BeaconBlockClient` (`crates/block-service/src/traits.rs:13`).
   The review notes the adapter wraps `Arc<dyn BeaconNodeClient>`, already `Send + Sync`, so the
   annotation *appears* removable — that is a hypothesis, and the requirement is satisfied by either
   removing it or recording why it cannot be removed plus the alternative taken (A-6).
2. `tokio::spawn` the orchestrator and hold its `JoinHandle`; on signal, `handle.shutdown()` then
   `timeout(join)` — making the existing watch/`wait_for` machinery real.
3. Give the Keymanager API server a cancellation token and a bounded join
   (`keymanager_adapters/spawn.rs:247-251`; axum `with_graceful_shutdown`).
4. Remove the in-async `std::process::exit` at `bootstrap/run.rs:83` and the fixed 100 ms sleep at
   `:319`, replacing them with an error return carrying the exit code and a real join respectively.

**Acceptance criteria.**
- A test that signals shutdown while a block publish is in flight asserts the publish **completes**
  before the process returns (today it is dropped).
- A test asserts `shutdown()` → orchestrator loop observes the watch change → returns `Ok(())` →
  join completes within the configured grace period (default 5 s, A-7).
- `rg 'process::exit' crates/rvc/src` returns no hit inside an `async fn`.
- No `tokio::time::sleep` is used as a stand-in for a join in `bootstrap/run.rs`.
- The named exit codes (EXIT_* 10/11/13/14) are preserved and asserted for the keystore-lock path.

#### ARCH-P0-5 — One runtime key-admission path

| | |
|---|---|
| **Closes** | Weakness 4 (HIGH) |
| **Evidence** | PB-B3 |
| **Constraints** | **C4** (binding) |

Both keymanager imports and secret-provider refresh must admit keys through a single path that
updates **all** of: `CompositeSigner`, `PubkeyMap`, `ValidatorStore`, denylist state, doppelganger
registration, and the `key_gen_tx` generation counter.

**This is a build, not a rewiring (VD-5).** The review describes `KeyChangeNotifier` as already
performing that atomic multi-store update. It does not: at HEAD it is a 61-line struct with exactly
two fields, `pubkey_map` and `key_gen_tx` (`crates/rvc/src/keymanager_adapters/notifier.rs:29-32`),
exposing `notify`, `insert_and_notify`, `remove_and_notify` (`:46-60`). It touches neither the
composite signer, nor `ValidatorStore`, nor the denylist, nor doppelganger. Satisfying this
requirement means **widening the notifier into a key-admission service** (or introducing one) — a
materially larger change than "route the provider path through the existing notifier."

**Keystore-less admission (C4).** The unified path must accept a raw `SecretKey` with **no keystore
file on disk and no denylist row to persist** — the shape secret-provider refresh delivers
(`bootstrap/enablement.rs:172-189`) — as a first-class admission mode, not an error path.

**Acceptance criteria.**
- A test admits a key via the secret-provider refresh callback and asserts, after admission:
  `pubkey_map` contains it; `ValidatorStore` has an entry; the `key_gen_tx` value increased;
  the forward-window machine has it registered.
- A follow-on test asserts the same key is **sampled by the liveness loop** and can transition out
  of `Pending` — the starvation defect, tested directly.
- A test admits a raw `SecretKey` with no keystore file present and asserts success (no filesystem
  write attempted, no denylist row required).
- The denylist re-check at `enablement.rs:174-183` (DELETE-races-refresh) is preserved and tested.
- Keymanager import behaviour is unchanged: existing keymanager adapter tests stay green.

#### ARCH-P0-6 — Proposer-config URL updates are applied, or the knob is rejected

| | |
|---|---|
| **Closes** | Weakness 7 (MEDIUM/HIGH) |
| **Evidence** | PB-B1 |

The apply callback at `bootstrap/tasks.rs:127-136` must write fetched updates (fee recipient,
builder enablement, gas limit, and the `_default` currently discarded by name) to `ValidatorStore`.
If applying is deferred, `config.proposer_config.url` must be **rejected at startup** with a named
config error rather than accepted and ignored (A-2 sets "apply" as the default).

**Acceptance criteria.**
- A wiremock-backed test serves a proposer config with a changed fee recipient, drives one refresh
  tick, and asserts `ValidatorStore` returns the **new** fee recipient for that pubkey.
- A test asserts a subsequent block proposal uses the updated fee recipient.
- A negative test asserts a malformed/unauthorized fetch leaves the previous value intact and logs
  at `warn`.
- If the reject-instead variant is taken, a startup test asserts the named `ConfigError` and exit
  code.

#### ARCH-P0-7 — Monitoring push reports live validator counts

| | |
|---|---|
| **Closes** | Weakness 7 |
| **Evidence** | PB-B2 |

Replace the boot-time constant closure at `bootstrap/tasks.rs:106` with a provider reading current
state (`PubkeyMap` / `ValidatorStore`), and make the two tuple elements mean different things
(total vs active/enabled) or collapse to one with a documented meaning (A-3).

**Acceptance criteria.**
- A test imports a key via the keymanager after the push task has started and asserts the next push
  payload carries the incremented count.
- A test deletes a key and asserts the count decrements.
- The active count reflects doppelganger enablement state, not merely loadedness.

#### ARCH-P0-8 — Resolve the t=0 `SlotContext` question empirically, then fix or document

| | |
|---|---|
| **Closes** | Weakness 8 (MEDIUM, unverified empirically) |
| **Evidence** | PB-A3 |

Land a wiremock test that pins the BN's actual behaviour for `get_block_root(slot=<current slot>)`
at slot start (404 vs. previous-slot root vs. head). Then:

- **If it 404s** (the expected case): capture the **parent/previous** root at t=0 for the proposal
  path and **re-capture** at phase 2 for sync-committee duties, so `sync_committee.rs:65-74` no
  longer skips.
- **If it does not 404**: record the measurement and downgrade the finding, keeping the wiremock
  test as the regression pin.

**Acceptance criteria.**
- The wiremock test exists and asserts a specific documented BN behaviour (not a self-consistency
  tautology).
- A test drives a full slot with a 404-on-current-slot BN and asserts sync-committee messages are
  **produced** (today: skipped).
- The H-5 TOCTOU property is preserved: the proposal and attestation phases still use one captured
  root, and the re-capture is scoped to the sync path with a test proving no cross-phase drift.
- A metric or `warn`-level counter exists for "sync messages skipped: no head root", so the failure
  is observable if it recurs.

#### ARCH-P0-9 — Move audit-log emission outside the slashing DB mutex

| | |
|---|---|
| **Closes** | Weakness 5 (the compounding half) |
| **Evidence** | PB-C2 |
| **Constraints** | **C2** (this requirement *is* C2) |

`audit_log` must not be called while a `parking_lot::MutexGuard<Connection>` is held. Restructure
`crates/slashing/src/scoped.rs:62-77` (and the corresponding `stage_attestation` path at `:88+`) so
the outcome is captured and emitted after the guard is released or handed off — accepting that
"staged" events then correlate with commit/discard rather than preceding them.

**Priority departure from the review** (which places this in Phase 4): the deadlock is a **live
availability hazard today**, triggerable by an ordinary observability change, and the fix is small
and independent of the PB-C1 critical-section redesign. Deferring it means carrying a
signing-wedges-permanently landmine through four phases. See *Departures*.

**Acceptance criteria.**
- A test installs a tracing subscriber that acquires the slashing DB lock on every event, performs a
  full stage→sign→commit, and **completes** (today: deadlocks — so the test must be written with a
  timeout that fails RED).
- An architecture-test-style scan asserts no `audit_log` call site is lexically inside a scope
  holding a staged guard.
- Audit-event content and ordering guarantees are re-documented in `scoped.rs` to match the new
  reality; the misleading `:70-74` note is replaced, not merely edited.
- `crates/slashing/src/stage.rs` is **not** modified by this requirement — `git diff <base> --
  crates/slashing/src/stage.rs` is empty for the PR. **This is not an arbitrary scope limit:** it is
  the mechanism by which ARCH-P0-9 sidesteps the tracing initiative's prospective byte-identical pin
  on that file (**A-12**, R9), so P0-9 can land in Phase 1 without any cross-plan negotiation. Do not
  relax it without re-reading A-12.

### P1 — Evolvability and scaling

#### ARCH-P1-1 — Config-drift gate (precondition on all future knob work)

**Closes** W6. **Evidence** PB-D1.

An architecture test, in the `kat_policy` scanner style, asserting: (i) every `CliOverrides` field
(`config/types.rs:1313-1383`, 65 today) is consumed in `merge_with_cli` (`:1210`); (ii) every clap
argument declared in `bin/rvc/src/cli.rs` maps to a `CliOverrides` field; (iii) every `Config` field
reachable from a knob has a validation or an explicit no-validation marker.

**Acceptance criteria.** Adding a clap arg without an override fails CI; adding an override field
without a `merge_with_cli` consumer fails CI; the failure message names the field. The gate is
demonstrated RED against a scratch commit that adds an orphan arg. **This gate must land before
ARCH-P1-2 and before any feature work that adds a knob** (G5).

#### ARCH-P1-2 — Extract `rvc-config`: one declaration per knob

**Closes** W6. **Evidence** PB-D1. **Constraints** **C3** (binding).

Collapse the four sites into one declaration per knob generating the clap arg, the override, the
merge, and the validation — macro-based or figment-style layered providers with provenance in error
messages. **The figment `Env` provider layer is forbidden** (C3): a general env-overrides-config
layer erodes the "env = security opt-outs only" rule. Ship ARCH-P1-3 alongside.

**Acceptance criteria.** Knob count declared once; `CliOverrides`, `merge_with_cli` and the clap
block are generated or eliminated; ARCH-P1-1's gate still passes (or becomes structurally
unnecessary and is replaced by a generation check); `rg 'figment::providers::Env'` returns nothing;
a config error names the provenance layer (file / CLI / default) of the offending value; behaviour
parity proven by a round-trip test over every existing knob.

#### ARCH-P1-3 — `RVC_*` environment-variable allow-list gate

**Closes** W6 / codifies Strength 6. **Constraints** **C3**.

A `kat_policy`-fashion scan pinning the exact set of `RVC_*` environment variables the code reads,
each with a recorded justification, so "env = security opt-outs only" is enforced rather than
observed.

**Acceptance criteria.** Reading a new `RVC_*` var without adding an allow-list entry fails CI; the
allow-list entry requires a reason string; the list is shrinking-only by convention, mirroring the
KAT `EXEMPTIONS` policy.

#### ARCH-P1-4 — `TaskExecutor`: named, metered, panic-contained, joined spawns

**Closes** W3 (structural half). **Evidence** PB-A2. **Constraints** **NG3** (utility, not framework).

A minimal lighthouse-style executor in the bootstrap layer: named spawns, per-task metrics, panic
containment, a `ShutdownReason` channel so a critical task failure produces a coordinated shutdown,
and a bounded join-all at exit. Ban raw `tokio::spawn` via clippy `disallowed-methods`.

**Acceptance criteria.** `rg 'tokio::spawn' crates/rvc/src bin/` returns only allow-listed sites
(target: zero outside the executor); a test asserts a panicking task triggers a reasoned shutdown
rather than a silent leak; every task has a name visible in a metric label; the existing spawns at
`bootstrap/tasks.rs:103,124`, `enablement.rs:170`, `keymanager_adapters/spawn.rs:247` are migrated.

#### ARCH-P1-5 — Slashing-DB critical-section redesign

**Closes** W5 (HIGH at scale). **Evidence** PB-C1. **Constraints** **C1** (binding), **C2**
(prerequisite: ARCH-P0-9), **C9**, and the cross-plan pin in **A-12**.

Shorten or shard the stage→sign→commit hold window so slashable signing meets deadlines at the
target validator count with a remote signer. **The design space is constrained**: a naive
"stage → release → sign → re-check-and-commit" is **rejected** because it cannot retain a released
row, and retain-on-ambiguity (timeouts and ambiguous remote errors *commit* the still-staged row) is
a safety property, not an implementation detail. Admissible designs are **tentative-commit-then-reconcile**
(commit before signing; reconcile/GC on definitive failure) or **per-pubkey connections**.

**Acceptance criteria.**
- A proptest/model test over the new ordering passes the EIP-3076 conformance vectors, run
  **before** the switchover.
- A test injecting a remote-signer timeout asserts the slashing row is **retained** (not rolled
  back) — the retain-on-ambiguity property, tested explicitly.
- A test injecting an ambiguous remote error (connection reset mid-response) asserts the same.
- A cancellation test asserts no signature can exist without its slashing record under future-drop
  at every await point.
- `rvc_signer_slashing_tx_hold_duration_ms` p99 improves against the Phase-0 baseline by the target
  in *Success Metrics*.
- The single unbypassable signing gate is preserved (C9): no new signing surface is introduced.

#### ARCH-P1-6 — Fold the non-slashable path and timeout constant into `signer/src/core.rs`

**Closes** W9. **Evidence** PB-D2.

`SignerService` (`crates/signer/src/lib.rs:169`) and `SigningGate` (`crates/signer/src/gate.rs:115`)
must differ only in policy inputs, not in duplicated code paths or duplicated timeout constants.

**Acceptance criteria.** One definition of the timeout constant, referenced by both; a test asserts
the non-slashable path behaves identically through both entry points; the workspace grep gate
forbidding direct `CompositeSigner` use still passes.

#### ARCH-P1-7 — Classify the DVT signing surface

**Closes** W9. **Evidence** PB-D2.

Route `PeerSignerService` (`crates/signer/src/dvt/peer_service.rs:227-230`) through `SigningGate`,
or formally register it in `signer-registry` with its own enforcement contract, so "every signing
surface is classified" holds **under the `dvt` feature**.

**Acceptance criteria.** The `signer-registry` enumeration gate runs with `--features dvt` in CI and
passes; a test asserts a DVT partial signature cannot be produced outside the registered contract.

#### ARCH-P1-8 — `Base` / `Infra` layer split with two new gates

**Closes** W10. **Evidence** PB-D4.

Split `Layer::Foundation` (`architecture-tests/src/lib.rs:73-88`) into **Base** (pure leaves, zero
internal out-edges, gated) and **Infra** (I/O services, may not depend on Domain, gated).
Reclassify `rvc-timing` deliberately — it is `Layer::Domain` at HEAD (`:72`), not Foundation (VD-3).

**Acceptance criteria.** Two new gates exist and are RED against a scratch Base→anything and
Infra→Domain edge; the generated `ARCHITECTURE.md` regenerates byte-identically to the checked-in
copy; every one of the 29 members has a row; `timing`'s classification is stated with a reason.

#### ARCH-P1-9 — One `ProduceBlockResponse`

**Closes** W9. **Evidence** PB-D2.

Sanction one home (default: `bn-manager` as the types facade, A-8) and delete the field-copying half
of `beacon_adapter`.

**Acceptance criteria.** `rg 'struct ProduceBlockResponse'` returns one hit; the adapter's field-copy
function is deleted; block-production behaviour tests unchanged.

#### ARCH-P1-10 — Extract the remote-signer HTTP client out of `crypto`

**Closes** W10. **Evidence** PB-D4.

Move `crypto/remote_signer/` (reqwest client) into an Infra crate so `crypto` becomes a Base leaf
(BLS + EIP-2333 + keystore only); move `is_aggregator`/duty selection to `eth-types`.

**Acceptance criteria.** `crypto` has zero I/O dependencies and passes the Base zero-out-edge gate;
fan-in consumers compile unchanged; no signing behaviour change (KAT-anchored signing-root tests
green).

#### ARCH-P1-11 — Retire the legacy doppelganger mechanism, carrying the KM-2 contract

**Closes** W9 (the `LegacySlashingHistoryReader` foot-gun) + Target-Architecture key-admission goal.
**Evidence** PB-D3. **Constraints** **C5** (binding).

Retire the legacy time-based `DoppelgangerGate`/`DoppelgangerService` once `ForwardWindowMachine`
covers its consumers, deleting `LegacySlashingHistoryReader` (`doppelganger/src/traits.rs:68-75`)
with it — collapsing four mechanisms to one plus the store-level flag.

**C5 is stronger than the review implies (VD-6).** The review says the KM-2 teardown contract is
owned by "the keymanager-api gate." There is no such gate:
`rg 'KM-2|lifecycle|stop_monitoring' crates/architecture-tests` returns **nothing**. The contract
lives in a trait default (`crates/keymanager-api/src/traits.rs:79-88` — `cancel_monitoring` defaults
to `stop_monitoring`), a doc table
(`crates/rvc/src/keymanager_adapters/doppelganger.rs:143-144`: `stop_monitoring` → **no-op** because
M-12 wall-clock elapse must not cancel machine state; `cancel_monitoring` → `ForwardWindowMachine::cancel`
for DELETE / re-import freshness), a runtime `debug` note (`:204-212`), and unit tests
(`keymanager_adapters/tests/misc_adapters.rs:112-121`). So the retirement must both preserve the
contract **and** add the gate the review assumed existed.

**Acceptance criteria.** In whichever mechanism survives: `stop_monitoring` leaves machine state
`Pending` (M-12 elapse ≠ cancel) and `cancel_monitoring` drops state for re-import freshness — both
tested; `rg 'LegacySlashingHistoryReader'` returns nothing; a new architecture test pins the KM-2
distinction so a future collapse of the two methods fails CI; the DELETE path still calls
`remove_validator` + `cancel_monitoring`.

#### ARCH-P1-12 — Head-event attestation triggering, timer authoritative

**Closes** W2 (the reference-client gap). **Constraints** **C7** (binding).

Trigger attestations on "1/3 slot **or** head event, whichever first". The 1/3-slot timer remains
**authoritative**; the SSE stream is a bounded `mpsc(64)` with a documented drop-on-overflow policy
(H-11) that falls back to polling on failover, so **dropped events are expected and must never be
logged as errors or counted as failures**.

**Acceptance criteria.** A test drops every SSE event and asserts every attestation still happens on
the timer; a test delivers an early head event and asserts the attestation fires earlier with no
duplicate; no `error!`/failure metric is emitted on SSE drop or failover; the drop counter is
labelled as expected-path.

#### ARCH-P1-13 — OR-merge doppelganger liveness across healthy BNs

**Closes** W10 (documented residual). **[review-carried, unverified at HEAD]** — cited at
`doppelganger .../liveness_loop.rs:19-24`, which today rides `query_first` with no cross-BN merge.
The fan-out primitive exists in `broadcast_inner`.

**Acceptance criteria.** A test with one BN reporting "not live" and another "live" asserts the
merged verdict is live-detected (fail-safe direction stated explicitly in the test name); the
existing documented-residual note is removed or rewritten.

#### ARCH-P1-14 — Fork readiness: delete the `Wire*` twins, write `docs/forks.md`

**Closes** W9 / Target-Architecture fork section. **Evidence** PB-D2.

Execute the already-documented `Wire*` twin deletion in `crates/eth-types/src/block_body.rs`
**before** the next body-changing fork, and add `docs/forks.md` as an add-a-fork checklist
enumerating the verified `ForkName`/`ForkSchedule`/`body_layout` dispatch sites.

**Acceptance criteria.** One SSZ stack per container; every affected `hash_tree_root` /
`signing_root` test is KAT-anchored per `CLAUDE.md` (this is the exact bug class the policy exists
for); `docs/forks.md` lists dispatch sites and the docs-freshness scan (ARCH-P2-5) verifies each path
exists.

#### ARCH-P1-15 — Scale validation at the target validator count

**Closes** W5 (verification half). **Evidence** PB-C1.

A load test at the target key count with injected remote-signer latency, run before any deployment
above the current supported count.

**Acceptance criteria.** Documented run at 200 keys / 200 ms injected signer latency (defaults, A-9)
showing zero missed attestation deadlines and a recorded `rvc_signer_slashing_tx_hold_duration_ms`
p99; the numbers are checked into the plan directory, not just observed.

#### ARCH-P1-16 — Remove the healthz-only tonic server, with a migration path

**Closes** W7. **Evidence** PB-E2. **Constraints** **C8** (binding).

Deleting the `DutyTrackerServer` at `bootstrap/run.rs:263-276` (and its `select!` arm at `:298`) is
**operator-visible**: k8s liveness/readiness probes or monitoring may target the gRPC endpoint.

**Acceptance criteria.** A deprecation note in the release notes naming the replacement probe
(default: the existing metrics/health HTTP surface, A-4); a documented probe-migration check;
the `grpc_address`/`grpc_port` config knobs are removed **or** repointed, not left accepting input
that does nothing (which would recreate PB-B1's failure mode); one release of deprecation warning
before removal.

### P2 — Polish

| ID | Requirement | Closes / Evidence | Acceptance criterion |
|---|---|---|---|
| **ARCH-P2-1** | Evict `ValidatorLockMap` entries on key removal / by LRU bound | W10 / PB-C3 | A test churns N keys and asserts the map size is bounded; no lock is evicted while held |
| **ARCH-P2-2** | Type the slashing storage layer: canonical pubkey/root newtypes replacing `pubkey: String` and string root comparison; remove `.expect("infallible")` canonicalization (`slashing/src/db/mod.rs:54`) **[review-carried, unverified at HEAD]** | W10 | No `String` pubkey or root comparison remains in `slashing/src/types.rs`; EIP-3076 vectors green; no new `.expect` in production code (`CLAUDE.md`) |
| **ARCH-P2-3** | Decentralize `metrics::definitions` so each crate registers its own metrics; `signer-server` adopts the shared registry | W10 | `metrics` has no reverse dependency on domain crates; the metrics-conformance gate still passes |
| **ARCH-P2-4** | Prune the KAT `EXEMPTIONS` entries that are in fact KAT-anchored | W10 | The list shrinks; `kat_policy` green; the shrinking-only convention in `CLAUDE.md` is respected (removals only, never additions) |
| **ARCH-P2-5** | Docs-freshness scan (every path mentioned in `docs/` exists) + retire the mis-titled `docs/architecture.md` | W10 / PB-E2 | Gate is RED against a scratch doc citing a dead path. **Executing the move is out of scope for the planning work**; see NG8 |
| **ARCH-P2-6** | `cargo-machete` / `cargo-udeps` in CI; remove `bin/rvc`'s ~6 unused workspace deps | W10 / PB-E2 | CI fails on an unused declared dependency |
| **ARCH-P2-7** | Delete `crates/sync-service` + its `[workspace.dependencies]` alias (`Cargo.toml:33`) + its `CLASSIFICATION` row (`architecture-tests/src/lib.rs:71`) | W10 / PB-E2 | Members list drops to 28; generated `ARCHITECTURE.md` regenerates byte-identically. **Ordinary recoverable delete — C10 does not apply** (it is tracked) |
| **ARCH-P2-8** | Honour `BnRole`/tier in `broadcast_inner` (`bn-manager/src/manager.rs:764`), or reject the config surface; add lighthouse-style pre-slot BN health re-check (~2 s before slot) | W7, reference gap / PB-B4 (verified) | A test asserts a role-scoped broadcast reaches only the intended tier and `tried` reflects the filtered count, **or** a startup test asserts the unsupported knob is rejected |
| **ARCH-P2-9** | Fix stale doc comments and the `signer-registry` shipped-fix TODO | W10 | No TODO referencing an already-shipped fix remains |

### Departures from the review's ranking

Three deliberate departures, each with a stated reason. Everything else follows the review's order.

| Departure | Review's placement | This PRD | Reason |
|---|---|---|---|
| **ARCH-P0-9** (audit log outside the mutex) | Phase 4, bundled into the lock redesign | **P0**, standalone and ahead of ARCH-P1-5 | It is a live availability hazard triggerable by an ordinary observability change (a subscriber that reads the DB wedges all signing, permanently, with no timeout — `scoped.rs:70-74`). The fix is small and does not depend on the redesign. Bundling it means carrying the landmine through four phases; it is also a **prerequisite** for C1's redesign, so doing it first strictly reduces that work's risk. |
| **ARCH-P0-8** (`SlotContext` t=0) | Weakness 8, MEDIUM, "unverified empirically" | **P0** | The review itself calls it the highest-priority empirical question. If it reproduces it is a *standing, silent, every-slot* reward loss for every sync-committee member — larger in expectation than several HIGH items. The P0 requirement is the *measurement plus the conditional fix*, which is cheap; leaving it MEDIUM leaves the question open indefinitely. |
| **ARCH-P0-1/2 split** | "delete the dead trees and add an orphan-directory gate" as one Phase-0 item | Two requirements, gate written **first** as the RED test, deletion gated on a **verified archive** | The trees have no git object behind them (PB-E1), so deletion is irreversible — a materially different risk class from every other delete in the plan. A single "delete them" issue cannot express the archive-verify-delete sequence, and the gate is what makes the deletion provable. |

Two items the review ranks HIGH that this PRD keeps at **P1**, with reasons:

- **W5 (global slashing mutex)** → ARCH-P1-5. It is HIGH *at scale*; at current supported key counts
  it is not a live defect, and its redesign is the highest-risk change in the initiative (C1). It
  belongs after the correctness fixes, with ARCH-P0-9 landed first.
- **W6 (config quadruple bookkeeping)** → ARCH-P1-1/2/3. Evolvability, not correctness — except that
  ARCH-P1-1 (the *gate*, not the collapse) is cheap and is a stated **precondition on all future
  knob-adding work**, so it should be scheduled early within P1 even though it is not P0.

---

## Success Metrics

Each metric names the instrument that produces it. Where the instrument does **not** exist at HEAD,
the metric carries an "instrument first" note — an unmeasurable target is a defective requirement.

| # | Metric | Instrument at HEAD | Baseline | Target | Requirement |
|---|---|---|---|---|---|
| **M1** | Missed-proposal rate under injected BN latency (6 × 10 s duty-fetch stall, warm and cold cache) | **Does not exist** — must be built as a harness test; instrument first | To be measured in Phase 0 (expected: 100 % miss with a stalled fetch, by construction of PB-A1) | **0 missed proposals** with duty fetches stalled for the full 60 s | ARCH-P0-3 |
| **M2** | p99 offset from slot start to entry of `maybe_propose_block` ("slot phase-0 start offset") | **Does not exist** as a metric; the phase span `slot.phase.block` exists (`coordinator/mod.rs:404`) and the basis-points deadline model is in `timing` | To be measured in Phase 0 | **p99 ≤ 1,000 ms** warm cache; **≤ 2,000 ms** cold cache (A-5) | ARCH-P0-3, ARCH-P1-12 |
| **M3** | Slashing-DB transaction hold duration, p99 | **Exists**: `rvc_signer_slashing_tx_hold_duration_ms{kind=block\|attestation}`, observed at `crates/signer/src/core.rs:219`, defined in `metrics::definitions`, regression-tested in `crates/signer/tests/tx_hold_metric.rs` | To be measured in Phase 0 under the ARCH-P1-15 load profile | p99 **below the per-sign budget implied by** 200 keys within one attestation window (A-9); no single hold exceeds the remote-signer timeout | ARCH-P1-5 |
| **M4** | Config declaration sites per knob | Counted by inspection; ARCH-P1-1's gate makes it machine-checkable | **4** sites (`cli.rs` 1,363 lines; `CliOverrides` **65** fields at `config/types.rs:1313-1383`; `Config` in a 3,187-line file; `merge_with_cli:1210` + `validate:1015`) | **1** declaration per knob; `CliOverrides` eliminated or generated | ARCH-P1-1, ARCH-P1-2 |
| **M5** | Architecture gate count, countable against requirement IDs | Countable in `crates/architecture-tests` | Existing suite: DAG acyclicity, forbidden edges, required edge, zero-out-edge pins, `ARCHITECTURE.md` byte match, KAT policy, log-field conformance, single-proto | **+7** gates: orphan-dir D1 **and** uncompiled-source D2 (ARCH-P0-2, two detectors), config-drift (P1-1), `RVC_*` allow-list (P1-3), Base zero-out-edge **and** Infra→Domain (P1-8, two), KM-2 teardown (P1-11); **+3** CI checks: `--features dvt` enumeration run (P1-7), docs-freshness (P2-5), unused-deps (P2-6) | ARCH-P0-2, P1-1, P1-3, P1-7, P1-8, P1-11, P2-5, P2-6 |
| **M6** | Untracked / non-member source lines in the repo | `git ls-files` vs. working tree; enforced by ARCH-P0-2 | **≈26,270** lines (19,750 + 3,749 + 2,771) plus `crates/rvc/src/commands/` | **0**, with a verified archive ref recorded | ARCH-P0-1, ARCH-P0-2 |
| **M7** | Inert config surfaces (accept input, no behavioural effect) | Enumerated and verified in PB-B1…PB-B4 | **4 verified** (PB-B1 proposer-config URL, PB-B2 monitoring count, PB-B3 provider refresh, PB-B4 `BnRole` broadcast routing) + 1 pending removal (healthz `grpc_address`/`grpc_port`) | **0** — each either applied or rejected at startup | ARCH-P0-5/6/7, P1-16, P2-8 |
| **M8** | Raw `tokio::spawn` sites outside the executor | `rg` + clippy `disallowed-methods` | ≥4 known (`tasks.rs:103,124`, `enablement.rs:170`, `spawn.rs:247`) | **0** outside the allow-list; every task named and joined | ARCH-P1-4 |
| **M9** | Duplicated seam count (types/paths with two definitions) | `rg` | ≥4 (`ProduceBlockResponse` ×2, `CliOverrides` ×2, non-slashable path ×2, `Wire*` twins) | **0** | ARCH-P0-1, P1-6, P1-9, P1-14 |
| **M10** | Shutdown work loss | New test harness | In-flight publish dropped on signal (by construction of PB-A2) | In-flight publish completes within the grace period; **0** half-applied key-state mutations | ARCH-P0-4 |

**Phase-0 measurement obligation.** M1, M2 and M3's baselines must be captured *before* any
behavioural change lands, or the targets are unfalsifiable. This is an entry criterion on the first
behavioural requirement (ARCH-P0-3), not a nice-to-have.

---

## Constraint Register (C1–C10)

These are **requirements-level constraints**: a design that satisfies a requirement's headline while
violating its constraint has not satisfied the requirement. Each is carried forward — none is
rejected — with the verified evidence and the concrete failure it prevents.

#### C1 — Retain-on-ambiguity is a safety property; lock-shortening must not break it

**Binds:** ARCH-P1-5. **Evidence:** `crates/slashing/src/stage.rs:24-48` (the guard owns the
`MutexGuard` from `stage_*` through `commit`/`discard`/`Drop`-rollback; the mutex is held across the
signer call by design); `crates/signer/src/core.rs` (the stage→sign→commit core inside
`spawn_blocking`).

Timeouts and ambiguous remote errors **commit the still-staged row**. That is only possible because
the row is still staged, under the lock, when the sign returns. **A "stage → release → sign →
re-check-and-commit" design cannot retain a released row and is therefore rejected outright.**
Admissible: tentative-commit-then-reconcile, or per-pubkey connections. Validation against the
EIP-3076 conformance vectors is a gate on the switchover, not a follow-up.

*Failure prevented:* a "harmless" lock-scope shrink that silently converts an ambiguous remote sign
into a rolled-back row — i.e. a signature that may exist on the wire with no slashing record. This
is the single highest-consequence mistake available in this initiative.

#### C2 — Audit-log emission must move outside the mutex

**Binds:** ARCH-P0-9 (is the requirement), prerequisite for ARCH-P1-5. **Evidence:**
`crates/slashing/src/scoped.rs:68-76` — `audit_log(...)` at `:75` fires while the guard returned by
`:68` still holds the connection mutex; `:70-74` documents that a DB-touching subscriber deadlocks
because parking_lot mutexes are non-reentrant.

*Failure prevented:* an operator adds an audit subscriber that reads the slashing DB and the process
stops signing forever while continuing to look healthy.

#### C3 — The figment `Env` provider layer is forbidden

**Binds:** ARCH-P1-2, ARCH-P1-3. Config consolidation may adopt figment-style layering with
provenance; it may **not** adopt figment's idiomatic `Env` provider. A general env-overrides-config
layer collides with the repo's "env = security opt-outs only" rule (`Config::validate_insecure_env_var`,
`crates/rvc/src/config/types.rs:1114`, is where that discipline is currently expressed). Codify the
rule with an `RVC_*` allow-list scan gate instead.

*Failure prevented:* every security opt-out becoming settable by an ambient environment variable as a
side effect of a "mechanical" config refactor.

#### C4 — Keystore-less key admission must be a first-class mode

**Binds:** ARCH-P0-5. **Evidence:** the refresh callback delivers a raw `SecretKey`
(`crates/rvc/src/bootstrap/enablement.rs:172-189`) with no keystore file and no denylist row; the
notifier path at `crates/rvc/src/keymanager_adapters/notifier.rs:29-60` assumes neither today
because it does almost nothing (VD-5) — the *adapters around it* assume keystore files and denylist
persistence.

*Failure prevented:* unifying the two admission paths by making the provider path write a fake
keystore to disk, or by failing provider admission on a missing keystore.

#### C5 — The KM-2 teardown contract must survive, and must gain a gate

**Binds:** ARCH-P1-11. **Evidence:** `crates/keymanager-api/src/traits.rs:79-88` (trait default:
`cancel_monitoring` falls back to `stop_monitoring`); `crates/rvc/src/keymanager_adapters/doppelganger.rs:143-144,
204-229` (`stop_monitoring` is a **no-op** for machine state — M-12 wall-clock elapse ≠ forward-window
cancel; `cancel_monitoring` calls `ForwardWindowMachine::cancel` for DELETE / re-import freshness);
`crates/keymanager-api/src/lifecycle.rs:29-33`; tests at
`crates/rvc/src/keymanager_adapters/tests/misc_adapters.rs:112-121`.

**Correction (VD-6):** the review attributes ownership to "the keymanager-api gate." No such gate
exists — `rg 'KM-2|lifecycle|stop_monitoring' crates/architecture-tests` returns nothing. The
contract is protected by a trait default and unit tests only.

*Failure prevented:* collapsing the two methods during the legacy-mechanism retirement, which would
either cancel a forward window on M-12 elapse (re-enabling a key that should stay Pending) or fail to
reset the window on re-import (admitting a key on a stale window).

#### C6 — Cold-cache pre-proposal fetch, not a silent skip

**Binds:** ARCH-P0-3. **Evidence:** the cache is invalidated per-slot at
`crates/rvc/src/orchestrator/coordinator/mod.rs:373` (`apply_key_gen_cache_invalidation`), so the
cold window is the first slot after boot **and** every slot after a `key_gen`-driven invalidation.
Proposal-first must fall back to a bounded, short-deadline duty fetch.

*Failure prevented:* "propose only if a cached duty exists" — which converts a key import into a
guaranteed missed proposal for the following slot.

#### C7 — SSE drops are normal, not errors

**Binds:** ARCH-P1-12. Head-event attestation triggering rides a bounded `mpsc(64)` with a documented
drop-on-overflow policy (H-11) and falls back to polling on endpoint failover. **The 1/3-slot timer
stays authoritative**; dropped events cost latency, never a duty, and must never be logged at
`error` or counted as failures. This is Lighthouse's stated model.

*Failure prevented:* making the event stream load-bearing (duties missed when events drop) or
alert-noisy (paging on expected drops).

#### C8 — Healthz removal is operator-visible

**Binds:** ARCH-P1-16. **Evidence:** `crates/rvc/src/bootstrap/run.rs:263-276` serves
`DutyTrackerServer` on `grpc_address:grpc_port`, logged at `:265`. k8s liveness/readiness or
monitoring probes may target it. Requires a deprecation note, a documented probe-migration check,
and disposal of the now-meaningless `grpc_address`/`grpc_port` knobs.

*Failure prevented:* a "hygiene" delete that causes k8s to kill every pod in the fleet on the next
rollout.

#### C9 — The keep-list: no phase may regress these

**Binds:** every requirement. Six preserved properties, each with its anchor:

| Keep | Anchor |
|---|---|
| The `architecture-tests` harness and its gate suite | `crates/architecture-tests/src/lib.rs`; extended, never replaced (NG2) |
| The cancellation-proof stage→sign→commit core | `crates/signer/src/core.rs`; `crates/slashing/src/stage.rs:24-30` |
| KAT-first policy for signing roots and container HTRs | `CLAUDE.md`; `crates/architecture-tests/tests/kat_policy.rs`; `EXEMPTIONS` shrinking-only |
| "env = security opt-outs only" | `crates/rvc/src/config/types.rs:1114`; to be gated by ARCH-P1-3 |
| A single unbypassable signing gate | Single wiring site + the workspace grep gate forbidding direct `CompositeSigner` use |
| Zero unbounded channels | The one data queue (SSE) is bounded `mpsc(64)` with a tested drop policy |

*Failure prevented:* a refactor that is locally clean and globally removes the property the gate
suite exists to guarantee.

#### C10 — Archive before deleting untracked trees

**Binds:** ARCH-P0-1. `git log --all` over the four orphan paths returns **nothing** — never
tracked, no blob, no reflog entry. `rm` is therefore **unrecoverable**, unlike every other deletion
in this initiative (`crates/sync-service`, the healthz server, the `Wire*` twins are all tracked).
Required sequence: archive to a **named** branch/tarball → **verify** the archive by restore-and-diff
→ delete in a separate commit. An issue that says only "delete the orphan trees" does not satisfy
ARCH-P0-1.

*Failure prevented:* discovering six months later that the orphan tree contained the only copy of
something — with no way to get it back.

---

## Non-Functional Requirements

| # | Requirement |
|---|---|
| NFR-1 | **No latency regression on the per-slot deadline path.** Measured against the Phase-0 M2/M3 baselines at the default `info` level. Applies to every requirement, including the "mechanical" ones. |
| NFR-2 | **No new unbounded channel, no new unnamed spawn.** Enforced by C9 and ARCH-P1-4. |
| NFR-3 | **Fail-closed startup preserved.** SEC-9 fork gate, GVR chain-swap gate, keystore fd-lock, and the named exit codes (EXIT_* 10/11/13/14) behave identically after ARCH-P0-4's `process::exit` removal. |
| NFR-4 | **Every phase ships independently and is separately revertible.** No requirement may leave the workspace in a state where a revert of one PR requires reverting another. |
| NFR-5 | **CI runtime must not regress materially** despite +6 gates and +2 checks; scanner-style gates (the `kat_policy` technique) are preferred over compile-heavy approaches. |
| NFR-6 | **Test commands per house practice:** `cargo nextest run --workspace` (not `cargo test --workspace`); `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets -- -D warnings`. |
| NFR-7 | **Observability of every fix.** Each corrected inert feature and each new fallback path (cold-cache fetch, SSE drop, sync-skip) emits a metric or a levelled log line, so a regression is detectable in production rather than only in tests. |
| NFR-8 | **Security-sensitive paths keep their existing properties**: `0o600` keystore permissions via `bin/rvc-keygen/src/fs_util.rs`, denylist re-checks, mTLS/CN allow-list on the signer, GVR checks. No requirement weakens these. |

---

## Out of Scope

- **Any code change, deletion, or source-file edit arising from this planning work.** This document
  and its siblings are the deliverable (NG7).
- **Deleting the orphan trees** — ARCH-P0-1 *specifies* the archive-verify-delete sequence; execution
  is downstream.
- **`docs/prd.md`, `docs/architecture.md`, `docs/project-plan.md`** — the older Test Audit
  Remediation initiative's artefacts (NG8).
- Store migration off SQLite (NG5); actor framework adoption (NG3); crate-DAG re-cutting (NG1);
  new protocol features (NG6).
- Charon-style DVT middleware integration. rvc's full-object signing API keeps that option open;
  taking it is a separate initiative.
- Retrofitting the `signer-server` process's own architecture gates (it shares the signing core; its
  composition root is out of this initiative's frame except where ARCH-P1-6/P1-7 touch it).

---

## Milestones & Phases

Indicative only — sequencing, entry/exit gates and estimates belong to the project plan. Shown here
so the requirement IDs have a visible spine and the dependencies are explicit.

| Phase | Theme | Requirements | Key dependency |
|---|---|---|---|
| **0** | Baseline + hygiene | ARCH-P0-2 (gate first) → ARCH-P0-1 (archive-verify-delete); capture M1/M2/M3 baselines | Baselines are an entry criterion for Phase 2 |
| **1** | Runtime honesty | ARCH-P0-6, ARCH-P0-7, ARCH-P0-5, ARCH-P0-8, ARCH-P0-9 | ARCH-P0-5 needs the notifier widening (VD-5) — size it as a build, not a rewiring |
| **2** | Task topology & slot ordering | ARCH-P0-3, ARCH-P0-4, ARCH-P1-4, ARCH-P1-12, ARCH-P1-13 | Needs Phase-0 baselines; ARCH-P0-4 gates ARCH-P0-3's testability |
| **3** | Config consolidation | ARCH-P1-1 → ARCH-P1-2 + ARCH-P1-3 | Gate strictly before collapse; blocks future knob-adding work |
| **4** | Seam cleanup & lock redesign | ARCH-P1-5, ARCH-P1-6, ARCH-P1-8, ARCH-P1-9, ARCH-P1-10, ARCH-P2-1, ARCH-P2-2, ARCH-P2-3 | ARCH-P0-9 **must** precede ARCH-P1-5 (C2); A-12 pin must be resolved first |
| **5** | Fork & scale readiness | ARCH-P1-14, ARCH-P1-15, ARCH-P1-7, ARCH-P1-11, ARCH-P1-16, ARCH-P2-4…P2-9 | Before the next hard fork / before >100-key deployments |

---

## Risks & Mitigations

| # | Risk | Likelihood × impact | Mitigation |
|---|---|---|---|
| R1 | **The lock redesign (ARCH-P1-5) breaks retain-on-ambiguity subtly** — green tests, wrong safety property | Low × Catastrophic | C1 rejects the naive design by name; EIP-3076 vectors + explicit timeout/ambiguous-error retention tests are gates on the switchover, not follow-ups; ARCH-P0-9 lands first to shrink the change |
| R2 | **Orphan trees deleted without a usable archive** | Medium × High (irreversible) | C10 + ARCH-P0-1's restore-and-diff verification with a recorded manifest hash, in a commit separate from the delete |
| R3 | **Removing `?Send` from `BeaconBlockClient` cascades further than expected** | Medium × Medium | The review's "appears removable" is treated as a hypothesis (A-6); the requirement is satisfied by removal *or* a recorded alternative, so ARCH-P0-4 cannot stall on it |
| R4 | **Proposal-first reordering introduces a new miss mode via the cold cache** | Medium × High | C6 makes the bounded fallback a requirement with its own tests, including the post-`key_gen` slot |
| R5 | **Head-event triggering makes SSE load-bearing** | Medium × High | C7: timer stays authoritative; a test that drops *every* event and still attests is an acceptance criterion |
| R6 | **ARCH-P0-5 is under-sized because the review overstated `KeyChangeNotifier`** | High (already materialised as a review error) × Medium | VD-5 states the corrected scope in the requirement itself, so the estimator sizes the build not the rewiring |
| R7 | **Healthz removal breaks a production probe** | Medium × High | C8: deprecation note, documented probe-migration check, one release of warning, knobs disposed rather than left inert |
| R8 | **Config collapse (ARCH-P1-2) silently drops a knob** | Medium × Medium | ARCH-P1-1's gate lands first and stays green through the migration; round-trip parity test over every existing knob |
| R9 | **Cross-plan collision: the tracing plan pins `crates/slashing/src/stage.rs` byte-identical to `0ae9a09`** | Medium × Medium | Verified **not wired in CI at HEAD** (`rg 'stage.rs\|TRC-1e\|byte-identical' .github` → no matches), so it is prospective. A-12 states the default resolution and ARCH-P0-9 is scoped to avoid `stage.rs` entirely |
| R10 | **Six new gates make CI slow or flaky, and get disabled** | Low × High (loses G7 entirely) | NFR-5: scanner-style gates only; each gate must name the offending path in its failure message so it is actionable rather than annoying |
| R11 | **The initiative drifts into a rewrite** | Medium × High | NG1–NG8 are stated as requirements-level exclusions, and the review's "fundamentally sound" verdict is adopted as a premise in the Overview |

---

## Assumptions

Per the no-ask constraint, **every open question is resolved to a stated default here. Nothing is
escalated.** Each entry names the question, the default taken, and what would overturn it.

| # | Open question | Stated default | Overturned by |
|---|---|---|---|
| **A-1** | Where do the unrecoverable orphan trees get archived? | Branch `archive/untracked-orphans-2026-08-12` **plus** a tarball at `plan/architecture-2026-08-12/archive/untracked-orphans-2026-08-12.tar.gz` (or an equivalent named path recorded in the ARCH-P0-1 issue). Both, not either — a branch can be pruned, a tarball can be lost. | A maintainer naming a different retention location; the *sequence* (archive → verify → delete) is not negotiable (C10) |
| **A-2** | Apply proposer-config URL updates, or reject the knob? | **Apply** them to `ValidatorStore`. Rejecting is the fallback if applying proves to need a `ValidatorStore` API change beyond the phase budget. | Discovering that `ValidatorStore` cannot express a runtime fee-recipient override |
| **A-3** | What do the two monitoring-push count fields mean? | Element 1 = **total loaded** validators; element 2 = **active** (doppelganger-enabled and not denylisted). Documented at the call site. | The monitoring endpoint's published schema specifying otherwise |
| **A-4** | What replaces the healthz gRPC probe? | The existing metrics HTTP surface serves as the liveness/readiness target; the deprecation note names it explicitly. | An operator-supplied probe requirement the metrics port cannot satisfy |
| **A-5** | Pre-proposal budget for M2 / ARCH-P0-3 | **1,000 ms p99 warm cache, 2,000 ms cold cache**, from a 12 s mainnet slot. The cold-cache duty fetch deadline is **500 ms**. | Phase-0 baseline measurement showing these are unachievable or trivially met — in which case they tighten |
| **A-6** | Is `?Send` on `BeaconBlockClient` actually removable? | **Assume yes** (the adapter wraps `Arc<dyn BeaconNodeClient>`, already `Send + Sync`) — but ARCH-P0-4 is satisfied by removal *or* by recording why not plus the alternative taken, so the requirement cannot stall on this. | A `!Send` type reachable from the trait's implementors that cannot be moved behind an owned handle |
| **A-7** | Shutdown grace period | **5 s** bounded join, after which tasks are aborted and the abort is logged at `warn` with the task name. | An in-flight publish measured to routinely exceed it |
| **A-8** | Where does the unified `ProduceBlockResponse` live? | **`bn-manager`**, sanctioned as the beacon-types facade (the review's first option). | A DAG check showing the edge is forbidden, in which case a small shared module |
| **A-9** | Scale-test target | **200 keys, 200 ms injected remote-signer latency**, mainnet slot timing. | A deployment target above 200 keys, which raises the number |
| **A-10** | Does the BN 404 a not-yet-produced slot root? | **Assume yes** (per the Beacon API), which makes PB-A3 a real defect — but ARCH-P0-8 requires *measuring* it before fixing, so a wrong assumption costs one wiremock test, not a wrong fix. | The wiremock/live-BN measurement in ARCH-P0-8 |
| **A-11** | Items marked **[review-carried, unverified at HEAD]** | Treated as **true for planning and prioritisation**, and as **requiring first-step verification inside their own issue**. No requirement's acceptance criterion depends solely on an unverified claim. | Verification during execution; a failed verification converts the requirement into a Verification Delta and may drop it |
| **A-12** | The tracing initiative's standing invariant — *"`crates/slashing/src/stage.rs` is byte-identical to `0ae9a09`, wired as a CI step in Phase 1 (TRC-1e)"* (`plan/tracing-2026-08-06/project-plan.md:69-70`) — conflicts with ARCH-P1-5, which must edit that file | **Verified not wired at HEAD**: `rg 'stage.rs\|TRC-1e\|byte-identical' .github` returns no matches, and `plan/tracing-2026-08-06/` is untracked in git. Default: the pin is **prospective**, and ARCH-P1-5 carries an explicit prerequisite to lift or scope it (e.g. re-pin to the post-redesign hash) **before** touching `stage.rs`. ARCH-P0-9 is scoped to `scoped.rs` only, so it is unaffected either way. | The tracing initiative landing TRC-1e in CI first, which converts this into a hard sequencing dependency between the two plans |
| **A-13** | Does this initiative own the `signer-server` composition root? | **No** — only where ARCH-P1-6/P1-7 touch shared signing code. | A finding that the two composition roots must change together |
| **A-14** | Naming of the new gates | Follow the existing convention: one test file per gate under `crates/architecture-tests/tests/`, named for the property (`orphan_dirs.rs`, `config_drift.rs`, `env_allowlist.rs`, `km2_lifecycle.rs`). | Existing harness structure requiring otherwise |
| **A-15** | Does `crates/rvc/src/commands/` contain anything not present in `bin/`? | **Assume it may** — which is precisely why C10's archive is unconditional. No content comparison is performed as part of the deletion decision; the archive makes the question answerable later. | Nothing — the archive requirement stands regardless |

---

## Verification Deltas

Review claims re-checked against HEAD (`0ae9a09`) that did **not** reproduce as stated. Each carries
the corrected fact forward into the requirement it affects.

#### VD-1 — The pre-proposal critical path is longer than the review states

**Review:** *"duty fetches … and epoch-boundary prep run before `maybe_propose_block`
(`coordinator/mod.rs:375-405`)."*

**HEAD:** the cited range is correct but incomplete in two ways. (i) **Both** `fetch_epoch_duties`
calls (`:376-379`, `:380-383`) run on **every slot**, not only at the epoch boundary — the
`// === Epoch boundary:` comment sits at `:375`, above them, while the actual
`if current_slot % SLOTS_PER_EPOCH == 0` guard begins at `:386`. The worst case is therefore not
confined to slot 0 of an epoch. (ii) `SlotContext::capture` (`:402`) is a **third** pre-proposal BN
round trip that the review's critical-path list omits.

**Carried into:** ARCH-P0-3's acceptance criteria enumerate all four items that must move or be
bounded, including `SlotContext::capture`.

#### VD-2 — Secret-provider-refreshed keys **are** registered with doppelganger; the defect is starvation

**Review:** *"secret-provider-refreshed keys are never scheduled for duties **or enabled by
doppelganger** (`bootstrap/enablement.rs:170-192`)"* and *"stay doppelganger-Pending forever."*

**HEAD:** `machine.register_for_import(&pk, epoch_clock.current_epoch())` **is** called at
`enablement.rs:185-188`, and `signer_for_refresh.add_local_key(sk)` at `:189`. The keys are admitted
to the composite signer and registered with the `ForwardWindowMachine`. What is missing is
`PubkeyMap`, `ValidatorStore`, and the `key_gen_tx` bump. Because the liveness loop is constructed
with `Some(Arc::clone(&keys.pubkey_map))` specifically to re-resolve indices after import
(`:137-145`), a key absent from `pubkey_map` is never sampled — so the outcome (*stuck Pending*) is
right, but the **mechanism is starvation, not absent registration**.

**Carried into:** ARCH-P0-5's acceptance criteria are written against `PubkeyMap` / `ValidatorStore` /
`key_gen_tx` and a liveness-sampling test, not against "register with doppelganger" — which would be
a no-op fix.

#### VD-3 — `timing` is classified `Domain`, not `Foundation`

**Review:** Target Architecture lists `timing` among the *"pure leaves: eth-types, observability,
telemetry, timing, web3signer-wire, signer-proto, metrics"* to become the new `Base` layer.

**HEAD:** `crates/architecture-tests/src/lib.rs:72` classifies `("rvc-timing", Layer::Domain,
"timing", "slot clock")` — it sits in the Domain block (`:64-72`), not Foundation (`:73-88`).

**Carried into:** ARCH-P1-8 requires `timing`'s reclassification to be a deliberate, reasoned
decision rather than an assumed no-op.

#### VD-4 — The orphan trees are not a "pre-refactor snapshot"; they were **never tracked**

**Review:** *"The apparent 'rvc-signer vs signer-server duplication' is a stale pre-refactor snapshot
— delete, don't merge,"* implying a refactor left them behind.

**HEAD:** `git log --all` over all four paths returns **nothing** — no commit, no blob, no reflog
entry. The tracked `bin/` copies were added fresh; the untracked originals were simply never removed.
Corroborated by: mtimes (orphans 2026-07-26 12:40 vs tracked 2026-07-28 00:48 — orphans are ~2 days
*older*); `bin/rvc-keygen/src/fs_util.rs` existing only in the tracked tree, with the orphan still
carrying 14 inline `0o600`/`set_permissions` sites against the member's 12 factored through
`fs_util.rs`; and `crates/rvc-signer/Cargo.toml:2` declaring `name = "rvc-signer-bin"` — the **same
package name** as `bin/rvc-signer/Cargo.toml:2`, so adding it to `[workspace] members` is a
duplicate-package hard error and it cannot be revived as-is.

**Carried into:** the delete conclusion is unchanged, but the **risk class** changes completely —
there is no git object to restore from, so `rm` is unrecoverable. This produced **C10** and the
archive-verify-delete structure of ARCH-P0-1, and it is why ARCH-P0-1 and ARCH-P0-2 are split.

#### VD-5 — `KeyChangeNotifier` does not do what the Target Architecture says it does

**Review:** *"both keymanager imports and secret-provider refresh flow through the
`KeyChangeNotifier` … which **atomically updates composite signer, `PubkeyMap`, `ValidatorStore`,
denylist, doppelganger registration, and bumps `key_gen_tx`**."*

**HEAD:** `crates/rvc/src/keymanager_adapters/notifier.rs` is 61 lines. `KeyChangeNotifier` has
exactly two fields — `pubkey_map` and `key_gen_tx` (`:29-32`) — and three methods: `notify` (bump the
counter, `:46-48`), `insert_and_notify` (`:51-54`), `remove_and_notify` (`:57-60`). It touches
neither the composite signer, nor `ValidatorStore`, nor the denylist, nor doppelganger registration.
Those updates happen in the *adapters* that own a notifier, not in the notifier.

**Carried into:** ARCH-P0-5 states explicitly that satisfying it means **building** a key-admission
service (or widening the notifier), not routing an existing path through an existing component. This
materially raises the estimate; R6 records the sizing risk.

#### VD-6 — There is no keymanager-api architecture gate owning the KM-2 teardown contract

**Review:** the retirement *"must preserve the KM-2 lifecycle invariant **the keymanager-api gate
currently owns**."*

**HEAD:** `rg 'KM-2|lifecycle|stop_monitoring' crates/architecture-tests` returns **no matches**. The
contract is expressed by a trait default (`crates/keymanager-api/src/traits.rs:79-88`), a doc table
and a runtime `debug` note (`crates/rvc/src/keymanager_adapters/doppelganger.rs:143-144, 204-229`),
module docs (`crates/keymanager-api/src/lifecycle.rs:29-33`), and unit tests
(`crates/rvc/src/keymanager_adapters/tests/misc_adapters.rs:112-121`) — i.e. by convention and
tests, not by a gate.

**Carried into:** ARCH-P1-11 must both preserve the contract **and add the gate the review assumed
existed**; C5 states the corrected protection level. This also strengthens the case for G7.

#### VD-7 — The `stage.rs` evidence for the mutex hold is a doc comment, not code

**Review:** cites *"`crates/slashing/src/stage.rs:32-48`"* as the evidence that the global mutex is
held across the sign call.

**HEAD:** `:32-48` is a module-level doc-comment section titled *"Trade-off: holding the mutex across
the signer call."* It is accurate and authoritative as **design intent** — it says the mutex is held
for the entire stage → signer-call → commit window, and concedes the remote-signer failure case at
`:43-44` — but it is prose. The mechanism lives in the guard-returning `stage_*` implementations and
their `MutexGuard<'db, Connection>` ownership, sketched at `:24-30` and pinned by the `!Send` note at
`:57-63`.

**Carried into:** ARCH-P1-5's acceptance criteria are written against the guard-returning code and
the EIP-3076 conformance vectors. A change that edits only the doc comment must fail them.

**Claims that reproduced exactly** (recorded so the absence of a delta is informative, not an
oversight): `bootstrap/run.rs:297-317` inline-`select!` shutdown; `run.rs:83` in-async
`process::exit`; `keymanager_adapters/spawn.rs:247-251` fire-and-forget spawn;
`block-service/src/traits.rs:13` `#[async_trait(?Send)]`; `tasks.rs:106` frozen validator count;
`tasks.rs:124-137` discarded proposer-config updates; `slashing/src/scoped.rs:70-75` audit-log inside
the mutex; `slot_context.rs:40-58` + `sync_committee.rs:65-70` sync-skip mechanism;
`cli.rs` = **1,363** lines; `config/types.rs` = **3,187** lines; `CliOverrides` = **65** fields;
`crates/rvc/src/main.rs` = **2,771** lines; `crates/rvc/Cargo.toml:3` `autobins = false`;
`sync-service` **is** a workspace member (`Cargo.toml:2`, alias at `:33`); 29 workspace members;
`RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS` exists and is observed at `crates/signer/src/core.rs:219`;
broadcast ignores `BnRole`/tier (`crates/bn-manager/src/manager.rs:764` iterates all clients);
`crates/rvc/src/bootstrap/run.rs:263-276` serves the healthz-only `DutyTrackerServer` in a top-level
`select!` arm (`:298`).
