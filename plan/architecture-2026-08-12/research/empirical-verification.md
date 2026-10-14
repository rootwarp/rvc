# Empirical Verification: Q1 (`SlotContext` t=0) and Q2 (`?Send` on `BeaconBlockClient`)

> Research note for the architecture-remediation initiative on the rs-vc Cargo workspace.
> Baseline: `develop` @ `0ae9a09` (v0.7.0). Authored 2026-08-12.
>
> **Authoritative inputs, in precedence order:**
> [`plan/architecture-2026-08-12/prd.md`](../prd.md) (scope, requirement IDs `ARCH-P0-*`, constraint
> register `C1`–`C10`) → [`docs/research/architecture-review-2026-08-11.md`](../../../docs/research/architecture-review-2026-08-11.md)
> (Weakness 8 and Weakness 3, the two claims resolved here) → the repository's
> [`CLAUDE.md`](../../../CLAUDE.md) (TDD, KAT-first policy, error handling).
>
> **This note resolves; it does not survey.** Both questions were left open by the review — Weakness 8
> explicitly ("unverified empirically"), Weakness 3 implicitly ("the annotation *appears* removable").
> Each section ends in a **verdict** binding on the downstream project plan.
>
> **No-ask constraint:** every open question is resolved to a stated default in *Assumptions*.
> Nothing is escalated.
>
> **Output confinement:** this is a planning artefact. No source file in the repository was modified,
> and nothing outside this file was written.
>
> **Tooling limitation — stated once, up front, and repeated at each affected section.**
> This session had **no shell tool** (available: `Read`, `Write`, `Edit`, `Glob`, `Grep`,
> `WebSearch`, `WebFetch`). Therefore **no `cargo` command was run, no `git worktree` was created,
> and no wiremock server was started.** Both verdicts rest on exhaustive static analysis of named
> files at HEAD plus primary external sources — never on an executed build. The two experiments are
> instead *specified* verbatim (Q2.3 commands; Q1.5 test skeleton) so each becomes the first task of
> its requirement, and each verdict states its residual risk explicitly. Nothing below should be
> read as "the build was tried." See **A-1**.

---

## Verdicts at a glance

| Q | Question | **Verdict** | Confidence | Effect on the plan |
|---|---|---|---|---|
| **Q1** | Does `SlotContext::capture` break sync-committee duties? (review Weakness 8) | **REAL — and understated.** Not partially real, not evaporated. Confirmed at every hop: t=0 query of an empty slot → spec-mandated `404` → `head_root = None` → **both** sync phases return early. And it is **not sync-only**: a third consumer, `block_proposal/mod.rs:104`, feeds the same field into `expected_parent_root`, leaving the H-4 parent-root check inert every slot and arming a dropped-proposal bug on any slot where `capture` succeeds (VD-Q1-6). Re-rank **MEDIUM → HIGH** | High | **ARCH-P0-8 must exist and must ship.** Five amendments in Q1.7. Load-bearing: cover *contributions* as well as messages; **split `SlotContext` into `parent_root` (t=0) and `head_root` (phase 2)** rather than making one capture succeed — the naive fix activates a missed-block bug; fix the seven `Ok`-for-anything mocks; sequence with-or-before ARCH-P0-3 |
| **Q2** | Is `?Send` on `BeaconBlockClient` removable? | **YES — but the review's one-line fix is incomplete.** Removing the annotation is *necessary and not sufficient*: `BeaconBlockClient` also needs a `Send + Sync` supertrait, without which `Arc<B>` keeps `DutyOrchestrator` `!Send`. Zero non-`Send` types block it. ≈20 lines, net negative | High on the audit; **the compile was not run** (Q2.3) | **ARCH-P0-4 item 1 must be amended** to name six annotation sites plus the supertrait. Risk **R3 → Low × Low**; assumption **A-6 → finding** |
| **Q2 (corollary)** | Does the `!Send` slashing staging guard contribute to the orchestrator's `!Send`-ness? | **NO — refuted by primary evidence.** `signer/src/core.rs:36-41`, `:284-287`, `:542` confine the guard to a `spawn_blocking` thread; the bare `tokio::spawn` at `core.rs:930` compile-proves `sign_slashable`'s future is `Send` | High | **ARCH-P0-4 is independent of the C1 critical-section redesign.** Nothing needs serialising between Phase 1 and the slashing work on `!Send` grounds |

**Two facts that change scheduling, and are stated nowhere upstream:**

1. **Q1 is worst when the system is healthiest.** The pre-`capture` duty fetches are cache-guarded
   (`duty_management.rs:66`, `:86`, `:106`), so on a warm cache they cost **zero** BN round trips
   and `capture` fires at t≈0+ε — guaranteeing the 404. Degraded BNs *accidentally mask* the defect.
   ARCH-P0-3 removes even that cover. (This also corrects `prd.md:80`.)
1a. **Q1 is not a sync-committee-only defect.** Enumerating consumers of `ctx.head_root`
   (`rg 'head_root' crates/rvc/src/orchestrator/`) returns three, not two. The third —
   `block_proposal/mod.rs:104` → `expected_parent_root` → `BlockResponseValidator` — means the
   naive fix ("make the capture succeed") would turn a currently-inert H-4 check into a
   valid-block rejector. **The fix must split the field, not repair the query.** (VD-Q1-6.)

2. **Q2's blocker is a missing supertrait, not a `!Send` type.** `BeaconBlockClient` is the **only**
   service trait in the workspace without `: Send + Sync` — eight peers declare it. The fix restores
   consistency rather than introducing a constraint.

---

## Q1 — Does `SlotContext::capture` break sync-committee duties?

### Q1.0 The claim under test

> "**8. SlotContext t=0 semantics may systematically degrade sync-committee duties — MEDIUM,
> unverified empirically.** `SlotContext::capture` queries the *current* slot's block root at slot
> start (`orchestrator/slot_context.rs:40-58`), before that block can exist; per the Beacon API this
> should 404, and the code then *skips* sync messages for the slot
> (`orchestrator/sync_committee.rs:65-70`). The runtime-model lens flags this as needing a
> wiremock/live-BN check — highest-priority empirical question in this review."
> — `docs/research/architecture-review-2026-08-11.md:116`

**Reframing the question, because the review asks it slightly wrong.** The review asks "does it
404?" That is not the discriminating question. `slot_context.rs:42-58` collapses **every** non-`Ok`
outcome into `head_root = None`:

```rust
let head_root = match beacon.get_block_root(&block_id).await {
    Ok(response) => match parse_hex_root(&response.data.root) { Ok(root) => Some(root), Err(e) => { warn!(…); None } },
    Err(e) => { warn!(slot, error = %e, "Failed to fetch block root for slot context; continuing without head_root"); None }
};
```

So 404 vs 400 vs 500 vs connection-refused are **behaviourally identical** to rvc. The status code
is irrelevant. The **only** BN response that would make Weakness 8 evaporate is a **`200` carrying
some usable root** — in practice the previous (parent) block's root, which is what a client that
resolves a slot-`block_id` "backwards over skips" would return. That is the single external fact
this section must pin, and it is what Q1.1–Q1.2 do.

### Q1.1 What the Beacon API specifies for `GET /eth/v1/beacon/blocks/{block_id}/root`

From the canonical OpenAPI source, `apis/beacon/blocks/root.yaml` in `ethereum/beacon-APIs` [1]:

| Code | Spec text | Applies here? |
|---|---|---|
| `200` | object with `execution_optimistic`, `finalized`, `data.root` (*"HashTreeRoot of BeaconBlock/BeaconBlockHeader object"*) | Only if a block exists at that `block_id` |
| `400` | *"The block ID supplied could not be parsed"*, e.g. `{code: 400, message: "Invalid block ID: current"}` | No — a decimal slot parses fine |
| `404` | **"Block not found"** | **Yes** |
| `500` | internal error | No |

`block_id` is specified as *"'head' … 'genesis', 'finalized', a slot number, or a hex-encoded
blockRoot with 0x prefix"* [1]. rvc passes a decimal slot number
(`slot_context.rs:41`: `let block_id = slot.to_string();`), so the `<slot>` form is in scope and
`404 Block not found` is the specified response when that slot carries no block.

**The spec does not describe a "resolve backwards to the previous block" behaviour for a slot
`block_id`.** The question was raised directly as `ethereum/beacon-APIs` issue #126, *"[Clarification]
Skipped slots in `/eth/v1/beacon/blocks/{block_id}` endpoint"* [2] — i.e. whether a skipped slot
should 404 or return the most recent non-skipped block. The shipped OpenAPI carries only
`404 Block not found`; there is no 200-with-parent branch. **[Confidence: high on the spec text,
which was fetched directly; medium on issue #126's *resolution*, whose comment thread was not
retrievable — the shipped spec is treated as the answer.]**

### Q1.2 What real clients actually return

Lighthouse, primary source, `beacon_node/http_api/src/block_id.rs` on `stable` [3]:

```rust
chain.block_root_at_slot(*slot, WhenSlotSkipped::None)
// …
root_opt.ok_or_else(|| warp_utils::reject::custom_not_found(format!("beacon block at slot {}", slot)))
```

Three things follow, and the third is the one that settles Q1:

1. `WhenSlotSkipped::None` — the "resolve backwards over skips" variant (`WhenSlotSkipped::Prev`)
   exists in Lighthouse and is deliberately **not** used here. So no parent root is substituted.
2. A missing block yields `custom_not_found` → HTTP 404, body
   `{"code":404,"message":"NOT_FOUND: beacon block at slot N"}`.
3. **The implementation does not distinguish a future slot from a skipped historical slot** — both
   take the same `None` branch. This is confirmed independently by Lighthouse issue #4904, whose
   whole complaint is that an operator *cannot* tell "missed slot" from "not yet proposed" because
   both return the same 404 [4].

**Disconfirming evidence, sought and found — then found to be obsolete.** Lighthouse issue #2186
(2021), *"bn `/eth/v1/beacon/blocks/{block_id}` return wrong information on skipped block"*,
reports precisely the evaporating case: querying skipped slot `554465` returned the data for block
`554464`, the most recent non-skipped block [5]. This was filed **as a bug**, on the grounds that
the endpoint should 404. The `WhenSlotSkipped::None` code at `stable` today [3] is that bug's
resolution. So the 200-with-parent behaviour is not hypothetical — it existed, it was
**deliberately removed**, and relying on it would be relying on a fixed defect.

**Cross-client.** The 404-on-empty-slot convention is the ecosystem norm rather than a Lighthouse
quirk: Teku issue #7635 argues about `blob_sidecars` on the explicit premise that *"404 error is
reserved for empty slots"* [6]. **[Confidence: high for Lighthouse (primary source read);
medium for Prysm/Teku/Nimbus/Lodestar — no primary source for their `blocks/{slot}/root` slot
resolution was retrieved. This is recorded as open question OQ-1 with a stated default in
*Assumptions* (A-2).]**

**Timing check — is the current slot even "empty" when rvc asks?** Yes, necessarily. `capture` is
called with `current_slot` from `self.clock.current_slot()` (`coordinator/mod.rs:357`, `:402`). At
t≈0 of slot N the proposer for slot N has not yet published; a block for slot N cannot exist in any
honest BN's fork-choice store. This is not a probabilistic claim about network propagation — it is
the ordering of the slot itself. So the query is against an empty slot **by construction, every
slot**, not only on skipped slots.

### Q1.3 What rvc does with each possible response — the error path end to end

Traced at HEAD, every hop:

| # | Hop | Location | Behaviour on a `404` |
|---|---|---|---|
| 1 | HTTP | `crates/beacon/src/client.rs:359-360` builds `/eth/v1/beacon/blocks/{block_id}/root`, then `self.get(&path)` (`:227-233`) | — |
| 2 | Status handling | `client.rs:976-978` — `if !status.is_success() { return Err(Self::api_error_from_response(response).await); }` | `Err(BeaconError::ApiError { status: 404, message: "Block not found" })` |
| 3 | Retry policy | `crates/beacon/src/retry.rs:59-61` — retryable ⇔ `429` or `5xx`; `retry.rs:92` asserts `!is_retryable_status(NOT_FOUND)` | **Not retried** on this BN. Correct, and it caps the waste at one round trip per BN |
| 4 | Multi-BN | `crates/bn-manager/src/manager.rs:918-923` — `query_first("get_block_root", BnRole::All, HealthTier::SmallLag, …)`; on all-healthy-failure it falls through to `fallback_unsynced` (`manager.rs:599-601`, `:683-727`) | Every BN 404s. `query_first` returns `Err`. **Every configured BN is queried, every slot, for a guaranteed-empty slot** — an unremarked cost the review does not mention |
| 5 | Capture | `crates/rvc/src/orchestrator/slot_context.rs:50-57` | `warn!(slot, error, "Failed to fetch block root for slot context; continuing without head_root")` → `head_root = None`. **`warn`, not `error`** |
| 6 | Reuse | `coordinator/mod.rs:402` captures `ctx` **once**; it is passed by reference to phase 1 (`:405`), phase 2, and phase 3. There is no re-capture anywhere in `run()` | `ctx.head_root == None` for the whole slot |
| 7a | Sync messages (phase 2) | `sync_committee.rs:65-74` — `None => { warn!(slot, "Skipping sync committee messages: head_root unavailable in slot context"); return; }` | **All sync-committee messages skipped** |
| 7b | Sync contributions (phase 3) | `sync_committee.rs:148-157` — same shape, *"Skipping sync committee contributions: head_root unavailable in slot context"* | **All contributions skipped** — a second consumer the review's `:65-70` citation misses |
| 8 | **Block proposal (phase 1)** | `maybe_propose_block(ctx.slot, ctx.epoch, &ctx)` at `:405` → `block_proposal/mod.rs:104` passes **`ctx.head_root`** as the fourth argument of `block_service.propose_block(slot, &pubkey, expected_proposer_index, ctx.head_root)`, whose parameter is named **`expected_parent_root: Option<Root>`** (`block-service/src/service/mod.rs:89-102`) and lands in `BlockResponseValidator.expected_parent_root` (`:97-101`) | **A third consumer, and a third defect — see below.** `None` ⇒ `check_parent_root` (`block-service/src/validation.rs:63-70`) short-circuits on `if let Some(expected)`, so the **H-4 parent-root validation of the produced block is inert every slot** |
| 9 | Attestations (phase 2) | `attestation_service.process_slot(current_slot)` at `:458-462` — takes `current_slot`, **not** `ctx` | Unaffected |

#### The proposal path is a third victim — and hides a latent missed-block bug (VD-Q1-6)

Enumerating every consumer of `ctx.head_root` in production code
(`rg 'head_root' crates/rvc/src/orchestrator/`, excluding tests) returns exactly three:
`sync_committee.rs:65`, `sync_committee.rs:148`, and **`block_proposal/mod.rs:104`**. The third was
missed by the review, by the PRD, and by the first draft of this note.

**It is a semantic type error that only "works" because the query always fails.** `SlotContext`
declares the field as *"Head block root at slot start"* (`slot_context.rs:24`) and populates it with
`get_block_root(slot)` — **slot N's own root**. `block_proposal/mod.rs:104` then feeds that value
into a parameter called `expected_parent_root`. A block proposed *for* slot N can never have slot
N's own root as its parent. The two names describe different chain positions and the code equates
them. `validation.rs:9`'s own doc comment fossilises the confusion: *"`parent_root` matches the
expected **head root** when provided (H-4)."*

Two consequences, in opposite directions:

1. **Today (`head_root == None`, every slot):** `check_parent_root` never fires. The H-4 parent-root
   check — defence against a BN returning a block built on the wrong ancestor — is **shipped and
   inert**, for the same root cause as the sync skip. That is the same failure family as PB-B1/PB-B2
   in the PRD: a validation that appears in the code, in the doc comment, and in review, and does
   nothing.
2. **Whenever `capture` *does* succeed — a latent dropped proposal.** In the cold-cache or
   degraded-BN window where `capture` fires late enough that slot N's block already exists
   (Q1.3 masking table), `expected_parent_root` = slot N's own root, the produced block's
   `parent_root` = slot N−1's root, they differ, and `check_parent_root` returns
   `BlockServiceError::ParentRootMismatch` (`validation.rs:63-70`) — **a valid block is rejected and
   the proposal is lost.** The window is narrow, but it opens precisely on the slow/degraded slots
   where proposals are already at risk.

This inverts the naive fix. "Just make `capture` succeed" would *activate* defect (2). Any change to
`SlotContext` must therefore fix the proposal path and the sync path **together** — see Q1.7
amendment 5, which is rewritten around this finding.

**Blast radius, corrected (VD-Q1-1):** the review cites only `sync_committee.rs:65-70` (messages).
Contributions at `:148-157` fail identically and independently. Both sync-committee reward
components are lost, not one. Attestations and proposals are untouched — the defect is exactly
co-extensive with the sync-committee duty.

**Observability, corrected:** the failure emits `warn` at three places per affected slot
(`slot_context.rs:51`, `sync_committee.rs:68`, `:151`) and **no metric**. There is no counter for
"sync messages skipped: no head root", so the condition is invisible on a dashboard and invisible
to alerting; an operator sees only `warn` lines and a sync-committee participation rate that is
quietly zero.

#### The masking analysis — and a correction to PB-A1 that inverts its effect

The intuitive escape is: *`capture` at `:402` runs after the duty fetches at `:376-383`, which
PB-A1 says can burn up to 6 × 10 s, so `capture` often fires late enough that slot N's block does
exist.* That would make the defect intermittent. **It does not hold in the healthy case, and the
reason is a PRD correction.**

`fetch_epoch_duties` is **cache-guarded on all three fetches**
(`crates/rvc/src/orchestrator/duty_management.rs:66`, `:86`, `:106` — each fetch sits behind
`if !self.duty_tracker.is_*_cached(epoch).await`), and the prefetch at `:132` is itself guarded by
a `prefetched_periods` set (`:162`). On a warm cache the two every-slot calls at
`coordinator/mod.rs:376-383` perform **zero BN round trips** — an eviction pass, three cache reads,
a count read. This corrects `prd.md:80`, which carries *"up to 6 × 10 s BN timeouts — **every
slot**"* tagged **[review-carried, unverified at HEAD]**. Verified: the 6 × 10 s worst case is real
but **conditional on cache miss** — cold cache after boot, after a `key_gen` invalidation
(`:373`), at an epoch rollover, or when fetches keep *failing* (a failed fetch never populates the
cache, so it retries every slot — the review's degraded-BN scenario, which stands).

Therefore:

| BN health | Pre-`capture` latency | Does slot N's block exist at `capture`? | Sync duties |
|---|---|---|---|
| **Healthy, warm cache (the steady state)** | ~microseconds | **No** — t≈0+ε | **Skipped, every slot** |
| Epoch boundary / cold cache | up to 3 × `duty_fetch` timeout | Sometimes | Intermittent |
| Degraded BN, repeated fetch failures | up to 6 × `duty_fetch` timeout | Often — but the BN is degraded anyway | Intermittent |

**This is the opposite of a mitigation.** The defect is at its *most* systematic exactly when
everything is healthy. And the corollary matters for scheduling: **ARCH-P0-3 (proposal-first
reordering) removes even the accidental cover.** Moving the duty fetches into the wait window makes
`capture` fire at t=0 deterministically on *every* slot in *every* BN-health regime. If ARCH-P0-3
lands before ARCH-P0-8, the sync-committee loss becomes 100% deterministic where it is currently
merely typical.

### Q1.4 Existing test coverage: what is pinned and what is not

Nothing pins the composition. This is a **mock-fidelity** failure of exactly the kind the repo
already has vocabulary for (`docs/issues/phase-2-mock-fidelity.md`).

**Every `with_get_block_root` stub in the workspace — all seven — returns `Ok(...)` for *any*
`block_id`:**

| Site | Stub |
|---|---|
| `crates/rvc/src/orchestrator/slot_context.rs:70-73` | `if block_id == "head" { head_root } else { slot_root }` — `Ok` either way |
| `crates/rvc/src/orchestrator/sync_committee.rs:388-391` | `Ok(…)`, ignores `block_id` |
| `crates/rvc/src/orchestrator/aggregation.rs:609-613` | `Ok(…)`, ignores `_id` |
| `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:253-257` | `Ok(…)`, ignores `_block_id` |
| `crates/rvc/tests/common/pipeline_fixture.rs:243-245` | `Ok(…)`, ignores `_block_id` |
| `crates/rvc/tests/sync_independent_of_attesting.rs:87-91` | `Ok(…)`, ignores `_block_id` |
| `crates/rvc/src/orchestrator/slot_context.rs:77-79` | the **only** error stub: `Err(BeaconError::HttpError("simulated BN error"))` |

**The suite is green because the mocks encode the unverified assumption.** Not one stub models the
BN's real answer for a slot-qualified query against the current slot.

The two halves are each pinned; the join is not:

| Test | Pins | Location |
|---|---|---|
| `test_capture_uses_slot_qualified_query` | capture queries `slot`, not `"head"` (the L-5 fix) | `slot_context.rs:90-113` |
| `test_capture_handles_bn_error` | BN error ⇒ `head_root == None`, no panic | `slot_context.rs:117-132` |
| `test_messages_skip_when_head_root_none` | `head_root == None` ⇒ messages skipped | `sync_committee.rs:615-647` |
| `test_contributions_skip_when_head_root_none` | `head_root == None` ⇒ contributions skipped | `sync_committee.rs:652-680` |
| — | **`capture(current_slot)` against a 404 BN ⇒ sync duties skipped** | **absent** |

Every sync-committee behaviour test that supplies a root constructs `SlotContext` **by hand** —
`SlotContext { slot: 0, epoch: 0, head_root: Some(r_captured) }` at `sync_committee.rs:582`,
`:634`, `:671`, `:710`, `:818`, `:921`, `:1014` and `coordinator/tests/sync_gating.rs` — bypassing
`capture` entirely. The struct is `pub(crate)` with public fields, which makes the bypass free.

The one test that *does* drive the real composition — `test_sync_runs_with_attesting_disabled`
(`crates/rvc/tests/sync_independent_of_attesting.rs:252`), which runs the full
`DutyOrchestrator::run()` loop through `capture` at `:402` — is defeated by its own mock at
`:87-91` returning `Ok` for any `block_id`. **That single stub is the whole reason the defect is
invisible to CI.** Changing those four lines to 404 on a slot-qualified query is the cheapest
possible RED demonstration and should be the first commit of ARCH-P0-8.

Two further gaps: the L-5 fix that introduced the slot-qualified query is pinned by
`test_capture_uses_slot_qualified_query` only against a mock that answers `Ok` for both forms, so
the test proves *which string was sent* and nothing about whether a real BN can answer it; and
`slot_context.rs:26-28`'s own doc comment — *"`None` when the beacon node query failed; downstream
phases handle this gracefully"* — frames `None` as an exceptional path when Q1.2 shows it is the
**normal** path.

### Q1.5 Probe

**Not executed — no shell tool was available in this session** (see the same limitation in Q2.3).
The wiremock probe is specified below so ARCH-P0-8 can run it as its RED step. It belongs in the
repo (unlike Q2.3's worktree experiment) because it is the regression pin the requirement asks for.

```rust
// crates/rvc/tests/slot_context_404.rs  (new)
// RED at HEAD: asserts `capture` yields None for the current slot, and that the
// sync phase therefore skips.  GREEN after the fix: a root is captured and
// messages are produced.
#[tokio::test]
async fn test_capture_against_spec_conformant_bn_404s_on_current_slot() {
    let server = wiremock::MockServer::start().await;
    let current_slot: Slot = 1_000;

    // Spec-conformant BN: 404 "Block not found" for the not-yet-produced current
    // slot (beacon-APIs apis/beacon/blocks/root.yaml; lighthouse block_id.rs
    // WhenSlotSkipped::None -> custom_not_found).
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(format!("/eth/v1/beacon/blocks/{current_slot}/root")))
        .respond_with(wiremock::ResponseTemplate::new(404)
            .set_body_json(serde_json::json!({
                "code": 404, "message": "NOT_FOUND: beacon block at slot 1000"
            })))
        .mount(&server).await;

    // The parent slot DOES have a block — this is the root the fix must capture.
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .and(wiremock::matchers::path(format!("/eth/v1/beacon/blocks/{}/root", current_slot - 1)))
        .respond_with(wiremock::ResponseTemplate::new(200)
            .set_body_json(serde_json::json!({
                "execution_optimistic": false, "finalized": false,
                "data": { "root": "0xaaaa…aaaa" }
            })))
        .mount(&server).await;

    let beacon = BeaconClient::new(&server.uri(), BeaconClientConfig::default()).unwrap();
    let ctx = SlotContext::capture(&beacon, current_slot, current_slot / 32).await;

    assert!(ctx.head_root.is_none(), "RED pin: a spec-conformant BN 404s the current slot");
    // …after the fix, invert to: assert_eq!(ctx.head_root, Some(parent_root));
}
```

A companion test must drive `maybe_produce_sync_messages` **through** `capture` (not through a
hand-built `SlotContext`) against the same server and assert messages are produced — that is the
join the suite is missing (Q1.4). Per `CLAUDE.md`, neither test names a `*_root` / `*tree_hash*` /
`*signing_root*` symbol, so the KAT-first policy scanner
(`crates/architecture-tests/tests/kat_policy.rs`) is not triggered; no KAT constant or
`// kat_exempt:` marker is required. **Do not name the test `test_capture_head_root`** — that
matches `.*_root$` and would pull it into the scanner's scope for no benefit.

### Q1.6 Verdict on Weakness #8

> **VERDICT — Q1: REAL, and understated on three counts. Not partially real; not evaporated.**
>
> 1. **The mechanism is confirmed at every hop.** rvc queries the current slot's root at t≈0
>    (`slot_context.rs:41-42`), when no block for that slot can exist by the ordering of the slot
>    itself. A spec-conformant BN answers `404 Block not found` (`beacon-APIs`
>    `apis/beacon/blocks/root.yaml` [1]; Lighthouse `block_id.rs`, `WhenSlotSkipped::None` →
>    `custom_not_found` [3], corroborated by issue #4904 [4]). rvc funnels that to
>    `head_root = None` (`slot_context.rs:50-57`), and both sync-committee phases return early
>    (`sync_committee.rs:65-74`, `:148-157`).
> 2. **The one escape route is closed by primary evidence.** A `200` carrying the parent root would
>    evaporate the finding. Lighthouse behaved that way until issue #2186 [5] classified it as a bug
>    and it was replaced with `WhenSlotSkipped::None`. Betting on it means betting on a fixed
>    defect.
> 3. **The status code is irrelevant to the outcome** — `slot_context.rs:42-58` collapses 404, 400,
>    500, and transport failure into the same `None`. The verdict therefore does not depend on
>    cross-client status-code agreement, only on the absence of a 200-with-parent behaviour.
>
> **Three understatements to carry forward:** (a) **contributions** (`:148-157`) fail identically
> and independently of messages (`:65-74`) — the review cites only the latter, so both
> sync-committee reward components are lost; (b) the failure is **most systematic when the BN is
> healthiest**, because the pre-`capture` duty fetches are cache-guarded
> (`duty_management.rs:66`, `:86`, `:106`) and cost nothing on a warm cache; (c) every configured
> BN is queried and 404s **every slot** (`manager.rs:918-923` `query_first` + `fallback_unsynced`),
> so there is a standing multi-BN request cost on top of the reward loss.
>
> **Re-rank: MEDIUM → HIGH.** The review's MEDIUM was explicitly conditioned on being
> *"unverified empirically."* With the mechanism confirmed end to end and the only disconfirming
> behaviour shown to be a fixed bug, a **standing, silent, total loss of both sync-committee reward
> components for every validator in the committee, with no `error`-level signal and no metric**
> belongs alongside Weaknesses 2 and 4.
>
> **Confidence: high.** The residual is that no live BN or wiremock probe was executed here
> (Q1.5) and no primary source was read for Prysm/Teku/Nimbus/Lodestar (OQ-1 / A-2). Neither
> residual can flip the verdict — only a 200-with-parent response could, and that behaviour is
> documented as removed.

A Phase-1 issue for this **should** exist. It should not be closed as "downgraded."

### Q1.7 Consequences for `ARCH-P0-8`

`prd.md:669-693` already anticipates this branch (*"If it 404s (the expected case)…"*). The
verification here settles the branch and adds five amendments:

| # | Amendment to ARCH-P0-8 | Why |
|---|---|---|
| **1** | **Take the 404 branch as decided; do not re-litigate.** The wiremock test still lands, but as a *regression pin on a known behaviour*, not as a branch selector. The "if it does not 404, record the measurement and downgrade" arm (`prd.md:683`) is retained only as a falsification hook | Q1.6. A Phase-1 issue that starts by re-asking the question spends its budget on settled work |
| **2** | **Widen the fix scope to both sync consumers.** The PRD's acceptance criteria (`prd.md:688-689`) name only sync *messages*. Contributions (`sync_committee.rs:148-157`) must be asserted too, or phase 3 stays broken with a green suite | VD-Q1-1 (Q1.3) |
| **3** | **Add a mock-fidelity criterion, and make it a scan.** *"No `with_get_block_root` stub in the workspace returns `Ok` unconditionally for a slot-qualified `block_id`."* All seven stubs (Q1.4) must be revisited; the six generic ones should route slot-qualified queries to a 404 by default | The stub at `sync_independent_of_attesting.rs:87-91` is single-handedly why CI is green. Fixing one call site leaves six loaded guns |
| **4** | **Sequence ARCH-P0-8 with-or-before ARCH-P0-3.** ARCH-P0-3's proposal-first reordering removes the cold-cache/degraded-BN latency that today intermittently masks the skip, making the loss deterministic on every slot. Additionally, **ARCH-P0-3's own acceptance tests must not use a mock that returns `Ok` for a slot-qualified query**, or they will bake the assumption into the new ordering | Q1.3 masking analysis. This dependency is not recorded anywhere in `prd.md` |
| **5** | **Split the field — do not just make one capture succeed.** See below; this amendment is rewritten around VD-Q1-6 and is the largest change to the PRD's stated fix | `block_proposal/mod.rs:104`; `block-service/src/service/mod.rs:89-102`; `block-service/src/validation.rs:9`, `:63-70`; `slot_context.rs:1-9`, `:24` |

#### Amendment 5 in full — `SlotContext` conflates two different chain positions

The PRD proposes *"capture the parent/previous root at t=0 for the proposal path and **re-capture**
at phase 2 for sync-committee duties"* (`prd.md:679-681`). VD-Q1-6 shows why the first half is
right and vindicates the second half that a naive reading (including this note's first draft) would
discard as an H-5 regression. The single `head_root` field is asked to be **three incompatible
things**:

| Consumer | Value it actually needs | Correct capture time |
|---|---|---|
| `block_proposal/mod.rs:104` → `expected_parent_root` | the **parent** of the block being proposed for slot N = the most recent block strictly before slot N | **t=0**, before proposing |
| `sync_committee.rs:65` (messages, phase 2) | the **head** the validator considers canonical at t=slot/3 — normally slot N's block once it arrives | **t=slot/3** |
| `sync_committee.rs:148` (contributions, phase 3) | the **same** head the messages phase used (this is what H-5 protects) | reuse phase 2's value |

**Recommended shape — two fields, each captured when it is meaningful:**

```rust
pub(crate) struct SlotContext {
    pub slot: Slot,
    pub epoch: Epoch,
    /// Parent of the block to be proposed for `slot`. Captured at t=0 via
    /// get_block_root(slot - 1), walking back over skipped slots (A-4).
    pub parent_root: Option<Root>,
    /// Head as of phase 2. Captured once at t=slot/3 and reused by phase 3,
    /// preserving H-5. Not populated at t=0 — nothing needs it there.
    pub head_root: Option<Root>,
}
```

**This preserves H-5 exactly.** H-5's property, as its own regression test names it, is
`test_messages_and_contributions_share_head_root` (`sync_committee.rs:558`) — *messages (phase 2)
and contributions (phase 3) must agree*. Capturing the head once at phase 2 and reusing it at phase
3 satisfies that in full. The t=0 capture was over-eager: it bought cross-phase consistency with the
one phase that could not supply a usable value, and the proposal path — the only phase that *can*
be served at t=0 — was handed the wrong semantic value anyway.

**L-5 is preserved too.** Both captures stay slot-qualified (`get_block_root(slot - 1)` at t=0;
`get_block_root(slot)` with a documented fallback at phase 2), so the literal `"head"` string that
L-5 removed (`slot_context.rs:32-39`) is not reintroduced except as the terminal, `warn`-logged
last resort in A-4.

**Additional acceptance criteria this creates for ARCH-P0-8:**

- A test asserting `check_parent_root` **fires** — a BN returning a block whose `parent_root` is
  not slot N−1's root must be rejected with `ParentRootMismatch`. This is the H-4 check that is
  inert today (VD-Q1-6 consequence 1) and it must be RED before the fix.
- A test for consequence 2: a slot on which slot N's block already exists when `capture` runs must
  still propose successfully. Today's code drops it.
- `block-service/src/validation.rs:9`'s doc comment (*"`parent_root` matches the expected head
  root"*) and `slot_context.rs:24` (*"Head block root at slot start"*) must both be corrected —
  they are the artefacts that made the conflation survive review.
- The walk-back over skipped slots (A-4) is **required, not optional polish**: if slot N−1 was
  skipped, slot N−2's root *is* the correct parent, and a capture that gives up at the first 404
  would re-arm consequence 2 on every post-skip slot.

The PRD's remaining criteria stand: the `warn`-level counter/metric for "sync messages skipped: no
head root" (`prd.md:692-693`) is **required**, because Q1.3 confirms there is no metric at all
today and the condition is invisible to alerting.

---

## Q2 — Is `?Send` on `BeaconBlockClient` removable?

### Q2.0 The claim under test

Two statements in the review, quoted verbatim:

> "Root cause is the `#[async_trait(?Send)]` on `BeaconBlockClient`
> (`block-service/src/traits.rs:13`) making the orchestrator un-spawnable."
> — review Weakness 3, `docs/research/architecture-review-2026-08-11.md:106`

> "Remove `?Send` from `BeaconBlockClient` (the adapter wraps `Arc<dyn BeaconNodeClient>`,
> already `Send + Sync` — the annotation appears removable) so `DutyOrchestrator::run` is spawned
> and joined"
> — review Target architecture / Runtime model, `:185`

The PRD carries this as hypothesis **A-6** (`prd.md:1218`) and risk **R3** (`prd.md:1194`).

Three separable propositions are bundled here, and they do **not** stand or fall together:

| | Proposition | Verdict (detail below) |
|---|---|---|
| **P1** | `?Send` on `BeaconBlockClient` is what makes `DutyOrchestrator::run()` `!Send` today | **True** — and it is the *only* such cause (Q2.2) |
| **P2** | Removing the `?Send` annotation is *sufficient* to make `DutyOrchestrator` spawnable | **False** — necessary but not sufficient (Q2.4, blocker B1) |
| **P3** | The `!Send` slashing-DB staging guard (`slashing/src/stage.rs:57-63`) contributes to the orchestrator's `!Send`-ness | **False** — refuted by primary evidence (Q2.2) |

P3 is not stated in the review, but it is the reading the constraint register invites (C1/C2 both
foreground the `!Send` guard) and it is the first hypothesis a reader forms. Refuting it is what
makes P1 safe to act on.

### Q2.1 Complete implementor inventory at HEAD

Exhaustive: `rg 'impl BeaconBlockClient for'` returns six impls, one declaration.

| # | Site | Kind | Struct shape | `Send + Sync` as a *type*? |
|---|---|---|---|---|
| — | `crates/block-service/src/traits.rs:13-14` | trait decl | `#[async_trait(?Send)] pub trait BeaconBlockClient` — **no supertraits at all** | n/a |
| 1 | `crates/rvc/src/beacon_adapter.rs:18-19` | **production (sole)** | `BeaconBlockAdapter(Arc<dyn BeaconNodeClient>)` | **Yes** — `BeaconNodeClient` declares `+ Send + Sync` at `crates/bn-manager/src/traits.rs:178-188` |
| 2 | `crates/block-service/src/service/tests/mocks.rs:415-416` | unit test | `MockBeaconClient { … std::sync::Mutex<Vec<…>> ×6, Option<ProduceBlockResponse>, bool ×2 }` (`mocks.rs:342-353`) | Yes |
| 3 | `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:127-128` | unit test | `struct MockBlockBeacon;` (unit struct, `:125`) | Yes |
| 4 | `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:180-181` | unit test | `BadProposerBlockBeacon { Slot, u64, Arc<AtomicBool> }` (`:174-178`) | Yes |
| 5 | `crates/rvc/tests/common/pipeline_fixture.rs:159-160` | integration test | `NoopBlockBeacon` | Yes (see Q2.3 note) |
| 6 | `crates/rvc/tests/sync_independent_of_attesting.rs:119-120` | integration test | `NoopBlockBeacon` | Yes (see Q2.3 note) |

**Finding.** There is exactly **one** production implementor, and it wraps a handle that the
workspace already guarantees is `Send + Sync`. Every other implementor is a test double built from
`std::sync::Mutex`, `Arc<AtomicBool>`, or nothing at all. **No implementor holds an `Rc`, a
`RefCell`, a `*const T`, or a non-`Send` client handle.** This is the strongest single fact in
favour of removability, and it reproduces the review's reasoning at `:185` — with the refinement
that the review only checked implementor #1.

The `?Send` annotation is also mirrored on five of the six impls (`mocks.rs:415`,
`coordinator/tests/mod.rs:127`, `:180`, `pipeline_fixture.rs:159`,
`sync_independent_of_attesting.rs:119`) — `async_trait`'s variance must match, so all six sites
change together. That is a mechanical 6-line edit, not a design change.

### Q2.2 Types held across an await in the orchestrator

`DutyOrchestrator::run(&mut self)` (`crates/rvc/src/orchestrator/coordinator/mod.rs:348`) holds
`&mut Self` across every `.await` in the loop body (`:373`, `:376-383`, `:393-396`, `:402`, `:405`,
and the phase-2/3 bodies). Therefore `run()`'s future is `Send` **iff** `DutyOrchestrator<C, S, B>`
is `Send`. Field-by-field audit of `coordinator/mod.rs:204-235`:

| Field | Type | `Send`? | Evidence |
|---|---|---|---|
| `clock` | `Arc<C>`, `C: SlotClock` | ✅ | `crates/timing/src/clock.rs:15` — `pub trait SlotClock: Send + Sync` |
| `beacon` | `Arc<dyn BeaconNodeClient>` | ✅ | `crates/bn-manager/src/traits.rs:178-188` — `+ Send + Sync` |
| `duty_tracker` | `Arc<DutyTracker>` | ✅ | `crates/duty-tracker/src/tracker.rs:131-141` — `Arc<dyn BeaconNodeClient>`, `RwLock<HashMap<…>>`, `Vec<String>`, `AtomicU64` |
| `block_service` | `BlockService<SignerService, B>` | ❌ **blocker B1** | `crates/block-service/src/service/mod.rs:27-34` holds `beacon: Arc<B>` where `B: BeaconBlockClient` carries **no** `Send + Sync` supertrait |
| `builder_service` | `Option<Arc<BuilderService>>` | ✅ | `crates/builder/src/service.rs:32-39`: `Arc<dyn RegistrationSigner>` + `Arc<dyn BuilderBeaconClient>` — **both** declared `: Send + Sync` (`crates/builder/src/traits.rs:16`, `:56`), plus `Arc<ValidatorStore>` and `tokio::sync::RwLock<…>` |
| `circuit_breaker` | `Arc<CircuitBreakerState>` | ✅ | atomics only |
| `config` | `OrchestratorConfig` | ✅ | `Arc<ForkSchedule>` + `Root` + `Duration`s |
| `pubkey_map` | `Arc<parking_lot::RwLock<HashMap<[u8;48], PublicKey>>>` | ✅ | `parking_lot::RwLock<T>` is `Send + Sync` when `T: Send + Sync`; the **guard** is `!Send`, the lock is not — see the guard scan below |
| `pubkey_index` | `SharedPubkeyIndexRegistry` | ✅ | same shape |
| `attestation_service` | `AttestationService<C, S>` | ✅ | `C: SlotClock`, `S: AttestationSubmitter` (`crates/bn-manager/src/submit.rs:33` — `: Send + Sync`) |
| `aggregation_service`, `sync_committee_service`, `duty_management` | — | ✅ | each composed of `Arc<SignerService>` + `Arc<dyn BeaconNodeClient>` + `Arc<DutyTracker>` + `PubkeyMap` + `Arc<ValidatorStore>` |
| `key_gen_rx`, `shutdown_rx` | `tokio::sync::watch::Receiver<_>` | ✅ | `Send + Sync` for `Send + Sync` payloads |
| `attesting_enabled`, `sync_enabled` | `Arc<AtomicBool>` | ✅ | — |
| `validator_store` | `Arc<ValidatorStore>` | ✅ | `crates/validator-store/src/store.rs:114-123` — `parking_lot::RwLock<StoreState>` + `Mutex<()>` + `Option<PathBuf>` |

`SignerService` (`crates/signer/src/lib.rs:212-224`) is `Send + Sync`: `Arc<CompositeSigner>`,
`Arc<dyn Signer>` (`crates/crypto/src/signer_trait.rs:15` — `pub trait Signer: Send + Sync`),
`Arc<SlashingDb>` (`crates/slashing/src/db/mod.rs:58-61` — `parking_lot::Mutex<Connection>`;
`Connection: Send`, so `Mutex<Connection>: Send + Sync`), `ValidatorLockMap`, and
`Arc<dyn SigningEnablement>` (`crates/doppelganger/src/enablement.rs:14` — `: Send + Sync`).

**Exactly one field fails. It is `Arc<B>`, and its only defect is the missing supertrait bound.**

#### Guard scan: no `!Send` lock guard is held across an await in the orchestrator

Requested explicitly because a `parking_lot::RwLockReadGuard` alive across an `.await` is `!Send`
and no trait change repairs it. Scanning every `.read()` / `.write()` / `.lock()` under
`crates/rvc/src/orchestrator/`, production code only:

| Site | Shape | Crosses an await? |
|---|---|---|
| `utils.rs:118`, `utils.rs:126` | `pubkey_map.read().get(..).cloned()` — temporary dropped at end of statement | No |
| `utils.rs:213-217` | `let map = pubkey_map.read();` inside a `{ … }` block producing a `HashSet` | No |
| `duty_management.rs:294-295` | `pubkey_map.read().clone()` + `pubkey_index.read()` inside a block, under the comment *"Build the preparations list under short sync locks (no await held)"* | No |
| `duty_management.rs:346` | `self.pubkey_map.read().clone()` — snapshot, guard dropped immediately | No |
| `duty_management.rs:162`, `:191` | `prefetched_periods.read().await` / `.write().await` — **`tokio::sync::RwLock`**, whose guards are `Send` when `T: Send + Sync` | Yes, but `Send` |

Every remaining `.lock()` hit under `orchestrator/` is inside `#[cfg(test)]` mock bodies
(`sync_committee.rs:403`, `:462`, `:597`, `:644`, `:715`, `:925`;
`coordinator/tests/sync_gating.rs:182`, `:223`). **No production `!Send` guard crosses an await.**
The "snapshot-then-drop" discipline is uniform and deliberate — the `duty_management.rs:292`
comment shows it was designed, not accidental.

#### P3 refuted: the slashing staging guard does **not** make the orchestrator `!Send`

`crates/slashing/src/stage.rs:57-63` states the guards are `!Send` and warns against holding them
across an `.await`. The obvious inference — that this is a second, deeper cause of the
orchestrator's `!Send`-ness, which no trait change can fix — is **wrong**, and the code says so
with primary evidence:

1. `crates/signer/src/core.rs:36-41` (module doc): *"`StagedBlock` / `StagedAttestation` hold a
   `parking_lot::MutexGuard` and must not cross a real `.await`. The core therefore runs stage +
   sign + finish inside `tokio::task::spawn_blocking`, driving the async sign via
   `Handle::block_on(timeout(...))` on that same thread."*
2. `crates/signer/src/core.rs:284-287` — the sign is `self.handle.block_on(tokio::time::timeout(…))`,
   a **blocking** call on the `spawn_blocking` thread. There is no `.await` inside the guard's
   lifetime, in the Rust-type sense.
3. `crates/signer/src/core.rs:542` — `tokio::task::spawn_blocking(move || body(session)).await`,
   with `F: FnOnce(SlashableSignSession) -> … + Send + 'static` at `:492`. `spawn_blocking`
   requires a `Send` closure, so `SlashableSignSession` — which owns `Arc<dyn Signer>` and the
   whole sign context — **is proven `Send` by the fact that the workspace compiles**.
4. Compile-checked proof that `sign_slashable`'s *future* is `Send`:
   `crates/signer/src/core.rs:930` wraps it in a bare `tokio::spawn(async move { sign_slashable(…).await })`
   inside a live unit test. `tokio::spawn` requires `Send`. That test is in the green suite.

So the `!Send` guard is confined to a blocking thread by construction and never appears in the
orchestrator's future. **P3 is refuted.** This matters beyond Q2: it means ARCH-P0-4 (spawn/join)
and the ARCH-P1 slashing critical-section redesign (C1) are **independent** work items — the first
is not blocked on the second, and the review's Phase 2 → Phase 4 ordering does not need revisiting
on this account.

### Q2.3 Experiment: the compilation check, specified but **not executed**

**Stated limitation, without euphemism.** This research session had no shell tool available (only
`Read`/`Write`/`Edit`/`Glob`/`Grep`/`WebSearch`/`WebFetch`). **No `cargo` invocation was run and no
git worktree was created.** Nothing in this document should be read as "the build was tried."
Q2's verdict rests on the exhaustive static audit in Q2.1–Q2.2, which is sound for `Send`-ness
because auto-trait derivation is structural, but it cannot see inference failures, `async_trait`
lifetime-elaboration surprises, or downstream crates outside the paths scanned.

The experiment is therefore **specified** here so it can be executed as the first task of
ARCH-P0-4, outside the repo working tree at `/Users/nil/git/dsrv/rvc`:

```bash
# 1. Throwaway worktree — never touch the develop checkout.
git -C /Users/nil/git/dsrv/rvc worktree add /tmp/rvc-send-probe 0ae9a09
cd /tmp/rvc-send-probe

# 2. Flip all six async_trait variance sites (Q2.1) and add the supertrait.
#    (a) trait declaration + supertrait bound — the blocker-B1 fix:
#        crates/block-service/src/traits.rs:13-14
#          -#[async_trait(?Send)]
#          -pub trait BeaconBlockClient {
#          +#[async_trait]
#          +pub trait BeaconBlockClient: Send + Sync {
#    (b) the five impl sites:
grep -rl 'async_trait(?Send)' crates/ \
  | xargs sed -i '' 's/#\[async_trait(?Send)\]/#[async_trait]/'

# 3. The discriminating check — libs first, then all targets.
cargo check -p block-service -p rvc
cargo check -p block-service -p rvc --all-targets
cargo check --workspace --all-targets --all-features

# 4. The behavioural proof the annotation was load-bearing: replace the LocalSet
#    scaffold at crates/rvc/tests/sync_independent_of_attesting.rs:269-273 with a
#    plain tokio::spawn, and assert it compiles.
cargo test -p rvc --test sync_independent_of_attesting

# 5. Tear down. Nothing is merged from this worktree.
cd / && git -C /Users/nil/git/dsrv/rvc worktree remove /tmp/rvc-send-probe --force
```

**Predicted outcome, stated in falsifiable form** (so the issue can record a delta if it is wrong):
step 3's first two commands succeed with **zero** errors; step 3's third command succeeds; step 4
compiles once the `LocalSet` scaffold is removed. The single expected *diagnostic* is not an error
at all — `clippy::arc_with_non_send_sync` allows that become redundant, listed in Q2.4.

If the prediction fails, the failure will name a concrete type in an
`` future cannot be sent between threads safely `` diagnostic; that type name is the deliverable
and belongs verbatim in the ARCH-P0-4 issue body.

**Where to look first if it does fail.** The Q2.2 audit covered `DutyOrchestrator`'s fields and
every lock guard under `crates/rvc/src/orchestrator/`. It did **not** read the bodies of everything
the loop awaits. The one shape that would falsify the prediction is a `std::sync::MutexGuard` (or a
`parking_lot` guard) held across an `.await`, and the two unaudited places it could live are
**`crates/block-service/src/service/**`** — awaited from `maybe_propose_block` via
`block_proposal/mod.rs:104` — and the recording test doubles, especially the `MockBeaconClient`
method bodies after `mocks.rs:439`, which hold `std::sync::Mutex<Vec<…>>` call logs. A body that
does `self.publish_calls.lock().unwrap().push(x)` and *then* awaits, rather than scoping the guard,
is the classic instance. Check those before doubting the field audit.

### Q2.4 The non-`Send` blockers, and the cost to fix each

**One structural blocker, and three follow-on chores.** Nothing here is a redesign.

| ID | Blocker / chore | Why | Fix | Cost |
|---|---|---|---|---|
| **B1** | `pub trait BeaconBlockClient` (`crates/block-service/src/traits.rs:14`) declares **no supertraits**, so `Arc<B>` in `BlockService` (`block-service/src/service/mod.rs:29`) is not `Send` even after the annotation flips | Removing `#[async_trait(?Send)]` makes the *method futures* `Send`; it does **not** make the *type* `B` `Send + Sync`. `DutyOrchestrator: Send` needs the latter, via `block_service: BlockService<SignerService, B>` | Add the supertrait: `pub trait BeaconBlockClient: Send + Sync` | 1 line |
| **B2** | Six `#[async_trait(?Send)]` attributes must flip together (`async_trait` variance must match between trait and impls) | Q2.1 table | mechanical `sed` | 6 lines |
| **B3** | `crates/rvc/tests/sync_independent_of_attesting.rs:248-250` documents the `!Send`-ness in a doc comment and `:269-273` builds a `tokio::task::LocalSet` + `spawn_local` scaffold purely to work around it | The scaffold becomes dead weight and the comment becomes false | Delete the `LocalSet`, use `tokio::spawn`; delete the comment. **This doubles as the acceptance test for ARCH-P0-4 item 1** — if it compiles, the orchestrator is spawnable | ~10 lines, net negative |
| **B4** | Three `#[allow(clippy::arc_with_non_send_sync)]` (`crates/rvc/src/bootstrap/services.rs:186`, `crates/rvc/src/config/builder.rs:3` (crate-level), `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:6` (module-level)) | **Verified stale at HEAD, independent of this change**: `services.rs:186` covers `build_builder_service(…)`, whose every field is `Send + Sync` per Q2.2 (`RegistrationSigner` and `BuilderBeaconClient` both declare `: Send + Sync`, `crates/builder/src/traits.rs:16`, `:56`). Rust does not warn on an `#[allow]` that never fires, so these survived as fossils | Delete all three; if any is still load-bearing, clippy will say which `Arc::new` and of what type | 3 lines; **do this in the same PR** — leaving them in place would mask a future regression of exactly this bug class |

There is a fourth `#[allow(clippy::arc_with_non_send_sync)]` at
`crates/rvc/src/orchestrator/sync_committee.rs:328` (test module) and one at
`crates/rvc/src/main.rs:1608` — the latter is inside an **untracked orphan tree** slated for
archive-then-delete under ARCH-P0-1 and must not be edited.

**Note on where the annotation *appears* to be needed but is not.** `BeaconBlockAdapter`
(`beacon_adapter.rs:18-19`) forwards to `Arc<dyn BeaconNodeClient>` methods, all of which are
declared with plain `#[async_trait]` (Send) at `crates/bn-manager/src/traits.rs:22`, `:40`, `:85`,
`:117`, `:138`, `:153`. Its bodies therefore already produce `Send` futures. The `?Send` on the
adapter is pure inheritance from the trait declaration, carrying no information.

### Q2.5 Verdict on `?Send` removability

> **VERDICT — Q2: YES, removable. The review's P1 is correct and its implied one-line fix (P2) is
> incomplete: `?Send` removal is necessary but not sufficient. The complete fix is `?Send` removal
> at six sites *plus* a `Send + Sync` supertrait on `BeaconBlockClient`. Total ≈20 lines, net
> negative after deleting the `LocalSet` scaffold. Zero non-`Send` types block it — the exhaustive
> implementor inventory (six impls, one production) and the field-by-field audit of
> `DutyOrchestrator`'s eighteen fields find exactly one failing field, and its only defect is the
> missing supertrait bound.**
>
> **Separately, and not claimed by the review: the `!Send` slashing staging guard is *not* a
> contributing cause** — `crates/signer/src/core.rs:36-41`, `:284-287`, `:542` confine it to a
> `spawn_blocking` thread, and the `tokio::spawn` at `core.rs:930` is compile-checked proof that
> `sign_slashable`'s future is `Send`.
>
> **Confidence: high on the static analysis, but the compile has not been run** (Q2.3). Treat the
> verdict as "no blocker found by exhaustive audit," not "the build was tried and passed."

**Recommended fix shape: the supertrait, not the bound sites.** Two routes exist:

| Route | Edit | Blast radius | Recommendation |
|---|---|---|---|
| **A — supertrait** | `pub trait BeaconBlockClient: Send + Sync` at `block-service/src/traits.rs:14` | 1 line; automatically satisfies every `B: BeaconBlockClient` bound in the workspace | **Recommended.** Matches the established house pattern — `BeaconNodeClient` (`bn-manager/src/traits.rs:185-186`), `SlotClock` (`timing/src/clock.rs:15`), `AttestationSubmitter` (`bn-manager/src/submit.rs:33`), `Signer` (`crypto/src/signer_trait.rs:15`), `ValidatorSigner` (`signer/src/traits.rs:32`), `SigningEnablement` (`doppelganger/src/enablement.rs:14`), `RegistrationSigner` / `BuilderBeaconClient` (`builder/src/traits.rs:16`, `:56`) all declare `Send + Sync` on the trait. `BeaconBlockClient` is the **only** service trait in the workspace that does not — that is the actual anomaly |
| **B — per-bound-site** | `+ Send + Sync` at all seven `B: BeaconBlockClient` bounds: `coordinator/mod.rs:125`, `:154`, `:208`, `:241`; `block_proposal/mod.rs:53`; `block-service/src/service/mod.rs:27`, `:36` | 7 lines across 3 files, 2 crates; every future bound site must remember it | Reject — it re-creates the "enforced by discipline, not by a declaration" failure mode this initiative exists to remove (PRD G7) |

Route A also makes `signer/src/traits.rs:30`'s existing instruction — *"Consumer mocks must use
`#[async_trait]` (not `?Send`) and be `Send + Sync`"* — uniformly true across the workspace instead
of true for one crate.

### Q2.6 Consequences for `ARCH-P0-4`

| PRD text | Required amendment |
|---|---|
| `prd.md:576-579` item 1: *"Remove `#[async_trait(?Send)]` from `BeaconBlockClient` (`crates/block-service/src/traits.rs:13`)"* | **Amend to:** remove `#[async_trait(?Send)]` at **all six sites** (Q2.1) **and** add the `Send + Sync` supertrait at `traits.rs:14`. An issue that names only `traits.rs:13` produces a change that compiles the trait but still leaves `DutyOrchestrator` un-spawnable — the developer then hits a confusing `Arc<B>` error and may wrongly conclude A-6 was falsified |
| `prd.md:1218` **A-6**: *"Assume yes … ARCH-P0-4 is satisfied by removal **or** by recording why not"* | **Resolve A-6 from assumption to finding.** The escape hatch stays (it costs nothing and the compile is unrun), but the default branch is now evidenced, and the issue should say so |
| `prd.md:1194` **R3**: *"Removing `?Send` … cascades further than expected — Medium × Medium"* | **Downgrade to Low × Low.** The cascade is bounded and enumerated: six annotations, one supertrait, one test scaffold, three stale clippy allows. No production type changes |
| ARCH-P0-4 acceptance criteria (`prd.md:587-594`) | **Add:** *"`crates/rvc/tests/sync_independent_of_attesting.rs` no longer uses `tokio::task::LocalSet` / `spawn_local`; the orchestrator future is driven by a bare `tokio::spawn`."* This is the sharpest available compile-time proof of spawnability, and it converts an existing workaround into the regression pin. **Add:** *"no `#[allow(clippy::arc_with_non_send_sync)]` remains in `crates/rvc/src/` outside the orphan trees."* |
| Sequencing vs the slashing redesign | **Record the independence explicitly.** ARCH-P0-4 has no dependency on the C1 critical-section redesign, because the `!Send` guard never enters the orchestrator's future (Q2.2, P3). Without this stated, a planner reading C1 and `stage.rs:57-63` together will serialise them unnecessarily |

---

## Verification deltas against the review and the PRD

Following the house convention: every claim that did not reproduce at HEAD is filed here with the
corrected fact, and the corrected fact is what the downstream project plan must carry.

| ID | Source claim | Status at HEAD | Corrected fact | Consequence |
|---|---|---|---|---|
| **VD-Q1-1** | Review `:116` cites the skip at `orchestrator/sync_committee.rs:65-70` — the **messages** path only. `prd.md:688-689` inherits this, naming only sync messages in its acceptance criteria | **Incomplete** | The contributions path fails identically and independently at `sync_committee.rs:148-157` (*"Skipping sync committee contributions: head_root unavailable in slot context"*). Both sync-committee reward components are lost | ARCH-P0-8 must assert both phases. Fixing only messages leaves phase 3 broken with a green suite |
| **VD-Q1-2** | `prd.md:80` (tagged **[review-carried, unverified at HEAD]**): `fetch_epoch_duties` costs *"up to 6 × 10 s BN timeouts"* — **every slot** | **Conditional, not unconditional** | All three fetches are cache-guarded (`duty_management.rs:66`, `:86`, `:106`), and the sync prefetch has its own `prefetched_periods` guard (`:162`). On a warm cache the two calls at `coordinator/mod.rs:376-383` make **zero** BN round trips. The 6× worst case is real but requires cache miss: cold boot, post-`key_gen` invalidation, epoch rollover, or repeatedly-failing fetches (a failed fetch never populates the cache, so it retries every slot — the review's degraded-BN case stands) | Inverts the intuition on Q1: the sync skip is **most systematic in the healthy steady state**. Also sharpens ARCH-P0-3's problem statement — the slot-critical-path cost is a *tail* risk, not a per-slot constant |
| **VD-Q1-3** | Review `:116` ranks Weakness 8 **MEDIUM**, explicitly conditioned on *"unverified empirically"* | **Condition discharged** | Mechanism verified end-to-end; the only evaporating behaviour (200-with-parent) is a **fixed Lighthouse bug** (issue #2186 [5] → `WhenSlotSkipped::None` [3]) | Re-rank **HIGH**. A standing total loss of both sync-committee components, with no `error` and no metric, ranks with Weaknesses 2 and 4 |
| **VD-Q1-4** | `slot_context.rs:26-28` doc comment: *"`None` when the beacon node query failed; downstream phases handle this gracefully"* | **Misleading** | `None` is not the failure path — it is the **normal** path on a spec-conformant BN. "Handled gracefully" means "the whole sync-committee duty is dropped" | The doc comment must be corrected as part of ARCH-P0-8, not left to contradict the fix |
| **VD-Q1-5** | Not claimed anywhere | **New** | `manager.rs:918-923` routes `get_block_root` through `query_first(BnRole::All, HealthTier::SmallLag)` with `fallback_unsynced` (`:599-601`, `:683-727`). A 404 is non-retryable (`retry.rs:59-61`, `:92`) but *is* an `Err`, so **every configured BN is queried and 404s, every slot** | A standing multi-BN request cost for a guaranteed-empty slot. Worth a line in the ARCH-P0-8 issue; disappears with the `slot - 1` fix |
| **VD-Q1-6** | Review `:116` and `prd.md:128-148` treat Weakness 8 as a **sync-committee-only** defect. Neither enumerates the consumers of `ctx.head_root` | **Incomplete, and it hides a second bug** | There are **three** production consumers, not two: `sync_committee.rs:65`, `:148`, and **`block_proposal/mod.rs:104`**, which passes `ctx.head_root` into a parameter named `expected_parent_root` (`block-service/src/service/mod.rs:89-102`) feeding `BlockResponseValidator` (`validation.rs:63-70`). `SlotContext` documents the field as *"Head block root at slot start"* (`slot_context.rs:24`) and fills it with slot N's **own** root — which can never be slot N's block's parent. Consequence (i): with `None` every slot, the **H-4 parent-root check is shipped and inert**. Consequence (ii): on any slot where `capture` *does* succeed (cold cache / degraded BN), the check compares a valid block's parent against slot N's own root, mismatches, and **drops the proposal** (`ParentRootMismatch`) | Largest change to the PRD's stated fix. "Make `capture` succeed" would **activate** a missed-block bug. ARCH-P0-8 must **split the field** into `parent_root` (captured at t=0 as `slot - 1`, walking back over skips) and `head_root` (captured at phase 2, reused at phase 3) — see Q1.7 amendment 5. Also vindicates the PRD's *"re-capture at phase 2"* (`prd.md:679-681`), which a naive H-5 reading would discard |
| **VD-Q2-1** | Review `:185` / `prd.md:576-579`: *"Remove `?Send` from `BeaconBlockClient` (`crates/block-service/src/traits.rs:13`)"* — implying a single-site edit suffices | **Necessary but not sufficient** | Removing `#[async_trait(?Send)]` makes the *method futures* `Send`; it does not make the *type* `B` `Send + Sync`. `DutyOrchestrator` holds `BlockService<SignerService, B>` (`coordinator/mod.rs:213`) which holds `beacon: Arc<B>` (`block-service/src/service/mod.rs:29`). `BeaconBlockClient` declares **no supertraits** (`traits.rs:14`). The complete fix is six annotation sites **plus** `pub trait BeaconBlockClient: Send + Sync` | ARCH-P0-4 item 1 must be reworded. Otherwise a developer flips one attribute, hits an opaque `Arc<B>` error, and may wrongly record A-6 as falsified |
| **VD-Q2-2** | Not claimed by the review, but strongly implied by constraints **C1**/**C2** plus `slashing/src/stage.rs:57-63` | **Refuted** | The `!Send` staging guard never enters the orchestrator's future. `signer/src/core.rs:36-41` documents the design, `:284-287` shows the sign is `Handle::block_on` (not `.await`), `:542` runs it under `spawn_blocking` with a `Send + 'static` closure bound (`:492`), and `core.rs:930` wraps `sign_slashable` in a bare `tokio::spawn` in a green test — compile-checked proof its future is `Send` | ARCH-P0-4 has **no dependency** on the C1 redesign. State this explicitly or a planner will serialise Phase 1 behind Phase 4 for no reason |
| **VD-Q2-3** | Not claimed | **New** | Three `#[allow(clippy::arc_with_non_send_sync)]` are **stale at HEAD**, independent of this initiative: `bootstrap/services.rs:186` (covers `build_builder_service`, whose every field is `Send + Sync` — `builder/src/traits.rs:16`, `:56`), `config/builder.rs:3` (crate-level), `coordinator/tests/mod.rs:6` (module-level). Rust never warns on an `#[allow]` that does not fire, so they survived as fossils | Delete all three in the ARCH-P0-4 PR. Leaving them masks a future regression of exactly this bug class |
| **VD-Q2-4** | `prd.md:1194` **R3**: *"Removing `?Send` … cascades further than expected — Medium × Medium"* | **Overstated** | The cascade is bounded and fully enumerated: 6 annotations, 1 supertrait, 1 test scaffold (`sync_independent_of_attesting.rs:248-250`, `:269-273`), 3 stale clippy allows. No production type changes | **Downgrade to Low × Low** |
| **VD-Q2-5** | `prd.md:1218` **A-6**: *"Assume yes … satisfied by removal **or** by recording why not"* | **Promotable** | The assumption is now evidenced by an exhaustive implementor inventory (six impls, one production) and a field-by-field `Send` audit of `DutyOrchestrator` | Promote A-6 from assumption to finding; retain the escape hatch only because the compile is unrun (A-1) |

---

## Assumptions

Per the no-ask constraint (`plan/tracing-2026-08-06/project-plan.md`), every open question is
resolved here to a stated default. Nothing is escalated.

| ID | Open question | **Stated default** | Falsifier — what would overturn it |
|---|---|---|---|
| **A-1** | Neither empirical experiment was executed: **this session had no shell tool** (available: `Read`/`Write`/`Edit`/`Glob`/`Grep`/`WebSearch`/`WebFetch`). No `cargo` ran; no `git worktree` was created; no wiremock server was started | **Treat the static analysis as authoritative pending execution.** Both experiments are specified verbatim (Q2.3 commands, Q1.5 test skeleton) and each becomes the **first task** of its requirement — Q2.3 for ARCH-P0-4, Q1.5 for ARCH-P0-8. Neither verdict is stated as "the build passed" | Q2: any `future cannot be sent between threads safely` diagnostic naming a type not in the Q2.2 table. Q1: a live BN returning `200` for a not-yet-produced slot |
| **A-2** (OQ-1) | Only Lighthouse's slot-`block_id` resolution was read from primary source. Prysm, Teku, Nimbus and Lodestar were **not** verified | **Assume all four are spec-conformant and `404`.** Justified because (i) the shipped OpenAPI documents only `404 Block not found` [1], (ii) the ecosystem treats 404 as reserved for empty slots (Teku #7635 [6]), (iii) returning the parent was classified as a *bug* [5], and (iv) **it does not matter**: `slot_context.rs:42-58` collapses every non-`Ok` to `None`, so only a `200` changes rvc's behaviour | A primary-source client implementation resolving a slot `block_id` backwards over skips (e.g. a `WhenSlotSkipped::Prev` equivalent) on this endpoint |
| **A-3** | `ethereum/beacon-APIs` issue #126's comment thread and resolution were not retrievable (the fetch returned only the opening post) | **The shipped OpenAPI is the resolution.** `root.yaml` documents `404 Block not found` and no 200-with-parent branch [1] | A merged beacon-APIs PR adding a documented parent-fallback for slot `block_id`s |
| **A-4** | With the `parent_root = get_block_root(slot - 1)` capture (Q1.7 amendment 5), how many consecutive skipped slots should be walked back before giving up? | **Four attempts (`slot-1` … `slot-4`), then `"head"` as a logged last resort.** Four covers the overwhelming majority of consecutive-skip runs on mainnet; `"head"` reintroduces the drift the L-5 fix removed (`slot_context.rs:32-39`) and must therefore be terminal, `warn`-logged, and counted. **The walk-back itself is not a tuning choice — it is required for correctness** (VD-Q1-6): giving up at the first 404 leaves `parent_root = None` on every post-skip slot, re-disabling the H-4 check exactly where a wrong-ancestor block is most likely | Only the *depth* is tunable — measured mainnet consecutive-skip distributions could argue for a different number. The existence of the walk-back is not negotiable |
| **A-5** | `self.config.timeouts.duty_fetch` is configurable (`duty_management.rs:70`, `:90`, `:110`); its default was **not** read at HEAD, so the review's "10 s" figure is carried unverified | **Carry the review's figure as illustrative only.** VD-Q1-2's conclusion — that warm-cache slots cost zero BN round trips — is independent of the timeout's value, because the guarded branches are not entered at all | Nothing; the conclusion does not depend on it. The figure should be verified before it appears in an ARCH-P0-3 acceptance criterion |
| **A-6** | Should ARCH-P0-8 land before, with, or after ARCH-P0-3? | **Same phase, ARCH-P0-8 first.** ARCH-P0-3 makes the sync-skip deterministic on every slot in every BN-health regime (Q1.3), so landing it first temporarily worsens a known reward defect | A scheduling constraint from outside this research track |
| **A-7** | Route A (`Send + Sync` supertrait, 1 line) vs Route B (`+ Send + Sync` at all seven `B: BeaconBlockClient` bound sites) | **Route A.** It matches the house pattern followed by all eight peer service traits and avoids re-creating an enforced-by-discipline seam (PRD G7) | An orphan-rule or coherence problem at a bound site — not expected, since no blanket impl targets `BeaconBlockClient` |
| **A-8** | Should the three stale `#[allow(clippy::arc_with_non_send_sync)]` (VD-Q2-3) be removed in the ARCH-P0-4 PR or deferred? | **Same PR.** They are directly adjacent to the change and would otherwise mask a regression of exactly the bug class being fixed | Clippy proving one is still load-bearing — in which case it names the `Arc::new` and its type, which belongs in the issue |
| **A-9** | `crates/rvc/src/main.rs:1608` also carries `#[allow(clippy::arc_with_non_send_sync)]` | **Do not touch.** It is inside an untracked orphan tree governed by ARCH-P0-1's archive-then-delete sequence (**C10**). Editing it would alter a tree that has **no git object behind it** and is unrecoverable by `rm` | None — this is a hard constraint |
| **A-10** | Do the two new Q1.5 tests need KAT anchoring under `CLAUDE.md`'s KAT-first policy? | **No.** Neither test name matches the scanner pattern `.*(tree_hash\|signing_root\|_root)$` (`crates/architecture-tests/tests/kat_policy.rs`), and neither asserts a spec-defined signing root or container `hash_tree_root` — they assert HTTP behaviour and duty production. **Names must avoid a `_root` suffix** so they stay out of scope | A reviewer judging `head_root` capture to be a spec-defined value — in which case add `// kat_exempt: BN transport behaviour, not a spec-defined root` |
| **A-11** | Does removing `?Send` require changes in `bin/rvc` or other workspace members outside `crates/block-service` and `crates/rvc`? | **Assume no.** `rg 'impl BeaconBlockClient for'` and `rg 'async_trait(?Send)'` across the workspace return hits only in those two crates plus their test trees (Q2.1) | `cargo check --workspace --all-targets --all-features` (Q2.3 step 3) reporting an error outside those crates |

---

## Sources

Primary sources are marked; type is noted where reliability differs. All URLs were fetched or
searched on 2026-08-12.

**External**

[1] [`ethereum/beacon-APIs` — `apis/beacon/blocks/root.yaml`](https://raw.githubusercontent.com/ethereum/beacon-APIs/master/apis/beacon/blocks/root.yaml) — **primary source, official OpenAPI specification**, fetched directly. Referenced for: the `block_id` parameter forms (`head` / `genesis` / `finalized` / `<slot>` / `0x<blockRoot>`) and the documented response set for `GET /eth/v1/beacon/blocks/{block_id}/root` — `200`, `400` *"The block ID supplied could not be parsed"*, **`404` "Block not found"**, `500`. Load-bearing for Q1.1: the spec contains **no** 200-with-parent branch for a slot `block_id`.

[2] [`ethereum/beacon-APIs` issue #126 — "[Clarification] Skipped slots in `/eth/v1/beacon/blocks/{block_id}` endpoint"](https://github.com/ethereum/beacon-APIs/issues/126) — official issue tracker. Referenced for: the question being asked explicitly upstream. **Partial retrieval — the fetch returned only the opening post; comments and resolution were not available.** Recorded as assumption **A-3**, resolved to "the shipped OpenAPI [1] is the answer."

[3] [`sigp/lighthouse` — `beacon_node/http_api/src/block_id.rs` (`stable`)](https://raw.githubusercontent.com/sigp/lighthouse/stable/beacon_node/http_api/src/block_id.rs) — **primary source, client implementation**, fetched directly. Referenced for: slot-`block_id` resolution via `chain.block_root_at_slot(*slot, WhenSlotSkipped::None)` and the `root_opt.ok_or_else(|| warp_utils::reject::custom_not_found(format!("beacon block at slot {}", slot)))` rejection — i.e. no parent substitution, and **no distinction between a future slot and a skipped historical slot**. The decisive external fact for Q1.6.

[4] [`sigp/lighthouse` issue #4904 — "Getting `404 not found` errors for missed blocks instead of a specific missed error code"](https://github.com/sigp/lighthouse/issues/4904) — official issue tracker (retrieved via search result summary, not direct fetch). Referenced for: independent corroboration that Lighthouse returns `{"code":404,"message":"NOT_FOUND: beacon block at slot N"}`, and that callers **cannot** distinguish "missed slot" from "not yet proposed" — both 404.

[5] [`sigp/lighthouse` issue #2186 — "bn `/eth/v1/beacon/blocks/{block_id}` return wrong information on skipped block"](https://github.com/sigp/lighthouse/issues/2186) — official issue tracker, 2021. Referenced for: the **disconfirming case, sought deliberately** — Lighthouse formerly returned block `554464`'s data for skipped slot `554465`. Filed as a bug on the grounds that a 404 was correct; the `WhenSlotSkipped::None` code at [3] is its resolution. This is why the 200-with-parent escape route is closed rather than merely unobserved. *(The fetch returned the issue body but not the closing comments; the resolution is inferred from [3], which is primary.)*

[6] [`Consensys/teku` issue #7635 — "Beacon API endpoint `/eth/v1/beacon/blob_sidecars/` returns 404 on empty blobs block"](https://github.com/Consensys/teku/issues/7635) — official issue tracker (retrieved via search result summary). Referenced only for the weaker, cross-client claim that *"404 error is reserved for empty slots"* is treated as settled convention in the ecosystem. Supporting, not load-bearing.

**In-repo (verified by opening the file at `develop` @ `0ae9a09`)**

| Area | Paths |
|---|---|
| Q1 mechanism | `crates/rvc/src/orchestrator/slot_context.rs:1-9`, `:26-28`, `:32-39`, `:40-61`, `:69-80`, `:90-132`; `crates/rvc/src/orchestrator/sync_committee.rs:62-74`, `:145-157`, `:388-391`, `:582`, `:615-680`, `:710`, `:818`, `:921`, `:1014` |
| Q1 error path | `crates/beacon/src/client.rs:227-233`, `:354-361`, `:955-1004`, `:976-978`; `crates/beacon/src/error.rs:5-14`; `crates/beacon/src/retry.rs:58-61`, `:86-94`; `crates/bn-manager/src/manager.rs:918-923`, `:599-601`, `:683-727`; `crates/bn-manager/src/mock.rs:42-50`, `:150-156` |
| Q1 proposal-path consumer (VD-Q1-6) | `crates/rvc/src/orchestrator/block_proposal/mod.rs:89-104`; `crates/block-service/src/service/mod.rs:89-102`, `:105-117`, `:119-131`; `crates/block-service/src/validation.rs:5-17`, `:19-29`, `:53-70` |
| Q1 slot loop / masking | `crates/rvc/src/orchestrator/coordinator/mod.rs:348-406`, `:412-462`; `crates/rvc/src/orchestrator/duty_management.rs:60-133`, `:159-192` |
| Q1 mock fidelity | `crates/rvc/src/orchestrator/aggregation.rs:609-613`; `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:253-257`; `crates/rvc/tests/common/pipeline_fixture.rs:243-245`; `crates/rvc/tests/sync_independent_of_attesting.rs:87-91`, `:252` |
| Q2 trait + implementors | `crates/block-service/src/traits.rs:13-14`, `:50`; `crates/block-service/src/service/mod.rs:27-34`, `:36`; `crates/block-service/src/service/tests/mocks.rs:342-353`, `:415-416`; `crates/rvc/src/beacon_adapter.rs:14-19`; `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:6`, `:125-128`, `:174-181`; `crates/rvc/tests/common/pipeline_fixture.rs:159-160`; `crates/rvc/tests/sync_independent_of_attesting.rs:119-120`, `:248-250`, `:269-273` |
| Q2 `Send` audit | `crates/rvc/src/orchestrator/coordinator/mod.rs:121-148`, `:204-235`, `:348`; `crates/bn-manager/src/traits.rs:22`, `:40`, `:85`, `:117`, `:138`, `:153`, `:178-188`; `crates/bn-manager/src/submit.rs:33-38`, `:89-96`; `crates/timing/src/clock.rs:15`; `crates/crypto/src/signer_trait.rs:15`; `crates/signer/src/traits.rs:30-32`; `crates/signer/src/lib.rs:212-224`; `crates/doppelganger/src/enablement.rs:14`; `crates/builder/src/service.rs:32-39`; `crates/builder/src/traits.rs:16`, `:56`; `crates/duty-tracker/src/tracker.rs:131-141`; `crates/validator-store/src/store.rs:1`, `:114-123`; `crates/slashing/src/db/mod.rs:58-64` |
| Q2 guard scan | `crates/rvc/src/orchestrator/utils.rs:118`, `:126`, `:213-217`; `crates/rvc/src/orchestrator/duty_management.rs:162`, `:191`, `:292-295`, `:346` |
| Q2 `spawn_blocking` proof | `crates/signer/src/core.rs:36-41`, `:284-287`, `:487-556` (esp. `:492`, `:542`), `:913-964` (esp. `:930`); `crates/slashing/src/stage.rs:10-63`, `:141-147`, `:226-232` |
| Stale clippy allows | `crates/rvc/src/bootstrap/services.rs:179-192`; `crates/rvc/src/config/builder.rs:3`; `crates/rvc/src/orchestrator/coordinator/tests/mod.rs:6`; `crates/rvc/src/orchestrator/sync_committee.rs:328`; `crates/rvc/src/main.rs:1608` *(orphan tree — read only, see A-9)* |
| Governing documents | `docs/research/architecture-review-2026-08-11.md:102-120`, `:185`, `:187`, `:203`, `:205`; `plan/architecture-2026-08-12/prd.md:80`, `:113`, `:128-148`, `:576-594`, `:669-693`, `:1194`, `:1218`; `CLAUDE.md` (KAT-first policy, TDD cycle); `crates/architecture-tests/tests/kat_policy.rs` (scanner pattern) |
