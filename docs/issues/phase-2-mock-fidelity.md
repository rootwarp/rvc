# Phase 2: Mock Fidelity & Concurrency

## Phase Overview
- **Goal:** All mock objects capture and assert on relevant parameters; concurrent and fail-closed tests prove safety properties
- **Issue count:** 7 issues, 15 total points
- **Estimated duration:** 3 days (with 2 parallel streams)
- **Entry criteria:** Phase 1 complete (for Stream C issues); Stream A/B can start during Phase 1
- **Exit criteria:** Block-service mocks capture slot, block content, signature, fork_schedule, genesis_validators_root; sync-service mocks capture all message fields and signer arguments; concurrent test proves mutex necessity; DB error propagation verified; phantom entry verified in DB; `cargo test` passes; `cargo clippy` clean

## Reconciliation (post RF2-01 / RF6-10)

Cross-track close-out against the refactoring plan (theme H4 / F123). This track **owns** mock
fidelity; the refactoring phase only reconciles status after layout changes.

| Issue | Status | Evidence |
|-------|--------|----------|
| **2.1** | **Done** | Landed as `0a1d50b` (`test(block-service): add CapturedCall structs…`). Survives RF6-10 mock merge. |
| **2.2** | **Done** | Landed as `dfb529f` (`test(block-service): add assertion helpers…`). Content helpers + RED tests for #2/#3/#4 still present. |
| **2.3** | **Superseded** | Target was the former sync-service crate twin mocks (`SyncService` / `SyncSigner` / `SyncBeaconClient`). **RF2-01 / B1** (`c56ecfc`) deleted that stack; **ARCH-3** removed the residual shell entirely. No mocks remain to extend. |
| **2.4** | **Superseded** | Same as 2.3 — assertion helpers would have attached to deleted mocks. Do not re-implement on the dead twin. Production path is `SyncCommitteeService` under `crates/rvc/src/orchestrator/sync_committee.rs` (own tests / `MockBeaconNodeClient`). |
| 2.5–2.7 | Unchanged by this reconciliation | Signer-side; out of H4 mock-fidelity scope. |

### Post-RF6-10 home for block-service mocks

Plan text still mentions crates/block-service/src/service.rs (pre-RF6-10 layout; path no longer exists). After RF6-10 the capturing surface lives at:

- `crates/block-service/src/service/tests/mocks.rs` — `CapturedProduceCall`, `CapturedPublishCall`, `CapturedSignBlockCall`, `MockBeaconClient`, `MockSigner`, assertion helpers
- Exactly **one** `impl BeaconBlockClient for` in the crate (merged capture mock)

### Capture fidelity (2.1/2.2 fields still captured)

| Struct | Fields | Populated by |
|--------|--------|--------------|
| `CapturedProduceCall` | `slot`, `randao_reveal`, `graffiti`, `builder_boost_factor` | `produce_block_v3` → `produce_full_calls` |
| `CapturedPublishCall` | `consensus_version`, `slot`, `proposer_index`, `signature_bytes` | `publish_block` / `publish_blinded_block` → `publish_full_calls` / `publish_blinded_full_calls` |
| `CapturedSignBlockCall` | `block_root`, `slot`, `pubkey`, `fork_schedule`, `genesis_validators_root` | `sign_block` → `block_calls` |

No mock discards an argument that 2.1 previously captured. Helpers: `assert_last_produce_slot`,
`assert_last_published_block`, `assert_last_published_blinded_block`, `assert_last_sign_block_domain`,
`last_produce_call`.

### Count-only assertion review (`assert_eq!(…len(), N)` in `crates/block-service`)

Every match is either **content-paired** or **justified** (routing / payload shape). None are sole
coverage for a fidelity finding.

| Location | Assertion | Disposition |
|----------|-----------|-------------|
| `propose.rs` routing tests | `publish_*_calls.len() == 1` (+ empty sibling) | **Justified** — endpoint routing; same tests also call `assert_last_published_*` content helpers |
| `propose.rs` dual propose | `block_calls.len() == 1` ×2 | **Content-paired** — immediately asserts `block_root` |
| `propose.rs` RANDAO epoch | `randao_calls.len() == 1` | **Content-paired** — asserts epoch value; also domain helper on sign path |
| `propose.rs` blob JSON | `blob_sidecars.len()` | **N/A** — response shape, not mock call count |
| `mocks.rs` capture infra | `block_calls.len() == 1` | **Content-paired** — slot + pubkey |
| `ssz.rs` publish path | `ssz_calls.len() == 1` | **Content-paired** — version / `is_blinded` / payload bytes |
| `ssz.rs` root / sig | `block_calls.len()`, `sig.len() == 96`, body/payload lens | **Content-paired** or size checks, not mock arg discard |

Findings #2–#4 remain guarded by content helpers and the dedicated RED helper tests in `mocks.rs`.
Findings #5–#6 (sync twin) are closed as **no longer applicable** after RF2-01.

---

## Phase Summary

| Issue | Title | Points | Stream | Blocked by | Status |
|-------|-------|--------|--------|------------|--------|
| 2.1 | Block-service CapturedCall structs + mock extensions | 3 | A | — | **Done** |
| 2.2 | Block-service assertion helpers + test updates | 2 | A | 2.1 | **Done** |
| 2.3 | Sync-service CapturedCall structs + mock extensions | 3 | B | — | **Superseded (RF2-01 / B1)** |
| 2.4 | Sync-service assertion helpers + test updates | 2 | B | 2.3 | **Superseded (RF2-01 / B1)** |
| 2.5 | Fix concurrent signer test with conflicting data | 2 | C | — | open (this track) |
| 2.6 | Add fail-closed DB error test | 2 | C | — | open (this track) |
| 2.7 | Extend phantom entry test with DB query | 1 | C | — | open (this track) |

## Phase Parallel Plan

| Day | Dev 1 (Stream C) | Dev 2 (Stream A → B) |
|-----|-------------------|----------------------|
| 4 | 2.5 Concurrent signer fix (2pts) | ~~2.3 Sync-service mock structs (3pts)~~ **dropped — superseded** |
| 5 | 2.6 Fail-closed DB test (2pts) | ~~2.3 cont.~~ |
| 6 | 2.7 Phantom entry query (1pt) | ~~2.4 Sync-service assertions (2pts)~~ **dropped — superseded** |

> Note: Stream A (Issues 2.1-2.2) starts during Phase 1 on Dev 2's schedule (Days 1-3).
> Stream B (2.3/2.4) must not be scheduled after RF2-01; points are retired, not deferred.

---

## Issues

### Issue 2.1: Block-Service CapturedCall Structs + Mock Extensions
- **Findings:** #2, #3, #4
- **Stream:** A
- **Story Points:** 3
- **Type:** chore (test infrastructure)
- **Priority:** P1
- **Blocked By:** none
- **Blocks:** Issue 2.2
- **Status:** **Done** (landed; post-RF6-10 home: `crates/block-service/src/service/tests/mocks.rs`)

**Description:**
Define `CapturedProduceCall`, `CapturedPublishCall`, and `CapturedSignBlockCall` structs in the block-service test module. Extend `MockBeaconClient` to capture full arguments in `produce_block_v3`, `publish_block`, and `publish_blinded_block`. Extend `MockSigner` to capture `fork_schedule` and `genesis_validators_root` in `sign_block`. Keep all existing fields for backward compatibility.

**Implementation Notes:**
- File (current): `crates/block-service/src/service/tests/mocks.rs` (was `service.rs` `#[cfg(test)]` before RF6-10)
- Add structs (per architecture doc Section 1.2):
  ```
  CapturedProduceCall { slot, randao_reveal, graffiti, builder_boost_factor }
  CapturedPublishCall { consensus_version, slot, proposer_index, signature_bytes }
  CapturedSignBlockCall { block_root, slot, pubkey, fork_schedule, genesis_validators_root }
  ```
- `MockBeaconClient` additions: `produce_full_calls: Mutex<Vec<CapturedProduceCall>>`, `publish_full_calls: Mutex<Vec<CapturedPublishCall>>`, `publish_blinded_full_calls: Mutex<Vec<CapturedPublishCall>>`
- `MockSigner` change: replace `block_calls: Mutex<Vec<(Root, Slot)>>` with `Mutex<Vec<CapturedSignBlockCall>>`
- Use `std::sync::Mutex` (matches existing block-service mock convention)
- All new capture fields initialized empty in constructors — zero breakage to existing tests
- If `SignedBeaconBlock` doesn't impl `Clone`, capture individual fields or SSZ bytes

**Acceptance Criteria:**
- [x] `CapturedProduceCall`, `CapturedPublishCall`, `CapturedSignBlockCall` structs defined
- [x] `MockBeaconClient::produce_block_v3` captures all arguments before returning
- [x] `MockBeaconClient::publish_block` and `publish_blinded_block` capture full block data
- [x] `MockSigner::sign_block` captures `fork_schedule` and `genesis_validators_root`
- [x] All existing block-service tests still pass (backward compatibility)
- [x] No existing mock constructor signatures changed

**Testing Notes:**
- Run `cargo test -p rvc-block-service` after each change to verify no regressions

---

### Issue 2.2: Block-Service Assertion Helpers + Test Updates
- **Findings:** #2, #3, #4
- **Stream:** A
- **Story Points:** 2
- **Type:** feature (test assertions)
- **Priority:** P1
- **Blocked By:** Issue 2.1
- **Blocks:** Phase 3 Stream A issues (3.1-3.4)
- **Status:** **Done** (landed; helpers + RED tests in `mocks.rs` / call sites in `propose.rs`)

**Description:**
Add assertion helper methods to `MockBeaconClient` and `MockSigner`. Update existing block-service tests to use the new capture fields, adding assertions that verify correct slot, block content, signature, fork_schedule, and genesis_validators_root are threaded through the pipeline.

**Implementation Notes:**
- File (current): `crates/block-service/src/service/tests/mocks.rs` (+ call sites in `propose.rs` / `ssz.rs`)
- Add helpers (per architecture doc Section 1.3):
  - `MockBeaconClient::assert_last_produce_slot(expected_slot)`
  - `MockBeaconClient::assert_last_published_block(expected_slot, expected_proposer)`
  - `MockSigner::assert_last_sign_block_domain(expected_fork, expected_gvr)`
- Update existing tests to call assertion helpers after the action under test
- Key validation: test must fail if production code passes `slot + 1` to `produce_block_v3` (#2)
- Key validation: test must fail if block content or signature is corrupted before publishing (#3)
- Key validation: test must fail if incorrect fork_schedule or genesis_validators_root passed to signer (#4)

**Acceptance Criteria:**
- [x] Test fails if production code passes `slot + 1` instead of `slot` to `produce_block_v3`
- [x] Test fails if block content or signature is corrupted before publishing
- [x] Test fails if production code passes incorrect fork_schedule or genesis_validators_root to signer
- [x] Assertion helpers provide clear error messages on failure

**Testing Notes:**
- Temporarily introduce the off-by-one (`slot + 1`) to verify RED step works
- Run `cargo test -p rvc-block-service`

---

### Issue 2.3: Sync-Service CapturedCall Structs + Mock Extensions
- **Findings:** #5, #6
- **Stream:** B
- **Story Points:** 3
- **Type:** chore (test infrastructure)
- **Priority:** P1
- **Blocked By:** none
- **Blocks:** Issue 2.4
- **Status:** **Superseded by RF2-01 / B1** — do not implement

**Description:**
Define `CapturedSyncSignCall`, `CapturedSelectionProofCall`, `CapturedContributionSignCall`, and `CapturedSubmittedMessages` structs in the sync-service test module. Extend `MockSigner` to capture full arguments in all sign methods. Extend `MockBeacon` to capture submitted messages and contribution proofs. Keep existing `AtomicUsize` counters for backward compatibility.

**Why superseded:**
the former sync-service crate no longer hosts a `SyncService` / `SyncSigner` / `SyncBeaconClient` twin (RF2-01,
commit `c56ecfc`); ARCH-3 deleted the residual shell. Capturing structs and mock extensions would target
deleted code (~900 lines of twin + isolation tests removed). Findings #5/#6 as originally filed against
those mocks are **no longer applicable**. Any future fidelity work belongs on production
`SyncCommitteeService` tests, not a resurrected twin.

**Implementation Notes (historical — do not execute):**
- File: the former sync-service lib (deleted with ARCH-3) — modify `#[cfg(test)]` module
- Add structs (per architecture doc Section 1.4):
  ```
  CapturedSyncSignCall { beacon_block_root, slot, pubkey, fork_schedule, genesis_validators_root }
  CapturedSelectionProofCall { slot, subcommittee_index, pubkey }
  CapturedContributionSignCall { contribution_and_proof, pubkey }
  CapturedSubmittedMessages { messages: Vec<SyncCommitteeMessage> }
  ```
- `MockSigner` additions: `sign_sync_calls`, `sign_selection_calls`, `sign_contribution_calls` (all `tokio::sync::Mutex<Vec<...>>`)
- `MockBeacon` additions: `submitted_messages: tokio::sync::Mutex<Vec<Vec<SyncCommitteeMessage>>>`, `submitted_proofs: tokio::sync::Mutex<Vec<Vec<SignedContributionAndProof>>>`
- MUST use `tokio::sync::Mutex` (sync-service traits are async)
- Keep existing `AtomicUsize` counters alongside capture vectors
- All new capture fields initialized empty — zero breakage
- Files NOT to modify: anything outside the former sync-service lib (deleted with ARCH-3)

**Acceptance Criteria:**
- [x] **Closed as superseded** — twin mocks deleted by RF2-01; no capture structs required
- [x] Confirmed: no `SyncService` / `SyncSigner` / `SyncBeaconClient` production surface remains

**Testing Notes:**
- N/A — package removed (ARCH-3)

---

### Issue 2.4: Sync-Service Assertion Helpers + Test Updates
- **Findings:** #5, #6
- **Stream:** B
- **Story Points:** 2
- **Type:** feature (test assertions)
- **Priority:** P1
- **Blocked By:** Issue 2.3
- **Blocks:** Phase 3 Stream B issues (3.5-3.7) — *those issues must retarget production `SyncCommitteeService` / orchestrator tests; they no longer depend on twin mock helpers*
- **Status:** **Superseded by RF2-01 / B1** — do not implement

**Description:**
Add assertion helper methods to `MockSigner` and `MockBeacon` for sync-service. Update existing sync-service tests to assert on captured fields: `beacon_block_root`, `validator_index`, `slot`, `signature` in submitted messages; `slot`, `pubkey`, `subcommittee_index` in signer calls.

**Why superseded:**
Same as 2.3. Assertion helpers and twin-test updates have no host module after the dead-code purge.
Phase 3 Stream B (3.5–3.7) should treat the "uses upgraded sync-service mocks" blocker as lifted /
retargeted rather than waiting on 2.4.

**Implementation Notes (historical — do not execute):**
- File: the former sync-service lib (deleted with ARCH-3) — modify `#[cfg(test)]` module
- Add helpers (per architecture doc Section 1.5):
  - `MockSigner::assert_last_sync_sign_args(expected_slot, expected_root)`
  - `MockBeacon::assert_last_submitted_messages(expected_count) -> Vec<SyncCommitteeMessage>`
- Update existing tests to add field-level assertions after action under test
- Key validation (#5): test must fail if any field (`beacon_block_root`, `validator_index`, `slot`, `signature`) in submitted message is incorrect
- Key validation (#6): test must fail if production code passes wrong `slot`, `pubkey`, or `subcommittee_index` to signer
- Async assertion helpers (use `.await`)
- Files NOT to modify: anything outside the former sync-service lib (deleted with ARCH-3)

**Acceptance Criteria:**
- [x] **Closed as superseded** — no twin assertion helpers to add
- [x] Downstream 3.5–3.7 noted to retarget production sync path (not blocked on this issue)

**Testing Notes:**
- N/A for twin path

---

### Issue 2.5: Fix Concurrent Signer Test With Conflicting Data
- **Findings:** #7
- **Stream:** C
- **Story Points:** 2
- **Type:** bug (test defect)
- **Priority:** P1
- **Blocked By:** none
- **Blocks:** none

**Description:**
Modify the concurrent same-validator signer test to use conflicting attestation data instead of identical data. Currently both concurrent tasks sign `AttestationData(source=59, target=60)`, so the slashing DB's idempotent re-sign path succeeds either way. The test passes even with the per-validator mutex removed. Fix it so one task uses `(source=59, target=60)` and the other uses `(source=58, target=60)` — same target, different source = double-vote attempt.

**Implementation Notes:**
- File: `crates/signer/src/lib.rs` — modify existing test (around line 1977-2013)
- Change task B's attestation data from `(source=59, target=60)` to `(source=58, target=60)`
- Keep the existing `Barrier::new(2)` for synchronization
- Assert exactly one task succeeds and one fails (order depends on scheduling)
- Use `results.iter().filter(|r| r.is_ok()).count() == 1` pattern
- The test proves mutex serialization because without the mutex, both could read "no existing record" before either writes
- Keep `#[tokio::test(flavor = "multi_thread", worker_threads = 2)]`
- Files NOT to modify: anything outside `crates/signer/src/lib.rs`

**Acceptance Criteria:**
- [ ] Test fails if the per-validator mutex is removed (both tasks would race to the DB)
- [ ] Exactly one concurrent task succeeds and one is rejected
- [ ] Test uses conflicting attestation data (same target epoch, different source)
- [ ] Test is deterministic in outcome count (1 success, 1 failure) regardless of scheduling

**Testing Notes:**
- Run with `cargo test -p signer test_concurrent`
- WARNING: If both tasks succeed, this indicates a real concurrency vulnerability — escalate immediately

---

### Issue 2.6: Add Fail-Closed DB Error Test
- **Findings:** #8
- **Stream:** C
- **Story Points:** 2
- **Type:** feature (new test)
- **Priority:** P1
- **Blocked By:** none
- **Blocks:** none

**Description:**
Add a test that injects a database error and asserts the signer returns a blocking error, not silent success. If a refactor silently swallows `DatabaseError` instead of propagating as `SlashingProtectionBlocked`, no existing test detects it.

**Implementation Notes:**
- File: `crates/signer/src/lib.rs` — add to existing `#[cfg(test)]` module
- Approach: file-backed `SlashingDb` via `tempfile::tempdir()`
  1. Create `SlashingDb::open(&db_path)`
  2. Record one valid attestation via `SignerService`
  3. Corrupt the SQLite file: `std::fs::write(&db_path, b"corrupted")`
  4. Attempt second attestation via `SignerService`
  5. Assert `result.is_err()` — DB error must propagate, not be swallowed
- Prerequisite: confirm `tempfile` is a dev-dependency (likely already is)
- Alternative if file corruption doesn't trigger right path: use `DROP TABLE` via raw SQL
- Assert broadly on `result.is_err()`, not specific SQLite error strings (platform-independent)
- Files NOT to modify: anything outside `crates/signer/src/lib.rs`

**Acceptance Criteria:**
- [ ] Test fails if `DatabaseError` is swallowed and signer returns `Ok(signature)` instead of error
- [ ] Uses file-backed `SlashingDb` with corruption to trigger real I/O error path
- [ ] Test cleanup: `tempdir()` auto-cleans on drop

**Testing Notes:**
- Run with `cargo test -p signer test_db_error`
- Verify `tempfile` dev-dependency exists: `grep tempfile crates/signer/Cargo.toml`

---

### Issue 2.7: Extend Phantom Entry Test With DB Query
- **Findings:** #17
- **Stream:** C
- **Story Points:** 1
- **Type:** bug (test defect)
- **Priority:** P1
- **Blocked By:** none
- **Blocks:** none

**Description:**
Extend the existing `test_signing_failure_after_recording_warns_phantom` test to query the `SlashingDb` after asserting the error type. Currently the test only checks the error type — it doesn't verify the phantom entry actually exists in the database.

**Implementation Notes:**
- File: `crates/signer/src/lib.rs` — extend existing test (around line 2054-2077)
- After the existing error type assertion, add:
  ```
  let records = slashing_db.get_attestations(&pubkey_hex).unwrap();
  assert_eq!(records.len(), 1, "phantom entry must exist after signing failure");
  assert_eq!(records[0].source_epoch, expected_source);
  assert_eq!(records[0].target_epoch, expected_target);
  ```
- Uses `SlashingDb::get_attestations()` which already exists as a public method (db.rs line 175)
- May need to extract `slashing_db` reference from the test setup — check if it's accessible
- Files NOT to modify: anything outside `crates/signer/src/lib.rs`

**Acceptance Criteria:**
- [ ] Test fails if the phantom entry write is removed from production code
- [ ] DB query verifies phantom record exists with expected source/target epochs
- [ ] Existing error type assertion preserved

**Testing Notes:**
- Run with `cargo test -p signer test_signing_failure_after_recording`
