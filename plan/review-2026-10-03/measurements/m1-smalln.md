# M1 at small N (RR1-10)

Issue: [#513](https://github.com/rootwarp/rvc/issues/513). Parent: #490 (left open).

Protocol: [`README.md`](./README.md). Machine-readable copy: [`m1-smalln.json`](./m1-smalln.json).
RED comparison: [`red-n200.md`](./red-n200.md) / [`red-n200.json`](./red-n200.json).

**M1 is not claimed at N=200.** `rvc_slot_phase_late_total` is expected non-zero at N=200 until RV-07. `DutyOrchestrator::run` awaits the block phase (`maybe_propose_block` at `crates/rvc/src/orchestrator/coordinator/mod.rs:570`) and then `tokio::join!`s attestation/sync, aggregate/contribution, and payload attestation (`:597`). The sequential attestation phase still holds that join, so an N=200 slot of about 20 s (the RED wall median overhang) keeps the loop past the next slot start. Issue #513 cites `:536` and `:563`; those calls sit at `:570` and `:597` on this tree. This note does not run N=200 phase adherence. That is M2.

## What was measured

Single-duty fixture: zero validators, `MockBeaconNodeClient`, one slot, `DutyOrchestrator::run`. The mock clock is `set_slot_with_offset_ms(slot, 0)` then `advance_ms(600)`, so capture is 600 ms into the slot. Deadlines are `OrchestratorConfig::new` (pre-Gloas 3,999 / 8,000 ms; Gloas 3,000 / 6,000 / 9,000 ms). Empty attestation work finishes at the attestation deadline, inside the 4,001 ms gap before the 8,000 ms aggregate deadline.

Two scenarios per run:

| Scenario | Slot | Epoch | Fork | Why |
|---|---:|---:|---|---|
| pre-Gloas | 65 | 2 | Phase0 | The 3,999–8,000 ms gap the issue names. Payload attestation does not run before Gloas. |
| Gloas | 2240 | 70 | Gloas | So `payload_attestation` is actually recorded. |

Three independent runs per clock mode. The headline cell is the **wall** median. Paused runs are recorded beside it.

`lateness_ms` is the phase offset checked against `[0, +50]`:

- block: `observed_ms - 600`. The deadline is 0 and has already passed at the wake, so the earliest legal fire is the wake.
- every other phase: `observed_ms - deadline_ms`.

The offset **metric** is `observed_ms` itself (`rvc_slot_phase_offset_ms{phase}` and `rvc_slot_phase_block_start_offset_ms{cache=cold}`). That is the value that reads about 600 ms for the block phase, where a whole-second clock read 0 at RED.

## Clock mode

RR0-08 keeps latency on **wall** and counts on **paused**, and stores both. Phase-fire offsets are a latency figure, so the protocol cell is **wall**. Paused is the clock the landed unit tests use (`start_paused = true`) and is included so the two modes can be compared the way `red-n200.*` compares them.

This is not `vc_scale_profile`. That harness advances the mock clock 8 s before `run` and does not read `rvc_slot_phase_*`. Using it here would zero the phase waits and would not be the `[0, +50]` measurement.

## Machine

| Field | Value |
|---|---|
| `git rev-parse HEAD` at process start | `7ea68c730dca060545d42164d15fde41c9e40f08` |
| Runtime | that SHA. Production sources were not edited for this measurement. |
| Host | hostname `cursor`, Linux 6.12.94+ x86_64, Intel(R) Xeon(R) Processor (family 6, model 207, stepping 2), 4 cores, 1 thread per core |
| `uname -a` | `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Fri Oct  2 18:10:29 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux` |
| rustc | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| cargo | `cargo 1.99.0 (5f94df478 2026-08-27)` |
| nextest | `cargo-nextest 0.9.146 (8af696ddc 2026-09-21)` |

The printer was an ignored unit test, run three times per clock mode, then deleted before the gate below. It only read the existing histograms. It is not in this commit. Each process printed `sha` `7ea68c730dca060545d42164d15fde41c9e40f08`.

Runs: paused 1 during the compile that started 2026-10-06T09:40:52Z and finished before 09:44:28Z; wall 2026-10-06T09:44:28Z, 09:44:45Z, 09:45:01Z; paused 2 and 3 at 2026-10-06T09:45:18Z. All six exited 0.

## Headline — wall, pre-Gloas (the 4 s gap)

| Phase | Deadline ms | Runs (elapsed ms) | Median elapsed | Lateness runs | Lateness median | In `[0, +50]` |
|---|---:|---|---:|---|---:|---|
| block | 0 (wake 600) | 600.0, 600.0, 600.0 | **600.0** | 0.0, 0.0, 0.0 | **0.0** | yes |
| attestation | 3999 | 4000.0, 4000.0, 3999.0 | **4000.0** | 1.0, 1.0, 0.0 | **1.0** | yes |
| sync_message | 3999 | 4001.0, 4000.0, 4000.0 | **4000.0** | 2.0, 1.0, 1.0 | **1.0** | yes |
| contribution | 8000 | 8001.0, 8000.0, 8000.0 | **8000.0** | 1.0, 0.0, 0.0 | **0.0** | yes |
| aggregate | 8000 | 8001.0, 8000.0, 8000.0 | **8000.0** | 1.0, 0.0, 0.0 | **0.0** | yes |
| payload_attestation | 8000 | no sample, no sample, no sample | — | — | — | not run before Gloas |

`rvc_slot_phase_block_start_offset_ms{cache=cold}`: 600.0, 600.0, 600.0, median **600.0**. Warm samples added: 0. `rvc_slot_phase_late_total` added 0 on attestation, sync_message, aggregate, contribution, and payload_attestation, on every run.

Attestation median 4000.0 ms is inside `[3999, 4049]`. It is 1 ms after the deadline, never early.

## Wall, Gloas (payload attestation included)

| Phase | Deadline ms | Runs (elapsed ms) | Median elapsed | Lateness median | In `[0, +50]` |
|---|---:|---|---:|---:|---|
| block | 0 (wake 600) | 600.0, 600.0, 600.0 | **600.0** | **0.0** | yes |
| attestation | 3000 | 3001.0, 3001.0, 3000.0 | **3001.0** | **1.0** | yes |
| sync_message | 3000 | 3001.0, 3001.0, 3000.0 | **3001.0** | **1.0** | yes |
| contribution | 6000 | 6000.0, 6000.0, 6001.0 | **6000.0** | **0.0** | yes |
| aggregate | 6000 | 6000.0, 6000.0, 6001.0 | **6000.0** | **0.0** | yes |
| payload_attestation | 9000 | 9001.0, 9001.0, 9000.0 | **9001.0** | **1.0** | yes |

Block-start cold mean: 600.0, 600.0, 600.0, median **600.0**. Late counters added 0.

## Paused (same fixture, not the protocol cell)

Every paused run was exact. Pre-Gloas: block 600.0, attestation 3999.0, sync_message 3999.0, contribution 8000.0, aggregate 8000.0, payload not run. Gloas: block 600.0, attestation 3000.0, sync_message 3000.0, contribution 6000.0, aggregate 6000.0, payload_attestation 9000.0. Lateness 0.0 on every fired phase. Block-start cold mean 600.0. Late counters added 0. Three runs, no spread.

## Side-by-side against `red-n200.*`

`red-n200.*` has no small-N column and no `rvc_slot_phase_*` samples. RR0-08 says the histogram was not scraped, and that a whole-second `set_slot` read is 0 (an 8 s `advance_time` read is 8,000 ms of mock time). Those are the RED cells this offset is compared with.

| Figure | RED | M1 small-N, wall median |
|---|---|---|
| `rvc_slot_phase_block_start_offset_ms` at a +600 ms anchor | **0** (whole-second read; not scraped in `red-n200.*`) | **600.0** |
| `rvc_slot_phase_offset_ms{phase=block}` | **0** (same clock read; family did not exist at RED) | **600.0** |
| Attestation elapsed, pre-Gloas | not in `red-n200.*` | **4000.0** (lateness **1.0**, inside `[3999, 4049]`) |
| Aggregate elapsed, pre-Gloas | not in `red-n200.*` | **8000.0** (lateness **0.0**, inside `[8000, 8050]`) |
| Payload attestation elapsed | not in `red-n200.*` | **9001.0** on Gloas (lateness **1.0**) |
| N=200 wall `last_publish_ms_after_att_deadline` | **17739.82913** | not run |
| N=200 wall `aggregate_deadline_misses` | **1** | not run |
| N=200 paused `sync_publish_ms_after_slot_start` | **20553.0** | not run |

The N=200 rows stay the RED baseline. They are not an M1 result.

## Phase-1 exit criteria

`plan/review-2026-10-03/00-summary.md` is not in the repo (the plan set is uncommitted). The eight criteria are the exit list on #490. Evidence is from this tree, SHA `7ea68c730dca060545d42164d15fde41c9e40f08`, rustc 1.99.0, 2026-10-06.

- [x] **Mock clock 600 ms into a second ⇒ `time_until_slot(next) == slot_duration − 600 ms`; all 3 `impl SlotClock` compile with only the new primitive added.**

  `cargo nextest run -p rvc-timing --locked` — `Summary [   0.044s] 51 tests run: 51 passed, 0 skipped`, exit 0. The three impls are `SystemSlotClock` (`crates/timing/src/clock.rs:184`), `MockSlotClock` (`:292`), and test-only `MinimalClock` (`:568`). Named passes:

  ```
  PASS rvc-timing clock::tests::minimal_clock_time_until_slot_is_sub_second
  PASS rvc-timing clock::tests::mock_clock_expresses_a_mid_second_start
  PASS rvc-timing clock::tests::minimal_clock_time_until_due_3333_is_remainder_to_3999ms
  Summary [   0.004s] 3 tests run: 3 passed, 48 skipped
  ```

- [x] **At a 600 ms mid-second start: phase 0 within 50 ms of the wake, attestation in `[3999, 4049]` and never early; a passed deadline fires immediately with a warn and `rvc_slot_phase_late_total`, and does not shift a later phase.**

  Wall pre-Gloas medians above: block elapsed **600.0** (lateness after the wake **0.0**), attestation **4000.0** (inside `[3999, 4049]`, lateness **1.0**), aggregate **8000.0** (lateness **0.0**). Phase 0 is 600 ms after the true slot start, which is the offset metric, and 0 ms after the wake. The landed test that owns this criterion passed:

  ```
  PASS rvc orchestrator::coordinator::tests::slot_anchor::attestation_phase_fires_in_3999_4049_from_a_mid_second_start
  ```

  That test is what asserts the already-due sync phase fires immediately, warns, increments `rvc_slot_phase_late_total`, and leaves the aggregate in `[8000, 8050]`. This M1 fixture's own late counters stayed 0, because on the default deadline set no measured phase was already past its deadline except block, which has no late label.

- [x] **A backward mock-clock step between slots does not re-process slot S: `rvc_slot_replay_skipped_total == 1` and phase 0 ran once.**

  ```
  PASS rvc orchestrator::coordinator::tests::slot_replay::backward_clock_step_between_slots_does_not_reprocess_slot_s
  ```

- [x] **`record_phase_block_start_offset` at +600 ms observes about 600 (RED read 0); a 600 ms late wake is in the attestation span's `time_into_slot`; `no_time_into_slot_ms.rs` is green.**

  M1 wall and paused: block-start cold mean **600.0** on all six runs, and `rvc_slot_phase_offset_ms{phase=block}` **600.0**. RED's documented whole-second read is 0.

  ```
  PASS rvc orchestrator::coordinator::tests::phase_block_offset::phase_block_start_offset_reports_the_true_offset
  PASS rvc orchestrator::coordinator::tests::spans::attestation_span_time_into_slot_includes_a_late_wake
  PASS rvc-architecture-tests::no_time_into_slot_ms t16_no_time_into_slot_ms_in_production_source
  ```

- [x] **`await_shutdown_and_drain` with a panicking registered task ⇒ `Err(CriticalTaskFailed)`, `exit_code() == 16`, drain still completed; `run.rs` has no `process::exit`.**

  ```
  PASS rvc bootstrap::run::tests::await_shutdown_and_drain_returns_err_on_task_failure
  PASS rvc bootstrap::run::tests::test_run_rs_has_no_process_exit_call
  ```

- [x] **Metrics port held ⇒ `Err(ListenerBind)` naming listener and address, `exit_code() == 15`, no orchestrator task spawned.**

  ```
  PASS rvc bootstrap::tasks::tests::bind_required_listeners_fails_with_listener_and_addr
  PASS rvc bootstrap::tasks::tests::bind_required_listeners_keymanager_port_held_is_listener_bind
  PASS rvc bootstrap::run::tests::bind_required_listeners_precedes_keystore_load_and_orchestrator_spawn
  PASS rvc bootstrap::tests::test_bootstrap_error_exit_codes_map_startup_gates
  ```

  The ordering test is the "no orchestrator task" evidence: `bind_required_listeners` is before `load_signing_keys` and before the `duty_orchestrator` spawn, so a bind error returns before that spawn.

- [x] **`spawn_result` returning `Ok(Err(e))` ⇒ drain and `rvc_task_exits_total{outcome="error"} == 1`, not `ok`.**

  ```
  PASS rvc bootstrap::executor::tests::spawn_result_task_returning_err_records_error_outcome
  PASS rvc bootstrap::run::tests::await_shutdown_and_drain_returns_exit_16_on_spawn_result_error
  ```

- [x] **M1 recorded at small N. Every fired phase's lateness is in `[0, +50]` ms. Offset metrics report the true value (600.0 where RED read 0). Same latency clock mode as RED (wall). M1 is not claimed at N=200.**

  Tables above. Worst wall lateness in the six runs is 2.0 ms (`sync_message` on pre-Gloas wall run 1). `rvc_slot_phase_late_total` added 0 on this fixture. It is expected non-zero at N=200 until RV-07. N=200 was not run.

The 13 `rvc` exit tests together: `Summary [   0.116s] 13 tests run: 13 passed, 832 skipped`, exit 0.

## Gate

Tree `7ea68c730dca060545d42164d15fde41c9e40f08`. Host `cursor`, Linux 6.12.94+ x86_64. rustc `1.99.0 (b940084d7 2026-09-28)`. cargo `1.99.0 (5f94df478 2026-08-27)`. nextest `0.9.146`. protoc `libprotoc 27.5`. Commands from 2026-10-06T09:45:55Z through 09:58:49Z. `CARGO_TERM_COLOR=never`. No production file, `Cargo.lock`, or `crates/slashing/src/stage.rs` change.

The known flakes (`retained_with_op_timeout_does_not_enclose_query_first`, group-commit worker disconnected) did not fire.

| # | Command | Result |
|---|---|---|
| 1 | `cargo fmt --all -- --check` | pass, exit 0 (09:45:55Z–09:45:57Z) |
| 2a | `cargo clippy --locked --workspace --all-targets -- -D warnings` | pass, exit 0, `Finished dev profile … in 58.84s` |
| 2b | `cargo clippy --locked --workspace --all-features --all-targets -- -D warnings` | pass, exit 0, `Finished dev profile … in 1m 28s` |
| 3 | `cargo check -p rvc --features test-utils --locked` | pass, exit 0, `Finished dev profile … in 19.24s` |
| 4 | `cargo nextest run --workspace --locked` | pass, exit 0, **5540 passed, 4 skipped, 0 failed** (`Summary [  80.567s] 5540 tests run: 5540 passed, 4 skipped`) |
| 5 | `cargo clean -p rvc-architecture-tests && cargo nextest run -p rvc-architecture-tests --locked` | pass, exit 0, **184 passed**, from clean (`Removed 3809 files, 680.9MiB total`; `Summary [  12.256s] 184 tests run: 184 passed, 0 skipped`) |
| 6 | Must-not-regress filters | pass (below) |

`plan/review-2026-10-03/00-summary.md` is not in the repo. The filter set is the standing-invariant table on #488, the Must-not-regress lines on #504–#512, and the protected tests named for this gate.

| Filter | Summary |
|---|---|
| `cargo nextest run -p rvc-timing --locked` | `51 tests run: 51 passed, 0 skipped` |
| `cargo nextest run -p rvc-slashing --locked -E 'binary(conformance) or binary(interchange) or binary(wal_hard_fail) or binary(sidecar_perms_l8)'` | `96 tests run: 96 passed, 0 skipped` |
| `cargo nextest run -p rvc-signer --locked -E 'binary(retain_on_ambiguity_matrix) or binary(gate_per_validator_lock) or binary(gate_doppelganger) or binary(gate_unknown_pubkey_fails_closed) or binary(gate_sign_timeout)'` | `51 tests run: 51 passed, 0 skipped` |
| `cargo nextest run -p rvc --locked -E 'binary(duty_coverage) or binary(sync_independent_of_attesting) or binary(ptc_duty_round_trip) or binary(proposal_first_budget) or binary(proposal_under_duty_stall) or binary(in_flight_publish_on_shutdown) or binary(gloas_data_index_round_trip) or binary(key_import_pipeline) or binary(pipeline_slashing) or binary(slot_processing_profile)'` | `37 tests run: 37 passed, 1 skipped` |
| `cargo nextest run -p rvc-architecture-tests --locked -E 'binary(mock_fidelity) or binary(docs_freshness) or binary(architecture_doc_matches_graph) or binary(uncompiled_source) or binary(orphan_dirs) or binary(gate_lock_ownership_doc) or binary(no_time_into_slot_ms) or binary(kat_policy) or binary(raw_spawn) or binary(telemetry_field_keys_match_registry) or binary(field_name_conformance) or binary(km2_lifecycle)'` | `67 tests run: 67 passed, 0 skipped` |
| `cargo nextest run -p rvc-bn-manager --locked` | `372 tests run: 372 passed, 0 skipped` |
| `cargo nextest run -p rvc-secret-provider --locked` | `69 tests run: 69 passed, 0 skipped` |
| `cargo nextest run -p rvc-secret-provider --features test-utils --locked` | `75 tests run: 75 passed, 0 skipped` |
| `cargo nextest run -p rvc-metrics --locked` | `45 tests run: 45 passed, 0 skipped` |
| `cargo nextest run -p rvc-metrics --locked -E 'binary(metric_name_stability)'` | `4 tests run: 4 passed, 0 skipped` |
| `cargo nextest run -p rvc-keymanager-api --locked` | `219 tests run: 219 passed, 0 skipped` |

The rvc filter's one skip is `test_slot_processing_profile_reports_p99`, which is `#[ignore]`. The binary was selected. Default nextest does not run ignored tests.

Workspace nextest's 4 skips are the ignored tests. `cargo test --workspace` was not used.
