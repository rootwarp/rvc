# M3 scheduled import during duties (RR3-07)

Issue: [#536](https://github.com/rootwarp/rvc/issues/536). Parent: #492 (left open).

Protocol: [`README.md`](./README.md) for median-of-3, host, toolchain, and SHA.
This is not `vc_scale_profile`. Machine-readable copy:
[`m3-scheduled-path.json`](./m3-scheduled-path.json).

The unscheduled baseline cited for the original same-slot cell is
[`rv15-import-during-duties-unscheduled.md`](./rv15-import-during-duties-unscheduled.md)
(table lines 99–104, record lines 114–119, PQ-7 lines 133–140). That file was
not re-run. PQ-7 on this tip is the boundary cell below, not that file and
not the same-slot `late_block_reserves` figure.

## Harness

`crates/rvc/tests/common/import_during_duties.rs`. The signature is the one
RR2-15 published and is unchanged:

```text
pub async fn run_import_during_duties(
    opts: ImportDuringDutiesOpts,
    admission: impl ImportAdmission,
) -> Result<ImportDuringDutiesRecord, String>
```

`ScheduledImport` calls `SlashingProtectionAdapter::new_on_clock` with the
pipeline fixture's `MockSlotClock`, then `import_interchange`, which is the
production path that calls `ImportWindowGate::admit`. `new_on_clock` is
`test-utils` only. Each call builds a private gate. Production still uses the
single gate from spawn.

`ImportDuringDutiesOpts` gained three fields. The RR2-15 constructor and the
same-slot scheduled constructor leave them at `fire_after_ms: None`,
`roll_slot_clock: false`, `following_slots: 0`, so those cells keep the
slot-end clamp and admit at phase entry.

`n200_boundary_attestation` is the PQ-7 cell: N=200, 50 ms mock-BN delay,
sync committee and aggregators on, proposer on, slot
`40 * SLOTS_PER_EPOCH` = **1280** (first slot of Deneb epoch 40; slot 1281
stays in that epoch and on Deneb). `fire_after_ms` is **11_600**.
`roll_slot_clock` is true. `following_slots` is 1, so the fixture serves a
proposer duty and attestation data for slot 1281 as well. The import waits
until 11_600 ms after the slot anchor, then the clock is synced without the
slot-end clamp, then `admit` runs. The harness shuts down only after the
import has finished and two block reserves have been recorded (slot N and
slot N+1).

The same-slot path still clamps the synced offset at `SLOT_DURATION_MS - 1`.
That clamp keeps `current_slot()` on slot N, so it cannot reach a later
reserve. The boundary path does not clamp.

An attestation-deadline miss is one attestation item whose estimated publish
completion is later than **4,999 ms** into slot N. The deadline is
`due_ms(3333, 12_000)` = **3,999 ms**. The slack is **1,000 ms**. Publishes
after 12_000 ms are slot N+1 and are not counted as slot N misses.

### Intervals

A block-reserve wait is the pair of `std::time::Instant`s taken in
`SlashableSignSession::reserve_then_sign` immediately before `reserve()` and
immediately after it returns, for `kind="block"` only. The log is
`test-utils` (and this crate's tests). The harness reads that log. It does
not poll `rvc_slashing_reserve_tx_hold_duration_ms`.

The conn-hold end is the `slashing DB import completed` event. That `info!`
runs on the import thread immediately after `ImportElapsedMs::observe_now`,
which samples `rvc_slashing_import_conn_hold_ms` (`conn.lock()` through
`COMMIT`). The conn-hold start is that event instant minus the histogram
sample. The subscriber is the process default, installed before the fixture,
because `spawn_blocking` does not see a thread-local subscriber. The event's
`metadata().name()` is the callsite; the harness matches the `message` field.

PQ-7 late is a closed-interval overlap of that hold with a recorded
block-reserve wait. An endpoint touch counts. `late_reserve_count` is the
function both the harness and the deterministic tests call.

The free window is **[4,499 ms, 11,800 ms)**: attestation due 3,999 ms plus
the 500 ms reserve, through slot end 12,000 ms minus the 200 ms block reserve.
At 11_600 ms the remainder to 11_800 ms is 200 ms, which is shorter than the
10 MB estimate, so the scheduled gate defers to slot N+1's open at 4,499 ms
into that slot (16,499 ms from slot N's start).

## What was measured

One generated EIP-3076 interchange, same shape as
[`rv15-conn-hold-10mb.md`](./rv15-conn-hold-10mb.md): compact JSON
**10,026,526 bytes**, **26,737** validators, **53,474** history rows. The
database is the on-disk `SlashingDb` that `pipeline_fixture` opens for N>1.

| Knob | Same-slot | Boundary |
|---|---|---|
| N | 200 | 200 |
| Slot | 1280 | 1280, and 1281 has a proposer duty |
| Fire | attestation phase entry | 11_600 ms after the slot anchor |
| Clock roll | clamped | rolls into slot N+1 |
| Profile | release | release |

## Machine

| Field | Value |
|---|---|
| Host | hostname `cursor`, Linux 6.12.94+ x86_64, Intel(R) Xeon(R) Processor (family 6, model 207, stepping 2), 4 cores, 1 thread per core, MemTotal 16,398,384 kB |
| `uname -a` | `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct  6 05:59:35 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux` |
| Disk | ext4 on `/dev/vdc` |
| rustc | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| cargo | `cargo 1.99.0 (5f94df478 2026-08-27)` |
| nextest | `cargo-nextest 0.9.146 (8af696ddc 2026-09-21)` |
| protoc | `libprotoc 3.21.12` |
| Profile | `CARGO_BUILD_JOBS=2 cargo nextest run --release -p rvc --test import_during_duties --locked --run-ignored ignored-only --no-capture` |
| `clock_mode` | `wall` |
| Harness `host` | `cursor linux/x86_64` |
| Harness `toolchain` | `rustc 1.99.0 (b940084d7 2026-09-28)` |

`git rev-parse HEAD` at process start, every run:
`0a74cc6435b6e96559c4104a785d08fe2bd0eabb`. `git status` at that moment
reported 4 dirty paths: `crates/signer/src/core.rs`, `crates/signer/src/lib.rs`,
`crates/rvc/tests/common/import_during_duties.rs`, and
`crates/rvc/tests/import_during_duties.rs`. These notes were written after
the runs, from those logs. The commit SHA is not the harness `sha`.

## PQ-7 boundary cell

All six processes exited 0. One conn-hold sample each. 200 slot-N attestation
items each. Zero slot-N deadline misses each. Two block reserves each: slot
N near 103–111 ms, slot N+1 near 12,056–12,070 ms.

| Run | When (UTC) | Admission | Late | Hold window (ms into slot N) | `conn_hold_ms` | Slot N+1 reserve (ms) | Deferred ms |
|---|---|---|---:|---|---:|---|---:|
| 1 | 2026-10-08T14:56:10Z – 14:56:32Z | unscheduled | 1 | 11639.237–12463.036 | 823.799 | 12056.919–12467.824 (410.906) | 0.0 |
| 2 | 2026-10-08T14:56:32Z – 14:56:45Z | unscheduled | 1 | 11627.263–12379.911 | 752.647 | 12058.389–12383.021 (324.632) | 0.0 |
| 3 | 2026-10-08T14:56:45Z – 14:56:59Z | unscheduled | 1 | 11643.168–12448.898 | 805.73 | 12065.488–12455.134 (389.645) | 0.0 |
| **Median** | | unscheduled | **1** | | **805.73** | | **0.0** |
| 1 | 2026-10-08T14:56:59Z – 14:57:17Z | scheduled | 0 | 16530.317–17340.259 | 809.942 | 12058.690–12063.582 (4.892) | 4899.0 |
| 2 | 2026-10-08T14:57:17Z – 14:57:35Z | scheduled | 0 | 16525.965–17288.658 | 762.694 | 12055.612–12059.136 (3.523) | 4899.0 |
| 3 | 2026-10-08T14:57:35Z – 14:57:53Z | scheduled | 0 | 16531.506–17280.784 | 749.278 | 12064.209–12070.955 (6.747) | 4898.0 |
| **Median** | | scheduled | **0** | | **762.694** | | **4899.0** |

Unscheduled run 1's 22 s includes the release rebuild. The later runs are the
test only.

The unscheduled hold opens just after 11,600 ms and is still open when slot
N+1's block reserve starts (~12,057–12,065 ms). That reserve's wait is
hundreds of milliseconds because `reserve()` blocks on `conn` until the
import commits. `late_block_reserves` is 1 on every unscheduled run.
`overlapping_phase` is `block` and `block_phase_overlapped` is true, from
slot N+1's block span.

The scheduled gate, seeing ~11,600 ms, defers **4,898–4,899 ms**. The hold
opens at 16,526–16,532 ms, which is slot N+1's free window (open at 16,499 ms).
Slot N+1's block reserve has already finished (ends 12,059–12,071 ms).
`late_block_reserves` is 0 on every scheduled run. `overlapping_phase` is
empty and `block_phase_overlapped` is false.

Slot N's own reserve (about 102–111 ms) meets neither hold.

## Same-slot scheduled cell

Retaken on this tree because the conn-hold window is no longer "import future
returned, minus the histogram". The end is the import-completed event. The
test `scheduled_import_at_n200_misses_no_deadline_and_no_late_block_reserve`
asserts `conn_hold_start_ms >= 4_499`. It does not treat `late_block_reserves
== 0` as PQ-7: this cell has one reserve, at t≈0, and the import is admitted
at attestation entry, so that reserve cannot meet the hold.

| Run | When (UTC) | Misses | `conn_hold_ms` | Last publish after 3,999 ms | Hold window (ms) | Deferred ms | Block reserve (ms) |
|---|---|---:|---:|---:|---|---:|---|
| 1 | 2026-10-08T14:57:53Z – 14:57:59Z | 0 | 745.365 | 425.752 | 4531.839–5277.204 | 505.0 | 102.940–108.689 (5.750) |
| 2 | 2026-10-08T14:57:59Z – 14:58:05Z | 0 | 767.944 | 392.725 | 4526.277–5294.221 | 501.0 | 101.940–107.548 (5.608) |
| 3 | 2026-10-08T14:58:05Z – 14:58:11Z | 0 | 735.628 | 395.582 | 4528.926–5264.554 | 504.0 | 102.968–107.553 (4.585) |
| **Median** | | **0** | **745.365** | **395.582** | | **504.0** | |

Every hold opens at or after 4,499 ms (4,526.277, 4,528.926, 4,531.839).
`block_phase_overlapped` is false. `overlapping_phase` is empty. One block
reserve each. `late_block_reserves` is 0, and that 0 is the t≈0 reserve
finishing before the hold, not a later reserve.

## Side by side

The unscheduled column is the cited RR2-15 file, not a new run. The boundary
columns are the new cell.

| Figure | Cited unscheduled (lines 114–119) | Boundary unscheduled | Boundary scheduled |
|---|---|---|---|
| Attestation-deadline misses, median | **0** (105, 0, 0) | **0** (0, 0, 0) | **0** (0, 0, 0) |
| `conn_hold_ms`, median | **726.726** | **805.73** (823.799, 752.647, 805.73) | **762.694** (809.942, 762.694, 749.278) |
| Late block reserves, median | not a later reserve on that tree (lines 133–140) | **1** (1, 1, 1) | **0** (0, 0, 0) |
| Hold opens (ms) | 4074.563, 4037.190, 4039.730 | 11639.237, 11627.263, 11643.168 | 16530.317, 16525.965, 16531.506 |

## Detector

`precise_intervals_count_a_synthetic_overlap` counts hold `[100, 200]`
against reserve `[190, 195]`, and counts a closed touch at `hold_end ==
reserve_start` (`[200, 205]`).

`precise_intervals_reject_a_non_overlapping_edge` rejects a reserve that
starts at 201, and the same-slot shape `[105.52, 111.218]` against
`[4536.292, 5305.907]`.

`poll_lagged_reserve_interval_misses_an_overlap_precise_endpoints_catch`
rebuilds the old poll interval. A reserve `[190, 195]` observed 30 ms late
is stored as `[220, 225]`. `late_reserve_count` on that reconstructed pair
is 0. `late_reserve_count` on `[190, 195]` is 1. The harness calls
`late_reserve_count` with the recorded endpoints, not the poll
reconstruction.

## Paused-clock gate logic

No new paused-clock test was added. These already cover the lines:

| Line | Test | Where |
|---|---|---|
| Defer when the estimate would cross the block reserve, and proceed when it fits | `import_admitted_at_8s_defers_past_the_next_t0_reserve_when_it_would_cross` | `crates/rvc/src/keymanager_adapters/import_window.rs` |
| Two concurrent 10 MB imports serialize | `two_concurrent_10mb_imports_serialize` | same file |
| `NoFreeWindow` for an unfittable payload | `unfittable_payload_returns_no_free_window` | same file |
| The wait is observable | `interchange_import_waits_for_a_free_window_and_reports_the_wait` | `crates/rvc/src/keymanager_adapters/tests/import_window.rs` |

## RR3-03 (#532) on this tip

Re-checked by the existing tests in `crates/validator-store/src/store.rs`.
No new test.

| Accept line | Test |
|---|---|
| A failed config save does not publish | `set_fee_recipient_with_missing_parent_dir_does_not_publish` |
| Concurrent durable writers lose no update and apply none partially | `test_concurrent_durable_writers_lose_no_update_and_apply_none_partially` |
| `set_enabled` concurrent with a durable update survives | `test_concurrent_set_enabled_survives_durable_update` |
| A reload racing a durable update leaves file and store in agreement | `test_reload_config_racing_durable_update_file_and_store_agree` |

## Duty fields at the cache boundary (RR3-04 / RR3-05)

`crates/architecture-tests/tests/no_numeric_duty_parse.rs`, test
`no_numeric_duty_parse_remains_downstream_of_the_cache`. This note does not
edit the RR3-05 region (`97e9e7eb`, refactor: [RR3-05] delete downstream
numeric duty parses).

## N=500

Reused, not re-run.
[`n500-informational.md`](./n500-informational.md) and
[`n500-informational.json`](./n500-informational.json) from #535.

That profile did not complete. All six processes wrote JSON and then failed
`vc_scale_profile.rs` because `budget_exceeded` was true (nextest exit 100).
Harness `sha` `97e9e7ebfceae8ba8765f61d0edcf3a676c8c20d`. Wall last attestation
publish median **-3100.241267** (500/500 publishes finished). Paused aggregate
proofs median **352** of 500 (truncated). Wall `overhang_ms` median
**108001.370705** is the 120 s shutdown, not a finished slot. Those figures
are informational. They are not an N=500 gate and they are not extrapolated.

## Formal flags

1. The harness `sha` is `0a74cc6435b6e96559c4104a785d08fe2bd0eabb`. The runs
   were on a dirty tree (the four source paths above). The commit SHA differs.
2. The cited unscheduled numbers are from
   `rv15-import-during-duties-unscheduled.md` lines 99–119. They were not
   re-measured. The boundary unscheduled column is a new cell (fire at
   11_600 ms, proposer on, slot 1281), not a replacement of that file.
3. Same-slot `late_block_reserves == 0` cannot see a later reserve. PQ-7 is
   the boundary cell: unscheduled median 1, scheduled median 0.
4. The conn-hold start is the import-completed event minus the histogram
   sample, not a poll. The residual is the tracing dispatch between
   `observe_now` and the subscriber, which shifts both ends together.
5. The block-reserve log is `cfg(any(test, feature = "test-utils"))` in
   `rvc-signer`. The production metric still observes the same return
   instant. `crates/slashing` was not edited. `Cargo.toml` and `Cargo.lock`
   were not edited.
6. N=500 is the existing incomplete record. It was not re-run.
7. protoc here is apt 3.21.12. M0's CI protoc was 27.5.
8. Parent #492 stays open.
9. `plan/review-2026-10-03/00-summary.md` is not in the repo. The
   must-not-regress filter set is the one recorded in
   [`m2-n200.md`](./m2-n200.md) lines 306–317.

## Gate

Tree at the measurement runs: `0a74cc6435b6e96559c4104a785d08fe2bd0eabb`, dirty
as noted above. Gates below are that tree plus the fork-hazard line renumber
(signer `lib.rs` gained 4 export lines; inventory and
`docs/gloas-fork-hazard-audit.md` moved 1029/1356/1431 to 1033/1360/1435).
Host `cursor`, Linux 6.12.94+ x86_64. rustc `1.99.0 (b940084d7 2026-09-28)`.
cargo `1.99.0 (5f94df478 2026-08-27)`. nextest `0.9.146`. gitleaks `8.21.2`.
protoc `libprotoc 3.21.12`. `CARGO_BUILD_JOBS=2`. No `Cargo.lock` change.
`crates/slashing/src/stage.rs` was not edited. `OPERATOR_KNOB_NAMES` stays 75
(the clean architecture run includes `config_drift`).

| # | Command | Result |
|---|---|---|
| 1 | `cargo fmt --all -- --check` | pass, exit 0 (2026-10-08T14:59:26Z, and again 15:10:28Z after the inventory edit) |
| 2a | `cargo clippy --locked --workspace --all-targets -- -D warnings` | pass, exit 0, `Finished dev profile [unoptimized + debuginfo] target(s) in 17.89s` |
| 2b | `cargo clippy --locked --workspace --all-features --all-targets -- -D warnings` | pass, exit 0, `Finished dev profile [unoptimized + debuginfo] target(s) in 18.78s` |
| 3 | `cargo check -p rvc --features test-utils --locked` | pass, exit 0, `Finished dev profile [unoptimized + debuginfo] target(s) in 3.32s` |
| 4 | `cargo nextest run -p rvc --locked` | pass, exit 0, **1092 passed, 7 skipped** (`Summary [  96.448s] 1092 tests run: 1092 passed (1 slow), 7 skipped`) |
| 4b | `cargo nextest run -p rvc --locked -E 'test(import_during_duties) or test(import_window)'` | pass, exit 0, **14 passed** (`Summary [   0.080s] 14 tests run: 14 passed, 1085 skipped`) |
| 5 | `cargo clean -p rvc-architecture-tests && cargo nextest run -p rvc-architecture-tests --locked` | pass, exit 0, **189 passed**, from clean (`Removed 6661 files, 1.3GiB total`; `Summary [  12.540s] 189 tests run: 189 passed, 0 skipped`). The first clean run, before the line renumber, failed `fork_hazard_inventory_matches_workspace` and was re-run after the inventory update. |
| 6 | `cargo nextest run --workspace --locked` | pass, exit 0, **5655 passed, 9 skipped** (`Summary [ 100.357s] 5655 tests run: 5655 passed (1 slow), 9 skipped`) |
| 7 | Must-not-regress filters | pass (below) |
| 8 | `gitleaks detect --no-git --source . --config .gitleaks.toml --redact --no-banner --exit-code 1` | pass, exit 0, gitleaks 8.21.2, `no leaks found` (40s). `.gitleaksignore` was not edited |

The slow workspace test is
`rvc::aggregation_dispatch aggregations_are_dispatched_concurrently`
(`SLOW [> 60.000s]`, `PASS [  74.714s]`). The same test in `-p rvc`:
`PASS [  73.701s]`. In the rvc filter: `PASS [  73.784s]`.

Workspace nextest's 9 skips are the seven previously recorded (the six in
[`m2-n200.md`](./m2-n200.md) plus the same-slot scheduled test) plus
`boundary_unscheduled_import_meets_next_slot_block_reserve` and
`boundary_scheduled_import_misses_next_slot_block_reserve`. `-p rvc`'s 7
skips are `slot_processing_profile`, `ungated_path_profile`,
`vc_scale_profile`, and the four ignored `import_during_duties` tests. The
rvc filter's 5 skips are `slot_processing_profile` plus those four. The
filter's 50 passes are the previous 47 plus
`precise_intervals_count_a_synthetic_overlap`,
`precise_intervals_reject_a_non_overlapping_edge`, and
`poll_lagged_reserve_interval_misses_an_overlap_precise_endpoints_catch`.
The slashing filter's one skip is the ignored 10 MB budget check.

`00-summary.md` is not in the repo. Filters are the `m2-n200.md` lines
306–317, run 2026-10-08T15:06:05Z through 15:07:50Z. All exit 0.

| Filter | Summary |
|---|---|
| `cargo nextest run -p rvc-timing --locked` | `51 tests run: 51 passed, 0 skipped` |
| `cargo nextest run -p rvc-slashing --locked -E 'binary(conformance) or binary(interchange) or binary(wal_hard_fail) or binary(sidecar_perms_l8)'` | `101 tests run: 101 passed, 1 skipped` |
| `cargo nextest run -p rvc-signer --locked -E 'binary(retain_on_ambiguity_matrix) or binary(gate_per_validator_lock) or binary(gate_doppelganger) or binary(gate_unknown_pubkey_fails_closed) or binary(gate_sign_timeout)'` | `51 tests run: 51 passed, 0 skipped` |
| `cargo nextest run -p rvc --locked -E 'binary(duty_coverage) or binary(sync_independent_of_attesting) or binary(ptc_duty_round_trip) or binary(proposal_first_budget) or binary(proposal_under_duty_stall) or binary(in_flight_publish_on_shutdown) or binary(gloas_data_index_round_trip) or binary(key_import_pipeline) or binary(pipeline_slashing) or binary(slot_processing_profile) or binary(attestation_data_memo) or binary(sync_dispatch) or binary(aggregation_dispatch) or binary(import_during_duties)'` | `50 tests run: 50 passed (1 slow), 5 skipped` |
| `cargo nextest run -p rvc-architecture-tests --locked -E 'binary(mock_fidelity) or binary(docs_freshness) or binary(architecture_doc_matches_graph) or binary(uncompiled_source) or binary(orphan_dirs) or binary(gate_lock_ownership_doc) or binary(no_time_into_slot_ms) or binary(kat_policy) or binary(raw_spawn) or binary(telemetry_field_keys_match_registry) or binary(field_name_conformance) or binary(km2_lifecycle) or binary(layer_edges) or binary(config_drift)'` | `86 tests run: 86 passed, 0 skipped` |
| `cargo nextest run -p rvc-bn-manager --locked` | `381 tests run: 381 passed, 0 skipped` |
| `cargo nextest run -p rvc-secret-provider --locked` | `69 tests run: 69 passed, 0 skipped` |
| `cargo nextest run -p rvc-secret-provider --features test-utils --locked` | `75 tests run: 75 passed, 0 skipped` |
| `cargo nextest run -p rvc-metrics --locked` | `45 tests run: 45 passed, 0 skipped` |
| `cargo nextest run -p rvc-metrics --locked -E 'binary(metric_name_stability)'` | `4 tests run: 4 passed, 0 skipped` |
| `cargo nextest run -p rvc-keymanager-api --locked` | `222 tests run: 222 passed, 0 skipped` |

Named passes from those runs:

```
PASS [   0.004s] rvc keymanager_adapters::import_window::tests::import_admitted_at_8s_defers_past_the_next_t0_reserve_when_it_would_cross
PASS [   0.004s] rvc keymanager_adapters::import_window::tests::two_concurrent_10mb_imports_serialize
PASS [   0.004s] rvc keymanager_adapters::import_window::tests::unfittable_payload_returns_no_free_window
PASS [   0.007s] rvc keymanager_adapters::tests::import_window::interchange_import_waits_for_a_free_window_and_reports_the_wait
PASS [   0.003s] rvc::import_during_duties precise_intervals_count_a_synthetic_overlap
PASS [   0.003s] rvc::import_during_duties precise_intervals_reject_a_non_overlapping_edge
PASS [   0.004s] rvc::import_during_duties poll_lagged_reserve_interval_misses_an_overlap_precise_endpoints_catch
PASS [   0.003s] rvc-validator-store store::tests::set_fee_recipient_with_missing_parent_dir_does_not_publish
PASS [   0.134s] rvc-validator-store store::tests::test_concurrent_durable_writers_lose_no_update_and_apply_none_partially
PASS [   0.008s] rvc-validator-store store::tests::test_concurrent_set_enabled_survives_durable_update
PASS [   0.197s] rvc-validator-store store::tests::test_reload_config_racing_durable_update_file_and_store_agree
PASS [   0.011s] rvc-architecture-tests::no_numeric_duty_parse no_numeric_duty_parse_remains_downstream_of_the_cache
PASS [   0.104s] rvc-architecture-tests::kat_policy kat_policy_no_unanchored_root_tests
PASS [   0.031s] rvc-architecture-tests::layer_edges g5a_holds_on_the_real_workspace_graph
PASS [   0.031s] rvc-architecture-tests::layer_edges g5b_holds_on_the_real_workspace_graph
PASS [   0.036s] rvc-architecture-tests::raw_spawn no_raw_spawns_outside_executor_and_allowlist
PASS [   0.208s] rvc-architecture-tests::uncompiled_source test_no_uncompiled_source_under_member_src
PASS [   0.018s] rvc-architecture-tests::mock_fidelity g8_no_dishonest_block_root_stubs
```

`gitleaks` 8.21.2:

```
scan completed in 40s
no leaks found
```
