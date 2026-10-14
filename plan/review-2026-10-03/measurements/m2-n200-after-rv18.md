# M2 at N=200, re-run after RR3 (RR3-07)

Issue: [#536](https://github.com/rootwarp/rvc/issues/536). Parent: #492 (left open).

Protocol: [`README.md`](./README.md). Harness:
`crates/rvc/tests/vc_scale_profile.rs` (`vc_scale_profile_emits_a_complete_record`).
Machine-readable copy: [`m2-n200-after-rv18.json`](./m2-n200-after-rv18.json).
Phase-2 record, restated below and not overwritten:
[`m2-n200.md`](./m2-n200.md) / [`m2-n200.json`](./m2-n200.json).

Latency is the **wall** cell. Counts and ordering are the **paused** cell.
Three independent runs per clock mode. The headline cell is the median.
Debug nextest profile, the same profile as `m2-n200`. The harness advances
the mock clock 8 s before `run`. `VC_SCALE_SLOTS` is 1.

The accept lines from `m2-n200.md` still hold. The gate was not loosened.
Nothing in the RR3-05 region (#534, commit `97e9e7eb`) was edited.

## What was run

`git rev-parse HEAD` inside each harness process printed
`1299a49035f00ba6fca59e97b09d865726dedb41`. That is develop at the time of
the run. The working tree already had the uncommitted RR3-07 harness in
`crates/rvc/tests/common/import_during_duties.rs`,
`crates/rvc/tests/import_during_duties.rs`, and
`crates/rvc/src/keymanager_adapters/slashing.rs` (`new_on_clock`).
`vc_scale_profile` does not call that harness. This commit adds the harness
and these notes together, so the commit SHA is not the harness `sha`.

Command, both clock modes:

```text
VC_SCALE_N=200 VC_SCALE_SLOTS=1 VC_SCALE_CLOCK=<wall|paused> \
  VC_SCALE_OUTPUT=<path> CARGO_BUILD_JOBS=2 \
  cargo nextest run -p rvc --locked --run-ignored ignored-only --no-capture \
  -E 'test(vc_scale_profile_emits_a_complete_record)'
```

All six exited 0.

| Clock | Process window (UTC) | Elapsed |
|---|---|---|
| wall 1 | 2026-10-08T12:53:46Z – 12:55:04Z | 78 s (includes the debug compile) |
| wall 2 | 2026-10-08T12:55:04Z – 12:55:07Z | 3 s |
| wall 3 | 2026-10-08T12:55:07Z – 12:55:10Z | 3 s |
| paused 1 | 2026-10-08T12:55:10Z – 12:55:11Z | 1 s |
| paused 2 | 2026-10-08T12:55:11Z – 12:55:12Z | 1 s |
| paused 3 | 2026-10-08T12:55:12Z – 12:55:13Z | 1 s |

## Machine

| Field | Value |
|---|---|
| `git rev-parse HEAD` at process start | `1299a49035f00ba6fca59e97b09d865726dedb41` |
| Phase-2 record SHA | `dd4aec0c4343dcb83d3b7dd7c6d9cd64c9dc1807` |
| Host | hostname `cursor`, Linux 6.12.94+ x86_64, Intel(R) Xeon(R) Processor (family 6, model 207, stepping 2), 4 cores, 1 thread per core, MemTotal 16,398,384 kB |
| `uname -a` | `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct  6 05:59:35 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux` |
| Disk | ext4 on `/dev/vdc` |
| Harness `host` field | `cursor linux/x86_64` |
| rustc | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| cargo | `cargo 1.99.0 (5f94df478 2026-08-27)` |
| nextest | `cargo-nextest 0.9.146 (8af696ddc 2026-09-21)` |
| protoc | `libprotoc 3.21.12` (apt `protobuf-compiler`) |
| Harness `toolchain` field | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| Profile | debug nextest, not `--release` |

The workspace `rust-version` is 1.92. CI installs `dtolnay/rust-toolchain@stable`.
The image default `rustc 1.83.0` cannot parse locked `cpufeatures 0.3.0`
(`edition2024`). These runs used stable 1.99.0. M0 recorded CI's
`arduino/setup-protoc@v3` as `libprotoc 27.5`. This VM used the apt package.

## Scenario

Same as [`m2-n200.md`](./m2-n200.md): `DutyOrchestrator::run`, N = 200, one
slot (slot 32, first slot of epoch 1, pre-Electra), one committee index `0`,
`with_request_delay(50 ms)`, `with_sync_committee(true)`,
`with_aggregators(true)`, 12 s slot, attestation deadline 3,999 ms, aggregate
deadline 8,000 ms, per-slot budget 120,000 ms. The mock clock is advanced 8 s
before `run`.

## Phase-2 numbers next to this re-run

Phase-2 runs and medians are copied from [`m2-n200.md`](./m2-n200.md) lines
66–78 and the non-protocol copies on lines 82–86. They were not re-derived.

| Figure | Clock | Phase-2 runs (`dd4aec0c`) | Phase-2 median | This re-run | This median | Accept |
|---|---|---|---|---|---|---|
| `last_publish_ms_after_att_deadline` | **wall** | -3527.843577, -3500.726064, -3568.643065 | **-3527.843577** | -3504.506697, -3514.365184, -3515.146715 | **-3514.365184** | ≤ +1000. Holds |
| Same stamp, ms into the harness slot | **wall** | 471.156423, 498.273936, 430.356935 | **471.156423** | 494.493303, 484.634816, 483.853285 | **484.634816** | ≤ 4999. Holds |
| `aggregate_deadline_misses` | **wall** | 0, 0, 0 | **0** | 0, 0, 0 | **0** | 0. Holds |
| `aggregate_proofs_after_deadline` | **wall** | 0, 0, 0 | **0** | 0, 0, 0 | **0** | |
| `overhang_ms` | **wall** | 0.0, 0.0, 0.0 | **0.0** | 0.0, 0.0, 0.0 | **0.0** | ≤ 500. Holds |
| `commits_per_attestation_phase` | **paused** | 12.0, 11.0, 12.0 | **12.0** | 16.0, 12.0, 14.0 | **14.0** | ≤ 25. Holds |
| `mean_batch` | **paused** | 16.666666666666668, 18.181818181818183, 16.666666666666668 | **16.666666666666668** | 12.5, 16.666666666666668, 14.285714285714286 | **14.285714285714286** | ≥ 8. Holds |
| `attestation_data_requests_per_slot` | **paused** | 201.0, 201.0, 201.0 | **201.0** | 201.0, 201.0, 201.0 | **201.0** | |
| `sync_publish_ms_after_slot_start` | **paused** | 153.0, 153.0, 153.0 | **153.0** | 153.0, 153.0, 153.0 | **153.0** | |
| `sync_messages_submitted` | **paused** | 200, 200, 200 | **200** | 200, 200, 200 | **200** | |
| `sync_submit_calls` | **paused** | 7, 7, 7 | **7** | 7, 7, 7 | **7** | |
| `aggregate_proofs_submitted` | **paused** | 200, 200, 200 | **200** | 200, 200, 200 | **200** | |
| `aggregate_submit_calls` | **paused** | 7, 7, 7 | **7** | 7, 7, 7 | **7** | |

All six harness runs: `successes` 200, `failures` 0, `budget_exceeded` false,
`overrun` false, `n` 200, `slots` 1.

Paused copies of the wall latency key (virtual time, not the protocol cell):

| | Runs | Median |
|---|---|---|
| Phase-2 (`m2-n200.md` line 83) | -3642.0, -3591.0, -3591.0 | **-3591.0** |
| This re-run | -3591.0, -3642.0, -3642.0 | **-3642.0** |

Wall copies of the sync-publish offset (not the protocol cell):

| | Runs | Median |
|---|---|---|
| Phase-2 (`m2-n200.md` line 85) | 189.91374199999998, 180.757005, 180.001143 | **180.757005** |
| This re-run | 184.872489, 179.52250999999998, 181.12247200000002 | **181.12247200000002** |

Wall copies of the commit cells (not the protocol cell). Phase-2 wall runs
from `m2-n200.json` `figures.commits_per_attestation_phase.wall_runs_same_key`
and `figures.mean_batch.wall_runs_same_key`: commits 14.0, 12.0, 14.0;
`mean_batch` 14.285714285714286, 16.666666666666668, 14.285714285714286.
This re-run: commits 12.0, 13.0, 13.0 (median **13.0**); `mean_batch`
16.666666666666668, 15.384615384615385, 15.384615384615385 (median
**15.384615384615385**). Wall aggregate submit calls this re-run: 25, 20, 23
(median **23**). Phase-2 wall aggregate submit calls were 23, 24, 20
(`m2-n200.md` lines 130–131).

## Judgment

The paused batch moved from **16.666666666666668** to **14.285714285714286**
and the paused commit count moved from **12.0** to **14.0**. Wall last
publish moved from **-3527.843577** to **-3514.365184** (13.478393 ms later
on the median; into-slot 471.156423 to 484.634816). Every accept line that
`m2-n200.md` published still holds:

- wall last publish ≤ +1,000 ms after the 3,999 ms deadline, and ≤ 4,999 ms
  into the slot
- wall aggregate-deadline misses **0**
- wall overhang **0.0** ≤ 500
- paused `mean_batch` **14.285714285714286** ≥ 8
- paused commits **14.0** ≤ 25

The gate was not loosened. No file from the RR3-05 change was edited for
this result.

## N=500

Not re-run. The informational record is
[`n500-informational.md`](./n500-informational.md). It is incomplete
(`budget_exceeded`, nextest exit 100, aggregate proofs truncated at a paused
median of 352/500). See that file. This re-run does not replace it.

## Formal flags

1. The harness `sha` is `1299a49035f00ba6fca59e97b09d865726dedb41`. The commit
   SHA differs.
2. Phase-2 numbers are cited from `m2-n200.md` / `m2-n200.json`. They were
   not recomputed.
3. Movement inside the accept lines is recorded above. It is not a reason to
   change the thresholds.
4. `VC_SCALE_SLOTS` is 1, same as the Phase-2 harness cell. The 32-slot
   aggregate accept remains `aggregations_are_dispatched_concurrently`.
5. Paused fetches stay **201.0** (1 memo + 200 aggregation fetches on the
   pre-Electra slot).
6. protoc here is apt 3.21.12. M0's CI protoc was 27.5.
7. Parent #492 stays open.

## Gate

The commands and pasted summaries are in
[`m3-scheduled-path.md`](./m3-scheduled-path.md). All of them exited 0,
including `cargo nextest run --workspace --locked` (5652 passed, 7 skipped)
and the must-not-regress filters from [`m2-n200.md`](./m2-n200.md) lines
306–317. The accept lines in the table above were not changed.
