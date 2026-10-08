# Informational N=500 (RR3-06)

Issue: [#535](https://github.com/rootwarp/rvc/issues/535). Parent: #492 (left open).

Protocol: [`README.md`](./README.md). Harness:
`crates/rvc/tests/vc_scale_profile.rs` (`vc_scale_profile_emits_a_complete_record`).
Machine-readable copy: [`n500-informational.json`](./n500-informational.json).

This record is informational. It is not an N=500 gate. PQ-1 keeps the gates at
N=200 ([`m2-n200.md`](./m2-n200.md)).

**The profile did not complete.** All six harness processes wrote a JSON record
and then failed `vc_scale_profile.rs:497` (`budget_exceeded` must not be true).
Nextest exit code 100. Aggregate proofs stopped below 500. The medians below
are the middle of the three measured values for that clock mode. They are not
a finished N=500 slot, and they are not extrapolated to one.

Latency cells that the runs actually finished (attestation publish, sync
messages) are marked complete. Count cells cut off by the budget are marked
incomplete.

## What was run

`git rev-parse HEAD` inside each harness process printed
`97e9e7ebfceae8ba8765f61d0edcf3a676c8c20d`. That is develop at the time of the
run. The working tree already had the uncommitted proposer-fixture edits in
`crates/rvc/tests/common/pipeline_fixture.rs` and
`crates/rvc/tests/fixture_proposer_reserve.rs`. The harness calls
`pipeline_fixture` with the defaults: no proposer duty,
`FixtureBlockProduction::Noop`, block-root byte `0xbb`. Those edits do not
change that path. This commit adds the fixture and these notes together, so
the commit SHA is not the harness `sha`.

Runs, all exit 100:

| Clock | Process window (UTC) | nextest summary |
|---|---|---|
| wall 1 | 2026-10-08T04:45:39Z – 04:48:31Z | 120.402 s |
| wall 2 | 2026-10-08T04:51:19Z – 04:53:20Z | 120.247 s |
| wall 3 | 2026-10-08T04:53:20Z – 04:55:20Z | 120.257 s |
| paused 1 | 2026-10-08T04:48:49Z – 04:50:50Z | 120.162 s |
| paused 2 | 2026-10-08T04:55:20Z – 04:57:21Z | 120.146 s |
| paused 3 | 2026-10-08T04:57:21Z – 04:59:22Z | 120.150 s |

Wall run 1's process window is 171.809 s because that invocation compiled the
test binary. Its nextest summary is still 120.402 s. An earlier invocation at
2026-10-08T04:45:25Z exited in 103 ms because `/usr/bin/time` was missing. It
wrote no JSON and is not a run. Later runs used the already-built debug binary.

README says a slot that hits the 120 s budget is recorded, not failed. This
harness still asserts `budget_exceeded` is not true after the write, so every
run is a test failure. The JSON on disk is the record. The per-slot budget was
not raised. The build stayed the debug nextest profile.

## Machine

| Field | Value |
|---|---|
| `git rev-parse HEAD` at process start | `97e9e7ebfceae8ba8765f61d0edcf3a676c8c20d` |
| Runtime | that SHA, debug test profile, default fixture path |
| Host | hostname `cursor`, Linux 6.12.94+ x86_64, Intel(R) Xeon(R) Processor (family 6, model 207, stepping 2), 4 cores, 1 thread per core, MemTotal 16,398,384 kB |
| `uname -a` | `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct  6 05:59:35 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux` |
| Disk | ext4 on `/dev/vdc` |
| Harness `host` field | `cursor linux/x86_64` |
| rustc | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| cargo | `cargo 1.99.0 (5f94df478 2026-08-27)` |
| nextest | `cargo-nextest 0.9.146 (8af696ddc 2026-09-21)` |
| protoc | `libprotoc 3.21.12` (apt `protobuf-compiler`) |
| Harness `toolchain` field | `rustc 1.99.0 (b940084d7 2026-09-28)` |

The workspace `rust-version` is 1.92. CI installs `dtolnay/rust-toolchain@stable`.
The image default `rustc 1.83.0` cannot parse locked `cpufeatures 0.3.0`
(`edition2024`). These runs used stable 1.99.0. M0 recorded CI's
`arduino/setup-protoc@v3` as `libprotoc 27.5`. This VM used the apt package.

## Scenario

`DutyOrchestrator::run`, N = 500, one slot (slot 32, first slot of epoch 1,
pre-Electra; Electra is epoch 50 in the fixture), one committee index `0`,
`with_request_delay(50 ms)`, `with_sync_committee(true)`,
`with_aggregators(true)`, 12 s slot, `DeadlineBps::default()` (attestation
deadline 3,999 ms, aggregate deadline 8,000 ms), per-slot budget 120,000 ms.
Default dispatch limits are concurrency 32 and publish concurrency 2.
`VC_SCALE_SLOTS` is 1. The mock clock is advanced 8 s before `run`.

No proposer duty. The block beacon is the default `Err`-returning path.
`crates/rvc/tests/common/fixture_bn.rs` was not added. The harness never
leaves the in-process `MockBeaconNodeClient`. The budget miss is aggregation
work against that mock's 50 ms delay in a debug build, not a missing HTTP
beacon.

## Headline medians

| Figure | Clock mode | Runs | Median | Finished? |
|---|---|---|---|---|
| Last attestation publish, ms after the 3,999 ms deadline | **wall** | -3100.241267, -3106.334698, -3092.080266 | **-3100.241267** | yes (500/500 publishes) |
| Same stamp, ms into the harness slot (3,999 + the cell) | **wall** | 898.758733, 892.665302, 906.919734 | **898.758733** | yes |
| `aggregate_deadline_misses` | **wall** | 0, 0, 0 | **0** | no — counts only submits that arrived |
| `aggregate_proofs_after_deadline` | **wall** | 0, 0, 0 | **0** | no — same truncation |
| `overhang_ms` (slot elapsed past 12 s) | **wall** | 108001.339083, 108001.370705, 108001.58033699999 | **108001.370705** | no — shutdown at the 120 s budget |
| `commits_per_attestation_phase` | **paused** | 31.0, 34.0, 29.0 | **31.0** | no — samples before shutdown |
| `mean_batch` | **paused** | 16.129032258064516, 14.705882352941176, 17.24137931034483 | **16.129032258064516** | no |
| `attestation_data_requests_per_slot` | **paused** | 353.0, 353.0, 353.0 | **353.0** | no |
| `sync_publish_ms_after_slot_start` | **paused** | 153.0, 153.0, 153.0 | **153.0** | yes (first stamp; 500/500 messages) |
| `sync_messages_submitted` | **paused** | 500, 500, 500 | **500** | yes |
| `sync_submit_calls` | **paused** | 16, 16, 16 | **16** | yes |
| `aggregate_proofs_submitted` | **paused** | 352, 352, 352 | **352** | no (500 required to finish) |
| `aggregate_submit_calls` | **paused** | 11, 11, 11 | **11** | no |

All six harness runs: `successes` 500, `failures` 0, `budget_exceeded` true,
`overrun` true, `n` 500, `slots` 1, `sync_committee_enabled` true,
`aggregators_enabled` true. `successes` 500 means the attestation items were
submitted. It does not mean the aggregate phase finished.

Paused copies of the wall latency key are -3336.0, -3387.0, -3336.0 (median
-3336.0). Those are virtual time. The protocol keeps latency from the wall
runs. Wall copies of the sync-publish offset are 182.722284, 181.764071,
181.746606 (median 181.764071) and are not the protocol cell.

Paused `overhang_ms` is 1517662.0, 1520344.0, 1531166.0 (median 1520344.0).
That is virtual time. `tokio::time::pause` auto-advances `Instant` across the
50 ms mock delays while the wall budget (`std::time::Instant`, 120 s) is what
shuts the slot down. The paused nextest summaries stay about 120.15 s. The
protocol overhang cell is the wall median.

## What the truncation shows

Attestations and sync finished. Aggregation did not.

Wall median last attestation stamp is 898.758733 ms into the harness slot,
3,100.241267 ms before the 3,999 ms deadline. Sync submitted 500 messages in
16 calls on every run, wall and paused. Sixteen waves is `ceil(500/32)` at
the default sign concurrency.

Aggregate proofs at shutdown: wall 230, 226, 226 (median 226); paused 352,
352, 352 (median 352). The paused clock skips the phase waits, so more of the
120 s wall budget is spent on the 50 ms mock delay and more proofs land.
Neither clock mode reached 500. The harness then failed the budget assert.

`aggregate_deadline_misses` 0 only counts `SubmitAggregateAndProofs` arrivals.
Proofs that were never submitted are not misses and are not on-time proofs.

Paused `attestation_data_requests_per_slot` 353.0 lines up with 352 aggregate
proofs plus one shared attestation-data fetch. Wall median 227.0 lines up
with 226 proofs plus that fetch. A finished pre-Electra slot with one
committee would also fetch once per aggregator. That finished count was not
measured.

Paused `commits_per_attestation_phase` 31.0 and `mean_batch`
16.129032258064516 are `rvc_slashing_group_commit_batch_size` samples that
landed before shutdown (`sample_count`, and `sample_sum / sample_count`).
They are not the commit count of a finished 500-validator phase.

## `fixture_bn.rs`

Not added. The N=500 harness does not speak HTTP. A wiremock beacon would not
be on this path, and no gated acceptance depends on one.

## Formal flags

1. No completed N=500 profile. Median-of-3 figures above are measured
   budget-truncated runs. Do not read `aggregate_proofs_submitted` 352 or
   `overhang_ms` 108001.370705 as a finished slot.
2. The harness `sha` is `97e9e7ebfceae8ba8765f61d0edcf3a676c8c20d`. The commit
   that adds these files also adds the proposer fixture, so the commit SHA
   differs. The scale path is the default Noop fixture.
3. `aggregate_deadline_misses` 0 is not evidence that 500 proofs met the
   8,000 ms deadline.
4. Paused overhang is virtual time. Wall overhang is the protocol cell, and
   it is the budget shutdown (~108 s past 12 s), not a natural slot end.
5. Attestation last-publish and sync message counts did finish. They are
   reported because those counters reached N. The ignored test still failed.
6. Debug profile, 4 cores, 50 ms mock delay, publish concurrency 2. The
   budget was not raised and the run was not switched to `--release`.
7. protoc here is apt 3.21.12. M0's CI protoc was 27.5.
8. Parent #492 stays open. This note does not add an N=500 gate.
