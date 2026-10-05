# RED recording at N=200 (RR0-08)

Protocol: [`README.md`](./README.md) (RR0-07). Harness:
`crates/rvc/tests/vc_scale_profile.rs` (`vc_scale_profile_emits_a_complete_record`).
Machine-readable copy: [`red-n200.json`](./red-n200.json).

The RED pin is the Phase-0 `develop` tip
`2a087157293690d277df9c59dd4d35210697577b`, plus the harness change in this
commit. Production runtime is identical to that tip. Three independent runs
per clock mode. The headline cell is the median. Every figure below names
its clock mode.

## What was run

`git rev-parse HEAD` inside each harness process printed
`91fb086fce04f9c90e1368e276b39e06d20cf49d`. That SHA is the previous
docs-only tip. It does not contain the sync and aggregate driver. The
harness copies that string into the `sha` field of every raw run.

The bytes that actually ran are the working-tree
`crates/rvc/tests/vc_scale_profile.rs` at measurement time, sha256
`e0383bd0cd90a74641a3f7a7f46bae218c533202b41e062697bf1764d6ef5802`.
`git diff 2a087157293690d277df9c59dd4d35210697577b -- crates/` is that file
only. This commit contains those harness bytes. No production source
differs from `2a087157`.

Runs: wall 2026-10-05T09:45:56Z through 09:47:05Z, paused through
2026-10-05T09:47:11Z. All six exited 0.

## Machine

| Field | Value |
|---|---|
| Phase-0 tip / runtime | `2a087157293690d277df9c59dd4d35210697577b` |
| `git rev-parse` at process start | `91fb086fce04f9c90e1368e276b39e06d20cf49d` (docs-only parent of this re-record; not the driver) |
| Harness source sha256 | `e0383bd0cd90a74641a3f7a7f46bae218c533202b41e062697bf1764d6ef5802` |
| Host | hostname `cursor`, Linux x86_64, Intel(R) Xeon(R) Processor (family 6, model 207, stepping 2), 4 cores, 1 thread per core |
| Harness `host` field | `cursor linux/x86_64` |
| rustc | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| cargo | `cargo 1.99.0 (5f94df478 2026-08-27)` |
| Harness `toolchain` field | `rustc 1.99.0 (b940084d7 2026-09-28)` |

The workspace `rust-version` is 1.92. CI installs `dtolnay/rust-toolchain@stable`.
The image default `rustc 1.83.0` cannot parse locked `cpufeatures 0.3.0`
(`edition2024`). These runs used stable 1.99.0.

## Scenario

`DutyOrchestrator::run`, N = 200, one slot (first slot of an epoch),
`with_request_delay(50 ms)`, `with_sync_committee(true)`,
`with_aggregators(true)`, 12 s slot, `DeadlineBps::default()` (attestation
deadline 3,999 ms, aggregate deadline 8,000 ms), per-slot budget 120,000 ms.

Attester and sync duties are prefetched. The mock clock is advanced 8 s
before `run`, which is what makes the attestation and aggregate phase waits
zero. Submit offsets are still `tokio::time::Instant` from the harness slot
start. `run` is shut down once the mock client has 200 attestation submits,
200 sync messages, and 200 aggregate proofs. `VC_SCALE_SLOTS` must be 1
because that shutdown is sticky.

## Headline medians

| Figure | Clock mode | Runs | Median |
|---|---|---|---|
| Last attestation publish, ms after the 3,999 ms deadline | **wall** | 17910.153543, 17739.82913, 17666.936998999998 | **17739.82913** |
| `aggregate_deadline_misses` | **wall** | 1, 1, 1 | **1** |
| `aggregate_proofs_after_deadline` | **wall** | 200, 200, 200 | **200** |
| `overhang_ms` (slot elapsed past 12 s) | **wall** | 10080.386788, 9959.462757000001, 9939.599388000002 | **9959.462757000001** |
| `commits_per_attestation_phase` | **paused** | 200.0, 200.0, 200.0 | **200.0** |
| `mean_batch` | **paused** | 1.0, 1.0, 1.0 | **1.0** |
| `attestation_data_requests_per_slot` | **paused** | 400.0, 400.0, 400.0 | **400.0** |
| `sync_publish_ms_after_slot_start` | **paused** | 20553.0, 20553.0, 20553.0 | **20553.0** |
| `sync_messages_submitted` | **paused** | 200, 200, 200 | **200** |
| `sync_submit_calls` | **paused** | 1, 1, 1 | **1** |
| `aggregate_proofs_submitted` | **paused** | 200, 200, 200 | **200** |
| `aggregate_submit_calls` | **paused** | 1, 1, 1 | **1** |

All six harness runs: `successes` 200, `failures` 0, `budget_exceeded` false,
`overrun` true, `n` 200, `slots` 1, `sync_committee_enabled` true,
`aggregators_enabled` true. Paused copies of the wall latency keys are in
the JSON (`last_publish` 16503.0 on every paused run, `overhang_ms` 9624.0).
Those paused numbers are virtual time. The protocol keeps latency from the
wall runs. Wall copies of the sync-publish offset are also real
(21784.416196, 21856.693969, 22028.691573; median 21856.693969) and are not
the protocol cell.

Process elapsed around `cargo nextest` (startup included, not a protocol
figure): wall 23 s, 23 s, 23 s; paused 2 s, 2 s, 2 s.

## The ~20 s/slot overrun is the recorded RED output

The attestation-chain model is one sequential validator after another:

`200 × (50 ms fetch + 50 ms publish + ~6 ms commit) = 200 × 106 ms = 21,200 ms`.

That is about 21.2 s of attestation work inside a 12 s slot, so the slot is
expected to finish late and to be stored as overrun, not as a test failure.
`run` also joins the aggregation phase with that work and publishes the sync
batch after the attestations, so the measured slot is not required to equal
21,200 ms.

What the wall-clock runs actually stored:

- Median `overhang_ms` is 9959.462757000001. Slot elapsed is
  `12,000 + overhang`, so the median slot took **21959.462757 ms** (about
  21.96 s). All three wall runs set `overrun: true` and
  `budget_exceeded: false`. The 120 s budget was not hit.
- Median last `SubmitAttestation` stamp is **17739.82913 ms after** the
  3,999 ms attestation deadline. Adding the deadline places that stamp at
  21738.82913 ms after the harness slot start.
- The measured ~21.96 s is the same kind of overrun as the 21.2 s product
  above. The gap between 21,200 ms and 21,959.46 ms is left as measured. It
  is not adjusted toward 20 s or toward 21.2 s. Aggregation overlaps the
  attestation chain through `tokio::join`, and the sync batch is submitted
  after the attestations, which is why the slot is longer than the
  attestation-only product.

Paused-clock counts, from `rvc_slashing_group_commit_batch_size` and the
mock-BN stamps:

- `attestation_data_requests_per_slot` is 400. The attestation phase and the
  aggregation phase each call `GetAttestationData` once per validator.
- `commits_per_attestation_phase` is 200 and `mean_batch` is 1.0.
  Attestation duties are still a sequential `for` loop
  (`crates/rvc/src/orchestrator/attestation.rs`). Each reserve is drained
  before the next validator enqueues. Aggregation does not fill the
  group-commit queue, so every histogram sample is 1. This is the measured
  value.

## Aggregate and sync figures are from real submits

Both duties ran. A miss count of 1 is one late batch, not an empty phase.

- `with_sync_committee(true)` and `with_aggregators(true)` are on. Aggregators
  use committee length 1, so every validator is selected. The fixture fork
  schedule puts Electra at epoch 50; slot 32 is pre-Electra, so the proofs
  are `VersionedSignedAggregateAndProof::PreElectra` and leave in one call.
- Paused: `sync_messages_submitted` 200, `sync_submit_calls` 1,
  `aggregate_proofs_submitted` 200, `aggregate_submit_calls` 1. Wall runs
  stored the same counts. Submit call counts are greater than 0.
- `aggregate_deadline_misses` is 1 on every wall and paused run.
  `aggregate_proofs_after_deadline` is 200. The single
  `SubmitAggregateAndProofs` stamp landed after the 8,000 ms deadline and
  carried all 200 proofs. The protocol cell is the wall median, 1, with 200
  proofs inside that late call.
- `sync_publish_ms_after_slot_start` is the first
  `SubmitSyncCommitteeMessages` stamp versus the harness slot start. The
  protocol cell is the paused median, **20553.0** ms. That is one batched
  submit of 200 messages.

Nothing in this table is a vacuous 0. `mean_batch` 1.0 is a real histogram
reading, explained above, not a missing phase.

## `rvc_slot_phase_*` is still not the measurement

`rvc_slot_phase_block_start_offset_ms` is sampled in
`record_phase_block_start_offset` from `MockSlotClock::current_time_secs`
minus `slot_start_time`. This driver calls `set_slot` and then
`advance_time(8)` before `run`, so a sample taken from that clock is
**8000 ms of mock time**. That is the 8 s advance, not the ~21.96 s wall
slot and not the ~17.7 s late attestation publish.

This recording did not scrape the histogram. There is no measured
`rvc_slot_phase_*` sample to report. Reading 8000 ms, or the old ~0 that
`set_slot` alone produces, and calling the slot on time would still treat
the mock clock as the overrun. Timing in this file is the mock-BN stamp
versus the harness slot start.

## Baseline identity

`b5543a971266985dcab2d2c60e4cd48e0be1fecc` through the Phase-0 tip is not a
runtime-identical range, and that is accepted as the baseline. The
pre-existing TRC body edits already on `develop` — TRC-5e, TRC-6b, TRC-6d,
TRC-6e, TRC-7d, plus the RR0-01 `test-utils` / `futures` wiring — are part
of that baseline. They are not a Phase-0 regression introduced by this
recording.

On the attestation path this harness drives, the only RR0 production body
edit is RR0-07's `drain_batch` observe (`crates/slashing/src/group_commit.rs`).
The RED pin is the Phase-0 `develop` tip above, with this harness change on
top and no other production diff.
