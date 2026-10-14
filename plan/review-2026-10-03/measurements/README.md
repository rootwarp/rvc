# Review measurements (2026-10-03)

Protocol for every measurement taken with the RR0-07 harness
(`crates/rvc/tests/vc_scale_profile.rs`). **Every later run under this
directory references this file.** Do not publish a number that skips it.

The harness is `#[ignore]`d. No CI job runs it. `cargo nextest run --workspace`
does not execute it.

## What each clock mode is for

Run **RED and GREEN in the same clock mode**. A wall-clock RED is not
comparable to a paused-clock GREEN, and the reverse is not comparable either.

| Figure | Clock mode |
|---|---|
| Last publish after the attestation deadline (`last_publish_ms_after_att_deadline`) | **wall** |
| Aggregate deadline misses (`aggregate_deadline_misses`) | **wall** |
| Overhang (`overhang_ms`, and `overrun` when the slot ran past 12 s) | **wall** |
| Attestation-data fetch count (`attestation_data_requests_per_slot`) | **paused** |
| Mean group-commit batch (`mean_batch`) and commits per attestation phase (`commits_per_attestation_phase`) | **paused** |
| Sync-publish offset (`sync_publish_ms_after_slot_start`, first `SubmitSyncCommitteeMessages` stamp versus the harness slot start) | **paused** |
| Sync messages submitted and aggregate proofs submitted | **paused** |

Latency figures come from a wall-clock run. Counts and ordering come from a
paused-clock run. Both modes write the same JSON keys; keep the cell that
this table names.

Timing is mock-BN call arrival versus the harness slot start
(`MockBeaconNodeClient` stamps, `tokio::time::Instant`). Do not read
`rvc_slot_phase_*`. That histogram is `MockSlotClock` time. This harness
advances that clock 8 s before `run`, so a sample is 8000 ms of mock time,
not the wall overrun.

## Scenario

| Knob | Value |
|---|---|
| Driver | `DutyOrchestrator::run` after prefetch of attester and sync duties, with `with_sync_committee(true)` and `with_aggregators(true)`. `VC_SCALE_SLOTS` must be 1 |
| Validators | `VC_SCALE_N` / `--validators` (record default N = 4; scale runs use their own N) |
| Slots | `VC_SCALE_SLOTS` / `--slots` (default 1). Each slot is the first slot of a new epoch so slashing protection accepts the vote |
| Mock BN delay | `with_request_delay(50 ms)` on every role-trait call, including attestation publish |
| Slot length | 12 s |
| Deadlines | `DeadlineBps::default()` — attestation 3999 ms, aggregate 8000 ms |
| Per-slot budget | **120_000 ms**. A slot of about 20 s (N = 200 at this delay) finishes inside the budget. Time past 12 s is `overhang_ms` and `overrun: true`. It is not a test failure. A slot that hits the 120 s budget sets `budget_exceeded` and is still recorded, not failed |

`aggregate_deadline_misses` counts `SubmitAggregateAndProofs` arrivals whose
offset from the harness slot start is greater than 8000 ms. The harness enables
`with_sync_committee(true)` and `with_aggregators(true)` and drives
`DutyOrchestrator::run`, so a 0 is "no late aggregate submit", not "nothing
aggregated". `aggregate_proofs_submitted` and `sync_messages_submitted` are the
proof and message counts inside those submits. `last_publish_ms_after_att_deadline`
is the worst slot's last `SubmitAttestation` arrival minus 3999 ms (negative
means the publish landed before the attestation deadline).

`commits_per_attestation_phase` and `mean_batch` are read from
`rvc_slashing_group_commit_batch_size` (`sample_count` / slots, and
`sample_sum / sample_count`). They are not inferred from validator count.

`sync_publish_ms_after_slot_start` is the milliseconds from the harness slot
start to the first `SubmitSyncCommitteeMessages` stamp. The protocol cell is
the **paused** run. The mock clock is advanced 8 s before `run` so the
attestation and aggregate phase waits are zero; submit offsets are still
`tokio::time::Instant` from that slot start.

## How many runs

Take the **median of 3** independent runs for each cell you keep. Record all
three values and the median. Do not keep a single run.

## Every file names the machine

Every JSON file this harness writes, and every later note in this directory,
carries:

| Field | Source |
|---|---|
| `sha` | `git rev-parse HEAD` of the tree that produced the number |
| `host` | hostname, OS, and architecture |
| `toolchain` | `rustc --version` |
| `clock_mode` | `wall` or `paused` |

## How to run

From the repository root. nextest 0.9 does not forward a `--output` argument.
Set `VC_SCALE_OUTPUT` for nextest. libtest accepts `--output` after `--`.

Wall clock (latency figures):

```bash
VC_SCALE_OUTPUT=/tmp/vc-scale-wall.json VC_SCALE_CLOCK=wall \
  cargo nextest run -p rvc --run-ignored ignored-only --no-capture \
  -E 'test(vc_scale_profile_emits_a_complete_record)'
```

Paused clock (counts and ordering):

```bash
VC_SCALE_OUTPUT=/tmp/vc-scale-paused.json VC_SCALE_CLOCK=paused \
  cargo nextest run -p rvc --run-ignored ignored-only --no-capture \
  -E 'test(vc_scale_profile_emits_a_complete_record)'
```

Same invocation through libtest, which does forward `--output`:

```bash
cargo test -p rvc --test vc_scale_profile -- --ignored --nocapture \
  --exact vc_scale_profile_emits_a_complete_record \
  -- --output /tmp/vc-scale-wall.json --clock wall
```

N = 200, one slot, paused clock:

```bash
VC_SCALE_N=200 VC_SCALE_SLOTS=1 VC_SCALE_CLOCK=paused \
  VC_SCALE_OUTPUT=/tmp/vc-scale-n200-paused.json \
  cargo nextest run -p rvc --run-ignored ignored-only --no-capture \
  -E 'test(vc_scale_profile_emits_a_complete_record)'
```

`--validators` and `--slots` are the libtest spellings of `VC_SCALE_N` and
`VC_SCALE_SLOTS`. CLI flags win over the environment variables.

Do not commit the JSON unless a later issue asks for a checked-in baseline.
Copy `sha`, `host`, `toolchain`, and `clock_mode` into that note and point it
back here.
