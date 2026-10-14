# P1 baseline — signing latency and slot processing (issue 1.1 / #207)

Issue **#207** / plan **1.1** recording of signing latency on the **untouched**
tree so the Glamsterdam NFR ("no regression in per-slot signing latency or the
attestation deadline path") is judgeable in Phase 6 issue **6.14**.

**Day 1 of the programme (D32).** This file lands before any Phase 1, 2 or 3
code change. The SHA below is `git rev-parse HEAD` of the worktree at recording
time: develop after **#205** group-commit, which is **not** Phase 1/2/3.

> **This is a baseline, not an acceptance run.** 6.14 is judged against this
> file: the **three-run median** p99 within **+10 %** of the series below, same
> fixture — not a single run. The numbers are the post-#205, pre-Gloas world.

This file does **not** change production source. The ARCH-5a instrument
(`crates/signer-server/tests/load_profile.rs`) is **not** modified and stays
`#[ignore]`.

Modelled field-for-field on
[`../../architecture-2026-08-12/measurements/m3-baseline-0ae9a09.md`](../../architecture-2026-08-12/measurements/m3-baseline-0ae9a09.md).
Related (same A-9 profile, different purpose):
[`../../architecture-2026-08-12/measurements/m3-post-group-commit.md`](../../architecture-2026-08-12/measurements/m3-post-group-commit.md).

---

## Harness

| Field | Value |
|---|---|
| **Measured commit** | `8e908a56c6f1d5de1e92afbcb7222e47551019f5` (`feat(slashing): group-commit reserve transactions behind one fsync`) |
| **D32** | This SHA is on `develop` with **zero** Phase 1/2/3 commits. It must remain an ancestor of every later Phase 1/2/3 commit. A post-1.2 or post-2.1 run is **not** a baseline. |
| **Production path in force** | `SlashableSignSession::reserve_then_sign` via group-commit `reserve_*` (`batch_size=50`, `wait_to_fill=1ms`) |
| **Sign-path source** | `crates/signer-server/tests/load_profile.rs` (`test_load_profile_reports_p99_above_serialized_floor`, `#[ignore]`) |
| **Sign-path fixture** | `helpers::make_load_fixture` — 200 EIP-2333 keys, `SlowSigner` (async 200 ms sleep), real `SlashingDb::open` temp file |
| **Sign-path** | `SignerServiceImpl::sign_attestation_data` → `SigningGate::sign_attestation` (`TimeoutPolicy::DiscardStagedRow`). **Not** the VC orchestrator (X8). |
| **Slot-processing source** | `RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS` (`crates/rvc/src/metrics.rs:55`), observed through `DutyOrchestrator::process_slot` |
| **Slot-processing fixture** | `crates/rvc/tests/common/pipeline_fixture.rs` — 1 local key, mock BN, **in-memory** `SlashingDb::open_in_memory`, 200 unique-epoch slots |
| **Instrument** | process-local exact `sample_sum` / `sample_count` deltas (not bucket quantile) |
| **Sign timeout** | `Duration::from_secs(4)` at the gate (`DEFAULT_SIGN_TIMEOUT`). No run hit it (200/200 successes). |

### Exact invocation (sign path, full A-9 profile)

JSON on stdout, and to `--output` (libtest; nextest 0.9 does not forward that arg):

```bash
cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
  --exact test_load_profile_reports_p99_above_serialized_floor \
  -- --output /tmp/p1-baseline/runN.json
```

nextest (summary on stdout only):

```bash
cargo nextest run -p rvc-signer-server --run-ignored ignored-only --no-capture \
  -E 'test(test_load_profile_reports_p99_above_serialized_floor)'
```

This recording used the `cargo test` form. The binary was compiled once
(`cargo test -p rvc-signer-server --test load_profile --no-run`), then three
independent process invocations wrote `/tmp/p1-baseline/run{1,2,3}.json` (not
checked in). Full 200×200 ms × 3 completed in this environment (~0.3 s wall
each after compile); no reduced calibration was required.

### Exact invocation (slot processing)

**The signer-server load harness does not populate this family.** It never
enters `crates/rvc` (X8). Sample count on
`RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS` after a load-profile run
is **0**.

Captured with a **one-off** driver over
`crates/rvc/tests/common/pipeline_fixture.rs` (plan Testing Notes). The driver
was **not** checked in — issue 1.1's diff is `plan/`-only; no new tests.

Reproduction for 6.14 (same method, recreate the driver):

`PipelineFixtureOpts::default()` only lists `SLOT_A`/`SLOT_B` (100/101) with
an **empty** `attestation_data_by_slot`. Driving any other slot against that
default records an empty-duty `process_slot` (timer still fires; the sample
is not a signed attestation). Populate **both** maps:

1. For `i` in `0..200`:
   `slot = (i + 1) * 32` (`SLOTS_PER_EPOCH`), `source_epoch = i`,
   insert `make_beacon_attestation_data(slot, source_epoch, 0x22, 0x33, 0x11)`
   into `attestation_data_by_slot`, and push `slot` onto `duty_slots`
   (strictly increasing source/target so slashing accepts the chain).
2. `pipeline_fixture(PipelineFixtureOpts { attestation_data_by_slot, duty_slots,
   initial_slot: 32, ..Default::default() })` — keeps `preload_signing_key =
   true` and in-memory `SlashingDb`.
3. For each of those 200 slots: `let results = fixture.process_slot(slot).await`.
   Assert `results` is **Ok**, `results.len() == 1`, and `results[0].success`
   (one successful attestation). A `Vec` of length 0 is an empty-duty sample;
   discard the run.
4. After **every** call, drain
   `RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS.with_label_values(&[])`
   via `get_sample_count` / `get_sample_sum` (exact per-sample deltas — same
   method as `load_profile.rs`). Do **not** use `histogram_quantile`: the first
   bucket is **0.01 s** and every sample here sat below it.
5. Nearest-rank p50/p95/p99/max on the 200 samples. Three independent process
   invocations; record all three plus the **median**. The NFR compares that
   median, not any single run.

Outputs at `/tmp/p1-baseline/slot-run{1,2,3}.json` (not checked in).

### Hardware / toolchain

| Field | Value |
|---|---|
| Host | Apple M4 Pro, arm64, 14 cores, 24 GB RAM |
| OS | macOS 26.6.2 (Darwin 25.6.0 / Build 25G83) |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| cargo | 1.97.1 (c980f4866 2026-06-30) |
| nextest | 0.9.85 (available; not used for the JSON runs) |
| Profile | `test` (unoptimized + debuginfo) |
| Measured (sign path) | 2026-09-05T17:23:59Z – 2026-09-05T17:24:02Z (UTC) |
| Measured (slot processing) | 2026-09-05T17:25:06Z – 2026-09-05T17:25:09Z (UTC) |

Same host family / rustc / cargo / `test` profile as
[`m3-post-group-commit.md`](../../architecture-2026-08-12/measurements/m3-post-group-commit.md).

### Injected latency profile (sign path)

| Parameter | Value |
|---|---|
| Keys | **200** (A-9), distinct pubkeys, one attestation each |
| Injected BLS latency | **200 ms** `tokio::time::sleep` on `helpers::SlowSigner` (async side, so `Handle::block_on(timeout(...))` observes it) |
| Arrival | 200 concurrent `JoinSet` tasks, `tokio` multi-thread 8 workers |
| DB | on-disk temp file, production `SlashingDb::open` |
| Pragmas in force | `journal_mode=WAL`, `synchronous=EXTRA`, `fullfsync=ON` (macOS) |
| Policy | `SigningGate` `Fixed(DiscardStagedRow)` |
| Group commit | default **50** / **1 ms** |

### Slot-processing profile

| Parameter | Value |
|---|---|
| Keys | **1** (pipeline_fixture default) |
| Injected BLS latency | **none** (real `LocalSigner`) |
| Arrival | 200 sequential `process_slot` calls, one slot per epoch |
| BN | mock (`PipelineBeacon`) |
| DB | in-memory `SlashingDb::open_in_memory` (pipeline_fixture default — **not** EXTRA/fullfsync) |
| Clock | `MockSlotClock`, advanced to the duty slot before each call |

This is a **different regime** from the A-9 sign path. Do not compare 3 ms
1-key in-memory slot processing to 230 ms 200-key injected `signer-server`
wall. 6.14 must re-run **each** fixture against its own column.

### Metric windows in force

Not changed by this issue (1.1 records; it does not redefine).

1. **Kept series** `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}`:
   reserve-entry (includes queue wait) → sign-return. Still contains the 200 ms
   injected sign (VD-5.2).
2. **Reserve-only series** `rvc_slashing_reserve_tx_hold_duration_ms{kind="attestation"}`:
   reserve-entry → COMMIT. Quantity group commit shortened.
3. **Slot processing** `rvc_orchestrator_slot_processing_duration_seconds`
   (no labels): `start_timer()` at `DutyOrchestrator::process_slot` entry
   (`crates/rvc/src/orchestrator/attestation.rs:127`), observed on drop.
   Native unit **seconds**. Histogram buckets in `metrics.rs:61` start at
   0.01 s; values below that still add to `sample_sum`.

Do **not** reconstruct any series here from a Prometheus `histogram_quantile`
scrape.

---

## Results — three runs + median (sign path)

All three runs: **200 / 200 successes**, **0 failures**,
`achieved_concurrency = 200`, `tx_hold_count = 200`,
`reserve_tx_hold_count = 200`.

`effective_concurrency = keys × injected_ms / total_wall_ms`.

### Client wall (`sign_attestation_data` call)

| Run | Start (UTC) | total_wall_ms | p50 | p95 | p99 | max | effective_conc. |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | 17:23:59Z | 235.280 | 219.577 | 230.034 | 230.477 | 233.867 | 170.011 |
| 2 | 17:24:01Z | 228.352 | 218.964 | 224.503 | 225.491 | 227.092 | 175.169 |
| 3 | 17:24:01Z | 234.636 | 219.890 | 225.845 | 230.074 | 233.341 | 170.477 |
| **median** | | **234.636** | **219.577** | **225.845** | **230.074** | **233.341** | **170.477** |

### `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}` (kept window)

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 218.903 | 230.258 | 230.258 | 230.258 | 43628.626 | 218.143 |
| 2 | 218.139 | 223.502 | 224.617 | 224.617 | 43719.492 | 218.597 |
| 3 | 219.319 | 225.073 | 230.833 | 230.833 | 43690.440 | 218.452 |
| **median** | **218.903** | **225.073** | **230.258** | **230.258** | **43690.440** | **218.452** |

This window still contains the 200 ms injected sign, so it **cannot** sit under
the A-9 per-sign budget of 19.995 ms (VD-5.2). That is expected. 6.14 compares
against **this column**, not against 19.995 ms.

### `rvc_slashing_reserve_tx_hold_duration_ms{kind="attestation"}` (reserve-only)

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 16.885 | 29.020 | 29.020 | 29.020 | 3080.675 | 15.403 |
| 2 | 15.619 | 21.088 | 21.088 | 21.088 | 2687.836 | 13.439 |
| 3 | 16.482 | 21.580 | 28.513 | 28.513 | 2900.726 | 14.504 |
| **median** | **16.482** | **21.580** | **28.513** | **28.513** | **2900.726** | **14.504** |

### Achieved concurrency

| Quantity | Value | How measured |
|---|---|---|
| **achieved_concurrency** | **200** (all three runs) | peak overlapping `SlowSigner::sign` calls |
| **effective_concurrency** | **170.477** (median) | `200 × 200 / total_wall_ms` |
| Implied per-sign serial cost | **1.173 ms** | median `total_wall_ms / 200` |
| Injected / remainder | 200 ms sign, overlapped; remainder is four group-commit fsyncs | |

Signs overlap fully (200 in flight). Same shape as
[`m3-post-group-commit.md`](../../architecture-2026-08-12/measurements/m3-post-group-commit.md).

### Reproducibility (sign path)

Kept-window p99 range 224.617–230.833 ms →
**(max − min) / min = 2.77 %**. Client-wall p99 range 225.491–230.477 ms →
**2.21 %**. Both well under the ARCH-5b 20 % reopen threshold and inside the
±5 % band for this host / `test` profile.

Reserve-tx p99 range 21.088–29.020 ms →
**(max − min) / min = 37.6 %** (absolute range **7.932 ms**). That relative
figure exceeds 20 %. It is **fsync/fullfsync jitter** on a ~15–29 ms
group-commit series, not a harness defect: `achieved_concurrency` is 200 on
every run, successes are 200/200, and the kept-window / wall series (which
contain the 200 ms inject) stay inside 3 %. ARCH-5a's 20 % rule was written
for the ~41 s serialized-hold series; at this scale a few milliseconds of
`EXTRA` + `fullfsync` noise is expected
([`m3-post-group-commit.md`](../../architecture-2026-08-12/measurements/m3-post-group-commit.md)
already recorded 12.0 % on the same family). **ARCH-5a is not reopened.**
Tolerance for a re-run on this host / `test` profile: **±5 %** on kept-window
p99 and total wall; reserve-tx p99 **±10 ms** (absolute), not 20 % relative.

---

## Results — three runs + median (slot processing)

All three runs: **200 / 200 successful `process_slot` calls**, **0 failures**,
histogram **count = 200**.

Native unit is **seconds**. Milliseconds shown for comparison with the sign
path; 6.14 may use either column as long as the unit is named.

### `rvc_orchestrator_slot_processing_duration_seconds` (seconds)

| Run | Start (UTC) | p50 | p95 | p99 | max | sum | count |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | 17:25:06Z | 0.002556375 | 0.003283333 | 0.003814333 | 0.003999667 | 0.509958621 | 200 |
| 2 | 17:25:07Z | 0.002103708 | 0.002952708 | 0.003356833 | 0.003817333 | 0.449421429 | 200 |
| 3 | 17:25:08Z | 0.002118958 | 0.003079541 | 0.003431750 | 0.003639375 | 0.456871208 | 200 |
| **median** | | **0.002118958** | **0.003079541** | **0.003431750** | **0.003817333** | **0.456871208** | **200** |

### Same series, milliseconds

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 2.556 | 3.283 | 3.814 | 4.000 | 509.959 | 2.550 |
| 2 | 2.104 | 2.953 | 3.357 | 3.817 | 449.421 | 2.247 |
| 3 | 2.119 | 3.080 | 3.432 | 3.639 | 456.871 | 2.284 |
| **median** | **2.119** | **3.080** | **3.432** | **3.817** | **456.871** | **2.284** |

### Reproducibility (slot processing)

p99 range 3.357–3.814 ms → **(max − min) / min = 13.6 %**, under 20 %.
Tolerance for a re-run on this host / `test` profile / in-memory fixture:
**±20 %** on p99 (sub-millisecond work; scheduling noise dominates). A p99
spread **> 50 %** or a sample count ≠ 200 is a driver defect, not a number to
average away.

---

## Per-sign budget (A-9), arithmetic shown — context, not this issue's yardstick

M3 / X6 is a prior architecture milestone. Constants are unchanged on this
tree: `SECONDS_PER_SLOT` still exists; `SLOT_DURATION_MS` is **added by
issue 1.2** and **does not exist on this SHA**.

| Symbol | Value | Source |
|---|---|---|
| `SECONDS_PER_SLOT` | 12 | `crates/eth-types/src/lib.rs` |
| `slot_duration_ms` | `12 × 1000 = 12_000` | |
| `ATTESTATION_DUE_BPS` | 3333 | `crates/timing/src/lib.rs` |
| `BASIS_POINTS` | 10_000 | same |
| `attestation_window_ms` | `due_ms(3333, 12_000) = 3333 × 12_000 / 10_000 = **3999**` | VD-S7 |
| `N` (A-9) | **200** keys | `prd.md` A-9 |
| `DEFAULT_SIGN_TIMEOUT` | **4000 ms** | `crates/signer/src/core.rs` |

```text
per_sign_budget_ms = attestation_window_ms / N
                   = 3999 / 200
                   = 19.995 ms
```

| Check | Yardstick | Median measured | Met? |
|---|---:|---:|---|
| Kept-window p99 vs per-sign budget | **19.995 ms** | **230.258 ms** | **no** (contains the 200 ms sign) |
| Reserve-tx p99 vs per-sign budget | **19.995 ms** | **28.513 ms** | **no** (~1.43×) |
| Slot-processing p99 vs per-sign budget | **19.995 ms** | **3.432 ms** | **yes** — **not comparable** (1 key, no inject, in-memory DB) |
| No single kept-window hold vs sign timeout | **4000 ms** | max **230.833 ms** | **yes** |
| 200 keys completable in one 3999 ms window | **3999 ms** total wall | **234.636 ms** | **yes** — **not X6** |

**X6 remains unmet** (same finding as #205). This file does not re-judge it.

### Phase 6 / 6.14 yardstick (this file's purpose)

6.14: the **three-run median** p99 **within +10 %** of the P1 1.1 baseline on
the **same fixture**. Compare median to median. A single process invocation
is **not** the gate — baseline slot-processing run 1 already has p99
**3.814 ms**, which is above the +10 % ceiling **3.775 ms** derived from the
median **3.432 ms**. Using that one run as the candidate would false-fail.

Derived ceilings from the **medians** above:

| Series | Baseline median p99 | +10 % ceiling (vs median) |
|---|---:|---:|
| Client wall (`sign_attestation_data`) | **230.074 ms** | **253.081 ms** |
| `rvc_signer_slashing_tx_hold_duration_ms` | **230.258 ms** | **253.284 ms** |
| `rvc_slashing_reserve_tx_hold_duration_ms` | **28.513 ms** | **31.364 ms** |
| `rvc_orchestrator_slot_processing_duration_seconds` | **0.003431750 s** (**3.432 ms**) | **0.003774925 s** (**3.775 ms**) |

A larger **median** delta **blocks the phase exit**. Do not wave it through,
and do not meet the NFR by swapping series or fixtures or by dropping the
noisiest run.

---

## How 6.14 should use this file

Cite **this file** and measured commit
`8e908a56c6f1d5de1e92afbcb7222e47551019f5`. Re-run **both** invocations, three
times each, same key count / injected latency / pragmas / `test` profile (or
record a profile change explicitly). Gate each series on the **three-run
median** p99, not on any one JSON document.

| Series | Baseline (this file, median) | After Gloas (expected) | 6.14 vs +10 % (median ≤) |
|---|---|---|---|
| kept-window / client wall | p99 **230.258 / 230.074 ms**; concurrency **200** | island work is on the **proposal** path; attestation sign should stay near this | wall median p99 ≤ **253.081 ms** |
| reserve-tx | p99 **28.513 ms** | unchanged unless slashing path moves | median p99 ≤ **31.364 ms** (or document a profile/fsync change) |
| slot processing | p99 **3.432 ms**; n = **200**; 1 key, in-memory | same fixture; Gloas deadline is 25 % of slot (P4 resolver) but this histogram is duration, not deadline headroom | median p99 ≤ **3.775 ms** |

Headroom vs the **resolved** Gloas attestation deadline is a 6.14 column, not
this one. On this tree the deadline is still pre-Gloas 3999 ms
(`ATTESTATION_DUE_BPS`). 6.14 must obtain the Gloas deadline through the
Phase 4 resolver (D9), never a hardcoded 2500.

---

## Honest scope limit (X8)

**This does not measure the VC path at A-9 scale.**
`crates/rvc/src/orchestrator/attestation.rs` remains a sequential
`for duty in duties { … .await }` loop. 200 keys × 200 ms = 40 s with a free
DB. The sign-path numbers are `signer-server` / `SigningGate` only. The slot-
processing numbers are **1 key**, mock BN, in-memory slashing DB.

`cargo nextest run --workspace` runtime is unchanged: the load-profile test
stays `#[ignore]`; no new tests were added.

---

## Verbatim harness JSON

### Sign path — run 1

```json
{
  "issue": "ARCH-5a",
  "target": "signer-server",
  "target_reason": "VC path wall is its sequential attestation loop, not the slashing mutex (X8)",
  "keys": 200,
  "injected_latency_ms": 200,
  "db_pragmas": {
    "journal_mode": "wal",
    "synchronous": "EXTRA",
    "fullfsync": "ON"
  },
  "achieved_concurrency": 200,
  "effective_concurrency": 170.011,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 235.280,
  "wall_ms": { "p50": 219.577, "p95": 230.034, "p99": 230.477, "max": 233.867 },
  "tx_hold_ms": { "p50": 218.903, "p95": 230.258, "p99": 230.258, "max": 230.258, "count": 200, "sum": 43628.626 },
  "reserve_tx_hold_ms": { "p50": 16.885, "p95": 29.020, "p99": 29.020, "max": 29.020, "count": 200, "sum": 3080.675 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```

### Sign path — run 2

```json
{
  "issue": "ARCH-5a",
  "target": "signer-server",
  "target_reason": "VC path wall is its sequential attestation loop, not the slashing mutex (X8)",
  "keys": 200,
  "injected_latency_ms": 200,
  "db_pragmas": {
    "journal_mode": "wal",
    "synchronous": "EXTRA",
    "fullfsync": "ON"
  },
  "achieved_concurrency": 200,
  "effective_concurrency": 175.169,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 228.352,
  "wall_ms": { "p50": 218.964, "p95": 224.503, "p99": 225.491, "max": 227.092 },
  "tx_hold_ms": { "p50": 218.139, "p95": 223.502, "p99": 224.617, "max": 224.617, "count": 200, "sum": 43719.492 },
  "reserve_tx_hold_ms": { "p50": 15.619, "p95": 21.088, "p99": 21.088, "max": 21.088, "count": 200, "sum": 2687.836 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```

### Sign path — run 3

```json
{
  "issue": "ARCH-5a",
  "target": "signer-server",
  "target_reason": "VC path wall is its sequential attestation loop, not the slashing mutex (X8)",
  "keys": 200,
  "injected_latency_ms": 200,
  "db_pragmas": {
    "journal_mode": "wal",
    "synchronous": "EXTRA",
    "fullfsync": "ON"
  },
  "achieved_concurrency": 200,
  "effective_concurrency": 170.477,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 234.636,
  "wall_ms": { "p50": 219.890, "p95": 225.845, "p99": 230.074, "max": 233.341 },
  "tx_hold_ms": { "p50": 219.319, "p95": 225.073, "p99": 230.833, "max": 230.833, "count": 200, "sum": 43690.440 },
  "reserve_tx_hold_ms": { "p50": 16.482, "p95": 21.580, "p99": 28.513, "max": 28.513, "count": 200, "sum": 2900.726 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```

### Slot processing — run 1

```json
{
  "issue": "1.1",
  "target": "rvc-orchestrator",
  "target_reason": "signer-server load_profile does not populate RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS",
  "harness": "crates/rvc/tests/common/pipeline_fixture.rs",
  "keys": 1,
  "slots": 200,
  "successes": 200,
  "failures": 0,
  "slot_processing_s": { "p50": 0.002556375, "p95": 0.003283333, "p99": 0.003814333, "max": 0.003999667, "count": 200, "sum": 0.509958621 },
  "slot_processing_ms": { "p50": 2.556, "p95": 3.283, "p99": 3.814, "max": 4.000, "count": 200, "sum": 509.959 }
}
```

### Slot processing — run 2

```json
{
  "issue": "1.1",
  "target": "rvc-orchestrator",
  "target_reason": "signer-server load_profile does not populate RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS",
  "harness": "crates/rvc/tests/common/pipeline_fixture.rs",
  "keys": 1,
  "slots": 200,
  "successes": 200,
  "failures": 0,
  "slot_processing_s": { "p50": 0.002103708, "p95": 0.002952708, "p99": 0.003356833, "max": 0.003817333, "count": 200, "sum": 0.449421429 },
  "slot_processing_ms": { "p50": 2.104, "p95": 2.953, "p99": 3.357, "max": 3.817, "count": 200, "sum": 449.421 }
}
```

### Slot processing — run 3

```json
{
  "issue": "1.1",
  "target": "rvc-orchestrator",
  "target_reason": "signer-server load_profile does not populate RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS",
  "harness": "crates/rvc/tests/common/pipeline_fixture.rs",
  "keys": 1,
  "slots": 200,
  "successes": 200,
  "failures": 0,
  "slot_processing_s": { "p50": 0.002118958, "p95": 0.003079541, "p99": 0.003431750, "max": 0.003639375, "count": 200, "sum": 0.456871208 },
  "slot_processing_ms": { "p50": 2.119, "p95": 3.080, "p99": 3.432, "max": 3.639, "count": 200, "sum": 456.871 }
}
```
