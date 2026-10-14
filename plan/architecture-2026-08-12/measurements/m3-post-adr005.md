# M3 post-ADR-005 — slashing tx-hold after `reserve_then_sign`

ARCH-5m recording of the **ARCH-5a** `signer-server` harness (A-9: 200 keys × 200 ms
injected BLS latency) on the tree that flipped the production slashable path to
`reserve_then_sign` (`b68d32b`). Compared with the pre-switchover baseline in
[`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md) (measured commit
`11bb5696b6025ee8dd19b17a2c1dbbf066e25c2b`).

> **This is the X6 judgment run, not a victory lap.** The yardstick is the
> derived per-sign budget **3999 / 200 = 19.995 ms**, not "it got faster than
> the baseline." Both observation windows are reported (VD-5.2). G6 is **not**
> claimed (X8).

This file does **not** change production source. The ignored profile harness
was extended only so the JSON carries the reserve-tx series and
`rvc_slashing_reconcile_total` (A-5.5).

---

## Harness

| Field | Value |
|---|---|
| **Architecture baseline** | `0ae9a09badea7dcd4fd28e943003cef87e714f9f` (v0.7.0) |
| **Baseline measured commit** | `11bb5696b6025ee8dd19b17a2c1dbbf066e25c2b` (`test(signer-server): add slashing hold-duration load harness`) — cited from [`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md) |
| **This tree (`git rev-parse HEAD`)** | `b68d32bfe7536e6a90ff0d843a7a3ecad23c2854` (`feat(signer): flip slashable production path to reserve_then_sign`) |
| **Production path in force** | `SlashableSignSession::reserve_then_sign` (`crates/signer/src/core.rs`) via the ARCH-5l switchover |
| **Source** | `crates/signer-server/tests/load_profile.rs` (`test_load_profile_reports_p99_above_serialized_floor`, `#[ignore]`) |
| **Fixture** | `helpers::make_load_fixture` — 200 EIP-2333 keys, `SlowSigner` (async 200 ms sleep), real `SlashingDb::open` temp file |
| **Path** | `SignerServiceImpl::sign_attestation_data` → `SigningGate::sign_attestation` (`TimeoutPolicy::DiscardStagedRow`, A-5.5). **Not** the VC orchestrator (X8 / A-5.4). |
| **Instrument** | process-local exact `sample_sum` / `sample_count` deltas (not bucket quantile) on both histograms, plus counter deltas on `rvc_slashing_reconcile_total` |
| **Sign timeout** | `Duration::from_secs(4)` at the gate (`DEFAULT_SIGN_TIMEOUT`). No run hit it (200/200 successes). |

### Exact invocation (full A-9 profile)

JSON on stdout, and to `--output` (libtest; nextest 0.9 does not forward that arg):

```bash
cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
  --exact test_load_profile_reports_p99_above_serialized_floor \
  -- --output /tmp/arch-5m-m3/runN.json
```

nextest (summary on stdout only):

```bash
cargo nextest run -p rvc-signer-server --run-ignored ignored-only --no-capture \
  -E 'test(test_load_profile_reports_p99_above_serialized_floor)'
```

This recording used the `cargo test` form, three independent process invocations,
outputs at `/tmp/arch-5m-m3/run{1,2,3}.json` (not checked in). Full 200×200 ms × 3
completed in this environment (~1.2 s wall each); no reduced calibration was
used.

The pre-ADR-005 harness asserted `SlowSigner::max_in_flight ≤ 2` and a
serialized floor on p99. Those asserts fired on every recording run
(`max_in_flight` 48–49) **after** JSON emit — that is the switchover working,
not a harness defect. The ignored test's non-vacuity check was then retargeted
to "signs overlap + both histograms record n samples" so the same invocation
stays a recorder. The three JSON documents below were produced by the
instrumented driver; they are not mixed with later confirmation runs.

### Hardware / toolchain

| Field | Value |
|---|---|
| Host | Apple M4 Pro, arm64, 14 cores, 24 GB RAM |
| OS | macOS 26.6.1 (Darwin 25.6.0 / Build 25G76) |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| cargo | 1.97.1 (c980f4866 2026-06-30) |
| nextest | 0.9.85 (available; not used for the JSON runs) |
| Profile | `test` (unoptimized + debuginfo) |
| Measured | 2026-08-17T20:17:45Z – 2026-08-17T20:17:50Z (UTC) |

Same host / OS / rustc / cargo / `test` profile as
[`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md).

### Injected latency profile

| Parameter | Value |
|---|---|
| Keys | **200** (A-9), distinct pubkeys, one attestation each |
| Injected BLS latency | **200 ms** `tokio::time::sleep` on `helpers::SlowSigner` (async side, so `Handle::block_on(timeout(...))` observes it) |
| Arrival | 200 concurrent `JoinSet` tasks, `tokio` multi-thread 8 workers |
| DB | on-disk temp file, production `SlashingDb::open` |
| Pragmas in force | `journal_mode=WAL`, `synchronous=EXTRA`, `fullfsync=ON` (macOS) |
| Policy | `SigningGate` `Fixed(DiscardStagedRow)` |

### Metric windows in force (both series)

`SlashableSignSession::reserve_then_sign` (`crates/signer/src/core.rs`):

1. **Kept series** `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}`:
   `tx_start = Instant::now()` **before** `reserve()` (`:512`). `tx_hold_ms` is
   taken **after** the sign future returns (`:542`), then `on_tx_hold_ms` on
   every terminal branch. Window = **reserve-entry (includes mutex wait) →
   sign-return**. Same definition as the baseline's stage-entry → sign-return.
2. **Reserve-only series** `rvc_slashing_reserve_tx_hold_duration_ms{kind="attestation"}`:
   same `tx_start`, observed at reserve return (`:516`–`:518`). Window =
   **reserve-entry (includes mutex wait) → COMMIT**. This is the quantity
   ADR-005 shortens. Baseline column was **N/A**.

Histogram buckets in `crates/metrics/src/definitions.rs` stop at 5 s; values
above that still add to `sample_sum`. These runs landed inside the buckets.
Percentiles here are still exact per-sample `sample_sum` deltas (a 200 µs
poller, because reserve observations fire before the RPC returns), **not**
`histogram_quantile`.

---

## Results — three runs + median

All three runs: **200 / 200 successes**, **0 failures**,
`tx_hold_count = 200`, `reserve_tx_hold_count = 200`.

`effective_concurrency = keys × injected_ms / total_wall_ms`.

### Client wall (`sign_attestation_data` call)

| Run | Start (UTC) | total_wall_ms | p50 | p95 | p99 | max | effective_conc. |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | 20:17:45Z | 1136.072 | 645.602 | 1096.346 | 1129.210 | 1133.695 | 35.209 |
| 2 | 20:17:47Z | 1128.463 | 641.803 | 1087.098 | 1119.877 | 1125.313 | 35.446 |
| 3 | 20:17:48Z | 1118.461 | 660.061 | 1079.056 | 1112.294 | 1116.470 | 35.763 |
| **median** | | **1128.463** | **645.602** | **1087.098** | **1119.877** | **1125.313** | **35.446** |

Baseline median total wall was **41 845.127 ms**. Post-change is **37.1×**
shorter. That is "got faster." It is **not** X6.

### `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}` (kept window)

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 645.441 | 1095.978 | 1128.957 | 1133.227 | 130705.848 | 653.529 |
| 2 | 641.492 | 1086.814 | 1119.528 | 1124.965 | 130348.057 | 651.740 |
| 3 | 659.798 | 1078.734 | 1112.136 | 1116.362 | 130732.085 | 653.660 |
| **median** | **645.441** | **1086.814** | **1119.528** | **1124.965** | **130705.848** | **653.529** |

Baseline median p99 was **41 624.385 ms**. The lock no longer spans the sign,
so the ~41 s queue collapsed. The window still contains the 200 ms injected
sign plus the reserve queue, so this series **cannot** sit under 19.995 ms at
A-9 (VD-5.2).

### `rvc_slashing_reserve_tx_hold_duration_ms{kind="attestation"}` (reserve-only)

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 442.848 | 892.642 | 925.632 | 929.642 | 90163.310 | 450.817 |
| 2 | 439.750 | 883.420 | 917.025 | 921.813 | 89844.750 | 449.224 |
| 3 | 457.633 | 876.050 | 909.189 | 914.055 | 90270.711 | 451.354 |
| **median** | **442.848** | **883.420** | **917.025** | **921.813** | **90163.310** | **450.817** |

Baseline column: **N/A** (not instrumented).

The shape is a serialized queue, not a 900 ms uncontended write. If sample
`i` (1-indexed) is `i × T`:

```text
sum = T × n × (n + 1) / 2
T   = 2 × median_sum / (200 × 201)
    = 2 × 90163.310 / 40200
    = 4.486 ms
```

That implied per-reserve cost (~4.5 ms, `EXTRA` + `fullfsync`) is the fsync
quantum. Contended p99 ≈ `200 × T` because `tx_start` is taken before
`reserve()`'s mutex acquire.

### Side-by-side with the baseline

| Series | Baseline median (commit `11bb5696b6025ee8dd19b17a2c1dbbf066e25c2b`) | This tree median (`b68d32bfe7536e6a90ff0d843a7a3ecad23c2854`) | X6 vs 19.995 ms |
|---|---|---|---|
| `rvc_signer_slashing_tx_hold_duration_ms` (kept window) | p99 **41 624.385 ms**; concurrency **1** | p99 **1 119.528 ms**; concurrency **49** | **no** (~56× over; still contains the 200 ms sign) |
| `rvc_slashing_reserve_tx_hold_duration_ms` (reserve-only) | **N/A** | p99 **917.025 ms**; implied uncontended **4.486 ms** | **no** (~46× over) |

### Achieved concurrency

| Quantity | Baseline | This tree | How measured |
|---|---|---|---|
| **achieved_concurrency** | **1** (all three runs) | **49** (median; 48 / 49 / 49) | peak overlapping `SlowSigner::sign` calls |
| **effective_concurrency** | **0.956** (median) | **35.446** (median) | `200 × 200 / total_wall_ms` |
| Implied per-sign serial cost | **209.226 ms** | **5.642 ms** | median `total_wall_ms / 200` |
| Injected / remainder | 200 ms / **~9.2 ms** | 200 ms sign, overlapped; remainder is the reserve/fsync queue | |

`achieved_concurrency ≈ 200 ms / 4.5 ms ≈ 44` is the expected overlap if
reserves serialize at ~4.5 ms and each sign lasts 200 ms. Measured 48–49
agrees. ARCH-5m compares against the same definition as the baseline
(`SlowSigner::max_in_flight`).

### Reproducibility

Reserve-tx p99 range 909.189–925.632 ms →
**(max − min) / min = 1.81 %**. Kept-window p99 range 1112.136–1128.957 ms →
**1.51 %**. Both well under the 20 % reopen threshold and inside the
ARCH-5b ±5 % band for this host / `test` profile. ARCH-5a is **not**
reopened.

---

## Per-sign budget (A-9), arithmetic shown — X6 judgment

M3's target is p99 **below the per-sign budget implied by 200 keys inside one
attestation window**, and no single hold above the remote-signer timeout.
The budget is derived, not picked. Same constants as the baseline:

| Symbol | Value | Source |
|---|---|---|
| `SECONDS_PER_SLOT` | 12 | `crates/eth-types/src/lib.rs` |
| `slot_duration_ms` | `12 × 1000 = 12_000` | |
| `ATTESTATION_DUE_BPS` | 3333 | `crates/timing/src/lib.rs` |
| `BASIS_POINTS` | 10_000 | same |
| `attestation_window_ms` | `due_ms(3333, 12_000) = 3333 × 12_000 / 10_000 = **3999**` | VD-S7; doctest `due_ms(ATTESTATION_DUE_BPS, 12000) == 3999` |
| `N` (A-9) | **200** keys | `prd.md` A-9 |
| `DEFAULT_SIGN_TIMEOUT` | **4000 ms** | `crates/signer/src/core.rs` |

```text
per_sign_budget_ms = attestation_window_ms / N
                   = 3999 / 200
                   = 19.995 ms
```

That is the X6 yardstick. It is **not** "got faster than the baseline."

| Check | Yardstick | Median measured | Met? |
|---|---:|---:|---|
| Kept-window p99 vs per-sign budget | **19.995 ms** | **1 119.528 ms** | **no** (~56×) |
| Reserve-tx p99 vs per-sign budget | **19.995 ms** | **917.025 ms** | **no** (~46×) |
| No single kept-window hold vs sign timeout | **4000 ms** | max **1 124.965 ms** | **yes** (timeout did not fire) |
| 200 keys completable in one 3999 ms window | **3999 ms** total wall | **1 128.463 ms** | yes on this host — **not X6** |

**X6 is unmet.** The finding is the deliverable.

The 3999 ms *window* is cleared at N=200 on this host (total wall ~1.1 s).
That is operational capacity under A-9, not the M3 p99 budget. Reporting
only that number would meet the milestone by changing the ruler.

---

## Next wall — fsync; group commit is a new requirement

The remaining serialized work is the reserve transaction under
`synchronous=EXTRA` + `fullfsync=ON` (`crates/slashing/src/db/open.rs:240-246`).
Two hundred durable commits per wave produce the ~917 ms contended reserve-tx
p99. Implied uncontended quantum **4.486 ms** is a fullfsync, not a rule-check.

**A-5.9 / A-A9 is hereby promoted from "admissible if measured" to a new
requirement, not absorbed into this phase:**

- **Name:** slashing-DB **group commit**.
- **Shape:** batch N pending reserve checks into one `BEGIN IMMEDIATE` → rule
  check → INSERT → `COMMIT` (one fsync), then release all N to sign.
- **Invariant:** preserves commit-before-sign exactly. Per-pubkey connections
  and DB sharding stay **rejected** (VD-S1).
- **Why now:** reserve-tx p99 **917.025 ms** ≫ **19.995 ms** with the mutex
  no longer spanning the sign. The next wall is fsync.
- **Not in Phase 5.** Filing it here is the measurement outcome. Scheduling
  it is a later decision.

A batch of ~50 at this 4.5 ms quantum would put queued reserve-tx p99 near
`200 / 50 × 4.5 ≈ 18 ms`, which is the first size that can honestly approach
X6 without redefining the window.

---

## Reconcile failures (A-5.5)

`SigningGate` is `TimeoutPolicy::DiscardStagedRow`. Under Discard, a failed
compensating delete is M-1's liveness mode (phantom row; never a double-sign).
Metered as `rvc_slashing_reconcile_total{kind="attestation",outcome="failed"}`.

| Run | deleted | not_applicable | **failed** |
|---|---:|---:|---:|
| 1 | 0 | 0 | **0** |
| 2 | 0 | 0 | **0** |
| 3 | 0 | 0 | **0** |

All 200 signs succeeded, so the success path does not call
`reconcile_unsigned` (row already committed). **Failed = 0** under this load.
Not a finding. A non-zero count here would have been a finding (A-5.5) and
would also have promoted a reconcile retry, not only group commit.

---

## Rollback plan (X7)

Reverting the switchover commit is safe **in the slashing direction** and is
a **single-commit** revert (NFR-4). It is **not** "revert and ship."

| Item | Statement |
|---|---|
| **Revert this commit** | `b68d32bfe7536e6a90ff0d843a7a3ecad23c2854` — `feat(signer): flip slashable production path to reserve_then_sign` |
| **What comes back** | Production slashable path calls `stage_then_sign` again. `reserve_then_sign` and `reserve_*` stay in the tree, unused by the core consumer (the ARCH-5i sibling). |
| **Slashing direction** | The old design retains strictly **less**, never more. No committed signature can become unrecorded by rolling back. Fail-safe. |
| **Schema / data** | **Unchanged.** Reserve and stage write the same attestation/block tables. **No migration** in either direction. |
| **EIP-3076 vectors** | Necessary and **insufficient**. They pass identically under both designs (VD-S3). Do not treat a green interchange suite as proof the revert is safe. |
| **Must re-run (all three proof surfaces)** | `crates/slashing/tests/reserve_concurrency.rs`; `crates/signer/tests/retain_on_ambiguity_matrix.rs`; `crates/signer/tests/reserve_cancellation.rs`. Not optional, not "vectors plus one." |
| **Revert shape** | One commit / one PR that restores `stage_then_sign` as the single core consumer. Do not fold unrelated work into the revert (NFR-4). |
| **After revert** | Re-record M3 against [`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md). Expect concurrency to fall back to **1** and kept-window p99 to climb back toward ~41 s under this profile. |

---

## Honest scope limit (X8)

**ARCH-P1-5 does not deliver G6 on the VC path.** Re-verified at
`b68d32bfe7536e6a90ff0d843a7a3ecad23c2854`:

`crates/rvc/src/orchestrator/attestation.rs:171-192` is a sequential

```text
for duty in duties {
    let result = self.process_attestation_duty(duty).await;
    ...
}
```

with no `join_all`, `FuturesUnordered`, or `spawn` anywhere under
`crates/rvc/src/orchestrator/` production code (only test modules spawn).
Therefore:

```text
200 keys × 200 ms = 40_000 ms = 40 s = ten mainnet slots
```

**with a completely free slashing DB.** The mutex is not that ceiling.
This measurement is `signer-server` / `SigningGate` only (A-5.4).

**VC-path attestation concurrency is filed as a separate, unscheduled
requirement.** It is not in Phase 5, not implied by ADR-005, and not
delivered by a faster reserve. Claiming G6 here would be false.

---

## Verbatim harness JSON

### Run 1

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
  "achieved_concurrency": 49,
  "effective_concurrency": 35.209,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 1136.072,
  "wall_ms": { "p50": 645.602, "p95": 1096.346, "p99": 1129.210, "max": 1133.695 },
  "tx_hold_ms": { "p50": 645.441, "p95": 1095.978, "p99": 1128.957, "max": 1133.227, "count": 200, "sum": 130705.848 },
  "reserve_tx_hold_ms": { "p50": 442.848, "p95": 892.642, "p99": 925.632, "max": 929.642, "count": 200, "sum": 90163.310 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```

### Run 2

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
  "achieved_concurrency": 49,
  "effective_concurrency": 35.446,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 1128.463,
  "wall_ms": { "p50": 641.803, "p95": 1087.098, "p99": 1119.877, "max": 1125.313 },
  "tx_hold_ms": { "p50": 641.492, "p95": 1086.814, "p99": 1119.528, "max": 1124.965, "count": 200, "sum": 130348.057 },
  "reserve_tx_hold_ms": { "p50": 439.750, "p95": 883.420, "p99": 917.025, "max": 921.813, "count": 200, "sum": 89844.750 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```

### Run 3

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
  "achieved_concurrency": 48,
  "effective_concurrency": 35.763,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 1118.461,
  "wall_ms": { "p50": 660.061, "p95": 1079.056, "p99": 1112.294, "max": 1116.470 },
  "tx_hold_ms": { "p50": 659.798, "p95": 1078.734, "p99": 1112.136, "max": 1116.362, "count": 200, "sum": 130732.085 },
  "reserve_tx_hold_ms": { "p50": 457.633, "p95": 876.050, "p99": 909.189, "max": 914.055, "count": 200, "sum": 90270.711 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```
