# M3 scale validation — 200 keys / 200 ms (ARCH-7m)

ARCH-7m recording of the **ARCH-5a** `signer-server` harness (A-9: 200 keys × 200 ms
injected BLS latency) on the **post-ADR-005** tree (`origin/develop`
`41e7646cb7a6fe7e81da6e8f2a60622672ded825`). Compared with the pre-redesign
Phase 5 baseline in [`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md)
(measured commit `11bb5696b6025ee8dd19b17a2c1dbbf066e25c2b`) and the
switchover recording in [`m3-post-adr005.md`](./m3-post-adr005.md)
(`b68d32bfe7536e6a90ff0d843a7a3ecad23c2854`).

> **This is the P1-15b validation run, not a new harness and not group
> commit.** 5A already exists. No production source was edited. C9
> anchor-2 proof surfaces were not opened. The yardstick is still
> **3999 / 200 = 19.995 ms**, plus **zero** missed attestation deadlines.

---

## Scope honesty (A-A8)

**This validates the `signer-server` / `SigningGate` path only.** It does
**not** validate the VC attestation loop at 200 keys.

Re-verified at `41e7646cb7a6fe7e81da6e8f2a60622672ded825`:
`crates/rvc/src/orchestrator/attestation.rs:171-192` is still a sequential

```text
for duty in duties {
    let result = self.process_attestation_duty(duty).await;
    ...
}
```

with no `join_all`, `FuturesUnordered`, or `spawn` anywhere under
`crates/rvc/src/orchestrator/` production code. Therefore:

```text
200 keys × 200 ms = 40_000 ms = 40 s = ten mainnet slots
```

**with a completely free slashing DB.** A green signer-server wave does not
license a G6 / 200-key claim on the VC path. That loop is unvalidated at
this count.

---

## Harness

| Field | Value |
|---|---|
| **Architecture baseline** | `0ae9a09badea7dcd4fd28e943003cef87e714f9f` (v0.7.0) |
| **Pre-redesign measured commit** | `11bb5696b6025ee8dd19b17a2c1dbbf066e25c2b` ([`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md)) |
| **Post-ADR-005 measured commit** | `b68d32bfe7536e6a90ff0d843a7a3ecad23c2854` ([`m3-post-adr005.md`](./m3-post-adr005.md)) |
| **This tree (`git rev-parse HEAD`)** | `41e7646cb7a6fe7e81da6e8f2a60622672ded825` (`feat(keymanager): retire time-based doppelganger opt-out gate`) |
| **Production path in force** | `SlashableSignSession::reserve_then_sign` (`crates/signer/src/core.rs`) |
| **Source** | `crates/signer-server/tests/load_profile.rs` (`test_load_profile_reports_p99_above_serialized_floor`, `#[ignore]`) |
| **Fixture** | `helpers::make_load_fixture` — 200 EIP-2333 keys, `SlowSigner` (async sleep), real `SlashingDb::open` temp file |
| **Path** | `SignerServiceImpl::sign_attestation_data` → `SigningGate::sign_attestation` (`TimeoutPolicy::DiscardStagedRow`). **Not** the VC orchestrator (A-A8). |
| **Kinds driven** | **`attestation` only.** The 5A profile does not call `sign_beacon_block`; `{kind="block"}` is not in this run. |
| **Instrument** | process-local exact `sample_sum` / `sample_count` deltas (not bucket quantile) on both histograms, plus `rvc_slashing_reconcile_total` |
| **Sign timeout** | `Duration::from_secs(4)` at the gate (`DEFAULT_SIGN_TIMEOUT`). No validation run hit it (200/200 successes). |
| **Harness changes** | **None landed.** Calibration temporarily set `LOAD_PROFILE_INJECTED_LATENCY` to 3500 ms in `helpers.rs` and reverted it before the 200 ms runs (`git diff` empty). |

### Exact invocation (full A-9 profile)

JSON on stdout, and to `--output` (libtest; nextest 0.9 does not forward that arg):

```bash
cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
  --exact test_load_profile_reports_p99_above_serialized_floor \
  -- --output /tmp/arch-7m-m3/runN.json
```

nextest (summary on stdout only):

```bash
cargo nextest run -p rvc-signer-server --run-ignored ignored-only --no-capture \
  -E 'test(test_load_profile_reports_p99_above_serialized_floor)'
```

This recording used the `cargo test` form. Calibration output
`/tmp/arch-7m-m3/cal-3500.json`; three validation outputs
`/tmp/arch-7m-m3/run{1,2,3}.json` (not checked in).

### Hardware / toolchain

| Field | Value |
|---|---|
| Host | Apple M4 Pro (`Mac16,8`), arm64, 14 cores (physical=logical), 24 GB RAM |
| OS | macOS 26.6.1 (Darwin 25.6.0 / Build 25G76) |
| Disk | Internal APFS SSD (Apple Fabric); `/tmp` and the worktree on `/dev/disk3s5` (`/System/Volumes/Data`) |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| cargo | 1.97.1 (c980f4866 2026-06-30) |
| nextest | 0.9.85 (available; not used for the JSON runs) |
| Profile | `test` (unoptimized + debuginfo) |
| Calibration | 2026-08-18T15:17:27Z (UTC) |
| Validation runs | 2026-08-18T15:17:59Z – 2026-08-18T15:18:05Z (UTC) |

Same host / OS / rustc / cargo / `test` profile as
[`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md) and
[`m3-post-adr005.md`](./m3-post-adr005.md).

### Injected latency profile

| Parameter | Value |
|---|---|
| Keys | **200** (A-9), distinct pubkeys, one attestation each |
| Injected BLS latency (validation) | **200 ms** `tokio::time::sleep` on `helpers::SlowSigner` |
| Injected BLS latency (calibration) | **3500 ms** (local fixture override, reverted; see below) |
| Arrival | 200 concurrent `JoinSet` tasks, `tokio` multi-thread 8 workers |
| DB | on-disk temp file, production `SlashingDb::open` |
| Pragmas in force | `journal_mode=WAL`, `synchronous=EXTRA`, `fullfsync=ON` (macOS) — `crates/slashing/src/db/open.rs:240-246` |
| Policy | `SigningGate` `Fixed(DiscardStagedRow)` |

### Metric windows in force (both series)

`SlashableSignSession::reserve_then_sign` (`crates/signer/src/core.rs`):

1. **Kept series** `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}`:
   reserve-entry (includes mutex wait) → sign-return. Same definition as
   ARCH-5b / ARCH-5m.
2. **Reserve-only series** `rvc_slashing_reserve_tx_hold_duration_ms{kind="attestation"}`:
   reserve-entry (includes mutex wait) → COMMIT.

Percentiles are exact per-sample `sample_sum` deltas (200 µs poller), **not**
`histogram_quantile`.

### Missed-deadline definition

The 5A harness does **not** emit a `missed_deadlines` field. ARCH-7m reads
the miss from the JSON it already prints:

```text
attestation_window_ms = due_ms(ATTESTATION_DUE_BPS, 12_000) = 3999
a sign misses iff its client wall_ms > 3999
the wave misses iff total_wall_ms > 3999
```

`failures` is a different signal (RPC / sign-timeout). Calibration was
aimed at **deadline misses with successes = 200**, not at
`DEFAULT_SIGN_TIMEOUT`.

---

## Calibration (RED first)

A harness that cannot show a miss cannot demonstrate success. Injected
latency was raised on the existing fixture until client wall cleared the
3999 ms window, then reverted. No new driver.

**Threshold (from ARCH-5m's fsync tail, not guessed):** last-completer wall
≈ reserve-tx p99 + injected. With reserve-tx p99 ≈ 917–930 ms,

```text
injected ≳ 3999 − 930 ≈ 3069 ms
```

is the first point the last sign is expected to miss. **3500 ms** sits
above that floor and **below** the 4000 ms sign timeout, so the BLS sleep
still completes (`failures = 0`) while the *deadline* is missed.

| | 200 ms (validation median) | **3500 ms (calibration)** |
|---|---:|---:|
| successes / failures | 200 / 0 | 200 / 0 |
| total_wall_ms | **1140.654** | **4435.519** |
| wall p50 / p95 / p99 / max | 675.542 / 1099.477 / 1131.481 / 1135.758 | 3943.781 / 4391.215 / 4426.260 / 4430.585 |
| Wave vs 3999 ms | **under** (0 misses) | **over** (`total_wall_ms` and `wall.max` > 3999) |
| achieved_concurrency | 45 | 200 |
| reserve-tx p99 | 929.660 | 925.539 |

The harness **reported** the miss: `total_wall_ms = 4435.519` and
`wall_ms.max = 4430.585` are both above 3999. `wall.p50 = 3943.781` is
still under, so this is a partial-wave miss (early signs land, the tail
does not) — the shape a deadline counter must be able to see.

Raising further to ≥ 4000 ms would flip the signal to sign-timeout
`failures`, which is not the attestation deadline. Stopped at 3500 ms.

Calibration JSON is in [Verbatim harness JSON](#verbatim-harness-json)
(`cal-3500`).

---

## Results — three 200 ms runs + median

All three validation runs: **200 / 200 successes**, **0 failures**,
`tx_hold_count = 200`, `reserve_tx_hold_count = 200`.

`effective_concurrency = keys × injected_ms / total_wall_ms`.

### Client wall (`sign_attestation_data` call)

| Run | Start (UTC) | total_wall_ms | p50 | p95 | p99 | max | effective_conc. |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | 15:17:59Z | 1140.654 | 675.542 | 1099.477 | 1131.481 | 1135.758 | 35.068 |
| 2 | 15:18:02Z | 1134.675 | 665.250 | 1092.057 | 1127.884 | 1131.397 | 35.252 |
| 3 | 15:18:03Z | 1171.083 | 677.331 | 1128.340 | 1165.881 | 1168.240 | 34.156 |
| **median** | | **1140.654** | **675.542** | **1099.477** | **1131.481** | **1135.758** | **35.068** |

### Missed attestation deadlines (target 0)

| Run | wall.max vs 3999 | total_wall vs 3999 | Missed deadlines |
|---|---|---|---|
| 1 | 1135.758 | 1140.654 | **0** |
| 2 | 1131.397 | 1134.675 | **0** |
| 3 | 1168.240 | 1171.083 | **0** |
| **median** | **1135.758** | **1140.654** | **0** |

**Zero missed attestation deadlines** at 200 keys / 200 ms.

### Throughput (signer-server wave)

| Quantity | Median | How |
|---|---:|---|
| Completions | **200 / 200** | successes |
| Wall | **1140.654 ms** | `total_wall_ms` |
| Throughput | **175.3 signs/s** | `200 / (1140.654 / 1000)` |
| Waves per 3999 ms window | **3.51** | `3999 / 1140.654` |
| Implied per-sign serial cost | **5.703 ms** | `total_wall_ms / 200` |

The 3999 ms *window* is cleared at N=200 on this host. That is operational
capacity under A-9 on the **signer-server** path. It is **not** X6 and
**not** a VC-path result.

### `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}` (kept window)

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 675.294 | 1098.875 | 1131.255 | 1135.579 | 134495.698 | 672.478 |
| 2 | 665.110 | 1091.885 | 1127.706 | 1131.260 | 132342.683 | 661.713 |
| 3 | 677.172 | 1128.204 | 1165.344 | 1167.992 | 135424.435 | 677.122 |
| **median** | **675.294** | **1098.875** | **1131.255** | **1135.579** | **134495.698** | **672.478** |

`{kind="block"}`: **not driven** by the 5A profile. No block series is
invented here.

### `rvc_slashing_reserve_tx_hold_duration_ms{kind="attestation"}` (reserve-only)

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 473.431 | 897.255 | 929.660 | 933.721 | 94156.765 | 470.784 |
| 2 | 462.471 | 889.586 | 925.900 | 929.823 | 91950.934 | 459.755 |
| 3 | 475.009 | 925.506 | 962.562 | 965.991 | 95006.496 | 475.032 |
| **median** | **473.431** | **897.255** | **929.660** | **933.721** | **94156.765** | **470.784** |

Implied uncontended reserve cost, same triangular-queue identity as ARCH-5m:

```text
sum = T × n × (n + 1) / 2
T   = 2 × median_sum / (200 × 201)
    = 2 × 94156.765 / 40200
    = 4.684 ms
```

That quantum is a fullfsync (`EXTRA` + `fullfsync=ON`), not a rule-check.

### Achieved concurrency

| Quantity | Pre-redesign (5b) | Post-ADR-005 (5m) | This tree (7m) |
|---|---|---|---|
| **achieved_concurrency** | **1** | **49** (median; 48 / 49 / 49) | **45** (median; 44 / 47 / 45) |
| **effective_concurrency** | **0.956** | **35.446** | **35.068** |
| Implied per-sign serial cost | **209.226 ms** | **5.642 ms** | **5.703 ms** |

### Reproducibility

Kept-window p99 range 1127.706–1165.344 ms →
**(max − min) / min = 3.34 %**. Reserve-tx p99 range 925.900–962.562 ms →
**3.96 %**. Both under the 20 % reopen threshold and inside the ARCH-5b
±5 % band for this host / `test` profile. ARCH-5a is **not** reopened.

---

## Per-sign budget (A-9) — p99 vs 19.995 ms

Same constants as ARCH-5b / ARCH-5m:

| Symbol | Value | Source |
|---|---|---|
| `SECONDS_PER_SLOT` | 12 | `crates/eth-types/src/lib.rs` |
| `slot_duration_ms` | `12 × 1000 = 12_000` | |
| `ATTESTATION_DUE_BPS` | 3333 | `crates/timing/src/lib.rs` |
| `attestation_window_ms` | `due_ms(3333, 12_000) = **3999**` | doctest `due_ms(ATTESTATION_DUE_BPS, 12000) == 3999` |
| `N` (A-9) | **200** keys | `prd.md` A-9 |
| `DEFAULT_SIGN_TIMEOUT` | **4000 ms** | `crates/signer/src/core.rs` |

```text
per_sign_budget_ms = attestation_window_ms / N
                   = 3999 / 200
                   = 19.995 ms
```

| Check | Yardstick | Median measured | Met? |
|---|---:|---:|---|
| Missed attestation deadlines | **0** | **0** | **yes** |
| Kept-window p99 vs per-sign budget | **19.995 ms** | **1131.255 ms** | **no** (~57×) |
| Reserve-tx p99 vs per-sign budget | **19.995 ms** | **929.660 ms** | **no** (~46×) |
| No single kept-window hold vs sign timeout | **4000 ms** | max **1135.579 ms** | **yes** |
| 200 keys completable in one 3999 ms window | **3999 ms** total wall | **1140.654 ms** | yes on this host — **not X6** |

X6 (p99 ≤ 19.995 ms) remains **unmet**, same finding as ARCH-5m. The
validation criterion that *is* this issue's (zero missed deadlines at
A-9 on signer-server) is met.

---

## Pre-redesign Phase 5 baseline comparison

| Series | Pre-redesign median (`11bb569`, 5b) | Post-ADR-005 median (`b68d32b`, 5m) | This tree median (`41e7646`, 7m) |
|---|---|---|---|
| kept-window p99 | **41 624.385 ms**; conc. **1** | **1 119.528 ms**; conc. **49** | **1 131.255 ms**; conc. **45** |
| reserve-tx p99 | **N/A** | **917.025 ms** | **929.660 ms** |
| total wall | **41 845.127 ms** | **1 128.463 ms** | **1 140.654 ms** |
| missed deadlines | not scored (p99 ≫ 3999) | 0 (wall.max 1 125 ms) | **0** (wall.max 1 136 ms) |

This tree vs ARCH-5m: kept-window p99 **+1.05 %**, reserve-tx p99
**+1.38 %**, total wall **+1.08 %** — inside the host ±5 % band. The
Phase 5 switchover gain vs pre-redesign is intact (~37× shorter wall;
concurrency 1 → ~45). Nothing in Phase 6/7 so far moved M3.

---

## fsync binds — stop. No group commit.

The remaining serialized work is the reserve transaction under
`synchronous=EXTRA` + `fullfsync=ON` (`crates/slashing/src/db/open.rs:240-246`).
Two hundred durable commits per wave produce the ~930 ms contended
reserve-tx p99. Implied uncontended quantum **4.684 ms** is a fullfsync.

**A-A9 is follow-on work, not absorbed here.** Group commit is admissible
because fsync is measured to bind (same promotion ARCH-5m already filed).
This issue lands **no** group-commit code, no `crates/slashing` edit, no
`crates/signer` edit.

---

## Reconcile failures (A-5.5)

| Run | deleted | not_applicable | **failed** |
|---|---:|---:|---:|
| cal-3500 | 0 | 0 | **0** |
| 1 | 0 | 0 | **0** |
| 2 | 0 | 0 | **0** |
| 3 | 0 | 0 | **0** |

---

## `tx_hold_metric.rs` pin (untouched)

`crates/signer/tests/tx_hold_metric.rs` was **not** edited.

| When | Result |
|---|---|
| Before the runs | 3 passed (`test_metric_recorded_on_stage_commit`, `_discard`, `_slashing_rejected`) |
| After the runs (helpers reverted) | 3 passed |

The metric being measured is still the metric that is pinned.

C9 anchor-2 surfaces (`reserve_concurrency.rs`,
`retain_on_ambiguity_matrix.rs`, `reserve_cancellation.rs`) were not
opened.

---

## Verbatim harness JSON

### Calibration (3500 ms injected)

```json
{
  "issue": "ARCH-5a",
  "target": "signer-server",
  "target_reason": "VC path wall is its sequential attestation loop, not the slashing mutex (X8)",
  "keys": 200,
  "injected_latency_ms": 3500,
  "db_pragmas": {
    "journal_mode": "wal",
    "synchronous": "EXTRA",
    "fullfsync": "ON"
  },
  "achieved_concurrency": 200,
  "effective_concurrency": 157.817,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 4435.519,
  "wall_ms": { "p50": 3943.781, "p95": 4391.215, "p99": 4426.260, "max": 4430.585 },
  "tx_hold_ms": { "p50": 3943.498, "p95": 4391.098, "p99": 4426.069, "max": 4430.384, "count": 200, "sum": 790169.485 },
  "reserve_tx_hold_ms": { "p50": 441.992, "p95": 889.907, "p99": 925.539, "max": 928.833, "count": 200, "sum": 89940.397 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```

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
  "achieved_concurrency": 44,
  "effective_concurrency": 35.068,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 1140.654,
  "wall_ms": { "p50": 675.542, "p95": 1099.477, "p99": 1131.481, "max": 1135.758 },
  "tx_hold_ms": { "p50": 675.294, "p95": 1098.875, "p99": 1131.255, "max": 1135.579, "count": 200, "sum": 134495.698 },
  "reserve_tx_hold_ms": { "p50": 473.431, "p95": 897.255, "p99": 929.660, "max": 933.721, "count": 200, "sum": 94156.765 },
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
  "achieved_concurrency": 47,
  "effective_concurrency": 35.252,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 1134.675,
  "wall_ms": { "p50": 665.250, "p95": 1092.057, "p99": 1127.884, "max": 1131.397 },
  "tx_hold_ms": { "p50": 665.110, "p95": 1091.885, "p99": 1127.706, "max": 1131.260, "count": 200, "sum": 132342.683 },
  "reserve_tx_hold_ms": { "p50": 462.471, "p95": 889.586, "p99": 925.900, "max": 929.823, "count": 200, "sum": 91950.934 },
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
  "achieved_concurrency": 45,
  "effective_concurrency": 34.156,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 1171.083,
  "wall_ms": { "p50": 677.331, "p95": 1128.340, "p99": 1165.881, "max": 1168.240 },
  "tx_hold_ms": { "p50": 677.172, "p95": 1128.204, "p99": 1165.344, "max": 1167.992, "count": 200, "sum": 135424.435 },
  "reserve_tx_hold_ms": { "p50": 475.009, "p95": 925.506, "p99": 962.562, "max": 965.991, "count": 200, "sum": 95006.496 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```
