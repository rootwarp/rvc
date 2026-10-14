# M3 post-group-commit — slashing reserve-tx after batching one fsync

Issue **#205** recording of the **ARCH-5a** `signer-server` harness (A-9: 200
keys × 200 ms injected BLS latency) on the tree that batches N pending
`reserve_*` checks into one `BEGIN IMMEDIATE` → rule check → INSERT →
`COMMIT`. Compared with:

- [`m3-post-adr005.md`](./m3-post-adr005.md) (ARCH-5m, `b68d32b`) — X6 unmet,
  reserve-tx p99 **917.025 ms**, fsync named, group commit filed
- [`m3-scale-200keys-200ms.md`](./m3-scale-200keys-200ms.md) (ARCH-7m,
  `41e7646`) — same wall, 0 missed deadlines, p99 **1131 / 930 ms**

> **This is the #205 judgment run.** The yardstick is still
> **3999 / 200 = 19.995 ms**, under **both** metric windows (VD-5.2). G6 is
> **not** claimed (X8). Pragmas are **unchanged** (`synchronous=EXTRA`,
> `fullfsync=ON`).

---

## Harness

| Field | Value |
|---|---|
| **Architecture baseline** | `0ae9a09badea7dcd4fd28e943003cef87e714f9f` (v0.7.0) |
| **Post-ADR-005 measured commit** | `b68d32bfe7536e6a90ff0d843a7a3ecad23c2854` ([`m3-post-adr005.md`](./m3-post-adr005.md)) |
| **Scale measured commit** | `41e7646cb7a6fe7e81da6e8f2a60622672ded825` ([`m3-scale-200keys-200ms.md`](./m3-scale-200keys-200ms.md)) |
| **This tree** | `feature/205-slashing-db-group-commit` based on `397385cad4344fdd73bab2d43d68c4a4c1e0d253` (uncommitted implementation at recording time) |
| **Production path in force** | `SlashableSignSession::reserve_then_sign` via group-commit `reserve_*` |
| **Group-commit knobs in force** | `batch_size=50`, `wait_to_fill=1ms` (`GroupCommitConfig::default`) |
| **Source** | `crates/signer-server/tests/load_profile.rs` (`test_load_profile_reports_p99_above_serialized_floor`, `#[ignore]`) |
| **Fixture** | `helpers::make_load_fixture` — 200 EIP-2333 keys, `SlowSigner` (async 200 ms sleep), real `SlashingDb::open` temp file |
| **Path** | `SignerServiceImpl::sign_attestation_data` → `SigningGate::sign_attestation` (`TimeoutPolicy::DiscardStagedRow`). **Not** the VC orchestrator (X8 / A-5.4). |
| **Instrument** | process-local exact `sample_sum` / `sample_count` deltas (not bucket quantile) on both histograms, plus `rvc_slashing_reconcile_total` |
| **Sign timeout** | `Duration::from_secs(4)` at the gate. No run hit it (200/200 successes). |

### Exact invocation (full A-9 profile)

```bash
cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
  --exact test_load_profile_reports_p99_above_serialized_floor \
  -- --output /tmp/arch-205-m3/runN.json
```

This recording used the `cargo test` form. The binary was compiled once, then
three consecutive independent process invocations (runs 4–6 below) were kept as
the judgment set. A first-invocation after compile (run 1) landed reserve-tx
p99 **33.028 ms** and is **not** mixed into the median — it is recorded as a
cold-process ceiling.

### Hardware / toolchain

| Field | Value |
|---|---|
| Host | Apple M4 Pro, arm64, 14 cores, 24 GB RAM |
| OS | macOS 26.6.2 (Darwin / Build 25G83) |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| cargo | 1.97.1 (c980f4866 2026-06-30) |
| Profile | `test` (unoptimized + debuginfo) |
| Measured | 2026-09-05T16:40:12Z – 2026-09-05T16:40:14Z (UTC) |

Same host family / rustc / cargo / `test` profile as
[`m3-post-adr005.md`](./m3-post-adr005.md). OS patch 26.6.1 → 26.6.2.

### Injected latency profile

| Parameter | Value |
|---|---|
| Keys | **200** (A-9), distinct pubkeys, one attestation each |
| Injected BLS latency | **200 ms** `tokio::time::sleep` on `helpers::SlowSigner` |
| Arrival | 200 concurrent `JoinSet` tasks, `tokio` multi-thread 8 workers |
| DB | on-disk temp file, production `SlashingDb::open` |
| Pragmas in force | `journal_mode=WAL`, `synchronous=EXTRA`, `fullfsync=ON` (macOS) |
| Policy | `SigningGate` `Fixed(DiscardStagedRow)` |
| Group commit | default **50** / **1 ms** |

### Metric windows in force (both series)

`SlashableSignSession::reserve_then_sign` (`crates/signer/src/core.rs`):

1. **Kept series** `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}`:
   reserve-entry (includes queue wait) → sign-return. Still contains the 200 ms
   injected sign (VD-5.2).
2. **Reserve-only series** `rvc_slashing_reserve_tx_hold_duration_ms{kind="attestation"}`:
   reserve-entry → COMMIT. This is the quantity group commit shortens.

---

## Results — three warm runs + median

All three judgment runs: **200 / 200 successes**, **0 failures**,
`tx_hold_count = 200`, `reserve_tx_hold_count = 200`.

`effective_concurrency = keys × injected_ms / total_wall_ms`.

### Client wall (`sign_attestation_data` call)

| Run | Start (UTC) | total_wall_ms | p50 | p95 | p99 | max | effective_conc. |
|---|---|---:|---:|---:|---:|---:|---:|
| 4 | 16:40:12Z | 242.307 | 238.702 | 240.278 | 240.590 | 240.777 | 165.080 |
| 5 | 16:40:13Z | 243.631 | 239.053 | 239.896 | 241.669 | 241.715 | 164.183 |
| 6 | 16:40:14Z | 243.149 | 240.415 | 241.800 | 241.907 | 241.911 | 164.508 |
| **median** | | **243.149** | **239.053** | **240.278** | **241.669** | **241.715** | **164.508** |

Post-ADR-005 median total wall was **1 128.463 ms**. Post-group-commit is
**~4.6×** shorter. That is "got faster." It is **not** X6.

### `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}` (kept window)

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 4 | 237.966 | 237.966 | 240.087 | 240.355 | 47152.691 | 235.763 |
| 5 | 235.709 | 237.829 | 237.829 | 237.829 | 47339.594 | 236.698 |
| 6 | 236.624 | 236.624 | 238.885 | 238.885 | 47345.184 | 236.726 |
| **median** | **236.624** | **237.829** | **238.885** | **238.885** | **47339.594** | **236.698** |

This window still contains the 200 ms injected sign, so it **cannot** sit under
19.995 ms at A-9 (VD-5.2).

### `rvc_slashing_reserve_tx_hold_duration_ms{kind="attestation"}` (reserve-only)

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 4 | 22.030 | 22.030 | 22.030 | 22.030 | 4406.095 | 22.030 |
| 5 | 24.070 | 24.070 | 24.070 | 24.070 | 4720.444 | 23.602 |
| 6 | 23.380 | 23.380 | 24.682 | 24.682 | 4681.141 | 23.406 |
| **median** | **23.380** | **23.380** | **24.070** | **24.070** | **4681.141** | **23.406** |

Shape is no longer a 200-step serialized queue. With `batch_size=50`, a 200-key
wave is **four** `COMMIT`s. Implied per-batch cost:

```text
T_batch ≈ median_p99 / (200 / 50) = 24.070 / 4 = 6.018 ms
```

That is one fullfsync plus the 50 in-txn rule checks / INSERTs, not a
single-row 4.5 ms quantum.

### Achieved concurrency

| Quantity | Post-ADR-005 (5m) | This tree | How measured |
|---|---|---|---|
| **achieved_concurrency** | **49** | **200** (all three runs) | peak overlapping `SlowSigner::sign` calls |
| **effective_concurrency** | **35.446** | **164.508** | `200 × 200 / total_wall_ms` |
| total wall | **1 128.463 ms** | **243.149 ms** | median |

Signs now overlap fully (200 in flight). The reserve queue is four group
commits, not 200 fsyncs.

### Reproducibility

Reserve-tx p99 range 22.030–24.682 ms →
**(max − min) / min = 12.0 %**. Under the 20 % reopen threshold. Kept-window
p99 range 237.829–240.087 ms → **1.0 %**.

A **cold first invocation** after compile (run 1, not in the median) measured
reserve-tx p99 **33.028 ms**. Do not mix it with the warm set.

---

## Per-sign budget (A-9) — X6 judgment

Same constants as the baselines:

```text
per_sign_budget_ms = attestation_window_ms / N
                   = 3999 / 200
                   = 19.995 ms
```

| Check | Yardstick | Median measured | Met? |
|---|---:|---:|---|
| Kept-window p99 vs per-sign budget | **19.995 ms** | **238.885 ms** | **no** (contains the 200 ms sign) |
| Reserve-tx p99 vs per-sign budget | **19.995 ms** | **24.070 ms** | **no** (~1.20×) |
| No single kept-window hold vs sign timeout | **4000 ms** | max **240.355 ms** | **yes** |
| 200 keys completable in one 3999 ms window | **3999 ms** total wall | **243.149 ms** | **yes** — **not X6** |
| Zero missed attestation deadlines | **0** failures | **0** (200/200) | **yes** |

**X6 is unmet.** Honest ceiling: reserve-tx p99 **24.070 ms** (warm median)
on this host / `test` profile at `batch_size=50`. Cold first-invocation
ceiling **33.028 ms**.

The 3999 ms *window* is cleared (total wall ~243 ms). That is operational
capacity under A-9, not the M3 p99 budget.

---

## Next wall — remaining group-commit fsyncs

Pragmas were **not** changed. The remaining serialized work is **four**
durable `COMMIT`s per 200-key wave (`200 / 50`). Implied per-batch **~6.0 ms**
is still a fullfsync plus the batch's SQL.

To put queued reserve-tx p99 under 19.995 ms without weakening durability:

- raise `group_commit_batch_size` toward the wave size (one `COMMIT` / wave
  would be ~6 ms on this host), **or**
- shrink per-batch SQL (not measured to bind separately from fsync).

**Do not** lower `synchronous` / `fullfsync`. That is out of scope and would
convert a crash into a lost record.

---

## Side-by-side

| Series | Post-ADR-005 median (`b68d32b`) | Scale median (`41e7646`) | This tree median | X6 vs 19.995 ms |
|---|---|---|---|---|
| kept-window p99 | **1 119.528 ms**; conc. **49** | **1 131.255 ms**; conc. **45** | **238.885 ms**; conc. **200** | **no** (contains 200 ms sign) |
| reserve-tx p99 | **917.025 ms** | **929.660 ms** | **24.070 ms** | **no** (~1.20×) |
| total wall | **1 128.463 ms** | **1 140.654 ms** | **243.149 ms** | n/a |
| missed deadlines | 0 | 0 | **0** | — |

---

## Reconcile failures (A-5.5)

| Run | deleted | not_applicable | **failed** |
|---|---:|---:|---:|
| 4 | 0 | 0 | **0** |
| 5 | 0 | 0 | **0** |
| 6 | 0 | 0 | **0** |

---

## Rollback plan (X7 style)

Reverting group commit is safe **in the slashing direction** and is a
**single-commit** revert (NFR-4). It is **not** "revert and ship" without
re-running proofs.

| Item | Statement |
|---|---|
| **Revert this change** | The commit that lands #205 on `feature/205-slashing-db-group-commit` (or `git revert` that commit once it exists). Restores per-reserve `BEGIN IMMEDIATE` + `COMMIT`. |
| **What comes back** | Each `reserve_*` is again its own durable transaction. `reserve_then_sign` and ADR-005 stay. Operator knobs disappear. |
| **Slashing direction** | Fail-safe. More fsyncs, never a signature released without a committed row. No committed signature becomes unrecorded. |
| **Schema / data** | **Unchanged.** Group commit writes the same attestation/block tables. **No migration.** |
| **EIP-3076 vectors** | Necessary and **insufficient**. They pass identically (VD-S3). |
| **Must re-run (all three proof surfaces)** | `crates/slashing/tests/reserve_concurrency.rs`; `crates/signer/tests/retain_on_ambiguity_matrix.rs`; `crates/signer/tests/reserve_cancellation.rs`. Plus `crates/slashing/tests/group_commit.rs` (deleted with the revert). |
| **Revert shape** | One commit / one PR. Do not fold unrelated work (NFR-4). |
| **After revert** | Re-record M3 against [`m3-post-adr005.md`](./m3-post-adr005.md). Expect reserve-tx p99 to climb back toward ~900 ms and concurrency to fall from 200 toward ~49. |

---

## Honest scope limit (X8)

**This does not deliver G6 on the VC path.**
`crates/rvc/src/orchestrator/attestation.rs` remains a sequential
`for duty in duties { … .await }` loop. 200 keys × 200 ms = 40 s with a free
DB. This measurement is `signer-server` / `SigningGate` only.

---

## Verbatim harness JSON (judgment set)

### Run 4

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
  "effective_concurrency": 165.080,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 242.307,
  "wall_ms": { "p50": 238.702, "p95": 240.278, "p99": 240.590, "max": 240.777 },
  "tx_hold_ms": { "p50": 237.966, "p95": 237.966, "p99": 240.087, "max": 240.355, "count": 200, "sum": 47152.691 },
  "reserve_tx_hold_ms": { "p50": 22.030, "p95": 22.030, "p99": 22.030, "max": 22.030, "count": 200, "sum": 4406.095 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```

### Run 5

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
  "effective_concurrency": 164.183,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 243.631,
  "wall_ms": { "p50": 239.053, "p95": 239.896, "p99": 241.669, "max": 241.715 },
  "tx_hold_ms": { "p50": 235.709, "p95": 237.829, "p99": 237.829, "max": 237.829, "count": 200, "sum": 47339.594 },
  "reserve_tx_hold_ms": { "p50": 24.070, "p95": 24.070, "p99": 24.070, "max": 24.070, "count": 200, "sum": 4720.444 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```

### Run 6

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
  "effective_concurrency": 164.508,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 243.149,
  "wall_ms": { "p50": 240.415, "p95": 241.800, "p99": 241.907, "max": 241.911 },
  "tx_hold_ms": { "p50": 236.624, "p95": 236.624, "p99": 238.885, "max": 238.885, "count": 200, "sum": 47345.184 },
  "reserve_tx_hold_ms": { "p50": 23.380, "p95": 23.380, "p99": 24.682, "max": 24.682, "count": 200, "sum": 4681.141 },
  "reconcile_total": { "kind": "attestation", "deleted": 0, "not_applicable": 0, "failed": 0 }
}
```
