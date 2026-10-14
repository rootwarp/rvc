# M3 baseline — slashing tx-hold under the ARCH-5a load profile

ARCH-5b recording of the **ARCH-5a** `signer-server` harness (A-9: 200 keys × 200 ms
injected BLS latency). Metric: PRD **M3** —
`rvc_signer_slashing_tx_hold_duration_ms` p99, plus the observation-window
decision required by **VD-5.2**.

> **This is a baseline, not an acceptance run.** X6 is judged by **ARCH-5m**
> against this file. The numbers below are the pre-ADR-005 hold-across-the-sign
> world. They are expected to miss the derived per-sign budget on the current
> series — that series still contains the sign.

Plan-directory name keeps the architecture baseline SHA `0ae9a09` (v0.7.0). The
harness did not exist at that commit; the run is on develop after ARCH-5a. The
metric window is the same as `0ae9a09` (verified below).

This file does **not** change production source. The reserve-tx series it
decides to add is **ARCH-5l** work (definition may land in **ARCH-5f**).

---

## Harness

| Field | Value |
|---|---|
| **Architecture baseline** | `0ae9a09badea7dcd4fd28e943003cef87e714f9f` (v0.7.0) |
| **Measured commit** | `11bb5696b6025ee8dd19b17a2c1dbbf066e25c2b` (`test(signer-server): add slashing hold-duration load harness`) |
| **Why not `0ae9a09` itself** | ARCH-5a is the instrument. `0ae9a09` has the same `tx_start` → `tx_hold_ms` window (`crates/signer/src/core.rs` then `:265` / `:288`; now `:359` / `:382`) but no load driver. Phase 1 ADR-006 (`fcdb5b1`, `fc2bc98`) is on this tree; it moved audit emission off the mutex and does not change the hold window. Later `9e2e9d4` (ARCH-5c fold) and `1637781` (ARCH-5n lock-map bound) also leave the window unchanged. |
| **Source** | `crates/signer-server/tests/load_profile.rs` (`test_load_profile_reports_p99_above_serialized_floor`, `#[ignore]`) |
| **Fixture** | `helpers::make_load_fixture` — 200 EIP-2333 keys, `SlowSigner` (async 200 ms sleep), real `SlashingDb::open` temp file |
| **Path** | `SignerServiceImpl::sign_attestation_data` → `SigningGate::sign_attestation` (`TimeoutPolicy::DiscardStagedRow`, A-5.5). **Not** the VC orchestrator (X8 / A-5.4). |
| **Instrument** | process-local `RVC_SIGNER_SLASHING_TX_HOLD_DURATION_MS{kind="attestation"}` via `get_sample_count` / `get_sample_sum` (exact sum, not bucket quantile) |
| **Sign timeout** | `Duration::from_secs(4)` at the gate (`DEFAULT_SIGN_TIMEOUT`). Wraps the BLS call only; it does **not** bound mutex wait. No run hit it (200/200 successes). |

### Exact invocation (full A-9 profile)

JSON on stdout, and to `--output` (libtest; nextest 0.9 does not forward that arg):

```bash
cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
  --exact test_load_profile_reports_p99_above_serialized_floor \
  -- --output /tmp/arch-5b-m3/runN.json
```

nextest (summary on stdout only):

```bash
cargo nextest run -p rvc-signer-server --run-ignored ignored-only --no-capture \
  -E 'test(test_load_profile_reports_p99_above_serialized_floor)'
```

This recording used the `cargo test` form, three independent process invocations,
outputs at `/tmp/arch-5b-m3/run{1,2,3}.json` (not checked in). Full 200×200 ms × 3
completed in this environment (~42 s wall each); no reduced calibration was
required.

### Hardware / toolchain

| Field | Value |
|---|---|
| Host | Apple M4 Pro, arm64, 14 cores, 24 GB RAM |
| OS | macOS 26.6.1 (Darwin 25.6.0 / Build 25G76) |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| cargo | 1.97.1 (c980f4866 2026-06-30) |
| nextest | 0.9.85 (available; not used for the JSON runs) |
| Profile | `test` (unoptimized + debuginfo) |
| Measured | 2026-08-17T17:24:03Z – 2026-08-17T17:26:10Z (UTC) |

### Injected latency profile

| Parameter | Value |
|---|---|
| Keys | **200** (A-9), distinct pubkeys, one attestation each |
| Injected BLS latency | **200 ms** `tokio::time::sleep` on `helpers::SlowSigner` (async side, so `Handle::block_on(timeout(...))` observes it) |
| Arrival | 200 concurrent `JoinSet` tasks, `tokio` multi-thread 8 workers |
| DB | on-disk temp file, production `SlashingDb::open` |
| Pragmas in force | `journal_mode=WAL`, `synchronous=EXTRA`, `fullfsync=ON` (macOS) |
| Policy | `SigningGate` `Fixed(DiscardStagedRow)` |

### Metric window in force (current series)

`SlashableSignSession::stage_then_sign` (`crates/signer/src/core.rs`):

1. `tx_start = Instant::now()` **before** `stage()` (`:359`).
2. `stage()` acquires `parking_lot::Mutex<Connection>` and `BEGIN IMMEDIATE`.
3. `tx_hold_ms` is taken **after** the sign future returns (`:382`), then
   `on_tx_hold_ms` on every terminal branch (commit, discard, timeout, blocked).

So the series is **stage-entry (includes mutex wait) → sign-return**. It is
**not** a lock-hold-excluding-the-sign metric. Histogram buckets in
`crates/metrics/src/definitions.rs` stop at 5 s; values above that still add to
`sample_sum`. Do **not** reconstruct this baseline from a Prometheus
`histogram_quantile` scrape — every sample here landed in `+Inf`.

---

## Results — three runs + median

All three runs: **200 / 200 successes**, **0 failures**,
`achieved_concurrency = 1` (`SlowSigner::max_in_flight`),
`tx_hold_count = 200`.

`effective_concurrency = keys × injected_ms / total_wall_ms`.
Serialized floor used by the harness: `keys × 200 ms / achieved_concurrency`
= **40 000 ms** (p99 must clear that minus one injected quantum).

### Client wall (`sign_attestation_data` call)

| Run | Start (UTC) | total_wall_ms | p50 | p95 | p99 | max | effective_conc. |
|---|---|---:|---:|---:|---:|---:|---:|
| 1 | 17:24:03Z | 41792.821 | 21101.370 | 39914.486 | 41583.209 | 41790.267 | 0.957 |
| 2 | 17:24:45Z | 41883.369 | 21109.271 | 39994.073 | 41670.817 | 41880.936 | 0.955 |
| 3 | 17:25:28Z | 41845.127 | 21119.864 | 39951.190 | 41632.299 | 41842.191 | 0.956 |
| **median** | | **41845.127** | **21109.271** | **39951.190** | **41632.299** | **41842.191** | **0.956** |

### `rvc_signer_slashing_tx_hold_duration_ms{kind="attestation"}`

| Run | p50 | p95 | p99 | max | sum | mean (sum/n) |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 21097.203 | 39909.728 | 41578.253 | 41785.414 | 4198873.176 | 20994.366 |
| 2 | 21104.376 | 39988.298 | 41665.091 | 41875.589 | 4204217.452 | 21021.087 |
| 3 | 21114.745 | 39945.314 | 41624.385 | 41835.316 | 4202061.288 | 21010.306 |
| **median** | **21104.376** | **39945.314** | **41624.385** | **41835.316** | **4202061.288** | **21010.306** |

### Achieved concurrency

| Quantity | Value | How measured |
|---|---|---|
| **achieved_concurrency** | **1** (all three runs) | peak overlapping `SlowSigner::sign` calls |
| **effective_concurrency** | **0.956** (median) | `200 × 200 / total_wall_ms` |
| Implied per-sign serial cost | **209.226 ms** | median `total_wall_ms / 200` |
| Injected / overhead | 200 ms / **~9.2 ms** | remainder is stage + `BEGIN IMMEDIATE` + rule check + INSERT/COMMIT + `fullfsync` + debug scheduling |

`achieved_concurrency = 1` is the harness non-vacuity result: the slashing
connection mutex serialises the sign. ARCH-5m must compare against the same
definition (`SlowSigner::max_in_flight`), not against tokio worker count.

### Reproducibility

tx-hold p99 range 41578.253–41665.091 ms →
**(max − min) / min = 0.209 %**, well under the ARCH-5b 20 % reopen threshold.
ARCH-5a is **not** reopened. Tolerance for a re-run on this host / `test`
profile: **±5 %** on p99 and total wall (far looser than observed; leaves room
for thermal / fsync noise). A p99 spread **> 20 %** is a harness defect, not
something to average away.

---

## Per-sign budget (A-9), arithmetic shown

M3's target is p99 **below the per-sign budget implied by 200 keys inside one
attestation window**, and no single hold above the remote-signer timeout.
The budget is derived, not picked.

Constants (mainnet, in-tree):

| Symbol | Value | Source |
|---|---|---|
| `SECONDS_PER_SLOT` | 12 | `crates/eth-types/src/lib.rs` |
| `slot_duration_ms` | `12 × 1000 = 12_000` | |
| `ATTESTATION_DUE_BPS` | 3333 | `crates/timing/src/lib.rs` |
| `BASIS_POINTS` | 10_000 | same |
| `attestation_window_ms` | `due_ms(3333, 12_000) = 3333 × 12_000 / 10_000 = **3999**` | VD-S7; doctest `due_ms(ATTESTATION_DUE_BPS, 12000) == 3999` |
| `N` (A-9) | **200** keys | `prd.md` A-9 |
| `DEFAULT_SIGN_TIMEOUT` | **4000 ms** | `crates/signer/src/core.rs` (the "no single hold exceeds the remote-signer timeout" bound) |

```text
per_sign_budget_ms = attestation_window_ms / N
                   = 3999 / 200
                   = 19.995 ms
```

That is the X6 yardstick. It is **not** "got faster than this baseline."

| Check | Yardstick | Median measured (current series) | Met? |
|---|---:|---:|---|
| M3 p99 vs per-sign budget | **19.995 ms** | **41 624.385 ms** | **no** (~2081×) |
| No single hold vs sign timeout | **4000 ms** | max **41 835.316 ms** | **no** (queueing; timeout did not fire) |
| Signs completable in one window at this hold | `floor(3999 / 209.226) = **19**` | matches research V6 (~20 at 200 ms) | — |

The timeout miss is **by construction of the current window under contention**:
`tx_start` is before `stage()`'s mutex acquire, so the last waiter records
~200 × 200 ms of queue + sign. The 4000 ms timeout only wraps the BLS call.

Even **uncontended**, the current series cannot meet 19.995 ms while A-9 injects
200 ms of sign — the sign sits inside the window (VD-5.2). That is why a second
series is required before anyone can honestly tick X6.

---

## Observation-window decision (VD-5.2)

**Taken: the issue default. The run does not contradict it.**

1. **Keep** `rvc_signer_slashing_tx_hold_duration_ms` with the current window
   (stage-entry, including mutex wait → sign-return). Before/after stays
   comparable. Under this profile the contended p99 **will** move after
   ADR-005 (lock no longer spans the sign, so the ~41 s queue collapses toward
   ~200 ms + reserve queue). The *uncontended* observation stays ≈ injected
   sign time, so this series alone can never sit under 19.995 ms at A-9.
2. **Add** a second series for the **reserve transaction only**
   (mutex acquire → `COMMIT`). That is the quantity ADR-005 shortens.
   **Adding the series is ARCH-5l** (definition may be landed by ARCH-5f in the
   `// ── ADR-005 (Phase 5) ──` block of `crates/metrics/src/definitions.rs`).
   Recommended name, so 5f/5l do not diverge:
   `rvc_signer_slashing_reserve_tx_duration_ms{kind="block"|"attestation"}`.
   Observe it at reserve return (`ARCH-5i` / `ARCH-5l`). It does **not** exist
   on this tree; ARCH-5m's baseline column for it is **N/A**.
3. **Record X6 under both definitions.** Reporting only the redefined series
   would meet the milestone by renaming the ruler.

### Consequence for `crates/signer/tests/tx_hold_metric.rs`

Every assertion in that file binds to the **existing** series
`rvc_signer_slashing_tx_hold_duration_ms`. **None** binds to the reserve-tx
series. ARCH-5l must not retarget these tests.

| Test | Cycle | Series it binds to |
|---|---|---|
| `test_metric_recorded_on_stage_commit` | stage → **commit** (attestation, success) | **existing** `{kind="attestation"}` |
| `test_metric_recorded_on_stage_discard` | stage → **discard** (block, `KeyNotFound`) | **existing** `{kind="block"}` |
| `test_metric_recorded_on_stage_slashing_rejected` | stage **rejected** (DoubleVote; no sign) | **existing** `{kind="attestation"}` |

Keeping the current window is what lets this file stay green with **zero**
edits across 5i/5l (ARCH-5d/5i acceptance). A new reserve-tx test belongs next
to the new series, not as a rewrite of these three.

### What would have overturned the default

- Harness p99 spread > 20 % → reopen ARCH-5a (did not happen).
- `achieved_concurrency` consistently > 2 → mutex is not the wall; the
  serialized-floor assertion would have failed (it passed; concurrency = 1).
- Measured uncontended hold ≪ 200 ms → injector bypassed `spawn_blocking`
  (the 1-key test `test_slow_signer_delays_are_observed_through_the_blocking_bridge`
  already forbids that; this run's ~9 ms overhead on top of 200 ms agrees).

None of those obtained.

---

## How ARCH-5m should use this file

Cite **this file** and measured commit `11bb5696b6025ee8dd19b17a2c1dbbf066e25c2b`.
Re-run the same invocation, three times, same key count / injected latency /
pragmas / `test` profile (or record a profile change explicitly).

| Series | Baseline (this file) | After ADR-005 (expected shape) | X6 vs 19.995 ms |
|---|---|---|---|
| `rvc_signer_slashing_tx_hold_duration_ms` (kept window) | p99 **41 624.385 ms** (median); concurrency **1** | contended p99 should fall toward **~200 ms + reserve queue**; `achieved_concurrency` should rise if signs overlap | still **cannot** pass while A-9 injects 200 ms |
| reserve-tx only (5l) | **N/A** (not instrumented) | mutex acquire → COMMIT; fsync-bound (`EXTRA` + `fullfsync`) | **this** is the series that can pass or fail X6 honestly |

If post-change reserve-tx p99 still exceeds 19.995 ms, that is A-5.9 (group
commit), not a silent redefinition of M3.

VC-path ceiling (X8) is **out of scope** here: 200 sequential 200 ms signs are
40 s with a free DB. This baseline is `signer-server` only.

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
  "achieved_concurrency": 1,
  "effective_concurrency": 0.957,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 41792.821,
  "wall_ms": { "p50": 21101.370, "p95": 39914.486, "p99": 41583.209, "max": 41790.267 },
  "tx_hold_ms": { "p50": 21097.203, "p95": 39909.728, "p99": 41578.253, "max": 41785.414, "count": 200, "sum": 4198873.176 }
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
  "achieved_concurrency": 1,
  "effective_concurrency": 0.955,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 41883.369,
  "wall_ms": { "p50": 21109.271, "p95": 39994.073, "p99": 41670.817, "max": 41880.936 },
  "tx_hold_ms": { "p50": 21104.376, "p95": 39988.298, "p99": 41665.091, "max": 41875.589, "count": 200, "sum": 4204217.452 }
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
  "achieved_concurrency": 1,
  "effective_concurrency": 0.956,
  "successes": 200,
  "failures": 0,
  "total_wall_ms": 41845.127,
  "wall_ms": { "p50": 21119.864, "p95": 39951.190, "p99": 41632.299, "max": 41842.191 },
  "tx_hold_ms": { "p50": 21114.745, "p95": 39945.314, "p99": 41624.385, "max": 41835.316, "count": 200, "sum": 4202061.288 }
}
```
