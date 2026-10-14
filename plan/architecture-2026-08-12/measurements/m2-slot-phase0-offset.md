# M2 baseline — slot phase-0 start offset (`rvc_slot_phase_block_start_offset_ms`)

Phase 0 / **ARCH-7c** recording of the **ARCH-7a** instrument as exercised by the **ARCH-7b** multi-slot harness and the ARCH-7a coordinator tests.
Metric: PRD **M2** — p99 offset from slot start to entry of `maybe_propose_block`.

> Phase 3 (ADR-004) target: **p99 ≤ 1,000 ms warm** / **≤ 2,000 ms cold** (A-5). Baselines below are pre-fix measurements; separate warm and cold p99 are recorded so each target is individually falsifiable.

---

## Harness

| Field | Value |
|---|---|
| **Harness commit** | `92d9bbde0aedec10dce43db20fd8c51bea8dd8e2` |
| **Metric** | `rvc_slot_phase_block_start_offset_ms{cache="warm"\|"cold"}` (`crates/metrics/src/definitions.rs`) |
| **Record site** | `DutyOrchestrator::record_phase_block_start_offset` immediately before `maybe_propose_block` |
| **Primary multi-slot source** | `crates/rvc/tests/proposal_under_duty_stall.rs` (ARCH-7b) |
| **Instrument credibility source** | `crates/rvc/src/orchestrator/coordinator/tests/phase_block_offset.rs` (ARCH-7a) |

### Exact commands

```bash
# Multi-slot warm/cold sample counts + MockSlotClock offsets (M1 harness co-measures M2)
cargo test -p rvc --test proposal_under_duty_stall -- --nocapture --test-threads=1

# ARCH-7a instrument tests (incl. SystemSlotClock + injected BN duty delay)
cargo test -p rvc --lib orchestrator::coordinator::tests::phase_block_offset -- --nocapture --test-threads=1
```

### Hardware / toolchain

| Field | Value |
|---|---|
| Host | Apple M4 Pro, arm64, 14 cores, 24 GB RAM |
| OS | macOS 26.6.1 (Darwin 25.6.0) |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| cargo | 1.97.1 (c980f4866 2026-06-30) |
| Profile | `test` (unoptimized + debuginfo) |
| Measured | 2026-08-12 (UTC) |

### Injected latency profile

Two distinct measurement surfaces (do not join casually):

| Surface | Latency profile | Clock |
|---|---|---|
| **A — multi-slot M1 harness** | duty stall ∈ {0 s, 10 s, 60 s} on duty endpoints only; harness advances MockSlotClock by **9 s** into each slot (`advance_time(9)`) so attestation-phase waits are zero | `MockSlotClock` + `start_paused` |
| **B — ARCH-7a credibility** | wiremock duty endpoints delayed by **D = 2 s** each; genesis positioned near slot start | `SystemSlotClock` (wall clock) |

### Cache condition (M2 histogram label)

| Label | Meaning |
|---|---|
| **cold** | first slot after boot, or the slot after a `key_gen` duty-cache invalidation |
| **warm** | steady-state slots after the cold flag clears |

This is **not** the M1 duty-cache warm/cold axis. A warm duty-cache multi-slot cell still records **1 cold** (boot) + **31 warm** offset samples for n=32.

### Sample count

| Surface | cold samples / cell | warm samples / cell | notes |
|---|---:|---:|---|
| A — each M1 matrix cell (n=32) | 1 | 31 | observed every cell both runs |
| A — cold-vs-warm attribution (3 slots) | 2 | 1 | boot cold, steady warm, post-`key_gen` cold |
| B — `test_offset_reflects_pre_proposal_work` | ≥ 1 | (run-dependent) | wall-clock duty delay path |

---

## Results — Surface A (MockSlotClock multi-slot harness)

Offset is computed as `(current_time_secs − slot_start_time) × 1000` on the slot clock. With second-resolution MockSlotClock and `advance_time(9)`, every sample is the discrete value **9000 ms**. Duty-stall inject advances **tokio virtual time** only; it does **not** move MockSlotClock, so stall magnitude does **not** appear in these offsets (M1 miss rate is the stall-sensitive instrument on this surface).

Histogram API exposes `get_sample_sum` / `get_sample_count` (no raw sample export). Cell means were taken as `Δsum / Δcount` under the M1 harness lock; means of exactly 9000 with integer-second clock imply a degenerate distribution at 9000 ms.

### Run 1 & Run 2 (identical)

Per matrix cell (all six stall×duty-cache cells):

| Label | n | sum (ms) | mean (ms) | min | p50 | p90 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **cold** | 1 | 9000 | 9000 | **9000** | **9000** | **9000** | **9000** | **9000** |
| **warm** | 31 | 279000 | 9000 | **9000** | **9000** | **9000** | **9000** | **9000** |

**Separate warm / cold p99 (Surface A):**

| | cold p99 | warm p99 |
|---|---:|---:|
| Run 1 | **9000 ms** | **9000 ms** |
| Run 2 | **9000 ms** | **9000 ms** |

**Tolerance agreement:** exact match (Δ = 0 ms). Stated re-run tolerance on Surface A: **±0 ms** (deterministic mock clock). Any mean ≠ 9000 under the current harness fixture means `advance_time(9)` or the second-resolution clock path changed.

---

## Results — Surface B (SystemSlotClock + wall-clock duty delay)

Proves the instrument captures pre-proposal work (ARCH-7a second RED): mock BN duty delay **D = 2 s** per delayed duty response; assert mean cold offset ≥ D.

| Run | D (ms) | cold_added | cold sum_delta (ms) | cold mean (ms) | warm_added |
|---:|---:|---:|---:|---:|---:|
| 1 | 2000 | 1 | 8000 | **8000** | 1 |
| 2 | 2000 | 1 | 8000 | **8000** | 1 |

With a single cold sample, the distribution is a point mass:

| Label | n | min | p50 | p90 | p99 | max |
|---|---:|---:|---:|---:|---:|---:|
| cold (Surface B, D=2 s) | 1 | 8000 | 8000 | 8000 | **8000** | 8000 |

`warm_added=1` on this test is process/registry concurrent observation under the lib test binary (global histogram); the cold mean is isolated via before/after sum delta on `cache=cold`.

**Tolerance agreement:** exact match across both runs (Δ mean = 0 ms). Stated re-run tolerance on Surface B: **±2000 ms** on cold mean (wall-clock scheduling + sequential multi-endpoint delay stacking; lower bound remains ≥ D = 2000 ms by test assertion).

Buckets (for re-scrape if `/metrics` is exported in a longer run):  
`5, 10, 25, 50, 100, 250, 500, 1000, 2000, 4000, 8000, 12000, 20000, 30000, 60000` ms — top bucket 60 s so a full 12 s slot and beyond is not clipped.

---

## Interpretation

**Surface A** records that, under the ARCH-7b multi-slot fixture, phase-0 entry sits at a **fixed 9000 ms** mock-clock offset (harness positions past 2/3 of the 12 s slot so attestation waits are zero). Warm and cold **labels** both fire with the expected sample split (1 cold boot + 31 warm), but the **numeric** offset does not encode duty-fetch cost on MockSlotClock — M1’s miss rate is the stall-sensitive co-metric on that surface.

**Surface B** records that with a real wall clock and a **2 s** per-endpoint duty delay near slot start, the cold offset mean is **8000 ms** (≥ D), so the histogram is a credible witness of pre-proposal work ordering (PB-A1). That large cold offset is the Phase-0 “bad baseline” shape Phase 3 is judged against once the slot loop is reordered (ADR-004).

**Phase 3 gates:** warm p99 ≤ **1000 ms**, cold p99 ≤ **2000 ms**. Surface A’s 9000 ms p99 is a **fixture position**, not a production steady-state claim — acceptance runs after ADR-004 must use a near-slot-start clock (SystemSlotClock / production) and report **separate** warm and cold p99 against the A-5 budgets. This file supplies the pre-fix numbers and the re-run commands so NFR-1 regressions are falsifiable.

---

## Re-run

See [`README.md`](./README.md). Percentiles above for Surface A follow from sum/count under a second-resolution degenerate distribution; if a future harness logs raw samples or scrapes histogram buckets, replace the percentile table with bucket-derived quantiles and keep the same tolerance section.
