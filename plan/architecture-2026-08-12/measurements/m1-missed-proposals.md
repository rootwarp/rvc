# M1 baseline — missed-proposal rate under injected BN duty-fetch latency

Phase 0 / **ARCH-7c** recording of the **ARCH-7b** harness result.
Metric: PRD **M1** — missed-proposal rate under injected BN latency (duty-fetch stall × warm/cold duty cache).

> **Expected at baseline:** ~100 % miss under a long cold-cache duty stall is **by construction of PB-A1** (pre-proposal `fetch_epoch_duties` runs before `maybe_propose_block`). Recording a bad number is the Phase-0 deliverable. **Owning fix:** **ADR-004 / Phase 3** (target: **0 missed proposals** with duty fetches stalled the full 60 s). This is **not** a Phase-0 failure.

---

## Harness

| Field | Value |
|---|---|
| **Harness commit** | `92d9bbde0aedec10dce43db20fd8c51bea8dd8e2` (`test(rvc): add proposal miss-rate harness under duty-fetch stall`) |
| **Source** | `crates/rvc/tests/proposal_under_duty_stall.rs` |
| **Instrument** | ARCH-7b `measure_miss_rate_under_stalled_duty_fetch` + matrix in `test_records_missed_proposal_rate_under_stall` |
| **Exact command** | `cargo test -p rvc --test proposal_under_duty_stall -- --nocapture --test-threads=1` |

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

| Parameter | Value |
|---|---|
| Stall injection | `DutyStallBeacon` delays **only** duty endpoints: `get_attester_duties`, `get_proposer_duties`, `post_sync_committee_duties` |
| Stall matrix | `{0 s, 10 s, 60 s}` per duty call |
| Non-duty BN paths | Fast (no stall) — `get_block_root`, produce/publish path |
| Duty-fetch timeout | harness `OperationTimeouts.duty_fetch = 10 s` (so a 60 s sleep hits timeout; 10 s sleep can still return duties) |
| Clock | `MockSlotClock` + `tokio` `start_paused = true` (virtual multi-second stalls; not wall-clock) |
| Sample size | `MATRIX_SAMPLE_SLOTS = 32` proposal slots per matrix cell (plan ≥ 32) |
| Slot sample | starts at slot 65, **skips epoch boundaries** (`slot % 32 == 0`) |

### Cache condition (M1 axis)

**Duty-cache** condition on `DutyTracker` (not the M2 histogram `cache=` label — see harness module docs):

| Label | Meaning |
|---|---|
| **cold** | empty duty caches at boot — slot loop must BN-fetch before propose |
| **warm** | attester/proposer/sync caches pre-seeded — duty-stall inject has no effect |

---

## Results

### Primary matrix (miss rate)

Each cell: `n = 32` expected proposals. Miss rate = `(expected − published) / expected`.

#### Run 1

| Duty cache | Stall | Expected | Published | Missed | Miss rate |
|---|---:|---:|---:|---:|---:|
| cold | 0 s | 32 | 32 | 0 | **0.0 %** |
| warm | 0 s | 32 | 32 | 0 | **0.0 %** |
| cold | 10 s | 32 | 32 | 0 | **0.0 %** |
| warm | 10 s | 32 | 32 | 0 | **0.0 %** |
| cold | **60 s** | 32 | 0 | 32 | **100.0 %** ← RED baseline |
| warm | 60 s | 32 | 32 | 0 | **0.0 %** ← harness contrast |

#### Run 2 (independent re-run)

| Duty cache | Stall | Expected | Published | Missed | Miss rate |
|---|---:|---:|---:|---:|---:|
| cold | 0 s | 32 | 32 | 0 | **0.0 %** |
| warm | 0 s | 32 | 32 | 0 | **0.0 %** |
| cold | 10 s | 32 | 32 | 0 | **0.0 %** |
| warm | 10 s | 32 | 32 | 0 | **0.0 %** |
| cold | **60 s** | 32 | 0 | 32 | **100.0 %** |
| warm | 60 s | 32 | 32 | 0 | **0.0 %** |

**Tolerance agreement:** exact match on every cell (Δ miss rate = 0). Stated re-run tolerance: **±0 slots / ±0.0 %** on this deterministic virtual-time harness (any non-zero published under cold×60 s, or any miss under warm×60 s / 0 s, is a harness regression — not measurement noise).

### Per-slot miss indicators (percentiles)

M1 is a **rate**. Treating each proposal slot as a Bernoulli miss indicator (`1` = missed, `0` = published), the distribution within a cell is degenerate:

| Cell | n | min | p50 | p90 | p99 | max | mean (= miss rate) |
|---|---:|---:|---:|---:|---:|---:|---:|
| cold × 60 s (RED) | 32 | 1 | 1 | 1 | 1 | 1 | 1.00 |
| warm × 60 s | 32 | 0 | 0 | 0 | 0 | 0 | 0.00 |
| cold × 0 s | 32 | 0 | 0 | 0 | 0 | 0 | 0.00 |
| warm × 0 s | 32 | 0 | 0 | 0 | 0 | 0 | 0.00 |
| cold × 10 s | 32 | 0 | 0 | 0 | 0 | 0 | 0.00 |
| warm × 10 s | 32 | 0 | 0 | 0 | 0 | 0 | 0.00 |

Same table for both runs.

### Control + attribution (same command)

| Test | Observation |
|---|---|
| `test_no_missed_proposal_without_stall` | cold duty-cache × 0 s × n=32 → published=32, miss_rate=0.0 % |
| `test_cold_cache_slot_is_measured_separately` | cold_offset_samples=2, warm_offset_samples=1 over slots [65,66,67]; 0 s stall fully publishes |

---

## Interpretation

Under a **cold duty cache** and a **60 s duty-fetch stall**, the orchestrator spends the duty-fetch timeout budget on pre-proposal `fetch_epoch_duties` and never reaches a successful produce/publish path for the proposer’s duty — **32/32 missed proposals (100 %)** over the plan sample. A **warm** duty cache fully masks the same 60 s stall (**0 % miss**), proving the harness attributes misses to **cache/ordering**, not a broken produce path. The 10 s stall cell remains green because the injected sleep equals the per-call duty-fetch timeout and duties can still return before the path gives up.

This **100 % cold×60 s miss rate is the Phase-0 baseline expected by construction of PB-A1**. It is **not** a Phase-0 bug. Phase 3 (**ADR-004**) owns driving M1 to **0 missed proposals** with duty fetches stalled the full 60 s (plus the 80 s envelope criteria in the phase plan). NFR-1 and C6 use this file as the pre-fix reference: any Phase-3 acceptance run is judged against these numbers, not against a green CI log that expired.

---

## Re-run

See [`README.md`](./README.md). One command:

```bash
cargo test -p rvc --test proposal_under_duty_stall -- --nocapture --test-threads=1
```

Look for `ARCH-7b M1 cell` / `ARCH-7b RED baseline` lines.
