# M1/M2 post-Phase-3 acceptance — proposal-first slot loop

ARCH-3k recording of the Phase-0 instrument (`rvc_slot_phase_block_start_offset_ms` + duty-endpoint stall) against the **reordered** slot loop (ADR-004 / ARCH-3i + C6 / ARCH-3j). Compared with the Phase-0 baselines in [`m1-missed-proposals.md`](./m1-missed-proposals.md) and [`m2-slot-phase0-offset.md`](./m2-slot-phase0-offset.md).

> **Targets (A-5 / Phase 3 exit):** **M1 = 0** missed proposals with duty fetches stalled 60 s (milestone) and 80 s (VD-35 envelope). **M2** p99 ≤ **1,000 ms** warm / ≤ **2,000 ms** cold, three scenarios (warm; cold post-boot; cold after `key_gen`). Cold cells must still **propose when a duty exists** (C6).

This file does **not** change slot-loop production order. It records the numbers.

---

## Harness

| Field | Value |
|---|---|
| **Base commit** | `56504314c5e45b82184fd840027d0e76753df4f5` (`develop` after 3i/3j/3f) |
| **Source** | `crates/rvc/tests/proposal_first_budget.rs` |
| **Instrument** | Same Phase-0 histogram: `RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS` recorded immediately before `maybe_propose_block`. Per-slot offset = Δsum / Δcount on `cache=warm` / `cache=cold`. |
| **Block-root stub** | `MockBeaconNodeClient::with_slot_aware_block_root` only (G-8). Local pin: `test_acceptance_harness_uses_a_slot_aware_block_root_stub`. |
| **Orchestrator** | Bare `tokio::spawn` (no `LocalSet`). |
| **Exact command** | `cargo nextest run -p rvc --test proposal_first_budget --no-capture` |

### Hardware / toolchain

| Field | Value |
|---|---|
| Host | Apple M4 Pro, arm64, 14 cores, 24 GB RAM |
| OS | macOS 26.6.1 (Darwin / Build 25G76) |
| rustc | 1.97.1 (8bab26f4f 2026-07-14) |
| cargo | 1.97.1 (c980f4866 2026-06-30) |
| nextest | 0.9.85 |
| Profile | `test` (unoptimized + debuginfo) |
| Measured | 2026-08-17T10:12:00Z (UTC) |

### Injected latency profile

| Parameter | Value |
|---|---|
| Clock | `MockSlotClock` + `tokio` `start_paused = true` (virtual stalls) |
| M1 stall, **warm** duty-cache | **all** duty endpoints (`get_attester_duties`, `get_proposer_duties`, `post_sync_committee_duties`) hang 60 s / 80 s |
| M1 stall, **cold** duty-cache | **epoch envelope** only: attester + sync hang 60 s / 80 s; proposer stays live so the ARCH-3j 500 ms cold fetch can still learn the duty (C6). VD-35's 80 s envelope is the hung `fetch_epoch_duties` × prefetch path in the post-duty window — it no longer sits in front of propose. |
| M2 budget cells | stall = 0; clock parked at **slot start** (not the Phase-0 `advance_time(9)` 9000 ms fixture) |
| Duty-fetch timeout | harness `OperationTimeouts.duty_fetch = 10 s` |
| Sample size | `MATRIX_SAMPLE_SLOTS = 32` proposal slots (skip epoch boundaries) |

### Cache axes (do not join)

| Axis | Warm | Cold |
|---|---|---|
| **M1 duty-cache** | attester/proposer/sync pre-seeded | empty at boot; C6 fetch must populate |
| **M2 histogram `cache=`** | steady-state slots after the boot flag clears | first slot after boot, or the slot after a `key_gen` invalidation |

---

## Results — M1 (missed proposals)

Each cell: `n = 32` expected proposals. Miss rate = `(expected − published) / expected`.

| Duty cache | Stall | Stall scope | Expected | Published | Missed | Miss rate |
|---|---:|---|---:|---:|---:|---:|
| warm | **60 s** | all duty endpoints | 32 | 32 | 0 | **0.0 %** |
| cold | **60 s** | epoch envelope (proposer live) | 32 | 32 | 0 | **0.0 %** |
| warm | **80 s** | all duty endpoints | 32 | 32 | 0 | **0.0 %** |
| cold | **80 s** | epoch envelope (proposer live) | 32 | 32 | 0 | **0.0 %** |

**Phase-0 contrast** ([`m1-missed-proposals.md`](./m1-missed-proposals.md)): cold × 60 s (all endpoints, including proposer) was **100 %** miss — `fetch_epoch_duties` ran *before* `maybe_propose_block`. After ADR-004 those fetches live in the post-duty window, so a 60 s / 80 s hang no longer drops the proposal.

A cold cell that also **stalls `get_proposer_duties`** still times out the 500 ms C6 fetch and misses (no duty learned). That is the C6 timeout path, not PB-A1. Acceptance therefore keeps proposer live on the cold cells so “propose when a duty exists” stays falsifiable.

**Tolerance:** deterministic virtual-time harness; re-run must match **±0 slots / ±0.0 %**.

---

## Results — M2 (phase-0 offset)

Offset is the Phase-0 instrument: `(current_time_secs − slot_start_time) × 1000` on `MockSlotClock`. Acceptance parks the clock at **slot start**, so the discrete second-resolution value is **0 ms** unless pre-proposal work advances the mock clock (it does not — duty stalls and the 500 ms C6 timeout move tokio virtual time only).

This is the same limitation recorded on Phase-0 Surface A; the difference is the **fixture position** (0 ms at t=0 vs 9000 ms after `advance_time(9)`). Entry to `maybe_propose_block` is witnessed by a histogram sample on every driven slot.

| Scenario | Label | n | min | mean | p99 | max | Budget | Pass |
|---|---|---:|---:|---:|---:|---:|---:|---|
| warm (steady-state after boot) | `cache=warm` | 31 | **0** | **0** | **0** | **0** | ≤ 1,000 ms | yes |
| cold after boot (one first-slot run × 32) | `cache=cold` | 32 | **0** | **0** | **0** | **0** | ≤ 2,000 ms | yes |
| cold after `key_gen` (invalidate before slots 2…32) | `cache=cold` | 31 | **0** | **0** | **0** | **0** | ≤ 2,000 ms | yes |

Published on every M2 cell: **32 / 32** (C6: cold boot and post-`key_gen` still propose when the BN serves a duty).

**Phase-0 contrast:** Surface A p99 was **9000 ms** (fixture). Surface B (SystemSlotClock + 2 s duty delay) cold mean was **8000 ms**. After proposal-first, epoch-duty delay is no longer on the pre-proposal path; the remaining pre-proposal work is parent-root walk-back plus an optional ≤ 500 ms proposer-only fetch, both inside the aggregate 1,000 ms deadline.

**Tolerance on this surface:** exact **0 ms** (deterministic mock clock at slot start). Any mean ≠ 0 means the clock was advanced before `record_phase_block_start_offset` or the instrument site moved.

---

## Behaviour-contract

`test_duties_performed_are_unchanged_by_the_reorder` (ARCH-3i) remains green. Which duties run is unchanged; only when they run changed.

---

## Re-run

```bash
cargo nextest run -p rvc --test proposal_first_budget --no-capture
```

Look for `ARCH-3k M1 cell` and `ARCH-3k M2` lines.

3i contract (must stay green):

```bash
cargo nextest run -p rvc -E 'test(test_duties_performed_are_unchanged_by_the_reorder)'
```
