# Architecture measurements (Phase 0 baselines + Phase 5 M3)

Checked-in baselines for success metrics that later phases must improve against.

- **M1 / M2 (Phase 0):** recorded under **ARCH-7c** on harness commit
  `92d9bbde0aedec10dce43db20fd8c51bea8dd8e2` (ARCH-7a metric + ARCH-7b harness).
- **M3 (Phase 5 entry E2):** recorded under **ARCH-5b** against the ARCH-5a
  `signer-server` load harness on develop `11bb569` (architecture baseline name
  `0ae9a09`). Gates every issue from `ARCH-5i` onward.
- **M3 post-ADR-005 (Phase 5 X6/X7/X8):** recorded under **ARCH-5m** on
  `b68d32b` against the same ARCH-5a profile. Cites the baseline measured
  commit `11bb5696b6025ee8dd19b17a2c1dbbf066e25c2b`.
- **M3 scale 200×200 ms (Phase 7 P1-15b):** recorded under **ARCH-7m** on
  `41e7646` against the same ARCH-5a profile. Cites
  [`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md) and
  [`m3-post-adr005.md`](./m3-post-adr005.md).
- **M3 post-group-commit (issue #205):** recorded on
  `feature/205-slashing-db-group-commit`. Cites
  [`m3-post-adr005.md`](./m3-post-adr005.md) and
  [`m3-scale-200keys-200ms.md`](./m3-scale-200keys-200ms.md).

| File | Metric | Role |
|---|---|---|
| [`m1-missed-proposals.md`](./m1-missed-proposals.md) | **M1** miss rate under duty-fetch stall | ~100 % cold×60 s miss is **expected**; ADR-004 / Phase 3 owns 0 % |
| [`m2-slot-phase0-offset.md`](./m2-slot-phase0-offset.md) | **M2** `rvc_slot_phase_block_start_offset_ms` p99 warm/cold | Separate warm/cold p99 for A-5 targets (≤1 s / ≤2 s) |
| [`m1-m2-post-phase3.md`](./m1-m2-post-phase3.md) | **M1/M2 after ADR-004** (ARCH-3k) | M1 = 0 at 60 s and 80 s; M2 p99 0 ms at slot start (≤1 s / ≤2 s) |
| [`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md) | **M3** slashing tx-hold (ARCH-5a / ARCH-5b) | Three-run median; concurrency = 1; observation-window decision (keep current series, add reserve-tx in 5l); per-sign budget = 3999/200 = 19.995 ms |
| [`m3-post-adr005.md`](./m3-post-adr005.md) | **M3 after ADR-005** (ARCH-5m) | Three-run median under **both** windows; X6 unmet (reserve-tx p99 917 ms ≫ 19.995 ms); fsync named; group commit filed; X7 rollback; X8 no G6 |
| [`m3-scale-200keys-200ms.md`](./m3-scale-200keys-200ms.md) | **M3 scale 200×200 ms** (ARCH-7m) | Post-ADR-005 tree; 0 missed deadlines; p99 1131 ms vs 19.995 ms; fsync still binds; no group commit; A-A8 signer-server only |
| [`m3-post-group-commit.md`](./m3-post-group-commit.md) | **M3 after group commit** (#205) | Three-run median under **both** windows; reserve-tx p99 **24.070 ms** (was 917 ms); 0 missed deadlines; X6 still unmet (~1.20×); next wall = remaining 4 fsyncs/wave |
| [`wire-twins-spike.md`](./wire-twins-spike.md) | **ARCH-7f** `Wire*` collapse spike | **Path C**; docs only — prototype must not merge |

---

## Re-run commands (one per metric)

From the repository root, on a clean tree at or after the harness commit:

### M1 — missed proposals

```bash
cargo test -p rvc --test proposal_under_duty_stall -- --nocapture --test-threads=1
```

Capture lines matching `ARCH-7b M1 cell` and `ARCH-7b RED baseline`.
Primary RED cell: **duty_cache=cold, stall=60s** → expect **miss_rate=100.0%** at Phase 0.
Contrast cell: **duty_cache=warm, stall=60s** → expect **miss_rate=0.0%** (harness soundness).

### M2 — slot phase-0 offset

```bash
# Multi-slot sample counts + MockSlotClock offsets (co-measured by M1 harness)
cargo test -p rvc --test proposal_under_duty_stall -- --nocapture --test-threads=1

# Instrument credibility (SystemSlotClock + injected duty delay ≥ D)
cargo test -p rvc --lib orchestrator::coordinator::tests::phase_block_offset -- --nocapture --test-threads=1
```

Histogram values: process-local `get_sample_sum` / `get_sample_count` on
`metrics::definitions::RVC_SLOT_PHASE_BLOCK_START_OFFSET_MS` with labels
`cache=cold` / `cache=warm`. Under the current M1 fixture (`MockSlotClock` +
`advance_time(9)`), means are **9000 ms** (second resolution). For wall-clock
duty reflection, use the ARCH-7a `test_offset_reflects_pre_proposal_work` path
(D = 2 s → cold mean ≥ 2000 ms; observed baseline mean **8000 ms**).

### M3 — slashing tx-hold (signer-server load profile)

The 200-key / 200 ms run is `#[ignore]`d. Full A-9 profile (what ARCH-5b recorded):

```bash
# JSON on stdout; --output also writes the same document (libtest only)
cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
  --exact test_load_profile_reports_p99_above_serialized_floor \
  -- --output /tmp/m3-baseline-run.json
```

nextest equivalent (stdout only; nextest 0.9 does not forward `--output`):

```bash
cargo nextest run -p rvc-signer-server --run-ignored ignored-only --no-capture \
  -E 'test(test_load_profile_reports_p99_above_serialized_floor)'
```

Run **three** times. Record all three plus the median; do not keep a single run.
Compare against [`m3-baseline-0ae9a09.md`](./m3-baseline-0ae9a09.md) and, after
the ADR-005 switchover, [`m3-post-adr005.md`](./m3-post-adr005.md). Capture
`achieved_concurrency`, `effective_concurrency`, wall,
`rvc_signer_slashing_tx_hold_duration_ms` p50/p95/p99/max,
`rvc_slashing_reserve_tx_hold_duration_ms` p50/p95/p99/max,
`rvc_slashing_reconcile_total{outcome="failed"}`, and the DB pragmas
object. A p99 spread **> 20 %** across the three runs is a harness defect
(reopen ARCH-5a), not a number to average.

Judge X6 against **3999 / 200 = 19.995 ms**, not against "faster than
baseline." This profile targets **`signer-server` / `SigningGate`**, not the
VC attestation loop (X8).

---

## Reproducibility / tolerance

| Metric | Surface | Independent runs | Stated tolerance |
|---|---|---|---|
| M1 miss rate | virtual-time matrix | exact match both runs (ARCH-7c) | **±0 slots / ±0.0 %** |
| M2 offset | MockSlotClock multi-slot | exact 9000 ms both runs | **±0 ms** |
| M2 offset | SystemSlotClock + D=2 s | exact 8000 ms mean both runs | **±2000 ms** mean; must stay **≥ D** |
| M3 tx-hold p99 | ARCH-5a 200×200 ms, `test` profile | three runs, 0.209 % p99 spread (ARCH-5b); post-ADR-005 1.51 % / 1.81 % (ARCH-5m, both series) | **±5 %** on this host; **> 20 %** reopens ARCH-5a |

**RED (reproducibility):** hand this README to a second person (or clean clone), re-run the commands, and compare against the tables in `m1-*.md` / `m2-*.md` / `m3-baseline-0ae9a09.md` / `m3-post-adr005.md`. If numbers fall outside the tolerance band, fix the README (or document a harness/fixture change) — do not silently “fix” a baseline by reordering the slot loop (that is Phase 3 / ADR-004) or by redefining the M3 observation window (that is ARCH-5b's recorded decision; the series add is ARCH-5l). Do not declare X6 met because total wall fits in 3999 ms — X6 is p99 vs 19.995 ms.

---

## Environment template (fill when re-baselining)

```
harness commit:  <git rev-parse HEAD of ARCH-7b-capable / ARCH-5a-capable tree>
rustc:           <rustc --version>
cargo:           <cargo --version>
host:            <cpu / cores / RAM / OS>
date (UTC):      <date -u +%Y-%m-%dT%H:%M:%SZ>
profile:         test | release   (M3 baseline is test)
```
