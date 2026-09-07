# Glamsterdam measurements

Checked-in baselines for NFRs that later phases must not regress.

- **P1 signing latency + slot processing (issue 1.1 / #207, D32):** recorded on
  develop `8e908a56c6f1d5de1e92afbcb7222e47551019f5` (post-#205 group-commit,
  **before** any Phase 1/2/3 code). Gates Phase 6 issue **6.14** (three-run
  median p99 within +10 % of this file, same fixtures).

| File | Metric | Role |
|---|---|---|
| [`p1-baseline-8e908a5.md`](./p1-baseline-8e908a5.md) | A-9 `signer-server` load profile (wall / tx-hold / reserve-tx) **and** `rvc_orchestrator_slot_processing_duration_seconds` via `pipeline_fixture` | Three-run median; SHA is an ancestor of every Phase 1/2/3 commit; 6.14 +10 % ceilings derived in-file |
| [`p6-6.14-dfb52a9.md`](./p6-6.14-dfb52a9.md) | P1 fixtures after V4/island; Gloas deadline via P4 `for_fork`; ungated 6.9b aggregate + 6.20 self-build propose | Issue **6.14** / #309; P1 +10 % **PASS**; island/envelope **ungated** |

---

## Re-run commands

From the repository root, on a clean tree at the measured commit (or later,
for a comparison run — never as a replacement baseline):

### Sign path (ARCH-5a load profile, `#[ignore]`)

```bash
cargo test -p rvc-signer-server --test load_profile -- --ignored --nocapture \
  --exact test_load_profile_reports_p99_above_serialized_floor \
  -- --output /tmp/p1-baseline/runN.json
```

Run **three** times. Record all three plus the median. nextest 0.9 does not
forward `--output`.

### Slot processing (`pipeline_fixture`)

The load harness does **not** populate
`RVC_ORCHESTRATOR_SLOT_PROCESSING_DURATION_SECONDS`. Issue 6.14 checks in the
driver P1 described:

```bash
cargo test -p rvc --test slot_processing_profile -- --ignored --nocapture \
  --exact test_slot_processing_profile_reports_p99 \
  -- --output /tmp/p6-6.14/slot-runN.json
```

200 unique-epoch `process_slot` calls, drain exact `sample_sum` / `sample_count`
after each, three process invocations. Do not use `histogram_quantile` (first
bucket is 0.01 s; samples are ~2–3 ms).

### Gloas attestation deadline (D9)

```bash
cargo bench -p rvc --bench deadline_rebenchmark -- --output /tmp/p6-6.14/deadline.json
```

### Ungated 6.9b aggregate + 6.20 self-build propose (no P1 column)

```bash
cargo test -p rvc --test ungated_path_profile -- --ignored --nocapture \
  --exact test_ungated_island_paths_report_p99 \
  -- --output /tmp/p6-6.14/ungated-runN.json
```

---

## Environment template (fill when re-baselining)

```
harness commit:  <git rev-parse HEAD — must predate Phase 1/2/3 for a P1 baseline>
rustc:           <rustc --version>
cargo:           <cargo --version>
host:            <cpu / cores / RAM / OS>
date (UTC):      <date -u +%Y-%m-%dT%H:%M:%SZ>
profile:         test | release   (P1 baseline is test)
```
