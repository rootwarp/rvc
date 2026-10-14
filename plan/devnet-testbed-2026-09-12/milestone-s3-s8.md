# Milestone S3–S8 — First live `run.sh` end-to-end (Issue 5.6)

> Phase 5 / Issue 5.6 record. Observation, **not a gate**. This file is the live
> double-run / fixture re-validation baseline: either two green `run.sh --profile
> fast` rehearsals with refreshed scrapes, or an explicit blocked-with-reason.

**Status: BLOCKED** — live end-to-end did not run. Two independent host
preconditions failed; the orchestrator stopped on the first:

1. **`target/release/rvc` is absent** (`run.sh` `_resolve_rvc_bin` → usage
   exit **2**, before minting a run dir or invoking any stage).
2. **Docker VM RAM is below the `00-preflight.sh` gate**
   (`PREFLIGHT_MIN_RAM_GIB=8`). Confirmed independently by `up.sh --profile
   fast` (same `die_usage` as [milestone-s1.md](milestone-s1.md)). Even a
   release binary would not have reached genesis.

No chain, no RVC process, no `run.json`, no `metrics-start.txt` /
`metrics-end.txt`, no `client.json` / `verdict.json`, no fixture refresh.
Numbers below are host/preflight facts from this attempt. Live KPI cells are
**not observed** — not invented.

Recorded: **2026-09-13T05:34:55Z** (UTC). Branch
`feature/5-6-live-e2e-validation` @ `59cfa3b2509157bff084f464f906b0c01c4ec75a`
(`develop`, `feat(devnet): add run.sh orchestrator and run.json`). Worktree
`/Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a0993f-e3c7-7d43-8d8c-4f2942761075`.

Constraint 2: no Rust / RVC source change. The missing binary was **not**
built (`cargo build --release` is a Phase 3 entry criterion / operator step;
this host may not have a release binary — it does not). Parser semantics and
hand-authored `rvc_metrics__{start,end}.txt` were **not** changed. `docs/devnet-testbed.md`
was **not** created (Issue 5.7 owns that file).

---

## Verdict

| Field | Value |
|---|---|
| Outcome | **blocked** |
| Blocker (live command) | missing `target/release/rvc` (`run.sh` usage exit **2**) |
| Blocker (would still fail) | Docker VM RAM &lt; 8 GiB (preflight usage exit **2**) |
| Two consecutive `run.sh --profile fast` exit 0 | not observed |
| Second run on a fresh genesis (S8, DN-12/D4) | not observed |
| Second-run wall-clock ≤ 45 min (S3) | not measured |
| All 13 K families in live scrape + `client.json` (S5a) | not observed |
| S5b non-zero families | not observed |
| Proposal / `no_proposal_window` (S6b) | not observed |
| `verdict.json` `s7_blocked = "pass"` (S7) | not observed |
| First real `run.json` vs `run_json__keypaths.txt` (P5-A12) | not observed |
| Fixtures refreshed from live scrape | **not done** |

### Exact Docker info numbers (the RAM gate)

Preflight reads `docker info --format '{{.NCPU}} {{.MemTotal}}'` and integer-divides
`MemTotal` by `1024 ** 3` (`scripts/devnet/00-preflight.sh`). Captured on this host
at the live attempt:

```text
$ docker info --format '{{.NCPU}} {{.MemTotal}}'
4 4107141120
```

| Source | Value |
|---|---|
| `docker info --format '{{.NCPU}}'` | **4** |
| `docker info --format '{{.MemTotal}}'` | **4107141120** (bytes) |
| Preflight `MemTotal // (1024 ** 3)` | **3** GiB |
| `docker info` `CPUs:` | **4** |
| `docker info` `Total Memory:` | **3.825GiB** |
| Docker Desktop `settings-store.json` `Cpus` | **4** |
| Docker Desktop `settings-store.json` `MemoryMiB` | **4096** |

Host RAM is **not** the failing check (24 GiB ≥ 8). The starved resource is the
Docker Desktop Linux VM. Identical to the S1 blocked record.

### RVC binary (the live-command gate)

```text
$ ls -la target/release/rvc
ls: target/release/rvc: No such file or directory
```

`target/` does not exist in this worktree. `run.sh` resolves `RVC_BIN` against
the repository root, never CWD, and **never builds** it.

---

## Command that stopped the sequence

Issue 5.6 live command, stdin closed, attempted **once**:

```bash
scripts/devnet/run.sh --profile fast < /dev/null
```

| Field | Value |
|---|---|
| Started (UTC) | 2026-09-13T05:34:55Z |
| Ended (UTC) | 2026-09-13T05:34:56Z |
| `/usr/bin/time -p` real | **0.52 s** |
| Exit | **2** (`die_usage`) |
| stderr | `[ERROR] RVC binary not found at /Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a0993f-e3c7-7d43-8d8c-4f2942761075/target/release/rvc; cargo build --release` |
| stdout | empty |
| Run dir minted | **no** (`_resolve_rvc_bin` is before `mint_run_id` / `mkdir`) |
| `scripts/devnet/runs/` | not created |
| `scripts/devnet/data/` | not created |
| Containers started | none (`docker ps -a --filter name=eth-devnet` empty) |
| `pgrep -f target/release/rvc` | empty |
| Stages reached | none (`up.sh` never invoked) |

A second back-to-back `run.sh` was **not** attempted: the first rehearsal is
already red on a host gate, and the blocked path forbids inventing a second
run's wall-clock / genesis identity.

### Supporting RAM-gate capture (not a second 5.6 rehearsal)

`run.sh` never reaches `up.sh` without a binary. To record that the S1 RAM
gate is still live on this Docker VM, `up.sh` was invoked once **after** the
live command, stdin closed:

```bash
scripts/devnet/up.sh --profile fast < /dev/null
```

| Field | Value |
|---|---|
| Started (UTC) | 2026-09-13T05:35:35Z |
| Ended (UTC) | 2026-09-13T05:35:36Z |
| `/usr/bin/time -p` real | **0.99 s** |
| Exit | **2** (`die_usage`) |
| stderr | `[INFO] running 00-preflight.sh` / `[ERROR] need >= 8 GiB RAM (docker VM has 3 GiB)` |
| stdout | empty |
| Containers started | none |
| `scripts/devnet/data/` | not created |
| `pull_images` | not reached |

Building `target/release/rvc` would not change this record's live KPI cells:
preflight would still exit 2 on the Docker VM.

---

## Host

| Field | Value |
|---|---|
| Hostname | `nil.local` |
| Hardware | Apple M4 Pro (`machdep.cpu.brand_string`) |
| Arch | arm64 / Darwin `RELEASE_ARM64_T6041` |
| OS | macOS 26.6.2 (Build 25G83) |
| Kernel | Darwin 25.6.0 (`xnu-12377.161.14~5`) |
| Host CPUs | **14** (`os.cpu_count()` / `hw.ncpu`) |
| Host RAM | **24 GiB** (`SC_PHYS_PAGES`; `hw.memsize` = 25769803776) |
| Free disk (data volume) | 507 GiB available on `/System/Volumes/Data` (`statvfs`; `df` 508Gi / 926 GiB, 44 % used) |
| Worktree | `/Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a0993f-e3c7-7d43-8d8c-4f2942761075` |
| rustc / cargo | 1.97.1 (not used; binary not built) |
| Docker client/server | 29.7.2 (context `desktop-linux`) |
| Docker OS / arch | Docker Desktop / linux / aarch64 |
| Docker kernel | 7.0.12-linuxkit |
| Docker name | `docker-desktop` |
| Docker storage | overlayfs (`io.containerd.snapshotter.v1`) |

Matches PRD F9 (macOS arm64, 14 CPU / 24 GiB) except the Docker VM, which is
provisioned at 4 CPU / 4 GiB (`MemoryMiB=4096`) and reports **3.825 GiB**.

---

## Image digests

Pins from `scripts/devnet/devnet.env` (index digests). `docker image inspect`
against those refs on this host **before any live bring-up** — not from a live
pipeline (preflight never reached `pull_images`).

| Env key | Pin (`repo:tag@sha256:<index digest>`) | `docker image inspect` |
|---|---|---|
| `IMG_GETH` | `ethereum/client-go:v1.17.5@sha256:523d3ba26623a619e912019068dc2784f02934070ac46bdae4d5b9df0d917814` | present; `Id=sha256:523d3ba26623a619e912019068dc2784f02934070ac46bdae4d5b9df0d917814`; `Architecture=arm64`; `Os=linux`; `Size=25982051`; `RepoDigests=["ethereum/client-go@sha256:523d3ba26623a619e912019068dc2784f02934070ac46bdae4d5b9df0d917814"]`; `RepoTags=["ethereum/client-go:v1.17.5"]`; `Created=2026-07-27T09:57:34.137690899Z` |
| `IMG_LIGHTHOUSE` | `sigp/lighthouse:v8.2.2@sha256:9a62bb8705455136e1cf96613460960f80dc2faa9d75b5c16a3bfcc9210dcdd1` | present; `Id=sha256:9a62bb8705455136e1cf96613460960f80dc2faa9d75b5c16a3bfcc9210dcdd1`; `Architecture=arm64`; `Os=linux`; `Size=63107227`; `RepoDigests=["sigp/lighthouse@sha256:9a62bb8705455136e1cf96613460960f80dc2faa9d75b5c16a3bfcc9210dcdd1"]`; `RepoTags=["sigp/lighthouse@sha256:9a62bb8705455136e1cf96613460960f80dc2faa9d75b5c16a3bfcc9210dcdd1"]`; `Created=2026-08-18T00:24:17.942659643Z` |
| `IMG_GENESIS` | `ethpandaops/ethereum-genesis-generator:6.2.1@sha256:15bb557cbd6d29fc1b7516a7147326a8c8d3af54f3c3ac534ec8772f6e875256` | present; `Id=sha256:15bb557cbd6d29fc1b7516a7147326a8c8d3af54f3c3ac534ec8772f6e875256`; `Architecture=arm64`; `Os=linux`; `Size=93774224`; `RepoDigests=["ethpandaops/ethereum-genesis-generator@sha256:15bb557cbd6d29fc1b7516a7147326a8c8d3af54f3c3ac534ec8772f6e875256"]`; `RepoTags=["ethpandaops/ethereum-genesis-generator@sha256:15bb557cbd6d29fc1b7516a7147326a8c8d3af54f3c3ac534ec8772f6e875256"]`; `Created=2026-08-24T14:47:03.631354298Z` |

Q1 (Lighthouse v8.2.2 on Electra-at-genesis) is **unanswered** by this attempt:
the BN never started.

---

## Planned key range (not generated)

From `devnet.env`. `02-keys.sh` did not run; `scripts/devnet/data/keys/` does not
exist.

| Field | Planned value | Live |
|---|---|---|
| `NUM_VALIDATORS` | 64 | not generated |
| `RVC_KEYS` | 16 | not generated |
| RVC derivation range | `[48, 64)` (`N−K` … `N`) | not generated |
| Profile | `fast` (`FAST_EPOCHS=4`, `FAST_DOPPELGANGER=off`) | not applied beyond flag parse |
| `data/keys/rvc/pubkeys.txt` | 16 × lowercase `0x`-prefixed 48-byte pubkeys | absent |

---

## Genesis validators root

**Not observed.** No BN, no `data/genesis/genesis_validators_root.txt`, no
`/eth/v1/beacon/genesis`. ADR-013 forbids inventing this from `devnet.env`.

---

## Per-stage wall-clocks (S3 inputs for 5.7)

**Not observed.** `run.sh` never invoked a stage. Cells are not estimated from
the 38.4 min chain-time arithmetic.

| Stage | `run.json` path | Live |
|---|---|---|
| up | `stages.up.seconds` / `exit_code` | not observed |
| attach | `stages.attach.seconds` / `exit_code` | not observed |
| soak | `stages.soak.seconds` / `exit_code` | not observed |
| report | `stages.report.seconds` / `exit_code` | not observed |
| down | `stages.down.seconds` / `exit_code` | not observed |
| **total** (S3, N = 4, pre-built binary, target ≤ 45 min) | — | **not measured** |

---

## S5a / S5b table

**Not scraped.** No RVC `/metrics` listener, no `metrics-start.txt` /
`metrics-end.txt`, no `client.json`.

Presence is family-level (D2/V4). Liveness (S5b) requires non-zero only for
K1, K3, K4, K5, K7, K11-fetched, K12; K2 / K6 / K8-blocked / K11-reorgs /
K13-exits are failure-only and would read zero on a green run.

| K | Family | S5a present | S5b non-zero required | Live |
|---|---|---|---|---|
| K1 | `rvc_orchestrator_slots_processed_total` | required | yes | not observed |
| K2 | `rvc_orchestrator_missed_slots_total` | required | no | not observed |
| K3 | `rvc_orchestrator_slot_processing_duration_seconds` | required | yes | not observed |
| K4 | `rvc_attestations_total` | required | yes | not observed |
| K5 | `rvc_aggregations_total` | required | yes | not observed |
| K6 | `rvc_proposals_total` | required | no (S6b) | not observed |
| K7 | `rvc_signing_duration_seconds` | required | yes | not observed |
| K8 | `rvc_slashing_protection_checks_total` | required | blocked must be 0 (S7) | not observed |
| K9 | `rvc_slashing_reserve_tx_hold_duration_ms` | required | no | not observed |
| K10 | `rvc_slot_phase_block_start_offset_ms` | required | no | not observed |
| K11 | `rvc_duties_fetched_total` | required | yes (fetched) | not observed |
| K11 | `rvc_duty_reorg_detected_total` | required | no | not observed |
| K12 | `rvc_bn_health_tier` | required | yes | not observed |
| K12 | `rvc_proposer_bn_latency_ms` | required | (K12) | not observed |
| K13 | `rvc_tasks_running` / `rvc_task_exits_total` / `rvc_sse_events_dropped_total` | required | no (exits) | not observed |

### S6b proposal

| Field | Live value |
|---|---|
| `rvc_proposals_total` | not observed |
| `no_proposal_window` annotation | not observed |
| Whether a proposal occurred | not observed |

A fabricated envelope_late / success count would be a false S6b.

### S7 slashing gate

| Field | Live value |
|---|---|
| `rvc_slashing_protection_checks_total{result="blocked"}` | not observed |
| `verdict.json` `gates.s7_blocked` | not written |
| Standalone re-report of a live `metrics-end.txt` | not reached |

---

## `run.json` / P5-A12

**Not written.** `run.sh` exits at `_resolve_rvc_bin` before `write_run_json_start`.
The P5-A12 fixture gap (first *real* `run.json` vs committed
`scripts/tests/fixtures/run_json__keypaths.txt`) remains open.

Stub-stage pytest still covers the synthetic producer:

```text
test_run_json_key_paths  (scripts/tests/test_devnet_run_sh.py)
```

That is **not** a live close of P5-A12.

---

## Live vs hand-authored fixtures

Issue 5.6 requires a cardinality diff of the first live scrape against
`scripts/tests/fixtures/rvc_metrics__{start,end}.txt`, then a refresh
(truncated, secrets-free) and a move of the hand-authored nasty cases to
`rvc_metrics__edge.txt`.

**Not performed.** There is no live scrape to diff. A discrepancy write-up
that named families would be fiction.

| File | Action taken |
|---|---|
| `scripts/tests/fixtures/rvc_metrics__start.txt` | **unchanged** (hand-authored Phase 4; blob `beb5e65b27fef7d174192f5726e379355709b71b`) |
| `scripts/tests/fixtures/rvc_metrics__end.txt` | **unchanged** (hand-authored Phase 4; blob `650c803d5551a350b9a2c0ed95fc065d2534c01c`) |
| `scripts/tests/fixtures/rvc_metrics__edge.txt` | **not created** (nasty cases stay in start/end until a real scrape exists) |
| Parser (`scripts/devnet_report.py`) | **unchanged** |

Resolution of live-vs-fixture discrepancies: **deferred** until a ≥ 8 GiB
Docker VM with a pre-built `target/release/rvc` produces `metrics-start.txt` /
`metrics-end.txt`. `docs/devnet-testbed.md` is not the place for a blocked
placeholder (Issue 5.7).

---

## pytest

Issue 5.6 AC: fixtures refreshed **and**
`uv run --with pytest --with pytest-socket pytest scripts/tests/ -q` green.
Fixtures were not refreshed. The command was still run on unmodified
`develop` HEAD so a fake scrape could not be blamed for the result.

```text
11 failed, 858 passed, 11 skipped, 3 warnings in 334.58s
```

The 11 failures **reproduce without any 5.6 edit**. They are not live-scrape
bugs:

| Count | Test | Cause |
|---|---|---|
| 5 | `test_devnet_down_sh.py` (`test_down_sh_removes_every_inventory_row`, `test_down_sh_kills_rvc_pid_before_purging_db`, `test_down_sh_stale_pid_is_skipped_not_killed`, `test_down_sh_matches_rvc_comm_basename`, `test_down_sh_removes_sqlite_wal_shm`) | `scripts/tests/fixtures/inventory__partial.json` was **never committed** on `develop` (Issue 5.1 testing notes name it; `git cat-file` on that path is fatal). Out of 5.6 blocked-path scope. |
| 6 | `test_validator_perf.py::test_every_null_metric_has_a_matching_degradation_entry` parametrized over `bn_genesis`, `bn_head_fork`, `bn_spec`, `validator_perf__{ok,degraded,threshold}` | G5 stem scan of `scripts/tests/fixtures/*.json` has no prefix for Phase 3 BN probes / Phase 5 `report.sh` stubs. Pre-existing fixture-dir collision. Out of 5.6 blocked-path scope. |

Phase 4 / 5.2–5.5 suites that consume the **unmodified** metric fixtures and
the synthetic `run.json` are green:

```text
pytest scripts/tests/test_devnet_{report,report_sh,run_sh,soak_sh}.py
152 passed, 1 warning in 86.94s
```

Hand-authored nasty cases in `rvc_metrics__{start,end}.txt` were left in place
so those tests stay the Phase 4 contract.

---

## Teardown / working tree

`down.sh` was **not reached** (no inventory, no pidfile, no containers).

| Check | After live `run.sh` | After supporting `up.sh` |
|---|---|---|
| `pgrep -f target/release/rvc` | empty | empty |
| `docker ps -aq --filter name=eth-devnet-` | empty | empty |
| `scripts/devnet/runs/` | absent | absent |
| `scripts/devnet/data/` | absent | absent |

`git status --porcelain` is **not** a clean tree: this worktree already carried
untracked plan/docs/audit files at checkout (same class as the S1 worktree).
The live attempt added **no** files under `scripts/devnet/{runs,data}/` and
did not modify tracked fixtures. The only file this issue adds is **this
record**.

---

## Acceptance criteria

| AC | Result |
|---|---|
| Two consecutive `run.sh --profile fast < /dev/null` both exit `0`, the second on a fresh genesis (S8, DN-12/D4) | **blocked** — first command exit 2; second not run |
| Second run's total wall-clock ≤ 45 min at `N = 4` with a pre-built binary, value recorded in `run.json` (S3) | **blocked** — no `run.json`, no wall-clock |
| All 13 K families present in the live scrape and in `client.json` (S5a); K1, K3, K4, K5, K7, K11-fetched, K12 non-zero (S5b) | **blocked** — no scrape |
| `verdict.json` of both runs has `s7_blocked = "pass"` (S7) | **blocked** — no `verdict.json` |
| Fixtures refreshed from the live scrape and `pytest scripts/tests/ -q` green | **blocked** — no live scrape; fixtures unchanged. Full `scripts/tests/` is 11-red on unmodified develop (5.1 missing fixture + G5 stem collision); Phase 4/5 report/run/soak 152-green |
| Every live-vs-fixture discrepancy written up (file, families, resolution) in the phase notes and in `docs/devnet-testbed.md` | **blocked** — no discrepancy to write; 5.7 owns `docs/devnet-testbed.md`; **this file** is the phase note |
| The first real `run.json` validates against `run_json__keypaths.txt`, closing P5-A12 | **blocked** — no real `run.json` |
| `down.sh` after each run leaves no RVC process and `git status --porcelain` clean | **blocked** — `down.sh` not reached; no RVC process anyway |

ACs 1–8 are **not met**.

---

## How to unblock (operator, not this issue)

Clear **both** host gates, then re-run the 5.6 sequence on a follow-up record
rather than editing these blocked cells in place.

1. Raise Docker Desktop VM memory so preflight's integer GiB is ≥ 8:

   ```bash
   docker info --format '{{.NCPU}} {{.MemTotal}}'
   # need: NCPU >= 4 and MemTotal // (1024 ** 3) >= 8
   ```

   On this host that means `settings-store.json` `MemoryMiB` **4096 → ≥ 8192**
   (and a Docker Desktop restart so `MemTotal` updates). Do **not** lower
   `PREFLIGHT_MIN_RAM_GIB` to sneak past the gate — that is not an S3–S8
   observation.

2. Provide a pre-built `target/release/rvc` (`cargo build --release`). These
   scripts never build RVC. A binary on a starved Docker VM is not sufficient.

3. Then, on that host:

   ```bash
   scripts/devnet/run.sh --profile fast < /dev/null   # keep runs/<id>/
   scripts/devnet/run.sh --profile fast < /dev/null   # fresh genesis; ≤ 45 min
   ```

   Refresh `rvc_metrics__{start,end}.txt` from the first live scrapes, move
   hand-authored nasty cases to `rvc_metrics__edge.txt`, write the
   live-vs-fixture cardinality diff, and close P5-A12 against the first real
   `run.json`.

Residual risk: **re-run Issue 5.6 on a ≥ 8 GiB Docker VM (F9) with a pre-built
release binary.** Until then S3, S5a, S5b, S6b, S7, S8 and the Phase 4 fixture
risk remain unproven on the developer host.
