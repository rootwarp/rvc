# Milestone S6 — Live `run.sh --profile safe` soak (Issue 6.6)

> Phase 6 / Issue 6.6 record. Observation, **not a gate**. This file is the live
> `--profile safe` soak baseline: either a green `run.sh --profile safe --keep`
> with measured offset / head epoch / wall-clocks against P6-A2, or an explicit
> blocked-with-reason. It is the only live proof that the Phase 2 key split is
> disjoint (DN-5 / ADR-011 / DN-18).

**Status: BLOCKED** — live end-to-end did not run. Two independent host
preconditions failed; the orchestrator stopped on the first:

1. **`target/release/rvc` is absent** (`run.sh` `_resolve_rvc_bin` → usage
   exit **2**, before minting a run dir or invoking any stage).
2. **Docker VM RAM is below the `00-preflight.sh` gate**
   (`PREFLIGHT_MIN_RAM_GIB=8`). Confirmed independently from
   `docker info --format '{{.NCPU}} {{.MemTotal}}'` (same numbers as
   [milestone-s3-s8.md](milestone-s3-s8.md) / [milestone-s1.md](milestone-s1.md)).
   Even a release binary would not have reached genesis.

No chain, no RVC process, no `run.json`, no `metrics-start.txt` /
`metrics-end.txt`, no `data/rvc/rvc.log`, no `client.json` / `verdict.json`,
no KPI-breach re-report. Numbers below are host/preflight facts from this
attempt. Live KPI cells are **not observed** — not invented.

Recorded: **2026-09-13T07:47:18Z** (UTC). Branch
`feature/6-6-live-safe-soak` @ `ecea022c20f334af94f0cc10d8c9fd6405f17adc`
(`develop`, `feat(devnet): wire --profile safe offset and FAIL_UNDER`). Worktree
`/Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a099ba-39c0-7bc3-a85f-3767e4bbb0ac`.

Constraint 2: no Rust / RVC source change. The missing binary was **not**
built (`cargo build --release` is a Phase 3 entry criterion / operator step;
this host may not have a release binary — it does not). `PREFLIGHT_MIN_RAM_GIB`
was **not** lowered. Scripts under `scripts/devnet/` were **not** changed.
`docs/devnet-testbed.md` §Safe profile records the same blocked cells (P6-A6);
this file is the phase note.

---

## Verdict

| Field | Value |
|---|---|
| Outcome | **blocked** |
| Blocker (live command) | missing `target/release/rvc` (`run.sh` usage exit **2**) |
| Blocker (would still fail) | Docker VM RAM &lt; 8 GiB (preflight usage exit **2**) |
| `run.sh --profile safe --keep` exit 0 | not observed |
| `grep -c 'doppelganger Detected' data/rvc/rvc.log` is 0 on a non-empty log with startup markers | not observed (no log) |
| `rvc_attestations_total{status="success"}` increases start → end | not observed |
| `verdict.json` `participation_rate` ≥ 0.95 **and** `target_rate` ≥ 0.95 | not observed |
| `run.json` records `profile` / `soak_start_offset_epochs` / `fail_under` | not written |
| KPI-breach `report.sh --fail-under participation_rate=1.01` exit 4 while chain up | not reached |
| Offset boundary vs P6-A2 predicted epoch 3 | not observed |
| Head epoch vs P6-A2 predicted 13 | not observed |
| Lighthouse VC DP delayed block production (P6-A12) | not observed |
| Per-stage wall-clocks | not measured |
| `down.sh --data` after re-report | not reached |

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
Docker Desktop Linux VM. Identical to the S1 and S3–S8 blocked records.

The live command never reached `00-preflight.sh` (`_resolve_rvc_bin` is earlier).
The RAM numbers above are an independent `docker info` capture on the same
host/VM, not a second `run.sh`. Building `target/release/rvc` would not change
this record's live KPI cells: preflight would still exit 2 on the Docker VM.

### RVC binary (the live-command gate)

```text
$ ls -la target/release/rvc
ls: target/release/rvc: No such file or directory
```

`target/` does not exist in this worktree. `run.sh` resolves `RVC_BIN` against
the repository root, never CWD, and **never builds** it.

---

## Command that stopped the sequence

Issue 6.6 live command, stdin closed, attempted **once**:

```bash
scripts/devnet/run.sh --profile safe --keep < /dev/null
```

| Field | Value |
|---|---|
| Started (UTC) | 2026-09-13T07:47:18Z |
| Ended (UTC) | 2026-09-13T07:47:18Z |
| `/usr/bin/time -p` real | **0.52 s** |
| Exit | **2** (`die_usage`) |
| stderr | `[ERROR] RVC binary not found at /Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a099ba-39c0-7bc3-a85f-3767e4bbb0ac/target/release/rvc; cargo build --release` |
| stdout | empty |
| `--keep` honoured | flag parsed; trap never installed (exit before `mint_run_id`) |
| Run dir minted | **no** (`_resolve_rvc_bin` is before `mint_run_id` / `mkdir`) |
| `scripts/devnet/runs/` | not created |
| `scripts/devnet/data/` | not created |
| Containers started | none (`docker ps -a --filter name=eth-devnet` empty) |
| Networks created | none (`docker network ls --filter name=eth-devnet` empty) |
| `pgrep -f target/release/rvc` | empty |
| Stages reached | none (`up.sh` never invoked) |

Flag parse and `resolve_profile safe` ran (an unknown-profile usage line would
have fired first). Those values lived only in the dying process environment
(`EPOCHS=8`, `DOPPELGANGER=on`, `SOAK_START_OFFSET_EPOCHS=3`,
`FAIL_UNDER=participation_rate=0.95,target_rate=0.95` from `devnet.env` /
6.3 wiring). They were **not** written to `run.json`.

A second `run.sh --profile safe` was **not** attempted: the issue budgets one
live command, the first is already red on a host gate, and the blocked path
forbids inventing soak wall-clocks / attestations / a verdict.

`up.sh` was **not** invoked as a supporting probe. The RAM gate is the same
Docker VM captured above; repeating S3–S8's post-hoc `up.sh` would not produce
S6 KPIs.

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
| Free disk (data volume) | 507 GiB available on `/System/Volumes/Data` (`statvfs`; `df` 507Gi / 926 GiB, 44 % used) |
| Worktree | `/Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a099ba-39c0-7bc3-a85f-3767e4bbb0ac` |
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
the BN never started. P6-A12 (Lighthouse VC doppelganger protection at genesis)
is likewise unanswered.

---

## Planned key range (not generated)

From `devnet.env`. `02-keys.sh` did not run; `scripts/devnet/data/keys/` does not
exist.

| Field | Planned value | Live |
|---|---|---|
| `NUM_VALIDATORS` | 64 | not generated |
| `RVC_KEYS` | 16 | not generated |
| RVC derivation range | `[48, 64)` (`N−K` … `N`) | not generated |
| Lighthouse VC range | `[0, 48)` | not generated |
| Profile | `safe` (`SAFE_EPOCHS=8`, `SAFE_DOPPELGANGER=on`, offset 3) | resolved in-process; not applied beyond flag parse |
| `data/keys/rvc/pubkeys.txt` | 16 × lowercase `0x`-prefixed 48-byte pubkeys | absent |

Disjointness of the two pubkey sets (DN-5) is **not proven** on this host.

---

## Genesis validators root

**Not observed.** No BN, no `data/genesis/genesis_validators_root.txt`, no
`/eth/v1/beacon/genesis`. ADR-013 forbids inventing this from `devnet.env`.

---

## Per-stage wall-clocks and P6-A2 offset

**Not observed.** `run.sh` never invoked a stage. Cells are not estimated from
the 83.2 min chain-time arithmetic. The 0.52 s figure above is the usage-2
command, **not** a soak wall-clock.

| Stage | `run.json` path | Live |
|---|---|---|
| up | `stages.up.seconds` / `exit_code` | not observed |
| attach | `stages.attach.seconds` / `exit_code` | not observed |
| soak | `stages.soak.seconds` / `exit_code` | not observed |
| report | `stages.report.seconds` / `exit_code` | not observed |
| down | `stages.down.seconds` / `exit_code` | not observed |
| **total** (issue budget ~95 min wall-clock) | — | **not measured** |

### Offset boundary vs P6-A2 predicted 13

P6-A2 arithmetic (wiring only; **not a measurement**):
`SOAK_START_OFFSET_EPOCHS=3` (2 monitoring epochs + 1 margin) + `EPOCHS=8` +
Phase 5's `+2` for `validator_perf.py`'s `to_epoch ≤ head − 2` clamp ⇒ chain
head at epoch **13 ≈ 83.2 min** (13 × 32 slots × 12 s), measured window
epochs 4…11.

| Field | P6-A2 predicted | Live |
|---|---|---|
| `SOAK_START_OFFSET_EPOCHS` | 3 | not observed (no `metrics-start.txt`) |
| sample window | epochs 4…11 | not observed (no `samples.jsonl`) |
| chain head epoch | 13 | not observed (no BN) |
| chain time | 83.2 min | not measured |
| wall-clock | ~95 min / attempt | not measured |

Deviation from P6-A2: **none to explain** — soak never started. Do not treat
the predicted 13 as an observed head epoch.

### Lighthouse VC doppelganger protection (P6-A12)

**Not observed.** `03-chain.sh` never ran, so the block-production health gate
did not have a chance to abort `1` in the first ~2 epochs. The decision path
(keep `--enable-doppelganger-protection` on the Lighthouse VC; drop it only if
that gate trips and record that DN-5 is proven from RVC's side only) was **not
taken**. Residual risk unchanged.

---

## Doppelganger log (S6 detection signal)

Detection does **not** exit the process — it permanently closes the gate and
logs `error!` once (`crates/rvc/src/liveness_loop.rs`). The issue criterion is
`grep -c 'doppelganger Detected' data/rvc/rvc.log` is `0` **on a non-empty log
whose startup markers are present**. A missing or empty log fails the
criterion.

| Field | Live value |
|---|---|
| `data/rvc/rvc.log` | **absent** (`scripts/devnet/data/` not created) |
| log non-empty with startup markers | no |
| `grep -c 'doppelganger Detected'` | not run (no file). A `0` count on a missing log would be a false pass |

---

## Attestations / disjoint keys (DN-5)

**Not scraped.** No RVC `/metrics` listener, no `metrics-start.txt` /
`metrics-end.txt`.

| Field | Live value |
|---|---|
| `rvc_attestations_total{status="success"}` at start | not observed |
| same at end | not observed |
| delta across the soak window | not observed |
| Gate opened (disjoint pubkey sets) | not proven |

A fabricated success delta would be a false DN-5.

---

## `verdict.json` / `run.json` (S6 + P6-A10)

**Not written.** `run.sh` exits at `_resolve_rvc_bin` before
`write_run_json_start`. `report.sh` was not invoked.

| Field | Expected under `safe` | Live |
|---|---|---|
| `run.json` `profile` | `safe` | not written |
| `run.json` `soak_start_offset_epochs` | `3` | not written |
| `run.json` `fail_under` | `participation_rate=0.95,target_rate=0.95` | not written |
| `run.json` `epochs` | `8` | not written |
| `verdict.json` `participation_rate` | ≥ 0.95 | not observed |
| `verdict.json` `target_rate` | ≥ 0.95 | not observed |
| `verdict.json` `exit_code` / `verdict` | `0` / `pass` | not written |

Stub-stage pytest covering the synthetic `run.json` producer is **not** a live
close of S6.

---

## KPI-breach re-report

Issue 6.6 requires `--keep` so the chain is still up for:

```bash
scripts/devnet/report.sh --run-dir <same> --fail-under participation_rate=1.01
```

Expected: exit **4** (PRD §4) against a live BN.

**Not reached.** No run dir, no chain, no `--keep` trap. Inventing an exit 4
from a fixture would not exercise the live path.

---

## Teardown / working tree

`down.sh --data` was **not reached** (no inventory, no pidfile, no containers,
no purge root). The post-command host already had nothing to tear down; that
is **not** a pass of the teardown AC.

| Check | After live `run.sh --profile safe --keep` |
|---|---|
| `pgrep -f target/release/rvc` | empty |
| `docker ps -aq --filter name=eth-devnet` | empty |
| `docker network ls --filter name=eth-devnet` | empty |
| `scripts/devnet/runs/` | absent |
| `scripts/devnet/data/` | absent |

`git status --porcelain` is **not** a clean tree: this worktree already carried
untracked plan/docs/audit files at checkout (same class as the S1 / S3–S8
worktrees). The live attempt added **no** files under `scripts/devnet/{runs,data}/`
and did not modify Rust or `scripts/devnet/*.sh`. This issue adds **this
record** and the blocked cells in `docs/devnet-testbed.md` §Safe profile.

---

## Acceptance criteria

| AC | Result |
|---|---|
| The run exits `0` and `grep -c 'doppelganger Detected' data/rvc/rvc.log` is `0` on a non-empty log whose startup markers are present | **blocked** — exit 2; no log |
| `rvc_attestations_total{status="success"}` increases across the soak window (`metrics-start.txt` → `metrics-end.txt`) | **blocked** — no scrape |
| `verdict.json` shows `participation_rate ≥ 0.95` **and** `target_rate ≥ 0.95`; `run.json` records profile, offset and `fail_under` | **blocked** — no `verdict.json` / `run.json` |
| `report.sh --run-dir <same> --fail-under participation_rate=1.01` exits `4` while the chain is still up | **blocked** — not reached |
| Measured head epoch, wall-clock and offset boundary written into `docs/devnet-testbed.md` §Safe profile beside the P6-A2 prediction; any deviation explained | **blocked cells recorded** — live values are `not observed`; P6-A2 13 is not treated as a measurement |
| `down.sh --data` afterwards leaves no container, network or `data/` | **blocked** — `down.sh` not reached; host was already empty |

ACs 1–4 and 6 are **not met**. AC 5 is the honest blocked write-up, not a live
measurement.

---

## How to unblock (operator, not this issue)

Clear **both** host gates, then re-run the 6.6 sequence on a follow-up record
rather than editing these blocked cells in place.

1. Raise Docker Desktop VM memory so preflight's integer GiB is ≥ 8:

   ```bash
   docker info --format '{{.NCPU}} {{.MemTotal}}'
   # need: NCPU >= 4 and MemTotal // (1024 ** 3) >= 8
   ```

   On this host that means `settings-store.json` `MemoryMiB` **4096 → ≥ 8192**
   is still not enough (Desktop “8 GiB” reports ~7 GiB after VM overhead).
   Raise until the printed integer is ≥ 8 (this host: likely **≥ 9216 MiB**)
   and restart Docker so `MemTotal` updates. Do **not** lower
   `PREFLIGHT_MIN_RAM_GIB` to sneak past the gate — that is not an S6
   observation.

2. Provide a pre-built `target/release/rvc` (`cargo build --release`). These
   scripts never build RVC. A binary on a starved Docker VM is not sufficient.

3. Then, on that host:

   ```bash
   scripts/devnet/run.sh --profile safe --keep < /dev/null
   # keep the chain up; re-report:
   RUN=$(ls -1t scripts/devnet/runs | head -1)
   scripts/devnet/report.sh --run-dir "scripts/devnet/runs/${RUN}" \
     --fail-under participation_rate=1.01    # expect 4
   grep -c 'doppelganger Detected' scripts/devnet/data/rvc/rvc.log
   scripts/devnet/down.sh --data
   ```

   Record measured `stages.*.seconds`, the observed offset boundary and head
   epoch against P6-A2's predicted 13, whether Lighthouse VC DP delayed block
   production (P6-A12), and write those numbers into `docs/devnet-testbed.md`
   §Safe profile. Do not invent them here.

Residual risk: **re-run Issue 6.6 on a ≥ 8 GiB Docker VM (F9) with a pre-built
release binary.** Until then S6, DN-5 live disjointness, DN-18's live half,
and P6-A12 remain unproven on the developer host. Issue 6.5 (nightly `safe`
job) stays blocked on this observation.
