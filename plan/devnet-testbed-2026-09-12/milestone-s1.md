# Milestone S1 — RVC attests on a local chain

> Phase 3 / Issue 3.4 record. Observation, **not a gate**. S1's ≤ 20 min under one
> command is re-measured in Phase 5 under `run.sh` (P-A5). This file is the Phase 5
> baseline: either a live attach observation, or an explicit blocked-with-reason.

**Status: BLOCKED** — live attach did not run. Docker VM RAM is below the
`00-preflight.sh` gate (`PREFLIGHT_MIN_RAM_GIB=8`). No chain, no RVC process, no
`validator_perf.py` JSON, no `/metrics` scrape. Numbers below are host/preflight
facts from this attempt. Live KPI cells are **not observed** — not invented.

Recorded: **2026-09-13T00:24:38Z** (UTC). Branch
`feature/3-4-live-attach-s1` @ `c026ca8b9198bba3a6a6eb957ec6d0e6a38c24d8`
(`develop`, `feat(devnet): attach RVC with health gate and rvc.json`).

---

## Verdict

| Field | Value |
|---|---|
| Outcome | **blocked** |
| Blocker | Docker VM RAM &lt; 8 GiB (preflight usage exit **2**) |
| Live `/health` 200 | not observed |
| Live DN-1 double-run | not observed |
| Included attestation | not observed |
| `rvc_attestations_total{status="success"}` | not observed |
| `rvc_slashing_protection_checks_total{result="blocked"}` | not observed |
| S1 wall-clock (fresh clone → first attested epoch) | not measured |

### Exact Docker info numbers (the gate)

Preflight reads `docker info --format '{{.NCPU}} {{.MemTotal}}'` and integer-divides
`MemTotal` by `1024 ** 3` (`scripts/devnet/00-preflight.sh`). Captured on this host:

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
Docker Desktop Linux VM.

### Command that stopped the sequence

```bash
scripts/devnet/up.sh --profile fast < /dev/null
```

| Field | Value |
|---|---|
| Started (UTC) | 2026-09-13T00:24:38Z |
| Ended (UTC) | 2026-09-13T00:24:39Z |
| `/usr/bin/time -p` real | **1.23 s** |
| Exit | **2** (`die_usage`) |
| stderr | `[INFO] running 00-preflight.sh` / `[ERROR] need >= 8 GiB RAM (docker VM has 3 GiB)` |
| stdout | empty |
| Containers started | none (`docker ps -a --filter name=eth-devnet` empty) |
| `scripts/devnet/data/` | not created |
| BN `http://127.0.0.1:5052` | connection refused |
| RVC `http://127.0.0.1:8080/health` | connection refused |

`pull_images` never ran (it is after `check_resources`). The three pinned images
were already present from earlier work; see [Image digests](#image-digests).

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
| Free disk (data volume) | 509 GiB available on `/System/Volumes/Data` (926 GiB, 44 % used) |
| Worktree | `/Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a09822-c114-7742-975a-db770fc1c8d0` |
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
against those refs on this host **before** the blocked `up.sh` — not from a live
bring-up (preflight never reached `pull_images`).

| Env key | Pin (`repo:tag@sha256:<index digest>`) | `docker image inspect` |
|---|---|---|
| `IMG_GETH` | `ethereum/client-go:v1.17.5@sha256:523d3ba26623a619e912019068dc2784f02934070ac46bdae4d5b9df0d917814` | present; `Id=sha256:523d3ba26623a619e912019068dc2784f02934070ac46bdae4d5b9df0d917814`; `Architecture=arm64`; `Os=linux`; `Size=25982051`; `RepoDigests=["ethereum/client-go@sha256:523d3ba26623a619e912019068dc2784f02934070ac46bdae4d5b9df0d917814"]`; `RepoTags=["ethereum/client-go:v1.17.5"]`; `Created=2026-07-27T09:57:34Z` |
| `IMG_LIGHTHOUSE` | `sigp/lighthouse:v8.2.2@sha256:9a62bb8705455136e1cf96613460960f80dc2faa9d75b5c16a3bfcc9210dcdd1` | present; `Id=sha256:9a62bb8705455136e1cf96613460960f80dc2faa9d75b5c16a3bfcc9210dcdd1`; `Architecture=arm64`; `Size=63107227`; `RepoDigests=["sigp/lighthouse@sha256:9a62bb8705455136e1cf96613460960f80dc2faa9d75b5c16a3bfcc9210dcdd1"]`; `Created=2026-08-18T00:24:17Z` |
| `IMG_GENESIS` | `ethpandaops/ethereum-genesis-generator:6.2.1@sha256:15bb557cbd6d29fc1b7516a7147326a8c8d3af54f3c3ac534ec8772f6e875256` | present; `Id=sha256:15bb557cbd6d29fc1b7516a7147326a8c8d3af54f3c3ac534ec8772f6e875256`; `Architecture=arm64`; `Size=93774224`; `RepoDigests=["ethpandaops/ethereum-genesis-generator@sha256:15bb557cbd6d29fc1b7516a7147326a8c8d3af54f3c3ac534ec8772f6e875256"]`; `Created=2026-08-24T14:47:03Z` |

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
| `data/keys/rvc/pubkeys.txt` | 16 × lowercase `0x`-prefixed 48-byte pubkeys | absent |
| `runs/<id>/rvc.json` `pubkeys` / `key_range` | would name those 16 keys | not written |

---

## Genesis validators root

**Not observed.** No BN, no `data/genesis/genesis_validators_root.txt`, no
`/eth/v1/beacon/genesis`. ADR-013 forbids inventing this from `devnet.env`.

---

## Sequence attempted

Issue 3.4 sequence, stdin closed:

1. `scripts/devnet/up.sh --profile fast < /dev/null` — **exit 2** at
   `00-preflight.sh` Docker VM RAM gate (above).
2. `scripts/devnet/attach-rvc.sh --run-dir scripts/devnet/runs/s1-blocked --profile fast < /dev/null`
   was still invoked to record the next failure, not because the chain was up.

| Field | Value |
|---|---|
| Attach started (UTC) | 2026-09-13T00:24:55Z |
| Attach ended (UTC) | 2026-09-13T00:24:56Z |
| `/usr/bin/time -p` real | **0.42 s** |
| Exit | **1** (`die_infra`) |
| stderr | `[ERROR] RVC binary not found at …/target/release/rvc (this script never builds it)` |
| `runs/s1-blocked/` | empty directory created by `resolve_run_dir`; **no** `rvc.json` |

`target/release/rvc` was missing. Building it is an allowed operator step, not a
Rust source change. **It was not built:** `up.sh` already cannot pass preflight
on this Docker VM, so attach cannot reach a live BN even with a binary. A
release build would not change this record's live KPI cells.

Commands **not reached** (would have been, after head epoch ≥ 3):

```bash
python3 scripts/validator_perf.py \
  --beacon-url "http://127.0.0.1:${CL_HTTP_PORT}" \
  --pubkeys-file scripts/devnet/data/keys/rvc/pubkeys.txt \
  --epochs 1 --allow-unfinalized --json
```

`CL_HTTP_PORT=5052` in `devnet.env`. `--beacon-url` is required (A3-6).

---

## `validator_perf.py` JSON

**Not run.** No JSON to paste. A fabricated object would be a false S1.

---

## Live metrics

**Not scraped.** No RVC `/metrics` listener.

| Series | Live value |
|---|---|
| `rvc_attestations_total{status="success"}` | not observed |
| `rvc_slashing_protection_checks_total{result="blocked"}` | not observed |

---

## Profile / doppelganger (A2)

| Field | Live value |
|---|---|
| Requested profile | `fast` |
| `FAST_DOPPELGANGER` in `devnet.env` | `off` → `doppelganger_detection = false` once rendered |
| `data/rvc/config.toml` | never rendered |
| `data/rvc/rvc.log` doppelganger line | no log file |
| RVC process exit | no process |

---

## Wall-clock

| Span | Reading |
|---|---|
| `up.sh` attempt | **1.23 s** real (2026-09-13T00:24:38Z – 00:24:39Z) |
| `attach-rvc.sh` attempt | **0.42 s** real (2026-09-13T00:24:55Z – 00:24:56Z) |
| Wait for head epoch ≥ 3 (~19 min) | not started |
| S1 (clone → first attested epoch, target ≤ 20 min) | **not measured** — observation, not a gate |

---

## Acceptance criteria

| AC | Result |
|---|---|
| `/health` 200 within 120 s against the real BN; `rvc.json` names the `$RVC_KEYS` pubkeys | **blocked** — no BN, no RVC, no `rvc.json` |
| `attach-rvc.sh --run-dir <new id> < /dev/null` a second time no-ops with pid unchanged (live DN-1) | **blocked** — first attach never spawned a pid |
| `rvc.log` shows `$RVC_KEYS` keystores loaded; no `No password found for public key` | **blocked** — no log |
| `validator_perf.py --epochs 1 --allow-unfinalized --json` ≥ 1 included attestation (exit 0 or 3/degraded) | **blocked** — command not reached |
| `rvc_attestations_total{status="success"} > 0` and `rvc_slashing_protection_checks_total{result="blocked"} == 0` | **blocked** — no scrape |
| `--profile fast`: `doppelganger_detection = false`; no `doppelganger` log line; no non-zero RVC exit | **blocked** — config/log never produced |
| `milestone-s1.md` with every field filled, or explicit blocked-with-reason | **this file** — blocked-with-reason; live fields marked not observed |

---

## How to unblock (operator, not this issue)

Raise Docker Desktop VM memory so preflight's integer GiB is ≥ 8, then re-run
the 3.4 sequence. The check is:

```bash
docker info --format '{{.NCPU}} {{.MemTotal}}'
# need: NCPU >= 4 and MemTotal // (1024 ** 3) >= 8
```

On this host that means `settings-store.json` `MemoryMiB` **4096 → ≥ 8192** (and
a Docker Desktop restart so `MemTotal` updates). Do not lower
`PREFLIGHT_MIN_RAM_GIB` to sneak past the gate — that is not an S1 observation.

Once unblocked, fill the live cells in a follow-up record rather than editing
this blocked baseline in place. Phase 5 should treat this file as "S1 not yet
observed on the F9 Docker VM" and re-measure under `run.sh`.
