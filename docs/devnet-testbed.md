# Local devnet performance testbed

`scripts/devnet/` brings up a local Electra chain (geth + Lighthouse), attaches a native `rvc` to a disjoint key range, soaks N epochs, and writes a pass/fail verdict. The mnemonic in [`scripts/devnet/devnet.env`](../scripts/devnet/devnet.env) is a **public BIP-39 test vector** (`test test test test test test test test test test test junk`). It is usable only on this stack. Every stage that launches, attaches, soaks, or reports refuses `CHAIN_ID ≠ 1337` (`require_chain_1337`, R6) and aborts with usage exit `2` before those keys can touch a live chain (`down.sh` and `up.sh --dry-run` do not call it — teardown and a plan-print must still run). Do not export `CHAIN_ID` to any other value, and do not point this mnemonic at any other network.

The scripts never compile RVC, never prompt on the default path (`< /dev/null`), and never write under `plan/`. Chain-side numbers come from [`validator-perf.md`](validator-perf.md) (`scripts/validator_perf.py`), consumed verbatim.

## Prerequisites

From the repo root. All of these are required; preflight exits `2` on the first miss.

| Tool | Why | Check |
|------|-----|--------|
| Docker daemon | geth, Lighthouse BN/VC, genesis-generator | `docker info >/dev/null` |
| `jq` | JSON contracts (`run.json`, `verdict.json`, inventory) | `command -v jq` |
| `curl` | BN + RVC health and `/metrics` | `command -v curl` |
| `openssl` | JWT for the EL/CL auth RPC | `command -v openssl` |
| Python 3.11+ | `validator_perf.py`, `devnet_report.py`, path/atomic helpers | `python3 --version` |
| `target/release/rvc` | native attach (the scripts **never** build it) | `test -x target/release/rvc` |

Host floor (F9): **≥ 4 CPUs, ≥ 8 GiB RAM, ≥ 20 GiB free** under `scripts/devnet/data/`. Preflight also reads the **Docker VM** (`docker info --format '{{.NCPU}} {{.MemTotal}}'`) and integer-divides `MemTotal` by `1024 ** 3`. The gate is that **printed integer**, not the Docker Desktop slider. A VM set to 4 GiB (`MemoryMiB=4096`) reports **3 GiB**; Desktop “8 GiB” / `MemoryMiB=8192` still reports **~7 GiB** (same ~180 MiB overhead) and dies with `need >= 8 GiB RAM (docker VM has 7 GiB)`. Raise until `MemTotal // (1024 ** 3)` is **≥ 8** — on this machine that is likely **≥ 9 GiB / 9216 MiB** — then restart Docker so `MemTotal` updates. Do not lower `PREFLIGHT_MIN_RAM_GIB`.

```bash
python3 --version          # 3.11 or newer
command -v jq curl openssl
docker info >/dev/null
docker info --format '{{.NCPU}} {{.MemTotal}}'
# need: NCPU >= 4 and MemTotal // (1024 ** 3) >= 8
# Desktop "8 GiB" / 8192 MiB is not enough (~7 GiB after VM overhead).
# Raise until the printed integer is ≥ 8 (this host: likely ≥ 9216 MiB).

# Build once. The testbed never compiles RVC.
cargo build --release
test -x target/release/rvc

# Process env wins over devnet.env. An exported CHAIN_ID other than 1337 is exit 2.
echo "${CHAIN_ID:-1337}"
unset CHAIN_ID
```

Images are pinned in `scripts/devnet/devnet.env` as `repo:tag@sha256:<index digest>` (geth `v1.17.5`, Lighthouse `v8.2.2`, genesis-generator `6.2.1`). First preflight pulls them; later runs skip a present pin unless `--force`.

Defaults: `NUM_VALIDATORS=64`, `RVC_KEYS=16` (Lighthouse VC gets derivation `[0, 48)`, RVC gets `[48, 64)`), `CHAIN_ID=1337`, Electra at epoch 0, 12 s × 32 slots.

## Platform support

Pinned images are **manifest-list (index) digests**, never a per-arch `images[].digest`. `devnet.env` records the matrix both this host and `ubuntu-latest` must run:

```
REQUIRED_PLATFORMS="linux/amd64 linux/arm64"
```

That key is asserted, not decorative. `00-preflight.sh` calls `assert_image_platforms` **before any `docker pull`**, against the `@sha256:`-pinned ref (never the floating tag — that would inspect a different image):

1. Read the **Docker daemon** platform (`docker version -f '{{.Server.Os}}/{{.Server.Arch}}'`). Docker Desktop on macOS arm64 reports `linux/arm64`; that is what a pull resolves against, not `darwin/arm64`.
2. Inspect each pin's index **from the registry** (`docker manifest inspect`, falling back to `docker buildx imagetools inspect --raw`). This is not an offline probe of a locally cached image: a present pin still needs Hub (or the fallback) and a Hub 401 / missing `buildx` is named on the usage-2 line.
3. Drop `unknown/unknown` attestation rows. Every `REQUIRED_PLATFORMS` entry must appear in every index, and the host platform must be one of them.
4. Exit **2** (`die_usage`) naming the image and platform if either check fails, or if the digest is a single-arch manifest (`not a multi-arch index`) rather than a list. **No layers are pulled.**

A host whose platform is missing from an index, or an index missing a required platform the host is not running on, both fail closed the same way. Do not pin a per-arch blob to "make it smaller": the other platform then has no index entry and preflight refuses to start.

Live `00-preflight.sh < /dev/null` on this F9 host (2026-09-13) exits **2** in 1 s: `need >= 8 GiB RAM (docker VM has 3 GiB)`. The RAM gate runs before the index-entry check; `PREFLIGHT_MIN_RAM_GIB` was not lowered. The platform matrix is proven offline by the stub tests; the linux/amd64 half is the nightly (issue 6.5).

## Quick start

One command, stdin closed, from a clean checkout with the purge root removed. `--profile` is required.

```bash
scripts/devnet/run.sh --profile fast < /dev/null
```

That is Launch → Attach → soak → Gather → teardown. Default teardown purges `scripts/devnet/data/` (EL/CL datadirs, keys, RVC slashing DB) and leaves `scripts/devnet/runs/<run-id>/` in place. `run-id` is `<UTC compact>-<git short sha>` (example: `20260913T060145Z-4a619dff`).

```bash
ls -1t scripts/devnet/runs | head -1
RUN=$(ls -1t scripts/devnet/runs | head -1)
jq '{verdict, exit_code, gates, annotations}' "scripts/devnet/runs/${RUN}/verdict.json"
```

A green run has `"verdict": "pass"` and `"exit_code": 0`. A `fast` window with no proposal is still a pass; look for `"no_proposal_window"` in `annotations`. A short unfinalized window often annotates `"degraded"` (see [Exit codes](#exit-codes)).

`--keep` skips teardown (chain stays up). `--profile safe` soaks 8 epochs with doppelganger detection **on** and applies `--fail-under participation_rate=0.95,target_rate=0.95`.

| Profile | Epochs | Doppelganger | `--fail-under` |
|---------|--------|--------------|----------------|
| `fast` | 4 (`FAST_EPOCHS`) | off | unset |
| `safe` | 8 (`SAFE_EPOCHS`) | **on** | `participation_rate=0.95,target_rate=0.95` |

A second `run.sh --profile fast < /dev/null` after a default (no `--keep`) run starts from a **fresh genesis**: `down.sh --data` already wiped the purge root. That is the S8 / DN-12 path.

## Launch

`scripts/devnet/up.sh` sequences `00-preflight.sh` → `01-genesis.sh` → `02-keys.sh` → `03-chain.sh`. It is idempotent: a second run with the chain already up is a no-op. Child exit codes propagate unchanged. It does **not** mint a run id or write `run.json`.

A staged Launch → Attach → Gather that needs `report.sh` has to go through `run.sh` first, so `run.json` exists before report:

```bash
scripts/devnet/run.sh --profile fast --stages up --keep --run-id manual < /dev/null
```

`--stages` always requires `--run-id`. `--keep` leaves the three containers running so Attach can follow. This writes `scripts/devnet/runs/manual/run.json`.

Ends when geth, the Lighthouse BN, and the Lighthouse VC on `[0, N−K)` are healthy and the BN head is Electra (`current_version == ELECTRA_FORK_VERSION`, `SECONDS_PER_SLOT=12`). Ports: EL RPC `8545`, BN HTTP `5052`, RVC metrics later on `8080`.

Stale EL/CL datadirs (GVR mismatch with `data/genesis/`) exit **2** and name `--force`. `--force` regenerates **genesis and keys together** (JWT, GVR, both VC and RVC subsets) — that coarseness is [ADR-003](#troubleshooting) / ADR-006, not a bug. See [Troubleshooting](#troubleshooting).

Standalone `up.sh` can bring the chain up for debugging, but **cannot feed `report.sh`** (usage **2**, naming `run.sh` — no `run.json`):

```bash
scripts/devnet/up.sh --profile fast < /dev/null
```

## Attach

`scripts/devnet/attach-rvc.sh` probes the live BN for genesis time and genesis validators root (never `devnet.env` — ADR-013), renders `network = "custom"` config under `scripts/devnet/data/rvc/`, starts `target/release/rvc`, and waits for `GET /health` → 200. `--run-dir` is required (no `runs/standalone` fallback). Default wait is 120 s (`--timeout`).

After Launch minted `runs/manual/` via `run.sh`:

```bash
scripts/devnet/run.sh --profile fast --stages attach --keep --run-id manual < /dev/null
```

The attach verb itself, pointed at that same dir:

```bash
scripts/devnet/attach-rvc.sh --profile fast --run-dir scripts/devnet/runs/manual < /dev/null
```

Success writes `runs/<id>/rvc.json` (endpoint, pid, pubkey set, key range, config path). **Timeout is exit 5 and no `rvc.json` is written** — soak and report then fail closed (usage 2, naming `attach-rvc.sh`). Already-attached (live pid + `/health` 200 owned by that pid) is a no-op; `--force` kills our rvc first.

`--docker` / `--docker=*` exits 2: *attach-rvc.sh --docker is not implemented (Phase 6 / DN-15)*. `run.sh --docker` passes that flag through and fails the same way.

`--profile fast` turns doppelganger **off** in the rendered config. Detection is **on only under `--profile safe`**. A latent key overlap will not be caught on `fast`.

## Gather

Two steps: soak (capture the metric window) then report (both halves + verdict). `report.sh` is a pure function of the run dir and needs `run.json` (produced by `run.sh`) plus `rvc.json` (produced by `attach-rvc.sh`). Standalone `up.sh` never writes `run.json`, so a Launch that skipped `run.sh` dies here with usage **2** naming `run.sh`.

Keep the chain and gather against the minted id:

```bash
scripts/devnet/run.sh --profile fast --stages soak,report --keep --run-id manual < /dev/null
```

### Soak

Holds N epochs behind per-slot health gates. Aborts **3** if RVC `/health` ≠ 200, BN `/eth/v1/node/health` ∉ {200, 206}, or K8 `result="blocked"` increases. A transient scrape error is a warning; the sample is skipped; the soak continues. Start/end scrapes are written even on a gate trip so report can still run.

`--epochs` is required on the stage itself (`run.sh` supplies it from the profile). `--gate-interval` defaults to `GATE_INTERVAL_SLOTS=1`. `--gate-interval 0` still visits every slot but does not sleep. `--run-dir` is required (empty `RUN_DIR` is usage **2** naming `attach-rvc.sh`, not a `standalone` fallback).

```bash
scripts/devnet/soak.sh --run-dir scripts/devnet/runs/manual --epochs 4 < /dev/null
```

Writes `metrics-start.txt`, `metrics-end.txt`, `samples.jsonl`.

### Report

Shells out to `scripts/validator_perf.py` for RVC's pubkeys only (`--pubkeys-file`, `--epochs` from `run.json`, `--allow-unfinalized`, `--json`) and to `scripts/devnet_report.py report` for the client half. Never passes `--degraded-ok` — it must observe validator_perf's `3` to annotate it.

```bash
scripts/devnet/report.sh --run-dir scripts/devnet/runs/manual < /dev/null
```

Writes `rvc-pubkeys.txt`, `chain.json`, `client.json`, `report.txt`, `verdict.json`. Re-report an old dir the same way; K8 `blocked` in `metrics-end.txt` still exits **3** (S7).

Inspect:

```bash
jq '{verdict, exit_code, gates, annotations}' scripts/devnet/runs/manual/verdict.json
jq '.gates' scripts/devnet/runs/manual/verdict.json
```

Gates: `s5a_presence` (all 13 K families in `client.json`), `s5b_liveness` (K1, K3, K4, K5, K7, `rvc_duties_fetched_total`, `rvc_bn_health_tier` non-zero), `s7_blocked` (K8 `blocked` end == 0), `chain_thresholds` (validator_perf). A missing K family is health **3**, not KPI **4**.

### Teardown

```bash
scripts/devnet/down.sh --run-dir scripts/devnet/runs/manual --data < /dev/null
```

`--data` purges `scripts/devnet/data/` only. `runs/` is immutable and is never deleted (ADR-005). Absent inventory rows are skips, never errors. A missing `inventory.json` falls back to an `eth-devnet-*` container name scan. Default `run.sh` (no `--keep`) already runs this via an EXIT trap and will not overwrite an earlier non-zero stage code.

`run.sh --stages down --run-id manual` also passes `--data`.

## Flag reference

Every operator verb sources `parse_common_flags`. Space and `=` forms are accepted (`--run-dir D` or `--run-dir=D`). Unknown flags exit **2**. `--` ends flag parsing.

### Common (all six verbs)

| Flag | Default | Notes |
|------|---------|--------|
| `--force` | off | Idempotency override. `up.sh` forwards it to 00–03 only. `run.sh` forwards it to 00–03 **and** attach. Regenerates genesis **and** keys together (ADR-003/006). |
| `--interactive` | off | Accepted and forwarded. Default path never prompts (DN-1, stdin closed). |
| `--dry-run` | off | Print the stage plan. **Not** a universal exit 0 — each verb still enforces its own preconditions (see below). |
| `--run-dir PATH` | no default on attach / soak / report (required or fail-closed); `down.sh` / genesis / chain fall back to `runs/standalone`; `run.sh` sets `runs/<run-id>/` | Refuses a symlink or world-writable dir. |
| `--data-dir PATH` | `scripts/devnet/data` | Override the purge root. Not `--data` (that is `down.sh` only). Refuses a symlink or world-writable dir. |
| `--profile {fast\|safe}` | unset (`attach-rvc.sh` defaults `fast`) | **Required on `run.sh`**. Sets `EPOCHS`, `DOPPELGANGER`, and (safe only) `FAIL_UNDER`. |

`--dry-run` still runs that verb's flag parse and preconditions, then prints a plan. `run.sh` / `up.sh` / `down.sh` skip the binary and live artifacts (`run.sh --dry-run` does not resolve `RVC_BIN`; `up.sh --dry-run` does not call `require_chain_1337`). `attach-rvc.sh --dry-run` still requires `--run-dir`, still resolves `RVC_BIN` (infra **1** if missing), and still validates keys. `soak.sh --dry-run` still requires `--epochs` and `rvc.json`. `report.sh --dry-run` still requires `--run-dir`.

### `up.sh`

Common flags only. Forwards `--force`, `--interactive`, `--run-dir`, `--profile` to 00–03. Does not mint a run id.

### `attach-rvc.sh`

| Flag | Default | Notes |
|------|---------|--------|
| `--timeout N` | `120` | Positive integer. `/health` not 200 within N s → exit **5**, no `rvc.json`. |
| `--docker` | off | **Not implemented** (Phase 6 / DN-15). Any `--docker` / `--docker=*` → usage **2**. |

`--run-dir` is required (no `runs/standalone` fallback).

### `soak.sh`

| Flag | Default | Notes |
|------|---------|--------|
| `--epochs N` | (required) | Non-negative integer. `0` skips the slot loop (still writes empty scrapes). `run.sh` supplies the profile value and rejects `0`. |
| `--gate-interval N` | `GATE_INTERVAL_SLOTS` (`1`) | Non-negative integer. `0` = no sleep, still one gate per slot. |

Needs `--run-dir` and `rvc.json` in that dir (else usage **2**, naming `attach-rvc.sh`). Empty `RUN_DIR` does **not** fall back to `standalone`.

### `report.sh`

| Flag | Default | Notes |
|------|---------|--------|
| `--strict` | off | validator_perf exit `3` becomes orchestrator **3** instead of `0` + `"degraded"`. |
| `--fail-under METRIC=VALUE` | none (`safe` profile supplies the default) | Repeatable. Forwarded verbatim to `validator_perf.py`. Child `4` → orchestrator **4**. |

`--run-dir` is required (no `runs/standalone` fallback). Needs `run.json` (else usage **2**, naming `run.sh`). Allowed metric names: `participation_rate`, `source_rate`, `target_rate`, `head_rate`, `attester_effectiveness`, `sync_participation_rate`, `estimated_apr` (see [validator-perf.md](validator-perf.md)).

### `down.sh`

| Flag | Default | Notes |
|------|---------|--------|
| `--data` | off | `rm -rf` the purge root after inventory teardown. Never touches `runs/`. `run.sh`'s trap always passes `--data`. |

Does not call `require_chain_1337` (teardown must still run). Unsets `MNEMONIC`.

### `run.sh`

| Flag | Default | Notes |
|------|---------|--------|
| `--profile {fast\|safe}` | (required) | See [Quick start](#quick-start). |
| `--epochs N` | profile default | Positive integer. Overrides `FAST_EPOCHS` / `SAFE_EPOCHS`. |
| `--stages LIST` | `up,attach,soak,report` (teardown via trap) | Comma-separated `up\|attach\|soak\|report\|down`. Requires `--run-id`. |
| `--run-id ID` | minted `<UTC>-<git sha>` | `[A-Za-z0-9._-]+`, no leading `.`/`-`, no `..`. Directory is `scripts/devnet/runs/<id>/`. |
| `--keep` | off | Skip the EXIT-trap `down.sh`. |
| `--docker` | off | Forwarded to `attach-rvc.sh` → currently usage **2** (Phase 6). |
| `--strict` | off | Forwarded to `report.sh`. |
| `--fail-under METRIC=VALUE` | profile / none | Repeatable; joined with commas and forwarded to `report.sh`. |

Missing `target/release/rvc` → usage **2** naming `cargo build --release`, **before** a run dir is minted. First non-zero child code is kept; teardown never overwrites it. Non-zero stages dump `docker logs` into `runs/<id>/logs/<container>.log`.

## Safe profile

`--profile safe` is the DN-18 path that proves the Phase 2 key split (DN-5) with doppelganger detection **on**. `resolve_profile` in `lib/common.sh` is the only producer of the four values; `03-chain.sh` / `attach-rvc.sh` / `soak.sh` / `report.sh` consume the variables, never `REPORT_FAIL_UNDER` and never the raw `--profile` flag.

| Knob | `fast` | `safe` |
|------|--------|--------|
| `EPOCHS` | 4 (`FAST_EPOCHS`) | 8 (`SAFE_EPOCHS`) |
| `DOPPELGANGER` | off | **on** |
| `SOAK_START_OFFSET_EPOCHS` | 0 | 3 |
| `FAIL_UNDER` | unset | `$REPORT_FAIL_UNDER` (`participation_rate=0.95,target_rate=0.95`) |

RVC omits `--no-doppelganger-detection` when `DOPPELGANGER=on` (CLI polarity; the TOML key is `[safety] doppelganger_detection`). The Lighthouse VC gets `--enable-doppelganger-protection` only under `safe`. Detection does **not** exit the process: it permanently closes the gate and logs `error!` once; that log line is the only detection signal. `run.json` records `soak_start_offset_epochs` and `fail_under`. `report.sh` forwards `--fail-under` from `FAIL_UNDER` (comma-split), never from `REPORT_FAIL_UNDER`.

### Why the soak starts at epoch 3 (P6-A2)

RVC withholds signing for 2 epochs (`DEFAULT_MONITORING_EPOCHS = 2`). A window that starts at genesis reports ≈ 0 attestations and fails S6. `soak.sh` therefore holds the DN-8 health gates for `SOAK_START_OFFSET_EPOCHS=3` (2 + 1 margin) **without sampling**, takes `metrics-start.txt` at that boundary, samples for `EPOCHS=8`, then holds **2 more epochs** of DN-8 gates (no sampling) so `validator_perf.py`'s `to_epoch ≤ head − 2` clamp does not pull the chain half back into the dark window. A dead BN during either hold still aborts **3**.

`validator_perf.py` is invoked with `--epochs` from `run.json` (not `--from-epoch`/`--to-epoch`). After offset 3 + sample 8 + clamp 2 the chain head is epoch **13 ≈ 83.2 min** (13 × 32 slots × 12 s) and the measured window is epochs 4…11. Live proof of the split is issue 6.6, not this wiring — and that live proof is **blocked** on this host (see below). `soak.sh` and `report.sh` call `resolve_profile` when `--profile` is set (`--epochs` on soak still wins). Re-report without `--profile` reads `fail_under` from `run.json`.

If `03-chain.sh`'s block-production health gate trips in the first ~2 epochs with Lighthouse VC doppelganger protection on (P6-A12, unverified at genesis), drop `--enable-doppelganger-protection` from the Lighthouse VC and record that DN-5 is proven from RVC's side only.

### Live S6 soak (issue 6.6)

**Not observed.** The first live `run.sh --profile safe --keep` on the developer host is **blocked** — see [`plan/devnet-testbed-2026-09-12/milestone-s6.md`](../plan/devnet-testbed-2026-09-12/milestone-s6.md). Do not treat the P6-A2 arithmetic (head epoch 13, 83.2 min, window 4…11) as a measurement.

| Field | P6-A2 / S6 predicted | Live |
|-------|----------------------|------|
| offset boundary (`SOAK_START_OFFSET_EPOCHS`) | epoch 3 | not observed |
| sample window | epochs 4…11 | not observed |
| chain head epoch | **13** | not observed |
| chain time (13 × 32 × 12 s) | 83.2 min | not measured |
| wall-clock (issue budget ~95 min) | — | not measured |
| Lighthouse VC DP delayed block production (P6-A12) | unverified at genesis | not observed |
| `rvc_attestations_total{status="success"}` delta | increase (disjoint keys) | not observed |
| `verdict.json` `participation_rate` / `target_rate` | ≥ 0.95 | not observed |
| `run.json` `profile` / `soak_start_offset_epochs` / `fail_under` | `safe` / `3` / `participation_rate=0.95,target_rate=0.95` | not written |
| `grep -c 'doppelganger Detected' data/rvc/rvc.log` | 0 on a non-empty log with startup markers | not observed (no log) |
| `report.sh --fail-under participation_rate=1.01` | exit 4, chain still up | not reached |

The live command stopped at `_resolve_rvc_bin` (usage **2**, missing `target/release/rvc`, `/usr/bin/time -p` real **0.52 s** on 2026-09-13T07:47:18Z). That 0.52 s is the usage-2 command, **not** a soak wall-clock. Even a release binary would still fail `00-preflight.sh` on this Docker VM (`docker info --format '{{.NCPU}} {{.MemTotal}}'` → `4 4107141120` → 3 GiB < 8). `--keep`, soak, KPI-breach re-report, and `down.sh --data` were not reached. Per-stage `run.json` `stages.*.seconds` do not exist. Do not invent them.

If a later host clears both gates (printed Docker VM GiB ≥ 8 **and** `target/release/rvc` present) and a `safe` run exits 0, write the measured head epoch, offset boundary, wall-clocks, and P6-A12 outcome in this table and in the S6 milestone. Do not edit these blocked cells in place. Do not lower `PREFLIGHT_MIN_RAM_GIB`.

## Exit codes

PRD §4 vocabulary, emitted only through `die_infra` / `die_usage` / `die_health` / `die_kpi` / `die_notready` in `lib/common.sh`.

| Code | Helper | Meaning | Typical cause |
|------|--------|---------|----------------|
| `0` | — | Pass | All gates green. `"degraded"` annotation is still `0` unless `--strict`. |
| `1` | `die_infra` | Infrastructure | Docker pull, genesis generator, keystore count, weak KDF, BN GET, `validator_perf.py` 1/2/5. |
| `2` | `die_usage` | Usage / preflight | Bad flag, missing tool, `CHAIN_ID ≠ 1337`, Docker VM &lt; 8 GiB, stale datadirs, missing `rvc.json`/`run.json`, missing `target/release/rvc` on `run.sh`, fork-schedule mismatch, `--docker`. |
| `3` | `die_health` | Health gate | RVC/BN unhealthy during soak, K8 `blocked` &gt; 0 (live or post-hoc), S5a missing family, S5b liveness, `--strict` + validator_perf `3`. |
| `4` | `die_kpi` | KPI threshold | `validator_perf.py` exit `4` (`--fail-under` breach). |
| `5` | `die_notready` | RVC never became ready | Attach `/health` timeout. **No `rvc.json`.** |

### `validator_perf.py` mapping (`report.sh`)

`--degraded-ok` is **not** passed. A short unfinalized `fast` window legitimately yields partial data.

| `validator_perf.py` | Orchestrator | Notes |
|---------------------|--------------|--------|
| `0` | `0` | `gates.chain_thresholds = "pass"` |
| `1` | `1` | `die_infra` |
| `2` | `1` | `die_infra` |
| `3` | `0` + `"degraded"` | `--strict` → `3` (`die_health`) |
| `4` | `4` | `die_kpi`; `gates.chain_thresholds = "fail"` |
| `5` | `1` | `die_infra` |

Among completed report gates the precedence is S7 / S5a / S5b (`3`) over a KPI `4` over a mapped degraded `3`. `verdict` is `"pass"` only when the assembled `exit_code` is `0`.

## Run-dir layout

Purge root `scripts/devnet/data/` is mutable and git-ignored. `scripts/devnet/runs/<id>/` is append-only, git-ignored, and **not** removed by `down.sh --data` (A6, ADR-005). `.gitignore` already lists both directories.

```
scripts/devnet/data/                         # purge root (--data)
  jwt/genesis/keys/{manifest.json,vc,rvc}/
  el/ cl/ rvc/{config.toml,validators.toml,rvc.pid,rvc.log,slashing_protection.sqlite}

scripts/devnet/runs/<id>/                    # kept after teardown
  run.json
  rvc.json
  inventory.json
  rvc-pubkeys.txt
  metrics-start.txt  metrics-end.txt  samples.jsonl
  client.json  chain.json  report.txt  verdict.json
  rvc/{config.toml,validators.toml}          # copies, not live paths
  logs/<container>.log
```

### `run.json` (writer: `run.sh`)

Start snapshot + end rewrite. Key paths: `schema_version`, `run_id`, `generated_at`, `git_sha`, `rvc_version`, `profile`, `epochs`, `key_range`, `pubkeys`, `genesis_validators_root`, `images.{geth,lighthouse,genesis}`, `fingerprint`, `stages.{up,attach,soak,report,down}.{exit_code,seconds}`, `verdict`, `window.{start_slot,end_slot,slots,epochs}`. Full list: [`scripts/tests/fixtures/run_json__keypaths.txt`](../scripts/tests/fixtures/run_json__keypaths.txt). `fingerprint` is `sha256` of chain params + image digests + key split + profile flags, **excluding** `rvc_version` (ADR-010).

### `rvc.json` (writer: `attach-rvc.sh`)

`schema_version`, `generated_at`, `endpoint`, `pid`, `key_range`, `pubkeys`, `config_path`. Full list: [`scripts/tests/fixtures/rvc_json__keypaths.txt`](../scripts/tests/fixtures/rvc_json__keypaths.txt). No `genesis_time` — soak reads that from the BN (ADR-013).

### `client.json` (writer: `devnet_report.py report`)

Top-level: `schema_version`, `generated_at`, `run`, `window`, `annotations`, `counters`, `histograms`, `gauges`, `presence`. Counters carry `start` / `end` / `delta` / `per_epoch` / `labels` / `monotonic_violation`. Histograms carry `p50` / `p95` / `p99` / `samples` / `saturated`. Full list: [`scripts/tests/fixtures/client_json__keypaths.txt`](../scripts/tests/fixtures/client_json__keypaths.txt).

K families (S5a presence is **family**-level; S5b non-zero required only where noted):

| K | Family | S5b non-zero |
|---|---------|--------------|
| K1 | `rvc_orchestrator_slots_processed_total` | yes |
| K2 | `rvc_orchestrator_missed_slots_total` | no (failure-only) |
| K3 | `rvc_orchestrator_slot_processing_duration_seconds` | yes |
| K4 | `rvc_attestations_total` | yes |
| K5 | `rvc_aggregations_total` | yes |
| K6 | `rvc_proposals_total` | no (`fast` may be 0 → `no_proposal_window`) |
| K7 | `rvc_signing_duration_seconds` | yes |
| K8 | `rvc_slashing_protection_checks_total` | `blocked` must be 0 (S7) |
| K9 | `rvc_slashing_reserve_tx_hold_duration_ms` | no |
| K10 | `rvc_slot_phase_block_start_offset_ms` | no |
| K11 | `rvc_duties_fetched_total` / `rvc_duty_reorg_detected_total` | fetched yes; reorgs no |
| K12 | `rvc_bn_health_tier` / `rvc_proposer_bn_latency_ms` | `rvc_bn_health_tier` yes |
| K13 | `rvc_tasks_running` / `rvc_task_exits_total` / `rvc_sse_events_dropped_total` | exits no |

### `verdict.json` (writer: `report.sh`)

```json
{
  "annotations": [],
  "exit_code": 0,
  "gates": {
    "chain_thresholds": "<pass|fail>",
    "s5a_presence": "<pass|fail>",
    "s5b_liveness": "<pass|fail>",
    "s7_blocked": "<pass|fail>"
  },
  "generated_at": "2026-09-13T00:00:00Z",
  "run_id": "<id>",
  "schema_version": 1,
  "verdict": "<pass|fail>"
}
```

`verdict` is `"pass"` only when `exit_code` is `0`. No live run on this host has produced either value.

Key paths: [`scripts/tests/fixtures/verdict_json__keypaths.txt`](../scripts/tests/fixtures/verdict_json__keypaths.txt). `chain.json` is `validator_perf.py --json` verbatim (upstream schema, no `schema_version` of our own).

### `report.txt`

Human two-halves table: client KPI rows, then `--- chain ---` with the same columns as [validator-perf.md](validator-perf.md) (`pubkey`, `index`, `status`, `part%`, `src%`, `tgt%`, `head%`, …). `null` renders as `—`, never `0`.

## Comparing two runs

`scripts/devnet_report.py compare` diffs two **finished** run directories. It is read-only and opens no socket.

```bash
scripts/devnet_report.py compare scripts/devnet/runs/<a> scripts/devnet/runs/<b>
scripts/devnet_report.py compare A B --rel 0.25 --abs-floor 1ms
scripts/devnet_report.py compare A B --json
```

Prints a per-KPI table (`kpi`, `A`, `B`, `delta`, `%`, `gate`). Exit **4** if any gated KPI regresses; **0** otherwise.

Default tolerances (Q4): latency and ratio KPIs use `rel=0.25` and `abs_floor=1ms`. A regression must exceed **both** the relative bound (strictly beyond: higher-is-worse `B > A × (1+rel)`, lower-is-worse `B < A × (1−rel)`) **and** `abs_floor` in the KPI's unit. Exact +25% does not fail. Failure-only KPIs gate at absolute 0 — K2 missed slots, K6 proposal failures, K8 `blocked`, K13 task exits. Only the worsening direction gates; an improvement is exit 0.

Chain half: gate only `participation_rate` and `target_rate`. Unknown `chain.json` keys render `gated=false` (including non-finite values, which are `absent`, never `0`). A missing KPI is `absent`, never `0`.

When the two `run.json` fingerprints differ **or either is missing**, compare prints `topology_delta` with the differing subkeys, sets `gated=false`, and exits **0** — it refuses to gate across topologies (ADR-010). `rvc_version` is not a fingerprint input.

## Measured wall-clocks (issue 5.6)

**Not observed.** The first live `run.sh --profile fast` end-to-end on the developer host is **blocked** — see [`plan/devnet-testbed-2026-09-12/milestone-s3-s8.md`](../plan/devnet-testbed-2026-09-12/milestone-s3-s8.md). Do not treat the arithmetic below as a measurement.

| Stage | `run.json` path | Live |
|-------|-----------------|------|
| up | `stages.up.seconds` | not observed |
| attach | `stages.attach.seconds` | not observed |
| soak | `stages.soak.seconds` | not observed |
| report | `stages.report.seconds` | not observed |
| down | `stages.down.seconds` | not observed |
| **total** (S3, N = 4, pre-built binary, target ≤ 45 min) | — | **not measured** |

S5a / S5b / S6b / S7 live cells are likewise **not observed** (no scrape, no `client.json`, no `verdict.json`). Arithmetic lower bound only: one epoch = 32 × 12 s = **6.4 min**; an N = 4 soak is 25.6 min of chain time; `validator_perf.py` clamps `to_epoch ≤ head − 2` even with `--allow-unfinalized`, so a full chain-side window wants head at epoch N + 2 ≈ **38.4 min**. S3's 45 min budget has almost no slack.

If a later host clears both gates (printed Docker VM GiB ≥ 8 **and** `target/release/rvc` present) and a run exits 0, `run.json` `stages.*.seconds` is the source of truth. Until then the S3–S8 milestone is the record. Do not treat an F9-shaped machine as a predicted `"pass"`.

## Troubleshooting

### Q1 — Lighthouse refuses Electra-at-genesis (ADR-008)

Open question: does pinned Lighthouse v8.2.2 start on Electra-at-genesis with FULU/BPO far-future and `BLOB_SCHEDULE: []`? If `03-chain.sh` dies with BN logs showing a genesis/fork rejection, **do not change scripts**. Flip the fork block in [`scripts/devnet/devnet.env`](../scripts/devnet/devnet.env) to Fulu-at-genesis (P-A6). Keep `ELECTRA_FORK_EPOCH=0`. Generator defaults for FULU/BPO are epoch 0 (ADR-008 is an env edit only):

```
FULU_FORK_EPOCH=0
BPO_1_EPOCH=0
BPO_2_EPOCH=0
```

Then re-run with `--force` so genesis **and** keys regenerate together:

```bash
scripts/devnet/run.sh --profile fast --force < /dev/null
```

`01-genesis.sh` templates `values.env` from those variables. `03-chain.sh` still asserts `head current_version == ELECTRA_FORK_VERSION`; if the BN comes up on Fulu (`0x70000000`) that assert prints both versions and exits **1**. Quote that line (or the BN rejection) and stop — do not lower the RAM gate to sneak past preflight. Issue 5.6 never started a BN, so Q1 is still unanswered.

### Stale datadirs — exit `2`, `--force` (ADR-003 / ADR-006)

```
EL datadir GVR does not match genesis (...); re-run with --force
```

`01-genesis.sh` owns the staleness verdict. `--force` on `up.sh` / `run.sh` is **coarse** (ADR-003 merged JWT+genesis and EL+BN+VC into two scripts): it rewrites the JWT, regenerates genesis (new GVR), and regenerates **both** key subsets together (ADR-006). Passwords and GVR must move together or the next attach hits a slashing-DB GVR mismatch (D4). There is no "genesis only" force. After `--force`, a leftover `data/rvc/slashing_protection.sqlite` from the old GVR is usage **2** (`stale slashing protection DB … purge`); `down.sh --data` (or the `run.sh` trap) removes it with the purge root.

### Weak-KDF abort — exit `1`

`02-keys.sh` reads every `voting-keystore.json` and aborts **1** (`keystore KDF too weak or unreadable`) if `.crypto.kdf.params.c < 10000`. The stage never passes `--insecure` to the key tool. Lighthouse only *warns* on PBKDF2 `c=2`; RVC skips the key and looks keyless, which then burns the 120 s attach window as exit **5**. If you see a weak-KDF abort, do not workaround with `--insecure`; fix the generator invocation (already the default).

### Exit `5` — no `rvc.json`, fail closed

Attach timeout (`--timeout`, default 120 s) kills the spawned pid, copies `rvc.log` into `runs/<id>/logs/`, and **does not write `rvc.json`**. `soak.sh` and `report.sh` then exit **2** naming `attach-rvc.sh`. Look at `data/rvc/rvc.log` and `runs/<id>/logs/`. Typical causes: missing/unexecutable `target/release/rvc` (on attach this is infra **1**, on `run.sh` usage **2**), fork-schedule mismatch (head `current_version` not in `/eth/v1/config/spec` → usage **2**, both printed), GVR mismatch vs `genesis_validators_root.txt`, or a weak-KDF keystore that slipped through and left RVC with zero keys.

### Doppelganger only under `--profile safe`

`fast` sets `FAST_DOPPELGANGER=off` so S1/S3 fit in one sitting (~2 epochs ≈ 12.8 min otherwise). `--profile safe` turns detection on (`SAFE_DOPPELGANGER=on`) and is what proves the DN-5 disjoint split (DN-18, Phase 6). A `fast` green run does **not** prove "no key overlap".

### Docker VM RAM / missing binary (this host's 5.6 / 6.6 snag)

```
[ERROR] RVC binary not found at …/target/release/rvc; cargo build --release     # run.sh, exit 2
[ERROR] need >= 8 GiB RAM (docker VM has 3 GiB)                                  # 00-preflight, exit 2
```

Both are usage **2**. Building RVC does not clear the RAM gate. Raise Docker Desktop until `docker info --format '{{.MemTotal}}'` integer-divided by `1024 ** 3` is **≥ 8**. Desktop “8 GiB” / `MemoryMiB=8192` is **not** enough (~7 GiB after VM overhead). On this host that is likely **≥ 9216 MiB**. Restart Docker so `MemTotal` updates. Do not lower `PREFLIGHT_MIN_RAM_GIB`. Issue 6.6 (`run.sh --profile safe --keep`) hit the same two gates; see [`milestone-s6.md`](../plan/devnet-testbed-2026-09-12/milestone-s6.md).

### `CHAIN_ID` leaked from the shell

Process env wins over `devnet.env`. `CHAIN_ID=1 cargo test` leftovers, CI env, etc. become `CHAIN_ID must be 1337 (got 1)`. `unset CHAIN_ID` and retry.

### `run.sh --stages` without `--run-id`

Usage **2**. Partial reruns always name an existing (or to-be-created) id under `scripts/devnet/runs/`.

## Dry-run notes (DN-13 proxy)

Proxy for "a reader who has never seen the repo reproduces a green run from this doc alone": the author copy-pastes only the commands in this file on a clean clone with the purge root removed. A second-reader sign-off is **follow-up, not a phase blocker**.

A green run's `verdict.json` has `"verdict": "pass"`. This attempt produced no `verdict.json`. Q1 is unanswered (no BN). Do not treat an F9-shaped host as a predicted `"pass"`.

| Field | Value |
|-------|--------|
| Who | Joonkyo Kim (`rootwarp@gmail.com`) |
| Date (UTC) | 2026-09-13T06:06:09Z |
| Host | `nil.local` (macOS arm64, host 14 CPU / 24 GiB; Docker Desktop VM 4 CPU / 3.825 GiB) |
| Clone path | `/tmp/rvc-devnet-5-7-dryrun` (`git clone --local` of this worktree, branch `feature/5-7-devnet-testbed-docs` @ `4a619dff`) |
| Worktree (same commands) | `/Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a09957-02c0-7610-90a5-3cf6a969151c` |
| Purge root | absent in both trees (`scripts/devnet/data/` and `scripts/devnet/runs/` not created) |
| Outcome | **blocked** — no `verdict.json` |

Commands typed (verbatim from this doc; stdin closed on the stage scripts):

```text
python3 --version                          # Python 3.13.7
command -v jq curl openssl                 # all present
docker info >/dev/null                     # ok
docker info --format '{{.NCPU}} {{.MemTotal}}'
# → 4 4107141120  (MemTotal // 1024**3 = 3 GiB; gate is ≥ 8)
echo "${CHAIN_ID:-1337}"                   # 1337
unset CHAIN_ID
test -x target/release/rvc                 # missing
scripts/devnet/run.sh --profile fast < /dev/null
# exit 2 in 0.52 s
# [ERROR] RVC binary not found at /private/tmp/rvc-devnet-5-7-dryrun/target/release/rvc; cargo build --release
# run dir not minted; no containers
```

`cargo build --release` from the prerequisite block was **not** run. Even a successful build would still fail `00-preflight.sh` on this Docker VM. Confirmed with the Launch command from this doc, after the one-command stopped:

```text
scripts/devnet/up.sh --profile fast < /dev/null
# exit 2 in 1.01 s
# [INFO] running 00-preflight.sh
# [ERROR] need >= 8 GiB RAM (docker VM has 3 GiB)
```

Inspect commands were typed and failed closed (no run dir, as the one-command never minted one):

```text
ls -1t scripts/devnet/runs | head -1
# ls: scripts/devnet/runs: No such file or directory
```

Worktree repeat of `scripts/devnet/run.sh --profile fast < /dev/null`: exit **2**, 0.21 s, same missing-binary message against this worktree path. `pgrep -f target/release/rvc` empty; `docker ps -aq --filter name=eth-devnet-` empty.

How to unblock (operator, not this doc): raise Docker Desktop until `MemTotal // (1024 ** 3) ≥ 8` (Desktop 8 GiB / 8192 MiB is not enough; this host likely ≥ 9216 MiB) and restart; `cargo build --release`; then re-run the Quick start. Record measured `stages.*.seconds` and the actual `verdict` in a follow-up; do not invent them here. See [`milestone-s3-s8.md`](../plan/devnet-testbed-2026-09-12/milestone-s3-s8.md).

Second-reader sign-off: **not done** (follow-up, not a phase blocker).
