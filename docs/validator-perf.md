# Validator performance estimator

`scripts/validator_perf.py` estimates consensus-layer performance of a validator set from a beacon node's HTTP API. It does not sign, does not talk to the execution layer, and does not require `rvc` to be running.

The script is stdlib-only Python 3.11+. It prints a human table on stdout by default. Diagnostics go to stderr.

To drive the same script from a local geth + Lighthouse + `rvc` stack (Launch / Attach / Gather, `verdict.json`), see [devnet-testbed.md](devnet-testbed.md).

## Prerequisites

- Python 3.11 or newer (`python3 --version`)
- A reachable beacon node (Lighthouse, Prysm, Teku, Nimbus, Lodestar, or Grandine) serving the Beacon API
- At least one validator pubkey (48-byte BLS hex)

Optional: [uv](https://docs.astral.sh/uv/) so the shebang `uv run --script` works. Plain `python3` is enough.

## Quick start

```bash
# Resolve keys and the epoch window; no metrics yet.
./scripts/validator_perf.py \
  --validators-config validators.toml \
  --config config.toml \
  --dry-run

# Full estimate: human table on stdout.
./scripts/validator_perf.py \
  --validators-config validators.toml \
  --config config.toml

# Same thing without a shebang:
python3 scripts/validator_perf.py \
  --validators-config validators.toml \
  --config config.toml
```

`--config` is an rvc `config.toml`. The script only reads `beacon_nodes` or `beacon_url` from it. `--validators-config` is an rvc `validators.toml`; the script only reads `[[validators]].pubkey`. You can skip both files and pass `--beacon-url` and `--pubkey` instead.

## Inputs

### Pubkeys (union)

At least one source is required. All supplied sources are merged and de-duplicated in first-seen order:

1. `--pubkey 0x…` (repeatable)
2. `--pubkeys-file PATH` — one key per line; blanks and `#` comments ignored
3. `--validators-config PATH` — every `[[validators]].pubkey` (see `validators.example.toml`)

Keys are lowercased and given a `0x` prefix if missing. A value that is not exactly 48 bytes of hex exits `2` and names the source and line.

```bash
./scripts/validator_perf.py \
  --beacon-url http://127.0.0.1:5052 \
  --pubkey 0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a
```

### Beacon URLs (override)

At least one URL is required:

1. `--beacon-url URL` (repeatable). If any flag is present, the config file is ignored for URLs.
2. Otherwise `--config PATH`: `beacon_nodes` if that array is present and non-empty, else `beacon_url`.

```toml
# config.toml — same keys rvc uses
beacon_url = "http://127.0.0.1:5052"
# beacon_nodes = ["http://bn1:5052", "http://bn2:5052"]
```

A URL may include basic auth or a path token. Logs and JSON never print the full URL; they show `scheme://host:port` only.

The script picks the first node that answers `node/version` and is not syncing. If that node dies mid-run, it promotes to the next URL (one advance per dying endpoint) and tags later epochs `endpoint_failover`.

### Epoch window

Inclusive `[from_epoch, to_epoch]`. Spec constants (`SLOTS_PER_EPOCH`, `SECONDS_PER_SLOT`, …) come from `GET /eth/v1/config/spec`, not hardcoded mainnet values.

Default:

- `MAX_SAFE_EPOCH = head_epoch − 2` (attestation rewards for epoch *N* are not final until *N+1* is processed)
- `to_epoch = min(MAX_SAFE_EPOCH, finalized_epoch)`
- `from_epoch = to_epoch − 31` (32 epochs)

| Flag | Effect |
|------|--------|
| `--epochs K` | Last *K* safe epochs (default 32). Cannot be combined with `--from-epoch` / `--to-epoch`. |
| `--from-epoch` / `--to-epoch` | Explicit inclusive range |
| `--allow-unfinalized` | Lifts the finalized clamp only; still respects `head − 2` |
| `--force-unsafe-window` | Allows `--to-epoch` past `MAX_SAFE_EPOCH` (warns; balance snapshot at the end slot may be unreachable) |

A `--to-epoch` above `MAX_SAFE_EPOCH` without `--force-unsafe-window` exits `2` and names `MAX_SAFE_EPOCH`.

## Output

### Human table (default)

One row per validator, worst effectiveness first. `null` renders as `—`, never `0`. Columns:

`pubkey` (abbreviated), `index`, `status`, `active epochs`, `part%`, `src%`, `tgt%`, `head%`, `missed`, `incl/sched`, `sync%`, `Δbal ETH`, `eff%`, `APR%`.

A `DEGRADED:` block lists metric, reason, and scope when data is missing. Footnotes explain why inclusion distance is absent and why `0/0` proposals is normal at this key count.

`--json` and the table are mutually exclusive on stdout: `--json` prints exactly one JSON document and nothing else.

### JSON (`--json`)

```bash
./scripts/validator_perf.py \
  --validators-config validators.toml \
  --config config.toml \
  --json > perf.json
```

`schema_version` is `1`. Shape is `scripts/tests/perf_schema.json`. Useful fields:

- `beacon.endpoint` — the node that served most of the run (redacted)
- `beacon.endpoints_used` — every node that served any request, in order
- `validators[]` — per-key metrics, balances, rewards, degradations
- `aggregate` — set-level rates and APR (EB-weighted)
- `degradations[]` — `{metric, scope, reason, detail}`
- `exit_code`

`reward_source` is `"rewards_api"`, `"balance_delta"`, or `null`. Balance-delta mode is the rewards-less fallback: consensus reward equals the balance delta, component fields are `null` (not `0`), and the run exits `3`.

### CSV (`--csv PATH`)

One row per validator, same flattened fields as JSON `validators[]`. `null` is an empty cell. Nested objects use dotted names (`proposals.scheduled`, `rewards_gwei.source`, …). `degradations` is a `;`-joined `reason@scope` summary; JSON is authoritative for the detail.

Legal together with `--json` (JSON on stdout, CSV in the file). Nothing is written under `scripts/`.

### Prometheus (`--prometheus PATH`)

Textfile-collector exposition for node_exporter. Unavailable metrics are **omitted**, not emitted as `0`. The file is replaced atomically and left mode `0644`.

Series names are prefixed `rvc_validator_perf_`. Labels are abbreviated `pubkey`, `index`, and `status`. There is no beacon URL in any label. `rvc_validator_perf_run_exit_code` and `rvc_validator_perf_run_generated_timestamp_seconds` detect a stale file.

### Dry-run (`--dry-run`)

Prints the window, redacted endpoint, `rewards_api` verdict (`available` / `route_absent` / `state_unavailable`), node version, and per-key `index` / `status` / effective balance. Exits `0` on success. Use this first against a new BN.

## Exit codes

| Code | Meaning | Typical cause |
|------|---------|----------------|
| `0` | OK | Complete run, no degradations (or `--degraded-ok` mapped `3 → 0`) |
| `1` | Unexpected error | Bug or unhandled exception |
| `2` | Usage | Bad pubkey, missing URL, unknown `--fail-under` name, window flags |
| `3` | Degraded | Missing rewards route, pruned state, leak epochs, … — see `DEGRADED:` / `degradations[]` |
| `4` | Threshold | A `--fail-under` metric was below the floor (`--degraded-ok` does **not** map `4 → 0`) |
| `5` | No beacon | Every URL failed at selection, or the last node died and none remained |

Among completed runs the precedence is `4 > 3 > 0`. A real missed attestation or missed proposal is a *finding* (exit `0`), not a degradation.

## Thresholds and cron

```bash
# Hourly artifact; silent on success.
./scripts/validator_perf.py \
  --validators-config /etc/rvc/validators.toml \
  --config /etc/rvc/config.toml \
  --json -q \
  > /var/lib/rvc/perf-$(date +%s).json

# CI smoke on a short unfinalized window.
./scripts/validator_perf.py \
  --pubkey 0x… \
  --beacon-url http://devnet-bn:5052 \
  --epochs 4 \
  --allow-unfinalized \
  --fail-under target_rate=0.95
```

`--fail-under METRIC=VALUE` is repeatable. Allowed names:

`participation_rate`, `source_rate`, `target_rate`, `head_rate`, `attester_effectiveness`, `sync_participation_rate`, `estimated_apr`.

An unknown name or a non-finite value exits `2`. A `null` metric cannot breach (that case is already exit `3`).

`-q` prints nothing on stderr for a healthy run; usage and abort errors still print. `-v` / `-vv` add per-request lines (`METHOD {template} via scheme://host:port`). `-v` and `-q` together exit `2`.

`--degraded-ok` maps exit `3` to `0` for cron that accepts partial data. It never touches `4`.

## Rate limiting and hosted nodes

Defaults: `--concurrency 4`, `--request-delay-ms 0`, connect timeout 5 s, read timeout 30 s.

Against a shared or hosted BN:

```bash
./scripts/validator_perf.py \
  --validators-config validators.toml \
  --beacon-url https://hosted-bn.example:5052 \
  --concurrency 1 \
  --request-delay-ms 50
```

`--concurrency 1` is strictly serial. `--request-delay-ms` is a global minimum gap between request *starts*, not per worker.

## Cache

A repeat run over the same keys skips the pubkey→index `POST states/head/validators` when every requested key is already cached for this network's genesis validators root.

- Location: `$XDG_CACHE_HOME/rvc-validator-perf/` (must be an absolute path), else `~/.cache/rvc-validator-perf/`
- File: `indices-<genesis_validators_root>.json` — **index only** (status and effective balance are still fetched live)
- `--no-cache` disables read and write
- A changed genesis root (devnet re-genesis) invalidates the cache
- Any read problem is a miss, never a failed run

The cache is never written inside the repo.

## Optional liveness check

`--liveness-check` asks the BN whether it *observed* a message in the current and previous epoch only. That is **not** on-chain inclusion (`part%` / M1). Teku often returns 400 (off by default) and Grandine 500 without `--track-liveness`; those are reported as unavailable and do **not** degrade the run.

## What a `null` means

`—` / JSON `null` is missing data, not a zero score:

- **Inactivity leak** — head rate is null for leak epochs (Altair has no head penalty)
- **Not in a sync committee** — `sync%` is null with **no** degradation (the normal case)
- **Rewards API absent or state pruned** — attestation rates and reward components are null; consensus reward falls back to the balance delta and is labelled `balance_delta`
- **Unknown pubkey** — the BN does not know the key; the row continues, rates null, exit `3`
- **Zero active epochs** — the key exists but was not active in the window; rates null, exit `0` (a fact, not a fault)

## Request budget

For 200 keys × 32 epochs with no sync-committee membership the script issues on the order of **76–78** HTTP requests (independent of key count). Detected sync membership adds up to `SLOTS_PER_EPOCH × epochs` extra requests (1024 on mainnet's default window) and logs that carve-out.

## Tests

```bash
uv run --with pytest --with pytest-socket pytest scripts/tests/ -q
```

The suite is offline (`pytest-socket` blocks DNS). A `UserWarning` about `socket.getaddrinfo` on the two network-block tests is expected.

## Flag reference

| Flag | Default | Notes |
|------|---------|--------|
| `--pubkey` | — | Repeatable |
| `--pubkeys-file` | — | Newline-separated hex |
| `--validators-config` | — | rvc `validators.toml` |
| `--beacon-url` | — | Repeatable; beats `--config` |
| `--config` | — | rvc `config.toml` (`beacon_nodes` / `beacon_url`) |
| `--epochs` | 32 | Cannot mix with `--from-epoch` / `--to-epoch` |
| `--from-epoch` / `--to-epoch` | derived | Inclusive |
| `--allow-unfinalized` | off | Still capped at `head − 2` |
| `--force-unsafe-window` | off | Past `MAX_SAFE_EPOCH` |
| `--json` | off | One JSON document on stdout |
| `--csv PATH` | — | Flattened `validators[]` |
| `--prometheus PATH` | — | Textfile collector |
| `--concurrency` | 4 | Pool width |
| `--request-delay-ms` | 0 | Global start spacing |
| `--connect-timeout` | 5 | Seconds |
| `--read-timeout` | 30 | Seconds |
| `--degraded-ok` | off | Maps `3 → 0` only |
| `--fail-under METRIC=VALUE` | — | Repeatable; exit `4` on breach |
| `--liveness-check` | off | Head-window sanity only |
| `--dry-run` | off | Window + keys, no metrics |
| `--no-cache` | off | Skip index cache |
| `-v` / `-vv` | 0 | Per-request diagnostics, redacted |
| `-q` | off | Silent stderr on a healthy run |
