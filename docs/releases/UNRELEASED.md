# Unreleased

Operator-visible behavior changes land here during the development cycle and
are folded into `docs/releases/vX.Y.Z.md` at release time.

## Dev process

CI now builds `develop` on push (compile job only).

## Slashing-DB group commit (issue #205)

Concurrent `reserve_*` checks share one `BEGIN IMMEDIATE` → rule check →
INSERT → `COMMIT` (one fsync), then all members are released to sign.
Commit-before-sign is unchanged. Per-pubkey connections stay rejected.

Operator knobs (defaults from the measured ~4.5 ms fullfsync quantum).
`rvc` reads the `[slashing]` table; `rvc-signer` reads `[signer]`. Copying
`[slashing] group_commit_*` into a signer TOML is a no-op.

| Knob | Default |
|---|---|
| `rvc`: `[slashing] group_commit_batch_size` / `--slashing-group-commit-batch-size` | 50 |
| `rvc`: `[slashing] group_commit_wait_to_fill_ms` / `--slashing-group-commit-wait-to-fill-ms` | 1 (0 disables wait) |
| `rvc-signer`: `[signer] group_commit_batch_size` / `--slashing-group-commit-batch-size` | 50 |
| `rvc-signer`: `[signer] group_commit_wait_to_fill_ms` / `--slashing-group-commit-wait-to-fill-ms` | 1 (0 disables wait) |

A slashable rule-check rejects only that member. A failed `COMMIT` rejects
every member of the batch. A cancelled waiter does not stall the others.

## API: Web3Signer HTTP client path (`crypto::remote_signer::*`)

The Web3Signer HTTP client has moved out of `rvc-crypto` into crate
`rvc-remote-signer-client` (workspace alias `remote-signer-client`).

**Import path change (library consumers only; operator-invisible):**

| Before | After |
|---|---|
| `crypto::remote_signer::*` | `remote_signer_client::*` |
| `crypto::RemoteSigner` | `remote_signer_client::RemoteSigner` |
| `crypto::RemoteSignerConfig` | `remote_signer_client::RemoteSignerConfig` |
| `crypto::REMOTE_SIGNER_INSECURE_ENV_VAR` | `remote_signer_client::REMOTE_SIGNER_INSECURE_ENV_VAR` |

`RVC_REMOTE_SIGNER_ALLOW_INSECURE` is unchanged (security opt-out; C3). Signing
roots, request bodies, and URL gating are unchanged.

---

## Breaking: gRPC healthz endpoint removed; leftover keys fail startup

Nothing listens on the old healthz gRPC bind. **`grpc_address` and
`grpc_port` are rejected at startup** (`ConfigError::RemovedKey`). A TOML
file or `--grpc-port` / `--grpc-address` flag that still names them fails
rather than parsing and doing nothing.

Any probe, monitor, or healthcheck still aimed at that port will fail.

**Replacement pair** on the metrics HTTP server (`metrics_address` /
`metrics_port`):

| Endpoint | Role |
|----------|------|
| **`GET /health`** | JSON diagnostic (`200` when ready, `503` otherwise). Same readiness predicate as `/readyz`. Not a Kubernetes probe. |
| **`GET /readyz`** | Readiness (plain text). `503 not ready` until beacon is connected, at least one validator is loaded, and the slashing DB is initialized. |

**Kubernetes probes** (plain text only — do not use `/health` for either):

- **Liveness → `GET /livez`** (always process-up). Closest match to the old
  gRPC healthz, which always reported healthy.
- **Readiness → `GET /readyz`**.

`/health` also returns `503` when the process is not ready, so it is **not**
a stand-in for gRPC healthz. Do **not** put `/health` or `/readyz` on a
liveness probe — both fail during BN blips or early startup and would
restart the pod in a loop.

**Action required:** finish the [probe-migration checklist](#probe-migration-checklist)
if you have not already. Move **liveness → `/livez`** and **readiness →
`/readyz`** on the metrics port before upgrade.

**Metrics bind defaults (probe reachability):**

- Default bind is **loopback** (`metrics_address` = `127.0.0.1`, `metrics_port` = `8080`).
- Probes from outside the process namespace (typical Kubernetes kubelet) need a bind the probe source can reach (often pod IP / `0.0.0.0` with appropriate network policy).
- Non-loopback metrics binds require the existing opt-in env var
  `RVC_METRICS_ALLOW_NON_LOOPBACK=true`; the same listener also serves
  `/metrics` and `/health` — restrict scrape/probe sources accordingly.

**Copy-pasteable Kubernetes probes** (set `port` to your `metrics_port`; default `8080`):

```yaml
livenessProbe:
  httpGet:
    path: /livez
    port: 8080   # metrics_port — must reach metrics_address from the probe source
  initialDelaySeconds: 10
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /readyz
    port: 8080   # metrics_port
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Probe-migration checklist

- [ ] Does any Kubernetes `livenessProbe` / `readinessProbe` target the **gRPC**
      port (`grpc_port`, default 50051) or the gRPC Healthz RPC?
- [ ] Does any external monitor, blackbox exporter, or load-balancer health check
      hit the gRPC port instead of the metrics HTTP port?
- [ ] Do any Docker / Compose `healthcheck` commands call the gRPC surface?
- [ ] After migrating: **liveness → `/livez`**, **readiness → `/readyz`**, both on
      **metrics** `port` (not gRPC). Never put `/health` or `/readyz` on the
      liveness probe. `/health` is JSON on the same listener; prefer plain
      text `/livez` + `/readyz` for Kubernetes.
- [ ] Is the metrics bind reachable from the probe source? Default is loopback
      only; non-loopback needs `RVC_METRICS_ALLOW_NON_LOOPBACK=true` and should
      be network-restricted (opening the port also exposes `/metrics` and `/health`).

---

## Config: `--help` presentation (defaults unchanged)

On **promoted / section knobs** — the ADR-009 fields that lost clap
`default_value` (e.g. `--metrics-port`) — `rvc start --help` no longer
prints clap's `[default: 8080]` annotation. The numeric and string
defaults themselves are **unchanged**; they now live in the flag doc
comments (and in `Config::default()`), so clap treats an absent flag as
"not supplied" rather than as the default value.

**CLI-only flags are not in that set.** `--log-format` has no
config-file knob and still prints clap's `[default: pretty]`. The other
three CLI-only args (`--enable-log-reload`, `--strict-permissions`,
`--strict-slashing-semantics`) stay CLI-only too; they do not print a
clap `[default:]` block. Do not assume every `[default: …]` line is
gone from `--help`.

**Before** (clap invented the default and printed it on Config knobs):

```text
      --metrics-port <METRICS_PORT>
          Port for the metrics HTTP server

          [default: 8080]
```

**After** (same default, now in the doc comment; clap prints no `[default:]`
on this flag):

```text
      --metrics-port <METRICS_PORT>
          Port for the metrics HTTP server (default: 8080)
```

`--flag` strings are unchanged. The `--help` move is presentation only.

**vs v0.7.0 (ADR-009, already shipped):** an absent flag **used to**
clobber the file. With `metrics_port = 9090` and no `--metrics-port`,
v0.7.0 bound **8080** (clap's invented default). ADR-009 already fixed
that precedence; this phase did not change it. A TOML
`metrics_port = 9090` with no `--metrics-port` still binds **9090**.

---

## Config: TOML section tables (flat spelling still accepted)

The validator-client config file now has section tables — the existing groups
(`[keymanager]`, `[tracing]`, `[grpc_signer]`, `[builder_limits]`,
`[monitoring]`, `[proposer_config]`, `[logfile]`) plus the newly documented
`[beacon]`, `[server]`, `[network]`, `[safety]`, `[slashing]`, and `[keys]`.

**The flat spelling still works and is not being removed.** Existing operator
files need no rewrite. Nested tables are the documented form going forward;
both spellings are valid and will stay valid.

**Before** — flat keys (corpus fixture
`crates/rvc/tests/fixtures/config/flat_legacy_full.toml`):

```toml
tracing_endpoint = "http://wire-otel:4318"
tracing_exporter = "gcp"
tracing_sample_rate = 0.37
tracing_max_queue_size = 3333
tracing_max_export_batch_size = 444
```

**After** — the same knobs as a section table (corpus fixture
`crates/rvc/tests/fixtures/config/nested_full.toml`):

```toml
[tracing]
endpoint = "http://wire-otel:4318"
exporter = "gcp"
sample_rate = 0.37
max_queue_size = 3333
max_export_batch_size = 444
```

Those two fixtures parse to the same `Config`
(`nested_tables_match_flat_legacy_snapshot` in
`crates/rvc/tests/config_wire_parity.rs`).

### Collision rule: **flat-wins**

If a file sets **both** spellings of the same logical field to *different*
values, the **flat** key wins. That rule has been in force since the first
nested-group migration (v0.7.0) and is preserved. Corpus fixture
`crates/rvc/tests/fixtures/config/collision.toml` pins it:

```toml
tracing_endpoint = "http://flat-otel:4318"

[tracing]
endpoint = "http://nested-otel:4318"
```

The loaded config uses `http://flat-otel:4318`
(`flat_key_wins_over_nested_table` in
`crates/rvc/tests/config_wire_parity.rs`). Operators with existing flat files
keep working even if an example snippet later adds a nested table beside them.

---

## Behaviour: `rvc slashing prune` source watermark

`rvc slashing prune` now raises the source floor before it deletes rows below
the target watermark. A database already pruned under the old code is not
repaired: those deleted rows cannot be reconstructed, and this change only
affects later prunes.

---

## Config: no knob removed, renamed, or re-defaulted (section collapse)

**The section-table collapse did not remove, rename, or re-default a knob.**
That collapse is one declaration per knob, not a schema break.

Evidence is the parity harness `crates/rvc/tests/config_wire_parity.rs`:
`every_knob_appears_in_the_parity_corpus` asserts the live operator-knob
set, and `flat_legacy_keys_still_parse` /
`nested_tables_match_flat_legacy_snapshot` require the pre-migration
snapshots to stay byte-identical aside from the healthz bind knobs
disposed later in this file.

## Config: leftover healthz bind knobs fail startup

See the breaking section at the top of this file. The live operator-knob
inventory is **69** after disposing `grpc_port` / `grpc_address` and adding
the two slashing group-commit knobs.

---

## Config: four BN timeouts now settable from the file

`--block-production-timeout`, `--attestation-timeout`, `--aggregate-timeout`,
and `--duty-fetch-timeout` were CLI-only. They now also load from the config
file (CLI still wins). Defaults are unchanged: they still come from
`bn_manager::OperationTimeouts::default()` (3s / 4s / 2s / 10s).
`--aggregate-timeout` still sets both aggregate fetch and aggregate submit.

Corpus fixture `crates/rvc/tests/fixtures/config/beacon_timeouts.toml` (the
values are non-default on purpose — it is a parse/round-trip fixture, not a
recommended production config):

```toml
[beacon]
block_production_timeout = 11
attestation_timeout = 12
aggregate_timeout = 13
duty_fetch_timeout = 14
```

The same four keys also parse as top-level flat keys (`block_production_timeout`,
…). A value of `0` is rejected from both the file and the CLI.

---

## Slashing: ADR-005 does not deliver G6 on the VC path

ARCH-P1-5 (`reserve_then_sign`) shortens the slashing-DB critical section on
the **signer-server** path. It does **not** make slashable signing scale to
the target validator count on the validator-client path. Attestation in
`crates/rvc/src/orchestrator/attestation.rs` is still a sequential
`for duty in duties { … .await }` loop; 200 keys × 200 ms remote-sign
latency is **40 s (ten mainnet slots) with a free slashing DB**. VC-path
attestation concurrency is a separate, unscheduled requirement. Do not read
this cycle as delivering G6.

---

## Behaviour: `--graffiti` applies to validator-store defaults

`--graffiti` is an in-memory validator-store default. Per-validator graffiti and keymanager-set values still win. Startup does not rewrite the validators file. The next `save_config` — a keymanager fee-recipient, gas-limit, or graffiti save, or any other snapshot of the in-memory defaults — persists that value over `[defaults].graffiti`. A later start without `--graffiti` keeps the persisted value. A save while the flag is absent leaves the file default unchanged.

## Breaking (behaviour): DVT peers connect lazily

`rvc-signer` DVT peers connect lazily with an explicit connect timeout; an
unreachable peer no longer fails startup. Allow-list and SNI errors remain
fatal. Startup logs those peers as configured and not yet dialled.

## Observability

Import conflicts are logged and counted (`rvc_slashing_import_conflicts_total`).

## Breaking (wire): Deneb/Electra/Fulu blocks are published as full SignedBlockContents with sidecars

Deneb/Electra/Fulu blocks are published as full SignedBlockContents with sidecars. Nodes that accepted the prior malformed payload may behave differently.
