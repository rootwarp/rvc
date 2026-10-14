# ARCH-6a — ADR-009 clap-default precedence probe

**Issue:** ARCH-6a (spike)  
**Date (UTC):** 2026-08-12T14:03:49Z  
**Tree:** `feature/arch-6a-adr009-precedence-probe` @ `fb29d5b0c995eb95ab92e9505854217d3a2eac2c`  
**rustc:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`  
**Host:** Darwin arm64 (macOS)

## Hypothesis (ADR-009 / F9–F10)

Nine clap fields use `default_value_t` / `default_value`, and
`impl From<StartArgs> for CliOverrides` wraps them in unconditional `Some(...)`.
`merge_with_cli`'s `set` arm then overwrites the TOML value even when the operator
never passed the flag. For metrics: TOML `metrics_port = 9090` + no `--metrics-port`
should become **8080** (clap default) if the defect is live.

## Probe method

Full binary path (`rvc start`), not a unit-only simulation. Same code path as
production: `CliOverrides::from(StartArgs)` → `load_config` → `merge_with_cli` →
`bootstrap::run` logs `metrics_port` at `crates/rvc/src/bootstrap/run.rs` (and
would bind at `tasks.rs`).

### Config file

Path: `/tmp/arch-6a-probe.YujZbW/config.toml`

```toml
beacon_url = "http://127.0.0.1:1"
keystore_path = "/tmp/arch-6a-probe.YujZbW/keystores"
slashing_db_path = "/tmp/arch-6a-probe.YujZbW/slashing.sqlite"
network = "mainnet"
metrics_address = "127.0.0.1"
metrics_port = 9090
grpc_address = "127.0.0.1"
grpc_port = 50051
keymanager_enabled = false
log_level = "info"
```

### Command (exact)

```bash
cargo build -p rvc-bin

# --metrics-port deliberately ABSENT
env -u OTEL_EXPORTER_OTLP_ENDPOINT -u OTEL_EXPORTER_OTLP_PROTOCOL \
    -u OTEL_METRICS_EXPORTER -u OTEL_TRACES_EXPORTER \
  RUST_LOG=info \
  ./target/debug/rvc start \
    --config /tmp/arch-6a-probe.YujZbW/config.toml \
    --init-slashing-db \
    --no-doppelganger-detection
```

`--init-slashing-db` and a dummy BN URL let startup reach the metrics-port log
before failing on genesis/BN connectivity. No `--metrics-port` was passed.

### Clap default confirmation

```text
      --metrics-port <METRICS_PORT>
          Port for the metrics HTTP server

          [default: 8080]
```

## Literal output (relevant lines)

```text
2026-08-12T14:03:49.608501Z  INFO rvc::cli: rvc starting version="0.7.0" network=mainnet commit="unknown"
2026-08-12T14:03:49.609239Z  INFO rvc::bootstrap::run: Starting validator client beacon_url=http://127.0.0.1:1/ beacon_nodes=["http://127.0.0.1:1/"] network=mainnet metrics_address=127.0.0.1 metrics_port=8080 grpc_address=127.0.0.1 grpc_port=50051 doppelganger_detection=false spec_version="v1.5.0-alpha.12"
...
Error: beacon error: HTTP request failed: error sending request for url (http://127.0.0.1:1/eth/v1/beacon/genesis)
```

**Observed port after merge:** `metrics_port=8080`  
**TOML asked for:** `9090`  
**Operator flag:** absent

## Mechanism (code path — same as live defect)

1. `bin/rvc/src/cli.rs` — `ServerArgs::metrics_port` has `default_value_t = DEFAULT_METRICS_PORT` (8080).
2. `CliOverrides::from(StartArgs)` sets `metrics_port: Some(server.metrics_port)` **unconditionally** (`cli.rs` ~615).
3. `Config::merge_with_cli` `set` arm: `if let Some(v) = metrics_port { self.metrics_port = v }` (`types.rs` ~942–945, arm for `metrics_port`).
4. `bootstrap::run` logs the post-merge value (`run.rs` ~61); metrics bind later uses the same `config.metrics_port` (`tasks.rs` ~82–88).

No path between `cli.rs` merge and the log re-applies the TOML. Integration tests already work around this (`bin/rvc/tests/integration_test.rs` comment: ports must be passed on the CLI because clap defaults clobber the file).

## Verdict

**Defect reproduces.** Binds/results **8080**, not 9090.

## Implication for ARCH-6b

- **ARCH-6b proceeds as written:** convert the nine clap fields with `default_value*` that are always `Some(...)` into true `Option<T>` (or equivalent presence detection) so absent flags leave TOML values intact; defaults live on `Config::default()` only.
- **ARCH-5b** still ships `CLAP_DEFAULT_CLOBBERS` (initially listing the nine, then shrinking to empty after ARCH-6b).
- Finding is **not** withdrawn.

## Acceptance checklist

- [x] Probe command + literal output recorded
- [x] Verdict stated: **defect reproduces**
- [x] ARCH-6b **confirmed** in writing (not cancelled)
