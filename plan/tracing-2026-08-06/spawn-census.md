# TRC-6a — executor spawn census

Production `executor.spawn(` / `executor.register(` sites on this commit.
Branched from develop `619cb9017fc840110cf4b103f9f172cafa8c5f96` (tip had not moved).
Shape A = 0. Shape B = 5. Detached = 9. Total = 14.

`register_opt(..., None)` is not a site. Comments (`// detached:`) sit on the line immediately above the nine detached calls. The five shape B calls have no such comment.

## Command

From the repo root. `executor.register(` does not match `register_opt`. Paths under `crates/**/tests/` are excluded. A hit is dropped only when a **column-0** `#[cfg(test)]` appears above it in the same file. A method-level (indented) `#[cfg(test)]` does not end the production region.

```bash
rg -n --sort path --glob '*.rs' -g '!**/tests/**' 'executor\.(spawn|register)\(' | while IFS=: read -r file line rest; do
  if awk -v n="$line" 'NR < n && /^#\[cfg\(test\)\]/ { found=1 } END { exit !found }' "$file"; then
    continue
  fi
  printf '%s:%s:%s\n' "$file" "$line" "$rest"
done
```

That command prints 14 lines, one per row below.

## Production sites (14)

| File | Line | Task | Call | Bucket | Reason |
|---|---:|---|---|---|---|
| `bin/rvc/src/logging.rs` | 312 | `log_reload` | spawn | detached | SIGHUP log-reload handler; process-lifetime signal loop, no caller trace to inherit. |
| `crates/rvc/src/bootstrap/run.rs` | 340 | `duty_orchestrator` | spawn | detached | Already a per-slot root inside the task (`slot.process`, `crates/rvc/src/orchestrator/coordinator/mod.rs:490`); not shape B. |
| `crates/rvc/src/bootstrap/run.rs` | 477 | `secret_provider_refresh` | spawn | detached | `secret_provider::RefreshService::run`; loop body is `crates/secret-provider/src/refresh.rs:179`, out of scope. |
| `crates/rvc/src/bootstrap/tasks.rs` | 118 | `metrics_server` | spawn | detached | Metrics server; serve loop is `crates/metrics/src/server.rs:96` (`serve_metrics_with_health`), out of P1-1 scope. |
| `crates/rvc/src/bootstrap/tasks.rs` | 140 | `monitoring_push` | spawn | B | Iteration loop. Loop site `crates/rvc/src/background_tasks/monitoring.rs:161`. TRC-6b owns the per-iteration root. |
| `crates/rvc/src/bootstrap/tasks.rs` | 164 | `proposer_config_refresh` | spawn | B | Iteration loop. Loop site `crates/rvc/src/background_tasks/config_url.rs:342`. TRC-6b owns the per-iteration root. |
| `crates/rvc/src/bootstrap/tasks.rs` | 207 | `bn.sse` | register | detached | BN SSE subscriber; process-lifetime Infra handle, loop lives in bn-manager, out of P1-1 scope. |
| `crates/rvc/src/bootstrap/tasks.rs` | 211 | `bn.sse.cancel` | spawn | detached | Cancel-forwarder for `bn.sse`; not an iteration loop. |
| `crates/rvc/src/bootstrap/tasks.rs` | 246 | `bn.sync_monitor` | register | detached | BN sync monitor; process-lifetime Infra handle, loop lives in bn-manager, out of P1-1 scope. |
| `crates/rvc/src/bootstrap/tasks.rs` | 250 | `bn.sync_monitor.cancel` | spawn | detached | Cancel-forwarder for `bn.sync_monitor`; not an iteration loop. |
| `crates/rvc/src/index_resolver.rs` | 86 | `index.resolve` | spawn | B | Iteration loop. Loop site `crates/rvc/src/index_resolver.rs:114` (`IndexResolver::run`). TRC-6b owns the per-iteration root. |
| `crates/rvc/src/keymanager_adapters/spawn.rs` | 273 | `keymanager_api` | spawn | detached | Keymanager API server; serve loop is `KeymanagerServer::run_with_shutdown` in `crates/keymanager-api/src/server.rs:175`, out of scope. |
| `crates/rvc/src/liveness_loop.rs` | 394 | `liveness_loop` | spawn | B | Iteration loop. Loop site `crates/rvc/src/liveness_loop.rs:185` (`LivenessObservationLoop::run`). TRC-6b owns the per-iteration root. |
| `crates/rvc/src/slashing_monitor.rs` | 131 | `slashing_monitor` | spawn | B | Iteration loop. Loop site `crates/rvc/src/slashing_monitor.rs:134`. TRC-6b owns the per-iteration root. |

Shape A = 0 at this HEAD. None of the 14 inherit a caller trace as a shape A root.

## Shape B loop sites

| Task | Spawn | Loop |
|---|---|---|
| `monitoring_push` | `crates/rvc/src/bootstrap/tasks.rs:140` | `crates/rvc/src/background_tasks/monitoring.rs:161` |
| `proposer_config_refresh` | `crates/rvc/src/bootstrap/tasks.rs:164` | `crates/rvc/src/background_tasks/config_url.rs:342` |
| `liveness_loop` | `crates/rvc/src/liveness_loop.rs:394` | `crates/rvc/src/liveness_loop.rs:185` |
| `slashing_monitor` | `crates/rvc/src/slashing_monitor.rs:131` | `crates/rvc/src/slashing_monitor.rs:134` |
| `index.resolve` | `crates/rvc/src/index_resolver.rs:86` | `crates/rvc/src/index_resolver.rs:114` |

## Not sites — `register_opt(..., None)`

These calls pass `None` and are not production sites. No `// detached:` comment.

```bash
rg -n --sort path --glob '*.rs' -g '!**/tests/**' 'executor\.register_opt::' | while IFS=: read -r file line rest; do
  if awk -v n="$line" 'NR < n && /^#\[cfg\(test\)\]/ { found=1 } END { exit !found }' "$file"; then
    continue
  fi
  printf '%s:%s:%s\n' "$file" "$line" "$rest"
done
```

| File | Line | Call | Mark |
|---|---:|---|---|
| `crates/rvc/src/bootstrap/tasks.rs` | 197 | `register_opt::<()>(bn.sse, …, None)` | not-a-site |
| `crates/rvc/src/bootstrap/tasks.rs` | 237 | `register_opt::<()>(bn.sync_monitor, …, None)` | not-a-site |
| `crates/rvc/src/slashing_monitor.rs` | 125 | `register_opt::<()>("slashing_monitor", …, None)` | not-a-site |

The slashing-monitor `None` call is the old no-op detached site. It left the census.

## `liveness_loop.rs` `#[cfg(test)]` trap

`crates/rvc/src/liveness_loop.rs` has method-level attributes at `:274` and `:342`. The column-0 module attribute is at `:400`. The production spawn is `:394`, above that module attribute.

Truncating the file at the first `#[cfg(test)]` (the method-level attribute at `:274`) hides `:394` and drops a real production site. The command above keeps `:394` because it only treats a column-0 `#[cfg(test)]` as the end of the production region.

`crates/architecture-tests/tests/spawn_span_continuity.rs` pins this census at 14 under tracing ADR-009. The gate ends the production region at the first column-0 `#[cfg(test)]` followed by `mod` (not the first bare `#[cfg(test)]`), skips `///` and `//!` lines, and does not count `register_opt(..., None)`. A site passes only when the preceding non-empty line is a `// detached:` comment, or it is one of the five shape-B rows and the loop file in the table above contains `parent: None` and `follows_from` for that task. The allow-list is empty.

## A-12 pin

```text
git diff 22aa3de5bf5ed0c03ed571694dc3a5652e460613 -- crates/slashing/src/stage.rs
```

Empty on this commit. `crates/slashing/src/stage.rs` is not edited. Blob sha `205106ae71c9c66d5ae4ad423fc7dd31412f690d` matches the pin.
