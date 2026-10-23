# TRC-6a — executor spawn census

Production executor sites. Shape A = 0. Shape B = 5. Detached = 11. Total = 16.

`register_opt(..., None)` is not a site. A `// detached:` comment sits on the line immediately above each detached call. The five shape B calls have no such comment.

Rows are content anchors. A line number is not a key. `census_anchors_match_sources` checks them.

## How a row is keyed

Production sites are `(file, enclosing item, task, call)`. Shape B loops are `(loop file, item containing the loop)`. Not-sites are `(file, enclosing item, task)`. The task is the whole first argument: a plain string literal, or the only `const` of that name in the production prefix whose initializer is a plain string followed by `;`. The next token is a comma. The scan reads lexer tokens. `enclosing_item` resolves the item on the production prefix, the source above the first `#[cfg(test)]` followed by `mod`. A hit inside an item whose name is declared twice, an untrusted token stream, or a hit outside every fn and `macro_rules!` fails the file. A path cell is repo-relative.

## Production sites (16)

| File | Item | Task | Call | Bucket | Reason |
|---|---|---|---|---|---|
| `bin/rvc/src/logging.rs` | `spawn_log_reload_handler` | `log_reload` | spawn | detached | SIGHUP log-reload handler; process-lifetime signal loop, no caller trace to inherit. |
| `crates/rvc/src/bootstrap/run.rs` | `run` | `duty_orchestrator` | spawn | detached | Already a per-slot root inside the task (`DutyOrchestrator::run`, span `slot.process`); not shape B. The call is `executor.spawn_result`; this column is the pin kind `spawn`. |
| `crates/rvc/src/bootstrap/run.rs` | `spawn_secret_provider_refresh` | `secret_provider_refresh` | spawn | detached | `RefreshService::run` in `crates/secret-provider`; loop body is out of scope. |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_background_tasks` | `metrics_server` | spawn | detached | Metrics server; serve loop is `serve_metrics_with_health` in `crates/metrics`, out of P1-1 scope. |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_background_tasks` | `monitoring_push` | spawn | B | Iteration loop in `start_monitoring_push`. TRC-6b owns the per-iteration root. |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_background_tasks` | `proposer_config_refresh` | spawn | B | Iteration loop in `start_proposer_config_refresh_with`. TRC-6b owns the per-iteration root. |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_sse_subscriber` | `bn.sse` | register | detached | BN SSE subscriber; process-lifetime Infra handle, loop lives in bn-manager, out of P1-1 scope. |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_sse_subscriber` | `bn.sse.cancel` | spawn | detached | Cancel-forwarder for `bn.sse`; not an iteration loop. |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_sync_monitor` | `bn.sync_monitor` | register | detached | BN sync monitor; process-lifetime Infra handle, loop lives in bn-manager, out of P1-1 scope. |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_sync_monitor` | `bn.sync_monitor.cancel` | spawn | detached | Cancel-forwarder for `bn.sync_monitor`; not an iteration loop. |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_proposer_sync_monitor` | `bn.proposer_sync_monitor` | register | detached | Proposer BN sync monitor; process-lifetime Infra handle, loop lives in bn-manager, out of P1-1 scope. |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_proposer_sync_monitor` | `bn.proposer_sync_monitor.cancel` | spawn | detached | Cancel-forwarder for `bn.proposer_sync_monitor`; not an iteration loop. |
| `crates/rvc/src/index_resolver.rs` | `spawn_index_resolver` | `index.resolve` | spawn | B | Iteration loop in `IndexResolver::run`. TRC-6b owns the per-iteration root. |
| `crates/rvc/src/keymanager_adapters/spawn.rs` | `spawn_keymanager_api` | `keymanager_api` | spawn | detached | Keymanager API server; serve loop is `KeymanagerServer::serve_on` in `crates/keymanager-api`, out of scope. |
| `crates/rvc/src/liveness_loop.rs` | `spawn_liveness_loop` | `liveness_loop` | spawn | B | Iteration loop in `LivenessObservationLoop::run`. TRC-6b owns the per-iteration root. |
| `crates/rvc/src/slashing_monitor.rs` | `spawn_with_interval` | `slashing_monitor` | spawn | B | Iteration loop in `spawn_with_interval`. TRC-6b owns the per-iteration root. |

Shape A = 0. None of the 16 inherit a caller trace as a shape A root.

## Shape B loop sites

| Task | Spawn file | Spawn item | Loop file | Loop item |
|---|---|---|---|---|
| `monitoring_push` | `crates/rvc/src/bootstrap/tasks.rs` | `spawn_background_tasks` | `crates/rvc/src/background_tasks/monitoring.rs` | `start_monitoring_push` |
| `proposer_config_refresh` | `crates/rvc/src/bootstrap/tasks.rs` | `spawn_background_tasks` | `crates/rvc/src/background_tasks/config_url.rs` | `start_proposer_config_refresh_with` |
| `liveness_loop` | `crates/rvc/src/liveness_loop.rs` | `spawn_liveness_loop` | `crates/rvc/src/liveness_loop.rs` | `LivenessObservationLoop::run` |
| `slashing_monitor` | `crates/rvc/src/slashing_monitor.rs` | `spawn_with_interval` | `crates/rvc/src/slashing_monitor.rs` | `spawn_with_interval` |
| `index.resolve` | `crates/rvc/src/index_resolver.rs` | `spawn_index_resolver` | `crates/rvc/src/index_resolver.rs` | `IndexResolver::run` |

## Not sites — `register_opt(..., None)`

These calls pass `None` and are not production sites. No `// detached:` comment.

| File | Item | Task | Call |
|---|---|---|---|
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_sse_subscriber` | `bn.sse` | register_opt |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_sync_monitor` | `bn.sync_monitor` | register_opt |
| `crates/rvc/src/bootstrap/tasks.rs` | `spawn_proposer_sync_monitor` | `bn.proposer_sync_monitor` | register_opt |
| `crates/rvc/src/slashing_monitor.rs` | `spawn_with_interval` | `slashing_monitor` | register_opt |

The slashing-monitor `None` call is the old no-op detached site. It left the census.

## `liveness_loop.rs` `#[cfg(test)]` shape

The first bare `#[cfg(test)]` in `crates/rvc/src/liveness_loop.rs` sits on a function and is indented. A later bare `#[cfg(test)]` does not sit on a function. The column-0 `#[cfg(test)]` is followed by `mod`. The production spawn is task `liveness_loop` in `spawn_liveness_loop`, after that first attribute and above the module attribute.

Truncating the file at the first bare `#[cfg(test)]` hides that spawn. The gate ends the production region at the first token `#[cfg(test)]` followed by `mod`, not at the first bare attribute.

`crates/architecture-tests/tests/spawn_span_continuity.rs` pins this census at 16 under tracing ADR-009. The gate treats `///` and `//!` as comments, and does not count `register_opt(..., None)`. A site passes only when the preceding non-empty line is a `// detached:` comment, or it is one of the five shape-B rows and the loop file contains `parent: None` and `follows_from` for that task. The allow-list is empty.

## A-12 pin

```text
git diff 22aa3de5bf5ed0c03ed571694dc3a5652e460613 -- crates/slashing/src/stage.rs
```

Empty on this commit. `crates/slashing/src/stage.rs` is not edited. Blob sha `205106ae71c9c66d5ae4ad423fc7dd31412f690d` matches the pin.

## bn-manager raw `tokio::spawn` (not executor sites)

These calls are outside the executor scan (`crates/rvc` + `bin/rvc`) and outside `raw_spawn` `ALLOW_LIST` (that list stays empty). #646 shifted them. They are not rows in the production-sites table above.

| File | Item | Call |
|---|---|---|
| `crates/bn-manager/src/fan_out.rs` | `wait_for_complete_detached` | `tokio::spawn` |
| `crates/bn-manager/src/fan_out.rs` | `spawn_detached` | `tokio::spawn` |
| `crates/bn-manager/src/fan_out.rs` | `health_sender` | `tokio::spawn` |
| `crates/bn-manager/src/manager.rs` | `BnManager::start_sse` | `tokio::spawn` |
| `crates/bn-manager/src/sse.rs` | `subscribe_events_admitted_inner` | `tokio::spawn` |
| `crates/bn-manager/src/sync_status.rs` | `start_sync_monitor_publishing` | `tokio::spawn` |
