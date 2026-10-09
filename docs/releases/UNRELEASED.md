# Unreleased

Operator-visible behavior changes land here during the development cycle and
are folded into `docs/releases/vX.Y.Z.md` at release time.

## Exit codes: listener bind is 15 and a critical task is 16

Two new process exit codes sit beside the existing startup codes. `12` stays
unused (reserved for the retired one-shot doppelganger check).

| Code | Constant | When |
|---|---|---|
| 15 | `EXIT_LISTENER_BIND` | `BootstrapError::ListenerBind`. The metrics listener, or the keymanager listener when keymanager is enabled, failed to bind. |
| 16 | `EXIT_CRITICAL_TASK_FAILED` | `BootstrapError::CriticalTaskFailed`. A registered task panicked, or a task started with `spawn_result` / `register_result` returned `Err`. |

The bind error is `failed to bind {listener} listener at {addr}: {source}`.
`listener` is `metrics` or `keymanager`, and `addr` is the socket that failed.
A non-loopback metrics address without `RVC_METRICS_ALLOW_NON_LOOPBACK=true`
is `BootstrapError::MetricsBind` and still exits **1**.

Exit 16 is returned after the task drain finishes. The drain log line is
`Registered task panicked; initiating process drain` for both a panic and an
`Err`. The series `rvc_task_exits_total` separates them: `outcome="panic"` or
`outcome="error"`. The process error is `critical task '{task}' failed; process exiting`.
A `JoinHandle<Result<_, _>>` passed to `register` (not `register_result`) still
counts every `Ok` as a clean exit. A supervisor that restarts on any non-zero
status restarts the process after exit 15 or 16.

## Startup: listeners bind before keystore load

`bind_required_listeners` runs after the beacon connection and before
`load_signing_keys`. The metrics listener is always bound. The keymanager
listener is bound only when keymanager is enabled. An unset keymanager address
uses `127.0.0.1:5062`.

A port clash returns `ListenerBind` (exit 15) before keystore decryption and
before the duty orchestrator is spawned. The error names the listener and the
address.

## Config: new [duties] section

Attestation, sync-message, and aggregation dispatch read a `[duties]` table.
`0` is rejected. A value above the range is rejected. A present CLI flag
overrides the file.

| Knob | CLI | Default | Accepted |
|---|---|---|---|
| `duty_dispatch_concurrency` | `--duty-dispatch-concurrency` | 32 | `1..=512` |
| `duty_publish_concurrency` | `--duty-publish-concurrency` | 2 | `1..=16` |

```toml
[duties]
duty_dispatch_concurrency = 32
duty_publish_concurrency = 2
```

`duty_dispatch_concurrency` is the number of in-flight sign requests in one
wave. `duty_publish_concurrency` is the number of publish waves in flight.

## Config: KDF budget

Keymanager keystore import has its own KDF budget under `[keymanager]`. These
three knobs are not `--key-decrypt-threads` / `key_decrypt_threads` (startup
keystore load). A present CLI flag overrides the file.

| Knob | CLI | Default | Accepted |
|---|---|---|---|
| `keymanager_import_kdf_concurrency` | `--keymanager-import-kdf-concurrency` | 2 | `1..=32` |
| `keymanager_import_kdf_total_mib` | `--keymanager-import-kdf-total-mib` | 512 | `>= 1` (MiB) |
| `keymanager_import_kdf_max_keystore_mib` | `--keymanager-import-kdf-max-keystore-mib` | 8192 | `1..=8192` (MiB), tighten-only |

`keymanager_import_kdf_max_keystore_mib` cannot exceed the decrypt working-set
ceiling (`MAX_KDF_WORKING_SET_BYTES`, 8 GiB, which is 8192 MiB). A larger
value is rejected. The default is that ceiling.

```toml
[keymanager]
keymanager_import_kdf_concurrency = 2
keymanager_import_kdf_total_mib = 512
keymanager_import_kdf_max_keystore_mib = 8192
```

## Config: knob inventory is 75

The live operator-knob inventory is **75**. That is the length of
`OPERATOR_KNOB_NAMES` in `crates/rvc/src/config/knobs.rs`, and the same count
`crates/architecture-tests/tests/config_drift.rs` asserts.

The five names added since the 70-name list are the two `[duties]` knobs and
the three `[keymanager]` import KDF knobs:

- `duty_dispatch_concurrency`
- `duty_publish_concurrency`
- `keymanager_import_kdf_concurrency`
- `keymanager_import_kdf_total_mib`
- `keymanager_import_kdf_max_keystore_mib`

`grpc_port` and `grpc_address` stay removed. The sentence further down that
used to say the inventory was 69 now says 75.

## Keymanager: imports may defer and can finish after disconnect

Keystore import runs on the blocking pool (`spawn_blocking`). The KDF
permit moves into that task. `import_keystore_blocking` decrypts the
keystore, writes the keystore file, and then admits the key. Decrypt runs
before that write. If the HTTP client drops and the handler is cancelled,
that blocking task still finishes: the file can be written and the key can
be admitted. Do not activate the key in any other client while the import
may still be running. An in-flight import can be absent from both
`GET /eth/v1/keystores` and the keystore directory (`keystore_path`) during
decrypt. A key missing from that list also does not prove the import
stopped after decrypt: the file is written before `admit`.

An interchange import takes a single-flight lock, then waits until its
estimated hold fits inside one free window of the current slot. After the
lock is acquired, that wait is at most one slot. Imports serialize on the
same lock, so a second import can wait longer while the first holds it. The
queue wait is capped at two slot durations (`QUEUE_WAIT_SLOTS`). Past that
cap the import is refused as `ImportQueueFull` with `retry_after_secs`
(HTTP 503 and `Retry-After`).

If `admit` cannot place the estimated hold in a free window it can reach
within one slot, or the blocking import starts after `latest_start`, the
import is refused as `NoFreeWindow` (HTTP 503, no `Retry-After`). Both paths
use the same message. It starts with the prefix `NoFreeWindow: ` and then
the gate text:

`NoFreeWindow: estimated hold {estimated_hold_ms} ms does not fit a free window of {window_ms} ms; split the payload`

`admit` returns that error when the estimate is longer than one free window,
or when no fitting start falls inside one slot of acquiring the mutex. An
estimate longer than the window still does not fit on a retry; split the
payload. `ImportAdmission::ensure_still_fits` returns the same error when
`tokio::time::Instant::now()` is after `latest_start`. `admit` had already
accepted that payload. A later request of the same payload can succeed when
its blocking start is still at or before the new `latest_start`. Before
genesis the import is admitted immediately.

A wait of at least 1 ms is recorded on `rvc_slashing_import_deferred_ms`.
The sample is the mutex queue plus the sleep until the window. It is not the
connection hold (`rvc_slashing_import_conn_hold_ms`). An import that is
admitted without waiting records nothing on the deferred histogram.

## Keymanager: fee recipient, gas limit, and graffiti persist before publish

`set_fee_recipient`, `set_gas_limit`, `set_graffiti`, and the matching
deletes call `ValidatorStore::update_config_durable`. That method writes the
validators file first, then applies the same change to the live store.

A failed save returns an error and leaves the previous live value in place.
A pubkey that is absent returns `NotFound` and does not rewrite the file.
If that pubkey is removed or replaced while the write is in progress, the
in-flight change is not published, the file is rewritten to match the live
key, and the call returns `NotFound`.

`map_durable_update_error` is the HTTP mapping:

| Outcome | Store result | HTTP |
|---|---|---|
| Pubkey absent when the candidate is cloned | `ValidatorStoreError::NotFound` | 404 |
| Pubkey removed or replaced during the write | `ValidatorStoreError::NotFound` | 404 |
| Save or repair failure (`write_toml_atomic`, or no config path) | any other `ValidatorStoreError` | 500 |

The remove-or-replace race is 404 because it returns `NotFound`. Before
RR3-03 the adapter mapped every store error to `ApiError::Internal`, which
is HTTP 500. `ApiError::NotFound` is HTTP 404.

## Behaviour: slot boundary drops undispatched duties

When the slot ends, attestation, sync-committee, and aggregation duties that
have not yet been pulled onto the sign pipeline are dropped. Each drop is
logged at `warn` and added to `SlotEndDropCounter`. The warn fields are
`dropped` (this slot) and `total_dropped` (process lifetime). The messages
are:

- `undispatched attestation duties dropped at slot end`
- `undispatched sync committee duties dropped at slot end`
- `undispatched aggregation duties dropped at slot end`

Signs already in flight drain. A publish is admitted only until `slot_end`
plus `SLOT_END_PUBLISH_OVERHANG` (500 ms). A submit still running at that
instant is cancelled. `SlotEndDropCounter` is in-process. It is not a
Prometheus series.

## Behaviour: duty validation rejects a malformed numeric field

A numeric field on an attester, proposer, or PTC duty that does not parse as
an integer is a named per-duty rejection (`DutyParseError`). That duty is
left out of the epoch cache. The epoch's other duties are still cached. The
rejection is counted on `rvc_duty_rejected_total{field}` and logged at
`warn` (`rejecting duty: malformed numeric field`). One bad duty does not
discard the rest of the epoch.

`field` is the wire name. Attester duties parse all five. Proposer and PTC
duties parse `slot` and `validator_index`.

| `field` | Attester | Proposer | PTC |
|---|---|---|---|
| `slot` | yes | yes | yes |
| `committee_index` | yes | | |
| `validator_index` | yes | yes | yes |
| `committee_length` | yes | | |
| `validator_committee_index` | yes | | |

## New metrics: slot phase, replay, import, and duty rejection

| Series | Labels | What one sample is |
|---|---|---|
| `rvc_slot_phase_offset_ms` | `phase` = `block`, `attestation`, `sync_message`, `aggregate`, `contribution`, `payload_attestation` | Milliseconds from the true slot start when that phase fires (`SlotAnchor::elapsed_ms`). |
| `rvc_slot_phase_late_total` | `phase` = `attestation`, `sync_message`, `aggregate`, `contribution`, `payload_attestation` | One increment inside `wait_until_bps` when that labelled deadline has already passed. There is no `phase="block"` child. |
| `rvc_slot_replay_skipped_total` | none | One increment when the clock steps back onto an already-processed slot. |
| `rvc_slashing_import_duration_ms` | none | One sample per `SlashingDb::import` call. Keymanager refusals before that call record nothing. See below. |
| `rvc_slashing_import_conn_hold_ms` | none | `conn.lock()` through `COMMIT`. A rejection before the lock records nothing here. |
| `rvc_slashing_import_deferred_ms` | none | Mutex-queue plus window sleep, when that wait is at least 1 ms. |
| `rvc_duty_rejected_total` | `field` (table above) | One increment per duty dropped at the cache for a malformed numeric field. |
| `rvc_task_exits_total` | `task`, `outcome` | Existing family. New label value `outcome="error"` for `spawn_result` / `register_result` returning `Err`. |
| `rvc_slashing_group_commit_batch_size` | none | Members drained by one non-empty `drain_batch`. Empty drains are not observed. |

`rvc_slot_phase_late_total` increments only for the label passed to
`wait_until_bps`. The process clock is `ServiceBuilder::build_slot_clock`:
`SystemSlotClock::new` then `with_deadline_schedule(deadline_schedule_from_timing)`.
`SystemSlotClock::new` first stores `DeadlineSchedule::uniform(DeadlineBps::default())`.
Production replaces that schedule before the clock is used.
`deadline_schedule_from_timing` sets pre-Gloas `sync_message` to
`attestation_due_bps` and `contribution` to `aggregate_due_bps`.
`TimingConfig::default` is 3333 and 6667 for those two. The Gloas defaults
are attestation 2500 with `sync_message_due_bps_gloas` 2500, and aggregate
5000 with `contribution_due_bps_gloas` 5000. On that installed schedule the
pairs are equal, so the coordinator takes one shared wait and labels it
`attestation` or `aggregate`. `sync_message` and `contribution` are not
passed to `wait_until_bps`, so those two children do not increment. They
increment only when the paired deadlines differ and each phase waits on its
own offset. `payload_attestation` always has its own wait, labelled
`payload_attestation`, and only when the slot's fork is Gloas or later.
That child can increment on the default schedule once that phase runs.
There is still no `phase="block"` child.

On the keymanager path, `import_interchange` returns before
`SlashingDb::import` for bad JSON, a format-version or genesis-validators-root
failure (`validate_interchange_metadata`), `ImportQueueFull`, `NoFreeWindow`
(from `admit` or from `ensure_still_fits`), and a slot-clock refusal
(`ImportDeferralError::Clock`, mapped to `SlashingProtectionError::Backend`).
None of those record `rvc_slashing_import_duration_ms`. The duration timer starts at the
top of `SlashingDb::import`. A call that gets that far records one sample
for the whole call, including a metadata re-check and `parse_interchange`.
A malformed `source_epoch`, `target_epoch`, or `slot` fails in
`parse_interchange` before `conn.lock()`: that is a duration sample and not
a connection-hold sample. `rvc_slashing_import_conn_hold_ms` starts at
`conn.lock()` and runs through `COMMIT`. A rollback after the lock still
records one hold sample.

`rvc_slashing_group_commit_batch_size` has no labels. `drain_batch` observes
the drained length once per non-empty drain. Buckets are 1, 2, 4, 8, 16,
25, 32, 50, 64, and 128. Mean batch size is `sample_sum / sample_count`.
Empty drains are not observed. This histogram does not change reserve,
commit, watermark, or PRAGMA behaviour.

`rvc_task_exits_total` force-registers `ok`, `panic`, `cancelled`, and
`error` at process init. `rvc_slashing_import_deferred_ms` uses the import
timing buckets plus `12000` and `24000` milliseconds. Duration and connection
hold keep the buckets listed under Observability below.

## Changed metric values: block-start offset is the true elapsed time

`rvc_slot_phase_block_start_offset_ms` is unchanged in name and in its
`cache` label (`cold` or `warm`). The sample is now `SlotAnchor::elapsed_ms`,
milliseconds since the true slot start, taken immediately before
`maybe_propose_block`. `cache=cold` is the post-boot slot and the slot that
sees a key-set change. Later slots are `cache=warm`.

A whole-second read of a sub-second offset records 0. This histogram records
the millisecond offset. `rvc_slot_phase_offset_ms` is a separate family and
is kept. Nothing was renamed.

`rvc_slashing_reserve_tx_hold_duration_ms` (`kind` is `attestation` or
`block`) starts in `SlashableSignSession::reserve_then_sign` before
`reserve()` and is observed only when `reserve()` returns `Ok`. The sample
includes the group-commit queue wait inside that call. Group commit is on
by default: `GroupCommitConfig::default` is batch size 50 and wait-to-fill
1 ms, and `ServiceBuilder::build_slashing_db` calls `set_group_commit` with
`GroupCommitConfig::try_from_knobs`. Unset knobs use those defaults. A
failed `reserve()` does not record this histogram.

`rvc_signer_slashing_tx_hold_duration_ms` uses the same start. It is
observed when the sign call returns, when the signer times out
(`finish_reserve_timeout`), and when `reserve()` returns `Err`. It is not a
stage-to-commit window. `kind` is `attestation` or `block`.

The p99 of `rvc_slashing_reserve_tx_hold_duration_ms{kind="block"}` can rise
after this release. The sample includes the default group-commit queue wait,
and an interchange import can hold the same connection from `conn.lock()`
through `COMMIT`. Do not page on that rise alone. Re-baseline after
upgrading. Investigate a sustained rise beyond the new baseline: the sample
cannot separate that contention from a slashing-DB stall. Page on
`rvc_slot_phase_late_total` and on the `Missed attestation deadline` warn.
That warn is logged once, at attestation-phase start, when the phase begins
more than one attestation-deadline offset past the deadline (about 8 s into
a 12 s slot on default `[timing]`). It does not cover a publish that lands
late after an on-time start. There is no Prometheus series for it.
`rvc_slot_phase_late_total` increments when `wait_until_bps` finds that
phase's deadline already passed, so it covers a late phase start, including
one that is past the deadline but not yet more than one offset past it.
Neither that counter nor the warn catches an attestation that starts on time
and publishes late.

Wall-clock last publish in the RR2-16 N=200 record
(`plan/review-2026-10-03/measurements/m2-n200.md`) falls against the RED
record in that note. Wall `last_publish_ms_after_att_deadline` RED median
**17739.82913**, M2 median **-3527.843577** (wall runs -3527.843577,
-3500.726064, -3568.643065). That field is a harness record. No Prometheus
series is named `last_publish`.

## Library consumers: operator-invisible API changes

Process flags, metrics, and the keymanager HTTP API are unchanged by the
items below. Library and embedding callers are.

- `SlotClock` requires `now_since_epoch`. The trait has no `attestation_time`
  method. `current_time_secs` and `current_time_ms` are default methods on
  `now_since_epoch`.
- `KeystoreManager::import_keystore` and `SlashingProtection::import_interchange`
  are `async`.
- `AttestationResult` is `{ validator_index, slot, outcome }`.
  `AttestationOutcome` is `Published`, `Failed(String)`, or
  `RejectedByBeaconNode { bn: Option<String>, message: String }`.
  `bn` is `PropagationOutcome::reported_by` and is `None` when that outcome
  names no endpoint. The old `success` / `error` fields are gone.
  Both types stay re-exported from `rvc::orchestrator`.
  `is_published` is true only for `Published`.
- `RemoteSigner::new_for_tests` and its `pub(crate)` alias `new_unchecked`
  compile only under `cfg(test)` or the `test-utils` feature.
  `OrchestratorDeps::for_test` has the same gate. Production code calls
  `RemoteSigner::new` and constructs `OrchestratorDeps` explicitly.
- `signer_server::server::run` joins its reloader, metrics, and HTTP tasks
  before it returns, including when the gRPC transport fails. The `Children`
  type is private. `rvc-signer` still exits when `run` returns. The join
  matters for an embedder that calls `run` again in-process.
- `DutyTracker::new` and `DutyTracker::new_with_source` take
  `Arc<dyn DutiesProvider>`. `LivenessObservationLoop::new` takes
  `Arc<dyn LivenessApi>`. `AggregationService::new` takes
  `Arc<dyn AttestationApi>` (that constructor is `pub(crate)`).
  `BeaconNodeClient` is the composition of the role traits. Its supertraits
  are `DutiesProvider`, `BlockProducer`, `AttestationApi`,
  `PayloadAttestationApi`, `SyncCommitteeApi`, `LivenessApi`, and
  `NodeStatusApi`. No new method was added to a beacon-node role trait.


## Tracing: dev/demo tail sampling profile (TRC-7c / #448)

`docker compose --profile tracing-tailsample` starts the pinned Jaeger v2
image with its built-in `tail_sampling` processor
(`config/jaeger/tail-sampling.yaml`). Traces that contain a
`"Missed attestation deadline"` span event, or any `ERROR` span, are kept.
Other traces are kept at 10%. This is a local demonstration topology, not
a production recommendation. `docker compose up` and `--profile tracing`
are unchanged, and the in-process head sample rate stays `0.01`.

## DevNet: canonical green soak pins (DSR-3.1 / #386)

Canonical fast-profile Docker soak+report archived after Phases 0–2:

- tip `909a705e6717d1a6323770c6c8b71d1251643902`
- `rvc:latest` `sha256:0d709ef8cececc10b3f6dfb774da5b13da463fcb9f003e3fec9f39d62dde6e3f`
- Lighthouse `sigp/lighthouse:v8.2.2@sha256:9a62bb8705455136e1cf96613460960f80dc2faa9d75b5c16a3bfcc9210dcdd1`
- run-id `dsr31-20260929-0408` (prior S5 roll-up `dsr25-20260929-0111`; aborted attempt `dsr31-20260929-0248` superseded)

Operator harness/metrics behavior relied on for green verdicts:

- **S5A** requires force-registered zero children (`missed_slots`, `task_exits`, `bn_health_tier`, slashing `blocked`)
- **S5B** liveness includes `bn_health_tier` / latency observations
- **S7** absent-as-0 for `blocked` on a valid scrape (empty/malformed scrape never passes)


## Metrics: S5A zero children force-registered at init (DSR-2.4 / #383)

Process init force-registers numeric zero samples (same pattern as PTC /
`envelope_late`) for rare-event / presence families that blake-manual S5A missed:

- `rvc_orchestrator_missed_slots_total`
- `rvc_task_exits_total{task,outcome}` (known tasks × `ok`/`panic`/`cancelled`/`error`)
- `rvc_bn_health_tier{endpoint="unknown"}` (real BN endpoints still come from the
  sync poller)
- `rvc_slashing_protection_checks_total{result="blocked"}`

**Decision (FR-P2-1):** those families stay **hard-required** in S5A once zeros
land. Soften S5A (FR-P2-2) is not done. See `docs/devnet-testbed.md` Decision Log.

## Metrics: `rvc_proposals_total` success / failed outcomes (DSR-1.2 / #377)

`rvc_proposals_total` now force-registers `outcome=success` and `outcome=failed`
(alongside `envelope_late`) at process init. The orchestrator increments
`success` on a completed propose+publish and `failed` on error or outer
timeout. Devnet report K6 presence treats zero-delta force-registered children
as absent and clears `no_proposal_window` when any proposal outcome delta is
non-zero.

## Behaviour: keymanager voluntary exit uses the beacon-node pool

The keymanager voluntary exit now uses the beacon-node pool instead of a single endpoint. A beacon node that answers HTTP 200 without the requested validator, or a genesis body whose validators root is not the configured root, is skipped; the next node is tried. The exit is not signed from that body.

## Behaviour: DELETE drains signing before export

DELETE `/eth/v1/keystores` disables the validator and drains the slashable
signing lock before exporting slashing protection (added latency, surfaced as
`rvc_keymanager_quiesce_wait_ms`). If a signature does not finish within the
drain timeout, DELETE fails, exports nothing, and leaves the key disabled;
retry it. A deleted key can be re-imported and signs again after the normal
doppelganger window, without a restart. When doppelganger detection is off,
re-import reopens signing immediately because the handler imports the
slashing-protection interchange before any keystore.

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
inventory is **75** (`OPERATOR_KNOB_NAMES` in
`crates/rvc/src/config/knobs.rs`). `grpc_port` and `grpc_address` stay
removed. The five names added since the 70-name list are the two `[duties]`
knobs and the three `[keymanager]` import KDF knobs.

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

## Slashing: VC attestation signs concurrently

ARCH-P1-5 (`reserve_then_sign`) shortens the slashing-DB critical section on
the **signer-server** path. `AttestationService::process_slot_until` in
`crates/rvc/src/orchestrator/attestation.rs` stops pulling new duties at
`slot_end`, signs with `buffer_unordered(dispatch_limits.concurrency)`, and
publishes each ready chunk with
`buffer_unordered(dispatch_limits.publish_concurrency)`. Sync-committee
messages and aggregation use the same limits. Those limits are the
`[duties]` knobs above (`duty_dispatch_concurrency` default 32,
`duty_publish_concurrency` default 2). The attestation-data memo fetches
one query per distinct committee, under `buffer_unordered(concurrency)`,
only before Electra. `memo_queries` returns that list when
`uses_electra_attestation_wire` is false. Electra and later start with one
query at `committee_index` 0. If the response fork disagrees,
`load_attestation_data_memo` drops the shared entry and refetches per
committee. A fetch error, or a target epoch that does not parse, does not
trigger that refetch.

---

## Behaviour: `--graffiti` applies to validator-store defaults

`--graffiti` is an in-memory validator-store default. Per-validator graffiti and keymanager-set values still win. Startup does not rewrite the validators file. The next `save_config` — a keymanager fee-recipient, gas-limit, or graffiti save, or any other snapshot of the in-memory defaults — persists that value over `[defaults].graffiti`. A later start without `--graffiti` keeps the persisted value. A save while the flag is absent leaves the file default unchanged.

## Breaking (behaviour): DVT peers connect lazily

`rvc-signer` DVT peers connect lazily with an explicit connect timeout; an
unreachable peer no longer fails startup. Allow-list and SNI errors remain
fatal. Startup logs those peers as configured and not yet dialled; `rvc_dvt_peer_ready{peer}` stays 0 until the first successful RPC.

## Observability

Import conflicts are logged and counted (`rvc_slashing_import_conflicts_total`).

On the keymanager path, `import_interchange` returns before `SlashingDb::import`
for bad JSON, a format-version or genesis-validators-root failure
(`validate_interchange_metadata`), `ImportQueueFull`, `NoFreeWindow`
(from `admit` or from `ensure_still_fits`), and a slot-clock refusal
(`ImportDeferralError::Clock`). Those refusals record no
`rvc_slashing_import_duration_ms` sample and no
`rvc_slashing_import_conn_hold_ms` sample.

`SlashingDb::import` records `rvc_slashing_import_duration_ms` for the whole
call, starting before its own metadata re-check and before `parse_interchange`.
A malformed `source_epoch`, `target_epoch`, or `slot` fails in that parse,
before `conn.lock()`: duration only. `rvc_slashing_import_conn_hold_ms` is
`conn.lock()` through `COMMIT`. A rollback after the lock is taken still
records one hold sample. Import prepares each SQL statement once.
Buckets for both histograms are 10, 25, 50, 100, 250, 500, 1000, 2500, 5000,
and 10000 milliseconds.

## Breaking (wire): Deneb/Electra/Fulu blocks are published as full SignedBlockContents with sidecars

Deneb/Electra/Fulu blocks are published as full SignedBlockContents with sidecars. The JSON produce/publish path is now live and publishes `SignedBlockContents` with `kzg_proofs` and `blobs`. Nodes that accepted the prior malformed payload may behave differently.

Electra SSZ publish relies on the landed RR ADR-R01 path (`resolve_block_region_end` / `deserialize_block_contents_ssz` in #345 `02336892`, and `sign_and_publish_ssz` SignedBlockContents framing in #346 `acb9d997`). DSR-1.1 (#376) verified that path with an Electra BlockContents fixture: the pre-fix unbounded `SignedBeaconBlock` framing is OffsetOutOfBounds-class against a 3-offset decoder; the landed framing is not. No additional wire change in DSR-1.1.

## Behaviour: BN attempt budgets

Each BN attempt gets a floored share of the operation budget; timeouts degrade node health, including when every node hangs.

## Breaking (wire): interchange exports shrink

Interchange exports collapse sub-watermark rows into one synthetic record per
validator. Files get smaller. Protection is non-weakening.

## Wire: Electra+ aggregate fetch

Electra+ aggregate fetch uses `/eth/v2`; BNs without v2 fall back once, logged.

## Wire: `SingleAttestation` sends quoted integers.

## Breaking / safety: keys that reach the pubkey map earn duties

Keys that reach the pubkey map — keystore load, keymanager import,
secret-provider refresh, and gRPC remote-signer keys — now receive duties.

With doppelganger enabled, signing waits on the validator-store `enabled`
flag and the forward window. With doppelganger disabled, signing waits only
on the store `enabled` flag — confirm these keys are not active elsewhere
before upgrading. Boot registration (keystore load and gRPC remote-signer
keys) preserves an existing `enabled = false` row. Force-enable applies only
to keymanager import and secret-provider admission: those paths insert the
key enabled, and the keymanager zero-window task sets `enabled` true.
