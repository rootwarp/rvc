# Gloas observability

Pre-fork alerting rules and dashboard panels over the six families this phase
makes operator-visible. Config keys, rollback status, and the remote-signer gap
live in [gloas-upgrade.md](gloas-upgrade.md) (issue 7.11).

No fork date is named here. No alert, panel, or runbook step converts a
calendar date into an epoch. Read `GLOAS_FORK_EPOCH` from the network's own
config at run time, the same way [gloas-upgrade.md](gloas-upgrade.md) does.

**No minimum remote-signer version is writable.** Consensys Web3Signer has no
Gloas sign types through 26.7.0 (the last version this note is allowed to
name). There is no later Web3Signer release in this document, and none should
be invented. If you need remote signing on a Gloas-scheduled network, run
`bin/rvc-signer` at the same commit as the validator client.

---

## Omit-not-zero

An absent series means **unavailable**, not zero. The same rule as the
Prometheus textfile export in [validator-perf.md](validator-perf.md):
unavailable metrics are omitted, not emitted as `0`.

Alerts therefore use `absent()` when the question is "is this series missing?",
and they compare against `0` only when rvc **emits** a zero (a capable/incapable
gauge, a counter at rest). Do **not** write `metric or vector(0)`,
`default(metric, 0)`, or `(metric unless metric) == 0` to fill a hole. That
turns "unscheduled" / "not yet probed" / "no rejection observed" into a fake
zero and pages on the wrong condition.

| State | What rvc does | What the alert must do |
|-------|---------------|------------------------|
| Series omitted | child never created, or `remove_label_values` | `absent(...)`; treat as unavailable |
| Series present at `0` | real gauge/counter value | `== 0` / `increase(...) > 0` is meaningful |
| Scrape down | every family absent | `absent(rvc_fork_current_id)` (or the scrape `up` series), not a per-family `== 0` |

---

## Scrape

rvc exposes Prometheus text on `GET /metrics` (`crates/metrics/src/server.rs`).
Default bind is loopback `metrics_port = 8080` ([running-guide.md](running-guide.md)).
`rvc-signer` exposes the same `rvc_signer_rejections_total` family on its own
registry (default `127.0.0.1:9101`).

Force-registration (`metrics::init` / `LazyLock::force`) makes some families
visible at rest; empty `MetricVec` children still stay omitted until a labelled
sample is observed. The per-family notes below say which is which.

---

## Six families (D5)

| Family | Owner | Type | Labels | Emitted when |
|--------|-------|------|--------|--------------|
| `rvc_fork_current_id` | 8.1 · `crates/rvc/src/metrics.rs` | gauge | none | `ForkName::id()` (phase0=0 … gloas=7) on every slot after the orchestrator loop starts. `init()` creates the series at `0` before the first slot. |
| `rvc_fork_next_activation_epoch` | 8.1 · `crates/rvc/src/metrics.rs` | gauge | `fork` (lowercase `ForkName`) | Next non-sentinel activation from `ForkSchedule::next_activation` (`crates/eth-types/src/fork.rs`). **Omitted** when the remainder is the far-future sentinel (`u64::MAX`); the child is removed, never set to `0` or `u64::MAX`. |
| `rvc_ptc_duties_total` | 7.6 / 8.2 · `crates/rvc/src/metrics.rs` | counter | `outcome` = `scheduled` / `skipped_no_data` / `dropped` | PTC duty path. Children are pre-created at `0` in `init()`. |
| `rvc_ptc_attestations_total` | 7.6 / 8.2 · `crates/rvc/src/metrics.rs` | counter | `status` = `success` / `failed` | Pool POST of signed payload attestations. Children pre-created at `0`. A 204 skip never increments this family. |
| `rvc_bn_capability_state` | 6.7 / 8.3 · `crates/bn-manager/src/metrics.rs` | gauge | `endpoint` (`scheme://host:port`, no userinfo/path), `capability` = `fork_recognised` / `produce_block_v4` | `BnManager::new` (`crates/bn-manager/src/manager.rs`) publishes **1** for both capabilities **before any probe** (optimistic). A later `record_outcomes` probe writes `1` (v4 success) or `0` (incapable). **`1` is not evidence that v4 was probed.** `0` is a real post-probe incapable sample. Configured endpoints are present from `new()`, not omitted. |
| `rvc_signer_rejections_total` | 8.4 · `crates/signer/src/metrics.rs` (VC) and `crates/signer-server/src/metrics.rs` (`rvc-signer`) | counter | `reason`, `sign_type`, `version` | Fail-closed type/version rejections. Children omitted until the first rejection. `reason` is `unsupported_type` / `unsupported_version`; `version` is a lowercase fork name or `unknown`. |

`rvc_validators_slashed_total` (`crates/metrics/src/definitions.rs`) is **not**
one of the six. It is the paging-immediately slashing gate and is listed with
the rules so it is not wired as `== 0`.

---

## Alert rules

Each rule states why it fires and what to do. `<current_epoch>` is **not** an
rvc family: substitute a scalar from the connected BN (head slot /
`SLOTS_PER_EPOCH` from that network's spec). `N` is an epoch count you choose.
Do not encode a calendar date as `N`.

### 1. Next activation absent (unscheduled) — informational, not paging

**Family:** `rvc_fork_next_activation_epoch`

```promql
absent(rvc_fork_next_activation_epoch) and on() rvc_fork_current_id
```

**Fires when:** the process is scraped (`rvc_fork_current_id` is present) and
no next-activation child exists. That is the omit-not-zero encoding of
`ForkSchedule::next_activation` returning `None` (trailing fork at `u64::MAX`).

**Why `absent()`, not `== 0`:** a missing child is "unscheduled", not epoch
zero. Comparing an omitted series to `0` would look like "the next fork
activates at genesis" and would page continuously.

**Operator action:** expected on a network that has not scheduled a later fork.
If you *have* set matching `gloas_fork_epoch` / `GLOAS_FORK_EPOCH` on both
sources ([gloas-upgrade.md](gloas-upgrade.md)) and this still fires after the
slot loop is running, the schedule never became a non-sentinel next activation
— check the two-source reconciliation, then the scrape. Do **not** page a
human for the unscheduled case alone.

### 2. Pre-fork warning — next activation within `N` epochs

**Family:** `rvc_fork_next_activation_epoch`

```promql
rvc_fork_next_activation_epoch - <current_epoch> < N
```

**Fires when:** the next-activation series **exists** and its value minus the
operator-supplied current epoch is less than `N`. PromQL leaves the result
empty when the left-hand series is omitted, so this does not fire while
unscheduled.

**Why not `or vector(0)`:** filling a hole with zero would fire this warning
for the entire life of an unscheduled process (`0 - current < N`).

**Operator action:** treat the named `fork` label as the upcoming activation.
Confirm [gloas-upgrade.md](gloas-upgrade.md) keys (`[fork_schedule]`, the six
Gloas `*_DUE_BPS*`, `SLOT_DURATION_MS`) match the BN spec. Watch
`rvc_bn_capability_state` for a **0** (rule 5) — a boot-time `1` is
optimistic, not a v4 probe. Run `rvc-signer` at this commit, not a
third-party Web3Signer. No minimum remote-signer version is writable.

### 3. Current fork id absent — scrape / slot-loop

**Family:** `rvc_fork_current_id`

```promql
absent(rvc_fork_current_id)
```

**Fires when:** the gauge is not on the scrape. After `init()` the series
exists (at `0` until the first slot), so this is scrape-down or a process that
never initialised metrics.

**Why not `== 0`:** `0` is `ForkName::Phase0` after the first `Fork boundary`
log, and is also the pre-slot default. `== 0` is not "missing".

**Operator action:** confirm `GET /metrics` is reachable from Prometheus and
that `rvc start` has entered the slot loop. Use the `Fork boundary` log line
(`epoch`, `fork`, `previous`) as the ground truth for the first resolution.
Do not page on `== 0` alone.

### 4. PTC submission rate below 0.99 over 1 h

**Families:** `rvc_ptc_attestations_total` and `rvc_ptc_duties_total`.

The rate is **7.6b's** `ptc_rate` (`scripts/devnet_scorecard.py`):
`success / scheduled`, not pool-POST `success / (success + failed)`.

```promql
(
  sum(increase(rvc_ptc_attestations_total{status="success"}[1h]))
  /
  sum(increase(rvc_ptc_duties_total{outcome="scheduled"}[1h]))
) < 0.99
and
sum(increase(rvc_ptc_duties_total{outcome="scheduled"}[1h])) > 0
```

```promql
sum(increase(rvc_ptc_duties_total{outcome="dropped"}[1h])) > 0
```

**Fires when:** at least one duty was `scheduled` (signed) in the hour and the
fraction that then POSTed `success` is below 0.99; or at least one duty was
`dropped` (fetch/sign failure) before it could be scheduled. The `scheduled > 0`
guard keeps a pre-Gloas rest-`0` process from looking like a 0 % rate.

`skipped_no_data` (HTTP 204) is never a failure: 7.6b returns `1.0` when
`scheduled = 0` and skipped > 0. The alert does the same operationally (does
not fire). Dropped duties never become `scheduled`, so they are invisible to
the ratio — that is why the companion `dropped` rule exists.

Do **not** substitute `success / (success + failed)` on
`rvc_ptc_attestations_total` alone. That denominator is pool POSTs, not 7.6b's
signed-duty count.

**Why not `== 0` on a missing child:** these two families pre-create children
at `0`, so rest is a present zero. If a child were ever omitted, `increase()`
on an absent series is empty — still not a fake 0 % rate.

**Operator action:** inspect `outcome` / `status` labels. `dropped` with
`rvc_signer_rejections_total` moving is a signer type/version gap (rule 6).
`scheduled` without matching `success` is a failed or missing pool POST
(rule 5). A 204 skip storm is the BN not serving payload-attestation data, not
a submission-rate miss. Pre-Gloas, both rules should stay silent.

### 5. Any BN capability gauge at 0

**Family:** `rvc_bn_capability_state`

```promql
rvc_bn_capability_state == 0
```

**Fires when:** a **present** `(endpoint, capability)` sample is `0`
(incapable) for `fork_recognised` or `produce_block_v4`. That `0` is written
only after a probe (`record_outcomes`).

**Boot-time `1` is optimistic, not a probe.** `BnManager::new`
(`crates/bn-manager/src/manager.rs`) publishes `1` for both capabilities
before any BN call. A later successful `produce_block_v4` writes `1` again; an
incapable outcome writes `0`. **Do not treat panel `1` as evidence that v4 was
probed**, and do not use `== 1` as a pre-fork readiness gate.

**Why this `== 0` is allowed:** `0` is an emitted post-probe incapable value,
not a hole. Configured endpoints already have a series from `new()` (at `1`).
`absent(rvc_bn_capability_state)` after startup is scrape-down, not "not yet
probed" and not "every BN is incapable". Do not default absent samples to `0`.

**Operator action:** the labelled `endpoint` was probed and cannot serve that
capability. If every remaining BN is `0` for `produce_block_v4` on a
Gloas-scheduled network, v4 produce will fail closed — do not guess a fork or
roll back with `--allow-unsupported-fork`. Reprobe, replace the BN, or take
that node out of the pool. `endpoint` is `scheme://host:port` only (no
credentials, no path). A persistent `1` with no `produce_block_v4` traffic is
still the boot optimistic value.

### 6. Any increase in signer rejections

**Family:** `rvc_signer_rejections_total`

```promql
sum(increase(rvc_signer_rejections_total[5m])) > 0
```

**Fires when:** a fail-closed rejection is counted on the VC scrape or on
`rvc-signer` (`:9101`). Labels name `reason` (`unsupported_type` /
`unsupported_version`), bounded `sign_type`, and `version` (lowercase fork or
`unknown`).

**Why not `== 0` / `absent() == false`:** children are omitted until the first
rejection. Absence is the healthy idle state ("no rejection observed"), not
zero. `increase()` on an absent series does not fire.

**Operator action:** the signer refused a type or version. Run `bin/rvc-signer`
at the same commit as rvc. Do **not** point rvc at a third-party Web3Signer
for Gloas PTC, proposer preferences, builder-request auth, or Gloas
block/aggregate duties and expect them to sign — **no minimum remote-signer
version is writable** (Web3Signer through 26.7.0). A lagging signer is a named
rejection, not a silent fallback.

### 7. Any increase in slashed validators — page immediately

**Family:** `rvc_validators_slashed_total` (paging gate; not one of the six)

```promql
increase(rvc_validators_slashed_total[1m]) > 0
```

**Fires when:** the counter moves. `for: 0s` — do not wait to confirm.

**Why `increase()`, not `== 0`:** the counter is registered at rest `0`. A
present zero is "no slash observed", which is healthy. Absence of the series
is scrape-down (rule 3), not "zero slashes". Never `or vector(0)`.

**Operator action:** page immediately. Stop treating the process as safe to
sign. Inspect the slashing DB and any doppelganger window; do not keep
submitting. This is the soak zero-slashing gate the later snapshot will
enforce.

---

## Dashboard panels

Six panels, one family each. A seventh paging stat sits beside them so the
slash counter is not mistaken for a "healthy zero" of a missing series.

| Panel | Query | How to read it |
|-------|-------|----------------|
| Current fork | `rvc_fork_current_id` | Stat. Map 0–7 → phase0 … gloas. Ignore `0` until a `Fork boundary` log has fired. |
| Next activation | `rvc_fork_next_activation_epoch` | Stat by `fork`. **No data = unscheduled** (omit-not-zero), never display `0`. |
| PTC duties | `increase(rvc_ptc_duties_total[1h])` | Stacked time series by `outcome`. `skipped_no_data` is 204; `dropped` is a failed duty. |
| PTC submissions | 7.6b `success / scheduled` over 1 h | Gauge, floor 0.99. Empty/NaN when `scheduled` did not move — not a 0 % miss. 204-only windows are 7.6b `1.0`, not a miss. |
| BN capability | `rvc_bn_capability_state` | Table by `endpoint`, `capability`. `0` = post-probe incapable (page). `1` = boot optimistic **or** a later successful probe — **not** "v4 was probed". Missing row after startup is scrape-down, not "not yet probed". |
| Signer rejections | `increase(rvc_signer_rejections_total[5m])` | Time series by `reason`, `sign_type`, `version`. No series = no rejection yet. |
| Slashed (paging) | `rvc_validators_slashed_total` | Stat. Any step up pages (rule 7). |

Annotate fork changes from the `Fork boundary` log (`fork`, `previous`,
`epoch`). Do not put a calendar date on the annotation.

---

## Daily soak snapshot

Issue 8.7 adds a repeatable daily snapshot (zero-slashing and PTC gates) and
documents its invocation here. Until that lands, scrape `/metrics` and evaluate
the rules by hand. A missing series is unavailable, distinct from a failed
gate.

Intended path, not yet written (un-backticked so docs-freshness does not
require a file that does not exist):

- 8.7 soak snapshot: scripts/gloas_soak_snapshot.sh (#338)

```bash
# 8.7: snapshot invocation
```

---

## Copy-paste Prometheus rules

`N` and `<current_epoch>` are operator substitutions. `for` values are
starting points, not spec constants.

```yaml
groups:
  - name: rvc-gloas-prefork
    rules:
      - alert: RvcForkNextActivationUnscheduled
        expr: absent(rvc_fork_next_activation_epoch) and on() rvc_fork_current_id
        labels:
          severity: info
        annotations:
          summary: Next-fork series omitted (unscheduled / sentinel).
          action: Expected until a later fork is scheduled. Not paging.

      - alert: RvcForkNextActivationSoon
        expr: rvc_fork_next_activation_epoch - <current_epoch> < N
        labels:
          severity: warning
        annotations:
          summary: Next fork activation within N epochs.
          action: Confirm gloas-upgrade.md keys and rvc-signer at this commit. A capability 1 is optimistic, not a v4 probe.

      - alert: RvcForkCurrentIdAbsent
        expr: absent(rvc_fork_current_id)
        labels:
          severity: warning
        annotations:
          summary: rvc_fork_current_id missing from scrape.
          action: Check GET /metrics and that the slot loop is running.

      - alert: RvcPtcSubmissionRateLow
        expr: |
          (
            sum(increase(rvc_ptc_attestations_total{status="success"}[1h]))
            /
            sum(increase(rvc_ptc_duties_total{outcome="scheduled"}[1h]))
          ) < 0.99
          and
          sum(increase(rvc_ptc_duties_total{outcome="scheduled"}[1h])) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: PTC success/scheduled below 0.99 over 1h (7.6b ptc_rate).
          action: Inspect status and outcome labels; pair with dropped duties.

      - alert: RvcPtcDutiesDropped
        expr: sum(increase(rvc_ptc_duties_total{outcome="dropped"}[1h])) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: PTC duties dropped before pool POST.
          action: Check signer rejections and BN payload-attestation fetch.

      - alert: RvcBnCapabilityIncapable
        expr: rvc_bn_capability_state == 0
        labels:
          severity: page
        annotations:
          summary: Beacon node incapable for a labelled capability (post-probe 0).
          action: 1 at boot is optimistic, not a v4 probe. Replace or drop the labelled endpoint.

      - alert: RvcSignerRejections
        expr: sum(increase(rvc_signer_rejections_total[5m])) > 0
        labels:
          severity: page
        annotations:
          summary: Fail-closed signer rejection (type or version).
          action: Run rvc-signer at this commit. No minimum Web3Signer version is writable.

      - alert: RvcValidatorSlashed
        expr: increase(rvc_validators_slashed_total[1m]) > 0
        for: 0s
        labels:
          severity: page
        annotations:
          summary: rvc_validators_slashed_total increased.
          action: Page immediately. Stop signing until the slashing event is understood.
```

---

## See also

- [gloas-upgrade.md](gloas-upgrade.md) — `[fork_schedule]`, Gloas deadlines, signer gap
- [running-guide.md](running-guide.md) — metrics bind and CLI
- [forks.md](forks.md) — Gloas dispatch sites
- [validator-perf.md](validator-perf.md) — omit-not-zero on the estimator export
- [web3signer-http-api.md](web3signer-http-api.md) — in-tree HTTP signer (not Consensys Web3Signer Gloas support)
