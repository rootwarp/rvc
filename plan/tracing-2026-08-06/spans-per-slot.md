# TRC-1f — spans-per-slot at sample rate 1.0 (Phase 1)

Attempted measurement of **spans per root `slot.process`** at head-based
sample rate **1.0**, against the TRC-1d (#405) Jaeger / OTLP stack, so
ADR-005's production sampling default (`DEFAULT_TRACING_SAMPLE_RATE = 0.01`)
can be judged against evidence rather than guesswork.

> **Outcome: deferred.** This cloud-agent VM cannot run the required
> multi-validator soak with OTLP → Jaeger. Measurement is deferred to
> **Phase 5 / TRC-5a**. ADR-005's default is **unchanged**.

Related: [`latency-baseline.md`](./latency-baseline.md) (TRC-1e / T20),
[`A-12-stage-rs-repin.md`](./A-12-stage-rs-repin.md) (T19). Root span site:
`crates/rvc/src/orchestrator/coordinator/mod.rs` ≈ line **490**
(`info_span!("slot.process", …)`).

---

## Status

| Field | Value |
|---|---|
| **Issue** | #409 (TRC-1f) |
| **Result** | **Deferred** (explicit) |
| **Reason** | Cloud agent VM has **no Docker** (`command -v docker` empty; no `/var/run/docker.sock`). TRC-1d Jaeger (`docker compose --profile tracing`) and `scripts/devnet` EL/CL images both require a container runtime. Native `LAUNCH_MODE` still depends on those chain containers. |
| **Follow-up** | **Phase 5 / TRC-5a** — perform the measurement on a host with Docker (or an equivalent OTLP collector + Electra soak) and replace this deferral with measured mean/max. |
| **ADR-005** | **Unchanged.** `DEFAULT_TRACING_SAMPLE_RATE` stays `0.01` pending that measurement. |
| **Plan tip (this file)** | Recorded against develop tip `1d0237947d90c5e4c9b825f1a97724e0fd41229b` (post-#461 TRC-1c). |
| **A-12 / T19 pin** | Remains `22aa3de5bf5ed0c03ed571694dc3a5652e460613` — not retargeted; `stage.rs` not edited. |

### Environment probe (why not measured here)

| Check | Result (UTC 2026-10-01) |
|---|---|
| Host | Intel Xeon (KVM), x86_64, 4 cores, ~15 GiB RAM |
| `command -v docker` | empty |
| `/var/run/docker.sock` | missing |
| TRC-1d stack | `docker compose --profile tracing` (Jaeger v2, OTLP/HTTP `:4318`) — blocked |
| Devnet | `scripts/devnet` (`LAUNCH_MODE=native` preferred) — blocked without containerized geth/lighthouse |

---

## Method (to run when measurement happens)

Reproduce on a machine with Docker and enough resources for a short Electra
devnet soak. Goal: **≥10** completed slots at sample rate **1.0**, then count
descendant spans under each root `slot.process`.

### 1. Tip and invariants

```bash
git checkout develop && git pull
# Confirm A-12 pin still matches; do not edit stage.rs.
```

### 2. Collector (TRC-1d)

```bash
docker compose --profile tracing up -d
curl -sS -o /dev/null -w '%{http_code}\n' -X POST \
  http://127.0.0.1:4318/v1/traces \
  -H 'Content-Type: application/json' -d '{}'
# Expect HTTP 200. Jaeger UI: http://127.0.0.1:16686
```

### 3. Devnet + native RVC → loopback OTLP

Prefer **`LAUNCH_MODE=native`** so the VC process can reach
`127.0.0.1:4318`. Docker-attached RVC sits on `${CONTAINER_PREFIX}-network`
(not compose `rvc-net`) and does **not** inherit compose OTel env — avoid
that path for this measurement unless you explicitly bridge networks and
inject env.

```bash
export LAUNCH_MODE=native
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
export OTEL_TRACES_SAMPLER_ARG=1.0
# Or equivalent: --tracing-endpoint http://127.0.0.1:4318 \
#               --tracing-sample-rate 1.0

# Typical Electra local soak (adjust keys/slots as needed):
# scripts/devnet/run.sh  — or up → attach-rvc → soak ≥10 slots → report → down
```

Record in the results table:

| Field | What to write |
|---|---|
| **Network** | e.g. local Electra devnet (`CHAIN_ID=1337` / `scripts/devnet`) |
| **Validator count** | `NUM_VALIDATORS` / `RVC_KEYS` actually attached |
| **Sample rate** | `1.0` (`OTEL_TRACES_SAMPLER_ARG` or `--tracing-sample-rate`) |
| **Slots** | ≥10 distinct root `slot.process` traces |
| **Commit** | `git rev-parse HEAD` of the measured tree |

### 4. Count spans per root `slot.process`

For each sampled root span named `slot.process` (coordinator hot path):

1. Open the trace in Jaeger (service `rvc`, or `--tracing-service-name`).
2. Count **all spans in that trace** that are the root plus its descendants
   (Jaeger "Spans" count for the trace is fine if the root is `slot.process`
   and nothing else shares the trace).
3. Over ≥10 such roots, compute **mean** and **max**.

Optional CLI (Jaeger HTTP API), once UI confirms data:

```bash
# Sketch only — adjust service name / lookback to match the soak window.
curl -sS 'http://127.0.0.1:16686/api/traces?service=rvc&limit=50' \
  | python3 -c '
import json,sys
from statistics import mean
roots=[]
for t in json.load(sys.stdin).get("data",[]):
    spans=t.get("spans",[])
    names={s["spanID"]: s.get("operationName") for s in spans}
    # root = span whose parentSpanID is absent/empty
    for s in spans:
        refs=s.get("references") or []
        if not any(r.get("refType")=="CHILD_OF" for r in refs):
            if s.get("operationName")=="slot.process":
                roots.append(len(spans))
if len(roots) < 10:
    raise SystemExit(f"need >=10 slot.process roots, got {len(roots)}")
print("n", len(roots), "mean", mean(roots), "max", max(roots), "counts", roots)
'
```

### 5. Fill results (placeholder until TRC-5a)

| Metric | Value |
|---|---|
| Mean spans / `slot.process` | *deferred — fill in TRC-5a* |
| Max spans / `slot.process` | *deferred — fill in TRC-5a* |
| Slots counted | *≥10 required* |
| Validators | *—* |
| Network | *—* |
| Method | OTLP → Jaeger (TRC-1d); rate 1.0; count under `slot.process` |
| Reproducibility | Second reader re-runs §§2–4 on the same tip class; expect same mean/max ± noise from duty mix / epoch boundary |

---

## ADR-005 implication (no default change)

ADR-005 / TRC-1a names the production head-based default as
`DEFAULT_TRACING_SAMPLE_RATE = 0.01` in
`crates/rvc-config/src/sections/tracing.rs`. Compose / local recipes may set
`OTEL_TRACES_SAMPLER_ARG=1.0` for visibility; that does **not** change the
binary default.

**Until Phase 5 / TRC-5a records mean/max spans per `slot.process` at rate
1.0, there is no empirical basis to raise or lower the 0.01 default.** This
file therefore states:

- The default **remains `0.01`**.
- No ADR-005 text, const, CLI default, or docs table is updated by TRC-1f.
- A future rate change (if any) must cite the measured spans-per-slot numbers
  once they exist in this file (or a successor note linked from here).

---

## Standing invariants (TRC-1f)

- Plan-only: this path under `plan/tracing-2026-08-06/` — no crate, Cargo,
  ADR default, or `stage.rs` edits.
- A-12 / T19 pin stays `22aa3de5bf5ed0c03ed571694dc3a5652e460613`.
- Closing #409 via **explicit deferral** is accepted; phase exit is not blocked.
