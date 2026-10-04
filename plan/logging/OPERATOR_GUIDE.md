# rs-vc Operator Guide — Reading the Log Stream & OTLP Traces

> **Audience: SREs / operators running `rvc` (the validator client) and `rvc-signer`
> (the remote signer).** This is the operator-facing counterpart to
> [`STANDARD.md`](./STANDARD.md) (the author/reviewer rubric). It teaches you to read the
> rs-vc log stream, dial verbosity, follow one duty or signing request end to end, and
> alert on the absence of the healthy `info` heartbeat.
>
> For the field taxonomy / level rules themselves, this guide **links to**
> [`STANDARD.md`](./STANDARD.md) rather than restating it. For the CLI flags that turn
> these knobs on, see [`docs/running-guide.md`](../../docs/running-guide.md); this guide
> deepens that material, it does not duplicate the flag tables.

---

## 1. Default levels & precedence

Both binaries default to **`info`** and share **one** filter implementation, so they
**cannot drift** on default level or precedence: each routes its subscriber init through
`telemetry::env_filter_or("info")` (`crates/telemetry/src/init.rs:147`, ADR-003;
`bin/rvc/src/main.rs:782`, `bin/rvc-signer/src/main.rs:250`). This is the reconciliation
that landed in Phase 3.

**`info` is the production default and is safe to leave on.** It is the operator
heartbeat — low, constant volume regardless of how many validators are loaded (see §5).

**Precedence — `RUST_LOG` always wins over the configured default / `--log-level`:**

| Source | Effect |
|---|---|
| `RUST_LOG` set to ≥1 valid directive | **Wins entirely.** Overrides `--log-level` / `log_level` config / the `info` default. |
| `RUST_LOG` unset, empty (`""`, `","`, whitespace), or malformed (`rvc=notalevel`) | Falls back to the default (`info` in production) — logging **never goes dark** on a `RUST_LOG=` style misconfig in a Dockerfile/k8s manifest. |
| `RUST_LOG=off` (explicit) | Honored — you asked for silence. Only *accidental*-empty falls back. |

The fallback behavior is deliberate and tested (`crates/telemetry/src/init.rs:113-164`):
an accidental "verbose off" never means "silent."

**Compile-time level floor (ADR-001).** The release build is compiled with
`release_max_level_debug`: **`trace!` statements are compiled OUT of `--release` binaries.**
Consequences for an operator:

- `debug` is **runtime-switchable** in a normal release build — `RUST_LOG=...=debug`
  works on the binary you already deployed.
- `trace` requires a **debug/test build** (`cargo build` without `--release`). Setting
  `RUST_LOG=...=trace` on a release binary raises the *filter* to trace, but the release
  binary contains no `trace!` callsites to emit, so you see nothing new. To get wire-level
  detail, run a debug build in a controlled environment — never in production (trace is the
  highest-volume level; see [`STANDARD.md` §1](./STANDARD.md#1-level-taxonomy-normative)).

---

## 2. `RUST_LOG` recipes (copy-paste)

`RUST_LOG` directives are `target=level` pairs, comma-separated. A bare level
(`RUST_LOG=debug`) sets the global floor. The `target` is the **compiled crate name**
(hyphens become underscores) optionally followed by a `::module::path`. Whitespace after
commas is tolerated (`warn, rvc=trace` is honored).

> **Target-name reference** (verify against `cargo tree`): the `rvc` binary *and* the
> orchestrator crate both compile as target **`rvc`** (so `rvc=debug` covers both); the
> multi-BN layer is **`rvc_bn_manager`** (package `rvc-bn-manager`); the intra-slot timing
> crate is **`rvc_timing`** (package `rvc-timing`); the signer's HTTP frontend module is
> **`rvc_signer_bin::http_api`**.

```bash
# Everything the rvc binary + orchestrator emit, at debug (per-duty decision points).
RUST_LOG=rvc=debug rvc start

# Quiet globally, but trace the orchestrator while debugging the beacon-node failover layer.
# (trace requires a DEBUG build — see §1. On a release build use =debug for rvc_bn_manager.)
RUST_LOG=rvc=trace,rvc_bn_manager=debug rvc start

# Slot-timing investigation: see the per-slot timing milestones at debug, rest at info.
RUST_LOG=info,rvc_timing=debug rvc start

# rvc-signer: trace the :9000 Web3Signer HTTP path (request framing, dispatch) only.
# Run a DEBUG build of rvc-signer for trace; =debug works on a release build.
RUST_LOG=warn,rvc_signer_bin::http_api=trace rvc-signer serve ...

# Two directives, hand-typed with a space after the comma (tolerated, not discarded):
RUST_LOG=warn, rvc=debug rvc start
```

These match the directive style already in
[`docs/running-guide.md:319-327`](../../docs/running-guide.md). `RUST_LOG` overrides
`--log-level` (§1).

### 2.1 Changing the level at runtime — `SIGHUP` reload (no restart)

`RUST_LOG` is read **once at startup**. To raise or lower verbosity on a running
process **without restarting it** (so you don't lose in-memory state or drop
duties), start the binary with the opt-in `--enable-log-reload` flag, then change
`RUST_LOG` **in the process's own environment** and send it `SIGHUP`. On `SIGHUP`
the binary **re-reads `RUST_LOG`** through the exact precedence in §1 and swaps
the active log filter in place; newly enabled `debug!`/`trace!` callsites begin
emitting immediately, and lowering the level quiets them again.

The catch is that `SIGHUP` re-reads the *running process's* environment, which was
captured at spawn — exporting a new `RUST_LOG` in your shell after launch does
**not** change it. So drive it through whatever owns the process's environment.
Under systemd (the common case for a deployed `rvc`/`rvc-signer`):

```ini
# /etc/systemd/system/rvc.service  (rvc-signer is identical bar the ExecStart)
[Service]
Environment=RUST_LOG=info
ExecStart=/usr/local/bin/rvc start --enable-log-reload
ExecReload=/bin/kill -HUP $MAINPID
```

```bash
# … incident: you need BN-selection decisions. Raise just that target to debug
# by updating the unit's environment, reloading systemd, then HUPing the process.
sudo systemctl set-environment RUST_LOG=info,rvc_bn_manager=debug   # or edit Environment=
sudo systemctl kill -s HUP rvc.service          # SIGHUP → reload; rvc_bn_manager now at debug
# (with the ExecReload above, `sudo systemctl reload rvc.service` does the same.)

# … done: drop back to a quiet baseline and reload again.
sudo systemctl set-environment RUST_LOG=info
sudo systemctl kill -s HUP rvc.service
```

For a bare foreground/`&`-backgrounded process (dev/testing), launch it under an
explicit `env` so the value lives in the *process's* environment, and re-launch
to change it — a plain shell-var change after launch is not seen by `SIGHUP`:

```bash
# rvc-signer takes the same flag (console-only output, see §7).
env RUST_LOG=warn rvc-signer serve --enable-log-reload ... &   # then `kill -HUP <pid>`
```

Notes & constraints:

- **Opt-in only.** Without `--enable-log-reload`, `SIGHUP` is **not** intercepted
  for log reload (default process behavior is unchanged). The reload *layer* is
  always present but is free on the default path — a disabled `debug!` still
  allocates nothing at `info` (the P0-6 zero-alloc gate still holds), so leaving
  the flag off costs nothing and turning it on adds no steady-state overhead.
- **You must change the environment the process re-reads** (see the systemd vs.
  bare-process examples above). `SIGHUP` re-reads `RUST_LOG` from the running
  process's environment, captured at spawn; exporting a new value in your *shell*
  after launch does not change it.
- **The §1 compile-time floor still applies.** `trace` requires a debug build; on
  a release binary a reload to `=trace` raises the filter but emits nothing new
  (no `trace!` callsites compiled in). `=debug` works on the release binary you
  already deployed.
- **Unix only.** `SIGHUP` reload is a Unix mechanism; on non-Unix targets the flag
  is accepted but inert (a one-line warning is logged at startup).
- **No new network surface.** Reload is signal-driven; it does **not** open any
  HTTP/admin endpoint (in particular it does not touch rvc-signer's `:9000`).

---

## 3. Canonical fields reference

Every structured field rs-vc emits comes from the **canonical registry** —
`crypto::logging::fields` (`crates/crypto/src/logging.rs:110-149`), the compile-checked
mirror of [`STANDARD.md` §2](./STANDARD.md#2-canonical-structured-field-registry-normative).
**`snake_case`, no `rvc.` prefix, no synonyms** (never `val_idx`, `validator`, `index`).
Correlation ids (`slot` / `epoch` / `validator_index` / `pubkey` / `duty` / `request_id` /
`committee_index`) live **once** on the duty/request span and inherit into every child
event — so you grep one of them and get the whole trace.

| Field | Operator meaning |
|---|---|
| `slot` | The beacon slot the line pertains to. Your primary correlation key. |
| `epoch` | The epoch (duty span). |
| `validator_index` | The validator a duty/sign line is for. |
| `committee_index` | Attestation committee index (matches Lighthouse). |
| `subcommittee_index` | Sync-committee contribution lines only. |
| `pubkey` | Validator public key — **always truncated** `0x{first10}...{last8}`. |
| `duty` | What kind of duty: `attestation` / `block` / `aggregate` / `sync_committee` / `sync_contribution` / `validator_registration` / `voluntary_exit`. |
| `request_id` | UUID correlating one signing / API request end to end, **including the :9000 hop** (§4). |
| `bn_url` | Beacon-node URL — **always redacted** (`***:***@host`, credentials stripped). |
| `head` | Attested head root — truncated `0x{first10hex}...{last8hex}`. |
| `block_root` | Proposed block root — truncated, same form. |
| `time_into_slot` | Nimbus-style timing signal (ms into the slot) on publish / slot-tick lines. |
| `network` | The chain (`mainnet`/`hoodi`/…). A **resource attribute** set once at init — it is **not** a per-event field, so don't grep events for it; in OTLP it is `network.name` on the resource. |

**Redaction is unconditional — even at `trace`** ([`STANDARD.md` §3](./STANDARD.md#3-secret-redaction-policy-normative-p0)):

- **`pubkey` is always truncated** to `0x{first10}...{last8}` (via
  `crypto::logging::TruncatedPubkey`). The full key never appears.
- **`bn_url` and any endpoint are always redacted** — `user:pass@` becomes `***:***@`
  (via `crypto::logging::RedactedUrl`). Raw credentials never appear in a log line.
- **Roots / signatures are truncated** to `0x{first10hex}...{last8hex}` (via
  `TruncatedRoot`); a full signing root or signature is never logged.
- **Secret keys, keystore passwords, mnemonics, full signing payloads** are forbidden at
  every level. If you ever see one, it is a bug — file it against the redaction gates.

So raising verbosity to `debug`/`trace` to chase an issue **never** exposes a key or a
credential. That is a hard P0 invariant, enforced by CI gates
([`STANDARD.md` §7](./STANDARD.md#7-enforcement-the-safety-net)).

> **What's enforced (and what isn't).** Field-name conformance to this registry is a
> **blocking** CI gate (Gate 5, issue 5.2) — but only over a **curated 16-event hot-path
> set** (the attestation/block/sign/duty lines you actually grep), **not** every log line in
> all 23 crates. So a green build guarantees the *covered* hot-path events use the canonical
> spellings above; it is **not** an exhaustive promise that no crate anywhere ever emits a
> stray key. If you spot a non-canonical key on some rarely-hit line, it is a normalization
> gap to file, not a contract violation — the covered set is the enforced floor, widening it
> to full breadth is future work.

---

## 4. Following a `request_id` (end to end, including the :9000 hop)

Every signing / API request to `rvc-signer`'s `:9000` Web3Signer HTTP frontend gets a
`request_id` that follows it from the calling client (Lighthouse / Prysm), through the
signer's handler, onto the audit line. Two mechanisms carry it across the boundary
(`bin/rvc-signer/src/http_api/routes.rs:56-110`):

1. **`x-request-id` header.** If the caller sends an `x-request-id` (bounded: non-empty,
   ≤128 ASCII-graphic chars), the signer **reuses** it as the `request_id`; otherwise it
   mints a fresh UUID v4 (`crypto::logging::new_request_id`). Either way the signer
   **echoes `x-request-id` back** on the response, so the caller can stitch both sides.
2. **W3C `traceparent`.** The handler span is parented from the inbound `traceparent`
   header (`telemetry::set_parent_from_headers`,
   `crates/telemetry/src/propagation.rs:66`) **before** it is entered, so the signer's
   spans join the **same OTLP trace** as the calling client. A missing/malformed
   `traceparent` degrades gracefully to a root span (no panic).

### Grepping the log stream

The `request_id` is a span field on the `sign` span, so it inherits onto the audit line
emitted per request (`bin/rvc-signer/src/audit/log.rs:32` — success at `info`, every
rejection at `warn`). Grep one id to get that request's lines:

```bash
# Pull every line for one request across the signer logs.
grep 'request_id=2f8e1c40-9a7b-4c1e-8d2a-1b3c4d5e6f70' rvc-signer.stdout.log
```

A representative **redacted** success excerpt (pretty format; pubkey truncated, no root /
signature / payload anywhere):

```text
2026-06-25T14:02:11Z  INFO sign{request_id=2f8e1c40-9a7b-4c1e-8d2a-1b3c4d5e6f70 slot=7806432 duty=attestation pubkey=0x93247f2209...611df74a}: rvc_signer_bin::http_api: sign request audit audit=true rpc=sign_attestation result=success backend=basic duration_ms=3 client_cn=lighthouse-vc-1
```

Read it as: span `sign` carries the correlation fields (`request_id`, `slot`, `duty`,
`pubkey` — all inherited); the event is the one-per-request **audit** line carrying only
metadata (`rpc` type, `result`, `backend`, `duration_ms`, peer `client_cn`). A rejection
looks identical but at `WARN` with `result=double_proposal` (or another reason). The
caller (Lighthouse/Prysm) logs the same id because the signer echoed `x-request-id`.

### OTLP-backend equivalent

In your tracing backend (Jaeger / Tempo / Grafana / Cloud Trace) you don't grep — you
**filter by attribute** or open the trace:

- Filter spans by the `request_id` span attribute
  (`request_id = 2f8e1c40-9a7b-4c1e-8d2a-1b3c4d5e6f70`) to find the signer's `sign` span.
- Because of `traceparent` continuity, the caller's span and the signer's `sign` span
  share **one trace id** — open that trace to see both sides of the `:9000` hop as a
  single waterfall. Filter the whole view to one chain with the `network.name` resource
  attribute (§3).

---

## 5. The `info` heartbeat — what healthy looks like

The `info` stream is the **operator liveness signal: milestones only**, low and constant
volume no matter how many validators are loaded. Anything that scales with validator count
or fires per-loop is `debug`/`trace`, never `info`
([`STANDARD.md` §1](./STANDARD.md#1-level-taxonomy-normative)). The Lodestar-style split
applies: **`Signed…` is `debug`, `Published…` is `info`** — so you alert on the
*published* milestones, the proof a duty actually went out.

A healthy `rvc` `info` stream is a recurring narrative
([`STANDARD.md` §6](./STANDARD.md#6-info-heartbeat-shape-normative)):

```text
info  "rvc starting"                {version, network, commit}     ← once, at startup
info  "Loaded validator keys"       {count}                        ← once
info  "connected to beacon node"    {bn_version}                   ← once / on reconnect
info  "epoch processed"             {epoch}                        ← every epoch boundary
info  "published attestation"       {slot, head, committee_index}  ← every assigned slot
info  "block proposed"              {slot, block_root}             ← on a proposer duty
info  (sync-committee msg / contribution)  {slot, subcommittee_index}
info  "validator registration"                                     ← builder registration
info  (optional per-slot tick)      {slot, time_into_slot}
warn  "failover"                    {bn_url}                       ← degraded but progressing
```

**Alert on ABSENCE, not just on errors.** The actionable signals are:

- No `"epoch processed"` for more than one epoch (~6.4 min on mainnet) → the orchestrator
  is stuck.
- An assigned slot with no `"published attestation"` → a missed attestation.
- `"connected to beacon node"` not re-appearing after a `warn "failover"` → no healthy BN.

Recurring `warn "failover"` means the multi-BN layer is degrading-but-progressing — worth
investigating, not yet an outage. `error` means an intended action did **not** complete
(all BNs unreachable; sign rejected by slashing protection; keystore decrypt failed) — page
on it.

To enrich the heartbeat with the per-duty *why* without flooding it, raise just one target
to `debug` (§2), e.g. `RUST_LOG=info,rvc_bn_manager=debug` to see BN-selection decisions
while the rest stays at the milestone level.

---

## 6. Pretty vs JSON output

**Pretty (human-readable) is the default** for both binaries — the `tracing_subscriber`
`fmt` layer renders the colorized, span-scoped lines shown in §4 and §5. This is what you
get on stdout/stderr with no extra configuration, and it is the right choice for
interactive debugging and `grep`. **Leaving the format unset keeps exactly today's
output** — JSON is strictly opt-in.

**JSON is the sanctioned profile for log aggregation** (shipping to Loki / Elasticsearch /
a SIEM, where a structured parser beats a regex). One JSON object per event, with the
canonical correlation fields (§3) flattened to **top-level keys** — so a backend can index
and filter by `request_id`, `slot`, or `validator_index` directly, no regex required.

### Selecting the format

Both binaries take the **same** knob — a `--log-format` flag, or the `RVC_LOG_FORMAT`
environment variable (an explicit flag wins over the env var; an unrecognized value falls
back to `pretty` rather than silencing logs):

| Selector | Value | Effect |
|----------|-------|--------|
| `--log-format <FMT>` | `pretty` (default) \| `json` | Console output format |
| `RVC_LOG_FORMAT` env | `pretty` (default) \| `json` | Same, when the flag is omitted |

```bash
# rvc daemon, structured output for the log shipper:
rvc start --log-format json ...
# rvc-signer, same flag:
rvc-signer serve --log-format json ...
# Or set it once in the environment (e.g. a systemd unit's Environment=):
env RVC_LOG_FORMAT=json rvc start ...
```

**Scope:** the selector governs the **console** stream only. The OTLP trace pipeline (§4),
the trace sampler, and the file appender's own format (§7) are unaffected — a `--logfile`
keeps its pretty on-disk rendering regardless of the console format.

### A sample JSON event

The §4 redacted audit line, emitted under `--log-format json`, is one object per line
(pretty-printed here for readability; on the wire it is a single line). The span's
correlation fields (`request_id`, `slot`, `duty`, `pubkey`) appear under `span`, and the
event's own fields are flattened to the top level:

```json
{
  "timestamp": "2026-06-25T14:02:11.000123Z",
  "level": "INFO",
  "target": "rvc_signer_bin::http_api",
  "message": "sign request audit",
  "audit": true,
  "rpc": "sign_attestation",
  "result": "success",
  "backend": "basic",
  "duration_ms": 3,
  "client_cn": "lighthouse-vc-1",
  "span": {
    "name": "sign",
    "request_id": "2f8e1c40-9a7b-4c1e-8d2a-1b3c4d5e6f70",
    "slot": 7806432,
    "duty": "attestation",
    "pubkey": "0x93247f2209...611df74a"
  }
}
```

Index it by `span.request_id` to follow one request end to end (including the `:9000` hop —
the caller echoes the same id, §4), or by `span.slot` / `validator_index` for per-duty
queries.

**Redaction is identical in both formats.** Secrets are redacted at the **value** level
*before* a field is recorded — a `pubkey` is the truncated `0x{first10}...{last8}` string
(via `TruncatedPubkey`), a beacon URL is credential-stripped (`RedactedUrl`), and roots /
signatures are truncated (`TruncatedRoot`). The JSON profile serializes those
already-redacted values verbatim, so **JSON is not a redaction bypass**: the full 96-char
pubkey, URL credentials, and full roots/signatures never appear in either format (proven by
a captured-subscriber test against the JSON layer in `crates/telemetry`).

---

## 7. File logging more verbose than the console (ADR-004)

A common operator setup: keep the **console at `info`** (clean heartbeat for humans / your
log shipper) while writing a **more verbose `debug` file** to disk for post-incident
forensics. ADR-004 supports this for `rvc`.

**`rvc` (validator client) — supported.** The file appender filters with its **own** level,
independent of the console. Set the file level via `logfile_level` (config) — it defaults to
`log_level` if omitted (`bin/rvc/src/main.rs:936`). Point `logfile` at a path to enable the
appender (`build_file_layer_config`, `bin/rvc/src/main.rs:924`).

```toml
# config.toml — console stays info; the on-disk file captures debug.
log_level      = "info"     # console / RUST_LOG default
logfile        = "/var/log/rvc/rvc.log"
logfile_level  = "debug"    # the file layer's independent level
```

The console keeps its low-volume `info` heartbeat; `/var/log/rvc/rvc.log` carries the
`debug` decision points for when you need them. (`RUST_LOG`, if set, still governs the
console filter per §1.)

**`rvc-signer` (remote signer) — console-only; file == console.** rvc-signer is
intentionally **console-only**: it does **not** wire the file appender, so it has **no
independent file level** — there is nothing to set more verbose than the console
(`bin/rvc-signer/src/main.rs:234-250`). Collect rvc-signer logs from the process's standard
streams (e.g. via your container runtime / `journald`) and set verbosity with `RUST_LOG`
(§2). This is the documented Phase-3 (issue 3.5) status: the appender is *capable* of an
independent file level, but exposing it for the signer is deferred rather than rushed into a
security-sensitive binary. ADR-004's "file more verbose than console" therefore applies to
`rvc`, not `rvc-signer`.

---

## 8. Sampled high-volume lines (1-in-N) — not dropped, sampled

A handful of `trace`/`debug` lines fire **once per validator per slot**. At a few thousand
validators that is thousands of identical lines every 12 s — enough to drown the stream the
moment you raise verbosity to chase an issue. To keep verbose levels usable at scale, the
very highest-volume of these are **sampled 1-in-N**: the line is emitted on the 1st hit and
every N-th hit thereafter, not on every call (issue 5.3,
`crypto::logging::should_log_sampled`).

**This is sampling, not loss.** A sampled line carries `(sampled 1-in-N)` in its message so
you can tell at a glance that the other N−1 occurrences were intentionally suppressed, not
dropped by a bug. The sampler is **behind** the level check, so a sampled line that is *off*
(e.g. `trace` on a release build, or the level not enabled) costs nothing at all — it is the
same zero-overhead-when-disabled guarantee as every other `trace`/`debug` line (§1, Gate 4).

| Line (message) | Crate / level | Rate | Fires |
|---|---|---|---|
| `staging attestation slashing-protection record on blocking thread (sampled 1-in-16)` | `rvc-signer` / `trace` | 1-in-16 | once per attestation **sign** (≈ once per validator per slot) |

Operator consequences:

- **Counts on a sampled line are not validator counts.** If you grep this line you see
  ~1/16th of the attestation signs, by design. Use the per-slot **`info` summary**
  (`"Batch attestation summary" {count}`, §5) or the `RVC_SIGNER_*` metrics for true totals —
  never tally a sampled `trace` line.
- **Sampling never hides a failure.** Only this one healthy, high-volume *progress* trace is
  sampled. Every **rejection / error** on the sign path (slashing-protection block, sign
  failure) is emitted at `warn`/`error` **unsampled** — you see every one.
- **Everything else is unsampled.** Per-duty `debug` decision points, the `info` heartbeat,
  and all `warn`/`error` lines are emitted in full. Only lines explicitly listed in the table
  above are sampled; the list is the complete inventory.

If you genuinely need every occurrence of a sampled line (e.g. reproducing a wire-level issue
on a small validator set), the rate lives next to the call site
(`ATTESTATION_STAGE_TRACE_SAMPLE_N` in `crates/signer/src/lib.rs`) — lower it to `1` and
rebuild a debug binary for that investigation.

---

## 9. Logging roadmap & deferred items

This section keeps every nice-to-have (P2) item — landed, deferred, or backlogged —
**first-class and discoverable**, so nothing is silently dropped. It is the durable
record an operator or a future contributor reads to know exactly **what shipped, what
was consciously parked, and (for the parked items) what it would take to pick them up**.

### 9.1 What is delivered

The required commitment — every must-have (P0) and should-have (P1) item — is **fully
delivered**, and the milestone bar that wraps this work is met (P2 is best-effort):

- **P0-1** — the logging standard, the operator guide (this document), and the **six
  fail-closed CI gates** (§9.4) are in place.
- **P0-2 / P0-3 / P0-4 / P0-6** — secret redaction at the value level (truncated pubkeys
  / roots / signatures, credential-stripped URLs; §3), correlation spans (§4), and the
  zero-allocation-when-disabled guarantee for `debug!`/`trace!` (§1, §8) are enforced.
- **P0-5** — both binaries share **one** filter init through `telemetry::env_filter_or`
  so default level and `RUST_LOG` precedence cannot drift (§1).
- **P1-1 / P1-2 / P1-3** — the breadth pass normalized field keys across the workspace and
  removed the legacy `rvc.` prefix; the `no_rvc_prefixed_keys_outside_allow_lists` grep
  gate keeps it from coming back (§3, §9.4).
- **P1-4** — this **OPERATOR_GUIDE.md**.

Three of the four P2 items also **landed**; the fourth (a workspace-wide conformance lint)
is the one conscious **deferral** (§9.3). The **canonical-field conformance gate (Gate 5)
is now BLOCKING** (§9.4) over the curated hot-path set.

### 9.2 Status of each nice-to-have (P2) item

No P2 item is dropped; each is recorded with its real state:

| Item | Status | What it is / where it lives |
|---|---|---|
| Log-event sampling | **LANDED** | Per-site `crypto::logging::should_log_sampled` (1-in-N **behind** the level check, zero cost when off); the attestation-stage progress trace samples **1-in-16** (`ATTESTATION_STAGE_TRACE_SAMPLE_N`, `crates/signer/src/lib.rs`). Operator semantics in §8. |
| Dynamic level reload | **LANDED** | Opt-in `--enable-log-reload`: `SIGHUP` re-reads `RUST_LOG` and swaps the active filter in place via `tracing_subscriber::reload::Layer`, no restart. Unix-only; no network surface. Operator workflow in §2.1. |
| JSON output profile | **LANDED** | Opt-in `--log-format json` (or `RVC_LOG_FORMAT=json`); **pretty stays the default** so output is unchanged unless you ask. Redaction is identical in both formats. Details in §6. |
| Workspace-wide conformance lint (dylint) | **DEFERRED** | A `dylint` field-name lint over all 23 crates. Conscious "not worth it / here's what it would take" conclusion — see §9.3. |

Two further follow-ups, surfaced during the work and **tracked so they are not lost**:

| Follow-up | Status | Detail |
|---|---|---|
| Truncate the full `pubkey` on the signer's gRPC paths | **BACKLOG** | The initiative truncates pubkeys to `0x{first10}...{last8}` everywhere on the hot path, but two non-hot-path gRPC sites still record the **full** pubkey on their span/event: `bin/rvc-signer/src/service.rs` (the v2 gRPC service, via its local `pubkey_hex`) and `bin/rvc-signer/src/dvt/peer_service.rs`. **Pubkeys are public, so this is not a secret leak** — it is a `STANDARD.md` truncation-conformance gap the hot-path pass did not reach. Fix: route these through `crypto::logging::TruncatedPubkey` like every other site. |
| Phase-init polish hardenings | **BACKLOG** | Three small follow-ups left after the init-consistency work: (a) a `telemetry::DEFAULT_LOG_LEVEL` const as the **single source of truth** for the default level, wired into both bins' defaults and the cross-binary parity-test literals (today the `"info"` default is repeated); (b) an **RAII env-guard** for the `RUST_LOG` test helpers so a panicking test cannot leak process env into a sibling; (c) harden telemetry's own per-module env-filter test off the `rendered.contains(..)` **3-substring** anti-pattern (`crates/telemetry/src/init.rs`) onto a structural assertion. |

### 9.3 Deferral: workspace-wide conformance lint (`dylint`) — DEFER

> **Feasibility conclusion: DEFER.** A `dylint` dataflow lint that flags non-`crypto::logging::fields`
> field names across **all 23 crates** (the P2-4 idea — broader than the curated Gate 5) requires a
> **nightly** toolchain, because `dylint` links `rustc` internals. It therefore **cannot** ride the
> existing **stable** mandatory `check` job; it would need a **separate, non-blocking, allow-failure CI
> lane** carrying its own nightly toolchain, plus an optional `lint/` crate kept **outside** the default
> workspace build. The marginal benefit over what already ships is low: **Gate 5 is now BLOCKING**
> (§9.4) over the curated hot-path set, **`STANDARD.md`** is the author/reviewer rubric, and the
> captured-subscriber conformance tests plus the `no_rvc_prefix` grep gate already enforce the canonical
> field names on that curated surface — and the team **explicitly accepted bounded (curated, not
> exhaustive-breadth) field-name enforcement** as the architectural floor. A documented "not worth it,
> here is what it would take" conclusion **is** the sanctioned, complete outcome for this item.

**What it would take** (so a future team can pick it up without rediscovery):

- An optional `lint/` **dylint** crate that reads emitted field idents and checks them against the
  canonical `crypto::logging::fields` set; keep it **advisory** (a report, not a hard error).
- A **separate nightly, allow-failure CI lane** for it, isolated from the stable `check` job.
- **Hard constraint preserved**: the stable standing invariant (`cargo fmt`, `cargo clippy -D warnings`,
  `cargo nextest`) and the **six existing gates** (§9.4) stay **untouched** — no new *mandatory*
  toolchain, no new blocking dependency on nightly. The lint only ever *adds* an advisory signal.

### 9.4 The six CI gates — present and enforcing

Conformance and redaction are held by **six fail-closed gates** (the safety net in
[`STANDARD.md` §7](./STANDARD.md#7-enforcement-the-safety-net)). All are present and green;
**Gate 5 is now blocking**:

| Gate | Runner | What it enforces |
|---|---|---|
| **Gate 1** | `cargo clippy -D warnings` | `disallowed-methods` bans the path-qualified secret sinks (`expose_secret`, `SecretKey::raw_bytes` / `::to_bytes`) — never the public-key / SSZ `to_bytes` (`clippy.toml`). |
| **Gate 2** | `gitleaks` (CI config) | Scans the source tree **and** an emitted trace-level log sample — 0 findings. Rides CI (`.github/workflows/ci.yml`, `.gitleaks*.toml`); it is an external tool, not a local `cargo` test. |
| **Gate 3** | `cargo nextest` | Captured-subscriber tests: raw secret **absent**, truncated/redacted form **present**, events fire at the intended level with canonical fields. |
| **Gate 4** | `cargo nextest` | Counting-allocator: a disabled `debug!`/`trace!` performs **zero** incremental allocation (`crates/*/tests/zero_alloc.rs`). |
| **Gate 5** | `cargo nextest` | Emitted field keys conform to the canonical registry — **BLOCKING** (`gate5_canonical_field_conformance_blocking`), enforced over a **curated 16-event hot-path set**, not full 23-crate breadth. The `no_rvc_prefixed_keys_outside_allow_lists` grep gate guards the prefix removal. |
| **Gate 6** | `cargo nextest` | The architecture DAG stays acyclic (`architecture_no_cycles`); the one new edge `rvc-signer-bin → rvc-telemetry` is allow-listed. |

The local gates can be confirmed green with the standing invariant
(`cargo nextest run --workspace`); Gate 2 (gitleaks) runs in CI and is not invoked locally.

---

## 10. From a log line to the trace

A `"Missed attestation deadline"` warn (and any other line emitted inside a
sampled span) can be opened as a trace. This section is the pivot, the
span-name inventory, the sample-rate trade-off, the `delay_ms` caveat, and
what a missing `trace_id` means. Span names in this section are unprefixed.

### 10.1 Log to trace pivot

1. Find `trace_id` on a log line that was emitted **inside a sampled span**.
   Pretty output puts `trace_id=<32 hex>` and `span_id=<16 hex>` on the line;
   JSON puts both at the top level (§6). Copy the 32 hex digits.
2. Open that id in the trace backend (Jaeger / Tempo / Grafana / Cloud Trace).
   The local Jaeger from the compose `tracing` profile is
   `http://127.0.0.1:16686`; the flag recipe is in
   [`docs/running-guide.md`](../../docs/running-guide.md) (OTLP/HTTP `:4318`).
3. Read the slot waterfall on service **`rvc`**:
   - `slot.process` — the slot root (`slot`, `epoch`).
   - the three phase children `slot.phase.block`, `slot.phase.attestation`,
     and `slot.phase.aggregation`. Each stamps sub-second `time_into_slot`
     when it fires (TRC-4c; §10.4).
4. Follow the sign hop into **`rvc-signer`**. On `rvc` the client span is
   `sign.grpc_remote_typed` (it injects `traceparent`). In the same trace the
   signer span is `signer.v2.sign_*` with `service.name` **`rvc-signer`**.
   On the signer log that span is `grpc.sign` and the backend name is the
   `otel.name` field (`signer.v2.sign_attestation_data`, and the rest of
   §10.2).

**The two services are `rvc` and `rvc-signer`, and they are distinct
(ADR-007).** They are two processes. The validator client defaults
`service.name` to `rvc` (`SERVICE_NAME` in `crates/telemetry/src/init.rs`).
The signer defaults it to `rvc-signer` (`DEFAULT_SIGNER_SERVICE_NAME` in
`bin/rvc-signer/src/main.rs`) so a shared collector lists two services
instead of folding the remote signer into the VC. One `trace_id` still joins
the hop. `--tracing-service-name` overrides either default; leave it unset
unless you mean to rename a service.

`sign.remote` is the HTTP Web3Signer client span, not this gRPC hop. The
signer's `:9000` handler span stays `sign` (§4).

### 10.2 Span-name inventory

Unprefixed names only. Every name in the tables is a span this tree emits.
`slot.phase.payload_attestation` is the Gloas sibling of the three phases in
§10.1; pre-Gloas it does not stamp `time_into_slot`. The PTC per-slot lookup
is not a span — there is no fifth `duty_tracker` lookup.

| Span | Where it sits |
|---|---|
| `slot.process` | Slot root on `rvc` |
| `epoch.boundary` | Child of `slot.process` on an epoch-boundary slot |
| `slot.phase.block` | Child of `slot.process` |
| `slot.phase.attestation` | Child of `slot.process` |
| `slot.phase.aggregation` | Child of `slot.process` |
| `slot.phase.payload_attestation` | Gloas phase, child of `slot.process` |

`duty_tracker.*`, including the four lookups (`get_duty`,
`get_duties_for_slot`, `get_proposer_duty`, `get_sync_committee_duties`):

| Span | Role |
|---|---|
| `duty_tracker.fetch_attester_duties` | Epoch fetch |
| `duty_tracker.check_attester_reorg` | Epoch reorg check |
| `duty_tracker.fetch_proposer_duties` | Epoch fetch |
| `duty_tracker.check_proposer_reorg` | Epoch reorg check |
| `duty_tracker.fetch_sync_committee_duties` | Epoch fetch |
| `duty_tracker.fetch_ptc_duties` | Epoch fetch (Gloas) |
| `duty_tracker.check_ptc_reorg` | Epoch reorg check (Gloas) |
| `duty_tracker.evict_old_caches` | Epoch cache eviction |
| `duty_tracker.get_duty` | Lookup |
| `duty_tracker.get_duties_for_slot` | Lookup |
| `duty_tracker.get_proposer_duty` | Lookup |
| `duty_tracker.get_sync_committee_duties` | Lookup |

Sign hop. `signer.v2.sign_*` includes `sign_block_header` and `sign_root`
(Gloas). In the backend those are the span names; on the signer log they are
`otel.name` on `grpc.sign`.

| Span |
|---|
| `sign.grpc_remote_typed` |
| `sign.remote` |
| `signer.v2.sign_beacon_block` |
| `signer.v2.sign_blinded_beacon_block` |
| `signer.v2.sign_randao_reveal` |
| `signer.v2.sign_attestation_data` |
| `signer.v2.sign_aggregate_and_proof` |
| `signer.v2.sign_sync_committee_message` |
| `signer.v2.sign_sync_aggregator_selection_data` |
| `signer.v2.sign_contribution_and_proof` |
| `signer.v2.sign_builder_registration` |
| `signer.v2.sign_voluntary_exit` |
| `signer.v2.sign_block_header` |
| `signer.v2.sign_root` |

`signer.dvt.*`:

| Span |
|---|
| `signer.dvt.coordinate` |
| `signer.dvt.partial_sign_beacon_block` |
| `signer.dvt.partial_sign_attestation_data` |
| `signer.dvt.partial_sign_sync_committee` |
| `signer.dvt.partial_sign_payload_attestation` |
| `signer.dvt.partial_sign_block_header` |
| `signer.dvt.partial_sign_root` |

Background loop and tick spans (TRC-6b). The loop root is `parent: None`
(not a child of `slot.process`); the tick `follows_from` that loop. Do not
look for these inside the slot waterfall.

| Loop | Tick |
|---|---|
| `index.resolve` | `index.resolve.tick` |
| `liveness_loop` | `liveness_loop.tick` |
| `monitoring_push` | `monitoring_push.tick` |
| `proposer_config_refresh` | `proposer_config_refresh.tick` |
| `slashing_monitor` | `slashing_monitor.tick` |

`liveness_loop` and `liveness_loop.tick` are `debug` spans. At `info` they
are quiet; that is the level, not a missing trace.

### 10.3 Sample rate

The default is **`0.01`** (`DEFAULT_TRACING_SAMPLE_RATE` in
`crates/rvc-config/src/sections/tracing.rs`, same constant on `rvc-signer`).
Precedence is explicit `--tracing-sample-rate` / config, then
`OTEL_TRACES_SAMPLER_ARG`, then `0.01`.

Startup logs the trade-off once the subscriber is up, whenever the resolved
rate is below `1.0`:

```text
tracing sample_rate is below 1.0; most traces will be dropped
```

At `0.0` the line is `tracing sample_rate is 0.0; exporter receives nothing`.
The default keeps export volume small and drops most traces, so a warn you
care about often has no `trace_id`. That is the head sampler, not a collector
outage.

**`--tracing-sample-rate 1.0` / `OTEL_TRACES_SAMPLER_ARG=1.0` is the
debugging profile.** Set it before the process starts and restart. `SIGHUP`
reloads `RUST_LOG` only (§2.1); it does not change the sample rate.

Sampling is head-based (`ParentBased` + `TraceIdRatioBased` in
`crates/telemetry/src/init.rs`). The decision is made when the trace starts.
**Head sampling cannot keep a dropped trace after the fact** — raising the
rate later does not recover a trace that was already discarded. Collector-side
tail sampling is the named forward path (P2, TRC-7c).

### 10.4 `delay_ms` is ±1000 ms

The `"Missed attestation deadline"` warn's `delay_ms` is **accurate to
±1000 ms**. `SystemSlotClock::current_unix_time`
(`crates/timing/src/clock.rs:171-173`) is
`SystemTime::now()….as_secs()` — whole seconds.
`SlotClock::current_time_secs` (`:197-198`) returns that value.
`phase_deadline` (`crates/rvc/src/orchestrator/coordinator/mod.rs:927-943`)
sources the number at `:930`:

```text
now_ms = self.clock.current_time_secs() * 1000
```

`overrun_ms` is `now_ms - deadline_ms` (`:941`). The warn logs it at `:981`:

```text
warn!(slot, delay_ms = deadline.overrun_ms, "Missed attestation deadline");
```

Because `now_ms` is the start of the current Unix second, the overrun is
coarse by up to one second. **Precision work is out of this initiative.**

Contrast that with sub-second `time_into_slot` on the phase spans (TRC-4c).
`record_time_into_slot` (`coordinator/mod.rs:1001-1006`) stamps milliseconds
from a `tokio::time::Instant` taken once per slot, after `slot.process`
opens. **`delay_ms` and `time_into_slot` are not the same precision.** A
phase span at 3999 ms does not confirm or refute a `delay_ms` that only
moves on whole-second boundaries. The slot clock cannot represent a
sub-second deadline such as 3999 ms; the phase span can.

### 10.5 Absent, not zero

**No `trace_id` does not mean a bug.** It means one of:

- the line is outside a span,
- the line is inside an unsampled span (the head sampler dropped the trace,
  §10.3), or
- there is no OTel layer (no `--tracing-endpoint` and no
  `OTEL_EXPORTER_OTLP_ENDPOINT`, so tracing never started).

The formatter does not substitute a zero id. You will not see
`trace_id=00000000000000000000000000000000` standing in for "missing."
Absence is the signal.

---

## See also

- [`STANDARD.md`](./STANDARD.md) — the normative level taxonomy, canonical field registry,
  redaction policy, and `#[instrument]` idioms (the author/reviewer rubric this guide
  mirrors for operators).
- [`docs/running-guide.md`](../../docs/running-guide.md) — the `--log-level`, `RUST_LOG`,
  and `--tracing-*` CLI flags and example invocations.
