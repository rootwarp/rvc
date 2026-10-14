# T20 — latency baseline (TRC-1e / Phase 1)

Recording of the **untouched** tip tree so later tracing phases (Phase 3/4 /
TRC-5e) can judge regressions against a known three-run median. Captured
**before** any instrumentation into the sign / per-slot hot path.

> **This is a baseline, not an acceptance gate.** Later phases compare their
> three-run medians to this file on the same fixtures / commands. It does
> **not** change production source and does **not** instrument `stage.rs`.

Method aligned with
[`../glamsterdam-2026-09-05/measurements/README.md`](../glamsterdam-2026-09-05/measurements/README.md)
(three independent process invocations; record all three plus the **median**
of criterion's central estimate).

Related pin: [`A-12-stage-rs-repin.md`](./A-12-stage-rs-repin.md) (T19).

---

## Harness

| Field | Value |
|---|---|
| **Measured commit (tip)** | `22aa3de5bf5ed0c03ed571694dc3a5652e460613` |
| **Short** | `22aa3de5` |
| **Subject** | `fix(devnet): cheap k8 metrics empty-body check (#401)` |
| **Why tip, not `0ae9a09`** | CD-1 / A-12: `stage.rs` and the surrounding sign path already differ from `0ae9a09`. T20 baselines the initiative-start tip. |
| **Sign-path bench** | `crates/signer/benches/sign_path.rs` (`rvc-signer`) |
| **Per-slot bench** | `crates/rvc/benches/per_slot.rs` (`rvc` — **not** `-p rvc-rvc`) |
| **Profile** | `bench` (criterion / release-optimized) |
| **What these benches measure** | Disabled-able `debug!`/`trace!` logging cost under `no_subscriber` / `subscriber_info` / `subscriber_trace` (issue 2.13 companions). They are **not** end-to-end BLS sign or slot-processing wall times. |

### Exact commands

From the repository root, clean tree at the measured commit:

```bash
cargo bench -p rvc-signer --bench sign_path
cargo bench -p rvc --bench per_slot
```

Three independent process invocations each. Criterion's middle number on the
`time:` line is the central estimate; the **median** of those three is the
baseline column below. Outputs are not checked in (local `/tmp` only).

### Hardware / toolchain (cloud agent VM)

| Field | Value |
|---|---|
| Host | Intel Xeon (KVM), x86_64, 4 cores / 4 threads, ~15 GiB RAM |
| Model | `Intel(R) Xeon(R) Processor` (family 6, model 207) |
| OS | Linux 6.12.94+ (`uname -a`: `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC … x86_64 GNU/Linux`) |
| Hypervisor | KVM |
| rustc | 1.99.0 (b940084d7 2026-09-28) |
| cargo | 1.99.0 (5f94df478 2026-08-27) |
| Measured (UTC) | 2026-10-01T14:02:03Z – 2026-10-01T14:06:10Z |

---

## Results — `sign_path` (three runs + median)

Criterion central estimates (`time:` middle value).

| Regime | Run 1 | Run 2 | Run 3 | **Median** |
|---|---:|---:|---:|---:|
| `sign_path_logging/no_subscriber` | 4.6195 ns | 4.6755 ns | 4.7291 ns | **4.6755 ns** |
| `sign_path_logging/subscriber_info` | 3.4727 ns | 3.5849 ns | 3.4414 ns | **3.4727 ns** |
| `sign_path_logging/subscriber_trace` | 3.2246 µs | 3.2421 µs | 3.2168 µs | **3.2246 µs** |

Sanity (by eye, same as the bench docs): `subscriber_info ≈ no_subscriber`
(filtered / no event fire); `subscriber_trace` is ~three orders of magnitude
higher (events fire + format).

## Results — `per_slot` (three runs + median)

| Regime | Run 1 | Run 2 | Run 3 | **Median** |
|---|---:|---:|---:|---:|
| `per_slot_logging/no_subscriber` | 3.9353 ns | 4.0568 ns | 4.2956 ns | **4.0568 ns** |
| `per_slot_logging/subscriber_info` | 3.8144 ns | 4.1890 ns | 4.1524 ns | **4.1524 ns** |
| `per_slot_logging/subscriber_trace` | 2.1765 µs | 2.3725 µs | 2.3691 µs | **2.3691 µs** |

Same sanity pattern: info ≈ no_subscriber; trace materially higher.

---

## T20 checkpoints / Phase 3 / Phase 4 / TRC-5e protocol

Use this file as the **pre-instrumentation** reference when later tracing work
touches the sign path or per-slot logging surface.

1. **Re-run on the same machine class when possible.** Criterion ns-scale
   numbers are noisy across hosts; compare medians, not single runs, and prefer
   same core count / similar rustc.
2. **Commands stay exactly** `cargo bench -p rvc-signer --bench sign_path` and
   `cargo bench -p rvc --bench per_slot`. Do not substitute load-profile tests
   or swap package names (`rvc`, not `rvc-rvc`).
3. **Three-run median** is the comparison unit (Glamsterdam measurements
   README). Record all three + median in any follow-up measurement note.
4. **Phase 3 / Phase 4:** if those phases add or densify `debug!`/`trace!` on
   the mirrored hot-path statements these benches time, re-run both benches and
   attach a delta note. A material rise in `subscriber_info` vs
   `no_subscriber` is a regression signal (disabled logging must stay cheap).
5. **TRC-5e (and any later "see it in a trace" check):** OTEL / span work must
   not silently inflate these baselines without an explicit recorded re-base.
   Spans-per-slot is a **separate** artifact (`spans-per-slot.md`, TRC-1f /
   #409) — do not conflate it with this logging-cost baseline.
6. **`stage.rs` stays out.** T19 / A-12 keeps `crates/slashing/src/stage.rs`
   byte-identical to the pin. Do not put timing probes inside `stage.rs`.

### Sanctioned "around stage.rs" site (document only — not instrumented here)

Future Phase 1+ work that needs a hook **adjacent** to the slashing critical
section (without editing `stage.rs`) should target:

| Site | Location |
|---|---|
| `SlashableSignSession::reserve_then_sign` | `crates/signer/src/core.rs` ≈ line **517** |

That is the production reserve → sign → commit session entry after ADR-005.
This T20 commit does **not** add spans, timers, or logging there.

---

## Standing invariants (TRC-1e)

- T19 CI step green on tip against A-12 pin `22aa3de5bf5ed0c03ed571694dc3a5652e460613`.
- These benches compile under
  `cargo clippy --locked --workspace --all-targets -- -D warnings`.
- No production edge changes → no `make architecture-doc` required for this
  issue.
