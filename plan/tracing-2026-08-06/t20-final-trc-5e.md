# T20 final — TRC-5e compare against the Phase-1 baseline

Three-run medians at info, with tracing export disabled, compared to
[`latency-baseline.md`](./latency-baseline.md). That file stays the Phase-1
baseline. This note does not replace it and does not change hot-path code.

Method is the baseline file: three independent `cargo bench` processes; the
**median** of criterion's central estimate (middle number on the `time:` line).
Commands are the ones in that file. `RUST_LOG=info`. OTEL exporter and sampler
variables were unset, so no trace exporter was configured. The benches install
their own `no_subscriber` / `subscriber_info` / `subscriber_trace` regimes; the
info regime is the production-shaped one (debug/trace filtered).

| Field | Value |
|---|---|
| **Compare target** | `plan/tracing-2026-08-06/latency-baseline.md` (tip `22aa3de5`, 2026-10-01) |
| **Measured commit** | `8fab00400df79c4f111ec69e8e7cb4d633295710` (develop, post-#484) |
| **Sign-path bench** | `cargo bench -p rvc-signer --bench sign_path` |
| **Per-slot bench** | `cargo bench -p rvc --bench per_slot` (package `rvc`, not `rvc-rvc`) |
| **Host** | Intel Xeon (KVM), model 207, x86_64, 4 cores / 4 threads, ~15 GiB RAM |
| **OS** | Linux 6.12.94+ |
| **rustc** | 1.99.0 (b940084d7 2026-09-28) — same as the baseline |
| **cargo** | 1.99.0 (5f94df478 2026-08-27) — same as the baseline |
| **Measured (UTC)** | 2026-10-03T14:19:47Z – 2026-10-03T14:25:05Z |

## `sign_path` — three central estimates + median

| Regime | Run 1 | Run 2 | Run 3 | **Median** | Phase-1 median | Delta |
|---|---:|---:|---:|---:|---:|---:|
| `sign_path_logging/no_subscriber` | 4.5008 ns | 4.4707 ns | 4.4925 ns | **4.4925 ns** | 4.6755 ns | −3.9% |
| `sign_path_logging/subscriber_info` | 3.9512 ns | 3.9540 ns | 3.9040 ns | **3.9512 ns** | 3.4727 ns | +13.8% |
| `sign_path_logging/subscriber_trace` | 3.1315 µs | 3.1556 µs | 3.1720 µs | **3.1556 µs** | 3.2246 µs | −2.1% |

## `per_slot` — three central estimates + median

| Regime | Run 1 | Run 2 | Run 3 | **Median** | Phase-1 median | Delta |
|---|---:|---:|---:|---:|---:|---:|
| `per_slot_logging/no_subscriber` | 3.7966 ns | 3.7470 ns | 3.7783 ns | **3.7783 ns** | 4.0568 ns | −6.9% |
| `per_slot_logging/subscriber_info` | 3.6863 ns | 3.7383 ns | 3.7480 ns | **3.7383 ns** | 4.1524 ns | −10.0% |
| `per_slot_logging/subscriber_trace` | 2.1269 µs | 2.1278 µs | 2.1315 µs | **2.1278 µs** | 2.3691 µs | −10.2% |

## Noise the baseline file describes

`latency-baseline.md` calls ns-scale numbers noisy, tells later runs to compare
three-run medians, and states the sanity the benches are for:
`subscriber_info ≈ no_subscriber`, `subscriber_trace` about three orders of
magnitude higher, and a **material rise of `subscriber_info` above
`no_subscriber`** as the regression signal. It is a compare target, not a
production gate. It does not publish a numeric percent band.

On this run, same machine class and the same rustc as the baseline:

- `subscriber_info` stays at or below `no_subscriber` (sign path 3.9512 ns vs
  4.4925 ns; per-slot 3.7383 ns vs 3.7783 ns). The baseline itself treats
  3.4727 ns and 4.6755 ns as that same "≈".
- The largest info-median move is +0.48 ns on the sign path (+13.8%). That is
  smaller than the baseline's own info-vs-no_subscriber gap (1.20 ns).
- Trace medians stay ~700× (sign path) and ~560× (per-slot) the no-subscriber
  medians, matching the baseline's ~690× and ~584×.

Those medians are inside the noise that file describes. No hot-path edit was
made to chase them.
