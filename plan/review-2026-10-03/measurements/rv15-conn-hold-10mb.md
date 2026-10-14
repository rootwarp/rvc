# RV-15 10 MB interchange connection hold (RR2-13)

Issue: [#526](https://github.com/rootwarp/rvc/issues/526). Parent: #491 (left open).

Protocol: [`README.md`](./README.md) for median-of-3, host, toolchain, and SHA.
This is not `vc_scale_profile`. The cell is `rvc_slashing_import_conn_hold_ms`
(`std::time::Instant` from `conn.lock()` through `COMMIT`). `clock_mode` is
**wall**. Design input for [#530](https://github.com/rootwarp/rvc/issues/530)
(RR3-01 `per_row_hold`).

Raise this number at standup the day it lands.

## What was measured

One generated EIP-3076 interchange, imported once per run into a fresh on-disk
database opened with `SlashingDb::open` (WAL, `synchronous=EXTRA`, mode
`0o600`). Compact JSON size is **10,026,526 bytes**. Each of 26,737 validators
has one attestation and one block, both with a 32-byte signing root.

| Count | Value |
|---|---:|
| Validators | 26,737 |
| Attestation rows | 26,737 |
| Block rows | 26,737 |
| History rows (attestations + blocks) | 53,474 |
| Raise-only watermark upserts | 80,211 (3 per validator) |
| Uncached `execute` calls on the parent | 133,685 |
| `prepare_cached` statements after this change | 3 |

The parent prepares the attestation insert, the block insert, and the
raise-only watermark upsert on every row. This change parses numeric fields
in `parse_interchange` before `conn.lock()`, then calls `prepare_cached` once
per statement and `execute` per row. `BEGIN IMMEDIATE`, raise-only watermarks,
and all-or-nothing commit are unchanged. No chunked or partial import.

The printer was an ignored test, run three times per tree, then deleted. It
read `rvc_slashing_import_conn_hold_ms` and `rvc_slashing_import_duration_ms`.
It is not in this commit.

## Machine

| Field | Value |
|---|---|
| Host | hostname `cursor`, Linux 6.12.94+ x86_64, Intel(R) Xeon(R) Processor (family 6, model 207, stepping 2), 4 cores, 1 thread per core, MemTotal 16,398,384 kB |
| `uname -a` | `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct  6 05:59:35 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux` |
| Disk | ext4 on `/dev/vdc` (the DB file lived on this filesystem, not tmpfs) |
| rustc | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| cargo | `cargo 1.99.0 (5f94df478 2026-08-27)` |
| nextest | `cargo-nextest 0.9.146 (8af696ddc 2026-09-21)` |
| Profile | `cargo nextest run --release` |
| `clock_mode` | `wall` |
| M-rig | unavailable; this cloud VM is the host |

`git rev-parse HEAD` at process start, both trees: `67d88e7ff5bfa58e57fa120655951c5b5fae034c`.

The before tree is that SHA (uncached `tx.execute`). The after tree is the
`parse_interchange` / `prepare_cached` import in this commit. The processes
ran before this note was committed. Import was not edited between the after
runs and this commit. The temporary printer was removed afterwards.

## Before — uncached prepare, parent `67d88e7f`

Runs at 2026-10-07T13:48:32Z, 13:49:22Z, and 13:49:24Z. All three exited 0.

| Run | `conn_hold_ms` | `duration_ms` |
|---|---:|---:|
| 1 | 1146.166 | 1146.171 |
| 2 | 1225.761 | 1225.767 |
| 3 | 1155.983 | 1155.990 |
| **Median** | **1155.983** | **1155.990** |

On this tree, duration and hold match: numeric parsing sat inside the lock.

## After — `prepare_cached`, this commit

Runs at 2026-10-07T13:53:43Z, 13:53:47Z, and 13:53:49Z. All three exited 0.
One hold sample per import.

| Run | `conn_hold_ms` | `duration_ms` |
|---|---:|---:|
| 1 | 658.322 | 665.893 |
| 2 | 689.438 | 697.397 |
| 3 | 654.892 | 662.903 |
| **Median** | **658.322** | **665.893** |

133,685 uncached prepares are gone. The hold median fell from **1155.983 ms**
to **658.322 ms**. Duration is a few milliseconds above the hold: numeric
parsing now happens before `conn.lock()`.

## RV-15b window and PQ-2

The free window in [#530](https://github.com/rootwarp/rvc/issues/530) is
`[slot_start + 3999 ms + 500 ms, slot_start + 12000 ms − 200 ms)`, length
**7301 ms**. The 10 MB hold median **658.322 ms** fits. PQ-2 does not apply.
No payload cap. `NoFreeWindow` is not introduced. AQ-6 margins are unchanged.

## Budget (RR2-14)

The budget is the after median measured on this host and toolchain. Issue
[#527](https://github.com/rootwarp/rvc/issues/527). Parent #491 stays open.
`conn_hold_for_10mb_import_stays_within_budget` in
`crates/slashing/tests/interchange.rs` is `#[ignore]`d and fails when a real
10 MB import's `conn_hold_ms` exceeds this budget.

| Field | Value |
|---|---|
| Budget | **658.322 ms** `conn_hold_ms` |
| Host | hostname `cursor`, Linux 6.12.94+ x86_64, Intel(R) Xeon(R) Processor (family 6, model 207, stepping 2), 4 cores, 1 thread per core, MemTotal 16,398,384 kB, ext4 on `/dev/vdc` |
| `uname -a` | `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct  6 05:59:35 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux` |
| Toolchain | `rustc 1.99.0 (b940084d7 2026-09-28)`; `cargo 1.99.0 (5f94df478 2026-08-27)` |
| Profile | `cargo nextest run --release`; `clock_mode` **wall** |
| Payload | 10,026,526 bytes; 26,737 validators; 53,474 history rows |

PQ-2 does not apply. **658.322 ms** fits the **7301 ms** window, so this note
does not publish a maximum fitting payload. No payload cap. `NoFreeWindow`
is not introduced.

## RR3-01 input

Use the after median.

| Figure | Value |
|---|---|
| 10 MB `conn_hold_ms` median | **658.322** |
| History rows | 53,474 |
| Hold / history row | 0.012311 ms (12.311 µs) |

This shape pays three watermark upserts for every two history rows. A file
with many attestations on fewer validators would be cheaper per history row.
The measured hold, the row count, and this shape are the inputs. Do not
replace them with a round number.
