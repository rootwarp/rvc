# RV-15 import during duties, unscheduled (RR2-15)

Issue: [#528](https://github.com/rootwarp/rvc/issues/528). Parent: #491 (left open).

Protocol: [`README.md`](./README.md) for median-of-3, host, toolchain, and SHA.
This is not `vc_scale_profile`. The cell is one 10 MB `import_interchange`
fired at attestation-phase entry on the unscheduled path (no RV-15b gate),
against the N=200 `pipeline_fixture` slot loop. `clock_mode` is **wall**.
Record-only. The 0-miss gate is [#536](https://github.com/rootwarp/rvc/issues/536)
(RR3-07), which calls the same harness.

## Harness signature

`crates/rvc/tests/common/import_during_duties.rs`:

```text
pub async fn run_import_during_duties(
    opts: ImportDuringDutiesOpts,
    admission: impl ImportAdmission,
) -> Result<ImportDuringDutiesRecord, String>
```

`ImportAdmission::admit` is the schedule hook. This note uses
`UnscheduledImport`: `SlashingProtection::import_interchange` runs on Tokio's
blocking pool as soon as the attestation phase records `time_into_slot`.
RR3-07 passes a different `ImportAdmission` that waits on RR3-02's gate.
`ImportDuringDutiesOpts::n200_unscheduled_attestation` is N=200, a 50 ms
mock-BN delay, sync committee and aggregators on, slot 32. The fixture opens
the on-disk `SlashingDb` itself (`N > 1`). The ignored test is
`import_during_duties_records_deadline_misses`.

An attestation-deadline miss is one attestation item whose estimated publish
completion is later than **4,999 ms** into the slot. The deadline is
`due_ms(3333, 12_000)` = **3,999 ms**. The slack is the RR2-03 / RR2-16
publish budget, **1,000 ms**. Estimated completion is the mock
`SubmitAttestation` arrival plus the 50 ms request delay.

`conn_hold_ms` is the delta of `rvc_slashing_import_conn_hold_ms` (one
sample, `conn.lock()` through `COMMIT`). The hold window is that duration
measured back from the import's return. A phase overlaps the hold when its
`[time_into_slot, span close]` interval meets that window. Attestation and
sync message run concurrently; one does not close the other.

The fixture block beacon is still `NoopBlockBeacon` (RR3-06 has not landed).
`block_phase_overlapped` is phase-span overlap, the PQ-7 input available on
this tree. It is not yet a block-reserve interval.

## What was measured

One generated EIP-3076 interchange, same shape as
[`rv15-conn-hold-10mb.md`](./rv15-conn-hold-10mb.md): compact JSON
**10,026,526 bytes**, **26,737** validators, one attestation and one block
each, **53,474** history rows. The metadata genesis root is the pipeline
fixture's `[0xaa; 32]` so the import passes the GVR check and takes `conn`.
That root has the same hex length as the RR2-13 constant, so the byte count
does not move.

The database is the one `pipeline_fixture` opens for N>1: `SlashingDb::open`
(WAL, `synchronous=EXTRA`, mode `0o600`) under a tempfile on this machine's
root filesystem. The import is `SlashingProtectionAdapter::import_interchange`.
No free-window gate.

| Knob | Value |
|---|---|
| N | 200 |
| Slot | 32 (first slot of epoch 1) |
| Mock delay | 50 ms |
| Sync committee / aggregators | on |
| Fire | attestation phase entry |
| Admission | `unscheduled` |

## Machine

| Field | Value |
|---|---|
| Host | hostname `cursor`, Linux 6.12.94+ x86_64, Intel(R) Xeon(R) Processor (family 6, model 207, stepping 2), 4 cores, 1 thread per core, MemTotal 16,398,384 kB |
| `uname -a` | `Linux cursor 6.12.94+ #1 SMP PREEMPT_DYNAMIC Tue Oct  6 05:59:35 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux` |
| Disk | ext4 on `/dev/vdc` (the DB file lived on this filesystem) |
| rustc | `rustc 1.99.0 (b940084d7 2026-09-28)` |
| cargo | `cargo 1.99.0 (5f94df478 2026-08-27)` |
| nextest | `cargo-nextest 0.9.146 (8af696ddc 2026-09-21)` |
| Profile | `cargo test -p rvc --release --test import_during_duties --locked -- --ignored --nocapture --exact import_during_duties_records_deadline_misses` |
| `clock_mode` | `wall` |
| M-rig | unavailable; this cloud VM is the host |

`git rev-parse HEAD` at process start, all three runs:
`1483670fd52f2225d1a8681dc0a4861412571db1`.

The runs executed the harness before this note was added. After the runs,
`phases.iter().any` became `phases.contains` for clippy, and the ignored
test's assertions were tightened. Neither change alters the record.

## Three runs

All three exited 0. One conn-hold sample each. 200 attestation items each.
`block_phase_overlapped` is false each time. `overlapping_phase` is
`attestation+sync_message` each time.

| Run | When | Misses | `conn_hold_ms` | Last publish after 3,999 ms | Hold window (ms into slot) |
|---|---|---:|---:|---:|---|
| 1 | 2026-10-07T15:20:49Z | 105 | 776.989 | 1114.165 | 4074.563–4851.553 |
| 2 | 2026-10-07T15:20:54Z | 0 | 726.726 | 994.638 | 4037.190–4763.917 |
| 3 | 2026-10-07T15:20:59Z | 0 | 680.646 | 993.617 | 4039.730–4720.376 |
| **Median** | | **0** | **726.726** | **994.638** | |

Block `time_into_slot` was **101 ms** on every run. Attestation and sync
message both recorded **3,999 ms** (run 1 recorded **4,000 ms**). The hold
starts about 40–80 ms after that entry: JSON parse is before `conn.lock()`.
The aggregate phase (8,000 ms) had not fired. The hold meets the attestation
phase and the sync-message phase. It does not meet the block phase.

## Record

| Figure | Median |
|---|---|
| Attestation-deadline misses | **0** (runs 105, 0, 0) |
| `rvc_slashing_import_conn_hold_ms` | **726.726** |
| Overlapping phase | **attestation+sync_message** |
| Block phase overlapped | **false** |

Run 1 is the cold database. Its hold, **776.989 ms**, pushed 105 of 200
attestations past 4,999 ms (last publish **1,114.165 ms** after the 3,999 ms
deadline). The two warm runs stayed inside the 1,000 ms slack (last publish
994.638 ms and 993.617 ms) and recorded **0** misses. The median is **0**.
This note does not turn that into a gate.

The idle 10 MB budget in [`rv15-conn-hold-10mb.md`](./rv15-conn-hold-10mb.md)
is **658.322 ms** with no duties on `conn`. This hold is longer because the
import shares the connection with the N=200 attestation group commits. That
is the unscheduled number. It is not a budget failure and it does not publish
a payload cap.

## PQ-7

Late, for a later block reserve, means the import's conn-hold interval meets
a block reserve's wait. On this tree the block phase opened at **101 ms** and
closed before attestation entry. The hold opened just after **3,999 ms**.
Those intervals do not meet. `block_phase_overlapped` is **false**. RR3-06
still has to make a real block reserve observable; RR3-07 compares the
scheduled path against the miss count and this overlap flag.
