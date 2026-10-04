# Phase 7 defers

P2 items that did not land. Recorded here so they are not silently dropped.
GitHub already closed each one `not_planned`. This file does not change code.

Recorded against develop `230ae984f6b2a33cdcce069ace72d6a209f0136e`
(parent `e9bac77ef2d670025e1766bb72fa42661786e04a`).

## Landed

| Issue | Result | Develop |
|---|---|---|
| #448 [TRC-7c] | merged | `e9bac77ef2d670025e1766bb72fa42661786e04a` |
| #449 [TRC-7d] | merged | `230ae984f6b2a33cdcce069ace72d6a209f0136e` |

## #445 [TRC-7a] — not planned

No branch and no commit. Develop at the decision was
`246ffaa4cb6bf376301c667f1d83bc1e4b6b32fd`.

Two real traces were readable, so the "no written opacity list" stop did not
fire: duty `eedccf339dc7f4456e8dd3390bd0b84b` (CI artifact 11276936988) and
`b70a9b3af1a6e37134d371379bf1f7c7` (artifact 11292225947).

The quiet spans were `beacon.http` (`crates/beacon/src/client.rs`),
`signer.v2.sign_attestation_data` (span in signer-server `trace_ctx.rs`, body
in `service.rs`), and `slot.process`. None of them has an existing info-only
Gate 4 body. The only info-only Gate 4 body near `slot.process` is
`disabled_per_slot_logging_is_zero_alloc` in `crates/rvc/tests/zero_alloc.rs`.
That test measures standalone `tracing::debug!` lines. It never enters
`slot.process`. The module docs leave `slot.process` and `slot.phase.*`
outside that region on purpose. The plan allows cases inside the existing
body, not a second test and not a new harness.

What it would take: an existing info-only Gate 4 body that already runs inside
one of those spans. This tree does not have one. Adding a call path is a
different issue.

Comment: https://github.com/rootwarp/rvc/issues/445#issuecomment-5976380932

## #446 [TRC-7b1] — deferred

No helper, no exposition change, no `server.rs` edit, no branch, no commit.
Same develop tip as #445.

The exporter cannot emit exemplars. `prometheus` is locked at 0.14.0
(`Cargo.toml` version `"0.14"`, default-features false). The protobuf feature
is off, so `ProtobufEncoder` is not compiled. There is no exemplar feature and
no OpenMetrics. The only encoder is `prometheus::TextEncoder`,
`text/plain; version=0.0.4`:

- `crates/metrics/src/server.rs:113-120`
- `crates/signer-server/src/metrics.rs:264-268` (`SignerMetrics::encode`)
- `crates/signer-server/src/metrics.rs:375-377` (scrape Content-Type)

`Histogram::observe` only bumps bucket, sum, and count. The 0.14 proto Bucket
is `cumulative_count` and `upper_bound` only. Switching the scrape to
OpenMetrics is an exposition-format change and was out of scope.

What it would take: an OpenMetrics exposition path. That is a separate
decision.

Comment: https://github.com/rootwarp/rvc/issues/446#issuecomment-5976427490

## #447 [TRC-7b2] — deferred with #446

No branch and no commit. There is no plumbing to attach exemplars, so latency
histograms and a dashboard pivot cannot start.

What it would take: the same OpenMetrics path as #446. This issue does not
start before that exists.

Comment: https://github.com/rootwarp/rvc/issues/447#issuecomment-5976427538
