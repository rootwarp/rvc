# A-12 / E3 — `stage.rs` pin re-resolution (ARCH-5e)

**Status:** resolved and **enforced**, 2026-10-01 (TRC-1e / T19).
**Decision:** proceed and **re-pin** to the post-redesign hash (stated default,
architecture phase-5 entry criterion **E3**).

## Pin (authoritative)

| Field | Value |
|---|---|
| **A-12 / T19 pin blob** | `f0f1dc5a8890b223464c9cc85fec719158a6c44c` |
| **Previous blob pin** | `463ff36184a946a0eea0d4d4839a8bc04f74479c` (W4-S1a, #820) |
| **Previous commit pin** | `22aa3de5bf5ed0c03ed571694dc3a5652e460613` (`22aa3de5`) |
| **Role** | Byte baseline of `crates/slashing/src/stage.rs` after W4-S2 (#832) |
| **Why a blob** | Each redesign is one commit. A commit cannot contain its own SHA, so T19 compares `git rev-parse HEAD:crates/slashing/src/stage.rs` to this blob. |
| **Why not `0ae9a09`** | CD-1: `stage.rs` changed under ARCH-5e (and follow-ons). Pinning `0ae9a09` would fail on tip. |
| **CI** | `.github/workflows/ci.yml` job `check`, step **T19 — stage.rs byte-identical to A-12 pin** |

```text
git rev-parse HEAD:crates/slashing/src/stage.rs
```

must equal `f0f1dc5a8890b223464c9cc85fec719158a6c44c` at every merge that retains
the T19 guard. Failure text in CI names **A-12** and points at this file.

## What A-12 was

The tracing initiative (TRC-1e / T19) prospectively pinned
`crates/slashing/src/stage.rs` as **byte-identical to `0ae9a09`**:

```text
git diff 0ae9a09 -- crates/slashing/src/stage.rs
```

must be empty at every tracing merge. That pin was *prospective* (the tracing
tree was not landed as a CI step on `develop` at the time of this resolution)
and exists so tracing instrumentation cannot creep into the slashing critical
section.

## Why it was lifted here

**ARCH-5e** (ADR-005 / ARCH-P1-5) is the **authorized changer** of `stage.rs`.
It adds `reserve_block` / `reserve_attestation` + `CommittedReservation`
**alongside** `stage_*` (A-5.2: `stage_*` is retained, not replaced). This is
not instrumentation; it is the tentative-commit API.

Per `plan/architecture-2026-08-12/issues/05-phase-5.md` entry criterion **E3**:

> Default taken: proceed and re-pin to the post-redesign hash, recorded in
> `plan/tracing-2026-08-06/`. The resolution is written into ARCH-5e's
> description before its first commit.

This file **is** that resolution. The pin is not discovered by a red CI step.

## Re-pin procedure (TRC-1e / T19)

When an authorized `stage.rs` redesign (ARCH-5e class) merges to `develop`:

1. Take `git rev-parse HEAD:crates/slashing/src/stage.rs` of the commit that
   contains the new bytes.
2. Replace the T19 `PIN_BLOB` in this file **and** in
   `.github/workflows/ci.yml`.
3. That `git rev-parse` must equal `PIN_BLOB` on tip.
4. Tracing work must still not instrument `stage.rs`; the pin's *purpose* is
   unchanged.

A commit SHA cannot name itself, so the guard compares blobs. W4-S1a is the
redesign that moved the pin off `22aa3de5`; W4-S2 moved it off `463ff361`.

**Previous pin** `22aa3de5bf5ed0c03ed571694dc3a5652e460613` is the tracing
initiative-start tip (`fix(devnet): cheap k8 metrics empty-body check (#401)`).
At that commit, `stage.rs` reflected the post-ARCH-5e surface.

**Previous blob pin** `463ff36184a946a0eea0d4d4839a8bc04f74479c` is the blob of
`stage.rs` after W4-S1a (#820): out-of-range slots and epochs are refused
before `pinned_gvr`, and every bind goes through `to_sql_i64`.

**Current pin** `f0f1dc5a8890b223464c9cc85fec719158a6c44c` is the blob of
`stage.rs` after W4-S2 (#832): the two `stage_*` rule-check closures became one
`crate::evaluate` call each (the EIP-3076 evaluator shared with group commit).
`BEGIN IMMEDIATE`, the single `ROLLBACK` on `Err` and the guard hand-off are
unchanged. That is not tracing instrumentation. T19 still rejects any other
byte change, including `#[instrument]`.

## What this does *not* authorize

- Deleting `stage_*` (deferred, A-5.2).
- Implementing `reconcile_unsigned` (that is **ARCH-5f**). Shipping `reserve_*`
  without 5f must not become a production caller — that re-opens M-1.
- Weakening C9's cancellation-proof `stage → sign → commit` core. `stage_*`
  and `stage_then_sign` stay.
- Any tracing / OTEL / `#[instrument]` edit inside `stage.rs`. Sanctioned
  "around stage.rs" sites for Phase 1+ live outside this file (see
  `latency-baseline.md`).
