# ARCH-3a — BN `get_block_root(<current slot>)` probe

**Issue:** ARCH-3a (spike) · **Requirement:** ARCH-P0-8 · **Blocks:** 3c  
**Date (UTC):** 2026-08-17T07:20:15Z  
**Tree:** `feature/arch-3a-bn-block-root-probe` @ `4b8abcdf3abd4351856969b8ef5d7753d5dd8346`  
**rustc:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`

## Question

Does a spec-conformant BN answer `404 Block not found` for
`GET /eth/v1/beacon/blocks/{slot}/root` when that slot's block does not yet
exist? If it instead returns a usable 200, ADR-003 is withdrawn and 3c–3f
collapse.

## Method

Spec-conformant **wiremock** BN (beacon-APIs `apis/beacon/blocks/root.yaml`;
lighthouse `WhenSlotSkipped::None` → `custom_not_found`):

| `block_id` | HTTP status | Body |
|---|---|---|
| current slot (`1000`) | **404** | `{"code":404,"message":"NOT_FOUND: beacon block at slot 1000"}` |
| `"head"` | **200** | `{"execution_optimistic":false,"finalized":false,"data":{"root":"0xaaa…aaa"}}` |

Driven through the **real** HTTP path (`BeaconClient` and `BnManager` via
`dyn BeaconNodeClient`), not `MockBeaconNodeClient`. Pin:
`crates/rvc/tests/bn_block_root_contract.rs`.

Capture + sync-committee join (cannot live in `crates/rvc/tests/` — `SlotContext`
is `pub(crate)` and was not widened):
`orchestrator::slot_context::tests::test_capture_yields_no_context_when_bn_404s_current_slot`.

## Observed

| Surface | Result |
|---|---|
| HTTP status | **404** |
| Response body | `{"code":404,"message":"NOT_FOUND: beacon block at slot 1000"}` |
| Client error | `BeaconError::ApiError { status: 404, message: <exact body above> }` |
| Transport rewrite? | **No** — neither `BeaconClient` nor `BnManager` remaps 404 to `HttpError`, a 200, or a different status. |
| `"head"` contrast | **200** with the configured root (mock is not a blanket 404). |
| `SlotContext::capture` | **`head_root = None`** (any `Err` arm, including this 404). |
| Sync-committee messages | **Zero** messages submitted after capture against the 404. |

**Retry policy (not measured as the primary pin):** 404 is not in
`RetryPolicy::is_retryable_status` (only 429 / 5xx). `BnManager` always
constructs per-BN clients with `max_retries=0`. A default-retry
`BeaconClient` (`max_retries=3`) against an `expect(1)` slot-404 mock is
hit once — recorded as policy confirmation, not as the contract pin.

Reproduced by:

```bash
cargo nextest run -p rvc --test bn_block_root_contract
cargo nextest run -p rvc --lib orchestrator::slot_context
```

## Decision

**Proceed with 3c–3f.**

The spec-conformant answer for a not-yet-produced slot block is 404, and
today's `capture` treats that as the normal path (`head_root = None`), which
drops the sync-committee message phase. ADR-003 stands. 3c splits
`parent_root` / `head_root` so a current-slot 404 no longer starves messages.

The capture test documents this defect (green against HEAD). **3c replaces
this pin** with new tests: t=0 `capture_parent` still leaves `head_root`
unset; messages require phase-2 `capture_head`. Do not invert
`head_root.is_none()` after t=0 capture.
