# TRC-5a — fixture beacon node (part 1)

Spike for the beacon node `scripts/trace-e2e.sh` needs so `bin/rvc` can reach
at least one attestation duty over a real HTTP transport. This file is the
endpoint list, the method used to derive it, and the confirmed point estimate.
It is not the spans-per-slot measurement deferred in
[`spans-per-slot.md`](./spans-per-slot.md), and it does not start TRC-5b
(signer), TRC-5c, TRC-5d (trace assert), or TRC-5e.

Related: issue #432, parent #431. Root span site:
`crates/rvc/src/orchestrator/coordinator/mod.rs` (`info_span!("slot.process")`).
Duty-path log: `Found attestation duties` in
`crates/rvc/src/orchestrator/attestation.rs`.

---

## Status

| Field | Value |
|---|---|
| **Issue** | #432 (TRC-5a) |
| **Result** | **Confirmed.** Part 1 stands the fixture up and `bin/rvc` reaches one attestation duty. |
| **Points** | **3** (range was 3–4). See [Confirmed estimate](#confirmed-estimate). |
| **Develop tip** | `84b5c5896dd9cc98bd8da427604bbc7f2439c8c2` (unchanged after re-fetch). |
| **A-12 / T19 pin** | Remains `22aa3de5bf5ed0c03ed571694dc3a5652e460613`. `stage.rs` was not edited. |
| **Out of scope** | TRC-5b, TRC-5c, TRC-5d, TRC-5e. No signer process, no OTLP collector, no CI trace assert. |

---

## Confirmed estimate

The ticket was sized **3, range 3–4**, because the route count was unknown
("start from MockBn (~14 routes)"). The spike confirms **3**.

The work is a static JSON server plus a small dynamic shim, not a new beacon
node and not a change to the validator client. `MockBn::mount_endpoints` in
`bin/rvc/tests/common/mock_bn.rs` is 12 mounts. The live client needed three
additions (`/eth/v2/node/version`, attestation data, pool submit) and then
three of the MockBn fixtures were never requested and were deleted. No Rust
production code changed.

---

## Method

1. **Enumerate** `MockBn::mount_endpoints`. That is the in-repo beacon mock
   the client already accepts in tests: genesis, spec, fork schedule, syncing,
   v1 node version, head fork, validators POST and GET, block root, proposer
   duties, attester duties, sync duties.
2. **Add the duty path MockBn does not serve.** Attester duties in MockBn are
   an empty list. Reaching "Found attestation duties" also needs
   `GET /eth/v1/validator/attestation_data` and
   `POST /eth/v2/beacon/pool/attestations`. The client probes
   `GET /eth/v2/node/version` before the v1 fallback (it only calls v1 on 404).
3. **Run** `./scripts/trace-e2e.sh` with Docker and `target/debug/rvc`. The
   fixture logs every request.
4. **Delete** every fixture the client never requested, then re-run. Deleted:
   `GET /eth/v1/config/fork_schedule` (MockBn comment already says the current
   client does not use it), `GET /eth/v1/node/version` (v2 returned 200), and
   `POST /eth/v1/validator/duties/sync/{epoch}` (not requested before the
   part-1 exit at the duty log).
5. **Re-run** the trimmed server. Same evidence: `slot.process` and
   `Found attestation duties`, then a successful submit.

`POST /eth/v1/beacon/states/{state_id}/validators` stays. It is the same
fixture file the client fetched with GET (one key is under the GET threshold).
The POST route is the dynamic shim for the large-key path.

`GET /eth/v1/events` was requested and answered **404**. The slot loop's
head-event wait has a timer arm, so the 404 does not block the attestation
phase. Part 1 does not implement SSE.

---

## Endpoint list

Twelve routes. Eleven JSON files under `scripts/tests/fixtures/`
(`trace_e2e_bn__*.json`); validators GET and POST share one file.
`scripts/trace_e2e_fixture_bn.py` is the shim: path parameters (`state_id`,
block id, epoch) and POST bodies are accepted here, and slot/epoch tokens are
filled from the genesis time the launcher sets.

| # | Method | Path | Fixture | Live part-1 run |
|---|---|---|---|---|
| 1 | GET | `/eth/v1/beacon/genesis` | `trace_e2e_bn__genesis.json` | 200 |
| 2 | GET | `/eth/v1/config/spec` | `trace_e2e_bn__spec.json` | 200 |
| 3 | GET | `/eth/v1/node/syncing` | `trace_e2e_bn__node_syncing.json` | 200 |
| 4 | GET | `/eth/v2/node/version` | `trace_e2e_bn__node_version_v2.json` | 200 |
| 5 | GET | `/eth/v1/beacon/states/{state_id}/fork` | `trace_e2e_bn__state_fork.json` | 200 (`head`) |
| 6 | POST | `/eth/v1/beacon/states/{state_id}/validators` | `trace_e2e_bn__validators.json` | not called (GET used) |
| 7 | GET | `/eth/v1/beacon/states/{state_id}/validators` | same file | 200 (`head`, `id=<pubkey>`) |
| 8 | GET | `/eth/v1/beacon/blocks/{block_id}/root` | `trace_e2e_bn__block_root.json` | 200 (`head` and slot `0`) |
| 9 | GET | `/eth/v1/validator/duties/proposer/{epoch}` | `trace_e2e_bn__duties_proposer.json` | 200 (epoch 0, empty) |
| 10 | POST | `/eth/v1/validator/duties/attester/{epoch}` | `trace_e2e_bn__duties_attester.json` | 200 (one duty) |
| 11 | GET | `/eth/v1/validator/attestation_data` | `trace_e2e_bn__attestation_data.json` | 200 (`slot=0&committee_index=0`) |
| 12 | POST | `/eth/v2/beacon/pool/attestations` | `trace_e2e_bn__pool_attestations.json` | 200 |

### Dropped after the live run

| Method | Path | Why |
|---|---|---|
| GET | `/eth/v1/config/fork_schedule` | Never requested. Fork schedule comes from `/eth/v1/config/spec`. |
| GET | `/eth/v1/node/version` | Never requested. v2 returned 200, so the v1 fallback did not run. |
| POST | `/eth/v1/validator/duties/sync/{epoch}` | Never requested before part 1 exits on the attestation-duty log. |

### Spec the client accepted

Epoch 0 is Electra. Altair through Electra epochs are `"0"` so the reverse
scan in `parse_fork_schedule` selects Electra. Fulu and Gloas epochs are
`18446744073709551615` (unscheduled), which matches the client's default
Gloas reconciliation. Head fork `current_version` is `0x05000000`.
`SECONDS_PER_SLOT` is `"12"` and `SLOT_DURATION_MS` is `"12000"`.

---

## Genesis, slot, and epoch

The script and the fixture share one genesis time.

- `TRACE_E2E_GENESIS_DELAY` (default 20) is added to `date +%s`.
- That integer is written to `config.toml` `genesis_time` and passed to the
  fixture as `TRACE_E2E_GENESIS_TIME`.
- `genesis_validators_root` is the same constant in the config and in
  `GET /eth/v1/beacon/genesis` (chain-swap gate). It is a harness root, not
  mainnet.
- Slot is `(unix_now - genesis_time) / 12`. Before genesis the clock is
  `BeforeGenesis` and the slot loop waits.
- For `POST .../duties/attester/{epoch}`, if the current slot is inside that
  epoch the duty `slot` is the current slot. Otherwise it is `epoch * 32`.
- `attestation_data` echoes the query `slot` and `committee_index`. Target
  epoch is `slot / 32`. Source epoch is the previous epoch, or `0` at epoch 0.

The harness validator is one committed EIP-2335 keystore
(`scripts/tests/fixtures/trace_e2e_validator_keystore.json`, scrypt n=2) whose
pubkey is `trace_e2e_validator_pubkey.txt`. The attester-duty fixture
substitutes that pubkey, so the duty survives the pubkey filter. Doppelganger
detection is off for this harness (`doppelganger_detection = false` and
`--no-doppelganger-detection`) so a fixture that cannot answer liveness does
not drop the duty before the log line.

---

## Evidence (refactor re-run)

`TRACE_E2E_GENESIS_DELAY=12 ./scripts/trace-e2e.sh` exited 0. Fixture log
showed the twelve-route server; the lines below are from `bin/rvc`
(`RUST_LOG=info`, pretty format, OTEL exporter env unset):

```
INFO slot.process{slot=0 epoch=0}:slot.phase.attestation{time_into_slot=4003}: rvc::orchestrator::attestation: Processing attestation duties for slot slot=0
INFO slot.process{slot=0 epoch=0}:slot.phase.attestation{time_into_slot=4003}: rvc_duty_tracker::tracker: Cached duties for epoch epoch=0 duties_count=1
INFO slot.process{slot=0 epoch=0}:slot.phase.attestation{time_into_slot=4003}: rvc::orchestrator::attestation: Found attestation duties slot=0 duty_count=1
INFO slot.process{slot=0 epoch=0}:...: rvc_bn_manager::submit: Attestation submission successful slot=0 count=1 target_epoch=0
INFO slot.process{slot=0 epoch=0}:slot.phase.attestation{time_into_slot=4003}: rvc::orchestrator::attestation: Batch attestation summary slot=0 count=1 target_epoch=0
INFO slot.process{slot=0 epoch=0}:slot.phase.attestation{time_into_slot=4003}: rvc::orchestrator::attestation: Slot processing complete slot=0 total=1 success=1 failed=0
```

`slot.process` is the parent span. `Found attestation duties` with
`duty_count=1` is the duty-path evidence. Submit success is additional, not
required for the part-1 exit.

---

## How to run part 1

Docker and a repo checkout. A local `target/debug/rvc` or `target/release/rvc`
(or `$RVC_BIN`) is used when it exists; otherwise the script builds the
Dockerfile `rvc` target.

```bash
./scripts/trace-e2e.sh
./scripts/trace-e2e.sh --up-only    # fixture ready, then exit
./scripts/trace-e2e.sh --part 2     # exit 1: FAIL part-not-in-scope
```

`set -euo pipefail`. Every wait goes through `wait_until <name> <seconds>`,
which exits `trace-e2e: FAIL <name>: timed out after <seconds>s`.
`TRACE_E2E_RUNTIME=python` runs the same server with host `python3` when a
daemon is not available. Default runtime is Docker (`python:3.12-alpine`).
