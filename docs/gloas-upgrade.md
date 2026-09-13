# Gloas operator upgrade

What to set before pointing rvc at a Gloas-scheduled network, and what is still
unknown because the live-gated legs have not run.

Linked from [running-guide.md](running-guide.md) (Configuration File). Dispatch
sites and the add-a-fork checklist live in [forks.md](forks.md). The class
inventory is [gloas-fork-hazard-audit.md](gloas-fork-hazard-audit.md).

No fork date is named here. Read `GLOAS_FORK_EPOCH` and every `*_DUE_BPS*` from
the network's own config at run time.

---

## Required config

### `[fork_schedule]` — local Gloas epoch and version

TOML only (`crates/rvc-config/src/sections/fork_schedule.rs`). Unknown keys
under the table fail startup and name the key.

| Key | Role |
|-----|------|
| `gloas_fork_epoch` | Local Gloas activation epoch. Unset and `u64::MAX` (also the decimal string `18446744073709551615`) are unscheduled. |
| `gloas_fork_version` | Local 4-byte version as hex text (`0x` / `0X`). Compared as bytes at startup, not as a string. |

The BN half is `/eth/v1/config/spec` keys `GLOAS_FORK_EPOCH` /
`GLOAS_FORK_VERSION`, parsed by `parse_fork_schedule`
(`crates/beacon/src/types.rs`). A missing BN key uses the unscheduled sentinels
`u64::MAX` / `[0xFF; 4]`. A present but malformed value is a parse error that
names that key.

Startup reconciles the two sources (`crates/rvc/src/startup.rs`
`reconcile_gloas_fork_schedule`, applied from `crates/rvc/src/bootstrap/services.rs`):

- both unscheduled → start
- either scheduled → both sources must supply the same epoch **and** version
- mismatch names `rvc-config` and `/eth/v1/config/spec` plus both epoch and
  version values
- not opt-outable via `--allow-unsupported-fork`

On a Gloas-scheduled network, set the local pair to the same values the BN
advertises. Leaving the table unset while the BN has a real epoch is a
fail-closed mismatch.

```toml
[fork_schedule]
gloas_fork_epoch = 600000
gloas_fork_version = "0x07000000"
```

### `[timing]` — six Gloas `*_DUE_BPS*` keys

TOML only (`crates/rvc-config/src/sections/timing.rs`). Unknown keys under the
table fail startup and name the key. Values are basis points of the slot
duration. Deadline milliseconds are `bps * slot_duration_ms / 10000`.

These six keys are the Gloas set. Copy them from the network config's BN spec
spellings (the four `*_DUE_BPS_GLOAS` keys plus `PAYLOAD_DUE_BPS` /
`PAYLOAD_ATTESTATION_DUE_BPS`). Do not assume the defaults match a given
devnet. Pre-Gloas `ATTESTATION_DUE_BPS` / `AGGREGATE_DUE_BPS` are a different
pair and stay on the pre-Gloas TOML keys.

| TOML key | Default | BN spec spelling | On a 12000 ms slot |
|----------|---------|------------------|--------------------|
| `attestation_due_bps_gloas` | 2500 | `ATTESTATION_DUE_BPS_GLOAS` | 3000 ms |
| `aggregate_due_bps_gloas` | 5000 | `AGGREGATE_DUE_BPS_GLOAS` | 6000 ms |
| `sync_message_due_bps_gloas` | 2500 | `SYNC_MESSAGE_DUE_BPS_GLOAS` | 3000 ms |
| `contribution_due_bps_gloas` | 5000 | `CONTRIBUTION_DUE_BPS_GLOAS` | 6000 ms |
| `payload_due_bps` | 5000 | `PAYLOAD_DUE_BPS` | 6000 ms |
| `payload_attestation_due_bps` | 7500 | `PAYLOAD_ATTESTATION_DUE_BPS` | 9000 ms |

Pre-Gloas `attestation_due_bps` / `aggregate_due_bps` stay 3333 / 6667 (3999 ms
/ 8000 ms on a 12 s slot). Some devnets set `aggregate_due_bps_gloas = 6667`.

Runtime selection is `DeadlineSchedule::for_fork` (`crates/timing/src/clock.rs`):
`>= Gloas` takes the Gloas set, built from these six keys in
`crates/rvc/src/config/builder.rs`. A TOML-only change moves the deadline
without a rebuild.

Phase order is validated at startup: Gloas attestation ≤ aggregate ≤ payload
attestation. A reversal names the offending key.

```toml
[timing]
attestation_due_bps = 3333
aggregate_due_bps = 6667
attestation_due_bps_gloas = 2500
aggregate_due_bps_gloas = 5000
sync_message_due_bps_gloas = 2500
contribution_due_bps_gloas = 5000
payload_due_bps = 5000
payload_attestation_due_bps = 7500
```

---

## `SECONDS_PER_SLOT` → `SLOT_DURATION_MS`

Slot duration is read from the BN `/eth/v1/config/spec` map
(`crates/beacon/src/types.rs` `parse_slot_duration_ms`):

| Spec key | Unit | How rvc uses it |
|----------|------|-----------------|
| `SLOT_DURATION_MS` | milliseconds | used as-is |
| `SECONDS_PER_SLOT` | seconds | converted as `seconds * 1000` |

Exactly one key is sufficient. Both may be present during a deprecation window
and are accepted when they agree exactly (`12` and `12000` is fine; `12` and
`13000` is a parse error naming both keys and both values). Neither key is a
parse error naming both. Extra keys such as `INTERVALS_PER_SLOT` are ignored.

Gloas networks publish `SLOT_DURATION_MS`. A BN that still only ships
`SECONDS_PER_SLOT` keeps working. Do not hard-code 12 s.

`scripts/validator_perf.py` is **not** the same parser. It prefers
`SLOT_DURATION_MS` when that key is present and falls back to
`SECONDS_PER_SLOT` only when ms is absent; it does not require the two keys
to agree. Use rvc's must-agree rule for the validator client, and see
[validator-perf.md](validator-perf.md) for the estimator.

---

## `network = "custom"` devnet fragment

Preset networks (`mainnet`, `hoodi`, `holesky`, `sepolia`) do not schedule
Gloas. A Glamsterdam / Gloas devnet is `network = "custom"` plus genesis
overrides.

`scripts/devnet_preflight.py` emits the genesis fragment after it has
cross-checked the network-config file against every BN `/eth/v1/config/spec`
and `/eth/v1/beacon/genesis`. Paste that fragment, then add `[fork_schedule]`
and `[timing]` from the same network config:

```toml
network = "custom"
genesis_time = 1606824023
genesis_validators_root = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"

[fork_schedule]
gloas_fork_epoch = 600000
gloas_fork_version = "0x07000000"

[timing]
attestation_due_bps_gloas = 2500
aggregate_due_bps_gloas = 5000
sync_message_due_bps_gloas = 2500
contribution_due_bps_gloas = 5000
payload_due_bps = 5000
payload_attestation_due_bps = 7500
```

The numeric values above are placeholders. Substitute the epoch, version, genesis
pair, and the six Gloas deadline keys (`*_DUE_BPS_GLOAS` plus `PAYLOAD_DUE_BPS` /
`PAYLOAD_ATTESTATION_DUE_BPS`) from the network's own
`network-configs/<devnet>/metadata/config.yaml`. Do not copy a number from this
file onto a live net.

---

## Rollback

Issues 7.8, 7.9, and 7.10 were not run in this execution (live-gated; skipped).
There is no rehearsal evidence for a rollback window. Do not treat the
paragraphs below as a completed 7.10 report.

Intended report paths, not yet written (un-backticked so docs-freshness does
not require files that do not exist):

- 7.8 local-keys soak: plan/glamsterdam-2026-09-05/devnet/run-local-keys.md (#327)
- 7.9 remote-signer / DVT soak: plan/glamsterdam-2026-09-05/devnet/run-remote-signer.md (#328)
- 7.10 rollback rehearsal: plan/glamsterdam-2026-09-05/devnet/rollback-rehearsal.md (#329)

Those three stay open blockers until a reachable Glamsterdam devnet exists and
the reports land. Merge this note without them.

### Code-backed behaviour (not rehearsal)

These are startup/signing rules in this tree, not observations from 7.10:

- An unknown head fork version is fatal (exit 13,
  `crates/rvc/src/startup.rs` `EXIT_UNSUPPORTED_FORK_VERSION` /
  `check_fork_compatibility`). A pre-Gloas binary that does not list the
  Gloas version in its known-versions array is designed to refuse a Gloas
  head rather than sign with the wrong domain.
- `--allow-unsupported-fork` is **not** a rollback workaround. It is a
  testnet/experimental opt-out of SEC-9. Using it to keep an old binary
  alive against a Gloas head would skip the fail-closed gate and can
  produce invalid signatures. Two-source Gloas reconciliation is a separate
  gate and has no opt-out.
- This initiative does not change the slashing-DB schema or EIP-3076
  interchange. That is why a same-file open on an older binary is *expected*
  to work; 7.10 has not proven it.

Until 7.10 writes the rehearsal report, no supported rollback window and no
point of no return are claimed. The designed boundary is Gloas activation of
the connected head: before that, a pre-Gloas binary still sees a known fork
version; after that, it is designed to exit 13.

---

## Remote-signer gap

**No minimum remote-signer version is writable.** Consensys Web3Signer has no
Gloas sign types through 26.7.0 (the last version this note is allowed to
name). There is no later Web3Signer release in this document, and none should
be invented.

Consequences:

- Do not point rvc at a third-party Web3Signer for Gloas PTC, proposer
  preferences, builder-request auth, or Gloas block/aggregate duties and
  expect them to sign.
- The in-tree signer is `bin/rvc-signer` (`crates/signer-server`). Gloas
  block, aggregate, and self-build envelope duties run over gRPC. The
  Web3Signer HTTP wire for those Gloas types is deferred; an HTTP signer
  without the types must reject them rather than mis-sign.
- PTC (`PAYLOAD_ATTESTATION`) and proposer preferences may run over either
  transport on `rvc-signer`. That is not a Web3Signer capability claim.
- A signer that lags the Gloas types is a fail-closed rejection (named type /
  version), not a silent fallback. 7.9 was supposed to record that on a live
  DVT cluster; it has not run (see Rollback).

If you need remote signing on a Gloas-scheduled network, run `rvc-signer` at
the same commit as the validator client. There is no third-party version
string to put in a runbook.

---

## See also

- [running-guide.md](running-guide.md) — `[timing]` defaults and CLI
- [forks.md](forks.md) — Gloas dispatch sites and the `Electra..Gloas` EIP-7549 guard
- [gloas-observability.md](gloas-observability.md) — pre-fork alerts and dashboard panels
- [gloas-fork-hazard-audit.md](gloas-fork-hazard-audit.md) — class inventory
- [validator-perf.md](validator-perf.md) — `SLOT_DURATION_MS` in the estimator
- [web3signer-http-api.md](web3signer-http-api.md) — in-tree HTTP signer (not Consensys Web3Signer Gloas support)
