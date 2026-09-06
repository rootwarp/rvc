# Gloas fork-addition hazard audit

Issue 2.2 / #216. Every site whose behaviour can change when a `ForkName` arm is
appended, classified before `ForkName::Gloas` lands.

The CI twin is `crates/architecture-tests/tests/fork_hazard_inventory.rs`. That
scan walks `crates/**` and `bin/**` (not `plan/` or `docs/`), skips its own
source, and fails on any hit missing from the inventory below — or on a count
mismatch. Adding a site means adding a row here **and** in the scanner
inventory, with one of the four verdicts. There is no `unclassified`.

Line numbers were opened on `feature/216-fork-hazard-audit` after 2.1
(`ForkName::COUNT`). Put `file:line` *outside* backticks —
`crates/architecture-tests/tests/docs_freshness.rs` treats a colon inside
`` `…` `` as a path token.

## Classes

| # | Pattern | Why it is a fork-addition hazard |
|---|---------|----------------------------------|
| 1 | `>= ForkName::X` | Open-ended ordering: a new last variant inherits the branch. |
| 2 | `.index = 0` / `.index = "0"` | EIP-7549 zeroing assignments driven by class-1 guards. |
| 3 | `match` on `ForkName` | Exhaustive → compile error (desired). `_ =>` → silent. |
| 4 | String-literal fork dispatch | `consensus_version` / `Eth-Consensus-Version` strings, including `_ =>`. |
| 5 | `.entries()` call sites | Greppable proxy for version → `ForkName` reverse lookup. |

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `inherit-intentionally` | Open-ended / table-driven behaviour is correct after a new arm. |
| `must-bound` | A new arm would silently extend the behaviour; bound before Gloas. |
| `decided-not-inherited` | Gloas must not take this path; a later phase owns the arm. |
| `test-only` | Test mirror; not production behaviour. |

## Counts

| Class | Count |
|-------|------:|
| 1 `>= ForkName::X` | 8 |
| 2 `.index = 0` | 6 |
| 3 `match ForkName` | 3 |
| 4 string-literal dispatch | 4 |
| 5 `.entries()` | 7 |
| **Total** | **28** |

Kind `exhaustive` / `_` applies to classes 3 and 4. Other classes use `—`.

<!-- BEGIN INVENTORY -->
| Site | Class | Kind | Verdict | Rationale | Issue |
|---|---|---|---|---|---|
| `bin/rvc-keygen/src/exit.rs` 107 | 1 | — | inherit-intentionally | Test re-implements the EIP-7044 Capella cap. Open-ended `>= Capella` is correct. Production definition is `signing_root.rs` 237. | — |
| `crates/beacon/src/client.rs` 398 | 1 | — | inherit-intentionally | Proposer-duties v1/v2 routing (4.5). Open-ended `>= Gloas` keeps later forks on v2 rather than silently falling back to deprecated v1. | 4.5 |
| `crates/crypto/src/signing_root.rs` 237 | 1 | — | inherit-intentionally | EIP-7044: voluntary-exit domain stays Capella-capped however many post-Capella forks exist. Open-ended `>=` is the spec. | — |
| `crates/crypto/src/signing_root.rs` 299 | 1 | — | inherit-intentionally | Test mirror of 237 (`legacy_voluntary_exit_root`). Same Capella-cap inherit. | — |
| `crates/rvc/src/orchestrator/aggregation.rs` 88 | 1 | — | decided-not-inherited | `>= Fulu` picks the `"fulu"` submit label. Gloas must not inherit; Phase 6 owns the versioned-wrapper choice. One of three production `>= Fulu` sites (plan cited four). | phase-6 |
| `crates/rvc/src/orchestrator/aggregation.rs` 130 | 1 | — | decided-not-inherited | `>= Fulu` selects `VersionedSignedAggregateAndProof::Fulu`. Same Phase-6 verdict as 88. | phase-6 |
| `crates/rvc/src/orchestrator/attestation.rs` 425 | 1 | — | decided-not-inherited | `>= Fulu` selects `VersionedAttestation::Fulu`. Phase 6; do not inherit via open-ended `>=`. | phase-6 |
| `crates/rvc/src/orchestrator/utils.rs` 144 | 1 | — | inherit-intentionally | `uses_electra_attestation_wire`: open-ended `>= Electra` so Gloas (and later forks) keep the Electra+ wire. Index zeroing is the separate `zeroes_committee_index` (`Electra..Gloas`). | 2.8 |
| `crates/rvc/src/orchestrator/attestation.rs` 417 | 2 | — | must-bound | Submission-path `SingleAttestation.data.index = "0"` inside `zeroes_committee_index`, not the Electra+ wrapper branch, so Gloas preserves the BN value. | 2.8 |
| `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs` 513 | 2 | — | test-only | Test applies `index = 0` when local `is_electra`. Follows 2.3 helper. | 2.3 |
| `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs` 636 | 2 | — | test-only | Pre-Electra path does not assign; the `if is_electra` still contains the assignment. 2.3. | 2.3 |
| `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs` 665 | 2 | — | test-only | Signing-root fixture zeros index by hand. Not a production guard. | 2.3 |
| `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs` 673 | 2 | — | test-only | Reconstructs submitted `index = "0"` to compare roots. Mirrors attestation.rs 417. | 2.8 |
| `crates/rvc/src/orchestrator/utils.rs` 163 | 2 | — | must-bound | The assignment gated by `zeroes_committee_index`. Bound together with the half-open `Electra..Gloas` predicate (2.3 / 2.8). | 2.3 |
| `bin/rvc/tests/common/mock_bn.rs` 268 | 3 | exhaustive | test-only | `match fork` → version hex. Compile error on a new variant. 2.5b/2.6 add Gloas `0x07000000`. | 2.5b |
| `crates/eth-types/src/fork.rs` 178 | 3 | exhaustive | inherit-intentionally | `ForkName::id` exhaustive `match self` with no `_ =>`. Deliberate fork-addition tripwire (2.1). 2.5b adds the Gloas arm. | 2.5b |
| `crates/eth-types/src/fork.rs` 196 | 3 | exhaustive | inherit-intentionally | `body_layout()` exhaustive match. 2.7 adds `Gloas => Some(BodyForkLayout::Gloas)`. | 2.7 |
| `crates/block-service/src/service/mod.rs` 581 | 4 | _ | decided-not-inherited | `ssz_block_format`: unblinded deneb/electra/fulu → `BlockContents`; `_ => BeaconBlock` silently skips the KZG bind. `"gloas"` would fall through. 2.7 leaves this untouched; Phase 6. | phase-6 |
| `crates/block-service/src/service/tests/mocks.rs` 520 | 4 | _ | test-only | Test body SSZ picker. Wildcard `_ =>` Deneb body. Mirrors production string dispatch. | — |
| `crates/block-service/src/service/tests/mocks.rs` 534 | 4 | _ | test-only | Blinded-body twin of 520. | — |
| `crates/block-service/src/service/tests/mocks.rs` 627 | 4 | exhaustive | test-only | `matches!` on deneb/electra/fulu for `BlockContents` bytes. Closed string set; `"gloas"` is false. | — |
| `crates/crypto/src/typed_signer.rs` 58 | 5 | — | must-bound | `SignContext::resolve` first-matches `fork_info.current_version` over `entries()`. Two `[0xFF;4]` rows (unscheduled Fulu+Gloas after 2.6) resolve Fulu, so `Gloas.fork_version()` does not round-trip. 2.6 pins the collision; 2.10 confines it to both-unscheduled. | 2.6 |
| `crates/eth-types/src/fork.rs` 210 | 5 | — | inherit-intentionally | `from_epoch` reverse-scans `entries()`; a new row is picked up automatically. Equal activation epochs pick the latest fork. | 2.5b |
| `crates/eth-types/src/fork.rs` 220 | 5 | — | inherit-intentionally | `fork_version` lookup through `entries()`. New row participates by construction. | 2.5b |
| `crates/eth-types/src/fork.rs` 229 | 5 | — | inherit-intentionally | `activation_epoch` lookup through `entries()`. Same inherit. | 2.5b |
| `crates/eth-types/src/fork.rs` 613 | 5 | — | test-only | Eight-ness assert `entries().len() == 8`. 2.5b rewrite of the former seven-ness table. | 2.5b |
| `crates/eth-types/src/fork.rs` 630 | 5 | — | test-only | 2.1 uniqueness test (`entries().len() == COUNT`). Sixth class-5 site; plan listed five against the pre-2.1 tree. | 2.1 |
| `crates/rvc-spec-vectors/src/bin/gen_spec_kat.rs` 1355 | 5 | — | test-only | tar `Archive::entries()`; not `ForkSchedule`. 4.0 generator, not a fork-addition hazard. | — |
<!-- END INVENTORY -->

## Notes

- **2.3 / 2.8 split EIP-7549 zeroing from Electra+ wire.** Zeroing is
  `zeroes_committee_index` (`Electra..Gloas`). Wire shape is
  `uses_electra_attestation_wire` (`>= Electra`, inherit-intentionally) so
  Gloas keeps `SingleAttestation` / committee-index query / Electra aggregate
  while preserving BN `data.index`. Class-2 assignments stay on the zeroing
  predicate.
- **Three, not four, `>= ForkName::Fulu` production sites.** The project plan
  cited four. The tree has `attestation.rs` 423, `aggregation.rs` 88,
  `aggregation.rs` 130. Recorded, not padded.
- **Class 5 grew by one in 2.1.** Plan-verified five: `typed_signer.rs` 58,
  `fork.rs` from_epoch / fork_version / activation_epoch, and the seven-ness
  test. 2.1 added `test_entries_contains_each_all_variant_exactly_once`
  (`fork.rs` 630). The 2.9 sentinel pin is the `u64::MAX - 1` stays-Fulu row
  in `test_from_epoch_table_matches_legacy_if_else_for_every_boundary`.
- **Not a class-3 `match ForkName`.** `crates/grpc-signer/src/client.rs` 761
  `test_mainnet_fork_ids_unchanged_for_all_eight_versions` is a test table of
  all variants, not a `match`. Adding Gloas is a 2.5b rewrite, not a compile
  error. The historical `_ => Deneb` silent default is gone (RF3-08).
- **`validate_fork_id`** (`crates/eth-types/src/ssz_helpers.rs` 315) is
  **not** one of the five scan classes. 2.4 replaced `ForkName::try_from`
  with an explicit `0..=6` decoder allowlist so id 7 cannot ride in on the
  Gloas arm. 2.9 re-pins that accept set with Gloas present.
- **Two-source fork schedule (D12).** No `/eth/v1/config/fork_schedule` client
  method exists. `crates/beacon/src/client.rs` 353–359 exposes
  `get_config_spec()` (`/eth/v1/config/spec`) and `get_fork_schedule()`, which
  derives the schedule from that spec. 2.6 parses Gloas epoch/version from the
  spec; 2.10 reconciles that BN-derived schedule against a local `rvc-config`
  pair (conditional fail-closed). The class-5 sentinel collision can persist
  only while Gloas is unscheduled on **both** sources.
- **Self-exclusion.** The scanner skips
  `crates/architecture-tests/tests/fork_hazard_inventory.rs` because its
  inventory literals contain the `>= ForkName::` snippets it searches for.
- **4.5 proposer-duties v2.** Class 1 grew by one (`client.rs` 398):
  `>= ForkName::Gloas` selects `/eth/v2/validator/duties/proposer/{epoch}`.
  Inherit-intentionally — a later fork must stay on v2, not fall back to
  deprecated v1. `ForkSchedule::unscheduled_gloas` shifted the `fork.rs`
  class-3/5 line numbers.

## Post-arm verdicts (issue 2.9)

After 2.5b–2.10, with Gloas configured at `u64::MAX`:

- **`from_epoch` reverse scan (class 5, inherit-intentionally).** Every
  realistic epoch resolves to Fulu or earlier. At exactly `u64::MAX` the
  reverse scan returns Gloas — intended, because the sentinel *is* Gloas's
  activation epoch, so `activation <= epoch` holds for every row and the
  latest wins. No consensus slot has `epoch == u64::MAX`. Pinned in
  `fork.rs` `test_from_epoch_table_matches_legacy_if_else_for_every_boundary`.
- **Class-5 reverse-lookup (2.6).** `SignContext::resolve` first-matches on
  version. Two `[0xFF;4]` rows (unscheduled Fulu+Gloas) resolve Fulu, so
  `Gloas.fork_version()` does not round-trip through that sentinel.
  A real `0x07000000` round-trips to Gloas. 2.10's two-source rule confines
  the collision to the fully-unscheduled case. Verdict stays `must-bound`.
- **Zeroing vs wire (2.8).** `zeroes_committee_index` is `Electra..Gloas`
  (Fulu zeros; Gloas preserves). `uses_electra_attestation_wire` is
  `>= Electra` (Gloas keeps the Electra+ wire). At the sentinel, realistic
  epochs are Fulu, so both predicates match pre-Gloas behaviour.
- **`validate_fork_id`.** Allowlist stays `{0,1,2,3,4,5,6}`. Id 7 is
  `Ok(Gloas)` on `ForkName::try_from` and `UnknownForkId(7)` on decode.
  Phase 4 owns the Gloas gRPC contract.
- **EIP-7044.** `capella_capped_fork_version` and `exit_fork_schedule`
  still Capella-cap. An exit at epoch 1_000_000 signs under Capella with
  Gloas in the schedule at `u64::MAX`.
- **Signing roots.** Attestation, block, aggregate, and voluntary-exit
  KATs in `crates/crypto/tests/signing_root_kat.rs` stay byte-identical
  with Gloas at the sentinel. Full L5 suite is issue 6.13.
