# Gloas fork-addition hazard audit

Issue 2.2 / #216. Every site whose behaviour can change when a `ForkName` arm is
appended, classified before `ForkName::Gloas` lands.

The CI twin is `crates/architecture-tests/tests/fork_hazard_inventory.rs`. That
scan walks `crates/**` and `bin/**` (not `plan/` or `docs/`), skips its own
source, and fails on any hit missing from the inventory below — or on a count
mismatch. Adding a site means adding a row here **and** in the scanner
inventory, with one of the four verdicts. There is no `unclassified`.

Each site cell is three backtick spans: workspace path, qualified item
(`enclosing_item`), and the normalised source line (trim, ASCII whitespace
collapsed to one space). A span that itself contains a backtick uses a
longer fence. `docs_freshness.rs` treats a colon inside `` `…` `` as a path
token, so the path span is only the path.

## Classes

| # | Pattern | Why it is a fork-addition hazard |
|---|---------|----------------------------------|
| 1 | `>= ForkName::X` | Open-ended ordering: a new last variant inherits the branch. |
| 2 | `.index = 0` / `.index = "0"` | EIP-7549 zeroing assignments driven by class-1 guards. |
| 3 | `match` on `ForkName` | Exhaustive → compile error (desired). A catch-all arm → silent. |
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
| 1 `>= ForkName::X` | 28 |
| 2 `.index = 0` | 8 |
| 3 `match ForkName` | 10 |
| 4 string-literal dispatch | 11 |
| 5 `.entries()` | 9 |
| **Total** | **66** |

Kind `exhaustive` / `_` applies to classes 3 and 4. Other classes use `—`.

Kind `_` marks a catch-all arm with no guard. `syn` parses each `match` and
`matches!` site, so the parser decides the scrutinee, the arms, the patterns
and the guards. A catch-all is `_`, `..`, a binding (`other =>`,
`x @ _ =>`, `ref other =>`, `mut other =>`), `&p`, a pattern macro, or a
tuple, slice or group of catch-alls. A tuple-struct or struct pattern
(`Ok(got) =>`, `S { .. } =>`, `Wrap::<T>(x) =>`) is a catch-all if all its
fields are catch-alls. For `Ok`, `Err`, `Some` and `None` (last path
segment), one more condition applies: another arm, another or-case of the
same arm, or an or-pattern in its own fields uses the same wrapper. Thus
`Ok(got)` after `Ok(ForkName::Fulu)` is a catch-all, but `Err(_)` next to
`Ok(…)` arms is not. An or-pattern is a catch-all if one of its cases is a
catch-all. Every single identifier except `None` is a binding. This
includes a bare variant name such as `Phase0 =>`, because source must not
import the `ForkName` variants. A site that syn does not parse gives a
failing hit (fail closed).

Class 3 counts an arm pattern or guard with a `ForkName` path segment that
another segment follows (`ForkName::X`, `crate::ForkName::X`,
`<ForkName>::X`, `r#ForkName::X`). In a file that has a `ForkName` token in
code, an arm pattern with a `Self::X` path (`<Self>::X`, `<(Self)>::X` and
`<Self as Tr>::X` too) also counts when `X` is a `ForkName` variant name. The
test reads the variant names from `pub enum ForkName` in
`crates/eth-types/src/fork.rs` with syn, so a new fork is picked up. In a file
that names `ForkName`, a match whose arms are only bare names, one-segment
paths, macros or `_` also counts. No source file may alias `ForkName`,
rename it, import its variants, or declare a `const`, `static` or
associated const whose type names `ForkName`. In an impl whose self type
names `ForkName`, in a trait, and in a macro body, a `Self` type of a const
counts as `ForkName` (outside a macro body, an array length does not), so
`const LAST: Self` and `trait Tr { const X: Self; }` fail the gate. In a
macro body, a `const` or `static` whose type has a `$` metavariable also
fails the gate. The gate test
`source_has_no_fork_name_alias_or_variant_import` scans every Rust file,
tests included, with syn and with a token check of `use`, `type`, `const`
and `static` items, macro bodies included. The only exemptions are in
`impl ForkName` in `crates/eth-types/src/fork.rs`: the variant list
`const ALL: [Self; 8]` and the name table
`const NAMES: [(ForkName, &str, u32); Self::COUNT]`. Each exemption is
anchored on its type text and must occur exactly once.

### Known limits

These shapes are not in any class. Each deferred item is tracked in a
follow-up issue.

- An equality or pattern test outside a `match`: `if fork == ForkName::Gloas`,
  `if let`, `let … else`, and `fork as u8`.
- Files outside `crates/` and `bin/` that `include!` or `#[path]` loads.
- Class 3 fingerprint is only the `match` line, not an arm-pattern digest.
  Tracked in a follow-up issue.
- A `macro_rules!` that builds a `match` from `$` tokens in a file that does
  not name `ForkName`. Tracked in a follow-up issue.
- Class 1 misses `>= crate::ForkName::Gloas`, `>= <ForkName>::Gloas`,
  `ForkName::Gloas <= fork` and `> ForkName::Fulu`. Tracked in a follow-up issue.
- `matches!(fork, ForkName::Gloas)` gives no class 3 hit, and a renamed
  `matches!` (`use core::matches as m`) is not a site. Tracked in a follow-up
  issue.
- Class 4 reads only the `match` body, so `match s == "gloas" {…}` is not a
  hit. Tracked in a follow-up issue.
- The alias gate does not see a `ForkName` that a macro metavariable carries
  into a `use` or `type` item, or a macro-built type. Tracked in #816.
- The alias gate does not see `lazy_static! { static ref … }`. Tracked in #816.
- The alias gate does not read generic defaults on struct, enum or trait
  items. Tracked in #816.
- The alias gate does not see a const value that wraps `ForkName`
  (`W(ForkName::Gloas)`). Tracked in #816.
- Class 3 does not see `ForkName` through a generic alias
  (`pub type Id<T> = T;` with `Id::<ForkName>::Gloas` or
  `<Id<ForkName>>::Gloas`). Tracked in #816.
- A renamed wrapper (`use Result::Ok as Good`) does not count as a sibling
  of `Ok`. Tracked in #816.
- A catch-all that is split across arms by a second tuple element is not
  seen. Tracked in #816.

<!-- BEGIN INVENTORY -->
| Site | Class | Kind | Verdict | Rationale | Issue |
|---|---|---|---|---|---|
| `bin/rvc-keygen/src/exit.rs` `tests::test_exit_round_trip_encrypt_decrypt_sign` `let capped = if fork_name >= ForkName::Capella { ForkName::Capella } else { fork_name };` | 1 | — | inherit-intentionally | Test re-implements the EIP-7044 Capella cap. Open-ended `>= Capella` is correct. Production definition is `signing_root.rs` 301. | — |
| `crates/beacon/src/client.rs` `BeaconClient::proposer_duties_path` `if ForkName::from_epoch(epoch, schedule) >= ForkName::Gloas { "v2" } else { "v1" };` | 1 | — | inherit-intentionally | Proposer-duties v1/v2 routing (4.5). Open-ended `>= Gloas` keeps later forks on v2 rather than silently falling back to deprecated v1. | 4.5 |
| `crates/beacon/src/prepare_check.rs` `compute_preparable` `&& (slot_fork >= ForkName::Gloas || response.consensus_version == "gloas")` | 1 | — | inherit-intentionally | Blinded prepare fails closed at `>= Gloas` or consensus version `gloas`. A later fork stays a blinded drop on this pre-Gloas path. | — |
| `crates/beacon/src/prepare_check.rs` `compute_preparable` `Ok(_) if slot_fork >= ForkName::Gloas => {` | 1 | — | inherit-intentionally | An unblinded Gloas or later slot on this pre-Gloas predicate is a parse rejection, so it is not signed through `check_preparable`. V4 does not call this function. | — |
| `crates/block-service/src/service/mod.rs` `BlockService<S, B>::propose_block_impl` `let produce_result = if fork >= ForkName::Gloas {` | 1 | — | inherit-intentionally | Produce dispatch: open-ended `>= Gloas` stays on V4 so a later fork does not fall back to V3. | — |
| `crates/block-service/src/service/mod.rs` `BlockService<S, B>::propose_block_impl` `let signed = if fork >= ForkName::Gloas {` | 1 | — | inherit-intentionally | Sign/publish dispatch: open-ended `>= Gloas` stays on `sign_and_publish_v4`. | — |
| `crates/block-service/src/service/mod.rs` `record_produced_response` `if slot_fork >= ForkName::Gloas {` | 1 | — | inherit-intentionally | Response log omits the pre-Gloas blinded field once `>= Gloas`. Later forks keep that shape. | — |
| `crates/block-service/src/service/mod.rs` `reject_blinded_at_gloas` `if slot_fork >= ForkName::Gloas || consensus_version == "gloas" {` | 1 | — | inherit-intentionally | `reject_blinded_at_gloas`: blinded production is pre-Gloas only. Open-ended `>= Gloas` or consensus version `gloas` drops the duty so a later fork keeps the no-blinded gate. | — |
| `crates/block-service/src/service/mod.rs` `reject_gloas_version_pre_gloas` `if got >= ForkName::Gloas {` | 1 | — | inherit-intentionally | A pre-Gloas slot whose consensus version parses as `>= Gloas` returns `ConsensusVersionMismatch` and is not hashed as Electra or Deneb. | — |
| `crates/block-service/src/service/mod.rs` `reject_gloas_version_pre_gloas` `if slot_fork >= ForkName::Gloas {` | 1 | — | inherit-intentionally | Early return in `reject_gloas_version_pre_gloas`: a slot already `>= Gloas` is not a pre-Gloas version mismatch. | 6.4 |
| `crates/builder/src/service.rs` `legacy_proposer_ops_retired` `fork >= ForkName::Gloas` | 1 | — | inherit-intentionally | `legacy_proposer_ops_retired`: open-ended `>= Gloas` so later forks keep prepare/register retired rather than silently restoring the pre-Gloas BN calls. | 6.10 |
| `crates/crypto/src/signing_root.rs` `capella_capped_fork_version` `let capped = if fork_name >= ForkName::Capella { ForkName::Capella } else { fork_name };` | 1 | — | inherit-intentionally | EIP-7044: voluntary-exit domain stays Capella-capped however many post-Capella forks exist. Open-ended `>=` is the spec. | — |
| `crates/crypto/src/signing_root.rs` `tests::legacy_voluntary_exit_root` `let capped = if fork_name >= ForkName::Capella { ForkName::Capella } else { fork_name };` | 1 | — | inherit-intentionally | Test mirror of 301 (`legacy_voluntary_exit_root`). Same Capella-cap inherit. | — |
| `crates/crypto/src/typed_signer.rs` `<LocalSigner as TypedSigner>::sign_aggregate_and_proof` `if ctx.fork_name >= ForkName::Gloas {` | 1 | — | inherit-intentionally | Pre-Electra aggregate signing fails closed at `>= Gloas` so a later fork does not sign `AggregateAndProof`. | — |
| `crates/crypto/src/typed_signer.rs` `<LocalSigner as TypedSigner>::sign_electra_aggregate_and_proof` `if ctx.fork_name >= ForkName::Gloas {` | 1 | — | inherit-intentionally | Electra aggregate signing fails closed at `>= Gloas` so a later fork does not sign `ElectraAggregateAndProof`. | — |
| `crates/grpc-signer/src/client.rs` `GrpcRemoteSigner::uses_gloas_rpc` `ctx.fork_name >= ForkName::Gloas` | 1 | — | inherit-intentionally | `uses_gloas_rpc`: open-ended `>= Gloas` so later forks keep the Gloas-safe header/root RPCs rather than silently falling back to decoder-bound legacy RPCs. | 4.20c |
| `crates/rvc/benches/deadline_rebenchmark.rs` `main` `assert!(fork >= ForkName::Gloas, "6.14 must resolve a Gloas-epoch slot; got {}", fork.as_ref());` | 1 | — | test-only | Bench asserts the slot resolved `>= Gloas`. Not a production guard. | — |
| `crates/rvc/src/orchestrator/aggregation.rs` `AggregationService::fetch_sign_aggregate` `if fork_name >= ForkName::Gloas {` | 1 | — | inherit-intentionally | Aggregate wrap: open-ended `>= Gloas` uses the island root so a later fork does not fall back to tree_hash 0.9. | — |
| `crates/rvc/src/orchestrator/aggregation.rs` `aggregate_fork_matches` `VersionedAggregateAttestation::Gloas(_) => fork >= ForkName::Gloas,` | 1 | — | inherit-intentionally | Aggregate body: open-ended `>= Gloas` accepts the Gloas variant so a later fork is not rejected as a fork mismatch. | — |
| `crates/rvc/src/orchestrator/coordinator/mod.rs` `DutyOrchestrator<C, S, B>::run_payload_attestation_phase` `if fork >= ForkName::Gloas {` | 1 | — | inherit-intentionally | PTC phase (4.13): open-ended `>= Gloas` so later forks keep the payload-attestation duty rather than silently dropping it. Threaded once-per-slot `ForkName`; not gated on decode failure. | 4.13 |
| `crates/rvc/src/orchestrator/duty_management.rs` `DutyManagementService::check_reorg_at_epoch_boundary` `if ForkName::from_epoch(epoch, &self.config.fork_schedule) >= ForkName::Gloas {` | 1 | — | inherit-intentionally | PTC reorg-check gate: same open-ended `>= Gloas` as the fetch path so uncached pre-Gloas epochs do not POST `duties/ptc`. | — |
| `crates/rvc/src/orchestrator/duty_management.rs` `DutyManagementService::fetch_epoch_duties` `let ptc_active = ForkName::from_epoch(epoch, &self.config.fork_schedule) >= ForkName::Gloas;` | 1 | — | inherit-intentionally | PTC duty fetch gate: open-ended `>= Gloas` so later forks keep skipping pre-Gloas `duties/ptc` (BN 500 spam) and keep fetching PTC once Gloas is active. | — |
| `crates/rvc/src/orchestrator/utils.rs` `uses_electra_attestation_wire` `fork >= ForkName::Electra` | 1 | — | inherit-intentionally | `uses_electra_attestation_wire`: open-ended `>= Electra` so Gloas (and later forks) keep the Electra+ wire. Index zeroing is the separate `zeroes_committee_index` (`Electra..Gloas`). | 2.8 |
| `crates/signer-server/src/dvt/peer_client.rs` `GrpcPeerRequester::uses_gloas_rpc` `matches!(ForkName::try_from(fork_id), Ok(name) if name >= ForkName::Gloas)` | 1 | — | inherit-intentionally | DVT peer `uses_gloas_rpc`: same open-ended `>= Gloas` as the gRPC client so later forks keep Gloas-safe RPCs. | 4.20c |
| `crates/signer/src/lib.rs` `<SignerService as ValidatorSigner>::sign_aggregate_and_proof` `if ForkName::from_epoch(epoch, fork_schedule) >= ForkName::Gloas {` | 1 | — | inherit-intentionally | Pre-Electra aggregate signing fails closed at `>= Gloas` rather than using the legacy decoder RPC. | — |
| `crates/signer/src/lib.rs` `<SignerService as ValidatorSigner>::sign_block_header` `if sign_ctx.fork_name >= ForkName::Gloas || header_owned.body_ssz.is_empty() {` | 1 | — | inherit-intentionally | `sign_block_header` gRPC factory: open-ended `>= Gloas` always uses `SignBlockHeader` so a later fork never ships Gloas-shaped body SSZ into a legacy decoder RPC. | 4.20c |
| `crates/signer/src/lib.rs` `<SignerService as ValidatorSigner>::sign_electra_aggregate_and_proof` `if ForkName::from_epoch(epoch, fork_schedule) >= ForkName::Gloas {` | 1 | — | inherit-intentionally | Electra aggregate path: open-ended `>= Gloas` fails closed instead of the pre-Electra `SignAggregateAndProof` decoder. | 4.20c |
| `crates/timing/src/clock.rs` `DeadlineSchedule::for_fork` `if fork >= ForkName::Gloas {` | 1 | — | inherit-intentionally | `DeadlineSchedule::for_fork`: open-ended `>= Gloas` selects the Gloas deadline set so later forks keep those offsets rather than silently reverting to pre-Gloas 3333/6667. | 4.19 |
| `crates/rvc/src/orchestrator/attestation.rs` `AttestationService<C, S>::attest` `single_data.index = "0".to_string();` | 2 | — | must-bound | Submission-path `SingleAttestation.data.index = "0"` inside `zeroes_committee_index`, not the Electra+ wrapper branch, so Gloas preserves the BN value. | 2.8 |
| `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs` `test_electra_crypto_attestation_data_index_zeroed` `crypto_data.index = 0;` | 2 | — | test-only | Test applies `index = 0` when local `is_electra`. Follows 2.3 helper. | 2.3 |
| `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs` `test_electra_signing_root_matches_submitted_data` `crypto_data.index = 0; // EIP-7549` | 2 | — | test-only | Signing-root fixture zeros index by hand. Not a production guard. | 2.3 |
| `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs` `test_electra_signing_root_matches_submitted_data` `submitted_beacon_data.index = "0".to_string();` | 2 | — | test-only | Reconstructs submitted `index = "0"` to compare roots. Mirrors attestation.rs 865. | 2.8 |
| `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs` `test_pre_electra_data_index_preserved` `crypto_data.index = 0;` | 2 | — | test-only | Pre-Electra path does not assign; the `if is_electra` still contains the assignment. 2.3. | 2.3 |
| `crates/rvc/src/orchestrator/utils.rs` `convert_and_normalize_attestation_data` `data.index = 0;` | 2 | — | must-bound | The assignment gated by `zeroes_committee_index`. Bound together with the half-open `Electra..Gloas` predicate (2.3 / 2.8). | 2.3 |
| `crates/rvc/tests/gloas_data_index_round_trip.rs` `test_electra_and_fulu_still_zero_index_on_signing_and_submission` `expected.index = 0;` | 2 | — | test-only | Electra/Fulu round-trip expects the submitted index to be zeroed. | — |
| `crates/rvc/tests/gloas_data_index_round_trip.rs` `test_gloas_data_index_0_and_1_round_trip` `zeroed.index = 0;` | 2 | — | test-only | Gloas round-trip builds a zeroed index to prove the signing path did not zero it. | — |
| `bin/rvc/tests/common/mock_bn.rs` `fork_version_hex` `match fork {` | 3 | exhaustive | test-only | `match fork` → version hex. Compile error on a new variant. 2.5b/2.6 add Gloas `0x07000000`. | 2.5b |
| `crates/beacon/src/client.rs` `BeaconClient::get_aggregate_attestation` `match fork {` | 3 | exhaustive | inherit-intentionally | Aggregate fetch v2 request table. Exhaustive `match fork` so a new variant is a compile error, not a silent v1 or v2 inherit. | RR-3.2 |
| `crates/beacon/src/client.rs` `decode_versioned_aggregate` `match requested {` | 3 | exhaustive | inherit-intentionally | v2 200 is accepted only when the response header, body `version`, and the requested fork agree. Pre-Electra is not decoded on this path. | RR-3.2 |
| `crates/beacon/src/prepare_check.rs` `compute_preparable` `match ForkName::from_str(&response.consensus_version) {` | 3 | _ | inherit-intentionally | The match is on the parse result. `ForkName::Gloas` is in a guard, so the scanner records it. A new variant does not fail compilation here. A slot at Gloas or later still takes the parse rejection in that guard. | — |
| `crates/beacon/src/prepare_check.rs` `ssz_format` `Ok(match fork {` | 3 | exhaustive | inherit-intentionally | SSZ shape is an exhaustive `match fork`: Deneb, Electra, and Fulu are block contents; Gloas and pre-Deneb are a beacon block. A new variant is a compile error. An unknown version string fails before the match. | — |
| `crates/block-service/src/service/mod.rs` `ssz_block_format` `let format = match fork {` | 3 | exhaustive | inherit-intentionally | `ssz_block_format` named Gloas `BeaconBlock` arm; exhaustive `match fork` so a new variant is a compile error, not a silent `BlockContents`/`BeaconBlock` inherit. Unknown version strings fail closed before the match. | 6.4 |
| `crates/eth-types/src/block.rs` `expected_kzg_proof_count` `match fork {` | 3 | exhaustive | inherit-intentionally | `expected_kzg_proof_count` is keyed on `ForkName`, not `BodyForkLayout` (Fulu must not inherit Electra's one-proof rule). Deneb/Electra are one proof per blob, Fulu is `CELLS_PER_EXT_BLOB` cell proofs, Gloas and pre-Deneb error. A new variant is a compile error. | RR-3.9 |
| `crates/eth-types/src/fork.rs` `ForkName::body_layout` `match self {` | 3 | exhaustive | inherit-intentionally | `body_layout()` exhaustive match. 2.7 adds `Gloas => Some(BodyForkLayout::Gloas)`. | 2.7 |
| `crates/eth-types/src/fork.rs` `ForkName::id` `match self {` | 3 | exhaustive | inherit-intentionally | `ForkName::id` exhaustive `match self` with no `_ =>`. Deliberate fork-addition tripwire (2.1). 2.5b adds the Gloas arm. | 2.5b |
| `crates/rvc/tests/gloas_data_index_round_trip.rs` `epoch_for` `match fork {` | 3 | _ | test-only | Test maps Electra/Fulu/Gloas epochs. `other` panics; not a production dispatch. | — |
| `crates/block-service/src/service/tests/mocks.rs` `build_ssz_bytes` `!is_blinded && matches!(consensus_version, "deneb" | "electra" | "fulu");` | 4 | exhaustive | test-only | `matches!` on deneb/electra/fulu for `BlockContents` bytes. Closed string set; `"gloas"` is false. | — |
| `crates/block-service/src/service/tests/mocks.rs` `test_blinded_body_ssz_for_version` `match consensus_version {` | 4 | _ | test-only | Blinded-body twin of 1170. Wildcard `_ =>` Deneb body. | — |
| `crates/block-service/src/service/tests/mocks.rs` `test_body_ssz_for_version` `match consensus_version {` | 4 | _ | test-only | Test body SSZ picker. Named Deneb, Electra/Fulu, and pre-Deneb/Gloas arms. `other` panics. | — |
| `crates/block-service/src/service/tests/propose.rs` `test_propose_block_gloas_slot_deneb_version_mismatch_drops_duty` `matches!(` | 4 | exhaustive | test-only | Asserts `ConsensusVersionMismatch` for a Gloas slot advertised as deneb. | — |
| `crates/block-service/src/service/tests/ssz.rs` `test_propose_block_ssz_gloas_slot_deneb_version_mismatch_drops_duty` `matches!(` | 4 | exhaustive | test-only | SSZ twin of the propose.rs version-mismatch assert. | — |
| `crates/block-service/src/service/tests/v4.rs` `test_fulu_slot_gloas_version_unblinded_json_drops_duty_before_hasher` `matches!(` | 4 | exhaustive | test-only | Fulu slot with a gloas JSON version must fail closed. | — |
| `crates/block-service/src/service/tests/v4.rs` `test_fulu_slot_gloas_version_unblinded_ssz_drops_duty_before_hasher` `matches!(` | 4 | exhaustive | test-only | Fulu slot with a gloas SSZ version must fail closed. | — |
| `crates/block-service/src/service/tests/v4.rs` `test_v4_consensus_version_mismatch_drops_duty_before_signer` `matches!(` | 4 | exhaustive | test-only | Gloas slot with a fulu version must fail closed. | — |
| `crates/bn-manager/src/manager.rs` `ssz_produce_format` `match consensus_version {` | 4 | _ | must-bound | V3 SSZ duty check picks `BlockContents` or `BeaconBlock` from the consensus version string. `_ => None` rejects an unknown version instead of inheriting either format. | — |
| `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs` `test_gloas_slot_dispatches_produce_block_v4` `match &envelopes[0] {` | 4 | _ | test-only | Envelope publish assert names consensus version `gloas`. Not a production dispatch. | — |
| `crates/rvc/src/orchestrator/sync_committee.rs` `tests::contribution_kat` `match name {` | 4 | _ | test-only | Test maps fixture fork names onto ContributionAndProof signing-root KATs. Closed set; `other` panics. Not a production consensus-version dispatch. | — |
| `crates/beacon/src/types.rs` `compare_fork_schedule` `expected.entries().into_iter().zip(FORK_SCHEDULE_KEYS)` | 5 | — | inherit-intentionally | BN admission compares each fork key of `/eth/v1/config/spec` with the local schedule. The key table has `ForkName::COUNT` rows, so a new fork does not compile until it has its spec keys. | — |
| `crates/crypto/src/typed_signer.rs` `SignContext::resolve` `.entries()` | 5 | — | must-bound | `SignContext::resolve` first-matches `fork_info.current_version` over `entries()`. Two `[0xFF;4]` rows (unscheduled Fulu+Gloas after 2.6) resolve Fulu, so `Gloas.fork_version()` does not round-trip. 2.6 pins the collision; 2.10 confines it to both-unscheduled. | 2.6 |
| `crates/eth-types/src/fork.rs` `ForkName::activation_epoch` `.entries()` | 5 | — | inherit-intentionally | `activation_epoch` lookup through `entries()`. Same inherit. | 2.5b |
| `crates/eth-types/src/fork.rs` `ForkName::fork_version` `.entries()` | 5 | — | inherit-intentionally | `fork_version` lookup through `entries()`. New row participates by construction. | 2.5b |
| `crates/eth-types/src/fork.rs` `ForkName::from_epoch` `.entries()` | 5 | — | inherit-intentionally | `from_epoch` reverse-scans `entries()`; a new row is picked up automatically. Equal activation epochs pick the latest fork. | 2.5b |
| `crates/eth-types/src/fork.rs` `ForkSchedule::next_activation` `self.entries()` | 5 | — | inherit-intentionally | `next_activation` scans `entries()` and skips `u64::MAX`. A new row participates by construction. | — |
| `crates/eth-types/src/fork.rs` `tests::test_entries_contains_each_all_variant_exactly_once` `let entries = schedule.entries();` | 5 | — | test-only | 2.1 uniqueness test (`entries().len() == COUNT`). | 2.1 |
| `crates/eth-types/src/fork.rs` `tests::test_fork_version_and_activation_epoch_unchanged_for_all_eight` `let entries = schedule.entries();` | 5 | — | test-only | Eight-ness assert `entries().len() == 8`. 2.5b rewrite of the former seven-ness table. | 2.5b |
| `crates/rvc-spec-vectors/src/bin/gen_spec_kat.rs` `load_gloas_from_tar` `let entries = tar.entries().map_err(|e| format!("read {}: {e}", archive.display()))?;` | 5 | — | test-only | tar `Archive::entries()`; not `ForkSchedule`. 4.0 generator, not a fork-addition hazard. | — |
<!-- END INVENTORY -->

## Notes

- **2.3 / 2.8 split EIP-7549 zeroing from Electra+ wire.** Zeroing is
  `zeroes_committee_index` (`Electra..Gloas`). Wire shape is
  `uses_electra_attestation_wire` (`>= Electra`, inherit-intentionally) so
  Gloas keeps `SingleAttestation` / committee-index query / Electra aggregate
  while preserving BN `data.index`. Class-2 assignments stay on the zeroing
  predicate.
- **6.15 closed the three production `>= ForkName::Fulu` sites.** Attestation
  and aggregate wrapper selection now matches the resolved fork (`== Gloas` /
  `== Fulu` / else Electra) so a Gloas epoch submits `Eth-Consensus-Version:
  gloas` rather than inheriting Fulu.
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
- **4.5 proposer-duties v2.** Class 1 grew by one (`client.rs` 401):
  `>= ForkName::Gloas` selects `/eth/v2/validator/duties/proposer/{epoch}`.
  Inherit-intentionally — a later fork must stay on v2, not fall back to
  deprecated v1. `ForkSchedule::unscheduled_gloas` shifted the `fork.rs`
  class-3/5 line numbers.
- **4.19 fork-aware deadlines.** Class 1 grew by one (`clock.rs` 30):
  `DeadlineSchedule::for_fork` uses `>= ForkName::Gloas` so a later fork
  keeps the Gloas deadline set. Inherit-intentionally — do not switch to
  `== Gloas` (that would drop a successor fork onto pre-Gloas 3333/6667).
- **6.4 Gloas SSZ format / blinded gate.** Class 3 grew by one
  (`service/mod.rs` 619): exhaustive `match fork` with a named Gloas
  `BeaconBlock` arm; a new variant is a compile error. Class 4 lost the
  old `_ => BeaconBlock` string table (unknown versions fail closed via
  `ForkName::from_str`). Class 1 grew by one (`service/mod.rs` 641):
  `>= Gloas` rejects blinded so a later fork keeps that gate.
  Inherit-intentionally. Four more class-1 `>= Gloas` sites from 4.20c
  (`grpc-signer` / `signer` / `signer-server`) are inventoried the same way.
- **Binding catch-alls.** Four test-only rows had Kind `exhaustive`
  because the old scanner saw only a `_ =>` arm:
  `gloas_data_index_round_trip.rs` `epoch_for`, `mocks.rs`
  `test_body_ssz_for_version`, `fork_transition.rs`
  `test_gloas_slot_dispatches_produce_block_v4` and `sync_committee.rs`
  `tests::contribution_kat`. Each has an `other => panic!(…)` arm, so the
  Kind is now `_`. The verdicts do not change.
- **Wrapper catch-alls.** `prepare_check.rs` `compute_preparable` had Kind
  `exhaustive`. Its `Ok(got) =>` arm takes every parsed fork that the guarded
  arms do not take, so a new variant does not fail compilation. A wrapper
  pattern with irrefutable fields (`Ok(got)`, `Some(_)`, `S { .. }`) is a
  catch-all for the values in that wrapper, so the Kind is now `_`. The
  verdict does not change.
- **FU-D2 contribution KAT lookup.** Class 4 grew by one
  (`crates/rvc/src/orchestrator/sync_committee.rs` `tests::contribution_kat`):
  a test-only match on fixture fork names. `other` panics. Not a production
  consensus-version dispatch.

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
