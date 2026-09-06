# Project Plan: rs-vc Glamsterdam (CL: Gloas) Readiness

> **Historical roll-up (D30).** The task lists below predate the issue-level split and the round-1
> and round-2 remediation; their IDs (2.1–2.4, 4.1–4.4, 5.1–5.4, 6.1–6.3 …) do **not** map to the
> issue IDs in [`issues/`](issues/). The roll-up of record is
> [`issues/00-summary.md`](issues/00-summary.md) and the phase files. **The Decision Log at the end of
> this file stays live** — 3.11, 5.3 and 8.9b write to it. Four superseded statements below were
> corrected in place on 2026-09-05 (D30); nothing else was regenerated.

## Summary
- Extends rs-vc across the Gloas boundary: fork identity, timing/config, PTC + proposer-preferences duties, an isolated `rvc-gloas` merkleization crate, `produceBlockV4`, then devnet and soak.
- 8 phases. P1-P3 start immediately (spec-content-independent); P4-P6 sit behind the spec-freeze gate; P5 additionally behind the P3 L1 go/no-go.
- Key constraint: **no calendar target.** `GLOAS_FORK_EPOCH` is the far-future sentinel on every network and Gloas is still Unstable. Every gate is a spec release, a vector result, or a devnet.

## Prerequisites
- Pinned `SPEC_TAG` on an `ethereum/consensus-specs` release ≥ `v1.7.0-alpha.12` (earlier tags carry no ProgressiveContainer cases); `eth-ssz-specs` 0.1.0; Python ≥ 3.12 for the L3 generator.
- CI cache for vector tarballs keyed on the pinned tag (`minimal` in CI, `mainnet` nightly); access to a `ethpandaops/glamsterdam-devnets` devnet (devnet-6+) and a remote-signer / DVT test cluster.
- **Unowned:** mainnet-readiness sign-off has no named owner. No other approvals outstanding before P1 starts.

## Phase 1: Timing and Deadline Configuration
- **Goal:** land `SLOT_DURATION_MS` + basis-point deadlines from runtime config, unblocking config parsing against master `mainnet.yaml` today · **Size:** M · **Entry:** none — start now
- **Requirements:** P0-11, P0-13 · **Deps:** none · **Retires:** merge conflicts across ~50 shared files; hardcoded-deadline divergence
### Tasks
- [ ] 1.1 — Rename `SECONDS_PER_SLOT`/`INTERVALS_PER_SLOT` to `SLOT_DURATION_MS` across `crates/timing` and all 39 call sites in 21 files (D31) · deps: none · complexity: medium
- [ ] 1.2 — Parse every `*_DUE_BPS*` from `rvc-config`, none hardcoded; missing or unknown keys fail closed with actionable text · deps: 1.1 · complexity: medium
- [ ] 1.3 — Add the six Gloas deadline keys (`ATTESTATION_DUE_BPS_GLOAS` 2500, `AGGREGATE_DUE_BPS_GLOAS`, `SYNC_MESSAGE_DUE_BPS_GLOAS` 2500, `CONTRIBUTION_DUE_BPS_GLOAS` 5000, `PAYLOAD_DUE_BPS` 5000, `PAYLOAD_ATTESTATION_DUE_BPS` 7500) as config-only values; record the pre-change signing-latency baseline · deps: 1.2 · complexity: medium
### Exit Criteria
- [ ] `rvc-config` parses an unmodified consensus-specs master `configs/mainnet.yaml`; existing suites green
- [ ] `AGGREGATE_DUE_BPS_GLOAS` resolves to either 5000 or 6667 from config alone, no rebuild; latency baseline recorded

## Phase 2: Fork Identity and Fork-Addition Hazard Audit
- **Goal:** add `ForkName::Gloas` and, in the same change, bound every open-ended `>= ForkName::X` comparison so the new arm cannot silently alter existing behaviour · **Size:** L · **Entry:** none — start now
- **Requirements:** P0-1, P0-2, P0-4, P0-12 (gate half), P2-2 · **Deps:** none (parallel with P1) · **Retires:** the live `data.index` bug; the workspace-wide `entries()` ripple; the fork-addition hazard class
### Tasks
- [ ] 2.1 — `ForkName::Gloas` (`id()==7`, `0x07000000`), `gloas_fork_{epoch,version}` on the flat `ForkSchedule`, arms in `AsRef<str>`/`FromStr`/`TryFrom<u32>` · deps: none · complexity: medium
- [ ] 2.2 — Widen `entries()` to `[_; ForkName::COUNT]` from one table (P0-2 + P2-2 in one pass); update `ALL: [Self; 7]`, the reverse-scan test, `ssz_helpers` `0u32..=6` loops, and `rvc-keygen`'s `exit_cap_schedule` · deps: 2.1 · complexity: high
- [ ] 2.3 — **Hazard audit.** Classify every `>= ForkName::X` site *and* every `index = 0` assignment as inherit-intentionally / must-bound / test-only. Confirmed inherit: `crypto/src/signing_root.rs:228,284` (EIP-7044 Capella exit cap). Confirmed must-bound: `orchestrator/utils.rs:143` and `orchestrator/attestation.rs:320`, whose `is_electra` bool drives the `:414-416` submission-path zeroing. The four `>= ForkName::Fulu` sites need an explicit decided-not-inherited verdict · deps: 2.1 · complexity: high
- [ ] 2.4 — Gate EIP-7549 zeroing to `Electra..Gloas` at **both** sites so `data.index` passes through verbatim at Gloas; `validate_fork_id` explicitly rejects fork id 7; `BodyForkLayout::Gloas` is a typed-error arm and `extract_blob_kzg_commitments` errors on it; fork epoch/version from `rvc-config` reconciled against the BN's spec-derived schedule (`get_config_spec()` / `get_fork_schedule()`, `crates/beacon/src/client.rs:325-334` — no `/eth/v1/config/fork_schedule` client method exists; D12, issue 2.10) · deps: 2.3 · complexity: high
### Exit Criteria
- [ ] Vector-free unit test: `data.index` **preserved** at Gloas, **zeroed** at Electra..Fulu, on both the signing and the submission path
- [ ] Audit table checked in with a verdict per site, no unclassified comparison left; exits still Capella-capped however many post-Capella entries sit at `u64::MAX`

## Phase 3: Vector Pipeline and L1 Merkleization Gate
- **Goal:** land `rvc-spec-vectors` and answer the blocking question — do `libssz` 0.3.0's `merkleize_progressive` / `mix_in_active_fields` match EIP-7916/7495? **A branch point, not a confirmation** · **Size:** M · **Entry:** none — start now; highest-leverage de-risking work in the plan
- **Requirements:** P0-8 (pipeline half) · **Deps:** none · **Retires:** ADR-001 reversal risk; the F122 self-referential-vector repeat; KAT-policy blockage of all container work
### Tasks
- [ ] 3.1 — New integration-only crate `rvc-spec-vectors` (dev-deps `snap`, `serde_yaml`, `hex`, `sha2`); `make spec-vectors` fetch, gitignored cache, CI key on `SPEC_TAG` · deps: none · complexity: medium
- [ ] 3.2 — `spec_kat.rs` codegen with machine-checkable provenance (source repo+tag, generator+version, input sha256, date); reading an rs-vc-computed root is a build failure (ADR-005) · deps: 3.1 · complexity: high
- [ ] 3.3 — **L1 gate.** `SPEC_PROGRESSIVE_*` from `eth-ssz-specs` at chunk counts 0,1,2,4,5,6,20,21,22,84,85,86 (boundaries 1/5/21/85): empty ⇒ `[0u8;32]`, ×4 growth, subtree-left/remainder-right, the **unverified left-subtree `merkleize(chunks[..n], limit=n)` padding**, and LSB-first `pack_bits` · deps: 3.2 · complexity: high
- [ ] 3.4 — Record the go/no-go. On **no-go**, open the ADR-007 fallback: hand-roll `gloas::merkle` internals against the same L1 vectors — container declarations and `active_fields` tables are unaffected. Add the `cargo tree -d` CI assertion (no `ethereum-types`, no second `primitive-types`), `--locked`, exact `=0.3.0` pins · deps: 3.3 · complexity: medium
### Exit Criteria
- [ ] Vectors fetch, verify by sha256 and parse in CI from a cold cache; `kat_policy.rs` green with zero new `EXEMPTIONS`
- [ ] All twelve L1 chunk-count cases pass against the chosen primitive implementation, and the go/no-go is written into the Decision Log

## Phase 4: PTC Duty and Proposer Preferences
- **Goal:** ship both new VC-signed duties end to end on the plain `tree_hash` 0.9 path, PTC first (tagged release) and preferences second (master-only, still moving) · **Size:** L · **Entry:** spec freeze — **not** L1-gated (ADR-006)
- **Requirements:** P0-3, P0-5 (PTC/preferences slice), P0-6, P0-7, P0-9, P1-2, P1-6 · **Deps:** P1 (deadlines), P2 (fork identity), P3 (KAT pipeline) · **Retires:** signer/DVT day-one lag; PTC duty loss; stale fee recipient after activation
### Tasks
- [ ] 4.1 — Plain `tree_hash` 0.9 containers in `eth-types`: `PayloadAttestationData/Message` and `PtcDuty` first; `ProposerPreferences`/`Signed…` after, gated on the PTC set landing · deps: P2 · complexity: medium
- [ ] 4.2 — `DOMAIN_PTC_ATTESTER 0x0C000000` and `DOMAIN_PROPOSER_PREFERENCES 0x0D000000` in the single `crypto` domain table and in `test_all_domains_are_unique`; two `DutyRef` arms; PTC fork version at `epoch_of(data.slot)`; re-verify the Capella exit cap. **No builder-domain arm** — `0x0B`/`0x0E` are builder-signed · deps: 4.1 · complexity: medium
- [ ] 4.3 — Beacon-API + duties: `POST duties/ptc/{epoch}`, `GET payload_attestation_data?slot=` (204 ⇒ skip, no fallback), `POST pool/payload_attestations` (GET dropped, D13), proposer-duties v2 at Gloas / v1 pre-Gloas and node-version v2 with v1 fallback (D25), then `POST proposer_preferences` (deps: the PTC endpoints); `PtcDuty` on the existing duty contract reorg-checked by a duties-endpoint re-fetch of `dependent_root` (no `head_v2` event exists), no PTC aggregation duty; `Eth-Consensus-Version` required on requests and **fail-closed** on responses (`client.rs:433`, `:554` fail open today) · deps: 4.1 · complexity: high
- [ ] 4.4 — Signer wire + DVT + slashing: `PlanInput::{PayloadAttestation, ProposerPreferences}` over the existing `object_root` idiom, both `Slashing::NonSlashable`; generic `{"version","data"}` wrapper; hard reject on unknown type **or** version; HTTP 400 stays a transient class, never a permanent `unsupported_sign_type`; startup capability probe; DVT peers verify only the planned root and `fork_version` (they hold no chain edge; the requesting VC observes `payload_present`/`blob_data_available` once per slot and sends identical bytes to every peer) and never aggregate across fork versions; PTC and preferences never written to the slashing DB, and the `(None,None) if !strict` arm (`db/mod.rs:256-263`, FU-33) is gated for Gloas epochs · deps: 4.2 · complexity: high
### Exit Criteria
- [ ] PTC round-trips against a fixture BN (fetch → 75%-of-slot fire → sign under `DOMAIN_PTC_ATTESTER` → POST pool) with the slashing DB untouched; `SignedProposerPreferences` broadcast for every upcoming proposal slot, one epoch early
- [ ] Unknown sign type **and** unknown version each rejected and a 400 never poisons a key; FU-33 regression green (same `(source_epoch, target_epoch)`, `index` 0 vs 1, roots absent → rejected, not deduplicated); **containment:** `SIGNER_SERVER_ALLOWED_EDGES` unchanged and neither `crypto` nor `signer-server` depends on `rvc-gloas`

## Phase 5: `rvc-gloas` Merkleization Island
- **Goal:** declare every progressively-merkleized Gloas container in an isolated crate that exports roots only as `[u8; 32]` · **Size:** L · **Entry:** spec freeze **and** the P3 L1 outcome
- **Requirements:** P0-10, P0-8 (L2/L3 KATs) · **Deps:** P3 (primitives + pipeline), P2 (fork identity) · **Retires:** wrong-root / total-duty-loss risk; SSZ stack contamination; spec-churn blast radius
### Tasks
- [ ] 5.1 — Crate skeleton `crates/gloas` (`rvc-gloas`) with exactly one workspace out-edge to `rvc-eth-types`; `CLASSIFICATION` row (Base); regenerate `ARCHITECTURE.md`. `merkle.rs` is the **only** primitive call site (ADR-007): `libssz` on a P3 go, hand-rolled against the same L1 vectors on a no-go · deps: P3 · complexity: high
- [ ] 5.2 — Declare sets (a)/(b)/(c) per ADR-004, re-declaring the whole field closure with **no inbound `TreeHash` bridge** (ADR-003 — delegation silently yields pre-Gloas roots for `AttesterSlashing → IndexedAttestation`, and `ExecutionRequests` is the same trap one level down) · deps: 5.1 · complexity: high
- [ ] 5.3 — Root API `gloas_block_root` / `gloas_aggregate_and_proof_root` / `gloas_attestation_root` / `gloas_indexed_attestation_root`; `GloasError` on an undecodable body or an `active_fields` width mismatch — never a zero, guessed or fallback root · deps: 5.2 · complexity: medium
- [ ] 5.4 — L2 KATs (`SPEC_GLOAS_<TYPE>_ROOT` from official `ssz_static` `roots.yaml`, set (c) additionally getting the `tree_hash` 0.9 differential with a `// kat_exempt: cross-implementation differential` marker) and L3 KATs (self-generated `KAT_GLOAS_<OBJ>_SIGNING_ROOT` + domains, since no official runner covers `compute_signing_root`/`compute_domain`/`get_domain`); re-verify every `active_fields` width (4/3/13) against the frozen tag · deps: 5.3 · complexity: high
### Exit Criteria
- [ ] Every island container asserts against an official `ssz_static` root; `kat_policy.rs` green with **zero** new `EXEMPTIONS`; set (c) differential vs `tree_hash` 0.9 passes
- [ ] `architecture-tests` scan finds no `tree_hash::`/`ssz::`/`ssz08::` import outside `#[cfg(test)]` in `rvc-gloas`; `cargo tree -d` clean; only `Root` crosses the crate boundary

## Phase 6: Block Production and Aggregate Path
- **Goal:** move proposal to `produceBlockV4` with the blinded flow retired, and route aggregate and block-body roots through the island · **Size:** L · **Entry:** P5 complete
- **Requirements:** P0-5 (V4 + failover), P0-12 (KAT + behavioural), P1-3 · **Deps:** P5 (roots), P4 (endpoint and wire foundations) · **Retires:** proposer-path panic on a Gloas body; double proposal on a blind retry; shape-preserving `data.index` defects
### Tasks
- [ ] 6.1 — `POST /eth/v4/validator/blocks/{slot}` with the required `BuilderConfig` body, `builder_preferences`, `Eth-Execution-Payload-Included` semantics and `Eth-Builder-Url` echo on `publishBlockV2`; the blinded path becomes pre-Gloas-only · deps: P5 · complexity: high
- [ ] 6.2 — `bn-manager`: an explicit non-idempotent call class for block production (ADR-008), and per-endpoint health that marks a BN unhealthy when it does not recognise the fork or lacks `/eth/v4` rather than degrading silently · deps: 6.1 · complexity: high
- [ ] 6.3 — Wire the Gloas block and aggregate roots through `rvc-gloas` into the pre-existing `DutyRef::BlockRoot` / `PlanInput::{Block, AggregateAndProof} { object_root }` idiom; `SignedProposerPreferences` supersedes `prepare_beacon_proposer` + `register_validator` after activation; add the L4 `data.index` 0/1 BN→signature→submission round-trip plus the `index=1` KAT row, the L5 sentinel-epoch byte-identity suite, and the deadline re-benchmark against the P1 baseline · deps: 6.1 · complexity: high
### Exit Criteria
- [ ] A Gloas proposal is produced, signed, slashing-checked and published without touching the blinded path; a BN lacking `/eth/v4` is marked unhealthy for it and no production POST is blind-retried across BNs
- [ ] L4 round-trip green for `index` 0 **and** 1 (submitted value byte-identical to the signed one); L5 byte-identity green; no regression against the P1 latency baseline

## Phase 7: Devnet Bring-Up
- **Goal:** run rs-vc across a live Glamsterdam devnet fork boundary with full duty coverage · **Size:** M · **Entry:** P1-P6 complete and a reachable devnet (devnet-6+)
- **Requirements:** P1-4, P1-5 · **Deps:** all prior phases · **Retires:** boundary-transition defects; undocumented operator upgrade path
### Tasks
- [ ] 7.1 — Fork-transition integration test: a fixture BN crossing the activation epoch mid-run, asserting duties continue with correct domains at epoch N-1 → N · deps: P6 · complexity: high
- [ ] 7.2 — Devnet run with local keys, then with a remote signer / DVT cluster, recording every fail-closed rejection; read client versions and fork epochs from the per-devnet network-config files at run time rather than assuming them · deps: P6 · complexity: medium
- [ ] 7.3 — Operator upgrade note in `docs/`: required config keys, the `SLOT_DURATION_MS` diff, rollback guidance, and an explicit statement that **no minimum remote-signer version is writable** (Web3Signer has no Gloas types through 26.7.0) · deps: 7.2 · complexity: low
### Exit Criteria
- [ ] ≥ 99% attestation effectiveness, ≥ 99% PTC-attestation submission, 0 missed proposals over 100 consecutive post-fork epochs, 0 slashable events
- [ ] Fork-transition test green in CI independently of devnet availability; operator note reviewed and merged

## Phase 8: Network Soak and Observability
- **Goal:** soak on the first public network that schedules the fork and reach sign-off · **Size:** M · **Entry:** P7 complete **and** a public network scheduling the fork — no date
- **Requirements:** P2-1 · **Deps:** P7 · **Retires:** unmonitored pre-fork activation; residual mainnet risk
### Tasks
- [ ] 8.1 — Metrics, logs and a pre-fork alerting dashboard for resolved current fork, next activation epoch, PTC submission rate, per-endpoint BN capability state, and signer rejections by type/version · deps: P7 · complexity: medium
- [ ] 8.2 — Soak run on the first scheduling public network with the zero-slashing gate enforced · deps: 8.1 · complexity: medium
- [ ] 8.3 — Re-pin `SPEC_TAG` to that network's shipped spec release and re-run L1-L5 · deps: 8.2 · complexity: low
### Exit Criteria
- [ ] ≥ 14 consecutive stable days on that network with 0 slashable events
- [ ] All KAT layers green against the network's shipped spec tag **before** the soak (D26); **`evidence complete`** recorded; **`release approved`** tracked separately and blocked until the accountable role is named (D16)

## Dependency Graph
- `P1, P2, P3` — no entry gate; **start immediately, in parallel.** `P4, P5, P6` — behind the spec-freeze gate.
- `P2 → P2` [internal, load-bearing: task 2.4's zeroing gate must land **with** 2.1's `ForkName` arm, or adding the arm introduces the `data.index` bug]
- `P3 → P5` [L1 go/no-go. On no-go, P5 is **not cancelled** — only 5.1's primitive source swaps to the ADR-007 hand-roll; declarations and `active_fields` tables are unchanged]
- `P3 → P4, P5, P6` [KAT-policy CI gate: no container or root test can merge before the pipeline exists]
- `P1, P2, P3 → P4` [**ADR-006 bypass:** PTC and preferences are plain `tree_hash` 0.9 containers, so P4 does **not** wait on the L1 outcome or on P5]
- `P5 → P6` [aggregate and block-body roots only; the PTC path never enters the island] · `P4, P6 → P7 → P8`

## Risk Register
| Risk | Impact | Likelihood | Mitigation |
|---|---|---|---|
| `libssz` progressive semantics diverge from EIP-7916 (left-subtree padding unverified) | Every Gloas root wrong; total duty loss | Medium | P3 L1 gate blocks P5; ADR-007 confines primitives to `gloas::merkle`; per-container `ssz_static` KAT as release gate |
| `libssz` abandoned or yanked (first published 2026-03-20) | Build breaks, or an unpatched bug in a root-gating dep | Medium | Exact `=0.3.0` pins, `--locked`; vendor the MIT/Apache source — vendoring, not a rewrite, is the answer |
| `data.index` zeroed at Gloas (**a live bug today**) | Payload status destroyed; shape-preserving ⇒ green KATs; on-chain slashable | High if unaddressed | Tasks 2.3/2.4 land with the `ForkName` arm; L4 round-trip (6.3); FU-33 gate (4.4) |
| Self-referential vectors (F122 repeat) | Green tests assert the bug | Medium | ADR-005 provenance header; generator forbidden to read rs-vc roots; zero new `EXEMPTIONS` |
| Spec churn before freeze | Rework of container declarations | High | Churn confined to `rvc-gloas` + `spec_kat.rs`; re-pin `SPEC_TAG` per release; treat a vector diff as a spec signal |
| Signer or DVT peer lags the new sign types | Duties dropped on day one (Web3Signer has none through 26.7.0) | High | Explicit rejection over silent fallback; startup capability probe; documented gap, no invented version |

## Open Questions
- `active_fields` widths (4/3/13) and every container declaration: re-verify at the freeze gate and pin by vector. `Attestation.aggregation_bits` — `ProgressiveBitlist` or unchanged `Bitlist`? Does not change the architecture; the island declares both.
- Which body lists beyond the slashing lists become `ProgressiveList` (deposits, voluntary_exits, bls_to_execution_changes), and the shape of `parent_execution_requests` — both block P5 sizing. `CommitteeBits` assumed inherited; `BuilderDepositRequest`/`BuilderExitRequest` field lists unread — confirm before KAT-ing `ExecutionRequests`.
- Does any column-sidecar surface remain VC-side? Is PTC duty *discovery* specified beyond the endpoint shape? `remote-signing-api` PR #28 names are provisional (bid → request auth rename expected); `BUILDER_REQUEST_AUTH` / `0x0B000001` tracked, not implemented.
- **Who owns mainnet-readiness sign-off?** Currently unowned — a P8 exit criterion with no assignee.

## Decision Log
- **Adopt `libssz` =0.3.0 inside a new `rvc-gloas` crate, roots exported only as `[u8; 32]`** — `libssz-merkle` has no `tree_hash` dependency edge, so the `tree_hash` 0.9 pin stands and no workspace-wide upgrade is forced. **Confirmed-by-vector 2026-09-06** (issue 3.11 / #241); was conditional on the P3 L1 gate.
- **No `TreeHash` bridge, inbound or outbound** — `crypto/src/signing.rs:219` and `sign_plan.rs:78-102` already take an `object_root: Root` with identity HTR, so Gloas roots reach signing through the existing idiom and **zero new edges enter `crypto`/`signer-server`**.
- **`entries()` widens to `[_; ForkName::COUNT]` from one table** — P0-2 and P2-2 done in one pass, ending the per-fork breaking signature change (so P2-2 is not deferred to a later phase).
- **Runtime fork gate, unconditional compilation (ADR-009)** — no cargo feature, which would escape default CI; pre-activation inertness is proven by the L5 byte-identity suite instead.
- **P0-13 lands in Phase 1, not behind the freeze gate the PRD's M2 implies** — reading deadlines from config is spec-content-independent; the disputed values are config, not code. **PTC and preferences ship on the `tree_hash` 0.9 path (ADR-006)**, decoupling P4 from the island and the L1 gate.
- **Phase to a spec-freeze gate and a devnet, never a date** — `GLOAS_FORK_EPOCH` is the far-future sentinel everywhere and consensus-specs still lists Gloas as Unstable.
- **2026-09-05 — round-2 and follow-up review decisions D19–D32** (`issues/00-cross-phase-decisions.md`): Web3Signer HTTP wire deferred for Gloas blocks/aggregates (D19); the self-build `ExecutionPayloadEnvelope` is VC-signed under `DOMAIN_BEACON_BUILDER` and `ExecutionPayload` enters the island embed-only (D20, ADR-010); builder request auth is a proposer duty (D21, ADR-011); gRPC keys get a typed facade in `SignerService` (D22); 4.19 moves the real waits (D23); the ADR-007 fallback is a vendored, patched `libssz-merkle` (D24); pre-Gloas endpoint routing preserved (D25); all-green KATs precede the soak (D26); body-root export (D27); single pyspec L3 oracle owned by 4.0 (D28); ADR-008 amended to failover-able production with single-flight sign + publish (D29); this file is historical except the Decision Log (D30); P0-11 rationale (D31); 1.1 first, parallel P1/P2/P3 variant (D32).
- **2026-09-06 — L1 go/no-go (issue 3.11 / #241): GO.** `libssz-merkle` =0.3.0 matches EIP-7916 `merkleize_progressive` and EIP-7495 `mix_in_active_fields` against the 3.4b pyspec oracle. ADR-001 is **confirmed-by-vector**. Phase 5.1 uses published `libssz` primitives; ADR-007 is **not** opened (no-go only). **Release gate:** no Gloas root ships without a passing official vector. **Phase 4 is independent of this verdict** (plain `tree_hash` 0.9, ADR-006) — PTC and proposer preferences do not wait on L1 or on `rvc-gloas`.
  - Oracle: 3.4a **pyspec** (3.4b ran); not shipped-vector; not INCONCLUSIVE (`research/l1-oracle.md`).
  - Pins: `SPEC_TAG=v1.7.0-beta.0`, `SSZ_SPECS_TAG=v0.1.0`.
  - Generator: `gen-spec-kat` 0.7.0; Python 3.13.7; `eth-ssz-specs==0.1.0` (wheel sha256 `466c6cef854cca45022a7cdc3922dd636e30b1a1dd5385845819e3d45ddddf41`); `scripts/gen_progressive_vectors.py`.
  - Input digests (`crates/rvc-spec-vectors/vectors.lock`): generated `vectors-generated/progressive/roots.yaml` sha256 `6ead45d55e0b7512dd6fd05b30609d6c030ec0a0235cc37f5cffabf00a9ba401`; ssz archive `ssz-test-vectors-v0.1.0.tar.gz` sha256 `e2a65f032b59835c26127295293ea1bc07d7ca0ea1fe0e4f1128dffed333f878`; consensus-specs `minimal.tar.gz` sha256 `ba9203686b7312cddf160bfd3d4ad55e531dace6662e0223fe9b13b979535441`; `mainnet.tar.gz` sha256 `0ef9c069293e2171dd75c5593faf7b97e32b9bcdce9285e870959938747c0774`.
  - Evidence: 3.7 `64828c1`; 3.8 `660c265`.

  3.7 `merkleize_progressive` (`libssz-merkle` 0.3.0 vs `SPEC_PROGRESSIVE_*`; empty `[0u8;32]`; padding 2/6/22/86):

  | count | note | libssz vs SPEC |
  |---:|---|---|
  | 0 | empty ⇒ `[0u8;32]` | pass |
  | 1 | fills level 1 (width 1) | pass |
  | 2 | opens level 2; **padding** | pass |
  | 4 | level 2 almost full | pass |
  | 5 | fills levels 1+2 (boundary 5) | pass |
  | 6 | opens level 3; **padding** | pass |
  | 20 | level 3 almost full | pass |
  | 21 | fills levels 1–3 (boundary 21) | pass |
  | 22 | opens level 4; **padding** | pass |
  | 84 | level 4 almost full | pass |
  | 85 | fills levels 1–4 (boundary 85) | pass |
  | 86 | opens level 5; **padding** | pass |

  3.8 `mix_in_active_fields` (LSB-first `pack_bits`; widths 3/4/13; all-ones + sparse bit-0-clear):

  | width | pattern | libssz vs SPEC |
  |---:|---|---|
  | 3 | all_ones | pass |
  | 3 | sparse_bit0_clear | pass |
  | 4 | all_ones | pass |
  | 4 | sparse_bit0_clear | pass |
  | 13 | all_ones | pass |
  | 13 | sparse_bit0_clear | pass |
