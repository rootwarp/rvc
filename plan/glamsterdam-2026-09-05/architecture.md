# Software Architecture: rs-vc Gloas (Glamsterdam) Readiness

## Principles

- rs-vc signs; it is never a beacon node and never a builder.
- Every signing root is KAT-anchored to an external oracle before the code producing it ships.
- Fork behaviour is configuration; fork *shape* is code. Unknown fork/domain/type/version fails closed.
- Two SSZ stacks may coexist, but only across a crate boundary that carries `[u8;32]` and nothing else.
- A young dependency may compute a root only where an official vector proves that root.
- No root constant without machine-checkable provenance (source tag, generator version, input digest).

## System Context

```
 rvc-config + BN /eth/v1/config/spec (two-source) ──▶ ┌──────────────────────────┐
                                                  │  rs-vc (single binary)   │
 beacon node(s) ◀── eth/v1|v2|v4 REST ──────────▶ │ duties · roots · signing │ ──▶ slashing DB
                                                  └───────────┬──────────────┘
 consensus-specs releases + eth-ssz-specs               remote signer / Web3Signer / DVT cluster
   └─ vectors ─▶ crates/rvc-spec-vectors (dev/CI) ─codegen─▶ spec_kat.rs
```

## Module Overview

| Module (crate) | Responsibility | Owns data | Depends on | Comms |
|---|---|---|---|---|
| `fork-identity` (`eth-types::fork`) | Resolve fork name/version/activation epoch from a schedule | `ForkName`, `ForkSchedule` | — | sync fn |
| `legacy-ssz` (`eth-types`) | All non-progressive containers + roots on `tree_hash` 0.9, incl. the new **plain** Gloas families | pre-Gloas + plain-Gloas types | `fork-identity` | sync fn |
| **`gloas-ssz` (`rvc-gloas`, new)** | Progressively-merkleized Gloas containers; exports roots only | Gloas container defs, `ACTIVE_FIELDS_*`, `SPEC_TAG` | `legacy-ssz` | sync fn → `Root` |
| `spec-vectors` (`rvc-spec-vectors`, new, dev-only) | Fetch/verify official vectors, emit `spec_kat.rs`, run `ssz_static` | vector cache (gitignored) | `eth-types`, `rvc-gloas` (dev) | offline codegen |
| `signing` (`crypto`) | Domain table, `compute_signing_root`, typed/composite signer | domain constants | `eth-types` | sync fn |
| `signer-wire` (`signer-server`, `remote-signer-client`, `web3signer-wire`) | Sign type/version negotiation, sign plan, DVT partial signing | sign-type enum, DVT session | `signing`, `slashing` | HTTP/gRPC |
| `bn-api` (`beacon`) | Typed beacon-API client incl. Gloas endpoints | — | `eth-types` | HTTP |
| `bn-failover` (`bn-manager`) | Per-endpoint BN health, fork-capability gating, idempotency class | BN health state | `bn-api` | sync |
| `duties` (`duty-tracker`) | Fetch/cache/reorg-check/schedule all duties incl. PTC | duty cache, dependent roots | `bn-failover` | sync |
| `attest-path` (`rvc::orchestrator`) | Attest/aggregate/PTC/preferences orchestration per slot | in-flight duty state | `duties`, `gloas-ssz`, `signing` | in-proc + HTTP |
| `proposal` (`block-service`, `builder`) | `produceBlockV4` flow, `BuilderConfig`, publish | in-flight proposal | `bn-failover`, `gloas-ssz`, `signing` | sync |
| `slashing` (`slashing`) | EIP-3076 record + check; FU-33 leniency gate | slashing DB | `eth-types` | sync, DB-owning |
| `timing-config` (`timing`, `rvc-config`) | `SLOT_DURATION_MS` + every `*_DUE_BPS` from config | resolved deadlines | — | sync fn |

## Module Dependency Graph

```
  spec-vectors ┄dev┄▶ rvc-gloas ─┐                    (no runtime edge)
                                 ▼
  timing-config      rvc-gloas ──▶ eth-types(fork+legacy-ssz) ◀── crypto ◀── signer-wire ─▶ slashing
        │                ▲                                          ▲
        │                ├──── proposal (block-service, builder) ───┤
        └──────────────▶ attest-path ──▶ duties ──▶ bn-failover ──▶ bn-api
```

No circular dependencies. `rvc-gloas` has exactly one workspace out-edge (`rvc-eth-types`, a pinned
sink), so every edge into it is provably acyclic. `rvc-eth-types` keeps zero workspace out-edges;
`build_edge_map` filters on `dep["path"]` (`architecture-tests/src/lib.rs:218`), so external deps are
uncounted and **in**-edges are unconstrained. `block-service → builder` stays in `FORBIDDEN_EDGES`.
No events; the VC is request/response and no bus is introduced.

## Module Details

### `gloas-ssz` — `crates/rvc-gloas` (package `rvc-gloas`), the merkleization island

- **Responsibility:** declare every container progressively merkleized at Gloas and return its root as
  `Root = [u8;32]`. Nothing else leaves the crate.
- **Entities, partitioned by merkleization class** (this partition *is* the test policy, ADR-004):

| Set | Containers | Tests |
|---|---|---|
| (a) progressive container at Gloas | `Attestation` (w=4), `IndexedAttestation` (w=3), `BeaconBlockBody` (w=13), `PayloadAttestation` (w=3), `ExecutionRequests` (w=5, two new fields), `AggregateAndProof` closure, **`ExecutionPayloadEnvelope` (w=5, signed by the proposer on self-build — D20) with its embedded `ExecutionPayload`** | KAT only |
| (b) plain container, progressive closure | `AttesterSlashing` (children are progressive) | KAT only |
| (c) fully unmodified closure, re-declared | `Eth1Data`, `AttestationData`, `ProposerSlashing`, `Deposit`, `SignedVoluntaryExit`, `SyncAggregate`, `SignedBlsToExecutionChange`, `DepositRequest`, `WithdrawalRequest`, `ConsolidationRequest`, `BuilderDepositRequest`, `BuilderExitRequest` | KAT + differential vs `tree_hash` 0.9 |

  Embed-only (merkleized, never signed): `ExecutionPayloadBid` / `SignedExecutionPayloadBid`, and
  `ExecutionPayload` inside the envelope — the island never exports an `ExecutionPayload` root on its
  own. Out of scope: `BeaconState` (no `beacon_state.rs` exists in `eth-types`, so rs-vc never
  computes a state root).
- **Data store:** none. **Events:** none.
- **Public API** (the whole surface — no Gloas type is public):

| Item | In | Out |
|---|---|---|
| `roots::gloas_block_root(&HeaderFields, body_ssz: &[u8])` | header leaves + body bytes | `Result<Root, GloasError>` |
| `roots::gloas_body_root(body_ssz: &[u8])` | body bytes | `Result<Root, GloasError>` — the header leaf for the gRPC header RPC (D27) |
| `roots::gloas_execution_payload_envelope_root(&[u8])` | envelope SSZ | `Result<Root, GloasError>` — self-build signing object (D20) |
| `roots::gloas_aggregate_and_proof_root(&[u8])` | aggregate SSZ | `Result<Root, GloasError>` |
| `roots::gloas_attestation_root` / `..._indexed_attestation_root` | SSZ bytes | `Result<Root, GloasError>` |
| `merkle::{merkleize_progressive, mix_in_active_fields}` | chunks / root+bits | `Node` (crate-internal + differential tests) |
| `SPEC_TAG`, `ACTIVE_FIELDS_*` | — | `&'static str`, `&'static [bool]`, KAT-pinned |

- **Internal layout:** `containers/` (`#[derive(SszEncode, SszDecode, HashTreeRoot)]`
  `#[ssz(progressive_container, active_fields=[…])]`) · `merkle.rs` (the only libssz-primitive call
  site, ADR-007) · `roots.rs` · generated `spec_kat.rs`.
- **Decisions:** ADR-001, ADR-002, ADR-003, ADR-004, ADR-007.
- **Failure modes:** undecodable body → `GloasError::InvalidBody`; `active_fields` width mismatch →
  `GloasError::ActiveFieldsWidth`. Never a zero, guessed, or fallback root — a seam `Err` drops the
  duty. Progressive lists are unbounded, so the "overflows chunk tree" class of
  `bitlist_tree_hash_root` cannot occur here.

### `fork-identity`

`ForkName::Gloas` (`id() == 7`, `0x07000000`) and `gloas_fork_{epoch,version}` on the **flat**
`ForkSchedule` — `rvc-config` and `rvc-keygen` build it by field name, so reshaping the struct has a
far larger blast radius than widening the getter. `BodyForkLayout::Gloas` exists as a **typed error**
arm, not a decoder: `block.rs:365-375` wires `impl_container_tree_hash!(BeaconBlock, "valid
Electra/Deneb BeaconBlockBody SSZ…", body_auto = …)`, whose `body_tree_hash_root` tries Electra then
Deneb and is `expect()`ed, so a Gloas body panics the proposer path today. `extract_blob_kzg_commitments`
must **error** on that arm, never return `Ok(vec![])`, which would silently disable the L-3
blob-binding control.

### `signing` (`crypto`) — changed, but no Gloas type and no libssz edge crosses in

Adds `DOMAIN_PTC_ATTESTER 0x0C000000` and `DOMAIN_PROPOSER_PREFERENCES 0x0D000000` to the domain table
and to `test_all_domains_are_unique` — domains stay in **one** table here, never in the seam, or the
uniqueness invariant splits. Adds `DutyRef::{PtcAttestation, ProposerPreferences}` over plain
`eth-types` containers via the existing `compute_signing_root<T: TreeHash>`; PTC resolves its fork
version at `epoch_of(data.slot)`. `DOMAIN_BUILDER_DEPOSIT 0x0E000000` gets no arm. `DOMAIN_BEACON_BUILDER
0x0B000000` gets **one** root-based arm, `DutyRef::ExecutionPayloadEnvelopeRoot { root, slot }`, used
only for the self-build envelope the spec verifies against the proposer's key (ADR-010, D20);
`DOMAIN_BUILDER_REQUEST_AUTH 0x0B000001` (builder-specs) gets `DutyRef::BuilderRequestAuth` on the
`BuilderRegistration` idiom (ADR-011, D21). A root-based `DutyRef::AggregateAndProofRoot` and a
`sign_block_header` variant carrying the five header leaves (D22) complete the Gloas set. Gloas blocks and aggregates reach signing as `Root` through the pre-existing
`DutyRef::BlockRoot { root, slot }` / `PlanInput::{Block, AggregateAndProof} { object_root }` idiom —
`compute_signing_root` over a `Root` is the identity HTR (`crypto/src/signing.rs:219`), so **no
`tree_hash` bridge for Gloas types exists anywhere**. A missing domain arm is a compile error.

### `signer-wire`

New `PlanInput::PayloadAttestation { object_root, fork_version, gvr }` and `::ProposerPreferences
{ … }`, both `Slashing::NonSlashable` with new `NonSlashableOp` arms — `object_root` is the existing
idiom (`sign_plan.rs:78-102`), so **`SIGNER_SERVER_ALLOWED_EDGES` does not widen**. The
`{"version","data"}` wrapper is modelled generically; an unknown `type` **or** `version` is a hard
reject. HTTP 400 stays a transient bad-request class, never a permanent `unsupported_sign_type` —
that would poison a key on a serialization bug. DVT agreement is limited to the **planned root and
fork version**: `signer-server` has no chain edge, so peers cannot independently observe
`payload_present`/`blob_data_available`. The requester owns that observation and it is bound into
the root the peers sign; partials disagreeing on planned root or fork version are never aggregated. Failure: signer lacks a Gloas type → duty dropped,
metric raised, startup capability probe errors with operator-actionable text.

### `attest-path` — the shape-invisible change

`attestation.data.index` is repurposed at Gloas to payload EMPTY(0)/FULL(1). rs-vc has no payload
view; the BN supplies it. **The requirement is preservation, not computation**, and rs-vc breaks it
today: `orchestrator/utils.rs:143-145` zeroes `data.index` for `fork_name >= ForkName::Electra`, and
`orchestrator/attestation.rs:414-416` re-zeroes it on the submitted `SingleAttestation`. Gloas is
`>= Electra`, so both sites destroy the payload-status bit. EIP-7549 zeroing must be gated to
`Electra..Gloas`; at Gloas the BN value passes through verbatim on **both** the signing and the
submission path, or the signature covers data the network never sees.

## Crate-by-Crate Change Map

| Crate | Change | Failure mode when wrong |
|---|---|---|
| `eth-types` (`fork.rs`) | `ForkName::Gloas`; `entries() -> [_; ForkName::COUNT]` from one table (P0-2 + P2-2 together). Ripple: `entries()` at `fork.rs:67`, `ALL: [Self; 7]` at `:130`, the reverse-scan test at `:482-490`, `ssz_helpers` `0u32..=6` fork-id loops, and `rvc-keygen`, which owns the EIP-7044 `exit_cap_schedule` path — exits must stay Capella-capped however many post-Capella entries sit at `u64::MAX` | Wrong fork version ⇒ wrong domain ⇒ slashing |
| `eth-types` (`ssz_helpers.rs`) | `validate_fork_id` must **explicitly reject** fork id 7 — preserved, not inherited; its decoders are fixed pre-Electra layouts | Gloas bytes fed into the `BodyForkLayout` panic |
| `eth-types` (`block.rs`, `block_body.rs`) | `BodyForkLayout::Gloas` typed-error arm; `extract_blob_kzg_commitments` errors on it | Proposer-path panic; silently disabled blob binding |
| `eth-types` (new plain containers) | `PayloadAttestationData/Message`, `ProposerPreferences`/`Signed…`, `PtcDuty` on `tree_hash` 0.9 | — |
| **`rvc-gloas`** (new) | The island (above). New `CLASSIFICATION` row (Base); regenerate `ARCHITECTURE.md` | Every Gloas root wrong |
| **`rvc-spec-vectors`** (new, dev) | Vector fetch/parse, `spec_kat.rs` codegen, `ssz_static` runner | KAT-first policy unmet |
| `crypto` | Four domains (`PTC_ATTESTER`, `PROPOSER_PREFERENCES`, `BUILDER_REQUEST_AUTH`; `BEACON_BUILDER` gains its single self-build arm) + uniqueness rows; `DutyRef::{PtcAttestation, ProposerPreferences, BuilderRequestAuth, AggregateAndProofRoot, ExecutionPayloadEnvelopeRoot}`; PTC epoch rule; exit-cap re-verification | Wrong domain ⇒ slashing |
| `beacon` | ptc duties, `payload_attestation_data` (204 ⇒ no duty), `pool/payload_attestations` (POST), `proposer_preferences`, `builder_preferences` (`BuilderPreferencesEntry[]` with signed request auth, D21), proposer-duties v2 **at Gloas only** and node-version v2 with v1 fallback (D25), `POST /eth/v4/validator/blocks/{slot}` + required `BuilderConfig` returning `BeaconBlock` **or** `BlockContents`, `POST /eth/v1/beacon/execution_payload_envelopes` with `Eth-Blob-Data-Included: true` (D20), `Eth-Builder-Url` echo; `Eth-Consensus-Version` required on requests and **fail-closed** on responses (`client.rs:433`, `:554` fail open today) | Misparsed fork ⇒ wrong container signed |
| `bn-manager` | Per-endpoint health on unrecognised fork or missing `/eth/v4`; block production is a **sequential failover** class (retry on connect/timeout/5xx, never after a 2xx) and **sign + publish** is the single-flight, slashing-DB-gated boundary (ADR-008 as amended, D29) | Silent degrade; missed proposal on a single slow BN |
| `duty-tracker` | `PtcDuty {pubkey, validator_index, slot}` on the existing duty contract, reorg-checked by re-fetching the duties endpoint and comparing `dependent_root` (no `head_v2` SSE event exists — the check mirrors the proposer path); no PTC aggregation duty | Missed PTC duty |
| `rvc::orchestrator` | Gate EIP-7549 index zeroing to `Electra..Gloas` (both sites); PTC + preferences duty flows; aggregate root via `rvc-gloas` | Payload status destroyed ⇒ on-chain slashable |
| `signer-server`, `remote-signer-client`, `web3signer-wire` | `PlanInput`/`NonSlashableOp` arms for PTC, preferences, request auth and the self-build envelope; `{version,data}` wrapper; fail closed on type **and** version; 400 stays transient. **Gloas block and aggregate over the HTTP wire are deferred (D19)** and rejected with a typed error | Key poisoning or wrong-domain signature |
| `signer` (`SignerService`), `grpc-signer` | **Typed facade (D22):** gRPC keys route through `TypedSigner` inside the enablement / slashing / timeout envelope — today `CompositeSigner::sign` rejects them and no production caller reaches `get_grpc_remote`; `sign_block_header` variant; fork-aware routing to 4.20a's header and root RPCs | gRPC keys sign nothing through the VC |
| `block-service`, `builder` | V4 production flow, `BuilderConfig`, `Eth-Execution-Payload-Included`; blinded path becomes pre-Gloas-only; **self-build:** sign block → publish → sign `ExecutionPayloadEnvelope` → publish with blobs before `payload_due_bps` (D20); **builder win:** echo `Eth-Builder-Url`, publish nothing else; per-slot `SignedBuilderRequestAuth` for every configured builder and `builder_preferences` submission (D21); `SignedProposerPreferences` broadcast supersedes `prepare_beacon_proposer` + `register_validator` | Missed proposal; payload never revealed; stale fee recipient |
| `slashing` | PTC + preferences never written (no spec container); gate the `(None,None) if !strict` arm (`db/mod.rs:256-263`, FU-33) for Gloas epochs | Double vote via `index` 0 vs 1 deduplicated away |
| `timing`, `rvc-config` | `SLOT_DURATION_MS` + all six `*_DUE_BPS*` from runtime config, none hardcoded | Missed deadline (attestation tightens to 25%) |
| `validator-store` (beyond 6.1's builder accessors), `doppelganger`, EIP-3076 interchange schema | **No change** — listed so unchanged is distinguishable from unlisted. `grpc-signer` **is** changed (D11, D22 — row above) | — |

## Cross-Cutting Concerns

- **Fork dispatch:** container variant *and* signing domain are selected by one predicate —
  `ForkName::from_epoch(epoch, schedule)` compared against `ForkName::Gloas` — resolved once per duty
  and threaded down. **Never** by `body_layout().is_none()`, by decode failure, by container shape, or
  by inference from a response header. The absence of a layout is never the guard.
- **Auth:** unchanged (mTLS/token to signer; BN auth per existing config). No new trust boundary.
- **Observability:** resolved fork + next activation epoch (P2-1), PTC submission rate, per-endpoint
  BN capability state, signer rejections by type/version.
- **Errors:** `thiserror` per crate, `anyhow` at binaries; every fork/domain/type error names the
  offending value. Fail-closed everywhere; no fallback signing.
- **Configuration:** fork epochs/versions and every deadline from `rvc-config`, cross-checked against
  BN `/eth/v1/config/fork_schedule`; missing or unknown values are actionable errors.
- **Test policy (`kat_policy.rs`):** every island container gets a `SPEC_GLOAS_<TYPE>_ROOT` assertion;
  set (c) additionally gets a libssz-vs-`tree_hash`-0.9 differential carrying `// kat_exempt:
  cross-implementation differential, not a spec-root assertion`. **Zero new `EXEMPTIONS` entries.**
- **Stack purity:** *containment* is compiler-enforced (`crypto`/`signer-server` do not depend on
  `rvc-gloas`, so no Gloas type can reach them). Purity *inside* `rvc-gloas` is not — both stacks are
  in its graph because set-(c) differentials need eth-types' `tree_hash` 0.9 types. A hand-rolled scan
  in `architecture-tests` (the `no_rvc_prefix.rs` idiom, no new dependency) asserts no
  `tree_hash::`/`ssz::`/`ssz08::` import outside `#[cfg(test)]` in that one small crate.

## Data Flows

```
PTC duty (plain containers — never touches the island)
  duties POST duties/ptc/{epoch} ─▶ timing PAYLOAD_ATTESTATION_DUE_BPS 7500 fires
  bn-api GET payload_attestation_data?slot= (204 ⇒ skip, no fallback)
  legacy-ssz htr(PayloadAttestationData) ─▶ signing(DOMAIN_PTC_ATTESTER, epoch_of(data.slot))
  signer-wire ─▶ POST pool/payload_attestations              [slashing DB untouched]

Gloas block proposal (island on the body leaf only)
  proposal POST /eth/v4/validator/blocks/{slot} + BuilderConfig ─▶ body SSZ
  gloas-ssz::roots::gloas_block_root(header, body_ssz) ─▶ Root
  signing DutyRef::BlockRoot ─▶ slashing check/record ─▶ signer-wire ─▶ POST blocks/v2 (+Eth-Builder-Url)

Self-build proposal (D20 — the only place the VC signs under DOMAIN_BEACON_BUILDER)
  produceBlockV4 include_payload=true ─▶ BlockContents { block, execution_payload_envelope, blobs, kzg_proofs }
  gloas_block_root ─▶ sign block ─▶ publish block (bare SignedBeaconBlock)
  gloas_execution_payload_envelope_root(envelope_ssz) ─▶ signing(DOMAIN_BEACON_BUILDER, epoch_of(slot))
  ─▶ POST execution_payload_envelopes  Eth-Blob-Data-Included: true  (envelope + blobs + proofs from the SAME response)
  Builder win ⇒ bare BeaconBlock; echo Eth-Builder-Url on publish; the builder releases its own envelope.

Attest / aggregate (root moves; shape does not)
  bn-api attestation_data ─▶ index PRESERVED at Gloas (7549 zeroing gated to Electra..Gloas)
  attest-path signs AttestationData via legacy-ssz; aggregate root via gloas-ssz (progressive)
  ─▶ signing(DOMAIN_AGGREGATE_AND_PROOF) ─▶ signer-wire ─▶ submit with the SAME index value
```

## Infrastructure

Single-process VC; deployment, topology and scaling unchanged (PTC adds one signature per assigned
validator per slot). The 25%-of-slot attestation deadline is the new latency constraint; benchmark
against the pre-change baseline.

| Module | Extraction readiness |
|---|---|
| `rvc-gloas`, `rvc-spec-vectors` | ready now — one out-edge / dev-only; swappable or deletable in one Cargo edit |
| `fork-identity` + `legacy-ssz` | keep together — both are `eth-types`, a pinned zero-out-edge sink |
| `attest-path` | needs work — shares the orchestrator slot context |
| all other modules | ready now (already separate crates) |

## Technology Choices

| Concern | Choice | Rationale |
|---|---|---|
| EIP-7916 progressive merkleization | `libssz-merkle =0.3.0` `merkleize_progressive` | source-verified: empty ⇒ `[0u8;32]`, growth ×4, subtree left / remainder right — matches the EIP text |
| EIP-7495 progressive container | `libssz-derive =0.3.0` `#[ssz(progressive_container, active_fields=[…])]` | `mix_in_active_fields = hash_nodes(root, pack_bits(bits))`, LSB-first, verbatim EIP-7495 |
| Unbounded lists/bitlists | `libssz-types =0.3.0` `ProgressiveList` / `ProgressiveBitlist` | no limit parameter survives under EIP-7916; deps are `libssz` + `libssz-merkle` + `smallvec` only |
| Gloas SSZ ser/de | `libssz =0.3.0` `SszEncode`/`SszDecode` | one self-consistent stack inside the island; never mixed with `ethereum_ssz` traits |
| Features | `default-features = false, features = ["sha2"]`; **never** `ethereum-types` | `sha2` is an optional normal dep supplying the hasher and unifies with the workspace `sha2` 0.10; `ethereum-types ^0.15` would pull `primitive-types` 0.13 beside 0.12.2. Assert with `cargo tree -d` in CI |
| Non-Gloas containers | unchanged `tree_hash` 0.9 / `ethereum_ssz` 0.9 + `ssz08` 0.8.3 / `ssz_types` 0.10.1 | **no workspace-wide upgrade required** — ADR-001 |
| Container / primitive vectors | consensus-specs releases ≥ `v1.7.0-alpha.12`; `eth-ssz-specs` 0.1.0 | `consensus-spec-tests` is archived; `roots.yaml` is a literal HTR; only eth-ssz-specs ships progressive vectors |
| Signing-root vectors | self-generated with recorded provenance | no official runner covers `compute_signing_root`/`compute_domain`/`get_domain` |

## KAT / Test-Vector Pipeline

`rvc-spec-vectors` is integration-only (dev-deps `snap`, `serde_yaml`, `hex`, `sha2`); it cannot live
in `architecture-tests`, whose P6 rule bars external deps. Vectors gitignored, fetched by `make
spec-vectors`, CI cache keyed on the pinned tag; `minimal` in CI, `mainnet` nightly.

| Layer | Source | Artifact | Closes |
|---|---|---|---|
| L1 primitive | `eth-ssz-specs` 0.1.0 | `SPEC_PROGRESSIVE_*` at chunk counts 0,1,2,4,5,6,20,21,22,84,85,86 (boundaries 1/5/21/85) | child order, ×4 growth, empty case, bitlist packing — **this is the ADR-001 gate** |
| L2 containers | consensus-specs `ssz_static/**/roots.yaml` | `SPEC_GLOAS_<TYPE>_ROOT` | `active_fields` width/order; misclassified sets |
| L3 signing roots + domains | self-generated from pyspec, provenance recorded | `KAT_GLOAS_<OBJ>_SIGNING_ROOT` | no official runner exists |
| L4 behavioural | in-tree | `data.index` 0/1 BN→signature→submission round-trip; fork-transition fixture BN | shape-preserving defects |
| L5 containment | in-tree | Gloas configured at the sentinel epoch ⇒ every existing signing-root test byte-identical | the NFR "behaves identically today" |

Generated `spec_kat.rs` carries source repo+tag, generator+version, input sha256 and date; the
generator reads vector files only, and reading any rs-vc-computed root is a build failure (ADR-005).

## Sequencing Seam

| Phase | Spec-content-**independent** (start now) | Spec-frozen (behind the M2 gate) |
|---|---|---|
| M1 | `entries()` widening + `ForkName::Gloas`; `SLOT_DURATION_MS`/`*_DUE_BPS` rename; config plumbing; `rvc-spec-vectors` + L1 vectors; **ADR-001 go/no-go gate**; the `data.index` zeroing gate (a bug today) | — |
| M2 | — | Gloas container declarations, `active_fields` tables, domains, duties, endpoints, L2–L4 |

EIP-7916/7495 are frozen even though the Gloas containers are not, so the primitive gate is M1 work.
PTC and proposer preferences are plain containers on the `tree_hash` 0.9 path (ADR-006) and therefore
do not wait on ADR-001 — only the proposal and aggregate paths do.

## ADRs

**ADR-001 · Adopt `libssz` 0.3.0 for Gloas merkleization · Accepted, confirmed-by-vector (2026-09-06, issue 3.11 / #241).** `libssz`, `libssz-merkle`,
`libssz-types`, `libssz-derive`, pinned `=0.3.0`, as external deps of `rvc-gloas`.
*Rationale:* source inspection of `libssz-merkle` 0.3.0 confirms `merkleize_progressive` returns
`[0u8;32]` on empty, recurses at `num_leaves * 4` with the subtree as the **left** child, and that
`mix_in_active_fields` is `hash_nodes(root, pack_bits(bits))` — the EIP text, not a doc string.
The P3 L1 gate (3.7/3.8) now matches those claims against the 3.4b pyspec oracle
(`SPEC_TAG=v1.7.0-beta.0`, `SSZ_SPECS_TAG=v0.1.0`, `gen-spec-kat` 0.7.0, Python 3.13.7,
`eth-ssz-specs==0.1.0` wheel sha256 `466c6cef854cca45022a7cdc3922dd636e30b1a1dd5385845819e3d45ddddf41`,
generated `roots.yaml` sha256 `6ead45d55e0b7512dd6fd05b30609d6c030ec0a0235cc37f5cffabf00a9ba401`,
ssz archive sha256 `e2a65f032b59835c26127295293ea1bc07d7ca0ea1fe0e4f1128dffed333f878`).
*Consequences:* the pinned `tree_hash` 0.9 / `ethereum_ssz` graph is untouched — `libssz-merkle`
depends only on `libssz`, `sha2` and an optional `ethereum-types`, with no `tree_hash` edge — so no
workspace-wide upgrade and no version churn. **L1 GO 2026-09-06:** all twelve `SPEC_PROGRESSIVE_*`
chunk counts pass (empty ⇒ `[0u8;32]`; left-subtree padding at 2/6/22/86, commits `64828c1` /
`660c265`); LSB-first `mix_in_active_fields` passes at widths 3/4/13. Phase 5.1 uses published
`libssz` primitives; ADR-007 is **not** opened. **Release gate:** no Gloas root ships without a
passing official vector. **Phase 4 is independent of this verdict** (plain `tree_hash` 0.9,
ADR-006). ADR-007 remains the escape hatch if a later re-pin fails; it does not move container
declarations or `active_fields` tables.

3.7 `merkleize_progressive` (`libssz-merkle` 0.3.0 vs `SPEC_PROGRESSIVE_*`):

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

3.8 `mix_in_active_fields` (LSB-first `pack_bits`; widths 3/4/13):

| width | pattern | libssz vs SPEC |
|---:|---|---|
| 3 | all_ones | pass |
| 3 | sparse_bit0_clear | pass |
| 4 | all_ones | pass |
| 4 | sparse_bit0_clear | pass |
| 13 | all_ones | pass |
| 13 | sparse_bit0_clear | pass |

**ADR-002 · Gloas SSZ is a new crate `rvc-gloas`, not a module in `eth-types` · Accepted.**
*Rationale:* the claim that a separate crate breaks `ZERO_OUT_EDGE_IF_PRESENT` is false —
`build_edge_map` filters on `dep["path"]` (`architecture-tests/src/lib.rs:218`), so in-edges to
`rvc-eth-types` are unconstrained. A crate makes containment compiler-enforced and keeps `eth-types`
single-stack. *Consequences:* one `CLASSIFICATION` row (Base), an `ARCHITECTURE.md` regeneration, and
~12 small containers declared twice — which ADR-004 turns into an oracle.

**ADR-003 · Re-declare the whole Gloas field closure; no inbound bridge · Accepted.** Never
`impl libssz::HashTreeRoot for <legacy type> { delegate to tree_hash }`.
*Rationale:* delegation compiles and silently yields a pre-Gloas root for `AttesterSlashing →
IndexedAttestation`, which *is* progressive at Gloas; `ExecutionRequests` is the same trap one level
down. *Consequences:* duplication bounded by ADR-004; and because the export is root-only there is no
outbound bridge either, so `#[derive(TreeHash)]` on a progressive body is structurally impossible.

**ADR-004 · Test policy follows the merkleization partition · Accepted.** Sets (a)/(b) get the
official `ssz_static` KAT only; set (c) gets KAT **plus** the `tree_hash` 0.9 differential.
*Rationale:* a differential against 0.9 fails by construction for progressive types, but proves the
re-declaration did not drift for unmodified ones. *Consequences:* `rvc-spec-vectors` must land before
any Gloas container is written; a container misclassified into set (c) is still caught by its own KAT.

**ADR-005 · Layered KAT pipeline with machine-checkable provenance · Accepted.** The generator reads
vector files only; reading an rs-vc-computed root is a build failure.
*Rationale:* `kat_policy.rs` checks constant *names*, not provenance — a self-referential generator
ships F122 again. *Consequences:* generator complexity; a build failure when vectors go stale.

**ADR-006 · PTC and proposer preferences ship on the `tree_hash` 0.9 path · Accepted.**
*Rationale:* `PayloadAttestationData`, `PayloadAttestationMessage` and `ProposerPreferences` are plain
`Container`s. *Consequences:* P0-9 is decoupled from the island and lands first, as the PRD requires.

**ADR-007 · The primitives are replaceable; the declarations are not · Accepted.** Every
libssz-primitive call sits in `gloas::merkle`.
*Rationale:* if the crate diverges or fails the L1 gate, reimplement `merkleize_progressive` +
`mix_in_active_fields` without touching container declarations or `active_fields` tables.
*Consequences:* exact `=0.3.0` pins, `--locked` builds, and a release gate that no Gloas root ships
without a passing official vector. **Amended (D24):** the fallback is a **vendored, patched
`libssz-merkle`** applied workspace-wide with `[patch.crates-io]`, because `libssz-types` and the
derive-generated code call `merkleize_progressive` directly (verified in the published 0.3.0
sources) — a wrapper swap inside `merkle.rs` would leave every list and derived container on the
unpatched primitive. Honest limit unchanged: a derive-macro *semantic* bug is not covered by a
primitive patch and triggers the 5.6–5.9 re-score.

**ADR-008 · Sign + publish is the single-flight boundary; production may fail over · Accepted, amended (D29).**
*Rationale:* producing a block is a beacon-node computation — the slashable event is *signing* two
blocks for one slot, which the slashing DB already gates; with D20 the block and its envelope come
from one `BlockContents` response and are used together, so consistency is by construction whichever
BN produced them. A single slow BN must not become a missed proposal. *Consequences:* `bn-manager`
gains a **sequential** `query_failover` for `produce_block_v4` (health-ordered, one in-flight, retry on
connect error / timeout / 5xx, never after a 2xx or a signer call; no parallel fan-out, so builders
see at most one authenticated bid request per BN tried), an explicit single-flight class for sign +
publish, and per-endpoint capability health.

**ADR-010 · The self-build execution payload envelope is VC-signed · Accepted (D20).** *Rationale:*
`verify_execution_payload_envelope_signature` expects the **proposer's** key when
`builder_index == BUILDER_INDEX_SELF_BUILD`, under `DOMAIN_BEACON_BUILDER`; the self-build bid is
`G2_POINT_AT_INFINITY` but the envelope is signed. *Consequences:* one `0x0B000000` arm in the sign
plan, root-based, non-slashable by spec but single-flight per slot; `ExecutionPayloadEnvelope` (w=5)
and its embedded `ExecutionPayload` join the island as set (a) with the envelope root as the only
export; the VC publishes with `Eth-Blob-Data-Included: true` so publication never depends on the
producing BN's cache. External-builder envelopes stay builder-signed.

**ADR-011 · Builder request auth is a proposer duty · Accepted (D21).** *Rationale:* every
`BuilderEntry` requires `auth: SignedBuilderRequestAuth`; builder-specs signs it with the proposer's
key under `DOMAIN_BUILDER_REQUEST_AUTH 0x0B000001`. *Consequences:* plain containers in `eth-types`,
a non-slashable `PlanInput` on the `BuilderRegistration` idiom, per-slot per-builder construction
from the `BuilderConfig` list, `builder_preferences` submission one epoch early; the domain value is
pinned from the cited builder-specs revision and the KAT fails if it moves.

**ADR-009 · Runtime fork gate, unconditional compilation · Accepted.** *Rationale:* a cargo feature
escapes default CI or trips `uncompiled_source.rs`. *Consequences:* Gloas compiles into every build
and must be provably inert pre-activation — that is L5.

## Open Questions

Assumptions recorded for this unattended run; nothing was asked of the user.

- Spec content read at `v1.7.0-beta.0`; every declaration and `active_fields` width (4/3/13) is
  re-verified at the M2 freeze gate and pinned by vectors, never derived in production code.
- Research conflicts on `Attestation.aggregation_bits` → `ProgressiveBitlist` vs unchanged `Bitlist`.
  **This does not change the architecture**: `Attestation` is a progressive *container* at Gloas
  either way, so the aggregate path enters the island regardless; only one field's root mechanism
  varies, and the island declares both. Resolve at freeze.
- `active_fields` is read as all-ones of width N; a genuinely sparse bitvector changes every root.
- Which body lists beyond the slashing lists become `ProgressiveList` (deposits, voluntary_exits,
  bls_to_execution_changes), and the shape of `parent_execution_requests` — both block M2 sizing.
- `CommitteeBits` is not redefined in `specs/gloas/beacon-chain.md`; assumed inherited
  `Bitvector[MAX_COMMITTEES_PER_SLOT]`. `BuilderDepositRequest`/`BuilderExitRequest` field lists were
  not read this run; confirm before KAT-ing `ExecutionRequests`.
- Does any column-sidecar surface remain VC-side? Is PTC duty *discovery* specified beyond the
  endpoint shape? Who owns mainnet-readiness sign-off? (currently unowned)

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| libssz semantics diverge from the frozen spec | Every Gloas root wrong; total duty loss | L1 vector gate blocks ADR-001 in M1; per-container `ssz_static` KAT as a release gate; ADR-007 escape hatch; exact `=0.3.0` pin |
| libssz abandoned or yanked (first published 2026-03-20) | Build breaks, or an unpatched bug in a root-gating dep | Vendorable MIT/Apache source, `--locked`; vendoring — not a 60-line rewrite — is the abandonment answer |
| `ethereum-types` feature enabled by accident | `primitive-types` 0.13 beside 0.12.2 | `default-features = false`; `cargo tree -d` assertion in CI |
| `data.index` zeroed at Gloas (**a bug today**) | Payload status destroyed; shape-preserving ⇒ green KATs; on-chain slashable | Gate EIP-7549 zeroing to `Electra..Gloas` at both sites; L4 round-trip test; FU-33 leniency fix |
| Self-referential vectors (F122 repeat) | Green tests assert the bug | ADR-005 provenance header; generator forbidden to read rs-vc roots; zero new `EXEMPTIONS` |
| Spec churn before freeze | Rework of container declarations | Churn lands only in `rvc-gloas` + `spec_kat.rs`; re-pin `SPEC_TAG` per release; treat a vector diff as a spec signal |
| `entries()` change ripples workspace-wide | Long-lived branch | M1's first change, mechanical, ahead of all Gloas content |
| Self-build envelope never revealed (D20) | Every self-built Gloas proposal lands an empty payload slot; execution rewards lost | 5.16 + 6.18–6.20 own sign + publish; 7.4 asserts it at the boundary; `payload_due_bps` is the publish deadline |
| gRPC keys cannot sign through the VC today (D22) | 100% duty loss for gRPC deployments, pre-Gloas included | 4.21 typed facade, not fork-gated; 4.20c's matrix proven on the VC path with a remote key |
| Signer or DVT peer lags the new sign types | Duties dropped day one (Web3Signer has no Gloas types) | Explicit rejection over silent fallback; startup capability probe; documented gap, no invented version |
