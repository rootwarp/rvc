# Forks — add-a-fork checklist

How rvc dispatches on consensus fork, and the work required to add the next one.

Fork identity is `ForkName`. Epoch → name → version is `ForkSchedule`. Blob-body SSZ is
`BodyForkLayout` (`body_layout` / `body_fork_layout`). Those three are the only fork
switches that may grow; everything else must call them.

Line numbers were opened on `develop` @ `bc1f63d`. Docs-freshness
(`crates/architecture-tests/tests/docs_freshness.rs`) checks every backticked
`crates/` / `bin/` / `plan/` / `docs/` path in this file. Put `file:line` *outside*
the backticks — a colon inside `` `…` `` is not a path token.

Operator keys for a Gloas-scheduled network: [gloas-upgrade.md](gloas-upgrade.md).

---

## 1. Dispatch sites

Eight `ForkName` variants, activation order: Phase0, Altair, Bellatrix, Capella,
Deneb, Electra, Fulu, Gloas (`crates/eth-types/src/fork.rs` 9–18, `ALL` at
149–158, `COUNT` = 8 at 161). Fulu is live on the schedule and on duty wire
tags; it **reuses the Electra body layout**. Gloas is a new
`BodyForkLayout::Gloas` (typed error; no decoder yet).

### 1.1 Source of truth — `ForkName` / `ForkSchedule`

| What | File | Lines | Role |
|---|---|---|---|
| `ForkName` enum | `crates/eth-types/src/fork.rs` | 9–18 | Sole fork identity. Exhaustive `match` sites fail to compile when a variant is added. Gloas is last. |
| `ForkSchedule` | `crates/eth-types/src/fork.rs` | 22–38 | Genesis version + epoch/version pair per post-genesis fork, including `gloas_fork_epoch` / `gloas_fork_version`. |
| `ForkSchedule::entries` | `crates/eth-types/src/fork.rs` | 99–110 | `[(ForkName, Epoch, Version); ForkName::COUNT]`, ascending, eight rows. **Array length is the fork count.** |
| `AsRef<str>` / `FromStr` | `crates/eth-types/src/fork.rs` | 113–133 | Lowercase BN `consensus_version` (`"electra"`, `"fulu"`, `"gloas"`). Case-sensitive; `"Gloas"` is `Err`. |
| `TryFrom<u32>` / `id` | `crates/eth-types/src/fork.rs` | 135–188 | Signer SSZ `fork_id` (Phase0=0 … Gloas=7). `8` is `UnknownForkIdError`. Exhaustive `id()` match is the fork-addition tripwire. |
| `ForkName::body_layout` | `crates/eth-types/src/fork.rs` | 195–202 | Deneb → `BodyForkLayout::Deneb`; Electra **and Fulu** → `Electra`; **Gloas → `Gloas`**; pre-Deneb → `None`. |
| `ForkName::from_epoch` | `crates/eth-types/src/fork.rs` | 208–216 | Reverse scan of `entries()`; equal activation epochs pick the latest fork. |
| `fork_version` / `activation_epoch` | `crates/eth-types/src/fork.rs` | 218–234 | Lookups through `entries()`. |
| BN `/eth/v1/config/spec` → schedule | `crates/beacon/src/types.rs` | 449–477 | `parse_fork_schedule`. Fulu **and Gloas** epoch/version are optional (`u64::MAX` / `[0xFF; 4]`). |

`from_epoch`, `fork_version`, `activation_epoch`, `SignContext::resolve`, and
`body_fork_layout` all go through `entries()` or `body_layout()`. Do not add a
parallel if-else on version bytes.

### 1.2 Body layout — `BodyForkLayout` / typed bodies

Three SSZ layouts exist for `BeaconBlockBody` (blob era). Electra added
`execution_requests` after `blob_kzg_commitments`; Fulu shares that layout.
Gloas is a third variant with **no decoder**: KZG extraction and layout HTR
return `BodySszError::GloasUnsupported` (never `Ok(vec![])`).

| What | File | Lines | Role |
|---|---|---|---|
| `BodyForkLayout` | `crates/eth-types/src/block.rs` | 19–26 | `Deneb` (12-field) / `Electra` (13-field; Fulu shares) / **`Gloas` (typed error)**. |
| `body_fork_layout` | `crates/eth-types/src/block.rs` | 36–42 | `ForkName::from_str(consensus_version).ok().and_then(ForkName::body_layout)`. `"gloas"` → `Some(Gloas)`. |
| `extract_blob_kzg_commitments` | `crates/eth-types/src/block.rs` | 57–73 | Layout → typed Deneb/Electra decoder. Empty list is `Ok(vec![])`; bad SSZ is `Err`; **Gloas is always `Err`**. |
| `BlockContents::kzg_commitment_root` | `crates/eth-types/src/block.rs` | 289–291 | Internal KZG fingerprint (not spec `hash_tree_root`). Takes `layout`. |
| `BeaconBlock::kzg_commitment_root` | `crates/eth-types/src/block.rs` | 357–359 | Same fingerprint on a bare block. |
| `try_tree_hash_root_for_layout` | `crates/eth-types/src/tree_hash_utils.rs` | 128–150 | Spec block HTR with an explicit layout (prefer this on proposal paths). |
| `BeaconBlockBodyElectra` | `crates/eth-types/src/block_body.rs` | 968 | 13-field full body. Comment: Fulu shares this layout. |
| `BlindedBeaconBlockBodyElectra` | `crates/eth-types/src/block_body.rs` | 1000 | Electra blinded (`ExecutionPayloadHeader`). |
| `BeaconBlockBodyDeneb` | `crates/eth-types/src/block_body.rs` | 1040 | 12-field full body; pre-Electra attestation limits. |
| `BlindedBeaconBlockBodyDeneb` | `crates/eth-types/src/block_body.rs` | 1072 | Deneb blinded. |
| `body_tree_hash_root_for_layout` | `crates/eth-types/src/block_body.rs` | 1159–1170 | Full-body leaf HTR, explicit layout. Gloas arm is `Err`. |
| `blinded_body_tree_hash_root_for_layout` | `crates/eth-types/src/block_body.rs` | 1173–1186 | Blinded leaf HTR, explicit layout. Gloas arm is `Err`. |
| Auto-detect HTR | `crates/eth-types/src/block_body.rs` | 1137–1156 | Electra decode first, then Deneb. Use only when `consensus_version` is unknown. |

Proposal path that already has the BN `consensus_version`:

| What | File | Lines | Role |
|---|---|---|---|
| SSZ `BlockContents` KZG bind | `crates/block-service/src/service/mod.rs` | 667–675 | `body_fork_layout` → `blob_kzg_count` / `kzg_commitment_root`. Fail-closed on bad SSZ. Skipped unless `ssz_block_format` returned `BlockContents`. |
| JSON `BlockAndBlobs` KZG bind | `crates/block-service/src/service/mod.rs` | 754–760 | Same `body_fork_layout` dispatch. |
| `ssz_block_format` | `crates/block-service/src/service/mod.rs` | 992–1014 | Exhaustive `match ForkName`. Blinded → always `BeaconBlock`. Unblinded Deneb/Electra/Fulu → `BlockContents`. **Named Gloas `BeaconBlock` arm** (bare `SignedBeaconBlock`; must not share a catch-all with pre-Deneb). Unknown version strings fail closed via `ForkName::from_str`. |
| `reject_blinded_at_gloas` | `crates/block-service/src/service/mod.rs` | 1018–1033 | Open-ended `>= Gloas` (slot fork or `consensus_version == "gloas"`) drops blinded production. |
| produceBlockV4 / v3 | `crates/block-service/src/service/mod.rs` | 307–320 | Slot fork `>= Gloas` calls `produce_block_v4` (`POST /eth/v4/validator/blocks/{slot}`); pre-Gloas stays `produce_block_v3` (`GET /eth/v3/validator/blocks/{slot}`). Dispatch is on the slot fork, never on response headers. |
| V4 HTTP | `crates/beacon/src/client.rs` | 643–693 | `produce_block_v4`; path prefix in `crates/beacon/src/v4_wire.rs` 13. Pre-Gloas v3 is 526. |
| V4 sign/publish | `crates/block-service/src/service/mod.rs` | 367–398 | Slot fork `>= Gloas` uses `sign_and_publish_v4`; pre-Gloas keeps V3 blinded/unblinded. |

### 1.3 Duty and signing dispatch

These sites branch on `ForkName` (or `fork_id = ForkName::id()`). They must not grow a
private fork table.

EIP-7549 committee-index **zeroing is bounded** `Electra..Gloas` (half-open:
Electra and Fulu zero; Gloas preserves the BN-supplied `index`, which is the
payload-status bit). Electra+ **wire shape** (`SingleAttestation`, committee-index
query, Electra aggregate) is open-ended `>= Electra` so Gloas keeps that shape.

EIP-7044 voluntary-exit Capella cap stays open-ended `>= Capella` **by design**
(`crates/crypto/src/signing_root.rs` 299–303 `capella_capped_fork_version`, test
mirror at 350). Gloas must inherit the cap; do not switch that `>=` to `== Capella`
or to `Electra..Gloas`.

| What | File | Lines | Role |
|---|---|---|---|
| Attestation fork + EIP-7549 | `crates/rvc/src/orchestrator/attestation.rs` | 319–320, 412–431 | `from_epoch(target_epoch)`; Electra+ → `SingleAttestation`; exact fork picks `VersionedAttestation::{Electra,Fulu,Gloas}` (not `>= Fulu`). Zeroing only if `zeroes_committee_index`. |
| Versioned BN wire enums | `crates/beacon/src/types.rs` | 76–99 | `VersionedAttestation` / `VersionedAggregateAttestation` / `VersionedSignedAggregateAndProof` — compile-forced grow-set, each with a **Gloas** arm. |
| Submit `Eth-Consensus-Version` | `crates/beacon/src/client.rs` | 1403–1413, 1174–1199 | Maps those enums to `"phase0"` / `"electra"` / `"fulu"` / **`"gloas"`**. |
| Aggregate fork + submit tag | `crates/rvc/src/orchestrator/aggregation.rs` | 84–99, 136–156, 367–372 | Exact Electra/Fulu/Gloas split for the submit tag; `>= Gloas` uses the island root (`sign_and_wrap_gloas`). |
| EIP-7549 index zeroing | `crates/rvc/src/orchestrator/utils.rs` | 134–136, 162–164 | `zeroes_committee_index`: **`(Electra..Gloas).contains(&fork)`**. Assignment at 163. Shared by attestation and aggregation. |
| Electra+ attestation wire | `crates/rvc/src/orchestrator/utils.rs` | 143–145 | `uses_electra_attestation_wire`: open-ended `>= Electra` so Gloas keeps `SingleAttestation`. Not the zeroing predicate. |
| Domain / signing root | `crates/crypto/src/signing_root.rs` | 264–266 | `fork_version_at` = `from_epoch` → `fork_version`. |
| EIP-7044 Capella cap | `crates/crypto/src/signing_root.rs` | 299–303, 350 | Voluntary-exit domain stays on Capella after Capella. **Definition** is `capella_capped_fork_version`. Open-ended `>= Capella` by design (EIP-7044). |
| Keygen EIP-7044 schedule | `bin/rvc-keygen/src/network.rs` | 22–39 | `exit_fork_schedule`: Capella at epoch 0, post-Capella (including Gloas) at `u64::MAX`. Production keygen signs via `sign_voluntary_exit` → `signing_root_for`. |
| Keygen exit cap (test only) | `bin/rvc-keygen/src/exit.rs` | 106–107 | Re-implements the Capella cap inside `#[cfg(test)]` `test_exit_round_trip_encrypt_decrypt_sign`. Not the production definition. Same open-ended `>= Capella`. |
| `SignContext` | `crates/crypto/src/typed_signer.rs` | 36–42, 55–78 | Carries resolved `ForkName`. `resolve` matches `fork_info.current_version` against `entries()`; **no silent Deneb default**. |
| gRPC `fork_id` | `crates/grpc-signer/src/client.rs` | 268–270 | `ctx.fork_name.id()`. |
| gRPC Gloas RPC | `crates/grpc-signer/src/client.rs` | 272–274 | `uses_gloas_rpc`: open-ended `>= Gloas` keeps header/root RPCs. |
| `validate_fork_id` | `crates/eth-types/src/ssz_helpers.rs` | 304–321 | **Not** `ForkName::try_from`. Allowlist `DECODER_SUPPORTED_FORK_IDS = 0..=6` (Phase0…Fulu). Gloas id 7 is `Ok` on `ForkName::try_from` and **rejected here** so Gloas SSZ never reaches these pre-Electra layouts. Encoders ignore `fork_id`. |
| `decode_attestation_ssz` | `crates/eth-types/src/ssz_helpers.rs` | 179–218 | Always pre-Electra three-field layout. Electra-shaped buffers → `ElectraLayoutUnsupported` (81, 204, 217), never a wrong `Attestation`. |

Gloas production dispatch that is not a duty-wire enum (every site; class
inventory in [gloas-fork-hazard-audit.md](gloas-fork-hazard-audit.md)):

| What | File | Lines | Role |
|---|---|---|---|
| Proposer-duties v1/v2 | `crates/beacon/src/client.rs` | 482–490 | `>= Gloas` → `/eth/v2/validator/duties/proposer/{epoch}`. No silent v1 fallback. |
| produceBlockV4 / v3 | `crates/block-service/src/service/mod.rs` | 307–320 | `>= Gloas` → `produce_block_v4` (`POST /eth/v4/validator/blocks/{slot}`); else `produce_block_v3` (`GET /eth/v3/validator/blocks/{slot}`). HTTP in `crates/beacon/src/client.rs` 526 / 643; path prefix `crates/beacon/src/v4_wire.rs` 13. |
| Deadline set | `crates/timing/src/clock.rs` | 29–35 | `DeadlineSchedule::for_fork`: `>= Gloas` selects the six Gloas `*_DUE_BPS*` offsets. |
| Coordinator attestation offset | `crates/rvc/src/orchestrator/coordinator/mod.rs` | 131–142, 479–480 | `from_epoch` then `for_fork`; one resolved fork per slot. |
| PTC phase | `crates/rvc/src/orchestrator/coordinator/mod.rs` | 1219–1250 | `run_payload_attestation_phase`: open-ended `>= Gloas` waits then calls `crates/rvc/src/orchestrator/payload_attestation.rs`. |
| Legacy proposer ops | `crates/builder/src/service.rs` | 26–28 | `legacy_proposer_ops_retired`: `>= Gloas` retires `prepare_beacon_proposer` / `register_validator`. |
| Signer header RPC | `crates/signer/src/lib.rs` | 953 | `>= Gloas` uses `SignBlockHeader` (no Gloas body SSZ into a legacy decoder). |
| Signer aggregate RPC | `crates/signer/src/lib.rs` | 1229, 1283 | `>= Gloas` rejects legacy `sign_aggregate_and_proof` / `sign_electra_aggregate_and_proof` (`UnsupportedDuty`); Gloas signs via the root RPC (`sign_aggregate_and_proof_root` 1248). |
| Typed-signer aggregate reject | `crates/crypto/src/typed_signer.rs` | 342, 361 | Same `>= Gloas` `UnsupportedDuty` on the local typed path. |
| DVT peer Gloas RPC | `crates/signer-server/src/dvt/peer_client.rs` | 204 | Same open-ended `>= Gloas` as the gRPC client. |

### 1.4 SEC-9 fail-closed startup gate

Unknown head fork version is fatal by default (exit 13). Named opt-out only.
Two-source Gloas schedule reconciliation (D12) is a separate fail-closed gate with **no** opt-out.

| What | File | Lines | Role |
|---|---|---|---|
| `EXIT_UNSUPPORTED_FORK_VERSION` | `crates/rvc/src/startup.rs` | 31 | Exit code 13. |
| `StartupError::UnsupportedForkVersion` | `crates/rvc/src/startup.rs` | 43–44 | `"unsupported consensus fork version {version}; upgrade rvc"`. |
| `check_fork_compatibility` | `crates/rvc/src/startup.rs` | 172–198 | Head `current_version` must be in the eight schedule versions (includes `gloas_fork_version` at 189). |
| Apply + opt-out | `crates/rvc/src/bootstrap/services.rs` | 64–82, 173–176 | Fatal unless `allow_unsupported_fork`. Do not weaken `check_fork_compatibility`. |
| CLI / config knob | `crates/rvc-config/src/sections/safety.rs` | 79–84 | `--allow-unsupported-fork`. Testnets / experimental forks only. |
| Fail-closed integration test | `bin/rvc/tests/integration_test.rs` | 584 | Head `0xdeadbeef` → exit 13. |
| `StartupError::ForkScheduleMismatch` | `crates/rvc/src/startup.rs` | 45–46, 67–80 | Names `rvc-config` and `/eth/v1/config/spec` plus both epoch and version values. |
| Two-source Gloas apply (no opt-out) | `crates/rvc/src/bootstrap/services.rs` | 157–163 | After `build_fork_schedule`, before SEC-9. Not routed through `apply_fork_compatibility_result`. |

---

## 2. KAT obligation

Every test that covers a **signing root** or a container **`hash_tree_root`** must
assert against a known-answer vector (`EXTERNAL_*` / `KAT_*` / `SPEC_*`), not
against another in-tree helper. Self-consistency
(`compute_x(a) == a.tree_hash_root()`) as the *sole* check is how field-order
bugs shipped green (F122). Policy: `CLAUDE.md` (KAT-first); gate:
`crates/architecture-tests/tests/kat_policy.rs`.

Name pattern `.*(tree_hash|signing_root|_root)$` must, in the **test body**:

1. reference an `EXTERNAL_*` / `KAT_*` / `SPEC_*` constant, or
2. carry `// kat_exempt: <reason>`, or
3. already sit on the shrinking-only `EXEMPTIONS` list — **never add a row**.

### Pattern to copy — body/block roots

The six body/block KATs live in `crates/eth-types/src/block_body.rs` (1198–1229).
They are independent `remerkleable` vectors. A new body-changing fork adds the
same four-constant set (full body/block + blinded body/block). Deneb blinded
currently reuses `EXTERNAL_DENEB_BLOCK_ROOT_HEX` because empty-ops full/blinded
bodies share HTR (`crates/eth-types/src/block.rs` 745–747).

| Constant | Line | Hex |
|---|---|---|
| `EXTERNAL_ELECTRA_BODY_ROOT_HEX` | 1198 | `58953d11e9b51a6e95c8c70ca51b7ad6b6e557a91caab298a71688dfab9e4870` |
| `EXTERNAL_ELECTRA_BLOCK_ROOT_HEX` | 1205 | `b3f19bf190b0ab2466738ba06bbaf6e481041ca66db733c549975b27b53c92b9` |
| `EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX` | 1211 | `e9e9fd39cc7fc4345e43bf31af21838d9389767cf62c0f8fdaf740b06d26f3e7` |
| `EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX` | 1217 | `6bf364098fe8b865ffecc0b1d88c5b6edada937e5c9c3c69726d1d46cf2e1d24` |
| `EXTERNAL_DENEB_BODY_ROOT_HEX` | 1222 | `6c74513b682d097373d9f9a962637d753a8f8d6af4efb0283ae5c4941308ec67` |
| `EXTERNAL_DENEB_BLOCK_ROOT_HEX` | 1228 | `86714640e5ee761d6ccc664996816f10ec496324bcac46a999f778abce1f906e` |

Assertions that must stay green and **byte-identical** after any body/SSZ edit
(`crates/eth-types/src/block.rs`):

- `test_beacon_block_body_leaf_is_typed_not_bytelist` (677) — Electra body + block
- `test_beacon_block_tree_hash_matches_external_electra_vector` (700)
- `test_blinded_beacon_block_tree_hash_matches_external_electra_vector` (711)
- `test_beacon_block_tree_hash_matches_external_deneb_vector` (724)
- `test_blinded_beacon_block_tree_hash_matches_external_deneb_vector` (742)

Signing-domain / duty-root KATs: `crates/crypto/tests/signing_root_kat.rs`. New
fork versions that change a domain must add a named `EXTERNAL_*` / `KAT_*` /
`SPEC_*` vector there (file-level hex that the test body does not mention will
not satisfy `kat_policy` — put the token in the test body).

---

## 3. Dual-SSZ status

### Current stack (HEAD)

| Pin | Where | Value |
|---|---|---|
| Workspace `ssz` | root `Cargo.toml` 92 | `ethereum_ssz` **0.9** |
| Workspace `ssz08` | root `Cargo.toml` 97 | `ethereum_ssz` **0.8.3** (body Encode/Decode) |
| `ssz_types` | root `Cargo.toml` 102 | **0.10.1** (`Encode`/`Decode` against 0.8 only) |
| `tree_hash` | root `Cargo.toml` 103 | **0.9** |
| Lockfile | `Cargo.lock` 1529 / 1544 | both `ethereum_ssz` **0.8.3** and **0.9.1** |

Crate-root types (`Checkpoint` at `crates/eth-types/src/lib.rs` 132–137, and the
other containers) carry **both** workspace `ssz` 0.9 and `ssz08` 0.8
`Encode`/`Decode`. Typed block bodies still encode through `ssz_types` 0.10.1
+ `ssz08`. **One struct per container.**

### Path C landed (ARCH-7h, 2026-08-18, baseline `ce9048c`)

The eight encode/decode-facing twins were collapsed onto the crate-root
types. Do not reintroduce a second struct per container.

How each class was collapsed (spike:
`plan/architecture-2026-08-12/measurements/wire-twins-spike.md`):

| Class | Types | How |
|---|---|---|
| Isomorphic | `Checkpoint`, `AttestationData`, `BeaconBlockHeader`, `DepositData`, `VoluntaryExit` | `ssz_container! { impl Type { fields… } }` decorate-macro (`ssz08_codec_impls!`) |
| Not isomorphic (`Vec<u8>` JSON vs BitList / BitVector / `[u8; 96]`) | `Attestation`, `ElectraAttestation`, `SignedVoluntaryExit` | Custom `ssz` 0.9 + `ssz08` impls that treat the existing bytes as spec bitlist / bitvector / Bytes96 |

Naive decorate of `Vec<u8>` encodes List[byte] (signature and committee bits
become **variable** fields). Empty-ops `EXTERNAL_*` body roots stay green
anyway because empty `List[T, N]` HTR depends only on `N`. A non-empty
Electra attestation-list encode/HTR KAT
(`KAT_ELECTRA_ATTESTATION_LIST_*` in `crates/eth-types/src/block_body.rs`)
is the proof the custom impls are spec SSZ.

**Do not take Path A or Path B.** Path A is the `tree_hash` 0.10 workspace
upgrade. Path B abandons 0.9. Path C does not need either.

The old Path A/B trigger comment on the body module is replaced by the
Path C record (date + baseline). Dual `ethereum_ssz` in `Cargo.lock` is
expected until a later, separately sized stack unification.

---

## 4. Per-fork checklist

Work the rows in order. A layout-preserving fork (Fulu-shaped: new name, same
body as the previous fork) still does every row except a new `BodyForkLayout`
variant and new body structs.

### Body variant

- [ ] Decide: new SSZ body, or share the previous layout (as Fulu shares Electra)?
      Gloas added `BodyForkLayout::Gloas` with **no decoder** (typed error).
- [ ] If new: add `BeaconBlockBody{Fork}` + `BlindedBeaconBlockBody{Fork}` in
      `crates/eth-types/src/block_body.rs` next to Electra (968 / 1000) and Deneb
      (1040 / 1072). Spec field **order** is merkleization-sensitive.
- [ ] Wire decode helpers (`decode_beacon_block_body_*`) and both HTR functions
      (`body_tree_hash_root_for_layout` 1159, `blinded_body_tree_hash_root_for_layout` 1173).
- [ ] Prefer crate-root types at the API boundary. New `Wire*` twins are forbidden
      (Path C; see §3). `EXEMPTIONS` must not grow.

### `body_layout` arm

- [ ] Add `ForkName::{NewFork}` (enum, `ALL`, `COUNT`, `AsRef`, `FromStr`, `id`, `TryFrom`).
- [ ] Extend `ForkName::body_layout` (`crates/eth-types/src/fork.rs` 195). Pre-Deneb stays `None`. A
      non-body-changing fork maps onto the previous `BodyForkLayout` (Fulu → Electra).
      A body-changing fork adds a `BodyForkLayout` variant and arms in
      `extract_blob_kzg_commitments` (`crates/eth-types/src/block.rs` 57) and both `*_for_layout` functions
      (Gloas → `GloasUnsupported`).
- [ ] Arm `ssz_block_format` (`crates/block-service/src/service/mod.rs` 992–1014) with a
      **named** exhaustive `match ForkName` arm. Do not reintroduce a `"deneb" | "electra" | "fulu"`
      string table or a catch-all `BeaconBlock` inherit (Gloas's named `BeaconBlock` arm is
      separate from pre-Deneb on purpose).
- [ ] Confirm `body_fork_layout("newfork")` matches `ForkName::from_str("newfork")?.body_layout()`
      (existing pin: `test_body_layout_matches_body_fork_layout_string_mapping` in
      `crates/eth-types/src/fork.rs` 583).
- [ ] `ssz_helpers` `validate_fork_id` (`crates/eth-types/src/ssz_helpers.rs` 304–321) is an
      independent `0..=6` decoder allowlist, **not** `ForkName::try_from`. Gloas id 7 is
      accepted by `ForkName` and rejected here. Do not widen to `ForkName::COUNT`.
      `decode_attestation_ssz` must not silently accept a new attestation shape.

### Root KAT

- [ ] Independent `remerkleable` (or consensus-spec) vectors for full + blinded
      **body** and **block** roots. Name them `EXTERNAL_{FORK}_BODY_ROOT_HEX` /
      `EXTERNAL_{FORK}_BLOCK_ROOT_HEX` (and blinded pair) next to the six
      constants at `crates/eth-types/src/block_body.rs` 1198–1229.
- [ ] Assert them from tests whose names match `*(tree_hash|signing_root|_root)`
      and whose **bodies** mention the `EXTERNAL_*` token (copy
      `crates/eth-types/src/block.rs` 677–748).
- [ ] Existing six hex strings must not change. A one-field-order swap in a
      scratch tree must turn the new assertion red before the type is trusted.
- [ ] Signing-root KATs in `crates/crypto/tests/signing_root_kat.rs` if any
      domain or fork-version mapping changes.

### `ForkSchedule` entry

- [ ] Two new fields on `ForkSchedule` (22–38): `{fork}_fork_epoch`,
      `{fork}_fork_version`.
- [ ] `entries()` (99) grows by one — the `[; ForkName::COUNT]` length is the compile-time
      checklist (eight today). `from_epoch` / `fork_version` / `activation_epoch` /
      `SignContext::resolve` pick it up automatically.
- [ ] `parse_fork_schedule` (`crates/beacon/src/types.rs` 449) reads
      `{FORK}_FORK_EPOCH` / `{FORK}_FORK_VERSION`. Until every BN advertises
      the pair, optional-with-sentinel is the Fulu/Gloas pattern (464–475).

### Startup gate

- [ ] `check_fork_compatibility` known-versions array (`crates/rvc/src/startup.rs` 181–190)
      includes the new `*_fork_version`. An unknown head version still exits 13.
- [ ] `allow_unsupported_fork` remains the only opt-out
      (`crates/rvc/src/bootstrap/services.rs` 173–176). Do not make unknown
      versions a warning by default. Two-source Gloas reconciliation is not this knob.
- [ ] `test_startup_fails_closed_on_unsupported_fork`
      (`bin/rvc/tests/integration_test.rs` 584) stays green.

### Conformance fixtures

- [ ] Duty wire: add a constructor arm on the enums at `crates/beacon/src/types.rs` 76–99
      and the submit header maps at `crates/beacon/src/client.rs` 1403–1413 (attestations)
      and 1174–1199 (aggregates). Cover the activation epoch and `activation - 1` in
      `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs`.
- [ ] Bound or inherit every `>= ForkName::X` site. EIP-7549 zeroing is
      `Electra..Gloas` (`crates/rvc/src/orchestrator/utils.rs` 134–136); EIP-7044
      stays open-ended `>= Capella`. See §1.3.
- [ ] If attestation/aggregate SSZ shape changed, add encode/HTR fixtures;
      empty-list body KATs are not enough (see §3).
- [ ] Slashing interchange (`crates/slashing/tests/conformance.rs`, vectors in
      `crates/slashing/tests/conformance`) only if EIP-3076 / signing-root
      rules changed — usually they do not.
- [ ] Bump `CONSENSUS_SPEC_VERSION` (`crates/eth-types/src/lib.rs` 129) when the
      implemented spec tag moves.
- [ ] This file: every new path is backticked without a line-number colon;
      `cargo nextest run -p rvc-architecture-tests --test docs_freshness` is green.
      Operator keys for the new fork go in a dedicated upgrade note (Gloas:
      [gloas-upgrade.md](gloas-upgrade.md)), not only here.
