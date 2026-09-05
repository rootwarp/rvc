# Forks — add-a-fork checklist

How rvc dispatches on consensus fork, and the work required to add the next one.

Fork identity is `ForkName`. Epoch → name → version is `ForkSchedule`. Blob-body SSZ is
`BodyForkLayout` (`body_layout` / `body_fork_layout`). Those three are the only fork
switches that may grow; everything else must call them.

Line numbers were opened on `develop` @ `500429b`. Docs-freshness
(`crates/architecture-tests/tests/docs_freshness.rs`) checks every backticked
`crates/` / `bin/` / `plan/` / `docs/` path in this file. Put `file:line` *outside*
the backticks — a colon inside `` `…` `` is not a path token.

---

## 1. Dispatch sites

Seven `ForkName` variants, activation order: Phase0, Altair, Bellatrix, Capella, Deneb,
Electra, Fulu (`crates/eth-types/src/fork.rs` 9–17, `ALL` at 130–138). Fulu is live on
the schedule and on duty wire tags; it **reuses the Electra body layout**.

### 1.1 Source of truth — `ForkName` / `ForkSchedule`

| What | File | Lines | Role |
|---|---|---|---|
| `ForkName` enum | `crates/eth-types/src/fork.rs` | 9–17 | Sole fork identity. Exhaustive `match` sites fail to compile when a variant is added. |
| `ForkSchedule` | `crates/eth-types/src/fork.rs` | 21–35 | Genesis version + epoch/version pair per post-genesis fork. |
| `ForkSchedule::entries` | `crates/eth-types/src/fork.rs` | 67–77 | `[(ForkName, Epoch, Version); 7]`, ascending. **Array length is the fork count.** |
| `AsRef<str>` / `FromStr` | `crates/eth-types/src/fork.rs` | 80–108 | Lowercase BN `consensus_version` (`"electra"`, `"fulu"`). Case-sensitive; `"Electra"` is `Err`. |
| `TryFrom<u32>` / `id` | `crates/eth-types/src/fork.rs` | 111–151 | Signer SSZ `fork_id` (Phase0=0 … Fulu=6). `7` is `UnknownForkIdError`. |
| `ForkName::body_layout` | `crates/eth-types/src/fork.rs` | 157–163 | Deneb → `BodyForkLayout::Deneb`; Electra **and Fulu** → `Electra`; pre-Deneb → `None`. |
| `ForkName::from_epoch` | `crates/eth-types/src/fork.rs` | 169–177 | Reverse scan of `entries()`; equal activation epochs pick the latest fork. |
| `fork_version` / `activation_epoch` | `crates/eth-types/src/fork.rs` | 179–195 | Lookups through `entries()`. |
| BN `/eth/v1/config/spec` → schedule | `crates/beacon/src/types.rs` | 234–256 | `parse_fork_schedule`. Fulu epoch/version are optional (`u64::MAX` / `[0xFF; 4]`). |

`from_epoch`, `fork_version`, `activation_epoch`, `SignContext::resolve`, and
`body_fork_layout` all go through `entries()` or `body_layout()`. Do not add a
parallel if-else on version bytes.

### 1.2 Body layout — `BodyForkLayout` / typed bodies

Two SSZ layouts exist for `BeaconBlockBody` (blob era). Electra added
`execution_requests` after `blob_kzg_commitments`; Fulu did not add a third layout.

| What | File | Lines | Role |
|---|---|---|---|
| `BodyForkLayout` | `crates/eth-types/src/block.rs` | 18–23 | `Deneb` (12-field body) / `Electra` (13-field; Fulu shares). |
| `body_fork_layout` | `crates/eth-types/src/block.rs` | 32–38 | `ForkName::from_str(consensus_version).ok().and_then(ForkName::body_layout)`. |
| `extract_blob_kzg_commitments` | `crates/eth-types/src/block.rs` | 52–66 | Layout → typed Deneb/Electra decoder. Empty list is `Ok(vec![])`; bad SSZ is `Err`. |
| `BlockContents::kzg_commitment_root` | `crates/eth-types/src/block.rs` | 282–284 | Internal KZG fingerprint (not spec `hash_tree_root`). Takes `layout`. |
| `BeaconBlock::kzg_commitment_root` | `crates/eth-types/src/block.rs` | 350–352 | Same fingerprint on a bare block. |
| `try_tree_hash_root_for_layout` | `crates/eth-types/src/tree_hash_utils.rs` | 125–147 | Spec block HTR with an explicit layout (prefer this on proposal paths). |
| `BeaconBlockBodyElectra` | `crates/eth-types/src/block_body.rs` | 915 | 13-field full body. Comment: Fulu shares this layout. |
| `BlindedBeaconBlockBodyElectra` | `crates/eth-types/src/block_body.rs` | 947 | Electra blinded (`ExecutionPayloadHeader`). |
| `BeaconBlockBodyDeneb` | `crates/eth-types/src/block_body.rs` | 987 | 12-field full body; pre-Electra attestation limits. |
| `BlindedBeaconBlockBodyDeneb` | `crates/eth-types/src/block_body.rs` | 1019 | Deneb blinded. |
| `body_tree_hash_root_for_layout` | `crates/eth-types/src/block_body.rs` | 1106–1116 | Full-body leaf HTR, explicit layout. |
| `blinded_body_tree_hash_root_for_layout` | `crates/eth-types/src/block_body.rs` | 1119–1131 | Blinded leaf HTR, explicit layout. |
| Auto-detect HTR | `crates/eth-types/src/block_body.rs` | 1084–1103 | Electra decode first, then Deneb. Use only when `consensus_version` is unknown. |

Proposal path that already has the BN `consensus_version`:

| What | File | Lines | Role |
|---|---|---|---|
| SSZ `BlockContents` KZG bind | `crates/block-service/src/service/mod.rs` | 342–349 | `body_fork_layout` → `blob_kzg_count` / `kzg_commitment_root`. Fail-closed on bad SSZ. Skipped unless `ssz_block_format` returned `BlockContents`. |
| JSON `BlockAndBlobs` KZG bind | `crates/block-service/src/service/mod.rs` | 429–434 | Same `body_fork_layout` dispatch. |
| `ssz_block_format` string table | `crates/block-service/src/service/mod.rs` | 573–585 | **Does not go through `ForkName` / `body_layout`.** Blinded → always `BeaconBlock`. Unblinded `"deneb"` / `"electra"` / `"fulu"` → `BlockContents`; anything else (including a new lowercase fork name) silently falls back to raw `BeaconBlock` and the 342 KZG bind is skipped. Call site: 303. Prefer `body_fork_layout(v).is_some()` over growing the string match. |

### 1.3 Duty and signing dispatch

These sites branch on `ForkName` (or `fork_id = ForkName::id()`). They must not grow a
private fork table.

| What | File | Lines | Role |
|---|---|---|---|
| Attestation fork + EIP-7549 | `crates/rvc/src/orchestrator/attestation.rs` | 319–320, 414–427 | `from_epoch(target_epoch)`; Electra+ → `SingleAttestation`; Fulu uses `VersionedAttestation::Fulu`. |
| Versioned BN wire enums | `crates/beacon/src/types.rs` | 47–67 | `VersionedAttestation` / `VersionedAggregateAttestation` / `VersionedSignedAggregateAndProof` — compile-forced grow-set. |
| Submit `Eth-Consensus-Version` | `crates/beacon/src/client.rs` | 886–890 | Maps those enums to `"phase0"` / `"electra"` / `"fulu"`. |
| Aggregate fork + submit tag | `crates/rvc/src/orchestrator/aggregation.rs` | 81–94, 130–134, 238 | Same Electra/Fulu split; `VersionedSignedAggregateAndProof::{Electra,Fulu}`. |
| EIP-7549 index zeroing | `crates/rvc/src/orchestrator/utils.rs` | 138–147 | `index = 0` iff `fork_name >= Electra`. Shared by attestation and aggregation. |
| Domain / signing root | `crates/crypto/src/signing_root.rs` | 80–88, 191–193 | `fork_version_at` = `from_epoch` → `fork_version`. |
| EIP-7044 Capella cap | `crates/crypto/src/signing_root.rs` | 226–230 | Voluntary-exit domain stays on Capella after Capella. **Definition** lives here. |
| Keygen EIP-7044 schedule | `bin/rvc-keygen/src/network.rs` | 21–37 | `exit_fork_schedule`: Capella at epoch 0, post-Capella at `u64::MAX`. Production keygen signs via `sign_voluntary_exit` → `signing_root_for`. |
| Keygen exit cap (test only) | `bin/rvc-keygen/src/exit.rs` | 106–107 | Re-implements the Capella cap inside `#[cfg(test)]` `test_exit_round_trip_encrypt_decrypt_sign` (67–114). Not the production definition. |
| `SignContext` | `crates/crypto/src/typed_signer.rs` | 33–38, 52–64 | Carries resolved `ForkName`. `resolve` matches `fork_info.current_version` against `entries()`; **no silent Deneb default**. |
| gRPC `fork_id` | `crates/grpc-signer/src/client.rs` | 217–224 | `ctx.fork_name.id()`. |
| `validate_fork_id` | `crates/eth-types/src/ssz_helpers.rs` | 285–287 | `ForkName::try_from(fork_id)`. **Not a layout switch** — encoders ignore `fork_id`. |
| `decode_attestation_ssz` | `crates/eth-types/src/ssz_helpers.rs` | 159–205 | Always pre-Electra three-field layout. Electra-shaped buffers → `ElectraLayoutUnsupported` (61, 184, 197), never a wrong `Attestation`. |

### 1.4 SEC-9 fail-closed startup gate

Unknown head fork version is fatal by default (exit 13). Named opt-out only.
Two-source Gloas schedule reconciliation (D12) is a separate fail-closed gate with **no** opt-out.

| What | File | Lines | Role |
|---|---|---|---|
| `EXIT_UNSUPPORTED_FORK_VERSION` | `crates/rvc/src/startup.rs` | 30 | Exit code 13. |
| `StartupError::UnsupportedForkVersion` | `crates/rvc/src/startup.rs` | 42–43 | `"unsupported consensus fork version {version}; upgrade rvc"`. |
| `check_fork_compatibility` | `crates/rvc/src/startup.rs` | 171–196 | Head `current_version` must be in the seven schedule versions (includes `fulu_fork_version` at 187). |
| Apply + opt-out | `crates/rvc/src/bootstrap/services.rs` | 64–82, 168–171 | Fatal unless `allow_unsupported_fork`. Do not weaken `check_fork_compatibility`. |
| CLI / config knob | `crates/rvc-config/src/sections/safety.rs` | 79–84 | `--allow-unsupported-fork`. Testnets / experimental forks only. |
| Fail-closed integration test | `bin/rvc/tests/integration_test.rs` | 530 | Head `0xdeadbeef` → non-zero exit. |
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

The six body/block KATs live in `crates/eth-types/src/block_body.rs` (1143–1174).
They are independent `remerkleable` vectors. A new body-changing fork adds the
same four-constant set (full body/block + blinded body/block). Deneb blinded
currently reuses `EXTERNAL_DENEB_BLOCK_ROOT_HEX` because empty-ops full/blinded
bodies share HTR (`crates/eth-types/src/block.rs` 737–738).

| Constant | Line | Hex |
|---|---|---|
| `EXTERNAL_ELECTRA_BODY_ROOT_HEX` | 1143 | `58953d11e9b51a6e95c8c70ca51b7ad6b6e557a91caab298a71688dfab9e4870` |
| `EXTERNAL_ELECTRA_BLOCK_ROOT_HEX` | 1150 | `b3f19bf190b0ab2466738ba06bbaf6e481041ca66db733c549975b27b53c92b9` |
| `EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX` | 1156 | `e9e9fd39cc7fc4345e43bf31af21838d9389767cf62c0f8fdaf740b06d26f3e7` |
| `EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX` | 1162 | `6bf364098fe8b865ffecc0b1d88c5b6edada937e5c9c3c69726d1d46cf2e1d24` |
| `EXTERNAL_DENEB_BODY_ROOT_HEX` | 1167 | `6c74513b682d097373d9f9a962637d753a8f8d6af4efb0283ae5c4941308ec67` |
| `EXTERNAL_DENEB_BLOCK_ROOT_HEX` | 1173 | `86714640e5ee761d6ccc664996816f10ec496324bcac46a999f778abce1f906e` |

Assertions that must stay green and **byte-identical** after any body/SSZ edit
(`crates/eth-types/src/block.rs`):

- `test_beacon_block_body_leaf_is_typed_not_bytelist` (669) — Electra body + block
- `test_beacon_block_tree_hash_matches_external_electra_vector` (692)
- `test_blinded_beacon_block_tree_hash_matches_external_electra_vector` (703)
- `test_beacon_block_tree_hash_matches_external_deneb_vector` (716)
- `test_blinded_beacon_block_tree_hash_matches_external_deneb_vector` (734)

Signing-domain / duty-root KATs: `crates/crypto/tests/signing_root_kat.rs`. New
fork versions that change a domain must add a named `EXTERNAL_*` / `KAT_*` /
`SPEC_*` vector there (file-level hex that the test body does not mention will
not satisfy `kat_policy` — put the token in the test body).

---

## 3. Dual-SSZ status

### Current stack (HEAD)

| Pin | Where | Value |
|---|---|---|
| Workspace `ssz` | root `Cargo.toml` 89 | `ethereum_ssz` **0.9** |
| Workspace `ssz08` | root `Cargo.toml` 94 | `ethereum_ssz` **0.8.3** (body Encode/Decode) |
| `ssz_types` | root `Cargo.toml` 99 | **0.10.1** (`Encode`/`Decode` against 0.8 only) |
| `tree_hash` | root `Cargo.toml` 100 | **0.9** |
| Lockfile | `Cargo.lock` 1526 / 1541 | both `ethereum_ssz` **0.8.3** and **0.9.1** |

Crate-root types (`Checkpoint` at `crates/eth-types/src/lib.rs` 121–127, and the
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
- [ ] If new: add `BeaconBlockBody{Fork}` + `BlindedBeaconBlockBody{Fork}` in
      `crates/eth-types/src/block_body.rs` next to Electra (915 / 947) and Deneb
      (987 / 1019). Spec field **order** is merkleization-sensitive.
- [ ] Wire decode helpers (`decode_beacon_block_body_*`) and both HTR functions
      (`body_tree_hash_root_for_layout` 1106, `blinded_body_tree_hash_root_for_layout` 1119).
- [ ] Prefer crate-root types at the API boundary. New `Wire*` twins are forbidden
      (Path C; see §3). `EXEMPTIONS` must not grow.

### `body_layout` arm

- [ ] Add `ForkName::{NewFork}` (enum, `ALL`, `AsRef`, `FromStr`, `id`, `TryFrom`).
- [ ] Extend `ForkName::body_layout` (`crates/eth-types/src/fork.rs` 157). Pre-Deneb stays `None`. A
      non-body-changing fork maps onto the previous `BodyForkLayout` (Fulu → Electra).
      A body-changing fork adds a `BodyForkLayout` variant and arms in
      `extract_blob_kzg_commitments` (`crates/eth-types/src/block.rs` 52) and both `*_for_layout` functions.
- [ ] Arm `ssz_block_format` (`crates/block-service/src/service/mod.rs` 573–585) for the new
      unblinded name, **or** replace the `"deneb" | "electra" | "fulu"` string match with
      `body_fork_layout(v).is_some()` so a new `ForkName` cannot silently fall back to raw
      `BeaconBlock`.
- [ ] Confirm `body_fork_layout("newfork")` matches `ForkName::from_str("newfork")?.body_layout()`
      (existing pin: `test_body_layout_matches_body_fork_layout_string_mapping` in
      `crates/eth-types/src/fork.rs` 518).
- [ ] `ssz_helpers` `fork_id` accepts the new `id` and still rejects `id + 1`.
      `decode_attestation_ssz` must not silently accept a new attestation shape.

### Root KAT

- [ ] Independent `remerkleable` (or consensus-spec) vectors for full + blinded
      **body** and **block** roots. Name them `EXTERNAL_{FORK}_BODY_ROOT_HEX` /
      `EXTERNAL_{FORK}_BLOCK_ROOT_HEX` (and blinded pair) next to the six
      constants at `crates/eth-types/src/block_body.rs` 1143–1174.
- [ ] Assert them from tests whose names match `*(tree_hash|signing_root|_root)`
      and whose **bodies** mention the `EXTERNAL_*` token (copy
      `crates/eth-types/src/block.rs` 669–740).
- [ ] Existing six hex strings must not change. A one-field-order swap in a
      scratch tree must turn the new assertion red before the type is trusted.
- [ ] Signing-root KATs in `crates/crypto/tests/signing_root_kat.rs` if any
      domain or fork-version mapping changes.

### `ForkSchedule` entry

- [ ] Two new fields on `ForkSchedule` (21–35): `{fork}_fork_epoch`,
      `{fork}_fork_version`.
- [ ] `entries()` (67) grows by one — the `[; 7]` length is the compile-time
      checklist. `from_epoch` / `fork_version` / `activation_epoch` /
      `SignContext::resolve` pick it up automatically.
- [ ] `parse_fork_schedule` (`crates/beacon/src/types.rs` 234) reads
      `{FORK}_FORK_EPOCH` / `{FORK}_FORK_VERSION`. Until every BN advertises
      the pair, optional-with-sentinel is the Fulu pattern (249–254).

### Startup gate

- [ ] `check_fork_compatibility` known-versions array (`crates/rvc/src/startup.rs` 180–188)
      includes the new `*_fork_version`. An unknown head version still exits 13.
- [ ] `allow_unsupported_fork` remains the only opt-out
      (`crates/rvc/src/bootstrap/services.rs` 168–171). Do not make unknown
      versions a warning by default. Two-source Gloas reconciliation is not this knob.
- [ ] `test_startup_fails_closed_on_unsupported_fork`
      (`bin/rvc/tests/integration_test.rs` 530) stays green.

### Conformance fixtures

- [ ] Duty wire: add a constructor arm on the enums at `crates/beacon/src/types.rs` 47–67
      and the submit header map at `crates/beacon/src/client.rs` 886–890. Cover the
      activation epoch and `activation - 1` in
      `crates/rvc/src/orchestrator/coordinator/tests/fork_transition.rs`.
- [ ] If attestation/aggregate SSZ shape changed, add encode/HTR fixtures;
      empty-list body KATs are not enough (see §3).
- [ ] Slashing interchange (`crates/slashing/tests/conformance.rs`, vectors in
      `crates/slashing/tests/conformance`) only if EIP-3076 / signing-root
      rules changed — usually they do not.
- [ ] Bump `CONSENSUS_SPEC_VERSION` (`crates/eth-types/src/lib.rs` 119) when the
      implemented spec tag moves.
- [ ] This file: every new path is backticked without a line-number colon;
      `cargo nextest run -p rvc-architecture-tests --test docs_freshness` is green.
