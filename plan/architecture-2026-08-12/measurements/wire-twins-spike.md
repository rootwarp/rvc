# ARCH-7f — Wire* twins Path C spike

**Issue:** ARCH-7f (spike; `07-phase-7.md` § ARCH-7f)  
**Date (UTC):** 2026-08-17T23:00:18Z  
**Tree:** `feature/arch-7f-wire-twins-spike` @ `c150ef017b2200e94c9a469c56b52a3633c73d24` (from `develop`)  
**Worktree:** `/Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a011eb-8ac9-77d2-9c48-56ee6c37f9e6`  
**rustc:** `rustc 1.97.1 (8bab26f4f 2026-07-14)`  
**cargo:** `cargo 1.97.1 (c980f4866 2026-06-30)`  
**nextest:** `cargo-nextest 0.9.85 (d5f93f64f 2024-11-26)`  
**Host:** Darwin arm64 (macOS)

**Verdict: Path C.** Dual `Encode`/`Decode` on one struct is legal Rust at HEAD. No coherence conflict. `VariableList` element bounds are not a compile blocker. **Do not take Path A or Path B.** ARCH-7h should collapse twins via Path C, not via a `tree_hash` / `ssz_types` upgrade.

This file is the landable deliverable. The Path C prototype was **reverted** after measurement; this worktree has no product-code diff vs `develop`. **Do not merge** any `Wire*` change from this issue. ARCH-7g/7h are out of scope.

---

## 1. Question

Can the eight `Wire*` twins in `crates/eth-types/src/block_body.rs` be collapsed at HEAD, or is the documented deletion trigger (`ssz_types` on `ethereum_ssz` 0.9 / workspace `ssz` aligned with `ssz_types`) still required?

Three candidate paths (issue table):

| Path | Description | This spike |
|---|---|---|
| **A** | Upgrade `ssz_types` to a release implementing `Encode`/`Decode` against `ethereum_ssz` 0.9 | Counted only; not migrated |
| **B** | Align the workspace on `ethereum_ssz` 0.8 (drop the 0.9 alias) | Counted only; not migrated |
| **C** *(default hypothesis)* | One struct per container; implement both trait sets on it (`ssz` 0.9 + `ssz08` 0.8) | **Tried. Holds.** |

Trigger at HEAD is **not** satisfied: root `Cargo.toml` pins `ssz = ethereum_ssz 0.9`, `ssz08 = ethereum_ssz 0.8.3`, `ssz_types = 0.10.1`, `tree_hash = 0.9`. `Cargo.lock` still carries both `ethereum_ssz` **0.8.3** (`:1526`) and **0.9.1** (`:1541`).

---

## 2. Method (as specified)

1. Baseline `cargo nextest run -p rvc-eth-types` (EXTERNAL_* roots).
2. Path C on **one** container: `WireCheckpoint` → `crate::Checkpoint`. `cargo check -p rvc-eth-types`.
3. Path C held → hard case: `ssz_types::VariableList` element (`WireAttestationElectra` → `crate::ElectraAttestation`).
4. Path A/B counted as cost signals only (no migration).
5. Six `EXTERNAL_*` hex constants left byte-identical.

---

## 3. Baseline

```text
$ cargo nextest run -p rvc-eth-types --no-fail-fast
    Finished `test` profile [unoptimized + debuginfo] target(s) in 17.50s
     Summary [   0.242s] 372 tests run: 372 passed, 0 skipped
```

EXTERNAL_* constants (unchanged throughout; `block_body.rs`):

| Constant | Hex |
|---|---|
| `EXTERNAL_ELECTRA_BODY_ROOT_HEX` | `58953d11e9b51a6e95c8c70ca51b7ad6b6e557a91caab298a71688dfab9e4870` |
| `EXTERNAL_ELECTRA_BLOCK_ROOT_HEX` | `b3f19bf190b0ab2466738ba06bbaf6e481041ca66db733c549975b27b53c92b9` |
| `EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX` | `e9e9fd39cc7fc4345e43bf31af21838d9389767cf62c0f8fdaf740b06d26f3e7` |
| `EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX` | `6bf364098fe8b865ffecc0b1d88c5b6edada937e5c9c3c69726d1d46cf2e1d24` |
| `EXTERNAL_DENEB_BODY_ROOT_HEX` | `6c74513b682d097373d9f9a962637d753a8f8d6af4efb0283ae5c4941308ec67` |
| `EXTERNAL_DENEB_BLOCK_ROOT_HEX` | `86714640e5ee761d6ccc664996816f10ec496324bcac46a999f778abce1f906e` |

`block.rs:671-738` assertions that must stay green against those constants:

- `test_beacon_block_body_leaf_is_typed_not_bytelist` — `EXTERNAL_ELECTRA_BODY_ROOT_HEX`, `EXTERNAL_ELECTRA_BLOCK_ROOT_HEX`
- `test_beacon_block_tree_hash_matches_external_electra_vector` — `EXTERNAL_ELECTRA_BLOCK_ROOT_HEX`
- `test_blinded_beacon_block_tree_hash_matches_external_electra_vector` — `EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX`
- `test_beacon_block_tree_hash_matches_external_deneb_vector` — `EXTERNAL_DENEB_BLOCK_ROOT_HEX`, `EXTERNAL_DENEB_BODY_ROOT_HEX`
- `test_blinded_beacon_block_tree_hash_matches_external_deneb_vector` — `EXTERNAL_DENEB_BLOCK_ROOT_HEX`

---

## 4. Path C — `WireCheckpoint` → `crate::Checkpoint`

`crate::Checkpoint` already derives `ssz` 0.9 `Encode`/`Decode` + `TreeHash` (`lib.rs`). `WireCheckpoint` was a parallel struct with the same two fields (`epoch: u64`, `root: [u8; 32]`) and `ssz08` impls from `ssz_container!`.

Prototype (measured, then `git checkout -- crates/eth-types/src/block_body.rs`):

1. Split `ssz_container!` so an `impl $ty { fields… }` arm can decorate an existing type (`ssz08_codec_impls!`).
2. `ssz_container! { impl crate::Checkpoint { epoch: crate::Epoch, root: crate::Root } }`.
3. `WireAttestationData.source/target` now `crate::Checkpoint`.
4. Deleted `struct WireCheckpoint`.

**Compile (no coherence conflict):**

```text
$ cargo check -p rvc-eth-types
    Checking rvc-eth-types v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-01a011eb-8ac9-77d2-9c48-56ee6c37f9e6/crates/eth-types)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 6.01s
```

**Tests after Checkpoint collapse:**

```text
$ cargo nextest run -p rvc-eth-types --no-fail-fast
     Summary [   0.223s] 372 tests run: 372 passed, 0 skipped
```

`ssz` 0.9 and `ssz08` 0.8 encodings of the same `Checkpoint` are byte-identical (`test_arch7f_checkpoint_dual_ssz_encodes_identically`). Field types are type aliases (`Epoch = u64`, `Root = [u8; 32]`); both trait stacks already implement `Encode`/`Decode` for those primitives.

---

## 5. Path C — `VariableList` element (`WireAttestationElectra`)

`ssz_types` 0.10.1:

```text
impl<T, N: Unsigned> ssz::Encode for VariableList<T, N> where T: ssz::Encode
impl<T, N> ssz::Decode for VariableList<T, N> where T: ssz::Decode, N: Unsigned
impl<T, N: Unsigned> tree_hash::TreeHash for VariableList<T, N> where T: tree_hash::TreeHash
```

`ssz` here is `ethereum_ssz` **0.8**. The element bound is therefore `ssz08::{Encode,Decode}` + `TreeHash` — not `ssz` 0.9.

Prototype: decorate `crate::AttestationData` and `crate::ElectraAttestation` with `ssz08` impls; change

```text
VariableList<WireAttestationElectra, MaxAttestationsElectra>
```

to

```text
VariableList<crate::ElectraAttestation, MaxAttestationsElectra>
```

on `BeaconBlockBodyElectra` / `BlindedBeaconBlockBodyElectra`.

**Compile (element bound holds):**

```text
$ cargo check -p rvc-eth-types
    Checking rvc-eth-types v0.7.0 (...)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.79s
```

**Tests after the element swap:**

```text
$ cargo nextest run -p rvc-eth-types --no-fail-fast
     Summary [   0.230s] 372 tests run: 372 passed, 0 skipped
```

No coherence error. No missing `Encode`/`Decode`/`TreeHash` bound. This is the fact the issue asked the compile to settle.

### 5.1 Field-type caveat (ARCH-7h, not a Path C falsifier)

`crate::ElectraAttestation` is **not SSZ-isomorphic** to `WireAttestationElectra`:

| Field | `WireAttestationElectra` | `crate::ElectraAttestation` |
|---|---|---|
| `aggregation_bits` | `BitList<MaxValidatorsPerSlot>` | `Vec<u8>` (JSON hex) |
| `data` | `WireAttestationData` | `AttestationData` (isomorphic once `Checkpoint` is shared) |
| `signature` | `[u8; 96]` | `Signature` = `Vec<u8>` |
| `committee_bits` | `BitVector<MaxCommitteesPerSlot>` | `Vec<u8>` (JSON hex) |

Decorating the crate-root fields with `ssz08_codec_impls!` encodes `Vec<u8>` as **List[byte]**, not Bitlist/Bitvector. A non-empty pair produces different SSZ bytes (`test_arch7f_electra_attestation_vec_ssz08_is_not_bitlist`).

Empty `List[T, N]` HTR depends only on `N` (composite packing). External-vector bodies use **empty** attestation lists, so swapping the element type does **not** move any `EXTERNAL_*` root. That is why the six assertions stayed green — not because a non-empty Electra attestation list would encode identically.

```text
$ cargo nextest run -p rvc-eth-types -E 'test(arch7f) or test(tree_hash_matches_external) or test(body_leaf_is_typed) or test(external_vector)'
     Summary [   0.029s] 14 tests run: 14 passed, 361 skipped
```

Final package run (includes three new `test_arch7f_*` diagnostics):

```text
$ cargo nextest run -p rvc-eth-types --no-fail-fast
     Summary [   0.688s] 375 tests run: 375 passed, 0 skipped

$ cargo check -p rvc-eth-types
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.49s
```

---

## 6. Twin classification (input to ARCH-7h)

Eight twins in the issue table. Path C is one strategy; application is per-twin.

| Wire twin | Crate-root | Field-isomorphic? | Path C decorate-macro? |
|---|---|---|---|
| `WireCheckpoint` | `Checkpoint` | **Yes** (`Epoch`/`Root` aliases) | **Yes — prototyped, KATs green** |
| `WireAttestationData` | `AttestationData` | **Yes** (after Checkpoint collapse) | Yes (`ssz08` impl already on crate-root in this prototype) |
| `WireBeaconBlockHeader` | `BeaconBlockHeader` | **Yes** (five primitives) | Yes |
| `WireDepositData` | `DepositData` | **Yes** (`[u8; 48/32/96]` + `u64`) | Yes |
| `WireVoluntaryExit` | `VoluntaryExit` | **Yes** (`Epoch` + `u64`) | Yes |
| `WireAttestation` | `Attestation` | **No** (`BitList`/`[u8; 96]` vs `Vec<u8>`/`Signature`) | Not the decorate-macro. Custom `ssz08` (bitlist/fixed-bytes) or keep Wire* until crate-root fields are spec-shaped |
| `WireAttestationElectra` | `ElectraAttestation` | **No** (BitList + BitVector + `[u8; 96]` vs three `Vec<u8>`) | Same. `VariableList` **compiles**; naive decorate is **not** spec SSZ |
| `WireSignedVoluntaryExit` | `SignedVoluntaryExit` | **No** (`[u8; 96]` vs `Signature` = `Vec<u8>`) | Same (fixed 96-byte vector vs List[byte]) |

`crate::Attestation` / `ElectraAttestation` / `SignedVoluntaryExit` also lack `ssz` 0.9 `Encode`/`Decode` today (JSON + hand `TreeHash` only). That is an API-shape job for 7h, not a reason to take Path A/B.

---

## 7. Paths A and B (counted; not migrated)

Counted because the issue requires a cost signal if C had failed. C did **not** fail. These numbers exist so 7h does not reopen A/B without new evidence.

### Path A — `ssz_types` 0.11+ (`Encode`/`Decode` on `ethereum_ssz` 0.9)

`ssz_types` 0.10.1 is the last release on `tree_hash` 0.9 / `ethereum_ssz` 0.8. Registry `ssz_types` 0.11.0 pins `ethereum_ssz = 0.9` **and** `tree_hash = 0.10`. `tree_hash` 0.10 pins `ethereum_ssz` 0.9 and `alloy-primitives` 1.0.

| Surface | Count at this tree |
|---|---|
| Workspace members depending on `tree_hash` | **7** — `eth-types`, `crypto`, `beacon`, `block-service`, `signer-server`, `rvc`, `bin/rvc-keygen` |
| `#[derive(TreeHash)]` sites | **40** after Checkpoint collapse (11 crate-root + 29 remaining `block_body` containers). Originally 41 including `WireCheckpoint` |
| Hand `impl_container_tree_hash!` sites | **10** (`aggregation.rs` 4, `sync_committee.rs` 3, `block.rs` 2, `attestation.rs` 1) |
| `EXTERNAL_*` / `KAT_*` / `SPEC_*` tokens in `eth-types` + `crypto` | **42** |
| Dual `ethereum_ssz` in `Cargo.lock` | **2** versions: 0.8.3 and 0.9.1 |

Path A is a workspace-wide `tree_hash` 0.9 → 0.10 upgrade touching every derive and every signing-root KAT. Not phase-7-sized. **Rejected.**

### Path B — drop workspace `ssz` 0.9, live on 0.8 only

| Surface | Count at this tree |
|---|---|
| Crates that depend on workspace `ssz` (0.9) | **1** — `rvc-eth-types` only |
| `ssz_derive` 0.9 type sites | **11** — `Checkpoint`, `AttestationData`, `Fork`, `ForkData`, `SigningData`, `BeaconBlockHeader`, `DepositMessage`, `DepositData`, `BLSToExecutionChange`, `VoluntaryExit`, `ValidatorRegistrationV1` |
| `web3signer-wire` | **no** `ssz` / `ssz_derive` |
| `signer-proto` | **no** `ssz` / `ssz_derive` |

Path B is smaller than A but still rewrites the crate-root SSZ stack and the `ssz_helpers` 0.9 codecs, and it **abandons** 0.9 rather than unifying on one struct. Path C already proves both trait sets can coexist. **Rejected.**

---

## 8. What ARCH-7h should do

**Branch 1 (collapse), Path C:**

1. Land the `ssz_container!` `impl` arm (or equivalent `ssz08_codec_impls!`).
2. Collapse the five isomorphic twins one commit each, re-run `EXTERNAL_*` after each: `WireCheckpoint` (prototyped then reverted here), `WireAttestationData`, `WireBeaconBlockHeader`, `WireDepositData`, `WireVoluntaryExit`.
3. For `WireAttestation` / `WireAttestationElectra` / `WireSignedVoluntaryExit`: do **not** decorate `Vec<u8>` fields. Either (a) keep those three `Wire*` until crate-root fields become `BitList`/`BitVector`/`[u8; 96]` with JSON adapters, or (b) write **custom** `ssz08` impls that treat the existing `Vec<u8>` as spec bitlist / fixed-bytes (same idea as `bitlist_tree_hash_root`). (b) is still Path C — one struct, both trait sets — not Path A/B.
4. Never collapse two containers in one commit. `EXEMPTIONS` must not grow. The six `EXTERNAL_*` hex strings must not change.

**Do not** record a Branch 2 deferral for “ssz_types still on 0.8”. That trigger is the Path A/B problem. Path C does not need it.

**Do not** treat empty-list HTR + empty-ops body KATs as proof that a non-empty `ElectraAttestation` list is spec-correct. Add a non-empty attestation-list encode/HTR KAT before collapsing the Electra element type.

---

## 9. Acceptance checklist (ARCH-7f)

- [x] Written verdict names **one** path: **C**.
- [x] Path C working prototype: `WireCheckpoint` deleted; `crate::Checkpoint` carries both trait sets (then reverted).
- [x] `VariableList` element case verified: bound holds; field-type mismatch recorded.
- [x] `cargo check -p rvc-eth-types` and `cargo nextest run -p rvc-eth-types` pasted.
- [x] Six `EXTERNAL_*` hex values unchanged.
- [x] No commit on `develop`. Prototype **reverted**; no product-code diff remains.

---

## 10. Re-run

```bash
cargo nextest run -p rvc-eth-types --no-fail-fast
cargo check -p rvc-eth-types
```

Focused EXTERNAL_* (diagnostics lived only in the discarded prototype):

```bash
cargo nextest run -p rvc-eth-types \
  -E 'test(tree_hash_matches_external) or test(body_leaf_is_typed)'
```
