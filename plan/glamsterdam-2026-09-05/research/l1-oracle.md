# L1 oracle spike (issue 3.4a / #231)

Which source supplies `merkleize_progressive` / `mix_in_active_fields` at the twelve
chunk counts 0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86.

- **Date:** 2026-09-06
- **Verdict:** **pyspec** — 3.4b runs
- **Pins:** `SPEC_TAG=v1.7.0-beta.0`, `SSZ_SPECS_TAG=v0.1.0`
  (`crates/rvc-spec-vectors/vectors.lock`)
- **Archive:** `ssz-test-vectors-v0.1.0.tar.gz`
  sha256 `e2a65f032b59835c26127295293ea1bc07d7ca0ea1fe0e4f1128dffed333f878`
  (22 574 bytes; GitHub release asset, digest matches `vectors.lock`)
- **Elapsed:** 2026-09-06 12:30–12:37 KST (~7 min wall). Under the 1-day box; no overrun.

This note is the input contract for 3.4b / 3.5. The recipe is **out of this box**.

## Verdict

**pyspec.** The twelve L1 primitive roots are not in the shipped `ssz-test-vectors-v0.1.0`
tree. `eth-ssz-specs` 0.1.0 *does* implement `merkleize_progressive` and
`mix_in_active_fields`, and its in-package tests already probe exactly those twelve
counts plus LSB-first packing. 3.4b therefore generates a checked-in artifact from the
pinned package; 3.4b is **not** skipped; 3.11 is **not** the next step.

Not **shipped-vector**: the archive is type-level (`hash_tree_root` of lists / containers),
never raw `merkleize_progressive(chunks)`. Five of the twelve counts have no shipped case
at all.

Not **INCONCLUSIVE**: left-subtree padding *is* distinguishable (shipped type-level cases
at counts 2, 6, 22, and the package's hand-built primitive tests at 2, 6, 22, 86). An
inconclusive result would have been a stronger no-go than a failed assertion and would
have routed to 3.11 without starting 3.4b. That path is not taken.

## What the archive actually contains

Extracted layout (gitignored cache, 3.2):

```
crates/rvc-spec-vectors/vectors/v0.1.0/
  ssz-test-vectors-v0.1.0.tar.gz
  fixtures/ssz/ssz/
    test_basic_types/                 59 JSON
    test_compatible_unions/           16 JSON  (3 progressive)
    test_decode_failure_smoke/         1 JSON
    test_merkleization_boundaries/     8 JSON  (bounded List/Bitvector only)
    test_progressive_containers/      15 JSON
    test_progressive_types/           18 JSON
```

117 JSON fixtures. Format is `ssz_test`: `{typeName, value, serialized, root, _info}`.
`root` is the typed `hash_tree_root`. There is **no** fixture whose payload is a raw
chunk list and whose `root` is `merkleize_progressive` of those chunks.

`test_merkleization_boundaries/` is ordinary `List`/`Bitvector` padding. It does not
exercise EIP-7916.

The in-package Python tests (`tests/test_merkleization.py`,
`tests/test_progressive_vectors.py`) are **not** in the tarball. They ship with
`eth-ssz-specs==0.1.0` and are the pyspec oracle 3.4b will call.

## How a ProgressiveList `root` relates to the primitive

EIP-7916:

```
merkleize_progressive(chunks, num_leaves=1):
    if len(chunks) == 0: return Bytes32()          # [0u8; 32], not a zero-subtree
    a = merkleize(chunks[:num_leaves], num_leaves) # pad the left subtree to num_leaves
    b = merkleize_progressive(chunks[num_leaves:], num_leaves * 4)
    return hash(a, b)
```

A shipped ProgressiveList root is **not** that value. It is
`mix_in_length(merkleize_progressive(pack(value)), len(value))`. Empty list HTR is
`sha256(ZERO || ZERO)` = `0xf5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`,
while 3.7's empty-input AC is `[0u8; 32]`. SHA-256 is one-way, so the inner primitive
root cannot be recovered from a list HTR. 3.5 must therefore consume 3.4b's generated
primitive roots, not copy `root` fields out of the JSON.

Uint64 packs four to a chunk, so element count ≠ chunk count. Bytes32 / composite
elements are one leaf each. Mapping below uses chunk count.

## Chunk count → source

Source is the L1 primitive oracle 3.5 / 3.7 will pin as `SPEC_PROGRESSIVE_*`.
"Shipped type-level" is inventory only: a JSON case whose *inner* `merkleize_progressive`
sees that many chunks. It is **not** a substitute for the primitive constant.

| chunk count | boundary | source | shipped type-level coverage |
|---:|---|---|---|
| 0 | empty | **pyspec** | `fixtures/ssz/ssz/test_progressive_types/test_progressive_list_empty.json` (Uint64, 0 elems); also `test_progressive_list_of_composites_empty.json`, `test_progressive_bitlist_empty.json`. HTR is `mix_in_length(ZERO, 0)`, **not** `[0u8; 32]`. |
| 1 | fills level 1 (width 1) | **pyspec** | `test_progressive_list_single_element.json` (Uint64 × 1 → 1 chunk); `test_progressive_list_fills_first_level.json` (Uint64 × 4 → 1 chunk); `test_progressive_list_of_composites_single.json`; `test_progressive_bitlist_small.json` (3 bits); `test_progressive_bitlist_fills_one_chunk.json` (256 bits). |
| 2 | opens level 2 (width 4), **padding** | **pyspec** | `test_progressive_list_opens_second_level.json` (Uint64 × 5 → 2 chunks). `_info` states the second level's lone chunk is padded to width four. Also `test_progressive_bitlist_opens_second_level.json` (257 bits → 2 chunks). |
| 4 | level 2 almost full | **pyspec** | **none** |
| 5 | fills levels 1+2 | **pyspec** | `test_progressive_list_fills_second_level.json` (Uint64 × 20 → 5 chunks) |
| 6 | opens level 3 (width 16), **padding** | **pyspec** | `test_progressive_list_opens_third_level.json` (Uint64 × 21 → 6 chunks); `test_progressive_list_of_composites_crosses_a_level.json` (Bytes32 × 6 → 6 chunks). |
| 20 | level 3 almost full | **pyspec** | **none** |
| 21 | fills levels 1–3 | **pyspec** | `test_progressive_list_fills_third_level.json` (Uint64 × 84 → 21 chunks) |
| 22 | opens level 4 (width 64), **padding** | **pyspec** | `test_progressive_list_opens_fourth_level.json` (Uint64 × 85 → 22 chunks) |
| 84 | level 4 almost full | **pyspec** | **none** |
| 85 | fills levels 1–4 | **pyspec** | **none** |
| 86 | opens level 5 (width 256), **padding** | **pyspec** | **none** |

Shipped JSON therefore covers inner chunk counts **0, 1, 2, 5, 6, 21, 22** only.
**4, 20, 84, 85, 86** have no shipped case.

The package already names the twelve counts as one list
([`tests/test_merkleization.py`](https://github.com/ethereum/ssz-specs/blob/v0.1.0/tests/test_merkleization.py)
at tag `v0.1.0`):

```python
PROGRESSIVE_CHUNK_COUNTS = [0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86]
```

`test_merkleize_progressive_matches_naive_definition` parametrizes that list.
`test_full_chunk_element_roots` in `tests/test_progressive_vectors.py` hard-codes
ProgressiveList[Uint256] HTRs at the same counts (still `mix_in_length`-wrapped).
3.4b must call `ssz.trees.merkleize_progressive` **directly**, not `hash_tree_root` of a
list, so the empty case stays `[0u8; 32]`.

## Left-subtree padding — distinguishable

**Yes. An available case distinguishes EIP-7916 `merkleize(chunks[:n], limit = n)` padding
from `limit = next_pow2(len(remaining))`.** That is the ADR-001 question. It is not
inconclusive.

`num_leaves` on the spine is always `4**k` (1, 4, 16, 64, 256, …), so
`limit = n` versus `limit = next_pow2(n)` is the same comparison — `n` is already a
power of two. The bug that actually ships green is padding the *partial* left subtree
to `next_pow2(len(chunks_at_this_level))` instead of to the level width `n`.

Discriminating counts (one occupant of the newly opened level):

| count | remaining at this level | EIP-7916 left subtree | wrong `next_pow2(remaining)` |
|---:|---:|---|---|
| 2 | 1 at width 4 | `merkleize([c], limit=4)` — pad two layers | `merkleize([c], limit=1)` — the chunk itself |
| 6 | 1 at width 16 | `limit=16` (four layers) | `limit=1` |
| 22 | 1 at width 64 | `limit=64` (six layers) | `limit=1` |
| 86 | 1 at width 256 | `limit=256` (eight layers) | `limit=1` |

Counts 4 / 20 / 84 do **not** distinguish: remaining is 3 / 15 / 63 and
`next_pow2(remaining)` equals the level width.

Evidence the padding is observable:

1. **Shipped JSON (type-level, still discriminating).**
   `test_progressive_list_opens_second_level.json` / `_opens_third_level.json` /
   `_opens_fourth_level.json` document "pads the … lone chunk out to width four /
   sixteen / sixty-four". A `limit = next_pow2(1)` implementation produces a different
   list HTR at those three cases. Count **86 is not in the archive**.
2. **Package primitive tests (the 3.4b oracle).**
   `test_merkleize_progressive_small_inputs_known_roots` spells the count-2 tree as
   `h(c0, h(h(h(c1, 0), Z[1]), 0))` and the count-6 tree as a width-16 pad of one
   occupant. `test_merkleize_progressive_opens_the_fourth_level` (22) and
   `_opens_the_fifth_level` (86) pad one occupant six / eight layers. Independent
   transcription: `naive_merkleize_progressive` uses
   `perfect_tree_root(chunks[:num_leaves], next_pow2(num_leaves))`.

3.7's "at least one case distinguishes left-subtree padding" AC is therefore satisfiable
from the pyspec artifact at 2, 6, 22, **and** 86. The shipped JSON at 2 / 6 / 22 is
supporting evidence, not the L1 constant.

## `active_fields` widths 3 / 4 / 13 (issue 3.8)

3.8 needs LSB-first `pack_bits` and `mix_in_active_fields(root, bits) == hash_nodes(root, pack_bits(bits))`
at widths 3 (`IndexedAttestation`), 4 (`Attestation`), 13 (`BeaconBlockBody`) — all-ones
plus a sparse pattern with bit 0 clear.

Same type-level vs primitive split: a container `root` is
`mix_in_active_fields(merkleize_progressive(leaves), active_fields)` and cannot be
inverted. 3.8's `SPEC_*` constants are primitive mix-ins over a pinned sample root,
so they are pyspec-generated even where a shipped container of that width exists.

| width | Gloas container | source | shipped type-level |
|---:|---|---|---|
| 3 | `IndexedAttestation` | **pyspec** (primitive mix-in) | **yes** — several fixtures, including a bit-0-clear sparse pattern |
| 4 | `Attestation` | **pyspec** | **none** — no shipped `ACTIVE_FIELDS` of length 4 |
| 13 | `BeaconBlockBody` | **pyspec** | **none** — no shipped `ACTIVE_FIELDS` of length 13 |

Shipped progressive-container layouts (from the filler at tag `v0.1.0`):

| `ACTIVE_FIELDS` | width | fixture |
|---|---:|---|
| `(1,)` | 1 | `test_progressive_container_single_field.json` |
| `(1, 0, 1)` Square | 3 | `test_progressive_container_square.json` — bits 0 and 2 set (`0x05`) |
| `(0, 1, 1)` Circle | 3 | `test_progressive_container_circle.json` — **bit 0 clear** (`0x06`); same three bytes as Square, different root |
| `(0, 0, 1)` | 3 | `test_progressive_container_leading_gaps.json` |
| `(1, 1, 1)` | 3 | `test_progressive_container_with_progressive_fields.json` — all-ones at width 3 |
| `(1, 0, 0, 1, 0, 1)` | 6 | `test_progressive_container_multiple_gaps.json` |
| `(1, *([0]*20), 1)` | 22 | `test_progressive_container_opens_the_fourth_level.json` |
| `(*([0]*255), 1)` | 256 | `test_progressive_container_widest_layout.json` |

LSB-first is already visible at width 3: Circle has bit 0 clear; Square vs Circle share
encoding and not roots; Square `[1,0,1]` vs all-ones `[1,1,1]` differ. That is
integration evidence, not the 3.8 primitive KAT.

The package's `test_mix_in_active_fields_packs_the_layout_into_one_word` pins
LSB-first packing (`[1,0,1] → 0x05`, `[0,1,1] → 0x06`, `[1]*9 → 0xff 0x01`) but does
not include widths 4 or 13. 3.4b generates those two widths (all-ones + bit-0-clear
sparse) by calling `ssz.mixins.mix_in_active_fields` on a fixed sample root.

## Contract for 3.4b (do not implement here)

3.4b runs. It does **not** start 3.11. It must emit, from `eth-ssz-specs==0.1.0` only
(ADR-005: no rs-vc path). Pin the **PyPI wheel digest** of that exact version when the
recipe lands (`[[generated]]` in `vectors.lock`); do not leave the pin as a version
string alone. The digest is measured in 3.4b — not invented here.

Pre-images are part of the oracle. The only published hex at unshipped counts
4 / 20 / 84 / 85 / 86 is `mix_in_length`-wrapped, 1-indexed ProgressiveList[Uint256]
HTRs in `test_full_chunk_element_roots`. Copying those (or any shipped JSON `root`)
into `SPEC_PROGRESSIVE_*` is a **recipe bug**: they are not `merkleize_progressive`
of `chunk_run(N)`.

Quoted pre-images, matching
[`tests/test_merkleization.py`](https://github.com/ethereum/ssz-specs/blob/v0.1.0/tests/test_merkleization.py)
at tag `v0.1.0`:

```python
# chunk_run(N)[i] == i.to_bytes(32, "little")  for i in range(N)
# mix-in sample root == sample_chunks[1] == (1).to_bytes(32, "little")
```

| primitive | pre-image | notes |
|---|---|---|
| `merkleize_progressive` | `chunk_run(N)` as above, `N ∈ {0,1,2,4,5,6,20,21,22,84,85,86}` | empty (`N=0`) is `[0u8; 32]`; 2, 6, 22, 86 are the padding cases |
| `mix_in_active_fields` | root = `(1).to_bytes(32, "little")` | same sample root for every width |

| width | all-ones | sparse (bit 0 clear) |
|---:|---|---|
| 3 | `[1, 1, 1]` | `[0, 1, 1]` (Circle) |
| 4 | `[1, 1, 1, 1]` | `[0, 1, 1, 1]` |
| 13 | `[1] * 13` | `[0] + [1] * 12` |

The tracked `vectors-generated/` artifact **must record each pre-image next to its
root** (chunk bytes / bitstring + hex root), so 3.5 cannot bind a constant to an
unspecified input. 3.5 codegens `SPEC_PROGRESSIVE_*` from that file, never from
shipped JSON `root` fields.

## Sources

- Extracted `ssz-test-vectors-v0.1.0.tar.gz` (digest above), inventory 2026-09-06
- [ethereum/ssz-specs v0.1.0](https://github.com/ethereum/ssz-specs/tree/v0.1.0)
  — `src/ssz/trees.py` (`merkleize_progressive`), `src/ssz/mixins.py`
  (`mix_in_active_fields`, LSB-first `active_fields_word`),
  `tests/test_merkleization.py` (`PROGRESSIVE_CHUNK_COUNTS`, naive transcription,
  hand-built padding trees), `tests/test_progressive_vectors.py`,
  `tests/fillers/ssz/test_progressive_{types,containers}.py`
- [EIP-7916](https://eips.ethereum.org/EIPS/eip-7916) — `merkleize(chunks[:num_leaves], num_leaves)`
- Phase 3 issue 3.4a / 3.4b / 3.7 / 3.8; ADR-001 in `architecture.md`
