#!/usr/bin/env python3
"""Emit merkleize_progressive / mix_in_active_fields vectors from eth-ssz-specs.

Pinned to eth-ssz-specs==0.1.0. Imports that package and the stdlib only.
Output path comes from --out (argv); this file must not name a destination.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from importlib.metadata import version
from pathlib import Path

if sys.version_info < (3, 12):
    raise SystemExit(
        f"error: python >= 3.12 required, got {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )

from ssz.chunks import Chunk, Root
from ssz.mixins import mix_in_active_fields
from ssz.trees import merkleize_progressive

# Matches eth-ssz-specs 0.1.0 tests/test_merkleization.py.
PROGRESSIVE_CHUNK_COUNTS = [0, 1, 2, 4, 5, 6, 20, 21, 22, 84, 85, 86]
SAMPLE_ROOT_BYTES = (1).to_bytes(32, "little")

# (width, bits, pattern). Sparse patterns keep bit 0 clear.
# Width 5 is ExecutionRequests / ExecutionPayloadEnvelope.
ACTIVE_FIELD_CASES: tuple[tuple[int, tuple[int, ...], str], ...] = (
    (3, (1, 1, 1), "all_ones"),
    (3, (0, 1, 1), "sparse_bit0_clear"),
    (4, (1, 1, 1, 1), "all_ones"),
    (4, (0, 1, 1, 1), "sparse_bit0_clear"),
    (5, (1, 1, 1, 1, 1), "all_ones"),
    (5, (0, 1, 1, 1, 1), "sparse_bit0_clear"),
    (13, tuple([1] * 13), "all_ones"),
    (13, tuple([0] + [1] * 12), "sparse_bit0_clear"),
)


def chunk_run(count: int) -> list[Chunk]:
    """chunk_run(N)[i] == i.to_bytes(32, "little")."""
    return [Chunk(i.to_bytes(32, "little")) for i in range(count)]


def hex32(node: bytes) -> str:
    raw = bytes(node)
    if len(raw) != 32:
        raise SystemExit(f"error: expected 32-byte node, got {len(raw)}")
    return "0x" + raw.hex()


def yaml_bits(bits: Sequence[int]) -> str:
    return "[" + ", ".join(str(int(b)) for b in bits) + "]"


def emit_yaml() -> str:
    lines: list[str] = [
        "# L1 primitive vectors from eth-ssz-specs==0.1.0.",
        '# chunk_run(N)[i] == i.to_bytes(32, "little")',
        '# mix-in sample root == (1).to_bytes(32, "little")',
        "# Do not copy mix_in_length-wrapped list roots into this file.",
        "package: eth-ssz-specs==0.1.0",
        "merkleize_progressive:",
    ]
    for count in PROGRESSIVE_CHUNK_COUNTS:
        chunks = chunk_run(count)
        root = merkleize_progressive(chunks)
        lines.append(f"  - chunk_count: {count}")
        if not chunks:
            lines.append("    chunks: []")
        else:
            lines.append("    chunks:")
            for chunk in chunks:
                lines.append(f"      - '{hex32(chunk)}'")
        lines.append(f"    root: '{hex32(root)}'")

    lines.append("mix_in_active_fields:")
    sample = Root(SAMPLE_ROOT_BYTES)
    for width, bits, pattern in ACTIVE_FIELD_CASES:
        if len(bits) != width:
            raise SystemExit(f"error: width {width} != len(bits) {len(bits)}")
        mixed = mix_in_active_fields(sample, bits)
        lines.append(f"  - width: {width}")
        lines.append(f"    pattern: {pattern}")
        lines.append(f"    bits: {yaml_bits(bits)}")
        lines.append(f"    sample_root: '{hex32(sample)}'")
        lines.append(f"    root: '{hex32(mixed)}'")

    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate progressive merkleization vectors.")
    parser.add_argument("--out", required=True, help="Destination YAML path")
    args = parser.parse_args()

    try:
        pkg_ver = version("eth-ssz-specs")
    except Exception as exc:
        raise SystemExit(f"error: eth-ssz-specs==0.1.0 is required ({exc})") from exc
    if pkg_ver != "0.1.0":
        raise SystemExit(f"error: need eth-ssz-specs==0.1.0, got {pkg_ver}")

    body = emit_yaml()
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Atomic replace so a failed run cannot leave a truncated artifact.
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
