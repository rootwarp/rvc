#!/usr/bin/env python3
"""Fail when a crate that a lock-only advisory ignore covers enters the build graph.

`deny.toml` and `.cargo/audit.toml` ignore some advisories because the
affected crate is only in Cargo.lock: no enabled feature compiles it. Both
scanners keep the ignore when a feature change compiles the crate. This check
reads the resolved graph (all features, all targets, normal, build and dev
edges) and fails if it contains an affected version of such a crate.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CARGO_TREE = (
    "cargo",
    "tree",
    "--locked",
    "--workspace",
    "--all-features",
    "--target",
    "all",
    "-e",
    "normal,build,dev",
    "--prefix",
    "none",
    "--format",
    "{p}",
)


@dataclass(frozen=True)
class LockOnlyIgnore:
    """A crate that an ignore entry covers only while the crate is not compiled."""

    crate: str
    advisories: tuple[str, ...]
    # The first version that is not affected. None: all versions are affected.
    fixed: str | None


LOCK_ONLY_IGNORES = (
    LockOnlyIgnore("derivative", ("RUSTSEC-2024-0388",), None),
    LockOnlyIgnore("chrono", ("RUSTSEC-2026-0543",), None),
    LockOnlyIgnore(
        "heapless",
        tuple(f"RUSTSEC-2026-{n:04d}" for n in range(574, 583)),
        "0.9.4",
    ),
)


def semver_key(text: str) -> tuple:
    """Return a key that orders versions by SemVer 2.0.0 precedence.

    A prerelease sorts before its release. Build metadata does not count.
    """
    core, _, pre = text.removeprefix("v").split("+", 1)[0].partition("-")
    numbers = tuple(int(part) for part in core.split("."))
    if not pre:
        return (numbers, 1, ())
    identifiers = tuple(
        (0, int(part), "") if part.isdigit() else (1, 0, part) for part in pre.split(".")
    )
    return (numbers, 0, identifiers)


def graph_packages(tree_output: str) -> set[tuple[str, str]]:
    """Return the (name, version) pairs in `cargo tree --prefix none --format {p}` output."""
    packages = set()
    for line in tree_output.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].startswith("v"):
            packages.add((fields[0], fields[1].removeprefix("v")))
    return packages


def violations(
    packages: Iterable[tuple[str, str]],
    ignores: Iterable[LockOnlyIgnore] = LOCK_ONLY_IGNORES,
) -> list[str]:
    """Return one message for each affected package in the resolved graph."""
    rules = {rule.crate: rule for rule in ignores}
    found = []
    for name, version in sorted(packages):
        rule = rules.get(name)
        if rule is None:
            continue
        if rule.fixed is not None and semver_key(version) >= semver_key(rule.fixed):
            continue
        found.append(
            f"{name} {version} is in the resolved build graph, but deny.toml and "
            f".cargo/audit.toml ignore {', '.join(rule.advisories)} as lock-only. "
            "Remove the feature that compiles it, or review the ignore."
        )
    return found


def main(run: Callable[..., subprocess.CompletedProcess] = subprocess.run) -> int:
    result = run(CARGO_TREE, cwd=ROOT, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"cargo tree failed ({result.returncode}):\n{result.stderr}", file=sys.stderr)
        return 2
    packages = graph_packages(result.stdout)
    if not packages:
        print("cargo tree printed no packages", file=sys.stderr)
        return 2
    found = violations(packages)
    for message in found:
        print(f"error: {message}", file=sys.stderr)
    if found:
        return 1
    crates = ", ".join(rule.crate for rule in LOCK_ONLY_IGNORES)
    print(f"lock-only advisory crates are not in the build graph: {crates}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
