#!/usr/bin/env python3
"""Prove that the strict config and the git-mode range scan find known blind spots.

- Allowlist shapes: the strict config (``RVC_GITLEAKS_CONFIG``) must report
  each one, and a control scan with ``.gitleaks.toml`` must not.
- Chunk shapes: ``scripts/gitleaks_range_scan.sh`` must report each one, and
  a control no-git scan must not.
- Merge shape: the range scan must report a secret that only a merge
  resolution adds.

Tokens are joined from fragments at run time, so this file is not a finding.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from gitleaks_strict_config import require_strict_config

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / ".gitleaks.toml"
CONFIG = Path(os.environ.get("RVC_GITLEAKS_CONFIG") or str(DEFAULT_CONFIG)).resolve()
GITLEAKS = os.environ.get("GITLEAKS_BIN", "gitleaks")
RANGE_SCAN = ROOT / "scripts" / "gitleaks_range_scan.sh"
CHUNK_SIZE = 10_000
GENERIC_CUT = 9
PDF_GAP = 200
MERGE_FILE = "merge.rs"


def token() -> str:
    return "k7Qm9pL2xV8n" + "R4wT6yH3cB5d" + "F1aE0sZ"


def allowlist_shapes() -> dict[str, tuple[str, str]]:
    """Return ``label -> (path, secret)``. Each one hits a default entry."""
    head, tail = token()[:12], token()[12:]
    return {
        "contains-false": ("src/lib.rs", head + "fal" + "se" + tail),
        "starts-true": ("src/lib.rs", "tr" + "ue" + token()),
        "ends-null": ("src/lib.rs", token() + "nu" + "ll"),
        "path-contains-gitleaks-toml": ("docs/my-" + "gitleaks.toml.md", token()),
        "path-ends-bin": ("docs/ca" + "bin", token()),
    }


def _key_line(secret: str) -> bytes:
    return f'let api_key = "{secret}";\n'.encode()


def _filler(size: int) -> bytes:
    """Comment lines of exactly ``size`` bytes."""
    out = bytearray()
    while size > 0:
        width = min(size, 80)
        out += b"/" * (width - 1) + b"\n"
        size -= width
    return bytes(out)


def pem_marker(kind: str) -> str:
    """Return a PEM marker. A call, so no .pyc holds a folded header."""
    return "-----" + kind + " RSA PRIVATE KEY-----"


def _pem() -> bytes:
    begin = pem_marker("BEGIN")
    end = pem_marker("END")
    body = "MIIB" + "OgIB" + "AAJB" + "AL7s" + "ynth" + "etic" + "CANA" + "RYKe" + "yMat" + "eria" + "l99"
    return f"{begin}\n{body}\n{end}\n".encode()


def chunk_boundary_files() -> dict[str, bytes]:
    """Return ``file name -> content`` for each chunk-boundary blind spot."""
    line = _key_line(token())
    cut = line.index(token().encode()) + GENERIC_CUT
    pem = _pem()
    begin_end = pem.index(b"\n")
    return {
        "generic.rs": _filler(CHUNK_SIZE - cut) + line,
        "pem.rs": _filler(CHUNK_SIZE - begin_end - 5) + pem,
        "pdf.rs": _filler(CHUNK_SIZE) + b"%PDF-1.7\n" + _filler(PDF_GAP) + line,
    }


REQUIRED_LABELS = frozenset(
    [f"strict-{label}" for label in allowlist_shapes()]
    + [f"default-hides-{label}" for label in allowlist_shapes()]
    + [f"git-range-{name}" for name in chunk_boundary_files()]
    + [f"git-range-{MERGE_FILE}"]
    + [f"no-git-misses-{name}" for name in chunk_boundary_files()]
)
seen_labels: set[str] = set()


def expect(label: str, code: int, want: int) -> None:
    if label not in REQUIRED_LABELS:
        raise SystemExit(f"unexpected label {label}")
    if label in seen_labels:
        raise SystemExit(f"label seen twice: {label}")
    seen_labels.add(label)
    if code != want:
        raise SystemExit(f"{label}: exit {code}, want {want}")
    print(f"{label}: exit {code}")


def require_expected_labels() -> None:
    missing = REQUIRED_LABELS - seen_labels
    if missing:
        raise SystemExit("expected labels not hit: " + ", ".join(sorted(missing)))


def _checked(proc: subprocess.CompletedProcess[str]) -> int:
    if proc.returncode not in (0, 1) or "leaks found" not in proc.stderr:
        sys.stderr.write(proc.stdout + proc.stderr)
        raise SystemExit(f"gitleaks did not finish (exit {proc.returncode})")
    return proc.returncode


def _report_files(report: Path) -> set[str]:
    return {finding["File"] for finding in json.loads(report.read_text(encoding="utf-8"))}


def scan_no_git(source: Path, config: Path, report: Path) -> int:
    proc = subprocess.run(
        [
            GITLEAKS,
            "detect",
            "--no-git",
            "--source",
            ".",
            "--config",
            str(config),
            "--ignore-gitleaks-allow",
            "--redact",
            "--no-banner",
            "--exit-code",
            "1",
            "--report-format",
            "json",
            "--report-path",
            str(report),
        ],
        cwd=source,
        check=False,
        capture_output=True,
        text=True,
    )
    return _checked(proc)


def _git(repo: Path, *args: str) -> None:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "canary",
        "GIT_AUTHOR_EMAIL": "canary@example.invalid",
        "GIT_COMMITTER_NAME": "canary",
        "GIT_COMMITTER_EMAIL": "canary@example.invalid",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
    }
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, env=env)


def check_allowlist_shapes(root: Path) -> None:
    for label, (rel, secret) in allowlist_shapes().items():
        tree = root / f"shape-{label}"
        (tree / rel).parent.mkdir(parents=True, exist_ok=True)
        (tree / rel).write_bytes(_key_line(secret))
        report = root / f"shape-{label}.json"
        expect(f"strict-{label}", scan_no_git(tree, CONFIG, report), 1)
        if _report_files(report) != {rel}:
            raise SystemExit(f"strict-{label}: findings in {sorted(_report_files(report))}")
        expect(f"default-hides-{label}", scan_no_git(tree, DEFAULT_CONFIG, report), 0)


def check_chunk_shapes(root: Path) -> None:
    files = chunk_boundary_files()
    repo = root / "chunk-repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "base")
    proc = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    )
    base = proc.stdout.strip()
    for name, data in files.items():
        (repo / name).write_bytes(data)
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "chunk shapes")
    _git(repo, "checkout", "-q", "-b", "side")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "side")
    _git(repo, "checkout", "-q", "-")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "main")
    _git(repo, "merge", "-q", "--no-ff", "--no-commit", "side")
    (repo / MERGE_FILE).write_bytes(_key_line(token()))
    _git(repo, "add", MERGE_FILE)
    _git(repo, "commit", "-q", "-m", "merge resolution")

    report = root / "git-range.json"
    proc = subprocess.run(
        [str(RANGE_SCAN), str(CONFIG), base, "--report-format", "json", "--report-path", str(report)],
        cwd=repo,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "GITLEAKS_BIN": GITLEAKS},
    )
    code = _checked(proc)
    found = _report_files(report)
    for name in [*files, MERGE_FILE]:
        expect(f"git-range-{name}", code if name in found else 0, 1)

    for name, data in files.items():
        tree = root / f"no-git-{name}"
        tree.mkdir()
        (tree / name).write_bytes(data)
        expect(f"no-git-misses-{name}", scan_no_git(tree, CONFIG, root / f"no-git-{name}.json"), 0)


def main() -> None:
    if shutil.which(GITLEAKS) is None and not Path(GITLEAKS).is_file():
        raise SystemExit(f"gitleaks is not runnable ({GITLEAKS})")
    require_strict_config(CONFIG)
    with tempfile.TemporaryDirectory(prefix="gitleaks-scope-canary-") as tmp:
        root = Path(tmp)
        check_allowlist_shapes(root)
        check_chunk_shapes(root)
    require_expected_labels()
    print("gitleaks scope canary: strict allowlist and git-mode range find every probe")


if __name__ == "__main__":
    main()
