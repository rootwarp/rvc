"""A small stand-in for ``gitleaks detect`` 8.21.2, for canary tests.

It finds ``api_key = "<value>"`` and PEM blocks, and applies the global and
rule allowlists, the no-git chunking, and the ``git log -p -U0`` reading of
8.21.2. When git writes to stderr, it reports ``failed to scan Git
repository`` and still exits 0, as 8.21.2 does. ``FAKE_GITLEAKS_CRASH=1``
makes it exit 2.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

CHUNK_SIZE = 10_000
GENERIC = re.compile(r'api_key = "([^"\n]+)"')
# The markers are joined so this file does not hold a private-key header.
_DASHES = "-" * 5
PEM = re.compile(
    _DASHES + "BEGIN[ A-Z]*PRIVATE KEY" + _DASHES + r"[\s\S]*?" + _DASHES + "END[ A-Z]*PRIVATE KEY" + _DASHES
)
FAULTY_DEFAULT_REGEXES = [r"(?i)^true|false|null$"]
FAULTY_DEFAULT_PATHS = [
    r"gitleaks\.toml",
    r"(.*?)(doc|docx|zip|xls|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$",
]


def _option(args: list[str], name: str) -> str | None:
    for index, arg in enumerate(args):
        if arg == name:
            return args[index + 1]
        if arg.startswith(name + "="):
            return arg.split("=", 1)[1]
    return None


def _global_allowlist(config: dict) -> tuple[list[str], list[str]]:
    own = config.get("allowlist", {})
    paths = list(own.get("paths", []))
    regexes = list(own.get("regexes", []))
    extend = config.get("extend", {})
    if extend.get("useDefault"):
        paths += FAULTY_DEFAULT_PATHS
        regexes += FAULTY_DEFAULT_REGEXES
    elif "path" in extend:
        with open(extend["path"], "rb") as handle:
            base = tomllib.load(handle).get("allowlist", {})
        paths += base.get("paths", [])
        regexes += base.get("regexes", [])
    return paths, regexes


def _rule_allows(config: dict, rule_id: str, rel: str, secret: str) -> bool:
    for rule in config.get("rules", []):
        if rule.get("id") != rule_id:
            continue
        for entry in rule.get("allowlists", []):
            path_hit = any(re.search(rx, rel) for rx in entry.get("paths", []))
            regex_hit = any(re.search(rx, secret) for rx in entry.get("regexes", []))
            if str(entry.get("condition", "OR")).upper() == "AND":
                if path_hit and regex_hit:
                    return True
            elif path_hit or regex_hit:
                return True
    return False


def _chunks(data: bytes) -> list[str]:
    out: list[str] = []
    for start in range(0, len(data), CHUNK_SIZE):
        chunk = data[start : start + CHUNK_SIZE]
        if chunk.startswith(b"%PDF"):
            break
        out.append(chunk.decode("utf-8", "replace"))
    return out


def _hits(fragment: str) -> list[tuple[str, str]]:
    hits = [("generic-api-key", m.group(1)) for m in GENERIC.finditer(fragment)]
    return hits + [("private-key", m.group(0)) for m in PEM.finditer(fragment)]


def _findings(config: dict, fragments: list[tuple[str, str]]) -> list[dict]:
    paths, regexes = _global_allowlist(config)
    found: list[dict] = []
    for rel, fragment in fragments:
        if any(re.search(rx, rel) for rx in paths):
            continue
        for rule_id, secret in _hits(fragment):
            if any(re.search(rx, secret) for rx in regexes):
                continue
            if _rule_allows(config, rule_id, rel, secret):
                continue
            found.append({"File": rel, "RuleID": rule_id, "Secret": secret})
    return found


def _tree_fragments() -> list[tuple[str, str]]:
    files = sorted(
        str(path.relative_to("."))
        for path in Path(".").rglob("*")
        if path.is_file() and ".git" not in path.parts
    )
    return [(rel, chunk) for rel in files for chunk in _chunks(Path(rel).read_bytes())]


def _patch_fragments(patch: str) -> list[tuple[str, str]]:
    """Return ``(path, added lines)`` for each hunk of ``git log -p`` output."""
    out: list[tuple[str, str]] = []
    path: str | None = None
    added: list[str] | None = None

    def flush() -> None:
        if path is not None and added:
            out.append((path, "\n".join(added) + "\n"))

    for line in patch.splitlines():
        if line.startswith(("diff --git ", "commit ")):
            flush()
            path, added = None, None
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else None
        elif line.startswith("@@"):
            flush()
            added = []
        elif added is not None and line.startswith("+"):
            added.append(line[1:])
    flush()
    return out


def _git_fragments(log_opts: str | None) -> list[tuple[str, str]] | None:
    """Return the fragments, or ``None`` when git wrote to stderr."""
    words = log_opts.split(" ") if log_opts else ["--full-history", "--all"]
    proc = subprocess.run(
        ["git", "log", "-p", "-U0", *words], check=False, capture_output=True, text=True
    )
    if proc.returncode != 0 or proc.stderr:
        for line in proc.stderr.splitlines():
            print(f"ERR [git] {line}", file=sys.stderr)
        print('ERR failed to scan Git repository error="stderr is not empty"', file=sys.stderr)
        return None
    return _patch_fragments(proc.stdout)


def main(args: list[str]) -> int:
    if os.environ.get("FAKE_GITLEAKS_CRASH") == "1":
        print("fatal: fake crash", file=sys.stderr)
        return 2
    if args[:1] != ["detect"] or _option(args, "--source") != ".":
        print(f"fake gitleaks: unsupported arguments {args}", file=sys.stderr)
        return 2
    with open(_option(args, "--config"), "rb") as handle:
        config = tomllib.load(handle)
    if "--no-git" in args:
        fragments = _tree_fragments()
    else:
        fragments = _git_fragments(_option(args, "--log-opts")) or []
    found = _findings(config, fragments)
    report = _option(args, "--report-path")
    if report:
        Path(report).write_text(json.dumps(found), encoding="utf-8")
    print(f"leaks found: {len(found)}" if found else "no leaks found", file=sys.stderr)
    return 1 if found and _option(args, "--exit-code") == "1" else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
