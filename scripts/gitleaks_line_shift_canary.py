#!/usr/bin/env python3
"""Prove the content allowlist survives line moves and still catches new secrets.

Gitleaks reports paths relative to ``--source`` when that source is ``.``.
The scans below run from a temporary directory so ``^crates/...$`` matches.
``--source canary`` would prefix every path with ``canary/`` and miss those anchors.

Each scan uses ``--ignore-gitleaks-allow`` and the real ``.gitleaks.toml``.
An inline allow comment is not a pass. A rebuilt config would force condition
AND and hide an OR entry that viper still reads from the real file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".gitleaks.toml"
GITLEAKS = os.environ.get("GITLEAKS_BIN", "gitleaks")

# Not an allowlisted path. A copied fixture value here must still be a finding.
OTHER_FILE = "crates/beacon/src/lib.rs"
# Allowlisted file used for the smuggle and graft cases.
GRAFT_FILE = "crates/beacon/src/types.rs"
REMOVED = "^__removed__$"


def unescape_anchored(pattern: str) -> str:
    body = pattern[1:-1]
    out: list[str] = []
    index = 0
    while index < len(body):
        if body[index] == "\\":
            out.append(body[index + 1])
            index += 2
            continue
        out.append(body[index])
        index += 1
    return "".join(out)


# Fixed literal, joined at runtime. An entropy floor is not enough: some
# draws above 3.5 are still not reported. The joined value is one gitleaks
# 8.21.2 reports under the real config (smuggle-fresh). Fragments stay
# separate so the full literal is not in this source file.
def fresh_token() -> str:
    return "qW3e" + "R7tY" + "1uI6" + "oP0a" + "S5dF" + "8gH2" + "jK4l" + "Z9xC"


def graft_prefix() -> str:
    return "Z9qR" + "7mK2"


def graft_suffix() -> str:
    return "p4Lm" + "8nQ1"


def load_allowlists() -> list[tuple[str, str, list[str]]]:
    """Return ``(rule id, path regex, regexes)`` in file order."""
    with CONFIG.open("rb") as handle:
        config = tomllib.load(handle)
    rows: list[tuple[str, str, list[str]]] = []
    for rule in config["rules"]:
        for entry in rule["allowlists"]:
            rows.append((rule["id"], entry["paths"][0], list(entry["regexes"])))
    return rows


def copy_without_regex(text: str, path_regex: str, secret_regex: str) -> str:
    """Return the real config with one regex in that path's block replaced.

    The replacement stays inside the block that names ``path_regex``. A rebuilt
    document would rewrite condition back to AND and hide an OR evasion.
    """
    if text.count(path_regex) != 1:
        raise SystemExit(f"path regex count is {text.count(path_regex)}")
    start = text.find(path_regex)
    block_start = text.rfind("[[rules.allowlists]]", 0, start)
    if block_start < 0:
        raise SystemExit("allowlist block not found")
    next_header = text.find("\n[[", start)
    end = len(text) if next_header < 0 else next_header + 1
    block = text[block_start:end]
    needle = "'''" + secret_regex + "'''"
    if block.count(needle) != 1:
        raise SystemExit(f"regex count is {block.count(needle)}")
    replaced = block.replace(needle, "'''" + REMOVED + "'''", 1)
    return text[:block_start] + replaced + text[end:]


def scan(source: Path, config: Path) -> int:
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
        ],
        cwd=source,
        check=False,
        capture_output=True,
        text=True,
    )
    err = proc.stderr
    if "no leaks found" not in err and "leaks found" not in err:
        sys.stderr.write(err)
        raise SystemExit(f"gitleaks did not finish (exit {proc.returncode})")
    if proc.returncode not in (0, 1):
        sys.stderr.write(err)
        raise SystemExit(f"unexpected gitleaks exit {proc.returncode}")
    return proc.returncode


REQUIRED_LABELS = frozenset(
    {
        "line-shift",
        "smuggle-fresh",
        "inline-allow",
        "synthetic-pem",
        "smuggle-other-file",
        "graft-prefix",
        "graft-suffix",
        "graft-both",
    }
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
    """Fail when ``expect`` did not run for every probe.

    A no-op ``expect`` still returns. This check is outside that function,
    so the missing labels fail the canary.
    """
    missing = REQUIRED_LABELS - seen_labels
    if missing:
        raise SystemExit("expected labels not hit: " + ", ".join(sorted(missing)))


def write_tree(root: Path, files: dict[str, bytes]) -> None:
    for rel, data in files.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)


def shifted(rel: str) -> bytes:
    return b"\n\n\n" + (ROOT / rel).read_bytes()


def synthetic_pem() -> bytes:
    """A private-key match that is not an allowlisted fixture.

    The begin marker is assembled so this source file does not itself contain
    the private-key keyword.
    """
    begin = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
    end = "-----" + "END RSA PRIVATE KEY" + "-----"
    body = "MIIB" + "OgIB" + "AAJB" + "AL7s" + "ynth" + "etic" + "CANA" + "RYKe" + "yMat" + "eria" + "l99"
    return f"{begin}\n{body}\n{end}\n".encode()


def main() -> None:
    if shutil.which(GITLEAKS) is None and not Path(GITLEAKS).is_file():
        raise SystemExit(f"gitleaks is not runnable ({GITLEAKS})")
    rows = load_allowlists()
    by_path = {unescape_anchored(path): (rule, path, regexes) for rule, path, regexes in rows}
    if GRAFT_FILE not in by_path:
        raise SystemExit(f"{GRAFT_FILE} is not allowlisted")
    if OTHER_FILE in by_path:
        raise SystemExit(f"{OTHER_FILE} is allowlisted; pick a different smuggle path")
    if not (ROOT / OTHER_FILE).is_file():
        raise SystemExit(f"missing {OTHER_FILE}")

    _graft_rule, _graft_path, graft_regexes = by_path[GRAFT_FILE]
    literal = unescape_anchored(graft_regexes[0])
    if any(char in literal for char in "\"\n\r"):
        raise SystemExit("graft literal cannot be placed in one quoted line")
    config_text = CONFIG.read_text(encoding="utf-8")
    fresh = fresh_token()
    prefix = graft_prefix()
    suffix = graft_suffix()
    if fresh in config_text or prefix in config_text or suffix in config_text:
        raise SystemExit("fixed canary token collides with the allowlist")
    parsed_regexes = sum(len(regexes) for _, _, regexes in rows)
    raw_literals = sum(1 for line in config_text.splitlines() if line.strip().startswith("'''^"))
    if raw_literals != parsed_regexes + len(rows):
        raise SystemExit(
            f"anchored literals {raw_literals}, expected {parsed_regexes} regexes plus {len(rows)} paths"
        )

    with tempfile.TemporaryDirectory(prefix="gitleaks-canary-") as tmp:
        root = Path(tmp)
        line_root = root / "line-shift"
        present = {
            unescape_anchored(path): shifted(unescape_anchored(path))
            for _rule, path, _rx in rows
            if (ROOT / unescape_anchored(path)).is_file()
        }
        if len(present) < 16:
            raise SystemExit(f"only {len(present)} allowlisted files exist in the tree")
        write_tree(line_root, present)
        shifted_files = 0
        for rel, data in present.items():
            original = (ROOT / rel).read_bytes()
            written = (line_root / rel).read_bytes()
            if written != data or written != b"\n\n\n" + original or written == original:
                raise SystemExit(f"shift did not apply to {rel}")
            shifted_files += 1
        if shifted_files != len(present):
            raise SystemExit(f"shifted {shifted_files}, copied {len(present)}")
        print(f"line-shift-files: {shifted_files}")
        expect("line-shift", scan(line_root, CONFIG), 0)

        smuggle = root / "smuggle-fresh"
        payload = shifted(GRAFT_FILE) + f'\napi_key = "{fresh}"\n'.encode()
        write_tree(smuggle, {GRAFT_FILE: payload})
        expect("smuggle-fresh", scan(smuggle, CONFIG), 1)

        inline = root / "inline-allow"
        inline_body = shifted(GRAFT_FILE) + f'\napi_key = "{fresh}" # gitleaks:allow\n'.encode()
        write_tree(inline, {GRAFT_FILE: inline_body})
        expect("inline-allow", scan(inline, CONFIG), 1)

        pem_tree = root / "synthetic-pem"
        write_tree(pem_tree, {"crates/beacon/src/lib.rs": synthetic_pem()})
        expect("synthetic-pem", scan(pem_tree, CONFIG), 1)

        other = root / "smuggle-other"
        other_payload = (ROOT / OTHER_FILE).read_bytes() + f'\napi_key = "{literal}"\n'.encode()
        write_tree(other, {OTHER_FILE: other_payload})
        expect("smuggle-other-file", scan(other, CONFIG), 1)

        grafts = {
            "graft-prefix": prefix + literal,
            "graft-suffix": literal + suffix,
            "graft-both": prefix + literal + suffix,
        }
        for label, value in grafts.items():
            tree = root / label
            body = shifted(GRAFT_FILE) + f'\napi_key = "{value}"\n'.encode()
            write_tree(tree, {GRAFT_FILE: body})
            expect(label, scan(tree, CONFIG), 1)

        # Each regex is checked on a one-line file at its allowlisted path.
        # Chunk prefixes are not all present in the working tree at once, so
        # the real file cannot show that every prefix is load-bearing.
        mutations = 0
        for rule, path, regexes in rows:
            rel = unescape_anchored(path)
            for regex_index, regex in enumerate(regexes):
                value = unescape_anchored(regex)
                if any(char in value for char in "\"\r"):
                    raise SystemExit(f"mutation value in {rel} cannot be quoted")
                if rule == "private-key":
                    body = value if value.endswith("\n") else value + "\n"
                else:
                    body = f'api_key = "{value}"\n'
                tree = root / f"mut-{mutations}"
                write_tree(tree, {rel: body.encode()})
                if scan(tree, CONFIG) != 0:
                    raise SystemExit(f"mutation control {rule} {rel} regex {regex_index} was not allowed")
                mutated_path = root / f"mut-{mutations}.toml"
                mutated_path.write_text(
                    copy_without_regex(config_text, path, regex),
                    encoding="utf-8",
                )
                code = scan(tree, mutated_path)
                if code != 1:
                    raise SystemExit(
                        f"mutation {rule} {rel} regex {regex_index}: exit {code}, want 1"
                    )
                mutations += 1
        if mutations != parsed_regexes:
            raise SystemExit(f"mutation count {mutations}, expected {parsed_regexes}")
        print(f"mutation: {mutations} removed entries still detected")

    require_expected_labels()
    print("gitleaks line-shift canary: line moves allowed; new and grafted values caught")


if __name__ == "__main__":
    main()
