#!/usr/bin/env python3
"""Write the strict gitleaks configs that CI scans with.

``[extend] useDefault = true`` appends the global allowlist of the default
gitleaks 8.21.2 config to each repo config (``config.go``, ``extend``).
Gitleaks has no key that removes those entries. Some of them hide real
secrets:

- ``(?i)^true|false|null$`` binds ``^`` and ``$`` only to the outer
  alternatives. A secret that contains ``false`` anywhere is allowed.
- The path ``gitleaks\\.toml`` has no anchor, so ``docs/my-gitleaks.toml.md``
  is allowed. Other path entries match any file name that ends in ``bin``,
  ``doc``, or ``exe``.

This script writes the default config of that release with its global
allowlist replaced by ``STRICT_ALLOWLIST``. Then it writes a copy of each
repo config that extends that file by path. Only the ``useDefault`` line
changes, so the per-rule allowlists stay the text that the canaries read.
AGENTS.md gives the commands.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tomllib
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GITLEAKS_VERSION = "8.21.2"
# Commit of the v8.21.2 tag. The release binary embeds this exact file.
DEFAULT_CONFIG_COMMIT = "43fae355e6fe4d99d2a7b240a224b85e2903aeb4"
DEFAULT_CONFIG_URL = (
    "https://raw.githubusercontent.com/gitleaks/gitleaks/"
    f"{DEFAULT_CONFIG_COMMIT}/config/gitleaks.toml"
)
DEFAULT_CONFIG_SHA256 = "2ce9d818ed5aac0d9a36638a317284bd733c26d5069c980829335183397430bb"
BASE_NAME = f"gitleaks-default-{GITLEAKS_VERSION}.toml"
REPO_CONFIGS = (ROOT / ".gitleaks.toml", ROOT / ".gitleaks-emitted.toml")
FETCH_TIMEOUT_SECONDS = 30

# The default regexes, with the true/false/null alternation grouped so the
# anchors apply to the whole value. No path entries: no tracked file needs
# one, and gitleaks skips binary content without a path rule. Gitleaks 8.21.2
# does not merge the stopwords of an extended allowlist, so none are listed.
STRICT_ALLOWLIST = """[allowlist]
description = "Default placeholder values, anchored to the whole secret"
regexes = [
    '''(?i)^(?:true|false|null)$''',
    '''^(?i:a+|b+|c+|d+|e+|f+|g+|h+|i+|j+|k+|l+|m+|n+|o+|p+|q+|r+|s+|t+|u+|v+|w+|x+|y+|z+|\\*+|\\.+)$''',
    '''^\\$(\\d+|{\\d+})$''',
    '''^\\$([A-Z_]+|[a-z_]+)$''',
    '''^\\${([A-Z_]+|[a-z_]+)}$''',
    '''^\\{\\{[ \\t]*[\\w ().|]+[ \\t]*}}$''',
    '''^\\$\\{\\{[ \\t]*((env|github|secrets|vars)(\\.[A-Za-z]\\w+)+[\\w "'&./=|]*)[ \\t]*}}$''',
    '''^%([A-Z_]+|[a-z_]+)%$''',
    '''^%[+\\-# 0]?[bcdeEfFgGoOpqstTUvxX]$''',
    '''^\\{\\d{0,2}}$''',
    '''^@([A-Z_]+|[a-z_]+)@$''',
]
"""


class StrictConfigError(Exception):
    """The input does not have the shape that this builder rewrites."""


def _is_header(line: str) -> bool:
    return line.lstrip().startswith("[")


def _folded_header(line: str) -> str:
    return "".join(line.split()).lower()


def replace_global_allowlist(default_text: str) -> str:
    """Return ``default_text`` with its one ``[allowlist]`` table replaced."""
    lines = default_text.splitlines(keepends=True)
    headers = [index for index, line in enumerate(lines) if _is_header(line)]
    folded = [_folded_header(lines[index]) for index in headers]
    if folded.count("[allowlist]") != 1:
        raise StrictConfigError("the default config must have exactly one [allowlist] table")
    if "[extend]" in folded:
        raise StrictConfigError("the default config must not extend another config")
    position = folded.index("[allowlist]")
    start = headers[position]
    if lines[start].strip() != "[allowlist]":
        raise StrictConfigError("the [allowlist] header has an unexpected spelling")
    end = headers[position + 1] if position + 1 < len(headers) else len(lines)
    result = "".join(lines[:start]) + STRICT_ALLOWLIST + "\n" + "".join(lines[end:])

    before = tomllib.loads(default_text)
    after = tomllib.loads(result)
    if after.get("rules") != before.get("rules"):
        raise StrictConfigError("the replacement changed a rule")
    if after["allowlist"] != tomllib.loads(STRICT_ALLOWLIST)["allowlist"]:
        raise StrictConfigError("the replacement did not install the strict allowlist")
    return result


def extend_by_path(config_text: str, base_path: Path) -> str:
    """Return ``config_text`` with ``useDefault = true`` changed to ``path``."""
    if not base_path.is_absolute():
        raise StrictConfigError("the base path must be absolute: canaries scan from other directories")
    quoted = str(base_path)
    if "'" in quoted or any(ord(char) < 0x20 for char in quoted):
        raise StrictConfigError(f"a TOML literal string cannot hold {quoted!r}")
    lines = config_text.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines) if line.strip() == "useDefault = true"]
    if len(matches) != 1:
        raise StrictConfigError("the config must have exactly one 'useDefault = true' line")
    before = tomllib.loads(config_text)
    if before.get("extend") != {"useDefault": True}:
        raise StrictConfigError("[extend] must hold only useDefault = true")
    index = matches[0]
    newline = "\n" if lines[index].endswith("\n") else ""
    lines[index] = f"path = '{quoted}'{newline}"
    result = "".join(lines)

    after = tomllib.loads(result)
    if after.pop("extend") != {"path": quoted}:
        raise StrictConfigError("the rewrite did not set [extend] path")
    before.pop("extend")
    if after != before:
        raise StrictConfigError("the rewrite changed more than [extend]")
    return result


def verify_digest(data: bytes, expected: str = DEFAULT_CONFIG_SHA256) -> str:
    """Return ``data`` as text if its SHA-256 is ``expected``."""
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise StrictConfigError(f"default config sha256 is {actual}, want {expected}")
    return data.decode("utf-8")


def write_strict_configs(default_text: str, configs: list[Path], out_dir: Path) -> list[Path]:
    """Write the strict base and one strict copy of each config into ``out_dir``."""
    out_dir = out_dir.resolve()
    base_text = replace_global_allowlist(default_text)
    rewritten = [
        (config, extend_by_path(config.read_text(encoding="utf-8"), out_dir / BASE_NAME))
        for config in configs
    ]
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / BASE_NAME).write_text(base_text, encoding="utf-8")
    written: list[Path] = []
    for config, text in rewritten:
        target = out_dir / config.name.lstrip(".")
        target.write_text(text, encoding="utf-8")
        written.append(target)
    return written


def require_strict_config(config: Path) -> None:
    """Exit unless ``config`` is a strict copy that extends a base by path.

    A canary that scans with a ``useDefault`` config passes or fails for the
    wrong reason, because the default allowlist hides some probes.
    """
    try:
        extend = tomllib.loads(config.read_text(encoding="utf-8")).get("extend", {})
    except (OSError, tomllib.TOMLDecodeError):
        extend = {}
    if "path" not in extend:
        raise SystemExit(
            f"{config} is not a strict config. Run 'python3 scripts/gitleaks_strict_config.py "
            "--out-dir target/gitleaks' and set RVC_GITLEAKS_CONFIG to the absolute path of "
            "target/gitleaks/gitleaks.toml"
        )


def fetch_default(url: str = DEFAULT_CONFIG_URL) -> bytes:
    with urllib.request.urlopen(url, timeout=FETCH_TIMEOUT_SECONDS) as response:
        return response.read()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--default",
        type=Path,
        help=f"local copy of the default config (else download {DEFAULT_CONFIG_URL})",
    )
    args = parser.parse_args(argv)
    try:
        data = args.default.read_bytes() if args.default else fetch_default()
        written = write_strict_configs(verify_digest(data), list(REPO_CONFIGS), args.out_dir)
    except (OSError, StrictConfigError, tomllib.TOMLDecodeError) as err:
        print(f"gitleaks_strict_config: {err}", file=sys.stderr)
        return 1
    for path in written:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
