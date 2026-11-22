"""Shape guard for the source-tree gitleaks allowlist (FU-C2).

Line fingerprints (``.gitleaksignore``) move when lines move. The replacement
is one rule allowlist per file: condition AND, one anchored path, and
anchored regexes that equal the captured secret. A wider pattern is a failure
of this guard.

Gitleaks 8.21.2 uppercases ``condition`` and treats an empty condition as OR
(``config.go``). Viper matches keys without regard to case, so ``Condition``
and ``[Allowlist]`` are the same fields as ``condition`` and ``[allowlist]``.
This guard folds keys the same way, rejects a case-only duplicate, and allows
only a fixed set of keys at each level. ``line`` and ``match`` regex targets
are rejected in any case because the key itself is not in that set.

``useDefault`` merges gitleaks' own allowlists into each rule after this file
is parsed. This guard reads only the tables in ``.gitleaks.toml``. It does
not inspect those merged default entries.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest
import yaml

from conftest import load_script

ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / ".gitleaks.toml"
IGNORE_PATH = ROOT / ".gitleaksignore"
CI_PATH = ROOT / ".github" / "workflows" / "ci.yml"
AGENTS_PATH = ROOT / "AGENTS.md"

# RE2 metacharacters. An unescaped one widens the match. Hyphen is not one
# outside a character class; PEM headers still escape it so this file does not
# contain a private-key keyword.
_META = set(r".^$*+?()[]{}|\\")

_GLOBAL_PATHS = [
    r"(^|/)target/",
    r"(^|/)tests/",
]

_BUILD = "python3 scripts/gitleaks_strict_config.py --out-dir target/gitleaks"
_SCAN = (
    "gitleaks detect --no-git --source . --config target/gitleaks/gitleaks.toml "
    "--ignore-gitleaks-allow --redact --no-banner --exit-code 1"
)
_HISTORY = './scripts/gitleaks_range_scan.sh "$PWD/target/gitleaks/gitleaks.toml" --history'
_CANARY_ENV = 'RVC_GITLEAKS_CONFIG="$PWD/target/gitleaks/gitleaks.toml"'

# Keys gitleaks will honor, folded to lowercase. Anything else is rejected,
# including a singular rule allowlist and a second global allowlist table.
_TOP_KEYS = frozenset({"title", "extend", "allowlist", "rules"})
_EXTEND_KEYS = frozenset({"usedefault"})
_GLOBAL_KEYS = frozenset({"description", "paths"})
_RULE_KEYS = frozenset({"id", "allowlists"})
_ENTRY_KEYS = frozenset({"description", "condition", "paths", "regexes"})


def _fresh_token() -> str:
    """Same joined value as the canary. The full literal is not in this file."""
    return "qW3e" + "R7tY" + "1uI6" + "oP0a" + "S5dF" + "8gH2" + "jK4l" + "Z9xC"


def _closing_anchor_escaped(pattern: str) -> bool:
    slashes = 0
    index = len(pattern) - 2
    while index >= 1 and pattern[index] == "\\":
        slashes += 1
        index -= 1
    return slashes % 2 == 1


def anchored_literal_problem(pattern: object) -> str | None:
    """Return why ``pattern`` is not ``^`` + escaped literal + ``$``.

    Escaping a letter or digit (``\\s``, ``\\d``, ``\\n``, ``\\x41``) is
    rejected: those are classes or encodings, not one exact character.
    """
    if not isinstance(pattern, str):
        return "pattern is not a string"
    if len(pattern) < 2 or not pattern.startswith("^") or not pattern.endswith("$"):
        return "pattern is not anchored"
    if _closing_anchor_escaped(pattern):
        return "closing anchor is escaped"
    body = pattern[1:-1]
    if body == "":
        return "empty literal"
    index = 0
    while index < len(body):
        char = body[index]
        if char == "\\":
            if index + 1 >= len(body):
                return "dangling escape"
            nxt = body[index + 1]
            if nxt.isalnum():
                return f"non-literal escape \\{nxt}"
            index += 2
            continue
        if char in _META:
            return f"unescaped metacharacter {char!r}"
        index += 1
    return None


def fold_keys(table: dict) -> tuple[dict[str, object], list[str]]:
    """Map lowercase key to value. A second spelling of the same key is an error.

    Viper keeps one value when ``condition`` and ``Condition`` are both set.
    Keeping both in this check would let the guard grade the spelling gitleaks
    did not use.
    """
    folded: dict[str, object] = {}
    problems: list[str] = []
    for key, value in table.items():
        if not isinstance(key, str):
            problems.append("key is not a string")
            continue
        low = key.lower()
        if low in folded:
            problems.append(f"case-only duplicate key {key}")
            continue
        folded[low] = value
    return folded, problems


def _unknown(folded: dict[str, object], allowed: frozenset[str], kind: str) -> list[str]:
    return [f"unknown {kind} key {key}" for key in sorted(set(folded) - allowed)]


def allowlist_problems(entry: object) -> list[str]:
    """Problems in one ``[[rules.allowlists]]`` table. Empty means in shape."""
    if not isinstance(entry, dict):
        return ["allowlist is not a table"]
    folded, problems = fold_keys(entry)
    problems.extend(_unknown(folded, _ENTRY_KEYS, "allowlist"))
    condition = folded.get("condition", None)
    if not isinstance(condition, str) or condition.upper() != "AND":
        problems.append("condition must be AND")
    paths = folded.get("paths")
    if not isinstance(paths, list) or len(paths) != 1:
        problems.append("allowlist needs exactly one path")
    else:
        path_problem = anchored_literal_problem(paths[0])
        if path_problem is not None:
            problems.append(f"path: {path_problem}")
    regexes = folded.get("regexes")
    if not isinstance(regexes, list) or not regexes:
        problems.append("allowlist needs at least one regex")
    elif isinstance(regexes, list):
        for regex in regexes:
            regex_problem = anchored_literal_problem(regex)
            if regex_problem is not None:
                problems.append(f"regex: {regex_problem}")
    return problems


def config_problems(config: dict) -> list[str]:
    """Problems in one parsed ``.gitleaks.toml`` document.

    Does not load the allowlists ``useDefault`` merges in from the default
    rules. Those entries are not in this document.
    """
    if not isinstance(config, dict):
        return ["config is not a table"]
    folded, problems = fold_keys(config)
    problems.extend(_unknown(folded, _TOP_KEYS, "top-level"))

    extend = folded.get("extend")
    if not isinstance(extend, dict):
        problems.append("extend must be a table")
    else:
        extend_folded, extend_problems = fold_keys(extend)
        problems.extend(extend_problems)
        problems.extend(_unknown(extend_folded, _EXTEND_KEYS, "extend"))
        if extend_folded.get("usedefault") is not True:
            problems.append("useDefault must be true")

    global_allow = folded.get("allowlist")
    if not isinstance(global_allow, dict):
        problems.append("global allowlist must be a table")
    else:
        global_folded, global_problems = fold_keys(global_allow)
        problems.extend(global_problems)
        problems.extend(_unknown(global_folded, _GLOBAL_KEYS, "global allowlist"))
        if global_folded.get("paths") != _GLOBAL_PATHS:
            problems.append("global allowlist paths changed")

    rules = folded.get("rules")
    if not isinstance(rules, list) or not rules:
        problems.append("rules must be a non-empty array")
        return problems

    ids: list[str] = []
    for rule in rules:
        if not isinstance(rule, dict):
            problems.append("rule is not a table")
            continue
        rule_folded, rule_problems = fold_keys(rule)
        problems.extend(rule_problems)
        problems.extend(_unknown(rule_folded, _RULE_KEYS, "rule"))
        rule_id = rule_folded.get("id")
        if not isinstance(rule_id, str):
            problems.append("rule id must be a string")
        else:
            ids.append(rule_id)
        allowlists = rule_folded.get("allowlists")
        if not isinstance(allowlists, list) or not allowlists:
            problems.append(f"{rule_id} needs allowlists")
            continue
        for entry in allowlists:
            problems.extend(allowlist_problems(entry))
    if ids.count("generic-api-key") != 1 or ids.count("private-key") != 1 or len(ids) != 2:
        problems.append(f"rule ids {ids}")
    return problems


def load_config() -> dict:
    with CONFIG_PATH.open("rb") as handle:
        return tomllib.load(handle)


class _WorkflowLoader(yaml.SafeLoader):
    """Keep GitHub's ``on:`` key as a string. ``true`` and ``false`` stay booleans."""


def _construct_loose_bool(loader: yaml.SafeLoader, node: yaml.Node):
    raw = loader.construct_scalar(node)
    lowered = raw.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return raw


_WorkflowLoader.add_constructor("tag:yaml.org,2002:bool", _construct_loose_bool)


def test_no_line_fingerprint_file():
    assert not IGNORE_PATH.exists(), ".gitleaksignore line fingerprints must be gone"


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


def test_every_rule_allowlist_is_and_path_bound_and_anchored():
    text = CONFIG_PATH.read_text(encoding="utf-8")
    folded_text = text.lower()
    assert "regextarget" not in folded_text
    assert "gitleaks:allow" not in folded_text
    assert ".gitleaksignore" not in folded_text
    assert "-----begin" not in folded_text

    config = load_config()
    problems = config_problems(config)
    assert problems == [], problems
    rules = config["rules"]

    seen_paths: set[str] = set()
    seen_files: set[str] = set()
    for rule in rules:
        allowlists = rule.get("allowlists") or []
        assert allowlists, f"{rule['id']} has no allowlist"
        for entry in allowlists:
            problems = allowlist_problems(entry)
            assert problems == [], problems
            path = entry["paths"][0]
            assert path not in seen_paths, f"duplicate allowlist path {path}"
            seen_paths.add(path)
            relative = unescape_anchored(path)
            parts = Path(relative).parts
            assert parts and ".." not in parts and not Path(relative).is_absolute()
            seen_files.add(relative)
            values = [unescape_anchored(regex) for regex in entry["regexes"]]
            assert len(values) == len(set(values))
            for value in values:
                assert len(value) >= 10
            # A shorter value may sit beside a longer one only when it is an
            # exact prefix of that fixture. Gitleaks 8.21.2 reads the working
            # tree in 10000-byte chunks with no overlap, so a value that
            # straddles a boundary is captured as a prefix. 35 is the shortest
            # prefix of that fixture the rule still reports.
            for value in values:
                longer = [
                    other
                    for other in values
                    if len(other) > len(value) and other.startswith(value)
                ]
                if longer:
                    assert len(value) >= 35

    assert any("docs/running-guide.md" == unescape_anchored(path) for path in seen_paths)
    for required in (
        "docs/running-guide.md",
        "crates/beacon/src/types.rs",
        "crates/slashing/src/db/interchange.rs",
        "crates/signer-server/src/http_api/tls_config/tests.rs",
        "validators.example.toml",
    ):
        assert required in seen_files
        assert (ROOT / required).is_file()
    flat = CONFIG_PATH.read_text(encoding="utf-8")
    assert r"^0x97f1d3a731\.\.\.db22c6bb$" in flat


@pytest.mark.parametrize(
    "entry",
    [
        {
            "condition": "AND",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["0xabc123456789"],
        },
        {
            "condition": "AND",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^.*$"],
        },
        {
            "condition": "OR",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "||",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "&&",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "AND",
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "AND",
            "regexTarget": "line",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "AND",
            "regexTarget": "match",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "AND",
            "regexTarget": "LINE",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "AND",
            "RegexTarget": "Match",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "AND",
            "paths": [r"(^|/)crates/beacon/src/types\.rs$"],
            "regexes": ["^0xabc123456789$"],
        },
        {
            "condition": "AND",
            "paths": [r"^crates/beacon/src/types\.rs$"],
            "regexes": [r"^0xabc\d+$"],
        },
    ],
)
def test_invalid_allowlist_shapes_are_rejected(entry: dict):
    assert allowlist_problems(entry), entry


def test_exact_secret_shape_is_accepted():
    entry = {
        "condition": "AND",
        "paths": [r"^docs/running-guide\.md$"],
        "regexes": [r"^0x97f1d3a731\.\.\.db22c6bb$"],
    }
    assert allowlist_problems(entry) == []


def test_condition_or_case_variant_is_rejected():
    """Gitleaks uppercases condition. A second key ``Condition = "OR"`` is OR."""
    entry = {
        "description": "Exact fixture values",
        "condition": "AND",
        "Condition": "OR",
        "paths": [r"^crates/duty\-tracker/src/tracker\.rs$"],
        "regexes": ["^0xpubkey_1234$"],
    }
    assert allowlist_problems(entry)


def test_second_allowlist_table_is_rejected():
    """Viper merges ``[Allowlist]`` into the global allowlist. tomllib keeps both keys."""
    text = CONFIG_PATH.read_text(encoding="utf-8")
    text += "\n[Allowlist]\npaths = ['''^crates/beacon/src/types\\.rs$''']\nregexes = ['''.*''']\n"
    document = tomllib.loads(text)
    assert config_problems(document)


def test_private_key_rule_override_is_rejected():
    """entropy or regex on the rule replaces the default and drops real keys."""
    config = load_config()
    private = next(rule for rule in config["rules"] if rule["id"] == "private-key")
    private["entropy"] = 99.0
    assert config_problems(config)
    del private["entropy"]
    private["regex"] = "a^"
    assert config_problems(config)


def test_ignore_gitleaks_allow_is_required_on_scans():
    canary = (ROOT / "scripts" / "gitleaks_line_shift_canary.py").read_text(encoding="utf-8")
    verify = (ROOT / "scripts" / "gitleaks_verify_false_canary.sh").read_text(encoding="utf-8")
    scan_body = canary.split("def scan", 1)[1].split("\ndef ", 1)[0]
    assert "--ignore-gitleaks-allow" in scan_body
    assert "gitleaks:allow" in canary
    assert "--ignore-gitleaks-allow" in verify


def test_rule_allowlist_override_is_rejected():
    """The singular ``[rules.allowlist]`` replaces ``[[rules.allowlists]]`` when used alone."""
    config = load_config()
    config["rules"][0]["allowlist"] = {
        "condition": "OR",
        "paths": [r"^crates/beacon/src/types\.rs$"],
    }
    assert config_problems(config)


def test_top_level_allowlists_array_is_rejected():
    text = CONFIG_PATH.read_text(encoding="utf-8")
    text += "\n[[allowlists]]\ncondition = \"OR\"\npaths = ['''^crates/beacon/src/types\\.rs$''']\n"
    document = tomllib.loads(text)
    assert config_problems(document)


def test_lowercase_and_is_accepted():
    entry = {
        "condition": "and",
        "paths": [r"^docs/running-guide\.md$"],
        "regexes": [r"^0x97f1d3a731\.\.\.db22c6bb$"],
    }
    assert allowlist_problems(entry) == []


def test_canary_uses_real_config_and_fixed_token():
    text = (ROOT / "scripts" / "gitleaks_line_shift_canary.py").read_text(encoding="utf-8")
    own = Path(__file__).read_text(encoding="utf-8")
    token = _fresh_token()
    assert "token_hex" not in text
    assert "render_config" not in text
    assert 'condition = "AND"' not in text
    assert token not in text
    assert token not in own
    for part in ("qW3e", "R7tY", "1uI6", "oP0a", "S5dF", "8gH2", "jK4l", "Z9xC"):
        assert part in text


def test_canary_require_labels_survives_noop_expect():
    text = (ROOT / "scripts" / "gitleaks_line_shift_canary.py").read_text(encoding="utf-8")
    expect_body = text.split("def expect", 1)[1].split("\ndef ", 1)[0]
    main_body = text.split("def main", 1)[1]
    assert "seen_labels.add" in expect_body
    assert "require_expected_labels()" in main_body
    assert "def require_expected_labels" in text


def test_secret_scan_job_pins_content_allowlist():
    document = yaml.load(CI_PATH.read_text(encoding="utf-8"), Loader=_WorkflowLoader)
    steps = document["jobs"]["secret-scan"]["steps"]
    runs = {step.get("name"): step.get("run", "") for step in steps}
    source = runs["Gitleaks — source tree"]
    assert "--ignore-gitleaks-allow" in source
    assert "--no-git" in source
    assert '--config "$RVC_GITLEAKS_CONFIG"' in source
    canary = runs["Gitleaks — line-shift canary"]
    assert "gitleaks_line_shift_canary.py" in canary
    script = ROOT / "scripts" / "gitleaks_line_shift_canary.py"
    assert script.is_file()


def test_agents_md_documents_gitleaks_command_and_size_cap():
    text = AGENTS_PATH.read_text(encoding="utf-8")
    assert _BUILD in text
    assert _SCAN in text
    assert _HISTORY in text
    assert _CANARY_ENV in text
    assert "--config .gitleaks.toml" not in text
    assert "History scan:" in text
    assert "git diff --shortstat develop...HEAD" in text
    assert "2,000" in text
    assert "1,800" in text


def test_line_shift_canary_reads_the_strict_config_from_env(monkeypatch, tmp_path):
    strict = tmp_path / "gitleaks.toml"
    monkeypatch.setenv("RVC_GITLEAKS_CONFIG", str(strict))
    assert load_script("gitleaks_line_shift_canary").CONFIG == strict
    monkeypatch.delenv("RVC_GITLEAKS_CONFIG")
    assert load_script("gitleaks_line_shift_canary").CONFIG == CONFIG_PATH


def test_verify_false_canary_reads_the_strict_config_from_env():
    verify = (ROOT / "scripts" / "gitleaks_verify_false_canary.sh").read_text(encoding="utf-8")
    assert 'config="${RVC_GITLEAKS_CONFIG:-$root/.gitleaks.toml}"' in verify
