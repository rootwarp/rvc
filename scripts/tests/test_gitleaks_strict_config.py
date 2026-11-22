"""Tests for scripts/gitleaks_strict_config.py.

The builder swaps the default global allowlist of gitleaks 8.21.2 for a
strict one and points ``.gitleaks.toml`` at that file. These tests use a
small default-shaped document. The real default file is not in the tree.
"""

from __future__ import annotations

import hashlib
import re
import tomllib
from pathlib import Path

import pytest

from conftest import load_script

ROOT = Path(__file__).resolve().parents[2]
INSTALL_SCRIPT = ROOT / "scripts" / "install_gitleaks.sh"

MINI_DEFAULT = """title = "gitleaks config"

[allowlist]
description = "global allow lists"
regexes = [
    '''(?i)^true|false|null$''',
]
paths = [
    '''gitleaks\\.toml''',
]
stopwords = [
    "abc",
]

[[rules]]
id = "generic-api-key"
regex = '''(?i)key\\s*=\\s*([a-z0-9]{10,})'''
keywords = ["key"]

[[rules]]
id = "private-key"
regex = '''(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY'''
keywords = ["-----begin"]
"""


@pytest.fixture(scope="module")
def gsc():
    return load_script("gitleaks_strict_config")


def _strict_allowlist(gsc) -> dict:
    return tomllib.loads(gsc.STRICT_ALLOWLIST)["allowlist"]


def test_replace_global_allowlist_swaps_only_the_global_table(gsc):
    original = tomllib.loads(MINI_DEFAULT)
    replaced = tomllib.loads(gsc.replace_global_allowlist(MINI_DEFAULT))
    assert replaced["allowlist"] == _strict_allowlist(gsc)
    assert replaced["rules"] == original["rules"]
    assert replaced["title"] == original["title"]


@pytest.mark.parametrize(
    "text",
    [
        MINI_DEFAULT.replace("[allowlist]", "[allowlist-x]"),
        MINI_DEFAULT + "\n[allowlist]\npaths = ['''x''']\n",
        MINI_DEFAULT.replace("[allowlist]", "[Allowlist]"),
        MINI_DEFAULT + "\n[extend]\nuseDefault = true\n",
    ],
    ids=["missing", "twice", "case-variant", "extend"],
)
def test_replace_global_allowlist_rejects_other_shapes(gsc, text):
    with pytest.raises(gsc.StrictConfigError):
        gsc.replace_global_allowlist(text)


SHAPES_THE_DEFAULT_HIDES = [
    "k7Qm9pL2xV8nfalseR4wT6yH3cB5dF1aE0sZ",
    "truek7Qm9pL2xV8nR4wT6yH3cB5dF1aE0sZ",
    "k7Qm9pL2xV8nR4wT6yH3cB5dF1aE0sZnull",
]


def test_strict_regexes_match_only_whole_placeholder_values(gsc):
    regexes = [re.compile(item) for item in _strict_allowlist(gsc)["regexes"]]
    bad_default = re.compile(r"(?i)^true|false|null$")
    for secret in SHAPES_THE_DEFAULT_HIDES:
        assert bad_default.search(secret), secret
        assert not any(rx.search(secret) for rx in regexes), secret
    for placeholder in ["false", "TRUE", "null", "${API_KEY}", "aaaaaaaaaa"]:
        assert any(rx.search(placeholder) for rx in regexes), placeholder


def test_strict_allowlist_has_no_path_or_stopword_entries(gsc):
    allowlist = _strict_allowlist(gsc)
    assert sorted(allowlist) == ["description", "regexes"]
    assert r"(?i)^true|false|null$" not in allowlist["regexes"]


def test_extend_by_path_changes_only_the_use_default_line(gsc, tmp_path):
    for name in (".gitleaks.toml", ".gitleaks-emitted.toml"):
        text = (ROOT / name).read_text(encoding="utf-8")
        base = tmp_path / "gitleaks-default.toml"
        strict = gsc.extend_by_path(text, base)
        before = tomllib.loads(text)
        after = tomllib.loads(strict)
        assert after.pop("extend") == {"path": str(base)}
        before.pop("extend")
        assert after == before
        changed = [
            (old, new)
            for old, new in zip(text.splitlines(), strict.splitlines(), strict=True)
            if old != new
        ]
        assert changed == [("useDefault = true", f"path = '{base}'")]


@pytest.mark.parametrize(
    "text",
    [
        "[extend]\npath = 'x'\n",
        "[extend]\nuseDefault = true\nuseDefault = true\n",
        "[extend]\nUseDefault = true\n",
        "[extend]\nuseDefault = false\n",
    ],
    ids=["missing", "twice", "case-variant", "false"],
)
def test_extend_by_path_rejects_other_extend_shapes(gsc, tmp_path, text):
    with pytest.raises(gsc.StrictConfigError):
        gsc.extend_by_path(text, tmp_path / "base.toml")


@pytest.mark.parametrize(
    "base",
    [Path("/tmp/it's.toml"), Path("/tmp/line\nbreak.toml"), Path("target/gitleaks/base.toml")],
    ids=["quote", "newline", "relative"],
)
def test_extend_by_path_rejects_a_base_path_it_cannot_use(gsc, base):
    text = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    with pytest.raises(gsc.StrictConfigError):
        gsc.extend_by_path(text, base)


def test_verify_digest_accepts_only_the_pinned_bytes(gsc):
    data = MINI_DEFAULT.encode()
    good = hashlib.sha256(data).hexdigest()
    assert gsc.verify_digest(data, good) == MINI_DEFAULT
    with pytest.raises(gsc.StrictConfigError):
        gsc.verify_digest(data + b"\n", good)


def test_write_strict_configs_writes_base_and_one_file_per_config(gsc, tmp_path):
    configs = [ROOT / ".gitleaks.toml", ROOT / ".gitleaks-emitted.toml"]
    out = tmp_path / "out"
    written = gsc.write_strict_configs(MINI_DEFAULT, configs, out)
    assert [path.name for path in written] == ["gitleaks.toml", "gitleaks-emitted.toml"]
    base = out / gsc.BASE_NAME
    assert tomllib.loads(base.read_text(encoding="utf-8"))["allowlist"] == _strict_allowlist(gsc)
    for path in written:
        assert path.parent == out.resolve()
        assert tomllib.loads(path.read_text(encoding="utf-8"))["extend"] == {
            "path": str(base.resolve())
        }


def test_main_fails_closed_on_a_default_file_with_other_bytes(gsc, tmp_path, capsys):
    fake = tmp_path / "default.toml"
    fake.write_text(MINI_DEFAULT, encoding="utf-8")
    code = gsc.main(["--default", str(fake), "--out-dir", str(tmp_path / "out")])
    assert code == 1
    assert "sha256" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_pinned_default_matches_the_installed_release(gsc):
    assert gsc.DEFAULT_CONFIG_COMMIT in gsc.DEFAULT_CONFIG_URL
    assert re.fullmatch(r"[0-9a-f]{40}", gsc.DEFAULT_CONFIG_COMMIT)
    assert re.fullmatch(r"[0-9a-f]{64}", gsc.DEFAULT_CONFIG_SHA256)
    install = INSTALL_SCRIPT.read_text(encoding="utf-8")
    assert f"GITLEAKS_VERSION={gsc.GITLEAKS_VERSION}\n" in install


def test_require_strict_config_accepts_only_a_copy_that_extends_by_path(gsc, tmp_path):
    strict = gsc.write_strict_configs(MINI_DEFAULT, [ROOT / ".gitleaks.toml"], tmp_path)[0]
    gsc.require_strict_config(strict)
    broken = tmp_path / "broken.toml"
    broken.write_text("[extend\n", encoding="utf-8")
    for config in (ROOT / ".gitleaks.toml", tmp_path / "absent.toml", broken):
        with pytest.raises(SystemExit, match="RVC_GITLEAKS_CONFIG"):
            gsc.require_strict_config(config)
