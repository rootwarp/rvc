"""Tests for scripts/gitleaks_line_shift_canary.py.

Most tests use ``fake_gitleaks.py``, which applies the allowlists the way
gitleaks 8.21.2 does. One test runs the real binary when gitleaks 8.21.2 and
a strict config are present.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import load_script

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def canary(monkeypatch):
    module = load_script("gitleaks_line_shift_canary")
    monkeypatch.setattr(module, "seen_labels", set())
    return module


@pytest.fixture
def faked(canary, monkeypatch, fake_gitleaks, strict_gitleaks_config):
    monkeypatch.setattr(canary, "GITLEAKS", str(fake_gitleaks))
    monkeypatch.setattr(canary, "CONFIG", strict_gitleaks_config)
    return canary


def test_main_passes_with_the_strict_config(faked, capsys):
    faked.main()
    out = capsys.readouterr().out
    assert "line moves allowed; new and grafted values caught" in out
    assert "removed entries still detected" in out
    assert faked.seen_labels == faked.REQUIRED_LABELS


def test_main_refuses_the_use_default_config(faked, monkeypatch):
    monkeypatch.setattr(faked, "CONFIG", ROOT / ".gitleaks.toml")
    with pytest.raises(SystemExit, match="RVC_GITLEAKS_CONFIG"):
        faked.main()


def test_default_config_hides_a_removed_entry_so_the_strict_config_is_required(
    faked, monkeypatch
):
    monkeypatch.setattr(faked, "require_strict_config", lambda config: None)
    monkeypatch.setattr(faked, "CONFIG", ROOT / ".gitleaks.toml")
    with pytest.raises(SystemExit, match=r"scripts/create_validator_keys\.sh regex 0: exit 0, want 1"):
        faked.main()


def test_main_fails_when_gitleaks_does_not_finish(faked, monkeypatch, capsys):
    monkeypatch.setenv("FAKE_GITLEAKS_CRASH", "1")
    with pytest.raises(SystemExit, match="did not finish"):
        faked.main()
    assert "fake crash" in capsys.readouterr().err


def test_main_fails_when_gitleaks_is_not_runnable(canary, monkeypatch, tmp_path):
    monkeypatch.setattr(canary, "GITLEAKS", str(tmp_path / "missing-gitleaks"))
    with pytest.raises(SystemExit, match="not runnable"):
        canary.main()


def test_copy_without_regex_replaces_one_regex_in_its_own_block(canary):
    text = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    path = r"^scripts/create_validator_keys\.sh$"
    copied = canary.copy_without_regex(text, path, r"^PBKDF2=false$")
    assert "'''^PBKDF2=false$'''" not in copied
    assert copied.count("'''^__removed__$'''") == 1
    assert len(copied.splitlines()) == len(text.splitlines())


@pytest.mark.parametrize(
    "path, regex, message",
    [
        (r"^absent\.rs$", r"^x$", "path regex count is 0"),
        (r"^scripts/create_validator_keys\.sh$", r"^absent$", "regex count is 0"),
    ],
)
def test_copy_without_regex_rejects_a_missing_target(canary, path, regex, message):
    text = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    with pytest.raises(SystemExit, match=message):
        canary.copy_without_regex(text, path, regex)


def test_copy_without_regex_rejects_a_path_outside_an_allowlist_block(canary):
    with pytest.raises(SystemExit, match="allowlist block not found"):
        canary.copy_without_regex("paths = ['''^a$''']\n", "^a$", "^b$")


def test_unescape_anchored_returns_the_literal(canary):
    assert canary.unescape_anchored(r"^0x97f1\.\.\.db22$") == "0x97f1...db22"
    assert canary.unescape_anchored(r"^\-\-\-x$") == "---x"


def test_expect_rejects_unknown_repeated_wrong_and_missing_labels(canary):
    with pytest.raises(SystemExit, match="unexpected label"):
        canary.expect("not-a-label", 0, 0)
    canary.expect("line-shift", 0, 0)
    with pytest.raises(SystemExit, match="seen twice"):
        canary.expect("line-shift", 0, 0)
    with pytest.raises(SystemExit, match="exit 0, want 1"):
        canary.expect("smuggle-fresh", 0, 1)
    with pytest.raises(SystemExit, match="expected labels not hit"):
        canary.require_expected_labels()


def test_main_with_the_real_gitleaks_binary(canary, monkeypatch):
    binary = os.environ.get("GITLEAKS_BIN", "gitleaks")
    config = os.environ.get("RVC_GITLEAKS_CONFIG")
    runnable = shutil.which(binary) is not None or Path(binary).is_file()
    version = (
        subprocess.run([binary, "version"], check=False, capture_output=True, text=True).stdout
        if runnable
        else ""
    )
    if version.strip() != "8.21.2" or not config or not Path(config).is_file():
        pytest.skip("needs gitleaks 8.21.2 and RVC_GITLEAKS_CONFIG set to a strict config")
    monkeypatch.setattr(canary, "GITLEAKS", binary)
    monkeypatch.setattr(canary, "CONFIG", Path(config))
    canary.main()
    assert canary.seen_labels == canary.REQUIRED_LABELS
