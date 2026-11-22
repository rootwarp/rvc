"""Tests for scripts/gitleaks_scope_canary.py.

CI runs the canary itself in the secret-scan job against gitleaks 8.21.2.
Most tests here use ``fake_gitleaks.py``. One test runs the real binary when
gitleaks 8.21.2 and a strict config are present.
"""

from __future__ import annotations

import os
import py_compile
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from conftest import load_script

SCRIPT = Path(__file__).resolve().parents[1] / "gitleaks_scope_canary.py"
BAD_DEFAULT_REGEX = re.compile(r"(?i)^true|false|null$")
BAD_DEFAULT_PATHS = [
    re.compile(r"gitleaks\.toml"),
    re.compile(r"(.*?)(doc|docx|zip|xls|pdf|bin|socket|vsidx|v2|suo|wsuo|.dll|pdb|exe|gltf)$"),
]


@pytest.fixture(scope="module")
def canary():
    return load_script("gitleaks_scope_canary")


def test_each_allowlist_shape_hits_a_default_entry(canary):
    shapes = canary.allowlist_shapes()
    assert len(shapes) >= 5
    for label, (path, secret) in shapes.items():
        by_regex = BAD_DEFAULT_REGEX.search(secret) is not None
        by_path = any(rx.search(path) for rx in BAD_DEFAULT_PATHS)
        assert by_regex or by_path, label
        assert secret not in {"true", "false", "null"}, label


def test_shape_tokens_are_not_literals_in_the_canary_source(canary):
    text = SCRIPT.read_text(encoding="utf-8")
    for _path, secret in canary.allowlist_shapes().values():
        assert secret not in text
    assert canary.token() not in text


def _chunk(canary, name: str) -> bytes:
    return canary.chunk_boundary_files()[name]


def test_generic_secret_straddles_the_first_chunk_boundary(canary):
    data = _chunk(canary, "generic.rs")
    start = data.index(canary.token().encode())
    assert start < canary.CHUNK_SIZE < start + len(canary.token())
    assert canary.CHUNK_SIZE - start == canary.GENERIC_CUT


def test_pem_block_straddles_the_first_chunk_boundary(canary):
    data = _chunk(canary, "pem.rs")
    begin = data.index(b"-----" + b"BEGIN RSA PRIVATE KEY")
    end = data.index(b"-----" + b"END RSA PRIVATE KEY")
    assert begin < canary.CHUNK_SIZE < end


def test_pdf_magic_starts_the_second_chunk_before_the_secret(canary):
    data = _chunk(canary, "pdf.rs")
    assert data[canary.CHUNK_SIZE : canary.CHUNK_SIZE + 4] == b"%PDF"
    assert b"%PDF" not in data[: canary.CHUNK_SIZE]
    assert data.index(canary.token().encode()) > canary.CHUNK_SIZE


def test_require_labels_survives_a_noop_expect(canary):
    text = SCRIPT.read_text(encoding="utf-8")
    expect_body = text.split("def expect", 1)[1].split("\ndef ", 1)[0]
    main_body = text.split("def main", 1)[1]
    assert "seen_labels.add" in expect_body
    assert "require_expected_labels()" in main_body
    for label in canary.allowlist_shapes():
        assert f"strict-{label}" in canary.REQUIRED_LABELS
        assert f"default-hides-{label}" in canary.REQUIRED_LABELS
    for name in canary.chunk_boundary_files():
        assert f"git-range-{name}" in canary.REQUIRED_LABELS
        assert f"no-git-misses-{name}" in canary.REQUIRED_LABELS
    assert f"git-range-{canary.MERGE_FILE}" in canary.REQUIRED_LABELS


def test_canary_refuses_the_use_default_config(canary, monkeypatch, fake_gitleaks):
    monkeypatch.setattr(canary, "GITLEAKS", str(fake_gitleaks))
    monkeypatch.setattr(canary, "CONFIG", canary.DEFAULT_CONFIG)
    with pytest.raises(SystemExit, match="RVC_GITLEAKS_CONFIG"):
        canary.main()


@pytest.fixture
def faked(canary, monkeypatch, fake_gitleaks, strict_gitleaks_config):
    monkeypatch.setattr(canary, "GITLEAKS", str(fake_gitleaks))
    monkeypatch.setattr(canary, "CONFIG", strict_gitleaks_config)
    monkeypatch.setattr(canary, "seen_labels", set())
    return canary


def test_main_passes_when_every_probe_is_found(faked, capsys):
    faked.main()
    out = capsys.readouterr().out
    assert "find every probe" in out
    assert faked.seen_labels == faked.REQUIRED_LABELS


def test_main_fails_when_the_strict_base_keeps_the_faulty_regex(faked, monkeypatch, tmp_path):
    base = faked.CONFIG.parent / "gitleaks-default-8.21.2.toml"
    text = base.read_text(encoding="utf-8")
    base.write_text(text.replace("(?i)^(?:true|false|null)$", "(?i)^true|false|null$"), encoding="utf-8")
    with pytest.raises(SystemExit, match="strict-contains-false: exit 0, want 1"):
        faked.main()


def test_main_fails_when_the_range_scan_reads_chunks(faked, monkeypatch, tmp_path):
    no_git = tmp_path / "no_git_range.sh"
    no_git.write_text(
        '#!/usr/bin/env bash\nconfig=$1\nshift 2\n'
        'exec "$GITLEAKS_BIN" detect --no-git --source . --config "$config" --exit-code 1 "$@"\n'
    )
    no_git.chmod(0o755)
    monkeypatch.setattr(faked, "RANGE_SCAN", no_git)
    with pytest.raises(SystemExit, match="git-range-generic.rs: exit 0, want 1"):
        faked.main()


def test_main_fails_when_gitleaks_does_not_finish(faked, monkeypatch, capsys):
    monkeypatch.setenv("FAKE_GITLEAKS_CRASH", "1")
    with pytest.raises(SystemExit, match="did not finish"):
        faked.main()
    assert "fake crash" in capsys.readouterr().err


def test_main_fails_when_a_finding_is_in_another_file(faked, monkeypatch):
    real_scan = faked.scan_no_git

    def scan_with_extra_file(source, config, report):
        (source / "extra.rs").write_bytes(faked._key_line(faked.token()))
        return real_scan(source, config, report)

    monkeypatch.setattr(faked, "scan_no_git", scan_with_extra_file)
    with pytest.raises(SystemExit, match="strict-contains-false: findings in"):
        faked.main()


def test_main_fails_when_gitleaks_is_not_runnable(faked, monkeypatch, tmp_path):
    monkeypatch.setattr(faked, "GITLEAKS", str(tmp_path / "missing-gitleaks"))
    with pytest.raises(SystemExit, match="not runnable"):
        faked.main()


def test_main_fails_when_the_range_scan_shows_no_merge_diffs(faked, monkeypatch, tmp_path):
    no_merge = tmp_path / "no_merge_range.sh"
    no_merge.write_text(
        '#!/usr/bin/env bash\nconfig=$1\nbase=$2\nshift 2\n'
        'exec "$GITLEAKS_BIN" detect --source . "--log-opts=${base}..HEAD" --config "$config" '
        '--exit-code 1 "$@"\n'
    )
    no_merge.chmod(0o755)
    monkeypatch.setattr(faked, "RANGE_SCAN", no_merge)
    with pytest.raises(SystemExit, match=f"git-range-{faked.MERGE_FILE}: exit 0, want 1"):
        faked.main()


def test_expect_rejects_unknown_repeated_and_missing_labels(canary, monkeypatch):
    monkeypatch.setattr(canary, "seen_labels", set())
    with pytest.raises(SystemExit, match="unexpected label"):
        canary.expect("not-a-label", 1, 1)
    canary.expect("strict-ends-null", 1, 1)
    with pytest.raises(SystemExit, match="seen twice"):
        canary.expect("strict-ends-null", 1, 1)
    with pytest.raises(SystemExit, match="expected labels not hit"):
        canary.require_expected_labels()


def _real_gitleaks_8_21_2() -> str | None:
    binary = os.environ.get("GITLEAKS_BIN", "gitleaks")
    if shutil.which(binary) is None and not Path(binary).is_file():
        return None
    proc = subprocess.run([binary, "version"], check=False, capture_output=True, text=True)
    return binary if proc.stdout.strip() == "8.21.2" else None


def test_main_with_the_real_gitleaks_binary(canary, monkeypatch):
    binary = _real_gitleaks_8_21_2()
    config = os.environ.get("RVC_GITLEAKS_CONFIG")
    if binary is None or not config or not Path(config).is_file():
        pytest.skip("needs gitleaks 8.21.2 and RVC_GITLEAKS_CONFIG set to a strict config")
    monkeypatch.setattr(canary, "GITLEAKS", binary)
    monkeypatch.setattr(canary, "CONFIG", Path(config).resolve())
    monkeypatch.setattr(canary, "seen_labels", set())
    canary.main()
    assert canary.seen_labels == canary.REQUIRED_LABELS


def test_no_compiled_script_holds_a_full_private_key_header(tmp_path):
    """A no-git scan reads ``__pycache__``. A folded marker would be a finding."""
    dashes = b"-" * 5
    header = re.compile(dashes + rb"BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY" + dashes)
    sources = sorted(SCRIPT.parent.glob("*.py")) + sorted(SCRIPT.parent.glob("tests/*.py"))
    assert SCRIPT in sources
    for source in sources:
        compiled = tmp_path / f"{source.parent.name}-{source.stem}.pyc"
        py_compile.compile(str(source), cfile=str(compiled), doraise=True)
        assert not header.search(compiled.read_bytes()), source.name
