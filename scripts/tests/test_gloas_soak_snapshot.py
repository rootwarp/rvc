"""Tests for scripts/gloas_soak_snapshot.py (issue 8.7).

Pytest prepends this directory, not scripts/, so the script is loaded by path.
HTTP is fixture-fed; pytest-socket (conftest autouse) blocks live sockets.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError

from conftest import load_script

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCRIPT = Path(__file__).resolve().parents[1] / "gloas_soak_snapshot.py"
REPO = SCRIPT.resolve().parents[1]
PASS_METRICS = _FIXTURES / "soak_metrics__pass.txt"
OK_PERF = _FIXTURES / "validator_perf__ok.json"


@pytest.fixture(scope="session")
def snap():
    return load_script("gloas_soak_snapshot")


def _argv(out_dir: Path, metrics: str | Path, *extra: str) -> list[str]:
    return [
        "--out-dir",
        str(out_dir),
        "--metrics",
        str(metrics),
        "--perf-json",
        str(OK_PERF),
        *extra,
    ]


def _run(snap, out_dir: Path, metrics: str | Path, *extra: str) -> int:
    return snap.main(_argv(out_dir, metrics, *extra))


def _drop_family(text: str, name: str) -> str:
    kept: list[str] = []
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith(f"# TYPE {name} "):
            continue
        if (
            stripped == name
            or stripped.startswith(f"{name} ")
            or stripped.startswith(f"{name}{{")
        ):
            continue
        kept.append(line)
    return "".join(kept)


def _patch(tmp_path: Path, old: str, new: str) -> Path:
    text = PASS_METRICS.read_text(encoding="utf-8")
    assert old in text
    path = tmp_path / "metrics.txt"
    path.write_text(text.replace(old, new), encoding="utf-8")
    return path


def _read_written(out_dir: Path) -> tuple[Path, dict]:
    written = sorted(out_dir.glob("gloas-soak-*.json"))
    assert len(written) == 1, written
    return written[0], json.loads(written[0].read_text(encoding="utf-8"))


def test_pep723_block_is_exact():
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.startswith("#!/usr/bin/env -S uv run --script\n")
    assert "# /// script\n" in source
    assert 'requires-python = ">=3.11"\n' in source
    assert "dependencies = []\n" in source
    assert "# ///\n" in source


def test_imports_are_stdlib_only():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module.split(".", 1)[0])
    extra = sorted({name for name in imported if name not in sys.stdlib_module_names})
    assert extra == []


def test_reuses_scorecard_parse_metrics_and_does_not_define_one():
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    defined = [
        node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
    ]
    assert "parse_metrics" not in defined
    assert "parse_metrics" in source
    assert "devnet_scorecard.py" in source


def test_script_does_not_run_main_on_import(capsys):
    source = SCRIPT.read_text(encoding="utf-8")
    guard_at = source.index('if __name__ == "__main__":')
    assert "sys.exit(main())" in source[guard_at:]
    load_script("gloas_soak_snapshot_guard")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""


def test_missing_args_exits_2(snap, capsys):
    assert snap.main([]) == snap.EXIT_USAGE == 2
    err = capsys.readouterr().err
    assert "--out-dir" in err or "--metrics" in err
    assert "Traceback" not in err


def test_pass_exits_0(snap, tmp_path, capsys):
    out = tmp_path / "soak"
    code = _run(snap, out, PASS_METRICS, "--json")
    captured = capsys.readouterr()
    assert code == snap.EXIT_OK == 0
    payload = json.loads(captured.out)
    assert payload["verdict"] == "pass"
    assert payload["failed_gates"] == []
    assert payload["gates"]["zero_slashing"]["status"] == "pass"
    assert payload["gates"]["ptc_submission"]["status"] == "pass"
    assert payload["gates"]["ptc_submission"]["ptc_rate"] == 1.0
    assert payload["gates"]["bn_capability"]["status"] == "pass"
    assert "gate:" not in captured.err
    _path, on_disk = _read_written(out)
    assert on_disk["verdict"] == "pass"


def test_snapshot_fails_when_slashed_total_resets(snap, tmp_path, capsys):
    base = PASS_METRICS.read_text(encoding="utf-8")
    start = tmp_path / "start.txt"
    end = tmp_path / "end.txt"
    start.write_text(
        base.replace(
            "rvc_validators_slashed_total 0",
            "rvc_validators_slashed_total 5",
        ),
        encoding="utf-8",
    )
    end.write_text(
        base.replace(
            "rvc_validators_slashed_total 0",
            "rvc_validators_slashed_total 1",
        ),
        encoding="utf-8",
    )
    out = tmp_path / "soak"
    code = _run(
        snap, out, end, "--metrics-start", str(start), "--json"
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["verdict"] != "pass"
    assert code == snap.EXIT_THRESHOLD == 4
    assert payload["verdict"] == "fail"
    assert "zero_slashing" in payload["failed_gates"]
    assert payload["gates"]["zero_slashing"]["slashed_total"]["start"] == 5
    assert payload["gates"]["zero_slashing"]["slashed_total"]["end"] == 1
    assert payload["gates"]["zero_slashing"]["slashed_total"]["delta"] == -4
    assert "gate: zero_slashing" in captured.err
    assert "Traceback" not in captured.err


def test_snapshot_fails_when_slashed_total_increases(snap, tmp_path, capsys):
    metrics = _patch(
        tmp_path,
        "rvc_validators_slashed_total 0",
        "rvc_validators_slashed_total 1",
    )
    out = tmp_path / "soak"
    code = _run(snap, out, metrics, "--json")
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == snap.EXIT_THRESHOLD == 4
    assert payload["verdict"] == "fail"
    assert "zero_slashing" in payload["failed_gates"]
    assert payload["gates"]["zero_slashing"]["slashed_total"]["delta"] == 1
    assert "gate: zero_slashing" in captured.err
    assert "Traceback" not in captured.err


def test_snapshot_fails_when_ptc_submission_rate_below_threshold(
    snap, tmp_path, capsys
):
    metrics = _patch(
        tmp_path,
        'rvc_ptc_attestations_total{status="success"} 100',
        'rvc_ptc_attestations_total{status="success"} 98',
    )
    out = tmp_path / "soak"
    code = _run(snap, out, metrics, "--json")
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == snap.EXIT_THRESHOLD == 4
    assert payload["verdict"] == "fail"
    assert "ptc_submission" in payload["failed_gates"]
    assert payload["gates"]["ptc_submission"]["ptc_rate"] == 0.98
    assert "gate: ptc_submission" in captured.err
    assert "Traceback" not in captured.err


def test_absent_series_reported_unavailable_not_failure(snap, tmp_path, capsys):
    text = _drop_family(
        PASS_METRICS.read_text(encoding="utf-8"), "rvc_ptc_duties_total"
    )
    assert "rvc_ptc_duties_total" not in text
    metrics = tmp_path / "metrics.txt"
    metrics.write_text(text, encoding="utf-8")
    out = tmp_path / "soak"
    code = _run(snap, out, metrics, "--json")
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["verdict"] != "fail"
    assert payload["verdict"] == "unavailable"
    assert code != snap.EXIT_THRESHOLD
    assert code == snap.EXIT_ERROR == 1
    assert payload["failed_gates"] == []
    assert payload["gates"]["ptc_submission"]["status"] == "unavailable"
    assert "rvc_ptc_duties_total" in payload["unavailable"]
    assert "gate:" not in captured.err
    assert "unavailable: rvc_ptc_duties_total" in captured.err
    assert "Traceback" not in captured.err


def test_snapshot_writes_only_to_the_named_directory(snap, tmp_path):
    snap.scorecard()
    before = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    out = tmp_path / "operator-named"
    out.mkdir()
    code = _run(snap, out, PASS_METRICS)
    assert code == 0
    written, payload = _read_written(out)
    assert payload["verdict"] == "pass"
    assert written.parent == out.resolve()
    assert not (SCRIPT.parent / written.name).exists()
    assert not (REPO / written.name).exists()
    after = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    assert after.stdout == before.stdout
    assert after.stderr == before.stderr


def test_out_dir_inside_repo_exits_2_and_does_not_write(snap, capsys):
    snap.scorecard()
    before = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=REPO,
        capture_output=True,
        text=True,
        check=True,
    )
    inside = SCRIPT.parent / "soak-should-not-exist"
    try:
        code = _run(snap, inside, PASS_METRICS)
        err = capsys.readouterr().err
        assert code == snap.EXIT_USAGE == 2
        assert "repository" in err
        assert not inside.exists()
        after = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=REPO,
            capture_output=True,
            text=True,
            check=True,
        )
        assert after.stdout == before.stdout
    finally:
        if inside.exists():
            for child in inside.glob("*"):
                child.unlink()
            inside.rmdir()


def test_blocked_increase_fails_zero_slashing(snap, tmp_path, capsys):
    metrics = _patch(
        tmp_path,
        'rvc_slashing_protection_checks_total{result="blocked"} 0',
        'rvc_slashing_protection_checks_total{result="blocked"} 1',
    )
    out = tmp_path / "soak"
    code = _run(snap, out, metrics, "--json")
    payload = json.loads(capsys.readouterr().out)
    assert code == 4
    assert "zero_slashing" in payload["failed_gates"]
    assert payload["gates"]["zero_slashing"]["blocked"]["delta"] == 1


def test_bn_capability_zero_fails(snap, tmp_path, capsys):
    metrics = _patch(
        tmp_path,
        'rvc_bn_capability_state{endpoint="http://127.0.0.1:5052",capability="produce_block_v4"} 1',
        'rvc_bn_capability_state{endpoint="http://127.0.0.1:5052",capability="produce_block_v4"} 0',
    )
    out = tmp_path / "soak"
    code = _run(snap, out, metrics, "--json")
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 4
    assert "bn_capability" in payload["failed_gates"]
    assert "gate: bn_capability" in captured.err


def test_signer_rejections_increase_fails(snap, tmp_path, capsys):
    text = PASS_METRICS.read_text(encoding="utf-8")
    text += (
        "\n# TYPE rvc_signer_rejections_total counter\n"
        'rvc_signer_rejections_total{reason="unsupported_type",'
        'sign_type="payload_attestation",version="gloas"} 1\n'
    )
    metrics = tmp_path / "metrics.txt"
    metrics.write_text(text, encoding="utf-8")
    out = tmp_path / "soak"
    code = _run(snap, out, metrics, "--json")
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 4
    assert "signer_rejections" in payload["failed_gates"]
    assert "gate: signer_rejections" in captured.err


def test_snapshot_refuses_hardlink_dest(snap, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(
        snap,
        "_generated_at",
        lambda: datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc),
    )
    out = tmp_path / "soak"
    out.mkdir()
    dest = out / "gloas-soak-2026-09-14.json"
    sibling = tmp_path / "sibling.json"
    sibling.write_text("keep-me\n", encoding="utf-8")
    os.link(sibling, dest)
    code = _run(snap, out, PASS_METRICS, "--json")
    captured = capsys.readouterr()
    assert code == snap.EXIT_ERROR == 1
    assert "hardlink" in captured.err
    assert sibling.read_text(encoding="utf-8") == "keep-me\n"
    assert dest.stat().st_nlink > 1
    assert captured.out == ""
    assert "Traceback" not in captured.err


def test_metrics_url_is_blocked_offline(snap, tmp_path, capsys):
    out = tmp_path / "soak"
    code = snap.main(
        [
            "--out-dir",
            str(out),
            "--metrics-url",
            "http://127.0.0.1:8080/metrics",
            "--perf-json",
            str(OK_PERF),
        ]
    )
    captured = capsys.readouterr()
    assert code == snap.EXIT_ERROR == 1
    assert "Traceback" not in captured.err
    assert "metrics fetch failed" in captured.err
    assert isinstance(SocketBlockedError, type)


def test_perf_json_skips_subprocess(snap, tmp_path, monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("validator_perf must not run when --perf-json is set")

    monkeypatch.setattr(snap.subprocess, "run", _boom)
    out = tmp_path / "soak"
    assert _run(snap, out, PASS_METRICS) == 0


def test_exit_codes_follow_validator_perf(snap):
    assert (
        snap.EXIT_OK,
        snap.EXIT_ERROR,
        snap.EXIT_USAGE,
        snap.EXIT_THRESHOLD,
    ) == (0, 1, 2, 4)
