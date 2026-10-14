"""Tests for scripts/gloas_soak_snapshot.sh."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from conftest import SCRIPT as VP_SCRIPT

WRAPPER = VP_SCRIPT.with_name("gloas_soak_snapshot.sh")
PY = VP_SCRIPT.with_name("gloas_soak_snapshot.py")


def _run(*args: str, **kwargs) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.pop("PYTHON", None)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [str(WRAPPER), *args],
        capture_output=True,
        text=True,
        env=env,
        **kwargs,
    )


def test_wrapper_exists_and_is_executable():
    assert WRAPPER.is_file()
    assert PY.is_file()
    assert WRAPPER.read_text(encoding="utf-8").startswith("#!/usr/bin/env bash\n")
    assert WRAPPER.stat().st_mode & stat.S_IXUSR
    assert PY.stat().st_mode & stat.S_IXUSR


def test_wrapper_syntax():
    proc = subprocess.run(
        ["bash", "-n", str(WRAPPER)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


def test_wrapper_help_exits_0_and_mentions_out_dir():
    proc = _run("--help")
    assert proc.returncode == 0
    text = proc.stdout + proc.stderr
    assert "--out-dir" in proc.stdout
    assert "--metrics-url" in text
    assert "unrecognized arguments" not in text
    assert "user:secret" not in text


def test_wrapper_no_args_exits_2_with_usage():
    proc = _run()
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "Usage:" in proc.stderr
    assert "Traceback" not in proc.stderr


def test_wrapper_python_flag_requires_a_path():
    proc = _run("--python")
    assert proc.returncode == 2
    assert "--python requires a path" in proc.stderr
    assert proc.stdout == ""


def test_wrapper_forwards_usage_errors():
    proc = _run("--metrics", "/no/such/metrics.txt")
    assert proc.returncode == 2
    assert "Traceback" not in proc.stdout
    assert "--out-dir" in (proc.stdout + proc.stderr)
