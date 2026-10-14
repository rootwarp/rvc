"""Hardening tests for scripts/devnet/lib/common.sh BN probes (issue 3.1 review)."""

from __future__ import annotations

import json
import shlex
from pathlib import Path

from test_devnet_common_sh import FIXTURES, assert_no_secret, run_common


def _curl_stub(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "curl.log"
    stub = tmp_path / "curl"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def test_bn_get_rejects_glob_charset_and_dotdot(tmp_path: Path):
    stub, log = _curl_stub(tmp_path)
    env = {"CURL": str(stub), "CL_HTTP_PORT": "5052"}
    cases = (
        "/eth/v1/beacon/states/head/fork[abc]",
        "/eth/v1/../config/spec",
        "/eth/v2/beacon/genesis",
        "/eth/v1/beacon/genesis?x=1",
        "/foo",
    )
    for path in cases:
        proc = run_common(f"bn_get {shlex.quote(path)}", env=env)
        assert proc.returncode == 2, path
        assert proc.stdout == ""
        assert "bn_get" in proc.stderr
        assert_no_secret(proc)
    assert not log.exists()


def test_bn_get_rejects_at_in_cl_http_port(tmp_path: Path):
    stub, log = _curl_stub(tmp_path)
    proc = run_common(
        "CL_HTTP_PORT='80@example.com' bn_get /eth/v1/beacon/genesis",
        env={"CURL": str(stub)},
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "CL_HTTP_PORT" in proc.stderr
    assert "@" in proc.stderr
    assert not log.exists()
    assert_no_secret(proc)


def test_parse_fork_versions_rejects_non_hex():
    raw = json.loads((FIXTURES / "bn_spec.json").read_text(encoding="utf-8"))
    raw["data"]["ELECTRA_FORK_VERSION"] = "*"
    proc = run_common(
        "parse_fork_versions",
        stdin=json.dumps(raw),
        env={"CURL": "/usr/bin/false"},
    )
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "fork version" in proc.stderr.lower() or "failed to parse" in proc.stderr
    assert_no_secret(proc)


def test_assert_fork_in_schedule_rejects_glob_star(tmp_path: Path):
    (tmp_path / "not-a-fork").write_text("", encoding="utf-8")
    globbed = run_common(
        "assert_fork_in_schedule 0x60000000 *",
        cwd=tmp_path,
        env={"CURL": "/usr/bin/false"},
    )
    quoted = run_common(
        "assert_fork_in_schedule 0x60000000 '*'",
        cwd=tmp_path,
        env={"CURL": "/usr/bin/false"},
    )
    for proc in (globbed, quoted):
        assert proc.returncode == 2
        assert proc.stdout == ""
        assert "0x hex" in proc.stderr or "fork version" in proc.stderr
        assert_no_secret(proc)
