"""Contract tests for scripts/devnet/lib/common.sh.

Each helper is exercised with `bash -c 'source lib/common.sh; …'` under
disable_socket() (conftest autouse). DOCKER/CURL default to /bin/echo.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

COMMON_SH = Path(__file__).resolve().parents[1] / "devnet" / "lib" / "common.sh"

_ISOLATE_KEYS = (
    "DOCKER",
    "CURL",
    "RUN_DIR",
    "FORCE",
    "PROFILE",
    "DRY_RUN",
    "INTERACTIVE",
    "DEVNET_STAGE_DIR",
    "DATA_DIR",
    "RUNS_DIR",
    "CHAIN_ID",
    "EPOCHS",
    "DOPPELGANGER",
    "FAIL_UNDER",
)

_MNEMONIC = "test test test test test test test test test test test junk"


def run_common(
    snippet: str,
    *,
    env: dict[str, str] | None = None,
    timeout: float = 10,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full.setdefault("DOCKER", "/bin/echo")
    full.setdefault("CURL", "/bin/echo")
    if env:
        full.update(env)
    return subprocess.run(
        ["bash", "-c", f"source {shlex.quote(str(COMMON_SH))}; {snippet}"],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        cwd=cwd,
    )


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob


def test_common_sh_exists_and_syntax():
    assert COMMON_SH.is_file(), COMMON_SH
    proc = subprocess.run(
        ["bash", "-n", str(COMMON_SH)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr


def test_source_is_silent_and_hides_mnemonic():
    proc = run_common("true")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    text = COMMON_SH.read_text(encoding="utf-8")
    assert re.search(r"\bread\b", text) is None


def test_wait_for_service_keeps_reference_name():
    text = COMMON_SH.read_text(encoding="utf-8")
    assert "wait_for_service()" in text
    assert "wait_for_http()" not in text


def test_log_helpers_write_stderr_not_stdout():
    proc = run_common("log_info i; log_success s; log_warn w; log_error e")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert "[INFO]" in proc.stderr
    assert "[SUCCESS]" in proc.stderr
    assert "[WARN]" in proc.stderr
    assert "[ERROR]" in proc.stderr
    assert_no_secret(proc)


def test_require_chain_1337_rejects_non_1337():
    proc = run_common("CHAIN_ID=5 require_chain_1337")
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "1337" in proc.stderr
    assert "5" in proc.stderr
    assert_no_secret(proc)


def test_require_chain_1337_accepts_1337():
    proc = run_common("CHAIN_ID=1337 require_chain_1337")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)


def test_require_chain_1337_uses_env_default():
    proc = run_common("require_chain_1337")
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)


@pytest.mark.parametrize(
    "fn,code",
    [
        ("die_infra", 1),
        ("die_usage", 2),
        ("die_health", 3),
        ("die_kpi", 4),
        ("die_notready", 5),
    ],
)
def test_die_helpers_exit_prd_codes_on_stderr(fn: str, code: int):
    marker = f"boom-{fn}"
    proc = run_common(f'{fn} {shlex.quote(marker)}')
    assert proc.returncode == code
    assert proc.stdout == ""
    assert marker in proc.stderr
    assert_no_secret(proc)


def test_parse_common_flags_sets_force_run_dir_profile_dry_run():
    proc = run_common(
        "parse_common_flags --force --dry-run --profile safe --run-dir /tmp/rvc-run; "
        'printf "FORCE=%s RUN_DIR=%s PROFILE=%s DRY_RUN=%s INTERACTIVE=%s\\n" '
        '"$FORCE" "$RUN_DIR" "$PROFILE" "$DRY_RUN" "$INTERACTIVE"'
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == (
        "FORCE=1 RUN_DIR=/tmp/rvc-run PROFILE=safe DRY_RUN=1 INTERACTIVE=0"
    )
    assert_no_secret(proc)


def test_parse_common_flags_interactive():
    proc = run_common(
        "parse_common_flags --interactive; printf 'INTERACTIVE=%s\\n' \"$INTERACTIVE\""
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "INTERACTIVE=1"


def test_parse_common_flags_unknown_exits_2():
    proc = run_common("parse_common_flags --nope")
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "unknown flag" in proc.stderr
    assert "--nope" in proc.stderr
    assert_no_secret(proc)


def test_parse_common_flags_run_dir_requires_path():
    proc = run_common("parse_common_flags --run-dir")
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "--run-dir" in proc.stderr


def test_resolve_run_dir_standalone_without_run_dir(tmp_path: Path):
    runs = tmp_path / "runs"
    proc = run_common(
        "parse_common_flags; resolve_run_dir",
        env={"RUNS_DIR": str(runs)},
    )
    assert proc.returncode == 0, proc.stderr
    got = Path(proc.stdout.strip())
    assert got == (runs / "standalone").resolve()
    assert got.is_dir()
    assert got.name == "standalone"
    assert got.parent.name == "runs"


def test_resolve_run_dir_default_is_scripts_devnet_runs_standalone():
    proc = run_common("parse_common_flags; resolve_run_dir")
    assert proc.returncode == 0, proc.stderr
    got = Path(proc.stdout.strip())
    assert got.as_posix().endswith("scripts/devnet/runs/standalone")
    assert got.is_dir()


def test_resolve_run_dir_uses_flag(tmp_path: Path):
    run_dir = tmp_path / "custom-run"
    proc = run_common(
        f"parse_common_flags --run-dir {shlex.quote(str(run_dir))}; resolve_run_dir"
    )
    assert proc.returncode == 0, proc.stderr
    got = Path(proc.stdout.strip())
    assert got == run_dir.resolve()
    assert got.is_dir()


def test_resolve_profile_fast():
    proc = run_common(
        "resolve_profile fast; "
        'printf "EPOCHS=%s DOPPELGANGER=%s FAIL_UNDER=%s\\n" '
        '"$EPOCHS" "$DOPPELGANGER" "${FAIL_UNDER-UNSET}"'
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "EPOCHS=4 DOPPELGANGER=off FAIL_UNDER=UNSET"
    assert_no_secret(proc)


def test_resolve_profile_safe():
    proc = run_common(
        "resolve_profile safe; "
        'printf "EPOCHS=%s DOPPELGANGER=%s FAIL_UNDER=%s\\n" '
        '"$EPOCHS" "$DOPPELGANGER" "${FAIL_UNDER-UNSET}"'
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "EPOCHS=8 DOPPELGANGER=on FAIL_UNDER=UNSET"
    assert_no_secret(proc)


def test_resolve_profile_unknown_exits_2():
    proc = run_common("resolve_profile bananas")
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "unknown profile" in proc.stderr
    assert_no_secret(proc)


def test_stub_defaults_docker_curl_stage_dir():
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    proc = subprocess.run(
        [
            "bash",
            "-c",
            f"source {shlex.quote(str(COMMON_SH))}; "
            'printf "%s\\n%s\\n%s\\n" "$DOCKER" "$CURL" "$DEVNET_STAGE_DIR"',
        ],
        capture_output=True,
        text=True,
        env=full,
        timeout=10,
    )
    assert proc.returncode == 0, proc.stderr
    docker, curl, stage = proc.stdout.strip().splitlines()
    assert docker == "docker"
    assert curl == "curl"
    assert stage.endswith("scripts/devnet")


def test_data_dir_and_runs_dir_are_exported():
    proc = run_common(
        "python3 -c \""
        "import os; "
        "print(os.environ['DATA_DIR']); "
        "print(os.environ['RUNS_DIR'])"
        '"'
    )
    assert proc.returncode == 0, proc.stderr
    data_dir, runs_dir = proc.stdout.strip().splitlines()
    assert data_dir.endswith("/scripts/devnet/data")
    assert runs_dir.endswith("/scripts/devnet/runs")


def test_docker_echo_indirection(tmp_path: Path):
    """DOCKER=/bin/echo makes every docker helper print instead of running."""
    run_dir = tmp_path / "run"
    uid = os.getuid()
    gid = os.getgid()
    proc = run_common(
        "parse_common_flags --run-dir \"$RUN_DIR\"; "
        "docker_run_as_user --rm hello-image; "
        "ensure_docker_network; "
        "capture_container_logs eth-devnet-geth; "
        "is_container_running eth-devnet-geth || true",
        env={"DOCKER": "/bin/echo", "RUN_DIR": str(run_dir)},
    )
    assert proc.returncode == 0, proc.stderr
    assert f"run -u {uid}:{gid} --rm hello-image" in proc.stdout
    assert "network create" in proc.stdout
    assert "eth-devnet-network" in proc.stdout
    log_path = run_dir / "logs" / "eth-devnet-geth.log"
    assert log_path.is_file()
    assert "logs -- eth-devnet-geth" in log_path.read_text(encoding="utf-8")


def test_docker_helpers_record_argv(tmp_path: Path):
    log = tmp_path / "docker.log"
    stub = tmp_path / "docker"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    run_dir = tmp_path / "run"
    proc = run_common(
        "parse_common_flags --run-dir \"$RUN_DIR\"; "
        "docker_run_as_user --rm img cmd; "
        "ensure_docker_network; "
        "capture_container_logs c1; "
        "is_container_running c1 || true; "
        "container_exists c1 || true",
        env={"DOCKER": str(stub), "RUN_DIR": str(run_dir)},
    )
    assert proc.returncode == 0, proc.stderr
    recorded = log.read_text(encoding="utf-8")
    assert "run -u" in recorded
    assert "network ls" in recorded
    assert "network create" in recorded
    assert "logs -- c1" in recorded
    assert "ps --format" in recorded


def test_inventory_append_one_row_per_call_mode_0600(tmp_path: Path):
    run_dir = tmp_path / "run"
    proc = run_common(
        "parse_common_flags --run-dir \"$RUN_DIR\"; "
        "inventory_append container eth-devnet-geth; "
        "inventory_append container eth-devnet-geth; "
        "inventory_append network eth-devnet-network; "
        "inventory_append datadir el \"$DATA_DIR/el\"",
        env={"RUN_DIR": str(run_dir)},
    )
    assert proc.returncode == 0, proc.stderr
    inventory = run_dir / "inventory.json"
    assert inventory.is_file()
    mode = inventory.stat().st_mode & 0o777
    assert mode == 0o600, oct(mode)
    rows = [
        json.loads(line)
        for line in inventory.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 4
    assert rows[0] == {"kind": "container", "name": "eth-devnet-geth"}
    assert rows[1] == {"kind": "container", "name": "eth-devnet-geth"}
    assert rows[2] == {"kind": "network", "name": "eth-devnet-network"}
    assert rows[3]["kind"] == "datadir"
    assert rows[3]["name"] == "el"
    assert rows[3]["path"].endswith("/el")
    assert_no_secret(proc)


def test_umask_077_on_sourced_shell(tmp_path: Path):
    target = tmp_path / "secret"
    proc = run_common(f"touch {shlex.quote(str(target))}")
    assert proc.returncode == 0, proc.stderr
    mode = target.stat().st_mode & 0o777
    assert mode == 0o600, oct(mode)


def test_validate_data_exists_names_artifact_and_stage(tmp_path: Path):
    missing = tmp_path / "jwt.hex"
    proc = run_common(
        "validate_data_exists jwt "
        f"{shlex.quote(str(missing))} 01-genesis.sh"
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "jwt" in proc.stderr
    assert str(missing) in proc.stderr
    assert "01-genesis.sh" in proc.stderr
    assert_no_secret(proc)


def test_validate_data_exists_ok(tmp_path: Path):
    present = tmp_path / "genesis.ssz"
    present.write_bytes(b"ssz")
    proc = run_common(
        "validate_data_exists genesis.ssz "
        f"{shlex.quote(str(present))} 01-genesis.sh"
    )
    assert proc.returncode == 0, proc.stderr


def test_require_cmd_missing_exits_2():
    proc = run_common("require_cmd definitely-not-a-devnet-cmd")
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "definitely-not-a-devnet-cmd" in proc.stderr


def test_require_cmd_present():
    proc = run_common("require_cmd bash")
    assert proc.returncode == 0, proc.stderr


def test_wait_for_service_uses_curl_stub(tmp_path: Path):
    log = tmp_path / "curl.log"
    stub = tmp_path / "curl"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    proc = run_common(
        "wait_for_service http://127.0.0.1:9/health",
        env={"CURL": str(stub)},
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    recorded = log.read_text(encoding="utf-8")
    assert "--fail" in recorded
    assert "--max-time" in recorded
    assert "-- http://127.0.0.1:9/health" in recorded
    assert "ready" in proc.stderr.lower() or "SUCCESS" in proc.stderr


def test_wait_for_service_timeout_returns_1():
    proc = run_common(
        "wait_for_service http://127.0.0.1:9/health 1",
        env={"CURL": "/usr/bin/false"},
    )
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "did not become ready" in proc.stderr


def test_wait_for_service_curl_echo_indirection():
    proc = run_common(
        "wait_for_service http://example.invalid/health",
        env={"CURL": "/bin/echo"},
    )
    assert proc.returncode == 0, proc.stderr
    # /bin/echo prints the curl flags+URL; wait_for_service swallows that
    # onto /dev/null, so success-without-a-daemon is the indirection proof.
    assert "SUCCESS" in proc.stderr or "ready" in proc.stderr.lower()


def test_resolve_run_dir_refuses_world_writable(tmp_path: Path):
    run_dir = tmp_path / "wide"
    run_dir.mkdir()
    run_dir.chmod(0o777)
    proc = run_common(
        f"parse_common_flags --run-dir {shlex.quote(str(run_dir))}; resolve_run_dir"
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "world-writable" in proc.stderr


def test_resolve_run_dir_refuses_symlink(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    proc = run_common(
        f"parse_common_flags --run-dir {shlex.quote(str(link))}; resolve_run_dir"
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "symlink" in proc.stderr


def test_resolve_run_dir_dash_name_is_not_mkdir_flag(tmp_path: Path):
    proc = run_common(
        "parse_common_flags --run-dir -m0777; resolve_run_dir",
        cwd=tmp_path,
    )
    assert proc.returncode == 0, proc.stderr
    got = Path(proc.stdout.strip())
    assert got.name == "-m0777"
    assert got.is_dir()
    assert not got.is_symlink()
    assert (got.stat().st_mode & 0o777) == 0o700


def test_inventory_append_rechmods_existing_0666(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    inventory = run_dir / "inventory.json"
    inventory.write_text("", encoding="utf-8")
    inventory.chmod(0o666)
    proc = run_common(
        "inventory_append container eth-devnet-geth",
        env={"RUN_DIR": str(run_dir)},
    )
    assert proc.returncode == 0, proc.stderr
    assert (inventory.stat().st_mode & 0o777) == 0o600
    rows = [
        json.loads(line)
        for line in inventory.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert rows == [{"kind": "container", "name": "eth-devnet-geth"}]


def test_inventory_append_refuses_symlink(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("untouched\n", encoding="utf-8")
    inventory = run_dir / "inventory.json"
    inventory.symlink_to(victim)
    proc = run_common(
        "inventory_append container eth-devnet-geth",
        env={"RUN_DIR": str(run_dir)},
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"


def test_inventory_append_escapes_c0_controls(tmp_path: Path):
    run_dir = tmp_path / "run"
    proc = run_common(
        "parse_common_flags --run-dir \"$RUN_DIR\"; "
        "inventory_append datadir $'el\\007x' /tmp/p",
        env={"RUN_DIR": str(run_dir)},
    )
    assert proc.returncode == 0, proc.stderr
    row = json.loads(
        (run_dir / "inventory.json").read_text(encoding="utf-8").splitlines()[0]
    )
    assert row == {"kind": "datadir", "name": "el\x07x", "path": "/tmp/p"}


def test_docker_run_as_user_rejects_user_override(tmp_path: Path):
    log = tmp_path / "docker.log"
    stub = tmp_path / "docker"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    for extra in ("-u 0:0", "-u0:0", "--user root", "--user=root"):
        proc = run_common(
            f"docker_run_as_user {extra} --rm img",
            env={"DOCKER": str(stub)},
        )
        assert proc.returncode == 2, extra
        assert proc.stdout == ""
        assert "-u/--user" in proc.stderr
    assert not log.exists()


def test_wait_for_service_rejects_non_numeric_max_attempts(tmp_path: Path):
    marker = tmp_path / "pwned"
    proc = run_common(
        "wait_for_service http://127.0.0.1:9/health '$(touch "
        f"{shlex.quote(str(marker))})'"
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "max_attempts" in proc.stderr
    assert not marker.exists()
    proc = run_common("wait_for_service http://127.0.0.1:9/health 1+1")
    assert proc.returncode == 2
    assert "max_attempts" in proc.stderr


def test_capture_container_logs_rejects_unsafe_name(tmp_path: Path):
    run_dir = tmp_path / "run"
    for name in ("../etc", "foo/bar", "-evil", ".", ".."):
        proc = run_common(
            f"capture_container_logs {shlex.quote(name)}",
            env={"RUN_DIR": str(run_dir)},
        )
        assert proc.returncode == 2, name
        assert proc.stdout == ""
        assert "invalid" in proc.stderr
    assert not (run_dir / "logs").exists()
