"""Contract tests for scripts/devnet/up.sh.

Stage stubs live on DEVNET_STAGE_DIR (P1-A8); disable_socket() via conftest.
Live double-run is skipped unless DEVNET_LIVE=1 and the pinned images are present.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from test_devnet_env import ENV_PATH, parse_env

UP = Path(__file__).resolve().parents[1] / "devnet" / "up.sh"
DEVNET_DIR = Path(__file__).resolve().parents[1] / "devnet"
CI_YML = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
WORKFLOWS = CI_YML.parent

_STAGES = (
    "00-preflight.sh",
    "01-genesis.sh",
    "02-keys.sh",
    "03-chain.sh",
)

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
    "IMG_GETH",
    "IMG_LIGHTHOUSE",
    "IMG_GENESIS",
    "PREFLIGHT_MIN_CPUS",
    "PREFLIGHT_MIN_RAM_GIB",
    "PREFLIGHT_MIN_FREE_GIB",
)

_MNEMONIC = "test test test test test test test test test test test junk"

# Bash `read` as a statement, not Python `.read()` or English "read".
_READ_CMD_RE = re.compile(r"(?m)^\s*read\s")
_INTERACTIVE_GUARD_RE = re.compile(
    r"\[\[\s*\"?\$\{?INTERACTIVE\}?\"?\s*==\s*\"?1\"?\s*\]\]"
)


def write_docker_stub(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "docker.log"
    stub = tmp_path / "docker"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def write_stage_stubs(
    tmp_path: Path,
    *,
    fail_stage: str | None = None,
    fail_code: int = 0,
) -> tuple[Path, Path]:
    stage_dir = tmp_path / "stages"
    stage_dir.mkdir()
    log = tmp_path / "stages.log"
    fail_name = fail_stage or ""
    for name in _STAGES:
        path = stage_dir / name
        path.write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$(basename \"$0\") $*\" >> {shlex.quote(str(log))}\n"
            f"printf 'ENV CHAIN_ID=%s IMG_GETH=%s IMG_LIGHTHOUSE=%s IMG_GENESIS=%s\\n' "
            f"\"${{CHAIN_ID-}}\" \"${{IMG_GETH-}}\" \"${{IMG_LIGHTHOUSE-}}\" "
            f"\"${{IMG_GENESIS-}}\" >> {shlex.quote(str(log))}\n"
            f"if [ \"$(basename \"$0\")\" = {shlex.quote(fail_name)} ]; then\n"
            f"  exit {int(fail_code)}\n"
            "fi\n"
            "exit 0\n",
            encoding="utf-8",
        )
        path.chmod(0o755)
    return stage_dir, log


def up_env(
    tmp_path: Path,
    extra: dict[str, str] | None = None,
    *,
    docker: Path | None = None,
    stage_dir: Path | None = None,
) -> dict[str, str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full["DOCKER"] = str(docker or (tmp_path / "docker"))
    full["CURL"] = "/bin/echo"
    full["DATA_DIR"] = str(tmp_path / "data")
    full["RUNS_DIR"] = str(tmp_path / "runs")
    if stage_dir is not None:
        full["DEVNET_STAGE_DIR"] = str(stage_dir)
    if extra:
        full.update(extra)
    return full


def run_up(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    env: dict[str, str] | None = None,
    fail_stage: str | None = None,
    fail_code: int = 0,
    stages: bool = True,
    timeout: float = 15,
    docker: Path | None = None,
    log: Path | None = None,
    stage_dir: Path | None = None,
    stage_log: Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path, Path | None]:
    if docker is None:
        stub, dlog = write_docker_stub(tmp_path)
    else:
        stub = docker
        dlog = log or (tmp_path / "docker.log")
    slog: Path | None = stage_log
    if stages and stage_dir is None:
        stage_dir, slog = write_stage_stubs(
            tmp_path, fail_stage=fail_stage, fail_code=fail_code
        )
    full = up_env(tmp_path, env, docker=stub, stage_dir=stage_dir)
    proc = subprocess.run(
        ["bash", str(UP), *args],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return proc, dlog, slog


def stub_cmds(log: Path | None) -> list[str]:
    if log is None or not log.is_file():
        return []
    return [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


def stage_cmd_lines(log: Path | None) -> list[str]:
    return [line for line in stub_cmds(log) if not line.startswith("ENV ")]


def stage_names(log: Path | None) -> list[str]:
    names = []
    for line in stage_cmd_lines(log):
        names.append(line.split(" ", 1)[0])
    return names


def env_lines(log: Path | None) -> list[str]:
    return [line for line in stub_cmds(log) if line.startswith("ENV ")]


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob


def _yaml_jobs(text: str) -> dict[str, str]:
    lines = text.splitlines()
    i = 0
    while i < len(lines) and lines[i] != "jobs:":
        i += 1
    jobs: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    job_re = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$")
    for line in lines[i + 1 :]:
        match = job_re.match(line)
        if match:
            if current is not None:
                jobs[current] = "\n".join(buf)
            current = match.group(1)
            buf = []
            continue
        if current is not None:
            buf.append(line)
    if current is not None:
        jobs[current] = "\n".join(buf)
    return jobs


def _interactive_guarded(lines: list[str], idx: int) -> bool:
    """True if `read` sits inside an INTERACTIVE==1 then/fi block."""
    depth = 0
    guarded_depth = 0
    for i, line in enumerate(lines):
        stripped = line.split("#", 1)[0]
        if _INTERACTIVE_GUARD_RE.search(stripped) and re.search(
            r"\bthen\b", stripped
        ):
            depth += 1
            guarded_depth += 1
        elif re.search(r"(^|[\s;])then\b", stripped):
            depth += 1
        if i == idx:
            return guarded_depth > 0
        if re.search(r"(^|[\s;])fi\b", stripped):
            if guarded_depth > 0 and depth == guarded_depth:
                guarded_depth -= 1
            if depth > 0:
                depth -= 1
    return False


def test_up_sh_exists_and_syntax():
    assert UP.is_file(), UP
    assert os.access(UP, os.X_OK)
    proc = subprocess.run(
        ["bash", "-n", str(UP)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = UP.read_text(encoding="utf-8")
    assert re.search(r"(?m)^\s*read\s", text) is None
    assert "read -p" not in text
    assert "source" in text and "lib/common.sh" in text
    assert "parse_common_flags" in text
    assert "run_stage()" in text
    assert "main()" in text
    assert "DEVNET_STAGE_DIR" in text
    assert "00-preflight.sh" in text
    assert "01-genesis.sh" in text
    assert "02-keys.sh" in text
    assert "03-chain.sh" in text
    assert "$DOCKER" not in text
    assert re.search(r"(?m)^\s*docker\s", text) is None
    assert "die_infra" not in text or "exit $?" in text


def test_dry_run_prints_four_stages_docker_log_empty(tmp_path: Path):
    proc, dlog, slog = run_up(tmp_path, ["--dry-run"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    err = proc.stderr
    i0 = err.find("00-preflight.sh")
    i1 = err.find("01-genesis.sh")
    i2 = err.find("02-keys.sh")
    i3 = err.find("03-chain.sh")
    assert -1 not in (i0, i1, i2, i3), err
    assert i0 < i1 < i2 < i3, err
    assert stub_cmds(dlog) == []
    assert stub_cmds(slog) == []
    assert not (tmp_path / "data").exists()
    assert_no_secret(proc)


def test_happy_stub_exits_0_all_four_in_order(tmp_path: Path):
    proc, dlog, slog = run_up(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert stage_names(slog) == list(_STAGES)
    assert stub_cmds(dlog) == []
    assert "devnet up" in proc.stderr
    assert_no_secret(proc)


def test_second_stub_run_exits_0_genesis_mtime_unchanged(tmp_path: Path):
    ssz = tmp_path / "data" / "genesis" / "genesis.ssz"
    ssz.parent.mkdir(parents=True)
    ssz.write_bytes(b"ssz")
    mtime = ssz.stat().st_mtime
    proc1, dlog, slog = run_up(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    proc2, _, slog2 = run_up(
        tmp_path,
        docker=tmp_path / "docker",
        log=dlog,
        stage_dir=tmp_path / "stages",
        stage_log=slog,
        stages=True,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert ssz.stat().st_mtime == mtime
    assert stub_cmds(dlog) == []
    assert stage_names(slog2) == list(_STAGES) * 2
    assert_no_secret(proc1)
    assert_no_secret(proc2)


@pytest.mark.parametrize(
    "fail_stage,code",
    [
        ("00-preflight.sh", 2),
        ("01-genesis.sh", 1),
        ("02-keys.sh", 2),
        ("03-chain.sh", 1),
    ],
)
def test_stage_failure_propagates_exact_code_and_stops(
    tmp_path: Path, fail_stage: str, code: int
):
    proc, dlog, slog = run_up(
        tmp_path, fail_stage=fail_stage, fail_code=code
    )
    assert proc.returncode == code, proc.stderr
    ran = stage_names(slog)
    idx = list(_STAGES).index(fail_stage)
    assert ran == list(_STAGES)[: idx + 1]
    assert stub_cmds(dlog) == []
    assert_no_secret(proc)


def test_force_and_run_dir_forwarded(tmp_path: Path):
    run_dir = tmp_path / "run"
    proc, _, slog = run_up(
        tmp_path,
        ["--force", "--run-dir", str(run_dir), "--profile", "fast"],
    )
    assert proc.returncode == 0, proc.stderr
    lines = stage_cmd_lines(slog)
    assert len(lines) == len(_STAGES)
    for line, name in zip(lines, _STAGES):
        assert line.startswith(name + " ")
        assert "--force" in line
        assert "--run-dir" in line
        assert str(run_dir) in line
        assert "--profile" in line
        assert "fast" in line
        assert "--dry-run" not in line
    assert_no_secret(proc)


def test_unknown_flag_exits_2_no_stages(tmp_path: Path):
    proc, dlog, slog = run_up(tmp_path, ["--nope"])
    assert proc.returncode == 2
    assert "unknown flag" in proc.stderr
    assert stub_cmds(dlog) == []
    assert stub_cmds(slog) == []
    assert_no_secret(proc)


def test_missing_stage_exits_2(tmp_path: Path):
    stage_dir, slog = write_stage_stubs(tmp_path)
    (stage_dir / "02-keys.sh").unlink()
    proc, dlog, _ = run_up(
        tmp_path, stages=True, stage_dir=stage_dir, stage_log=slog
    )
    assert proc.returncode == 2
    assert "02-keys.sh" in proc.stderr
    assert stage_names(slog) == ["00-preflight.sh", "01-genesis.sh"]
    assert stub_cmds(dlog) == []
    assert_no_secret(proc)


def test_chain_id_1_reaches_first_stage(tmp_path: Path):
    stage_dir, slog = write_stage_stubs(tmp_path)
    pre = stage_dir / "00-preflight.sh"
    pre.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$(basename \"$0\")\" >> {shlex.quote(str(slog))}\n"
        f"printf 'ENV CHAIN_ID=%s\\n' \"${{CHAIN_ID-}}\" >> {shlex.quote(str(slog))}\n"
        "if [ \"${CHAIN_ID-}\" = 1 ]; then exit 2; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    pre.chmod(0o755)
    proc, dlog, _ = run_up(
        tmp_path,
        env={"CHAIN_ID": "1"},
        stage_dir=stage_dir,
        stage_log=slog,
        stages=True,
    )
    assert proc.returncode == 2
    blob = slog.read_text(encoding="utf-8")
    assert "ENV CHAIN_ID=1" in blob
    assert "01-genesis.sh" not in blob
    assert stub_cmds(dlog) == []
    assert_no_secret(proc)


def test_img_geth_override_reaches_first_stage(tmp_path: Path):
    unpinned = "ethereum/client-go:v1.17.5"
    proc, dlog, slog = run_up(tmp_path, env={"IMG_GETH": unpinned})
    assert proc.returncode == 0, proc.stderr
    seen = env_lines(slog)
    assert seen, stub_cmds(slog)
    assert f"IMG_GETH={unpinned}" in seen[0]
    assert stage_names(slog) == list(_STAGES)
    assert stub_cmds(dlog) == []
    assert_no_secret(proc)


def test_no_unguarded_read_in_scripts_devnet():
    hits: list[str] = []
    for path in sorted(DEVNET_DIR.rglob("*")):
        if not path.is_file() or path.suffix not in {".sh", ".env"}:
            continue
        if path.name.startswith("."):
            continue
        text = path.read_text(encoding="utf-8")
        lines = text.splitlines()
        for i, line in enumerate(lines):
            code = line.split("#", 1)[0]
            if not _READ_CMD_RE.search(code):
                continue
            if _interactive_guarded(lines, i):
                continue
            rel = path.relative_to(DEVNET_DIR)
            hits.append(f"{rel}:{i + 1}:{line.strip()}")
    assert hits == [], "unguarded read prompt:\n" + "\n".join(hits)


def test_ci_scripts_job_no_cargo_no_devnet():
    text = CI_YML.read_text(encoding="utf-8")
    jobs = _yaml_jobs(text)
    assert "scripts" in jobs, sorted(jobs)
    assert "devnet" not in jobs
    body = jobs["scripts"]
    assert "cargo" not in body.lower()
    assert "rust-toolchain" not in body
    assert "dtolnay" not in body
    assert re.search(r"astral-sh/setup-uv@[0-9a-f]{40}", body)
    assert "v10.1.0" in body
    assert "persist-credentials: false" in body
    assert "contents: read" in body
    assert "0.12.13" in body
    assert "checksum:" in body
    assert "pytest==9.1.1" in body
    assert "pytest-socket==0.8.1" in body
    assert "shellcheck scripts/devnet/" in body
    assert "test_devnet_*.py" in body
    assert "pytest scripts/tests/ -q" not in body
    assert "pytest scripts/tests/\n" not in body
    on_block = text.split("jobs:", 1)[0]
    assert "pull_request" in on_block
    for wf in WORKFLOWS.glob("*.yml"):
        if "devnet" not in wf.name.lower():
            continue
        content = wf.read_text(encoding="utf-8")
        assert "pull_request" not in content, wf


def _live_up_available() -> bool:
    if os.environ.get("DEVNET_LIVE") != "1":
        return False
    docker = shutil.which("docker")
    if docker is None:
        return False
    info = subprocess.run(
        [docker, "info"],
        capture_output=True,
        timeout=15,
        stdin=subprocess.DEVNULL,
    )
    if info.returncode != 0:
        return False
    env = parse_env(ENV_PATH)
    for key in ("IMG_GETH", "IMG_LIGHTHOUSE", "IMG_GENESIS"):
        inspect = subprocess.run(
            [docker, "image", "inspect", "--", env[key]],
            capture_output=True,
            timeout=15,
            stdin=subprocess.DEVNULL,
        )
        if inspect.returncode != 0:
            return False
    return True


def _docker_ps_q(docker: str) -> set[str]:
    proc = subprocess.run(
        [docker, "ps", "-q"],
        capture_output=True,
        text=True,
        timeout=15,
        stdin=subprocess.DEVNULL,
    )
    return {line for line in proc.stdout.splitlines() if line.strip()}


def _http_code(url: str) -> str:
    proc = subprocess.run(
        [
            "curl",
            "-s",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            "2",
            "--",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=10,
        stdin=subprocess.DEVNULL,
    )
    return (proc.stdout or "").strip()


def _live_cleanup(docker: str) -> None:
    for name in (
        "eth-devnet-validator",
        "eth-devnet-beacon",
        "eth-devnet-geth",
    ):
        subprocess.run(
            [docker, "rm", "-f", "--", name],
            capture_output=True,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
    subprocess.run(
        [docker, "network", "rm", "--", "eth-devnet-network"],
        capture_output=True,
        timeout=60,
        stdin=subprocess.DEVNULL,
    )


@pytest.mark.skipif(
    not _live_up_available(),
    reason="DEVNET_LIVE=1 and pinned images required",
)
def test_live_up_twice_noop(tmp_path: Path):
    docker = shutil.which("docker")
    assert docker is not None
    data = tmp_path / "data"
    runs = tmp_path / "runs"
    env = os.environ.copy()
    for key in _ISOLATE_KEYS:
        env.pop(key, None)
    env["DATA_DIR"] = str(data)
    env["RUNS_DIR"] = str(runs)
    env["CHAIN_WAIT_ATTEMPTS"] = "90"
    env["CHAIN_WAIT_SLEEP"] = "2"
    try:
        t0 = time.monotonic()
        proc1 = subprocess.run(
            ["bash", str(UP)],
            capture_output=True,
            text=True,
            env=env,
            timeout=600,
            stdin=subprocess.DEVNULL,
        )
        wall = time.monotonic() - t0
        assert proc1.returncode == 0, proc1.stderr
        assert_no_secret(proc1)
        ssz = data / "genesis" / "genesis.ssz"
        assert ssz.is_file()
        mtime = ssz.stat().st_mtime
        health = _http_code("http://127.0.0.1:5052/eth/v1/node/health")
        assert health in {"200", "206"}, health
        running = subprocess.run(
            [docker, "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=15,
            stdin=subprocess.DEVNULL,
        )
        names = set(running.stdout.splitlines())
        assert "eth-devnet-geth" in names
        assert "eth-devnet-beacon" in names
        assert "eth-devnet-validator" in names
        before = _docker_ps_q(docker)
        proc2 = subprocess.run(
            ["bash", str(UP)],
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
            stdin=subprocess.DEVNULL,
        )
        assert proc2.returncode == 0, proc2.stderr
        assert_no_secret(proc2)
        assert ssz.stat().st_mtime == mtime
        after = _docker_ps_q(docker)
        assert after == before
        assert wall > 0
    finally:
        _live_cleanup(docker)
