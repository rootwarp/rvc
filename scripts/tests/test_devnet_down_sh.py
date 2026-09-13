"""Contract tests for scripts/devnet/down.sh (issue 5.1).

DOCKER stubs record argv; pid cases use a real child plus a `ps` comm stub.
disable_socket() via conftest autouse. No live docker, no sockets.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

DOWN = Path(__file__).resolve().parents[1] / "devnet" / "down.sh"
COMMON = Path(__file__).resolve().parents[1] / "devnet" / "lib" / "common.sh"
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "inventory__partial.json"

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
    "VALIDATOR_PERF",
    "DEVNET_REPORT",
    "PURGE_DATA",
)

_MNEMONIC = "test test test test test test test test test test test junk"
_READ_CMD_RE = re.compile(r"(?m)^\s*read\s")


def write_docker_stub(
    tmp_path: Path,
    *,
    containers: list[str] | None = None,
    networks: list[str] | None = None,
) -> tuple[Path, Path]:
    log = tmp_path / "docker.log"
    state = tmp_path / "docker-state"
    state.mkdir(exist_ok=True)
    running = state / "running"
    allc = state / "all"
    nets = state / "networks"
    cons = containers if containers is not None else [
        "eth-devnet-geth",
        "eth-devnet-beacon",
        "eth-devnet-validator",
    ]
    nws = networks if networks is not None else ["eth-devnet-network"]
    allc.write_text("".join(f"{c}\n" for c in cons), encoding="utf-8")
    running.write_text("".join(f"{c}\n" for c in cons), encoding="utf-8")
    nets.write_text("".join(f"{n}\n" for n in nws), encoding="utf-8")
    stub = tmp_path / "docker"
    stub.write_text(
        "#!/bin/sh\n"
        f"log={shlex.quote(str(log))}\n"
        f"running={shlex.quote(str(running))}\n"
        f"all={shlex.quote(str(allc))}\n"
        f"networks={shlex.quote(str(nets))}\n"
        "printf '%s\\n' \"$*\" >> \"$log\"\n"
        "cmd=\"$1\"\n"
        "shift || true\n"
        "remove_name() {\n"
        "  name=\"$1\"\n"
        "  file=\"$2\"\n"
        "  if [ -f \"$file\" ]; then\n"
        "    grep -Fxv -- \"$name\" \"$file\" > \"$file.tmp\" || true\n"
        "    mv \"$file.tmp\" \"$file\"\n"
        "  fi\n"
        "}\n"
        "case \"$cmd\" in\n"
        "  ps)\n"
        "    aq=0\n"
        "    allflag=0\n"
        "    for a in \"$@\"; do\n"
        "      case \"$a\" in\n"
        "        -aq|-qa|-q) aq=1 ;;\n"
        "        -a) allflag=1 ;;\n"
        "      esac\n"
        "    done\n"
        "    if [ \"$aq\" -eq 1 ]; then cat \"$all\"; exit 0; fi\n"
        "    if [ \"$allflag\" -eq 1 ]; then cat \"$all\"; exit 0; fi\n"
        "    cat \"$running\"\n"
        "    exit 0\n"
        "    ;;\n"
        "  network)\n"
        "    sub=\"${1:-}\"\n"
        "    shift || true\n"
        "    case \"$sub\" in\n"
        "      ls) cat \"$networks\"; exit 0 ;;\n"
        "      rm)\n"
        "        for a in \"$@\"; do\n"
        "          case \"$a\" in\n"
        "            -*|--) ;;\n"
        "            *) remove_name \"$a\" \"$networks\" ;;\n"
        "          esac\n"
        "        done\n"
        "        exit 0\n"
        "        ;;\n"
        "    esac\n"
        "    exit 0\n"
        "    ;;\n"
        "  rm)\n"
        "    for a in \"$@\"; do\n"
        "      case \"$a\" in\n"
        "        -*|--) ;;\n"
        "        *)\n"
        "          remove_name \"$a\" \"$running\"\n"
        "          remove_name \"$a\" \"$all\"\n"
        "          ;;\n"
        "      esac\n"
        "    done\n"
        "    exit 0\n"
        "    ;;\n"
        "  stop)\n"
        "    for a in \"$@\"; do\n"
        "      case \"$a\" in\n"
        "        -*|--) ;;\n"
        "        *) remove_name \"$a\" \"$running\" ;;\n"
        "      esac\n"
        "    done\n"
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def write_ps_stub(tmp_path: Path) -> tuple[Path, Path]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    map_path = tmp_path / "ps-comm"
    map_path.write_text("", encoding="utf-8")
    real_ps = shutil.which("ps") or "/bin/ps"
    stub = bin_dir / "ps"
    stub.write_text(
        "#!/bin/sh\n"
        f"map={shlex.quote(str(map_path))}\n"
        f"real={shlex.quote(real_ps)}\n"
        "pid=\"\"\n"
        "want_comm=0\n"
        "prev=\"\"\n"
        "for a in \"$@\"; do\n"
        "  if [ \"$prev\" = \"-p\" ]; then pid=\"$a\"; fi\n"
        "  case \"$a\" in\n"
        "    -p*)\n"
        "      rest=\"${a#-p}\"\n"
        "      if [ -n \"$rest\" ] && [ \"$rest\" != \"$a\" ]; then pid=\"$rest\"; fi\n"
        "      ;;\n"
        "    *comm*) want_comm=1 ;;\n"
        "  esac\n"
        "  prev=\"$a\"\n"
        "done\n"
        "if [ \"$want_comm\" -eq 1 ] && [ -n \"$pid\" ] && [ -f \"$map\" ]; then\n"
        "  mapped=$(awk -v p=\"$pid\" '$1==p {print $2; found=1} END {exit found?0:1}' \"$map\")\n"
        "  if [ $? -eq 0 ]; then\n"
        "    printf '%s\\n' \"$mapped\"\n"
        "    exit 0\n"
        "  fi\n"
        "fi\n"
        "exec \"$real\" \"$@\"\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return bin_dir, map_path


def map_ps_comm(map_path: Path, pid: int, comm: str) -> None:
    with map_path.open("a", encoding="utf-8") as fh:
        fh.write(f"{pid} {comm}\n")


def plant_partial_inventory(run_dir: Path, data_dir: Path) -> Path:
    text = FIXTURE.read_text(encoding="utf-8").replace("__DATA_DIR__", str(data_dir))
    run_dir.mkdir(parents=True, exist_ok=True)
    inv = run_dir / "inventory.json"
    inv.write_text(text, encoding="utf-8")
    inv.chmod(0o600)
    return inv


def plant_data_tree(data_dir: Path) -> tuple[Path, Path, Path, Path]:
    data_dir.mkdir(parents=True, exist_ok=True)
    data_dir.chmod(0o700)
    el = data_dir / "el"
    el.mkdir(parents=True, exist_ok=True)
    (el / "chaindata").write_text("el", encoding="utf-8")
    rvc = data_dir / "rvc"
    rvc.mkdir(parents=True, exist_ok=True)
    rvc.chmod(0o700)
    db = rvc / "slashing_protection.sqlite"
    db.write_text("slash", encoding="utf-8")
    pidfile = rvc / "rvc.pid"
    vc_db = (
        data_dir / "cl" / "validator" / "validators" / "slashing_protection.sqlite"
    )
    vc_db.parent.mkdir(parents=True, exist_ok=True)
    vc_db.write_text("vc-slash", encoding="utf-8")
    return el, db, pidfile, vc_db


def down_env(
    tmp_path: Path,
    extra: dict[str, str] | None = None,
    *,
    docker: Path | None = None,
    bin_dir: Path | None = None,
) -> dict[str, str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full["DOCKER"] = str(docker or (tmp_path / "docker"))
    full["CURL"] = "/bin/echo"
    full["DATA_DIR"] = str(tmp_path / "data")
    full["RUNS_DIR"] = str(tmp_path / "runs")
    if bin_dir is not None:
        full["PATH"] = str(bin_dir) + os.pathsep + full.get("PATH", "")
    if extra:
        full.update(extra)
    return full


def run_down(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    env: dict[str, str] | None = None,
    docker: Path | None = None,
    log: Path | None = None,
    bin_dir: Path | None = None,
    timeout: float = 20,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    if docker is None:
        stub, dlog = write_docker_stub(tmp_path)
    else:
        stub = docker
        dlog = log or (tmp_path / "docker.log")
    full = down_env(tmp_path, env, docker=stub, bin_dir=bin_dir)
    proc = subprocess.run(
        ["bash", str(DOWN), *args],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return proc, dlog


def stub_cmds(log: Path | None) -> list[str]:
    if log is None or not log.is_file():
        return []
    return [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob


def pid_alive(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    proc = subprocess.run(
        ["ps", "-p", str(pid), "-o", "stat="],
        capture_output=True,
        text=True,
        timeout=5,
        stdin=subprocess.DEVNULL,
    )
    st = (proc.stdout or "").strip()
    if not st or st.startswith("Z"):
        return False
    return True


def kill_pid(pid: int | None) -> None:
    if pid is None or pid <= 1:
        return
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        return
    for _ in range(20):
        if not pid_alive(pid):
            return
        time.sleep(0.05)


def wait_alive(pid: int, timeout: float = 2.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pid_alive(pid):
            return
        time.sleep(0.05)
    raise AssertionError(f"pid {pid} never started")


def spawn_sleep() -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        ["sleep", "300"],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def spawn_standin(tmp_path: Path, db: Path, mark: Path) -> subprocess.Popen[bytes]:
    script = tmp_path / "rvc-standin.py"
    script.write_text(
        "import os, signal, sys, time\n"
        "db, mark = sys.argv[1], sys.argv[2]\n"
        "def on_term(signum, frame):\n"
        "    with open(mark, 'w', encoding='utf-8') as fh:\n"
        "        fh.write('db_present' if os.path.exists(db) else 'db_absent')\n"
        "    raise SystemExit(0)\n"
        "signal.signal(signal.SIGTERM, on_term)\n"
        "while True:\n"
        "    time.sleep(0.2)\n",
        encoding="utf-8",
    )
    return subprocess.Popen(
        [sys.executable, str(script), str(db), str(mark)],
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_down_sh_syntax():
    assert DOWN.is_file(), DOWN
    assert os.access(DOWN, os.X_OK)
    proc = subprocess.run(
        ["bash", "-n", str(DOWN)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    common_n = subprocess.run(
        ["bash", "-n", str(COMMON)], capture_output=True, text=True
    )
    assert common_n.returncode == 0, common_n.stderr
    text = DOWN.read_text(encoding="utf-8")
    assert _READ_CMD_RE.search(text) is None
    assert "read -p" not in text
    assert "source" in text and "lib/common.sh" in text
    assert "parse_common_flags" in text
    assert "--data" in text
    assert "parse_down_flags" in text
    assert "remove_resource" in text
    assert "inventory_rows" in text
    assert "inventory_name_scan" in text
    assert re.search(r"(?m)^\s*docker\s", text) is None
    common = COMMON.read_text(encoding="utf-8")
    assert "VALIDATOR_PERF=" in common
    assert "DEVNET_REPORT=" in common
    assert "inventory_rows()" in common
    assert "remove_resource()" in common
    assert "inventory_name_scan()" in common
    assert "stop_rvc()" in common
    assert "name=${CONTAINER_PREFIX}-" in common or "name=eth-devnet-" in common
    assert "--format" in common
    assert "_canon_path" in common
    assert "_basename_is_rvc" in common
    assert '"pid"' in common or "pid)" in common


def test_down_sh_removes_every_inventory_row(tmp_path: Path):
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    el, db, pidfile, _vc_db = plant_data_tree(data_dir)
    pidfile.write_text("424242\n", encoding="utf-8")
    plant_partial_inventory(run_dir, data_dir)
    write_docker_stub(tmp_path, containers=["eth-devnet-geth"], networks=[])
    proc, dlog = run_down(
        tmp_path,
        ["--run-dir", str(run_dir)],
        docker=tmp_path / "docker",
        log=tmp_path / "docker.log",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    cmds = stub_cmds(dlog)
    assert any(c.startswith("rm ") and "eth-devnet-geth" in c for c in cmds), cmds
    assert not any(
        c.startswith("rm ") and "eth-devnet-already-gone" in c for c in cmds
    ), cmds
    assert "skip container eth-devnet-already-gone" in proc.stderr
    assert not el.exists()
    assert not db.exists()
    assert not pidfile.exists()
    assert run_dir.is_dir()
    assert (run_dir / "inventory.json").is_file()


def test_down_sh_absent_resource_is_not_an_error(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "inventory.json").write_text(
        '{"kind":"container","name":"eth-devnet-already-gone"}\n',
        encoding="utf-8",
    )
    write_docker_stub(tmp_path, containers=[], networks=[])
    proc, dlog = run_down(
        tmp_path,
        ["--run-dir", str(run_dir)],
        docker=tmp_path / "docker",
        log=tmp_path / "docker.log",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    assert "skip" in proc.stderr
    assert "eth-devnet-already-gone" in proc.stderr
    cmds = stub_cmds(dlog)
    assert not any(c.startswith("rm ") for c in cmds), cmds


def test_down_sh_name_scan_fallback_without_inventory(tmp_path: Path):
    write_docker_stub(
        tmp_path,
        containers=[
            "eth-devnet-geth",
            "eth-devnet-beacon",
            "eth-devnet-validator",
        ],
        networks=["eth-devnet-network"],
    )
    proc, dlog = run_down(
        tmp_path,
        docker=tmp_path / "docker",
        log=tmp_path / "docker.log",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    assert "name scan" in proc.stderr
    cmds = stub_cmds(dlog)
    assert any(
        c.startswith("ps ")
        and "name=eth-devnet-" in c
        and "{{.Names}}" in c
        for c in cmds
    ), cmds
    rms = [c for c in cmds if c.startswith("rm ")]
    assert any("eth-devnet-geth" in c for c in rms), rms
    assert any("eth-devnet-beacon" in c for c in rms), rms
    assert any("eth-devnet-validator" in c for c in rms), rms
    assert any("network rm" in c and "eth-devnet-network" in c for c in cmds), cmds
    allc = (tmp_path / "docker-state" / "all").read_text(encoding="utf-8").strip()
    nets = (tmp_path / "docker-state" / "networks").read_text(encoding="utf-8").strip()
    assert allc == ""
    assert nets == ""
    assert not (tmp_path / "runs" / "standalone" / "inventory.json").exists()


def test_down_sh_data_purges_slashing_db(tmp_path: Path):
    data_dir = tmp_path / "data"
    _el, db, pidfile, vc_db = plant_data_tree(data_dir)
    pidfile.write_text("424242\n", encoding="utf-8")
    write_docker_stub(tmp_path, containers=[], networks=[])
    proc1, dlog = run_down(
        tmp_path,
        ["--data"],
        docker=tmp_path / "docker",
        log=tmp_path / "docker.log",
    )
    assert proc1.returncode == 0, proc1.stderr
    assert proc1.stdout == ""
    assert_no_secret(proc1)
    assert not data_dir.exists()
    assert not db.exists()
    assert not vc_db.exists()
    leftover = list(tmp_path.rglob("slashing_protection.sqlite"))
    assert leftover == [], leftover
    proc2, _ = run_down(
        tmp_path,
        ["--data"],
        docker=tmp_path / "docker",
        log=dlog,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert proc2.stdout == ""
    assert_no_secret(proc2)
    assert not data_dir.exists()


def test_down_sh_leaves_runs_dir(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_data_tree(data_dir)
    runs = tmp_path / "runs" / "old"
    runs.mkdir(parents=True)
    sentinel = runs / "keep.txt"
    sentinel.write_text("keep\n", encoding="utf-8")
    inv = runs / "inventory.json"
    inv.write_text('{"kind":"container","name":"eth-devnet-geth"}\n', encoding="utf-8")
    write_docker_stub(tmp_path, containers=[], networks=[])
    proc, _ = run_down(
        tmp_path,
        ["--data"],
        docker=tmp_path / "docker",
        log=tmp_path / "docker.log",
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    assert not data_dir.exists()
    assert sentinel.is_file()
    assert sentinel.read_text(encoding="utf-8") == "keep\n"
    assert inv.is_file()


def test_down_sh_kills_rvc_pid_before_purging_db(tmp_path: Path):
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    _el, db, pidfile, _vc_db = plant_data_tree(data_dir)
    plant_partial_inventory(run_dir, data_dir)
    mark = tmp_path / "term-mark"
    bin_dir, ps_map = write_ps_stub(tmp_path)
    write_docker_stub(tmp_path, containers=["eth-devnet-geth"], networks=[])
    child = spawn_standin(tmp_path, db, mark)
    try:
        wait_alive(child.pid)
        pidfile.write_text(f"{child.pid}\n", encoding="utf-8")
        map_ps_comm(ps_map, child.pid, "rvc")
        proc, _ = run_down(
            tmp_path,
            ["--data", "--run-dir", str(run_dir)],
            docker=tmp_path / "docker",
            log=tmp_path / "docker.log",
            bin_dir=bin_dir,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == ""
        assert_no_secret(proc)
        assert not pid_alive(child.pid)
        assert not db.exists()
        assert not data_dir.exists()
        assert mark.is_file(), proc.stderr
        assert mark.read_text(encoding="utf-8") == "db_present"
        err = proc.stderr
        stop_at = err.find("stopping rvc pid")
        db_at = err.find("removing slashing_db")
        purge_at = err.find("purging data dir")
        assert stop_at != -1, err
        assert purge_at != -1, err
        assert stop_at < purge_at, err
        if db_at != -1:
            assert stop_at < db_at, err
    finally:
        kill_pid(child.pid)
        child.wait(timeout=2)


def test_down_sh_stale_pid_is_skipped_not_killed(tmp_path: Path):
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    _el, _db, pidfile, _vc_db = plant_data_tree(data_dir)
    plant_partial_inventory(run_dir, data_dir)
    bin_dir, ps_map = write_ps_stub(tmp_path)
    write_docker_stub(tmp_path, containers=["eth-devnet-geth"], networks=[])
    child = spawn_sleep()
    try:
        wait_alive(child.pid)
        pidfile.write_text(f"{child.pid}\n", encoding="utf-8")
        map_ps_comm(ps_map, child.pid, "python3")
        proc, _ = run_down(
            tmp_path,
            ["--run-dir", str(run_dir)],
            docker=tmp_path / "docker",
            log=tmp_path / "docker.log",
            bin_dir=bin_dir,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == ""
        assert_no_secret(proc)
        assert pid_alive(child.pid)
        assert "skip pid" in proc.stderr
        assert "not rvc" in proc.stderr
        assert "stopping rvc" not in proc.stderr
    finally:
        kill_pid(child.pid)
        child.wait(timeout=2)


def test_down_sh_matches_rvc_comm_basename(tmp_path: Path):
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    _el, _db, pidfile, _vc_db = plant_data_tree(data_dir)
    plant_partial_inventory(run_dir, data_dir)
    bin_dir, ps_map = write_ps_stub(tmp_path)
    write_docker_stub(tmp_path, containers=["eth-devnet-geth"], networks=[])
    child = spawn_sleep()
    try:
        wait_alive(child.pid)
        pidfile.write_text(f"{child.pid}\n", encoding="utf-8")
        map_ps_comm(ps_map, child.pid, "/Users/dev/work/target/release/rvc")
        proc, _ = run_down(
            tmp_path,
            ["--run-dir", str(run_dir)],
            docker=tmp_path / "docker",
            log=tmp_path / "docker.log",
            bin_dir=bin_dir,
        )
        assert proc.returncode == 0, proc.stderr
        assert_no_secret(proc)
        assert not pid_alive(child.pid)
        assert "stopping rvc pid" in proc.stderr
        assert not pidfile.exists()
    finally:
        kill_pid(child.pid)
        child.wait(timeout=2)


def test_down_sh_removes_sqlite_wal_shm(tmp_path: Path):
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    _el, db, pidfile, _vc_db = plant_data_tree(data_dir)
    pidfile.write_text("424242\n", encoding="utf-8")
    wal = Path(str(db) + "-wal")
    shm = Path(str(db) + "-shm")
    wal.write_text("wal", encoding="utf-8")
    shm.write_text("shm", encoding="utf-8")
    plant_partial_inventory(run_dir, data_dir)
    write_docker_stub(tmp_path, containers=["eth-devnet-geth"], networks=[])
    proc, _ = run_down(
        tmp_path,
        ["--run-dir", str(run_dir)],
        docker=tmp_path / "docker",
        log=tmp_path / "docker.log",
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    assert not db.exists()
    assert not wal.exists()
    assert not shm.exists()


def test_down_sh_refuses_inventory_path_escape(tmp_path: Path):
    data_dir = tmp_path / "data"
    run_dir = tmp_path / "run"
    plant_data_tree(data_dir)
    run_dir.mkdir()
    secret = tmp_path / "runs" / "secret.txt"
    secret.parent.mkdir(parents=True)
    secret.write_text("keep\n", encoding="utf-8")
    escaped = f"{data_dir}/../runs"
    (run_dir / "inventory.json").write_text(
        '{"kind":"datadir","name":"escaped","path":"%s"}\n' % escaped,
        encoding="utf-8",
    )
    write_docker_stub(tmp_path, containers=[], networks=[])
    proc, _ = run_down(
        tmp_path,
        ["--run-dir", str(run_dir)],
        docker=tmp_path / "docker",
        log=tmp_path / "docker.log",
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    assert "path outside data dir" in proc.stderr
    assert secret.is_file()
    assert secret.read_text(encoding="utf-8") == "keep\n"
    assert (data_dir / "el").is_dir()


def test_down_sh_data_refuses_runs_dir(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_data_tree(data_dir)
    sentinel = tmp_path / "runs" / "keep.txt"
    sentinel.parent.mkdir(parents=True)
    sentinel.write_text("keep\n", encoding="utf-8")
    write_docker_stub(tmp_path, containers=[], networks=[])
    proc, _ = run_down(
        tmp_path,
        ["--data"],
        env={"DATA_DIR": str(tmp_path / "data" / "..")},
        docker=tmp_path / "docker",
        log=tmp_path / "docker.log",
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    assert "RUNS_DIR" in proc.stderr
    assert sentinel.is_file()
    assert sentinel.read_text(encoding="utf-8") == "keep\n"
    assert data_dir.is_dir()


def test_down_sh_skips_non_devnet_container(tmp_path: Path):
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "inventory.json").write_text(
        '{"kind":"container","name":"postgres"}\n',
        encoding="utf-8",
    )
    write_docker_stub(
        tmp_path,
        containers=["postgres", "eth-devnet-geth"],
        networks=[],
    )
    proc, dlog = run_down(
        tmp_path,
        ["--run-dir", str(run_dir)],
        docker=tmp_path / "docker",
        log=tmp_path / "docker.log",
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    assert "skip container postgres" in proc.stderr
    cmds = stub_cmds(dlog)
    assert not any(c.startswith("rm ") and "postgres" in c for c in cmds), cmds
    allc = (tmp_path / "docker-state" / "all").read_text(encoding="utf-8")
    assert "postgres" in allc
    assert "eth-devnet-geth" in allc
