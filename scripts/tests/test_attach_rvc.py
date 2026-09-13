"""Stub-tested attach-rvc.sh: launch, health gate, rvc.json, inventory (issue 3.3)."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import sqlite3
import stat
import subprocess
import time
from pathlib import Path

import pytest

from test_attach_render import _GENESIS_GVR, _MNEMONIC, assert_no_password, plant_rvc_tree
from test_devnet_env import ENV_PATH, parse_env

ATTACH = Path(__file__).resolve().parents[1] / "devnet" / "attach-rvc.sh"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
KEYPATHS = FIXTURES / "rvc_json__keypaths.txt"

_ENV = parse_env(ENV_PATH)
_N = int(_ENV["NUM_VALIDATORS"])
_K = int(_ENV["RVC_KEYS"])

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
    "RVC_BIN",
    "RVC_METRICS_PORT",
    "ATTACH_TIMEOUT",
    "NUM_VALIDATORS",
    "RVC_KEYS",
)

_READ_CMD_RE = re.compile(r"(?m)^\s*read\s")
_REAL_CURL = shutil.which("curl") or "/usr/bin/curl"


def json_keypaths(obj: object, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.add(path)
            paths |= json_keypaths(value, path)
    elif isinstance(obj, list):
        elem = f"{prefix}[]"
        for item in obj:
            paths |= json_keypaths(item, elem)
    return paths


def free_port() -> int:
    # pytest-socket blocks socket.socket in this process; bind in a subprocess.
    proc = subprocess.run(
        [
            "python3",
            "-c",
            "import socket; s=socket.socket(); s.bind(('127.0.0.1',0)); "
            "print(s.getsockname()[1])",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return int(proc.stdout.strip())


def file_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def inventory_rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def pid_alive(pid: int) -> bool:
    if pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def kill_pid(pid: int | None) -> None:
    if pid is None or pid <= 1:
        return
    try:
        os.kill(pid, 9)
    except OSError:
        return
    for _ in range(20):
        if not pid_alive(pid):
            return
        time.sleep(0.05)


def read_pidfile(data_dir: Path) -> int | None:
    path = data_dir / "rvc" / "rvc.pid"
    if not path.is_file():
        return None
    text = path.read_text(encoding="utf-8").strip()
    if not text.isdigit():
        return None
    return int(text)


def plant_attach_tree(data_dir: Path, *, n_keys: int | None = None) -> list[str]:
    n_keys = _K if n_keys is None else n_keys
    data_dir.mkdir(parents=True, exist_ok=True)
    data_dir.chmod(0o700)
    pubkeys = [f"{i:096x}" for i in range(n_keys)]
    plant_rvc_tree(data_dir, pubkeys=pubkeys)
    rvc_keys = data_dir / "keys" / "rvc"
    prefixed = [f"0x{pk}" for pk in pubkeys]
    pub_path = rvc_keys / "pubkeys.txt"
    pub_path.write_text("".join(f"{pk}\n" for pk in prefixed), encoding="utf-8")
    pub_path.chmod(0o600)
    genesis = data_dir / "genesis"
    genesis.mkdir(parents=True, exist_ok=True)
    (genesis / "genesis_validators_root.txt").write_text(
        _GENESIS_GVR + "\n", encoding="utf-8"
    )
    return prefixed


def write_slashing_db(path: Path, gvr: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path))
    try:
        con.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)")
        con.execute(
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            ("genesis_validators_root", gvr),
        )
        con.commit()
    finally:
        con.close()
    path.chmod(0o600)


def write_curl_stub(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "curl.log"
    stub = tmp_path / "curl"
    genesis = FIXTURES / "bn_genesis.json"
    spec = FIXTURES / "bn_spec.json"
    fork = FIXTURES / "bn_head_fork.json"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "url=\"\"\n"
        "for a in \"$@\"; do url=\"$a\"; done\n"
        "case \"$url\" in\n"
        "  */eth/v1/beacon/genesis)\n"
        f"    cat {shlex.quote(str(genesis))}\n"
        "    exit 0\n"
        "    ;;\n"
        "  */eth/v1/config/spec)\n"
        f"    cat {shlex.quote(str(spec))}\n"
        "    exit 0\n"
        "    ;;\n"
        "  */eth/v1/beacon/states/head/fork)\n"
        f"    cat {shlex.quote(str(fork))}\n"
        "    exit 0\n"
        "    ;;\n"
        "  */health|*/readyz|*/livez)\n"
        f"    exec {shlex.quote(_REAL_CURL)} \"$@\"\n"
        "    ;;\n"
        "esac\n"
        "printf '%s\\n' 'unscripted curl' >&2\n"
        "exit 1\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def write_rvc_stub(
    tmp_path: Path,
    *,
    mode: str = "healthy",
    port: int,
) -> tuple[Path, Path, Path, Path]:
    argv_log = tmp_path / "rvc-argv.log"
    inv_snap = tmp_path / "inv-at-spawn.json"
    pid_out = tmp_path / "rvc-stub.pid"
    env_out = tmp_path / "rvc-stub.env"
    stub = tmp_path / "rvc"
    stub.write_text(
        "#!/usr/bin/env python3\n"
        "import os, shutil, sys, time\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        f"ARGV_LOG = {str(argv_log)!r}\n"
        f"INV_SNAP = {str(inv_snap)!r}\n"
        f"PID_OUT = {str(pid_out)!r}\n"
        f"ENV_OUT = {str(env_out)!r}\n"
        f"MODE = {mode!r}\n"
        f"PORT = {int(port)}\n"
        "\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        path = self.path.split('?', 1)[0]\n"
        "        if path in ('/health', '/readyz', '/livez'):\n"
        "            self.send_response(200)\n"
        "            self.send_header('Content-Type', 'application/json')\n"
        "            self.end_headers()\n"
        "            self.wfile.write(b'{\"healthy\":true}\\n')\n"
        "        else:\n"
        "            self.send_response(404)\n"
        "            self.end_headers()\n"
        "    def log_message(self, fmt, *args):\n"
        "        return\n"
        "\n"
        "class Server(HTTPServer):\n"
        "    allow_reuse_address = True\n"
        "\n"
        "def main():\n"
        "    with open(ARGV_LOG, 'a', encoding='utf-8') as fh:\n"
        "        fh.write(' '.join(sys.argv) + '\\n')\n"
        "    with open(PID_OUT, 'w', encoding='utf-8') as fh:\n"
        "        fh.write(str(os.getpid()) + '\\n')\n"
        "    with open(ENV_OUT, 'w', encoding='utf-8') as fh:\n"
        "        fh.write('MNEMONIC=' + ('1' if 'MNEMONIC' in os.environ else '0') + '\\n')\n"
        "    run_dir = os.environ.get('RUN_DIR') or ''\n"
        "    inv = os.path.join(run_dir, 'inventory.json') if run_dir else ''\n"
        "    if inv and os.path.isfile(inv):\n"
        "        shutil.copy(inv, INV_SNAP)\n"
        "    sys.stdout.write('rvc-stub mode=%s\\n' % MODE)\n"
        "    sys.stdout.flush()\n"
        "    if MODE == 'fail':\n"
        "        raise SystemExit(1)\n"
        "    if MODE == 'never':\n"
        "        while True:\n"
        "            time.sleep(30)\n"
        "    port = int(os.environ.get('RVC_METRICS_PORT') or PORT)\n"
        "    Server(('127.0.0.1', port), Handler).serve_forever()\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, argv_log, inv_snap, pid_out


def attach_env(
    tmp_path: Path,
    *,
    rvc: Path,
    curl: Path,
    port: int,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full["RVC_BIN"] = str(rvc)
    full["CURL"] = str(curl)
    full["DOCKER"] = "/bin/echo"
    full["DATA_DIR"] = str(tmp_path / "data")
    full["RUNS_DIR"] = str(tmp_path / "runs")
    full["RVC_METRICS_PORT"] = str(port)
    full["PROFILE"] = "fast"
    if extra:
        full.update(extra)
    return full


def run_attach(
    tmp_path: Path,
    args: list[str] | tuple[str, ...],
    *,
    rvc: Path,
    curl: Path,
    port: int,
    extra: dict[str, str] | None = None,
    timeout: float = 30,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    env = attach_env(tmp_path, rvc=rvc, curl=curl, port=port, extra=extra)
    return subprocess.run(
        ["bash", str(ATTACH), *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
        cwd=cwd,
    )


def start_leftover_health(port: int) -> subprocess.Popen[str]:
    code = (
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        "class H(BaseHTTPRequestHandler):\n"
        "    def do_GET(self):\n"
        "        self.send_response(200); self.end_headers(); self.wfile.write(b'ok')\n"
        "    def log_message(self, *a): return\n"
        "class S(HTTPServer):\n"
        "    allow_reuse_address = True\n"
        f"S(('127.0.0.1', {int(port)}), H).serve_forever()\n"
    )
    return subprocess.Popen(
        ["python3", "-c", code],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        text=True,
    )


def assert_no_secrets(proc: subprocess.CompletedProcess[str], data_dir: Path) -> None:
    assert_no_password(proc, data_dir)
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob
    texts = [blob]
    for path in (
        data_dir / "rvc" / "rvc.log",
        *data_dir.parent.glob("run*/logs/rvc.log"),
    ):
        if path.is_file():
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
    for text in texts:
        assert _MNEMONIC not in text
        for pw_path in (
            data_dir / "keys" / "rvc" / "passwords.txt",
            data_dir / "rvc" / "passwords.txt",
        ):
            if not pw_path.is_file():
                continue
            for line in pw_path.read_text(encoding="utf-8").splitlines():
                if "=" not in line:
                    continue
                password = line.split("=", 1)[1]
                if password:
                    assert password not in text


def assert_passwords_absent_from_log(data_dir: Path) -> None:
    pw = data_dir / "rvc" / "passwords.txt"
    log = data_dir / "rvc" / "rvc.log"
    assert pw.is_file()
    assert log.is_file()
    log_text = log.read_text(encoding="utf-8", errors="replace")
    for line in pw.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        password = line.split("=", 1)[1]
        if password:
            assert password not in log_text
    assert _MNEMONIC not in log_text


def test_attach_rvc_sh_exists_and_syntax():
    assert ATTACH.is_file(), ATTACH
    proc = subprocess.run(
        ["bash", "-n", str(ATTACH)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = ATTACH.read_text(encoding="utf-8")
    assert "set -euo pipefail" in text
    assert "lib/common.sh" in text
    assert "parse_common_flags" in text
    assert 'RVC_BIN="${RVC_BIN:-target/release/rvc}"' in text
    assert "cargo" not in text
    assert "_resolve_rvc_bin" in text
    assert "_pid_is_our_rvc" in text
    assert "_health_owned_by_pid" in text
    assert "O_NOFOLLOW" in text
    assert "env -u MNEMONIC" in text
    assert "wait_for_service" in text
    assert "render_rvc_config" in text
    assert "assert_slashing_db_gvr" in text
    assert "spawn_rvc" in text
    assert "is_rvc_attached" in text
    assert "--init-slashing-db" in text
    assert "--metrics-address 127.0.0.1" in text
    assert "die_notready" in text
    assert "Phase 6" in text and "DN-15" in text
    assert _READ_CMD_RE.search(text) is None
    main_src = text.split("main() {", 1)[1]
    assert main_src.index("_inventory_attach_rows") < main_src.index("spawn_rvc")


def test_attach_rvc_shellcheck():
    exe = shutil.which("shellcheck")
    if exe is None:
        pytest.skip("shellcheck not installed")
    proc = subprocess.run(
        [exe, str(ATTACH)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_attach_docker_flag_exits_2(tmp_path: Path):
    proc = run_attach(
        tmp_path,
        ["--docker"],
        rvc=tmp_path / "missing-rvc",
        curl=tmp_path / "missing-curl",
        port=9,
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "Phase 6" in proc.stderr
    assert "DN-15" in proc.stderr
    assert "unknown flag" not in proc.stderr
    assert _MNEMONIC not in proc.stdout + proc.stderr

    run_dir = tmp_path / "run"
    proc2 = run_attach(
        tmp_path,
        ["--run-dir", str(run_dir), "--docker"],
        rvc=tmp_path / "missing-rvc",
        curl=tmp_path / "missing-curl",
        port=9,
    )
    assert proc2.returncode == 2
    assert "Phase 6" in proc2.stderr
    assert "DN-15" in proc2.stderr


def test_attach_requires_run_dir(tmp_path: Path):
    proc = run_attach(
        tmp_path,
        ["--timeout", "1"],
        rvc=tmp_path / "missing-rvc",
        curl=tmp_path / "missing-curl",
        port=9,
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "--run-dir" in proc.stderr
    assert _MNEMONIC not in proc.stdout + proc.stderr


def test_stale_slashing_db_exits_2(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    db = data_dir / "rvc" / "slashing_protection.sqlite"
    write_slashing_db(db, "0x" + "cd" * 32)
    curl, _ = write_curl_stub(tmp_path)
    rvc, _, _, _ = write_rvc_stub(tmp_path, mode="healthy", port=free_port())
    run_dir = tmp_path / "run"
    proc = run_attach(
        tmp_path,
        ["--run-dir", str(run_dir), "--timeout", "1"],
        rvc=rvc,
        curl=curl,
        port=free_port(),
    )
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    err = proc.stderr
    assert "slashing_protection.sqlite" in err or str(db) in err
    assert "purge" in err.lower()
    assert not (run_dir / "rvc.json").exists()
    assert_no_secrets(proc, data_dir)


def test_inventory_rows_precede_spawn(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    rvc, argv_log, inv_snap, pid_out = write_rvc_stub(
        tmp_path, mode="fail", port=port
    )
    run_dir = tmp_path / "run"
    proc = run_attach(
        tmp_path,
        ["--run-dir", str(run_dir), "--timeout", "4"],
        rvc=rvc,
        curl=curl,
        port=port,
    )
    assert proc.returncode == 5, proc.stderr
    assert not (run_dir / "rvc.json").exists()
    rows = inventory_rows(run_dir / "inventory.json")
    kinds = {(r.get("kind"), r.get("name")) for r in rows}
    assert ("pid", "rvc") in kinds
    assert ("slashing_db", "slashing_protection.sqlite") in kinds
    pid_row = next(r for r in rows if r["kind"] == "pid")
    slash_row = next(r for r in rows if r["kind"] == "slashing_db")
    assert pid_row["path"].endswith("/rvc.pid")
    assert slash_row["path"].endswith("/slashing_protection.sqlite")
    assert inv_snap.is_file(), proc.stderr
    snap_rows = inventory_rows(inv_snap)
    snap_kinds = {(r.get("kind"), r.get("name")) for r in snap_rows}
    assert ("pid", "rvc") in snap_kinds
    assert ("slashing_db", "slashing_protection.sqlite") in snap_kinds
    assert argv_log.is_file()
    argv = argv_log.read_text(encoding="utf-8")
    assert " start " in f" {argv} "
    assert "-c" in argv
    assert "--init-slashing-db" in argv
    assert "--metrics-address" in argv
    assert "127.0.0.1" in argv
    assert_no_secrets(proc, data_dir)
    if pid_out.is_file():
        kill_pid(int(pid_out.read_text(encoding="utf-8").strip() or "0"))


def test_attach_timeout_exits_5_and_writes_no_rvc_json(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    rvc, _, _, pid_out = write_rvc_stub(tmp_path, mode="never", port=port)
    run_dir = tmp_path / "run"
    proc = run_attach(
        tmp_path,
        ["--run-dir", str(run_dir), "--timeout", "4"],
        rvc=rvc,
        curl=curl,
        port=port,
    )
    assert proc.returncode == 5, proc.stderr
    assert not (run_dir / "rvc.json").exists()
    copied = run_dir / "logs" / "rvc.log"
    assert copied.is_file(), proc.stderr
    assert copied.stat().st_size >= 0
    stub_pid = None
    if pid_out.is_file():
        raw = pid_out.read_text(encoding="utf-8").strip()
        if raw.isdigit():
            stub_pid = int(raw)
    assert stub_pid is not None
    assert not pid_alive(stub_pid)
    assert_no_secrets(proc, data_dir)
    kill_pid(stub_pid)


def test_attach_twice_is_noop(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    rvc, _, _, pid_out = write_rvc_stub(tmp_path, mode="healthy", port=port)
    run_dir = tmp_path / "run"
    args = ["--run-dir", str(run_dir), "--timeout", "8"]
    live: list[int] = []
    try:
        first = run_attach(tmp_path, args, rvc=rvc, curl=curl, port=port)
        assert first.returncode == 0, first.stderr
        assert_no_secrets(first, data_dir)
        pidfile = data_dir / "rvc" / "rvc.pid"
        assert pidfile.is_file()
        first_bytes = pidfile.read_bytes()
        first_pid = read_pidfile(data_dir)
        assert first_pid is not None
        live.append(first_pid)
        assert pid_alive(first_pid)

        second = run_attach(tmp_path, args, rvc=rvc, curl=curl, port=port)
        assert second.returncode == 0, second.stderr
        assert "already attached" in second.stderr
        assert pidfile.read_bytes() == first_bytes
        assert read_pidfile(data_dir) == first_pid
        assert pid_alive(first_pid)
        assert_no_secrets(second, data_dir)

        forced = run_attach(
            tmp_path, [*args, "--force"], rvc=rvc, curl=curl, port=port
        )
        assert forced.returncode == 0, forced.stderr
        assert_no_secrets(forced, data_dir)
        new_pid = read_pidfile(data_dir)
        assert new_pid is not None
        live.append(new_pid)
        assert new_pid != first_pid
        assert pidfile.read_bytes() != first_bytes
        assert pid_alive(new_pid)
        assert not pid_alive(first_pid)
        assert (run_dir / "rvc.json").is_file()
        doc = json.loads((run_dir / "rvc.json").read_text(encoding="utf-8"))
        assert doc["pid"] == new_pid
    finally:
        for pid in live:
            kill_pid(pid)
        if pid_out.is_file():
            raw = pid_out.read_text(encoding="utf-8").strip()
            if raw.isdigit():
                kill_pid(int(raw))


def test_rvc_json_key_paths(tmp_path: Path):
    data_dir = tmp_path / "data"
    planted = plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    rvc, _, _, pid_out = write_rvc_stub(tmp_path, mode="healthy", port=port)
    run_dir = tmp_path / "run"
    proc = None
    pid = None
    try:
        proc = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout == ""
        assert_no_secrets(proc, data_dir)
        assert_passwords_absent_from_log(data_dir)
        pid = read_pidfile(data_dir)
        assert pid is not None
        rvc_json = run_dir / "rvc.json"
        assert rvc_json.is_file()
        assert file_mode(rvc_json) == 0o600
        doc = json.loads(rvc_json.read_text(encoding="utf-8"))
        got = json_keypaths(doc)
        want = {
            line
            for line in KEYPATHS.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        assert got == want
        assert sorted(got) == KEYPATHS.read_text(encoding="utf-8").splitlines()
        pub_path = data_dir / "keys" / "rvc" / "pubkeys.txt"
        pub_text = pub_path.read_text(encoding="utf-8")
        pub_lines = [ln for ln in pub_text.splitlines() if ln]
        assert len(pub_lines) == _K
        assert doc["pubkeys"] == pub_lines
        assert doc["pubkeys"] == planted
        reconstructed = "\n".join(doc["pubkeys"]) + "\n"
        assert reconstructed == pub_text
        for pk in doc["pubkeys"]:
            assert pk == pk.lower()
            assert pk.startswith("0x")
            assert len(pk) == 2 + 96
        assert doc["schema_version"] == 1
        assert doc["pid"] == pid
        assert doc["endpoint"] == f"http://127.0.0.1:{port}"
        assert doc["key_range"] == [_N - _K, _N]
        assert Path(doc["config_path"]).resolve() == (
            data_dir / "rvc" / "config.toml"
        ).resolve()
        copied_c = run_dir / "rvc" / "config.toml"
        copied_v = run_dir / "rvc" / "validators.toml"
        assert copied_c.is_file()
        assert copied_v.is_file()
        assert copied_c.read_bytes() == (
            data_dir / "rvc" / "config.toml"
        ).read_bytes()
        assert copied_v.read_bytes() == (
            data_dir / "rvc" / "validators.toml"
        ).read_bytes()
        assert stat.S_ISREG(rvc_json.stat().st_mode)
    finally:
        if pid is not None:
            kill_pid(pid)
        if pid_out.is_file():
            raw = pid_out.read_text(encoding="utf-8").strip()
            if raw.isdigit():
                kill_pid(int(raw))
        if proc is not None:
            assert_no_secrets(proc, data_dir)


def test_leftover_health_dead_stub_writes_no_rvc_json(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    leftover = start_leftover_health(port)
    try:
        deadline = time.time() + 5
        up = False
        while time.time() < deadline:
            probe = subprocess.run(
                [
                    _REAL_CURL,
                    "-sS",
                    "--fail",
                    "--max-time",
                    "1",
                    f"http://127.0.0.1:{port}/health",
                ],
                capture_output=True,
            )
            if probe.returncode == 0:
                up = True
                break
            time.sleep(0.05)
        assert up, "leftover /health did not start"
        curl, _ = write_curl_stub(tmp_path)
        rvc, _, _, pid_out = write_rvc_stub(tmp_path, mode="fail", port=port)
        run_dir = tmp_path / "run"
        proc = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--timeout", "4"],
            rvc=rvc,
            curl=curl,
            port=port,
        )
        log = data_dir / "rvc" / "rvc.log"
        pidfile = data_dir / "rvc" / "rvc.pid"
        dbg = proc.stderr
        if log.is_file():
            dbg += "\nLOG:" + log.read_text(encoding="utf-8", errors="replace")
        if pidfile.is_file():
            dbg += "\nPIDFILE:" + pidfile.read_text(encoding="utf-8")
        if pid_out.is_file():
            dbg += "\nSTUBPID:" + pid_out.read_text(encoding="utf-8")
        assert proc.returncode == 5, dbg
        assert not (run_dir / "rvc.json").exists()
        assert_no_secrets(proc, data_dir)
        if pid_out.is_file():
            raw = pid_out.read_text(encoding="utf-8").strip()
            if raw.isdigit():
                kill_pid(int(raw))
    finally:
        leftover.kill()
        leftover.wait(timeout=5)


def test_force_skips_kill_of_foreign_pid(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    rvc_dir = data_dir / "rvc"
    rvc_dir.mkdir(parents=True, exist_ok=True)
    sleeper = subprocess.Popen(["sleep", "300"])
    try:
        pidfile = rvc_dir / "rvc.pid"
        pidfile.write_text(f"{sleeper.pid}\n", encoding="utf-8")
        pidfile.chmod(0o600)
        port = free_port()
        curl, _ = write_curl_stub(tmp_path)
        rvc, _, _, pid_out = write_rvc_stub(tmp_path, mode="healthy", port=port)
        run_dir = tmp_path / "run"
        proc = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--timeout", "8", "--force"],
            rvc=rvc,
            curl=curl,
            port=port,
        )
        assert proc.returncode == 0, proc.stderr
        assert sleeper.poll() is None
        assert "skip kill" in proc.stderr
        new_pid = read_pidfile(data_dir)
        assert new_pid is not None
        assert new_pid != sleeper.pid
        kill_pid(new_pid)
        if pid_out.is_file():
            raw = pid_out.read_text(encoding="utf-8").strip()
            if raw.isdigit():
                kill_pid(int(raw))
        assert_no_secrets(proc, data_dir)
    finally:
        sleeper.kill()
        sleeper.wait(timeout=5)


def test_rvc_log_refuses_leaf_symlink(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    rvc_dir = data_dir / "rvc"
    rvc_dir.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim.log"
    victim.write_text("KEEP\n", encoding="utf-8")
    (rvc_dir / "rvc.log").symlink_to(victim)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    rvc, _, _, pid_out = write_rvc_stub(tmp_path, mode="healthy", port=port)
    run_dir = tmp_path / "run"
    proc = run_attach(
        tmp_path,
        ["--run-dir", str(run_dir), "--timeout", "8"],
        rvc=rvc,
        curl=curl,
        port=port,
    )
    assert proc.returncode == 2, proc.stderr
    assert "symlink" in proc.stderr
    assert "rvc.log" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "KEEP\n"
    assert not (run_dir / "rvc.json").exists()
    if pid_out.is_file():
        raw = pid_out.read_text(encoding="utf-8").strip()
        if raw.isdigit():
            kill_pid(int(raw))


def test_copied_log_refuses_dest_symlink(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    rvc, _, _, pid_out = write_rvc_stub(tmp_path, mode="never", port=port)
    run_dir = tmp_path / "run"
    log_dir = run_dir / "logs"
    log_dir.mkdir(parents=True)
    victim = tmp_path / "victim-dest.log"
    victim.write_text("KEEP\n", encoding="utf-8")
    (log_dir / "rvc.log").symlink_to(victim)
    proc = run_attach(
        tmp_path,
        ["--run-dir", str(run_dir), "--timeout", "4"],
        rvc=rvc,
        curl=curl,
        port=port,
    )
    assert proc.returncode == 2, proc.stderr
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "KEEP\n"
    assert not (run_dir / "rvc.json").exists()
    if pid_out.is_file():
        raw = pid_out.read_text(encoding="utf-8").strip()
        if raw.isdigit():
            kill_pid(int(raw))


def test_relative_rvc_bin_uses_repo_root_not_cwd(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    cwd = tmp_path / "cwd"
    planted = cwd / "cwd-planted"
    planted.mkdir(parents=True)
    marker = cwd / "pwned"
    evil = planted / "rvc"
    evil.write_text(
        "#!/bin/sh\n"
        f"echo pwned > {shlex.quote(str(marker))}\n"
        "exit 0\n",
        encoding="utf-8",
    )
    evil.chmod(0o755)
    curl, _ = write_curl_stub(tmp_path)
    run_dir = tmp_path / "run"
    proc = run_attach(
        tmp_path,
        ["--run-dir", str(run_dir), "--timeout", "1"],
        rvc=tmp_path / "unused-rvc",
        curl=curl,
        port=free_port(),
        extra={"RVC_BIN": "cwd-planted/rvc"},
        cwd=cwd,
    )
    assert proc.returncode != 0
    assert not marker.exists()
    repo_bin = (ATTACH.resolve().parents[2] / "cwd-planted" / "rvc").as_posix()
    assert repo_bin in proc.stderr
    assert "not found" in proc.stderr
    assert not (run_dir / "rvc.json").exists()


def test_mnemonic_not_exported_to_child(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    rvc, _, _, pid_out = write_rvc_stub(tmp_path, mode="healthy", port=port)
    run_dir = tmp_path / "run"
    pid = None
    try:
        proc = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
            extra={"MNEMONIC": _MNEMONIC},
        )
        assert proc.returncode == 0, proc.stderr
        env_out = tmp_path / "rvc-stub.env"
        assert env_out.is_file(), proc.stderr
        assert env_out.read_text(encoding="utf-8").strip() == "MNEMONIC=0"
        assert_no_secrets(proc, data_dir)
        pid = read_pidfile(data_dir)
    finally:
        if pid is not None:
            kill_pid(pid)
        if pid_out.is_file():
            raw = pid_out.read_text(encoding="utf-8").strip()
            if raw.isdigit():
                kill_pid(int(raw))
