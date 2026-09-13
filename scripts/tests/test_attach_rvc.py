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
    "SOAK_START_OFFSET_EPOCHS",
    "RVC_BIN",
    "RVC_METRICS_PORT",
    "ATTACH_TIMEOUT",
    "NUM_VALIDATORS",
    "RVC_KEYS",
    "LAUNCH_MODE",
    "RVC_IMAGE",
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
    assert "launch_rvc_native" in text
    assert "launch_rvc_docker" in text
    assert "LAUNCH_MODE" in text
    assert "is_rvc_attached" in text
    assert "--init-slashing-db" in text
    assert "--metrics-address 127.0.0.1" in text
    assert "--metrics-address 0.0.0.0" in text
    assert "--no-healthcheck" in text
    assert "RVC_METRICS_ALLOW_NON_LOOPBACK" in text
    assert "State.Health" not in text
    assert "die_notready" in text
    assert "not implemented" not in text
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
    # P6-A13: inverted from Phase 3's "not implemented" stub. --docker is
    # accepted; usage-2 is --run-dir / missing inputs, never DN-15.
    proc = run_attach(
        tmp_path,
        ["--docker"],
        rvc=tmp_path / "missing-rvc",
        curl=tmp_path / "missing-curl",
        port=9,
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "unknown flag" not in proc.stderr
    assert "not implemented" not in proc.stderr
    assert "Phase 6" not in proc.stderr
    assert "DN-15" not in proc.stderr
    assert "--run-dir" in proc.stderr
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
    assert proc2.stdout == ""
    assert "unknown flag" not in proc2.stderr
    assert "not implemented" not in proc2.stderr
    assert "Phase 6" not in proc2.stderr
    assert "DN-15" not in proc2.stderr

    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    curl, _ = write_curl_stub(tmp_path)
    dry = run_attach(
        tmp_path,
        ["--run-dir", str(run_dir), "--docker", "--dry-run"],
        rvc=tmp_path / "missing-rvc",
        curl=curl,
        port=9,
    )
    assert dry.returncode == 0, dry.stderr
    assert dry.stdout == ""
    assert "unknown flag" not in dry.stderr
    assert "not implemented" not in dry.stderr
    assert "launch_rvc_docker" in dry.stderr
    assert "eth-devnet-rvc" in dry.stderr
    assert not (run_dir / "rvc.json").exists()
    assert_no_secrets(dry, data_dir)


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


def test_attach_omits_no_doppelganger_flag_under_safe(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    rvc, argv_log, _, pid_out = write_rvc_stub(tmp_path, mode="fail", port=port)
    run_dir = tmp_path / "run"
    try:
        proc_safe = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--profile", "safe", "--timeout", "4"],
            rvc=rvc,
            curl=curl,
            port=port,
        )
        assert proc_safe.returncode == 5, proc_safe.stderr
        argv_safe = argv_log.read_text(encoding="utf-8")
        assert " start " in f" {argv_safe} "
        assert "--init-slashing-db" in argv_safe
        assert "--no-doppelganger-detection" not in argv_safe
        assert_no_secrets(proc_safe, data_dir)

        argv_log.write_text("", encoding="utf-8")
        proc_fast = run_attach(
            tmp_path,
            [
                "--run-dir",
                str(run_dir),
                "--profile",
                "fast",
                "--force",
                "--timeout",
                "4",
            ],
            rvc=rvc,
            curl=curl,
            port=port,
        )
        assert proc_fast.returncode == 5, proc_fast.stderr
        argv_fast = argv_log.read_text(encoding="utf-8")
        assert " start " in f" {argv_fast} "
        assert "--init-slashing-db" in argv_fast
        assert "--no-doppelganger-detection" in argv_fast
        assert_no_secrets(proc_fast, data_dir)
    finally:
        if pid_out.is_file():
            raw = pid_out.read_text(encoding="utf-8").strip()
            if raw.isdigit():
                kill_pid(int(raw))


DOWN = Path(__file__).resolve().parents[1] / "devnet" / "down.sh"
_FAKE_CID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def write_docker_rvc_stub(
    tmp_path: Path,
    *,
    mode: str = "healthy",
    port: int,
) -> tuple[Path, Path, Path, Path]:
    log = tmp_path / "docker.log"
    inv_snap = tmp_path / "inv-at-docker-run.json"
    pid_out = tmp_path / "docker-stub.pid"
    state = tmp_path / "docker-state"
    state.mkdir(exist_ok=True)
    running = state / "running"
    allc = state / "all"
    cidf = state / "cid"
    running.write_text("", encoding="utf-8")
    allc.write_text("", encoding="utf-8")
    cidf.write_text(_FAKE_CID + "\n", encoding="utf-8")
    server_py = tmp_path / "docker-health.py"
    server_py.write_text(
        "#!/usr/bin/env python3\n"
        "import os, sys, time\n"
        "from http.server import BaseHTTPRequestHandler, HTTPServer\n"
        f"PORT = {int(port)}\n"
        f"PID_OUT = {str(pid_out)!r}\n"
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
        "    port = int(os.environ.get('RVC_METRICS_PORT') or PORT)\n"
        "    httpd = Server(('127.0.0.1', port), Handler)\n"
        "    with open(PID_OUT, 'w', encoding='utf-8') as fh:\n"
        "        fh.write(str(os.getpid()) + '\\n')\n"
        "    httpd.serve_forever()\n"
        "\n"
        "if __name__ == '__main__':\n"
        "    main()\n",
        encoding="utf-8",
    )
    server_py.chmod(0o755)
    stub = tmp_path / "docker"
    stub.write_text(
        "#!/bin/sh\n"
        f"log={shlex.quote(str(log))}\n"
        f"running={shlex.quote(str(running))}\n"
        f"all={shlex.quote(str(allc))}\n"
        f"cidf={shlex.quote(str(cidf))}\n"
        f"invsnap={shlex.quote(str(inv_snap))}\n"
        f"pidout={shlex.quote(str(pid_out))}\n"
        f"server={shlex.quote(str(server_py))}\n"
        f"mode={shlex.quote(mode)}\n"
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
        "kill_server() {\n"
        "  if [ -f \"$pidout\" ]; then\n"
        "    spid=$(tr -d '[:space:]' < \"$pidout\")\n"
        "    if [ -n \"$spid\" ]; then kill -KILL \"$spid\" 2>/dev/null || true; fi\n"
        "  fi\n"
        "}\n"
        "case \"$cmd\" in\n"
        "  image)\n"
        "    exit 0\n"
        "    ;;\n"
        "  ps)\n"
        "    allflag=0\n"
        "    for a in \"$@\"; do\n"
        "      if [ \"$a\" = \"-a\" ]; then allflag=1; fi\n"
        "    done\n"
        "    if [ \"$allflag\" -eq 1 ]; then cat \"$all\"; else cat \"$running\"; fi\n"
        "    exit 0\n"
        "    ;;\n"
        "  inspect)\n"
        "    fmt=\"\"\n"
        "    prev=\"\"\n"
        "    name=\"\"\n"
        "    for a in \"$@\"; do\n"
        "      if [ \"$prev\" = \"-f\" ] || [ \"$prev\" = \"--format\" ]; then fmt=\"$a\"; fi\n"
        "      case \"$a\" in\n"
        "        -f=*|--format=*) fmt=\"${a#*=}\" ;;\n"
        "        --|-f|--format) ;;\n"
        "        -*) ;;\n"
        "        *) name=\"$a\" ;;\n"
        "      esac\n"
        "      prev=\"$a\"\n"
        "    done\n"
        "    if ! grep -Fxq -- \"$name\" \"$all\" 2>/dev/null; then exit 1; fi\n"
        "    case \"$fmt\" in\n"
        "      '{{.Id}}'|\"{{.Id}}\") cat \"$cidf\"; exit 0 ;;\n"
        "      '{{.State.Pid}}'|\"{{.State.Pid}}\")\n"
        "        if [ -f \"$pidout\" ]; then cat \"$pidout\"; else printf '4242\\n'; fi\n"
        "        exit 0\n"
        "        ;;\n"
        "    esac\n"
        "    printf '%s\\n' '[]'\n"
        "    exit 0\n"
        "    ;;\n"
        "  run)\n"
        "    if [ -n \"${RUN_DIR:-}\" ] && [ -f \"$RUN_DIR/inventory.json\" ]; then\n"
        "      cp \"$RUN_DIR/inventory.json\" \"$invsnap\"\n"
        "    fi\n"
        "    name=\"\"\n"
        "    detached=0\n"
        "    prev=\"\"\n"
        "    for a in \"$@\"; do\n"
        "      if [ \"$prev\" = \"--name\" ]; then name=\"$a\"; fi\n"
        "      case \"$a\" in\n"
        "        --name=*) name=\"${a#--name=}\" ;;\n"
        "        -d|--detach) detached=1 ;;\n"
        "      esac\n"
        "      prev=\"$a\"\n"
        "    done\n"
        "    if [ \"$mode\" = \"fail\" ]; then exit 1; fi\n"
        "    if [ -n \"$name\" ]; then\n"
        "      printf '%s\\n' \"$name\" >> \"$all\"\n"
        "      if [ \"$detached\" -eq 1 ]; then printf '%s\\n' \"$name\" >> \"$running\"; fi\n"
        "    fi\n"
        "    if [ \"$mode\" != \"never\" ]; then\n"
        "      rm -f \"$pidout\"\n"
        "      nohup python3 \"$server\" >/dev/null 2>&1 &\n"
        "      i=0\n"
        "      while [ \"$i\" -lt 50 ]; do\n"
        "        if [ -f \"$pidout\" ]; then break; fi\n"
        "        i=$((i + 1))\n"
        "        sleep 0.05\n"
        "      done\n"
        "    fi\n"
        "    cat \"$cidf\"\n"
        "    exit 0\n"
        "    ;;\n"
        "  rm)\n"
        "    kill_server\n"
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
        "  logs)\n"
        "    printf 'rvc-docker-stub log\\n'\n"
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log, inv_snap, pid_out


def _kill_stub_pidfile(pid_out: Path) -> None:
    if not pid_out.is_file():
        return
    raw = pid_out.read_text(encoding="utf-8").strip()
    if raw.isdigit():
        kill_pid(int(raw))


def test_attach_sh_has_no_state_health():
    text = ATTACH.read_text(encoding="utf-8")
    assert text.count("State.Health") == 0


def test_attach_docker_inventory_precedes_run(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    docker, dlog, inv_snap, pid_out = write_docker_rvc_stub(
        tmp_path, mode="never", port=port
    )
    run_dir = tmp_path / "run"
    try:
        proc = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--docker", "--timeout", "4"],
            rvc=tmp_path / "unused-rvc",
            curl=curl,
            port=port,
            extra={"DOCKER": str(docker)},
        )
        assert proc.returncode == 5, proc.stderr
        assert not (run_dir / "rvc.json").exists()
        assert inv_snap.is_file(), proc.stderr
        snap_rows = inventory_rows(inv_snap)
        snap_kinds = {(r.get("kind"), r.get("name")) for r in snap_rows}
        assert ("container", "eth-devnet-rvc") in snap_kinds
        assert ("slashing_db", "slashing_protection.sqlite") in snap_kinds
        rows = inventory_rows(run_dir / "inventory.json")
        kinds = {(r.get("kind"), r.get("name")) for r in rows}
        assert ("container", "eth-devnet-rvc") in kinds
        argv = dlog.read_text(encoding="utf-8")
        run_lines = [
            ln
            for ln in argv.splitlines()
            if ln.startswith("run ") or ln.startswith("run\t")
        ]
        assert run_lines, argv
        run_argv = "\n".join(run_lines)
        assert "--no-healthcheck" in run_argv
        assert "RVC_METRICS_ALLOW_NON_LOOPBACK=true" in run_argv
        assert "--init-slashing-db" in run_argv
        assert "--metrics-address 0.0.0.0" in run_argv
        assert "-c /data/config.toml" in run_argv
        assert "eth-devnet-network" in run_argv
        assert "eth-devnet-rvc" in run_argv
        assert "rvc:latest" in run_argv
        assert f"127.0.0.1:{port}:8080" in run_argv
        assert re.search(r"(?:^|\s)-u\s+\d+:\d+(?:\s|$)", run_argv), run_argv
        assert f"-u {os.getuid()}:{os.getgid()}" in run_argv
        assert re.search(
            rf"(?:^|\s)-v\s+{re.escape(str(data_dir / 'rvc'))}:/data(?:\s|$)",
            run_argv,
        ), run_argv
        assert re.search(
            rf"(?:^|\s)-v\s+{re.escape(str(data_dir / 'keys' / 'rvc'))}"
            r":/data/keys/rvc(?:\s|$)",
            run_argv,
        ), run_argv
        assert "--metrics-address 127.0.0.1" not in run_argv
        assert "State.Health" not in argv
        assert_no_secrets(proc, data_dir)
        cfg = (data_dir / "rvc" / "config.toml").read_text(encoding="utf-8")
        assert 'beacon_url = "http://eth-devnet-beacon:5052"' in cfg
        assert 'keystore_path = "/data/keys/rvc"' in cfg
        assert 'password_file = "/data/passwords.txt"' in cfg
        assert 'slashing_db_path = "/data/slashing_protection.sqlite"' in cfg
        assert _GENESIS_GVR in cfg
    finally:
        _kill_stub_pidfile(pid_out)


def test_attach_docker_timeout_exits_5_and_writes_no_rvc_json(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    docker, _, _, pid_out = write_docker_rvc_stub(
        tmp_path, mode="never", port=port
    )
    run_dir = tmp_path / "run"
    try:
        proc = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--docker", "--timeout", "4"],
            rvc=tmp_path / "unused-rvc",
            curl=curl,
            port=port,
            extra={"DOCKER": str(docker)},
        )
        assert proc.returncode == 5, proc.stderr
        assert not (run_dir / "rvc.json").exists()
        copied = run_dir / "logs" / "rvc.log"
        assert copied.is_file(), proc.stderr
        assert_no_secrets(proc, data_dir)
    finally:
        _kill_stub_pidfile(pid_out)


def test_attach_docker_twice_is_noop(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    docker, dlog, _, pid_out = write_docker_rvc_stub(
        tmp_path, mode="healthy", port=port
    )
    run_dir = tmp_path / "run"
    args = ["--run-dir", str(run_dir), "--docker", "--timeout", "8"]
    try:
        first = run_attach(
            tmp_path,
            args,
            rvc=tmp_path / "unused-rvc",
            curl=curl,
            port=port,
            extra={"DOCKER": str(docker)},
        )
        assert first.returncode == 0, first.stderr
        assert_no_secrets(first, data_dir)
        rvc_json = run_dir / "rvc.json"
        assert rvc_json.is_file()
        first_doc = json.loads(rvc_json.read_text(encoding="utf-8"))
        assert first_doc["launch_mode"] == "docker"
        assert first_doc["container_id"] == _FAKE_CID
        first_runs = dlog.read_text(encoding="utf-8").count("\nrun ") + (
            1 if dlog.read_text(encoding="utf-8").startswith("run ") else 0
        )
        assert first_runs >= 1

        second = run_attach(
            tmp_path,
            args,
            rvc=tmp_path / "unused-rvc",
            curl=curl,
            port=port,
            extra={"DOCKER": str(docker)},
        )
        assert second.returncode == 0, second.stderr
        assert "already attached" in second.stderr
        second_doc = json.loads(rvc_json.read_text(encoding="utf-8"))
        assert second_doc == first_doc
        assert_no_secrets(second, data_dir)
        runs_after = dlog.read_text(encoding="utf-8").count("\nrun ") + (
            1 if dlog.read_text(encoding="utf-8").startswith("run ") else 0
        )
        assert runs_after == first_runs
    finally:
        _kill_stub_pidfile(pid_out)


def test_attach_docker_safe_omits_no_doppelganger_flag(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    docker, dlog, _, pid_out = write_docker_rvc_stub(
        tmp_path, mode="never", port=port
    )
    run_dir = tmp_path / "run"
    try:
        proc_safe = run_attach(
            tmp_path,
            [
                "--run-dir",
                str(run_dir),
                "--docker",
                "--profile",
                "safe",
                "--timeout",
                "4",
            ],
            rvc=tmp_path / "unused-rvc",
            curl=curl,
            port=port,
            extra={"DOCKER": str(docker)},
        )
        assert proc_safe.returncode == 5, proc_safe.stderr
        argv_safe = dlog.read_text(encoding="utf-8")
        assert "--init-slashing-db" in argv_safe
        assert "--no-doppelganger-detection" not in argv_safe
        assert_no_secrets(proc_safe, data_dir)

        dlog.write_text("", encoding="utf-8")
        proc_fast = run_attach(
            tmp_path,
            [
                "--run-dir",
                str(run_dir),
                "--docker",
                "--profile",
                "fast",
                "--force",
                "--timeout",
                "4",
            ],
            rvc=tmp_path / "unused-rvc",
            curl=curl,
            port=port,
            extra={"DOCKER": str(docker)},
        )
        assert proc_fast.returncode == 5, proc_fast.stderr
        argv_fast = dlog.read_text(encoding="utf-8")
        assert "--init-slashing-db" in argv_fast
        assert "--no-doppelganger-detection" in argv_fast
        assert_no_secrets(proc_fast, data_dir)
    finally:
        _kill_stub_pidfile(pid_out)


def test_attach_docker_down_can_remove_container(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    db = data_dir / "rvc" / "slashing_protection.sqlite"
    write_slashing_db(db, _GENESIS_GVR)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    docker, dlog, _, pid_out = write_docker_rvc_stub(
        tmp_path, mode="never", port=port
    )
    run_dir = tmp_path / "run"
    try:
        proc = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--docker", "--timeout", "4"],
            rvc=tmp_path / "unused-rvc",
            curl=curl,
            port=port,
            extra={"DOCKER": str(docker)},
        )
        assert proc.returncode == 5, proc.stderr
        assert not (run_dir / "rvc.json").exists()
        rows = inventory_rows(run_dir / "inventory.json")
        assert any(
            r.get("kind") == "container" and r.get("name") == "eth-devnet-rvc"
            for r in rows
        )
        env = attach_env(
            tmp_path,
            rvc=tmp_path / "unused-rvc",
            curl=curl,
            port=port,
            extra={"DOCKER": str(docker), "PURGE_DATA": "1"},
        )
        down = subprocess.run(
            ["bash", str(DOWN), "--run-dir", str(run_dir), "--data"],
            capture_output=True,
            text=True,
            env=env,
            timeout=20,
            stdin=subprocess.DEVNULL,
        )
        assert down.returncode == 0, down.stderr
        cmds = [
            line
            for line in dlog.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert any("rm " in c and "eth-devnet-rvc" in c for c in cmds), cmds
        assert not db.exists()
        assert not data_dir.exists()
        assert_no_secrets(proc, data_dir)
    finally:
        _kill_stub_pidfile(pid_out)


def test_attach_native_noops_when_docker_healthy(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    docker, dlog, _, pid_out = write_docker_rvc_stub(
        tmp_path, mode="healthy", port=port
    )
    rvc, _, _, rvc_pid_out = write_rvc_stub(tmp_path, mode="healthy", port=port)
    run_dir = tmp_path / "run"
    extra = {"DOCKER": str(docker)}
    try:
        first = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--docker", "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
            extra=extra,
        )
        assert first.returncode == 0, first.stderr
        runs_before = sum(
            1 for ln in dlog.read_text(encoding="utf-8").splitlines() if ln.startswith("run ")
        )
        second = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
            extra=extra,
        )
        assert second.returncode == 0, second.stderr
        assert "already attached" in second.stderr
        runs_after = sum(
            1 for ln in dlog.read_text(encoding="utf-8").splitlines() if ln.startswith("run ")
        )
        assert runs_after == runs_before
        assert_no_secrets(second, data_dir)
    finally:
        _kill_stub_pidfile(pid_out)
        _kill_stub_pidfile(rvc_pid_out)


def test_attach_docker_noops_when_native_healthy(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    docker, dlog, _, pid_out = write_docker_rvc_stub(
        tmp_path, mode="healthy", port=port
    )
    rvc, _, _, rvc_pid_out = write_rvc_stub(tmp_path, mode="healthy", port=port)
    run_dir = tmp_path / "run"
    extra = {"DOCKER": str(docker)}
    live: list[int] = []
    try:
        first = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
            extra=extra,
        )
        assert first.returncode == 0, first.stderr
        native_pid = read_pidfile(data_dir)
        assert native_pid is not None
        live.append(native_pid)
        runs_before = sum(
            1 for ln in dlog.read_text(encoding="utf-8").splitlines() if ln.startswith("run ")
        )
        second = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--docker", "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
            extra=extra,
        )
        assert second.returncode == 0, second.stderr
        assert "already attached" in second.stderr
        assert read_pidfile(data_dir) == native_pid
        assert pid_alive(native_pid)
        runs_after = sum(
            1 for ln in dlog.read_text(encoding="utf-8").splitlines() if ln.startswith("run ")
        )
        assert runs_after == runs_before
        assert_no_secrets(second, data_dir)
    finally:
        for pid in live:
            kill_pid(pid)
        _kill_stub_pidfile(pid_out)
        _kill_stub_pidfile(rvc_pid_out)


def test_attach_force_native_removes_docker_container(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    docker, dlog, _, pid_out = write_docker_rvc_stub(
        tmp_path, mode="healthy", port=port
    )
    rvc, _, _, rvc_pid_out = write_rvc_stub(tmp_path, mode="healthy", port=port)
    run_dir = tmp_path / "run"
    extra = {"DOCKER": str(docker)}
    live: list[int] = []
    try:
        first = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--docker", "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
            extra=extra,
        )
        assert first.returncode == 0, first.stderr
        forced = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--force", "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
            extra=extra,
        )
        assert forced.returncode == 0, forced.stderr
        cmds = dlog.read_text(encoding="utf-8").splitlines()
        assert any("rm " in c and "eth-devnet-rvc" in c for c in cmds), cmds
        new_pid = read_pidfile(data_dir)
        assert new_pid is not None
        live.append(new_pid)
        assert pid_alive(new_pid)
        assert_no_secrets(forced, data_dir)
    finally:
        for pid in live:
            kill_pid(pid)
        _kill_stub_pidfile(pid_out)
        _kill_stub_pidfile(rvc_pid_out)


def test_attach_force_docker_kills_native_pid(tmp_path: Path):
    data_dir = tmp_path / "data"
    plant_attach_tree(data_dir)
    port = free_port()
    curl, _ = write_curl_stub(tmp_path)
    docker, dlog, _, pid_out = write_docker_rvc_stub(
        tmp_path, mode="healthy", port=port
    )
    rvc, _, _, rvc_pid_out = write_rvc_stub(tmp_path, mode="healthy", port=port)
    run_dir = tmp_path / "run"
    extra = {"DOCKER": str(docker)}
    native_pid = None
    try:
        first = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
            extra=extra,
        )
        assert first.returncode == 0, first.stderr
        native_pid = read_pidfile(data_dir)
        assert native_pid is not None
        assert pid_alive(native_pid)
        forced = run_attach(
            tmp_path,
            ["--run-dir", str(run_dir), "--docker", "--force", "--timeout", "8"],
            rvc=rvc,
            curl=curl,
            port=port,
            extra=extra,
        )
        assert forced.returncode == 0, forced.stderr
        assert "killing rvc pid" in forced.stderr
        assert not pid_alive(native_pid)
        doc = json.loads((run_dir / "rvc.json").read_text(encoding="utf-8"))
        assert doc["launch_mode"] == "docker"
        assert any(
            ln.startswith("run ") for ln in dlog.read_text(encoding="utf-8").splitlines()
        )
        assert_no_secrets(forced, data_dir)
    finally:
        if native_pid is not None:
            kill_pid(native_pid)
        _kill_stub_pidfile(pid_out)
        _kill_stub_pidfile(rvc_pid_out)
