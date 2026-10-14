"""Docker-free contract tests for scripts/devnet/02-keys.sh (issue 2.3).

PATH docker shim exits non-zero; disable_socket() via conftest autouse.
No --force: that regenerates keystores and needs docker (K-A5/K-A8).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
from pathlib import Path

from test_devnet_env import ENV_PATH, parse_env

# conftest.SCRIPT/load_script are validator_perf.py-specific.
SCRIPT = Path(__file__).resolve().parent
KEYS = SCRIPT.parent / "devnet" / "02-keys.sh"

_ENV = parse_env(ENV_PATH)
_N = int(_ENV["NUM_VALIDATORS"])
_K = int(_ENV["RVC_KEYS"])
_MNEMONIC = _ENV["MNEMONIC"]

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
)

_GOOD_CONFIG = (
    "PRESET_BASE: 'mainnet'\n"
    "SLOT_DURATION_MS: 12000\n"
    "ELECTRA_FORK_EPOCH: 0\n"
)


def pubkey(i: int) -> str:
    return f"0x{i:096x}"


def normalize_pubkey(pk: str) -> str:
    return pk.lower().removeprefix("0x")


def keystore_body(pk: str) -> str:
    bare = normalize_pubkey(pk)
    doc = {
        "crypto": {
            "kdf": {
                "function": "pbkdf2",
                "params": {
                    "c": 262144,
                    "dklen": 32,
                    "prf": "hmac-sha256",
                    "salt": "aa",
                },
            }
        },
        "pubkey": bare,
        "version": 4,
    }
    return json.dumps(doc, separators=(",", ":")) + "\n"


def file_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def assert_socket_disabled() -> None:
    # pytest-socket replaces socket.socket; do not construct (that warns).
    assert "pytest_socket" in getattr(socket.socket, "__module__", "")


def write_docker_shim(tmp_path: Path) -> tuple[Path, Path]:
    shim_dir = tmp_path / "shim-bin"
    shim_dir.mkdir(exist_ok=True)
    log = tmp_path / "docker.log"
    docker = shim_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "exit 1\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    return shim_dir, log


def keys_env(tmp_path: Path, shim_dir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full["DOCKER"] = "docker"
    full["CURL"] = "/bin/echo"
    full["RUNS_DIR"] = str(tmp_path / "runs")
    full["PATH"] = str(shim_dir) + os.pathsep + full.get(
        "PATH", os.environ.get("PATH", "")
    )
    if extra:
        full.update(extra)
    return full


def plant_genesis(data_root: Path) -> None:
    genesis = data_root / "genesis"
    genesis.mkdir(parents=True, exist_ok=True)
    (genesis / "config.yaml").write_text(_GOOD_CONFIG, encoding="utf-8")
    (genesis / "genesis.json").write_text("{}\n", encoding="utf-8")
    (genesis / "genesis.ssz").write_bytes(b"ssz")


def plant_valtools(data_root: Path, n: int | None = None) -> Path:
    n = _N if n is None else n
    valtools = data_root / "keys" / "valtools"
    validators = valtools / "validators"
    secrets = valtools / "secrets"
    validators.mkdir(parents=True, exist_ok=True)
    secrets.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        pk = pubkey(i)
        d = validators / pk
        d.mkdir(exist_ok=True)
        ks = d / "voting-keystore.json"
        ks.write_text(keystore_body(pk), encoding="utf-8")
        ks.chmod(0o600)
        sec = secrets / pk
        sec.write_text(f"secret-{i}\n", encoding="utf-8")
        sec.chmod(0o600)
    return valtools


def plant_manifest(data_root: Path, n: int | None = None) -> Path:
    n = _N if n is None else n
    pubkeys = [pubkey(i) for i in range(n)]
    doc = {
        "schema_version": 1,
        "generated_at": "2026-09-12T00:00:00Z",
        "validators": [
            {
                "index": i,
                "pubkey": pk,
                "keystore_path": (
                    f"valtools/validators/{pk}/voting-keystore.json"
                ),
            }
            for i, pk in enumerate(pubkeys)
        ],
    }
    path = data_root / "keys" / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


def seed_synthetic_tree(data_root: Path) -> None:
    data_root.chmod(0o700)
    plant_genesis(data_root)
    plant_valtools(data_root)
    plant_manifest(data_root)


def load_manifest(data_root: Path) -> dict:
    return json.loads((data_root / "keys" / "manifest.json").read_text(encoding="utf-8"))


def rvc_keystore_files(data_root: Path) -> list[Path]:
    rvc = data_root / "keys" / "rvc"
    if not rvc.is_dir():
        return []
    return sorted(
        p
        for p in rvc.glob("keystore-0x*.json")
        if re.fullmatch(r"keystore-0x[0-9a-f]{96}\.json", p.name)
    )


def vc_validator_dirs(data_root: Path) -> list[Path]:
    vc = data_root / "keys" / "vc" / "validators"
    if not vc.is_dir():
        return []
    return sorted(p for p in vc.glob("0x*") if p.is_dir())


def vc_pubkeys(data_root: Path) -> set[str]:
    return {p.name.lower() for p in vc_validator_dirs(data_root)}


def rvc_pubkeys(data_root: Path) -> set[str]:
    found: set[str] = set()
    for path in rvc_keystore_files(data_root):
        match = re.fullmatch(r"keystore-(0x[0-9a-f]{96})\.json", path.name)
        assert match, path.name
        found.add(match.group(1))
    return found


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob


def assert_no_password(
    proc: subprocess.CompletedProcess[str], data_root: Path
) -> None:
    blob = proc.stdout + proc.stderr
    pw_path = data_root / "keys" / "rvc" / "passwords.txt"
    if not pw_path.is_file():
        return
    for line in pw_path.read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        password = line.split("=", 1)[1]
        if password:
            assert password not in blob


def assert_no_docker(log: Path) -> None:
    assert (not log.exists()) or log.read_text(encoding="utf-8") == ""


def run_keys_docker_free(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    seed: bool = True,
    timeout: float = 20,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    if any(a == "--force" or str(a).startswith("--force=") for a in args):
        raise AssertionError("docker-free suite must not pass --force")
    data_root = tmp_path
    data_root.chmod(0o700)
    if seed:
        seed_synthetic_tree(data_root)
    shim_dir, log = write_docker_shim(tmp_path)
    full = keys_env(tmp_path, shim_dir)
    proc = subprocess.run(
        ["bash", str(KEYS), "--data-dir", str(data_root), *args],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return proc, log


def test_keys_script_syntax():
    assert KEYS.is_file(), KEYS
    assert KEYS == SCRIPT.parent / "devnet" / "02-keys.sh"
    assert bool(KEYS.stat().st_mode & stat.S_IXUSR)
    proc = subprocess.run(
        ["bash", "-n", str(KEYS)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = KEYS.read_text(encoding="utf-8")
    assert re.search(r"(?m)^\s*read\s", text) is None
    assert "split_keys()" in text
    assert "assert_disjoint_keysets()" in text
    assert_socket_disabled()


def test_vc_and_rvc_pubkey_sets_are_disjoint(tmp_path: Path):
    proc, log = run_keys_docker_free(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert_no_docker(log)
    assert_no_secret(proc)
    assert_no_password(proc, tmp_path)
    man = load_manifest(tmp_path)
    rows = man["validators"]
    assert len(rows) == _N
    vc = vc_pubkeys(tmp_path)
    rvc = rvc_pubkeys(tmp_path)
    manifest = {row["pubkey"].lower() for row in rows}
    assert len(vc) == _N - _K
    assert len(rvc) == _K
    assert vc.isdisjoint(rvc)
    assert vc | rvc == manifest


def test_rvc_set_equals_manifest_tail(tmp_path: Path):
    proc, log = run_keys_docker_free(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert_no_docker(log)
    man = load_manifest(tmp_path)
    rows = man["validators"]
    tail = {row["pubkey"].lower() for row in rows[_N - _K :]}
    head = {row["pubkey"].lower() for row in rows[: _N - _K]}
    rvc = rvc_pubkeys(tmp_path)
    vc = vc_pubkeys(tmp_path)
    assert rvc == tail
    assert vc == head
    assert rvc != head
    swapped = {row["pubkey"].lower() for row in rows[:_K]}
    assert rvc != swapped


def test_rvc_dir_holds_exactly_k_keystores(tmp_path: Path):
    proc, log = run_keys_docker_free(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert_no_docker(log)
    files = rvc_keystore_files(tmp_path)
    assert len(files) == _K
    rvc = tmp_path / "keys" / "rvc"
    extras = [
        p
        for p in rvc.iterdir()
        if p.is_file()
        and p.name not in {"passwords.txt", "pubkeys.txt"}
        and not re.fullmatch(r"keystore-0x[0-9a-f]{96}\.json", p.name)
    ]
    assert extras == []
    for path in files:
        assert not path.is_symlink()
        assert file_mode(path) == 0o600
        body = json.loads(path.read_text(encoding="utf-8"))
        assert "kdf" in body["crypto"]
        bare = body["pubkey"].lower().removeprefix("0x")
        assert path.name == f"keystore-0x{bare}.json"


def test_passwords_and_pubkeys_files_match_keystores(tmp_path: Path):
    proc, log = run_keys_docker_free(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert_no_docker(log)
    assert_no_password(proc, tmp_path)
    rvc = tmp_path / "keys" / "rvc"
    pw_path = rvc / "passwords.txt"
    pub_path = rvc / "pubkeys.txt"
    assert pw_path.is_file()
    assert pub_path.is_file()
    assert file_mode(pw_path) == 0o600
    found = subprocess.run(
        ["find", str(pw_path), "-perm", "600"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert found.returncode == 0
    assert str(pw_path) in found.stdout
    pw_lines = [ln for ln in pw_path.read_text(encoding="utf-8").splitlines() if ln]
    assert len(pw_lines) == _K
    pw_keys: list[str] = []
    files = {p.name: p for p in rvc_keystore_files(tmp_path)}
    for line in pw_lines:
        assert "=" in line
        key, value = line.split("=", 1)
        assert key != "*"
        assert value
        norm = normalize_pubkey(key)
        pw_keys.append(norm)
        ks = files.get(f"keystore-0x{norm}.json")
        assert ks is not None, key
        ks_pk = normalize_pubkey(
            json.loads(ks.read_text(encoding="utf-8"))["pubkey"]
        )
        assert norm == ks_pk
        secret = tmp_path / "keys" / "valtools" / "secrets" / f"0x{ks_pk}"
        assert value == secret.read_text(encoding="utf-8").rstrip("\n")
    assert len(set(pw_keys)) == _K
    pub_lines = [ln for ln in pub_path.read_text(encoding="utf-8").splitlines() if ln]
    assert len(pub_lines) == _K
    for line in pub_lines:
        assert re.fullmatch(r"0x[0-9a-f]{96}", line), line
    assert {normalize_pubkey(pk) for pk in pub_lines} == set(pw_keys)
    assert set(pub_lines) == rvc_pubkeys(tmp_path)


def test_missing_subset_is_repaired_without_force(tmp_path: Path):
    proc1, log = run_keys_docker_free(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    assert_no_docker(log)
    rvc = tmp_path / "keys" / "rvc"
    vc = tmp_path / "keys" / "vc"
    pw_body = (rvc / "passwords.txt").read_text(encoding="utf-8")
    pub_body = (rvc / "pubkeys.txt").read_text(encoding="utf-8")
    sample = next(
        (tmp_path / "keys" / "valtools" / "validators").glob("0x*")
    ) / "voting-keystore.json"
    mtime = sample.stat().st_mtime
    shutil.rmtree(rvc)
    proc2, _ = run_keys_docker_free(tmp_path, seed=False)
    assert proc2.returncode == 0, proc2.stderr
    assert_no_docker(log)
    assert_no_secret(proc2)
    assert_no_password(proc2, tmp_path)
    assert sample.stat().st_mtime == mtime
    assert rvc.is_dir()
    assert (rvc / "passwords.txt").read_text(encoding="utf-8") == pw_body
    assert (rvc / "pubkeys.txt").read_text(encoding="utf-8") == pub_body
    assert len(rvc_keystore_files(tmp_path)) == _K
    shutil.rmtree(vc)
    proc3, _ = run_keys_docker_free(tmp_path, seed=False)
    assert proc3.returncode == 0, proc3.stderr
    assert_no_docker(log)
    assert len(vc_validator_dirs(tmp_path)) == _N - _K
    assert vc_pubkeys(tmp_path).isdisjoint(rvc_pubkeys(tmp_path))
    assert "skipping manifest.json" in proc2.stderr
    assert "already present" in proc2.stderr
    assert "--force" not in proc2.args


def test_overlapping_pubkeys_exit_1(tmp_path: Path):
    proc1, log = run_keys_docker_free(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    assert_no_docker(log)
    vc_dirs = vc_validator_dirs(tmp_path)
    rvc_files = rvc_keystore_files(tmp_path)
    assert vc_dirs and rvc_files
    victim = vc_dirs[0]
    injected = rvc_files[0]
    match = re.fullmatch(r"keystore-(0x[0-9a-f]{96})\.json", injected.name)
    assert match
    rvc_pk = match.group(1)
    secrets = tmp_path / "keys" / "vc" / "secrets"
    (secrets / victim.name).unlink()
    shutil.rmtree(victim)
    dest = tmp_path / "keys" / "vc" / "validators" / rvc_pk
    dest.mkdir()
    shutil.copy2(injected, dest / "voting-keystore.json")
    src_secret = tmp_path / "keys" / "valtools" / "secrets" / rvc_pk
    shutil.copy2(src_secret, secrets / rvc_pk)
    assert len(vc_validator_dirs(tmp_path)) == _N - _K
    assert len(rvc_keystore_files(tmp_path)) == _K
    assert rvc_pk in vc_pubkeys(tmp_path)
    proc2, _ = run_keys_docker_free(tmp_path, seed=False)
    assert proc2.returncode == 1, proc2.stderr
    assert proc2.stdout == ""
    assert_no_docker(log)
    assert_no_secret(proc2)
    err = proc2.stderr.lower()
    assert "intersect" in err or "overlap" in err
    assert str(_N - _K) in proc2.stderr
    assert str(_K) in proc2.stderr
