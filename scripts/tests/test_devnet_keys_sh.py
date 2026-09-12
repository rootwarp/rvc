"""Contract tests for scripts/devnet/02-keys.sh.

DOCKER stubs are scratch scripts (P1-A8); disable_socket() via conftest autouse.
Live val-tools run is skipped unless the pinned IMG_GENESIS is already present.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from test_devnet_env import ENV_PATH, parse_env

KEYS = Path(__file__).resolve().parents[1] / "devnet" / "02-keys.sh"

_ENV = parse_env(ENV_PATH)
_N = int(_ENV["NUM_VALIDATORS"])
_MNEMONIC = _ENV["MNEMONIC"]
_IMG = _ENV["IMG_GENESIS"]

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

_UNUSED_TREES = (
    "nimbus-keys",
    "teku-keys",
    "teku-secrets",
    "lodestar-secrets",
    "prysm",
)

_GOOD_CONFIG = (
    "PRESET_BASE: 'mainnet'\n"
    "SLOT_DURATION_MS: 12000\n"
    "ELECTRA_FORK_EPOCH: 0\n"
)


def pubkey(i: int) -> str:
    return f"0x{i:096x}"


def keystore_body(*, c: int | None = 262144, missing_c: bool = False) -> str:
    if missing_c:
        return '{"crypto":{"kdf":{"params":{}}}}\n'
    return (
        '{"crypto":{"kdf":{"function":"pbkdf2","params":{"c":'
        + str(c)
        + ',"dklen":32,"prf":"hmac-sha256","salt":"aa"}}},"version":4}\n'
    )


def write_docker_stub(
    tmp_path: Path,
    *,
    fail_run: bool = False,
    n_keys: int | None = None,
) -> tuple[Path, Path]:
    log = tmp_path / "docker.log"
    if n_keys is None:
        n_assign = 'n="$source_max"\n'
    else:
        n_assign = f"n={int(n_keys)}\n"
    stub = tmp_path / "docker"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "cmd=\"$1\"\n"
        "shift || true\n"
        "case \"$cmd\" in\n"
        "  run)\n"
        f"    if [ {1 if fail_run else 0} -ne 0 ]; then\n"
        "      printf 'using mnemonic: fail-path\\n' >&2\n"
        "      exit 1\n"
        "    fi\n"
        "    host=\"\"\n"
        "    mnemonic=\"\"\n"
        "    source_max=\"\"\n"
        "    prev=\"\"\n"
        "    for arg in \"$@\"; do\n"
        "      case \"$prev\" in\n"
        "        --source-mnemonic) mnemonic=\"$arg\" ;;\n"
        "        --source-max) source_max=\"$arg\" ;;\n"
        "      esac\n"
        "      case \"$arg\" in\n"
        "        *:/data/keys)\n"
        "          host=\"${arg%:/data/keys}\"\n"
        "          ;;\n"
        "      esac\n"
        "      prev=\"$arg\"\n"
        "    done\n"
        f"    {n_assign}"
        "    if [ -z \"$host\" ] || [ -z \"$n\" ]; then\n"
        "      exit 1\n"
        "    fi\n"
        "    out=\"$host/valtools\"\n"
        "    if [ -e \"$out\" ]; then\n"
        "      printf 'output for assignments already exists\\n' >&2\n"
        "      exit 1\n"
        "    fi\n"
        "    mkdir -p \"$out/keys\" \"$out/secrets\" \"$out/nimbus-keys\" \\\n"
        "      \"$out/teku-keys\" \"$out/teku-secrets\" \"$out/lodestar-secrets\" \\\n"
        "      \"$out/prysm/direct/accounts\"\n"
        "    i=0\n"
        "    while [ \"$i\" -lt \"$n\" ]; do\n"
        "      pk=$(printf '0x%096x' \"$i\")\n"
        "      mkdir -p \"$out/keys/$pk\" \"$out/nimbus-keys/$pk\"\n"
        "      printf '%s\\n' "
        "'{\"crypto\":{\"kdf\":{\"params\":{\"c\":262144}}}}' "
        "> \"$out/keys/$pk/voting-keystore.json\"\n"
        "      printf 'secret-%s\\n' \"$pk\" > \"$out/secrets/$pk\"\n"
        "      chmod 644 \"$out/keys/$pk/voting-keystore.json\" \"$out/secrets/$pk\"\n"
        "      printf 'nimbus\\n' > \"$out/nimbus-keys/$pk/keystore.json\"\n"
        "      printf 'teku\\n' > \"$out/teku-keys/${pk}.json\"\n"
        "      printf 'teku-secret\\n' > \"$out/teku-secrets/${pk}.txt\"\n"
        "      printf 'lodestar\\n' > \"$out/lodestar-secrets/$pk\"\n"
        "      i=$((i + 1))\n"
        "    done\n"
        "    printf '[]\\n' > \"$out/pubkeys.json\"\n"
        "    printf '{}\\n' > \"$out/prysm/direct/accounts/all-accounts.keystore.json\"\n"
        "    chmod 644 \"$out/prysm/direct/accounts/all-accounts.keystore.json\"\n"
        "    if [ -n \"$mnemonic\" ]; then\n"
        "      printf 'using mnemonic: %s\\n' \"$mnemonic\" >&2\n"
        "    fi\n"
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def keys_env(
    tmp_path: Path,
    extra: dict[str, str] | None = None,
    *,
    docker: Path | None = None,
) -> dict[str, str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full["DOCKER"] = str(docker or (tmp_path / "docker"))
    full["CURL"] = "/bin/echo"
    full["DATA_DIR"] = str(tmp_path / "data")
    full["RUNS_DIR"] = str(tmp_path / "runs")
    if extra:
        full.update(extra)
    return full


def plant_genesis(tmp_path: Path) -> Path:
    genesis = tmp_path / "data" / "genesis"
    genesis.mkdir(parents=True, exist_ok=True)
    cfg = genesis / "config.yaml"
    if not cfg.exists():
        cfg.write_text(_GOOD_CONFIG, encoding="utf-8")
    return cfg


def plant_keystores(
    tmp_path: Path,
    n: int | None = None,
    *,
    c: int | None = 262144,
    missing_c: bool = False,
    empty_body: bool = False,
    symlink: bool = False,
    secret_mode: int = 0o600,
) -> Path:
    n = _N if n is None else n
    valtools = tmp_path / "data" / "keys" / "valtools"
    validators = valtools / "validators"
    secrets = valtools / "secrets"
    validators.mkdir(parents=True, exist_ok=True)
    secrets.mkdir(parents=True, exist_ok=True)
    victim = tmp_path / "victim-keystore.json"
    body = "" if empty_body else keystore_body(c=c, missing_c=missing_c)
    if symlink:
        victim.write_text(body or keystore_body(c=2), encoding="utf-8")
    for i in range(n):
        pk = pubkey(i)
        d = validators / pk
        d.mkdir(exist_ok=True)
        dest = d / "voting-keystore.json"
        if symlink:
            dest.symlink_to(victim)
        elif empty_body:
            dest.write_bytes(b"")
        else:
            dest.write_text(body, encoding="utf-8")
        sec = secrets / pk
        sec.write_text(f"secret-{i}\n", encoding="utf-8")
        sec.chmod(secret_mode)
    return valtools


def run_keys(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    env: dict[str, str] | None = None,
    fail_run: bool = False,
    n_keys: int | None = None,
    timeout: float = 20,
    docker: Path | None = None,
    log: Path | None = None,
    plant_config: bool = True,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    if docker is None:
        stub, log_path = write_docker_stub(
            tmp_path, fail_run=fail_run, n_keys=n_keys
        )
    else:
        stub = docker
        log_path = log or (tmp_path / "docker.log")
    if plant_config:
        plant_genesis(tmp_path)
    full = keys_env(tmp_path, env, docker=stub)
    proc = subprocess.run(
        ["bash", str(KEYS), *args],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return proc, log_path


def source_keys(
    tmp_path: Path,
    snippet: str,
    *,
    env: dict[str, str] | None = None,
    timeout: float = 10,
) -> subprocess.CompletedProcess[str]:
    stub, _ = write_docker_stub(tmp_path)
    plant_genesis(tmp_path)
    full = keys_env(tmp_path, env, docker=stub)
    return subprocess.run(
        ["bash", "-c", f"source {shlex.quote(str(KEYS))}; {snippet}"],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


def stub_cmds(log: Path) -> list[str]:
    if not log.is_file():
        return []
    return [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


def run_cmds(cmds: list[str]) -> list[str]:
    return [c for c in cmds if c.startswith("run ")]


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob


def file_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def validator_dirs(tmp_path: Path) -> list[Path]:
    root = tmp_path / "data" / "keys" / "valtools" / "validators"
    if not root.is_dir():
        return []
    return sorted(p for p in root.glob("0x*") if p.is_dir())


def _live_genesis_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    img = parse_env(ENV_PATH).get("IMG_GENESIS", "")
    if not img:
        return False
    info = subprocess.run(
        [docker, "info"],
        capture_output=True,
        timeout=15,
        stdin=subprocess.DEVNULL,
    )
    if info.returncode != 0:
        return False
    inspect = subprocess.run(
        [docker, "image", "inspect", "--", img],
        capture_output=True,
        timeout=15,
        stdin=subprocess.DEVNULL,
    )
    return inspect.returncode == 0


def test_keys_sh_exists_and_syntax():
    assert KEYS.is_file(), KEYS
    assert bool(KEYS.stat().st_mode & stat.S_IXUSR)
    proc = subprocess.run(
        ["bash", "-n", str(KEYS)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = KEYS.read_text(encoding="utf-8")
    assert re.search(r"(?m)^\s*read\s", text) is None
    assert "read -p" not in text
    assert "read -r" not in text
    assert "source" in text and "lib/common.sh" in text
    assert "docker_run_as_user" in text
    assert "generate_keystores()" in text
    assert "assert_key_count()" in text
    assert "assert_kdf_strength()" in text
    assert "keys_exist()" in text
    assert "--insecure" not in text
    assert "NUM_VALIDATORS-1" not in text
    assert "$((NUM_VALIDATORS" not in text
    assert "manifest.json" not in text
    assert "/rvc/" not in text
    assert "passwords.txt" not in text
    assert "--entrypoint" in text
    assert "/usr/local/bin/eth2-val-tools" in text
    assert "--source-max" in text
    assert '"$NUM_VALIDATORS"' in text
    assert "/data/keys/valtools" in text
    assert "${KEYS_DIR}:/data/keys" in text
    assert re.search(r"(?m)^\s*docker\s", text) is None
    counted = subprocess.run(
        ["grep", "-rc", "--", "--insecure", str(KEYS)],
        capture_output=True,
        text=True,
    )
    assert counted.stdout.strip().endswith(":0") or counted.returncode == 1


def test_stub_generate_writes_n_validator_dirs(tmp_path: Path):
    jwt = tmp_path / "data" / "jwt" / "jwt.hex"
    jwt.parent.mkdir(parents=True)
    jwt.write_text("ab" * 32, encoding="utf-8")
    jwt.chmod(0o600)
    jwt_body = jwt.read_text(encoding="utf-8")
    proc, log = run_keys(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    assert proc.stdout == ""
    dirs = validator_dirs(tmp_path)
    assert len(dirs) == _N
    keys_dir = tmp_path / "data" / "keys"
    valtools = keys_dir / "valtools"
    secrets = valtools / "secrets"
    assert keys_dir.is_dir()
    assert not keys_dir.is_symlink()
    assert keys_dir.stat().st_uid == os.getuid()
    assert file_mode(keys_dir) == 0o700
    assert file_mode(valtools) == 0o700
    for d in dirs:
        ks = d / "voting-keystore.json"
        assert ks.is_file()
        assert not ks.is_symlink()
        assert file_mode(ks) == 0o600
        sec = secrets / d.name
        assert sec.is_file()
        assert not sec.is_symlink()
        assert file_mode(sec) == 0o600
        assert stat.filemode(sec.stat().st_mode) == "-rw-------"
    for name in _UNUSED_TREES:
        assert not (valtools / name).exists(), name
    assert (valtools / "pubkeys.json").is_file()
    assert not (keys_dir / "vc").exists()
    assert not (keys_dir / "rvc").exists()
    assert not (keys_dir / "manifest.json").exists()
    assert not (keys_dir / "passwords.txt").exists()
    assert jwt.read_text(encoding="utf-8") == jwt_body
    cmds = run_cmds(stub_cmds(log))
    assert len(cmds) == 1
    argv = cmds[0]
    uid = os.getuid()
    gid = os.getgid()
    assert f"run -u {uid}:{gid}" in argv
    assert "--rm" in argv
    assert f"{keys_dir}:/data/keys" in argv
    assert f"{tmp_path / 'data'}:/data" not in argv
    assert "/jwt" not in argv
    assert "--entrypoint /usr/local/bin/eth2-val-tools" in argv
    assert _IMG in argv
    assert " keystores " in argv
    assert "--source-min 0" in argv
    assert f"--source-max {_N}" in argv
    assert f"--source-max {_N - 1}" not in argv
    assert "--out-loc /data/keys/valtools" in argv
    assert "--insecure" not in argv
    vlog = keys_dir / "valtools.log"
    assert vlog.is_file()
    assert file_mode(vlog) == 0o600
    log_text = vlog.read_text(encoding="utf-8")
    assert _MNEMONIC not in log_text
    assert "<redacted>" in log_text


def test_second_run_is_noop_without_force(tmp_path: Path):
    proc1, log = run_keys(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    sample = validator_dirs(tmp_path)[0] / "voting-keystore.json"
    body = sample.read_text(encoding="utf-8")
    mtime = sample.stat().st_mtime
    first_runs = len(run_cmds(stub_cmds(log)))
    proc2, _ = run_keys(tmp_path, docker=tmp_path / "docker", log=log)
    assert proc2.returncode == 0, proc2.stderr
    assert_no_secret(proc2)
    assert sample.read_text(encoding="utf-8") == body
    assert sample.stat().st_mtime == mtime
    assert len(run_cmds(stub_cmds(log))) == first_runs
    assert "already present" in proc2.stderr


def test_stdin_devnull_twice(tmp_path: Path):
    proc1, log = run_keys(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    proc2, _ = run_keys(tmp_path, docker=tmp_path / "docker", log=log)
    assert proc2.returncode == 0, proc2.stderr
    assert len(run_cmds(stub_cmds(log))) == 1


def test_force_regenerates_keystores(tmp_path: Path):
    proc1, log = run_keys(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    sample = validator_dirs(tmp_path)[0] / "voting-keystore.json"
    old = 1_000_000.0
    os.utime(sample, (old, old))
    proc2, _ = run_keys(
        tmp_path, ["--force"], docker=tmp_path / "docker", log=log
    )
    assert proc2.returncode == 0, proc2.stderr
    assert_no_secret(proc2)
    assert sample.stat().st_mtime > old
    assert len(run_cmds(stub_cmds(log))) == 2


def test_missing_genesis_config_exits_2_naming_stage(tmp_path: Path):
    proc, log = run_keys(tmp_path, plant_config=False)
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "config.yaml" in proc.stderr
    assert "01-genesis.sh" in proc.stderr
    assert stub_cmds(log) == []
    assert_no_secret(proc)


def test_chain_id_1_exits_2(tmp_path: Path):
    proc, log = run_keys(tmp_path, env={"CHAIN_ID": "1"})
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "1337" in proc.stderr
    assert stub_cmds(log) == []
    assert_no_secret(proc)


def test_generator_failure_exits_1(tmp_path: Path):
    proc, _ = run_keys(tmp_path, fail_run=True)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "keystores failed" in proc.stderr
    assert_no_secret(proc)


def test_assert_key_count_accepts_n(tmp_path: Path):
    plant_keystores(tmp_path, _N)
    proc = source_keys(tmp_path, "assert_key_count")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)


def test_assert_key_count_exits_1_when_n_minus_1(tmp_path: Path):
    plant_keystores(tmp_path, _N - 1)
    proc = source_keys(tmp_path, "assert_key_count")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert str(_N - 1) in proc.stderr
    assert str(_N) in proc.stderr
    assert_no_secret(proc)


def test_source_max_n_minus_1_makes_assert_key_count_exit_1(tmp_path: Path):
    proc, log = run_keys(tmp_path, n_keys=_N - 1)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert str(_N - 1) in proc.stderr
    assert str(_N) in proc.stderr
    cmds = run_cmds(stub_cmds(log))
    assert len(cmds) == 1
    assert f"--source-max {_N}" in cmds[0]
    assert f"--source-max {_N - 1}" not in cmds[0]
    assert_no_secret(proc)


def test_assert_kdf_strength_exits_1_on_c_2(tmp_path: Path):
    plant_keystores(tmp_path, 1, c=2)
    proc = source_keys(tmp_path, "assert_kdf_strength")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "KDF" in proc.stderr
    assert_no_secret(proc)


def test_existing_weak_kdf_exits_1_without_docker_run(tmp_path: Path):
    plant_keystores(tmp_path, _N, c=2)
    stub, log = write_docker_stub(tmp_path, fail_run=True)
    plant_genesis(tmp_path)
    proc, _ = run_keys(tmp_path, docker=stub, log=log)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "KDF" in proc.stderr
    assert run_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_assert_kdf_strength_exits_1_on_symlink(tmp_path: Path):
    plant_keystores(tmp_path, 1, symlink=True)
    proc = source_keys(tmp_path, "assert_kdf_strength")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "symlink" in proc.stderr
    assert_no_secret(proc)


def test_assert_kdf_strength_exits_1_on_empty_body(tmp_path: Path):
    plant_keystores(tmp_path, 1, empty_body=True)
    proc = source_keys(tmp_path, "assert_kdf_strength")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "KDF" in proc.stderr or "unreadable" in proc.stderr or "empty" in proc.stderr
    assert_no_secret(proc)


def test_assert_kdf_strength_exits_1_on_missing_c(tmp_path: Path):
    plant_keystores(tmp_path, 1, missing_c=True)
    proc = source_keys(tmp_path, "assert_kdf_strength")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "KDF" in proc.stderr
    assert_no_secret(proc)


def test_assert_kdf_strength_exits_1_on_non_numeric_c(tmp_path: Path):
    valtools = tmp_path / "data" / "keys" / "valtools" / "validators"
    d = valtools / pubkey(0)
    d.mkdir(parents=True)
    (d / "voting-keystore.json").write_text(
        '{"crypto":{"kdf":{"params":{"c":"2"}}}}\n', encoding="utf-8"
    )
    proc = source_keys(tmp_path, "assert_kdf_strength")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "KDF" in proc.stderr
    assert_no_secret(proc)


def test_existing_symlink_keystore_exits_1_without_docker_run(tmp_path: Path):
    plant_keystores(tmp_path, _N, symlink=True)
    stub, log = write_docker_stub(tmp_path, fail_run=True)
    plant_genesis(tmp_path)
    proc, _ = run_keys(tmp_path, docker=stub, log=log)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "symlink" in proc.stderr
    assert run_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_noop_reapplies_secret_mode_600(tmp_path: Path):
    proc1, log = run_keys(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    keys_dir = tmp_path / "data" / "keys"
    valtools = keys_dir / "valtools"
    secrets = valtools / "secrets"
    sample = next(secrets.glob("0x*"))
    sample.chmod(0o644)
    keys_dir.chmod(0o755)
    valtools.chmod(0o755)
    secrets.chmod(0o755)
    assert file_mode(sample) == 0o644
    proc2, _ = run_keys(tmp_path, docker=tmp_path / "docker", log=log)
    assert proc2.returncode == 0, proc2.stderr
    assert_no_secret(proc2)
    assert file_mode(sample) == 0o600
    assert stat.filemode(sample.stat().st_mode) == "-rw-------"
    assert file_mode(keys_dir) == 0o700
    assert file_mode(secrets) == 0o700
    assert len(run_cmds(stub_cmds(log))) == 1


def test_dry_run_exits_0_without_docker_run(tmp_path: Path):
    proc, log = run_keys(tmp_path, ["--dry-run"])
    assert proc.returncode == 0, proc.stderr
    assert run_cmds(stub_cmds(log)) == []
    assert "keys plan" in proc.stderr
    assert "generate_keystores" in proc.stderr
    assert "assert_key_count" in proc.stderr
    assert "assert_kdf_strength" in proc.stderr
    assert not (tmp_path / "data" / "keys" / "valtools").exists()
    assert_no_secret(proc)


def test_unknown_flag_exits_2(tmp_path: Path):
    proc, log = run_keys(tmp_path, ["--nope"])
    assert proc.returncode == 2
    assert "unknown flag" in proc.stderr
    assert stub_cmds(log) == []


def test_data_dir_symlink_exits_2(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    data = tmp_path / "data"
    data.symlink_to(real)
    proc, log = run_keys(tmp_path)
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert stub_cmds(log) == []


def test_assert_kdf_strength_exits_1_when_no_keystores(tmp_path: Path):
    valtools = tmp_path / "data" / "keys" / "valtools" / "validators"
    valtools.mkdir(parents=True)
    proc = source_keys(tmp_path, "assert_kdf_strength")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert_no_secret(proc)


@pytest.mark.skipif(
    not _live_genesis_available(),
    reason="pinned IMG_GENESIS not present (1.2 owns the pull)",
)
def test_live_valtools_count_and_kdf(tmp_path: Path):
    docker = shutil.which("docker")
    assert docker is not None
    plant_genesis(tmp_path)
    env = keys_env(tmp_path, docker=Path(docker))
    proc = subprocess.run(
        ["bash", str(KEYS)],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    data = tmp_path / "data"
    keys_dir = data / "keys"
    valtools = keys_dir / "valtools"
    dirs = validator_dirs(tmp_path)
    assert len(dirs) == _N
    assert keys_dir.stat().st_uid == os.getuid()
    secrets = valtools / "secrets"
    for d in dirs:
        ks = d / "voting-keystore.json"
        assert ks.is_file()
        assert not ks.is_symlink()
        parsed = json.loads(ks.read_text(encoding="utf-8"))
        c = parsed["crypto"]["kdf"]["params"]["c"]
        assert isinstance(c, int)
        assert c >= 10000
        sec = secrets / d.name
        assert sec.is_file()
        assert file_mode(sec) == 0o600
        assert stat.filemode(sec.stat().st_mode) == "-rw-------"
    for name in _UNUSED_TREES:
        assert not (valtools / name).exists(), name
    jwt = data / "jwt"
    assert not jwt.exists() or list(jwt.glob("*")) == []
    sample = dirs[0] / "voting-keystore.json"
    mtime = sample.stat().st_mtime
    proc2 = subprocess.run(
        ["bash", str(KEYS)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert sample.stat().st_mtime == mtime
    text = sample.read_text(encoding="utf-8")
    edited = re.sub(r'"c"\s*:\s*\d+', '"c": 2', text, count=1)
    assert edited != text
    sample.write_text(edited, encoding="utf-8")
    proc3 = subprocess.run(
        ["bash", str(KEYS)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    assert proc3.returncode == 1
    assert "KDF" in proc3.stderr
    assert_no_secret(proc3)
    vlog = keys_dir / "valtools.log"
    if vlog.is_file():
        assert _MNEMONIC not in vlog.read_text(encoding="utf-8", errors="replace")
        assert file_mode(vlog) == 0o600
