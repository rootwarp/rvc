"""Contract tests for scripts/devnet/02-keys.sh.

DOCKER stubs are scratch scripts (P1-A8); disable_socket() via conftest autouse.
Live val-tools run is skipped unless DEVNET_LIVE=1 and the pinned IMG_GENESIS is present.
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
_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_MANIFEST_KEYPATHS = _FIXTURES / "manifest_json__keypaths.txt"

_ENV = parse_env(ENV_PATH)
_N = int(_ENV["NUM_VALIDATORS"])
_MNEMONIC = _ENV["MNEMONIC"]
_IMG = _ENV["IMG_GENESIS"]

# Known-answer pubkeys for the public BIP-39 test mnemonic in devnet.env
# at EIP-2334 m/12381/3600/i/0/0 from eth2-val-tools pubkeys, N=64.
KAT_PUBKEY_0 = (
    "0xa39882700ed7f72fcdbac07081b7c0c912cb8647ed8494926e6c9c2fc1a7415c"
    "7c60e3afcc3d3278fe25b50b851c3ad5"
)
KAT_PUBKEY_1 = (
    "0x8efdefbccd6479b9953a5ec6416e6d48201865968567379b213040dbf0be7efa"
    "00d66343c21a7e801d6bfd7403cfcfa7"
)
KAT_PUBKEY_63 = (
    "0xab0b0a68c9ab8ef73338f8ee1bce7bdfb4fdd1020b4163bec31b952651141db4"
    "c8db7fc4b0c97cb8645ad2a58344c1c8"
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


def unsorted_pubkey(i: int) -> str:
    return f"0x{255 - i:02x}{'cd' * 47}"


def _json_keypaths(obj: object, prefix: str = "") -> set[str]:
    paths: set[str] = set()
    if isinstance(obj, dict):
        for key, value in obj.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.add(path)
            paths |= _json_keypaths(value, path)
    elif isinstance(obj, list):
        elem = f"{prefix}[]"
        for item in obj:
            paths |= _json_keypaths(item, elem)
    return paths


def _pk_snippet(style: str) -> str:
    if style == "unsorted":
        return (
            "      pk=$(printf '0x%02x' $((255 - $i)))\n"
            "      k=0\n"
            "      while [ \"$k\" -lt 47 ]; do\n"
            "        pk=\"${pk}cd\"\n"
            "        k=$((k + 1))\n"
            "      done\n"
        )
    return '      pk=$(printf \'0x%096x\' "$i")\n'


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
    pubkeys_mode: str = "ok",
) -> tuple[Path, Path]:
    log = tmp_path / "docker.log"
    if n_keys is None:
        n_assign = 'n="$source_max"\n'
    else:
        n_assign = f"n={int(n_keys)}\n"
    pk_style = "unsorted" if pubkeys_mode == "unsorted" else "sequential"
    pk_block = _pk_snippet(pk_style)
    if pubkeys_mode == "short":
        emit_assign = '      emit=$((n - 1))\n'
    else:
        emit_assign = '      emit="$n"\n'
    dup_flag = "1" if pubkeys_mode == "dup" else "0"
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
        "    is_pubkeys=0\n"
        "    for arg in \"$@\"; do\n"
        "      case \"$prev\" in\n"
        "        --source-mnemonic) mnemonic=\"$arg\" ;;\n"
        "        --validators-mnemonic) mnemonic=\"$arg\" ;;\n"
        "        --source-max) source_max=\"$arg\" ;;\n"
        "      esac\n"
        "      case \"$arg\" in\n"
        "        pubkeys) is_pubkeys=1 ;;\n"
        "        --source-max=*) source_max=\"${arg#--source-max=}\" ;;\n"
        "        --source-mnemonic=*) mnemonic=\"${arg#--source-mnemonic=}\" ;;\n"
        "        --validators-mnemonic=*) mnemonic=\"${arg#--validators-mnemonic=}\" ;;\n"
        "        *:/data/keys)\n"
        "          host=\"${arg%:/data/keys}\"\n"
        "          ;;\n"
        "      esac\n"
        "      prev=\"$arg\"\n"
        "    done\n"
        f"    {n_assign}"
        "    if [ \"$is_pubkeys\" -eq 1 ]; then\n"
        "      if [ -z \"$n\" ]; then\n"
        "        exit 1\n"
        "      fi\n"
        "      printf 'cobra noise on stderr\\n' >&2\n"
        "      printf 'ignored-line\\n'\n"
        f"{emit_assign}"
        f"      dup={dup_flag}\n"
        "      i=0\n"
        "      while [ \"$i\" -lt \"$emit\" ]; do\n"
        f"{pk_block}"
        "        if [ \"$dup\" -eq 1 ] && [ \"$i\" -eq $((emit - 1)) ]; then\n"
        "          i=0\n"
        f"{pk_block}"
        "          i=$((emit - 1))\n"
        "        fi\n"
        "        printf '%s\\n' \"$pk\"\n"
        "        i=$((i + 1))\n"
        "      done\n"
        "      exit 0\n"
        "    fi\n"
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
        f"{pk_block}"
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


def plant_genesis(tmp_path: Path, data_root: Path | None = None) -> Path:
    genesis = (data_root or (tmp_path / "data")) / "genesis"
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
    data_root: Path | None = None,
) -> Path:
    n = _N if n is None else n
    root = data_root or (tmp_path / "data")
    valtools = root / "keys" / "valtools"
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


def plant_manifest(
    tmp_path: Path,
    n: int | None = None,
    *,
    data_root: Path | None = None,
    pubkeys: list[str] | None = None,
) -> Path:
    n = _N if n is None else n
    root = data_root or (tmp_path / "data")
    if pubkeys is None:
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
    path = root / "keys" / "manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path


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
    pubkeys_mode: str = "ok",
    data_root: Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    if docker is None:
        stub, log_path = write_docker_stub(
            tmp_path,
            fail_run=fail_run,
            n_keys=n_keys,
            pubkeys_mode=pubkeys_mode,
        )
    else:
        stub = docker
        log_path = log or (tmp_path / "docker.log")
    if plant_config:
        plant_genesis(tmp_path, data_root=data_root)
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


def keystore_cmds(cmds: list[str]) -> list[str]:
    return [c for c in run_cmds(cmds) if " keystores " in f" {c} "]


def pubkey_cmds(cmds: list[str]) -> list[str]:
    return [c for c in run_cmds(cmds) if " pubkeys " in f" {c} "]


def load_manifest(tmp_path: Path, data_root: Path | None = None) -> dict:
    root = data_root or (tmp_path / "data")
    return json.loads((root / "keys" / "manifest.json").read_text(encoding="utf-8"))


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
    if os.environ.get("DEVNET_LIVE") != "1":
        return False
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
    assert "build_manifest()" in text
    assert "assert_manifest_rows()" in text
    assert "manifest_has_n_rows()" in text
    assert "require_chain_1337" in text
    assert "keys_exist()" in text
    assert "--insecure" not in text
    assert "NUM_VALIDATORS-1" not in text
    assert "$((NUM_VALIDATORS" not in text
    assert "manifest.json" in text
    assert "/rvc/" not in text
    assert "passwords.txt" not in text
    assert "split_keys" not in text
    assert "--entrypoint" in text
    assert "/usr/local/bin/eth2-val-tools" in text
    assert "--validators-mnemonic" in text
    assert "--source-mnemonic" in text
    assert "pubkeys" in text
    assert "--source-max" in text
    assert '"$NUM_VALIDATORS"' in text
    assert "/data/keys/valtools" in text
    assert "${KEYS_DIR}:/data/keys" in text
    assert "protolambda/eth2-val-tools:0.2.2@sha256:46147228" in text
    assert "/app/eth2-val-tools" in text
    assert "O_NOFOLLOW" in text
    assert "O_EXCL" in text
    assert "os.urandom" in text
    assert "${MANIFEST_JSON}.tmp" not in text
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
    assert not (keys_dir / "passwords.txt").exists()
    man_path = keys_dir / "manifest.json"
    assert man_path.is_file()
    assert not man_path.is_symlink()
    assert file_mode(man_path) == 0o600
    manifest = json.loads(man_path.read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1
    assert re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", manifest["generated_at"]
    )
    rows = manifest["validators"]
    assert len(rows) == _N
    for i, row in enumerate(rows):
        assert row["index"] == i
        assert row["pubkey"] == pubkey(i)
        assert row["keystore_path"] == (
            f"valtools/validators/{pubkey(i)}/voting-keystore.json"
        )
    assert jwt.read_text(encoding="utf-8") == jwt_body
    cmds = run_cmds(stub_cmds(log))
    ks_cmds = keystore_cmds(cmds)
    pk_cmds = pubkey_cmds(cmds)
    assert len(ks_cmds) == 1
    assert len(pk_cmds) == 1
    argv = ks_cmds[0]
    pk_argv = pk_cmds[0]
    uid = os.getuid()
    gid = os.getgid()
    assert f"run -u {uid}:{gid}" in argv
    assert "--rm" in argv
    assert f"{keys_dir}:/data/keys" in argv
    assert f"{tmp_path / 'data'}:/data" not in argv
    assert "/jwt" not in argv
    assert "--entrypoint /usr/local/bin/eth2-val-tools" in argv
    assert "--entrypoint /usr/local/bin/eth2-val-tools" in pk_argv
    assert _IMG in argv
    assert _IMG in pk_argv
    assert " keystores " in argv
    assert " pubkeys " in pk_argv
    assert "--source-min 0" in argv
    assert f"--source-max {_N}" in argv
    assert f"--source-max {_N - 1}" not in argv
    assert "--out-loc /data/keys/valtools" in argv
    assert "--insecure" not in argv
    assert "--validators-mnemonic=" in pk_argv
    assert "--source-min=0" in pk_argv
    assert f"--source-max={_N}" in pk_argv
    assert f"{keys_dir}:/data/keys" not in pk_argv
    assert f"run -u {uid}:{gid}" not in pk_argv
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
    man = tmp_path / "data" / "keys" / "manifest.json"
    man_mtime = man.stat().st_mtime
    first_runs = len(run_cmds(stub_cmds(log)))
    proc2, _ = run_keys(tmp_path, docker=tmp_path / "docker", log=log)
    assert proc2.returncode == 0, proc2.stderr
    assert_no_secret(proc2)
    assert sample.read_text(encoding="utf-8") == body
    assert sample.stat().st_mtime == mtime
    assert man.stat().st_mtime == man_mtime
    assert len(run_cmds(stub_cmds(log))) == first_runs
    assert "already present" in proc2.stderr
    assert "skipping manifest.json" in proc2.stderr


def test_stdin_devnull_twice(tmp_path: Path):
    proc1, log = run_keys(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    proc2, _ = run_keys(tmp_path, docker=tmp_path / "docker", log=log)
    assert proc2.returncode == 0, proc2.stderr
    cmds = run_cmds(stub_cmds(log))
    assert len(keystore_cmds(cmds)) == 1
    assert len(pubkey_cmds(cmds)) == 1
    assert "skipping manifest.json" in proc2.stderr


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
    cmds = run_cmds(stub_cmds(log))
    assert len(keystore_cmds(cmds)) == 2
    assert len(pubkey_cmds(cmds)) == 2


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
    cmds = run_cmds(stub_cmds(log))
    assert len(keystore_cmds(cmds)) == 1
    assert len(pubkey_cmds(cmds)) == 1


def test_dry_run_exits_0_without_docker_run(tmp_path: Path):
    proc, log = run_keys(tmp_path, ["--dry-run"])
    assert proc.returncode == 0, proc.stderr
    assert run_cmds(stub_cmds(log)) == []
    assert "keys plan" in proc.stderr
    assert "generate_keystores" in proc.stderr
    assert "assert_key_count" in proc.stderr
    assert "assert_kdf_strength" in proc.stderr
    assert "build_manifest" in proc.stderr
    assert "assert_manifest_rows" in proc.stderr
    assert not (tmp_path / "data" / "keys" / "valtools").exists()
    assert not (tmp_path / "data" / "keys" / "manifest.json").exists()
    assert_no_secret(proc)


def test_unknown_flag_exits_2(tmp_path: Path):
    proc, log = run_keys(tmp_path, ["--nope"])
    assert proc.returncode == 2
    assert "unknown flag" in proc.stderr
    assert stub_cmds(log) == []


def test_manifest_symlink_dest_exits_2(tmp_path: Path):
    plant_keystores(tmp_path)
    victim = tmp_path / "victim-manifest"
    victim.write_text("untouched\n", encoding="utf-8")
    man = tmp_path / "data" / "keys" / "manifest.json"
    man.symlink_to(victim)
    proc, log = run_keys(tmp_path)
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"
    assert pubkey_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


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


def test_kat_pubkeys_recorded_and_not_c_sorted():
    for pk in (KAT_PUBKEY_0, KAT_PUBKEY_1, KAT_PUBKEY_63):
        assert re.fullmatch(r"0x[0-9a-f]{96}", pk), pk
    assert len({KAT_PUBKEY_0, KAT_PUBKEY_1, KAT_PUBKEY_63}) == 3
    kat = [KAT_PUBKEY_0, KAT_PUBKEY_1, KAT_PUBKEY_63]
    assert kat != sorted(kat)


def test_manifest_json_matches_committed_keypaths(tmp_path: Path):
    proc, _ = run_keys(tmp_path)
    assert proc.returncode == 0, proc.stderr
    manifest = load_manifest(tmp_path)
    actual = _json_keypaths(manifest)
    expected = {
        line
        for line in _MANIFEST_KEYPATHS.read_text(encoding="utf-8").splitlines()
        if line
    }
    assert actual - expected == set()
    assert expected - actual == set()


def test_short_pubkeys_exits_1(tmp_path: Path):
    plant_keystores(tmp_path)
    stub, log = write_docker_stub(tmp_path, pubkeys_mode="short")
    proc, _ = run_keys(tmp_path, docker=stub, log=log)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert str(_N) in proc.stderr
    assert "pubkey" in proc.stderr.lower()
    assert_no_secret(proc)
    assert not (tmp_path / "data" / "keys" / "manifest.json").exists()


def test_duplicated_pubkeys_exits_1(tmp_path: Path):
    plant_keystores(tmp_path)
    stub, log = write_docker_stub(tmp_path, pubkeys_mode="dup")
    proc, _ = run_keys(tmp_path, docker=stub, log=log)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "duplicated" in proc.stderr
    assert_no_secret(proc)
    assert not (tmp_path / "data" / "keys" / "manifest.json").exists()


def test_missing_manifest_is_built_without_regenerating_keys(tmp_path: Path):
    plant_keystores(tmp_path)
    sample = validator_dirs(tmp_path)[0] / "voting-keystore.json"
    mtime = sample.stat().st_mtime
    proc, log = run_keys(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    assert sample.stat().st_mtime == mtime
    cmds = run_cmds(stub_cmds(log))
    assert keystore_cmds(cmds) == []
    assert len(pubkey_cmds(cmds)) == 1
    man = load_manifest(tmp_path)
    assert len(man["validators"]) == _N
    assert man["validators"][0]["index"] == 0
    assert man["validators"][_N - 1]["index"] == _N - 1


def test_manifest_mtime_unchanged_on_second_run(tmp_path: Path):
    proc1, log = run_keys(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    man = tmp_path / "data" / "keys" / "manifest.json"
    old = 1_000_000.0
    os.utime(man, (old, old))
    proc2, _ = run_keys(tmp_path, docker=tmp_path / "docker", log=log)
    assert proc2.returncode == 0, proc2.stderr
    assert man.stat().st_mtime == old
    assert "skipping manifest.json" in proc2.stderr
    assert_no_secret(proc2)


def test_manifest_pubkeys_differ_from_c_sort(tmp_path: Path):
    proc, _ = run_keys(tmp_path, pubkeys_mode="unsorted")
    assert proc.returncode == 0, proc.stderr
    man = load_manifest(tmp_path)
    pubs = [row["pubkey"] for row in man["validators"]]
    assert pubs == [unsorted_pubkey(i) for i in range(_N)]
    assert pubs != sorted(pubs)
    dir_names = [p.name for p in validator_dirs(tmp_path)]
    assert dir_names == sorted(dir_names)
    assert pubs != dir_names


def test_data_dir_flag_refuses_symlink(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    proc, log = run_keys(tmp_path, ["--data-dir", str(link)], plant_config=False)
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert stub_cmds(log) == []
    assert_no_secret(proc)


def test_data_dir_flag_refuses_world_writable(tmp_path: Path):
    wide = tmp_path / "wide"
    wide.mkdir()
    wide.chmod(0o777)
    proc, log = run_keys(tmp_path, ["--data-dir", str(wide)], plant_config=False)
    assert proc.returncode == 2
    assert "world-writable" in proc.stderr
    assert stub_cmds(log) == []
    assert_no_secret(proc)


def test_data_dir_flag_writes_under_t_only(tmp_path: Path):
    t = tmp_path / "T"
    plant_genesis(tmp_path, data_root=t)
    default_data = tmp_path / "data"
    proc, log = run_keys(
        tmp_path,
        ["--data-dir", str(t)],
        plant_config=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    assert (t / "keys" / "manifest.json").is_file()
    assert (t / "keys" / "valtools" / "validators").is_dir()
    assert len(load_manifest(tmp_path, data_root=t)["validators"]) == _N
    assert not (default_data / "keys").exists()
    assert not (default_data / "genesis").exists()
    cmds = run_cmds(stub_cmds(log))
    assert len(keystore_cmds(cmds)) == 1
    assert len(pubkey_cmds(cmds)) == 1
    assert f"{t / 'keys'}:/data/keys" in keystore_cmds(cmds)[0]


def test_path_docker_shim_not_invoked_when_artifacts_present(tmp_path: Path):
    t = tmp_path / "T"
    plant_genesis(tmp_path, data_root=t)
    plant_keystores(tmp_path, data_root=t)
    plant_manifest(tmp_path, data_root=t)
    shim_dir = tmp_path / "shim-bin"
    shim_dir.mkdir()
    dlog = tmp_path / "path-docker.log"
    docker = shim_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(dlog))}\n"
        "exit 1\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    full = keys_env(
        tmp_path, extra={"DATA_DIR": str(tmp_path / "unused-default")}
    )
    full["DOCKER"] = "docker"
    full["PATH"] = str(shim_dir) + os.pathsep + full.get(
        "PATH", os.environ.get("PATH", "")
    )
    proc = subprocess.run(
        ["bash", str(KEYS), "--data-dir", str(t)],
        capture_output=True,
        text=True,
        env=full,
        timeout=20,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    assert not dlog.exists() or dlog.read_text(encoding="utf-8") == ""
    assert "skipping manifest.json" in proc.stderr
    assert "already present" in proc.stderr
    assert not (tmp_path / "unused-default" / "keys").exists()


def test_assert_manifest_rows_accepts_n(tmp_path: Path):
    plant_keystores(tmp_path)
    plant_manifest(tmp_path)
    proc = source_keys(tmp_path, "assert_manifest_rows")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)


def test_assert_manifest_rows_exits_1_on_short(tmp_path: Path):
    plant_keystores(tmp_path, _N - 1)
    plant_manifest(tmp_path, _N - 1)
    proc = source_keys(tmp_path, "assert_manifest_rows")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert_no_secret(proc)


@pytest.mark.skipif(
    not _live_genesis_available(),
    reason="DEVNET_LIVE=1 and pinned IMG_GENESIS required",
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
    man_path = keys_dir / "manifest.json"
    assert man_path.is_file()
    man = json.loads(man_path.read_text(encoding="utf-8"))
    assert man["schema_version"] == 1
    assert len(man["validators"]) == _N
    assert man["validators"][0]["pubkey"] == KAT_PUBKEY_0
    assert man["validators"][1]["pubkey"] == KAT_PUBKEY_1
    assert man["validators"][63]["pubkey"] == KAT_PUBKEY_63
    pubs = [row["pubkey"] for row in man["validators"]]
    assert pubs != sorted(pubs)
