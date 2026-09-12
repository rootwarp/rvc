"""Contract tests for scripts/devnet/01-genesis.sh.

DOCKER stubs are scratch scripts (P1-A8); disable_socket() via conftest autouse.
Live generator run is skipped unless the pinned IMG_GENESIS is already present.
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

GENESIS = Path(__file__).resolve().parents[1] / "devnet" / "01-genesis.sh"

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

_MNEMONIC = "test test test test test test test test test test test junk"

_GOOD_CONFIG = (
    "PRESET_BASE: 'mainnet'\n"
    "SLOT_DURATION_MS: 12000\n"
    "ELECTRA_FORK_EPOCH: 0\n"
)

_GVR_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_GVR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_JWT_XTRACE_LEAK = (
    "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
)


def write_docker_stub(
    tmp_path: Path,
    *,
    fail_run: bool = False,
    config: str = _GOOD_CONFIG,
    gvr: str = _GVR_A,
) -> tuple[Path, Path]:
    log = tmp_path / "docker.log"
    payload = tmp_path / "generator-output" / "metadata"
    payload.mkdir(parents=True)
    (payload / "config.yaml").write_text(config, encoding="utf-8")
    (payload / "genesis.ssz").write_bytes(b"ssz")
    (payload / "genesis.json").write_text("{}\n", encoding="utf-8")
    (payload / "genesis_validators_root.txt").write_text(gvr, encoding="utf-8")
    (payload / "deposit_contract.txt").write_text(
        "0x4242424242424242424242424242424242424242\n", encoding="utf-8"
    )
    (payload / "deposit_contract_block.txt").write_text("0\n", encoding="utf-8")
    stub = tmp_path / "docker"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "cmd=\"$1\"\n"
        "shift || true\n"
        "case \"$cmd\" in\n"
        "  run)\n"
        f"    if [ {1 if fail_run else 0} -ne 0 ]; then\n"
        "      exit 1\n"
        "    fi\n"
        "    host=\"\"\n"
        "    for arg in \"$@\"; do\n"
        "      case \"$arg\" in\n"
        "        *:/data)\n"
        "          host=\"${arg%:/data}\"\n"
        "          ;;\n"
        "      esac\n"
        "    done\n"
        "    if [ -z \"$host\" ]; then\n"
        "      exit 1\n"
        "    fi\n"
        "    mkdir -p \"$host/metadata\" \"$host/jwt\"\n"
        f"    cp -R {shlex.quote(str(payload))}/. \"$host/metadata/\"\n"
        f"    printf '%s\\n' \"+ echo -n {_JWT_XTRACE_LEAK}\" >&2\n"
        "    printf 'leaked-jwt\\n' > \"$host/jwt/jwtsecret\"\n"
        "    chmod 644 \"$host/jwt/jwtsecret\" \"$host/metadata/config.yaml\"\n"
        "    printf 'mnemo\\n' > \"$host/metadata/mnemonics.yaml\"\n"
        "    chmod 644 \"$host/metadata/mnemonics.yaml\"\n"
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def genesis_env(
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


def run_genesis(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    env: dict[str, str] | None = None,
    fail_run: bool = False,
    config: str = _GOOD_CONFIG,
    gvr: str = _GVR_A,
    timeout: float = 20,
    docker: Path | None = None,
    log: Path | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    if docker is None:
        stub, log_path = write_docker_stub(
            tmp_path, fail_run=fail_run, config=config, gvr=gvr
        )
    else:
        stub = docker
        log_path = log or (tmp_path / "docker.log")
    full = genesis_env(tmp_path, env, docker=stub)
    proc = subprocess.run(
        ["bash", str(GENESIS), *args],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return proc, log_path


def source_genesis(
    tmp_path: Path,
    snippet: str,
    *,
    env: dict[str, str] | None = None,
    timeout: float = 10,
) -> subprocess.CompletedProcess[str]:
    stub, _ = write_docker_stub(tmp_path)
    full = genesis_env(tmp_path, env, docker=stub)
    return subprocess.run(
        ["bash", "-c", f"source {shlex.quote(str(GENESIS))}; {snippet}"],
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


def yaml_has(text: str, key: str, val: str) -> bool:
    pat = rf"^{re.escape(key)}:\s*['\"]?{re.escape(val)}['\"]?\s*$"
    return re.search(pat, text, re.M) is not None


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


def test_genesis_sh_exists_and_syntax():
    assert GENESIS.is_file(), GENESIS
    proc = subprocess.run(
        ["bash", "-n", str(GENESIS)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = GENESIS.read_text(encoding="utf-8")
    # No bash `read` prompt; Python `.read()` in the JWT writer is fine.
    assert re.search(r"(?m)^\s*read\s", text) is None
    assert "read -p" not in text
    assert "read -r" not in text
    assert "source" in text and "lib/common.sh" in text
    assert "docker_run_as_user" in text
    assert "make_jwt()" in text
    assert "render_values_env()" in text
    assert "run_generator()" in text
    assert "copy_metadata()" in text
    assert "assert_generated_config()" in text
    assert "genesis_is_stale()" in text
    assert "$((FULU" not in text
    assert "tmp.$$" not in text
    assert "O_NOFOLLOW" in text
    assert "SLOTS_PER_EPOCH" not in text
    assert "SLOT_DURATION_IN_SECONDS" not in text
    assert "SECONDS_PER_SLOT" not in text
    assert re.search(r"\bdocker\b", text) is None or '"$DOCKER"' in text
    assert "bare docker" not in text
    # Stage must not shell out to a bare docker binary.
    assert re.search(r'(?m)^\s*docker\s', text) is None


def test_assert_generated_config_accepts_quoted_mainnet(tmp_path: Path):
    genesis_dir = tmp_path / "data" / "genesis"
    genesis_dir.mkdir(parents=True)
    (genesis_dir / "config.yaml").write_text(_GOOD_CONFIG, encoding="utf-8")
    proc = source_genesis(tmp_path, "assert_generated_config")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)


def test_assert_generated_config_exits_1_without_slot_duration(tmp_path: Path):
    genesis_dir = tmp_path / "data" / "genesis"
    genesis_dir.mkdir(parents=True)
    (genesis_dir / "config.yaml").write_text(
        "PRESET_BASE: 'mainnet'\nELECTRA_FORK_EPOCH: 0\n", encoding="utf-8"
    )
    proc = source_genesis(tmp_path, "assert_generated_config")
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "SLOT_DURATION_MS" in proc.stderr
    assert_no_secret(proc)


def test_assert_generated_config_exits_1_without_preset_base(tmp_path: Path):
    genesis_dir = tmp_path / "data" / "genesis"
    genesis_dir.mkdir(parents=True)
    (genesis_dir / "config.yaml").write_text(
        "SLOT_DURATION_MS: 12000\nELECTRA_FORK_EPOCH: 0\n", encoding="utf-8"
    )
    proc = source_genesis(tmp_path, "assert_generated_config")
    assert proc.returncode == 1
    assert "PRESET_BASE" in proc.stderr
    assert_no_secret(proc)


def test_assert_generated_config_exits_1_without_electra_epoch_zero(tmp_path: Path):
    genesis_dir = tmp_path / "data" / "genesis"
    genesis_dir.mkdir(parents=True)
    (genesis_dir / "config.yaml").write_text(
        "PRESET_BASE: 'mainnet'\nSLOT_DURATION_MS: 12000\nELECTRA_FORK_EPOCH: 1\n",
        encoding="utf-8",
    )
    proc = source_genesis(tmp_path, "assert_generated_config")
    assert proc.returncode == 1
    assert "ELECTRA_FORK_EPOCH" in proc.stderr
    assert_no_secret(proc)


def test_assert_generated_config_does_not_require_seconds_per_slot(tmp_path: Path):
    genesis_dir = tmp_path / "data" / "genesis"
    genesis_dir.mkdir(parents=True)
    (genesis_dir / "config.yaml").write_text(_GOOD_CONFIG, encoding="utf-8")
    proc = source_genesis(tmp_path, "assert_generated_config")
    assert proc.returncode == 0, proc.stderr


def test_stub_generate_writes_jwt_values_and_gvr(tmp_path: Path):
    proc, log = run_genesis(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    data = tmp_path / "data"
    jwt = data / "jwt" / "jwt.hex"
    values = data / "genesis" / "values.env"
    gvr = data / "genesis" / "genesis_validators_root.txt"
    ssz = data / "genesis" / "genesis.ssz"
    assert jwt.is_file()
    body = jwt.read_text(encoding="utf-8").strip()
    assert re.fullmatch(r"[0-9a-f]{64}", body)
    mode = jwt.stat().st_mode & 0o777
    assert mode == 0o600, oct(mode)
    assert jwt.stat().st_uid == os.getuid()
    text = values.read_text(encoding="utf-8")
    assert "SLOTS_PER_EPOCH" not in text
    assert "SLOT_DURATION_IN_SECONDS" not in text
    assert "PRESET_BASE=mainnet" in text
    assert "SLOT_DURATION_MS=12000" in text
    assert "ELECTRA_FORK_EPOCH=0" in text
    assert "NUMBER_OF_VALIDATORS=64" in text
    assert "FULU_FORK_EPOCH=18446744073709551615" in text
    assert "BPO_1_EPOCH=18446744073709551615" in text
    parsed = parse_env(values)
    ts = int(parsed["GENESIS_TIMESTAMP"])
    assert abs(ts - time.time()) < 15
    assert parsed["GENESIS_DELAY"] == "30"
    assert gvr.is_file()
    assert ssz.is_file()
    assert (data / "genesis" / "deploy_block.txt").read_text(encoding="utf-8") == "0\n"
    cmds = run_cmds(stub_cmds(log))
    assert len(cmds) == 1
    uid = os.getuid()
    gid = os.getgid()
    assert f"run -u {uid}:{gid}" in cmds[0]
    assert "--rm" in cmds[0]
    assert cmds[0].rstrip().endswith(" all")
    assert "/config/values.env" in cmds[0]
    assert ":/data" in cmds[0]
    img = parse_env(ENV_PATH)["IMG_GENESIS"]
    assert img in cmds[0]
    blob = proc.stdout + proc.stderr
    assert _JWT_XTRACE_LEAK not in blob
    assert "+ echo -n 0x" not in blob
    jwtsecret = data / "genesis" / "jwt" / "jwtsecret"
    mnemonics = data / "genesis" / "metadata" / "mnemonics.yaml"
    assert jwtsecret.is_file()
    assert not jwtsecret.is_symlink()
    assert (jwtsecret.stat().st_mode & 0o777) == 0o600
    assert mnemonics.is_file()
    assert (mnemonics.stat().st_mode & 0o777) == 0o600
    gen_log = data / "genesis" / "generator.log"
    assert gen_log.is_file()
    assert (gen_log.stat().st_mode & 0o777) == 0o600
    assert _JWT_XTRACE_LEAK not in gen_log.read_text(encoding="utf-8")
    assert _MNEMONIC not in gen_log.read_text(encoding="utf-8")


def test_values_env_slots_per_epoch_count_is_zero(tmp_path: Path):
    proc, _ = run_genesis(tmp_path)
    assert proc.returncode == 0, proc.stderr
    values = tmp_path / "data" / "genesis" / "values.env"
    counted = values.read_text(encoding="utf-8").count("SLOTS_PER_EPOCH")
    assert counted == 0


def test_second_run_is_noop_without_force(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    jwt = tmp_path / "data" / "jwt" / "jwt.hex"
    ssz = tmp_path / "data" / "genesis" / "genesis.ssz"
    jwt_body = jwt.read_text(encoding="utf-8")
    jwt_mtime = jwt.stat().st_mtime
    ssz_mtime = ssz.stat().st_mtime
    first_runs = len(run_cmds(stub_cmds(log)))
    proc2, _ = run_genesis(
        tmp_path,
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert_no_secret(proc2)
    assert jwt.read_text(encoding="utf-8") == jwt_body
    assert jwt.stat().st_mtime == jwt_mtime
    assert ssz.stat().st_mtime == ssz_mtime
    assert len(run_cmds(stub_cmds(log))) == first_runs
    assert "already present" in proc2.stderr


def test_el_datadir_different_gvr_exits_2_naming_force(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    el = tmp_path / "data" / "el"
    el.mkdir()
    (el / "genesis_validators_root.txt").write_text(_GVR_B, encoding="utf-8")
    (el / "chaindata").write_text("x", encoding="utf-8")
    proc2, _ = run_genesis(
        tmp_path,
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 2
    assert proc2.stdout == ""
    assert "--force" in proc2.stderr
    assert "EL" in proc2.stderr
    assert len(run_cmds(stub_cmds(log))) == 1
    assert_no_secret(proc2)


def test_el_datadir_matching_gvr_is_noop(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    el = tmp_path / "data" / "el"
    el.mkdir()
    gvr = (tmp_path / "data" / "genesis" / "genesis_validators_root.txt").read_text(
        encoding="utf-8"
    )
    (el / "genesis_validators_root.txt").write_text(gvr, encoding="utf-8")
    (el / "chaindata").write_text("x", encoding="utf-8")
    jwt = tmp_path / "data" / "jwt" / "jwt.hex"
    ssz = tmp_path / "data" / "genesis" / "genesis.ssz"
    jwt_mtime = jwt.stat().st_mtime
    ssz_mtime = ssz.stat().st_mtime
    proc2, _ = run_genesis(
        tmp_path,
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert jwt.stat().st_mtime == jwt_mtime
    assert ssz.stat().st_mtime == ssz_mtime
    assert len(run_cmds(stub_cmds(log))) == 1


def test_el_datadir_without_gvr_file_is_stale(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    el = tmp_path / "data" / "el"
    el.mkdir()
    (el / "chaindata").write_text("x", encoding="utf-8")
    proc2, _ = run_genesis(
        tmp_path,
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 2
    assert "--force" in proc2.stderr


def test_empty_el_datadir_is_not_stale(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    (tmp_path / "data" / "el").mkdir()
    proc2, _ = run_genesis(
        tmp_path,
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert len(run_cmds(stub_cmds(log))) == 1


def test_force_regenerates_genesis_and_jwt_mtimes(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    jwt = tmp_path / "data" / "jwt" / "jwt.hex"
    ssz = tmp_path / "data" / "genesis" / "genesis.ssz"
    old_jwt = jwt.read_text(encoding="utf-8")
    old = 1_000_000.0
    os.utime(jwt, (old, old))
    os.utime(ssz, (old, old))
    proc2, _ = run_genesis(
        tmp_path,
        ["--force"],
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert_no_secret(proc2)
    assert jwt.stat().st_mtime > old
    assert ssz.stat().st_mtime > old
    assert jwt.read_text(encoding="utf-8") != old_jwt
    assert len(run_cmds(stub_cmds(log))) == 2


def test_force_overrides_stale_el_datadir(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    el = tmp_path / "data" / "el"
    el.mkdir()
    (el / "genesis_validators_root.txt").write_text(_GVR_B, encoding="utf-8")
    proc2, _ = run_genesis(
        tmp_path,
        ["--force"],
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert len(run_cmds(stub_cmds(log))) == 2


def test_chain_id_1_exits_2(tmp_path: Path):
    proc, log = run_genesis(tmp_path, env={"CHAIN_ID": "1"})
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "1337" in proc.stderr
    assert stub_cmds(log) == []
    assert_no_secret(proc)


def test_generator_failure_exits_1(tmp_path: Path):
    proc, _ = run_genesis(tmp_path, fail_run=True)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "generator failed" in proc.stderr
    assert_no_secret(proc)


def test_bad_generated_config_exits_1(tmp_path: Path):
    proc, _ = run_genesis(
        tmp_path,
        config="PRESET_BASE: 'minimal'\nSLOT_DURATION_MS: 12000\nELECTRA_FORK_EPOCH: 0\n",
    )
    assert proc.returncode == 1
    assert "PRESET_BASE" in proc.stderr
    assert_no_secret(proc)


def test_dry_run_exits_0_without_docker_run(tmp_path: Path):
    proc, log = run_genesis(tmp_path, ["--dry-run"])
    assert proc.returncode == 0, proc.stderr
    assert run_cmds(stub_cmds(log)) == []
    assert "genesis plan" in proc.stderr
    assert "make_jwt" in proc.stderr
    assert "run_generator" in proc.stderr
    assert not (tmp_path / "data" / "jwt" / "jwt.hex").exists()
    assert_no_secret(proc)


def test_dry_run_still_catches_stale_datadir(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    el = tmp_path / "data" / "el"
    el.mkdir()
    (el / "genesis_validators_root.txt").write_text(_GVR_B, encoding="utf-8")
    proc2, _ = run_genesis(
        tmp_path,
        ["--dry-run"],
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 2
    assert "--force" in proc2.stderr
    assert len(run_cmds(stub_cmds(log))) == 1


def test_genesis_is_stale_fresh_tree(tmp_path: Path):
    proc = source_genesis(
        tmp_path,
        'if genesis_is_stale; then printf STALE; else printf FRESH; fi',
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "FRESH"


def test_genesis_is_stale_mismatch(tmp_path: Path):
    genesis_dir = tmp_path / "data" / "genesis"
    genesis_dir.mkdir(parents=True)
    (genesis_dir / "genesis_validators_root.txt").write_text(_GVR_A, encoding="utf-8")
    el = tmp_path / "data" / "el"
    el.mkdir()
    (el / "genesis_validators_root.txt").write_text(_GVR_B, encoding="utf-8")
    proc = source_genesis(
        tmp_path,
        'if genesis_is_stale; then printf STALE; else printf FRESH; fi',
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == "STALE"


def test_cl_datadir_different_gvr_exits_2(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    cl = tmp_path / "data" / "cl"
    cl.mkdir()
    (cl / "genesis_validators_root.txt").write_text(_GVR_B, encoding="utf-8")
    proc2, _ = run_genesis(
        tmp_path,
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 2
    assert "--force" in proc2.stderr
    assert "CL" in proc2.stderr


def test_jwt_missing_on_existing_genesis_is_repaired(tmp_path: Path):
    proc1, log = run_genesis(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    jwt = tmp_path / "data" / "jwt" / "jwt.hex"
    jwt.unlink()
    proc2, _ = run_genesis(
        tmp_path,
        docker=tmp_path / "docker",
        log=log,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert jwt.is_file()
    assert re.fullmatch(r"[0-9a-f]{64}", jwt.read_text(encoding="utf-8").strip())
    assert len(run_cmds(stub_cmds(log))) == 1


def test_unknown_flag_exits_2(tmp_path: Path):
    proc, log = run_genesis(tmp_path, ["--nope"])
    assert proc.returncode == 2
    assert "unknown flag" in proc.stderr
    assert stub_cmds(log) == []


def test_make_jwt_refuses_dest_symlink(tmp_path: Path):
    jwt_dir = tmp_path / "data" / "jwt"
    jwt_dir.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_text("untouched\n", encoding="utf-8")
    (jwt_dir / "jwt.hex").symlink_to(victim)
    proc = source_genesis(tmp_path, "make_jwt")
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"
    assert_no_secret(proc)


def test_make_jwt_does_not_follow_pid_tmp_symlink(tmp_path: Path):
    jwt_dir = tmp_path / "data" / "jwt"
    jwt_dir.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_text("untouched\n", encoding="utf-8")
    planted = jwt_dir / f"jwt.hex.tmp.{os.getpid()}"
    planted.symlink_to(victim)
    proc = source_genesis(tmp_path, "make_jwt")
    assert proc.returncode == 0, proc.stderr
    jwt = jwt_dir / "jwt.hex"
    assert jwt.is_file()
    assert not jwt.is_symlink()
    assert re.fullmatch(r"[0-9a-f]{64}", jwt.read_text(encoding="utf-8").strip())
    assert (jwt.stat().st_mode & 0o777) == 0o600
    assert victim.read_text(encoding="utf-8") == "untouched\n"
    assert planted.is_symlink()
    assert_no_secret(proc)


def test_data_dir_symlink_exits_2(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    data = tmp_path / "data"
    data.symlink_to(real)
    proc, log = run_genesis(tmp_path)
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert stub_cmds(log) == []


@pytest.mark.skipif(
    not _live_genesis_available(),
    reason="pinned IMG_GENESIS not present (1.2 owns the pull)",
)
def test_live_generator_assert_config(tmp_path: Path):
    docker = shutil.which("docker")
    assert docker is not None
    env = genesis_env(tmp_path, docker=Path(docker))
    proc = subprocess.run(
        ["bash", str(GENESIS)],
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    data = tmp_path / "data"
    config = (data / "genesis" / "config.yaml").read_text(encoding="utf-8")
    assert yaml_has(config, "SLOT_DURATION_MS", "12000"), config
    assert yaml_has(config, "PRESET_BASE", "mainnet"), config
    assert yaml_has(config, "ELECTRA_FORK_EPOCH", "0"), config
    values = (data / "genesis" / "values.env").read_text(encoding="utf-8")
    assert values.count("SLOTS_PER_EPOCH") == 0
    assert "SLOT_DURATION_IN_SECONDS" not in values
    jwt = data / "jwt" / "jwt.hex"
    assert re.fullmatch(r"[0-9a-f]{64}", jwt.read_text(encoding="utf-8").strip())
    assert (jwt.stat().st_mode & 0o777) == 0o600
    assert jwt.stat().st_uid == os.getuid()
    assert (data / "genesis" / "genesis_validators_root.txt").is_file()
    assert (data / "genesis" / "genesis.ssz").is_file()
    assert (data / "genesis" / "deploy_block.txt").read_text(encoding="utf-8") == "0\n"
    jwt_mtime = jwt.stat().st_mtime
    ssz_mtime = (data / "genesis" / "genesis.ssz").stat().st_mtime
    proc2 = subprocess.run(
        ["bash", str(GENESIS)],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
        stdin=subprocess.DEVNULL,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert jwt.stat().st_mtime == jwt_mtime
    assert (data / "genesis" / "genesis.ssz").stat().st_mtime == ssz_mtime
    jwtsecret = data / "genesis" / "jwt" / "jwtsecret"
    if jwtsecret.is_file():
        assert not jwtsecret.is_symlink()
        assert (jwtsecret.stat().st_mode & 0o777) == 0o600
    mnemonics = data / "genesis" / "metadata" / "mnemonics.yaml"
    if mnemonics.is_file():
        assert (mnemonics.stat().st_mode & 0o777) == 0o600
    assert "+ echo -n 0x" not in proc.stderr
    gen_log = data / "genesis" / "generator.log"
    if gen_log.is_file():
        log_text = gen_log.read_text(encoding="utf-8", errors="replace")
        assert _MNEMONIC not in log_text
        assert (gen_log.stat().st_mode & 0o777) == 0o600
