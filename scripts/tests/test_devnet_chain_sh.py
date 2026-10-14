"""Contract tests for scripts/devnet/03-chain.sh (1.5a EL+BN, 1.5b VC).

DOCKER/CURL stubs are scratch scripts (P1-A8); disable_socket() via conftest.
Live chain is skipped unless DEVNET_LIVE=1 and the pinned images are present.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import time
from collections import Counter
from pathlib import Path

import pytest

from test_devnet_env import ENV_PATH, parse_env

CHAIN = Path(__file__).resolve().parents[1] / "devnet" / "03-chain.sh"
KEYS = Path(__file__).resolve().parents[1] / "devnet" / "02-keys.sh"
GENESIS = Path(__file__).resolve().parents[1] / "devnet" / "01-genesis.sh"

_ENV = parse_env(ENV_PATH)
_N = int(_ENV["NUM_VALIDATORS"])
_K = int(_ENV["RVC_KEYS"])
_VC = _N - _K
_DEV_ACCOUNT = _ENV["DEV_ACCOUNT"]
_ZERO_ACCOUNT = "0x" + "0" * 40

_INVENTORY_ONCE = {
    ("network", "eth-devnet-network"): 1,
    ("container", "eth-devnet-geth"): 1,
    ("container", "eth-devnet-beacon"): 1,
    ("container", "eth-devnet-validator"): 1,
    ("datadir", "el"): 1,
    ("datadir", "cl"): 1,
    ("datadir", "validator"): 1,
}

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
    "IMG_GETH",
    "IMG_LIGHTHOUSE",
    "IMG_GENESIS",
    "CHAIN_WAIT_ATTEMPTS",
    "CHAIN_WAIT_SLEEP",
    "BEACON_TESTNET_DIR",
    "VC_KEYS_SRC",
    "RVC_KEYS",
    "CURL_HEALTH_CODE",
    "CURL_HEAD_SLOT",
    "CURL_SYNC_DISTANCE",
    "CURL_SECONDS_PER_SLOT",
    "CURL_CURRENT_VERSION",
    "CURL_CHAIN_ID_RESULT",
    "DEV_ACCOUNT",
    "NUM_VALIDATORS",
)

_MNEMONIC = "test test test test test test test test test test test junk"
_GVR = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_GVR_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_JWT = "ab" * 32


def write_docker_stub(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "docker.log"
    state = tmp_path / "docker-state"
    state.mkdir()
    stub = tmp_path / "docker"
    stub.write_text(
        "#!/bin/sh\n"
        f"log={shlex.quote(str(log))}\n"
        f"state={shlex.quote(str(state))}\n"
        "running=\"$state/running\"\n"
        "all=\"$state/all\"\n"
        "networks=\"$state/networks\"\n"
        "touch \"$running\" \"$all\" \"$networks\"\n"
        "printf '%s\\n' \"$*\" >> \"$log\"\n"
        "cmd=\"$1\"\n"
        "shift || true\n"
        "dump_inv() {\n"
        "  printf 'INV_BEFORE\\n' >> \"$log\"\n"
        "  if [ -n \"${RUN_DIR:-}\" ] && [ -f \"$RUN_DIR/inventory.json\" ]; then\n"
        "    cat \"$RUN_DIR/inventory.json\" >> \"$log\"\n"
        "  fi\n"
        "  printf 'INV_END\\n' >> \"$log\"\n"
        "}\n"
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
        "    allflag=0\n"
        "    for a in \"$@\"; do\n"
        "      if [ \"$a\" = \"-a\" ]; then allflag=1; fi\n"
        "    done\n"
        "    if [ \"$allflag\" -eq 1 ]; then cat \"$all\"; else cat \"$running\"; fi\n"
        "    exit 0\n"
        "    ;;\n"
        "  network)\n"
        "    sub=\"${1:-}\"\n"
        "    shift || true\n"
        "    case \"$sub\" in\n"
        "      ls)\n"
        "        cat \"$networks\"\n"
        "        exit 0\n"
        "        ;;\n"
        "      create)\n"
        "        dump_inv\n"
        "        printf '%s\\n' \"$1\" >> \"$networks\"\n"
        "        exit 0\n"
        "        ;;\n"
        "      rm)\n"
        "        remove_name \"$1\" \"$networks\"\n"
        "        exit 0\n"
        "        ;;\n"
        "    esac\n"
        "    exit 0\n"
        "    ;;\n"
        "  run)\n"
        "    dump_inv\n"
        "    name=\"\"\n"
        "    detached=0\n"
        "    is_init=0\n"
        "    is_vc=0\n"
        "    prev=\"\"\n"
        "    for a in \"$@\"; do\n"
        "      if [ \"$prev\" = \"--name\" ]; then name=\"$a\"; fi\n"
        "      case \"$a\" in\n"
        "        --name=*) name=\"${a#--name=}\" ;;\n"
        "        -d|--detach) detached=1 ;;\n"
        "        init) is_init=1 ;;\n"
        "        validator_client) is_vc=1 ;;\n"
        "      esac\n"
        "      prev=\"$a\"\n"
        "    done\n"
        "    if [ \"$is_init\" -eq 1 ] && [ -n \"${EL_DATA_DIR:-}\" ]; then\n"
        "      mkdir -p \"$EL_DATA_DIR/geth/chaindata\"\n"
        "    fi\n"
        "    if [ -n \"$name\" ]; then\n"
        "      printf '%s\\n' \"$name\" >> \"$all\"\n"
        "      if [ \"$detached\" -eq 1 ]; then\n"
        "        printf '%s\\n' \"$name\" >> \"$running\"\n"
        "      fi\n"
        "    fi\n"
        "    if [ \"${is_vc:-0}\" -eq 1 ] && [ -n \"${DATA_DIR:-}\" ]; then\n"
        "      vdir=\"$DATA_DIR/cl/validator/validators\"\n"
        "      defs=\"$vdir/validator_definitions.yml\"\n"
        "      if [ -d \"$vdir\" ] && [ ! -f \"$defs\" ]; then\n"
        "        printf '%s\\n' '---' > \"$defs\"\n"
        "        for d in \"$vdir\"/0x*; do\n"
        "          if [ -d \"$d\" ]; then\n"
        "            printf -- '- voting_public_key: %s\\n' \"$(basename \"$d\")\" >> \"$defs\"\n"
        "          fi\n"
        "        done\n"
        "      fi\n"
        "    fi\n"
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
        "  logs)\n"
        "    printf 'stub logs for %s\\n' \"$*\"\n"
        "    if [ -n \"${MNEMONIC:-}\" ]; then\n"
        "      printf 'leak-mnemonic %s\\n' \"$MNEMONIC\"\n"
        "    fi\n"
        "    printf 'leak-jwt aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n'\n"
        "    printf 'password=stubVcPasswordTokenValue\\n'\n"
        "    printf 'b64 dGVzdHBhc3N3b3JkMTIzNDU2Nzg5MDEyMzQ1\\n'\n"
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def write_curl_stub(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "curl.log"
    stub = tmp_path / "curl"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "args=\"$*\"\n"
        "case \"$args\" in\n"
        "  *eth_chainId*)\n"
        "    printf '%s\\n' \"{\\\"jsonrpc\\\":\\\"2.0\\\",\\\"result\\\":\\\"${CURL_CHAIN_ID_RESULT:-0x539}\\\",\\\"id\\\":1}\"\n"
        "    exit 0\n"
        "    ;;\n"
        "  *node/health*)\n"
        "    printf '%s' \"${CURL_HEALTH_CODE:-206}\"\n"
        "    exit 0\n"
        "    ;;\n"
        "  *node/syncing*)\n"
        "    printf '%s\\n' \"{\\\"data\\\":{\\\"head_slot\\\":\\\"${CURL_HEAD_SLOT:-0}\\\",\\\"sync_distance\\\":\\\"${CURL_SYNC_DISTANCE:-2}\\\",\\\"is_syncing\\\":true,\\\"is_optimistic\\\":false,\\\"el_offline\\\":false}}\"\n"
        "    exit 0\n"
        "    ;;\n"
        "  *config/spec*)\n"
        "    printf '%s\\n' \"{\\\"data\\\":{\\\"SECONDS_PER_SLOT\\\":\\\"${CURL_SECONDS_PER_SLOT:-12}\\\",\\\"ELECTRA_FORK_VERSION\\\":\\\"${ELECTRA_FORK_VERSION:-0x60000000}\\\"}}\"\n"
        "    exit 0\n"
        "    ;;\n"
        "  *states/head/fork*)\n"
        "    printf '%s\\n' \"{\\\"data\\\":{\\\"previous_version\\\":\\\"${CURL_CURRENT_VERSION:-0x60000000}\\\",\\\"current_version\\\":\\\"${CURL_CURRENT_VERSION:-0x60000000}\\\",\\\"epoch\\\":\\\"0\\\"}}\"\n"
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "printf '%s\\n' '{\"error\":\"unscripted curl\"}' >&2\n"
        "exit 1\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def pubkey(i: int) -> str:
    return f"0x{i:096x}"


def seed_keys(data: Path, n: int | None = None, *, root: Path | None = None) -> Path:
    n = _VC if n is None else n
    src = root if root is not None else (data / "keys" / "vc")
    validators = src / "validators"
    secrets = src / "secrets"
    validators.mkdir(parents=True, exist_ok=True)
    secrets.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        pk = pubkey(i)
        d = validators / pk
        d.mkdir(exist_ok=True)
        ks = d / "voting-keystore.json"
        ks.write_text(
            '{"crypto":{"kdf":{"params":{"c":262144}}}}\n', encoding="utf-8"
        )
        ks.chmod(0o600)
        sec = secrets / pk
        sec.write_text(f"secret-{i}\n", encoding="utf-8")
        sec.chmod(0o600)
    return src


def seed_rvc_pubkeys(data: Path) -> Path:
    rvc = data / "keys" / "rvc"
    rvc.mkdir(parents=True, exist_ok=True)
    lines = [pubkey(i) + "\n" for i in range(_VC, _N)]
    path = rvc / "pubkeys.txt"
    path.write_text("".join(lines), encoding="utf-8")
    path.chmod(0o600)
    return path


def seed_genesis(data: Path, *, keys: bool = True) -> None:
    jwt = data / "jwt"
    genesis = data / "genesis"
    jwt.mkdir(parents=True, exist_ok=True)
    genesis.mkdir(parents=True, exist_ok=True)
    (jwt / "jwt.hex").write_text(_JWT, encoding="utf-8")
    (jwt / "jwt.hex").chmod(0o600)
    (genesis / "genesis.json").write_text("{}\n", encoding="utf-8")
    (genesis / "genesis.ssz").write_bytes(b"ssz")
    (genesis / "config.yaml").write_text(
        "PRESET_BASE: 'mainnet'\nSLOT_DURATION_MS: 12000\nELECTRA_FORK_EPOCH: 0\n",
        encoding="utf-8",
    )
    (genesis / "genesis_validators_root.txt").write_text(_GVR + "\n", encoding="utf-8")
    if keys:
        seed_keys(data)
        seed_rvc_pubkeys(data)


def chain_env(
    tmp_path: Path,
    extra: dict[str, str] | None = None,
    *,
    docker: Path | None = None,
    curl: Path | None = None,
) -> dict[str, str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full["DOCKER"] = str(docker or (tmp_path / "docker"))
    full["CURL"] = str(curl or (tmp_path / "curl"))
    full["DATA_DIR"] = str(tmp_path / "data")
    full["RUNS_DIR"] = str(tmp_path / "runs")
    full["RUN_DIR"] = str(tmp_path / "run")
    full["CHAIN_WAIT_ATTEMPTS"] = "1"
    full["CHAIN_WAIT_SLEEP"] = "0"
    if extra:
        full.update(extra)
    return full


def run_chain(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    env: dict[str, str] | None = None,
    timeout: float = 20,
    docker: Path | None = None,
    curl: Path | None = None,
    log: Path | None = None,
    seed: bool = True,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    if docker is None:
        stub, log_path = write_docker_stub(tmp_path)
    else:
        stub = docker
        log_path = log or (tmp_path / "docker.log")
    if curl is None:
        curl_stub, _ = write_curl_stub(tmp_path)
    else:
        curl_stub = curl
    if seed:
        seed_genesis(tmp_path / "data")
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    full = chain_env(tmp_path, env, docker=stub, curl=curl_stub)
    proc = subprocess.run(
        ["bash", str(CHAIN), "--run-dir", str(run_dir), *args],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return proc, log_path


def source_chain(
    tmp_path: Path,
    snippet: str,
    *,
    env: dict[str, str] | None = None,
    timeout: float = 10,
) -> subprocess.CompletedProcess[str]:
    write_docker_stub(tmp_path)
    write_curl_stub(tmp_path)
    seed_genesis(tmp_path / "data")
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    full = chain_env(tmp_path, env)
    return subprocess.run(
        ["bash", "-c", f"source {shlex.quote(str(CHAIN))}; {snippet}"],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )


def stub_cmds(log: Path) -> list[str]:
    if not log.is_file():
        return []
    return [
        line
        for line in log.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("INV_")
        and not line.startswith("{")
        and line != "INV_END"
        and line != "INV_BEFORE"
    ]


def run_cmds(cmds: list[str]) -> list[str]:
    return [c for c in cmds if c.startswith("run ")]


def detach_cmds(cmds: list[str]) -> list[str]:
    return [c for c in run_cmds(cmds) if " -d " in f" {c} "]


def named_cmds(cmds: list[str], name: str) -> list[str]:
    needle = f"--name {name}"
    eq = f"--name={name}"
    return [c for c in cmds if needle in c or eq in c]


def inventory_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def inventory_at_cmd(log: Path, predicate) -> list[dict[str, str]] | None:
    lines = log.read_text(encoding="utf-8").splitlines() if log.is_file() else []
    i = 0
    while i < len(lines):
        line = lines[i]
        if predicate(line):
            j = i + 1
            while j < len(lines) and lines[j] != "INV_BEFORE":
                j += 1
            if j >= len(lines):
                return None
            rows: list[dict[str, str]] = []
            j += 1
            while j < len(lines) and lines[j] != "INV_END":
                if lines[j].strip():
                    rows.append(json.loads(lines[j]))
                j += 1
            return rows
        i += 1
    return None


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob
    assert _JWT not in blob


def named_kinds(rows: list[dict[str, str]]) -> set[tuple[str, str]]:
    return {(r["kind"], r["name"]) for r in rows}


def inventory_counts(rows: list[dict[str, str]]) -> Counter[tuple[str, str]]:
    return Counter((r["kind"], r["name"]) for r in rows)


def file_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def vc_cmd(cmds: list[str]) -> str:
    found = [c for c in cmds if "validator_client" in c]
    assert found, cmds
    return found[0]


def validator_dirs(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    return sorted(p for p in root.glob("0x*") if p.is_dir())


def stop_stub_container(tmp_path: Path, name: str) -> None:
    running = tmp_path / "docker-state" / "running"
    lines = [
        ln
        for ln in running.read_text(encoding="utf-8").splitlines()
        if ln != name
    ]
    running.write_text(("\n".join(lines) + "\n") if lines else "", encoding="utf-8")


def slashing_db(tmp_path: Path) -> Path:
    return (
        tmp_path
        / "data"
        / "cl"
        / "validator"
        / "validators"
        / "slashing_protection.sqlite"
    )


def test_chain_sh_exists_and_syntax():
    assert CHAIN.is_file(), CHAIN
    proc = subprocess.run(
        ["bash", "-n", str(CHAIN)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = CHAIN.read_text(encoding="utf-8")
    assert re.search(r"(?m)^\s*read\s", text) is None
    assert "read -p" not in text
    assert "source" in text and "lib/common.sh" in text
    assert "start_geth()" in text
    assert "start_beacon()" in text
    assert "copy_vc_keys()" in text
    assert "start_vc()" in text
    assert "wait_for_chain()" in text
    assert "assert_head_fork_electra()" in text
    assert "docker_run_as_user" in text
    assert "inventory_append" in text
    assert "capture_container_logs" in text
    assert "--nodiscover" in text
    assert "--syncmode=full" in text
    assert "--gcmode=archive" in text
    assert "--subscribe-all-subnets" in text
    assert "--metrics" in text
    assert "--testnet-dir=" in text
    assert "--execution-endpoint=" in text
    assert "${GETH_CONTAINER}:8551" in text
    assert "127.0.0.1:${EL_RPC_PORT}:8545" in text
    assert "127.0.0.1:${CL_HTTP_PORT}:5052" in text
    assert "127.0.0.1:${CL_METRICS_PORT}:5054" in text
    assert "127.0.0.1:${EL_AUTH_PORT}:8551" not in text
    assert "--slots-per-restore-point" not in text
    assert "validator_client" in text
    assert "--suggested-fee-recipient=" in text
    assert "--init-slashing-protection" in text
    assert "VC_KEYS_SRC=" in text
    assert "_bind_chain_paths" in text
    assert "${KEYS_DIR}/vc" in text
    assert "${KEYS_DIR}/valtools" not in text
    assert "--validators-dir" not in text
    assert "_reset_vc_datadir" in text
    assert "_prune_unlisted_vc_keys" in text
    assert "_vc_datadir_contains_rvc" in text
    assert "_refuse_symlink_parents" in text
    assert "pubkeys.txt" in text
    assert "${CL_DATA_DIR}/validator" in text
    assert "data/keys/vc" in text
    assert "head_slot + sync_distance" in text or "head_slot+sync_distance" in text
    assert re.search(r'(?m)^\s*docker\s', text) is None
    assert re.search(r'(?m)^\s*curl\s', text) is None
    assert '"$DOCKER"' in text
    assert '"$CURL"' in text


def test_inventory_appended_before_create(tmp_path: Path):
    proc, log = run_chain(tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    run_dir = tmp_path / "run"
    rows = inventory_rows(run_dir / "inventory.json")
    kinds = named_kinds(rows)
    assert ("network", "eth-devnet-network") in kinds
    assert ("container", "eth-devnet-geth") in kinds
    assert ("container", "eth-devnet-beacon") in kinds
    assert ("container", "eth-devnet-validator") in kinds
    assert ("datadir", "el") in kinds
    assert ("datadir", "cl") in kinds
    assert ("datadir", "validator") in kinds
    el = next(r for r in rows if r["kind"] == "datadir" and r["name"] == "el")
    cl = next(r for r in rows if r["kind"] == "datadir" and r["name"] == "cl")
    vc_dir = next(r for r in rows if r["kind"] == "datadir" and r["name"] == "validator")
    assert el["path"].endswith("/el")
    assert cl["path"].endswith("/cl")
    assert vc_dir["path"].endswith("/cl/validator") or vc_dir["path"].endswith(
        "/cl/validator/"
    )

    net_inv = inventory_at_cmd(log, lambda c: c.startswith("network create "))
    assert net_inv is not None
    assert ("network", "eth-devnet-network") in named_kinds(net_inv)

    geth_inv = inventory_at_cmd(
        log,
        lambda c: c.startswith("run ") and "eth-devnet-geth" in c and " init " not in f" {c} ",
    )
    if geth_inv is None:
        geth_inv = inventory_at_cmd(log, lambda c: c.startswith("run ") and " init " in f" {c} ")
    assert geth_inv is not None
    geth_kinds = named_kinds(geth_inv)
    assert ("container", "eth-devnet-geth") in geth_kinds
    assert ("datadir", "el") in geth_kinds

    bn_inv = inventory_at_cmd(
        log, lambda c: c.startswith("run ") and "beacon_node" in c
    )
    assert bn_inv is not None
    bn_kinds = named_kinds(bn_inv)
    assert ("datadir", "cl") in bn_kinds
    assert ("network", "eth-devnet-network") in bn_kinds

    vc_inv = inventory_at_cmd(
        log, lambda c: c.startswith("run ") and "validator_client" in c
    )
    assert vc_inv is not None, log.read_text(encoding="utf-8")
    vc_kinds = named_kinds(vc_inv)
    assert ("container", "eth-devnet-validator") in vc_kinds
    assert ("datadir", "validator") in vc_kinds
    cmds = stub_cmds(log)
    create_idx = next(i for i, c in enumerate(cmds) if c.startswith("network create "))
    # inventory_append is a bash-side write; the stub snapshot at create proves the row existed.
    assert create_idx >= 0
    vc_run_idx = next(i for i, c in enumerate(cmds) if "validator_client" in c)
    assert vc_run_idx > create_idx


def test_force_recreates_both_containers(tmp_path: Path):
    proc1, log = run_chain(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    first = stub_cmds(log)
    first_detach = detach_cmds(first)
    assert named_cmds(first_detach, "eth-devnet-geth")
    assert named_cmds(first_detach, "eth-devnet-beacon")
    assert named_cmds(first_detach, "eth-devnet-validator")
    first_inits = [c for c in first if c.startswith("run ") and " init " in f" {c} "]
    assert len(first_inits) == 1

    proc2, _ = run_chain(
        tmp_path,
        ["--force"],
        docker=tmp_path / "docker",
        curl=tmp_path / "curl",
        log=log,
        seed=False,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert_no_secret(proc2)
    cmds = stub_cmds(log)
    rms = [c for c in cmds if c.startswith("rm ")]
    assert any("eth-devnet-geth" in c for c in rms)
    assert any("eth-devnet-beacon" in c for c in rms)
    assert any("eth-devnet-validator" in c for c in rms)
    detach = detach_cmds(cmds)
    geth_d = named_cmds(detach, "eth-devnet-geth")
    bn_d = named_cmds(detach, "eth-devnet-beacon")
    vc_d = named_cmds(detach, "eth-devnet-validator")
    assert len(geth_d) == 2, geth_d
    assert len(bn_d) == 2, bn_d
    assert len(vc_d) == 2, vc_d
    inits = [c for c in cmds if c.startswith("run ") and " init " in f" {c} "]
    assert len(inits) == 1
    rows = inventory_rows(tmp_path / "run" / "inventory.json")
    assert inventory_counts(rows) == _INVENTORY_ONCE


def test_second_run_with_both_running_is_noop(tmp_path: Path):
    proc1, log = run_chain(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    first = stub_cmds(log)
    proc2, _ = run_chain(
        tmp_path,
        docker=tmp_path / "docker",
        curl=tmp_path / "curl",
        log=log,
        seed=False,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert_no_secret(proc2)
    assert "already running" in proc2.stderr
    second = stub_cmds(log)
    assert run_cmds(second) == run_cmds(first)
    assert [c for c in second if c.startswith("network create ")] == [
        c for c in first if c.startswith("network create ")
    ]
    assert inventory_counts(inventory_rows(tmp_path / "run" / "inventory.json")) == (
        _INVENTORY_ONCE
    )


def test_wrong_testnet_dir_exits_1_with_logs_and_inventory(tmp_path: Path):
    proc, log = run_chain(
        tmp_path,
        env={
            "BEACON_TESTNET_DIR": "/wrong",
            "CURL_HEALTH_CODE": "503",
        },
    )
    assert proc.returncode == 1, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    beacon_log = tmp_path / "run" / "logs" / "eth-devnet-beacon.log"
    assert beacon_log.is_file(), proc.stderr
    log_text = beacon_log.read_text(encoding="utf-8")
    assert "stub logs" in log_text
    assert _MNEMONIC not in log_text
    assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" not in log_text
    assert "stubVcPasswordTokenValue" not in log_text
    assert "dGVzdHBhc3N3b3JkMTIzNDU2Nzg5MDEyMzQ1" not in log_text
    assert "<redacted>" in log_text
    rows = inventory_rows(tmp_path / "run" / "inventory.json")
    kinds = named_kinds(rows)
    assert ("network", "eth-devnet-network") in kinds
    assert ("container", "eth-devnet-geth") in kinds
    assert ("datadir", "el") in kinds
    assert ("datadir", "cl") in kinds
    cmds = stub_cmds(log)
    bn = [c for c in cmds if c.startswith("run ") and "beacon_node" in c]
    assert bn, cmds
    assert "--testnet-dir=/wrong" in bn[0]
    assert "--slots-per-restore-point" not in bn[0]


def test_missing_genesis_exits_2(tmp_path: Path):
    proc, log = run_chain(tmp_path, seed=False)
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "01-genesis.sh" in proc.stderr
    assert stub_cmds(log) == []


def test_chain_id_1_exits_2(tmp_path: Path):
    proc, log = run_chain(tmp_path, env={"CHAIN_ID": "1"})
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "1337" in proc.stderr
    assert stub_cmds(log) == []
    assert_no_secret(proc)


def test_dry_run_exits_0_without_docker_run(tmp_path: Path):
    proc, log = run_chain(tmp_path, ["--dry-run"])
    assert proc.returncode == 0, proc.stderr
    assert run_cmds(stub_cmds(log)) == []
    assert "chain plan" in proc.stderr
    assert "start_geth" in proc.stderr
    assert "copy_vc_keys" in proc.stderr
    assert "start_vc" in proc.stderr
    assert_no_secret(proc)


def test_geth_and_beacon_use_docker_run_as_user(tmp_path: Path):
    proc, log = run_chain(tmp_path)
    assert proc.returncode == 0, proc.stderr
    uid = os.getuid()
    gid = os.getgid()
    prefix = f"run -u {uid}:{gid}"
    cmds = run_cmds(stub_cmds(log))
    assert cmds
    assert all(c.startswith(prefix) for c in cmds), cmds
    geth = named_cmds(detach_cmds(cmds), "eth-devnet-geth")
    bn = [c for c in cmds if "beacon_node" in c]
    vc = vc_cmd(cmds)
    assert geth
    assert "--nodiscover" in geth[0]
    assert "--syncmode=full" in geth[0]
    assert "--gcmode=archive" in geth[0]
    assert "--authrpc.jwtsecret=/jwt/jwt.hex" in geth[0]
    assert bn
    assert "--metrics" in bn[0]
    assert "--subscribe-all-subnets" in bn[0]
    assert "--execution-endpoint=http://eth-devnet-geth:8551" in bn[0]
    assert "--testnet-dir=/genesis" in bn[0]
    assert "--slots-per-restore-point" not in bn[0]
    assert "127.0.0.1:8545:8545" in geth[0]
    assert "127.0.0.1:8551:8551" not in geth[0]
    assert " -p 8551:" not in f" {geth[0]} "
    assert "127.0.0.1:5052:5052" in bn[0]
    assert "127.0.0.1:5054:5054" in bn[0]
    assert "--init-slashing-protection" in vc
    assert f"--suggested-fee-recipient={_DEV_ACCOUNT}" in vc
    assert "--beacon-nodes=http://eth-devnet-beacon:5052" in vc
    assert "--testnet-dir=/genesis" in vc
    assert " -p " not in f" {vc} "
    img = parse_env(ENV_PATH)
    assert img["IMG_GETH"] in geth[0]
    assert img["IMG_LIGHTHOUSE"] in bn[0]
    assert img["IMG_LIGHTHOUSE"] in vc


def test_assert_head_fork_electra_rejects_fulu(tmp_path: Path):
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; resolve_run_dir >/dev/null; "
        "assert_head_fork_electra",
        env={"CURL_CURRENT_VERSION": "0x70000000"},
    )
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "0x70000000" in proc.stderr
    assert "ELECTRA_FORK_VERSION" in proc.stderr
    beacon_log = tmp_path / "run" / "logs" / "eth-devnet-beacon.log"
    assert beacon_log.is_file()


def test_assert_head_fork_electra_rejects_wrong_seconds(tmp_path: Path):
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; resolve_run_dir >/dev/null; "
        "assert_head_fork_electra",
        env={"CURL_SECONDS_PER_SLOT": "6"},
    )
    assert proc.returncode == 1
    assert "SECONDS_PER_SLOT" in proc.stderr
    assert "6" in proc.stderr


def test_unknown_flag_exits_2(tmp_path: Path):
    proc, log = run_chain(tmp_path, ["--nope"])
    assert proc.returncode == 2
    assert "unknown flag" in proc.stderr
    assert stub_cmds(log) == []


def test_health_206_clock_slot_zero_head_passes(tmp_path: Path):
    """Live BN-only path: health 206, canonical head_slot=0, clock = sync_distance."""
    proc, _ = run_chain(
        tmp_path,
        env={
            "CURL_HEALTH_CODE": "206",
            "CURL_HEAD_SLOT": "0",
            "CURL_SYNC_DISTANCE": "2",
        },
    )
    assert proc.returncode == 0, proc.stderr
    assert "clock slot > 1" in proc.stderr
    assert_no_secret(proc)


def test_clock_slot_not_advanced_exits_1(tmp_path: Path):
    proc, _ = run_chain(
        tmp_path,
        env={
            "CURL_HEALTH_CODE": "206",
            "CURL_HEAD_SLOT": "0",
            "CURL_SYNC_DISTANCE": "1",
        },
    )
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "clock slot" in proc.stderr
    beacon_log = tmp_path / "run" / "logs" / "eth-devnet-beacon.log"
    assert beacon_log.is_file()


def test_gvr_mismatch_without_force_exits_2(tmp_path: Path):
    seed_genesis(tmp_path / "data")
    el = tmp_path / "data" / "el"
    el.mkdir()
    (el / "genesis_validators_root.txt").write_text(_GVR_B + "\n", encoding="utf-8")
    (el / "geth" / "chaindata").mkdir(parents=True)
    proc, log = run_chain(tmp_path, seed=False)
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "--force" in proc.stderr
    assert "GVR" in proc.stderr
    assert run_cmds(stub_cmds(log)) == []


def test_force_mismatched_gvr_reinits_geth(tmp_path: Path):
    proc1, log = run_chain(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    el_gvr = tmp_path / "data" / "el" / "genesis_validators_root.txt"
    assert el_gvr.read_text(encoding="utf-8").strip() == _GVR
    el_gvr.write_text(_GVR_B + "\n", encoding="utf-8")
    proc2, _ = run_chain(
        tmp_path,
        ["--force"],
        docker=tmp_path / "docker",
        curl=tmp_path / "curl",
        log=log,
        seed=False,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert el_gvr.read_text(encoding="utf-8").strip() == _GVR
    inits = [c for c in stub_cmds(log) if c.startswith("run ") and " init " in f" {c} "]
    assert len(inits) == 2, inits


def test_matching_gvr_stamp_is_not_overwritten(tmp_path: Path):
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; "
        "mkdir -p \"$EL_DATA_DIR\"; "
        "printf '%s\\n' '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' "
        "> \"$EL_DATA_DIR/genesis_validators_root.txt\"; "
        "_stamp_gvr \"$EL_DATA_DIR\"; "
        "cat \"$EL_DATA_DIR/genesis_validators_root.txt\"",
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def test_jwt_symlink_exits_2(tmp_path: Path):
    seed_genesis(tmp_path / "data")
    jwt = tmp_path / "data" / "jwt" / "jwt.hex"
    victim = tmp_path / "victim"
    victim.write_text("untouched\n", encoding="utf-8")
    jwt.unlink()
    jwt.symlink_to(victim)
    proc, log = run_chain(tmp_path, seed=False)
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"
    assert stub_cmds(log) == []


def test_jwt_mode_0644_exits_2(tmp_path: Path):
    seed_genesis(tmp_path / "data")
    jwt = tmp_path / "data" / "jwt" / "jwt.hex"
    jwt.chmod(0o644)
    proc, log = run_chain(tmp_path, seed=False)
    assert proc.returncode == 2
    assert "0600" in proc.stderr
    assert stub_cmds(log) == []


def test_host_binds_loopback_and_skips_authrpc_publish(tmp_path: Path):
    proc, log = run_chain(tmp_path)
    assert proc.returncode == 0, proc.stderr
    cmds = run_cmds(stub_cmds(log))
    geth = named_cmds(detach_cmds(cmds), "eth-devnet-geth")
    bn = [c for c in cmds if "beacon_node" in c]
    vc = vc_cmd(cmds)
    assert geth and bn
    assert "-p 127.0.0.1:8545:8545" in geth[0]
    assert "8551:8551" not in geth[0]
    assert "-p 127.0.0.1:5052:5052" in bn[0]
    assert "-p 127.0.0.1:5054:5054" in bn[0]
    assert " -p " not in f" {vc} "


def test_vc_row_appended_before_run(tmp_path: Path):
    proc, log = run_chain(tmp_path)
    assert proc.returncode == 0, proc.stderr
    vc_inv = inventory_at_cmd(
        log, lambda c: c.startswith("run ") and "validator_client" in c
    )
    assert vc_inv is not None
    kinds = named_kinds(vc_inv)
    assert ("container", "eth-devnet-validator") in kinds
    assert ("datadir", "validator") in kinds


def test_vc_command_has_fee_recipient_and_slashing_protection(tmp_path: Path):
    proc, log = run_chain(tmp_path)
    assert proc.returncode == 0, proc.stderr
    vc = vc_cmd(run_cmds(stub_cmds(log)))
    assert "--init-slashing-protection" in vc
    match = re.search(r"--suggested-fee-recipient=(\S+)", vc)
    assert match, vc
    addr = match.group(1)
    assert re.fullmatch(r"0x[0-9a-fA-F]{40}", addr), addr
    assert addr.lower() != _ZERO_ACCOUNT
    assert addr == _DEV_ACCOUNT


def test_chain_adds_lh_dp_flag_under_safe(tmp_path: Path):
    proc_fast, log = run_chain(tmp_path)
    assert proc_fast.returncode == 0, proc_fast.stderr
    fast_vc = vc_cmd(run_cmds(stub_cmds(log)))
    assert "--enable-doppelganger-protection" not in fast_vc
    assert "--init-slashing-protection" in fast_vc
    assert f"--suggested-fee-recipient={_DEV_ACCOUNT}" in fast_vc

    proc_safe, _ = run_chain(
        tmp_path,
        ["--force", "--profile", "safe"],
        docker=tmp_path / "docker",
        curl=tmp_path / "curl",
        log=log,
        seed=False,
    )
    assert proc_safe.returncode == 0, proc_safe.stderr
    vcs = [c for c in run_cmds(stub_cmds(log)) if "validator_client" in c]
    assert len(vcs) >= 2, vcs
    assert "--enable-doppelganger-protection" not in vcs[0]
    assert "--enable-doppelganger-protection" in vcs[-1]
    assert "--init-slashing-protection" in vcs[-1]



def test_copy_vc_keys_count_and_owner(tmp_path: Path):
    proc, _ = run_chain(tmp_path)
    assert proc.returncode == 0, proc.stderr
    dest = tmp_path / "data" / "cl" / "validator" / "validators"
    dirs = validator_dirs(dest)
    assert len(dirs) == _VC
    uid = os.getuid()
    for d in dirs:
        assert d.stat().st_uid == uid
        assert stat.S_ISDIR(d.stat().st_mode)
        ks = d / "voting-keystore.json"
        assert ks.is_file()
        assert not ks.is_symlink()
        assert ks.stat().st_uid == uid
        assert file_mode(ks) == 0o600
    secrets = tmp_path / "data" / "cl" / "validator" / "secrets"
    secs = sorted(p for p in secrets.glob("0x*") if p.is_file())
    assert len(secs) == _VC
    for s in secs:
        assert s.stat().st_uid == uid
        assert file_mode(s) == 0o600
        assert not s.is_symlink()
    dest_names = {d.name for d in dirs}
    rvc_pks = {
        ln
        for ln in (tmp_path / "data" / "keys" / "rvc" / "pubkeys.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if ln
    }
    assert dest_names.isdisjoint(rvc_pks)


def test_missing_keys_exits_2(tmp_path: Path):
    seed_genesis(tmp_path / "data", keys=False)
    proc, log = run_chain(tmp_path, seed=False)
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "data/keys/vc" in proc.stderr
    assert "02-keys.sh" in proc.stderr
    assert run_cmds(stub_cmds(log)) == []


def test_vc_keys_moved_away_exits_2(tmp_path: Path):
    seed_genesis(tmp_path / "data")
    vc = tmp_path / "data" / "keys" / "vc"
    away = tmp_path / "away-vc"
    vc.rename(away)
    proc, log = run_chain(tmp_path, seed=False)
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "data/keys/vc" in proc.stderr
    assert "02-keys.sh" in proc.stderr
    assert run_cmds(stub_cmds(log)) == []


def test_zero_fee_recipient_exits_2(tmp_path: Path):
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; resolve_run_dir >/dev/null; "
        f"DEV_ACCOUNT={shlex.quote(_ZERO_ACCOUNT)}; start_vc",
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "non-zero" in proc.stderr
    assert "validator_client" not in (tmp_path / "docker.log").read_text(
        encoding="utf-8"
    )


def test_resume_preserves_slashing_db_skips_init(tmp_path: Path):
    proc1, log = run_chain(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    db = slashing_db(tmp_path)
    extra = db.parent / "validator_definitions.yml"
    db.write_text("keep-slash-db\n", encoding="utf-8")
    extra.write_text("keep-defs\n", encoding="utf-8")
    stop_stub_container(tmp_path, "eth-devnet-validator")
    proc2, _ = run_chain(
        tmp_path,
        docker=tmp_path / "docker",
        curl=tmp_path / "curl",
        log=log,
        seed=False,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert db.is_file()
    assert not db.is_symlink()
    assert db.read_text(encoding="utf-8") == "keep-slash-db\n"
    assert extra.read_text(encoding="utf-8") == "keep-defs\n"
    vcs = [c for c in run_cmds(stub_cmds(log)) if "validator_client" in c]
    assert len(vcs) == 2, vcs
    assert "--init-slashing-protection" in vcs[0]
    assert "--init-slashing-protection" not in vcs[1]
    assert len(validator_dirs(db.parent)) == _VC


def test_used_datadir_missing_sqlite_exits_2(tmp_path: Path):
    dest = tmp_path / "data" / "cl" / "validator" / "validators"
    dest.mkdir(parents=True)
    (dest / "validator_definitions.yml").write_text("used-defs\n", encoding="utf-8")
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; resolve_run_dir >/dev/null; "
        "start_vc",
    )
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "--force" in proc.stderr
    log_text = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "validator_client" not in log_text
    assert "--init-slashing-protection" not in log_text
    assert (dest / "validator_definitions.yml").read_text(encoding="utf-8") == (
        "used-defs\n"
    )


def test_used_datadir_wal_without_sqlite_exits_2(tmp_path: Path):
    dest = tmp_path / "data" / "cl" / "validator" / "validators"
    dest.mkdir(parents=True)
    (dest / "slashing_protection.sqlite-wal").write_text("wal\n", encoding="utf-8")
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; resolve_run_dir >/dev/null; "
        "start_vc",
    )
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "--force" in proc.stderr
    log_text = (tmp_path / "docker.log").read_text(encoding="utf-8")
    assert "validator_client" not in log_text
    assert "--init-slashing-protection" not in log_text


def test_force_resets_vc_datadir_and_inits_slashing(tmp_path: Path):
    proc1, log = run_chain(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    db = slashing_db(tmp_path)
    db.write_text("old-slash-db\n", encoding="utf-8")
    defs = db.parent / "validator_definitions.yml"
    rvc_pk = pubkey(_N - 1)
    stale = defs.read_text(encoding="utf-8") if defs.is_file() else "---\n"
    defs.write_text(stale + f"- voting_public_key: {rvc_pk}\n", encoding="utf-8")
    proc2, _ = run_chain(
        tmp_path,
        ["--force"],
        docker=tmp_path / "docker",
        curl=tmp_path / "curl",
        log=log,
        seed=False,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert not db.exists()
    vcs = [c for c in run_cmds(stub_cmds(log)) if "validator_client" in c]
    assert len(vcs) == 2, vcs
    assert all("--init-slashing-protection" in c for c in vcs)
    assert len(validator_dirs(db.parent)) == _VC
    assert defs.is_file()
    text = defs.read_text(encoding="utf-8")
    assert text.count("voting_public_key:") == _VC
    rvc_pks = [
        ln
        for ln in (tmp_path / "data" / "keys" / "rvc" / "pubkeys.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if ln
    ]
    assert rvc_pks
    for pk in rvc_pks:
        assert pk not in text


def test_copy_vc_keys_refuses_dest_secret_symlink(tmp_path: Path):
    victim = tmp_path / "victim-secret"
    victim.write_text("untouched\n", encoding="utf-8")
    pk = pubkey(0)
    proc = source_chain(
        tmp_path,
        "mkdir -p \"$VALIDATOR_DATA_DIR/secrets\"; "
        f"ln -s {shlex.quote(str(victim))} \"$VALIDATOR_DATA_DIR/secrets/{pk}\"; "
        "copy_vc_keys",
    )
    assert proc.returncode == 2, proc.stderr
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"


def test_copy_vc_keys_refuses_dest_keystore_symlink(tmp_path: Path):
    victim = tmp_path / "victim-keystore"
    victim.write_text("untouched\n", encoding="utf-8")
    pk = pubkey(0)
    proc = source_chain(
        tmp_path,
        "mkdir -p \"$VALIDATOR_DATA_DIR/validators/" + pk + "\"; "
        f"ln -s {shlex.quote(str(victim))} "
        f"\"$VALIDATOR_DATA_DIR/validators/{pk}/voting-keystore.json\"; "
        "copy_vc_keys",
    )
    assert proc.returncode == 2, proc.stderr
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"


def test_copy_vc_keys_refuses_dest_parent_dir_symlink(tmp_path: Path):
    victim = tmp_path / "victim-keydir"
    victim.mkdir()
    (victim / "voting-keystore.json").write_text("stolen\n", encoding="utf-8")
    pk = pubkey(0)
    proc = source_chain(
        tmp_path,
        "mkdir -p \"$VALIDATOR_DATA_DIR/validators\"; "
        f"ln -s {shlex.quote(str(victim))} "
        f"\"$VALIDATOR_DATA_DIR/validators/{pk}\"; "
        "copy_vc_keys",
    )
    assert proc.returncode == 2, proc.stderr
    assert "symlink" in proc.stderr
    assert (victim / "voting-keystore.json").read_text(encoding="utf-8") == "stolen\n"


def test_copy_vc_keys_prunes_unlisted_dest(tmp_path: Path):
    extra_pk = pubkey(_N - 1)
    stray_pk = "0x" + "ee" * 48
    proc = source_chain(
        tmp_path,
        "copy_vc_keys; "
        f"mkdir -p \"$VALIDATOR_DATA_DIR/validators/{extra_pk}\" "
        f"\"$VALIDATOR_DATA_DIR/validators/{stray_pk}\"; "
        f"printf '{{}}\\n' > \"$VALIDATOR_DATA_DIR/validators/{extra_pk}/voting-keystore.json\"; "
        f"printf '{{}}\\n' > \"$VALIDATOR_DATA_DIR/validators/{stray_pk}/voting-keystore.json\"; "
        f"printf 'leftover-rvc\\n' > \"$VALIDATOR_DATA_DIR/secrets/{extra_pk}\"; "
        "copy_vc_keys",
    )
    assert proc.returncode == 0, proc.stderr
    dest = tmp_path / "data" / "cl" / "validator" / "validators"
    assert not (dest / extra_pk).exists()
    assert not (dest / stray_pk).exists()
    extra_sec = tmp_path / "data" / "cl" / "validator" / "secrets" / extra_pk
    assert not extra_sec.exists()
    assert len(validator_dirs(dest)) == _VC
    dest_names = {d.name for d in validator_dirs(dest)}
    assert extra_pk not in dest_names
    assert stray_pk not in dest_names


def test_copy_vc_keys_refuses_rvc_pubkey_in_definitions(tmp_path: Path):
    rvc_pk = pubkey(_N - 1)
    proc = source_chain(
        tmp_path,
        "copy_vc_keys; "
        "mkdir -p \"$VALIDATOR_DATA_DIR/validators\"; "
        f"printf '%s\\n' '- voting_public_key: {rvc_pk}' "
        "> \"$VALIDATOR_DATA_DIR/validators/validator_definitions.yml\"; "
        "copy_vc_keys",
    )
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "RVC" in proc.stderr or "rvc" in proc.stderr
    assert "--force" in proc.stderr
    assert "pubkeys.txt" in proc.stderr
    dest = tmp_path / "data" / "cl" / "validator" / "validators"
    defs = dest / "validator_definitions.yml"
    assert rvc_pk in defs.read_text(encoding="utf-8")
    assert len(validator_dirs(dest)) == _VC


def test_running_rvc_leftovers_refuse_without_noop(tmp_path: Path):
    proc1, log = run_chain(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    dest = tmp_path / "data" / "cl" / "validator" / "validators"
    rvc_pk = pubkey(_N - 1)
    extra = dest / rvc_pk
    extra.mkdir()
    (extra / "voting-keystore.json").write_text("{}\n", encoding="utf-8")
    defs = dest / "validator_definitions.yml"
    body = defs.read_text(encoding="utf-8") if defs.is_file() else "---\n"
    defs.write_text(body + f"- voting_public_key: {rvc_pk}\n", encoding="utf-8")
    first_runs = run_cmds(stub_cmds(log))
    proc2, _ = run_chain(
        tmp_path,
        docker=tmp_path / "docker",
        curl=tmp_path / "curl",
        log=log,
        seed=False,
    )
    assert proc2.returncode == 2, proc2.stderr
    assert proc2.stdout == ""
    assert "--force" in proc2.stderr
    assert "already running" not in proc2.stderr or "RVC" in proc2.stderr
    assert extra.is_dir()
    assert rvc_pk in defs.read_text(encoding="utf-8")
    assert run_cmds(stub_cmds(log)) == first_runs


def test_running_unlisted_extra_is_pruned_without_force(tmp_path: Path):
    proc1, log = run_chain(tmp_path)
    assert proc1.returncode == 0, proc1.stderr
    dest = tmp_path / "data" / "cl" / "validator" / "validators"
    stray_pk = "0x" + "ee" * 48
    stray = dest / stray_pk
    stray.mkdir()
    (stray / "voting-keystore.json").write_text("{}\n", encoding="utf-8")
    db = slashing_db(tmp_path)
    db.write_text("keep-slash-db\n", encoding="utf-8")
    proc2, _ = run_chain(
        tmp_path,
        docker=tmp_path / "docker",
        curl=tmp_path / "curl",
        log=log,
        seed=False,
    )
    assert proc2.returncode == 0, proc2.stderr
    assert not stray.exists()
    assert len(validator_dirs(dest)) == _VC
    vcs = [c for c in run_cmds(stub_cmds(log)) if "validator_client" in c]
    assert len(vcs) == 2, vcs


def test_fail_chain_refuses_log_symlink(tmp_path: Path):
    victim = tmp_path / "victim-log"
    victim.write_text("untouched\n", encoding="utf-8")
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; resolve_run_dir >/dev/null; "
        "mkdir -p \"$RUN_DIR/logs\"; "
        f"ln -s {shlex.quote(str(victim))} \"$RUN_DIR/logs/eth-devnet-validator.log\"; "
        "assert_head_fork_electra",
        env={"CURL_CURRENT_VERSION": "0x70000000"},
    )
    assert proc.returncode == 2, proc.stderr
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"


def test_fail_chain_refuses_dangling_log_symlink(tmp_path: Path):
    victim = tmp_path / "absent-victim-log"
    assert not victim.exists()
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; resolve_run_dir >/dev/null; "
        "mkdir -p \"$RUN_DIR/logs\"; "
        f"ln -s {shlex.quote(str(victim))} \"$RUN_DIR/logs/eth-devnet-validator.log\"; "
        "assert_head_fork_electra",
        env={"CURL_CURRENT_VERSION": "0x70000000"},
    )
    assert proc.returncode == 2, proc.stderr
    assert "symlink" in proc.stderr
    assert not victim.exists()
    dest = tmp_path / "run" / "logs" / "eth-devnet-validator.log"
    assert dest.is_symlink()


def test_scrub_redacts_secret_file_and_password_token(tmp_path: Path):
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; resolve_run_dir >/dev/null; "
        "mkdir -p \"$RUN_DIR/logs\"; "
        "printf '%s\\n' 'leak secret-0 here' 'password=SuperSecretPasswordValue123' "
        "> \"$RUN_DIR/logs/eth-devnet-validator.log\"; "
        "_scrub_container_log \"$RUN_DIR/logs/eth-devnet-validator.log\"; "
        "cat \"$RUN_DIR/logs/eth-devnet-validator.log\"",
    )
    assert proc.returncode == 0, proc.stderr
    text = proc.stdout
    assert "secret-0" not in text
    assert "SuperSecretPasswordValue123" not in text
    assert "<redacted>" in text


def test_scrub_refuses_non_regular_log(tmp_path: Path):
    proc = source_chain(
        tmp_path,
        "parse_common_flags --run-dir \"$RUN_DIR\"; resolve_run_dir >/dev/null; "
        "mkdir -p \"$RUN_DIR/logs/eth-devnet-beacon.log\"; "
        "_scrub_container_log \"$RUN_DIR/logs/eth-devnet-beacon.log\"",
    )
    assert proc.returncode == 1, proc.stderr
    assert "regular file" in proc.stderr


def test_data_dir_flag_rebinds_vc_paths(tmp_path: Path):
    t = tmp_path / "T"
    t.mkdir()
    proc = source_chain(
        tmp_path,
        f"parse_common_flags --data-dir {shlex.quote(str(t))}; "
        "_bind_chain_paths; "
        'printf "%s\\n%s\\n" "$VC_KEYS_SRC" "$VALIDATOR_DATA_DIR"',
    )
    assert proc.returncode == 0, proc.stderr
    resolved = t.resolve()
    assert proc.stdout.strip().splitlines() == [
        f"{resolved}/keys/vc",
        f"{resolved}/cl/validator",
    ]


def test_vc_keys_src_override(tmp_path: Path):
    seed_genesis(tmp_path / "data", keys=False)
    alt = tmp_path / "alt-keys"
    seed_keys(tmp_path / "data", root=alt)
    proc, log = run_chain(
        tmp_path,
        env={"VC_KEYS_SRC": str(alt)},
        seed=False,
    )
    assert proc.returncode == 0, proc.stderr
    dest = tmp_path / "data" / "cl" / "validator" / "validators"
    assert len(validator_dirs(dest)) == _VC
    assert not (tmp_path / "data" / "keys" / "vc" / "validators").exists()
    assert not (tmp_path / "data" / "keys" / "valtools" / "validators").exists()
    vc = vc_cmd(run_cmds(stub_cmds(log)))
    assert "--init-slashing-protection" in vc


def _live_chain_available() -> bool:
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


def _vc_attested(text: str) -> bool:
    for line in text.splitlines():
        if "Successfully published attestation" not in line:
            continue
        if re.search(r"count:\s*0(?:\D|$)", line):
            continue
        return True
    return False


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


@pytest.mark.skipif(not _live_chain_available(), reason="DEVNET_LIVE=1 and pinned images required")
def test_live_electra_head(tmp_path: Path):
    pytest.importorskip("pytest_socket")
    docker = shutil.which("docker")
    assert docker is not None
    data = tmp_path / "data"
    runs = tmp_path / "runs"
    run_dir = tmp_path / "run"
    env = os.environ.copy()
    for key in _ISOLATE_KEYS:
        env.pop(key, None)
    env["DATA_DIR"] = str(data)
    env["RUNS_DIR"] = str(runs)
    env["EL_RPC_PORT"] = "18545"
    env["EL_AUTH_PORT"] = "18551"
    env["CL_HTTP_PORT"] = "15052"
    env["CL_METRICS_PORT"] = "15054"
    env["CHAIN_WAIT_ATTEMPTS"] = "90"
    env["CHAIN_WAIT_SLEEP"] = "2"
    try:
        gen = subprocess.run(
            ["bash", str(GENESIS), "--run-dir", str(run_dir)],
            capture_output=True,
            text=True,
            env=env,
            timeout=180,
            stdin=subprocess.DEVNULL,
        )
        assert gen.returncode == 0, gen.stderr
        keys = subprocess.run(
            ["bash", str(KEYS), "--run-dir", str(run_dir)],
            capture_output=True,
            text=True,
            env=env,
            timeout=180,
            stdin=subprocess.DEVNULL,
        )
        assert keys.returncode == 0, keys.stderr
        proc = subprocess.run(
            ["bash", str(CHAIN), "--run-dir", str(run_dir)],
            capture_output=True,
            text=True,
            env=env,
            timeout=240,
            stdin=subprocess.DEVNULL,
        )
        assert proc.returncode == 0, proc.stderr
        assert_no_secret(proc)
        assert "Electra" in proc.stderr or "0x60000000" in proc.stderr
        dest = data / "cl" / "validator" / "validators"
        assert len(validator_dirs(dest)) == _VC
        deadline = time.monotonic() + (2 * 32 * 12)
        attested = False
        log_blob = ""
        while time.monotonic() < deadline:
            logs = subprocess.run(
                [docker, "logs", "--", "eth-devnet-validator"],
                capture_output=True,
                text=True,
                timeout=30,
                stdin=subprocess.DEVNULL,
            )
            log_blob = (logs.stdout or "") + (logs.stderr or "")
            if _vc_attested(log_blob):
                attested = True
                break
            time.sleep(2)
        assert attested, log_blob[-4000:]
    finally:
        _live_cleanup(docker)
