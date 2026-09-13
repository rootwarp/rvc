"""Contract tests for scripts/devnet/run.sh (issue 5.5).

Stage stubs live on DEVNET_STAGE_DIR; disable_socket() via conftest.
No docker daemon, no network, no sockets.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

RUN = Path(__file__).resolve().parents[1] / "devnet" / "run.sh"
DEVNET_DIR = Path(__file__).resolve().parents[1] / "devnet"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
KEYPATHS = FIXTURES / "run_json__keypaths.txt"

_NUMBERED = (
    "00-preflight.sh",
    "01-genesis.sh",
    "02-keys.sh",
    "03-chain.sh",
)
_VERBS = (
    "up.sh",
    "attach-rvc.sh",
    "soak.sh",
    "report.sh",
    "down.sh",
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
    "SOAK_START_OFFSET_EPOCHS",
    "IMG_GETH",
    "IMG_LIGHTHOUSE",
    "IMG_GENESIS",
    "RVC_BIN",
    "RVC_KEYS",
    "NUM_VALIDATORS",
    "KEEP",
    "STRICT",
    "RVC_STUB_VERSION",
    "DEVNET_FAIL_STAGE",
    "DEVNET_FAIL_CODE",
    "DEVNET_DOWN_CODE",
)

_MNEMONIC = "test test test test test test test test test test junk"
_READ_CMD_RE = re.compile(r"(?m)^\s*read\s")
_PUBKEYS = [
    "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
    "0x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
]
_GVR = "0xabababababababababababababababababababababababababababababababab"


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


def _committed_keypaths() -> list[str]:
    return KEYPATHS.read_text(encoding="utf-8").splitlines()


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


def write_rvc_stub(tmp_path: Path) -> Path:
    stub = tmp_path / "rvc"
    stub.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" = --version ]; then\n"
        "  printf '%s\\n' \"${RVC_STUB_VERSION:-rvc 0.7.0}\"\n"
        "  exit 0\n"
        "fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub


def plant_data(tmp_path: Path) -> None:
    data = tmp_path / "data"
    genesis = data / "genesis"
    genesis.mkdir(parents=True, exist_ok=True)
    (genesis / "genesis_validators_root.txt").write_text(_GVR + "\n", encoding="utf-8")
    keys = data / "keys" / "rvc"
    keys.mkdir(parents=True, exist_ok=True)
    (keys / "pubkeys.txt").write_text(
        "".join(f"{pk}\n" for pk in _PUBKEYS), encoding="utf-8"
    )
    data.chmod(0o700)


def _stub_common(log: Path) -> str:
    return (
        "#!/bin/sh\n"
        f"log={shlex.quote(str(log))}\n"
        "printf '%s\\n' \"$(basename \"$0\") $*\" >> \"$log\"\n"
        "run_dir=\"\"\n"
        "prev=\"\"\n"
        "for a in \"$@\"; do\n"
        "  if [ \"$prev\" = --run-dir ]; then run_dir=\"$a\"; fi\n"
        "  prev=\"$a\"\n"
        "done\n"
        "fail_name=${DEVNET_FAIL_STAGE:-}\n"
        "fail_code=${DEVNET_FAIL_CODE:-0}\n"
    )


def write_stage_stubs(tmp_path: Path) -> tuple[Path, Path]:
    stage_dir = tmp_path / "stages"
    stage_dir.mkdir(parents=True, exist_ok=True)
    log = tmp_path / "stages.log"
    samples = (
        '{"slot":10,"t":"2026-09-12T00:00:00Z","gauges":{}}\n'
        '{"slot":12,"t":"2026-09-12T00:00:24Z","gauges":{}}\n'
    )
    verdict = '{"exit_code":0,"schema_version":1,"verdict":"pass"}\n'
    pubkeys_body = "".join(f"{pk}\n" for pk in _PUBKEYS)
    rvc_json = json.dumps(
        {"key_range": [48, 64], "pubkeys": _PUBKEYS, "schema_version": 1},
        separators=(",", ":"),
    )
    header = _stub_common(log)

    for name in _NUMBERED:
        path = stage_dir / name
        path.write_text(
            header
            + "if [ \"$(basename \"$0\")\" = \"$fail_name\" ]; then\n"
            + "  exit \"$fail_code\"\n"
            + "fi\n"
            + "exit 0\n",
            encoding="utf-8",
        )
        path.chmod(0o755)

    up = stage_dir / "up.sh"
    up.write_text(
        header
        + "dir=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n"
        + "for s in 00-preflight.sh 01-genesis.sh 02-keys.sh 03-chain.sh; do\n"
        + "  \"$dir/$s\" \"$@\" || exit $?\n"
        + "done\n"
        + "data_dir=${DATA_DIR:-}\n"
        + "if [ -n \"$data_dir\" ] && [ \"$data_dir\" != / ]; then\n"
        + "  mkdir -p -- \"$data_dir/genesis\" \"$data_dir/keys/rvc\"\n"
        + f"  printf '%s' {shlex.quote(_GVR + chr(10))} "
        + "> \"$data_dir/genesis/genesis_validators_root.txt\"\n"
        + f"  printf '%s' {shlex.quote(pubkeys_body)} "
        + "> \"$data_dir/keys/rvc/pubkeys.txt\"\n"
        + "  chmod 700 \"$data_dir\" 2>/dev/null || true\n"
        + "fi\n"
        + "exit 0\n",
        encoding="utf-8",
    )
    up.chmod(0o755)

    attach = stage_dir / "attach-rvc.sh"
    attach.write_text(
        header
        + "if [ \"$(basename \"$0\")\" = \"$fail_name\" ]; then\n"
        + "  exit \"$fail_code\"\n"
        + "fi\n"
        + "if [ -n \"$run_dir\" ]; then\n"
        + "  mkdir -p -- \"$run_dir\"\n"
        + f"  printf '%s\\n' {shlex.quote(rvc_json)} > \"$run_dir/rvc.json\"\n"
        + "fi\n"
        + "exit 0\n",
        encoding="utf-8",
    )
    attach.chmod(0o755)

    soak = stage_dir / "soak.sh"
    soak.write_text(
        header
        + "if [ -n \"$run_dir\" ]; then\n"
        + "  mkdir -p -- \"$run_dir\"\n"
        + f"  printf '%s' {shlex.quote(samples)} > \"$run_dir/samples.jsonl\"\n"
        + "fi\n"
        + "if [ \"$(basename \"$0\")\" = \"$fail_name\" ]; then\n"
        + "  exit \"$fail_code\"\n"
        + "fi\n"
        + "exit 0\n",
        encoding="utf-8",
    )
    soak.chmod(0o755)

    report = stage_dir / "report.sh"
    report.write_text(
        header
        + "if [ -n \"$run_dir\" ]; then\n"
        + "  mkdir -p -- \"$run_dir\"\n"
        + f"  printf '%s' {shlex.quote(verdict)} > \"$run_dir/verdict.json\"\n"
        + "fi\n"
        + "if [ \"$(basename \"$0\")\" = \"$fail_name\" ]; then\n"
        + "  exit \"$fail_code\"\n"
        + "fi\n"
        + "exit 0\n",
        encoding="utf-8",
    )
    report.chmod(0o755)

    down = stage_dir / "down.sh"
    down.write_text(
        header
        + "down_code=${DEVNET_DOWN_CODE:-0}\n"
        + "data_dir=${DATA_DIR:-}\n"
        + "if [ -n \"$data_dir\" ] && [ \"$data_dir\" != / ] "
        + "&& [ -d \"$data_dir\" ]; then\n"
        + "  rm -rf -- \"$data_dir\"\n"
        + "fi\n"
        + "if [ \"$(basename \"$0\")\" = \"$fail_name\" ]; then\n"
        + "  exit \"$fail_code\"\n"
        + "fi\n"
        + "exit \"$down_code\"\n",
        encoding="utf-8",
    )
    down.chmod(0o755)
    return stage_dir, log


def run_env(
    tmp_path: Path,
    extra: dict[str, str] | None = None,
    *,
    docker: Path | None = None,
    stage_dir: Path | None = None,
    rvc: Path | None = None,
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
    if rvc is not None:
        full["RVC_BIN"] = str(rvc)
    if extra:
        full.update(extra)
    return full


def run_run(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    env: dict[str, str] | None = None,
    timeout: float = 20,
    plant: bool = True,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    if plant:
        plant_data(tmp_path)
    docker, _dlog = write_docker_stub(tmp_path)
    rvc = write_rvc_stub(tmp_path)
    stage_dir, slog = write_stage_stubs(tmp_path)
    full = run_env(
        tmp_path, env, docker=docker, stage_dir=stage_dir, rvc=rvc
    )
    proc = subprocess.run(
        ["bash", str(RUN), *args],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return proc, slog, tmp_path / "runs"


def stub_cmds(log: Path | None) -> list[str]:
    if log is None or not log.is_file():
        return []
    return [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


def stage_names(log: Path | None) -> list[str]:
    names = []
    for line in stub_cmds(log):
        names.append(line.split(" ", 1)[0])
    return names


def run_dirs(runs: Path) -> list[Path]:
    if not runs.is_dir():
        return []
    return sorted(p for p in runs.iterdir() if p.is_dir())


def load_run_json(runs: Path) -> dict:
    dirs = run_dirs(runs)
    assert dirs, f"no run dirs under {runs}"
    path = dirs[-1] / "run.json"
    return json.loads(path.read_text(encoding="utf-8"))


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob


def test_run_sh_exists_and_syntax():
    assert RUN.is_file(), RUN
    assert os.access(RUN, os.X_OK)
    proc = subprocess.run(
        ["bash", "-n", str(RUN)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = RUN.read_text(encoding="utf-8")
    assert _READ_CMD_RE.search(text) is None
    assert "read -p" not in text
    assert "source" in text and "lib/common.sh" in text
    assert "parse_common_flags" in text
    assert "resolve_profile" in text
    assert "mint_run_id()" in text
    assert "record_exit()" in text
    assert "write_run_json_start()" in text
    assert "write_run_json_end()" in text
    assert "up.sh" in text
    assert "attach-rvc.sh" in text
    assert "soak.sh" in text
    assert "report.sh" in text
    assert "down.sh" in text
    assert "00-preflight.sh" not in text
    assert "cargo build --release" in text
    assert "jq -S" in text
    assert "fingerprint" in text
    assert ".tmp.$$" not in text
    assert "_atomic_replace_stdin" in text
    assert "_snapshot_run_identity" in text


def test_run_sh_happy_stub_exits_0(tmp_path: Path):
    proc, slog, runs = run_run(tmp_path, ["--profile", "fast"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    names = stage_names(slog)
    assert names[:5] == [
        "up.sh",
        "00-preflight.sh",
        "01-genesis.sh",
        "02-keys.sh",
        "03-chain.sh",
    ]
    assert "attach-rvc.sh" in names
    assert "soak.sh" in names
    assert "report.sh" in names
    assert "down.sh" in names
    assert names.index("attach-rvc.sh") < names.index("soak.sh")
    assert names.index("soak.sh") < names.index("report.sh")
    assert names.index("report.sh") < names.index("down.sh")
    doc = load_run_json(runs)
    assert doc["schema_version"] == 1
    assert doc["profile"] == "fast"
    assert doc["epochs"] == 4
    assert doc["fingerprint"]
    assert doc["stages"]["up"]["exit_code"] == 0
    assert doc["stages"]["attach"]["exit_code"] == 0
    assert doc["stages"]["soak"]["exit_code"] == 0
    assert doc["stages"]["report"]["exit_code"] == 0
    assert doc["stages"]["down"]["exit_code"] == 0
    assert "seconds" in doc["stages"]["up"]
    assert doc["window"]["start_slot"] == 10
    assert doc["window"]["end_slot"] == 12
    assert doc["verdict"] == "pass"
    assert doc["rvc_version"]
    assert doc["pubkeys"] == _PUBKEYS
    assert doc["genesis_validators_root"] == _GVR
    assert not (tmp_path / "data").exists()
    assert_no_secret(proc)


def test_run_sh_missing_rvc_exits_2(tmp_path: Path):
    plant_data(tmp_path)
    docker, _ = write_docker_stub(tmp_path)
    stage_dir, slog = write_stage_stubs(tmp_path)
    missing = tmp_path / "no-such-rvc"
    full = run_env(
        tmp_path,
        docker=docker,
        stage_dir=stage_dir,
        rvc=missing,
    )
    proc = subprocess.run(
        ["bash", str(RUN), "--profile", "fast"],
        capture_output=True,
        text=True,
        env=full,
        timeout=15,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "cargo build --release" in proc.stderr
    assert stub_cmds(slog) == []
    assert run_dirs(tmp_path / "runs") == []
    assert_no_secret(proc)


def test_run_json_key_paths(tmp_path: Path):
    proc, _slog, runs = run_run(tmp_path, ["--profile", "fast"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    dirs = run_dirs(runs)
    assert len(dirs) == 1
    path = dirs[0] / "run.json"
    text = path.read_text(encoding="utf-8")
    assert "NaN" not in text
    assert "Infinity" not in text
    doc = json.loads(text)
    json.dumps(doc, allow_nan=False)
    actual = json_keypaths(doc)
    expected = _committed_keypaths()
    assert "" not in expected
    assert expected == sorted(expected)
    assert sorted(actual) == expected
    assert doc["schema_version"] == 1
    assert isinstance(doc["fingerprint"], str)
    assert re.fullmatch(r"[0-9a-f]{64}", doc["fingerprint"])
    assert doc["soak_start_offset_epochs"] == 0
    assert doc["fail_under"] == ""
    assert doc["key_range"] == [48, 64]
    assert doc["pubkeys"] == _PUBKEYS
    assert doc["genesis_validators_root"] == _GVR
    assert "images" in doc
    assert doc["rvc_version"]
    assert not (tmp_path / "data").exists()
    assert_no_secret(proc)


def test_run_json_survives_data_purge_without_preseed(tmp_path: Path):
    proc, _slog, runs = run_run(tmp_path, ["--profile", "fast"], plant=False)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert not (tmp_path / "data").exists()
    doc = load_run_json(runs)
    assert doc["pubkeys"] == _PUBKEYS
    assert doc["genesis_validators_root"] == _GVR
    assert doc["key_range"] == [48, 64]
    assert_no_secret(proc)


@pytest.mark.parametrize(
    "fail_stage,code",
    [
        ("00-preflight.sh", 2),
        ("01-genesis.sh", 1),
        ("02-keys.sh", 1),
        ("03-chain.sh", 1),
        ("attach-rvc.sh", 5),
        ("soak.sh", 3),
        ("report.sh", 4),
    ],
)
def test_run_sh_exits_with_first_nonzero_child_code(
    tmp_path: Path, fail_stage: str, code: int
):
    proc, slog, _runs = run_run(
        tmp_path,
        ["--profile", "fast"],
        env={
            "DEVNET_FAIL_STAGE": fail_stage,
            "DEVNET_FAIL_CODE": str(code),
        },
    )
    assert proc.returncode == code, proc.stderr
    assert proc.stdout == ""
    names = stage_names(slog)
    assert "down.sh" in names
    if fail_stage == "soak.sh":
        assert "report.sh" in names
        assert names.index("soak.sh") < names.index("report.sh")
        assert names.index("report.sh") < names.index("down.sh")
    elif fail_stage == "report.sh":
        assert "report.sh" in names
    else:
        assert "report.sh" not in names
        if fail_stage in _NUMBERED or fail_stage == "attach-rvc.sh":
            assert "soak.sh" not in names
    if fail_stage in _NUMBERED:
        assert fail_stage in names
        assert "attach-rvc.sh" not in names
    assert_no_secret(proc)


def test_run_sh_teardown_never_overwrites_exit_code(tmp_path: Path):
    proc, slog, _runs = run_run(
        tmp_path,
        ["--profile", "fast"],
        env={
            "DEVNET_FAIL_STAGE": "attach-rvc.sh",
            "DEVNET_FAIL_CODE": "5",
            "DEVNET_DOWN_CODE": "9",
        },
    )
    assert proc.returncode == 5, proc.stderr
    assert proc.stdout == ""
    names = stage_names(slog)
    assert "attach-rvc.sh" in names
    assert "down.sh" in names
    assert "soak.sh" not in names
    assert_no_secret(proc)


def test_run_sh_keep_skips_teardown(tmp_path: Path):
    proc, slog, _runs = run_run(tmp_path, ["--profile", "fast", "--keep"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    names = stage_names(slog)
    assert "down.sh" not in names
    assert "report.sh" in names
    assert "attach-rvc.sh" in names
    assert (tmp_path / "data").is_dir()
    assert_no_secret(proc)


def test_run_sh_stages_requires_run_id(tmp_path: Path):
    proc, slog, runs = run_run(tmp_path, ["--profile", "fast", "--stages", "report"])
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "--run-id" in proc.stderr
    assert stub_cmds(slog) == []
    assert run_dirs(runs) == []
    assert_no_secret(proc)

    plant_data(tmp_path)
    docker, _ = write_docker_stub(tmp_path)
    rvc = write_rvc_stub(tmp_path)
    stage_dir, slog2 = write_stage_stubs(tmp_path)
    existing = tmp_path / "runs" / "reuse-me"
    existing.mkdir(parents=True)
    start = {
        "epochs": 4,
        "fingerprint": "a" * 64,
        "generated_at": "2026-09-12T00:00:00Z",
        "genesis_validators_root": _GVR,
        "git_sha": "deadbee",
        "images": {"genesis": "g", "geth": "e", "lighthouse": "l"},
        "key_range": [48, 64],
        "profile": "fast",
        "pubkeys": _PUBKEYS,
        "run_id": "reuse-me",
        "rvc_version": "rvc 0.7.0",
        "schema_version": 1,
    }
    (existing / "run.json").write_text(
        json.dumps(start, sort_keys=True) + "\n", encoding="utf-8"
    )
    full = run_env(
        tmp_path, docker=docker, stage_dir=stage_dir, rvc=rvc
    )
    proc2 = subprocess.run(
        [
            "bash",
            str(RUN),
            "--profile",
            "fast",
            "--stages",
            "report",
            "--run-id",
            "reuse-me",
            "--keep",
        ],
        capture_output=True,
        text=True,
        env=full,
        timeout=20,
        stdin=subprocess.DEVNULL,
    )
    assert proc2.returncode == 0, proc2.stderr
    names = stage_names(slog2)
    assert names == ["report.sh"]
    assert run_dirs(tmp_path / "runs") == [existing]
    doc = json.loads((existing / "run.json").read_text(encoding="utf-8"))
    assert doc["run_id"] == "reuse-me"
    assert doc["fingerprint"] == "a" * 64
    assert_no_secret(proc2)


def test_run_json_fingerprint_excludes_rvc_version(tmp_path: Path):
    proc1, _, runs = run_run(
        tmp_path,
        ["--profile", "fast", "--run-id", "fp-ver-a"],
        env={"RVC_STUB_VERSION": "rvc 0.7.0"},
    )
    assert proc1.returncode == 0, proc1.stderr
    doc_a = json.loads((runs / "fp-ver-a" / "run.json").read_text(encoding="utf-8"))
    fp1 = doc_a["fingerprint"]
    ver1 = doc_a["rvc_version"]

    proc2, _, _ = run_run(
        tmp_path,
        ["--profile", "fast", "--run-id", "fp-ver-b"],
        env={"RVC_STUB_VERSION": "rvc 9.9.9"},
    )
    assert proc2.returncode == 0, proc2.stderr
    doc_b = json.loads((runs / "fp-ver-b" / "run.json").read_text(encoding="utf-8"))
    fp2 = doc_b["fingerprint"]
    ver2 = doc_b["rvc_version"]
    assert ver1 != ver2
    assert fp1 == fp2
    assert {p.name for p in run_dirs(runs)} == {"fp-ver-a", "fp-ver-b"}

    proc_keys, _, runs_k = run_run(
        tmp_path / "keys",
        ["--profile", "fast", "--run-id", "fp-keys"],
        env={"RVC_KEYS": "8"},
    )
    assert proc_keys.returncode == 0, proc_keys.stderr
    fp_keys = json.loads(
        (runs_k / "fp-keys" / "run.json").read_text(encoding="utf-8")
    )["fingerprint"]
    assert fp_keys != fp1

    proc_img, _, runs_i = run_run(
        tmp_path / "img",
        ["--profile", "fast", "--run-id", "fp-img"],
        env={
            "IMG_GETH": (
                "ethereum/client-go:v1.17.5@"
                "sha256:0000000000000000000000000000000000000000000000000000000000000000"
            )
        },
    )
    assert proc_img.returncode == 0, proc_img.stderr
    fp_img = json.loads(
        (runs_i / "fp-img" / "run.json").read_text(encoding="utf-8")
    )["fingerprint"]
    assert fp_img != fp1
    assert_no_secret(proc1)
    assert_no_secret(proc2)


def test_run_sh_unknown_flag_exits_2(tmp_path: Path):
    proc, slog, runs = run_run(tmp_path, ["--profile", "fast", "--nope"])
    assert proc.returncode == 2
    assert "unknown flag" in proc.stderr
    assert stub_cmds(slog) == []
    assert run_dirs(runs) == []
    assert_no_secret(proc)


def test_run_sh_missing_profile_exits_2(tmp_path: Path):
    proc, slog, runs = run_run(tmp_path, [])
    assert proc.returncode == 2
    assert "--profile" in proc.stderr
    assert stub_cmds(slog) == []
    assert_no_secret(proc)


def test_run_sh_rejects_dot_run_id(tmp_path: Path):
    proc, slog, runs = run_run(tmp_path, ["--profile", "fast", "--run-id", "."])
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "run-id" in proc.stderr
    assert stub_cmds(slog) == []
    assert not (runs / "run.json").exists()
    assert_no_secret(proc)

    proc2, slog2, _ = run_run(
        tmp_path, ["--profile", "fast", "--run-id", "-evil"]
    )
    assert proc2.returncode == 2, proc2.stderr
    assert "run-id" in proc2.stderr
    assert stub_cmds(slog2) == []
    assert not (runs / "run.json").exists()


def test_run_sh_dump_refuses_symlink_container_log(tmp_path: Path):
    plant_data(tmp_path)
    docker, _ = write_docker_stub(tmp_path)
    rvc = write_rvc_stub(tmp_path)
    stage_dir, slog = write_stage_stubs(tmp_path)
    run_id = "logtest"
    run_dir = tmp_path / "runs" / run_id
    log_dir = run_dir / "logs"
    log_dir.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_text("UNTOUCHED\n", encoding="utf-8")
    (log_dir / "eth-devnet-geth.log").symlink_to(victim)
    full = run_env(tmp_path, docker=docker, stage_dir=stage_dir, rvc=rvc)
    full["DEVNET_FAIL_STAGE"] = "attach-rvc.sh"
    full["DEVNET_FAIL_CODE"] = "5"
    proc = subprocess.run(
        ["bash", str(RUN), "--profile", "fast", "--run-id", run_id],
        capture_output=True,
        text=True,
        env=full,
        timeout=20,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 5, proc.stderr
    assert victim.read_text(encoding="utf-8") == "UNTOUCHED\n"
    assert (log_dir / "eth-devnet-geth.log").is_symlink()
    assert "report.sh" not in stage_names(slog)
    assert_no_secret(proc)


def test_run_sh_dump_skips_when_run_dir_is_file(tmp_path: Path):
    plant_data(tmp_path)
    docker, dlog = write_docker_stub(tmp_path)
    rvc = write_rvc_stub(tmp_path)
    stage_dir, slog = write_stage_stubs(tmp_path)
    attach = stage_dir / "attach-rvc.sh"
    header = _stub_common(slog)
    attach.write_text(
        header
        + "if [ -n \"$run_dir\" ]; then\n"
        + "  rm -rf -- \"$run_dir\"\n"
        + "  printf 'not-a-dir\\n' > \"$run_dir\"\n"
        + "fi\n"
        + "exit 5\n",
        encoding="utf-8",
    )
    attach.chmod(0o755)
    run_id = "filedir"
    full = run_env(tmp_path, docker=docker, stage_dir=stage_dir, rvc=rvc)
    proc = subprocess.run(
        ["bash", str(RUN), "--profile", "fast", "--run-id", run_id],
        capture_output=True,
        text=True,
        env=full,
        timeout=20,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 5, proc.stderr
    assert (tmp_path / "runs" / run_id).is_file()
    assert not Path("/logs/eth-devnet-geth.log").exists()
    assert not Path("/logs/eth-devnet-beacon.log").exists()
    assert not Path("/logs/eth-devnet-validator.log").exists()
    docker_lines = stub_cmds(dlog)
    assert not any(line.startswith("logs ") for line in docker_lines)
    assert "report.sh" not in stage_names(slog)
    assert_no_secret(proc)


def test_run_json_safe_records_offset_and_fail_under(tmp_path: Path):
    proc, slog, runs = run_run(tmp_path, ["--profile", "safe"])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    doc = load_run_json(runs)
    assert doc["profile"] == "safe"
    assert doc["epochs"] == 8
    assert doc["soak_start_offset_epochs"] == 3
    assert doc["fail_under"] == "participation_rate=0.95,target_rate=0.95"
    actual = json_keypaths(doc)
    expected = _committed_keypaths()
    assert sorted(actual) == expected
    soak_cmd = next(c for c in stub_cmds(slog) if c.startswith("soak.sh "))
    report_cmd = next(c for c in stub_cmds(slog) if c.startswith("report.sh "))
    assert "--epochs 8" in soak_cmd
    assert "--fail-under participation_rate=0.95" in report_cmd
    assert "--fail-under target_rate=0.95" in report_cmd
    assert_no_secret(proc)

