"""Contract tests for scripts/devnet/soak.sh (issue 5.2).

CURL / DOCKER / DEVNET_REPORT stubs; disable_socket() via conftest autouse.
Injected NOW_UNIX + --gate-interval 0 keeps the suite sub-second.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
from pathlib import Path

from test_devnet_common_sh import run_common

SOAK = Path(__file__).resolve().parents[1] / "devnet" / "soak.sh"
COMMON = Path(__file__).resolve().parents[1] / "devnet" / "lib" / "common.sh"
ENV_PATH = Path(__file__).resolve().parents[1] / "devnet" / "devnet.env"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

_GENESIS_TIME = 1_710_000_000
_SECONDS_PER_SLOT = 12
_START_SLOT = 10
_NOW_UNIX = str(_GENESIS_TIME + _START_SLOT * _SECONDS_PER_SLOT)
_SLOTS_PER_EPOCH = "6"
_EPOCHS = "1"
_GATED_SLOTS = 6

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
    "NOW_UNIX",
    "SLOTS_PER_EPOCH",
    "SECONDS_PER_SLOT",
    "GATE_INTERVAL_SLOTS",
    "SCRAPE_TIMEOUT_S",
    "SOAK_EPOCHS",
    "CL_HTTP_PORT",
    "RVC_METRICS_PORT",
)

_MNEMONIC = "test test test test test test test test test test test junk"
_READ_CMD_RE = re.compile(r"(?m)^\s*read\s")


def _rvc_json_doc(**extra: object) -> dict[str, object]:
    doc: dict[str, object] = {
        "config_path": "/tmp/rvc/config.toml",
        "endpoint": "http://127.0.0.1:8080",
        "generated_at": "2026-09-12T00:00:00Z",
        "key_range": [48, 64],
        "pid": 4242,
        "pubkeys": [
            "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
        ],
        "schema_version": 1,
    }
    doc.update(extra)
    return doc


def plant_rvc_json(run_dir: Path, **extra: object) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "rvc.json"
    path.write_text(json.dumps(_rvc_json_doc(**extra), sort_keys=True) + "\n")
    path.chmod(0o600)
    return path


def write_curl_stub(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "curl.log"
    stub = tmp_path / "curl"
    state = tmp_path / "curl-state"
    state.mkdir(exist_ok=True)
    genesis = FIXTURES / "bn_genesis.json"
    (state / "rvc-health").write_text("200", encoding="utf-8")
    (state / "bn-health").write_text("200", encoding="utf-8")
    (state / "k8-blocked").write_text("0", encoding="utf-8")
    (state / "metrics-code").write_text("200", encoding="utf-8")
    (state / "metrics-exit").write_text("0", encoding="utf-8")
    stub.write_text(
        "#!/bin/sh\n"
        f"log={shlex.quote(str(log))}\n"
        f"state={shlex.quote(str(state))}\n"
        f"genesis={shlex.quote(str(genesis))}\n"
        "printf '%s\\n' \"$*\" >> \"$log\"\n"
        "url=\"\"\n"
        "out=\"\"\n"
        "want_code=0\n"
        "prev=\"\"\n"
        "for a in \"$@\"; do\n"
        "  url=\"$a\"\n"
        "  if [ \"$prev\" = \"-o\" ]; then out=\"$a\"; fi\n"
        "  case \"$a\" in\n"
        "    *http_code*) want_code=1 ;;\n"
        "  esac\n"
        "  prev=\"$a\"\n"
        "done\n"
        "emit() {\n"
        "  if [ -n \"$out\" ]; then\n"
        "    if [ \"$out\" != /dev/null ]; then\n"
        "      printf '%s\\n' \"$1\" > \"$out\"\n"
        "    fi\n"
        "  else\n"
        "    printf '%s\\n' \"$1\"\n"
        "  fi\n"
        "}\n"
        "case \"$url\" in\n"
        "  */eth/v1/beacon/genesis)\n"
        "    emit \"$(cat \"$genesis\")\"\n"
        "    if [ \"$want_code\" -eq 1 ]; then tr -d '[:space:]' < \"$state/metrics-code\"; fi\n"
        "    exit 0\n"
        "    ;;\n"
        "  */eth/v1/node/health)\n"
        "    if [ \"$want_code\" -eq 1 ]; then\n"
        "      tr -d '[:space:]' < \"$state/bn-health\"\n"
        "    fi\n"
        "    exit 0\n"
        "    ;;\n"
        "  */health)\n"
        "    if [ \"$want_code\" -eq 1 ]; then\n"
        "      tr -d '[:space:]' < \"$state/rvc-health\"\n"
        "    fi\n"
        "    exit 0\n"
        "    ;;\n"
        "  */metrics)\n"
        "    mex=$(tr -d '[:space:]' < \"$state/metrics-exit\")\n"
        "    if [ \"$mex\" != 0 ]; then exit 1; fi\n"
        "    if [ -f \"$state/metrics-body\" ]; then\n"
        "      body=$(cat \"$state/metrics-body\")\n"
        "    else\n"
        "      blocked_file=\"$state/k8-seq\"\n"
        "      if [ -f \"$blocked_file\" ]; then\n"
        "        blocked=$(head -n 1 \"$blocked_file\")\n"
        "        tail -n +2 \"$blocked_file\" > \"$blocked_file.tmp\" || true\n"
        "        mv \"$blocked_file.tmp\" \"$blocked_file\"\n"
        "      else\n"
        "        blocked=$(tr -d '[:space:]' < \"$state/k8-blocked\")\n"
        "      fi\n"
        "      [ -n \"$blocked\" ] || blocked=0\n"
        "      body=$(printf '%s\\n%s' 'rvc_slashing_protection_checks_total{result=\"safe\"} 80' \"rvc_slashing_protection_checks_total{result=\\\"blocked\\\"} ${blocked}\")\n"
        "    fi\n"
        "    emit \"$body\"\n"
        "    if [ \"$want_code\" -eq 1 ]; then\n"
        "      tr -d '[:space:]' < \"$state/metrics-code\"\n"
        "    fi\n"
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "printf '%s\\n' 'unscripted curl' >&2\n"
        "exit 1\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def write_report_stub(tmp_path: Path) -> tuple[Path, Path]:
    log = tmp_path / "report.log"
    stub = tmp_path / "devnet_report"
    start = FIXTURES / "rvc_metrics__start.txt"
    end = FIXTURES / "rvc_metrics__end.txt"
    fail_once = tmp_path / "fail-gauges-once"
    stub.write_text(
        "#!/bin/sh\n"
        f"log={shlex.quote(str(log))}\n"
        f"start={shlex.quote(str(start))}\n"
        f"end={shlex.quote(str(end))}\n"
        f"fail_once={shlex.quote(str(fail_once))}\n"
        "printf '%s\\n' \"$*\" >> \"$log\"\n"
        "out=\"\"\n"
        "append=\"\"\n"
        "slot=\"\"\n"
        "gauges=0\n"
        "prev=\"\"\n"
        "for a in \"$@\"; do\n"
        "  if [ \"$prev\" = \"--out\" ]; then out=\"$a\"; fi\n"
        "  if [ \"$prev\" = \"--append\" ]; then append=\"$a\"; fi\n"
        "  if [ \"$prev\" = \"--slot\" ]; then slot=\"$a\"; fi\n"
        "  if [ \"$a\" = \"--gauges-only\" ]; then gauges=1; fi\n"
        "  prev=\"$a\"\n"
        "done\n"
        "if [ \"$gauges\" -eq 1 ]; then\n"
        "  if [ -f \"$fail_once\" ]; then\n"
        "    rm -f \"$fail_once\"\n"
        "    exit 1\n"
        "  fi\n"
        "  [ -n \"$slot\" ] || slot=0\n"
        "  printf '%s\\n' \"{\\\"gauges\\\": {\\\"rvc_tasks_running\\\": [{\\\"labels\\\": {\\\"task\\\": \\\"orchestrator\\\"}, \\\"v\\\": 1}]}, \\\"slot\\\": ${slot}, \\\"t\\\": \\\"2026-09-12T00:00:00Z\\\"}\" >> \"$append\"\n"
        "  exit 0\n"
        "fi\n"
        "if [ -n \"$out\" ]; then\n"
        "  case \"$out\" in\n"
        "    *metrics-end.txt) cp \"$end\" \"$out\" ;;\n"
        "    *) cp \"$start\" \"$out\" ;;\n"
        "  esac\n"
        "  exit 0\n"
        "fi\n"
        "exit 2\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def soak_env(
    tmp_path: Path,
    extra: dict[str, str] | None = None,
    *,
    docker: Path | None = None,
    curl: Path | None = None,
    report: Path | None = None,
) -> dict[str, str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full["DOCKER"] = str(docker or (tmp_path / "docker"))
    full["CURL"] = str(curl or (tmp_path / "curl"))
    full["DEVNET_REPORT"] = str(report or (tmp_path / "devnet_report"))
    full["DATA_DIR"] = str(tmp_path / "data")
    full["RUNS_DIR"] = str(tmp_path / "runs")
    full["NOW_UNIX"] = _NOW_UNIX
    full["SLOTS_PER_EPOCH"] = _SLOTS_PER_EPOCH
    full["SECONDS_PER_SLOT"] = str(_SECONDS_PER_SLOT)
    if extra:
        full.update(extra)
    return full


def run_soak(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    env: dict[str, str] | None = None,
    timeout: float = 20,
    reset_stubs: bool = True,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    docker = tmp_path / "docker"
    if not docker.exists():
        docker.write_text(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$0.log\"\nexit 0\n",
            encoding="utf-8",
        )
        docker.chmod(0o755)
    if reset_stubs or not (tmp_path / "curl").exists():
        curl, clog = write_curl_stub(tmp_path)
    else:
        curl = tmp_path / "curl"
        clog = tmp_path / "curl.log"
    if reset_stubs or not (tmp_path / "devnet_report").exists():
        report, rlog = write_report_stub(tmp_path)
    else:
        report = tmp_path / "devnet_report"
        rlog = tmp_path / "report.log"
    full = soak_env(tmp_path, env, docker=docker, curl=curl, report=report)
    proc = subprocess.run(
        ["bash", str(SOAK), *args],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return proc, clog, rlog


def stub_cmds(log: Path | None) -> list[str]:
    if log is None or not log.is_file():
        return []
    return [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob


def assert_artifacts(run_dir: Path) -> None:
    assert (run_dir / "metrics-start.txt").is_file()
    assert (run_dir / "metrics-end.txt").is_file()
    assert (run_dir / "samples.jsonl").is_file()


def sample_rows(run_dir: Path) -> list[dict]:
    path = run_dir / "samples.jsonl"
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def soak_args(run_dir: Path, extra: list[str] | None = None) -> list[str]:
    args = [
        "--run-dir",
        str(run_dir),
        "--epochs",
        _EPOCHS,
        "--gate-interval",
        "0",
    ]
    if extra:
        args.extend(extra)
    return args


def test_soak_sh_syntax():
    assert SOAK.is_file(), SOAK
    assert os.access(SOAK, os.X_OK)
    proc = subprocess.run(
        ["bash", "-n", str(SOAK)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    common_n = subprocess.run(
        ["bash", "-n", str(COMMON)], capture_output=True, text=True
    )
    assert common_n.returncode == 0, common_n.stderr
    text = SOAK.read_text(encoding="utf-8")
    assert _READ_CMD_RE.search(text) is None
    assert "read -p" not in text
    assert "source" in text and "lib/common.sh" in text
    assert "parse_common_flags" in text
    assert "--epochs" in text
    assert "--gate-interval" in text
    assert "--gauges-only" in text
    assert "--slot" in text
    assert '--slot "$slot"' in text
    assert "current_slot" in text
    assert "O_NOFOLLOW" in text
    assert "die_health" in text
    assert "attach-rvc.sh" in text
    assert re.search(r"(?m)^\s*docker\s", text) is None
    common = COMMON.read_text(encoding="utf-8")
    assert "bn_url()" in common
    assert "rvc_url()" in common
    assert "bn_genesis_time()" in common
    assert "current_slot()" in common
    assert "sleep_until_slot()" in common
    assert "k8_blocked_total()" in common
    assert "_curl_hardened()" in common
    assert "-q" in common
    assert "--no-location" in common
    assert "--path-as-is" in common
    assert "wait_for_http()" not in common
    assert "http_code()" not in common
    assert "wait_for_http()" not in text
    env_text = ENV_PATH.read_text(encoding="utf-8")
    assert "GATE_INTERVAL_SLOTS=1" in env_text
    assert "SCRAPE_TIMEOUT_S=5" in env_text


def test_soak_sh_missing_rvc_json_exits_2(tmp_path: Path):
    proc, _, _ = run_soak(tmp_path, ["--epochs", "1", "--gate-interval", "0"])
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "rvc.json" in proc.stderr
    assert "attach-rvc.sh" in proc.stderr
    assert_no_secret(proc)

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    proc2, _, _ = run_soak(
        tmp_path,
        ["--run-dir", str(run_dir), "--epochs", "1", "--gate-interval", "0"],
    )
    assert proc2.returncode == 2, proc2.stderr
    assert proc2.stdout == ""
    assert "rvc.json" in proc2.stderr
    assert "attach-rvc.sh" in proc2.stderr
    assert_no_secret(proc2)


def test_soak_gate_rvc_unhealthy_exits_3(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    write_curl_stub(tmp_path)
    write_report_stub(tmp_path)
    (tmp_path / "curl-state" / "rvc-health").write_text("503", encoding="utf-8")
    proc, _, _ = run_soak(tmp_path, soak_args(run_dir), reset_stubs=False)
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "RVC /health" in proc.stderr
    assert "503" in proc.stderr
    assert_no_secret(proc)
    assert_artifacts(run_dir)
    assert (run_dir / "metrics-start.txt").stat().st_size > 0
    assert (run_dir / "metrics-end.txt").stat().st_size > 0


def test_soak_gate_bn_health_exits_3(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    write_curl_stub(tmp_path)
    (tmp_path / "curl-state" / "bn-health").write_text("500", encoding="utf-8")
    write_report_stub(tmp_path)
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    full = soak_env(
        tmp_path,
        docker=docker,
        curl=tmp_path / "curl",
        report=tmp_path / "devnet_report",
    )
    proc = subprocess.run(
        ["bash", str(SOAK), *soak_args(run_dir)],
        capture_output=True,
        text=True,
        env=full,
        timeout=20,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "node/health" in proc.stderr
    assert "500" in proc.stderr
    assert_no_secret(proc)
    assert_artifacts(run_dir)


def test_soak_gate_k8_blocked_exits_3(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    write_curl_stub(tmp_path)
    (tmp_path / "curl-state" / "k8-seq").write_text("0\n1\n", encoding="utf-8")
    write_report_stub(tmp_path)
    docker = tmp_path / "docker"
    docker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    docker.chmod(0o755)
    full = soak_env(
        tmp_path,
        docker=docker,
        curl=tmp_path / "curl",
        report=tmp_path / "devnet_report",
    )
    proc = subprocess.run(
        ["bash", str(SOAK), *soak_args(run_dir)],
        capture_output=True,
        text=True,
        env=full,
        timeout=20,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "blocked" in proc.stderr.lower()
    assert_no_secret(proc)
    assert_artifacts(run_dir)


def test_soak_transient_scrape_error_continues(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    (tmp_path / "fail-gauges-once").write_text("1", encoding="utf-8")
    proc, _, rlog = run_soak(tmp_path, soak_args(run_dir))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert "WARN" in proc.stderr or "warn" in proc.stderr.lower()
    assert "skipping sample" in proc.stderr
    assert_no_secret(proc)
    rows = sample_rows(run_dir)
    assert len(rows) == _GATED_SLOTS - 1
    cmds = stub_cmds(rlog)
    gauges = [c for c in cmds if "--gauges-only" in c]
    assert len(gauges) == _GATED_SLOTS


def test_soak_samples_jsonl_one_row_per_slot(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    proc, _, rlog = run_soak(tmp_path, soak_args(run_dir))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    assert_artifacts(run_dir)
    rows = sample_rows(run_dir)
    assert len(rows) == _GATED_SLOTS
    slots = [row["slot"] for row in rows]
    assert slots == list(range(_START_SLOT, _START_SLOT + _GATED_SLOTS))
    for row in rows:
        assert set(row) >= {"t", "slot", "gauges"}
        assert isinstance(row["gauges"], dict)
        assert row["t"]
    cmds = stub_cmds(rlog)
    gauges = [c for c in cmds if "--gauges-only" in c]
    assert len(gauges) == _GATED_SLOTS
    for cmd, slot in zip(gauges, slots):
        assert "--slot" in cmd
        assert str(slot) in cmd
        assert "--append" in cmd
    outs = [c for c in cmds if "--out" in c]
    assert any("metrics-start.txt" in c for c in outs)
    assert any("metrics-end.txt" in c for c in outs)


def test_soak_uses_bn_genesis_not_rvc_json_for_slot_clock(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir, genesis_time="9999999999")
    proc, clog, _ = run_soak(tmp_path, soak_args(run_dir))
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    curl_cmds = stub_cmds(clog)
    genesis = [c for c in curl_cmds if "/eth/v1/beacon/genesis" in c]
    assert genesis, curl_cmds
    assert len(genesis) == 1
    rows = sample_rows(run_dir)
    assert rows[0]["slot"] == _START_SLOT
    rvc = json.loads((run_dir / "rvc.json").read_text(encoding="utf-8"))
    assert rvc["genesis_time"] == "9999999999"


def test_soak_dn1_double_run_no_prompt(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    proc1, _, _ = run_soak(tmp_path, soak_args(run_dir))
    assert proc1.returncode == 0, proc1.stderr
    assert proc1.stdout == ""
    assert_no_secret(proc1)
    proc2, _, _ = run_soak(tmp_path, soak_args(run_dir))
    assert proc2.returncode == 0, proc2.stderr
    assert proc2.stdout == ""
    assert_no_secret(proc2)
    assert_artifacts(run_dir)
    assert len(sample_rows(run_dir)) == _GATED_SLOTS


def test_soak_report_parses_soak_output(tmp_path: Path, dr):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    proc, _, _ = run_soak(tmp_path, soak_args(run_dir))
    assert proc.returncode == 0, proc.stderr
    run_json = FIXTURES / "run__fast_n4.json"
    (run_dir / "run.json").write_text(
        run_json.read_text(encoding="utf-8"), encoding="utf-8"
    )
    code = dr.main(["report", "--run-dir", str(run_dir)])
    assert code == 0
    client_path = run_dir / "client.json"
    assert client_path.is_file()
    text = client_path.read_text(encoding="utf-8")
    client = json.loads(text)
    assert "NaN" not in text
    assert "Infinity" not in text
    json.dumps(client, allow_nan=False, sort_keys=True)
    assert client["window"]["start_slot"] == _START_SLOT
    assert client["window"]["end_slot"] == _START_SLOT + _GATED_SLOTS - 1


def test_common_bn_url_rvc_url_current_slot(tmp_path: Path):
    curl, log = write_curl_stub(tmp_path)
    proc = run_common(
        'printf "%s\\n%s\\n%s\\n" "$(bn_url)" "$(rvc_url)" "$(current_slot)"',
        env={
            "CURL": str(curl),
            "NOW_UNIX": _NOW_UNIX,
            "CL_HTTP_PORT": "5052",
            "RVC_METRICS_PORT": "8080",
        },
    )
    assert proc.returncode == 0, proc.stderr
    bn, rvc, slot = proc.stdout.strip().splitlines()
    assert bn == "http://127.0.0.1:5052"
    assert rvc == "http://127.0.0.1:8080"
    assert slot == str(_START_SLOT)
    recorded = log.read_text(encoding="utf-8")
    assert "/eth/v1/beacon/genesis" in recorded
    proc2 = run_common(
        "bn_genesis_time >/dev/null; current_slot >/dev/null; current_slot",
        env={
            "CURL": str(curl),
            "NOW_UNIX": _NOW_UNIX,
            "CL_HTTP_PORT": "5052",
            "RVC_METRICS_PORT": "8080",
        },
    )
    assert proc2.returncode == 0, proc2.stderr
    assert proc2.stdout.strip() == str(_START_SLOT)
    genesis_lines = [
        line
        for line in log.read_text(encoding="utf-8").splitlines()
        if "/eth/v1/beacon/genesis" in line
    ]
    assert len(genesis_lines) == 2


def test_soak_k8_unreadable_exits_3(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    write_curl_stub(tmp_path)
    write_report_stub(tmp_path)
    (tmp_path / "curl-state" / "metrics-code").write_text("404", encoding="utf-8")
    proc, _, _ = run_soak(tmp_path, soak_args(run_dir), reset_stubs=False)
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "K8" in proc.stderr
    assert "unreadable" in proc.stderr
    assert_no_secret(proc)
    assert_artifacts(run_dir)


def test_soak_k8_missing_series_exits_3(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    write_curl_stub(tmp_path)
    write_report_stub(tmp_path)
    (tmp_path / "curl-state" / "metrics-body").write_text(
        'rvc_slashing_protection_checks_total{result="safe"} 80\n',
        encoding="utf-8",
    )
    proc, _, _ = run_soak(tmp_path, soak_args(run_dir), reset_stubs=False)
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "K8" in proc.stderr
    assert_no_secret(proc)
    assert_artifacts(run_dir)


def test_soak_dead_bn_at_start_exits_3(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    write_curl_stub(tmp_path)
    write_report_stub(tmp_path)
    (tmp_path / "curl-state" / "bn-health").write_text("000", encoding="utf-8")
    proc, clog, _ = run_soak(tmp_path, soak_args(run_dir), reset_stubs=False)
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "node/health" in proc.stderr
    assert_no_secret(proc)
    assert_artifacts(run_dir)
    genesis = [c for c in stub_cmds(clog) if "/eth/v1/beacon/genesis" in c]
    assert genesis == [], genesis


def test_soak_refuses_symlink_artifacts(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    secret = tmp_path / "secret.txt"
    secret.write_text("keep\n", encoding="utf-8")
    (run_dir / "samples.jsonl").symlink_to(secret)
    proc, _, _ = run_soak(tmp_path, soak_args(run_dir))
    assert proc.returncode == 2, proc.stderr
    assert proc.stdout == ""
    assert "symlink" in proc.stderr
    assert_no_secret(proc)
    assert secret.read_text(encoding="utf-8") == "keep\n"


def test_soak_curl_uses_hardened_flags(tmp_path: Path):
    run_dir = tmp_path / "run"
    plant_rvc_json(run_dir)
    proc, clog, _ = run_soak(tmp_path, soak_args(run_dir))
    assert proc.returncode == 0, proc.stderr
    cmds = stub_cmds(clog)
    health = [c for c in cmds if "/health" in c or "/metrics" in c]
    assert health, cmds
    for line in health:
        assert "-q" in line or "--disable" in line
        assert "--no-location" in line
        assert "-g" in line
        assert "--path-as-is" in line
        assert "--proto" in line
