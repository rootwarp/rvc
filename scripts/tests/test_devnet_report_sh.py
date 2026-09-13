"""Contract tests for scripts/devnet/report.sh (issues 5.3 and 5.4).

VALIDATOR_PERF is a stub that echoes a fixture and exits a parameterised code.
DEVNET_REPORT wraps the real devnet_report.py (issue 5.4) unless overridden.
disable_socket() via conftest autouse. No live BN, no sockets.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

REPORT = Path(__file__).resolve().parents[1] / "devnet" / "report.sh"
DEVNET_REPORT_PY = Path(__file__).resolve().parents[1] / "devnet_report.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
KEYPATHS = FIXTURES / "verdict_json__keypaths.txt"

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
    "VALIDATOR_PERF",
    "DEVNET_REPORT",
    "STRICT",
)

_MNEMONIC = "test test test test test test test test test test test junk"
_READ_CMD_RE = re.compile(r"(?m)^\s*read\s")

_PUBKEYS = [
    "0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
    "0x222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222",
]


def _bare(pk: str) -> str:
    item = pk.strip()
    if item.lower().startswith("0x"):
        item = item[2:]
    return item.lower()


_BARE_PUBKEYS = [_bare(pk) for pk in _PUBKEYS]


def _fixture_json(name: str) -> Path:
    return FIXTURES / f"validator_perf__{name}.json"


def write_devnet_report_wrapper(tmp_path: Path) -> tuple[Path, Path]:
    argv_log = tmp_path / "devnet_report.argv"
    stub = tmp_path / "devnet_report"
    stub.write_text(
        "#!/bin/sh\n"
        f"log={shlex.quote(str(argv_log))}\n"
        f"py={shlex.quote(str(DEVNET_REPORT_PY))}\n"
        ": > \"$log\"\n"
        "for a in \"$@\"; do\n"
        "  printf '%s\\n' \"$a\" >> \"$log\"\n"
        "done\n"
        "exec python3 \"$py\" \"$@\"\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, argv_log


def write_perf_stub(tmp_path: Path) -> tuple[Path, Path]:
    argv_log = tmp_path / "validator_perf.argv"
    stub = tmp_path / "validator_perf"
    stub.write_text(
        "#!/bin/sh\n"
        f"log={shlex.quote(str(argv_log))}\n"
        ": > \"$log\"\n"
        "for a in \"$@\"; do\n"
        "  printf '%s\\n' \"$a\" >> \"$log\"\n"
        "done\n"
        "body=${VP_BODY:-}\n"
        "code=${VP_EXIT:-0}\n"
        "if [ -n \"$body\" ] && [ -f \"$body\" ]; then\n"
        "  cat \"$body\"\n"
        "fi\n"
        "exit \"$code\"\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, argv_log


def report_env(
    tmp_path: Path,
    extra: dict[str, str] | None = None,
    *,
    stub: Path | None = None,
) -> dict[str, str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full["DOCKER"] = "/bin/echo"
    full["CURL"] = "/bin/echo"
    full["DATA_DIR"] = str(tmp_path / "data")
    full["RUNS_DIR"] = str(tmp_path / "runs")
    full["VALIDATOR_PERF"] = str(stub or (tmp_path / "validator_perf"))
    full["VP_BODY"] = str(_fixture_json("ok"))
    full["VP_EXIT"] = "0"
    if extra is None or "DEVNET_REPORT" not in extra:
        dr_stub, _ = write_devnet_report_wrapper(tmp_path)
        full["DEVNET_REPORT"] = str(dr_stub)
    if extra:
        full.update(extra)
    return full


def plant_run_dir(
    tmp_path: Path,
    *,
    epochs: int | None = None,
    pubkeys: list[str] | None = None,
    phase2: bool = True,
    run_json: bool = True,
    rvc_json: bool = True,
    soak: bool = True,
    metrics_end: Path | None = None,
) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    keys = list(pubkeys if pubkeys is not None else _PUBKEYS)
    body = "".join(f"{pk}\n" for pk in keys)
    if phase2:
        phase_dir = tmp_path / "data" / "keys" / "rvc"
        phase_dir.mkdir(parents=True, exist_ok=True)
        (phase_dir / "pubkeys.txt").write_text(body, encoding="utf-8")
    if rvc_json:
        doc = {
            "schema_version": 1,
            "generated_at": "2026-09-12T00:00:00Z",
            "endpoint": "http://127.0.0.1:8080",
            "pid": 4242,
            "key_range": [48, 64],
            "pubkeys": keys,
            "config_path": "/tmp/config.toml",
        }
        (run_dir / "rvc.json").write_text(
            json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8"
        )
    if run_json:
        text = (FIXTURES / "run__fast_n4.json").read_text(encoding="utf-8")
        if epochs is not None:
            parsed = json.loads(text)
            parsed["epochs"] = epochs
            parsed["pubkeys"] = keys
            text = json.dumps(parsed, sort_keys=True) + "\n"
        (run_dir / "run.json").write_text(text, encoding="utf-8")
    if soak:
        shutil.copyfile(
            FIXTURES / "rvc_metrics__start.txt", run_dir / "metrics-start.txt"
        )
        shutil.copyfile(
            metrics_end or (FIXTURES / "rvc_metrics__end.txt"),
            run_dir / "metrics-end.txt",
        )
        shutil.copyfile(
            FIXTURES / "samples__gauges.jsonl", run_dir / "samples.jsonl"
        )
    return run_dir


def run_report(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    env: dict[str, str] | None = None,
    stub: Path | None = None,
    vp_exit: int = 0,
    vp_body: str = "ok",
    timeout: float = 30,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    if stub is None:
        stub, argv_log = write_perf_stub(tmp_path)
    else:
        argv_log = tmp_path / "validator_perf.argv"
    extra = {
        "VP_EXIT": str(vp_exit),
        "VP_BODY": str(_fixture_json(vp_body)),
    }
    if env:
        extra.update(env)
    full = report_env(tmp_path, extra, stub=stub)
    proc = subprocess.run(
        ["bash", str(REPORT), *args],
        capture_output=True,
        text=True,
        env=full,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    return proc, argv_log


def argv_list(log: Path) -> list[str]:
    if not log.is_file():
        return []
    return [line for line in log.read_text(encoding="utf-8").splitlines() if line]


def argv_pairs(argv: list[str]) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    i = 0
    while i < len(argv):
        key = argv[i]
        if key.startswith("--") and i + 1 < len(argv) and not argv[i + 1].startswith(
            "--"
        ):
            out.setdefault(key, []).append(argv[i + 1])
            i += 2
            continue
        out.setdefault(key, []).append("")
        i += 1
    return out


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob


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


def _strip_metric_family(path: Path, family: str) -> None:
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines(keepends=True)
        if family not in line
    ]
    path.write_text("".join(lines), encoding="utf-8")


def _committed_keypaths() -> list[str]:
    return KEYPATHS.read_text(encoding="utf-8").splitlines()


def _load_verdict(run_dir: Path) -> dict:
    return json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))


def _rewrite_blocked(
    run_dir: Path,
    value: str | None,
    *,
    files: tuple[str, ...] = ("metrics-end.txt",),
) -> None:
    needle = 'rvc_slashing_protection_checks_total{result="blocked"}'
    for name in files:
        path = run_dir / name
        out: list[str] = []
        for line in path.read_text(encoding="utf-8").splitlines(True):
            if needle in line:
                if value is None:
                    continue
                out.append(f"{needle} {value}\n")
                continue
            out.append(line)
        path.write_text("".join(out), encoding="utf-8")


def test_report_sh_syntax():
    assert REPORT.is_file(), REPORT
    assert os.access(REPORT, os.X_OK)
    proc = subprocess.run(
        ["bash", "-n", str(REPORT)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = REPORT.read_text(encoding="utf-8")
    assert _READ_CMD_RE.search(text) is None
    assert "read -p" not in text
    assert "source" in text and "lib/common.sh" in text
    assert "parse_common_flags" in text
    assert "translate_perf_exit()" in text
    assert "--fail-under" in text
    assert "--strict" in text
    assert "VALIDATOR_PERF" in text
    assert "--allow-unfinalized" in text
    assert "--json" in text
    assert "--pubkeys-file" in text
    assert re.search(r"(?m)^\s*docker\s", text) is None
    assert "verdict.json" in text
    assert "client.json" in text
    assert "write_verdict()" in text
    assert "assert_no_blocked()" in text
    assert "DEVNET_REPORT" in text
    after = text.split("write_verdict()", 1)[1]
    match = re.match(r"(?s) \{.*?\n\}\n", after)
    assert match is not None
    verdict_fn = match.group(0)
    assert "jq" in verdict_fn
    assert "python3" not in verdict_fn
    assert "_render_chain_half" not in verdict_fn
    assert "O_NOFOLLOW" in text
    assert ".tmp.$$" not in text
    assert "KEYS_DIR}/rvc/pubkeys" not in text
    assert "DRY_RUN=0" in text


def test_report_sh_chain_json_is_child_stdout(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    proc, argv_log = run_report(
        tmp_path, ["--run-dir", str(run_dir)], vp_body="ok", vp_exit=0
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    chain = run_dir / "chain.json"
    assert chain.is_file()
    assert chain.read_bytes() == _fixture_json("ok").read_bytes()
    argv = argv_list(argv_log)
    pairs = argv_pairs(argv)
    assert "--pubkeys-file" in pairs
    assert Path(pairs["--pubkeys-file"][0]).resolve() == (
        run_dir / "rvc-pubkeys.txt"
    ).resolve()
    assert pairs["--epochs"] == ["4"]
    assert "--allow-unfinalized" in argv
    assert "--json" in argv
    assert pairs["--beacon-url"] == ["http://127.0.0.1:5052"]
    assert "--degraded-ok" not in argv


def test_report_sh_rvc_pubkeys_is_bare_hex_from_rvc_json(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    phase2 = tmp_path / "data" / "keys" / "rvc" / "pubkeys.txt"
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 0, proc.stderr
    dest = run_dir / "rvc-pubkeys.txt"
    assert dest.is_file()
    lines = [ln for ln in dest.read_text(encoding="utf-8").splitlines() if ln]
    assert lines == _BARE_PUBKEYS
    assert dest.read_bytes() != phase2.read_bytes()
    assert [_bare(pk) for pk in phase2.read_text(encoding="utf-8").splitlines() if pk] == lines
    rvc = json.loads((run_dir / "rvc.json").read_text(encoding="utf-8"))
    assert [_bare(pk) for pk in rvc["pubkeys"]] == lines
    assert all(not ln.startswith(("0x", "0X")) for ln in lines)
    assert all(re.fullmatch(r"[0-9a-f]{96}", ln) for ln in lines)


def test_report_sh_rvc_pubkeys_prefers_rvc_json_over_phase2(tmp_path: Path):
    other = [
        "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    ]
    run_dir = plant_run_dir(tmp_path, pubkeys=_PUBKEYS)
    phase2 = tmp_path / "data" / "keys" / "rvc" / "pubkeys.txt"
    phase2.write_text("".join(f"{pk}\n" for pk in other), encoding="utf-8")
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 0, proc.stderr
    lines = [
        ln
        for ln in (run_dir / "rvc-pubkeys.txt").read_text(encoding="utf-8").splitlines()
        if ln
    ]
    assert lines == _BARE_PUBKEYS
    assert "a" * 96 not in lines


def test_report_sh_rvc_pubkeys_from_rvc_json_without_phase2(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path, phase2=False)
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 0, proc.stderr
    dest = run_dir / "rvc-pubkeys.txt"
    assert dest.is_file()
    lines = [ln for ln in dest.read_text(encoding="utf-8").splitlines() if ln]
    assert lines == _BARE_PUBKEYS


def test_report_sh_epochs_from_run_json_not_profile(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path, epochs=7)
    proc, argv_log = run_report(
        tmp_path,
        ["--run-dir", str(run_dir), "--profile", "safe"],
        env={"EPOCHS": "99", "PROFILE": "safe"},
    )
    assert proc.returncode == 0, proc.stderr
    pairs = argv_pairs(argv_list(argv_log))
    assert pairs["--epochs"] == ["7"]
    assert "99" not in argv_list(argv_log)
    assert "8" not in pairs.get("--epochs", [])


def test_report_sh_missing_run_json_exits_2(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path, run_json=False)
    proc, argv_log = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "run.json" in proc.stderr
    assert "run.sh" in proc.stderr
    assert argv_list(argv_log) == []
    assert not (run_dir / "chain.json").exists()
    assert_no_secret(proc)


def test_report_sh_missing_rvc_json_exits_2(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path, rvc_json=False)
    proc, argv_log = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 2
    assert "rvc.json" in proc.stderr
    assert "attach-rvc.sh" in proc.stderr
    assert argv_list(argv_log) == []
    assert_no_secret(proc)


@pytest.mark.parametrize(
    ("child", "strict", "expected"),
    [
        (0, False, 0),
        (1, False, 1),
        (2, False, 1),
        (3, False, 0),
        (3, True, 3),
        (4, False, 4),
        (5, False, 1),
        (7, False, 1),
    ],
)
def test_report_sh_exit_map_table(
    tmp_path: Path, child: int, strict: bool, expected: int
):
    run_dir = plant_run_dir(tmp_path)
    body = {0: "ok", 3: "degraded", 4: "threshold"}.get(child, "ok")
    args = ["--run-dir", str(run_dir)]
    if strict:
        args.append("--strict")
    proc, _ = run_report(tmp_path, args, vp_exit=child, vp_body=body)
    assert proc.returncode == expected, proc.stderr
    assert proc.stdout == ""
    assert (run_dir / "chain.json").is_file()
    if child == 3 and not strict:
        assert "degraded" in proc.stderr
    if child == 3 and strict:
        assert proc.returncode == 3
        assert "degraded" in proc.stderr
    if child == 4:
        verdict = _load_verdict(run_dir)
        assert verdict["exit_code"] == 4
        assert verdict["verdict"] == "fail"
        assert verdict["gates"]["chain_thresholds"] == "fail"
        assert verdict["gates"]["s5a_presence"] == "pass"
        assert verdict["gates"]["s5b_liveness"] == "pass"
        assert verdict["gates"]["s7_blocked"] == "pass"
    assert_no_secret(proc)


def test_report_sh_strict_surfaces_degraded(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    proc, argv_log = run_report(
        tmp_path,
        ["--run-dir", str(run_dir), "--strict"],
        vp_exit=3,
        vp_body="degraded",
    )
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "degraded" in proc.stderr
    assert "--degraded-ok" not in argv_list(argv_log)
    assert (run_dir / "chain.json").read_bytes() == _fixture_json(
        "degraded"
    ).read_bytes()
    assert_no_secret(proc)


def test_report_sh_fail_under_passthrough(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    proc, argv_log = run_report(
        tmp_path,
        ["--run-dir", str(run_dir), "--fail-under", "participation_rate=0.95"],
        vp_exit=4,
        vp_body="threshold",
    )
    assert proc.returncode == 4, proc.stderr
    assert proc.stdout == ""
    argv = argv_list(argv_log)
    pairs = argv_pairs(argv)
    assert pairs["--fail-under"] == ["participation_rate=0.95"]
    assert "--degraded-ok" not in argv
    assert (run_dir / "chain.json").read_bytes() == _fixture_json(
        "threshold"
    ).read_bytes()
    verdict = _load_verdict(run_dir)
    assert verdict["exit_code"] == 4
    assert verdict["verdict"] == "fail"
    assert verdict["gates"]["chain_thresholds"] == "fail"
    assert verdict["gates"]["s7_blocked"] == "pass"
    assert_no_secret(proc)


def test_report_sh_never_passes_degraded_ok(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    proc, argv_log = run_report(
        tmp_path,
        ["--run-dir", str(run_dir)],
        vp_exit=3,
        vp_body="degraded",
    )
    assert proc.returncode == 0, proc.stderr
    argv = argv_list(argv_log)
    assert argv
    assert "--degraded-ok" not in argv
    text = REPORT.read_text(encoding="utf-8")
    assert "--degraded-ok" not in text
    assert "degraded" in proc.stderr


def test_report_sh_stdin_devnull_twice(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    first, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    second, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert first.returncode == 0, first.stderr
    assert second.returncode == first.returncode
    assert first.stdout == ""
    assert second.stdout == ""
    assert_no_secret(first)
    assert_no_secret(second)


def test_report_sh_run_dir_required(tmp_path: Path):
    proc, argv_log = run_report(tmp_path, [])
    assert proc.returncode == 2
    assert "--run-dir" in proc.stderr
    assert argv_list(argv_log) == []
    assert_no_secret(proc)


def test_report_sh_dry_run_env_does_not_skip(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    proc, argv_log = run_report(
        tmp_path, ["--run-dir", str(run_dir)], env={"DRY_RUN": "1"}
    )
    assert proc.returncode == 0, proc.stderr
    assert argv_list(argv_log)
    assert (run_dir / "chain.json").is_file()
    assert "dry-run complete" not in proc.stderr
    assert_no_secret(proc)


def test_report_sh_dry_run_flag_skips_child(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    proc, argv_log = run_report(
        tmp_path, ["--run-dir", str(run_dir), "--dry-run"]
    )
    assert proc.returncode == 0, proc.stderr
    assert argv_list(argv_log) == []
    assert not (run_dir / "chain.json").exists()
    assert "dry-run complete" in proc.stderr
    assert_no_secret(proc)


def test_report_sh_chain_json_refuses_dest_symlink(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    victim = tmp_path / "victim-chain"
    victim.write_text("untouched\n", encoding="utf-8")
    dest = run_dir / "chain.json"
    dest.symlink_to(victim)
    proc, argv_log = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 2, proc.stderr
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"
    assert dest.is_symlink()
    assert argv_list(argv_log)
    assert_no_secret(proc)


def test_report_sh_rvc_pubkeys_refuses_dest_symlink(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    victim = tmp_path / "victim-pubkeys"
    victim.write_text("untouched\n", encoding="utf-8")
    dest = run_dir / "rvc-pubkeys.txt"
    dest.symlink_to(victim)
    proc, argv_log = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 2, proc.stderr
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"
    assert dest.is_symlink()
    assert argv_list(argv_log) == []
    assert not (run_dir / "chain.json").exists()
    assert_no_secret(proc)


def test_report_sh_verdict_key_paths(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    for name in ("client.json", "chain.json", "report.txt", "verdict.json"):
        assert (run_dir / name).is_file(), name
    report_txt = (run_dir / "report.txt").read_text(encoding="utf-8")
    assert "rvc_attestations_total" in report_txt
    assert "--- chain ---" in report_txt
    assert "soak window" in report_txt
    assert "key_range" in report_txt
    assert "part%" in report_txt
    text = (run_dir / "verdict.json").read_text(encoding="utf-8")
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
    assert doc["verdict"] == "pass"
    assert doc["exit_code"] == 0
    assert doc["run_id"] == "20260912T000000Z-f110c1e"
    assert doc["gates"]["s5a_presence"] == "pass"
    assert doc["gates"]["s5b_liveness"] == "pass"
    assert doc["gates"]["s7_blocked"] == "pass"
    assert doc["gates"]["chain_thresholds"] == "pass"
    dr_argv = argv_list(tmp_path / "devnet_report.argv")
    assert dr_argv[:1] == ["report"]
    assert "--run-dir" in dr_argv


def test_report_sh_blocked_in_metrics_end_exits_3(tmp_path: Path):
    run_dir = plant_run_dir(
        tmp_path, metrics_end=FIXTURES / "rvc_metrics__end_blocked.txt"
    )
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "blocked" in proc.stderr.lower()
    assert_no_secret(proc)
    verdict = json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["gates"]["s7_blocked"] == "fail"
    assert verdict["verdict"] == "fail"
    assert verdict["exit_code"] == 3
    assert verdict["gates"]["s5b_liveness"] == "pass"


def test_report_sh_missing_family_fails_s5a(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    family = "rvc_slashing_reserve_tx_hold_duration_ms"
    _strip_metric_family(run_dir / "metrics-start.txt", family)
    _strip_metric_family(run_dir / "metrics-end.txt", family)
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert family in proc.stderr
    assert "K9" in proc.stderr
    assert_no_secret(proc)
    verdict = json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))
    assert verdict["gates"]["s5a_presence"] == "fail"
    assert verdict["verdict"] == "fail"
    assert verdict["exit_code"] == 3


def test_report_sh_no_proposal_window_annotation(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    client = json.loads((run_dir / "client.json").read_text(encoding="utf-8"))
    verdict = json.loads((run_dir / "verdict.json").read_text(encoding="utf-8"))
    assert "no_proposal_window" in client["annotations"]
    assert "no_proposal_window" in verdict["annotations"]
    assert client["presence"]["K6"] == "family_present_child_absent"
    assert verdict["gates"]["s5a_presence"] == "pass"
    assert verdict["verdict"] == "pass"
    assert verdict["exit_code"] == 0


def test_report_sh_k_rows_match_committed_families():
    text = REPORT.read_text(encoding="utf-8")
    match = re.search(r"(?ms)^_K_ROWS=\(\n(.*?)^\)\s*$", text)
    assert match is not None
    got = []
    for raw in match.group(1).splitlines():
        line = raw.strip().strip('"')
        if line:
            got.append(line)
    want = [
        ln
        for ln in (FIXTURES / "k_rows__families.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if ln.strip()
    ]
    assert got == want


@pytest.mark.parametrize("value", ["1e2", "+1"])
def test_report_sh_blocked_nonzero_forms_exit_3(tmp_path: Path, value: str):
    run_dir = plant_run_dir(tmp_path)
    _rewrite_blocked(run_dir, value)
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "blocked" in proc.stderr.lower()
    assert_no_secret(proc)
    verdict = _load_verdict(run_dir)
    assert verdict["gates"]["s7_blocked"] == "fail"
    assert verdict["verdict"] == "fail"
    assert verdict["exit_code"] == 3


@pytest.mark.parametrize("value", ["+Inf", "NaN", None])
def test_report_sh_blocked_unreadable_not_pass(tmp_path: Path, value: str | None):
    run_dir = plant_run_dir(tmp_path)
    if value is None:
        _rewrite_blocked(
            run_dir,
            None,
            files=("metrics-start.txt", "metrics-end.txt"),
        )
    else:
        _rewrite_blocked(run_dir, value)
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    verdict = _load_verdict(run_dir)
    assert verdict["verdict"] != "pass"
    assert verdict["gates"]["s7_blocked"] == "fail"
    assert verdict["exit_code"] == 3


def test_report_sh_blocked_missing_from_end_only_exits_3(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    start = (run_dir / "metrics-start.txt").read_text(encoding="utf-8")
    assert 'result="blocked"} 0' in start
    _rewrite_blocked(run_dir, None, files=("metrics-end.txt",))
    assert 'result="blocked"}' in (
        run_dir / "metrics-start.txt"
    ).read_text(encoding="utf-8")
    assert 'result="blocked"}' not in (
        run_dir / "metrics-end.txt"
    ).read_text(encoding="utf-8")
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    verdict = _load_verdict(run_dir)
    assert verdict["gates"]["s7_blocked"] == "fail"
    assert verdict["verdict"] != "pass"
    assert verdict["exit_code"] == 3


def test_report_sh_blocked_end_then_deleted_exits_3(tmp_path: Path):
    run_dir = plant_run_dir(
        tmp_path, metrics_end=FIXTURES / "rvc_metrics__end_blocked.txt"
    )
    assert 'result="blocked"} 1' in (
        run_dir / "metrics-end.txt"
    ).read_text(encoding="utf-8")
    _rewrite_blocked(run_dir, None, files=("metrics-end.txt",))
    assert 'result="blocked"}' not in (
        run_dir / "metrics-end.txt"
    ).read_text(encoding="utf-8")
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    verdict = _load_verdict(run_dir)
    assert verdict["gates"]["s7_blocked"] == "fail"
    assert verdict["verdict"] != "pass"
    assert verdict["exit_code"] == 3


def test_report_sh_s5b_zero_k1_exits_3(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    path = run_dir / "metrics-end.txt"
    text = path.read_text(encoding="utf-8")
    text = text.replace(
        'rvc_orchestrator_slots_processed_total{result="success"} 228',
        'rvc_orchestrator_slots_processed_total{result="success"} 100',
    )
    path.write_text(text, encoding="utf-8")
    proc, _ = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert "S5b" in proc.stderr or "liveness" in proc.stderr.lower()
    assert "K1" in proc.stderr
    assert_no_secret(proc)
    verdict = _load_verdict(run_dir)
    assert verdict["gates"]["s5b_liveness"] == "fail"
    assert verdict["gates"]["s5a_presence"] == "pass"
    assert verdict["verdict"] == "fail"
    assert verdict["exit_code"] == 3


def test_report_sh_blocked_precedes_kpi_4(tmp_path: Path):
    run_dir = plant_run_dir(
        tmp_path, metrics_end=FIXTURES / "rvc_metrics__end_blocked.txt"
    )
    proc, _ = run_report(
        tmp_path,
        ["--run-dir", str(run_dir)],
        vp_exit=4,
        vp_body="threshold",
    )
    assert proc.returncode == 3, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    verdict = _load_verdict(run_dir)
    assert verdict["exit_code"] == 3
    assert verdict["verdict"] == "fail"
    assert verdict["gates"]["s7_blocked"] == "fail"
    assert verdict["gates"]["chain_thresholds"] == "fail"


def test_report_sh_chain_half_sanitizes_control_chars(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    doc = json.loads(_fixture_json("ok").read_text(encoding="utf-8"))
    injected = "active_ongoing\nDEGRADED:\ninjected  forged  all"
    doc["validators"][0]["status"] = injected
    doc["degradations"] = [
        {
            "metric": "rewards_gwei",
            "scope": "scope",
            "reason": "state_unavailable\nDEGRADED:\nforged",
            "detail": "detail",
        }
    ]
    body = tmp_path / "injected-status.json"
    body.write_text(json.dumps(doc) + "\n", encoding="utf-8")
    proc, _ = run_report(
        tmp_path, ["--run-dir", str(run_dir)], env={"VP_BODY": str(body)}
    )
    assert proc.returncode == 0, proc.stderr
    assert_no_secret(proc)
    report_txt = (run_dir / "report.txt").read_text(encoding="utf-8")
    heading_lines = [
        ln for ln in report_txt.splitlines() if ln.strip() == "DEGRADED:"
    ]
    assert len(heading_lines) == 1
    assert "\nDEGRADED:\ninjected" not in report_txt
    assert "injected" in report_txt
    assert any(
        "injected" in ln and ln.strip() != "DEGRADED:"
        for ln in report_txt.splitlines()
    )


def test_report_sh_reads_fail_under_not_report_fail_under(tmp_path: Path):
    text = REPORT.read_text(encoding="utf-8")
    assert text.count("REPORT_FAIL_UNDER") == 0
    run_dir = plant_run_dir(tmp_path)
    proc, argv_log = run_report(
        tmp_path,
        ["--run-dir", str(run_dir)],
        env={"FAIL_UNDER": "participation_rate=0.95,target_rate=0.95"},
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    argv = argv_list(argv_log)
    pairs = argv_pairs(argv)
    assert pairs["--fail-under"] == [
        "participation_rate=0.95",
        "target_rate=0.95",
    ]
    assert "REPORT_FAIL_UNDER" not in argv
    assert_no_secret(proc)


def test_report_sh_reads_fail_under_from_run_json(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    path = run_dir / "run.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    doc["fail_under"] = "participation_rate=0.95,target_rate=0.95"
    path.write_text(json.dumps(doc, sort_keys=True) + "\n", encoding="utf-8")
    proc, argv_log = run_report(tmp_path, ["--run-dir", str(run_dir)])
    assert proc.returncode == 0, proc.stderr
    pairs = argv_pairs(argv_list(argv_log))
    assert pairs["--fail-under"] == [
        "participation_rate=0.95",
        "target_rate=0.95",
    ]
    assert_no_secret(proc)


def test_report_sh_profile_safe_applies_fail_under(tmp_path: Path):
    run_dir = plant_run_dir(tmp_path)
    proc, argv_log = run_report(
        tmp_path, ["--run-dir", str(run_dir), "--profile", "safe"]
    )
    assert proc.returncode == 0, proc.stderr
    pairs = argv_pairs(argv_list(argv_log))
    assert pairs["--fail-under"] == [
        "participation_rate=0.95",
        "target_rate=0.95",
    ]
    assert_no_secret(proc)


