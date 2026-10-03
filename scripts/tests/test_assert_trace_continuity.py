"""Contract tests for scripts/assert-trace-continuity.sh (TRC-5c / #434).

Fixtures are checked-in Jaeger query documents (GET /api/traces?service=rvc).
service.name is data[].processes[processID].serviceName, not a span tag.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "assert-trace-continuity.sh"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

PASS = FIXTURES / "continuity__pass.json"
MISSING = FIXTURES / "continuity__missing_span.json"
SAME = FIXTURES / "continuity__same_service.json"
EMPTY = FIXTURES / "continuity__empty.json"
MALFORMED = FIXTURES / "continuity__malformed.json"
MISSING_TRACE_ID = FIXTURES / "continuity__missing_trace_id.json"
MULTI_PASS_EMPTY = FIXTURES / "continuity__multi_pass_then_empty.json"
MULTI_EMPTY_PASS = FIXTURES / "continuity__multi_empty_then_pass.json"


def _run(
    *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    run_env = os.environ.copy()
    run_env.pop("TRACE_E2E_SPANS_FILE", None)
    if env:
        run_env.update(env)
    return subprocess.run(
        [str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=run_env,
        check=False,
    )


def _text(proc: subprocess.CompletedProcess[str]) -> str:
    return proc.stdout + proc.stderr


def test_script_is_executable_and_strict() -> None:
    assert SCRIPT.is_file()
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    assert SCRIPT.stat().st_mode & stat.S_IXUSR
    syntax = subprocess.run(
        ["bash", "-n", str(SCRIPT)], capture_output=True, text=True, check=False
    )
    assert syntax.returncode == 0, syntax.stderr


def test_pass_fixture_exits_0() -> None:
    doc = json.loads(PASS.read_text(encoding="utf-8"))
    names = {
        span["operationName"]
        for trace in doc["data"]
        for span in trace["spans"]
    }
    assert "slot.process" in names
    assert "signer.v2.sign_block_header" in names or "signer.v2.sign_root" in names
    services = {
        proc["serviceName"]
        for trace in doc["data"]
        for proc in trace["processes"].values()
    }
    assert services >= {"rvc", "rvc-signer"}

    proc = _run(str(PASS))
    assert proc.returncode == 0, _text(proc)
    assert "assert-trace-continuity: ok" in proc.stdout
    assert "serviceNames=rvc,rvc-signer" in proc.stdout


def test_missing_span_exits_nonzero_and_names_spans_and_services() -> None:
    proc = _run(str(MISSING))
    assert proc.returncode != 0
    text = _text(proc)
    assert "assert-trace-continuity: FAIL missing-span:" in text
    assert "slot.process" in text
    assert "signer.v2.sign_attestation_data" in text
    assert "serviceNames=rvc,rvc-signer" in text
    assert "operationNames=" in text


def test_same_service_exits_nonzero_and_ignores_span_tag() -> None:
    doc = json.loads(SAME.read_text(encoding="utf-8"))
    trace = doc["data"][0]
    ops = {span["operationName"] for span in trace["spans"]}
    assert ops == {"slot.process", "signer.v2.sign_block_header"}
    services = {proc["serviceName"] for proc in trace["processes"].values()}
    assert services == {"rvc"}
    signer = next(
        span for span in trace["spans"] if span["operationName"] != "slot.process"
    )
    tag_values = {
        tag["value"] for tag in signer["tags"] if tag["key"] == "service.name"
    }
    assert tag_values == {"rvc-signer"}
    assert len({span["processID"] for span in trace["spans"]}) == 2

    proc = _run(str(SAME))
    assert proc.returncode != 0
    text = _text(proc)
    assert "assert-trace-continuity: FAIL same-service:" in text
    assert "slot.process" in text
    assert "signer.v2.sign_block_header" in text
    assert "serviceNames=rvc" in text
    assert "rvc-signer" not in text


def test_empty_exits_nonzero_with_named_message() -> None:
    proc = _run(str(EMPTY))
    assert proc.returncode != 0
    text = _text(proc)
    assert "assert-trace-continuity: FAIL empty:" in text
    assert "operationNames=(none)" in text
    assert "serviceNames=(none)" in text
    assert "Traceback" not in text
    assert "unbound variable" not in text


def test_malformed_exits_nonzero_with_named_message() -> None:
    proc = _run(str(MALFORMED))
    assert proc.returncode != 0
    text = _text(proc)
    assert "assert-trace-continuity: FAIL malformed:" in text
    assert text.strip().startswith("assert-trace-continuity: FAIL malformed:")
    assert "operationNames=(none)" in text
    assert "serviceNames=(none)" in text
    assert "Traceback" not in text
    assert "unbound variable" not in text


def test_missing_trace_id_does_not_join_spans() -> None:
    doc = json.loads(MISSING_TRACE_ID.read_text(encoding="utf-8"))
    assert all(
        "traceID" not in trace and all("traceID" not in span for span in trace["spans"])
        for trace in doc["data"]
    )
    proc = _run(str(MISSING_TRACE_ID))
    assert proc.returncode != 0
    text = _text(proc)
    assert "assert-trace-continuity: FAIL missing-trace-id:" in text
    assert "assert-trace-continuity: ok" not in text
    assert "slot.process" in text
    assert "signer.v2.sign_attestation_data" in text
    assert "serviceNames=rvc,rvc-signer" in text
    assert "operationNames=" in text


def test_parent_trace_id_still_groups_when_span_ids_are_absent(tmp_path: Path) -> None:
    doc = json.loads(MISSING.read_text(encoding="utf-8"))
    for trace in doc["data"]:
        assert trace["traceID"]
        for span in trace["spans"]:
            del span["traceID"]
    path = tmp_path / "span-ids-absent.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    proc = _run(str(path))
    assert proc.returncode != 0
    text = _text(proc)
    assert "assert-trace-continuity: FAIL missing-span:" in text
    assert "assert-trace-continuity: ok" not in text


def test_second_json_value_is_malformed() -> None:
    for path in (MULTI_PASS_EMPTY, MULTI_EMPTY_PASS):
        text = path.read_text(encoding="utf-8")
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            assert exc.msg == "Extra data"
        else:
            raise AssertionError(f"{path.name} parsed as one JSON value")
        proc = _run(str(path))
        assert proc.returncode != 0, path.name
        got = _text(proc)
        assert "assert-trace-continuity: FAIL malformed:" in got
        assert got.strip().startswith("assert-trace-continuity: FAIL malformed:")
        assert "assert-trace-continuity: ok" not in got
        assert "operationNames=(none)" in got
        assert "serviceNames=(none)" in got


def test_env_override_selects_spans_file_without_an_argument() -> None:
    proc = _run(env={"TRACE_E2E_SPANS_FILE": str(PASS)})
    assert proc.returncode == 0, _text(proc)


def test_argument_overrides_env(tmp_path: Path) -> None:
    proc = _run(str(PASS), env={"TRACE_E2E_SPANS_FILE": str(MALFORMED)})
    assert proc.returncode == 0, _text(proc)

    missing = tmp_path / "absent.json"
    proc = _run(env={"TRACE_E2E_SPANS_FILE": str(missing)})
    assert proc.returncode != 0
    assert "assert-trace-continuity: FAIL missing-file:" in _text(proc)
