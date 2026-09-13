"""DN-17 compare tests. Fixtures only; disable_socket() is autouse in conftest."""

from __future__ import annotations

import hashlib
import json
import math
import os
import shutil
from pathlib import Path

_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_RUN_A = _FIXTURES / "run_a"
_RUN_B = _FIXTURES / "run_b"


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


def _committed_keypaths(name: str) -> set[str]:
    return {
        line
        for line in (_FIXTURES / name).read_text(encoding="utf-8").splitlines()
        if line
    }


def _tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix().encode("utf-8")
        if path.is_symlink():
            digest.update(b"L")
            digest.update(rel)
            digest.update(os.readlink(path).encode("utf-8"))
            continue
        if not path.is_file():
            continue
        digest.update(b"F")
        digest.update(rel)
        digest.update(path.read_bytes())
    return digest.hexdigest()


def _clone_pair(tmp_path: Path) -> tuple[Path, Path]:
    a = tmp_path / "run_a"
    b = tmp_path / "run_b"
    shutil.copytree(_RUN_A, a)
    shutil.copytree(_RUN_B, b)
    return a, b


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _dump(path: Path, obj: object) -> None:
    path.write_text(
        json.dumps(obj, sort_keys=True) + "\n", encoding="utf-8"
    )


def _kpi(payload: dict, name: str) -> dict:
    for row in payload["kpis"]:
        if row["kpi"] == name:
            return row
    raise AssertionError(f"missing kpi {name}")


def _run_json(dr, capsys, a: Path, b: Path, extra: list[str] | None = None) -> tuple[int, dict, str]:
    capsys.readouterr()
    code = dr.main(["compare", str(a), str(b), "--json", *(extra or [])])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    return code, payload, captured.err


def test_compare_exits_4_on_latency_regression(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    client = _load(b / "client.json")
    client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = 0.05
    _dump(b / "client.json", client)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 4
    row = _kpi(payload, "K7.p95")
    assert row["gate"] == "fail"
    assert row["gated"] is True
    assert row["a"] == 0.01
    assert row["b"] == 0.05


def test_compare_ignores_improvement_in_gated_direction(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    client = _load(b / "client.json")
    client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = 0.001
    client["counters"]["rvc_orchestrator_missed_slots_total"][0]["delta"] = 0
    _dump(b / "client.json", client)
    a_client = _load(a / "client.json")
    a_client["counters"]["rvc_orchestrator_missed_slots_total"][0]["delta"] = 4
    _dump(a / "client.json", a_client)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 0
    assert _kpi(payload, "K7.p95")["gate"] == "pass"
    assert _kpi(payload, "K2")["gate"] == "pass"
    assert _kpi(payload, "K2")["b"] == 0
    assert _kpi(payload, "K2")["a"] == 4


def test_compare_ignores_delta_below_abs_floor(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    # A=0.002 s → rel×|A|=0.0005 s; abs_floor=0.001 s. Delta 0.0007 s is
    # above rel but below the floor, so only abs_floor keeps this a pass.
    a_client = _load(a / "client.json")
    b_client = _load(b / "client.json")
    a_client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = 0.002
    b_client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = 0.0027
    _dump(a / "client.json", a_client)
    _dump(b / "client.json", b_client)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 0
    row = _kpi(payload, "K7.p95")
    assert row["gate"] == "pass"
    assert row["a"] == 0.002
    assert row["b"] == 0.0027
    assert row["delta"] > 0.25 * row["a"]
    assert row["delta"] < 0.001


def test_compare_gates_failure_only_kpis_at_zero(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    client = _load(b / "client.json")
    # 4 → 5 is exactly 25% relative; failure-only still gates at absolute 0.
    a_client = _load(a / "client.json")
    a_client["counters"]["rvc_orchestrator_missed_slots_total"][0]["delta"] = 4
    _dump(a / "client.json", a_client)
    client["counters"]["rvc_orchestrator_missed_slots_total"][0]["delta"] = 5
    client["counters"]["rvc_slashing_protection_checks_total"][1]["delta"] = 1
    client["counters"]["rvc_proposals_total"][0]["delta"] = 1
    client["counters"]["rvc_task_exits_total"][0]["delta"] = 1
    _dump(b / "client.json", client)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 4
    assert _kpi(payload, "K2")["gate"] == "fail"
    assert _kpi(payload, "K8.blocked")["gate"] == "fail"
    assert _kpi(payload, "K6.failure")["gate"] == "fail"
    assert _kpi(payload, "K13.exits")["gate"] == "fail"


def test_compare_exact_rel_increase_is_not_a_regression(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    client = _load(b / "client.json")
    client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = 0.0125
    _dump(b / "client.json", client)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 0
    row = _kpi(payload, "K7.p95")
    assert row["a"] == 0.01
    assert row["b"] == 0.0125
    assert row["gate"] == "pass"
    chain = _load(b / "chain.json")
    chain["aggregate"]["participation_rate"] = 0.75
    _dump(b / "chain.json", chain)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 0
    assert _kpi(payload, "participation_rate")["gate"] == "pass"


def test_compare_just_beyond_rel_exits_4(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    client = _load(b / "client.json")
    client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = (
        math.nextafter(0.01 * 1.25, math.inf)
    )
    _dump(b / "client.json", client)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 4
    assert _kpi(payload, "K7.p95")["gate"] == "fail"


def test_compare_exits_4_on_ratio_regression(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    chain = _load(b / "chain.json")
    chain["aggregate"]["participation_rate"] = 0.7
    chain["aggregate"]["target_rate"] = 0.7
    _dump(b / "chain.json", chain)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 4
    part = _kpi(payload, "participation_rate")
    target = _kpi(payload, "target_rate")
    assert part["gate"] == "fail"
    assert target["gate"] == "fail"
    assert part["a"] == 1.0
    assert part["b"] == 0.7
    assert part["gated"] is True


def test_compare_honours_rel_and_abs_floor_overrides(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    client = _load(b / "client.json")
    client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = 0.02
    _dump(b / "client.json", client)
    default_code, default_payload, _ = _run_json(dr, capsys, a, b)
    assert default_code == 4
    assert _kpi(default_payload, "K7.p95")["gate"] == "fail"
    code, payload, _err = _run_json(
        dr, capsys, a, b, extra=["--rel", "2", "--abs-floor", "50ms"]
    )
    assert code == 0
    assert _kpi(payload, "K7.p95")["gate"] == "pass"
    assert payload["rel"] == 2.0
    assert payload["abs_floor"] == 0.05


def test_compare_missing_fingerprint_is_incomparable(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    for path in (a / "run.json", b / "run.json"):
        doc = _load(path)
        del doc["fingerprint"]
        _dump(path, doc)
    client = _load(b / "client.json")
    client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = 0.5
    _dump(b / "client.json", client)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 0
    assert payload["gated"] is False
    assert payload["topology_delta"] is not None
    assert _kpi(payload, "K7.p95")["gate"] == "pass"
    assert _kpi(payload, "K7.p95")["gated"] is False

    sided = tmp_path / "one_sided"
    sided.mkdir()
    a2, b2 = _clone_pair(sided)
    doc = _load(b2 / "run.json")
    del doc["fingerprint"]
    _dump(b2 / "run.json", doc)
    client = _load(b2 / "client.json")
    client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = 0.5
    _dump(b2 / "client.json", client)
    code, payload, _err = _run_json(dr, capsys, a2, b2)
    assert code == 0
    assert payload["gated"] is False
    assert payload["topology_delta"]["fingerprint"]["b"] is None


def test_compare_refuses_to_gate_on_fingerprint_mismatch(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    run_b = _load(b / "run.json")
    run_b["fingerprint"] = "b" * 64
    run_b["images"] = dict(run_b["images"])
    run_b["images"]["geth"] = "ethereum/client-go:other@sha256:00"
    _dump(b / "run.json", run_b)
    client = _load(b / "client.json")
    client["histograms"]["rvc_signing_duration_seconds"][0]["p95"] = 0.5
    _dump(b / "client.json", client)
    capsys.readouterr()
    table_code = dr.main(["compare", str(a), str(b)])
    table_out = capsys.readouterr().out
    assert table_code == 0
    assert "topology_delta" in table_out
    assert "fingerprint" in table_out
    assert "images.geth" in table_out
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 0
    assert payload["gated"] is False
    assert payload["topology_delta"]["fingerprint"]["a"] != payload[
        "topology_delta"
    ]["fingerprint"]["b"]
    assert "images.geth" in payload["topology_delta"]
    assert _kpi(payload, "K7.p95")["gate"] == "pass"
    assert _kpi(payload, "K7.p95")["gated"] is False


def test_compare_tolerates_unknown_chain_json_keys(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    chain_a = _load(a / "chain.json")
    chain_b = _load(b / "chain.json")
    chain_a["aggregate"]["surprise_rate"] = 1.0
    chain_b["aggregate"]["surprise_rate"] = 0.1
    chain_a["aggregate"]["inf_rate"] = 1.0
    chain_b["aggregate"]["inf_rate"] = float("inf")
    chain_a["aggregate"]["nan_rate"] = float("nan")
    chain_b["aggregate"]["nan_rate"] = float("nan")
    chain_b["novel_top_level"] = 99
    _dump(a / "chain.json", chain_a)
    _dump(b / "chain.json", chain_b)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 0
    surprise = _kpi(payload, "surprise_rate")
    assert surprise["gated"] is False
    assert surprise["gate"] == "false"
    assert surprise["a"] == 1.0
    assert surprise["b"] == 0.1
    novel = _kpi(payload, "novel_top_level")
    assert novel["gated"] is False
    assert novel["a"] is None
    assert novel["b"] == 99
    inf_row = _kpi(payload, "inf_rate")
    assert inf_row["gated"] is False
    assert inf_row["a"] == 1.0
    assert inf_row["b"] is None
    assert inf_row["b"] != 0
    nan_row = _kpi(payload, "nan_rate")
    assert nan_row["gated"] is False
    assert nan_row["a"] is None
    assert nan_row["b"] is None
    assert nan_row["a"] != 0
    assert nan_row["b"] != 0


def test_compare_absent_kpi_is_absent_not_zero(dr, tmp_path, capsys):
    a, b = _clone_pair(tmp_path)
    client_a = _load(a / "client.json")
    del client_a["counters"]["rvc_orchestrator_missed_slots_total"]
    _dump(a / "client.json", client_a)
    client_b = _load(b / "client.json")
    client_b["counters"]["rvc_orchestrator_missed_slots_total"][0]["delta"] = 3
    _dump(b / "client.json", client_b)
    chain_b = _load(b / "chain.json")
    del chain_b["aggregate"]["participation_rate"]
    _dump(b / "chain.json", chain_b)
    code, payload, _err = _run_json(dr, capsys, a, b)
    assert code == 0
    missed = _kpi(payload, "K2")
    assert missed["gate"] == "absent"
    assert missed["a"] is None
    assert missed["b"] == 3
    assert missed["delta"] is None
    assert missed["a"] != 0
    part = _kpi(payload, "participation_rate")
    assert part["gate"] == "absent"
    assert part["b"] is None
    assert part["b"] != 0
    capsys.readouterr()
    table_code = dr.main(["compare", str(a), str(b)])
    table_out = capsys.readouterr().out
    assert table_code == 0
    k2_line = next(
        line for line in table_out.splitlines() if line.startswith("K2 ")
    )
    assert "absent" in k2_line
    assert " 0 " not in f" {k2_line} "


def test_compare_json_matches_committed_keypaths(dr, capsys):
    before_a = _tree_digest(_RUN_A)
    before_b = _tree_digest(_RUN_B)
    capsys.readouterr()
    code = dr.main(["compare", str(_RUN_A), str(_RUN_B), "--json"])
    captured = capsys.readouterr()
    assert code == 0
    text = captured.out
    payload = json.loads(text)
    assert text == json.dumps(payload, allow_nan=False, sort_keys=True) + "\n"
    actual = _json_keypaths(payload)
    expected = _committed_keypaths("compare_json__keypaths.txt")
    assert actual - expected == set()
    assert expected - actual == set()
    assert _tree_digest(_RUN_A) == before_a
    assert _tree_digest(_RUN_B) == before_b


def test_compare_does_not_modify_run_dirs(dr, tmp_path):
    a, b = _clone_pair(tmp_path)
    before_a = _tree_digest(a)
    before_b = _tree_digest(b)
    assert dr.main(["compare", str(a), str(b)]) == 0
    assert _tree_digest(a) == before_a
    assert _tree_digest(b) == before_b


def test_compare_table_headers(dr, capsys):
    capsys.readouterr()
    code = dr.main(["compare", str(_RUN_A), str(_RUN_B)])
    out = capsys.readouterr().out
    assert code == 0
    header = out.splitlines()[0]
    for col in ("kpi", "A", "B", "delta", "%", "gate"):
        assert col in header
    assert "K7.p95" in out
    assert "participation_rate" in out
