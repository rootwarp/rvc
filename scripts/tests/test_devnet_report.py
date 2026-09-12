"""Tests for scripts/devnet_report.py.

Pytest prepends this directory, not scripts/, so the script is loaded by path.
"""

from __future__ import annotations

import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError

from conftest import FakeTransport, raw_text

_METRICS_URL = "http://127.0.0.1:5064/metrics"
_FIXTURES = Path(__file__).resolve().parent / "fixtures"
_CLOCK_T = datetime(2026, 9, 12, 0, 0, 0, tzinfo=timezone.utc)
_TIER_LABELS = {"endpoint": "http://127.0.0.1:5052"}
_SCORE_LABELS = {
    "endpoint": "http://127.0.0.1:5052",
    "pool": "proposer",
}
_TASK_LABELS = {"task": "orchestrator"}


def _clock() -> datetime:
    return _CLOCK_T


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


def _counter_series(blocks, **labels):
    for block in blocks:
        if block["labels"] == labels:
            return block
    raise AssertionError(f"no series with labels {labels}")


def _gauge_series(folded, name, **labels):
    for block in folded[name]:
        if block["labels"] == labels:
            return block
    raise AssertionError(f"no series {name} with labels {labels}")


def _parse_fixture(dr, name: str):
    return dr.parse_metrics(raw_text(dr, name).body.decode("utf-8"))


def test_load_script_resolves_named_module(dr, vp):
    assert dr.__file__.endswith("devnet_report.py")
    assert vp.__file__.endswith("validator_perf.py")
    assert Path(vp.__file__).name == "validator_perf.py"


def test_exit_codes_follow_prd_section_4(dr):
    assert (
        ("EXIT_OK", dr.EXIT_OK),
        ("EXIT_INFRA", dr.EXIT_INFRA),
        ("EXIT_USAGE", dr.EXIT_USAGE),
        ("EXIT_HEALTH", dr.EXIT_HEALTH),
        ("EXIT_KPI", dr.EXIT_KPI),
        ("EXIT_NOTREADY", dr.EXIT_NOTREADY),
    ) == (
        ("EXIT_OK", 0),
        ("EXIT_INFRA", 1),
        ("EXIT_USAGE", 2),
        ("EXIT_HEALTH", 3),
        ("EXIT_KPI", 4),
        ("EXIT_NOTREADY", 5),
    )


def test_compare_subcommand_registered_but_deferred(dr):
    assert dr.main(["compare", "a", "b"]) == 2


def test_scrape_http_503_exits_1(dr, tmp_path):
    transport = FakeTransport(
        {("GET", "/metrics"): [raw_text(dr, "rvc_metrics__ok", status=503)]}
    )
    out = tmp_path / "metrics.txt"
    code = dr.main(
        ["scrape", "--url", _METRICS_URL, "--out", str(out)],
        transport=transport,
    )
    assert code == 1


def test_scrape_timeout_exits_1(dr, tmp_path):
    def timeout():
        raise TimeoutError("timed out")

    transport = FakeTransport({("GET", "/metrics"): [timeout]})
    out = tmp_path / "metrics.txt"
    code = dr.main(
        ["scrape", "--url", _METRICS_URL, "--out", str(out)],
        transport=transport,
    )
    assert code == 1


def test_gauges_only_without_slot_exits_2(dr, tmp_path):
    assert (
        dr.main(
            [
                "scrape",
                "--url",
                _METRICS_URL,
                "--gauges-only",
                "--append",
                str(tmp_path / "samples.jsonl"),
            ]
        )
        == 2
    )


def test_slot_without_gauges_only_exits_2(dr, tmp_path):
    assert (
        dr.main(
            [
                "scrape",
                "--url",
                _METRICS_URL,
                "--out",
                str(tmp_path / "metrics.txt"),
                "--slot",
                "12",
            ]
        )
        == 2
    )


def test_out_and_append_are_mutually_exclusive(dr, tmp_path):
    assert (
        dr.main(
            [
                "scrape",
                "--url",
                _METRICS_URL,
                "--out",
                str(tmp_path / "metrics.txt"),
                "--append",
                str(tmp_path / "samples.jsonl"),
            ]
        )
        == 2
    )


def test_scrape_without_out_or_append_exits_2(dr):
    assert dr.main(["scrape", "--url", _METRICS_URL]) == 2


def test_append_without_gauges_only_exits_2(dr, tmp_path):
    assert (
        dr.main(
            [
                "scrape",
                "--url",
                _METRICS_URL,
                "--append",
                str(tmp_path / "samples.jsonl"),
            ]
        )
        == 2
    )


def test_scrape_without_url_exits_2(dr, tmp_path):
    assert dr.main(["scrape", "--out", str(tmp_path / "metrics.txt")]) == 2


def test_write_json_atomic_leaves_no_tmp_and_sorts_keys(dr, tmp_path):
    path = tmp_path / "out.json"
    dr.write_json_atomic(path, {"b": 1, "a": 2})
    assert path.read_text(encoding="utf-8") == '{"a": 2, "b": 1}\n'
    leftover = [p.name for p in tmp_path.iterdir() if p.name != "out.json"]
    assert leftover == []


def test_nan_maps_to_null_not_valueerror(dr, tmp_path):
    path = tmp_path / "out.json"
    dr.write_json_atomic(path, {"v": float("nan")})
    assert json.loads(path.read_text(encoding="utf-8")) == {"v": None}


def test_main_never_opens_a_socket_with_fake_transport(dr, tmp_path):
    raw = raw_text(dr, "rvc_metrics__ok")
    transport = FakeTransport({("GET", "/metrics"): [raw]})
    out = tmp_path / "metrics.txt"
    code = dr.main(
        ["scrape", "--url", _METRICS_URL, "--out", str(out)],
        transport=transport,
    )
    assert code == 0
    assert out.read_bytes() == raw.body


def test_main_reraises_socket_blocked_error(dr, tmp_path):
    with pytest.raises(SocketBlockedError):
        dr.main(
            ["scrape", "--url", _METRICS_URL, "--out", str(tmp_path / "metrics.txt")]
        )


def test_invalid_url_error_omits_userinfo_and_query(dr, tmp_path, capsys):
    out = str(tmp_path / "metrics.txt")
    secret = "s3cret"
    query = "token=abc"
    urls = (
        f"http://user:{secret}@127.0.0.1:5064/metrics?{query}",
        f"http://user:{secret}@/metrics?{query}",
        f"http://127.0.0.1:99999/metrics?{query}",
        f"ftp://user:{secret}@host/path?{query}",
    )
    for url in urls:
        capsys.readouterr()
        assert dr.main(["scrape", "--url", url, "--out", out]) == 2
        err = capsys.readouterr().err
        assert secret not in err
        assert query not in err


def test_parse_handles_escaped_quote_in_label_value(dr):
    start = _parse_fixture(dr, "rvc_metrics__start")
    endpoints = [
        sample.labels["endpoint"] for sample in start["rvc_bn_health_tier"].samples
    ]
    assert 'http://bn.local:5052/"metrics"' in endpoints


def test_parse_defaults_missing_type_to_untyped(dr):
    start = _parse_fixture(dr, "rvc_metrics__start")
    family = start["rvc_scrape_orphan"]
    assert family.type == "untyped"
    assert family.samples[0].value == 1.0


def test_parse_le_plus_inf_is_math_inf(dr):
    assert dr._parse_le("+Inf") == math.inf
    start = _parse_fixture(dr, "rvc_metrics__start")
    inf_les = [
        sample.labels["le"]
        for sample in start["rvc_signing_duration_seconds"].samples
        if sample.labels.get("le") == "+Inf"
    ]
    assert inf_les
    assert dr._parse_le(inf_les[0]) == math.inf


def test_parse_rejects_summary_family(dr):
    text = (
        "# TYPE rpc_duration_seconds summary\n"
        'rpc_duration_seconds{quantile="0.01"} 3102\n'
        "rpc_duration_seconds_sum 1.7560473e+07\n"
        "rpc_duration_seconds_count 2693\n"
    )
    with pytest.raises(dr.UsageError):
        dr.parse_metrics(text)
    assert dr.EXIT_USAGE == 2


def test_series_key_is_label_order_independent(dr):
    a = dr._parse_labels('task="orchestrator",outcome="ok"')
    b = dr._parse_labels('outcome="ok",task="orchestrator"')
    assert list(a.items()) != list(b.items())
    assert dr.series_key("rvc_task_exits_total", a) == dr.series_key(
        "rvc_task_exits_total", b
    )
    start = _parse_fixture(dr, "rvc_metrics__start")
    end = _parse_fixture(dr, "rvc_metrics__end")
    start_sample = start["rvc_task_exits_total"].samples[0]
    end_sample = end["rvc_task_exits_total"].samples[0]
    assert list(start_sample.labels.items()) != list(end_sample.labels.items())
    assert dr.series_key("rvc_task_exits_total", start_sample.labels) == dr.series_key(
        "rvc_task_exits_total", end_sample.labels
    )


def test_family_list_comes_from_scrape_not_source(dr):
    for name in ("rvc_metrics__start", "rvc_metrics__end"):
        text = raw_text(dr, name).body.decode("utf-8")
        families = dr.parse_metrics(text)
        assert text.count("# TYPE rvc_attestations_total ") == 1
        assert list(families).count("rvc_attestations_total") == 1
        proposals = families["rvc_proposals_total"]
        children = {tuple(sorted(sample.labels.items())) for sample in proposals.samples}
        assert children == {(("outcome", "envelope_late"),)}


def test_unit_carried_per_family(dr):
    start = _parse_fixture(dr, "rvc_metrics__start")
    assert dr.unit_for(start["rvc_signing_duration_seconds"].name) == "seconds"
    assert (
        dr.unit_for(start["rvc_slashing_reserve_tx_hold_duration_ms"].name)
        == "milliseconds"
    )
    assert dr.unit_for(start["rvc_attestations_total"].name) == "count"


def test_parse_rejects_leftover_label_tokens(dr):
    with pytest.raises(dr.InfraError):
        dr.parse_metrics('foo{not_a_label} 1\n')
    with pytest.raises(dr.InfraError):
        dr.parse_metrics('foo{a="b" leftover} 1\n')
    with pytest.raises(dr.InfraError):
        dr.parse_metrics('foo{a="unterminated} 1\n')
    assert dr.EXIT_INFRA == 1


def test_parse_malformed_line_is_infra_and_truncated(dr):
    line = "not a metric " + ("x" * 500)
    with pytest.raises(dr.InfraError) as caught:
        dr.parse_metrics(line + "\n")
    msg = str(caught.value)
    assert "x" * 500 not in msg
    assert len(msg) < 300
    assert dr.EXIT_INFRA == 1


def test_parse_caps_raise_infra(dr, monkeypatch):
    monkeypatch.setattr(dr, "MAX_RESPONSE_BYTES", 16)
    with pytest.raises(dr.InfraError):
        dr.parse_metrics("a 1\n" * 20)
    monkeypatch.setattr(dr, "MAX_RESPONSE_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(dr, "_MAX_METRIC_SAMPLES", 1)
    with pytest.raises(dr.InfraError):
        dr.parse_metrics("a 1\nb 1\n")
    monkeypatch.setattr(dr, "_MAX_METRIC_SAMPLES", 100_000)
    monkeypatch.setattr(dr, "_MAX_METRIC_LINE", 8)
    with pytest.raises(dr.InfraError):
        dr.parse_metrics("abcdefghij 1\n")
    monkeypatch.setattr(dr, "_MAX_METRIC_LINE", 8 * 1024)
    monkeypatch.setattr(dr, "_MAX_LABEL_VALUE_BYTES", 4)
    with pytest.raises(dr.InfraError):
        dr.parse_metrics('foo{a="12345"} 1\n')


def test_counter_delta_flags_monotonic_violation(dr):
    start = _parse_fixture(dr, "rvc_metrics__start")
    end = _parse_fixture(dr, "rvc_metrics__end")
    missed = _counter_series(
        dr.counter_delta(start, end, epochs=4)[
            "rvc_orchestrator_missed_slots_total"
        ]
    )
    assert missed["start"] == 3
    assert missed["end"] == 1
    assert missed["delta"] == -2
    assert missed["monotonic_violation"] is True


def test_counter_delta_treats_new_label_set_as_start_zero(dr):
    start = _parse_fixture(dr, "rvc_metrics__start")
    end = _parse_fixture(dr, "rvc_metrics__end")
    blocks = dr.counter_delta(start, end, epochs=4)["rvc_attestations_total"]
    failed = _counter_series(blocks, status="failed")
    assert failed["start"] == 0
    assert failed["end"] == 1
    assert failed["delta"] == 1
    assert failed["monotonic_violation"] is False
    success = _counter_series(blocks, status="success")
    assert success["start"] == 80
    assert success["end"] == 192


def test_counter_per_epoch_divides_by_epochs_argument(dr):
    start = _parse_fixture(dr, "rvc_metrics__start")
    end = _parse_fixture(dr, "rvc_metrics__end")
    by_four = _counter_series(
        dr.counter_delta(start, end, epochs=4)[
            "rvc_orchestrator_slots_processed_total"
        ],
        result="success",
    )
    by_eight = _counter_series(
        dr.counter_delta(start, end, epochs=8)[
            "rvc_orchestrator_slots_processed_total"
        ],
        result="success",
    )
    assert by_four["delta"] == 128
    assert by_four["per_epoch"] == 128 / 4
    assert by_eight["per_epoch"] == 128 / 8
    assert by_four["per_epoch"] != by_eight["per_epoch"]


def test_gauge_fold_reports_last_min_max_samples(dr):
    folded = dr.fold_gauges(_FIXTURES / "samples__gauges.jsonl")
    tier = _gauge_series(folded, "rvc_bn_health_tier", **_TIER_LABELS)
    assert tier["last"] == 3
    assert tier["min"] == 1
    assert tier["max"] == 4
    assert tier["samples"] == 3
    tasks = _gauge_series(folded, "rvc_tasks_running", **_TASK_LABELS)
    assert tasks == {
        "labels": _TASK_LABELS,
        "last": 2,
        "min": 1,
        "max": 2,
        "samples": 3,
    }


def test_gauge_fold_skips_malformed_line(dr):
    folded = dr.fold_gauges(_FIXTURES / "samples__gauges.jsonl")
    tier = _gauge_series(folded, "rvc_bn_health_tier", **_TIER_LABELS)
    assert tier["samples"] == 3
    assert tier["last"] == 3


def test_gauge_fold_ignores_nan_for_min_max(dr):
    folded = dr.fold_gauges(_FIXTURES / "samples__gauges.jsonl")
    score = _gauge_series(
        folded, "rvc_proposer_bn_health_score", **_SCORE_LABELS
    )
    assert score["last"] is None
    assert score["min"] == 0.25
    assert score["max"] == 1
    assert score["samples"] == 3


def test_scrape_gauges_only_appends_one_line_per_call(dr, tmp_path):
    path = tmp_path / "samples.jsonl"
    raw = raw_text(dr, "rvc_metrics__ok")
    transport = FakeTransport({("GET", "/metrics"): [raw, raw, raw]})
    assert not path.exists()
    for i, slot in enumerate((10, 11, 12)):
        code = dr.main(
            [
                "scrape",
                "--url",
                _METRICS_URL,
                "--gauges-only",
                "--slot",
                str(slot),
                "--append",
                str(path),
            ],
            transport=transport,
            clock=_clock,
        )
        assert code == 0
        if i == 0:
            assert path.is_file()
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]
    assert [row["slot"] for row in rows] == [10, 11, 12]
    assert all(row["t"] == "2026-09-12T00:00:00Z" for row in rows)
    assert all(set(row) == {"t", "slot", "gauges"} for row in rows)


def test_window_from_samples_slots_are_end_minus_start(dr):
    assert dr.window_from_samples(_FIXTURES / "samples__gauges.jsonl") == {
        "start_slot": 10,
        "end_slot": 12,
        "slots": 2,
    }


def test_jsonl_refuses_symlink_and_non_regular(dr, tmp_path):
    real = tmp_path / "samples.jsonl"
    real.write_text(
        '{"slot": 10, "gauges": {}}\n{"slot": 11, "gauges": {}}\n',
        encoding="utf-8",
    )
    link = tmp_path / "link.jsonl"
    link.symlink_to(real)
    with pytest.raises(dr.InfraError):
        dr.fold_gauges(link)
    transport = FakeTransport(
        {("GET", "/metrics"): [raw_text(dr, "rvc_metrics__ok")]}
    )
    assert (
        dr.main(
            [
                "scrape",
                "--url",
                _METRICS_URL,
                "--gauges-only",
                "--slot",
                "10",
                "--append",
                str(link),
            ],
            transport=transport,
            clock=_clock,
        )
        == 1
    )
    assert real.read_text(encoding="utf-8").count("\n") == 2
    fifo = tmp_path / "fifo.jsonl"
    os.mkfifo(fifo)
    with pytest.raises(dr.InfraError):
        dr.fold_gauges(fifo)
    with pytest.raises(dr.InfraError):
        dr._append_jsonl_line(fifo, {"slot": 1, "gauges": {}})


def test_jsonl_caps_raise_infra(dr, tmp_path, monkeypatch):
    path = tmp_path / "samples.jsonl"
    path.write_text(
        '{"slot": 1, "gauges": {}}\n{"slot": 2, "gauges": {}}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(dr, "_MAX_JSONL_BYTES", 16)
    with pytest.raises(dr.InfraError):
        dr.fold_gauges(path)
    monkeypatch.setattr(dr, "_MAX_JSONL_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(dr, "_MAX_JSONL_LINE", 8)
    with pytest.raises(dr.InfraError):
        dr.fold_gauges(path)
    monkeypatch.setattr(dr, "_MAX_JSONL_LINE", 64 * 1024)
    monkeypatch.setattr(dr, "_MAX_JSONL_BYTES", 16)
    with pytest.raises(dr.InfraError):
        dr._append_jsonl_line(path, {"slot": 3, "gauges": {}})


def test_window_from_samples_rejects_single_row(dr, tmp_path):
    path = tmp_path / "samples.jsonl"
    path.write_text(
        json.dumps({"t": "2026-09-12T00:00:00Z", "slot": 10, "gauges": {}})
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(dr.UsageError):
        dr.window_from_samples(path)
    assert dr.EXIT_USAGE == 2


def test_window_from_samples_rejects_non_increasing_slots(dr, tmp_path):
    path = tmp_path / "samples.jsonl"
    rows = (
        {"t": "2026-09-12T00:00:00Z", "slot": 12, "gauges": {}},
        {"t": "2026-09-12T00:00:12Z", "slot": 11, "gauges": {}},
    )
    path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    with pytest.raises(dr.UsageError):
        dr.window_from_samples(path)
    assert dr.EXIT_USAGE == 2


def test_samples_jsonl_matches_committed_keypaths(dr, tmp_path):
    path = tmp_path / "samples.jsonl"
    transport = FakeTransport(
        {("GET", "/metrics"): [raw_text(dr, "rvc_metrics__start")]}
    )
    assert (
        dr.main(
            [
                "scrape",
                "--url",
                _METRICS_URL,
                "--gauges-only",
                "--slot",
                "10",
                "--append",
                str(path),
            ],
            transport=transport,
            clock=_clock,
        )
        == 0
    )
    obj = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    actual = _json_keypaths(obj)
    expected = {
        line
        for line in (_FIXTURES / "samples_jsonl__keypaths.txt")
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    }
    assert actual - expected == set()
    assert expected - actual == set()
