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


def test_quantile_matches_hand_computed_p50_p95_p99(dr):
    # 5 cumulative buckets. Per-interval observations:
    # (0, 1] → 10, (1, 5] → 30, (5, 10] → 30, (10, 50] → 29, (50, +Inf] → 1
    buckets = {
        1.0: 10.0,
        5.0: 40.0,
        10.0: 70.0,
        50.0: 99.0,
        math.inf: 100.0,
    }
    count_delta = 100.0
    rank_p50 = 0.50 * count_delta
    expected_p50 = 5.0 + (10.0 - 5.0) * ((rank_p50 - 40.0) / (70.0 - 40.0))
    rank_p95 = 0.95 * count_delta
    expected_p95 = 10.0 + (50.0 - 10.0) * ((rank_p95 - 70.0) / (99.0 - 70.0))
    rank_p99 = 0.99 * count_delta
    expected_p99 = 10.0 + (50.0 - 10.0) * ((rank_p99 - 70.0) / (99.0 - 70.0))
    assert dr.histogram_quantile(buckets, 0.50) == pytest.approx(
        expected_p50, abs=1e-9, rel=0
    )
    assert dr.histogram_quantile(buckets, 0.95) == pytest.approx(
        expected_p95, abs=1e-9, rel=0
    )
    assert dr.histogram_quantile(buckets, 0.99) == pytest.approx(
        expected_p99, abs=1e-9, rel=0
    )
    row = dr.histogram_stats(buckets, count_delta=count_delta)
    assert row["p50"] == pytest.approx(expected_p50, abs=1e-9, rel=0)
    assert row["p95"] == pytest.approx(expected_p95, abs=1e-9, rel=0)
    assert row["p99"] == pytest.approx(expected_p99, abs=1e-9, rel=0)
    assert row["p50_bucket"] == [5.0, 10.0]


def test_quantile_interpolates_from_zero_in_lowest_bucket(dr):
    # K10-shaped: lowest le is 5.0 > 0, so the first bucket interpolates from 0.
    buckets = {
        5.0: 80.0,
        10.0: 90.0,
        25.0: 95.0,
        50.0: 99.0,
        math.inf: 100.0,
    }
    rank = 0.50 * 100.0
    expected = 0.0 + (5.0 - 0.0) * (rank / 80.0)
    assert dr.histogram_quantile(buckets, 0.50) == pytest.approx(
        expected, abs=1e-9, rel=0
    )
    row = dr.histogram_stats(buckets)
    assert row["p50"] == pytest.approx(expected, abs=1e-9, rel=0)
    assert row["p50_bucket"] == [0.0, 5.0]


def test_quantile_marks_saturated_when_rank_lands_in_plus_inf(dr):
    largest_finite = 12.0
    buckets = {
        0.01: 10.0,
        1.0: 20.0,
        largest_finite: 30.0,
        math.inf: 100.0,
    }
    rank = 0.99 * 100.0
    assert rank > 30.0
    assert dr.histogram_quantile(buckets, 0.99) == largest_finite
    row = dr.histogram_stats(buckets)
    assert row["p99"] == largest_finite
    assert row["saturated"] is True


def test_quantile_zero_observations_yields_null_and_no_observations(dr):
    start = _parse_fixture(dr, "rvc_metrics__start")
    end = _parse_fixture(dr, "rvc_metrics__end")
    rows = dr.fold_histograms(start, end)
    series = rows["rvc_slot_phase_block_start_offset_ms"]
    assert len(series) == 1
    row = series[0]
    assert row["samples"] == 0
    assert row["p50"] is None
    assert row["p95"] is None
    assert row["p99"] is None
    assert row["mean"] is None
    assert row["annotation"] == "no_observations"
    assert row["unit"] == "milliseconds"
    empty = {5.0: 0.0, 10.0: 0.0, math.inf: 0.0}
    assert dr.histogram_quantile(empty, 0.50) is None


def test_mean_is_sum_delta_over_count_delta(dr):
    buckets = {1.0: 4.0, 5.0: 10.0, math.inf: 10.0}
    sum_delta = 23.5
    count_delta = 10.0
    row = dr.histogram_stats(
        buckets, sum_delta=sum_delta, count_delta=count_delta
    )
    assert row["mean"] == sum_delta / count_delta
    assert row["samples"] == 10
    assert row["sum_delta"] == sum_delta
    start = _parse_fixture(dr, "rvc_metrics__start")
    end = _parse_fixture(dr, "rvc_metrics__end")
    key = dr.series_key("rvc_signing_duration_seconds", {})
    delta = dr.bucket_deltas(start, end)[key]
    assert delta.sum_delta == 0.12 - 0.05
    assert delta.count_delta == 20.0 - 10.0
    signed = dr.histogram_stats(delta)
    assert signed["mean"] == (0.12 - 0.05) / (20.0 - 10.0)


def test_nan_sum_yields_null_mean_not_nan(dr):
    buckets = {1.0: 4.0, 5.0: 10.0, math.inf: 10.0}
    row = dr.histogram_stats(
        buckets, sum_delta=float("nan"), count_delta=10.0
    )
    assert row["mean"] is None
    assert row["sum_delta"] is None
    assert row["p50"] is not None
    assert row["samples"] == 10
    missing = dr.histogram_stats(buckets, count_delta=10.0)
    assert missing["mean"] is None
    assert missing["p50"] is not None


def test_bucket_deltas_join_is_label_order_independent(dr):
    start = _parse_fixture(dr, "rvc_metrics__start")
    end = _parse_fixture(dr, "rvc_metrics__end")
    start_sample = start["rvc_proposer_bn_latency_ms"].samples[0]
    end_sample = end["rvc_proposer_bn_latency_ms"].samples[0]
    assert list(start_sample.labels.items()) != list(end_sample.labels.items())
    start_labels = {k: v for k, v in start_sample.labels.items() if k != "le"}
    end_labels = {k: v for k, v in end_sample.labels.items() if k != "le"}
    assert dr.series_key("rvc_proposer_bn_latency_ms", start_labels) == (
        dr.series_key("rvc_proposer_bn_latency_ms", end_labels)
    )
    deltas = dr.bucket_deltas(start, end)
    latency_key = dr.series_key(
        "rvc_proposer_bn_latency_ms",
        {"endpoint": "http://127.0.0.1:5052", "pool": "proposer"},
    )
    hold_key = dr.series_key(
        "rvc_slashing_reserve_tx_hold_duration_ms", {"kind": "attestation"}
    )
    offset_key = dr.series_key(
        "rvc_slot_phase_block_start_offset_ms", {"cache": "warm"}
    )
    latency = deltas[latency_key]
    hold = deltas[hold_key]
    offset = deltas[offset_key]
    latency_buckets = dict(latency.buckets)
    assert latency_buckets[5.0] == 9.0 - 4.0
    assert latency_buckets[10.0] == 15.0 - 7.0
    assert latency_buckets[25.0] == 16.0 - 8.0
    assert latency.count_delta == 16.0 - 8.0
    assert latency.sum_delta == 120.0 - 60.0
    assert latency.unit == "milliseconds"
    hold_buckets = dict(hold.buckets)
    assert hold_buckets[1.0] == 7.0 - 3.0
    assert hold_buckets[5.0] == 14.0 - 6.0
    assert hold.count_delta == 21.0 - 10.0
    assert hold.sum_delta == 170.0 - 80.0
    assert hold.unit == "milliseconds"
    assert dict(offset.buckets)[5.0] == 0.0 - 0.0
    assert offset.count_delta == 0.0
    assert offset.unit == "milliseconds"
    start_hold = start["rvc_slashing_reserve_tx_hold_duration_ms"].samples[0]
    end_hold = end["rvc_slashing_reserve_tx_hold_duration_ms"].samples[0]
    assert list(start_hold.labels.items()) != list(end_hold.labels.items())
    start_off = start["rvc_slot_phase_block_start_offset_ms"].samples[0]
    end_off = end["rvc_slot_phase_block_start_offset_ms"].samples[0]
    assert list(start_off.labels.items()) != list(end_off.labels.items())


def _assert_json_safe(row: object) -> None:
    json.dumps(row, allow_nan=False, sort_keys=True)


def test_histogram_stats_json_has_no_nonfinite(dr):
    saturated = {
        0.01: 10.0,
        1.0: 20.0,
        12.0: 30.0,
        math.inf: 100.0,
    }
    row = dr.histogram_stats(saturated)
    assert row["saturated"] is True
    assert row["p50"] == 12.0
    assert row["p50_bucket"] == [12.0, None]
    _assert_json_safe(row)
    nan_counts = {1.0: float("nan"), 5.0: 10.0, math.inf: 10.0}
    nan_row = dr.histogram_stats(nan_counts)
    assert nan_row["p50"] is None or math.isfinite(nan_row["p50"])
    _assert_json_safe(nan_row)
    start = _parse_fixture(dr, "rvc_metrics__start")
    end = _parse_fixture(dr, "rvc_metrics__end")
    _assert_json_safe(dr.fold_histograms(start, end))


def test_invalid_le_is_infra_error_not_valueerror(dr):
    for raw in ("bogus", ""):
        text = (
            "# TYPE foo histogram\n"
            f'foo_bucket{{le="{raw}"}} 1\n'
            'foo_bucket{le="+Inf"} 1\n'
            "foo_sum 1\n"
            "foo_count 1\n"
        )
        families = dr.parse_metrics(text)
        with pytest.raises(dr.InfraError):
            dr.fold_histograms(families, families)
        with pytest.raises(dr.InfraError):
            dr.bucket_deltas(families, families)


def test_overflow_le_spellings_do_not_collide_with_plus_inf(dr):
    for raw in ("1e309", "Inf", "+inf", "Infinity", "-Inf"):
        with pytest.raises(dr.InfraError):
            dr._parse_le(raw)
        text = (
            "# TYPE foo histogram\n"
            'foo_bucket{le="0.1"} 1\n'
            f'foo_bucket{{le="{raw}"}} 2\n'
            'foo_bucket{le="+Inf"} 3\n'
            "foo_count 3\n"
        )
        families = dr.parse_metrics(text)
        with pytest.raises(dr.InfraError):
            dr.fold_histograms(families, families)


def test_missing_plus_inf_yields_no_observations(dr):
    buckets = {1.0: 4.0, 5.0: 10.0}
    row = dr.histogram_stats(buckets, count_delta=10.0, sum_delta=4.0)
    assert row["samples"] == 0
    assert row["p50"] is None
    assert row["p95"] is None
    assert row["p99"] is None
    assert row["mean"] is None
    assert row["annotation"] == "no_observations"
    _assert_json_safe(row)
    assert dr.histogram_quantile(buckets, 0.50) is None


def test_extreme_le_span_yields_no_observations_after_sanitize(dr):
    # Finite bounds so wide that linear interpolation overflows to inf.
    buckets = {
        -1e308: 0.0,
        1e308: 100.0,
        math.inf: 100.0,
    }
    assert dr.histogram_quantile(buckets, 0.50) is None
    row = dr.histogram_stats(buckets, count_delta=100.0, sum_delta=1.0)
    assert row["samples"] == 0
    assert row["p50"] is None
    assert row["p95"] is None
    assert row["p99"] is None
    assert row["mean"] is None
    assert row["p50_bucket"] is None
    assert row["annotation"] == "no_observations"
    _assert_json_safe(row)


def test_samples_value_does_not_emit_huge_ints(dr):
    buckets = {1.0: 1e308, math.inf: 1e308}
    row = dr.histogram_stats(buckets, count_delta=1e308, sum_delta=1.0)
    samples = row["samples"]
    assert samples == 1e308
    assert isinstance(samples, float)
    dumped = json.dumps({"samples": samples}, allow_nan=False)
    assert len(dumped) < 40
    modest = dr.histogram_stats({1.0: 10.0, math.inf: 10.0})
    assert modest["samples"] == 10
    assert isinstance(modest["samples"], int)
