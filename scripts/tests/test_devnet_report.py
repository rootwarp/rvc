"""Tests for scripts/devnet_report.py.

Pytest prepends this directory, not scripts/, so the script is loaded by path.
"""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError

from conftest import FakeTransport, raw_text

_METRICS_URL = "http://127.0.0.1:5064/metrics"


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
