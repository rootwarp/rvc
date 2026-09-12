"""Tests for scripts/devnet_report.py.

Pytest prepends this directory, not scripts/, so the script is loaded by path.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError

from conftest import FakeTransport, raw_text

_METRICS_URL = "http://127.0.0.1:5064/metrics"


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
