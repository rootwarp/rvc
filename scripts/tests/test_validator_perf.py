"""Tests for scripts/validator_perf.py.

Pytest prepends this directory, not scripts/, so the script is loaded by path.
"""

from __future__ import annotations

import ast
import base64
import csv
import http.client
import inspect
import io
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from pytest_socket import SocketBlockedError

from conftest import (
    FakeTransport,
    SCRIPT,
    concurrent_failures,
    load_script,
    raw_response,
    route_map,
)


def test_exit_codes_are_the_six_documented_values(vp):
    assert (
        vp.EXIT_OK,
        vp.EXIT_ERROR,
        vp.EXIT_USAGE,
        vp.EXIT_DEGRADED,
        vp.EXIT_THRESHOLD,
        vp.EXIT_NO_BEACON,
    ) == (0, 1, 2, 3, 4, 5)


def test_epochs_per_year_constant_absent(vp):
    assert not hasattr(vp, "EPOCHS_PER_YEAR")


def test_log_writes_only_to_the_injected_stream(vp, capsys):
    buf = io.StringIO()
    log = vp.Log(0, buf)
    log.error("failed %s", "bn0")
    log.warn("slow %s", "bn0")
    text = buf.getvalue()
    assert "failed bn0" in text
    assert "slow bn0" in text
    captured = capsys.readouterr()
    assert captured.out == ""


def test_log_quiet_suppresses_warn_and_info(vp):
    buf = io.StringIO()
    log = vp.Log(-1, buf)
    log.warn("warn-line")
    log.info("info-line")
    log.error("error-line")
    text = buf.getvalue()
    assert "error-line" in text
    assert "warn-line" not in text
    assert "info-line" not in text


def test_log_info_requires_verbose(vp):
    default = io.StringIO()
    vp.Log(0, default).info("verbose-only")
    assert default.getvalue() == ""
    verbose = io.StringIO()
    vp.Log(1, verbose).info("verbose-only")
    assert "verbose-only" in verbose.getvalue()


def test_section_banners_in_order():
    source = SCRIPT.read_text(encoding="utf-8")
    found = [int(n) for n in re.findall(r"# ===== § (\d+)\.", source)]
    assert found == list(range(1, 17))


def test_pep723_block_is_exact():
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.startswith("#!/usr/bin/env -S uv run --script\n")
    assert "# /// script\n" in source
    assert 'requires-python = ">=3.11"\n' in source
    assert "dependencies = []\n" in source
    assert "# ///\n" in source


def test_imports_are_stdlib_only():
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    imported: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.extend(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.append(node.module.split(".", 1)[0])
    extra = sorted({name for name in imported if name not in sys.stdlib_module_names})
    assert extra == []


def test_endpoint_repr_omits_secrets(vp):
    ep = vp.Endpoint(
        "bn0",
        "https",
        "bn.example",
        5052,
        "/abc123SECRET",
        "Basic dXNlcjpzZWNyZXQ=",
    )
    shown = repr(ep) + str(ep)
    assert "/abc123SECRET" not in shown
    assert "dXNlcjpzZWNyZXQ=" not in shown


def test_parse_uint_rejects_underscored_and_padded(vp):
    field = "effective_balance"
    for raw in ("1_000", " 42 ", "+7", "", "0x2a", None, 42):
        with pytest.raises((vp.UsageError, ValueError)) as ei:
            vp.parse_uint(raw, field)
        assert field in str(ei.value)


def test_parse_int_accepts_signed_quoted_gwei(vp):
    assert vp.parse_int("-100", "head") == -100
    assert vp.parse_int("0", "head") == 0
    assert vp.parse_int("1834000", "head") == 1834000
    for raw in ("-", "--1"):
        with pytest.raises((vp.UsageError, ValueError)) as ei:
            vp.parse_int(raw, "head")
        assert "head" in str(ei.value)


def test_opt_int_returns_none_for_absent_key(vp):
    absent = vp.opt_int({}, "inclusion_delay")
    present_zero = vp.opt_int({"inclusion_delay": "0"}, "inclusion_delay")
    assert absent is None
    assert present_zero == 0
    assert absent != present_zero


def test_normalize_pubkey_adds_prefix_and_lowercases(vp):
    raw = "AB" * 48
    assert vp.normalize_pubkey(raw, "keys.txt:1") == "0x" + "ab" * 48


def test_normalize_pubkey_rejects_47_bytes_naming_origin(vp):
    origin = "keys.txt:4"
    with pytest.raises(vp.UsageError) as ei:
        vp.normalize_pubkey("ab" * 47, origin)
    assert origin in str(ei.value)


def test_network_is_blocked():
    with pytest.raises(SocketBlockedError, match="getaddrinfo"):
        socket.getaddrinfo("example.com", 80)


def test_vp_fixture_loads_the_script_by_path(vp):
    assert vp.SCHEMA_VERSION == 1
    assert Path(vp.__file__).resolve() == SCRIPT.resolve()


def test_script_does_not_run_main_on_import(capsys):
    source = SCRIPT.read_text(encoding="utf-8")
    guard_at = source.index('if __name__ == "__main__":')
    assert "sys.exit(main())" in source[guard_at:]
    # session-scoped vp already ran; load again here so capsys sees import I/O
    mod = load_script("validator_perf_guard")
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert mod.SCHEMA_VERSION == 1


def test_faketransport_records_calls_in_order(vp):
    ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    first = vp.RawResponse(503, b"retry", False)
    second = vp.RawResponse(200, b"ok", False)
    other = vp.RawResponse(200, b"spec", False)
    transport = FakeTransport(
        route_map(
            **{
                "GET /eth/v1/node/syncing": [first, second],
                "GET /eth/v1/config/spec": [other],
            }
        )
    )
    assert transport(ep, "GET", "/eth/v1/node/syncing", None) is first
    assert transport(ep, "GET", "/eth/v1/config/spec", b"") is other
    assert transport(ep, "GET", "/eth/v1/node/syncing", None) is second
    assert transport.calls == [
        ("bn0", "GET", "/eth/v1/node/syncing", None),
        ("bn0", "GET", "/eth/v1/config/spec", b""),
        ("bn0", "GET", "/eth/v1/node/syncing", None),
    ]
    transport.drop(ep)
    assert transport.drops == [ep]


def test_faketransport_raises_on_an_unscripted_call(vp):
    ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    transport = FakeTransport(
        {("GET", "/eth/v1/node/syncing"): [vp.RawResponse(200, b"", False)]}
    )
    with pytest.raises(KeyError):
        transport(ep, "GET", "/unscripted", None)
    assert transport(ep, "GET", "/eth/v1/node/syncing", None).status == 200
    with pytest.raises(IndexError):
        transport(ep, "GET", "/eth/v1/node/syncing", None)


def test_faketransport_query_strip_is_validators_get_only(vp):
    ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    validators = vp.RawResponse(200, b"[]", False)
    syncing = vp.RawResponse(200, b"{}", False)
    transport = FakeTransport(
        {
            ("GET", "/eth/v1/beacon/states/head/validators"): [validators],
            ("GET", "/eth/v1/node/syncing"): [syncing],
        }
    )
    got = transport(
        ep, "GET", "/eth/v1/beacon/states/head/validators?id=1&id=2", None
    )
    assert got is validators
    with pytest.raises(KeyError, match="unscripted"):
        transport(ep, "GET", "/eth/v1/node/syncing?lag=1", None)


def test_faketransport_satisfies_the_transport_alias(vp):
    ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
    body = vp.RawResponse(200, b"{}", False)
    transport = FakeTransport({("GET", "/x"): [body]})
    assert list(inspect.signature(transport).parameters) == [
        "ep",
        "method",
        "path",
        "body",
    ]
    got = transport(ep, "GET", "/x", b"payload")
    assert got is body
    assert isinstance(got, vp.RawResponse)


def test_redact_emits_scheme_host_port_only(vp):
    ep = vp.parse_endpoint(
        "https://user:secret@bn.example:5052/abc123SECRET/",
        "bn0",
    )
    shown = vp.redact(ep)
    assert shown == "https://bn.example:5052"
    assert "secret" not in shown
    assert "abc123SECRET" not in shown


def test_parse_endpoint_percent_decodes_userinfo_before_base64(vp):
    ep = vp.parse_endpoint("https://u:p%40ss@h:5052/", "bn0")
    expected = "Basic " + base64.b64encode(b"u:p@ss").decode("ascii")
    literal = "Basic " + base64.b64encode(b"u:p%40ss").decode("ascii")
    assert ep.auth_header == expected
    assert ep.auth_header != literal


def test_parse_endpoint_readds_ipv6_brackets(vp):
    ep = vp.parse_endpoint("http://[::1]:5052", "bn0")
    assert ep.host == "[::1]"


def test_parse_endpoint_keeps_base_path(vp):
    ep = vp.parse_endpoint("https://h:5052/abc123SECRET/", "bn0")
    assert ep.base_path == "/abc123SECRET"


def test_parse_endpoint_defaults_port_by_scheme(vp):
    assert vp.parse_endpoint("https://h", "bn0").port == 443
    assert vp.parse_endpoint("http://h", "bn1").port == 80


def test_parse_endpoint_rejects_unknown_scheme(vp):
    with pytest.raises(vp.UsageError):
        vp.parse_endpoint("ftp://h", "bn0")


def test_parse_endpoint_malformed_netloc_raises_usage_error(vp):
    url = "https://h:99999"
    with pytest.raises(vp.UsageError) as ei:
        vp.parse_endpoint(url, "bn0")
    assert url in str(ei.value)
    with pytest.raises(vp.UsageError) as ei:
        vp.parse_endpoint("https://h:abc", "bn1")
    assert "https://h:abc" in str(ei.value)


def test_parse_endpoint_absent_userinfo_has_no_auth(vp):
    assert vp.parse_endpoint("https://h:5052", "bn0").auth_header is None


def test_endpoint_label_is_positional(vp):
    a = vp.parse_endpoint("http://same.example:5052", "bn0")
    b = vp.parse_endpoint("http://same.example:5052", "bn1")
    assert a.label == "bn0"
    assert b.label == "bn1"
    assert a.host == b.host == "same.example"


def test_endpoint_is_frozen(vp):
    ep = vp.parse_endpoint("http://h", "bn0")
    with pytest.raises(FrozenInstanceError):
        ep.base_path = "/abc123SECRET"


FIXTURES = Path(__file__).resolve().parent / "fixtures"

PK1 = "0x" + "11" * 48
PK2 = "0x" + "22" * 48
PK3 = "0x" + "33" * 48
PK4 = "0x" + "44" * 48

_DOCUMENTED_FLAGS = {
    "--pubkey",
    "--pubkeys-file",
    "--validators-config",
    "--beacon-url",
    "--config",
    "--epochs",
    "--from-epoch",
    "--to-epoch",
    "--allow-unfinalized",
    "--force-unsafe-window",
    "--json",
    "--csv",
    "--prometheus",
    "--concurrency",
    "--request-delay-ms",
    "--connect-timeout",
    "--read-timeout",
    "--degraded-ok",
    "--fail-under",
    "--liveness-check",
    "--dry-run",
    "--no-cache",
    "-v",
    "-q",
}


def _load_pubkeys(vp, argv):
    return vp.load_pubkeys(vp.build_parser().parse_args(argv))


def test_pubkey_union_across_three_sources_in_input_order(vp):
    # --pubkey ∪ --pubkeys-file ∪ --validators-config, first-seen; file dups PK1.
    toml = str(FIXTURES / "validators__three_entries.toml")
    pubfile = str(FIXTURES / "pubkeys__two_one_dup.txt")
    expected = [PK4, PK1, PK2, PK3]
    assert (
        _load_pubkeys(
            vp,
            ["--pubkey", PK4, "--pubkeys-file", pubfile, "--validators-config", toml],
        )
        == expected
    )
    # Argv order must not change operand order; second --pubkey is append + de-dup.
    assert (
        _load_pubkeys(
            vp,
            [
                "--validators-config",
                toml,
                "--pubkeys-file",
                pubfile,
                "--pubkey",
                PK4,
                "--pubkey",
                PK1,
            ],
        )
        == expected
    )


def test_short_pubkey_exits_2_naming_source_and_line(vp):
    path = str(FIXTURES / "pubkeys__short_hex.txt")
    with pytest.raises(vp.UsageError) as ei:
        _load_pubkeys(vp, ["--pubkeys-file", path])
    msg = str(ei.value)
    assert path in msg
    assert f"{path}:3" in msg
    assert vp.EXIT_USAGE == 2


def test_short_cli_pubkey_names_flag_origin(vp):
    with pytest.raises(vp.UsageError) as ei:
        _load_pubkeys(vp, ["--pubkey", "aa" * 47])
    assert "--pubkey #1" in str(ei.value)
    assert vp.EXIT_USAGE == 2


def test_short_toml_pubkey_names_table_origin(vp, tmp_path):
    path = str(tmp_path / "validators__short.toml")
    Path(path).write_text(f'[[validators]]\npubkey = "{"aa" * 47}"\n', encoding="utf-8")
    with pytest.raises(vp.UsageError) as ei:
        _load_pubkeys(vp, ["--validators-config", path])
    assert f"{path} [[validators]] #1" in str(ei.value)
    assert vp.EXIT_USAGE == 2


def test_pubkeys_file_ignores_blanks_and_comments(vp):
    path = str(FIXTURES / "pubkeys__two_one_dup.txt")
    assert _load_pubkeys(vp, ["--pubkeys-file", path]) == [PK1, PK4]


def test_validators_config_accepts_unprefixed_pubkey(vp):
    path = str(FIXTURES / "validators__unprefixed.toml")
    assert _load_pubkeys(vp, ["--validators-config", path]) == [
        "0x" + "aa" * 48,
    ]


def test_no_pubkeys_exits_2(vp):
    with pytest.raises(vp.UsageError) as ei:
        _load_pubkeys(vp, [])
    assert "pubkey" in str(ei.value).lower()
    assert vp.EXIT_USAGE == 2


def test_validators_config_opened_in_binary_mode(vp, monkeypatch):
    path = str(FIXTURES / "validators__three_entries.toml")
    modes: list[str] = []
    real_load = vp.tomllib.load

    def spy(fp, *a, **kw):
        modes.append(getattr(fp, "mode", ""))
        return real_load(fp, *a, **kw)

    monkeypatch.setattr(vp.tomllib, "load", spy)
    assert _load_pubkeys(vp, ["--validators-config", path]) == [PK1, PK2, PK3]
    assert any("b" in mode for mode in modes)


def test_parser_declares_every_documented_flag(vp):
    parser = vp.build_parser()
    names = {opt for action in parser._actions for opt in action.option_strings}
    dests = {action.dest: list(action.option_strings) for action in parser._actions}
    assert _DOCUMENTED_FLAGS <= names
    assert names - _DOCUMENTED_FLAGS <= {"-h", "--help"}
    assert dests["verbose"] == ["-v"]
    assert dests["quiet"] == ["-q"]


def _https_ep(vp, *, label="bn0", host="bn.example", base_path="", auth_header=None):
    return vp.Endpoint(label, "https", host, 5052, base_path, auth_header)


def _patch_https(monkeypatch, vp, *, status=200, body=b"{}"):
    constructed = []

    class FakeSock:
        def __init__(self):
            self.timeouts = []

        def settimeout(self, timeout):
            self.timeouts.append(timeout)

    class FakeResp:
        def __init__(self):
            self.status = status
            self.read_amt = None

        def read(self, amt=None):
            self.read_amt = amt
            if amt is None:
                return body
            return body[:amt]

    class FakeHTTPSConnection:
        def __init__(self, host, port=None, timeout=None, **_kwargs):
            constructed.append(self)
            self.host = host
            self.port = port
            self.timeout = timeout
            self.sock = None
            self.closed = False
            self.requests = []
            self.response = FakeResp()

        def connect(self):
            self.sock = FakeSock()

        def request(self, method, url, body=None, headers=None, **_kwargs):
            self.requests.append((method, url, body, dict(headers or {})))

        def getresponse(self):
            return self.response

        def close(self):
            self.closed = True
            self.sock = None

    monkeypatch.setattr(vp.http.client, "HTTPSConnection", FakeHTTPSConnection)
    return constructed


def test_transport_reuses_one_connection_per_thread_per_endpoint(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    for _ in range(5):
        raw = transport(ep, "GET", "/eth/v1/config/spec", None)
        assert raw.status == 200
        assert raw.truncated is False
    assert len(constructed) == 1


def test_transport_opens_separate_connections_per_thread(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    errors: list[Exception] = []

    def worker():
        try:
            transport(ep, "GET", "/eth/v1/config/spec", None)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(constructed) == 2


def test_transport_sets_read_timeout_on_the_socket_after_connect(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    connect_timeout = 1.25
    read_timeout = 4.5
    transport = vp.HttpTransport(connect_timeout, read_timeout)
    transport(_https_ep(vp), "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 1
    conn = constructed[0]
    assert conn.timeout == connect_timeout
    assert conn.sock is not None
    assert conn.sock.timeouts == [read_timeout]


def test_transport_marks_truncated_over_the_cap(vp, monkeypatch):
    cap = 32
    monkeypatch.setattr(vp, "MAX_RESPONSE_BYTES", cap)
    payload = b"x" * (cap + 1)
    constructed = _patch_https(monkeypatch, vp, body=payload)
    transport = vp.HttpTransport(1.25, 4.5)
    raw = transport(_https_ep(vp), "GET", "/eth/v1/config/spec", None)
    assert raw.truncated is True
    assert constructed[0].response.read_amt == cap + 1


def test_transport_sends_authorization_and_base_path(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    auth = "Basic " + base64.b64encode(b"user:secret").decode("ascii")
    ep = _https_ep(vp, base_path="/abc123SECRET", auth_header=auth)
    transport = vp.HttpTransport(1.25, 4.5)
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed[0].requests) == 1
    method, url, body, headers = constructed[0].requests[0]
    assert method == "GET"
    assert url == "/abc123SECRET/eth/v1/config/spec"
    assert body is None
    assert headers["Authorization"] == auth


def test_drop_closes_and_forgets_the_connection(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 1
    transport.drop(ep)
    assert constructed[0].closed is True
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 2


def test_close_from_main_thread_closes_worker_connections(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    errors: list[Exception] = []

    def worker():
        try:
            transport(ep, "GET", "/eth/v1/config/spec", None)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert errors == []
    assert len(constructed) == 2
    assert all(not conn.closed for conn in constructed)
    transport.close()
    assert all(conn.closed for conn in constructed)


def test_transport_separate_connections_per_endpoint_drop_is_selective(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep0 = _https_ep(vp, label="bn0", host="bn0.example")
    ep1 = _https_ep(vp, label="bn1", host="bn1.example")
    transport(ep0, "GET", "/eth/v1/config/spec", None)
    transport(ep1, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 2
    transport.drop(ep0)
    assert constructed[0].closed is True
    assert constructed[1].closed is False
    transport(ep1, "GET", "/eth/v1/node/version", None)
    assert len(constructed) == 2
    transport(ep0, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 3


def test_transport_sets_content_type_only_on_body(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    transport(ep, "GET", "/eth/v1/config/spec", None)
    transport(ep, "POST", "/eth/v1/beacon/states/head/validators", b'{"ids":[]}')
    get_headers = constructed[0].requests[0][3]
    post_headers = constructed[0].requests[1][3]
    assert "Content-Type" not in get_headers
    assert post_headers["Content-Type"] == "application/json"
    assert constructed[0].requests[1][2] == b'{"ids":[]}'


def test_transport_rebuilds_when_cached_sock_is_none(vp, monkeypatch):
    constructed = _patch_https(monkeypatch, vp)
    transport = vp.HttpTransport(1.25, 4.5)
    ep = _https_ep(vp)
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 1
    constructed[0].sock = None
    transport(ep, "GET", "/eth/v1/config/spec", None)
    assert len(constructed) == 2
    assert constructed[0].closed is True
    assert constructed[1].sock is not None
    assert constructed[1].sock.timeouts == [4.5]
    assert constructed[1].timeout == 1.25


def test_transport_module_contains_no_log_call():
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"# ===== § 5\. Transport =====(.*?)# ===== § 6\.",
        source,
        re.DOTALL,
    )
    assert match is not None
    assert "log." not in match.group(1)


def test_socket_blocked(vp):
    from pytest_socket import SocketBlockedError, disable_socket, enable_socket

    disable_socket()
    try:
        transport = vp.HttpTransport(0.1, 0.1)
        ep = vp.Endpoint("bn0", "https", "example.invalid", 443, "", None)
        with pytest.raises(SocketBlockedError):
            transport(ep, "GET", "/eth/v1/config/spec", None)
    finally:
        enable_socket()


def _load_beacon_urls(vp, argv):
    return vp.load_beacon_urls(vp.build_parser().parse_args(argv))


def _minimal_opts_argv(*extra):
    return ["--pubkey", PK1, "--beacon-url", "http://h:5052", *extra]


def test_beacon_nodes_beats_beacon_url_in_config(vp):
    path = str(FIXTURES / "config__both_keys.toml")
    eps = _load_beacon_urls(vp, ["--config", path])
    assert [e.host for e in eps] == ["alpha.example", "beta.example"]
    assert all(e.host != "primary.example" for e in eps)


def test_beacon_url_flag_beats_the_config_file_entirely(vp):
    path = str(FIXTURES / "config__both_keys.toml")
    eps = _load_beacon_urls(
        vp,
        ["--config", path, "--beacon-url", "http://flag.example:5052"],
    )
    assert [e.host for e in eps] == ["flag.example"]


def test_empty_beacon_nodes_falls_through_to_beacon_url(vp):
    path = str(FIXTURES / "config__empty_nodes.toml")
    eps = _load_beacon_urls(vp, ["--config", path])
    assert [e.host for e in eps] == ["only.example"]


def test_no_beacon_url_exits_2_not_5(vp, tmp_path):
    with pytest.raises(vp.UsageError) as ei:
        vp.build_options(["--pubkey", PK1])
    assert ei.type is vp.UsageError
    assert not isinstance(ei.value, vp.NoBeaconAvailable)
    assert "beacon" in str(ei.value).lower()
    assert vp.EXIT_USAGE == 2
    assert vp.EXIT_NO_BEACON == 5
    assert vp.EXIT_USAGE != vp.EXIT_NO_BEACON
    empty = tmp_path / "config__no_urls.toml"
    empty.write_text('network = "hoodi"\n', encoding="utf-8")
    with pytest.raises(vp.UsageError) as ei:
        vp.build_options(["--pubkey", PK1, "--config", str(empty)])
    assert "beacon" in str(ei.value).lower()
    assert vp.EXIT_USAGE == 2


def test_epochs_with_from_epoch_exits_2(vp):
    with pytest.raises(vp.UsageError) as ei:
        vp.build_options(_minimal_opts_argv("--epochs", "4", "--from-epoch", "1"))
    assert "epoch" in str(ei.value).lower()
    assert vp.EXIT_USAGE == 2
    with pytest.raises(vp.UsageError):
        vp.build_options(_minimal_opts_argv("--epochs", "4", "--to-epoch", "10"))


def test_verbose_and_quiet_together_exits_2(vp):
    with pytest.raises(vp.UsageError):
        vp.build_options(_minimal_opts_argv("-v", "-q"))
    assert vp.EXIT_USAGE == 2


def test_options_is_frozen(vp):
    opts = vp.build_options(_minimal_opts_argv())
    with pytest.raises(FrozenInstanceError):
        opts.verbosity = 1
    assert isinstance(opts.pubkeys, tuple)
    assert isinstance(opts.endpoints, tuple)
    assert isinstance(opts.fail_under, tuple)


def test_endpoint_labels_are_bn0_bn1_in_config_order(vp):
    path = str(FIXTURES / "config__both_keys.toml")
    eps = _load_beacon_urls(vp, ["--config", path])
    assert [e.label for e in eps] == ["bn0", "bn1"]
    assert [e.host for e in eps] == ["alpha.example", "beta.example"]


def test_verbosity_tiers(vp):
    assert vp.build_options(_minimal_opts_argv()).verbosity == 0
    assert vp.build_options(_minimal_opts_argv("-q")).verbosity == -1
    assert vp.build_options(_minimal_opts_argv("-v")).verbosity == 1
    assert vp.build_options(_minimal_opts_argv("-vv")).verbosity == 2


def test_unset_window_fields_are_none(vp):
    opts = vp.build_options(_minimal_opts_argv())
    assert opts.epochs is None
    assert opts.from_epoch is None
    assert opts.to_epoch is None


def test_from_and_to_epoch_without_epochs_ok(vp):
    opts = vp.build_options(
        _minimal_opts_argv("--from-epoch", "10", "--to-epoch", "20")
    )
    assert opts.epochs is None
    assert opts.from_epoch == 10
    assert opts.to_epoch == 20


def test_two_beacon_url_flags_ignore_config(vp):
    path = str(FIXTURES / "config__both_keys.toml")
    eps = _load_beacon_urls(
        vp,
        [
            "--config",
            path,
            "--beacon-url",
            "http://flag0.example:5052",
            "--beacon-url",
            "http://flag1.example:5052",
        ],
    )
    assert [e.host for e in eps] == ["flag0.example", "flag1.example"]
    assert [e.label for e in eps] == ["bn0", "bn1"]


def test_beacon_url_only_config(vp):
    path = str(FIXTURES / "config__beacon_url_only.toml")
    eps = _load_beacon_urls(vp, ["--config", path])
    assert [e.host for e in eps] == ["solo.example"]
    assert [e.label for e in eps] == ["bn0"]


def test_non_str_beacon_nodes_entry_raises_usage_error(vp, tmp_path):
    path = tmp_path / "config__int_node.toml"
    path.write_text("beacon_nodes = [5052]\n", encoding="utf-8")
    with pytest.raises(vp.UsageError) as ei:
        _load_beacon_urls(vp, ["--config", str(path)])
    msg = str(ei.value)
    assert "--config" in msg
    assert "5052" in msg
    assert "beacon" in msg.lower()


def test_non_list_beacon_nodes_raises_usage_error(vp, tmp_path):
    path = tmp_path / "config__string_nodes.toml"
    path.write_text(
        'beacon_nodes = "http://string.example:5052"\n'
        'beacon_url = "http://fallback.example:5052"\n',
        encoding="utf-8",
    )
    with pytest.raises(vp.UsageError) as ei:
        _load_beacon_urls(vp, ["--config", str(path)])
    msg = str(ei.value)
    assert "--config" in msg
    assert "beacon_nodes" in msg


def test_non_str_beacon_url_raises_usage_error(vp, tmp_path):
    path = tmp_path / "config__int_url.toml"
    path.write_text("beacon_url = 5052\n", encoding="utf-8")
    with pytest.raises(vp.UsageError) as ei:
        _load_beacon_urls(vp, ["--config", str(path)])
    msg = str(ei.value)
    assert "--config" in msg
    assert "5052" in msg
    assert "beacon_url" in msg


def test_empty_beacon_url_flag_raises_usage_error(vp):
    with pytest.raises(vp.UsageError) as ei:
        _load_beacon_urls(vp, ["--beacon-url", ""])
    msg = str(ei.value)
    assert "--beacon-url" in msg
    assert "beacon" in msg.lower()


# ----- VP-1h: §6 _call retry matrix -----

_REWARDS_TEMPLATE = "/eth/v1/beacon/rewards/attestations/{epoch}"
_SPEC_TEMPLATE = "/eth/v1/config/spec"
_VERSION_TEMPLATE = "/eth/v1/node/version"
_SECRET_URL = "https://user:secret@bn.example:5052/abc123SECRET/"


def _boom(exc: BaseException):
    def inner():
        raise exc

    return inner


def _raw(vp, status, body=b"{}", truncated=False, headers=None):
    return vp.RawResponse(status, body, truncated, headers or {})


def _client(
    vp,
    transport,
    *,
    request_delay=0.0,
    verbosity=1,
    ep=None,
    stream=None,
    endpoints=None,
):
    buf = stream if stream is not None else io.StringIO()
    if endpoints is None:
        if ep is None:
            ep = vp.Endpoint("bn0", "http", "127.0.0.1", 5052, "", None)
        endpoints = [ep]
    log = vp.Log(verbosity, buf)
    return vp.BeaconClient(endpoints, transport, request_delay=request_delay, log=log), buf


def _no_sleep(monkeypatch, vp):
    slept = []
    monkeypatch.setattr(vp.time, "sleep", lambda s: slept.append(s))
    return slept


def test_retry_on_429_honours_capped_retry_after(vp, monkeypatch):
    slept = _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    transport = FakeTransport(
        {
            ("GET", path): [
                _raw(vp, 429, headers={"Retry-After": "7200"}),
                _raw(vp, 200, b'{"data": true}'),
            ]
        }
    )
    client, _ = _client(vp, transport)
    got = client._call("GET", path, {}, None)
    assert got == {"data": True}
    assert len(transport.calls) == 2
    assert slept == [vp.MAX_RETRY_AFTER]
    assert vp.MAX_RETRY_AFTER == 30.0


def test_retry_on_503_backs_off_then_succeeds(vp, monkeypatch):
    slept = _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    body = b'{"ok": true}'
    transport = FakeTransport(
        {("GET", path): [_raw(vp, 503), _raw(vp, 503), _raw(vp, 200, body)]}
    )
    client, _ = _client(vp, transport)
    got = client._call("GET", path, {}, None)
    assert got == {"ok": True}
    assert len(transport.calls) == 3
    assert slept  # exponential backoff, not a real wait


def test_500_from_a_rewards_route_retries_exactly_once(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    fmt = {"epoch": 7}
    path = _REWARDS_TEMPLATE.format(**fmt)
    transport = FakeTransport(
        {("POST", path): [_raw(vp, 500), _raw(vp, 500), _raw(vp, 500)]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client._call("POST", _REWARDS_TEMPLATE, fmt, b"[]", retry_500=True)
    assert ei.value.status == 500
    assert ei.value.template == _REWARDS_TEMPLATE
    assert len(transport.calls) == 2


def test_500_elsewhere_retries_once_then_raises(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    transport = FakeTransport(
        {("GET", path): [_raw(vp, 500), _raw(vp, 500), _raw(vp, 500)]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client._call("GET", path, {}, None, retry_500=False)
    assert ei.value.status == 500
    assert len(transport.calls) == 2


def test_400_and_404_and_405_and_414_are_never_retried(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    for status in (400, 404, 405, 414):
        transport = FakeTransport(
            {("GET", path): [_raw(vp, status), _raw(vp, 200)]}
        )
        client, _ = _client(vp, transport)
        with pytest.raises(vp.BeaconStatus) as ei:
            client._call("GET", path, {}, None)
        assert ei.value.status == status
        assert ei.value.template == path
        assert len(transport.calls) == 1


def test_204_returns_none_before_json_loads(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    loaded = []
    real = vp.json.loads

    def spy(raw, *a, **k):
        loaded.append(raw)
        return real(raw, *a, **k)

    monkeypatch.setattr(vp.json, "loads", spy)
    path = _VERSION_TEMPLATE
    transport = FakeTransport({("GET", path): [_raw(vp, 204, b"")]})
    client, _ = _client(vp, transport)
    assert client._call("GET", path, {}, None) is None
    assert loaded == []


def test_ssl_error_and_gaierror_fail_fast(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _VERSION_TEMPLATE
    cases = (
        ssl.SSLError("certificate verify failed"),
        socket.gaierror(-2, "Name or service not known"),
    )
    for exc in cases:
        transport = FakeTransport(
            {("GET", path): [_boom(exc), _boom(exc), _boom(exc)]}
        )
        client, _ = _client(vp, transport)
        with pytest.raises(vp.BeaconTransport):
            client._call("GET", path, {}, None)
        assert len(transport.calls) == 1
        assert transport.drops == []


def test_timeout_and_connection_error_retry_to_max_attempts(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _VERSION_TEMPLATE
    for exc in (
        TimeoutError("timed out"),
        ConnectionError("reset"),
        http.client.IncompleteRead(b""),
    ):
        transport = FakeTransport({("GET", path): [_boom(exc) for _ in range(5)]})
        client, _ = _client(vp, transport)
        with pytest.raises(vp.BeaconTransport):
            client._call("GET", path, {}, None)
        assert len(transport.calls) == 3
        assert len(transport.drops) == 2


def test_drop_called_before_every_retry(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    transport = FakeTransport(
        {("GET", path): [_raw(vp, 503), _raw(vp, 503), _raw(vp, 200, b"{}")]}
    )
    client, _ = _client(vp, transport)
    client._call("GET", path, {}, None)
    assert len(transport.calls) == 3
    assert len(transport.drops) == 2


def test_truncated_body_is_a_hard_error(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    loaded = []
    real = vp.json.loads

    def spy(raw, *a, **k):
        loaded.append(raw)
        return real(raw, *a, **k)

    monkeypatch.setattr(vp.json, "loads", spy)
    path = _SPEC_TEMPLATE
    transport = FakeTransport(
        {("GET", path): [_raw(vp, 200, b'{"ok": true}', truncated=True)]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client._call("GET", path, {}, None)
    assert ei.value.template == path
    assert loaded == []
    assert len(transport.calls) == 1
    assert len(transport.drops) == 1


def test_empty_200_body_is_beacon_status(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    path = _SPEC_TEMPLATE
    transport = FakeTransport({("GET", path): [_raw(vp, 200, b"")]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client._call("GET", path, {}, None)
    assert ei.value.status == 200
    assert ei.value.template == path
    assert len(transport.calls) == 1


def test_no_url_or_secret_in_any_retry_log_line(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    ep = vp.parse_endpoint(_SECRET_URL, "bn0")
    buf = io.StringIO()
    templates = []

    def run(method, template, fmt, body, queue, **call_kw):
        path = template.format(**fmt)
        transport = FakeTransport({(method, path): queue})
        client, _ = _client(vp, transport, ep=ep, stream=buf)
        try:
            client._call(method, template, fmt, body, **call_kw)
        except (vp.BeaconStatus, vp.BeaconTransport):
            pass
        templates.append(template)

    ok = _raw(vp, 200)
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 429, headers={"Retry-After": "7200"}), ok])
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 503), _raw(vp, 503), ok])
    run(
        "POST",
        _REWARDS_TEMPLATE,
        {"epoch": 9},
        b"[]",
        [_raw(vp, 500), _raw(vp, 500)],
        retry_500=True,
    )
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 500), _raw(vp, 500)])
    for status in (400, 404, 405, 414):
        run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, status)])
    run("GET", _VERSION_TEMPLATE, {}, None, [_raw(vp, 204, b"")])
    run("GET", _VERSION_TEMPLATE, {}, None, [_boom(ssl.SSLError("bad cert"))])
    run(
        "GET",
        _VERSION_TEMPLATE,
        {},
        None,
        [_boom(socket.gaierror(-2, "Name or service not known"))],
    )
    run("GET", _VERSION_TEMPLATE, {}, None, [_boom(TimeoutError())] * 3)
    run("GET", _VERSION_TEMPLATE, {}, None, [_boom(ConnectionError())] * 3)
    run(
        "GET",
        _VERSION_TEMPLATE,
        {},
        None,
        [_boom(http.client.IncompleteRead(b""))] * 3,
    )
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 200, b"{}", truncated=True)])
    run("GET", _SPEC_TEMPLATE, {}, None, [_raw(vp, 200, b"")])

    text = buf.getvalue()
    assert "secret" not in text
    assert "abc123SECRET" not in text
    assert "user:secret" not in text
    for template in templates:
        assert template in text
    assert _REWARDS_TEMPLATE.format(epoch=9) not in text
    assert "/abc123SECRET" not in text


def test_request_spacing_lock_enforces_minimum_gap(vp, monkeypatch):
    clock = {"t": 10.0}
    vp._next_request_start = 0.0
    monkeypatch.setattr(vp.time, "monotonic", lambda: clock["t"])

    def sleep(seconds):
        clock["t"] += seconds

    monkeypatch.setattr(vp.time, "sleep", sleep)
    starts = []
    path = _VERSION_TEMPLATE

    def ok():
        starts.append(clock["t"])
        return _raw(vp, 200)

    transport = FakeTransport({("GET", path): [ok, ok]})
    client, _ = _client(vp, transport, request_delay=0.05)
    client._call("GET", path, {}, None)
    client._call("GET", path, {}, None)
    assert len(starts) == 2
    assert starts[1] - starts[0] >= 0.05


# ----- VP-1i: §6 typed calls -----

_VALIDATORS_PATH = "/eth/v1/beacon/states/head/validators"
_PROPOSER_TEMPLATE = "/eth/v1/validator/duties/proposer/{epoch}"


def _query_ids(path: str) -> list[str]:
    return parse_qs(urlsplit(path).query).get("id", [])


def _data_raw(vp, data, status=200):
    return _raw(vp, status, json.dumps({"data": data}).encode())


def test_states_validators_posts_an_object_not_an_array(vp):
    ids = ["0x" + "ab" * 48, "0x" + "cd" * 48]
    att_path = _REWARDS_TEMPLATE.format(epoch=4)
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [_data_raw(vp, [])],
            ("POST", att_path): [_data_raw(vp, {})],
        }
    )
    client, _ = _client(vp, transport)
    client.states_validators("head", ids)
    client.rewards_attestations(4, ids)
    validators_body = json.loads(transport.calls[0][3])
    rewards_body = json.loads(transport.calls[1][3])
    assert validators_body == {"ids": ids}
    assert isinstance(validators_body, dict)
    assert not isinstance(validators_body, list)
    assert rewards_body == ids
    assert isinstance(rewards_body, list)


def test_200_keys_produce_exactly_one_post(vp):
    ids = [str(i) for i in range(200)]
    transport = FakeTransport({("POST", _VALIDATORS_PATH): [_data_raw(vp, [])]})
    client, _ = _client(vp, transport)
    client.states_validators("head", ids)
    assert len(transport.calls) == 1
    assert transport.calls[0][1] == "POST"
    assert transport.calls[0][2] == _VALIDATORS_PATH
    assert json.loads(transport.calls[0][3]) == {"ids": ids}


def test_post_414_falls_back_to_four_chunked_gets(vp):
    ids = [str(i) for i in range(200)]
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [_raw(vp, 414)],
            ("GET", _VALIDATORS_PATH): [_data_raw(vp, []) for _ in range(4)],
        }
    )
    client, _ = _client(vp, transport)
    client.states_validators("head", ids)
    posts = [c for c in transport.calls if c[1] == "POST"]
    gets = [c for c in transport.calls if c[1] == "GET"]
    assert len(posts) == 1
    assert posts[0][2] == _VALIDATORS_PATH
    assert len(gets) == 4
    seen = []
    sizes = []
    for _label, _method, path, _body in gets:
        chunk = _query_ids(path)
        assert len(chunk) <= vp.GET_ID_CHUNK
        assert vp.GET_ID_CHUNK == 64
        sizes.append(len(chunk))
        seen.extend(chunk)
    assert sizes == [64, 64, 64, 8]
    assert seen == ids


def test_post_404_and_405_also_trigger_the_get_fallback(vp):
    ids = ["10", "11", "12"]
    for status in (404, 405):
        transport = FakeTransport(
            {
                ("POST", _VALIDATORS_PATH): [_raw(vp, status)],
                ("GET", _VALIDATORS_PATH): [_data_raw(vp, [])],
            }
        )
        client, _ = _client(vp, transport)
        client.states_validators("head", ids)
        assert [c[1] for c in transport.calls] == ["POST", "GET"]
        assert transport.calls[0][2] == _VALIDATORS_PATH
        assert _query_ids(transport.calls[1][2]) == ids


def test_states_validators_rejects_empty_ids(vp):
    transport = FakeTransport({})
    client, _ = _client(vp, transport)
    with pytest.raises(ValueError):
        client.states_validators("head", [])
    with pytest.raises(ValueError):
        client.states_validators("head", iter([]))
    with pytest.raises(TypeError):
        client.states_validators("head", "0xabcd")
    with pytest.raises(TypeError):
        client.states_validators("head", b"0xabcd")
    assert transport.calls == []


def test_no_method_reaches_the_validators_route_unfiltered():
    source = SCRIPT.read_text(encoding="utf-8")
    tree = ast.parse(source)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            chunk = ast.get_source_segment(source, node) or ""
            if "/validators" in chunk:
                found.append(node.name)
    assert found == ["states_validators"]


def test_header_returns_none_on_404(vp):
    path = "/eth/v1/beacon/headers/123"
    transport = FakeTransport({("GET", path): [_raw(vp, 404)]})
    client, _ = _client(vp, transport)
    assert client.header("123") is None
    assert len(transport.calls) == 1


def test_rewards_block_returns_none_on_404(vp):
    path = "/eth/v1/beacon/rewards/blocks/123"
    transport = FakeTransport({("GET", path): [_raw(vp, 404)]})
    client, _ = _client(vp, transport)
    assert client.rewards_block(123) is None
    assert len(transport.calls) == 1


def test_rewards_routes_pass_retry_500(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    att_path = _REWARDS_TEMPLATE.format(epoch=3)
    transport = FakeTransport({("POST", att_path): [_raw(vp, 500), _raw(vp, 500)]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.rewards_attestations(3, ["1"])
    assert ei.value.status == 500
    assert len(transport.calls) == 2

    duty_path = _PROPOSER_TEMPLATE.format(epoch=3)
    transport = FakeTransport({("GET", duty_path): [_raw(vp, 500), _raw(vp, 500)]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.proposer_duties(3)
    assert ei.value.status == 500
    assert len(transport.calls) == 2

    transport = FakeTransport(
        {("GET", _SPEC_TEMPLATE): [_raw(vp, 400), _raw(vp, 200, b'{"data": {}}')]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.spec()
    assert ei.value.status == 400
    assert len(transport.calls) == 1

    for name in (
        "rewards_attestations",
        "rewards_block",
        "rewards_sync_committee",
    ):
        assert "retry_500=True" in inspect.getsource(getattr(vp.BeaconClient, name))
    assert "retry_500=True" not in inspect.getsource(vp.BeaconClient.proposer_duties)
    assert "retry_500=True" not in inspect.getsource(vp.BeaconClient.spec)


def test_endpoints_used_records_redacted_strings_only(vp):
    ep = vp.parse_endpoint(_SECRET_URL, "bn0")
    transport = FakeTransport(
        {("GET", _SPEC_TEMPLATE): [_data_raw(vp, {"SLOTS_PER_EPOCH": "32"})]}
    )
    client, _ = _client(vp, transport, ep=ep)
    client.spec()
    used = client.endpoints_used
    assert used == ["https://bn.example:5052"]
    blob = " ".join(used)
    assert "secret" not in blob
    assert "user:secret" not in blob
    assert "abc123SECRET" not in blob
    assert "/abc123SECRET" not in blob
    used.append("leaked")
    assert "leaked" not in client.endpoints_used


def test_states_validators_post_204_raises_not_none(vp):
    transport = FakeTransport({("POST", _VALIDATORS_PATH): [_raw(vp, 204, b"")]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.states_validators("head", ["1"])
    assert ei.value.status == 204
    assert [c[1] for c in transport.calls] == ["POST"]


def test_states_validators_get_chunk_204_raises_not_empty_list(vp):
    ids = [str(i) for i in range(65)]
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [_raw(vp, 414)],
            ("GET", _VALIDATORS_PATH): [
                _data_raw(vp, [{"index": "0"}]),
                _raw(vp, 204, b""),
            ],
        }
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.states_validators("head", ids)
    assert ei.value.status == 204
    assert [c[1] for c in transport.calls] == ["POST", "GET", "GET"]


def test_post_400_and_500_do_not_get_fallback(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    ids = ["1", "2"]
    for status in (400, 500):
        transport = FakeTransport(
            {
                ("POST", _VALIDATORS_PATH): [_raw(vp, status), _raw(vp, status)],
                ("GET", _VALIDATORS_PATH): [_data_raw(vp, [])],
            }
        )
        client, _ = _client(vp, transport)
        with pytest.raises(vp.BeaconStatus) as ei:
            client.states_validators("head", ids)
        assert ei.value.status == status
        assert all(c[1] == "POST" for c in transport.calls)
        assert not any(c[1] == "GET" for c in transport.calls)


def test_header_400_still_raises(vp):
    path = "/eth/v1/beacon/headers/123"
    transport = FakeTransport({("GET", path): [_raw(vp, 400)]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.header("123")
    assert ei.value.status == 400
    assert len(transport.calls) == 1


def test_rewards_sync_committee_404_raises(vp):
    path = "/eth/v1/beacon/rewards/sync_committee/5"
    transport = FakeTransport({("POST", path): [_raw(vp, 404)]})
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus) as ei:
        client.rewards_sync_committee(5, ["1"])
    assert ei.value.status == 404
    assert len(transport.calls) == 1


def test_current_stays_zero_on_500(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    transport = FakeTransport(
        {("GET", _SPEC_TEMPLATE): [_raw(vp, 500), _raw(vp, 500)]}
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.BeaconStatus):
        client.spec()
    assert client._current == 0


def test_get_fallback_query_not_passed_through_str_format(vp):
    ids = ["foo{bar}", "baz"]
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [_raw(vp, 414)],
            ("GET", _VALIDATORS_PATH): [_data_raw(vp, [])],
        }
    )
    client, _ = _client(vp, transport)
    client.states_validators("head", ids)
    assert [c[1] for c in transport.calls] == ["POST", "GET"]
    assert _query_ids(transport.calls[1][2]) == ids


# ----- VP-1j: §7 Spec, ChainContext, select_endpoint -----

_GENESIS_PATH = "/eth/v1/beacon/genesis"
_HEADER_HEAD_PATH = "/eth/v1/beacon/headers/head"
_FINALITY_PATH = "/eth/v1/beacon/states/head/finality_checkpoints"
_SYNCING_PATH = "/eth/v1/node/syncing"


def _chain_transport(vp, *, spec="spec__mainnet", spec_body=None):
    spec_resp = (
        _raw(vp, 200, spec_body)
        if spec_body is not None
        else raw_response(vp, spec)
    )
    return FakeTransport(
        route_map(
            **{
                f"GET {_SPEC_TEMPLATE}": [spec_resp],
                f"GET {_GENESIS_PATH}": [raw_response(vp, "genesis__mainnet")],
                f"GET {_HEADER_HEAD_PATH}": [raw_response(vp, "headers__head")],
                f"GET {_FINALITY_PATH}": [
                    raw_response(vp, "finality_checkpoints__head")
                ],
            }
        )
    )


def _load_ctx(vp, *, spec="spec__mainnet", spec_body=None):
    transport = _chain_transport(vp, spec=spec, spec_body=spec_body)
    client, _ = _client(vp, transport)
    ctx = vp.load_chain_context(client)
    return ctx, transport, client


def test_epochs_per_year_is_82181_25_on_mainnet_timing(vp):
    ctx, _, _ = _load_ctx(vp, spec="spec__mainnet")
    assert ctx.spec.seconds_per_slot == 12
    assert ctx.spec.slots_per_epoch == 32
    assert ctx.spec.epochs_per_year == 82181.25


def test_epochs_per_year_halves_at_six_second_slots(vp):
    ctx, _, _ = _load_ctx(vp, spec="spec__spe8")
    assert ctx.spec.seconds_per_slot == 6
    assert ctx.spec.slots_per_epoch == 8
    assert ctx.spec.epochs_per_year == 31_557_600 / 48


def test_load_chain_context_issues_exactly_four_calls(vp):
    ctx, transport, _ = _load_ctx(vp)
    assert [(c[1], c[2]) for c in transport.calls] == [
        ("GET", _SPEC_TEMPLATE),
        ("GET", _GENESIS_PATH),
        ("GET", _HEADER_HEAD_PATH),
        ("GET", _FINALITY_PATH),
    ]
    assert ctx.genesis_time == 1606824023
    assert ctx.network_name == "mainnet"
    assert ctx.finalized_epoch == 99
    assert ctx.rewards_api == ""


def test_head_epoch_derived_from_header_slot_not_clock(vp):
    ctx, transport, _ = _load_ctx(vp, spec="spec__mainnet")
    assert ctx.head_slot == 3232
    assert ctx.head_epoch == 101
    assert ctx.spec.slots_per_epoch == 32
    src = inspect.getsource(vp.load_chain_context)
    assert "time.time" not in src
    assert "datetime" not in src
    clock_epoch = int(vp.time.time() - ctx.genesis_time) // (
        ctx.spec.seconds_per_slot * ctx.spec.slots_per_epoch
    )
    assert clock_epoch != 101
    assert [c[2] for c in transport.calls] == [
        _SPEC_TEMPLATE,
        _GENESIS_PATH,
        _HEADER_HEAD_PATH,
        _FINALITY_PATH,
    ]


def test_select_endpoint_skips_a_syncing_node(vp):
    endpoints = [
        vp.Endpoint("bn0", "http", "syncing.example", 5052, "", None),
        vp.Endpoint("bn1", "http", "ready.example", 5052, "", None),
    ]
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [
                    raw_response(vp, "node_version__lighthouse"),
                    raw_response(vp, "node_version__lighthouse"),
                ],
                f"GET {_SYNCING_PATH}": [
                    raw_response(vp, "node_syncing__is_syncing"),
                    raw_response(vp, "node_syncing__ready"),
                ],
            }
        )
    )
    client, _ = _client(vp, transport, endpoints=endpoints)
    vp.select_endpoint(client)
    assert [c[0] for c in transport.calls] == ["bn0", "bn0", "bn1", "bn1"]
    assert [(c[1], c[2]) for c in transport.calls] == [
        ("GET", _VERSION_TEMPLATE),
        ("GET", _SYNCING_PATH),
        ("GET", _VERSION_TEMPLATE),
        ("GET", _SYNCING_PATH),
    ]
    assert client._current == 1
    assert client._endpoint().label == "bn1"


def test_all_endpoints_failing_raises_no_beacon_available(vp):
    endpoints = [
        vp.Endpoint("bn0", "http", "dead0.example", 5052, "", None),
        vp.Endpoint("bn1", "http", "dead1.example", 5052, "", None),
    ]
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [_raw(vp, 404), _raw(vp, 404)],
            }
        )
    )
    client, _ = _client(vp, transport, endpoints=endpoints)
    with pytest.raises(vp.NoBeaconAvailable):
        vp.select_endpoint(client)
    assert [c[0] for c in transport.calls] == ["bn0", "bn1"]


def test_missing_spec_key_names_the_key(vp, load):
    payload = load("spec__mainnet")
    key = "EPOCHS_PER_SYNC_COMMITTEE_PERIOD"
    del payload["data"][key]
    transport = _chain_transport(vp, spec_body=json.dumps(payload).encode())
    client, _ = _client(vp, transport)
    with pytest.raises(vp.UsageError) as ei:
        vp.load_chain_context(client)
    assert key in str(ei.value)
    assert not isinstance(ei.value, vp.NoBeaconAvailable)


def test_network_name_is_none_without_config_name(vp, load):
    payload = load("spec__mainnet")
    payload["data"].pop("CONFIG_NAME")
    ctx, _, _ = _load_ctx(vp, spec_body=json.dumps(payload).encode())
    assert ctx.network_name is None


def test_head_header_404_and_204_are_not_usage_error_missing_slot(vp):
    for status in (404, 204):
        transport = _chain_transport(vp)
        transport.routes[("GET", _HEADER_HEAD_PATH)] = [_raw(vp, status, b"")]
        client, _ = _client(vp, transport)
        with pytest.raises(vp.NoBeaconAvailable) as ei:
            vp.load_chain_context(client)
        assert ei.type is vp.NoBeaconAvailable
        assert not isinstance(ei.value, vp.UsageError)
        assert "missing slot" not in str(ei.value)


@pytest.mark.parametrize(
    "path",
    [_SPEC_TEMPLATE, _GENESIS_PATH, _FINALITY_PATH],
)
def test_phase1_204_is_no_beacon_available(vp, path):
    transport = _chain_transport(vp)
    transport.routes[("GET", path)] = [_raw(vp, 204, b"")]
    client, _ = _client(vp, transport)
    with pytest.raises(vp.NoBeaconAvailable) as ei:
        vp.load_chain_context(client)
    assert "missing slot" not in str(ei.value)


def test_select_then_load_records_lighthouse_version(vp):
    transport = _chain_transport(vp)
    transport.routes[("GET", _VERSION_TEMPLATE)] = [
        raw_response(vp, "node_version__lighthouse")
    ]
    transport.routes[("GET", _SYNCING_PATH)] = [
        raw_response(vp, "node_syncing__ready")
    ]
    client, _ = _client(vp, transport)
    vp.select_endpoint(client)
    ctx = vp.load_chain_context(client)
    assert ctx.node_version == "Lighthouse/v5.3.0-aa11a3b"
    assert [(c[1], c[2]) for c in transport.calls] == [
        ("GET", _VERSION_TEMPLATE),
        ("GET", _SYNCING_PATH),
        ("GET", _SPEC_TEMPLATE),
        ("GET", _GENESIS_PATH),
        ("GET", _HEADER_HEAD_PATH),
        ("GET", _FINALITY_PATH),
    ]


def test_select_endpoint_ready_node_is_exactly_two_calls(vp):
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [
                    raw_response(vp, "node_version__lighthouse")
                ],
                f"GET {_SYNCING_PATH}": [raw_response(vp, "node_syncing__ready")],
            }
        )
    )
    client, _ = _client(vp, transport)
    vp.select_endpoint(client)
    assert [(c[1], c[2]) for c in transport.calls] == [
        ("GET", _VERSION_TEMPLATE),
        ("GET", _SYNCING_PATH),
    ]
    assert client._current == 0
    assert client._selected_version == "Lighthouse/v5.3.0-aa11a3b"
    assert client._pinned is True
    assert client._generation == 0


def test_all_syncing_endpoints_raise_no_beacon_available(vp):
    endpoints = [
        vp.Endpoint("bn0", "http", "sync0.example", 5052, "", None),
        vp.Endpoint("bn1", "http", "sync1.example", 5052, "", None),
    ]
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [
                    raw_response(vp, "node_version__lighthouse"),
                    raw_response(vp, "node_version__lighthouse"),
                ],
                f"GET {_SYNCING_PATH}": [
                    raw_response(vp, "node_syncing__is_syncing"),
                    raw_response(vp, "node_syncing__is_syncing"),
                ],
            }
        )
    )
    client, _ = _client(vp, transport, endpoints=endpoints)
    with pytest.raises(vp.NoBeaconAvailable):
        vp.select_endpoint(client)
    assert [c[0] for c in transport.calls] == ["bn0", "bn0", "bn1", "bn1"]
    assert client._selected_version == ""


def test_select_endpoint_skips_nonempty_version_required(vp):
    transport = FakeTransport(
        route_map(
            **{
                f"GET {_VERSION_TEMPLATE}": [_raw(vp, 204, b"")],
                f"GET {_SYNCING_PATH}": [raw_response(vp, "node_syncing__ready")],
            }
        )
    )
    client, _ = _client(vp, transport)
    with pytest.raises(vp.NoBeaconAvailable):
        vp.select_endpoint(client)
    assert [c[2] for c in transport.calls] == [_VERSION_TEMPLATE]
    assert client._selected_version == ""


def test_spec_is_frozen(vp):
    ctx, _, _ = _load_ctx(vp)
    with pytest.raises(FrozenInstanceError):
        ctx.spec.slots_per_epoch = 8
    with pytest.raises(FrozenInstanceError):
        ctx.spec.epochs_per_year = 1.0


def test_spec_underscored_uint_names_the_key(vp, load):
    payload = load("spec__mainnet")
    payload["data"]["SLOTS_PER_EPOCH"] = "1_000"
    transport = _chain_transport(vp, spec_body=json.dumps(payload).encode())
    client, _ = _client(vp, transport)
    with pytest.raises(vp.UsageError) as ei:
        vp.load_chain_context(client)
    assert "SLOTS_PER_EPOCH" in str(ei.value)


def test_non_positive_slots_per_epoch_names_the_key(vp, load):
    payload = load("spec__mainnet")
    payload["data"]["SLOTS_PER_EPOCH"] = "0"
    transport = _chain_transport(vp, spec_body=json.dumps(payload).encode())
    client, _ = _client(vp, transport)
    with pytest.raises(vp.UsageError) as ei:
        vp.load_chain_context(client)
    assert "SLOTS_PER_EPOCH" in str(ei.value)


# ----- VP-1k: §8 resolve_window -----


def _spec_from_fixture(vp, load, name="spec__mainnet"):
    raw = load(name)["data"]
    return vp.Spec(
        slots_per_epoch=int(raw["SLOTS_PER_EPOCH"]),
        seconds_per_slot=int(raw["SECONDS_PER_SLOT"]),
        epochs_per_sync_committee_period=int(raw["EPOCHS_PER_SYNC_COMMITTEE_PERIOD"]),
        min_epochs_to_inactivity_penalty=int(raw["MIN_EPOCHS_TO_INACTIVITY_PENALTY"]),
        raw=raw,
    )


def _chain_ctx(
    vp,
    load,
    *,
    spec="spec__mainnet",
    head_epoch=100,
    finalized_epoch=97,
    head_slot=None,
):
    spec_obj = _spec_from_fixture(vp, load, spec)
    if head_slot is None:
        head_slot = head_epoch * spec_obj.slots_per_epoch
    return vp.ChainContext(
        spec=spec_obj,
        genesis_time=0,
        network_name=spec_obj.raw.get("CONFIG_NAME"),
        head_slot=head_slot,
        head_epoch=head_epoch,
        finalized_epoch=finalized_epoch,
        node_version="",
        rewards_api="",
        genesis_validators_root="",
    )


def _window_opts(vp, **kw):
    return replace(vp.build_options(_minimal_opts_argv()), **kw)


def test_default_window_is_66_to_97(vp, load):
    w = vp.resolve_window(_window_opts(vp), _chain_ctx(vp, load))
    assert (w.from_epoch, w.to_epoch) == (66, 97)
    assert w.finalized_only is True
    assert w.epochs == 32


def test_allow_unfinalized_gives_67_to_98(vp, load):
    opts = _window_opts(vp, allow_unfinalized=True)
    w = vp.resolve_window(opts, _chain_ctx(vp, load))
    assert (w.from_epoch, w.to_epoch) == (67, 98)
    assert w.finalized_only is False


def test_epochs_4_lookback(vp, load):
    w = vp.resolve_window(_window_opts(vp, epochs=4), _chain_ctx(vp, load))
    assert (w.from_epoch, w.to_epoch) == (94, 97)
    assert w.epochs == 4
    assert len(list(w)) == 4


def test_to_epoch_equal_max_safe_is_allowed(vp, load):
    ctx = _chain_ctx(vp, load)
    w = vp.resolve_window(_window_opts(vp, to_epoch=98), ctx)
    assert w.to_epoch == 98
    assert w.from_epoch == 67
    assert w.forced_unsafe is False


def test_to_epoch_99_exits_2_naming_max_safe_epoch_98(vp, load):
    opts = _window_opts(vp, to_epoch=99)
    with pytest.raises(vp.UsageError) as ei:
        vp.resolve_window(opts, _chain_ctx(vp, load))
    assert "MAX_SAFE_EPOCH=98" in str(ei.value)
    assert vp.EXIT_USAGE == 2


def test_force_unsafe_window_downgrades_to_a_warning_and_sets_forced_unsafe(vp, load):
    ctx = _chain_ctx(vp, load)
    with pytest.raises(vp.UsageError):
        vp.resolve_window(_window_opts(vp, to_epoch=99), ctx)
    buf = io.StringIO()
    log = vp.Log(0, buf)
    opts = _window_opts(vp, to_epoch=99, force_unsafe_window=True)
    w = vp.resolve_window(opts, ctx, log)
    assert w.forced_unsafe is True
    assert w.to_epoch == 99
    assert "MAX_SAFE_EPOCH=98" in buf.getvalue()


def test_snapshot_slots_are_3232_and_4256(vp, load):
    # RD-4: from*SPE / to*SPE would be 3200 / 4192.
    ctx = _chain_ctx(vp, load, head_epoch=133, finalized_epoch=131)
    opts = _window_opts(vp, from_epoch=100, to_epoch=131)
    w = vp.resolve_window(opts, ctx)
    assert (w.from_epoch, w.to_epoch) == (100, 131)
    assert w.start_slot == 3232
    assert w.end_slot == 4256


def test_spe8_shifts_every_derived_slot(vp, load):
    ctx = _chain_ctx(
        vp, load, spec="spec__spe8", head_epoch=133, finalized_epoch=131
    )
    assert ctx.spec.slots_per_epoch == 8
    opts = _window_opts(vp, from_epoch=100, to_epoch=131)
    w = vp.resolve_window(opts, ctx)
    assert w.start_slot == (100 + 1) * 8 == 808
    assert w.end_slot == (131 + 2) * 8 == 1064


def test_from_greater_than_to_exits_2(vp, load):
    opts = _window_opts(vp, from_epoch=10, to_epoch=5)
    with pytest.raises(vp.UsageError) as ei:
        vp.resolve_window(opts, _chain_ctx(vp, load))
    assert vp.EXIT_USAGE == 2
    assert ei.type is vp.UsageError


def test_negative_epoch_exits_2(vp, load):
    opts = _window_opts(vp, from_epoch=-1, to_epoch=5)
    with pytest.raises(vp.UsageError) as ei:
        vp.resolve_window(opts, _chain_ctx(vp, load))
    assert vp.EXIT_USAGE == 2
    assert ei.type is vp.UsageError


def test_future_epoch_exits_2(vp, load):
    opts = _window_opts(vp, from_epoch=90, to_epoch=101)
    with pytest.raises(vp.UsageError) as ei:
        vp.resolve_window(opts, _chain_ctx(vp, load))
    assert vp.EXIT_USAGE == 2
    assert ei.type is vp.UsageError
    assert "MAX_SAFE_EPOCH" not in str(ei.value)


def test_end_slot_reachable_false_only_under_force_unsafe(vp, load):
    ctx = _chain_ctx(vp, load)
    assert vp.resolve_window(_window_opts(vp), ctx).end_slot_reachable is True
    forced = _window_opts(vp, to_epoch=99, force_unsafe_window=True)
    w = vp.resolve_window(forced, ctx, vp.Log(0, io.StringIO()))
    assert w.end_slot_reachable is False
    assert w.forced_unsafe is True


def test_window_iterates_inclusively(vp, load):
    w = vp.resolve_window(_window_opts(vp), _chain_ctx(vp, load))
    epochs = list(w)
    assert epochs == list(range(w.from_epoch, w.to_epoch + 1))
    assert len(epochs) == w.epochs == w.to_epoch - w.from_epoch + 1


# ----- VP-1l: §9 resolve_validators + ValidatorRef -----

_FAR_FUTURE_EPOCH = 2**64 - 1


def _resolve(vp, pubkeys, *, name=None, payload=None, verbosity=1):
    if name is not None:
        resp = raw_response(vp, name)
    else:
        resp = _raw(vp, 200, json.dumps(payload).encode())
    transport = FakeTransport({("POST", _VALIDATORS_PATH): [resp]})
    client, buf = _client(vp, transport, verbosity=verbosity)
    refs = vp.resolve_validators(client, pubkeys)
    return refs, transport, buf


def test_resolve_returns_index_status_eb_and_activation_window(vp):
    refs, transport, _ = _resolve(
        vp, [PK1, PK2, PK3], name="states_validators__basic"
    )
    assert len(refs) == 3
    a, b, c = refs
    assert a.pubkey == PK1
    assert a.index == 1
    assert a.status == "active_ongoing"
    assert a.effective_balance_gwei == 32_000_000_000
    assert a.activation_epoch == 0
    assert a.exit_epoch == _FAR_FUTURE_EPOCH
    assert a.slashed is False
    assert a.rewards_eligible is True
    assert b.pubkey == PK2
    assert b.index == 2
    assert b.status == "active_exiting"
    assert b.effective_balance_gwei == 2_048_000_000_000
    assert b.activation_epoch == 10
    assert b.exit_epoch == 200
    assert c.pubkey == PK3
    assert c.index == 3
    assert c.status == "pending_queued"
    assert c.effective_balance_gwei == 32_000_000_000
    assert c.activation_epoch == 500
    assert c.exit_epoch == _FAR_FUTURE_EPOCH
    assert len(transport.calls) == 1
    assert transport.calls[0][1] == "POST"


def test_unknown_pubkey_is_null_index_unknown_status_and_run_continues(vp):
    refs, transport, _ = _resolve(
        vp, [PK1, PK4, PK2], name="states_validators__unknown_pubkey"
    )
    assert [r.pubkey for r in refs] == [PK1, PK4, PK2]
    assert refs[0].index == 1
    assert refs[0].status == "active_ongoing"
    assert refs[1].index is None
    assert refs[1].status == "unknown"
    assert refs[1].effective_balance_gwei is None
    assert refs[1].activation_epoch is None
    assert refs[1].exit_epoch is None
    assert refs[1].rewards_eligible is False
    assert refs[1].is_active_at(0) is False
    assert refs[1].is_active_at(100) is False
    assert refs[1].active_epochs_in([100, 131]) == 0
    assert refs[2].index == 2
    assert refs[2].status == "active_ongoing"
    assert len(transport.calls) == 1


def test_results_keyed_by_pubkey_not_position(vp, load):
    payload = load("states_validators__basic")
    by_pk = {row["validator"]["pubkey"]: row for row in payload["data"]}
    # Neither request order nor reverse(request): zip would assign 2, 3, 1.
    order = [PK2, PK3, PK1]
    assert order != [PK1, PK2, PK3]
    assert order != list(reversed([PK1, PK2, PK3]))
    payload["data"] = [by_pk[pk] for pk in order]
    refs, _, _ = _resolve(vp, [PK1, PK2, PK3], payload=payload)
    assert [r.pubkey for r in refs] == [PK1, PK2, PK3]
    assert {r.pubkey: r.index for r in refs} == {PK1: 1, PK2: 2, PK3: 3}


def test_unrecognised_status_passes_through(vp, load):
    payload = load("states_validators__basic")
    for row in payload["data"]:
        pk = row["validator"]["pubkey"]
        if pk == PK1:
            row["status"] = "active_weird"
        elif pk == PK3:
            row["status"] = ""
    quiet, _, quiet_buf = _resolve(
        vp, [PK1, PK2, PK3], payload=payload, verbosity=0
    )
    by_pk = {r.pubkey: r for r in quiet}
    assert by_pk[PK1].status == "active_weird"
    assert by_pk[PK2].status == "active_exiting"
    assert by_pk[PK3].status == ""
    assert by_pk[PK3].status != "unknown"
    assert "active_weird" not in quiet_buf.getvalue()
    _, _, verbose_buf = _resolve(
        vp, [PK1, PK2, PK3], payload=payload, verbosity=1
    )
    text = verbose_buf.getvalue()
    assert "active_weird" in text
    assert PK1 in text


def test_is_active_at_respects_activation_and_exit(vp):
    refs, _, _ = _resolve(
        vp, [PK1], name="states_validators__mid_window_activation"
    )
    ref = refs[0]
    assert ref.activation_epoch == 116
    assert ref.is_active_at(115) is False
    assert ref.is_active_at(116) is True
    assert ref.is_active_at(131) is True
    assert ref.active_epochs_in([100, 131]) == 16
    window = type("W", (), {"from_epoch": 100, "to_epoch": 131})()
    assert ref.active_epochs_in(window) == 16
    exiting = vp.ValidatorRef(
        PK2, 2, "active_exiting", 32_000_000_000, 0, 110, False
    )
    assert exiting.is_active_at(109) is True
    assert exiting.is_active_at(110) is False
    assert exiting.active_epochs_in([100, 131]) == 10


def test_rewards_eligible_false_for_eb_zero(vp):
    payload = {
        "data": [
            {
                "index": "1",
                "balance": "0",
                "status": "pending_initialized",
                "validator": {
                    "pubkey": PK1,
                    "withdrawal_credentials": "0x" + "00" * 32,
                    "effective_balance": "0",
                    "slashed": False,
                    "activation_eligibility_epoch": "0",
                    "activation_epoch": str(_FAR_FUTURE_EPOCH),
                    "exit_epoch": str(_FAR_FUTURE_EPOCH),
                    "withdrawable_epoch": str(_FAR_FUTURE_EPOCH),
                },
            }
        ]
    }
    refs, _, _ = _resolve(vp, [PK1], payload=payload)
    assert refs[0].index == 1
    assert refs[0].effective_balance_gwei == 0
    assert refs[0].rewards_eligible is False
    direct = vp.ValidatorRef(
        PK1, 1, "active_ongoing", 0, 0, _FAR_FUTURE_EPOCH, False
    )
    assert direct.rewards_eligible is False


def test_resolve_empty_pubkeys_makes_zero_calls(vp):
    transport = FakeTransport({})
    client, _ = _client(vp, transport)
    assert vp.resolve_validators(client, []) == []
    assert transport.calls == []


def test_validator_ref_is_frozen(vp):
    ref = vp.ValidatorRef(
        PK1, 1, "active_ongoing", 32_000_000_000, 0, _FAR_FUTURE_EPOCH, False
    )
    with pytest.raises(FrozenInstanceError):
        ref.index = 99


def test_state_id_is_head(vp):
    refs, transport, _ = _resolve(
        vp, [PK1, PK2, PK3], name="states_validators__basic"
    )
    assert refs
    assert len(transport.calls) == 1
    _label, method, path, body = transport.calls[0]
    assert method == "POST"
    assert path == "/eth/v1/beacon/states/head/validators"
    assert path == _VALIDATORS_PATH
    assert re.search(r"/states/\d+/validators", path) is None
    assert json.loads(body) == {"ids": [PK1, PK2, PK3]}


# ----- VP-1m: §7 probe_rewards_api -----

_BLOCKS_HEAD_PATH = "/eth/v1/beacon/rewards/blocks/head"


def _status_queue(vp, status, body=None):
    if body is None:
        body = b'{"data": {}}' if 200 <= status < 300 else b"{}"
    # Rewards 500 retries once (RD-9); script the second response too.
    if status == 500:
        return [_raw(vp, 500, body), _raw(vp, 500, body)]
    return [_raw(vp, status, body)]


def _probe_transport(vp, *, blocks, att, head_epoch=100, extra=None):
    att_path = _REWARDS_TEMPLATE.format(epoch=head_epoch - 2)
    routes = {
        ("GET", _BLOCKS_HEAD_PATH): _status_queue(vp, blocks),
        ("POST", att_path): _status_queue(vp, att),
    }
    if extra:
        routes.update(extra)
    return FakeTransport(routes), att_path


def _run_probe(vp, *, blocks, att, head_epoch=100, ids=("1",), extra=None):
    transport, _ = _probe_transport(
        vp, blocks=blocks, att=att, head_epoch=head_epoch, extra=extra
    )
    client, _ = _client(vp, transport)
    verdict = vp.probe_rewards_api(client, head_epoch, list(ids))
    return verdict, transport


def _raw_from_probe_leg(vp, leg):
    return _raw(vp, leg["status"], json.dumps(leg["body"]).encode())


def _run_probe_fixture(vp, load, name, *, head_epoch=100, ids=("1",)):
    pair = load(name)
    att_path = _REWARDS_TEMPLATE.format(epoch=head_epoch - 2)
    transport = FakeTransport(
        {
            ("GET", _BLOCKS_HEAD_PATH): [_raw_from_probe_leg(vp, pair["blocks"])],
            ("POST", att_path): [_raw_from_probe_leg(vp, pair["attestations"])],
        }
    )
    client, _ = _client(vp, transport)
    verdict = vp.probe_rewards_api(client, head_epoch, list(ids))
    return verdict, transport


def test_probe_404_and_404_is_route_absent(vp, load):
    pair = load("probe__route_absent")
    assert pair["blocks"]["status"] == 404
    assert pair["attestations"]["status"] == 404
    verdict, transport = _run_probe_fixture(vp, load, "probe__route_absent")
    assert verdict == "route_absent"
    assert len(transport.calls) == 2


def test_probe_200_and_404_is_state_unavailable(vp, load):
    pair = load("probe__state_unavailable")
    assert pair["blocks"]["status"] == 200
    assert pair["attestations"]["status"] == 404
    verdict, transport = _run_probe_fixture(vp, load, "probe__state_unavailable")
    assert verdict == "state_unavailable"
    assert len(transport.calls) == 2


def test_probe_200_and_200_is_available(vp):
    verdict, _ = _run_probe(vp, blocks=200, att=200)
    assert verdict == "available"


def test_probe_404_blocks_but_200_attestations_is_available(vp):
    verdict, _ = _run_probe(vp, blocks=404, att=200)
    assert verdict == "available"


def test_probe_500_and_400_fold_into_state_unavailable(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    # Lodestar 500 / Nimbus 400 on attestations, even when blocks is 2xx.
    lodestar, _ = _run_probe(vp, blocks=200, att=500)
    nimbus, _ = _run_probe(vp, blocks=200, att=400)
    assert lodestar == "state_unavailable"
    assert nimbus == "state_unavailable"
    # Non-2xx + non-2xx must not collapse to route_absent (the 4-row 2xx table trap).
    both_miss, _ = _run_probe(vp, blocks=404, att=500)
    nimbus_absent, _ = _run_probe(vp, blocks=404, att=400)
    assert both_miss == "state_unavailable"
    assert nimbus_absent == "state_unavailable"


def test_probe_issues_exactly_two_requests(vp):
    verdict, transport = _run_probe(vp, blocks=200, att=200, ids=("1",))
    assert verdict == "available"
    assert len(transport.calls) == 2
    assert [c[1] for c in transport.calls] == ["GET", "POST"]
    assert transport.calls[0][2] == _BLOCKS_HEAD_PATH
    assert json.loads(transport.calls[1][3]) == ["1"]


def test_probe_empty_ids_skips_attestations_post(vp):
    # POST [] is the unfiltered rewards form; do not script a POST so a call fails.
    for blocks, expected in ((200, "state_unavailable"), (404, "route_absent")):
        transport = FakeTransport(
            {("GET", _BLOCKS_HEAD_PATH): _status_queue(vp, blocks)}
        )
        client, _ = _client(vp, transport)
        verdict = vp.probe_rewards_api(client, 100, [])
        assert verdict == expected
        assert len(transport.calls) == 1
        assert transport.calls[0][1] == "GET"
        assert transport.calls[0][2] == _BLOCKS_HEAD_PATH
        assert transport.calls[0][3] is None
        assert not any(c[1] == "POST" for c in transport.calls)
        assert not any(c[3] == b"[]" for c in transport.calls)


def test_probe_attestations_204_is_not_2xx(vp):
    # Teku 204 (store not ready) unwraps to None; that is not a 2xx success.
    unavailable, t_ok = _run_probe(vp, blocks=200, att=204)
    assert unavailable == "state_unavailable"
    assert t_ok.calls[1][1] == "POST"
    absent, t_404 = _run_probe(vp, blocks=404, att=204)
    assert absent == "route_absent"
    assert t_404.calls[1][1] == "POST"


def test_probe_body_carries_a_resolved_eb_nonzero_index(vp):
    payload = {
        "data": [
            {
                "index": "10",
                "balance": "0",
                "status": "pending_initialized",
                "validator": {
                    "pubkey": PK1,
                    "withdrawal_credentials": "0x" + "00" * 32,
                    "effective_balance": "0",
                    "slashed": False,
                    "activation_eligibility_epoch": "0",
                    "activation_epoch": str(_FAR_FUTURE_EPOCH),
                    "exit_epoch": str(_FAR_FUTURE_EPOCH),
                    "withdrawable_epoch": str(_FAR_FUTURE_EPOCH),
                },
            },
            {
                "index": "20",
                "balance": "32000000000",
                "status": "active_ongoing",
                "validator": {
                    "pubkey": PK2,
                    "withdrawal_credentials": "0x" + "00" * 32,
                    "effective_balance": "32000000000",
                    "slashed": False,
                    "activation_eligibility_epoch": "0",
                    "activation_epoch": "0",
                    "exit_epoch": str(_FAR_FUTURE_EPOCH),
                    "withdrawable_epoch": str(_FAR_FUTURE_EPOCH),
                },
            },
        ]
    }
    head_epoch = 100
    att_path = _REWARDS_TEMPLATE.format(epoch=head_epoch - 2)
    transport = FakeTransport(
        {
            ("POST", _VALIDATORS_PATH): [
                _raw(vp, 200, json.dumps(payload).encode())
            ],
            ("GET", _BLOCKS_HEAD_PATH): _status_queue(vp, 200),
            ("POST", att_path): _status_queue(vp, 200),
        }
    )
    client, _ = _client(vp, transport)
    refs = vp.resolve_validators(client, [PK1, PK2])
    assert refs[0].rewards_eligible is False
    assert refs[1].rewards_eligible is True
    ids = [str(r.index) for r in refs if r.rewards_eligible]
    assert ids == ["20"]
    verdict = vp.probe_rewards_api(client, head_epoch, ids)
    assert verdict == "available"
    rewards_calls = [c for c in transport.calls if "rewards" in c[2]]
    assert len(rewards_calls) == 2
    body = json.loads(rewards_calls[1][3])
    assert body == ["20"]
    assert "10" not in body


def test_probe_uses_head_minus_two(vp):
    head_epoch = 101
    verdict, transport = _run_probe(vp, blocks=200, att=200, head_epoch=head_epoch)
    assert verdict == "available"
    assert transport.calls[0][2] == _BLOCKS_HEAD_PATH
    assert transport.calls[1][2] == _REWARDS_TEMPLATE.format(epoch=99)
    assert "/100" not in transport.calls[1][2]
    assert "/101" not in transport.calls[1][2]
    src = inspect.getsource(vp.probe_rewards_api)
    assert "head_epoch - 2" in src
    assert "head_epoch - 1" not in src


def test_probe_non_2xx_does_not_raise(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    cases = (
        (404, 404, "route_absent"),
        (200, 404, "state_unavailable"),
        (200, 500, "state_unavailable"),
        (200, 400, "state_unavailable"),
        (404, 200, "available"),
    )
    for blocks, att, expected in cases:
        verdict, _ = _run_probe(vp, blocks=blocks, att=att)
        assert verdict == expected
        assert verdict in ("available", "route_absent", "state_unavailable")


# ----- VP-2a: §10 detect_leak + build_ideal_index -----

_GWEI = 1_000_000_000
_EB_31 = 31 * _GWEI
_EB_32 = 32 * _GWEI
_EB_2048 = 2048 * _GWEI


def _rewards_body(payload):
    env = payload[0] if isinstance(payload, list) else payload
    if isinstance(env, dict) and "data" in env and "ideal_rewards" not in env:
        return env["data"]
    return env


def _ideal_rows(payload):
    data = _rewards_body(payload)
    if isinstance(data, dict):
        return data["ideal_rewards"]
    return data


def _active_ref(
    vp,
    index=1,
    eb=_EB_32,
    activation=0,
    exit_epoch=_FAR_FUTURE_EPOCH,
    *,
    pubkey=PK1,
    status="active_ongoing",
    slashed=False,
):
    return vp.ValidatorRef(
        pubkey, index, status, eb, activation, exit_epoch, slashed
    )


def _flag_tuple(row):
    return int(row["source"]), int(row["target"]), int(row["head"])


def test_detect_leak_true_when_largest_eb_row_is_all_zero(vp, load):
    rows = _ideal_rows(load("rewards_attestations__leak"))
    largest = max(rows, key=lambda r: int(r["effective_balance"]))
    assert _flag_tuple(largest) == (0, 0, 0)
    assert _flag_tuple(rows[0]) != (0, 0, 0)
    assert vp.detect_leak(rows) is True


def test_detect_leak_false_when_largest_eb_row_is_nonzero(vp, load):
    payload = load("rewards_attestations__basic")
    envelopes = payload if isinstance(payload, list) else [payload]
    assert envelopes
    for env in envelopes:
        rows = _ideal_rows(env)
        largest = max(rows, key=lambda r: int(r["effective_balance"]))
        assert _flag_tuple(largest) != (0, 0, 0)
        assert vp.detect_leak(rows) is False


def test_detect_leak_uses_the_largest_eb_row_not_the_first(vp):
    rows = [
        {
            "effective_balance": "32000000000",
            "head": "0",
            "target": "0",
            "source": "0",
            "inactivity": "0",
        },
        {
            "effective_balance": "2048000000000",
            "head": "117376",
            "target": "939008",
            "source": "586880",
            "inactivity": "0",
        },
    ]
    assert _flag_tuple(rows[0]) == (0, 0, 0)
    assert int(rows[1]["effective_balance"]) > int(rows[0]["effective_balance"])
    assert _flag_tuple(rows[1]) != (0, 0, 0)
    assert vp.detect_leak(rows) is False


def test_detect_leak_false_when_largest_eb_target_is_nonzero(vp):
    rows = [
        {
            "effective_balance": "32000000000",
            "head": "0",
            "target": "0",
            "source": "0",
            "inactivity": "0",
        },
        {
            "effective_balance": "2048000000000",
            "head": "0",
            "target": "14672",
            "source": "0",
            "inactivity": "0",
        },
    ]
    assert _flag_tuple(rows[0]) == (0, 0, 0)
    assert _flag_tuple(rows[1]) == (0, 14672, 0)
    assert vp.detect_leak(rows) is False


def test_detect_leak_false_on_empty_ideal_rows(vp):
    assert vp.detect_leak([]) is False


def test_build_ideal_index_is_a_dict_keyed_by_effective_balance(vp, load):
    rows = _ideal_rows(load("rewards_attestations__ideal_filtered"))
    wanted = next(r for r in rows if int(r["effective_balance"]) == _EB_31)
    assert rows[0] is not wanted
    index = vp.build_ideal_index(rows)
    assert isinstance(index, dict)
    assert index[_EB_31] == _flag_tuple(wanted)
    positional = _flag_tuple(rows[0])
    assert index[_EB_31] != positional


def test_ideal_index_duplicate_eb_last_wins(vp):
    rows = [
        {
            "effective_balance": "32000000000",
            "head": "1",
            "target": "2",
            "source": "3",
            "inactivity": "0",
        },
        {
            "effective_balance": "32000000000",
            "head": "10",
            "target": "20",
            "source": "30",
            "inactivity": "0",
        },
    ]
    index = vp.build_ideal_index(rows)
    assert index[_EB_32] == (30, 20, 10)
    assert len(index) == 1


def test_ideal_index_missing_eb_returns_none_not_zero(vp, load):
    rows = _ideal_rows(load("rewards_attestations__ideal_filtered"))
    assert all(int(r["effective_balance"]) != _EB_32 for r in rows)
    index = vp.build_ideal_index(rows)
    assert index.get(_EB_32) is None
    assert index.get(_EB_32) != (0, 0, 0)


def test_ideal_index_handles_a_2048_row_table(vp):
    rows = [
        {
            "effective_balance": str(eth * _GWEI),
            "head": str(eth),
            "target": str(eth * 2),
            "source": str(eth * 3),
            "inactivity": "0",
        }
        for eth in range(1, 2049)
    ]
    index = vp.build_ideal_index(rows)
    assert len(index) == 2048
    assert index[_EB_2048] == (2048 * 3, 2048 * 2, 2048)


def test_ideal_index_not_cached_across_epochs(vp, load):
    a = vp.build_ideal_index(_ideal_rows(load("rewards_attestations__basic")))
    b = vp.build_ideal_index(_ideal_rows(load("rewards_attestations__ideal_filtered")))
    assert a is not b
    assert a != b


# ----- VP-2b: §10 evaluate_epoch — eligibility → leak → sign predicates -----


def _eval_epoch(vp, epoch, resp, refs, eb_by_index, log=None):
    kwargs = {}
    if log is not None:
        kwargs["log"] = log
    return vp.evaluate_epoch(epoch, _rewards_body(resp), refs, eb_by_index, **kwargs)


def test_leak_epoch_credits_source_and_target(vp, load):
    # RD-2: credited flags pay 0 in a leak; >0 reports 0% for a correct vote.
    resp = load("rewards_attestations__leak")
    row = _rewards_body(resp)["total_rewards"][0]
    assert _flag_tuple(row) == (0, 0, 0)
    ref = _active_ref(vp, index=int(row["validator_index"]))
    outcomes = _eval_epoch(vp, 100, resp, [ref], {ref.index: _EB_32})
    o = outcomes[ref.index]
    assert o.source_credited is True
    assert o.target_credited is True
    assert o.leak is True


def test_leak_epoch_head_is_none_not_false(vp, load):
    resp = load("rewards_attestations__leak")
    ref = _active_ref(vp)
    o = _eval_epoch(vp, 100, resp, [ref], {ref.index: _EB_32})[ref.index]
    assert o.head_credited is None
    assert o.head_credited is not False
    assert o.leak is True


def test_leak_epoch_has_no_ideal_denominator(vp, load):
    resp = load("rewards_attestations__leak")
    ref = _active_ref(vp)
    o = _eval_epoch(vp, 100, resp, [ref], {ref.index: _EB_32})[ref.index]
    assert o.flag_ideal_gwei is None
    assert o.leak is True


def _ideal_32():
    return [
        {
            "effective_balance": str(_EB_32),
            "head": "1834",
            "target": "14672",
            "source": "9170",
            "inclusion_delay": "0",
            "inactivity": "0",
        }
    ]


def _att_resp(total, ideal=None):
    return {
        "ideal_rewards": _ideal_32() if ideal is None else ideal,
        "total_rewards": total,
    }


def _flags(index, source, target, head, inactivity="0"):
    return {
        "validator_index": str(index),
        "head": str(head),
        "target": str(target),
        "source": str(source),
        "inactivity": str(inactivity),
    }


def test_fixture_a_gives_source_rate_075_and_head_rate_05(vp, load):
    envelopes = load("rewards_attestations__basic")
    assert isinstance(envelopes, list) and len(envelopes) == 4
    rows = [_rewards_body(env)["total_rewards"][0] for env in envelopes]
    assert sum(int(r["source"]) == -100 for r in rows) == 1
    assert sum(int(r["head"]) == 0 for r in rows) == 2
    ref = _active_ref(vp)
    outcomes = []
    for i, env in enumerate(envelopes):
        got = _eval_epoch(vp, 100 + i, env, [ref], {ref.index: _EB_32})
        assert ref.index in got
        outcomes.append(got[ref.index])
        assert got[ref.index].leak is False
    assert sum(o.source_credited for o in outcomes) / 4 == 0.75
    assert sum(o.head_credited for o in outcomes) / 4 == 0.5


def test_missed_attestations_predicate(vp):
    ref = _active_ref(vp)
    missed = _eval_epoch(
        vp, 100, _att_resp([_flags(1, -1, -2, 0)]), [ref], {1: _EB_32}
    )[1]
    source_only = _eval_epoch(
        vp, 100, _att_resp([_flags(1, -100, 0, 0)]), [ref], {1: _EB_32}
    )[1]
    assert missed.missed is True
    assert missed.source_credited is False
    assert missed.target_credited is False
    assert source_only.missed is False
    assert source_only.source_credited is False
    assert source_only.target_credited is True


def test_participation_credits_target_only_epoch(vp, load):
    envelopes = load("rewards_attestations__basic")
    target_only = next(
        env
        for env in envelopes
        if int(_rewards_body(env)["total_rewards"][0]["source"]) == -100
    )
    row = _rewards_body(target_only)["total_rewards"][0]
    assert int(row["target"]) == 0
    ref = _active_ref(vp)
    o = _eval_epoch(vp, 101, target_only, [ref], {ref.index: _EB_32})[ref.index]
    assert o.source_credited is False
    assert o.target_credited is True
    assert (o.source_credited or o.target_credited) is True
    assert o.missed is False


def test_ineligible_epoch_enters_no_denominator(vp):
    refs, _, _ = _resolve(
        vp, [PK1], name="states_validators__mid_window_activation"
    )
    ref = refs[0]
    assert ref.activation_epoch == 116
    assert ref.index == 42
    resp = _att_resp([_flags(42, 0, 0, 0)])
    pre = _eval_epoch(vp, 115, resp, [ref], {42: _EB_32})
    assert 42 not in pre
    assert pre == {}
    on = _eval_epoch(vp, 116, resp, [ref], {42: _EB_32})
    assert 42 in on
    assert on[42].missed is False


def test_zero_filled_row_outside_a_leak_for_an_inactive_validator_is_not_perfect(
    vp,
):
    inactive = _active_ref(vp, activation=500)
    assert inactive.is_active_at(100) is False
    resp = _att_resp([_flags(1, 0, 0, 0)])
    assert vp.detect_leak(resp["ideal_rewards"]) is False
    outcomes = _eval_epoch(vp, 100, resp, [inactive], {1: _EB_32})
    assert 1 not in outcomes
    credited = _eval_epoch(vp, 100, resp, [_active_ref(vp)], {1: _EB_32})[1]
    assert credited.source_credited is True
    assert credited.target_credited is True


def test_missing_row_yields_no_outcome_not_a_zero_outcome(vp):
    ref = _active_ref(vp)
    outcomes = _eval_epoch(vp, 100, _att_resp([]), [ref], {1: _EB_32})
    assert 1 not in outcomes
    assert outcomes.get(1) is None
    assert outcomes == {}


def test_missing_ideal_row_sets_flag_ideal_none(vp, load):
    resp = load("rewards_attestations__ideal_filtered")
    rows = _ideal_rows(resp)
    assert all(int(r["effective_balance"]) != _EB_32 for r in rows)
    ref = _active_ref(vp, eb=_EB_32)
    o = _eval_epoch(vp, 100, resp, [ref], {ref.index: _EB_32})[ref.index]
    assert o.flag_ideal_gwei is None
    assert o.leak is False
    assert o.source_credited is True


def test_head_positive_implies_source_and_target_nonnegative_sanity_logs_at_v_and_keeps_the_row(
    vp,
):
    ref = _active_ref(vp)
    resp = _att_resp([_flags(1, -1, -1, 10)])
    quiet = io.StringIO()
    verbose = io.StringIO()
    kept = _eval_epoch(
        vp, 100, resp, [ref], {1: _EB_32}, log=vp.Log(1, verbose)
    )
    assert 1 in kept
    o = kept[1]
    assert o.head_credited is True
    assert o.source_credited is False
    assert o.target_credited is False
    text = verbose.getvalue()
    assert "head" in text
    assert "100" in text
    _eval_epoch(vp, 100, resp, [ref], {1: _EB_32}, log=vp.Log(0, quiet))
    assert quiet.getvalue() == ""


# ----- VP-2c: §10 collect_attestations + D7 reduce + D6 EB-0 -----


class _RecordingPool:
    def __init__(self, inner):
        self._inner = inner
        self.results = []

    def submit(self, fn, *args, **kwargs):
        results = self.results

        def wrapped(*a, **kw):
            result = fn(*a, **kw)
            results.append(result)
            return result

        return self._inner.submit(wrapped, *args, **kwargs)


def _att_window(vp, from_epoch, to_epoch):
    spe = 32
    return vp.Window(
        from_epoch,
        to_epoch,
        to_epoch + 2,
        to_epoch,
        True,
        False,
        (from_epoch + 1) * spe,
        (to_epoch + 2) * spe,
        True,
    )


def _att_ok(vp, indices=(1,)):
    payload = {
        "data": _att_resp([_flags(i, 9170, 14672, 1834) for i in indices])
    }
    return _raw(vp, 200, json.dumps(payload).encode())


def _att_routes(w, response, *, fail_epoch=None, fail=None):
    routes = {}
    for epoch in w:
        path = _REWARDS_TEMPLATE.format(epoch=epoch)
        item = fail if fail_epoch is not None and epoch == fail_epoch else response
        routes[("POST", path)] = list(item) if isinstance(item, list) else [item]
    return routes


def _collect_att(
    vp, w, refs, routes, *, concurrency=4, budget=None, pool=None
):
    transport = FakeTransport(routes)
    client, _ = _client(vp, transport)
    if budget is None:
        budget = vp.RequestBudget()
    if pool is not None:
        outcomes, degs = vp.collect_attestations(client, w, refs, pool, budget)
        return outcomes, degs, transport, budget
    with ThreadPoolExecutor(max_workers=concurrency) as owned:
        outcomes, degs = vp.collect_attestations(client, w, refs, owned, budget)
    return outcomes, degs, transport, budget


def _many_refs(vp, n):
    return [
        _active_ref(vp, index=i, pubkey=f"0x{i:096x}") for i in range(1, n + 1)
    ]


def _walk_worker_result(obj):
    seen: set[int] = set()
    stack = [obj]
    has_bytes = False
    has_ideal = False
    while stack:
        cur = stack.pop()
        ident = id(cur)
        if ident in seen:
            continue
        seen.add(ident)
        if isinstance(cur, (bytes, bytearray, memoryview)):
            has_bytes = True
            continue
        if isinstance(cur, dict):
            if "ideal_rewards" in cur:
                has_ideal = True
            stack.extend(cur.keys())
            stack.extend(cur.values())
        elif isinstance(cur, (list, tuple, set, frozenset)):
            stack.extend(cur)
        else:
            inner = getattr(cur, "__dict__", None)
            if inner is not None:
                stack.append(inner)
    return has_bytes, has_ideal


def test_one_post_per_epoch_regardless_of_validator_count(vp):
    w = _att_window(vp, 100, 131)
    assert w.epochs == 32
    refs = _many_refs(vp, 200)
    ok = _att_ok(vp, indices=(1,))
    outcomes, _degs, transport, _budget = _collect_att(
        vp, w, refs, _att_routes(w, ok)
    )
    posts = [
        c
        for c in transport.calls
        if c[1] == "POST" and "rewards/attestations/" in c[2]
    ]
    assert len(posts) == 32
    assert {c[2] for c in posts} == {
        _REWARDS_TEMPLATE.format(epoch=e) for e in w
    }
    for _label, _method, _path, body in posts:
        payload = json.loads(body)
        assert isinstance(payload, list)
        assert not isinstance(payload, dict)
        assert payload == [str(i) for i in range(1, 201)]
        assert len(payload) == 200
    assert 1 in outcomes


def test_eb_zero_key_excluded_from_the_body_up_front(vp):
    refs, _, _ = _resolve(vp, [PK1, PK2], name="states_validators__eb_zero")
    assert refs[0].effective_balance_gwei == 0
    assert refs[0].rewards_eligible is False
    assert refs[1].rewards_eligible is True
    w = _att_window(vp, 100, 100)
    ok = _att_ok(vp, indices=(refs[1].index,))
    _outcomes, _degs, transport, _budget = _collect_att(
        vp, w, refs, _att_routes(w, ok)
    )
    posts = [c for c in transport.calls if c[1] == "POST"]
    assert posts
    body = json.loads(posts[0][3])
    assert isinstance(body, list)
    assert str(refs[0].index) not in body
    assert str(refs[1].index) in body
    assert body == [str(refs[1].index)]


def test_eb_zero_epoch_post_issued_once(vp):
    refs, _, _ = _resolve(vp, [PK1, PK2], name="states_validators__eb_zero")
    w = _att_window(vp, 100, 100)
    ok = _att_ok(vp, indices=(refs[1].index,))
    _outcomes, _degs, transport, budget = _collect_att(
        vp, w, refs, _att_routes(w, ok)
    )
    posts = [
        c
        for c in transport.calls
        if c[1] == "POST" and "rewards/attestations/" in c[2]
    ]
    assert len(posts) == 1
    assert posts[0][2] == _REWARDS_TEMPLATE.format(epoch=100)
    assert budget.extra == 0
    assert budget.flagged is False


def test_eb_zero_key_reports_effective_balance_zero_reason(vp):
    refs, _, _ = _resolve(vp, [PK1, PK2], name="states_validators__eb_zero")
    w = _att_window(vp, 100, 100)
    ok = _att_ok(vp, indices=(refs[1].index,))
    outcomes, degs, _transport, _budget = _collect_att(
        vp, w, refs, _att_routes(w, ok)
    )
    assert refs[0].index not in outcomes
    zero = [
        d
        for d in degs
        if d.reason == "effective_balance_zero"
        and d.scope == f"validator:{refs[0].index}"
    ]
    assert zero
    assert all(d.reason == "effective_balance_zero" for d in zero)


def test_worker_returns_epoch_outcomes_not_raw_bytes(vp):
    w = _att_window(vp, 100, 100)
    refs = [_active_ref(vp)]
    ok = _att_ok(vp, indices=(1,))
    transport = FakeTransport(_att_routes(w, ok))
    client, _ = _client(vp, transport)
    budget = vp.RequestBudget()
    with ThreadPoolExecutor(max_workers=1) as inner:
        pool = _RecordingPool(inner)
        _outcomes, _degs = vp.collect_attestations(
            client, w, refs, pool, budget
        )
    assert pool.results
    src = inspect.getsource(vp.collect_attestations)
    assert "as_completed" in src
    for result in pool.results:
        assert isinstance(result, dict)
        assert all(isinstance(k, int) for k in result)
        assert all(isinstance(v, vp.EpochOutcome) for v in result.values())
        has_bytes, has_ideal = _walk_worker_result(result)
        assert has_bytes is False
        assert has_ideal is False


def _prysm_att(vp, index, eb, *, source, target, head):
    ideal = [
        {
            "effective_balance": str(eb),
            "head": str(head),
            "target": str(target),
            "source": str(source),
            "inclusion_delay": "0",
            "inactivity": "0",
        }
    ]
    payload = {
        "data": _att_resp(
            [_flags(index, source, target, head)], ideal=ideal
        )
    }
    return _raw(vp, 200, json.dumps(payload).encode())


def test_recovered_split_unions_disjoint_ideal_rows(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    refs = [
        _active_ref(vp, index=1, eb=_EB_32, pubkey=PK1),
        _active_ref(vp, index=2, eb=_EB_2048, pubkey=PK2),
    ]
    left = _prysm_att(vp, 1, _EB_32, source=9170, target=14672, head=1834)
    right = _prysm_att(
        vp, 2, _EB_2048, source=586880, target=939008, head=117376
    )
    path = _REWARDS_TEMPLATE.format(epoch=100)
    routes = {
        ("POST", path): [_raw(vp, 500), _raw(vp, 500), left, right]
    }
    outcomes, degs, transport, budget = _collect_att(vp, w, refs, routes)
    bodies = [json.loads(c[3]) for c in transport.calls if c[1] == "POST"]
    assert ["1", "2"] in bodies
    assert ["1"] in bodies
    assert ["2"] in bodies
    assert 1 in outcomes and 2 in outcomes
    assert outcomes[1][0].flag_ideal_gwei == 9170 + 14672 + 1834
    assert outcomes[2][0].flag_ideal_gwei == 586880 + 939008 + 117376
    assert outcomes[1][0].flag_ideal_gwei is not None
    assert outcomes[2][0].flag_ideal_gwei is not None
    assert not any(d.scope == "epoch:100" for d in degs)
    assert budget.extra > 0
    assert budget.flagged is True


def test_mixed_split_failure_degrades_the_epoch(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    refs = [
        _active_ref(vp, index=1, eb=_EB_32, pubkey=PK1),
        _active_ref(vp, index=2, eb=_EB_2048, pubkey=PK2),
    ]
    left = _prysm_att(vp, 1, _EB_32, source=9170, target=14672, head=1834)
    path = _REWARDS_TEMPLATE.format(epoch=100)
    routes = {
        ("POST", path): [
            _raw(vp, 500),
            _raw(vp, 500),
            left,
            _raw(vp, 500),
            _raw(vp, 500),
        ]
    }
    outcomes, degs, _transport, budget = _collect_att(vp, w, refs, routes)
    assert all(not series for series in outcomes.values())
    assert any(
        d.scope == "epoch:100" and d.reason == "state_unavailable" for d in degs
    )
    assert budget.extra > 0
    assert budget.flagged is True


def test_collect_emits_inactivity_leak_degradation(vp):
    w = _att_window(vp, 100, 100)
    refs = [_active_ref(vp)]
    leak = raw_response(vp, "rewards_attestations__leak")
    outcomes, degs, _transport, _budget = _collect_att(
        vp, w, refs, _att_routes(w, leak)
    )
    assert 1 in outcomes
    o = outcomes[1][0]
    assert o.epoch == 100
    assert o.leak is True
    assert o.head_credited is None
    assert any(
        d.reason == "inactivity_leak" and d.scope == "epoch:100" for d in degs
    )


def test_batch_split_is_depth_capped_at_two(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    refs = _many_refs(vp, 8)
    fail = [_raw(vp, 500) for _ in range(40)]
    outcomes, degs, transport, _budget = _collect_att(
        vp, w, refs, _att_routes(w, fail)
    )
    posts = [
        c
        for c in transport.calls
        if c[1] == "POST" and "rewards/attestations/" in c[2]
    ]
    sizes = [len(json.loads(c[3])) for c in posts]
    assert 8 in sizes
    assert 4 in sizes
    assert 2 in sizes
    assert 1 not in sizes
    assert len(posts) <= 14
    assert any(d.scope == "epoch:100" for d in degs)
    assert all(not series for series in outcomes.values())


def test_split_requests_counted_outside_the_budget(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    refs = _many_refs(vp, 4)
    fail = [_raw(vp, 500) for _ in range(40)]
    _outcomes, _degs, transport, budget = _collect_att(
        vp, w, refs, _att_routes(w, fail)
    )
    posts = [
        c
        for c in transport.calls
        if c[1] == "POST" and "rewards/attestations/" in c[2]
    ]
    assert len(posts) > 1
    assert budget.extra > 0
    assert budget.flagged is True


def test_one_epoch_failure_degrades_only_that_epoch(vp):
    w = _att_window(vp, 100, 131)
    assert w.epochs == 32
    refs = [_active_ref(vp)]
    ok = _att_ok(vp, indices=(1,))
    failed = 115
    routes = _att_routes(w, ok, fail_epoch=failed, fail=_raw(vp, 404))
    outcomes, degs, _transport, _budget = _collect_att(vp, w, refs, routes)
    series = outcomes[1]
    assert len(series) == 31
    assert all(o.epoch != failed for o in series)
    assert {o.epoch for o in series} == set(w) - {failed}
    epoch_degs = [d for d in degs if d.scope.startswith("epoch:")]
    assert len(epoch_degs) == 1
    assert epoch_degs[0].scope == f"epoch:{failed}"


def test_all_epochs_failing_gives_null_metrics_not_exit_1(vp):
    w = _att_window(vp, 100, 103)
    refs = [_active_ref(vp)]
    fail = _raw(vp, 404)
    outcomes, degs, _transport, _budget = _collect_att(
        vp, w, refs, _att_routes(w, fail)
    )
    assert 1 in outcomes
    assert outcomes[1] == []
    assert all(not series for series in outcomes.values())
    assert {d.scope for d in degs} == {f"epoch:{e}" for e in w}
    assert vp.EXIT_ERROR == 1
    assert vp.EXIT_DEGRADED == 3


def test_concurrency_one_is_serial(vp):
    opts = vp.build_options(_minimal_opts_argv("--concurrency", "1"))
    assert opts.concurrency == 1
    w = _att_window(vp, 100, 103)
    refs = [_active_ref(vp)]
    ok = _att_ok(vp, indices=(1,))
    _outcomes, _degs, transport, _budget = _collect_att(
        vp,
        w,
        refs,
        _att_routes(w, ok),
        concurrency=opts.concurrency,
    )
    posts = [
        c
        for c in transport.calls
        if c[1] == "POST" and "rewards/attestations/" in c[2]
    ]
    assert [c[2] for c in posts] == [
        _REWARDS_TEMPLATE.format(epoch=e) for e in w
    ]


def test_all_eb_zero_issues_zero_rewards_posts(vp):
    refs, _, _ = _resolve(vp, [PK1], name="states_validators__eb_zero")
    refs = [r for r in refs if r.effective_balance_gwei == 0]
    assert refs and refs[0].rewards_eligible is False
    w = _att_window(vp, 100, 103)
    _outcomes, degs, transport, _budget = _collect_att(vp, w, refs, {})
    assert transport.calls == []
    assert all(d.reason == "effective_balance_zero" for d in degs)
    assert not any("rewards/attestations" in c[2] for c in transport.calls)


# ----- VP-1n: §16 main + --dry-run + exits 0/2/5 -----

# headers__head slot 3232 / spec__mainnet SPE 32 → head_epoch 101; probe uses 99.
_DRY_RUN_HEAD_EPOCH = 101
_DRY_RUN_ATT_PATH = _REWARDS_TEMPLATE.format(epoch=_DRY_RUN_HEAD_EPOCH - 2)


def _dry_run_argv(*extra, url="https://bn.example:5052"):
    return [
        "--validators-config",
        str(FIXTURES / "validators__three_entries.toml"),
        "--beacon-url",
        url,
        "--dry-run",
        *extra,
    ]


def _dry_run_routes(vp, *, probe="probe__state_unavailable"):
    pair = json.loads((FIXTURES / f"{probe}.json").read_text())
    return {
        ("GET", _VERSION_TEMPLATE): [raw_response(vp, "node_version__lighthouse")],
        ("GET", _SYNCING_PATH): [raw_response(vp, "node_syncing__ready")],
        ("GET", _SPEC_TEMPLATE): [raw_response(vp, "spec__mainnet")],
        ("GET", _GENESIS_PATH): [raw_response(vp, "genesis__mainnet")],
        ("GET", _HEADER_HEAD_PATH): [raw_response(vp, "headers__head")],
        ("GET", _FINALITY_PATH): [
            raw_response(vp, "finality_checkpoints__head")
        ],
        ("POST", _VALIDATORS_PATH): [raw_response(vp, "states_validators__basic")],
        ("GET", _BLOCKS_HEAD_PATH): [_raw_from_probe_leg(vp, pair["blocks"])],
        ("POST", _DRY_RUN_ATT_PATH): [
            _raw_from_probe_leg(vp, pair["attestations"])
        ],
    }


def _run_dry_run(vp, *, probe="probe__state_unavailable", extra=(), url=None):
    transport = FakeTransport(_dry_run_routes(vp, probe=probe))
    argv = _dry_run_argv(*extra, url=url or "https://bn.example:5052")
    code = vp.main(argv, transport=transport)
    return code, transport


def test_dry_run_prints_window_endpoint_verdict_and_keys(vp, capsys):
    code, transport = _run_dry_run(vp, probe="probe__state_unavailable")
    assert code == 0
    captured = capsys.readouterr()
    out, err = captured.out, captured.err
    # table on stdout; diagnostics stay on stderr (silent at default verbosity)
    assert err == ""
    assert "window: epochs 68–99 (slots 2208, 3232)" in out
    assert "https://bn.example:5052" in out
    assert "state_unavailable" in out
    assert "Lighthouse/v5.3.0-aa11a3b" in out
    expected = (
        (PK1, "1", "active_ongoing", "32000000000"),
        (PK2, "2", "active_exiting", "2048000000000"),
        (PK3, "3", "pending_queued", "32000000000"),
    )
    for pk, index, status, eb in expected:
        matches = [ln for ln in out.splitlines() if pk in ln]
        assert len(matches) == 1, pk
        line = matches[0]
        assert index in line
        assert status in line
        assert eb in line
        assert line not in err
    # architecture §7: probe body is the first rewards_eligible index only
    att_posts = [
        c for c in transport.calls if c[1] == "POST" and "rewards/attestations" in c[2]
    ]
    assert len(att_posts) == 1
    assert json.loads(att_posts[0][3]) == ["1"]


def test_dry_run_exits_0(vp, capsys):
    code, transport = _run_dry_run(vp)
    assert code == vp.EXIT_OK == 0
    assert transport.calls
    capsys.readouterr()


def test_usage_error_exits_2(vp, capsys):
    code = vp.main([])
    assert code == vp.EXIT_USAGE == 2
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    assert "pubkey" in captured.err.lower()


def test_no_beacon_exits_5(vp, capsys):
    transport = FakeTransport(
        {("GET", _VERSION_TEMPLATE): [_raw(vp, 404)]}
    )
    code = vp.main(_dry_run_argv(), transport=transport)
    assert code == vp.EXIT_NO_BEACON == 5
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.out
    assert "https://" not in captured.err
    assert captured.err.strip() != ""


def test_unexpected_exception_exits_1_without_traceback_on_stdout(vp, capsys):
    transport = FakeTransport(
        {("GET", _VERSION_TEMPLATE): [_boom(RuntimeError("boom"))]}
    )
    code = vp.main(_dry_run_argv(), transport=transport)
    assert code == vp.EXIT_ERROR == 1
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    assert "boom" in captured.err


def test_bootstrap_failure_exits_5_not_3(vp, capsys, monkeypatch):
    _no_sleep(monkeypatch, vp)
    routes = _dry_run_routes(vp)
    routes[("GET", _SPEC_TEMPLATE)] = [_raw(vp, 500), _raw(vp, 500)]
    transport = FakeTransport(routes)
    code = vp.main(_dry_run_argv(), transport=transport)
    assert code == vp.EXIT_NO_BEACON == 5
    assert code != vp.EXIT_DEGRADED
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.out
    assert "HTTP 500" in captured.err
    assert _SPEC_TEMPLATE in captured.err
    assert "(500," not in captured.err
    assert "https://" not in captured.err


def test_probe_404_does_not_exit_5(vp, capsys):
    code, _transport = _run_dry_run(vp, probe="probe__route_absent")
    assert code == vp.EXIT_OK == 0
    captured = capsys.readouterr()
    assert "route_absent" in captured.out
    assert "route_absent" not in captured.err


def test_dry_run_leaks_no_secret(vp, capsys):
    code, _transport = _run_dry_run(
        vp, extra=("-v",), url=_SECRET_URL
    )
    assert code == 0
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "secret" not in text
    assert "abc123SECRET" not in text
    assert "https://bn.example:5052" in captured.out
    assert "window:" in captured.out
    assert "via https://bn.example:5052" in captured.err
    assert "GET" not in captured.out


def test_transport_closed_on_every_path(vp, capsys, monkeypatch):
    _no_sleep(monkeypatch, vp)
    success = FakeTransport(_dry_run_routes(vp))
    assert vp.main(_dry_run_argv(), transport=success) == 0
    assert success.closed is True

    boom = FakeTransport(
        {("GET", _VERSION_TEMPLATE): [_boom(RuntimeError("boom"))]}
    )
    assert vp.main(_dry_run_argv(), transport=boom) == vp.EXIT_ERROR
    assert boom.closed is True

    usage = FakeTransport(_dry_run_routes(vp))
    assert vp.main(_dry_run_argv("--to-epoch", "100"), transport=usage) == (
        vp.EXIT_USAGE
    )
    assert usage.closed is True
    capsys.readouterr()


def test_main_body_has_no_metric_logic():
    source = SCRIPT.read_text(encoding="utf-8")
    match = re.search(
        r"# ===== § 16\. main =====(.*)$",
        source,
        re.DOTALL,
    )
    assert match is not None
    body = match.group(1)
    for token in (
        "participation",
        "estimated_apr",
        "flag_actual",
        "flag_ideal",
        "rewards_gwei",
        "inactivity_gwei",
        "consensus_reward",
        "evaluate_epoch",
        "BALANCE_TOLERANCE",
    ):
        assert token not in body
    for name in (
        "build_options",
        "select_endpoint",
        "load_chain_context",
        "resolve_window",
        "resolve_validators",
        "probe_rewards_api",
        "collect_attestations",
        "collect_proposals",
        "collect_balances",
        "collect_sync",
        "build_validator_report",
        "build_aggregate",
        "decide_exit_code",
        "render_json",
        "render_table",
        "render_csv",
        "render_prometheus",
        "_render_dry_run",
        "replace(",
        "ThreadPoolExecutor",
        "RequestBudget",
        "opts.concurrency",
        "shutdown",
    ):
        assert name in body
    order = [
        "select_endpoint",
        "load_chain_context",
        "resolve_window",
        "resolve_validators",
        "probe_rewards_api",
        "collect_attestations",
        "collect_proposals",
        "collect_balances",
        "collect_sync",
        "build_validator_report",
        "build_aggregate",
        "decide_exit_code",
        "render_json",
        "render_table",
        "render_csv",
        "render_prometheus",
    ]
    positions = [body.index(name) for name in order]
    assert positions == sorted(positions)


# ----- VP-2d: §13 balance snapshots (D5, P0-8, A8) -----

_ETH_GWEI = 1_000_000_000
_EB_32 = 32_000_000_000
_EB_2048 = 2_048_000_000_000
_CONSENSUS_REWARD_GWEI = 1_834_000


def _validators_at(slot: int) -> str:
    return f"/eth/v1/beacon/states/{slot}/validators"


def _p08_window(vp, load, **kw):
    ctx = _chain_ctx(
        vp, load, head_epoch=133, finalized_epoch=131, **kw
    )
    return vp.resolve_window(
        _window_opts(vp, from_epoch=100, to_epoch=131), ctx
    )


def _snap_ref(vp, index, pubkey, eb, status="active_ongoing", act=0, ex=None):
    return vp.ValidatorRef(
        pubkey, index, status, eb, act, _FAR_FUTURE_EPOCH if ex is None else ex, False
    )


def _p08_refs(vp):
    return [
        _snap_ref(vp, 1, PK1, _EB_32),
        _snap_ref(vp, 2, PK2, _EB_2048, "active_exiting", 10, 200),
        _snap_ref(vp, 3, PK3, _EB_32, "pending_queued", 500),
    ]


def _collect_snaps(vp, w, refs, routes):
    transport = FakeTransport(routes)
    client, _ = _client(vp, transport)
    snaps, degs = vp.collect_balances(client, w, refs)
    return snaps, degs, transport


def _slot_routes(vp, w, start_name, end_name=None):
    routes = {
        ("POST", _validators_at(w.start_slot)): [
            raw_response(vp, start_name)
        ]
    }
    if end_name is not None:
        routes[("POST", _validators_at(w.end_slot))] = [
            raw_response(vp, end_name)
        ]
    return routes


def test_balance_requests_go_to_snapshot_slots_3232_and_4256(vp, load):
    # VP-1k already owns test_snapshot_slots_are_3232_and_4256 for Window math.
    w = _p08_window(vp, load)
    assert (w.start_slot, w.end_slot) == (3232, 4256)
    unknown = vp.ValidatorRef(PK4, None, "unknown", None, None, None, False)
    refs = _p08_refs(vp) + [unknown]
    snaps, _degs, transport = _collect_snaps(
        vp,
        w,
        refs,
        _slot_routes(
            vp, w, "states_validators__snapshot_start", "states_validators__snapshot_end"
        ),
    )
    paths = [c[2] for c in transport.calls]
    assert _validators_at(3232) in paths
    assert _validators_at(4256) in paths
    for _label, method, path, body in transport.calls:
        assert method == "POST"
        payload = json.loads(body)
        assert payload == {"ids": ["1", "2", "3"]}
        assert PK4 not in payload["ids"]
        assert "None" not in payload["ids"]
    assert 1 in snaps and 2 in snaps and 3 in snaps


def test_snapshots_use_states_validators_not_validator_balances(vp, load):
    # D5: ValidatorBalanceResponse has no effective_balance.
    w = _p08_window(vp, load)
    _snaps, _degs, transport = _collect_snaps(
        vp,
        w,
        _p08_refs(vp),
        _slot_routes(
            vp, w, "states_validators__snapshot_start", "states_validators__snapshot_end"
        ),
    )
    assert transport.calls
    for _label, _method, path, _body in transport.calls:
        assert path.endswith("/validators")
        assert "/validator_balances" not in path
        assert not path.endswith("/validator_balances")


def test_exactly_two_snapshot_requests(vp, load):
    w = _p08_window(vp, load)
    many = [
        _snap_ref(vp, i, f"0x{i:096x}", _EB_32) for i in range(1, 51)
    ]
    _snaps, _degs, transport = _collect_snaps(
        vp,
        w,
        many,
        _slot_routes(
            vp, w, "states_validators__snapshot_start", "states_validators__snapshot_end"
        ),
    )
    assert len(transport.calls) == 2
    assert {c[2] for c in transport.calls} == {
        _validators_at(w.start_slot),
        _validators_at(w.end_slot),
    }


def test_effective_balance_changed_flag(vp):
    ref = _snap_ref(vp, 1, PK1, _EB_32)
    changed_snap = vp.BalanceSnapshot(
        start_gwei=_EB_32,
        end_gwei=31_000_000_000,
        eb_start_gwei=_EB_32,
        eb_end_gwei=31_000_000_000,
    )
    eb, changed = vp.effective_balance_for(changed_snap, ref)
    assert changed is True
    assert eb == 31_000_000_000
    same = vp.BalanceSnapshot(_EB_32, _EB_32 + 1_834_000, _EB_32, _EB_32)
    eb_same, changed_same = vp.effective_balance_for(same, ref)
    assert changed_same is False
    assert eb_same == _EB_32
    missing_start = vp.BalanceSnapshot(None, _EB_32 + 1_834_000, None, _EB_32)
    eb_ms, changed_ms = vp.effective_balance_for(missing_start, ref)
    assert eb_ms == _EB_32
    assert changed_ms is False


def test_diverged_delta_annotates_and_exits_0(vp, load):
    w = _p08_window(vp, load)
    ref = _snap_ref(vp, 1, PK1, _EB_32)
    snaps, degs, _transport = _collect_snaps(
        vp,
        w,
        [ref],
        _slot_routes(
            vp, w, "states_validators__snapshot_start", "balances__diverged"
        ),
    )
    snap = snaps[1]
    consensus_reward = _CONSENSUS_REWARD_GWEI
    original = consensus_reward
    assert snap.delta_gwei == original - _ETH_GWEI
    got = vp.reconcile_balance(snap.delta_gwei, consensus_reward)
    assert got.reconciliation == "diverged"
    assert got.consensus_reward_gwei == original
    assert consensus_reward == original
    assert got.exit_code == vp.EXIT_OK == 0
    assert all(d.reason != "diverged" for d in degs)


def test_within_tolerance_is_consistent(vp, load):
    w = _p08_window(vp, load)
    ref = _snap_ref(vp, 1, PK1, _EB_32)
    snaps, _degs, _transport = _collect_snaps(
        vp,
        w,
        [ref],
        _slot_routes(
            vp, w, "states_validators__snapshot_start", "states_validators__snapshot_end"
        ),
    )
    delta = snaps[1].delta_gwei
    assert delta == 1_834_000
    inside = vp.reconcile_balance(delta, delta + vp.BALANCE_TOLERANCE_GWEI)
    assert inside.reconciliation == "consistent"
    assert vp.BALANCE_TOLERANCE_GWEI == 50_000_000
    exact = vp.reconcile_balance(delta, delta)
    assert exact.reconciliation == "consistent"


def _pruned_slot(vp, slot: int) -> dict:
    path = _validators_at(slot)
    return {
        ("POST", path): [_raw(vp, 404)],
        ("GET", path): [_raw(vp, 404)],
    }


def test_snapshot_failure_falls_back_to_head_eb_with_state_unavailable(vp, load):
    w = _p08_window(vp, load)
    ref = _snap_ref(vp, 2, PK2, _EB_2048, "active_exiting", 10, 200)
    routes = {**_pruned_slot(vp, w.start_slot), **_pruned_slot(vp, w.end_slot)}
    snaps, degs, _transport = _collect_snaps(vp, w, [ref], routes)
    snap = snaps[2]
    assert snap.start_gwei is None
    assert snap.end_gwei is None
    assert snap.eb_start_gwei is None
    assert snap.eb_end_gwei is None
    assert snap.delta_gwei is None
    eb, changed = vp.effective_balance_for(snap, ref)
    assert eb == ref.effective_balance_gwei == _EB_2048
    assert changed is False
    assert any(d.reason == "state_unavailable" for d in degs)
    assert all(d.metric == "balance" for d in degs)


def test_end_slot_unreachable_reports_unavailable_not_a_wrong_slot(vp, load):
    ctx = _chain_ctx(
        vp, load, head_epoch=133, finalized_epoch=131, head_slot=4000
    )
    opts = _window_opts(
        vp, from_epoch=100, to_epoch=131, force_unsafe_window=True
    )
    w = vp.resolve_window(opts, ctx)
    assert w.start_slot == 3232
    assert w.end_slot == 4256
    assert w.end_slot_reachable is False
    ref = _snap_ref(vp, 1, PK1, _EB_32)
    snaps, _degs, transport = _collect_snaps(
        vp,
        w,
        [ref],
        _slot_routes(vp, w, "states_validators__snapshot_start"),
    )
    paths = [c[2] for c in transport.calls]
    assert _validators_at(3232) in paths
    assert _validators_at(4256) not in paths
    assert all("4256" not in p for p in paths)
    assert all("/4000/" not in p for p in paths)
    snap = snaps[1]
    got = vp.reconcile_balance(snap.delta_gwei, _CONSENSUS_REWARD_GWEI)
    assert got.reconciliation == "unavailable"
    assert got.consensus_reward_gwei == _CONSENSUS_REWARD_GWEI


def test_2048_eth_effective_balance_is_carried(vp, load):
    w = _p08_window(vp, load)
    ref = _snap_ref(vp, 2, PK2, _EB_2048, "active_exiting", 10, 200)
    snaps, _degs, _transport = _collect_snaps(
        vp,
        w,
        [ref],
        _slot_routes(
            vp, w, "states_validators__snapshot_start", "states_validators__snapshot_end"
        ),
    )
    snap = snaps[2]
    assert snap.eb_start_gwei == _EB_2048
    assert snap.eb_end_gwei == _EB_2048
    eb, changed = vp.effective_balance_for(snap, ref)
    assert eb == _EB_2048
    assert eb != _EB_32
    assert changed is False
    assert snap.start_gwei == _EB_2048
    assert snap.end_gwei == 2_048_001_834_000


def test_start_slot_pruned_uses_end_eb_without_changed_flag(vp, load):
    w = _p08_window(vp, load)
    ref = _snap_ref(vp, 1, PK1, _EB_32)
    routes = {
        **_pruned_slot(vp, w.start_slot),
        ("POST", _validators_at(w.end_slot)): [
            raw_response(vp, "states_validators__snapshot_end")
        ],
    }
    snaps, degs, transport = _collect_snaps(vp, w, [ref], routes)
    snap = snaps[1]
    assert snap.eb_start_gwei is None
    assert snap.start_gwei is None
    assert snap.eb_end_gwei == _EB_32
    assert snap.end_gwei == 32_001_834_000
    eb, changed = vp.effective_balance_for(snap, ref)
    assert eb == _EB_32
    assert changed is False
    assert any(d.reason == "state_unavailable" for d in degs)
    paths = [c[2] for c in transport.calls]
    assert _validators_at(w.end_slot) in paths
    assert snap.delta_gwei is None


def test_empty_parsed_snapshot_is_state_unavailable(vp, load):
    w = _p08_window(vp, load)
    ref = _snap_ref(vp, 1, PK1, _EB_32)
    empty = _raw(vp, 200, b'{"data": []}')
    routes = {
        ("POST", _validators_at(w.start_slot)): [empty],
        ("POST", _validators_at(w.end_slot)): [
            _raw(vp, 200, b'{"data": []}')
        ],
    }
    snaps, degs, _transport = _collect_snaps(vp, w, [ref], routes)
    snap = snaps[1]
    assert snap.start_gwei is None
    assert snap.end_gwei is None
    assert snap.eb_start_gwei is None
    assert snap.eb_end_gwei is None
    assert any(d.reason == "state_unavailable" for d in degs)
    eb, changed = vp.effective_balance_for(snap, ref)
    assert eb == ref.effective_balance_gwei == _EB_32
    assert changed is False


# ----- VP-2e: §14 ValidatorReport + M6 + M9 + per-validator APR -----


def _snap(vp, eb=_EB_32):
    return vp.BalanceSnapshot(eb, eb, eb, eb)


def _report_window(vp, from_epoch=100, to_epoch=103):
    return _att_window(vp, from_epoch, to_epoch)


def _eval_outcomes(vp, envelopes, ref, eb, start_epoch=100):
    out = []
    for i, env in enumerate(envelopes):
        got = _eval_epoch(vp, start_epoch + i, env, [ref], {ref.index: eb})
        if ref.index in got:
            out.append(got[ref.index])
    return out


def _hand_m6(envelopes, eb):
    actual = 0
    ideal = 0
    for env in envelopes:
        body = _rewards_body(env)
        rows = body["ideal_rewards"]
        largest = max(rows, key=lambda r: int(r["effective_balance"]))
        if _flag_tuple(largest) == (0, 0, 0):
            continue
        ideal_row = next(
            (r for r in rows if int(r["effective_balance"]) == eb), None
        )
        if ideal_row is None:
            continue
        tr = body["total_rewards"][0]
        actual += int(tr["source"]) + int(tr["target"]) + int(tr["head"])
        ideal += (
            int(ideal_row["source"])
            + int(ideal_row["target"])
            + int(ideal_row["head"])
        )
    if ideal == 0:
        return None
    return max(0.0, min(1.0, actual / ideal))


def _mk_outcome(vp, **kw):
    fields = dict(
        epoch=100,
        source_credited=True,
        target_credited=True,
        head_credited=True,
        missed=False,
        flag_actual_gwei=0,
        flag_ideal_gwei=1,
        inactivity_gwei=0,
        leak=False,
    )
    fields.update(kw)
    return vp.EpochOutcome(**fields)


def _build_report(
    vp,
    load,
    ref,
    outcomes,
    *,
    spec="spec__mainnet",
    snap=None,
    window=None,
    degradations=None,
    **kwargs,
):
    if snap is None:
        snap = _snap(vp, ref.effective_balance_gwei or _EB_32)
    if window is None:
        window = _report_window(vp)
    return vp.build_validator_report(
        ref,
        outcomes,
        snap,
        _spec_from_fixture(vp, load, spec),
        window,
        degradations,
        **kwargs,
    )


def test_effectiveness_matches_a_hand_computed_ratio(vp, load):
    envelopes = load("rewards_attestations__basic")
    assert isinstance(envelopes, list) and len(envelopes) == 4
    ref = _active_ref(vp)
    outcomes = _eval_outcomes(vp, envelopes, ref, _EB_32)
    assert len(outcomes) == 4
    expected = _hand_m6(envelopes, _EB_32)
    assert expected is not None
    report = _build_report(vp, load, ref, outcomes)
    assert report.attester_effectiveness == expected
    # Fixture-side actuals, not EpochOutcome.flag_ideal_gwei (would tautologize).
    actuals = [
        int(row["source"]) + int(row["target"]) + int(row["head"])
        for env in envelopes
        for row in [_rewards_body(env)["total_rewards"][0]]
    ]
    ideals = []
    for env in envelopes:
        row = next(
            r
            for r in _rewards_body(env)["ideal_rewards"]
            if int(r["effective_balance"]) == _EB_32
        )
        ideals.append(int(row["source"]) + int(row["target"]) + int(row["head"]))
    assert actuals == [o.flag_actual_gwei for o in outcomes]
    assert sum(ideals) != 0
    assert expected == max(0.0, min(1.0, sum(actuals) / sum(ideals)))


def test_leak_epochs_excluded_from_effectiveness(vp, load):
    leak_env = load("rewards_attestations__leak")
    basic = load("rewards_attestations__basic")
    ref = _active_ref(vp)
    leak_o = _eval_outcomes(vp, [leak_env], ref, _EB_32, start_epoch=99)
    basic_o = _eval_outcomes(vp, basic, ref, _EB_32, start_epoch=100)
    assert leak_o and leak_o[0].leak is True
    assert leak_o[0].flag_ideal_gwei is None
    leak_only = _build_report(vp, load, ref, leak_o)
    assert leak_only.leak_epochs_excluded == 1
    assert leak_only.attester_effectiveness is None
    assert leak_only.attester_effectiveness != 0.0
    assert leak_only.head_rate is None
    assert leak_only.head_rate != 0.0
    mixed = _build_report(vp, load, ref, leak_o + basic_o)
    basic_only = _build_report(vp, load, ref, basic_o)
    assert mixed.leak_epochs_excluded == 1
    assert mixed.attester_effectiveness == basic_only.attester_effectiveness
    assert mixed.attester_effectiveness == _hand_m6(basic, _EB_32)
    assert mixed.head_rate == basic_only.head_rate == 0.5


def test_missing_ideal_row_nulls_effectiveness_for_that_epoch_not_zero(vp, load):
    missing_env = load("rewards_attestations__ideal_filtered")
    rows = _ideal_rows(missing_env)
    assert all(int(r["effective_balance"]) != _EB_32 for r in rows)
    ref = _active_ref(vp, eb=_EB_32)
    missing_o = _eval_outcomes(vp, [missing_env], ref, _EB_32)
    assert missing_o and missing_o[0].flag_ideal_gwei is None
    assert missing_o[0].leak is False
    assert missing_o[0].flag_actual_gwei != 0
    only = _build_report(vp, load, ref, missing_o)
    assert only.attester_effectiveness is None
    assert only.attester_effectiveness != 0.0
    assert any(
        d.reason == "ideal_row_missing" and d.scope == f"epoch:{missing_o[0].epoch}"
        for d in only.degradations
    )
    basic = load("rewards_attestations__basic")
    basic_o = _eval_outcomes(vp, basic, ref, _EB_32, start_epoch=101)
    mixed = _build_report(vp, load, ref, missing_o + basic_o)
    basic_only = _build_report(vp, load, ref, basic_o)
    assert mixed.attester_effectiveness == basic_only.attester_effectiveness
    assert mixed.attester_effectiveness == _hand_m6(basic, _EB_32)
    polluted = (
        missing_o[0].flag_actual_gwei + sum(o.flag_actual_gwei for o in basic_o)
    ) / sum(o.flag_ideal_gwei for o in basic_o if o.flag_ideal_gwei)
    assert mixed.attester_effectiveness != polluted
    assert any(
        d.reason == "ideal_row_missing" and d.scope == f"epoch:{missing_o[0].epoch}"
        for d in mixed.degradations
    )
    assert not any(d.reason == "ideal_row_missing" for d in basic_only.degradations)


def test_effectiveness_clamped_to_zero_one(vp, load):
    ref = _active_ref(vp)
    over = _build_report(
        vp,
        load,
        ref,
        [_mk_outcome(vp, flag_actual_gwei=200, flag_ideal_gwei=100)],
    )
    under = _build_report(
        vp,
        load,
        ref,
        [_mk_outcome(vp, flag_actual_gwei=-50, flag_ideal_gwei=100)],
    )
    assert over.attester_effectiveness == 1.0
    assert under.attester_effectiveness == 0.0
    zero_den = _build_report(
        vp,
        load,
        ref,
        [_mk_outcome(vp, flag_actual_gwei=10, flag_ideal_gwei=0)],
    )
    assert zero_den.attester_effectiveness is None


def test_effectiveness_method_label_is_reward_ratio(vp, load):
    envelopes = load("rewards_attestations__basic")
    ref = _active_ref(vp)
    report = _build_report(
        vp, load, ref, _eval_outcomes(vp, envelopes, ref, _EB_32)
    )
    assert report.effectiveness_method == "reward_ratio"
    empty = _build_report(vp, load, ref, [])
    assert empty.effectiveness_method == "reward_ratio"
    assert empty.attester_effectiveness is None


def test_estimated_apr_matches_to_four_decimal_places(vp, load):
    envelopes = load("rewards_attestations__basic")
    ref = _active_ref(vp)
    outcomes = _eval_outcomes(vp, envelopes, ref, _EB_32)
    window = _att_window(vp, 100, 131)
    assert window.epochs == 32
    spec = _spec_from_fixture(vp, load, "spec__mainnet")
    snap = _snap(vp, _EB_32)
    report = vp.build_validator_report(ref, outcomes, snap, spec, window)
    eb, _changed = vp.effective_balance_for(snap, ref)
    total = report.rewards_gwei["total"]
    expected = total / eb * spec.epochs_per_year / window.epochs
    assert spec.epochs_per_year == 82181.25
    assert report.window_epochs == window.epochs
    assert report.window_epochs != report.active_epochs
    assert round(report.estimated_apr, 4) == round(expected, 4)


def test_apr_halves_on_six_second_slots(vp, load):
    envelopes = load("rewards_attestations__basic")
    ref = _active_ref(vp)
    outcomes = _eval_outcomes(vp, envelopes, ref, _EB_32)
    window = _att_window(vp, 100, 131)
    snap = _snap(vp, _EB_32)
    mainnet = _spec_from_fixture(vp, load, "spec__mainnet")
    spe8 = _spec_from_fixture(vp, load, "spec__spe8")
    r_main = vp.build_validator_report(ref, outcomes, snap, mainnet, window)
    r_spe8 = vp.build_validator_report(ref, outcomes, snap, spe8, window)
    total = r_main.rewards_gwei["total"]
    eb, _ = vp.effective_balance_for(snap, ref)
    hardcoded = total / eb * 82181.25 / window.epochs
    expected_spe8 = total / eb * spe8.epochs_per_year / window.epochs
    assert spe8.seconds_per_slot == 6
    assert spe8.epochs_per_year != 82181.25
    assert round(r_spe8.estimated_apr, 12) == round(expected_spe8, 12)
    assert r_spe8.estimated_apr != pytest.approx(hardcoded)
    assert r_spe8.estimated_apr != pytest.approx(r_main.estimated_apr)
    assert r_spe8.estimated_apr / r_main.estimated_apr == pytest.approx(
        spe8.epochs_per_year / mainnet.epochs_per_year
    )
    src = inspect.getsource(vp.build_validator_report)
    assert "82181" not in src
    assert "EPOCHS_PER_YEAR" not in src
    assert not hasattr(vp, "EPOCHS_PER_YEAR")


def test_apr_denominator_is_the_validators_own_effective_balance(vp, load):
    envelopes = load("rewards_attestations__basic")
    ref = _active_ref(vp, eb=_EB_32)
    outcomes = _eval_outcomes(vp, envelopes, ref, _EB_32)
    window = _att_window(vp, 100, 131)
    snap = _snap(vp, _EB_2048)
    spec = _spec_from_fixture(vp, load)
    report = vp.build_validator_report(ref, outcomes, snap, spec, window)
    eb, _ = vp.effective_balance_for(snap, ref)
    assert eb == _EB_2048
    assert eb != _EB_32
    total = report.rewards_gwei["total"]
    own = total / _EB_2048 * spec.epochs_per_year / window.epochs
    thirty_two = total / _EB_32 * spec.epochs_per_year / window.epochs
    assert round(report.estimated_apr, 12) == round(own, 12)
    assert report.estimated_apr != pytest.approx(thirty_two)


def test_zero_active_epochs_gives_null_rates_not_zero(vp, load):
    ref = _active_ref(vp)
    existing = [
        vp.Degradation("balance", "run", "state_unavailable", "slot 0")
    ]
    report = _build_report(vp, load, ref, [], degradations=list(existing))
    for name in (
        "participation_rate",
        "source_rate",
        "target_rate",
        "head_rate",
        "attester_effectiveness",
        "estimated_apr",
    ):
        val = getattr(report, name)
        assert val is None, name
        assert val != 0.0, name
    assert report.missed_attestations is None
    assert report.missed_attestations != 0
    assert report.active_epochs == 0
    assert report.degradations == existing
    assert report.reward_source == "rewards_api"
    empty = _build_report(vp, load, ref, [])
    assert empty.degradations == []


def test_inactivity_summed_with_its_negative_sign(vp, load):
    ref = _active_ref(vp)
    o = _mk_outcome(
        vp,
        flag_actual_gwei=1000,
        source_gwei=400,
        target_gwei=500,
        head_gwei=100,
        inactivity_gwei=-300,
        flag_ideal_gwei=1000,
    )
    assert o.inactivity_gwei < 0
    report = _build_report(vp, load, ref, [o])
    total = report.rewards_gwei["total"]
    assert report.rewards_gwei["inactivity"] == -300
    assert total == 1000 + (-300)
    assert total != 1000
    assert total != 1000 + 300
    assert total != abs(-300) + 1000


def test_slashed_validator_is_reported_with_its_status(vp, load):
    ref = _active_ref(vp, status="active_slashed", slashed=True)
    envelopes = load("rewards_attestations__basic")
    outcomes = _eval_outcomes(vp, envelopes, ref, _EB_32)
    report = _build_report(vp, load, ref, outcomes)
    assert report.ref.status == "active_slashed"
    assert report.ref.slashed is True
    assert report.ref is ref


# ----- VP-2f: §14 build_aggregate — EB-weighted APR, R9, slashed (RD-5) -----

_RATE_FIELDS = (
    "participation_rate",
    "source_rate",
    "target_rate",
    "head_rate",
    "attester_effectiveness",
)


def _n_outcomes(vp, n, **kw):
    return [_mk_outcome(vp, epoch=100 + i, **kw) for i in range(n)]


def _agg_window(vp, from_epoch=100, to_epoch=131):
    return _att_window(vp, from_epoch, to_epoch)


def _force_rates(report, rate, **extra):
    fields = {name: rate for name in _RATE_FIELDS}
    fields.update(extra)
    return replace(report, **fields)


def test_aggregate_apr_is_effective_balance_weighted(vp, load):
    refs, _, _ = _resolve(vp, [PK1, PK2], name="states_validators__basic")
    by_pk = {r.pubkey: r for r in refs}
    ref32, ref2048 = by_pk[PK1], by_pk[PK2]
    assert ref32.effective_balance_gwei == _EB_32
    assert ref2048.effective_balance_gwei == _EB_2048
    spec = _spec_from_fixture(vp, load)
    window = _agg_window(vp)
    assert window.epochs == 32
    reward_32 = 1_000_000
    reward_2048 = 1_000_000
    r32 = vp.build_validator_report(
        ref32,
        _n_outcomes(vp, 1, flag_actual_gwei=reward_32, flag_ideal_gwei=reward_32),
        _snap(vp, _EB_32),
        spec,
        window,
    )
    r2048 = vp.build_validator_report(
        ref2048,
        _n_outcomes(
            vp, 1, flag_actual_gwei=reward_2048, flag_ideal_gwei=reward_2048
        ),
        _snap(vp, _EB_2048),
        spec,
        window,
    )
    eb32, _ = vp.effective_balance_for(r32.balance, r32.ref)
    eb2048, _ = vp.effective_balance_for(r2048.balance, r2048.ref)
    assert eb32 == _EB_32 and eb2048 == _EB_2048
    sum_reward = r32.rewards_gwei["total"] + r2048.rewards_gwei["total"]
    sum_eb = eb32 + eb2048
    expected = sum_reward / sum_eb * spec.epochs_per_year / window.epochs
    count_weighted = (r32.estimated_apr + r2048.estimated_apr) / 2
    assert expected != pytest.approx(count_weighted)
    agg = vp.build_aggregate([r32, r2048], spec)
    assert round(agg["estimated_apr"], 12) == round(expected, 12)
    assert agg["estimated_apr"] != pytest.approx(count_weighted)
    assert agg["consensus_reward_gwei"] == sum_reward


def test_rate_means_weighted_by_active_epochs(vp, load):
    spec = _spec_from_fixture(vp, load)
    window = _agg_window(vp)
    short = _force_rates(
        _build_report(
            vp,
            load,
            _active_ref(vp, index=1, pubkey=PK1),
            _n_outcomes(vp, 4),
            window=window,
        ),
        1.0,
        active_epochs=4,
    )
    long = _force_rates(
        _build_report(
            vp,
            load,
            _active_ref(vp, index=2, pubkey=PK2),
            _n_outcomes(vp, 32),
            window=window,
        ),
        0.0,
        active_epochs=32,
    )
    assert short.active_epochs / long.active_epochs == 1 / 8
    expected = (4 * 1.0 + 32 * 0.0) / (4 + 32)
    count_weighted = (1.0 + 0.0) / 2
    assert expected != pytest.approx(count_weighted)
    agg = vp.build_aggregate([short, long], spec)
    for name in _RATE_FIELDS:
        assert agg[name] == pytest.approx(expected), name
        assert agg[name] != pytest.approx(count_weighted), name


def test_mid_window_activation_does_not_dilute_the_aggregate(vp, load):
    refs, _, _ = _resolve(
        vp, [PK1], name="states_validators__mid_window_activation"
    )
    mid_ref = refs[0]
    assert mid_ref.activation_epoch == 116
    assert mid_ref.status == "pending_queued"
    spec = _spec_from_fixture(vp, load)
    window = _agg_window(vp)
    n_mid = mid_ref.active_epochs_in(window)
    assert n_mid == 16
    assert n_mid != window.epochs
    mid = vp.build_validator_report(
        mid_ref,
        [
            _mk_outcome(
                vp, epoch=116 + i, flag_actual_gwei=1000, flag_ideal_gwei=1000
            )
            for i in range(n_mid)
        ],
        _snap(vp, _EB_32),
        spec,
        window,
    )
    peer = vp.build_validator_report(
        _active_ref(vp, index=2, pubkey=PK2),
        _n_outcomes(
            vp,
            window.epochs,
            source_credited=False,
            target_credited=False,
            head_credited=False,
            missed=True,
            flag_actual_gwei=0,
            flag_ideal_gwei=1,
        ),
        _snap(vp, _EB_32),
        spec,
        window,
        proposer_gwei=1_000_000,
    )
    assert mid.active_epochs == 16
    assert peer.active_epochs == 32
    assert mid.participation_rate == 1.0
    assert peer.participation_rate == 0.0
    expected = (16 * 1.0 + 32 * 0.0) / (16 + 32)
    count_weighted = (1.0 + 0.0) / 2
    assert expected != pytest.approx(count_weighted)
    agg = vp.build_aggregate([mid, peer], spec)
    for name in _RATE_FIELDS:
        assert agg[name] == pytest.approx(expected), name
        assert agg[name] != pytest.approx(count_weighted), name
        assert agg[name] != pytest.approx(0.0), name
        assert agg[name] != pytest.approx(1.0), name
    inactive = vp.build_validator_report(
        mid_ref, [], _snap(vp, _EB_32), spec, window
    )
    assert inactive.participation_rate is None
    assert inactive.active_epochs == 0
    inactive = replace(inactive, window_epochs=1)
    zero = vp.build_aggregate([inactive, peer], spec)
    assert zero["estimated_apr"] == pytest.approx(peer.estimated_apr)
    inactive_eb, _ = vp.effective_balance_for(inactive.balance, inactive.ref)
    peer_eb, _ = vp.effective_balance_for(peer.balance, peer.ref)
    diluted = (
        (inactive.rewards_gwei["total"] + peer.rewards_gwei["total"])
        / (inactive_eb + peer_eb)
        * spec.epochs_per_year
        / peer.window_epochs
    )
    wrong_window = (
        peer.rewards_gwei["total"]
        / peer_eb
        * spec.epochs_per_year
        / inactive.window_epochs
    )
    assert zero["estimated_apr"] != pytest.approx(diluted)
    assert zero["estimated_apr"] != pytest.approx(wrong_window)


def test_slashed_excluded_from_weighted_means_but_counted_in_by_status(vp, load):
    spec = _spec_from_fixture(vp, load)
    window = _agg_window(vp)
    healthy = vp.build_validator_report(
        _active_ref(vp, index=1, pubkey=PK1),
        _n_outcomes(vp, 32, flag_actual_gwei=1_000_000, flag_ideal_gwei=1_000_000),
        _snap(vp, _EB_32),
        spec,
        window,
    )
    slashed = vp.build_validator_report(
        _active_ref(
            vp, index=2, pubkey=PK2, status="active_slashed", slashed=True
        ),
        _n_outcomes(
            vp,
            32,
            source_credited=False,
            target_credited=False,
            head_credited=False,
            missed=True,
            flag_actual_gwei=0,
            flag_ideal_gwei=1,
        ),
        _snap(vp, _EB_2048),
        spec,
        window,
    )
    assert slashed.participation_rate == 0.0
    assert slashed.ref.status.startswith("active_slashed")
    assert slashed.missed_attestations == 32
    poison = 99_000_000
    slashed = replace(
        slashed,
        rewards_gwei={**slashed.rewards_gwei, "total": poison},
    )
    assert slashed.rewards_gwei["total"] != 0
    agg = vp.build_aggregate([healthy, slashed], spec)
    assert agg["validators"] == 2
    assert agg["by_status"]["active_slashed"] == 1
    assert agg["by_status"]["active_ongoing"] == 1
    for name in _RATE_FIELDS:
        assert agg[name] == pytest.approx(getattr(healthy, name)), name
        assert agg[name] != pytest.approx(0.5), name
    assert agg["missed_attestations"] == healthy.missed_attestations
    assert agg["missed_attestations"] != slashed.missed_attestations
    assert agg["consensus_reward_gwei"] == healthy.rewards_gwei["total"]
    assert agg["consensus_reward_gwei"] != healthy.rewards_gwei["total"] + poison
    eb, _ = vp.effective_balance_for(healthy.balance, healthy.ref)
    expected_apr = (
        healthy.rewards_gwei["total"]
        / eb
        * spec.epochs_per_year
        / window.epochs
    )
    poisoned = (
        (healthy.rewards_gwei["total"] + slashed.rewards_gwei["total"])
        / (eb + _EB_2048)
        * spec.epochs_per_year
        / window.epochs
    )
    assert agg["estimated_apr"] == pytest.approx(expected_apr)
    assert agg["estimated_apr"] != pytest.approx(poisoned)


def test_unknown_pubkey_excluded_from_aggregates(vp, load):
    refs, _, _ = _resolve(
        vp, [PK1, PK4, PK2], name="states_validators__unknown_pubkey"
    )
    unknown_ref = next(r for r in refs if r.index is None)
    assert unknown_ref.status == "unknown"
    stub = vp._unknown_ref(PK4)
    assert stub.index is None and stub.status == "unknown"
    spec = _spec_from_fixture(vp, load)
    window = _agg_window(vp)
    known = vp.build_validator_report(
        next(r for r in refs if r.pubkey == PK1),
        _n_outcomes(vp, 32, flag_actual_gwei=500_000, flag_ideal_gwei=500_000),
        _snap(vp, _EB_32),
        spec,
        window,
    )
    unknown_empty = vp.build_validator_report(
        unknown_ref, [], _snap(vp, 0), spec, window
    )
    # Forced zeros / poison total would drag means and the sum if included (P0-4).
    poison = 77_000_000
    unknown = _force_rates(
        unknown_empty,
        0.0,
        active_epochs=32,
        missed_attestations=99,
        estimated_apr=0.0,
        rewards_gwei={**unknown_empty.rewards_gwei, "total": poison},
    )
    assert unknown.rewards_gwei["total"] != 0
    agg = vp.build_aggregate([known, unknown], spec)
    assert agg["validators"] == 2
    assert agg["by_status"]["unknown"] == 1
    for name in _RATE_FIELDS:
        assert agg[name] == pytest.approx(getattr(known, name)), name
        assert agg[name] != pytest.approx(0.5), name
    assert agg["missed_attestations"] == known.missed_attestations
    assert agg["missed_attestations"] != 99
    eb, _ = vp.effective_balance_for(known.balance, known.ref)
    expected_apr = (
        known.rewards_gwei["total"] / eb * spec.epochs_per_year / window.epochs
    )
    assert agg["estimated_apr"] == pytest.approx(expected_apr)
    assert agg["consensus_reward_gwei"] == known.rewards_gwei["total"]
    assert agg["consensus_reward_gwei"] != known.rewards_gwei["total"] + poison


def test_all_null_metric_aggregates_to_null_not_zero(vp, load):
    spec = _spec_from_fixture(vp, load)
    empty_a = _build_report(
        vp, load, _active_ref(vp, index=1, pubkey=PK1), []
    )
    empty_b = _build_report(
        vp, load, _active_ref(vp, index=2, pubkey=PK2), []
    )
    agg = vp.build_aggregate([empty_a, empty_b], spec)
    for name in (*_RATE_FIELDS, "estimated_apr", "missed_attestations"):
        assert agg[name] is None, name
        assert agg[name] != 0.0, name
    leak = _mk_outcome(
        vp,
        leak=True,
        head_credited=None,
        flag_ideal_gwei=None,
        source_credited=True,
        target_credited=True,
        missed=False,
    )
    leak_a = _build_report(
        vp, load, _active_ref(vp, index=1, pubkey=PK1), [leak]
    )
    leak_b = _build_report(
        vp, load, _active_ref(vp, index=2, pubkey=PK2), [leak]
    )
    assert leak_a.head_rate is None
    assert leak_a.source_rate == 1.0
    leak_agg = vp.build_aggregate([leak_a, leak_b], spec)
    assert leak_agg["head_rate"] is None
    assert leak_agg["head_rate"] != 0.0
    assert leak_agg["source_rate"] == pytest.approx(1.0)
    assert leak_agg["attester_effectiveness"] is None
    assert leak_agg["attester_effectiveness"] != 0.0


def test_by_status_counts_every_input_validator(vp, load):
    spec = _spec_from_fixture(vp, load)
    reports = [
        _build_report(
            vp, load, _active_ref(vp, index=1, pubkey=PK1), []
        ),
        _build_report(
            vp,
            load,
            _active_ref(vp, index=2, pubkey=PK2, status="active_ongoing"),
            [],
        ),
        _build_report(
            vp,
            load,
            _active_ref(
                vp, index=3, pubkey=PK3, status="active_slashed", slashed=True
            ),
            [],
        ),
        _build_report(vp, load, vp._unknown_ref(PK4), []),
        _build_report(
            vp,
            load,
            _active_ref(
                vp,
                index=5,
                pubkey="0x" + "55" * 48,
                status="pending_queued",
            ),
            [],
        ),
        _build_report(
            vp,
            load,
            _active_ref(
                vp,
                index=6,
                pubkey="0x" + "66" * 48,
                status="exited_unslashed",
            ),
            [],
        ),
    ]
    agg = vp.build_aggregate(reports, spec)
    assert agg["validators"] == len(reports)
    assert sum(agg["by_status"].values()) == len(reports)
    assert agg["by_status"] == {
        "active_ongoing": 2,
        "active_slashed": 1,
        "unknown": 1,
        "pending_queued": 1,
        "exited_unslashed": 1,
    }
    assert agg["proposals"] == {"scheduled": 0, "included": 0, "missed": 0}


# ----- VP-2g: §15 render_table + golden files (P0-9) -----

_PK_DOC = "0x9324" + "ab" * 44 + "a6d3"
_BOX_DRAWING = "─━│┃┌┐└┘├┤┬┴┼╔╗╚╝╠╣╦╩╬═║╭╮╯╰"
_TABLE_COL_COUNT = 14


def _rewards_gwei(total=0):
    return {
        "source": 0,
        "target": 0,
        "head": 0,
        "inactivity": 0,
        "proposer": 0,
        "sync": 0,
        "total": total,
    }


def _table_report(vp, ref=None, **kw):
    if ref is None:
        ref = _active_ref(vp)
    fields = dict(
        ref=ref,
        active_epochs=32,
        participation_rate=1.0,
        source_rate=1.0,
        target_rate=1.0,
        head_rate=1.0,
        missed_attestations=0,
        attester_effectiveness=1.0,
        effectiveness_method="reward_ratio",
        leak_epochs_excluded=0,
        proposals={"scheduled": 0, "included": 0, "missed": 0},
        sync=None,
        balance=vp.BalanceSnapshot(_EB_32, _EB_32, _EB_32, _EB_32),
        rewards_gwei=_rewards_gwei(0),
        reward_source="rewards_api",
        estimated_apr=0.05,
        window_epochs=32,
        degradations=[],
    )
    fields.update(kw)
    return vp.ValidatorReport(**fields)


def _table_ctx(vp, load, genesis_time=1606824023):
    spec = _spec_from_fixture(vp, load)
    return vp.ChainContext(
        spec=spec,
        genesis_time=genesis_time,
        network_name="mainnet",
        head_slot=4256,
        head_epoch=133,
        finalized_epoch=131,
        node_version="Lighthouse/v8.2.2",
        rewards_api="available",
        genesis_validators_root="",
    )


def _table_window(vp):
    return _att_window(vp, 100, 131)


def _table_run(vp, load, reports, *, ctx=None, window=None):
    if ctx is None:
        ctx = _table_ctx(vp, load)
    if window is None:
        window = _table_window(vp)
    return vp.RunReport(
        ctx,
        window,
        reports,
        vp.build_aggregate(reports, ctx.spec),
        [],
        ["http://bn0:5052"],
        0,
    )


def _render_table(vp, run):
    buf = io.StringIO()
    vp.render_table(run, buf)
    return buf.getvalue()


def _cut_cols(line: str) -> list[str]:
    return [part.strip() for part in line.split("  ") if part.strip()]


def _table_header_and_rows(text: str) -> tuple[list[str], list[list[str]]]:
    header = None
    rows = []
    for line in text.splitlines():
        cols = _cut_cols(line)
        if not cols:
            continue
        if header is None:
            if cols[0] == "pubkey":
                header = cols
            continue
        if cols[0].startswith("0x"):
            rows.append(cols)
    assert header is not None
    return header, rows


def _golden_reports(vp):
    worst = _table_report(
        vp,
        ref=_active_ref(vp, index=1, pubkey=PK1),
        participation_rate=0.5,
        source_rate=0.5,
        target_rate=0.5,
        head_rate=0.5,
        missed_attestations=16,
        attester_effectiveness=0.5,
        estimated_apr=0.02,
        rewards_gwei=_rewards_gwei(1_000_000),
        proposals={"scheduled": 1, "included": 0, "missed": 1},
        balance=vp.BalanceSnapshot(_EB_32, _EB_32 + 1_834_000, _EB_32, _EB_32),
    )
    best = _table_report(
        vp,
        ref=_active_ref(vp, index=2, pubkey=PK2),
        attester_effectiveness=1.0,
        estimated_apr=0.0471,
        rewards_gwei=_rewards_gwei(2_000_000),
        proposals={"scheduled": 1, "included": 1, "missed": 0},
        sync=vp.SyncOutcome(True, 32, 16, 0),
        balance=vp.BalanceSnapshot(_EB_32, _EB_32 + 2_000_000, _EB_32, _EB_32),
    )
    empty = _table_report(
        vp,
        ref=vp._unknown_ref(_PK_DOC),
        active_epochs=0,
        participation_rate=None,
        source_rate=None,
        target_rate=None,
        head_rate=None,
        missed_attestations=None,
        attester_effectiveness=None,
        estimated_apr=None,
        reward_source=None,
        rewards_gwei=_rewards_gwei(0),
        proposals={"scheduled": 0, "included": 0, "missed": 0},
        balance=vp.BalanceSnapshot(None, None, None, None),
    )
    return [best, empty, worst]


def test_null_renders_em_dash_never_zero(vp, load):
    report = _table_report(
        vp,
        ref=_active_ref(vp, index=7, pubkey=PK1),
        head_rate=None,
        missed_attestations=0,
    )
    text = _render_table(vp, _table_run(vp, load, [report]))
    header, rows = _table_header_and_rows(text)
    cell = rows[0][header.index("head%")]
    assert cell == "—"
    assert "0" not in cell


# table__golden_phase2.txt is superseded (anti-churn b).
# Phase 3 asserts table__golden.txt (real incl/sched and sync%).
def test_golden_table_matches_exactly(vp, load):
    text = _render_table(vp, _table_run(vp, load, _golden_reports(vp)))
    expected = (FIXTURES / "table__golden.txt").read_text(encoding="utf-8")
    assert text == expected


def test_final_golden_table_matches(vp, load):
    text = _render_table(vp, _table_run(vp, load, _golden_reports(vp)))
    expected = (FIXTURES / "table__golden.txt").read_text(encoding="utf-8")
    assert text == expected
    header, rows = _table_header_and_rows(text)
    incl = header.index("incl/sched")
    sync = header.index("sync%")
    assert any("/" in row[incl] and "—" not in row[incl] for row in rows)
    assert any(row[sync] != "—" for row in rows)


def test_phase2_golden_retired_not_silently_failing():
    # table__golden_phase2.txt is superseded; do not assert against it.
    source = Path(__file__).read_text(encoding="utf-8")
    assert "table__golden_phase2.txt" in source
    assert "superseded" in source
    assert (FIXTURES / "table__golden_phase2.txt").is_file()
    asserted = [
        line
        for line in source.splitlines()
        if "table__golden_phase2.txt" in line
        and "read_text" in line
        and not line.lstrip().startswith("#")
    ]
    assert asserted == []


def test_rows_sorted_by_effectiveness_ascending(vp, load):
    best = _table_report(
        vp,
        ref=_active_ref(vp, index=1, pubkey=PK1),
        attester_effectiveness=1.0,
    )
    worst = _table_report(
        vp,
        ref=_active_ref(vp, index=2, pubkey=PK2),
        attester_effectiveness=0.1,
    )
    missing = _table_report(
        vp,
        ref=_active_ref(vp, index=3, pubkey=PK3),
        attester_effectiveness=None,
    )
    text = _render_table(vp, _table_run(vp, load, [best, missing, worst]))
    _, rows = _table_header_and_rows(text)
    assert [row[0] for row in rows] == [
        "0x2222…2222",
        "0x1111…1111",
        "0x3333…3333",
    ]


def test_pubkey_abbreviated_head_and_tail(vp, load):
    assert len(_PK_DOC) == 2 + 96
    report = _table_report(vp, ref=_active_ref(vp, index=1234, pubkey=_PK_DOC))
    text = _render_table(vp, _table_run(vp, load, [report]))
    assert _PK_DOC not in text
    assert "0x9324…a6d3" in text


def test_columns_separated_by_two_spaces_and_cut_friendly(vp, load):
    text = _render_table(vp, _table_run(vp, load, _golden_reports(vp)))
    assert not any(ch in text for ch in _BOX_DRAWING)
    header, rows = _table_header_and_rows(text)
    assert header == [
        "pubkey",
        "index",
        "status",
        "active epochs",
        "part%",
        "src%",
        "tgt%",
        "head%",
        "missed",
        "incl/sched",
        "sync%",
        "Δbal ETH",
        "eff%",
        "APR%",
    ]
    assert len(header) == _TABLE_COL_COUNT
    assert len(rows) == 3
    for row in rows:
        assert len(row) == _TABLE_COL_COUNT
    table_lines = [
        line
        for line in text.splitlines()
        if line.startswith("pubkey") or line.startswith("0x")
    ]
    assert table_lines
    for line in table_lines:
        assert "  " in line


def test_no_ansi_escape_in_output(vp, load):
    text = _render_table(vp, _table_run(vp, load, _golden_reports(vp)))
    assert "\x1b" not in text
    assert "\033" not in text


def test_aggregate_block_reports_window_and_wall_clock_span(vp, load):
    ctx = _table_ctx(vp, load)
    window = _table_window(vp)
    text = _render_table(
        vp, _table_run(vp, load, _golden_reports(vp), ctx=ctx, window=window)
    )
    assert f"epochs {window.from_epoch}–{window.to_epoch}" in text
    start = ctx.genesis_time + window.start_slot * ctx.spec.seconds_per_slot
    end = ctx.genesis_time + window.end_slot * ctx.spec.seconds_per_slot
    assert time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start)) in text
    assert time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end)) in text


def test_footnotes_state_inclusion_distance_and_zero_proposals(vp, load):
    text = _render_table(vp, _table_run(vp, load, _golden_reports(vp)))
    assert "inclusion distance is absent because it requires a full block scan" in text
    assert (
        "0/0 proposals is normal at this key count — 200 keys over 32 epochs "
        "expect ≈0.19 proposals; proposals_expected is not implemented"
    ) in text


def test_degraded_block_header_present_when_empty(vp, load):
    run = _table_run(vp, load, _golden_reports(vp))
    assert run.degradations == []
    text = _render_table(vp, run)
    assert "DEGRADED:" in text
    assert text.split("DEGRADED:", 1)[1].strip() == ""


def test_degraded_block_lists_metric_reason_and_scope(vp, load):
    deg = vp.Degradation("head_rate", "epoch:100", "inactivity_leak", "leak")
    run = replace(_table_run(vp, load, _golden_reports(vp)), degradations=[deg])
    text = _render_table(vp, run)
    body = text.split("DEGRADED:", 1)[1]
    assert "head_rate" in body
    assert "inactivity_leak" in body
    assert "epoch:100" in body
    assert body.strip() != ""


# ----- VP-2h: §15 render_json + perf_schema.json + subset walker (D9) -----

PERF_SCHEMA_PATH = Path(__file__).resolve().parent / "perf_schema.json"
_REASON_ENUM = (
    "rewards_api_unsupported",
    "state_unavailable",
    "inactivity_leak",
    "proposer_duties_unavailable",
    "block_reward_unavailable",
    "ideal_row_missing",
    "effective_balance_zero",
    "sync_committees_unavailable",
    "endpoint_failover",
)


class SchemaMismatch(Exception):
    pass


def _is_json_type(value, name: str) -> bool:
    if name == "null":
        return value is None
    if name == "boolean":
        return isinstance(value, bool)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "string":
        return isinstance(value, str)
    if name == "array":
        return isinstance(value, list)
    if name == "object":
        return isinstance(value, dict)
    return False


def validate_schema(instance, schema, path="$"):
    if not isinstance(schema, dict):
        return
    expected = schema.get("type")
    if expected is not None:
        names = [expected] if isinstance(expected, str) else list(expected)
        if not any(_is_json_type(instance, name) for name in names):
            raise SchemaMismatch(
                f"{path}: expected {'|'.join(names)}, got {type(instance).__name__}"
            )
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaMismatch(f"{path}: {instance!r} not in enum")
    if instance is None:
        # Nullable union already matched; do not apply properties/required/items.
        return
    required = schema.get("required")
    if required:
        if not isinstance(instance, dict):
            raise SchemaMismatch(f"{path}: expected object")
        for key in required:
            if key not in instance:
                raise SchemaMismatch(f"{path}: missing required {key}")
    props = schema.get("properties")
    if props and isinstance(instance, dict):
        for key, sub in props.items():
            if key in instance:
                validate_schema(instance[key], sub, f"{path}.{key}")
    items = schema.get("items")
    if items is not None and isinstance(instance, list):
        for i, item in enumerate(instance):
            validate_schema(item, items, f"{path}[{i}]")


def _load_perf_schema():
    return json.loads(PERF_SCHEMA_PATH.read_text(encoding="utf-8"))


def _allows_null(node) -> bool:
    expected = node.get("type")
    names = [expected] if isinstance(expected, str) else list(expected or [])
    return "null" in names or None in (node.get("enum") or [])


def _json_run(vp, load, *, endpoints_used=None, degradations=None, exit_code=0):
    ctx = replace(
        _chain_ctx(vp, load, head_epoch=133, finalized_epoch=131),
        rewards_api="available",
        node_version="Lighthouse/v8.2.2",
        genesis_time=1606824000,
    )
    window = _att_window(vp, 100, 131)
    report = _build_report(
        vp,
        load,
        _active_ref(vp),
        _n_outcomes(vp, 4, flag_actual_gwei=1_834_000, flag_ideal_gwei=1_834_000),
        window=window,
        snap=vp.BalanceSnapshot(
            _EB_32, _EB_32 + 1_834_000, _EB_32, _EB_32
        ),
    )
    agg = vp.build_aggregate([report], ctx.spec)
    if endpoints_used is None:
        endpoints_used = [_SECRET_URL]
    if degradations is None:
        degradations = [
            vp.Degradation("head_rate", "epoch:100", "inactivity_leak", "leak")
        ]
    return vp.RunReport(
        ctx, window, [report], agg, degradations, endpoints_used, exit_code
    )


def _print_json_with_warning(vp, run) -> None:
    vp.Log(0, sys.stderr).warn("slow bn0")
    print(vp.render_json(run))


def test_json_stdout_is_exactly_one_document(vp, load, capsys):
    _print_json_with_warning(vp, _json_run(vp, load))
    captured = capsys.readouterr()
    json.loads(captured.out)
    _, end = json.JSONDecoder().raw_decode(captured.out.lstrip())
    assert captured.out[end:].strip() == ""
    lines = [ln for ln in captured.out.splitlines() if ln]
    assert len(lines) == 1
    assert "slow bn0" in captured.err
    assert "slow bn0" not in captured.out


def test_json_validates_against_perf_schema(vp, load):
    clock = lambda: datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
    doc = json.loads(vp.render_json(_json_run(vp, load), clock=clock))
    validate_schema(doc, _load_perf_schema())
    assert doc["generated_at"] == "2026-08-30T12:00:00Z"


def test_generated_at_rejects_a_naive_datetime(vp, load):
    with pytest.raises(TypeError, match="timezone-aware"):
        vp.render_json(
            _json_run(vp, load), clock=lambda: datetime(2026, 8, 30, 12, 0)
        )


def test_schema_version_is_1(vp, load):
    assert vp.SCHEMA_VERSION == 1
    schema = _load_perf_schema()
    assert schema["properties"]["schema_version"]["enum"] == [1]
    doc = json.loads(vp.render_json(_json_run(vp, load)))
    assert doc["schema_version"] == 1


def test_schema_covers_proposals_sync_and_reward_source_as_nullable():
    schema = _load_perf_schema()
    validator = schema["properties"]["validators"]["items"]["properties"]
    for name in ("proposals", "sync", "reward_source"):
        assert _allows_null(validator[name]), name
    assert _allows_null(
        schema["properties"]["aggregate"]["properties"]["reward_source"]
    )


def test_schema_reason_enum_is_closed_and_has_nine_values():
    schema = _load_perf_schema()
    run_enum = schema["properties"]["degradations"]["items"]["properties"][
        "reason"
    ]["enum"]
    val_enum = schema["properties"]["validators"]["items"]["properties"][
        "degradations"
    ]["items"]["properties"]["reason"]["enum"]
    assert list(run_enum) == list(_REASON_ENUM)
    assert list(val_enum) == list(_REASON_ENUM)
    assert len(run_enum) == 9
    assert len(set(run_enum)) == 9


def test_walker_rejects_a_wrong_type(vp, load):
    doc = json.loads(vp.render_json(_json_run(vp, load)))
    doc["schema_version"] = "1"
    with pytest.raises(SchemaMismatch, match="schema_version"):
        validate_schema(doc, _load_perf_schema())


def test_walker_rejects_a_missing_required_field(vp, load):
    doc = json.loads(vp.render_json(_json_run(vp, load)))
    del doc["network"]
    with pytest.raises(SchemaMismatch, match="network"):
        validate_schema(doc, _load_perf_schema())


def test_walker_accepts_an_explicit_null_in_a_nullable_union(vp, load):
    doc = json.loads(vp.render_json(_json_run(vp, load)))
    row = doc["validators"][0]
    row["proposals"] = None
    row["sync"] = None
    row["reward_source"] = None
    doc["aggregate"]["reward_source"] = None
    validate_schema(doc, _load_perf_schema())


def test_walker_rejects_an_unknown_reason_enum(vp, load):
    doc = json.loads(vp.render_json(_json_run(vp, load)))
    doc["degradations"][0]["reason"] = "not_a_reason"
    with pytest.raises(SchemaMismatch, match="reason"):
        validate_schema(doc, _load_perf_schema())


def test_walker_rejects_a_validator_missing_pubkey(vp, load):
    doc = json.loads(vp.render_json(_json_run(vp, load)))
    del doc["validators"][0]["pubkey"]
    with pytest.raises(SchemaMismatch, match="pubkey"):
        validate_schema(doc, _load_perf_schema())


def test_endpoint_stays_a_string_and_endpoints_used_is_an_array(vp, load):
    schema = _load_perf_schema()
    beacon_schema = schema["properties"]["beacon"]["properties"]
    assert beacon_schema["endpoint"]["type"] == "string"
    assert beacon_schema["endpoints_used"]["type"] == "array"
    used = ["http://bn0:5052", "http://bn1:5052"]
    doc = json.loads(vp.render_json(_json_run(vp, load, endpoints_used=used)))
    assert isinstance(doc["beacon"]["endpoint"], str)
    assert isinstance(doc["beacon"]["endpoints_used"], list)
    assert doc["beacon"]["endpoints_used"] == used
    assert doc["beacon"]["endpoint"] == used[-1]


def test_no_beacon_url_or_secret_in_the_json_document(vp, load):
    text = vp.render_json(_json_run(vp, load, endpoints_used=[_SECRET_URL]))
    assert "secret" not in text
    assert "abc123SECRET" not in text
    assert "user:" not in text
    shown = "https://bn.example:5052"
    doc = json.loads(text)
    assert doc["beacon"]["endpoint"] == shown
    assert doc["beacon"]["endpoints_used"] == [shown]


def test_gwei_emitted_as_numbers_not_strings(vp, load):
    text = vp.render_json(_json_run(vp, load))
    assert re.search(r'"start_gwei":\s*\d', text)
    assert not re.search(r'"start_gwei":\s*"', text)
    doc = json.loads(text)
    balance = doc["validators"][0]["balance"]
    for key in (
        "start_gwei",
        "end_gwei",
        "delta_gwei",
        "effective_balance_gwei",
    ):
        assert type(balance[key]) is int
    for value in doc["validators"][0]["rewards_gwei"].values():
        if value is not None:
            assert type(value) is int
    reward = doc["aggregate"]["consensus_reward_gwei"]
    if reward is not None:
        assert type(reward) is int


# ----- VP-2i: §14 decide_exit_code + §16 full-run wiring (P0-11, P0-12) -----

_FULL_FROM = 98
_FULL_TO = 98
_G5_EXCEPTIONS = ("sync.participation_rate",)
_R9_NULL_FIELDS = frozenset(
    {
        "participation_rate",
        "source_rate",
        "target_rate",
        "head_rate",
        "missed_attestations",
        "attester_effectiveness",
        "estimated_apr",
    }
)
_NULL_METRIC_FIELDS = (
    "participation_rate",
    "source_rate",
    "target_rate",
    "head_rate",
    "missed_attestations",
    "attester_effectiveness",
    "estimated_apr",
    "proposals.scheduled",
    "proposals.missed",
    "proposals.included",
    "sync.participation_rate",
    "balance.start_gwei",
    "balance.end_gwei",
    "balance.delta_gwei",
    "rewards_gwei.source",
    "rewards_gwei.target",
    "rewards_gwei.head",
    "rewards_gwei.inactivity",
    "rewards_gwei.proposer",
    "rewards_gwei.sync",
    "rewards_gwei.total",
)
_SCOPE_RE = re.compile(r"^(?:run|validator:(?:unknown|\d+)|epoch:\d+)$")
_M1_M6 = frozenset(
    {
        "participation_rate",
        "source_rate",
        "target_rate",
        "head_rate",
        "missed_attestations",
        "attester_effectiveness",
    }
)
_M9_FIELDS = frozenset(
    {
        "rewards_gwei.source",
        "rewards_gwei.target",
        "rewards_gwei.head",
        "rewards_gwei.inactivity",
        "rewards_gwei.proposer",
        "rewards_gwei.sync",
        "rewards_gwei.total",
        "estimated_apr",
    }
)
# Architecture §5: which null fields each reason may explain.
_REASON_COVERS = {
    "rewards_api_unsupported": _M1_M6 | _M9_FIELDS,
    "state_unavailable": frozenset(_NULL_METRIC_FIELDS),
    "inactivity_leak": frozenset({"head_rate", "attester_effectiveness"}),
    "ideal_row_missing": frozenset({"attester_effectiveness"}),
    "effective_balance_zero": _M1_M6 | frozenset({"estimated_apr"}),
    "proposer_duties_unavailable": frozenset(
        {"proposals.scheduled", "proposals.missed"}
    ),
    "block_reward_unavailable": frozenset({"rewards_gwei.proposer"}),
    "sync_committees_unavailable": frozenset({"sync.participation_rate"}),
    "endpoint_failover": _M1_M6,
}
_REASON_PRODUCERS = {
    "rewards_api_unsupported": ("probe__route_absent",),
    "state_unavailable": (
        "probe__state_unavailable",
        "rewards_attestations__404_all",
    ),
    "inactivity_leak": ("rewards_attestations__leak",),
    "proposer_duties_unavailable": (
        "duties_proposer__404",
        "duties_proposer__teku_503",
        "duties_proposer__nimbus_400",
        "duties_proposer__lodestar_500",
    ),
    "block_reward_unavailable": ("rewards_blocks__404_headers_200",),
    "ideal_row_missing": ("rewards_attestations__ideal_filtered",),
    "effective_balance_zero": ("states_validators__eb_zero",),
    "sync_committees_unavailable": (
        "state_sync_committees__400_outside_period",
    ),
    "endpoint_failover": ("failover__midrun_promotion",),
}
_G5_KIND_PREFIXES = (
    ("failover__", "declared"),
    ("liveness__", "declared"),
    ("thresholds__", "rewards"),
    ("rewards_attestations__", "rewards"),
    ("states_validators__", "validators"),
    ("duties_proposer__", "duties"),
    ("probe__", "probe"),
    ("rewards_blocks__", "blocks"),
    ("state_sync_committees__", "sync_membership"),
    ("sync_committee__", "sync_scan"),
    ("balances__", "balances"),
    ("spec__", "bootstrap"),
    ("genesis__", "bootstrap"),
    ("headers__", "headers"),
    ("node_syncing__", "syncing"),
    ("node_version__", "bootstrap"),
    ("finality_checkpoints__", "bootstrap"),
    ("cache__", "declared"),
    ("run__", "declared"),
)
_G5_SKIP = {
    "failover__midrun_promotion": "scenario descriptor; exercised by VP-4a tests",
    "failover__first_503": "scenario descriptor; exercised by VP-4b tests",
    "liveness__head_window": "scenario descriptor; exercised by VP-4e tests",
    "spec__spe8": "SPE change would miss snapshot routes; not a G5 overlay",
    "node_syncing__is_syncing": "selection abort exit 5; no report",
    "cache__genesis_root_changed": "declared VP-5c; cache file, not a BN overlay",
    "run__fast_n4": "devnet report run.json fixture; not a BN overlay",
    "manifest__multiarch": "devnet preflight docker index fixture; not a BN overlay",
    "manifest__amd64_only": "devnet preflight docker index fixture; not a BN overlay",
    "manifest__single": "devnet preflight docker index fixture; not a BN overlay",
    "manifest__unknown_only": "devnet preflight docker index fixture; not a BN overlay",
}


def _full_argv(*extra, url="https://bn.example:5052", pubkeys=(PK1,)):
    argv: list[str] = []
    for pk in pubkeys:
        argv.extend(["--pubkey", pk])
    argv.extend(
        [
            "--beacon-url",
            url,
            "--from-epoch",
            str(_FULL_FROM),
            "--to-epoch",
            str(_FULL_TO),
            "--concurrency",
            "1",
            *extra,
        ]
    )
    return argv


def _full_run_routes(
    vp,
    *,
    rewards=None,
    validators="states_validators__basic",
    start="states_validators__snapshot_start",
    end="states_validators__snapshot_end",
    fail_collect=False,
):
    routes = _dry_run_routes(vp, probe="probe__state_unavailable")
    pair = json.loads((FIXTURES / "probe__state_unavailable.json").read_text())
    routes[("GET", _BLOCKS_HEAD_PATH)] = [_raw_from_probe_leg(vp, pair["blocks"])]
    routes[("POST", _DRY_RUN_ATT_PATH)] = [_att_ok(vp, indices=(1,))]
    routes[("POST", _VALIDATORS_PATH)] = [raw_response(vp, validators)]
    collect_path = _REWARDS_TEMPLATE.format(epoch=_FULL_FROM)
    if fail_collect:
        routes[("POST", collect_path)] = [_raw(vp, 404)]
    elif rewards is not None:
        routes[("POST", collect_path)] = [raw_response(vp, rewards)]
    else:
        routes[("POST", collect_path)] = [_att_ok(vp, indices=(1,))]
    spe = 32
    routes[("POST", _validators_at((_FULL_FROM + 1) * spe))] = [
        raw_response(vp, start)
    ]
    routes[("POST", _validators_at((_FULL_TO + 2) * spe))] = [
        raw_response(vp, end)
    ]
    routes[("GET", _PROPOSER_TEMPLATE.format(epoch=_FULL_FROM))] = [
        _raw(vp, 200, b'{"data": []}')
    ]
    # A7: empty membership so full-run tests do not pay the SM2 scan.
    sync_state = _FULL_FROM * spe
    routes[
        (
            "GET",
            f"/eth/v1/beacon/states/{sync_state}/sync_committees"
            f"?epoch={_FULL_FROM}",
        )
    ] = [raw_response(vp, "state_sync_committees__empty")]
    return routes


def _run_full(
    vp,
    *extra,
    routes=None,
    url="https://bn.example:5052",
    pubkeys=None,
    transport=None,
    **route_kw,
):
    argv_kw: dict = {"url": url}
    if pubkeys is not None:
        argv_kw["pubkeys"] = pubkeys
    if transport is None:
        transport = FakeTransport(routes or _full_run_routes(vp, **route_kw))
    code = vp.main(_full_argv(*extra, **argv_kw), transport=transport)
    return code, transport


def _stdout_json(capsys):
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    doc = json.loads(captured.out)
    _, end = json.JSONDecoder().raw_decode(captured.out.lstrip())
    assert captured.out[end:].strip() == ""
    return doc, captured


def test_exit_0_on_a_fully_available_run(vp, capsys):
    code, transport = _run_full(vp, "--json")
    assert code == vp.EXIT_OK == 0
    doc, captured = _stdout_json(capsys)
    assert doc["exit_code"] == 0
    assert doc["degradations"] == []
    assert "DEGRADED:" not in captured.out
    att = [
        c
        for c in transport.calls
        if c[1] == "POST" and "rewards/attestations/" in c[2]
    ]
    assert any(
        c[2] == _REWARDS_TEMPLATE.format(epoch=_FULL_FROM) for c in att
    )
    snaps = [
        c
        for c in transport.calls
        if c[1] == "POST" and "/states/" in c[2] and c[2] != _VALIDATORS_PATH
    ]
    assert len(snaps) == 2


def test_exit_2_on_a_usage_error(vp, capsys):
    test_usage_error_exits_2(vp, capsys)


def test_exit_3_on_a_leak_epoch(vp, capsys):
    code, _transport = _run_full(
        vp, "--json", rewards="rewards_attestations__leak"
    )
    assert code == vp.EXIT_DEGRADED == 3
    assert code != vp.EXIT_OK
    doc, _captured = _stdout_json(capsys)
    assert doc["exit_code"] == 3
    assert any(d["reason"] == "inactivity_leak" for d in doc["degradations"])
    row = doc["validators"][0]
    assert row["head_rate"] is None
    assert row["source_rate"] is not None
    assert row["target_rate"] is not None


def test_exit_3_on_a_missing_ideal_row(vp, capsys):
    code, _transport = _run_full(
        vp, "--json", rewards="rewards_attestations__ideal_filtered"
    )
    assert code == vp.EXIT_DEGRADED == 3
    doc, _captured = _stdout_json(capsys)
    assert any(d["reason"] == "ideal_row_missing" for d in doc["degradations"])
    assert doc["validators"][0]["attester_effectiveness"] is None


def test_exit_3_on_an_eb_zero_key(vp, capsys):
    code, _transport = _run_full(
        vp, "--json", validators="states_validators__eb_zero"
    )
    assert code == vp.EXIT_DEGRADED == 3
    doc, _captured = _stdout_json(capsys)
    assert any(
        d["reason"] == "effective_balance_zero" for d in doc["degradations"]
    )
    row = doc["validators"][0]
    assert row["source_rate"] is None
    assert row["target_rate"] is None
    assert row["head_rate"] is None
    assert row["attester_effectiveness"] is None


def test_exit_3_on_an_unknown_pubkey(vp, capsys):
    code, _transport = _run_full(
        vp,
        "--json",
        validators="states_validators__unknown_pubkey",
        pubkeys=(PK4,),
    )
    assert code == vp.EXIT_DEGRADED == 3
    assert code not in (vp.EXIT_ERROR, vp.EXIT_NO_BEACON)
    doc, _captured = _stdout_json(capsys)
    assert len(doc["validators"]) == 1
    row = doc["validators"][0]
    assert row["index"] is None
    assert row["status"] == "unknown"
    assert any(d["reason"] == "state_unavailable" for d in row["degradations"])
    assert any(d["reason"] == "state_unavailable" for d in doc["degradations"])

    code, _transport = _run_full(
        vp,
        "--json",
        validators="states_validators__unknown_pubkey",
        pubkeys=(PK1, PK4),
    )
    assert code == vp.EXIT_DEGRADED == 3
    assert code not in (vp.EXIT_ERROR, vp.EXIT_NO_BEACON)
    doc, _captured = _stdout_json(capsys)
    by_pk = {v["pubkey"]: v for v in doc["validators"]}
    assert set(by_pk) == {PK1, PK4}
    assert by_pk[PK1]["index"] == 1
    assert by_pk[PK1]["source_rate"] is not None
    unknown = by_pk[PK4]
    assert unknown["index"] is None
    assert unknown["status"] == "unknown"
    assert any(
        d["reason"] == "state_unavailable" for d in unknown["degradations"]
    )


def test_exit_5_when_no_beacon_is_reachable(vp, capsys):
    transport = FakeTransport({("GET", _VERSION_TEMPLATE): [_raw(vp, 404)]})
    code = vp.main(_full_argv(), transport=transport)
    assert code == vp.EXIT_NO_BEACON == 5
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.out
    assert captured.err.strip() != ""


def test_exit_1_on_an_unhandled_exception(vp, capsys, monkeypatch):
    source = SCRIPT.read_text(encoding="utf-8")
    assert source.count("except Exception") == 1

    def boom(*_a, **_k):
        raise RuntimeError("metric boom")

    monkeypatch.setattr(vp, "collect_attestations", boom)
    code, _transport = _run_full(vp, "--json")
    assert code == vp.EXIT_ERROR == 1
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out
    out = captured.out.strip()
    if out:
        json.loads(out)
    assert "metric boom" in captured.err


def test_degraded_ok_maps_3_to_0(vp, capsys):
    code, _transport = _run_full(
        vp,
        "--json",
        "--degraded-ok",
        rewards="rewards_attestations__leak",
    )
    assert code == vp.EXIT_OK == 0
    doc, _captured = _stdout_json(capsys)
    assert doc["exit_code"] == 0
    assert any(d["reason"] == "inactivity_leak" for d in doc["degradations"])


def test_diverged_balance_does_not_degrade(vp, capsys):
    code, _transport = _run_full(
        vp, "--json", end="balances__diverged"
    )
    assert code == vp.EXIT_OK == 0
    doc, _captured = _stdout_json(capsys)
    assert doc["exit_code"] == 0
    assert doc["degradations"] == []
    rec = doc["validators"][0]["balance"]["reconciliation"]
    assert rec == "diverged"
    assert not any(d.get("reason") == "diverged" for d in doc["degradations"])


def test_full_run_leaks_no_secret_in_stdout_or_stderr(vp, capsys):
    code, _transport = _run_full(vp, "-v", "--json", url=_SECRET_URL)
    assert code == vp.EXIT_OK == 0
    captured = capsys.readouterr()
    text = captured.out + captured.err
    assert "secret" not in text
    assert "abc123SECRET" not in text
    json.loads(captured.out)
    assert "https://bn.example:5052" in captured.err


def _reasons_for_row(row, run_degs):
    reasons = {d["reason"] for d in row.get("degradations") or []}
    index = row.get("index")
    unknown = index is None or row.get("status") == "unknown"
    for d in run_degs:
        scope = d.get("scope") or ""
        if index is not None and scope == f"validator:{index}":
            reasons.add(d["reason"])
        elif unknown and scope == "validator:unknown":
            if not d.get("detail") or d["detail"] == row.get("pubkey"):
                reasons.add(d["reason"])
        elif not unknown and (
            scope == "run" or scope.startswith("epoch:")
        ):
            reasons.add(d["reason"])
    return reasons


def _json_fixture_stems():
    return tuple(sorted(p.stem for p in FIXTURES.glob("*.json")))


def _g5_kind(stem: str) -> str:
    for prefix, kind in _G5_KIND_PREFIXES:
        if stem.startswith(prefix):
            return kind
    raise AssertionError(f"unclassified fixture {stem}")


def _duty_status(stem: str) -> int:
    if stem.endswith("503"):
        return 503
    if stem.endswith("500"):
        return 500
    if stem.endswith("400"):
        return 400
    if stem.endswith("404"):
        return 404
    return 200


def _queued_raw(vp, stem, status):
    item = raw_response(vp, stem, status=status)
    n = 3 if status == 503 else (2 if status == 500 else 1)
    return [item] * n


def _rewards_collect_raw(vp, stem):
    payload = json.loads((FIXTURES / f"{stem}.json").read_text())
    if stem.endswith("404_all"):
        return raw_response(vp, stem, status=404)
    if isinstance(payload, list):
        payload = payload[0]
    return _raw(vp, 200, json.dumps(payload).encode())


def _schedule_our_proposal(vp, routes, *, blocks=None, headers=None):
    slot = _FULL_FROM * 32
    duties = json.loads((FIXTURES / "duties_proposer__ok.json").read_text())
    duties["data"] = [
        {**row, "slot": str(slot)}
        for row in duties["data"]
        if row["validator_index"] == "1"
    ]
    routes[("GET", _PROPOSER_TEMPLATE.format(epoch=_FULL_FROM))] = [
        _raw(vp, 200, json.dumps(duties).encode())
    ]
    if blocks is not None:
        routes[("GET", _blocks_path(slot))] = list(blocks)
    if headers is not None:
        routes[("GET", _slot_header_path(slot))] = list(headers)
    return routes


def _script_sync_scan(vp, routes, stem, status=200):
    item = raw_response(vp, stem, status=status)
    spe = 32
    for slot in range(_FULL_FROM * spe, (_FULL_TO + 1) * spe):
        path = f"/eth/v1/beacon/rewards/sync_committee/{slot}"
        routes[("POST", path)] = [item]
    return routes


def _enable_sync_membership(vp, routes, stem, status=200):
    spe = 32
    path = (
        f"/eth/v1/beacon/states/{_FULL_FROM * spe}/sync_committees"
        f"?epoch={_FULL_FROM}"
    )
    routes[("GET", path)] = _queued_raw(vp, stem, status)
    return routes


def _g5_routes(vp, stem):
    if stem in _G5_SKIP:
        raise AssertionError(f"{stem} must pytest.skip, not overlay")
    kind = _g5_kind(stem)
    routes = _full_run_routes(vp)
    if kind not in ("sync_membership", "sync_scan"):
        # empty.json includes index 42; G5 must not treat that as membership.
        spe = 32
        path = (
            f"/eth/v1/beacon/states/{_FULL_FROM * spe}/sync_committees"
            f"?epoch={_FULL_FROM}"
        )
        routes[("GET", path)] = [
            _raw(vp, 200, b'{"data": {"validators": []}}')
        ]
    collect = _REWARDS_TEMPLATE.format(epoch=_FULL_FROM)
    overlaid = False
    if kind == "rewards":
        raw = _rewards_collect_raw(vp, stem)
        routes[("POST", collect)] = [raw]
        if stem.endswith("404_all"):
            routes[("POST", _DRY_RUN_ATT_PATH)] = [raw]
        overlaid = True
    elif kind == "validators":
        if stem == "states_validators__snapshot_start":
            routes[("POST", _validators_at((_FULL_FROM + 1) * 32))] = [
                raw_response(vp, stem)
            ]
        elif stem == "states_validators__snapshot_end":
            routes[("POST", _validators_at((_FULL_TO + 2) * 32))] = [
                raw_response(vp, stem)
            ]
        elif stem == "states_validators__post_414":
            routes[("POST", _VALIDATORS_PATH)] = [
                raw_response(vp, stem, status=414)
            ]
            routes[("GET", _VALIDATORS_PATH)] = [
                raw_response(vp, "states_validators__basic")
            ] * 4
        else:
            body = raw_response(vp, stem)
            routes[("POST", _VALIDATORS_PATH)] = [body]
            routes[("POST", _validators_at((_FULL_FROM + 1) * 32))] = [body]
            routes[("POST", _validators_at((_FULL_TO + 2) * 32))] = [body]
        overlaid = True
    elif kind == "duties":
        routes[("GET", _PROPOSER_TEMPLATE.format(epoch=_FULL_FROM))] = (
            _queued_raw(vp, stem, _duty_status(stem))
        )
        overlaid = True
    elif kind == "probe":
        pair = json.loads((FIXTURES / f"{stem}.json").read_text())
        routes[("GET", _BLOCKS_HEAD_PATH)] = [
            _raw_from_probe_leg(vp, pair["blocks"])
        ]
        routes[("POST", _DRY_RUN_ATT_PATH)] = [
            _raw_from_probe_leg(vp, pair["attestations"])
        ]
        if stem.endswith("route_absent"):
            routes.pop(("POST", collect), None)
        else:
            routes[("POST", collect)] = [_raw(vp, 404)]
        overlaid = True
    elif kind == "blocks":
        if stem.endswith("404_headers_200"):
            pair = json.loads((FIXTURES / f"{stem}.json").read_text())
            _schedule_our_proposal(
                vp,
                routes,
                blocks=[_raw_from_probe_leg(vp, pair["blocks"])],
                headers=[_raw_from_probe_leg(vp, pair["headers"])],
            )
        elif stem.endswith("data_null"):
            _schedule_our_proposal(
                vp,
                routes,
                blocks=[raw_response(vp, stem)],
                headers=[raw_response(vp, "headers__slot_present")],
            )
        else:
            _schedule_our_proposal(
                vp, routes, blocks=[raw_response(vp, stem)]
            )
        overlaid = True
    elif kind == "sync_membership":
        status = 400 if "400" in stem else 200
        _enable_sync_membership(vp, routes, stem, status)
        if stem.endswith("intersect"):
            _script_sync_scan(
                vp, routes, "sync_committee__lodestar_negative"
            )
        overlaid = True
    elif kind == "sync_scan":
        _enable_sync_membership(
            vp, routes, "state_sync_committees__intersect"
        )
        status = 404 if "skipped" in stem else 200
        _script_sync_scan(vp, routes, stem, status=status)
        overlaid = True
    elif kind == "balances":
        routes[("POST", _validators_at((_FULL_TO + 2) * 32))] = [
            raw_response(vp, stem)
        ]
        overlaid = True
    elif kind == "headers":
        if stem.endswith("head"):
            routes[("GET", _HEADER_HEAD_PATH)] = [raw_response(vp, stem)]
        elif stem.endswith("slot_present"):
            _schedule_our_proposal(
                vp,
                routes,
                blocks=[_raw(vp, 404)],
                headers=[raw_response(vp, stem)],
            )
        elif stem.endswith("slot_404"):
            _schedule_our_proposal(
                vp,
                routes,
                blocks=[_raw(vp, 404)],
                headers=[raw_response(vp, stem, status=404)],
            )
        else:
            raise AssertionError(f"headers fixture {stem} has no overlay")
        overlaid = True
    elif kind == "syncing":
        routes[("GET", _SYNCING_PATH)] = [raw_response(vp, stem)]
        overlaid = True
    elif kind == "bootstrap":
        mapping = {
            "spec__mainnet": ("GET", _SPEC_TEMPLATE),
            "genesis__mainnet": ("GET", _GENESIS_PATH),
            "node_version__lighthouse": ("GET", _VERSION_TEMPLATE),
            "finality_checkpoints__head": ("GET", _FINALITY_PATH),
        }
        if stem not in mapping:
            raise AssertionError(f"bootstrap fixture {stem} has no overlay")
        routes[mapping[stem]] = [raw_response(vp, stem)]
        overlaid = True
    if not overlaid:
        raise AssertionError(f"{stem} classified {kind} but did not overlay")
    return routes


def _g5_pubkeys(stem):
    if stem == "states_validators__unknown_pubkey":
        return (PK4,)
    return None


def _lenient_full_transport(vp, routes):
    inner = FakeTransport(routes)

    class _Transport:
        def __init__(self):
            self.calls = inner.calls
            self.drops = inner.drops
            self.closed = False
            self.routes = inner.routes

        def __call__(self, ep, method, path, body):
            try:
                return inner(ep, method, path, body)
            except KeyError:
                if method == "GET" and "/eth/v1/beacon/rewards/blocks/" in path:
                    if not path.endswith("/head"):
                        return _raw(vp, 404)
                if method == "GET" and "/eth/v1/beacon/headers/" in path:
                    if not path.endswith("/head"):
                        return _raw(vp, 404)
                if (
                    method == "POST"
                    and "/eth/v1/beacon/rewards/sync_committee/" in path
                ):
                    return _raw(vp, 404)
                raise

        def drop(self, ep):
            inner.drop(ep)

        def close(self):
            inner.close()
            self.closed = inner.closed

    return _Transport()


def _g5_doc(vp, capsys, monkeypatch, stem):
    _no_sleep(monkeypatch, vp)
    routes = _g5_routes(vp, stem)
    transport = _lenient_full_transport(vp, routes)
    pubkeys = _g5_pubkeys(stem)
    extra = {} if pubkeys is None else {"pubkeys": pubkeys}
    _run_full(vp, "--json", "--no-cache", transport=transport, **extra)
    captured = capsys.readouterr()
    out = captured.out.strip()
    assert out, f"{stem} produced no JSON report"
    return json.loads(out)


def _lookup_metric(row, path):
    cur = row
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _not_in_committee(row):
    sync = row.get("sync")
    if not isinstance(sync, dict):
        return True
    return sync.get("in_committee") is not True


def _is_r9_known_zero_active(row):
    unknown = row.get("index") is None or row.get("status") == "unknown"
    if unknown or row.get("active_epochs") != 0:
        return False
    status = row.get("status") or ""
    # EB-0 / rewards-less still report active_* with empty outcomes.
    return not status.startswith("active_")


def _is_all_skipped_sync(row):
    # All-404 scan: in committee, zero eligible slots. Fact, like R9, not A7.
    sync = row.get("sync")
    if not isinstance(sync, dict):
        return False
    return (
        sync.get("in_committee") is True
        and sync.get("participation_rate") is None
        and (sync.get("slots_eligible") or 0) == 0
    )


def _matching_reasons(field, reasons):
    return frozenset(
        r for r in reasons if field in _REASON_COVERS.get(r, ())
    )


def _assert_g5_doc(stem, doc):
    run_degs = list(doc["degradations"])
    for row in doc["validators"]:
        reasons = _reasons_for_row(row, run_degs)
        r9 = _is_r9_known_zero_active(row)
        for field in _NULL_METRIC_FIELDS:
            value = _lookup_metric(row, field)
            if value is not None:
                continue
            if field in _G5_EXCEPTIONS and _not_in_committee(row):
                continue
            if r9 and field in _R9_NULL_FIELDS:
                continue
            if field == "sync.participation_rate" and _is_all_skipped_sync(
                row
            ):
                continue
            covered = _matching_reasons(field, reasons)
            assert covered, (stem, field, row.get("pubkey"), reasons)


@pytest.mark.parametrize("stem", _json_fixture_stems())
def test_every_null_metric_has_a_matching_degradation_entry(
    vp, capsys, monkeypatch, stem
):
    skip = _G5_SKIP.get(stem)
    if skip:
        pytest.skip(skip)
    doc = _g5_doc(vp, capsys, monkeypatch, stem)
    _assert_g5_doc(stem, doc)


def test_not_in_committee_is_the_only_exception():
    assert _G5_EXCEPTIONS == ("sync.participation_rate",)
    assert len(_G5_EXCEPTIONS) == 1
    src = inspect.getsource(_assert_g5_doc)
    assert "_G5_EXCEPTIONS" in src
    assert "_not_in_committee" in src
    assert "_is_all_skipped_sync" in src
    assert "_is_all_skipped_sync" not in str(_G5_EXCEPTIONS)


def _failing_snapshot_doc(vp, capsys, monkeypatch):
    _no_sleep(monkeypatch, vp)
    routes = _full_run_routes(vp)
    routes.update(_pruned_slot(vp, (_FULL_FROM + 1) * 32))
    routes.update(_pruned_slot(vp, (_FULL_TO + 2) * 32))
    _run_full(vp, "--json", routes=routes)
    doc, _captured = _stdout_json(capsys)
    return doc


def _doc_reasons(doc):
    got = {d["reason"] for d in doc["degradations"]}
    for row in doc["validators"]:
        got.update(d["reason"] for d in row.get("degradations") or [])
    return got


def test_every_reason_in_the_closed_enum_is_produced_by_a_fixture(
    vp, capsys, monkeypatch
):
    assert list(_REASON_PRODUCERS) == list(_REASON_ENUM)
    missing = []
    for reason, names in _REASON_PRODUCERS.items():
        for name in names:
            assert (FIXTURES / f"{name}.json").is_file(), name
            if reason == "endpoint_failover":
                produced = {d.reason for d in _midrun_failover_degs(vp, monkeypatch)}
            else:
                produced = _doc_reasons(_g5_doc(vp, capsys, monkeypatch, name))
            if reason not in produced:
                missing.append((reason, name, produced))
    snap = _failing_snapshot_doc(vp, capsys, monkeypatch)
    if "state_unavailable" not in _doc_reasons(snap):
        missing.append(
            ("state_unavailable", "failing_balance_snapshot", _doc_reasons(snap))
        )
    assert missing == []


def test_zero_active_validator_reports_null_rates_no_degradation_exit_0(
    vp, capsys
):
    code, _transport = _run_full(
        vp, "--json", validators="states_validators__zero_active"
    )
    assert code == vp.EXIT_OK == 0
    doc, _captured = _stdout_json(capsys)
    assert doc["exit_code"] == 0
    assert doc["degradations"] == []
    assert len(doc["validators"]) == 1
    row = doc["validators"][0]
    assert row["index"] is not None
    assert row["status"] != "unknown"
    assert row["active_epochs"] == 0
    assert row["degradations"] == []
    for field in _R9_NULL_FIELDS:
        assert row[field] is None, field
        assert row[field] != 0, field
    assert row["balance"]["effective_balance_gwei"] not in (None, 0)


def test_scope_values_are_run_validator_or_epoch(vp, capsys, monkeypatch):
    prefixes = set()
    for reason, names in _REASON_PRODUCERS.items():
        if reason == "endpoint_failover":
            for d in _midrun_failover_degs(vp, monkeypatch):
                assert _SCOPE_RE.fullmatch(d.scope), d
                prefixes.add(d.scope.split(":", 1)[0])
            continue
        for name in names:
            doc = _g5_doc(vp, capsys, monkeypatch, name)
            for d in list(doc["degradations"]) + [
                deg
                for row in doc["validators"]
                for deg in row.get("degradations") or []
            ]:
                scope = d["scope"]
                assert _SCOPE_RE.fullmatch(scope), (name, d)
                prefixes.add(scope.split(":", 1)[0])
    snap = _failing_snapshot_doc(vp, capsys, monkeypatch)
    for d in snap["degradations"]:
        assert _SCOPE_RE.fullmatch(d["scope"]), d
        prefixes.add(d["scope"].split(":", 1)[0])
    assert prefixes <= {"run", "validator", "epoch"}
    assert {"run", "validator", "epoch"} <= prefixes


# ----- VP-3a: §11 proposer duties — four failure codes (RD-3, P0-7) -----


def _duty_error(vp, name, status):
    item = raw_response(vp, name, status=status)
    # 500 retries once; 503 retries up to _MAX_ATTEMPTS; 400/404 are semantic.
    n = 3 if status == 503 else (2 if status == 500 else 1)
    return [item] * n


def _duty_routes(w, response, *, fail_epoch=None, fail=None):
    routes = {}
    for epoch in w:
        path = _PROPOSER_TEMPLATE.format(epoch=epoch)
        item = fail if fail_epoch is not None and epoch == fail_epoch else response
        routes[("GET", path)] = list(item) if isinstance(item, list) else [item]
    return routes


def _blocks_path(slot):
    return f"/eth/v1/beacon/rewards/blocks/{slot}"


def _slot_header_path(slot):
    return f"/eth/v1/beacon/headers/{slot}"


def _inclusion_transport(vp, routes):
    inner = FakeTransport(routes)

    class _Transport:
        def __init__(self):
            self.calls = inner.calls
            self.drops = inner.drops
            self.closed = False
            self.routes = inner.routes

        def __call__(self, ep, method, path, body):
            try:
                return inner(ep, method, path, body)
            except KeyError:
                if method == "GET" and (
                    "/eth/v1/beacon/rewards/blocks/" in path
                    or "/eth/v1/beacon/headers/" in path
                ):
                    return _raw(vp, 404)
                raise

        def drop(self, ep):
            inner.drop(ep)

        def close(self):
            inner.close()
            self.closed = inner.closed

    return _Transport()


def _collect_prop(
    vp,
    w,
    index_set,
    routes,
    *,
    concurrency=4,
    budget=None,
    pool=None,
    rewards_api="available",
):
    transport = _inclusion_transport(vp, routes)
    client, _ = _client(vp, transport)
    if budget is None:
        budget = vp.RequestBudget()
    if pool is not None:
        outcomes, degs, available = vp.collect_proposals(
            client, w, index_set, pool, budget, rewards_api
        )
        return outcomes, degs, available, transport, budget
    with ThreadPoolExecutor(max_workers=concurrency) as owned:
        outcomes, degs, available = vp.collect_proposals(
            client, w, index_set, owned, budget, rewards_api
        )
    return outcomes, degs, available, transport, budget


def _assert_duties_unavailable(vp, outcomes, degs, available, epoch):
    assert available is False
    assert vp._DUTIES_UNAVAILABLE == frozenset({400, 404, 500, 503})
    assert any(
        d.reason == "proposer_duties_unavailable" and d.scope == f"epoch:{epoch}"
        for d in degs
    )
    assert not any(d.reason == "state_unavailable" for d in degs)
    decided = [o.included for series in outcomes.values() for o in series]
    assert all(flag is None for flag in decided)


def test_scheduled_slots_intersected_with_our_index_set(vp, load):
    payload = load("duties_proposer__ok")
    rows = payload["data"]
    assert len(rows) == 32
    w = _att_window(vp, 100, 100)
    index_set = {1, 99}
    ok = raw_response(vp, "duties_proposer__ok")
    routes = _duty_routes(w, ok)
    routes[("GET", _blocks_path(3200))] = [raw_response(vp, "rewards_blocks__ok")]
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, index_set, routes
    )
    assert available is True
    assert degs == []
    ours = [o for series in outcomes.values() for o in series]
    assert {o.validator_index for o in ours} <= index_set
    assert {o.validator_index for o in ours} == {1}
    assert len(ours) == 1
    o = ours[0]
    assert o.slot == 3200
    assert o.epoch == 100
    assert o.included is True
    assert o.reward_gwei == 1_234_567
    assert 99 in outcomes
    assert outcomes[99] == []
    gets = [c for c in transport.calls if "duties/proposer/" in c[2]]
    assert len(gets) == 1
    assert gets[0][1] == "GET"


def test_teku_503_takes_the_unavailable_path(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    fail = _duty_error(vp, "duties_proposer__teku_503", 503)
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, _duty_routes(w, fail)
    )
    _assert_duties_unavailable(vp, outcomes, degs, available, 100)
    gets = [c for c in transport.calls if "duties/proposer/" in c[2]]
    assert len(gets) == 3
    assert all(c[1] == "GET" for c in gets)


def test_nimbus_400_takes_the_unavailable_path(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    fail = _duty_error(vp, "duties_proposer__nimbus_400", 400)
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, _duty_routes(w, fail)
    )
    _assert_duties_unavailable(vp, outcomes, degs, available, 100)
    gets = [c for c in transport.calls if "duties/proposer/" in c[2]]
    assert len(gets) == 1


def test_lodestar_500_takes_the_unavailable_path(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    fail = _duty_error(vp, "duties_proposer__lodestar_500", 500)
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, _duty_routes(w, fail)
    )
    _assert_duties_unavailable(vp, outcomes, degs, available, 100)
    gets = [c for c in transport.calls if "duties/proposer/" in c[2]]
    assert len(gets) == 2


def test_404_takes_the_unavailable_path(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    fail = _duty_error(vp, "duties_proposer__404", 404)
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, _duty_routes(w, fail)
    )
    _assert_duties_unavailable(vp, outcomes, degs, available, 100)
    gets = [c for c in transport.calls if "duties/proposer/" in c[2]]
    assert len(gets) == 1


def test_unavailable_duties_null_scheduled_and_missed_but_not_included(vp):
    w = _att_window(vp, 100, 100)
    fail = _duty_error(vp, "duties_proposer__404", 404)
    outcomes, degs, available, _transport, _budget = _collect_prop(
        vp, w, {1}, _duty_routes(w, fail)
    )
    assert available is False
    scheduled = None if not available else sum(len(s) for s in outcomes.values())
    missed = (
        None
        if not available
        else sum(1 for s in outcomes.values() for o in s if o.included is False)
    )
    assert scheduled is None
    assert missed is None
    assert all(o.included is None for s in outcomes.values() for o in s)
    assert all(o.included is not False for s in outcomes.values() for o in s)
    assert not any("included" in d.metric for d in degs)
    assert not any(d.reason == "block_reward_unavailable" for d in degs)


def test_unavailable_duties_emit_proposer_duties_unavailable_and_exit_3(vp, load):
    w = _att_window(vp, 100, 100)
    fail = _duty_error(vp, "duties_proposer__404", 404)
    _outcomes, degs, available, _transport, _budget = _collect_prop(
        vp, w, {1}, _duty_routes(w, fail)
    )
    assert available is False
    assert any(
        d.reason == "proposer_duties_unavailable" and d.scope == "epoch:100"
        for d in degs
    )
    run = vp.RunReport(
        _chain_ctx(vp, load),
        w,
        [],
        {},
        degs,
        [],
        vp.EXIT_OK,
    )
    assert vp.decide_exit_code(run, _window_opts(vp)) == vp.EXIT_DEGRADED == 3
    assert vp.EXIT_ERROR == 1
    assert vp.decide_exit_code(run, _window_opts(vp)) != vp.EXIT_ERROR


def test_one_duties_request_per_epoch(vp):
    w = _att_window(vp, 100, 131)
    assert w.epochs == 32
    index_set = set(range(1, 201))
    ok = raw_response(vp, "duties_proposer__ok")
    _outcomes, _degs, available, transport, _budget = _collect_prop(
        vp, w, index_set, _duty_routes(w, ok)
    )
    assert available is True
    gets = [
        c
        for c in transport.calls
        if c[1] == "GET" and "duties/proposer/" in c[2]
    ]
    assert len(gets) == 32
    assert {c[2] for c in gets} == {
        _PROPOSER_TEMPLATE.format(epoch=e) for e in w
    }
    assert not any(c[1] == "POST" for c in transport.calls)
    src = inspect.getsource(vp.collect_proposals)
    assert "as_completed" in src


def test_duties_500_is_not_treated_as_a_rewards_retention_miss(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    index_set = set(range(1, 201))
    fail = _duty_error(vp, "duties_proposer__lodestar_500", 500)
    outcomes, degs, available, transport, budget = _collect_prop(
        vp, w, index_set, _duty_routes(w, fail)
    )
    _assert_duties_unavailable(vp, outcomes, degs, available, 100)
    gets = [c for c in transport.calls if "duties/proposer/" in c[2]]
    assert len(gets) == 2
    assert all(c[1] == "GET" for c in gets)
    assert not any(c[1] == "POST" for c in transport.calls)
    assert not any("rewards/" in c[2] for c in transport.calls)
    assert budget.extra == 0
    assert budget.flagged is False
    src = inspect.getsource(vp.collect_proposals)
    assert "retry_500" not in src
    assert "_fetch_epoch_rewards" not in src
    assert "state_unavailable" not in src
    assert "retry_500=True" not in inspect.getsource(
        vp.BeaconClient.proposer_duties
    )


def test_duties_transport_error_takes_the_unavailable_path(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    path = _PROPOSER_TEMPLATE.format(epoch=100)
    routes = {("GET", path): [_boom(TimeoutError("timed out"))] * 3}
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    _assert_duties_unavailable(vp, outcomes, degs, available, 100)
    assert any(d.detail == "transport" for d in degs)
    assert len(transport.calls) == 3


def test_unknown_duties_status_fails_closed_as_unavailable(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    w = _att_window(vp, 100, 100)
    path = _PROPOSER_TEMPLATE.format(epoch=100)
    routes = {("GET", path): [_raw(vp, 418)]}
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    _assert_duties_unavailable(vp, outcomes, degs, available, 100)
    assert any(d.detail == "HTTP 418" for d in degs)
    assert len(transport.calls) == 1


def test_duties_non_list_data_takes_the_unavailable_path(vp):
    w = _att_window(vp, 100, 100)
    path = _PROPOSER_TEMPLATE.format(epoch=100)
    routes = {("GET", path): [_raw(vp, 200, b'{"data": null}')]}
    outcomes, degs, available, _transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    _assert_duties_unavailable(vp, outcomes, degs, available, 100)
    assert sum(len(s) for s in outcomes.values()) == 0


def test_duties_dedup_cap_and_drop_slots_outside_epoch(vp):
    w = _att_window(vp, 100, 100)
    assert w.end_slot - w.start_slot == 32
    rows = [
        {"pubkey": PK1, "validator_index": "1", "slot": "3200"},
        {"pubkey": PK1, "validator_index": "1", "slot": "3200"},
        {"pubkey": PK1, "validator_index": "1", "slot": "3199"},
        {"pubkey": PK1, "validator_index": "1", "slot": "3232"},
        {"pubkey": PK1, "validator_index": "1", "slot": "3201"},
    ]
    rows.extend(
        {
            "pubkey": PK1,
            "validator_index": "1",
            "slot": str(3200 + i),
        }
        for i in range(40)
    )
    path = _PROPOSER_TEMPLATE.format(epoch=100)
    body = json.dumps({"data": rows}).encode()
    routes = {("GET", path): [_raw(vp, 200, body)]}
    outcomes, degs, available, _transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    assert available is True
    assert degs == []
    slots = [o.slot for o in outcomes[1]]
    assert slots == sorted(set(slots))
    assert 3199 not in slots
    assert 3232 not in slots
    assert 3200 in slots
    assert 3201 in slots
    assert all(3200 <= slot < 3232 for slot in slots)
    assert len(slots) <= 32
    assert len(slots) == 32


# ----- VP-3b: §11 inclusion — rewards/blocks → headers/{slot} confirm (RD-8) -----

_ORPHANED_FOOTNOTE = (
    "an orphaned block is not canonical and reads as missed"
)


def _blocks_calls(transport):
    return [
        c
        for c in transport.calls
        if c[1] == "GET" and "/eth/v1/beacon/rewards/blocks/" in c[2]
    ]


def _slot_header_calls(transport):
    return [
        c
        for c in transport.calls
        if c[1] == "GET" and "/eth/v1/beacon/headers/" in c[2]
    ]


def _duty_ok_routes(vp, w, *, slot=3200, blocks=None, headers=None):
    routes = _duty_routes(w, raw_response(vp, "duties_proposer__ok"))
    if blocks is not None:
        routes[("GET", _blocks_path(slot))] = list(blocks)
    if headers is not None:
        routes[("GET", _slot_header_path(slot))] = list(headers)
    return routes


def test_404_from_rewards_blocks_with_header_200_is_included_not_missed(vp, load):
    pair = load("rewards_blocks__404_headers_200")
    assert pair["blocks"]["status"] == 404
    assert pair["headers"]["status"] == 200
    w = _att_window(vp, 100, 100)
    routes = _duty_ok_routes(
        vp,
        w,
        blocks=[_raw_from_probe_leg(vp, pair["blocks"])],
        headers=[_raw_from_probe_leg(vp, pair["headers"])],
    )
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    assert available is True
    o = outcomes[1][0]
    assert o.included is True
    assert o.included is not False
    assert o.reward_gwei is None
    assert any(
        d.reason == "block_reward_unavailable" and d.scope == "epoch:100"
        for d in degs
    )
    run = vp.RunReport(
        _chain_ctx(vp, load),
        w,
        [],
        {},
        degs,
        [],
        vp.EXIT_OK,
    )
    assert vp.decide_exit_code(run, _window_opts(vp)) == vp.EXIT_DEGRADED == 3
    assert _blocks_calls(transport)
    assert _slot_header_calls(transport)
    report = _build_report(
        vp,
        load,
        _active_ref(vp),
        [],
        proposal_outcomes=outcomes[1],
        degradations=degs,
    )
    assert report.proposals == {"scheduled": 1, "included": 1, "missed": 0}
    assert report.rewards_gwei["proposer"] is None
    assert report.rewards_gwei["proposer"] != 0


def test_404_from_both_is_genuinely_missed_and_exits_0(vp, load):
    w = _att_window(vp, 100, 100)
    routes = _duty_ok_routes(
        vp,
        w,
        blocks=[_raw(vp, 404)],
        headers=[raw_response(vp, "headers__slot_404", status=404)],
    )
    outcomes, degs, available, _transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    assert available is True
    o = outcomes[1][0]
    assert o.included is False
    assert o.reward_gwei is None
    assert not any(d.reason == "block_reward_unavailable" for d in degs)
    run = vp.RunReport(
        _chain_ctx(vp, load),
        w,
        [],
        {},
        degs,
        [],
        vp.EXIT_OK,
    )
    assert vp.decide_exit_code(run, _window_opts(vp)) == vp.EXIT_OK == 0


def test_200_gives_included_and_the_proposer_reward(vp, load):
    payload = load("rewards_blocks__ok")
    total = int(payload["data"]["total"])
    w = _att_window(vp, 100, 100)
    routes = _duty_ok_routes(
        vp, w, blocks=[raw_response(vp, "rewards_blocks__ok")]
    )
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    assert available is True
    assert degs == []
    o = outcomes[1][0]
    assert o.included is True
    assert o.reward_gwei == total
    report = _build_report(
        vp, load, _active_ref(vp), [], proposal_outcomes=outcomes[1]
    )
    assert report.rewards_gwei["proposer"] == total
    assert report.rewards_gwei["total"] == total
    assert report.proposals == {"scheduled": 1, "included": 1, "missed": 0}
    assert not _slot_header_calls(transport)


def test_data_null_is_treated_as_reward_unreadable_not_missed(vp, load):
    payload = load("rewards_blocks__data_null")
    assert payload["data"] is None
    w = _att_window(vp, 100, 100)
    routes = _duty_ok_routes(
        vp,
        w,
        blocks=[raw_response(vp, "rewards_blocks__data_null")],
        headers=[raw_response(vp, "headers__slot_present")],
    )
    outcomes, degs, available, _transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    assert available is True
    o = outcomes[1][0]
    assert o.included is True
    assert o.included is not False
    assert o.reward_gwei is None
    assert any(d.reason == "block_reward_unavailable" for d in degs)
    report = _build_report(
        vp,
        load,
        _active_ref(vp),
        [],
        proposal_outcomes=outcomes[1],
        degradations=degs,
    )
    assert report.proposals["included"] == 1
    assert report.rewards_gwei["proposer"] is None
    assert report.rewards_gwei["proposer"] != 0


def test_mismatched_proposer_index_is_not_ours(vp, load):
    payload = load("rewards_blocks__ok")
    payload["data"]["proposer_index"] = "99"
    w = _att_window(vp, 100, 100)
    routes = _duty_ok_routes(
        vp, w, blocks=[_raw(vp, 200, json.dumps(payload).encode())]
    )
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    assert available is True
    o = outcomes[1][0]
    assert o.validator_index == 1
    assert o.included is False
    assert o.reward_gwei is None
    assert degs == []
    assert not _slot_header_calls(transport)


def test_route_absent_uses_headers_alone(vp):
    w = _att_window(vp, 100, 100)
    routes = _duty_ok_routes(
        vp, w, headers=[raw_response(vp, "headers__slot_present")]
    )
    outcomes, degs, available, transport, _budget = _collect_prop(
        vp, w, {1}, routes, rewards_api="route_absent"
    )
    assert available is True
    assert _blocks_calls(transport) == []
    assert _slot_header_calls(transport)
    o = outcomes[1][0]
    assert o.included is True
    assert o.reward_gwei is None
    assert not any(d.reason == "block_reward_unavailable" for d in degs)


def test_no_headers_call_when_rewards_blocks_returns_200(vp):
    w = _att_window(vp, 100, 100)
    routes = _duty_ok_routes(
        vp, w, blocks=[raw_response(vp, "rewards_blocks__ok")]
    )
    _outcomes, _degs, _available, transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    assert _blocks_calls(transport)
    assert _slot_header_calls(transport) == []


def test_included_still_derived_when_duties_are_unavailable(vp, load):
    w = _att_window(vp, 100, 101)
    fail = _duty_error(vp, "duties_proposer__404", 404)
    duty_101 = _raw(
        vp,
        200,
        json.dumps(
            {
                "data": [
                    {
                        "pubkey": PK1,
                        "validator_index": "1",
                        "slot": "3232",
                    }
                ]
            }
        ).encode(),
    )
    routes = _duty_routes(w, duty_101, fail_epoch=100, fail=fail)
    routes[("GET", _blocks_path(3232))] = [
        raw_response(vp, "rewards_blocks__ok")
    ]
    outcomes, degs, available, _transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    assert available is False
    assert any(
        d.reason == "proposer_duties_unavailable" and d.scope == "epoch:100"
        for d in degs
    )
    ours = outcomes[1]
    assert len(ours) == 1
    assert ours[0].slot == 3232
    assert ours[0].included is True
    report = _build_report(
        vp,
        load,
        _active_ref(vp),
        [],
        proposal_outcomes=ours,
        duties_available=False,
    )
    assert report.proposals["scheduled"] is None
    assert report.proposals["missed"] is None
    assert report.proposals["included"] == 1


def test_orphaned_block_reads_as_missed_and_is_documented(vp, load):
    w = _att_window(vp, 100, 100)
    routes = _duty_ok_routes(
        vp,
        w,
        blocks=[_raw(vp, 404)],
        headers=[raw_response(vp, "headers__slot_404", status=404)],
    )
    outcomes, degs, _available, _transport, _budget = _collect_prop(
        vp, w, {1}, routes
    )
    assert outcomes[1][0].included is False
    assert not any(d.reason == "block_reward_unavailable" for d in degs)
    text = _render_table(vp, _table_run(vp, load, _golden_reports(vp)))
    assert _ORPHANED_FOOTNOTE in text


# ----- VP-3c: §12 sync membership — one request per period, state_id inside (RD-12) -----

_SYNC_MEMBERSHIP_RE = re.compile(
    r"/eth/v1/beacon/states/([^/]+)/sync_committees\?epoch=(\d+)$"
)
_SYNC_REWARDS_RE = re.compile(r"/eth/v1/beacon/rewards/sync_committee/(\d+)$")


class _Scan404:
    status = 404
    body = b'{"code":404,"message":"Block not found"}'
    truncated = False
    headers: dict = {}


class _SyncMembershipTransport:
    """Serves membership GETs; scan POSTs default to skipped-slot 404."""

    def __init__(
        self,
        membership_resp,
        *,
        head_resp=None,
        scan_resp=None,
        scan_by_slot=None,
        membership_by_epoch=None,
    ):
        self.membership_resp = membership_resp
        self.head_resp = head_resp
        self.scan_resp = scan_resp
        self.scan_by_slot = scan_by_slot or {}
        self.membership_by_epoch = membership_by_epoch or {}
        self.calls: list[tuple[str, str, str, object]] = []
        self.drops: list = []
        self.closed = False

    def __call__(self, ep, method, path, body):
        self.calls.append((ep.label, method, path, body))
        match = _SYNC_REWARDS_RE.search(path)
        if match:
            slot = int(match.group(1))
            item = self.scan_by_slot.get(slot, self.scan_resp)
            if item is None:
                item = _Scan404()
            if callable(item):
                item = item(slot)
            return item
        if "/sync_committees" not in path:
            raise KeyError(f"unscripted FakeTransport call: {method} {path}")
        if self.head_resp is not None and "/states/head/" in path:
            return self.head_resp
        if self.membership_by_epoch:
            _state_id, epoch = _parse_sync_membership_path(path)
            if epoch in self.membership_by_epoch:
                return self.membership_by_epoch[epoch]
        return self.membership_resp

    def drop(self, ep):
        self.drops.append(ep)

    def close(self):
        self.closed = True


def _sync_membership_calls(transport):
    return [
        c
        for c in transport.calls
        if c[1] == "GET" and "/sync_committees" in c[2]
    ]


def _sync_scan_calls(transport):
    return [c for c in transport.calls if "rewards/sync_committee" in c[2]]


def _parse_sync_membership_path(path: str):
    match = _SYNC_MEMBERSHIP_RE.search(path)
    assert match is not None, path
    return match.group(1), int(match.group(2))


def _collect_sync(vp, w, ctx, index_set, transport, *, concurrency=1):
    client, _ = _client(vp, transport)
    budget = vp.RequestBudget()
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        outcomes, degs = vp.collect_sync(
            client, w, ctx, index_set, pool, budget
        )
    return outcomes, degs, transport, budget


def _sync_exit(vp, load, degs):
    run = _json_run(vp, load, degradations=list(degs))
    return vp.decide_exit_code(run, vp.build_options(_minimal_opts_argv()))


def _assert_state_id_inside_period(ctx, transport, w=None):
    spec = ctx.spec
    n = spec.epochs_per_sync_committee_period
    spe = spec.slots_per_epoch
    membership = _sync_membership_calls(transport)
    assert membership
    for _label, _method, path, _body in membership:
        state_id, epoch = _parse_sync_membership_path(path)
        assert state_id != "head"
        slot = int(state_id)
        assert slot == epoch * spe
        period_first = (epoch // n) * n
        period_last = period_first + n - 1
        assert period_first <= slot // spe <= period_last
        if w is not None and epoch == w.from_epoch and w.from_epoch % n == n - 1:
            assert slot != w.start_slot


def test_one_request_per_period_not_per_epoch(vp, load):
    spec = _spec_from_fixture(vp, load)
    assert spec.epochs_per_sync_committee_period == 256
    w32 = _att_window(vp, 66, 97)
    assert w32.epochs == 32
    ctx = _chain_ctx(vp, load, head_epoch=101)
    resp = raw_response(vp, "state_sync_committees__intersect")
    outcomes, _degs, transport, _budget = _collect_sync(
        vp, w32, ctx, {1}, _SyncMembershipTransport(resp)
    )
    membership = _sync_membership_calls(transport)
    assert len(membership) == 1
    assert w32.epochs != len(membership)
    assert outcomes[1].in_committee is True

    w_straddle = _att_window(vp, 240, 271)
    assert w_straddle.epochs == 32
    assert 240 // 256 != 271 // 256
    ctx_late = _chain_ctx(vp, load, head_epoch=280)
    outcomes2, _degs, transport2, _budget = _collect_sync(
        vp,
        w_straddle,
        ctx_late,
        {1},
        _SyncMembershipTransport(resp),
    )
    membership2 = _sync_membership_calls(transport2)
    assert len(membership2) == 2
    assert w_straddle.epochs != len(membership2)
    assert outcomes2[1].in_committee is True


def test_state_id_lies_inside_the_period(vp, load):
    spec = _spec_from_fixture(vp, load)
    n = spec.epochs_per_sync_committee_period
    w = _att_window(vp, 66, 97)
    period = 66 // n
    # Head lives in a later period so state_id="head" is the silent-null 400.
    ctx = _chain_ctx(vp, load, head_epoch=300)
    assert ctx.head_epoch // n != period
    ok = raw_response(vp, "state_sync_committees__intersect")
    outside = raw_response(
        vp, "state_sync_committees__400_outside_period", status=400
    )
    outcomes, degs, transport, _budget = _collect_sync(
        vp,
        w,
        ctx,
        {1},
        _SyncMembershipTransport(ok, head_resp=outside),
    )
    assert degs == []
    assert 1 in outcomes
    _assert_state_id_inside_period(ctx, transport, w)

    # Last epoch of a 256-period: start_slot is already period 1.
    w_edge = _att_window(vp, 255, 286)
    assert w_edge.start_slot // spec.slots_per_epoch == 256
    ctx_edge = _chain_ctx(vp, load, head_epoch=400)
    assert ctx_edge.head_epoch // n != 0
    _outcomes, degs_edge, transport_edge, _budget = _collect_sync(
        vp,
        w_edge,
        ctx_edge,
        {1},
        _SyncMembershipTransport(ok, head_resp=outside),
    )
    assert degs_edge == []
    _assert_state_id_inside_period(ctx_edge, transport_edge, w_edge)

    spec64 = replace(spec, epochs_per_sync_committee_period=64)
    ctx64 = replace(ctx_edge, spec=spec64)
    _outcomes, degs64, transport64, _budget = _collect_sync(
        vp,
        w_edge,
        ctx64,
        {1},
        _SyncMembershipTransport(ok, head_resp=outside),
    )
    assert degs64 == []
    _assert_state_id_inside_period(ctx64, transport64, w_edge)


def test_state_id_clamped_to_head_when_future(vp, load):
    spec = _spec_from_fixture(vp, load)
    w = _att_window(vp, 66, 97)
    slot = w.from_epoch * spec.slots_per_epoch
    ctx = _chain_ctx(vp, load, head_epoch=50, head_slot=slot - 1)
    assert slot > ctx.head_slot
    ok = raw_response(vp, "state_sync_committees__intersect")
    _outcomes, degs, transport, _budget = _collect_sync(
        vp, w, ctx, {1}, _SyncMembershipTransport(ok)
    )
    assert degs == []
    membership = _sync_membership_calls(transport)
    assert membership
    for _label, _method, path, _body in membership:
        state_id, _epoch = _parse_sync_membership_path(path)
        assert state_id == "head"


def test_400_outside_period_is_reported_as_sync_committees_unavailable(
    vp, load
):
    w = _att_window(vp, 66, 97)
    ctx = _chain_ctx(vp, load, head_epoch=101)
    outside = raw_response(
        vp, "state_sync_committees__400_outside_period", status=400
    )
    message = load("state_sync_committees__400_outside_period")["message"]
    outcomes, degs, _transport, _budget = _collect_sync(
        vp, w, ctx, {1}, _SyncMembershipTransport(outside)
    )
    assert degs
    assert all(d.reason == "sync_committees_unavailable" for d in degs)
    assert all(
        d.scope.startswith("epoch:") or d.scope == "run" for d in degs
    )
    assert not any(d.scope.startswith("period:") for d in degs)
    assert any(message in d.detail for d in degs)
    assert all(not o.in_committee for o in outcomes.values())
    assert all(o.participation_rate is None for o in outcomes.values())


def test_empty_intersection_gives_null_m8_with_no_degradation_and_exit_0(
    vp, load
):
    w = _att_window(vp, 66, 97)
    ctx = _chain_ctx(vp, load, head_epoch=101)
    empty = raw_response(vp, "state_sync_committees__empty")
    outcomes, degs, _transport, _budget = _collect_sync(
        vp, w, ctx, {1, 2}, _SyncMembershipTransport(empty)
    )
    assert degs == []
    assert set(outcomes) == {1, 2}
    for outcome in outcomes.values():
        assert outcome.in_committee is False
        assert outcome.participation_rate is None
    assert _sync_exit(vp, load, degs) == vp.EXIT_OK == 0


def test_empty_intersection_skips_the_per_slot_scan_entirely(vp, load):
    w = _att_window(vp, 66, 97)
    ctx = _chain_ctx(vp, load, head_epoch=101)
    empty = raw_response(vp, "state_sync_committees__empty")
    _outcomes, degs, transport, _budget = _collect_sync(
        vp, w, ctx, {1}, _SyncMembershipTransport(empty)
    )
    assert degs == []
    assert _sync_scan_calls(transport) == []
    assert not any(
        "rewards/sync_committee" in c[2] for c in transport.calls
    )


def test_epochs_per_sync_committee_period_read_from_spec_not_hardcoded(
    vp, load
):
    src = inspect.getsource(vp.sync_periods)
    assert "256" not in src
    assert "epochs_per_sync_committee_period" in src
    w = _att_window(vp, 50, 81)
    assert w.epochs == 32
    spec256 = _spec_from_fixture(vp, load)
    spec64 = replace(spec256, epochs_per_sync_committee_period=64)
    assert spec64.epochs_per_sync_committee_period == 64
    assert vp.sync_periods(w, spec256) == [0]
    assert vp.sync_periods(w, spec64) == [0, 1]
    ctx = replace(
        _chain_ctx(vp, load, head_epoch=101),
        spec=spec64,
    )
    ok = raw_response(vp, "state_sync_committees__empty")
    _outcomes, _degs, transport, _budget = _collect_sync(
        vp, w, ctx, {1}, _SyncMembershipTransport(ok)
    )
    assert len(_sync_membership_calls(transport)) == 2


def test_sync_committees_failure_degrades_and_exits_3(vp, load):
    w = _att_window(vp, 66, 97)
    ctx = _chain_ctx(vp, load, head_epoch=101)
    missing = _raw(vp, 404)
    outcomes, degs, _transport, _budget = _collect_sync(
        vp, w, ctx, {1}, _SyncMembershipTransport(missing)
    )
    assert degs
    assert all(d.reason == "sync_committees_unavailable" for d in degs)
    assert all(
        d.scope.startswith("epoch:") or d.scope == "run" for d in degs
    )
    assert not any(d.scope.startswith("period:") for d in degs)
    assert all(o.participation_rate is None for o in outcomes.values())
    assert _sync_exit(vp, load, degs) == vp.EXIT_DEGRADED == 3
    assert vp.EXIT_ERROR == 1


# ----- VP-3d: §12 per-slot scan — membership-set filter, skipped-slot 404 (M8) -----


def _sync_scan_slots(transport):
    slots = []
    for _label, _method, path, _body in _sync_scan_calls(transport):
        match = _SYNC_REWARDS_RE.search(path)
        assert match is not None, path
        slots.append(int(match.group(1)))
    return slots


def _sync_epoch_slots(w, spe=32):
    return range(w.from_epoch * spe, (w.to_epoch + 1) * spe)


def _sync_scan_transport(vp, load, *, scan_resp, scan_by_slot=None, index_set=(1, 2)):
    w = _att_window(vp, 100, 100)
    ctx = _chain_ctx(vp, load, head_epoch=110)
    membership = raw_response(vp, "state_sync_committees__intersect")
    transport = _SyncMembershipTransport(
        membership, scan_resp=scan_resp, scan_by_slot=scan_by_slot
    )
    outcomes, degs, transport, budget = _collect_sync(
        vp, w, ctx, set(index_set), transport
    )
    return w, outcomes, degs, transport, budget


def _lodestar_scan(vp, load):
    return raw_response(vp, "sync_committee__lodestar_negative")


def _dropping_scan(vp, load):
    env = load("sync_committee__lodestar_negative")
    rows = [
        row
        for row in env["data"]
        if str(row["validator_index"]) != "2"
    ]
    return _raw(vp, 200, json.dumps({**env, "data": rows}).encode())


def _member_miss_scan(vp):
    payload = {
        "execution_optimistic": False,
        "finalized": True,
        "data": [{"validator_index": "1", "reward": "-16"}],
    }
    return _raw(vp, 200, json.dumps(payload).encode())


def test_lodestar_negative_rows_for_non_members_are_filtered_by_the_computed_set(
    vp, load
):
    env = load("sync_committee__lodestar_negative")
    by_idx = {
        int(row["validator_index"]): int(row["reward"]) for row in env["data"]
    }
    assert by_idx[1] > 0
    assert by_idx[2] < 0
    w, outcomes, degs, transport, _budget = _sync_scan_transport(
        vp, load, scan_resp=_lodestar_scan(vp, load)
    )
    assert degs == []
    member, other = outcomes[1], outcomes[2]
    assert member.in_committee is True
    assert other.in_committee is False
    assert other.slots_eligible == 0
    assert other.slots_signed == 0
    assert other.participation_rate is None
    assert member.slots_eligible == len(_sync_epoch_slots(w))
    assert member.slots_signed == member.slots_eligible
    assert member.participation_rate == 1.0
    for _label, _method, _path, body in _sync_scan_calls(transport):
        assert json.loads(body) == ["1"]
        assert "2" not in json.loads(body)


def test_dropping_clients_and_lodestar_produce_the_same_m8(vp, load):
    _w, lodestar, degs_l, _t1, _b1 = _sync_scan_transport(
        vp, load, scan_resp=_lodestar_scan(vp, load)
    )
    _w, dropping, degs_d, _t2, _b2 = _sync_scan_transport(
        vp, load, scan_resp=_dropping_scan(vp, load)
    )
    assert degs_l == [] and degs_d == []
    for idx in (1, 2):
        a, b = lodestar[idx], dropping[idx]
        assert a.in_committee == b.in_committee
        assert a.slots_eligible == b.slots_eligible
        assert a.slots_signed == b.slots_signed
        assert a.participation_rate == b.participation_rate
        assert a.reward_gwei == b.reward_gwei
    assert lodestar[1].participation_rate == dropping[1].participation_rate
    assert lodestar[2].in_committee is False
    assert dropping[2].in_committee is False


def test_skipped_slot_404_excluded_from_the_denominator_not_a_miss(vp, load):
    body = load("sync_committee__skipped_slot_404")
    assert body["code"] == 404
    w = _att_window(vp, 100, 100)
    skipped = raw_response(vp, "sync_committee__skipped_slot_404", status=404)
    signed = _dropping_scan(vp, load)
    first_slot = w.from_epoch * 32
    w, outcomes, degs, transport, _budget = _sync_scan_transport(
        vp,
        load,
        scan_resp=signed,
        scan_by_slot={first_slot: skipped},
        index_set=(1,),
    )
    n_slots = len(_sync_epoch_slots(w))
    member = outcomes[1]
    assert degs == []
    assert member.in_committee is True
    assert member.slots_eligible == n_slots - 1
    assert member.slots_signed == n_slots - 1
    assert member.slots_eligible != n_slots
    assert member.participation_rate == 1.0
    assert _sync_exit(vp, load, degs) == vp.EXIT_OK == 0
    assert any(
        c[2].endswith(f"/sync_committee/{first_slot}")
        for c in _sync_scan_calls(transport)
    )


def test_negative_reward_for_a_member_is_a_miss(vp, load):
    w, outcomes, degs, _transport, _budget = _sync_scan_transport(
        vp, load, scan_resp=_member_miss_scan(vp), index_set=(1,)
    )
    member = outcomes[1]
    n_slots = len(_sync_epoch_slots(w))
    assert degs == []
    assert member.in_committee is True
    assert member.slots_eligible == n_slots
    assert member.slots_signed == 0
    assert member.participation_rate == 0.0
    assert member.reward_gwei < 0


def test_scan_covers_every_slot_in_the_window(vp, load):
    w, _outcomes, degs, transport, _budget = _sync_scan_transport(
        vp, load, scan_resp=_lodestar_scan(vp, load), index_set=(1,)
    )
    assert degs == []
    slots = _sync_scan_slots(transport)
    expected = list(_sync_epoch_slots(w))
    assert sorted(slots) == expected
    assert len(slots) == w.epochs * 32
    assert expected[0] == w.from_epoch * 32
    assert expected[0] != w.start_slot
    assert w.start_slot not in slots
    assert len(_sync_membership_calls(transport)) == 1


def test_scan_cost_is_reported_and_flagged_as_the_sm2_carve_out(vp, load):
    w, _outcomes, degs, transport, budget = _sync_scan_transport(
        vp, load, scan_resp=_lodestar_scan(vp, load), index_set=(1,)
    )
    assert degs == []
    n = len(_sync_epoch_slots(w))
    assert n > 0
    assert budget.extra == n
    assert budget.extra == len(_sync_scan_calls(transport))
    assert budget.flagged is True
    src = inspect.getsource(vp.collect_sync)
    assert "add_extra" in src
    assert "SM2" in src


def test_sync_reward_feeds_m9(vp, load):
    ref = _active_ref(vp)
    att = [_mk_outcome(vp, flag_actual_gwei=10, flag_ideal_gwei=10)]
    without = _build_report(vp, load, ref, att)
    sync = vp.SyncOutcome(True, 4, 4, 96)
    with_sync = _build_report(vp, load, ref, att, sync=sync)
    assert with_sync.rewards_gwei["sync"] == 96
    assert with_sync.sync is sync
    assert with_sync.rewards_gwei["total"] == without.rewards_gwei["total"] + 96
    assert without.rewards_gwei["sync"] == 0
    w, outcomes, _degs, _transport, _budget = _sync_scan_transport(
        vp, load, scan_resp=_dropping_scan(vp, load), index_set=(1,)
    )
    scanned = outcomes[1]
    assert scanned.reward_gwei == 48 * scanned.slots_signed
    fed = _build_report(vp, load, ref, att, sync=scanned)
    assert fed.rewards_gwei["sync"] == scanned.reward_gwei
    assert fed.rewards_gwei["total"] == without.rewards_gwei["total"] + scanned.reward_gwei


def test_no_scan_without_membership(vp, load):
    w = _att_window(vp, 100, 100)
    ctx = _chain_ctx(vp, load, head_epoch=110)
    empty = raw_response(vp, "state_sync_committees__empty")
    outcomes, degs, transport, budget = _collect_sync(
        vp, w, ctx, {1, 2}, _SyncMembershipTransport(empty)
    )
    assert degs == []
    assert _sync_scan_calls(transport) == []
    assert budget.extra == 0
    assert budget.flagged is False
    assert all(not o.in_committee for o in outcomes.values())
    src = inspect.getsource(vp.collect_sync)
    assert "rewards_sync_committee" in src


def test_members_are_scored_per_period_not_the_window_union(vp, load):
    spec = _spec_from_fixture(vp, load)
    n = spec.epochs_per_sync_committee_period
    spe = spec.slots_per_epoch
    w = _att_window(vp, 240, 271)
    assert w.epochs == 32
    assert 240 // n != 271 // n
    ctx = _chain_ctx(vp, load, head_epoch=280)
    period0 = raw_response(vp, "state_sync_committees__intersect")
    period1 = raw_response(vp, "state_sync_committees__empty")
    signed = _dropping_scan(vp, load)
    off_period = _member_miss_scan(vp)
    period1_first = n * spe

    def scan(slot):
        return signed if slot < period1_first else off_period

    transport = _SyncMembershipTransport(
        period1,
        scan_resp=scan,
        membership_by_epoch={240: period0, 256: period1},
    )
    outcomes, degs, transport, _budget = _collect_sync(
        vp, w, ctx, {1}, transport
    )
    member = outcomes[1]
    period0_slots = (n - w.from_epoch) * spe
    assert degs == []
    assert member.in_committee is True
    assert member.slots_eligible == period0_slots
    assert member.slots_signed == period0_slots
    assert member.participation_rate == 1.0
    assert member.participation_rate != 0.5
    assert member.slots_eligible != w.epochs * spe
    slots = sorted(_sync_scan_slots(transport))
    assert slots[0] == w.from_epoch * spe
    assert slots[0] != w.start_slot
    assert slots[-1] == (w.to_epoch + 1) * spe - 1
    assert slots[-1] != w.end_slot - 1


def test_all_404_with_membership_is_skipped_only_not_a_miss(vp, load):
    w = _att_window(vp, 100, 100)
    ctx = _chain_ctx(vp, load, head_epoch=110)
    membership = raw_response(vp, "state_sync_committees__intersect")
    skipped = raw_response(vp, "sync_committee__skipped_slot_404", status=404)
    outcomes, degs, transport, budget = _collect_sync(
        vp,
        w,
        ctx,
        {1},
        _SyncMembershipTransport(membership, scan_resp=skipped),
    )
    member = outcomes[1]
    assert degs == []
    assert member.in_committee is True
    assert member.slots_eligible == 0
    assert member.slots_signed == 0
    assert member.reward_gwei == 0
    assert member.participation_rate is None
    assert _sync_exit(vp, load, degs) == vp.EXIT_OK == 0
    assert len(_sync_scan_calls(transport)) == w.epochs * 32
    assert budget.flagged is True


# ----- VP-3e: §13/§14 M9 balance-delta fallback + reward_source (P1-2, D13, SM4) -----

_REWARD_COMPONENT_KEYS = (
    "source",
    "target",
    "head",
    "inactivity",
    "proposer",
    "sync",
)


def _rewards_less_routes(
    vp, *, with_proposal=False, fail_balances=False, validators=None
):
    full_kw = {"fail_collect": True}
    if validators is not None:
        full_kw["validators"] = validators
    routes = _full_run_routes(vp, **full_kw)
    missing = raw_response(vp, "rewards_attestations__404_all", status=404)
    routes[("POST", _DRY_RUN_ATT_PATH)] = [missing]
    routes[("POST", _REWARDS_TEMPLATE.format(epoch=_FULL_FROM))] = [missing]
    if fail_balances:
        spe = 32
        routes.update(_pruned_slot(vp, (_FULL_FROM + 1) * spe))
        routes.update(_pruned_slot(vp, (_FULL_TO + 2) * spe))
    if with_proposal:
        slot = _FULL_FROM * 32
        duties = json.loads(
            (FIXTURES / "duties_proposer__ok.json").read_text()
        )
        duties["data"] = [
            {**row, "slot": str(slot)}
            for row in duties["data"]
            if row["validator_index"] == "1"
        ]
        routes[("GET", _PROPOSER_TEMPLATE.format(epoch=_FULL_FROM))] = [
            _raw(vp, 200, json.dumps(duties).encode())
        ]
        pair = json.loads(
            (FIXTURES / "rewards_blocks__404_headers_200.json").read_text()
        )
        routes[("GET", _blocks_path(slot))] = [
            _raw_from_probe_leg(vp, pair["blocks"])
        ]
        routes[("GET", _slot_header_path(slot))] = [
            raw_response(vp, "headers__slot_present")
        ]
    return routes


def _run_rewards_less(vp, capsys, *extra, pubkeys=None, **route_kw):
    run_kw = {}
    if pubkeys is not None:
        run_kw["pubkeys"] = pubkeys
    code, transport = _run_full(
        vp,
        "--json",
        *extra,
        routes=_rewards_less_routes(vp, **route_kw),
        **run_kw,
    )
    doc, _captured = _stdout_json(capsys)
    return code, transport, doc


def test_rewards_less_run_nulls_m1_through_m6(vp, capsys):
    _code, _transport, doc = _run_rewards_less(vp, capsys)
    row = doc["validators"][0]
    for field in (
        "participation_rate",
        "source_rate",
        "target_rate",
        "head_rate",
        "missed_attestations",
        "attester_effectiveness",
    ):
        assert row[field] is None, field
        assert row[field] != 0, field


def test_rewards_less_run_still_derives_proposals_included(vp, capsys):
    _code, _transport, doc = _run_rewards_less(
        vp, capsys, with_proposal=True
    )
    row = doc["validators"][0]
    assert row["proposals"]["included"] == 1
    assert row["proposals"]["included"] is not False


def test_rewards_less_run_keeps_balance_figures(vp, capsys):
    _code, _transport, doc = _run_rewards_less(vp, capsys)
    balance = doc["validators"][0]["balance"]
    assert balance["start_gwei"] == 32_000_000_000
    assert balance["end_gwei"] == 32_001_834_000
    assert balance["delta_gwei"] == _CONSENSUS_REWARD_GWEI == 1_834_000


def test_consensus_reward_equals_delta_gwei(vp, capsys):
    _code, _transport, doc = _run_rewards_less(vp, capsys)
    row = doc["validators"][0]
    delta = row["balance"]["delta_gwei"]
    assert delta == _CONSENSUS_REWARD_GWEI
    assert row["rewards_gwei"]["total"] == delta
    assert doc["aggregate"]["consensus_reward_gwei"] == delta


def test_reward_source_is_balance_delta(vp, capsys):
    _code, _transport, doc = _run_rewards_less(vp, capsys)
    assert doc["validators"][0]["reward_source"] == "balance_delta"
    assert doc["aggregate"]["reward_source"] == "balance_delta"


def test_rewards_gwei_components_are_null_never_zero(vp, capsys):
    _code, _transport, doc = _run_rewards_less(vp, capsys)
    components = doc["validators"][0]["rewards_gwei"]
    for key in _REWARD_COMPONENT_KEYS:
        assert components[key] is None, key
        assert components[key] != 0, key
    # G5: summing (component or 0) would report a silent 0 here.
    silent_zero = sum(components[k] or 0 for k in _REWARD_COMPONENT_KEYS)
    assert silent_zero == 0
    assert components["total"] != silent_zero
    assert components["total"] == _CONSENSUS_REWARD_GWEI


def test_rewards_less_run_exits_3(vp, capsys):
    code, _transport, doc = _run_rewards_less(vp, capsys)
    assert code == vp.EXIT_DEGRADED == 3
    assert doc["exit_code"] == 3


def test_no_liveness_request_is_issued(vp, capsys):
    _code, transport, _doc = _run_rewards_less(vp, capsys)
    assert not any("liveness" in c[2] for c in transport.calls)


def test_reconciliation_is_unavailable_in_balance_delta_mode(vp, capsys):
    _code, _transport, doc = _run_rewards_less(vp, capsys)
    rec = doc["validators"][0]["balance"]["reconciliation"]
    assert rec == "unavailable"
    assert rec != "consistent"


def test_apr_computed_and_labelled_balance_delta(vp, capsys):
    _code, _transport, doc = _run_rewards_less(vp, capsys)
    row = doc["validators"][0]
    eb = row["balance"]["effective_balance_gwei"]
    delta = row["balance"]["delta_gwei"]
    epochs_per_year = 82181.25
    expected = delta / eb * epochs_per_year / doc["window"]["epochs"]
    assert row["reward_source"] == "balance_delta"
    assert row["estimated_apr"] is not None
    assert row["estimated_apr"] == pytest.approx(expected)
    assert doc["aggregate"]["reward_source"] == "balance_delta"
    assert doc["aggregate"]["estimated_apr"] == pytest.approx(expected)


def test_aggregate_reward_source_is_balance_delta_if_any_validator_used_it(
    vp, load
):
    spec = _spec_from_fixture(vp, load)
    api = _build_report(
        vp, load, _active_ref(vp, index=1, pubkey=PK1), _n_outcomes(vp, 1)
    )
    delta = replace(
        api,
        ref=_active_ref(vp, index=2, pubkey=PK2),
        reward_source="balance_delta",
    )
    assert api.reward_source == "rewards_api"
    mixed = vp.build_aggregate([api, delta], spec)
    assert mixed["reward_source"] == "balance_delta"
    all_api = vp.build_aggregate(
        [api, replace(delta, reward_source="rewards_api")], spec
    )
    assert all_api["reward_source"] == "rewards_api"


def test_both_unavailable_nulls_reward_source_and_apr(vp, capsys):
    _code, _transport, doc = _run_rewards_less(
        vp, capsys, fail_balances=True
    )
    row = doc["validators"][0]
    assert row["reward_source"] is None
    assert row["estimated_apr"] is None
    assert row["rewards_gwei"]["total"] is None
    assert doc["aggregate"]["reward_source"] is None
    assert doc["aggregate"]["estimated_apr"] is None
    assert doc["aggregate"]["consensus_reward_gwei"] is None


def test_unknown_pubkey_on_rewards_less_run_is_not_rewards_api_zeros(
    vp, capsys
):
    _code, _transport, doc = _run_rewards_less(
        vp,
        capsys,
        validators="states_validators__unknown_pubkey",
        pubkeys=(PK1, PK4),
    )
    unknown = next(v for v in doc["validators"] if v["pubkey"] == PK4)
    assert unknown["index"] is None
    assert unknown["status"] == "unknown"
    for key in (*_REWARD_COMPONENT_KEYS, "total"):
        assert unknown["rewards_gwei"][key] is None, key
        assert unknown["rewards_gwei"][key] != 0, key
    assert unknown["reward_source"] is None


def test_route_absent_skips_collect_and_labels_unsupported(vp, capsys):
    routes = _full_run_routes(vp)
    pair = json.loads((FIXTURES / "probe__route_absent.json").read_text())
    routes[("GET", _BLOCKS_HEAD_PATH)] = [
        _raw_from_probe_leg(vp, pair["blocks"])
    ]
    routes[("POST", _DRY_RUN_ATT_PATH)] = [
        _raw_from_probe_leg(vp, pair["attestations"])
    ]
    collect_path = _REWARDS_TEMPLATE.format(epoch=_FULL_FROM)
    del routes[("POST", collect_path)]
    code, transport = _run_full(vp, "--json", routes=routes)
    doc, _captured = _stdout_json(capsys)
    att_posts = [
        c
        for c in transport.calls
        if c[1] == "POST" and "rewards/attestations/" in c[2]
    ]
    assert [c[2] for c in att_posts] == [_DRY_RUN_ATT_PATH]
    assert collect_path not in {c[2] for c in att_posts}
    assert any(
        d["reason"] == "rewards_api_unsupported" for d in doc["degradations"]
    )
    assert doc["validators"][0]["reward_source"] == "balance_delta"
    assert code == vp.EXIT_DEGRADED == 3
    assert doc["exit_code"] == 3


def test_known_zero_active_stays_r9_when_attestation_degraded(vp, load):
    window = _report_window(vp)
    pending = _active_ref(
        vp, index=3, pubkey=PK3, activation=500, status="pending_queued"
    )
    assert pending.active_epochs_in(window) == 0
    leftover = _CONSENSUS_REWARD_GWEI
    snap = vp.BalanceSnapshot(_EB_32, _EB_32 + leftover, _EB_32, _EB_32)
    r9 = _build_report(
        vp,
        load,
        pending,
        [],
        snap=snap,
        window=window,
        attestation_degraded=True,
    )
    assert r9.reward_source == "rewards_api"
    for name in (
        "participation_rate",
        "source_rate",
        "target_rate",
        "head_rate",
        "estimated_apr",
    ):
        assert getattr(r9, name) is None, name
    assert r9.rewards_gwei["total"] != leftover
    assert r9.rewards_gwei["total"] != snap.delta_gwei
    active = _build_report(
        vp,
        load,
        _active_ref(vp, index=1, pubkey=PK1),
        [],
        snap=snap,
        window=window,
        attestation_degraded=True,
    )
    assert active.reward_source == "balance_delta"
    spec = _spec_from_fixture(vp, load)
    agg = vp.build_aggregate([r9, active], spec)
    assert agg["reward_source"] == "balance_delta"


def test_perf_schema_json_unchanged():
    repo = SCRIPT.resolve().parent.parent
    path = "scripts/tests/perf_schema.json"
    for args in (
        ["git", "diff", "--", path],
        ["git", "diff", "HEAD", "--", path],
        ["git", "diff", "--cached", "--", path],
    ):
        proc = subprocess.run(
            args,
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
        assert proc.stdout == "", args


# ----- VP-3g: M-C SM2 ≤120-request budget + fixture roll-call -----

# headers__head slot 3232 / finalized epoch 99 → default window [68, 99].
_MC_FROM_EPOCH = 68
_MC_TO_EPOCH = 99
_MC_SPE = 32
_MC_START_SLOT = (_MC_FROM_EPOCH + 1) * _MC_SPE  # 2208
_MC_END_SLOT = (_MC_TO_EPOCH + 2) * _MC_SPE  # 3232
_MC_SYNC_QUERY_EPOCH = _MC_FROM_EPOCH
_MC_SYNC_STATE_ID = _MC_SYNC_QUERY_EPOCH * _MC_SPE  # 2176
_MC_HEAD_EPOCH = 101
_MC_PROBE_EPOCH = _MC_HEAD_EPOCH - 2  # 99
_MC_SYNC_MEMBERSHIP_PATH = (
    f"/eth/v1/beacon/states/{_MC_SYNC_STATE_ID}/sync_committees"
    f"?epoch={_MC_SYNC_QUERY_EPOCH}"
)

# Architecture §4.1; empty duties → 0 proposal confirms.
ARCHITECTURE_SCHEDULE = {
    "selection": 2,
    "bootstrap": 4,
    "resolve": 1,
    "probe": 2,
    "rewards": 32,
    "duties": 32,
    "balances": 2,
    "sync_membership": 1,
}

_MC_FIXTURE_FILES = (
    "rewards_attestations__leak.json",
    "rewards_attestations__ideal_filtered.json",
    "states_validators__eb_zero.json",
    "rewards_blocks__404_headers_200.json",
    "probe__route_absent.json",
    "probe__state_unavailable.json",
    "states_validators__post_414.json",
    "spec__spe8.json",
    "duties_proposer__teku_503.json",
    "duties_proposer__nimbus_400.json",
    "duties_proposer__lodestar_500.json",
    "sync_committee__lodestar_negative.json",
    "states_validators__mid_window_activation.json",
    "states_validators__unknown_pubkey.json",
    "balances__diverged.json",
    "rewards_attestations__404_all.json",
    "states_validators__zero_active.json",
)

_P0_ACCEPTANCE = {
    "P0-1": (
        "test_pubkey_union_across_three_sources_in_input_order",
        "test_short_pubkey_exits_2_naming_source_and_line",
    ),
    "P0-2": (
        "test_beacon_nodes_beats_beacon_url_in_config",
        "test_beacon_url_flag_beats_the_config_file_entirely",
    ),
    "P0-3": (
        "test_default_window_is_66_to_97",
        "test_allow_unfinalized_gives_67_to_98",
        "test_to_epoch_99_exits_2_naming_max_safe_epoch_98",
        "test_spe8_shifts_every_derived_slot",
        "test_epochs_per_year_halves_at_six_second_slots",
        "test_epochs_with_from_epoch_exits_2",
    ),
    "P0-4": (
        "test_200_keys_produce_exactly_one_post",
        "test_post_414_falls_back_to_four_chunked_gets",
        "test_unknown_pubkey_is_null_index_unknown_status_and_run_continues",
        "test_states_validators_rejects_empty_ids",
        "test_post_404_and_405_also_trigger_the_get_fallback",
        "test_no_method_reaches_the_validators_route_unfiltered",
        "test_no_unfiltered_validators_call_in_the_whole_run",
    ),
    "P0-5": (
        "test_fixture_a_gives_source_rate_075_and_head_rate_05",
        "test_leak_epoch_credits_source_and_target",
        "test_leak_epoch_head_is_none_not_false",
        "test_one_post_per_epoch_regardless_of_validator_count",
        "test_missed_attestations_predicate",
        "test_request_count_independent_of_validator_count",
    ),
    "P0-6": (
        "test_build_ideal_index_is_a_dict_keyed_by_effective_balance",
        "test_missing_ideal_row_nulls_effectiveness_for_that_epoch_not_zero",
        "test_effectiveness_matches_a_hand_computed_ratio",
        "test_estimated_apr_matches_to_four_decimal_places",
        "test_apr_halves_on_six_second_slots",
        "test_effective_balance_changed_flag",
    ),
    "P0-7": (
        "test_404_from_rewards_blocks_with_header_200_is_included_not_missed",
        "test_teku_503_takes_the_unavailable_path",
        "test_nimbus_400_takes_the_unavailable_path",
        "test_lodestar_500_takes_the_unavailable_path",
        "test_empty_intersection_gives_null_m8_with_no_degradation_and_exit_0",
        "test_lodestar_negative_rows_for_non_members_are_filtered_by_the_computed_set",
        "test_one_request_per_period_not_per_epoch",
        "test_unavailable_duties_null_scheduled_and_missed_but_not_included",
    ),
    "P0-8": (
        "test_snapshot_slots_are_3232_and_4256",
        "test_balance_requests_go_to_snapshot_slots_3232_and_4256",
        "test_diverged_delta_annotates_and_exits_0",
        "test_end_slot_unreachable_reports_unavailable_not_a_wrong_slot",
        "test_diverged_balance_does_not_degrade",
        "test_snapshots_use_states_validators_not_validator_balances",
    ),
    "P0-9": (
        "test_golden_table_matches_exactly",
        "test_final_golden_table_matches",
        "test_null_renders_em_dash_never_zero",
        "test_rows_sorted_by_effectiveness_ascending",
    ),
    "P0-10": (
        "test_json_stdout_is_exactly_one_document",
        "test_json_validates_against_perf_schema",
        "test_schema_version_is_1",
    ),
    "P0-11": (
        "test_exit_0_on_a_fully_available_run",
        "test_exit_2_on_a_usage_error",
        "test_exit_3_on_a_leak_epoch",
        "test_exit_5_when_no_beacon_is_reachable",
        "test_degraded_ok_maps_3_to_0",
    ),
    "P0-12": (
        "test_redact_emits_scheme_host_port_only",
        "test_no_url_or_secret_in_any_retry_log_line",
        "test_full_run_leaks_no_secret_in_stdout_or_stderr",
        "test_transport_sets_read_timeout_on_the_socket_after_connect",
        "test_no_beacon_url_or_secret_in_the_json_document",
    ),
    "P0-13": (
        "test_probe_200_and_404_is_state_unavailable",
        "test_probe_404_and_404_is_route_absent",
        "test_probe_body_carries_a_resolved_eb_nonzero_index",
        "test_probe_issues_exactly_two_requests",
    ),
    "P0-14": (
        "test_network_is_blocked",
        "test_socket_blocked",
    ),
}

_MC_NULL_RULES = {
    "M4-in-leak": (
        "test_leak_epoch_head_is_none_not_false",
        "test_exit_3_on_a_leak_epoch",
    ),
    "M8-not-in-committee": (
        "test_empty_intersection_gives_null_m8_with_no_degradation_and_exit_0",
        "test_not_in_committee_is_the_only_exception",
    ),
    "M1/M5-rewards-less": (
        "test_rewards_less_run_nulls_m1_through_m6",
    ),
}


def _mc_att_path(epoch: int) -> str:
    return _REWARDS_TEMPLATE.format(epoch=epoch)


def _mc_att_posts(calls):
    return [
        c[2]
        for c in calls
        if c[1] == "POST" and "/rewards/attestations/" in c[2]
    ]


def tally_request_phases(
    calls,
    *,
    from_epoch=_MC_FROM_EPOCH,
    to_epoch=_MC_TO_EPOCH,
    probe_epoch=_MC_PROBE_EPOCH,
):
    """Per-phase counts from FakeTransport.calls, classified by path."""
    counts = {
        "selection": 0,
        "bootstrap": 0,
        "resolve": 0,
        "probe": 0,
        "rewards": 0,
        "duties": 0,
        "balances": 0,
        "sync_membership": 0,
        "proposal_confirms": 0,
        "sync_scan": 0,
        "other": 0,
    }
    window_att = {
        _mc_att_path(epoch) for epoch in range(from_epoch, to_epoch + 1)
    }
    probe_att = _mc_att_path(probe_epoch)
    att_left: dict[str, int] = {}
    for _label, method, path, _body in calls:
        if path in (_VERSION_TEMPLATE, _SYNCING_PATH):
            counts["selection"] += 1
        elif path in (
            _SPEC_TEMPLATE,
            _GENESIS_PATH,
            _HEADER_HEAD_PATH,
            _FINALITY_PATH,
        ):
            counts["bootstrap"] += 1
        elif method == "POST" and path == _VALIDATORS_PATH:
            counts["resolve"] += 1
        elif method == "GET" and path == _BLOCKS_HEAD_PATH:
            counts["probe"] += 1
        elif method == "POST" and "/rewards/attestations/" in path:
            att_left[path] = att_left.get(path, 0) + 1
        elif method == "GET" and "/validator/duties/proposer/" in path:
            counts["duties"] += 1
        elif (
            method == "POST"
            and path.endswith("/validators")
            and "/beacon/states/" in path
            and path != _VALIDATORS_PATH
        ):
            counts["balances"] += 1
        elif method == "GET" and "/sync_committees" in path:
            counts["sync_membership"] += 1
        elif method == "POST" and "/rewards/sync_committee/" in path:
            counts["sync_scan"] += 1
        elif method == "GET" and (
            "/rewards/blocks/" in path or "/beacon/headers/" in path
        ):
            counts["proposal_confirms"] += 1
        else:
            counts["other"] += 1
    for path, n in att_left.items():
        remaining = n
        if path in window_att and remaining:
            counts["rewards"] += 1
            remaining -= 1
        if path == probe_att and remaining:
            counts["probe"] += 1
            remaining -= 1
        counts["other"] += remaining
    return counts


def _mc_pubkeys(n: int) -> list[str]:
    return [f"0x{i:096x}" for i in range(1, n + 1)]


def _mc_validators_payload(pubkeys: list[str]) -> dict:
    rows = []
    for i, pk in enumerate(pubkeys, start=1):
        rows.append(
            {
                "index": str(i),
                "balance": "32001834000",
                "status": "active_ongoing",
                "validator": {
                    "pubkey": pk,
                    "withdrawal_credentials": "0x" + "00" * 32,
                    "effective_balance": "32000000000",
                    "slashed": False,
                    "activation_eligibility_epoch": "0",
                    "activation_epoch": "0",
                    "exit_epoch": "18446744073709551615",
                    "withdrawable_epoch": "18446744073709551615",
                },
            }
        )
    return {
        "execution_optimistic": False,
        "finalized": False,
        "data": rows,
    }


def _mc_empty_sync_raw(vp):
    payload = {
        "execution_optimistic": False,
        "finalized": True,
        "data": {"validators": [], "validator_aggregates": []},
    }
    return _raw(vp, 200, json.dumps(payload).encode())


def _mc_routes(vp, pubkeys, *, membership=False):
    routes = _dry_run_routes(vp)
    n = len(pubkeys)
    validators = _raw(vp, 200, json.dumps(_mc_validators_payload(pubkeys)).encode())
    att = _att_ok(vp, indices=range(1, n + 1))
    duties = _raw(vp, 200, b'{"data": []}')
    routes[("POST", _VALIDATORS_PATH)] = [validators]
    routes[("GET", _BLOCKS_HEAD_PATH)] = [raw_response(vp, "rewards_blocks__ok")]
    for epoch in range(_MC_FROM_EPOCH, _MC_TO_EPOCH + 1):
        copies = 2 if epoch == _MC_PROBE_EPOCH else 1
        routes[("POST", _mc_att_path(epoch))] = [att] * copies
        routes[("GET", _PROPOSER_TEMPLATE.format(epoch=epoch))] = [duties]
    routes[("POST", _validators_at(_MC_START_SLOT))] = [validators]
    routes[("POST", _validators_at(_MC_END_SLOT))] = [validators]
    if membership:
        routes[("GET", _MC_SYNC_MEMBERSHIP_PATH)] = [
            raw_response(vp, "state_sync_committees__intersect")
        ]
        scan = _raw(
            vp,
            200,
            json.dumps(
                {"data": [{"validator_index": "1", "reward": "48"}]}
            ).encode(),
        )
        for slot in range(
            _MC_FROM_EPOCH * _MC_SPE, (_MC_TO_EPOCH + 1) * _MC_SPE
        ):
            path = f"/eth/v1/beacon/rewards/sync_committee/{slot}"
            routes[("POST", path)] = [scan]
    else:
        routes[("GET", _MC_SYNC_MEMBERSHIP_PATH)] = [_mc_empty_sync_raw(vp)]
    return routes


def _mc_argv(pubkeys_file: Path):
    return [
        "--pubkeys-file",
        str(pubkeys_file),
        "--beacon-url",
        "https://bn.example:5052",
        "--concurrency",
        "1",
        "--json",
    ]


def _run_mc_budget(vp, tmp_path, n_keys, *, membership=False):
    keys = _mc_pubkeys(n_keys)
    pubfile = tmp_path / f"keys_{n_keys}.txt"
    pubfile.write_text("\n".join(keys) + "\n", encoding="utf-8")
    transport = FakeTransport(_mc_routes(vp, keys, membership=membership))
    code = vp.main(_mc_argv(pubfile), transport=transport)
    return code, transport


def _validators_ids(method, path, body):
    if method == "GET":
        return parse_qs(urlsplit(path).query).get("id", [])
    if not body:
        return []
    raw = body.decode() if isinstance(body, (bytes, bytearray)) else body
    payload = json.loads(raw)
    if isinstance(payload, dict):
        ids = payload.get("ids")
        if isinstance(ids, list):
            return ids
        return []
    if isinstance(payload, list):
        return payload
    return []


def test_request_budget_matches_the_architecture_schedule(vp, tmp_path, capsys):
    expected = dict(ARCHITECTURE_SCHEDULE)
    assert expected == {
        "selection": 2,
        "bootstrap": 4,
        "resolve": 1,
        "probe": 2,
        "rewards": 32,
        "duties": 32,
        "balances": 2,
        "sync_membership": 1,
    }
    assert sum(expected.values()) == 76
    code, transport = _run_mc_budget(vp, tmp_path, 200)
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    doc = json.loads(captured.out)
    assert doc["window"]["from_epoch"] == _MC_FROM_EPOCH
    assert doc["window"]["to_epoch"] == _MC_TO_EPOCH
    assert doc["window"]["epochs"] == 32
    tally = tally_request_phases(transport.calls)
    core = {key: tally[key] for key in expected}
    assert core == expected
    assert tally["proposal_confirms"] == 0
    assert tally["sync_scan"] == 0
    assert tally["other"] == 0
    assert len(transport.calls) == 76
    probe_att = _mc_att_path(_MC_PROBE_EPOCH)
    window_att = {
        _mc_att_path(epoch)
        for epoch in range(_MC_FROM_EPOCH, _MC_TO_EPOCH + 1)
    }
    att_paths = _mc_att_posts(transport.calls)
    assert set(att_paths) == window_att
    assert att_paths.count(probe_att) == 2
    for path in window_att:
        if path == probe_att:
            continue
        assert att_paths.count(path) == 1
    assert any(
        c[1] == "GET" and c[2] == _BLOCKS_HEAD_PATH for c in transport.calls
    )


def test_request_budget_under_120_for_200_keys_32_epochs(vp, tmp_path, capsys):
    code, transport = _run_mc_budget(vp, tmp_path, 200)
    capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    assert len(transport.calls) <= 120


def test_request_count_independent_of_validator_count(vp, tmp_path, capsys):
    code_200, transport_200 = _run_mc_budget(vp, tmp_path, 200)
    capsys.readouterr()
    code_2000, transport_2000 = _run_mc_budget(vp, tmp_path, 2000)
    capsys.readouterr()
    assert code_200 == code_2000 == vp.EXIT_OK == 0
    assert len(transport_200.calls) == len(transport_2000.calls)
    tally_200 = tally_request_phases(transport_200.calls)
    tally_2000 = tally_request_phases(transport_2000.calls)
    core = tuple(ARCHITECTURE_SCHEDULE)
    assert {k: tally_200[k] for k in core} == {k: tally_2000[k] for k in core}
    assert {k: tally_200[k] for k in core} == ARCHITECTURE_SCHEDULE
    assert tally_200["other"] == tally_2000["other"] == 0
    resolve_200 = [
        c for c in transport_200.calls if c[1] == "POST" and c[2] == _VALIDATORS_PATH
    ]
    resolve_2000 = [
        c
        for c in transport_2000.calls
        if c[1] == "POST" and c[2] == _VALIDATORS_PATH
    ]
    assert len(resolve_200) == len(resolve_2000) == 1
    assert len(json.loads(resolve_200[0][3])["ids"]) == 200
    assert len(json.loads(resolve_2000[0][3])["ids"]) == 2000
    for calls in (transport_200.calls, transport_2000.calls):
        gets = [
            c
            for c in calls
            if c[1] == "GET" and c[2].split("?", 1)[0].endswith("/validators")
        ]
        assert gets == []


def test_sync_membership_carve_out_is_reported_not_hidden(vp, tmp_path, capsys):
    code, transport = _run_mc_budget(vp, tmp_path, 200, membership=True)
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    n_calls = len(transport.calls)
    assert n_calls > 120
    tally = tally_request_phases(transport.calls)
    scan_slots = _MC_SPE * 32
    assert tally["sync_scan"] == scan_slots
    assert tally["sync_membership"] == 1
    core = {key: tally[key] for key in ARCHITECTURE_SCHEDULE}
    assert core == ARCHITECTURE_SCHEDULE
    assert tally["proposal_confirms"] == 0
    extra = n_calls - 76
    assert extra == scan_slots
    assert "SM2 carve-out" in captured.err
    assert str(scan_slots) in captured.err
    assert extra > 0


def test_fixture_roll_call():
    assert len(_MC_FIXTURE_FILES) == 17
    missing = [
        name
        for name in _MC_FIXTURE_FILES
        if not (FIXTURES / name).is_file()
    ]
    assert missing == []
    for name in _MC_FIXTURE_FILES:
        path = FIXTURES / name
        assert path.name == name


def test_no_unfiltered_validators_call_in_the_whole_run(vp, tmp_path, capsys):
    code, transport = _run_mc_budget(vp, tmp_path, 200)
    capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    validator_calls = [
        c
        for c in transport.calls
        if "/states/" in c[2] and c[2].split("?", 1)[0].endswith("/validators")
    ]
    assert validator_calls
    for _label, method, path, body in validator_calls:
        ids = _validators_ids(method, path, body)
        assert ids, (method, path, body)


def _assert_named_tests(present, mapping):
    for req, names in mapping.items():
        assert names, req
        missing = [name for name in names if name not in present]
        assert missing == [], f"{req} missing {missing}"


def test_p0_acceptance_matrix():
    assert list(_P0_ACCEPTANCE) == [f"P0-{i}" for i in range(1, 15)]
    present = {
        name
        for name, obj in inspect.getmembers(
            sys.modules[__name__], inspect.isfunction
        )
        if name.startswith("test_")
    }
    _assert_named_tests(present, _P0_ACCEPTANCE)
    assert list(_MC_NULL_RULES) == [
        "M4-in-leak",
        "M8-not-in-committee",
        "M1/M5-rewards-less",
    ]
    _assert_named_tests(present, _MC_NULL_RULES)


# ----- VP-4a: §6/§4.5 mid-run promotion — lock-under-comparison (D11) -----


def _midrun_spec(load):
    spec = load("failover__midrun_promotion")
    assert spec["concurrent_failures"] == 4
    assert spec["expected_advances"] == 1
    assert spec["reason"] == "endpoint_failover"
    return spec


def _midrun_endpoints(vp, spec, *, secret=False):
    urls = list(spec["endpoints"])
    if secret:
        urls = [
            "https://user:secret@" + u.split("://", 1)[1].rstrip("/") + "/hidden/"
            for u in urls
        ]
    return [vp.parse_endpoint(url, f"bn{i}") for i, url in enumerate(urls)]


def _midrun_client(vp, transport, spec, *, secret=False):
    client = _client(
        vp, transport, endpoints=_midrun_endpoints(vp, spec, secret=secret)
    )[0]
    client._pinned = True
    return client


def test_four_concurrent_failures_advance_exactly_once(vp, load, monkeypatch):
    _no_sleep(monkeypatch, vp)
    spec = _midrun_spec(load)
    n = spec["concurrent_failures"]
    path = _REWARDS_TEMPLATE.format(epoch=100)
    head_epoch = 200
    probe_att = _REWARDS_TEMPLATE.format(epoch=head_epoch - 2)
    fail = _raw(vp, 503)
    ok = _data_raw(vp, {})
    transport = FakeTransport(
        {
            ("bn0", "POST", path): concurrent_failures(n, fail) + [fail] * (n * 3),
            ("bn1", "POST", path): [ok] * n,
            ("bn1", "GET", _BLOCKS_HEAD_PATH): [_raw(vp, 200, b'{"data": {}}')],
            ("bn1", "POST", probe_att): [ok],
            ("bn2", "POST", path): [ok] * n,
            ("bn3", "POST", path): [ok] * n,
        }
    )
    client = _midrun_client(vp, transport, spec)
    client._probe_head_epoch = head_epoch
    client._probe_ids = ["1"]
    client._rewards_api = "available"

    def work():
        return client.rewards_attestations(100, ["1"])

    with ThreadPoolExecutor(max_workers=n) as pool:
        futs = [pool.submit(work) for _ in range(n)]
        for fut in futs:
            fut.result()
    assert client._current == spec["expected_advances"]
    assert client._endpoint().label == "bn1"
    assert client._endpoint().label != "bn3"
    assert client._current != 3
    probe_on_bn1 = [
        c
        for c in transport.calls
        if c[0] == "bn1" and (c[2] == _BLOCKS_HEAD_PATH or c[2] == probe_att)
    ]
    assert len(probe_on_bn1) == 2
    orig_on_bn1 = [c for c in transport.calls if c[0] == "bn1" and c[2] == path]
    assert len(orig_on_bn1) == n


def test_workers_on_a_stale_endpoint_retry_on_current_without_advancing(
    vp, load, monkeypatch
):
    _no_sleep(monkeypatch, vp)
    spec = _midrun_spec(load)
    transport = FakeTransport({})
    client = _midrun_client(vp, transport, spec)
    endpoints = client._endpoints
    with client._lock:
        client._current = 1
    stale = endpoints[0]
    current = client._promote_from(stale)
    assert current is endpoints[1]
    assert client._current == 1
    with ThreadPoolExecutor(max_workers=4) as pool:
        got = [
            fut.result()
            for fut in [pool.submit(client._promote_from, stale) for _ in range(4)]
        ]
    assert client._current == 1
    assert all(ep is endpoints[1] for ep in got)


def test_promotion_retries_original_when_reprobe_fails(vp, load, monkeypatch):
    _no_sleep(monkeypatch, vp)
    spec = _midrun_spec(load)
    fail_path = _REWARDS_TEMPLATE.format(epoch=50)
    fail = _raw(vp, 503)
    ok = _data_raw(vp, {})
    transport = FakeTransport(
        {
            ("bn0", "POST", fail_path): [fail] * 3,
            ("bn1", "GET", _BLOCKS_HEAD_PATH): [_boom(ssl.SSLError("bad cert"))],
            ("bn1", "POST", fail_path): [ok],
        }
    )
    client = _midrun_client(vp, transport, spec)
    client._probe_head_epoch = 100
    client._probe_ids = ["1"]
    client._rewards_api = "available"
    assert client.rewards_attestations(50, ["1"]) == {}
    assert client._current == 1
    assert any(c[0] == "bn1" and c[2] == fail_path for c in transport.calls)


def test_promotion_reruns_the_capability_probe(vp, load, monkeypatch):
    _no_sleep(monkeypatch, vp)
    spec = _midrun_spec(load)
    fail_path = _REWARDS_TEMPLATE.format(epoch=50)
    head_epoch = 100
    probe_att = _REWARDS_TEMPLATE.format(epoch=head_epoch - 2)
    fail = _raw(vp, 503)
    ok = _data_raw(vp, {})
    transport = FakeTransport(
        {
            ("bn0", "POST", fail_path): [fail] * 3,
            ("bn1", "POST", fail_path): [ok],
            ("bn1", "GET", _BLOCKS_HEAD_PATH): [_raw(vp, 200, b'{"data": {}}')],
            ("bn1", "POST", probe_att): [ok],
        }
    )
    client = _midrun_client(vp, transport, spec)
    client._probe_head_epoch = head_epoch
    client._probe_ids = ["1"]
    client._rewards_api = "available"
    client.rewards_attestations(50, ["1"])
    probe_on_bn1 = [
        c
        for c in transport.calls
        if c[0] == "bn1"
        and (c[2] == _BLOCKS_HEAD_PATH or c[2] == probe_att)
    ]
    assert len(probe_on_bn1) == 2
    assert [c[1] for c in probe_on_bn1] == ["GET", "POST"]


def _midrun_failover_degs(vp, monkeypatch):
    _no_sleep(monkeypatch, vp)
    spec = json.loads(
        (FIXTURES / "failover__midrun_promotion.json").read_text()
    )
    w = _att_window(vp, 100, 101)
    refs = [_active_ref(vp)]
    ok = _att_ok(vp, indices=(1,))
    fail = _raw(vp, 503)
    path100 = _REWARDS_TEMPLATE.format(epoch=100)
    path101 = _REWARDS_TEMPLATE.format(epoch=101)
    probe_att = _REWARDS_TEMPLATE.format(epoch=198)
    transport = FakeTransport(
        {
            ("bn0", "POST", path100): [ok],
            ("bn0", "POST", path101): [fail] * 3,
            ("bn1", "GET", _BLOCKS_HEAD_PATH): [_raw(vp, 404)],
            ("bn1", "POST", probe_att): [_raw(vp, 404)],
            ("bn1", "POST", path101): [_raw(vp, 404)],
        }
    )
    client = _midrun_client(vp, transport, spec)
    client._probe_head_epoch = 200
    client._probe_ids = ["1"]
    client._rewards_api = "available"
    budget = vp.RequestBudget()
    with ThreadPoolExecutor(max_workers=1) as pool:
        _outcomes, degs = vp.collect_attestations(client, w, refs, pool, budget)
    return degs


def test_epochs_after_promotion_degrade_with_endpoint_failover(vp, load, monkeypatch):
    spec = _midrun_spec(load)
    degs = _midrun_failover_degs(vp, monkeypatch)
    hits = [
        d
        for d in degs
        if d.reason == spec["reason"] and d.scope.startswith("epoch:")
    ]
    assert hits
    assert all(d.scope == "epoch:101" for d in hits)
    opts = vp.build_options(_minimal_opts_argv())
    run = vp.RunReport(
        vp.ChainContext(
            vp.Spec(32, 12, 256, 4, {}),
            0,
            None,
            0,
            0,
            0,
            "",
            "available",
            "",
        ),
        _att_window(vp, 100, 101),
        [],
        {},
        degs,
        [],
        0,
    )
    assert vp.decide_exit_code(run, opts) == vp.EXIT_DEGRADED == 3


def test_no_refetch_of_already_served_epochs(vp, load, monkeypatch):
    _no_sleep(monkeypatch, vp)
    spec = _midrun_spec(load)
    w = _att_window(vp, 100, 101)
    refs = [_active_ref(vp)]
    ok = _att_ok(vp, indices=(1,))
    fail = _raw(vp, 503)
    path100 = _REWARDS_TEMPLATE.format(epoch=100)
    path101 = _REWARDS_TEMPLATE.format(epoch=101)
    transport = FakeTransport(
        {
            ("bn0", "POST", path100): [ok],
            ("bn0", "POST", path101): [fail] * 3,
            ("bn1", "POST", path101): [ok],
        }
    )
    client = _midrun_client(vp, transport, spec)
    budget = vp.RequestBudget()
    with ThreadPoolExecutor(max_workers=1) as pool:
        outcomes, _degs = vp.collect_attestations(client, w, refs, pool, budget)
    posts_100 = [c for c in transport.calls if c[2] == path100]
    assert len(posts_100) == 1
    assert posts_100[0][0] == "bn0"
    posts_101 = [c for c in transport.calls if c[2] == path101]
    assert any(c[0] == "bn1" for c in posts_101)
    assert {o.epoch for o in outcomes[1]} == {100, 101}


def test_all_endpoints_exhausted_exits_5(vp, monkeypatch, capsys):
    _no_sleep(monkeypatch, vp)
    routes = _full_run_routes(vp)
    fail = _raw(vp, 503)
    collect = _REWARDS_TEMPLATE.format(epoch=_FULL_FROM)
    routes[("POST", collect)] = [fail] * 20
    pair = json.loads((FIXTURES / "probe__state_unavailable.json").read_text())
    routes[("GET", _BLOCKS_HEAD_PATH)] = list(routes[("GET", _BLOCKS_HEAD_PATH)]) + [
        _raw_from_probe_leg(vp, pair["blocks"])
    ]
    routes[("POST", _DRY_RUN_ATT_PATH)] = list(routes[("POST", _DRY_RUN_ATT_PATH)]) + [
        _raw_from_probe_leg(vp, pair["attestations"])
    ]
    transport = FakeTransport(routes)
    argv = _full_argv(
        "--json",
        "--beacon-url",
        "http://bn1.example:5052",
    )
    code = vp.main(argv, transport=transport)
    assert code == vp.EXIT_NO_BEACON == 5
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "Traceback" not in captured.err
    assert captured.err.strip() != ""


def test_endpoints_used_records_both_in_order_redacted(vp, load, monkeypatch):
    _no_sleep(monkeypatch, vp)
    spec = _midrun_spec(load)
    path = _REWARDS_TEMPLATE.format(epoch=100)
    fail = _raw(vp, 503)
    ok = _data_raw(vp, {})
    transport = FakeTransport(
        {
            ("bn0", "POST", path): [fail] * 3,
            ("bn1", "POST", path): [ok],
        }
    )
    client = _midrun_client(vp, transport, spec, secret=True)
    client.rewards_attestations(100, ["1"])
    used = client.endpoints_used
    assert used == ["https://bn0:5052", "https://bn1:5052"]
    blob = " ".join(used)
    assert "secret" not in blob
    assert "user:secret" not in blob
    assert "hidden" not in blob
    assert "/hidden" not in blob


def test_one_promotion_attempt_per_endpoint(vp, load):
    spec = _midrun_spec(load)
    client = _midrun_client(vp, FakeTransport({}), spec)
    endpoints = client._endpoints
    first = client._promote_from(endpoints[0])
    assert first is endpoints[1]
    assert client._current == 1
    again = client._promote_from(endpoints[0])
    assert again is endpoints[1]
    assert client._current == 1
    nxt = client._promote_from(endpoints[1])
    assert nxt is endpoints[2]
    assert client._current == 2


# ----- VP-4b: P1-1 selection-time AC + beacon.endpoints_used[] -----


def _first_503_spec(load):
    spec = load("failover__first_503")
    assert spec["selection_status"] == 503
    assert len(spec["endpoints"]) == 2
    return spec


def _selection_urls(spec, *, secret=False):
    urls = list(spec["endpoints"])
    if secret:
        urls = [
            "https://user:secret@" + u.split("://", 1)[1].rstrip("/") + "/hidden/"
            for u in urls
        ]
    return urls


def _selection_skip_routes(vp, *, bn0):
    routes = _full_run_routes(vp)
    if bn0 == "503":
        # Exhaust the retry budget so select_endpoint walks on, not _promote_from.
        routes[("bn0", "GET", _VERSION_TEMPLATE)] = [
            _raw(vp, 503)
        ] * vp._MAX_ATTEMPTS
    elif bn0 == "syncing":
        routes[("bn0", "GET", _VERSION_TEMPLATE)] = [
            raw_response(vp, "node_version__lighthouse")
        ]
        routes[("bn0", "GET", _SYNCING_PATH)] = [
            raw_response(vp, "node_syncing__is_syncing")
        ]
    else:
        raise AssertionError(bn0)
    return routes


def _run_selection_failover(vp, load, *extra, bn0="503", secret=False):
    spec = _first_503_spec(load)
    urls = _selection_urls(spec, secret=secret)
    transport = FakeTransport(_selection_skip_routes(vp, bn0=bn0))
    argv = _full_argv(*extra, "--beacon-url", urls[1], url=urls[0])
    code = vp.main(argv, transport=transport)
    return spec, urls, code, transport


def _shown_urls(vp, urls):
    return [vp.redact(vp.parse_endpoint(url, f"bn{i}")) for i, url in enumerate(urls)]


def test_first_bn_503_completes_on_the_second(vp, load, capsys, monkeypatch):
    _no_sleep(monkeypatch, vp)
    promoted = []
    orig = vp.BeaconClient._promote_from

    def wrapped(self, ep):
        promoted.append(ep.label)
        return orig(self, ep)

    monkeypatch.setattr(vp.BeaconClient, "_promote_from", wrapped)
    spec, _urls, code, transport = _run_selection_failover(vp, load, "--json")
    assert spec["selection_status"] == 503
    assert code == vp.EXIT_OK == 0
    assert promoted == []
    doc, _captured = _stdout_json(capsys)
    validate_schema(doc, _load_perf_schema())
    assert doc["exit_code"] == 0
    assert doc["degradations"] == []
    row = doc["validators"][0]
    for name in (
        "participation_rate",
        "source_rate",
        "target_rate",
        "head_rate",
        "attester_effectiveness",
    ):
        assert row[name] is not None, name
    bn0 = [c for c in transport.calls if c[0] == "bn0"]
    assert bn0
    assert all(c[2] == _VERSION_TEMPLATE for c in bn0)
    assert len(bn0) == vp._MAX_ATTEMPTS
    assert any(c[0] == "bn1" and c[2] == _SPEC_TEMPLATE for c in transport.calls)
    collect = _REWARDS_TEMPLATE.format(epoch=_FULL_FROM)
    assert any(c[0] == "bn1" and c[2] == collect for c in transport.calls)
    assert not any(c[0] == "bn0" and c[2] != _VERSION_TEMPLATE for c in transport.calls)


def test_endpoints_used_records_which_endpoint_served_the_run(
    vp, load, capsys, monkeypatch
):
    _no_sleep(monkeypatch, vp)
    _spec, urls, code, _transport = _run_selection_failover(vp, load, "--json")
    assert code == vp.EXIT_OK == 0
    doc, _captured = _stdout_json(capsys)
    shown = _shown_urls(vp, urls)
    assert doc["beacon"]["endpoints_used"] == shown
    assert doc["beacon"]["endpoint"] == shown[-1]
    assert shown[-1] == vp.redact(vp.parse_endpoint(urls[1], "bn1"))


def test_beacon_endpoint_stays_a_string(vp, load, capsys, monkeypatch):
    schema = _load_perf_schema()
    assert schema["properties"]["beacon"]["properties"]["endpoint"]["type"] == "string"
    _no_sleep(monkeypatch, vp)
    _spec, _urls, code, _transport = _run_selection_failover(vp, load, "--json")
    assert code == vp.EXIT_OK == 0
    doc, _captured = _stdout_json(capsys)
    endpoint = doc["beacon"]["endpoint"]
    assert isinstance(endpoint, str)
    assert not isinstance(endpoint, list)


def test_syncing_node_is_skipped_at_selection(vp, load, capsys, monkeypatch):
    _no_sleep(monkeypatch, vp)
    _spec, _urls, code, transport = _run_selection_failover(
        vp, load, "--json", bn0="syncing"
    )
    assert code == vp.EXIT_OK == 0
    doc, _captured = _stdout_json(capsys)
    assert doc["degradations"] == []
    assert [c[2] for c in transport.calls if c[0] == "bn0"] == [
        _VERSION_TEMPLATE,
        _SYNCING_PATH,
    ]
    assert any(c[0] == "bn1" and c[2] == _SPEC_TEMPLATE for c in transport.calls)
    row = doc["validators"][0]
    assert row["source_rate"] is not None
    assert row["target_rate"] is not None


def test_schema_version_still_1(vp, load, capsys):
    assert vp.SCHEMA_VERSION == 1
    schema = _load_perf_schema()
    assert schema["properties"]["schema_version"]["enum"] == [1]
    doc = json.loads(vp.render_json(_json_run(vp, load)))
    assert doc["schema_version"] == 1
    code, _transport = _run_full(vp, "--json")
    assert code == vp.EXIT_OK == 0
    live, _captured = _stdout_json(capsys)
    assert live["schema_version"] == 1


def test_endpoints_used_entries_are_redacted(vp, load, capsys, monkeypatch):
    _no_sleep(monkeypatch, vp)
    _spec, urls, code, _transport = _run_selection_failover(
        vp, load, "--json", secret=True
    )
    assert code == vp.EXIT_OK == 0
    doc, captured = _stdout_json(capsys)
    used = doc["beacon"]["endpoints_used"]
    assert used == _shown_urls(vp, urls)
    blob = " ".join([doc["beacon"]["endpoint"], *used])
    assert "secret" not in blob
    assert "user:secret" not in blob
    assert "hidden" not in blob
    assert "/hidden" not in blob
    for entry in used:
        parsed = urlsplit(entry)
        assert parsed.username is None
        assert parsed.password is None
        assert parsed.path in ("", "/")
    assert "secret" not in captured.out
    assert "user:" not in captured.out


# ----- VP-4c: §4/§14 --fail-under allowlist + evaluate_thresholds + exit 4 -----

_THRESHOLD_ALLOWLIST = (
    "participation_rate",
    "source_rate",
    "target_rate",
    "head_rate",
    "attester_effectiveness",
    "sync_participation_rate",
    "estimated_apr",
)


def _fail_under_window_routes(vp, envelopes, from_epoch, to_epoch):
    routes = _full_run_routes(vp)
    spe = 32
    empty_duties = _raw(vp, 200, b'{"data": []}')
    for i, env in enumerate(envelopes):
        epoch = from_epoch + i
        routes[("POST", _REWARDS_TEMPLATE.format(epoch=epoch))] = [
            _raw(vp, 200, json.dumps(env).encode())
        ]
        routes[("GET", _PROPOSER_TEMPLATE.format(epoch=epoch))] = [empty_duties]
    routes[("POST", _validators_at((from_epoch + 1) * spe))] = [
        raw_response(vp, "states_validators__snapshot_start")
    ]
    routes[("POST", _validators_at((to_epoch + 2) * spe))] = [
        raw_response(vp, "states_validators__snapshot_end")
    ]
    sync_state = from_epoch * spe
    routes[
        (
            "GET",
            f"/eth/v1/beacon/states/{sync_state}/sync_committees"
            f"?epoch={from_epoch}",
        )
    ] = [raw_response(vp, "state_sync_committees__empty")]
    return routes


def _run_with_thresholds(vp, load, reports, fail_under, *, degradations=None):
    run = _table_run(vp, load, reports)
    if degradations is not None:
        run = replace(run, degradations=list(degradations))
    hits = vp.evaluate_thresholds(run, vp.parse_thresholds(fail_under))
    opts = _window_opts(vp, fail_under=tuple(fail_under))
    code = vp.decide_exit_code(run, opts)
    return replace(run, threshold_breaches=hits, exit_code=code), opts


def test_allowlist_has_exactly_seven_names(vp):
    assert vp.THRESHOLD_METRICS == frozenset(_THRESHOLD_ALLOWLIST)
    assert len(vp.THRESHOLD_METRICS) == 7
    for name in _THRESHOLD_ALLOWLIST:
        assert vp.parse_thresholds([f"{name}=0.95"]) == {name: 0.95}


def test_unknown_metric_name_exits_2(vp, capsys):
    raw = "targt_rate=0.95"
    code = vp.main(_minimal_opts_argv("--fail-under", raw))
    assert code == vp.EXIT_USAGE == 2
    err = capsys.readouterr().err
    assert "targt_rate" in err
    assert raw in err
    with pytest.raises(vp.UsageError) as ei:
        vp.parse_thresholds([raw])
    assert "targt_rate" in str(ei.value)


def test_malformed_pair_exits_2(vp, capsys):
    for raw in (
        "target_rate",
        "target_rate=abc",
        "target_rate=nan",
        "target_rate=inf",
        "target_rate=-inf",
    ):
        code = vp.main(_minimal_opts_argv("--fail-under", raw))
        assert code == vp.EXIT_USAGE == 2
        err = capsys.readouterr().err
        assert raw in err
        with pytest.raises(vp.UsageError) as ei:
            vp.parse_thresholds([raw])
        assert raw in str(ei.value)


def test_repeated_fail_under_flags_all_apply(vp, load):
    opts = vp.build_options(
        _minimal_opts_argv(
            "--fail-under",
            "target_rate=0.95",
            "--fail-under",
            "source_rate=0.90",
        )
    )
    assert opts.fail_under == ("target_rate=0.95", "source_rate=0.90")
    parsed = vp.parse_thresholds(opts.fail_under)
    assert parsed == {"target_rate": 0.95, "source_rate": 0.90}
    report = _table_report(vp, source_rate=0.50, target_rate=0.50)
    run, _opts = _run_with_thresholds(
        vp, load, [report], opts.fail_under
    )
    assert any("source_rate" in item for item in run.threshold_breaches)
    assert any("target_rate" in item for item in run.threshold_breaches)
    assert run.exit_code == vp.EXIT_THRESHOLD == 4


def test_target_rate_090_against_095_exits_4(vp, capsys, load):
    envelopes = load("thresholds__target_090")
    assert isinstance(envelopes, list) and len(envelopes) == 10
    ref = _active_ref(vp)
    outcomes = _eval_outcomes(vp, envelopes, ref, _EB_32)
    assert len(outcomes) == 10
    report = _build_report(
        vp, load, ref, outcomes, window=_att_window(vp, 100, 109)
    )
    assert report.target_rate == pytest.approx(0.90)
    assert report.target_rate < 0.95
    run, _opts = _run_with_thresholds(
        vp, load, [report], ("target_rate=0.95",)
    )
    assert run.exit_code == vp.EXIT_THRESHOLD == 4
    from_epoch = _FULL_TO - len(envelopes) + 1
    to_epoch = _FULL_TO
    code, _transport = _run_full(
        vp,
        "--json",
        "--fail-under",
        "target_rate=0.95",
        "--from-epoch",
        str(from_epoch),
        "--to-epoch",
        str(to_epoch),
        routes=_fail_under_window_routes(
            vp, envelopes, from_epoch, to_epoch
        ),
    )
    assert code == vp.EXIT_THRESHOLD == 4
    doc, _captured = _stdout_json(capsys)
    assert doc["exit_code"] == 4
    assert doc["validators"][0]["target_rate"] == pytest.approx(0.90)


def test_null_metric_cannot_breach(vp, capsys):
    code, _transport = _run_full(
        vp,
        "--json",
        "--fail-under",
        "target_rate=0.95",
        routes=_rewards_less_routes(vp),
    )
    assert code != vp.EXIT_ERROR
    assert code != vp.EXIT_THRESHOLD
    assert code == vp.EXIT_DEGRADED == 3
    doc, _captured = _stdout_json(capsys)
    assert doc["exit_code"] == 3
    assert doc["validators"][0]["target_rate"] is None
    assert not doc.get("threshold_breaches")


def test_breach_plus_degradation_yields_4(vp, capsys, load):
    report = _table_report(vp, target_rate=0.90)
    deg = vp.Degradation("head_rate", "epoch:100", "inactivity_leak", "")
    run, _opts = _run_with_thresholds(
        vp,
        load,
        [report],
        ("target_rate=0.95",),
        degradations=[deg],
    )
    assert run.degradations
    assert run.exit_code == vp.EXIT_THRESHOLD == 4
    code, _transport = _run_full(
        vp,
        "--json",
        "--fail-under",
        "target_rate=1.1",
        rewards="rewards_attestations__leak",
    )
    assert code == vp.EXIT_THRESHOLD == 4
    doc, _captured = _stdout_json(capsys)
    assert doc["exit_code"] == 4
    assert any(d["reason"] == "inactivity_leak" for d in doc["degradations"])


def test_degraded_ok_does_not_touch_4(vp, capsys, load):
    report = _table_report(vp, target_rate=0.90)
    deg = vp.Degradation("head_rate", "epoch:100", "inactivity_leak", "")
    run = _table_run(vp, load, [report])
    run = replace(run, degradations=[deg])
    opts = _window_opts(
        vp, fail_under=("target_rate=0.95",), degraded_ok=True
    )
    assert vp.decide_exit_code(run, opts) == vp.EXIT_THRESHOLD == 4
    code, _transport = _run_full(
        vp,
        "--json",
        "--degraded-ok",
        "--fail-under",
        "target_rate=1.1",
        rewards="rewards_attestations__leak",
    )
    assert code == vp.EXIT_THRESHOLD == 4
    assert code != vp.EXIT_OK
    doc, _captured = _stdout_json(capsys)
    assert doc["exit_code"] == 4


def test_thresholds_evaluated_per_validator_and_on_the_aggregate(vp, load):
    bad = _table_report(
        vp,
        ref=_active_ref(vp, index=1, pubkey=PK1),
        target_rate=0.50,
        attester_effectiveness=0.50,
    )
    good = _table_report(
        vp,
        ref=_active_ref(vp, index=2, pubkey=PK2),
        target_rate=1.00,
        attester_effectiveness=1.00,
    )
    run = _table_run(vp, load, [bad, good])
    assert run.aggregate["target_rate"] == pytest.approx(0.75)
    per_validator = vp.evaluate_thresholds(run, {"target_rate": 0.60})
    assert any(item.startswith("validator:1:") for item in per_validator)
    assert not any(item.startswith("validator:2:") for item in per_validator)
    assert not any(item.startswith("aggregate:") for item in per_validator)
    both = vp.evaluate_thresholds(run, {"target_rate": 0.80})
    assert any(item.startswith("validator:1:") for item in both)
    assert not any(item.startswith("validator:2:") for item in both)
    assert any(item.startswith("aggregate:") for item in both)


def test_sync_participation_rate_fires_for_in_committee_only(vp, load):
    member = _table_report(
        vp,
        ref=_active_ref(vp, index=1, pubkey=PK1),
        sync=vp.SyncOutcome(True, 32, 16, 48),
    )
    assert member.sync is not None
    assert member.sync.in_committee is True
    assert member.sync.participation_rate == pytest.approx(0.5)
    absent = _table_report(
        vp,
        ref=_active_ref(vp, index=2, pubkey=PK2),
        sync=None,
    )
    outsider = _table_report(
        vp,
        ref=_active_ref(vp, index=3, pubkey=PK3),
        sync=vp.SyncOutcome(False, 0, 0, 0),
    )
    assert outsider.sync is not None
    assert outsider.sync.in_committee is False
    assert outsider.sync.participation_rate is None
    run = _table_run(vp, load, [member, absent, outsider])
    hits = vp.evaluate_thresholds(run, {"sync_participation_rate": 0.95})
    assert "validator:1:sync_participation_rate" in hits
    assert not any(item.startswith("validator:2:") for item in hits)
    assert not any(item.startswith("validator:3:") for item in hits)
    assert "aggregate:sync_participation_rate" not in hits


def test_breaching_rows_are_marked_in_table_and_json(vp, load):
    # 0.80 + 1.00 → aggregate 0.90, so the summary tgt% is also under 0.95.
    bad = _table_report(
        vp,
        ref=_active_ref(vp, index=1, pubkey=PK1),
        target_rate=0.80,
        attester_effectiveness=0.50,
    )
    good = _table_report(
        vp,
        ref=_active_ref(vp, index=2, pubkey=PK2),
        target_rate=1.00,
        attester_effectiveness=1.00,
    )
    run, _opts = _run_with_thresholds(
        vp, load, [bad, good], ("target_rate=0.95",)
    )
    assert run.aggregate["target_rate"] == pytest.approx(0.90)
    text = _render_table(vp, run)
    header, rows = _table_header_and_rows(text)
    tgt = header.index("tgt%")
    by_pk = {row[0].rstrip("!"): row for row in rows}
    assert by_pk["0x1111…1111"][tgt].endswith("!")
    assert not by_pk["0x2222…2222"][tgt].endswith("!")
    assert "!" in by_pk["0x1111…1111"][0]
    summary = next(ln for ln in text.splitlines() if ln.startswith("part%"))
    assert "tgt% 90.00!" in summary
    doc = json.loads(vp.render_json(run))
    assert "validator:1:target_rate" in doc["threshold_breaches"]
    assert "aggregate:target_rate" in doc["threshold_breaches"]
    assert "validator:2:target_rate" not in doc["threshold_breaches"]
    by_json = {row["pubkey"]: row for row in doc["validators"]}
    assert "target_rate" in by_json[PK1]["threshold_breaches"]
    assert "target_rate" not in by_json[PK2]["threshold_breaches"]
    validate_schema(doc, _load_perf_schema())


# ----- VP-4d: §6 --request-delay-ms + strictly-serial AC (P1-3) -----

_PHASE_RANK = {
    "selection": 0,
    "bootstrap": 1,
    "resolve": 2,
    "probe": 3,
    "rewards": 4,
    "duties": 5,
    "balances": 6,
    "sync": 7,
    "proposal_confirms": 8,
    "sync_scan": 9,
}


def _vp4d_phase(method: str, path: str) -> str:
    if path in (_VERSION_TEMPLATE, _SYNCING_PATH):
        return "selection"
    if path in (
        _SPEC_TEMPLATE,
        _GENESIS_PATH,
        _HEADER_HEAD_PATH,
        _FINALITY_PATH,
    ):
        return "bootstrap"
    if method == "POST" and path == _VALIDATORS_PATH:
        return "resolve"
    if method == "GET" and path == _BLOCKS_HEAD_PATH:
        return "probe"
    if method == "POST" and "/rewards/attestations/" in path:
        return "rewards"
    if method == "GET" and "/validator/duties/proposer/" in path:
        return "duties"
    if (
        method == "POST"
        and "/beacon/states/" in path
        and path.endswith("/validators")
        and path != _VALIDATORS_PATH
    ):
        return "balances"
    if "/sync_committees" in path:
        return "sync"
    if method == "GET" and (
        "/rewards/blocks/" in path or "/beacon/headers/" in path
    ):
        return "proposal_confirms"
    if method == "POST" and "/rewards/sync_committee/" in path:
        return "sync_scan"
    return "other"


class _StartRecorder:
    def __init__(self, inner, now):
        self._inner = inner
        self._now = now
        self.starts: list[tuple[str, str, float]] = []
        self._lock = threading.Lock()

    def __call__(self, ep, method, path, body):
        with self._lock:
            self.starts.append((method, path, self._now()))
        return self._inner(ep, method, path, body)

    def drop(self, ep):
        self._inner.drop(ep)

    def close(self):
        self._inner.close()

    @property
    def calls(self):
        return self._inner.calls


def _install_virtual_clock(vp, monkeypatch, *, t0=10.0):
    # Per-thread time so concurrent sleeps overlap; a global += would
    # serialize per-worker delays and hide the 4×-rate bug.
    local = threading.local()
    vp._next_request_start = 0.0

    def monotonic():
        return getattr(local, "t", t0)

    def sleep(seconds):
        local.t = getattr(local, "t", t0) + seconds

    monkeypatch.setattr(vp.time, "monotonic", monotonic)
    monkeypatch.setattr(vp.time, "sleep", sleep)
    return monotonic


def _assert_min_gap(times, delay):
    ordered = sorted(times)
    assert len(ordered) >= 2
    for earlier, later in zip(ordered, ordered[1:]):
        assert later - earlier >= delay - 1e-9


def test_default_concurrency_is_4(vp):
    opts = vp.build_options(_minimal_opts_argv())
    assert vp.DEFAULT_CONCURRENCY == 4
    assert opts.concurrency == 4


def test_no_test_sleeps():
    source = Path(__file__).read_text(encoding="utf-8")
    assert re.search(r"time\.sleep\s*\(", source) is None


def test_concurrency_1_issues_requests_strictly_serially(vp, tmp_path, capsys):
    keys = _mc_pubkeys(1)
    pubfile = tmp_path / "keys_serial.txt"
    pubfile.write_text("\n".join(keys) + "\n", encoding="utf-8")
    transport = FakeTransport(_mc_routes(vp, keys))
    argv = [
        "--pubkeys-file",
        str(pubfile),
        "--beacon-url",
        "https://bn.example:5052",
        "--concurrency",
        "1",
        "--json",
    ]
    code = vp.main(argv, transport=transport)
    capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    phases = [_vp4d_phase(c[1], c[2]) for c in transport.calls]
    assert "other" not in phases
    ranks = [_PHASE_RANK[p] for p in phases]
    assert ranks == sorted(ranks)
    att_epochs = [
        int(c[2].rsplit("/", 1)[-1])
        for c in transport.calls
        if c[1] == "POST" and "/rewards/attestations/" in c[2]
    ]
    assert att_epochs[0] == _MC_PROBE_EPOCH
    assert att_epochs[1:] == list(
        range(_MC_FROM_EPOCH, _MC_TO_EPOCH + 1)
    )
    duty_epochs = [
        int(c[2].rsplit("/", 1)[-1])
        for c in transport.calls
        if c[1] == "GET" and "/validator/duties/proposer/" in c[2]
    ]
    assert duty_epochs == list(range(_MC_FROM_EPOCH, _MC_TO_EPOCH + 1))


def test_request_delay_enforced_globally_not_per_worker(vp, monkeypatch):
    now = _install_virtual_clock(vp, monkeypatch)
    w = _att_window(vp, 100, 103)
    assert w.epochs == 4
    inner = FakeTransport(_att_routes(w, _att_ok(vp, indices=(1,))))
    transport = _StartRecorder(inner, now)
    client, _ = _client(vp, transport, request_delay=0.05)
    with ThreadPoolExecutor(max_workers=4) as pool:
        vp.collect_attestations(
            client, w, [_active_ref(vp)], pool, vp.RequestBudget()
        )
    times = [t for _method, _path, t in transport.starts]
    assert len(times) == 4
    _assert_min_gap(times, 0.05)


def test_delay_applies_across_every_phase(vp, monkeypatch, capsys):
    now = _install_virtual_clock(vp, monkeypatch)
    inner = FakeTransport(_full_run_routes(vp))
    transport = _StartRecorder(inner, now)
    code, _ = _run_full(
        vp, "--json", "--request-delay-ms", "50", transport=transport
    )
    capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    times = [t for _method, _path, t in transport.starts]
    _assert_min_gap(times, 0.05)
    present = {_vp4d_phase(method, path) for method, path, _t in transport.starts}
    for phase in ("rewards", "duties", "balances", "sync"):
        assert phase in present


def test_zero_delay_adds_no_measurable_overhead(vp, monkeypatch):
    now = _install_virtual_clock(vp, monkeypatch)
    slept = []
    inner_sleep = vp.time.sleep

    def sleep(seconds):
        slept.append(seconds)
        inner_sleep(seconds)

    monkeypatch.setattr(vp.time, "sleep", sleep)
    path = _VERSION_TEMPLATE

    def ok():
        return _raw(vp, 200)

    transport = FakeTransport({("GET", path): [ok, ok, ok, ok]})
    recorder = _StartRecorder(transport, now)
    client, _ = _client(vp, recorder, request_delay=0.0)
    for _ in range(4):
        client._call("GET", path, {}, None)
    times = [t for _method, _path, t in recorder.starts]
    assert times == [10.0, 10.0, 10.0, 10.0]
    assert slept == []
    assert vp._next_request_start == 0.0


def test_delay_does_not_stack_with_retry_backoff(vp, monkeypatch):
    # Frozen clock: a stacked delay+backoff would appear as a second sleep.
    clock = {"t": 10.0}
    monkeypatch.setattr(vp.time, "monotonic", lambda: clock["t"])
    slept = _no_sleep(monkeypatch, vp)
    vp._next_request_start = 0.0
    path = _SPEC_TEMPLATE
    transport = FakeTransport(
        {
            ("GET", path): [
                _raw(vp, 429, headers={"Retry-After": "1"}),
                _raw(vp, 200, b'{"data": true}'),
            ]
        }
    )
    client, _ = _client(vp, transport, request_delay=0.05)
    got = client._call("GET", path, {}, None)
    assert got == {"data": True}
    assert len(transport.calls) == 2
    assert slept == [1.0]


# ----- VP-5c: §9 pubkey→index cache keyed by genesis root -----

_MAINNET_GENESIS_ROOT = (
    "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
)
_STALE_CACHE_INDEX = 999999
_CHANGED_GENESIS_ROOT = (
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)


def _cache_file(xdg_cache_home, root=_MAINNET_GENESIS_ROOT):
    return (
        xdg_cache_home / "rvc-validator-perf" / f"indices-{root}.json"
    )


def _dup_routes(routes, n=2):
    return {key: list(queue) * n for key, queue in routes.items()}


def _cache_argv(*extra, pubkeys=(PK1,)):
    argv: list[str] = []
    for pk in pubkeys:
        argv.extend(["--pubkey", pk])
    argv.extend(
        ["--beacon-url", "https://bn.example:5052", "--dry-run", *extra]
    )
    return argv


def _run_cached(vp, *extra, pubkeys=(PK1,), routes=None, transport=None):
    if transport is None:
        transport = FakeTransport(routes or _dry_run_routes(vp))
    code = vp.main(_cache_argv(*extra, pubkeys=pubkeys), transport=transport)
    return code, transport


def _resolution_posts(calls):
    seq = calls.calls if hasattr(calls, "calls") else calls
    return [
        c
        for c in seq
        if c[1] == "POST" and c[2] == _VALIDATORS_PATH
    ]


def test_cache_hit_removes_exactly_one_request(vp, xdg_cache_home, capsys):
    argv = _full_argv("--json")
    transport = FakeTransport(_dup_routes(_full_run_routes(vp), 2))
    code1 = vp.main(argv, transport=transport)
    n1 = len(transport.calls)
    doc1, _captured = _stdout_json(capsys)
    assert _resolution_posts(transport.calls[:n1])
    code2 = vp.main(argv, transport=transport)
    doc2, _captured = _stdout_json(capsys)
    first, second = transport.calls[:n1], transport.calls[n1:]
    assert code1 == code2
    assert len(second) == n1 - 1
    first_keys = [(c[1], c[2]) for c in first]
    second_keys = [(c[1], c[2]) for c in second]
    removed = [key for key in first_keys if key not in second_keys]
    assert removed == [("POST", _VALIDATORS_PATH)]
    assert ("POST", _VALIDATORS_PATH) not in second_keys
    assert doc1["validators"] == doc2["validators"]
    assert doc1["exit_code"] == doc2["exit_code"]


def test_dry_run_cache_hit_prints_live_status_and_eb(
    vp, xdg_cache_home, capsys
):
    code, _t1 = _run_cached(vp, pubkeys=(PK1,))
    assert code == vp.EXIT_OK
    capsys.readouterr()
    code, transport = _run_cached(vp, pubkeys=(PK1,))
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK
    line = next(ln for ln in captured.out.splitlines() if PK1 in ln)
    assert "status=active_ongoing" in line
    assert "eb=32000000000" in line
    assert "status= " not in line
    assert "eb=None" not in line
    assert _resolution_posts(transport)


def test_changed_genesis_root_invalidates_the_cache(
    vp, xdg_cache_home, capsys
):
    dest = _cache_file(xdg_cache_home)
    dest.parent.mkdir(parents=True)
    dest.write_bytes(
        (FIXTURES / "cache__genesis_root_changed.json").read_bytes()
    )
    payload = json.loads(dest.read_text(encoding="utf-8"))
    assert payload["genesis_validators_root"] == _CHANGED_GENESIS_ROOT
    assert payload["genesis_validators_root"] != _MAINNET_GENESIS_ROOT
    assert payload["entries"][PK1] == _STALE_CACHE_INDEX
    code, transport = _run_cached(vp, pubkeys=(PK1,))
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK
    assert _resolution_posts(transport)
    text = captured.out + captured.err
    assert str(_STALE_CACHE_INDEX) not in text
    assert f"{PK1} index=1 " in captured.out


def test_cache_key_is_compared_not_merely_stored(
    vp, xdg_cache_home, capsys
):
    dest = _cache_file(xdg_cache_home, _MAINNET_GENESIS_ROOT)
    dest.parent.mkdir(parents=True)
    dest.write_text(
        json.dumps(
            {
                "genesis_validators_root": _CHANGED_GENESIS_ROOT,
                "written_at": "2020-12-01T12:00:23+00:00",
                "entries": {PK1: _STALE_CACHE_INDEX},
            }
        ),
        encoding="utf-8",
    )
    assert dest.name == f"indices-{_MAINNET_GENESIS_ROOT}.json"
    # Filename matches the live root; the stored root does not — miss.
    got = vp._cache_read(_MAINNET_GENESIS_ROOT, [PK1], None)
    assert got is None
    code, transport = _run_cached(vp, pubkeys=(PK1,))
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK
    assert _resolution_posts(transport)
    assert str(_STALE_CACHE_INDEX) not in captured.out
    assert f"{PK1} index=1 " in captured.out


def test_partial_hit_falls_back_to_a_full_resolve(
    vp, xdg_cache_home, capsys
):
    code, _t1 = _run_cached(vp, pubkeys=(PK1,))
    assert code == vp.EXIT_OK
    capsys.readouterr()
    cached = json.loads(
        _cache_file(xdg_cache_home).read_text(encoding="utf-8")
    )
    assert PK1 in cached["entries"]
    assert PK2 not in cached["entries"]
    code, transport = _run_cached(vp, pubkeys=(PK1, PK2))
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK
    posts = _resolution_posts(transport)
    assert len(posts) == 1
    assert json.loads(posts[0][3]) == {"ids": [PK1, PK2]}
    assert f"{PK1} index=1 " in captured.out
    assert f"{PK2} index=2 " in captured.out


def test_only_the_index_is_cached(vp, xdg_cache_home, capsys):
    code, _transport = _run_cached(vp, pubkeys=(PK1, PK2, PK3))
    capsys.readouterr()
    assert code == vp.EXIT_OK
    raw = _cache_file(xdg_cache_home).read_text(encoding="utf-8")
    data = json.loads(raw)
    assert data["genesis_validators_root"] == _MAINNET_GENESIS_ROOT
    assert "written_at" in data
    assert data["entries"] == {PK1: 1, PK2: 2, PK3: 3}
    assert "status" not in raw
    assert "effective_balance" not in raw
    assert "activation_epoch" not in raw
    for value in data["entries"].values():
        assert type(value) is int


def test_malformed_cache_is_a_miss_not_an_error(
    vp, xdg_cache_home, capsys
):
    dest = _cache_file(xdg_cache_home)
    dest.parent.mkdir(parents=True)
    for body in ("{", "[", "null", '{"entries": []}', "not-json"):
        dest.write_text(body, encoding="utf-8")
        code, transport = _run_cached(vp, "-v", pubkeys=(PK1,))
        captured = capsys.readouterr()
        assert code == vp.EXIT_OK
        assert "Traceback" not in captured.out
        assert "Traceback" not in captured.err
        assert _resolution_posts(transport)


def test_unwritable_cache_dir_does_not_fail_the_run(
    vp, tmp_path, monkeypatch, capsys
):
    blocked = tmp_path / "blocked-cache"
    blocked.mkdir()
    blocked.chmod(0o500)
    monkeypatch.setenv("XDG_CACHE_HOME", str(blocked))
    try:
        code, transport = _run_cached(vp, "-v", pubkeys=(PK1,))
    finally:
        blocked.chmod(0o700)
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK
    assert "Traceback" not in captured.out
    assert _resolution_posts(transport)


def test_cache_written_atomically(vp, xdg_cache_home, monkeypatch, capsys):
    seen: list[tuple[str, str, bool, bool]] = []
    real_replace = vp.os.replace

    def spy(src, dst):
        seen.append(
            (str(src), str(dst), os.path.exists(src), os.path.exists(dst))
        )
        return real_replace(src, dst)

    monkeypatch.setattr(vp.os, "replace", spy)
    code, _transport = _run_cached(vp, pubkeys=(PK1,))
    capsys.readouterr()
    assert code == vp.EXIT_OK
    dest = _cache_file(xdg_cache_home)
    assert seen
    src, dst, src_exists, dst_existed = seen[0]
    assert src_exists is True
    assert dst == str(dest)
    assert src != dst
    assert dst_existed is False
    assert not src.endswith(os.path.basename(dst) + ".tmp")
    assert os.path.basename(src).startswith("idx.")
    assert json.loads(dest.read_text(encoding="utf-8"))["entries"][PK1] == 1
    mode = dest.parent.stat().st_mode & 0o777
    assert mode == 0o700


def test_no_cache_file_inside_the_repo(vp, tmp_path, monkeypatch, capsys):
    repo = SCRIPT.resolve().parent.parent
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    before = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo,
    )
    code, _transport = _run_cached(vp, pubkeys=(PK1,))
    capsys.readouterr()
    assert code == vp.EXIT_OK
    after = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo,
    )
    added = set(after.splitlines()) - set(before.splitlines())
    assert not any(b"indices-" in line for line in added)
    stray = [
        path
        for path in (repo / "scripts").rglob("indices-*.json")
        if "xdg-cache" not in path.parts
    ]
    assert stray == []
    fallback = tmp_path / "home" / ".cache" / "rvc-validator-perf"
    written = list(fallback.glob("indices-*.json"))
    assert written


def test_no_cache_flag_disables_read_and_write(
    vp, xdg_cache_home, capsys
):
    dest = _cache_file(xdg_cache_home)
    dest.parent.mkdir(parents=True)
    stale = {
        "genesis_validators_root": _MAINNET_GENESIS_ROOT,
        "written_at": "2020-12-01T12:00:23+00:00",
        "entries": {PK1: _STALE_CACHE_INDEX},
    }
    dest.write_text(json.dumps(stale), encoding="utf-8")
    before = dest.read_text(encoding="utf-8")
    code, transport = _run_cached(vp, "--no-cache", pubkeys=(PK1,))
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK
    assert _resolution_posts(transport)
    assert dest.read_text(encoding="utf-8") == before
    assert str(_STALE_CACHE_INDEX) not in captured.out
    assert f"{PK1} index=1 " in captured.out
    # Write is disabled on a miss too.
    dest.unlink()
    code, _transport = _run_cached(vp, "--no-cache", pubkeys=(PK1,))
    capsys.readouterr()
    assert code == vp.EXIT_OK
    assert not dest.exists()


def test_cache_write_unions_existing_entries(vp, xdg_cache_home, capsys):
    code, _t1 = _run_cached(vp, pubkeys=(PK1,))
    assert code == vp.EXIT_OK
    capsys.readouterr()
    code, transport = _run_cached(vp, pubkeys=(PK2,))
    capsys.readouterr()
    assert code == vp.EXIT_OK
    assert _resolution_posts(transport)
    data = json.loads(_cache_file(xdg_cache_home).read_text(encoding="utf-8"))
    assert data["entries"][PK1] == 1
    assert data["entries"][PK2] == 2


def test_relative_xdg_cache_home_is_treated_as_unset(
    vp, tmp_path, monkeypatch, capsys
):
    repo = SCRIPT.resolve().parent.parent
    monkeypatch.setenv("XDG_CACHE_HOME", "relative-cache")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    code, _transport = _run_cached(vp, pubkeys=(PK1,))
    capsys.readouterr()
    assert code == vp.EXIT_OK
    assert not (repo / "relative-cache").exists()
    written = list(
        (tmp_path / "home" / ".cache" / "rvc-validator-perf").glob(
            "indices-*.json"
        )
    )
    assert written


def test_non_hex_genesis_root_is_a_cache_miss(vp, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))
    assert vp._cache_path("mainnet") is None
    assert vp._cache_path("../0x" + "aa" * 32) is None
    assert vp._cache_path("0x" + "aa" * 31) is None
    assert vp._cache_read("mainnet", [PK1], None) is None
    assert vp._cache_read("0x" + "aa" * 32 + "/../x", [PK1], None) is None
    vp._cache_write("not-a-root", {PK1: 1}, None)
    assert list((tmp_path / "xdg").rglob("*.json")) == []


# ----- VP-5a: §15 render_csv — same fields as validators[] (P2-1) -----

# Hand-written full JSON validator leaf list (in-committee sync.*). Drift
# against the renderer is the failure this test exists for.
_HANDWRITTEN_CSV_FIELDS = (
    "pubkey",
    "index",
    "status",
    "active_epochs",
    "participation_rate",
    "source_rate",
    "target_rate",
    "head_rate",
    "missed_attestations",
    "attester_effectiveness",
    "effectiveness_method",
    "leak_epochs_excluded",
    "proposals.scheduled",
    "proposals.included",
    "proposals.missed",
    "sync.in_committee",
    "sync.participation_rate",
    "sync.slots_eligible",
    "sync.slots_signed",
    "sync.reward_gwei",
    "balance.start_gwei",
    "balance.end_gwei",
    "balance.delta_gwei",
    "balance.effective_balance_gwei",
    "balance.effective_balance_changed",
    "balance.start_slot",
    "balance.end_slot",
    "balance.reconciliation",
    "rewards_gwei.source",
    "rewards_gwei.target",
    "rewards_gwei.head",
    "rewards_gwei.inactivity",
    "rewards_gwei.proposer",
    "rewards_gwei.sync",
    "rewards_gwei.total",
    "estimated_apr",
    "reward_source",
    "degradations",
    "threshold_breaches",
)


def _flatten_json(d, prefix=""):
    if not isinstance(d, dict):
        return {prefix: d} if prefix else {}
    out = {}
    for key, value in d.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            out.update(_flatten_json(value, path))
        else:
            out[path] = value
    return out


def _write_csv(vp, run, tmp_path, name="out.csv"):
    path = tmp_path / name
    vp.render_csv(run, str(path))
    return path


def _csv_rows(path: Path):
    with path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return reader.fieldnames, list(reader)


def test_csv_columns_match_the_json_validator_fields(vp, load, tmp_path):
    run = _table_run(vp, load, _golden_reports(vp))
    header, _rows = _csv_rows(_write_csv(vp, run, tmp_path))
    complete = next(
        row
        for row in json.loads(vp.render_json(run))["validators"]
        if isinstance(row.get("sync"), dict)
    )
    json_keys = set(_flatten_json(complete))
    assert set(header) == json_keys
    assert json_keys == set(_HANDWRITTEN_CSV_FIELDS)
    assert "sync" not in header


def test_csv_null_renders_empty_never_zero(vp, load, tmp_path):
    report = _table_report(
        vp,
        ref=_active_ref(vp, index=7, pubkey=PK1),
        head_rate=None,
        missed_attestations=0,
    )
    _header, rows = _csv_rows(
        _write_csv(vp, _table_run(vp, load, [report]), tmp_path)
    )
    cell = rows[0]["head_rate"]
    assert cell == ""
    assert "0" not in cell
    assert rows[0]["missed_attestations"] == "0"


def test_csv_golden_matches(vp, load, tmp_path):
    run = _table_run(vp, load, _golden_reports(vp))
    text = _write_csv(vp, run, tmp_path).read_text(encoding="utf-8")
    expected = (FIXTURES / "csv__golden.csv").read_text(encoding="utf-8")
    assert text == expected


def test_csv_header_stable_when_unknown_is_first(vp, load, tmp_path):
    unknown = _table_report(
        vp,
        ref=vp._unknown_ref(PK1),
        active_epochs=0,
        participation_rate=None,
        source_rate=None,
        target_rate=None,
        head_rate=None,
        missed_attestations=None,
        attester_effectiveness=None,
        estimated_apr=None,
        reward_source=None,
        balance=vp.BalanceSnapshot(None, None, None, None),
    )
    outsider = _table_report(
        vp, ref=_active_ref(vp, index=2, pubkey=PK2)
    )
    member = _table_report(
        vp,
        ref=_active_ref(vp, index=3, pubkey=PK3),
        sync=vp.SyncOutcome(True, 32, 16, 0),
    )
    run = _table_run(vp, load, [unknown, outsider, member])
    header, rows = _csv_rows(_write_csv(vp, run, tmp_path))
    for name in (
        "sync.in_committee",
        "sync.participation_rate",
        "sync.slots_eligible",
        "sync.slots_signed",
        "sync.reward_gwei",
    ):
        assert name in header
    assert "sync" not in header
    assert len(rows) == 3
    assert rows[0]["index"] == ""
    assert rows[0]["sync.in_committee"] == ""
    assert rows[1]["sync.in_committee"] == ""
    assert rows[2]["sync.in_committee"] == "true"
    assert rows[2]["sync.participation_rate"] == "0.5"


def test_one_row_per_validator_including_unknown_keys(vp, load, tmp_path):
    known = _table_report(vp, ref=_active_ref(vp, index=1, pubkey=PK1))
    unknown = _table_report(
        vp,
        ref=vp._unknown_ref(PK2),
        active_epochs=0,
        participation_rate=None,
        source_rate=None,
        target_rate=None,
        head_rate=None,
        missed_attestations=None,
        attester_effectiveness=None,
        estimated_apr=None,
        reward_source=None,
        balance=vp.BalanceSnapshot(None, None, None, None),
    )
    run = _table_run(vp, load, [known, unknown])
    _header, rows = _csv_rows(_write_csv(vp, run, tmp_path))
    assert len(rows) == len(run.validators) == 2
    assert rows[1]["status"] == "unknown"
    assert rows[1]["index"] == ""
    assert rows[0]["index"] == "1"


def test_csv_and_json_together_are_legal(vp, tmp_path, capsys):
    dest = tmp_path / "together.csv"
    code, _transport = _run_full(vp, "--json", "--csv", str(dest))
    assert code == vp.EXIT_OK
    doc, captured = _stdout_json(capsys)
    assert dest.is_file()
    header, rows = _csv_rows(dest)
    assert header
    assert len(rows) == len(doc["validators"])
    assert "DEGRADED:" not in captured.out
    assert dest.read_text(encoding="utf-8") not in captured.out


def test_csv_written_only_to_the_named_path(vp, tmp_path, capsys):
    repo = SCRIPT.resolve().parent.parent
    dest = tmp_path / "operator-named.csv"
    before = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo,
    )
    before_csv = {p for p in (repo / "scripts").rglob("*.csv")}
    code, _transport = _run_full(vp, "--csv", str(dest))
    capsys.readouterr()
    assert code == vp.EXIT_OK
    assert dest.is_file()
    after = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=repo,
    )
    added = set(after.splitlines()) - set(before.splitlines())
    assert added == set()
    after_csv = {p for p in (repo / "scripts").rglob("*.csv")}
    assert after_csv == before_csv
    assert dest.resolve() not in after_csv


def test_degradations_column_documented_as_a_summary(vp, load, tmp_path):
    doc = inspect.getdoc(vp.render_csv)
    assert doc is not None
    lower = doc.lower()
    assert "summary" in lower
    assert "json" in lower
    assert "authoritative" in lower
    deg = vp.Degradation(
        "head_rate", "epoch:100", "inactivity_leak", "full leak detail"
    )
    extra = vp.Degradation(
        "balance", "validator:1", "state_unavailable", "slot missing"
    )
    report = _table_report(vp, degradations=[deg, extra])
    _header, rows = _csv_rows(
        _write_csv(vp, _table_run(vp, load, [report]), tmp_path)
    )
    assert (
        rows[0]["degradations"]
        == "inactivity_leak@epoch:100;state_unavailable@validator:1"
    )
    assert "full leak detail" not in rows[0]["degradations"]
    assert "slot missing" not in rows[0]["degradations"]


def test_csv_quotes_fields_containing_separators(vp, load, tmp_path):
    report = _table_report(
        vp,
        ref=_active_ref(vp, index=1, pubkey=PK1, status="active,ongoing"),
    )
    path = _write_csv(vp, _table_run(vp, load, [report]), tmp_path)
    text = path.read_text(encoding="utf-8")
    assert '"active,ongoing"' in text
    _header, rows = _csv_rows(path)
    assert rows[0]["status"] == "active,ongoing"


# ----- VP-4e: --liveness-check opt-in, distinct field (P1-2, RD-6) -----

_LIVENESS_HEAD = _DRY_RUN_HEAD_EPOCH  # 101 from headers__head
_LIVENESS_PREV = _LIVENESS_HEAD - 1


def _liveness_path(epoch: int) -> str:
    return f"/eth/v1/validator/liveness/{epoch}"


def _script_liveness(vp, routes, item=None, *, status=200):
    if item is None:
        item = (
            raw_response(vp, "liveness__head_window")
            if status == 200
            else _raw(vp, status, headers={"Retry-After": "0"})
        )
    n = 2 if status == 500 else 1
    queue = [item] * n
    for epoch in (_LIVENESS_HEAD, _LIVENESS_PREV):
        routes[("POST", _liveness_path(epoch))] = list(queue)
    return routes


def _liveness_calls(transport):
    return [
        c
        for c in transport.calls
        if c[1] == "POST" and "/validator/liveness/" in c[2]
    ]


def test_no_liveness_request_without_the_flag(vp, capsys):
    routes = _script_liveness(vp, _full_run_routes(vp))
    code, transport = _run_full(vp, "--json", routes=routes)
    capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    assert _liveness_calls(transport) == []
    assert not any("liveness" in c[2] for c in transport.calls)

    routes = _script_liveness(vp, _rewards_less_routes(vp))
    code, transport = _run_full(vp, "--json", routes=routes)
    doc, _captured = _stdout_json(capsys)
    assert code == vp.EXIT_DEGRADED == 3
    assert _liveness_calls(transport) == []
    assert not any("liveness" in c[2] for c in transport.calls)
    assert doc["validators"][0]["participation_rate"] is None
    assert "liveness_sanity" not in doc["validators"][0]


def test_liveness_check_flag_issues_the_request(vp, capsys):
    routes = _script_liveness(vp, _full_run_routes(vp))
    code, transport = _run_full(
        vp, "--json", "--liveness-check", routes=routes
    )
    doc, _captured = _stdout_json(capsys)
    assert code == vp.EXIT_OK == 0
    calls = _liveness_calls(transport)
    assert calls
    paths = [c[2] for c in calls]
    assert _liveness_path(_LIVENESS_HEAD) in paths
    assert _liveness_path(_LIVENESS_PREV) in paths
    row = doc["validators"][0]
    assert "liveness_sanity" in row
    assert row["liveness_sanity"] == [
        {"epoch": _LIVENESS_HEAD, "observed": True},
        {"epoch": _LIVENESS_PREV, "observed": True},
    ]
    validate_schema(doc, _load_perf_schema())


def test_liveness_reported_under_a_distinct_field_never_merged_into_m1(
    vp, capsys
):
    routes = _script_liveness(vp, _rewards_less_routes(vp))
    code, transport = _run_full(
        vp, "--json", "--liveness-check", routes=routes
    )
    doc, _captured = _stdout_json(capsys)
    assert code == vp.EXIT_DEGRADED == 3
    row = doc["validators"][0]
    assert row["participation_rate"] is None
    assert row["missed_attestations"] is None
    assert "liveness_sanity" in row
    assert row["liveness_sanity"] is not None
    assert row["liveness_sanity"] != row["participation_rate"]
    src = inspect.getsource(vp.build_validator_report)
    assert "liveness" not in src
    assert _liveness_calls(transport)


def test_liveness_covers_current_and_previous_epoch_only(vp, capsys):
    routes = _script_liveness(vp, _full_run_routes(vp))
    _code, transport = _run_full(
        vp, "--json", "--liveness-check", routes=routes
    )
    capsys.readouterr()
    epochs = [
        int(c[2].rsplit("/", 1)[-1]) for c in _liveness_calls(transport)
    ]
    assert epochs == [_LIVENESS_HEAD, _LIVENESS_PREV]
    assert len(epochs) == 2
    assert len(epochs) != 32
    assert _FULL_FROM not in epochs
    src = inspect.getsource(vp._liveness_epochs) + inspect.getsource(
        vp.collect_liveness
    )
    assert "head_epoch" in src
    assert "head_epoch - 1" in src


def test_teku_400_and_grandine_500_report_unavailable_without_degrading_the_run(
    vp, capsys, monkeypatch
):
    _no_sleep(monkeypatch, vp)
    cases = (
        (400, "teku/v26.8.0", "Teku"),
        (500, "Grandine/2.0.6", "Grandine"),
    )
    for status, version, name in cases:
        routes = _full_run_routes(vp)
        routes[("GET", _VERSION_TEMPLATE)] = [
            _raw(
                vp,
                200,
                json.dumps({"data": {"version": version}}).encode(),
            )
        ]
        _script_liveness(vp, routes, status=status)
        code, transport = _run_full(
            vp, "--json", "--liveness-check", routes=routes
        )
        doc, captured = _stdout_json(capsys)
        assert code == vp.EXIT_OK == 0, name
        assert doc["exit_code"] == 0, name
        assert doc["degradations"] == [], name
        assert _liveness_calls(transport), name
        row = doc["validators"][0]
        assert row["liveness_sanity"] is None, name
        assert row["participation_rate"] is not None, name
        blob = captured.err + captured.out
        assert name in blob, name
        assert "unavailable" in blob.lower(), name

    routes = _script_liveness(vp, _rewards_less_routes(vp), status=400)
    code, _transport = _run_full(
        vp, "--json", "--liveness-check", routes=routes
    )
    doc, _captured = _stdout_json(capsys)
    assert code == vp.EXIT_DEGRADED == 3
    assert doc["exit_code"] == 3
    assert doc["validators"][0]["liveness_sanity"] is None
    assert doc["validators"][0]["participation_rate"] is None
    assert not any("liveness" in d["reason"] for d in doc["degradations"])


def test_liveness_cause_versions_first_status_is_fallback_only(vp):
    assert "Teku" in vp._liveness_cause(500, "teku/v26.8.0")
    assert "Grandine" in vp._liveness_cause(400, "Grandine/2.0.6")
    lighthouse_400 = vp._liveness_cause(400, "Lighthouse/v5.3.0")
    lighthouse_500 = vp._liveness_cause(500, "Lighthouse/v5.3.0")
    assert "Teku" not in lighthouse_400
    assert "Grandine" not in lighthouse_500
    assert "HTTP 400" in lighthouse_400
    assert "HTTP 500" in lighthouse_500
    assert "Teku" in vp._liveness_cause(400, "")
    assert "Grandine" in vp._liveness_cause(500, "")


def test_liveness_missing_index_is_null_int_index_and_is_live_false(vp):
    head = 10
    body = json.dumps(
        {
            "data": [
                {"index": 1, "is_live": True},
                {"index": "2", "is_live": False},
            ]
        }
    ).encode()
    ok = _raw(vp, 200, body)
    transport = FakeTransport(
        {
            ("POST", _liveness_path(head)): [ok],
            ("POST", _liveness_path(head - 1)): [ok],
        }
    )
    client, _buf = _client(vp, transport)
    by_index, cause = vp.collect_liveness(
        client, head, ["1", "2", "3"], "Lighthouse/v5.3.0"
    )
    assert cause is None
    assert by_index[1] == [
        {"epoch": head, "observed": True},
        {"epoch": head - 1, "observed": True},
    ]
    assert by_index[2] == [
        {"epoch": head, "observed": False},
        {"epoch": head - 1, "observed": False},
    ]
    assert by_index[3] == [
        {"epoch": head, "observed": None},
        {"epoch": head - 1, "observed": None},
    ]
    assert by_index[3][0]["observed"] is not False


def test_liveness_footnote_states_what_it_does_not_mean(vp, load, capsys):
    run = replace(
        _table_run(vp, load, _golden_reports(vp)),
        liveness_checked=True,
    )
    text = _render_table(vp, run)
    assert vp._LIVENESS_FOOTNOTE in text
    lower = text.lower()
    assert "does not mean" in lower
    assert "included on chain" in lower
    assert "not canonical" in lower
    assert "not participation_rate" in lower
    routes = _script_liveness(vp, _full_run_routes(vp))
    code, _transport = _run_full(vp, "--liveness-check", routes=routes)
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    assert vp._LIVENESS_FOOTNOTE in captured.out
    assert "does not mean" in captured.out.lower()


# ----- VP-4f: P1-5 — -q prints nothing on a healthy run -----


def test_quiet_healthy_run_prints_nothing_on_stderr(vp, capsys):
    code, transport = _run_full(vp, "-q")
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    assert transport.calls
    assert captured.err == ""


def test_quiet_still_prints_errors(vp, capsys):
    code = vp.main(["-q"])
    captured = capsys.readouterr()
    assert code == vp.EXIT_USAGE == 2
    assert captured.err.strip() != ""
    assert "pubkey" in captured.err.lower()

    transport = FakeTransport({("GET", _VERSION_TEMPLATE): [_raw(vp, 404)]})
    code = vp.main(_full_argv("-q"), transport=transport)
    captured = capsys.readouterr()
    assert code == vp.EXIT_NO_BEACON == 5
    assert captured.err.strip() != ""
    assert "https://" not in captured.err


def test_quiet_does_not_suppress_stdout(vp, capsys):
    code, _transport = _run_full(vp, "-q")
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    assert captured.err == ""
    assert "pubkey" in captured.out
    assert captured.out.strip() != ""

    code, _transport = _run_full(vp, "-q", "--json")
    doc, captured = _stdout_json(capsys)
    assert code == vp.EXIT_OK == 0
    assert captured.err == ""
    assert doc["exit_code"] == 0
    assert doc["validators"]


def test_verbose_adds_per_request_diagnostics_still_redacted(vp, capsys):
    code, _transport = _run_full(vp, "-v", "--json", url=_SECRET_URL)
    captured = capsys.readouterr()
    assert code == vp.EXIT_OK == 0
    err = captured.err
    assert _SPEC_TEMPLATE in err
    assert _VERSION_TEMPLATE in err
    assert _REWARDS_TEMPLATE in err
    assert _REWARDS_TEMPLATE.format(epoch=_FULL_FROM) not in err
    assert f"via {vp.redact(vp.parse_endpoint(_SECRET_URL, 'bn0'))}" in err
    assert "https://bn.example:5052" in err
    text = captured.out + err
    assert "secret" not in text
    assert "abc123SECRET" not in text


def test_vv_is_accepted_and_more_verbose_than_v(vp, capsys):
    assert vp.build_options(_minimal_opts_argv("-vv")).verbosity == 2
    assert (
        vp.build_options(_minimal_opts_argv("-vv")).verbosity
        > vp.build_options(_minimal_opts_argv("-v")).verbosity
    )
    code_default, _transport = _run_full(vp, "--json")
    default_err = capsys.readouterr().err
    code_v, _transport = _run_full(vp, "-v", "--json")
    v_err = capsys.readouterr().err
    code_vv, _transport = _run_full(vp, "-vv", "--json")
    vv_err = capsys.readouterr().err
    assert code_default == code_v == code_vv == vp.EXIT_OK == 0
    assert len(v_err) > len(default_err)
    assert len(vv_err) >= len(v_err)
    assert _SPEC_TEMPLATE in v_err
    assert _SPEC_TEMPLATE in vv_err
    assert vv_err.count(_SPEC_TEMPLATE) >= v_err.count(_SPEC_TEMPLATE)


def test_csv_neutralizes_formula_injection(vp, load, tmp_path):
    for raw in ("=cmd|'/C calc'!A0", "+1+1", "-1+1", "@SUM(A1)"):
        report = _table_report(
            vp,
            ref=_active_ref(vp, index=1, pubkey=PK1, status=raw),
        )
        path = _write_csv(vp, _table_run(vp, load, [report]), tmp_path)
        text = path.read_text(encoding="utf-8")
        _header, rows = _csv_rows(path)
        assert rows[0]["status"] == "'" + raw
        assert "'" + raw in text
    rewards = _rewards_gwei(0)
    rewards["inactivity"] = -100
    numeric = _table_report(vp, rewards_gwei=rewards)
    _header, rows = _csv_rows(
        _write_csv(vp, _table_run(vp, load, [numeric]), tmp_path)
    )
    assert rows[0]["rewards_gwei.inactivity"] == "-100"


# ----- VP-5b: §15 Prometheus exposition + --prometheus flag (P2-2) -----

_PROM_NOW = datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc)
_PROM_SAMPLE = re.compile(
    r"^[a-zA-Z_:][a-zA-Z0-9_:]*\{"
    r'(?:[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*"'
    r'(?:,[a-zA-Z_][a-zA-Z0-9_]*="(?:[^"\\]|\\.)*")*)?'
    r"\} [+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?$"
)
_PROM_TYPE = re.compile(
    r"^# TYPE ([a-zA-Z_:][a-zA-Z0-9_:]*) "
    r"(counter|gauge|untyped|histogram|summary)$"
)


def _write_prom(vp, run, tmp_path, name="out.prom", clock=None):
    path = tmp_path / name
    vp.render_prometheus(
        run, str(path), clock=clock or (lambda: _PROM_NOW)
    )
    return path


def test_null_metrics_are_omitted_not_zero(vp, load, tmp_path):
    report = _table_report(
        vp,
        ref=_active_ref(vp, index=7, pubkey=PK1),
        head_rate=None,
        missed_attestations=0,
    )
    text = _write_prom(vp, _table_run(vp, load, [report]), tmp_path).read_text(
        encoding="utf-8"
    )
    abbrev = vp._abbrev_pubkey(PK1)
    assert vp._emit("rvc_validator_perf_head_rate", None, {"pubkey": abbrev}) is None
    assert "rvc_validator_perf_head_rate" not in text
    assert re.search(r"head_rate.*0$", text, re.M) is None
    assert "rvc_validator_perf_missed_attestations_total{" in text
    assert re.search(
        r"rvc_validator_perf_missed_attestations_total\{[^}]*pubkey=\""
        + re.escape(abbrev)
        + r"\"[^}]*\} 0$",
        text,
        re.M,
    )
    zero = _table_report(
        vp,
        ref=_active_ref(vp, index=8, pubkey=PK2),
        head_rate=0.0,
    )
    zero_text = _write_prom(
        vp, _table_run(vp, load, [zero]), tmp_path, name="zero.prom"
    ).read_text(encoding="utf-8")
    assert "rvc_validator_perf_head_rate{" in zero_text
    assert re.search(r"rvc_validator_perf_head_rate\{[^}]*\} 0(\.0)?$", zero_text, re.M)


def test_exposition_parses(vp, load, tmp_path):
    text = _write_prom(
        vp, _table_run(vp, load, _golden_reports(vp)), tmp_path
    ).read_text(encoding="utf-8")
    typed = None
    families: list[str] = []
    for line in text.splitlines():
        type_match = _PROM_TYPE.match(line)
        if type_match:
            typed = type_match.group(1)
            families.append(typed)
            continue
        if not line or line.startswith("#"):
            continue
        assert _PROM_SAMPLE.match(line), line
        name = line.split("{", 1)[0]
        assert typed == name
    assert families
    assert len(families) == len(set(families))
    for name in families:
        if name.endswith("_total"):
            assert f"# TYPE {name} gauge" in text
        pos_type = text.index(f"# TYPE {name} ")
        pos_sample = text.index(f"{name}{{")
        assert pos_type < pos_sample


def test_prometheus_golden_matches(vp, load, tmp_path):
    text = _write_prom(
        vp, _table_run(vp, load, _golden_reports(vp)), tmp_path
    ).read_text(encoding="utf-8")
    expected = (FIXTURES / "prometheus__golden.prom").read_text(encoding="utf-8")
    assert text == expected


def test_written_atomically_via_os_replace(vp, tmp_path, monkeypatch, capsys):
    dest = tmp_path / "metrics.prom"
    seen: list[tuple[str, str, bool, bool, int | None]] = []
    real_replace = vp.os.replace

    def spy(src, dst):
        src_mode = os.stat(src).st_mode & 0o777 if os.path.exists(src) else None
        seen.append(
            (
                str(src),
                str(dst),
                os.path.exists(src),
                os.path.exists(dst),
                src_mode,
            )
        )
        return real_replace(src, dst)

    monkeypatch.setattr(vp.os, "replace", spy)
    code, _transport = _run_full(vp, "--no-cache", "--prometheus", str(dest))
    capsys.readouterr()
    assert code == vp.EXIT_OK
    assert dest.is_file()
    hits = [item for item in seen if item[1] == str(dest)]
    assert hits
    src, dst, src_exists, dst_existed, src_mode = hits[0]
    assert src_exists is True
    assert dst == str(dest)
    assert src != dst
    assert dst_existed is False
    assert not src.endswith(os.path.basename(dst) + ".tmp")
    assert os.path.basename(src).startswith("prom.")
    assert os.path.dirname(src) == os.path.dirname(dst)
    assert src_mode == 0o644
    assert dest.stat().st_mode & 0o777 == 0o644


def test_pubkey_label_is_abbreviated(vp, load, tmp_path):
    assert len(_PK_DOC) == 2 + 96
    report = _table_report(vp, ref=_active_ref(vp, index=1234, pubkey=_PK_DOC))
    text = _write_prom(vp, _table_run(vp, load, [report]), tmp_path).read_text(
        encoding="utf-8"
    )
    assert _PK_DOC not in text
    assert 'pubkey="0x9324…a6d3"' in text


def test_no_beacon_url_or_secret_in_any_label(vp, load, tmp_path):
    run = _json_run(vp, load, endpoints_used=[_SECRET_URL])
    text = _write_prom(vp, run, tmp_path).read_text(encoding="utf-8")
    assert vp._prom_escape('a\r\n"\\') == r'a\r\n\"\\'
    assert "secret" not in text
    assert "abc123SECRET" not in text
    assert "user:" not in text
    assert "http://" not in text
    assert "https://" not in text
    for line in text.splitlines():
        if not line or line.startswith("#") or "{" not in line:
            continue
        labels = line.split("{", 1)[1].rsplit("}", 1)[0]
        assert "bn.example" not in labels
        assert "5052" not in labels
        assert "/eth/" not in labels


def test_degradations_total_emitted_per_reason(vp, load, tmp_path):
    leak = vp.Degradation("head_rate", "epoch:100", "inactivity_leak", "leak")
    leak2 = vp.Degradation("head_rate", "epoch:101", "inactivity_leak", "leak")
    missing = vp.Degradation(
        "attester_effectiveness", "epoch:102", "ideal_row_missing", ""
    )
    run = replace(
        _table_run(vp, load, [_table_report(vp)]),
        degradations=[leak, leak2, missing],
    )
    text = _write_prom(vp, run, tmp_path).read_text(encoding="utf-8")
    assert "# TYPE rvc_validator_perf_degradations_total gauge" in text
    assert re.search(
        r'rvc_validator_perf_degradations_total\{reason="ideal_row_missing"\} 1$',
        text,
        re.M,
    )
    assert re.search(
        r'rvc_validator_perf_degradations_total\{reason="inactivity_leak"\} 2$',
        text,
        re.M,
    )
    assert "rewards_api_unsupported" not in text
    assert "state_unavailable" not in text


def test_exit_code_and_generated_timestamp_emitted(vp, load, tmp_path):
    run = replace(_table_run(vp, load, [_table_report(vp)]), exit_code=3)
    text = _write_prom(vp, run, tmp_path).read_text(encoding="utf-8")
    assert re.search(r"rvc_validator_perf_run_exit_code\{\} 3$", text, re.M)
    ts = int(_PROM_NOW.timestamp())
    assert re.search(
        r"rvc_validator_perf_run_generated_timestamp_seconds\{\} "
        + str(ts)
        + r"$",
        text,
        re.M,
    )


def test_prometheus_flag_present_in_the_parser(vp):
    parser = vp.build_parser()
    names = {opt for action in parser._actions for opt in action.option_strings}
    dests = {action.dest: action for action in parser._actions}
    assert "--prometheus" in names
    assert dests["prometheus"].option_strings == ["--prometheus"]
    opts = vp.build_options(_minimal_opts_argv("--prometheus", "/tmp/out.prom"))
    assert opts.prometheus == "/tmp/out.prom"
    assert vp.build_options(_minimal_opts_argv()).prometheus is None


