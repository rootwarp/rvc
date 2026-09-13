"""Tests for scripts/devnet_preflight.py.

Pytest prepends this directory, not scripts/, so the script is loaded by path.
HTTP is stubbed; pytest-socket (conftest autouse) blocks live sockets.
"""

from __future__ import annotations

import ast
import importlib.util
import json
import socket
import sys
from pathlib import Path

import pytest
from pytest_socket import SocketBlockedError

from conftest import FakeTransport

SCRIPT = Path(__file__).resolve().parents[1] / "devnet_preflight.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
CONFIG = FIXTURES / "preflight__config.yaml"

BN0 = "http://127.0.0.1:5052"
BN1 = "http://127.0.0.1:5053"

SPEC_DATA = {
    "GLOAS_FORK_EPOCH": "70",
    "GLOAS_FORK_VERSION": "0x08000000",
    "SLOT_DURATION_MS": "12000",
    "ATTESTATION_DUE_BPS": "3333",
    "AGGREGATE_DUE_BPS": "6667",
    "SYNC_MESSAGE_DUE_BPS": "3333",
    "CONTRIBUTION_DUE_BPS": "6667",
    "ATTESTATION_DUE_BPS_GLOAS": "2500",
    "AGGREGATE_DUE_BPS_GLOAS": "6667",
    "SYNC_MESSAGE_DUE_BPS_GLOAS": "2500",
    "CONTRIBUTION_DUE_BPS_GLOAS": "5000",
    "PAYLOAD_DUE_BPS": "5000",
    "PAYLOAD_ATTESTATION_DUE_BPS": "7500",
}

GENESIS_DATA = {
    "genesis_time": "1710000000",
    "genesis_validators_root": (
        "0xabababababababababababababababababababababababababababababababab"
    ),
    "genesis_fork_version": "0x10000000",
}

GVR_A = GENESIS_DATA["genesis_validators_root"]
GVR_B = "0x" + "cd" * 32

VERSION_LH = "Lighthouse/v5.3.0-aa11a3b"
VERSION_TEKU = "Teku/v24.10.0"


def _raw(dp, data, status=200):
    return dp.RawResponse(status, json.dumps({"data": data}).encode(), False)


def _version_raw(dp, version, status=200):
    return dp.RawResponse(
        status, json.dumps({"data": {"version": version}}).encode(), False
    )


def _routes(
    dp,
    *,
    spec=None,
    genesis=None,
    version=VERSION_LH,
    bn="bn0",
):
    spec = SPEC_DATA if spec is None else spec
    genesis = GENESIS_DATA if genesis is None else genesis
    return {
        (bn, "GET", "/eth/v1/config/spec"): [_raw(dp, spec)],
        (bn, "GET", "/eth/v1/beacon/genesis"): [_raw(dp, genesis)],
        (bn, "GET", "/eth/v1/node/version"): [_version_raw(dp, version)],
    }


def _argv(*urls: str, config: Path | None = None) -> list[str]:
    argv = ["--network-config", str(config or CONFIG)]
    for url in urls or (BN0,):
        argv.extend(["--beacon-url", url])
    return argv


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


def test_script_does_not_run_main_on_import(capsys):
    source = SCRIPT.read_text(encoding="utf-8")
    guard_at = source.index('if __name__ == "__main__":')
    assert "sys.exit(main())" in source[guard_at:]
    spec = importlib.util.spec_from_file_location("devnet_preflight_guard", SCRIPT)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == ""
    assert mod.EXIT_OK == 0


def test_network_is_blocked():
    with pytest.raises(SocketBlockedError, match="getaddrinfo"):
        socket.getaddrinfo("example.com", 80)


def test_parse_config_yaml_skips_comments_quotes_and_nested(dp):
    text = CONFIG.read_text(encoding="utf-8")
    got = dp.parse_config_yaml(text, str(CONFIG))
    assert got["CONFIG_NAME"] == "preflight"
    assert got["GLOAS_FORK_EPOCH"] == "70"
    assert got["GLOAS_FORK_VERSION"] == "0x08000000"
    assert got["AGGREGATE_DUE_BPS_GLOAS"] == "6667"
    assert "BLOB_SCHEDULE" not in got
    assert "EPOCH" not in got
    assert "MAX_BLOBS_PER_BLOCK" not in got
    assert "#" not in got["CONFIG_NAME"]


def test_parse_config_yaml_duplicate_key(dp):
    with pytest.raises(dp.UsageError, match="duplicate key"):
        dp.parse_config_yaml("GLOAS_FORK_EPOCH: 1\nGLOAS_FORK_EPOCH: 2\n", "t")


def test_missing_required_flags_exit_2(dp, capsys):
    code = dp.main([])
    captured = capsys.readouterr()
    assert code == dp.EXIT_USAGE == 2
    assert "network-config" in captured.err
    assert "Traceback" not in captured.err


def test_beacon_url_required(dp, capsys):
    code = dp.main(["--network-config", str(CONFIG)])
    captured = capsys.readouterr()
    assert code == dp.EXIT_USAGE == 2
    assert "beacon-url" in captured.err


def test_missing_config_file_exit_2(dp, capsys, tmp_path):
    missing = tmp_path / "no-such-config.yaml"
    code = dp.main(_argv(BN0, config=missing), transport=FakeTransport({}))
    captured = capsys.readouterr()
    assert code == dp.EXIT_USAGE == 2
    assert "no-such-config.yaml" in captured.err


def test_matching_fixture_exits_0_prints_fragment_and_versions(dp, capsys):
    routes = {}
    routes.update(_routes(dp, bn="bn0", version=VERSION_LH))
    routes.update(_routes(dp, bn="bn1", version=VERSION_TEKU))
    code = dp.main(_argv(BN0, BN1), transport=FakeTransport(routes))
    captured = capsys.readouterr()
    assert code == dp.EXIT_OK == 0
    assert 'network = "custom"' in captured.out
    assert "genesis_time = 1710000000" in captured.out
    assert f'genesis_validators_root = "{GVR_A}"' in captured.out
    assert VERSION_LH in captured.err
    assert VERSION_TEKU in captured.err
    assert "http://127.0.0.1:5052" in captured.err
    assert "http://127.0.0.1:5053" in captured.err
    assert "AGGREGATE_DUE_BPS_GLOAS: 6667" in captured.err
    assert "Traceback" not in captured.err


def test_genesis_validators_root_disagreement_names_both_endpoints(dp, capsys):
    routes = {}
    routes.update(_routes(dp, bn="bn0", genesis=GENESIS_DATA))
    routes.update(
        _routes(
            dp,
            bn="bn1",
            genesis={**GENESIS_DATA, "genesis_validators_root": GVR_B},
        )
    )
    code = dp.main(_argv(BN0, BN1), transport=FakeTransport(routes))
    captured = capsys.readouterr()
    assert code != 0
    assert code == dp.EXIT_ERROR == 1
    err = captured.err
    assert "genesis_validators_root" in err
    assert "http://127.0.0.1:5052" in err
    assert "http://127.0.0.1:5053" in err
    assert "/eth/v1/beacon/genesis" in err
    assert GVR_A in err
    assert GVR_B in err
    assert 'network = "custom"' not in captured.out


def test_one_key_mismatch_names_key_values_and_sources(dp, capsys):
    spec = {**SPEC_DATA, "GLOAS_FORK_EPOCH": "71"}
    code = dp.main(_argv(BN0), transport=FakeTransport(_routes(dp, spec=spec)))
    captured = capsys.readouterr()
    assert code == dp.EXIT_ERROR == 1
    err = captured.err
    assert "GLOAS_FORK_EPOCH" in err
    assert "mismatch" in err
    assert "70" in err
    assert "71" in err
    assert "network-config=" in err
    assert "preflight__config.yaml" in err
    assert "http://127.0.0.1:5052=/eth/v1/config/spec" in err
    assert 'network = "custom"' not in captured.out


def test_missing_gloas_fork_epoch_from_config(dp, tmp_path, capsys):
    text = CONFIG.read_text(encoding="utf-8").replace("GLOAS_FORK_EPOCH: 70\n", "")
    assert "GLOAS_FORK_EPOCH" not in text
    path = tmp_path / "config.yaml"
    path.write_text(text, encoding="utf-8")
    code = dp.main(_argv(BN0, config=path), transport=FakeTransport(_routes(dp)))
    captured = capsys.readouterr()
    assert code == dp.EXIT_ERROR == 1
    err = captured.err
    assert "GLOAS_FORK_EPOCH" in err
    assert "missing" in err
    assert "network-config=" in err
    assert "18446744073709551615" not in err
    assert 'network = "custom"' not in captured.out


def test_missing_gloas_fork_epoch_from_spec(dp, capsys):
    spec = {k: v for k, v in SPEC_DATA.items() if k != "GLOAS_FORK_EPOCH"}
    code = dp.main(_argv(BN0), transport=FakeTransport(_routes(dp, spec=spec)))
    captured = capsys.readouterr()
    assert code == dp.EXIT_ERROR == 1
    err = captured.err
    assert "GLOAS_FORK_EPOCH" in err
    assert "missing" in err
    assert "http://127.0.0.1:5052=/eth/v1/config/spec" in err
    assert "18446744073709551615" not in err
    assert 'network = "custom"' not in captured.out


def test_missing_due_bps_key_from_spec(dp, capsys):
    spec = {k: v for k, v in SPEC_DATA.items() if k != "ATTESTATION_DUE_BPS"}
    code = dp.main(_argv(BN0), transport=FakeTransport(_routes(dp, spec=spec)))
    captured = capsys.readouterr()
    assert code == dp.EXIT_ERROR == 1
    assert "ATTESTATION_DUE_BPS" in captured.err
    assert "missing" in captured.err


def test_aggregate_due_bps_gloas_mismatch_is_reported_not_asserted(dp, capsys):
    spec = {**SPEC_DATA, "AGGREGATE_DUE_BPS_GLOAS": "5000"}
    code = dp.main(_argv(BN0), transport=FakeTransport(_routes(dp, spec=spec)))
    captured = capsys.readouterr()
    assert code == dp.EXIT_OK == 0
    assert "AGGREGATE_DUE_BPS_GLOAS: 6667" in captured.err
    assert "5000" not in captured.err
    assert 'network = "custom"' in captured.out


def test_aggregate_due_bps_gloas_absent_from_spec_ok(dp, capsys):
    spec = {k: v for k, v in SPEC_DATA.items() if k != "AGGREGATE_DUE_BPS_GLOAS"}
    code = dp.main(_argv(BN0), transport=FakeTransport(_routes(dp, spec=spec)))
    captured = capsys.readouterr()
    assert code == dp.EXIT_OK == 0
    assert "AGGREGATE_DUE_BPS_GLOAS: 6667" in captured.err


def test_http_404_on_spec_fails_closed(dp, capsys):
    routes = _routes(dp)
    routes[("bn0", "GET", "/eth/v1/config/spec")] = [
        dp.RawResponse(404, b"missing", False)
    ]
    code = dp.main(_argv(BN0), transport=FakeTransport(routes))
    captured = capsys.readouterr()
    assert code == dp.EXIT_ERROR == 1
    assert "HTTP 404" in captured.err
    assert "/eth/v1/config/spec" in captured.err
    assert "http://127.0.0.1:5052" in captured.err
    assert 'network = "custom"' not in captured.out


def test_quiet_still_prints_versions_and_fragment(dp, capsys):
    code = dp.main(
        _argv(BN0) + ["-q"], transport=FakeTransport(_routes(dp, version=VERSION_LH))
    )
    captured = capsys.readouterr()
    assert code == dp.EXIT_OK == 0
    assert VERSION_LH in captured.err
    assert 'network = "custom"' in captured.out


def test_verbose_and_quiet_are_exclusive(dp, capsys):
    code = dp.main(_argv(BN0) + ["-v", "-q"], transport=FakeTransport({}))
    captured = capsys.readouterr()
    assert code == dp.EXIT_USAGE == 2
    assert "mutually exclusive" in captured.err


def test_invalid_url_error_omits_userinfo_and_query(dp, capsys):
    secret = "s3cret"
    query = "token=abc"
    urls = (
        f"http://user:{secret}@/eth?{query}",
        f"http://127.0.0.1:99999/eth?{query}",
        f"ftp://user:{secret}@host/path?{query}",
    )
    for url in urls:
        capsys.readouterr()
        code = dp.main(
            ["--network-config", str(CONFIG), "--beacon-url", url],
            transport=FakeTransport({}),
        )
        err = capsys.readouterr().err
        assert code == dp.EXIT_USAGE == 2
        assert secret not in err
        assert query not in err
        assert url not in err

    capsys.readouterr()
    code = dp.main(
        [
            "--network-config",
            f"ftp://user:{secret}@host/path?{query}",
            "--beacon-url",
            BN0,
        ],
        transport=FakeTransport({}),
    )
    err = capsys.readouterr().err
    assert code == dp.EXIT_USAGE == 2
    assert secret not in err
    assert query not in err


def test_config_url_error_omits_userinfo_and_query(dp, capsys):
    secret = "s3cret"
    query = "token=abc"
    url = f"http://user:{secret}@configs.example/metadata/config.yaml?{query}"
    routes = {
        ("config", "GET", "/metadata/config.yaml?token=abc"): [
            dp.RawResponse(404, b"nope", False)
        ]
    }
    code = dp.main(
        ["--network-config", url, "--beacon-url", BN0],
        transport=FakeTransport(routes),
    )
    captured = capsys.readouterr()
    assert code == dp.EXIT_ERROR == 1
    assert "HTTP 404" in captured.err
    assert secret not in captured.err
    assert query not in captured.err
    assert "user:" not in captured.err


def test_transport_error_includes_safe_cause(dp, capsys):
    def boom():
        raise TimeoutError("timed out")

    routes = _routes(dp)
    routes[("bn0", "GET", "/eth/v1/node/version")] = [boom]
    code = dp.main(_argv(BN0), transport=FakeTransport(routes))
    captured = capsys.readouterr()
    assert code == dp.EXIT_ERROR == 1
    assert "transport error" in captured.err
    assert "TimeoutError: timed out" in captured.err
    assert "http://127.0.0.1:5052=/eth/v1/node/version" in captured.err


def test_transport_error_omits_unsafe_cause(dp, capsys):
    secret = "s3cret"
    query = "token=abc"

    def boom():
        raise ConnectionError(f"failed http://user:{secret}@bn/path?{query}")

    routes = _routes(dp)
    routes[("bn0", "GET", "/eth/v1/node/version")] = [boom]
    code = dp.main(_argv(BN0), transport=FakeTransport(routes))
    captured = capsys.readouterr()
    assert code == dp.EXIT_ERROR == 1
    assert "transport error" in captured.err
    assert "ConnectionError" in captured.err
    assert secret not in captured.err
    assert query not in captured.err


def test_network_config_url(dp, capsys):
    yaml_body = CONFIG.read_bytes()
    routes = {
        ("config", "GET", "/metadata/config.yaml"): [
            dp.RawResponse(200, yaml_body, False)
        ]
    }
    routes.update(_routes(dp, bn="bn0", version=VERSION_LH))
    code = dp.main(
        [
            "--network-config",
            "http://configs.example/metadata/config.yaml",
            "--beacon-url",
            BN0,
        ],
        transport=FakeTransport(routes),
    )
    captured = capsys.readouterr()
    assert code == dp.EXIT_OK == 0
    assert 'network = "custom"' in captured.out
    assert VERSION_LH in captured.err
