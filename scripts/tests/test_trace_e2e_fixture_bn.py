"""Contract tests for the TRC-5a fixture beacon node and trace-e2e.sh part 1.

No sockets (conftest disables them). The shell script is checked statically
and via --help / --part 2, which exit before Docker.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from conftest import load_script

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "trace-e2e.sh"
FIXTURES = Path(__file__).resolve().parent / "fixtures"
GVR = "0x" + "11" * 32
PUBKEY = "0x" + "ab" * 48


def mod():
    return load_script("trace_e2e_fixture_bn")


def ctx(server, now: int = 1_700_000_000):
    return server.FixtureContext(
        fixtures_dir=FIXTURES,
        genesis_time=1_700_000_000,
        genesis_validators_root=GVR,
        validator_pubkey=PUBKEY,
        validator_index="0",
        now=now,
    )


def test_route_table_is_mock_bn_plus_duty_path():
    server = mod()
    # MockBn 12 mounts + v2 version + attestation_data + pool submit = 15,
    # then the part-1 refactor drops the three fixtures the client never
    # requested (fork_schedule, v1 node/version, sync duties).
    assert len(server.ROUTES) == 12
    patterns = [(method, pattern) for method, pattern, _file, _kind in server.ROUTES]
    required = [
        ("GET", r"^/eth/v1/beacon/genesis$"),
        ("GET", r"^/eth/v1/config/spec$"),
        ("GET", r"^/eth/v1/node/syncing$"),
        ("GET", r"^/eth/v2/node/version$"),
        ("GET", r"^/eth/v1/beacon/states/[^/]+/fork$"),
        ("POST", r"^/eth/v1/beacon/states/[^/]+/validators$"),
        ("GET", r"^/eth/v1/beacon/states/[^/]+/validators$"),
        ("GET", r"^/eth/v1/beacon/blocks/[^/]+/root$"),
        ("GET", r"^/eth/v1/validator/duties/proposer/(?P<epoch>\d+)$"),
        ("POST", r"^/eth/v1/validator/duties/attester/(?P<epoch>\d+)$"),
        ("GET", r"^/eth/v1/validator/attestation_data$"),
        ("POST", r"^/eth/v2/beacon/pool/attestations$"),
    ]
    assert patterns == required


def test_every_route_fixture_file_exists():
    server = mod()
    for _method, _pattern, filename, _kind in server.ROUTES:
        assert (FIXTURES / filename).is_file(), filename


def test_attester_duty_slot_tracks_runtime_genesis():
    server = mod()
    # 36 seconds after genesis → slot 3 (12s slots), still epoch 0.
    body_status = server.dispatch(
        ctx(server, now=1_700_000_000 + 36),
        "POST",
        "/eth/v1/validator/duties/attester/0",
    )
    status, raw = body_status
    assert status == 200
    duty = json.loads(raw)["data"][0]
    assert duty["slot"] == "3"
    assert duty["pubkey"] == PUBKEY
    assert duty["validator_index"] == "0"


def test_attester_duty_for_other_epoch_uses_that_epoch_start():
    server = mod()
    status, raw = server.dispatch(
        ctx(server, now=1_700_000_000 + 36),
        "POST",
        "/eth/v1/validator/duties/attester/2",
    )
    assert status == 200
    assert json.loads(raw)["data"][0]["slot"] == str(2 * 32)


def test_attestation_data_echoes_requested_slot():
    server = mod()
    status, raw = server.dispatch(
        ctx(server, now=1_700_000_000 + 36),
        "GET",
        "/eth/v1/validator/attestation_data?slot=3&committee_index=1",
    )
    assert status == 200
    data = json.loads(raw)["data"]
    assert data["slot"] == "3"
    assert data["index"] == "1"
    assert data["target"]["epoch"] == "0"
    assert data["source"]["epoch"] == "0"


def test_genesis_substitutes_runtime_values():
    server = mod()
    status, raw = server.dispatch(ctx(server), "GET", "/eth/v1/beacon/genesis")
    assert status == 200
    data = json.loads(raw)["data"]
    assert data["genesis_time"] == "1700000000"
    assert data["genesis_validators_root"] == GVR


def test_unknown_route_is_404():
    server = mod()
    status, raw = server.dispatch(ctx(server), "GET", "/eth/v1/does-not-exist")
    assert status == 404
    assert b"no handler" in raw


def test_post_submit_accepts_empty_success_body():
    server = mod()
    status, raw = server.dispatch(
        ctx(server), "POST", "/eth/v2/beacon/pool/attestations"
    )
    assert status == 200
    assert json.loads(raw) == {}


def test_script_is_part1_only_and_shellcheck_friendly():
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in text
    assert "shopt -s nullglob" in text
    assert 'fixture_files=("${FIXTURE_DIR}"/trace_e2e_bn__*.json)' in text
    assert "fail fixture-bn-ready" in text or 'wait_until fixture-bn-ready' in text
    assert "wait_until attestation-duty" in text
    assert "5b" in text
    # Containerized rvc uses the fixture alias on the private network, not
    # the host-published loopback port.
    assert "host.docker.internal" not in text
    assert "--network-alias" in text
    assert 'beacon_url="http://${bn_alias}:5052"' in text
    assert '127.0.0.1:${bn_port}:5052' in text


def test_part_other_than_1_exits_named_without_docker():
    proc = subprocess.run(
        [str(SCRIPT), "--part", "2"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1
    assert "FAIL part-not-in-scope" in proc.stderr
    assert "part 1" in proc.stderr


def test_help_exits_zero():
    proc = subprocess.run(
        [str(SCRIPT), "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0
    assert "part 1" in proc.stdout.lower() or "Part 1" in proc.stdout
