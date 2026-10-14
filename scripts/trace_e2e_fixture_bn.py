#!/usr/bin/env python3
"""MockBn-based fixture beacon node for trace-e2e part 1 (TRC-5a).

Route set starts from `MockBn::mount_endpoints` in
`bin/rvc/tests/common/mock_bn.rs`, plus the attestation-duty calls
(`attestation_data`, pool submit) and the `/eth/v2/node/version` probe.
A part-1 run then drops every fixture the client never requests:
`fork_schedule`, v1 `node/version` (v2 returned 200), and sync duties.

Static JSON lives under `scripts/tests/fixtures/trace_e2e_bn__*.json`.
Path parameters and POST bodies are handled here; slot and epoch tokens are
filled from the genesis time the launcher sets, using the same
`SECONDS_PER_SLOT` / `SLOTS_PER_EPOCH` the spec fixture advertises.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Mapping
from urllib.parse import parse_qs, urlsplit

# Logical routes (method + path pattern). Validators GET and POST share one file.
# Count is the spike's confirmed endpoint list (see spike-fixture-bn.md).
ROUTES: tuple[tuple[str, str, str, str], ...] = (
    ("GET", r"^/eth/v1/beacon/genesis$", "trace_e2e_bn__genesis.json", "genesis"),
    ("GET", r"^/eth/v1/config/spec$", "trace_e2e_bn__spec.json", "static"),
    ("GET", r"^/eth/v1/node/syncing$", "trace_e2e_bn__node_syncing.json", "head"),
    ("GET", r"^/eth/v2/node/version$", "trace_e2e_bn__node_version_v2.json", "static"),
    (
        "GET",
        r"^/eth/v1/beacon/states/[^/]+/fork$",
        "trace_e2e_bn__state_fork.json",
        "static",
    ),
    (
        "POST",
        r"^/eth/v1/beacon/states/[^/]+/validators$",
        "trace_e2e_bn__validators.json",
        "validator",
    ),
    (
        "GET",
        r"^/eth/v1/beacon/states/[^/]+/validators$",
        "trace_e2e_bn__validators.json",
        "validator",
    ),
    (
        "GET",
        r"^/eth/v1/beacon/blocks/[^/]+/root$",
        "trace_e2e_bn__block_root.json",
        "static",
    ),
    (
        "GET",
        r"^/eth/v1/validator/duties/proposer/(?P<epoch>\d+)$",
        "trace_e2e_bn__duties_proposer.json",
        "static",
    ),
    (
        "POST",
        r"^/eth/v1/validator/duties/attester/(?P<epoch>\d+)$",
        "trace_e2e_bn__duties_attester.json",
        "attester",
    ),
    (
        "GET",
        r"^/eth/v1/validator/attestation_data$",
        "trace_e2e_bn__attestation_data.json",
        "attestation_data",
    ),
    (
        "POST",
        r"^/eth/v2/beacon/pool/attestations$",
        "trace_e2e_bn__pool_attestations.json",
        "static",
    ),
)

COMPILED: tuple[tuple[str, re.Pattern[str], str, str], ...] = tuple(
    (method, re.compile(pattern), filename, kind) for method, pattern, filename, kind in ROUTES
)

SECONDS_PER_SLOT = 12
SLOTS_PER_EPOCH = 32


@dataclass(frozen=True)
class FixtureContext:
    """Run-time values substituted into fixture tokens."""

    fixtures_dir: Path
    genesis_time: int
    genesis_validators_root: str
    validator_pubkey: str
    validator_index: str
    seconds_per_slot: int = SECONDS_PER_SLOT
    slots_per_epoch: int = SLOTS_PER_EPOCH
    now: int | None = None

    def unix_now(self) -> int:
        if self.now is not None:
            return self.now
        return int(time.time())

    def current_slot(self) -> int:
        elapsed = self.unix_now() - self.genesis_time
        if elapsed < 0:
            return 0
        return elapsed // self.seconds_per_slot

    def duty_slot(self, epoch: int) -> int:
        slot = self.current_slot()
        if slot // self.slots_per_epoch == epoch:
            return slot
        return epoch * self.slots_per_epoch


def load_fixture_text(ctx: FixtureContext, filename: str) -> str:
    path = ctx.fixtures_dir / filename
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise FileNotFoundError(f"trace-e2e fixture missing: {path}") from exc


def require_fixtures(ctx: FixtureContext) -> None:
    missing = [name for _m, _p, name, _k in ROUTES if not (ctx.fixtures_dir / name).is_file()]
    if missing:
        joined = ", ".join(missing)
        raise SystemExit(f"trace-e2e-fixture: FAIL fixture-files: missing {joined}")


def _replace(text: str, tokens: Mapping[str, str]) -> str:
    for key, value in tokens.items():
        text = text.replace(key, value)
    return text


def render(ctx: FixtureContext, filename: str, tokens: Mapping[str, str]) -> bytes:
    text = _replace(load_fixture_text(ctx, filename), tokens)
    # Reject a leftover token so a missed substitution cannot reach bin/rvc.
    leftover = re.findall(r"__[A-Z0-9_]+__", text)
    if leftover:
        names = ", ".join(sorted(set(leftover)))
        raise ValueError(f"unsubstituted fixture tokens in {filename}: {names}")
    json.loads(text)
    return text.encode("utf-8")


def base_tokens(ctx: FixtureContext) -> dict[str, str]:
    slot = ctx.current_slot()
    epoch = slot // ctx.slots_per_epoch
    return {
        "__GENESIS_TIME__": str(ctx.genesis_time),
        "__GENESIS_VALIDATORS_ROOT__": ctx.genesis_validators_root,
        "__PUBKEY__": ctx.validator_pubkey,
        "__VALIDATOR_INDEX__": ctx.validator_index,
        "__HEAD_SLOT__": str(slot),
        "__SLOT__": str(slot),
        "__EPOCH__": str(epoch),
        "__TARGET_EPOCH__": str(epoch),
        "__SOURCE_EPOCH__": str(epoch if epoch == 0 else epoch - 1),
        "__COMMITTEE_INDEX__": "0",
    }


def attestation_tokens(ctx: FixtureContext, query: Mapping[str, list[str]]) -> dict[str, str]:
    tokens = base_tokens(ctx)
    slot_raw = (query.get("slot") or ["0"])[0]
    committee = (query.get("committee_index") or ["0"])[0]
    try:
        slot = int(slot_raw)
    except ValueError as exc:
        raise ValueError(f"attestation_data slot is not an integer: {slot_raw}") from exc
    if slot < 0:
        raise ValueError(f"attestation_data slot is negative: {slot}")
    epoch = slot // ctx.slots_per_epoch
    tokens["__SLOT__"] = str(slot)
    tokens["__EPOCH__"] = str(epoch)
    tokens["__TARGET_EPOCH__"] = str(epoch)
    tokens["__SOURCE_EPOCH__"] = str(epoch if epoch == 0 else epoch - 1)
    tokens["__COMMITTEE_INDEX__"] = committee
    return tokens


def dispatch(
    ctx: FixtureContext,
    method: str,
    target: str,
) -> tuple[int, bytes]:
    """Return ``(status, body)`` for one beacon API request."""

    split = urlsplit(target)
    path = split.path
    query = parse_qs(split.query, keep_blank_values=True)
    method = method.upper()

    for route_method, pattern, filename, kind in COMPILED:
        if route_method != method:
            continue
        match = pattern.match(path)
        if match is None:
            continue
        tokens = base_tokens(ctx)
        if kind == "attester":
            epoch = int(match.group("epoch"))
            slot = ctx.duty_slot(epoch)
            epoch_of_slot = slot // ctx.slots_per_epoch
            tokens["__SLOT__"] = str(slot)
            tokens["__EPOCH__"] = str(epoch_of_slot)
            tokens["__TARGET_EPOCH__"] = str(epoch_of_slot)
            tokens["__SOURCE_EPOCH__"] = str(
                epoch_of_slot if epoch_of_slot == 0 else epoch_of_slot - 1
            )
        elif kind == "attestation_data":
            tokens = attestation_tokens(ctx, query)
        body = render(ctx, filename, tokens)
        return 200, body

    message = f"trace-e2e fixture has no handler for {method} {path}"
    payload = json.dumps({"code": 404, "message": message}).encode("utf-8")
    return 404, payload


def context_from_env(fixtures_dir: Path, now: int | None = None) -> FixtureContext:
    def required(name: str) -> str:
        value = os.environ.get(name, "").strip()
        if not value:
            raise SystemExit(f"trace-e2e-fixture: FAIL config: {name} is required")
        return value

    genesis_raw = required("TRACE_E2E_GENESIS_TIME")
    try:
        genesis_time = int(genesis_raw)
    except ValueError as exc:
        raise SystemExit(
            f"trace-e2e-fixture: FAIL config: TRACE_E2E_GENESIS_TIME={genesis_raw!r} is not an integer"
        ) from exc

    pubkey = required("TRACE_E2E_VALIDATOR_PUBKEY")
    if not pubkey.startswith("0x"):
        pubkey = "0x" + pubkey

    return FixtureContext(
        fixtures_dir=fixtures_dir,
        genesis_time=genesis_time,
        genesis_validators_root=required("TRACE_E2E_GENESIS_VALIDATORS_ROOT"),
        validator_pubkey=pubkey,
        validator_index=os.environ.get("TRACE_E2E_VALIDATOR_INDEX", "0").strip() or "0",
        now=now,
    )


class _Handler(BaseHTTPRequestHandler):
    ctx: FixtureContext

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("trace-e2e-fixture: " + (fmt % args) + "\n")

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length:
            self.rfile.read(length)
        try:
            status, body = dispatch(self.ctx, self.command, self.path)
        except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
            status = 500
            body = json.dumps({"code": 500, "message": str(exc)}).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        sys.stderr.write(
            f"trace-e2e-fixture: {self.command} {self.path} -> {status}\n"
        )

    def do_GET(self) -> None:  # noqa: N802
        self._serve()

    def do_POST(self) -> None:  # noqa: N802
        self._serve()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="trace-e2e fixture beacon node")
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args(argv)

    ctx = context_from_env(args.fixtures)
    require_fixtures(ctx)
    _Handler.ctx = ctx

    server = ThreadingHTTPServer((args.bind, args.port), _Handler)
    sys.stderr.write(
        f"trace-e2e-fixture: listening on {args.bind}:{args.port} "
        f"genesis_time={ctx.genesis_time} routes={len(ROUTES)}\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
