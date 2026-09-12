#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Scrape RVC /metrics and render client-side reports for the local devnet testbed."""

import argparse
import http.client
import json
import math
import os
import socket
import ssl
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TextIO
from urllib.parse import urlsplit

# ===== § 1. Header, constants, exit codes =====

SCHEMA_VERSION = 1
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
EXIT_OK, EXIT_INFRA, EXIT_USAGE, EXIT_HEALTH, EXIT_KPI, EXIT_NOTREADY = (
    0,
    1,
    2,
    3,
    4,
    5,
)

# ===== § 2. Errors and diagnostics =====


class UsageError(Exception):
    pass


class InfraError(Exception):
    pass


class Log:
    def __init__(self, verbosity: int, stream: TextIO) -> None:
        self._verbosity = verbosity
        self._stream = stream

    def error(self, msg: str, *a: object) -> None:
        self._emit(msg, a)

    def warn(self, msg: str, *a: object) -> None:
        if self._verbosity >= 0:
            self._emit(msg, a)

    def info(self, msg: str, *a: object) -> None:
        if self._verbosity >= 1:
            self._emit(msg, a)

    def _emit(self, msg: str, a: tuple[object, ...]) -> None:
        print(msg % a if a else msg, file=self._stream)


# ===== § 4. CLI and configuration =====


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    p = _ArgumentParser(
        description=(
            "Scrape RVC Prometheus metrics and render client-side reports."
        ),
    )
    sub = p.add_subparsers(
        dest="command", required=True, parser_class=_ArgumentParser
    )

    scrape = sub.add_parser("scrape")
    scrape.add_argument("--url")
    scrape.add_argument("--out")
    scrape.add_argument("--gauges-only", action="store_true")
    scrape.add_argument("--slot", type=int, metavar="N")
    scrape.add_argument("--append")

    report = sub.add_parser("report")
    report.add_argument("--run-dir")

    compare = sub.add_parser("compare")
    compare.add_argument("a")
    compare.add_argument("b")
    compare.add_argument("--rel", type=float)
    compare.add_argument("--abs-floor")
    return p


@dataclass(frozen=True)
class Options:
    command: str
    url: str | None
    out: str | None
    append: str | None
    gauges_only: bool
    slot: int | None
    run_dir: str | None
    a: str | None
    b: str | None
    rel: float | None
    abs_floor: str | None


def _validate_scrape(args: argparse.Namespace) -> None:
    if not args.url:
        raise UsageError("--url is required")
    if args.out and args.append:
        raise UsageError("--out and --append are mutually exclusive")
    if not args.out and not args.append:
        raise UsageError("--out or --append is required")
    if args.gauges_only and not args.append:
        raise UsageError("--gauges-only requires --append")
    if args.append and not args.gauges_only:
        raise UsageError("--append requires --gauges-only")
    if args.gauges_only and args.slot is None:
        raise UsageError("--gauges-only requires --slot")
    if args.slot is not None and not args.gauges_only:
        raise UsageError("--slot requires --gauges-only")


def build_options(argv: list[str] | None = None) -> Options:
    args = build_parser().parse_args(argv)
    if args.command == "scrape":
        _validate_scrape(args)
    return Options(
        command=args.command,
        url=getattr(args, "url", None),
        out=getattr(args, "out", None),
        append=getattr(args, "append", None),
        gauges_only=bool(getattr(args, "gauges_only", False)),
        slot=getattr(args, "slot", None),
        run_dir=getattr(args, "run_dir", None),
        a=getattr(args, "a", None),
        b=getattr(args, "b", None),
        rel=getattr(args, "rel", None),
        abs_floor=getattr(args, "abs_floor", None),
    )


def main(argv: list[str] | None = None, *, transport=None) -> int:
    log = Log(0, sys.stderr)
    active = transport
    try:
        opts = build_options(argv)
        if opts.command == "scrape":
            if active is None:
                active = HttpTransport(
                    DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT
                )
            cmd_scrape(opts, transport=active)
        elif opts.command == "report":
            cmd_report(opts)
        elif opts.command == "compare":
            cmd_compare(opts)
        else:
            raise UsageError(f"unknown command: {opts.command!r}")
        return EXIT_OK
    except UsageError as exc:
        log.error("%s", exc)
        return EXIT_USAGE
    except InfraError as exc:
        log.error("%s", exc)
        return EXIT_INFRA
    finally:
        closer = getattr(active, "close", None)
        if callable(closer):
            closer()


# ===== § 5. Transport =====


@dataclass(frozen=True)
class Endpoint:
    label: str
    scheme: str
    host: str
    port: int
    base_path: str = ""


@dataclass(frozen=True)
class RawResponse:
    status: int
    body: bytes
    truncated: bool = False


Transport = Callable[[Endpoint, str, str, bytes | None], RawResponse]


def _redact_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    scheme = parsed.scheme or "?"
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if not host:
        host = "<invalid-host>"
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port is None:
        if scheme == "https":
            port = 443
        elif scheme == "http":
            port = 80
        else:
            return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def parse_endpoint(url: str) -> tuple[Endpoint, str]:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
    except ValueError as exc:
        raise UsageError("invalid URL") from exc
    if parsed.scheme not in ("http", "https"):
        raise UsageError(f"unsupported URL scheme: {parsed.scheme!r}")
    if parsed.username is not None or parsed.password is not None:
        raise UsageError(f"URL userinfo is not supported: {_redact_url(url)}")
    if not host:
        raise UsageError(f"invalid URL: {_redact_url(url)}")
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError as exc:
        raise UsageError(f"invalid URL: {_redact_url(url)}") from exc
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    path = parsed.path or "/metrics"
    if path == "/":
        path = "/metrics"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    ep = Endpoint(
        label="metrics",
        scheme=parsed.scheme,
        host=host,
        port=port,
        base_path="",
    )
    return ep, path


class HttpTransport:
    def __init__(self, connect_timeout: float, read_timeout: float) -> None:
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout

    def __call__(
        self, ep: Endpoint, method: str, path: str, body: bytes | None
    ) -> RawResponse:
        factory = (
            http.client.HTTPSConnection
            if ep.scheme == "https"
            else http.client.HTTPConnection
        )
        conn = factory(ep.host, ep.port, timeout=self._connect_timeout)
        try:
            conn.connect()
            sock = conn.sock
            if sock is not None:
                sock.settimeout(self._read_timeout)
            headers: dict[str, str] = {}
            if body is not None:
                headers["Content-Type"] = "application/json"
            conn.request(method, ep.base_path + path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            return RawResponse(resp.status, raw, len(raw) > MAX_RESPONSE_BYTES)
        finally:
            conn.close()

    def drop(self, ep: Endpoint) -> None:
        return None

    def close(self) -> None:
        return None


def fetch_metrics(url: str, *, transport: Transport) -> RawResponse:
    ep, path = parse_endpoint(url)
    try:
        return transport(ep, "GET", path, None)
    except (
        TimeoutError,
        ConnectionError,
        http.client.HTTPException,
        ssl.SSLError,
        socket.gaierror,
        OSError,
    ) as exc:
        raise InfraError(f"metrics fetch failed: {exc}") from exc


def cmd_scrape(opts: Options, *, transport: Transport) -> None:
    raw = fetch_metrics(opts.url or "", transport=transport)
    if raw.truncated:
        raise InfraError("metrics response exceeded MAX_RESPONSE_BYTES")
    if raw.status != 200:
        raise InfraError(f"metrics HTTP {raw.status}")
    if opts.gauges_only:
        return
    dest = opts.out
    if dest is None:
        raise UsageError("--out is required")
    try:
        with open(dest, "wb") as fh:
            fh.write(raw.body)
    except OSError as exc:
        raise InfraError(f"failed to write {dest}: {exc}") from exc


# ===== § 9. Compare =====


def cmd_report(_opts: Options) -> None:
    raise UsageError("report lands with DN-9 in later Phase 4 issues")


def cmd_compare(_opts: Options) -> None:
    raise UsageError("compare lands with DN-17 in Phase 6")


# ===== § 10. JSON writer =====


def _generated_at(clock: Callable[[], datetime] | None) -> str:
    now = clock() if clock is not None else datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise TypeError("generated_at clock must be timezone-aware")
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _finite_or_none(obj: object) -> object:
    if isinstance(obj, float):
        return obj if math.isfinite(obj) else None
    if isinstance(obj, dict):
        return {key: _finite_or_none(value) for key, value in obj.items()}
    if isinstance(obj, list):
        return [_finite_or_none(item) for item in obj]
    return obj


def write_json_atomic(path: str | os.PathLike[str], obj: object) -> None:
    dest = os.path.abspath(path)
    directory = os.path.dirname(dest) or "."
    payload = json.dumps(
        _finite_or_none(obj), allow_nan=False, sort_keys=True
    )
    fd, tmp = tempfile.mkstemp(
        prefix="devnet_report.", suffix=".tmp", dir=directory
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.write("\n")
        os.replace(tmp, dest)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


if __name__ == "__main__":
    sys.exit(main())
