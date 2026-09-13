#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Estimate consensus-layer performance of a validator set from the Beacon API."""

import argparse
import base64
import csv
import http.client
import json
import math
import os
import random
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import tomllib
from collections.abc import Callable, Iterator, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Literal, TextIO
from urllib.parse import unquote, urlencode, urlsplit

# ===== § 1. Header, constants, exit codes =====

SCHEMA_VERSION = 1
SECONDS_PER_JULIAN_YEAR = 31_557_600
DEFAULT_EPOCHS = 32
DEFAULT_CONCURRENCY = 4
DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_RETRY_AFTER = 30.0
GET_ID_CHUNK = 64
BALANCE_TOLERANCE_GWEI = 50_000_000
EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2
EXIT_DEGRADED, EXIT_THRESHOLD, EXIT_NO_BEACON = 3, 4, 5

# ===== § 2. Errors and diagnostics =====


class UsageError(Exception):
    pass


class NoBeaconAvailable(Exception):
    pass


class BeaconStatus(Exception):
    def __init__(self, status: int, template: str, endpoint_label: str) -> None:
        super().__init__(status, template, endpoint_label)
        self.status = status
        self.template = template
        self.endpoint_label = endpoint_label


class BeaconTransport(Exception):
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


# ===== § 3. Parsing and redaction primitives =====

_UINT = re.compile(r"[0-9]+")
_INT = re.compile(r"-?[0-9]+")


def _parse_num(pattern: re.Pattern[str], raw: object, field: str) -> int:
    if not isinstance(raw, str) or pattern.fullmatch(raw) is None:
        raise UsageError(f"invalid {field}: {raw!r}")
    return int(raw)


def parse_uint(raw: object, field: str) -> int:
    return _parse_num(_UINT, raw, field)


def parse_int(raw: object, field: str) -> int:
    return _parse_num(_INT, raw, field)


def opt_int(raw: object, field: str) -> int | None:
    if isinstance(raw, dict):
        if field not in raw:
            return None
        raw = raw[field]
    return parse_int(raw, field)


def normalize_pubkey(raw: str, origin: str) -> str:
    text = raw.lower() if isinstance(raw, str) else ""
    if text.startswith("0x"):
        text = text[2:]
    if re.fullmatch(r"[0-9a-f]{96}", text) is None:
        raise UsageError(f"{origin}: pubkey must be 48-byte hex")
    return "0x" + text


def parse_endpoint(url: str, label: str) -> "Endpoint":
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        raise UsageError(f"invalid URL: {url!r}") from exc
    if parsed.scheme not in ("http", "https"):
        raise UsageError(f"unsupported URL scheme: {parsed.scheme!r}")
    if ":" in host:
        host = f"[{host}]"
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    base_path = parsed.path.rstrip("/")
    auth_header = None
    if parsed.username is not None or parsed.password is not None:
        user = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        token = base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        auth_header = f"Basic {token}"
    return Endpoint(
        label=label,
        scheme=parsed.scheme,
        host=host,
        port=port,
        base_path=base_path,
        auth_header=auth_header,
    )


def redact(ep: "Endpoint") -> str:
    return f"{ep.scheme}://{ep.host}:{ep.port}"


# ===== § 4. CLI and configuration =====


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Estimate consensus-layer performance of a validator set from the Beacon API.",
    )
    p.add_argument("--pubkey", action="append")
    p.add_argument("--pubkeys-file")
    p.add_argument("--validators-config")
    p.add_argument("--beacon-url", action="append")
    p.add_argument("--config")
    p.add_argument("--epochs", type=int)
    p.add_argument("--from-epoch", type=int)
    p.add_argument("--to-epoch", type=int)
    p.add_argument("--allow-unfinalized", action="store_true")
    p.add_argument("--force-unsafe-window", action="store_true")
    p.add_argument("--json", action="store_true")
    p.add_argument("--csv")
    p.add_argument("--prometheus")
    p.add_argument("--concurrency", type=int)
    p.add_argument("--request-delay-ms", type=int)
    p.add_argument("--connect-timeout", type=float)
    p.add_argument("--read-timeout", type=float)
    p.add_argument("--degraded-ok", action="store_true")
    p.add_argument("--fail-under", action="append")
    p.add_argument("--liveness-check", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--no-cache", action="store_true")
    p.add_argument("-v", action="count", default=0, dest="verbose")
    p.add_argument("-q", action="store_true", dest="quiet")
    return p


def _read_source(
    out: list[str],
    seen: set[str],
    items: list[tuple[str, object]],
) -> None:
    for origin, raw in items:
        key = normalize_pubkey(raw if isinstance(raw, str) else "", origin)
        if key not in seen:
            seen.add(key)
            out.append(key)


def _pubkeys_from_file(path: str) -> list[tuple[str, object]]:
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except (OSError, UnicodeDecodeError, ValueError) as e:
        raise UsageError(f"{path}: {e}") from e
    items: list[tuple[str, object]] = []
    for lineno, line in enumerate(lines, start=1):
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        items.append((f"{path}:{lineno}", text))
    return items


def _pubkeys_from_validators_config(path: str) -> list[tuple[str, object]]:
    try:
        # tomllib.load requires a binary handle; text mode raises TypeError.
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except OSError as e:
        raise UsageError(f"{path}: {e.strerror}") from e
    except tomllib.TOMLDecodeError as e:
        raise UsageError(f"{path}: {e}") from e
    entries = data.get("validators", [])
    if not isinstance(entries, list):
        raise UsageError(f"{path}: [[validators]] must be an array")
    items: list[tuple[str, object]] = []
    for n, entry in enumerate(entries, start=1):
        origin = f"{path} [[validators]] #{n}"
        raw: object = entry.get("pubkey") if isinstance(entry, dict) else ""
        items.append((origin, raw if raw is not None else ""))
    return items


def load_pubkeys(args: argparse.Namespace) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    _read_source(
        out,
        seen,
        [(f"--pubkey #{n}", raw) for n, raw in enumerate(args.pubkey or [], start=1)],
    )
    if args.pubkeys_file:
        _read_source(out, seen, _pubkeys_from_file(args.pubkeys_file))
    if args.validators_config:
        _read_source(out, seen, _pubkeys_from_validators_config(args.validators_config))
    if not out:
        raise UsageError(
            "no pubkeys: supply --pubkey, --pubkeys-file, or --validators-config"
        )
    return out


def _load_toml(path: str) -> dict:
    try:
        # tomllib.load requires a binary handle; text mode raises TypeError.
        with open(path, "rb") as fh:
            return tomllib.load(fh)
    except OSError as e:
        raise UsageError(f"{path}: {e.strerror}") from e
    except tomllib.TOMLDecodeError as e:
        raise UsageError(f"{path}: {e}") from e


def _as_url(raw: object, origin: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise UsageError(f"{origin}: invalid beacon URL: {raw!r}")
    return raw


def _urls_from_config(path: str) -> list[str]:
    data = _load_toml(path)
    origin = f"--config {path}"
    if "beacon_nodes" in data:
        nodes = data["beacon_nodes"]
        if not isinstance(nodes, list) or not all(
            isinstance(item, str) for item in nodes
        ):
            raise UsageError(
                f"{origin}: beacon_nodes must be an array of URL strings, got {nodes!r}"
            )
        if nodes:
            return list(nodes)
        # Empty beacon_nodes is a leftover, not "use nothing".
    if "beacon_url" in data:
        url = data["beacon_url"]
        if not isinstance(url, str):
            raise UsageError(f"{origin}: beacon_url must be a string, got {url!r}")
        if url:
            return [url]
    return []


def load_beacon_urls(args: argparse.Namespace) -> list["Endpoint"]:
    if args.beacon_url is not None:
        origin = "--beacon-url"
        raw = list(args.beacon_url)
    elif args.config:
        origin = f"--config {args.config}"
        raw = _urls_from_config(args.config)
    else:
        origin = "--beacon-url"
        raw = []
    if not raw:
        raise UsageError(
            "no beacon URL: supply --beacon-url or --config with beacon_nodes or beacon_url"
        )
    return [
        parse_endpoint(_as_url(url, origin), f"bn{i}") for i, url in enumerate(raw)
    ]


def _validate_combinations(args: argparse.Namespace) -> None:
    # Syntactic only; window bounds need chain data (§8).
    if args.quiet and args.verbose:
        raise UsageError("-v and -q are mutually exclusive")
    if args.epochs is not None and (
        args.from_epoch is not None or args.to_epoch is not None
    ):
        raise UsageError("--epochs cannot be combined with --from-epoch/--to-epoch")


def _verbosity(args: argparse.Namespace) -> int:
    return -1 if args.quiet else args.verbose


THRESHOLD_METRICS = frozenset(
    {
        "participation_rate",
        "source_rate",
        "target_rate",
        "head_rate",
        "attester_effectiveness",
        "sync_participation_rate",
        "estimated_apr",
    }
)


def parse_thresholds(raw: Sequence[str]) -> dict[str, float]:
    out: dict[str, float] = {}
    for item in raw:
        if "=" not in item:
            raise UsageError(
                f"invalid --fail-under {item!r}: expected METRIC=VALUE"
            )
        name, value = item.split("=", 1)
        if name not in THRESHOLD_METRICS:
            raise UsageError(
                f"unknown --fail-under metric {name!r}: {item!r}"
            )
        try:
            parsed = float(value)
        except ValueError:
            raise UsageError(
                f"invalid --fail-under {item!r}: value is not a float"
            ) from None
        if not math.isfinite(parsed):
            raise UsageError(
                f"invalid --fail-under {item!r}: value is not a finite float"
            )
        out[name] = parsed
    return out


@dataclass(frozen=True)
class Options:
    pubkeys: tuple[str, ...]
    endpoints: tuple["Endpoint", ...]
    epochs: int | None
    from_epoch: int | None
    to_epoch: int | None
    allow_unfinalized: bool
    force_unsafe_window: bool
    verbosity: int
    connect_timeout: float
    read_timeout: float
    concurrency: int
    request_delay_ms: int
    dry_run: bool
    json: bool
    csv: str | None
    prometheus: str | None
    degraded_ok: bool
    fail_under: tuple[str, ...]
    liveness_check: bool
    no_cache: bool


def build_options(argv: list[str] | None = None) -> Options:
    args = build_parser().parse_args(argv)
    _validate_combinations(args)
    fail_under = tuple(args.fail_under or [])
    parse_thresholds(fail_under)

    def pick(value, default):
        return default if value is None else value

    return Options(
        pubkeys=tuple(load_pubkeys(args)),
        endpoints=tuple(load_beacon_urls(args)),
        epochs=args.epochs,
        from_epoch=args.from_epoch,
        to_epoch=args.to_epoch,
        allow_unfinalized=args.allow_unfinalized,
        force_unsafe_window=args.force_unsafe_window,
        verbosity=_verbosity(args),
        connect_timeout=pick(args.connect_timeout, DEFAULT_CONNECT_TIMEOUT),
        read_timeout=pick(args.read_timeout, DEFAULT_READ_TIMEOUT),
        concurrency=pick(args.concurrency, DEFAULT_CONCURRENCY),
        request_delay_ms=pick(args.request_delay_ms, 0),
        dry_run=args.dry_run,
        json=args.json,
        csv=args.csv,
        prometheus=args.prometheus,
        degraded_ok=args.degraded_ok,
        fail_under=fail_under,
        liveness_check=args.liveness_check,
        no_cache=args.no_cache,
    )


# ===== § 5. Transport =====


@dataclass(frozen=True)
class Endpoint:
    label: str
    scheme: str
    host: str
    port: int
    base_path: str = field(repr=False)
    auth_header: str | None = field(repr=False)


@dataclass(frozen=True)
class RawResponse:
    status: int
    body: bytes
    truncated: bool
    headers: dict[str, str] = field(default_factory=dict)  # Retry-After (VP-1h)


Transport = Callable[[Endpoint, str, str, bytes | None], RawResponse]


class HttpTransport:
    def __init__(self, connect_timeout: float, read_timeout: float) -> None:
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._local = threading.local()
        self._lock = threading.Lock()
        # close() must reach every thread's map; local storage is not shared.
        self._maps: list[dict[Endpoint, http.client.HTTPConnection]] = []

    def _map(self) -> dict[Endpoint, http.client.HTTPConnection]:
        conns = getattr(self._local, "conns", None)
        if conns is None:
            conns = {}
            self._local.conns = conns
            with self._lock:
                self._maps.append(conns)
        return conns

    def _conn_for(self, ep: Endpoint) -> http.client.HTTPConnection:
        conns = self._map()
        conn = conns.get(ep)
        if conn is not None and conn.sock is not None:
            return conn
        if conn is not None:
            conn.close()
        factory = (
            http.client.HTTPSConnection
            if ep.scheme == "https"
            else http.client.HTTPConnection
        )
        conn = factory(ep.host, ep.port, timeout=self._connect_timeout)
        conn.connect()
        conn.sock.settimeout(self._read_timeout)
        conns[ep] = conn
        return conn

    def __call__(
        self, ep: Endpoint, method: str, path: str, body: bytes | None
    ) -> RawResponse:
        conn = self._conn_for(ep)
        headers: dict[str, str] = {}
        if ep.auth_header:
            headers["Authorization"] = ep.auth_header
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, ep.base_path + path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read(MAX_RESPONSE_BYTES + 1)
        getheaders = getattr(resp, "getheaders", None)
        headers = (
            {k.lower(): v for k, v in getheaders()} if callable(getheaders) else {}
        )
        return RawResponse(resp.status, raw, len(raw) > MAX_RESPONSE_BYTES, headers)

    def drop(self, ep: Endpoint) -> None:
        conn = self._map().pop(ep, None)
        if conn is not None:
            conn.close()

    def close(self) -> None:
        with self._lock:
            maps = list(self._maps)
        for conns in maps:
            for conn in list(conns.values()):
                conn.close()
            conns.clear()


# ===== § 6. BeaconClient =====

_REQUEST_SLOT_LOCK = threading.Lock()
_next_request_start = 0.0
_MAX_ATTEMPTS = 3
_BACKOFF_BASE = 0.5


def _await_slot(delay: float) -> None:
    global _next_request_start
    if delay <= 0:
        return
    # Reserve the slot under the lock; sleep after release so workers do not serialize.
    with _REQUEST_SLOT_LOCK:
        now = time.monotonic()
        start = max(now, _next_request_start)
        _next_request_start = start + delay
        wait = start - now
    if wait > 0:
        time.sleep(wait)


def _header(headers: dict[str, str], name: str) -> str | None:
    want = name.lower()
    for key, value in headers.items():
        if key.lower() == want:
            return value
    return None


def _retry_after_delay(headers: dict[str, str], attempt: int) -> float:
    raw = _header(headers, "retry-after")
    if raw is not None:
        try:
            seconds = float(raw)
        except (TypeError, ValueError):
            seconds = float("nan")
        if math.isfinite(seconds) and seconds >= 0.0:
            return min(seconds, MAX_RETRY_AFTER)
    return _BACKOFF_BASE * (2 ** attempt) * (0.5 + random.random())


def _classify(
    status: int | None,
    exc: BaseException | None,
    _is_rewards_route: bool,
) -> Literal["retry", "fail", "semantic"]:
    if exc is not None:
        # SSLError/gaierror subclass OSError; TimeoutError is OSError in 3.10+.
        if isinstance(exc, (ssl.SSLError, socket.gaierror)):
            return "fail"
        if isinstance(exc, (TimeoutError, ConnectionError, http.client.HTTPException)):
            return "retry"
        return "fail"
    if status in (429, 503):
        return "retry"
    if status == 500:
        # Rewards and non-rewards 500 share a one-retry cap in _call.
        return "retry"
    if status in (400, 404, 405, 414):
        return "semantic"
    return "semantic"


def _promotable(exc: BaseException) -> bool:
    if isinstance(exc, BeaconTransport):
        return True
    return isinstance(exc, BeaconStatus) and exc.status == 503


class BeaconClient:
    def __init__(
        self,
        endpoints: list[Endpoint],
        transport: Transport,
        *,
        request_delay: float,
        log: Log,
    ) -> None:
        self._endpoints = endpoints
        self._transport = transport
        self._request_delay = request_delay
        self._log = log
        self._lock = threading.Lock()
        self._current = 0
        self._used: list[str] = []
        self._generation = 0
        self._pinned = False
        self._tls = threading.local()
        self._probe_head_epoch: int | None = None
        self._probe_ids: list[str] = []
        self._rewards_api: str | None = None

    def _endpoint(self) -> Endpoint:
        with self._lock:
            return self._endpoints[self._current]

    def _promote_from(self, ep: Endpoint) -> Endpoint:
        """Advance by one iff `ep` is still current.

        Concurrent failures on the same endpoint collapse to a single
        advance. If `ep` is stale, return the current endpoint and do
        not skip ahead. One promotion attempt per endpoint.
        """
        with self._lock:
            cur = self._endpoints[self._current]
            if cur is not ep:
                return cur
            nxt = self._current + 1
            if nxt >= len(self._endpoints):
                raise NoBeaconAvailable("no beacon node available")
            self._current = nxt
            self._generation += 1
            new = self._endpoints[nxt]
            shown = redact(new)
            if shown not in self._used:
                self._used.append(shown)
        try:
            self._reprobe()
        except (BeaconStatus, BeaconTransport, NoBeaconAvailable):
            pass
        return new

    def _reprobe(self) -> None:
        head = self._probe_head_epoch
        if head is None:
            return
        probe_rewards_api(self, head, self._probe_ids)

    def _call(
        self,
        method: str,
        template: str,
        fmt: dict,
        body: bytes | None,
        *,
        retry_500: bool = False,
        extra: str = "",
        allow_promote: bool = True,
    ) -> object:
        path = template.format(**fmt) + extra
        _await_slot(self._request_delay)
        ep = self._endpoint()
        shown = redact(ep)
        with self._lock:
            if shown not in self._used:
                self._used.append(shown)
        label = ep.label
        last_exc: BaseException | None = None
        raw: RawResponse | None = None
        try:
            for attempt in range(_MAX_ATTEMPTS):
                self._log.info("%s %s via %s", method, template, redact(ep))
                try:
                    raw = self._transport(ep, method, path, body)
                except (
                    ssl.SSLError,
                    socket.gaierror,
                    TimeoutError,
                    ConnectionError,
                    http.client.HTTPException,
                ) as exc:
                    last_exc = exc
                    action = _classify(None, exc, retry_500)
                    if action == "retry" and attempt + 1 < _MAX_ATTEMPTS:
                        self._transport.drop(ep)
                        time.sleep(_retry_after_delay({}, attempt))
                        continue
                    raise BeaconTransport(template, label) from exc
                if raw.truncated:
                    # Truncation leaves the keep-alive connection in an unknown state.
                    self._transport.drop(ep)
                    raise BeaconStatus(raw.status, template, label)
                if raw.status == 204:
                    return None
                if 200 <= raw.status < 300:
                    try:
                        return json.loads(raw.body)
                    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                        raise BeaconStatus(raw.status, template, label) from exc
                action = _classify(raw.status, None, retry_500)
                retry_limit = 2 if raw.status == 500 else _MAX_ATTEMPTS
                if action == "retry" and attempt + 1 < retry_limit:
                    self._transport.drop(ep)
                    time.sleep(_retry_after_delay(raw.headers, attempt))
                    continue
                raise BeaconStatus(raw.status, template, label)
            if last_exc is not None:
                raise BeaconTransport(template, label) from last_exc
            if raw is None:
                raise BeaconTransport(template, label)
            raise BeaconStatus(raw.status, template, label)
        except (BeaconStatus, BeaconTransport) as exc:
            allow = allow_promote and getattr(self._tls, "allow_promote", True)
            if not allow or not self._pinned or not _promotable(exc):
                raise
            try:
                self._promote_from(ep)
            except NoBeaconAvailable:
                if self._generation:
                    raise
                raise exc from None
            return self._call(
                method,
                template,
                fmt,
                body,
                retry_500=retry_500,
                extra=extra,
                allow_promote=allow_promote,
            )

    def _unwrap_call(
        self,
        method: str,
        template: str,
        fmt: dict,
        body: bytes | None = None,
        *,
        retry_500: bool = False,
        none_on: tuple[int, ...] = (),
    ) -> object:
        try:
            payload = self._call(method, template, fmt, body, retry_500=retry_500)
        except BeaconStatus as exc:
            if exc.status in none_on:
                return None
            raise
        if isinstance(payload, dict) and "data" in payload:
            return payload["data"]
        return payload

    def _as_list(self, payload: object, template: str) -> list:
        if payload is None:
            raise BeaconStatus(204, template, self._endpoint().label)
        rows = (
            payload["data"]
            if isinstance(payload, dict) and "data" in payload
            else payload
        )
        if not isinstance(rows, list):
            raise BeaconStatus(200, template, self._endpoint().label)
        return rows

    def spec(self) -> dict:
        return self._unwrap_call("GET", "/eth/v1/config/spec", {})

    def genesis(self) -> dict:
        return self._unwrap_call("GET", "/eth/v1/beacon/genesis", {})

    def node_version(self) -> str:
        data = self._unwrap_call("GET", "/eth/v1/node/version", {})
        return data["version"] if isinstance(data, dict) else data

    def syncing(self) -> dict:
        return self._unwrap_call("GET", "/eth/v1/node/syncing", {})

    def header(self, block_id: str) -> dict | None:
        return self._unwrap_call(
            "GET",
            "/eth/v1/beacon/headers/{block_id}",
            {"block_id": block_id},
            none_on=(404,),
        )

    def finality_checkpoints(self, state_id: str) -> dict:
        return self._unwrap_call(
            "GET",
            "/eth/v1/beacon/states/{state_id}/finality_checkpoints",
            {"state_id": state_id},
        )

    def states_validators(self, state_id: str, ids: Sequence[str]) -> list:
        if isinstance(ids, (str, bytes)):
            raise TypeError("ids must be a sequence of id strings, not str or bytes")
        id_list = list(ids)
        if not id_list:
            raise ValueError("ids must be non-empty")
        template = "/eth/v1/beacon/states/{state_id}/validators"
        fmt = {"state_id": state_id}
        try:
            payload = self._call(
                "POST", template, fmt, json.dumps({"ids": id_list}).encode()
            )
        except BeaconStatus as exc:
            if exc.status not in (404, 405, 414):
                raise
        else:
            return self._as_list(payload, template)
        rows: list = []
        for offset in range(0, len(id_list), GET_ID_CHUNK):
            chunk = id_list[offset : offset + GET_ID_CHUNK]
            query = urlencode([("id", item) for item in chunk])
            payload = self._call("GET", template, fmt, None, extra="?" + query)
            rows.extend(self._as_list(payload, template))
        return rows

    def rewards_attestations(self, epoch: int, ids: Sequence[str]) -> dict:
        id_list = list(ids)
        if not id_list:
            raise ValueError("ids must be non-empty")
        return self._unwrap_call(
            "POST",
            "/eth/v1/beacon/rewards/attestations/{epoch}",
            {"epoch": epoch},
            json.dumps(id_list).encode(),
            retry_500=True,
        )

    def rewards_block(self, slot: int) -> dict | None:
        return self._unwrap_call(
            "GET",
            "/eth/v1/beacon/rewards/blocks/{slot}",
            {"slot": slot},
            retry_500=True,
            none_on=(404,),
        )

    def rewards_sync_committee(self, slot: int, ids: Sequence[str]) -> list | None:
        return self._unwrap_call(
            "POST",
            "/eth/v1/beacon/rewards/sync_committee/{slot}",
            {"slot": slot},
            json.dumps(list(ids)).encode(),
            retry_500=True,
        )

    def proposer_duties(self, epoch: int) -> list:
        return self._unwrap_call(
            "GET",
            "/eth/v1/validator/duties/proposer/{epoch}",
            {"epoch": epoch},
        )

    def sync_committee(self, state_id: str, epoch: int) -> list:
        data = self._unwrap_call(
            "GET",
            "/eth/v1/beacon/states/{state_id}/sync_committees?epoch={epoch}",
            {"state_id": state_id, "epoch": epoch},
        )
        return data["validators"] if isinstance(data, dict) else data

    def liveness(self, epoch: int, ids: Sequence[str]) -> list:
        return self._unwrap_call(
            "POST",
            "/eth/v1/validator/liveness/{epoch}",
            {"epoch": epoch},
            json.dumps(list(ids)).encode(),
        )

    @property
    def endpoints_used(self) -> list[str]:
        with self._lock:
            return list(self._used)


# ===== § 7. Chain context and bootstrap =====


def _spec_uint(raw: dict, key: str) -> int:
    if key not in raw:
        raise UsageError(f"missing spec key {key}")
    value = parse_uint(raw[key], key)
    if (
        key in ("SLOTS_PER_EPOCH", "SECONDS_PER_SLOT", "SLOT_DURATION_MS")
        and value < 1
    ):
        raise UsageError(f"invalid {key}: {raw[key]!r}")
    return value


def _spec_seconds_per_slot(raw: dict) -> int:
    if "SLOT_DURATION_MS" in raw:
        ms = _spec_uint(raw, "SLOT_DURATION_MS")
        if ms % 1000 != 0:
            raise UsageError(f"invalid SLOT_DURATION_MS: {raw['SLOT_DURATION_MS']!r}")
        return ms // 1000
    if "SECONDS_PER_SLOT" in raw:
        return _spec_uint(raw, "SECONDS_PER_SLOT")
    raise UsageError("missing spec key SLOT_DURATION_MS and SECONDS_PER_SLOT")


def _nested_uint(obj: object, keys: tuple[str, ...], field: str) -> int:
    cur: object = obj
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            raise UsageError(f"missing {field}")
        cur = cur[key]
    return parse_uint(cur, field)


def _require_data(payload: object, what: str) -> dict:
    # header() maps 404→None; 204 is None from _call. Phase 1 abort is exit 5.
    if payload is None:
        raise NoBeaconAvailable(f"{what} unavailable")
    if not isinstance(payload, dict):
        raise UsageError(f"invalid {what}")
    return payload


def _is_syncing(status: object) -> bool:
    if not isinstance(status, dict):
        return True
    flag = status.get("is_syncing")
    if flag is False or (isinstance(flag, str) and flag.lower() == "false"):
        return False
    return True


@dataclass(frozen=True)
class Spec:
    slots_per_epoch: int
    seconds_per_slot: int
    epochs_per_sync_committee_period: int
    min_epochs_to_inactivity_penalty: int
    raw: dict[str, str]

    @property
    def epochs_per_year(self) -> float:
        return SECONDS_PER_JULIAN_YEAR / (
            self.seconds_per_slot * self.slots_per_epoch
        )


@dataclass(frozen=True)
class ChainContext:
    spec: Spec
    genesis_time: int
    network_name: str | None
    head_slot: int
    head_epoch: int
    finalized_epoch: int
    node_version: str
    rewards_api: str  # "" until VP-1m probe_rewards_api
    genesis_validators_root: str


def select_endpoint(client: BeaconClient) -> None:
    client._selected_version = ""
    for i in range(len(client._endpoints)):
        with client._lock:
            client._current = i
        try:
            version = client.node_version()
        except (BeaconStatus, BeaconTransport):
            continue
        if not isinstance(version, str) or not version:
            continue
        try:
            status = client.syncing()
        except (BeaconStatus, BeaconTransport):
            continue
        if _is_syncing(status):
            continue
        client._selected_version = version
        client._pinned = True
        return
    raise NoBeaconAvailable("no beacon node available")


def load_chain_context(client: BeaconClient) -> ChainContext:
    raw = _require_data(client.spec(), "spec")
    spec = Spec(
        slots_per_epoch=_spec_uint(raw, "SLOTS_PER_EPOCH"),
        seconds_per_slot=_spec_seconds_per_slot(raw),
        epochs_per_sync_committee_period=_spec_uint(
            raw, "EPOCHS_PER_SYNC_COMMITTEE_PERIOD"
        ),
        min_epochs_to_inactivity_penalty=_spec_uint(
            raw, "MIN_EPOCHS_TO_INACTIVITY_PENALTY"
        ),
        raw=raw,
    )
    genesis = _require_data(client.genesis(), "genesis")
    genesis_time = _nested_uint(genesis, ("genesis_time",), "genesis_time")
    raw_root = genesis.get("genesis_validators_root")
    genesis_validators_root = raw_root if isinstance(raw_root, str) else ""
    header = _require_data(client.header("head"), "head header")
    head_slot = _nested_uint(header, ("header", "message", "slot"), "slot")
    checkpoints = _require_data(
        client.finality_checkpoints("head"), "finality checkpoints"
    )
    finalized_epoch = _nested_uint(
        checkpoints, ("finalized", "epoch"), "finalized.epoch"
    )
    config_name = raw.get("CONFIG_NAME")
    network_name = (
        config_name if isinstance(config_name, str) and config_name else None
    )
    version = getattr(client, "_selected_version", "")
    if not isinstance(version, str):
        version = ""
    return ChainContext(
        spec=spec,
        genesis_time=genesis_time,
        network_name=network_name,
        head_slot=head_slot,
        head_epoch=head_slot // spec.slots_per_epoch,
        finalized_epoch=finalized_epoch,
        node_version=version,
        rewards_api="",
        genesis_validators_root=genesis_validators_root,
    )


_PROBE_VERDICT = {
    (True, True): "available",
    (True, False): "state_unavailable",
    (False, True): "available",
    (False, False): "route_absent",
}
def probe_rewards_api(
    client: BeaconClient, head_epoch: int, ids: Sequence[str]
) -> str:
    client._probe_head_epoch = head_epoch
    client._probe_ids = list(ids)
    prev = getattr(client._tls, "allow_promote", True)
    client._tls.allow_promote = False
    try:
        try:
            blocks = client.rewards_block("head")
        except BeaconStatus as exc:
            blocks_ok, blocks_404 = 200 <= exc.status < 300, exc.status == 404
        else:
            # rewards_block maps 404 → None; that None is the 404 column, not 2xx.
            blocks_ok, blocks_404 = (False, True) if blocks is None else (True, False)
        id_list = list(ids)
        if not id_list:
            # POST [] is the unfiltered rewards form on some clients; classify from GET.
            att_ok, att_404 = False, True
        else:
            try:
                att = client.rewards_attestations(head_epoch - 2, id_list)
            except BeaconStatus as exc:
                att_ok, att_404 = 200 <= exc.status < 300, exc.status == 404
            else:
                # Teku 204 unwraps to None; store-not-ready is not a 2xx success.
                att_ok, att_404 = (False, True) if att is None else (True, False)
        verdict = _PROBE_VERDICT[(blocks_ok, att_ok)]
        # 500/400 are not 2xx, so the 4-row table would say route_absent; fold them.
        if verdict == "route_absent" and not (blocks_404 and att_404):
            verdict = "state_unavailable"
        client._rewards_api = verdict
        return verdict
    finally:
        client._tls.allow_promote = prev


def _liveness_epochs(head_epoch: int) -> tuple[int, ...]:
    # Spec SHOULD: current and previous epoch only. Do not walk the window.
    if head_epoch < 1:
        return (head_epoch,)
    return (head_epoch, head_epoch - 1)


def _liveness_cause(status: int | None, node_version: str) -> str:
    ver = node_version.lower()
    if "teku" in ver:
        return "Teku (liveness off by default)"
    if "grandine" in ver:
        return "Grandine (needs --track-liveness)"
    # 400/500 name Teku/Grandine only when version did not name a client.
    if not ver:
        if status == 400:
            return "Teku (liveness off by default)"
        if status == 500:
            return "Grandine (needs --track-liveness)"
    if status is not None:
        return f"HTTP {status}"
    return "unavailable"


def _liveness_index(raw: object) -> int | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    try:
        return parse_uint(raw, "index")
    except UsageError:
        return None


def collect_liveness(
    client: "BeaconClient",
    head_epoch: int,
    ids: Sequence[str],
    node_version: str,
    log: Log | None = None,
) -> tuple[dict[int, list[dict]], str | None]:
    """Opt-in head-window sanity check. Never a degradation (RD-6)."""
    id_list = [item for item in ids if item]
    if not id_list:
        return {}, None
    by_index: dict[int, list[dict]] = {}
    for epoch in _liveness_epochs(head_epoch):
        try:
            rows = client.liveness(epoch, id_list)
        except BeaconStatus as exc:
            cause = _liveness_cause(exc.status, node_version)
            if log is not None:
                log.warn("liveness_sanity unavailable: %s", cause)
            return {}, cause
        except (BeaconTransport, NoBeaconAvailable):
            cause = _liveness_cause(None, node_version)
            if log is not None:
                log.warn("liveness_sanity unavailable: %s", cause)
            return {}, cause
        if not isinstance(rows, list):
            cause = _liveness_cause(None, node_version)
            if log is not None:
                log.warn("liveness_sanity unavailable: %s", cause)
            return {}, cause
        live_by: dict[int, bool] = {}
        for row in rows:
            if not isinstance(row, dict):
                continue
            idx = _liveness_index(row.get("index"))
            if idx is None:
                continue
            live_by[idx] = row.get("is_live") is True
        for raw in id_list:
            idx = _liveness_index(raw)
            if idx is None:
                continue
            # Missing from the response is null, not a true-negative false.
            by_index.setdefault(idx, []).append(
                {"epoch": epoch, "observed": live_by.get(idx)}
            )
    return by_index, None


# ===== § 8. Window resolution =====


@dataclass(frozen=True)
class Window:
    from_epoch: int
    to_epoch: int
    head_epoch: int
    finalized_epoch: int
    finalized_only: bool
    forced_unsafe: bool
    start_slot: int
    end_slot: int
    end_slot_reachable: bool

    @property
    def epochs(self) -> int:
        return self.to_epoch - self.from_epoch + 1

    def __iter__(self) -> Iterator[int]:
        return iter(range(self.from_epoch, self.to_epoch + 1))


def resolve_window(
    opts: Options, ctx: ChainContext, log: Log | None = None
) -> Window:
    max_safe_epoch = ctx.head_epoch - 2
    if opts.to_epoch is None:
        to_epoch = (
            max_safe_epoch
            if opts.allow_unfinalized
            else min(max_safe_epoch, ctx.finalized_epoch)
        )
    else:
        to_epoch = opts.to_epoch
    k = DEFAULT_EPOCHS if opts.epochs is None else opts.epochs
    from_epoch = (
        to_epoch - k + 1 if opts.from_epoch is None else opts.from_epoch
    )

    if from_epoch > to_epoch:
        raise UsageError(
            f"from-epoch {from_epoch} is greater than to-epoch {to_epoch}"
        )
    if from_epoch < 0 or to_epoch < 0:
        raise UsageError(f"negative epoch: {from_epoch}..{to_epoch}")
    if from_epoch > ctx.head_epoch or to_epoch > ctx.head_epoch:
        raise UsageError(
            f"epoch not yet reached (head_epoch={ctx.head_epoch})"
        )

    forced_unsafe = False
    if opts.to_epoch is not None and to_epoch > max_safe_epoch:
        if not opts.force_unsafe_window:
            raise UsageError(
                f"--to-epoch {to_epoch} exceeds MAX_SAFE_EPOCH={max_safe_epoch}"
            )
        forced_unsafe = True
        if log is not None:
            log.warn(
                "--to-epoch %s exceeds MAX_SAFE_EPOCH=%s; "
                "continuing due to --force-unsafe-window",
                to_epoch,
                max_safe_epoch,
            )

    spe = ctx.spec.slots_per_epoch
    # process_epoch fires on the last slot of E, so S has rewards through E-2.
    start_slot = (from_epoch + 1) * spe
    end_slot = (to_epoch + 2) * spe
    end_slot_reachable = end_slot <= ctx.head_slot
    if not end_slot_reachable and not opts.force_unsafe_window:
        raise UsageError(
            f"end_slot {end_slot} is not reachable from head_slot {ctx.head_slot}"
        )

    return Window(
        from_epoch=from_epoch,
        to_epoch=to_epoch,
        head_epoch=ctx.head_epoch,
        finalized_epoch=ctx.finalized_epoch,
        finalized_only=to_epoch <= ctx.finalized_epoch,
        forced_unsafe=forced_unsafe,
        start_slot=start_slot,
        end_slot=end_slot,
        end_slot_reachable=end_slot_reachable,
    )


# ===== § 9. Validator resolution =====

_KNOWN_VALIDATOR_STATUSES = frozenset(
    {
        "pending_initialized",
        "pending_queued",
        "active_ongoing",
        "active_exiting",
        "active_slashed",
        "exited_unslashed",
        "exited_slashed",
        "withdrawal_possible",
        "withdrawal_done",
    }
)


@dataclass(frozen=True)
class ValidatorRef:
    pubkey: str
    index: int | None
    status: str
    effective_balance_gwei: int | None
    activation_epoch: int | None
    exit_epoch: int | None
    slashed: bool

    def is_active_at(self, epoch: int) -> bool:
        act, ex = self.activation_epoch, self.exit_epoch
        return act is not None and ex is not None and act <= epoch < ex

    def active_epochs_in(self, window) -> int:
        start = getattr(window, "from_epoch", None)
        end = getattr(window, "to_epoch", None)
        if start is None or end is None:
            start, end = window[0], window[1]
        return sum(
            1 for epoch in range(start, end + 1) if self.is_active_at(epoch)
        )

    @property
    def rewards_eligible(self) -> bool:
        eb = self.effective_balance_gwei
        return self.index is not None and eb is not None and eb > 0


def _unknown_ref(pubkey: str) -> ValidatorRef:
    return ValidatorRef(pubkey, None, "unknown", None, None, None, False)


def _ref_from_row(row: object, log: Log) -> ValidatorRef | None:
    if not isinstance(row, dict):
        return None
    validator = row.get("validator")
    if not isinstance(validator, dict):
        return None
    raw_pk = validator.get("pubkey")
    if not isinstance(raw_pk, str):
        return None
    try:
        pubkey = normalize_pubkey(raw_pk, "validator.pubkey")
    except UsageError:
        return None
    status = row.get("status")
    if not isinstance(status, str):
        status = ""
    if status not in _KNOWN_VALIDATOR_STATUSES:
        log.info("unrecognised validator status %s for %s", status, pubkey)
    return ValidatorRef(
        pubkey=pubkey,
        index=parse_uint(row.get("index"), "index"),
        status=status,
        effective_balance_gwei=parse_uint(
            validator.get("effective_balance"), "effective_balance"
        ),
        activation_epoch=parse_uint(
            validator.get("activation_epoch"), "activation_epoch"
        ),
        exit_epoch=parse_uint(validator.get("exit_epoch"), "exit_epoch"),
        slashed=validator.get("slashed") is True,
    )


def resolve_validators(
    client: BeaconClient, pubkeys: list[str]
) -> list[ValidatorRef]:
    keys = [normalize_pubkey(pk, "pubkey") for pk in pubkeys]
    if not keys:
        return []
    # Unknown ids are dropped and order is unspecified; key by pubkey.
    by_pk: dict[str, ValidatorRef] = {}
    for row in client.states_validators("head", keys):
        ref = _ref_from_row(row, client._log)
        if ref is not None:
            by_pk[ref.pubkey] = ref
    return [by_pk.get(pk) or _unknown_ref(pk) for pk in keys]


_GVR_RE = re.compile(r"0x[0-9a-fA-F]{64}")


def _cache_dir() -> str:
    xdg = os.environ.get("XDG_CACHE_HOME")
    # Relative XDG_CACHE_HOME would land inside the repo (SM3).
    if xdg and os.path.isabs(xdg):
        return os.path.join(xdg, "rvc-validator-perf")
    return os.path.join(os.path.expanduser("~"), ".cache", "rvc-validator-perf")


def _cache_path(root: str) -> str | None:
    if _GVR_RE.fullmatch(root) is None:
        return None
    return os.path.join(_cache_dir(), f"indices-{root}.json")


def _cache_miss(log: Log | None, reason: object) -> None:
    if log is not None:
        log.info("index cache miss: %s", reason)
    return None


def _entries_from_payload(data: object, root: str) -> dict[str, int] | None:
    if not isinstance(data, dict):
        return None
    if data.get("genesis_validators_root") != root:
        return None
    raw = data.get("entries")
    if not isinstance(raw, dict):
        return None
    out: dict[str, int] = {}
    for key, val in raw.items():
        if not isinstance(key, str) or type(val) is not int or val < 0:
            continue
        out[key] = val
    return out


def _cache_read(
    root: str, pubkeys: Sequence[str], log: Log | None = None
) -> dict[str, int] | None:
    path = _cache_path(root)
    if path is None:
        return _cache_miss(log, "genesis_validators_root")
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return _cache_miss(log, "not found")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return _cache_miss(log, exc)
    entries = _entries_from_payload(data, root)
    if entries is None:
        return _cache_miss(log, "genesis_validators_root")
    out: dict[str, int] = {}
    for pk in pubkeys:
        val = entries.get(pk)
        if type(val) is not int or val < 0:
            return _cache_miss(log, "incomplete")
        out[pk] = val
    return out


def _load_cache_entries(root: str) -> dict[str, int]:
    path = _cache_path(root)
    if path is None:
        return {}
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return _entries_from_payload(data, root) or {}


def _ensure_cache_dir() -> str:
    directory = _cache_dir()
    os.makedirs(directory, mode=0o700, exist_ok=True)
    os.chmod(directory, 0o700)
    return directory


def _cache_write(
    root: str, entries: dict[str, int], log: Log | None = None
) -> None:
    dest = _cache_path(root)
    if dest is None or not entries:
        return
    tmp = ""
    try:
        _ensure_cache_dir()
        merged = _load_cache_entries(root)
        merged.update(entries)
        payload = {
            "genesis_validators_root": root,
            "written_at": datetime.now(timezone.utc).isoformat(),
            "entries": merged,
        }
        # Random tmp name; dest+".tmp" is symlink-plantable.
        fd, tmp = tempfile.mkstemp(prefix="idx.", suffix=".tmp", dir=_cache_dir())
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        os.replace(tmp, dest)
    except OSError as exc:
        if log is not None:
            log.info("index cache write failed: %s", exc)
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _hydrate_cached_refs(
    client: BeaconClient,
    state_id: str,
    pubkeys: Sequence[str],
    cached: dict[str, int],
    log: Log | None = None,
) -> tuple[list[ValidatorRef] | None, list | None]:
    ids = [str(cached[pk]) for pk in pubkeys if pk in cached]
    if not ids:
        return None, None
    try:
        rows = client.states_validators(state_id, ids)
    except (BeaconStatus, BeaconTransport):
        return None, None
    lg = log if log is not None else client._log
    by_pk: dict[str, ValidatorRef] = {}
    for row in rows:
        ref = _ref_from_row(row, lg)
        if ref is not None:
            by_pk[ref.pubkey] = ref
    refs = [by_pk.get(pk) or _unknown_ref(pk) for pk in pubkeys]
    if all(ref.index is None for ref in refs):
        return None, None
    return refs, rows


# ===== § 10. Attestation metrics — M1–M6 =====


def _ideal_row(row: dict) -> tuple[int, int, int, int]:
    return (
        parse_int(row.get("effective_balance"), "effective_balance"),
        parse_int(row.get("source"), "source"),
        parse_int(row.get("target"), "target"),
        parse_int(row.get("head"), "head"),
    )


def detect_leak(ideal_rows: list[dict]) -> bool:
    if not ideal_rows:
        return False
    _eb, source, target, head = max(
        (_ideal_row(row) for row in ideal_rows), key=lambda t: t[0]
    )
    return source == target == head == 0


def build_ideal_index(
    ideal_rows: list[dict],
) -> dict[int, tuple[int, int, int]]:
    index: dict[int, tuple[int, int, int]] = {}
    for row in ideal_rows:
        eb, source, target, head = _ideal_row(row)
        index[eb] = (source, target, head)
    return index


@dataclass(frozen=True)
class EpochOutcome:
    epoch: int
    source_credited: bool
    target_credited: bool
    head_credited: bool | None
    missed: bool
    flag_actual_gwei: int
    flag_ideal_gwei: int | None
    inactivity_gwei: int
    leak: bool
    source_gwei: int = 0
    target_gwei: int = 0
    head_gwei: int = 0


def evaluate_epoch(
    epoch: int,
    resp: dict,
    refs: list[ValidatorRef],
    eb_by_index: dict[int, int],
    log: Log | None = None,
) -> dict[int, EpochOutcome]:
    ideal_rows = resp.get("ideal_rewards") or []
    leak = detect_leak(ideal_rows)
    ideals = build_ideal_index(ideal_rows)
    by_index: dict[int, dict] = {}
    for row in resp.get("total_rewards") or []:
        by_index[parse_int(row.get("validator_index"), "validator_index")] = row
    out: dict[int, EpochOutcome] = {}
    for ref in refs:
        ineligible = not ref.is_active_at(epoch)
        if ineligible:
            continue
        idx = ref.index
        # Missing row is "not eligible", not a zero reward (clients disagree on fill).
        missing_row = idx is None or idx not in by_index
        if missing_row:
            continue
        row = by_index[idx]
        source = parse_int(row.get("source"), "source")
        target = parse_int(row.get("target"), "target")
        head = parse_int(row.get("head"), "head")
        inactivity = parse_int(row.get("inactivity"), "inactivity")
        if head > 0 and (source < 0 or target < 0) and log is not None:
            log.info(
                "head > 0 implies source/target >= 0: epoch %s index %s source=%s target=%s",
                epoch,
                idx,
                source,
                target,
            )
        # Sign, not positivity: a credited leak flag pays 0. Head is None in a leak.
        source_credited = source >= 0
        target_credited = target >= 0
        missed = source < 0 and target < 0
        head_credited = None if leak else head > 0
        flags = None if leak else ideals.get(eb_by_index.get(idx))
        flag_ideal_gwei = None if flags is None else flags[0] + flags[1] + flags[2]
        out[idx] = EpochOutcome(
            epoch=epoch,
            source_credited=source_credited,
            target_credited=target_credited,
            head_credited=head_credited,
            missed=missed,
            flag_actual_gwei=source + target + head,
            flag_ideal_gwei=flag_ideal_gwei,
            inactivity_gwei=inactivity,
            leak=leak,
            source_gwei=source,
            target_gwei=target,
            head_gwei=head,
        )
    return out


@dataclass(frozen=True)
class Degradation:
    metric: str
    scope: str
    reason: str
    detail: str


@dataclass
class RequestBudget:
    extra: int = 0
    flagged: bool = False
    _lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )

    def add_extra(self, n: int = 2) -> None:
        with self._lock:
            self.extra += n
            self.flagged = True


_SPLIT_DEPTH = 2


def _merge_attestation_rewards(parts: list[dict]) -> dict:
    merged = dict(parts[0])
    total: list = []
    ideals: dict[int, dict] = {}
    for part in parts:
        total.extend(part.get("total_rewards") or [])
        for row in part.get("ideal_rewards") or []:
            if not isinstance(row, dict):
                continue
            try:
                eb = parse_int(row.get("effective_balance"), "effective_balance")
            except UsageError:
                continue
            ideals[eb] = row
    merged["total_rewards"] = total
    merged["ideal_rewards"] = list(ideals.values())
    return merged


def _fetch_epoch_rewards(
    client: BeaconClient, epoch: int, ids: list[str], budget, depth: int = 0
):
    try:
        return client.rewards_attestations(epoch, ids)
    except BeaconStatus as exc:
        if exc.status != 500 or depth >= _SPLIT_DEPTH or len(ids) < 2:
            raise
        mid = len(ids) // 2
        budget.add_extra(2)
        parts: list[dict] = []
        err: BaseException | None = None
        for chunk in (ids[:mid], ids[mid:]):
            try:
                part = _fetch_epoch_rewards(
                    client, epoch, chunk, budget, depth + 1
                )
            except BeaconStatus as child:
                err = child
                continue
            if isinstance(part, dict):
                parts.append(part)
        # A mixed 500 must not look like a missing row with no degradation.
        if err is not None:
            raise err
        if len(parts) != 2:
            raise
        return _merge_attestation_rewards(parts)


def collect_attestations(
    client: BeaconClient,
    w: Window,
    refs: Sequence[ValidatorRef],
    pool,
    budget,
    rewards_api: str = "available",
) -> tuple[dict[int, list[EpochOutcome]], list[Degradation]]:
    eligible = [ref for ref in refs if ref.rewards_eligible]
    ids = [str(ref.index) for ref in eligible]
    eb_by_index = {
        ref.index: ref.effective_balance_gwei
        for ref in eligible
        if ref.index is not None and ref.effective_balance_gwei is not None
    }
    degs = [
        Degradation(
            "attestation",
            f"validator:{ref.index}",
            "effective_balance_zero",
            "",
        )
        for ref in refs
        if ref.index is not None and not ref.rewards_eligible
    ]
    out: dict[int, list[EpochOutcome]] = {
        ref.index: [] for ref in eligible if ref.index is not None
    }
    # POST [] is unfiltered on some clients.
    if not ids:
        return out, degs
    if rewards_api == "route_absent":
        degs.append(
            Degradation("attestation", "run", "rewards_api_unsupported", "")
        )
        return out, degs
    log = getattr(client, "_log", None)
    start_gen: dict[int, int] = {}

    def worker(epoch: int) -> dict[int, EpochOutcome]:
        start_gen[epoch] = getattr(client, "_generation", 0)
        resp = _fetch_epoch_rewards(client, epoch, ids, budget)
        if not isinstance(resp, dict):
            raise BeaconStatus(
                204,
                "/eth/v1/beacon/rewards/attestations/{epoch}",
                client._endpoint().label,
            )
        return evaluate_epoch(epoch, resp, eligible, eb_by_index, log=log)

    futs = {pool.submit(worker, epoch): epoch for epoch in w}
    for fut in as_completed(futs):
        epoch = futs[fut]
        try:
            reduced = fut.result()
        except (BeaconStatus, BeaconTransport) as exc:
            detail = (
                f"HTTP {exc.status}"
                if isinstance(exc, BeaconStatus)
                else "transport"
            )
            started = start_gen.get(epoch, 0)
            reason = (
                "endpoint_failover"
                if getattr(client, "_generation", 0) > started or started > 0
                else "state_unavailable"
            )
            degs.append(
                Degradation("attestation", f"epoch:{epoch}", reason, detail)
            )
            continue
        for idx, outcome in reduced.items():
            out.setdefault(idx, []).append(outcome)
        if any(o.leak for o in reduced.values()):
            degs.append(
                Degradation("head_rate", f"epoch:{epoch}", "inactivity_leak", "")
            )
    for series in out.values():
        series.sort(key=lambda o: o.epoch)
    return out, degs


# ===== § 11. Proposals — M7 and M9's proposer component =====

# Lighthouse/Prysm/Grandine 404; Teku 503; Nimbus 400 (PrunedStateError); Lodestar 500.
_DUTIES_UNAVAILABLE = frozenset({400, 404, 500, 503})


@dataclass(frozen=True)
class ProposalOutcome:
    slot: int
    epoch: int
    validator_index: int
    included: bool | None
    reward_gwei: int | None


def _proposal_from_duty(
    row: object, epoch: int, index_set: set[int]
) -> ProposalOutcome | None:
    if not isinstance(row, dict):
        return None
    try:
        idx = parse_uint(row.get("validator_index"), "validator_index")
        slot = parse_uint(row.get("slot"), "slot")
    except UsageError:
        return None
    if idx not in index_set:
        return None
    return ProposalOutcome(slot, epoch, idx, None, None)


def _window_slots_per_epoch(w: Window) -> int | None:
    n = w.epochs
    delta = w.end_slot - w.start_slot
    if n <= 0 or delta <= 0 or delta % n:
        return None
    spe = delta // n
    return spe if spe >= 1 else None


def _duties_for_epoch(
    rows: list,
    epoch: int,
    index_set: set[int],
    spe: int | None,
) -> list[ProposalOutcome]:
    slot_lo = epoch * spe if spe is not None else None
    slot_hi = slot_lo + spe if slot_lo is not None and spe is not None else None
    cap = spe
    seen: set[int] = set()
    hits: list[ProposalOutcome] = []
    for row in rows:
        outcome = _proposal_from_duty(row, epoch, index_set)
        if outcome is None:
            continue
        if slot_lo is not None and slot_hi is not None and not (
            slot_lo <= outcome.slot < slot_hi
        ):
            continue
        if outcome.slot in seen:
            continue
        if cap is not None and len(hits) >= cap:
            break
        seen.add(outcome.slot)
        hits.append(outcome)
    return hits


def _block_reward_fields(resp: object) -> tuple[int, int] | None:
    if not isinstance(resp, dict):
        return None
    try:
        return (
            parse_uint(resp.get("proposer_index"), "proposer_index"),
            parse_uint(resp.get("total"), "total"),
        )
    except UsageError:
        return None


def _header_proposer_index(data: object) -> int | None:
    if not isinstance(data, dict):
        return None
    header = data.get("header")
    if not isinstance(header, dict):
        return None
    message = header.get("message")
    if not isinstance(message, dict):
        return None
    try:
        return parse_uint(message.get("proposer_index"), "proposer_index")
    except UsageError:
        return None


def _reward_unreadable(epoch: int, slot: int) -> Degradation:
    return Degradation(
        "proposals",
        f"epoch:{epoch}",
        "block_reward_unavailable",
        f"slot {slot}",
    )


def _confirm_inclusion(
    client: BeaconClient,
    slot: int,
    validator_index: int,
    epoch: int,
    rewards_api: str,
) -> tuple[bool | None, int | None, Degradation | None]:
    if rewards_api != "route_absent":
        try:
            resp = client.rewards_block(slot)
        except (BeaconStatus, BeaconTransport):
            resp = None
        fields = _block_reward_fields(resp)
        if fields is not None:
            proposer, total = fields
            if proposer != validator_index:
                return False, None, None
            return True, total, None
        # 404, {"data": null}, and unreadable 200 all look like None here.
    try:
        header = client.header(str(slot))
    except (BeaconStatus, BeaconTransport):
        return None, None, None
    if header is None:
        return False, None, None
    proposer = _header_proposer_index(header)
    if proposer is not None and proposer != validator_index:
        return False, None, None
    if rewards_api == "route_absent":
        return True, None, None
    return True, None, _reward_unreadable(epoch, slot)


def collect_proposals(
    client: BeaconClient,
    w: Window,
    index_set: set[int],
    pool,
    budget,
    rewards_api: str = "available",
) -> tuple[dict[int, list[ProposalOutcome]], list[Degradation], bool]:
    degs: list[Degradation] = []
    out: dict[int, list[ProposalOutcome]] = {idx: [] for idx in index_set}
    available = True
    spe = _window_slots_per_epoch(w)
    template = "/eth/v1/validator/duties/proposer/{epoch}"

    def worker(epoch: int) -> list[ProposalOutcome]:
        rows = client.proposer_duties(epoch)
        if not isinstance(rows, list):
            # Empty-list would report scheduled=0 with no degradation.
            raise BeaconStatus(200, template, client._endpoint().label)
        return _duties_for_epoch(rows, epoch, index_set, spe)

    futs = {pool.submit(worker, epoch): epoch for epoch in w}
    for fut in as_completed(futs):
        epoch = futs[fut]
        try:
            hits = fut.result()
        except (BeaconStatus, BeaconTransport) as exc:
            # Transport and unknown codes abort as exit 1/5 if left uncaught.
            available = False
            detail = (
                f"HTTP {exc.status}"
                if isinstance(exc, BeaconStatus)
                else "transport"
            )
            degs.append(
                Degradation(
                    "proposals",
                    f"epoch:{epoch}",
                    "proposer_duties_unavailable",
                    detail,
                )
            )
            continue
        for outcome in hits:
            out.setdefault(outcome.validator_index, []).append(outcome)

    def fill(
        outcome: ProposalOutcome,
    ) -> tuple[ProposalOutcome, Degradation | None]:
        included, reward, deg = _confirm_inclusion(
            client,
            outcome.slot,
            outcome.validator_index,
            outcome.epoch,
            rewards_api,
        )
        return replace(outcome, included=included, reward_gwei=reward), deg

    pending = [o for series in out.values() for o in series]
    filled: dict[int, list[ProposalOutcome]] = {idx: [] for idx in out}
    confirm_futs = {pool.submit(fill, o): o for o in pending}
    for fut in as_completed(confirm_futs):
        try:
            outcome, deg = fut.result()
        except (BeaconStatus, BeaconTransport):
            outcome, deg = confirm_futs[fut], None
        filled.setdefault(outcome.validator_index, []).append(outcome)
        if deg is not None:
            degs.append(deg)
    for series in filled.values():
        series.sort(key=lambda o: o.slot)
    return filled, degs, available


# ===== § 12. Sync committee — M8 =====


@dataclass(frozen=True)
class SyncOutcome:
    in_committee: bool
    slots_eligible: int
    slots_signed: int
    reward_gwei: int

    @property
    def participation_rate(self) -> float | None:
        if not self.in_committee or self.slots_eligible <= 0:
            return None
        return self.slots_signed / self.slots_eligible


def sync_periods(w: Window, spec: Spec) -> list[int]:
    n = spec.epochs_per_sync_committee_period
    return list(range(w.from_epoch // n, w.to_epoch // n + 1))


def sync_period_state_id(
    w: Window, spec: Spec, period: int, head_slot: int
) -> str:
    # Query epoch, not w.start_slot: start_slot is (from_epoch+1)*SPE (RD-4)
    # and already sits in the next period when from_epoch is a period's last.
    slot = _sync_query_epoch(w, spec, period) * spec.slots_per_epoch
    return "head" if slot > head_slot else str(slot)


def _sync_query_epoch(w: Window, spec: Spec, period: int) -> int:
    return max(w.from_epoch, period * spec.epochs_per_sync_committee_period)


def _sync_member_indices(raw: object, ours: set[int]) -> set[int]:
    rows = raw if isinstance(raw, list) else []
    found: set[int] = set()
    for item in rows:
        if isinstance(item, int):
            idx = item
        else:
            try:
                idx = parse_uint(item, "index")
            except UsageError:
                continue
        if idx in ours:
            found.add(idx)
    return found


def _empty_sync(indices: set[int]) -> dict[int, SyncOutcome]:
    blank = SyncOutcome(False, 0, 0, 0)
    return {idx: blank for idx in indices}


def _classify_sync_row(reward: int | None) -> str:
    if reward is None:
        return "skipped"
    if reward > 0:
        return "signed"
    return "missed"


def _sync_reward_row(row: object) -> tuple[int, int] | None:
    if not isinstance(row, dict):
        return None
    try:
        idx = parse_uint(row.get("validator_index"), "validator_index")
        reward = parse_int(row.get("reward"), "reward")
    except UsageError:
        return None
    return idx, reward


def _sync_period_of_slot(slot: int, spec: Spec) -> int:
    return (slot // spec.slots_per_epoch) // spec.epochs_per_sync_committee_period


def _sync_scan_slots(w: Window, spec: Spec) -> range:
    # M8 is [from_epoch, to_epoch]; start_slot/end_slot are RD-4 snapshots.
    spe = spec.slots_per_epoch
    return range(w.from_epoch * spe, (w.to_epoch + 1) * spe)


def collect_sync(
    client: BeaconClient,
    w: Window,
    ctx: ChainContext,
    index_set,
    pool,
    budget,
) -> tuple[dict[int, SyncOutcome], list[Degradation]]:
    indices = set(index_set)
    if not indices:
        return {}, []
    spec = ctx.spec
    degs: list[Degradation] = []
    members_by_period: dict[int, set[int]] = {}

    def worker(period: int) -> set[int]:
        epoch = _sync_query_epoch(w, spec, period)
        state_id = sync_period_state_id(w, spec, period, ctx.head_slot)
        return _sync_member_indices(
            client.sync_committee(state_id, epoch), indices
        )

    futs = {
        pool.submit(worker, period): period for period in sync_periods(w, spec)
    }
    for fut in as_completed(futs):
        period = futs[fut]
        try:
            members_by_period[period] = fut.result()
        except (BeaconStatus, BeaconTransport) as exc:
            epoch = _sync_query_epoch(w, spec, period)
            if isinstance(exc, BeaconStatus) and exc.status == 400:
                detail = (
                    f"HTTP {exc.status} Epoch is outside the sync committee "
                    "period of the state (state_id must sit inside the period)"
                )
            elif isinstance(exc, BeaconStatus):
                detail = f"HTTP {exc.status}"
            else:
                detail = "transport"
            degs.append(
                Degradation(
                    "sync",
                    f"epoch:{epoch}",
                    "sync_committees_unavailable",
                    detail,
                )
            )
    if degs:
        return _empty_sync(indices), degs
    members = set().union(*members_by_period.values()) if members_by_period else set()
    if not members:
        return {
            idx: SyncOutcome(False, 0, 0, 0) for idx in indices
        }, []

    slots = _sync_scan_slots(w, spec)
    n_slots = len(slots)
    if n_slots > 0:
        # SM2 carve-out: per-slot scan is the documented exception to the 120 bound.
        budget.add_extra(n_slots)
        log = getattr(client, "_log", None)
        if log is not None:
            log.warn(
                "sync committee scan issued %s extra requests (SM2 carve-out)",
                n_slots,
            )

    def scan_slot(slot: int):
        period = _sync_period_of_slot(slot, spec)
        slot_members = members_by_period.get(period) or set()
        ids = [str(i) for i in sorted(slot_members or members)]
        try:
            return client.rewards_sync_committee(slot, ids)
        except BeaconStatus as exc:
            if exc.status == 404:
                return None
            raise

    eligible = {idx: 0 for idx in members}
    signed = {idx: 0 for idx in members}
    reward = {idx: 0 for idx in members}
    scan_futs = {pool.submit(scan_slot, slot): slot for slot in slots}
    for fut in as_completed(scan_futs):
        slot = scan_futs[fut]
        rows = fut.result()
        # Eligible set is this slot's period, not the window union.
        slot_members = members_by_period.get(_sync_period_of_slot(slot, spec)) or set()
        if not slot_members or rows is None or not isinstance(rows, list):
            continue
        by_idx: dict[int, int] = {}
        for row in rows:
            parsed = _sync_reward_row(row)
            if parsed is None:
                continue
            idx, rew = parsed
            if idx in slot_members:
                by_idx[idx] = rew
        for idx in slot_members:
            if idx not in by_idx:
                eligible[idx] += 1
                continue
            kind = _classify_sync_row(by_idx[idx])
            if kind == "skipped":
                continue
            eligible[idx] += 1
            if kind == "signed":
                signed[idx] += 1
            reward[idx] += by_idx[idx]
    return {
        idx: SyncOutcome(
            idx in members,
            eligible.get(idx, 0),
            signed.get(idx, 0),
            reward.get(idx, 0),
        )
        for idx in indices
    }, []


# ===== § 13. Balances and effective balance =====


@dataclass(frozen=True)
class BalanceSnapshot:
    start_gwei: int | None
    end_gwei: int | None
    eb_start_gwei: int | None
    eb_end_gwei: int | None

    @property
    def delta_gwei(self) -> int | None:
        if self.start_gwei is None or self.end_gwei is None:
            return None
        return self.end_gwei - self.start_gwei


@dataclass(frozen=True)
class BalanceReconciliation:
    reconciliation: str
    consensus_reward_gwei: int | None
    exit_code: int


def _row_balance(row: object) -> tuple[int, int, int] | None:
    if not isinstance(row, dict):
        return None
    validator = row.get("validator")
    if not isinstance(validator, dict):
        return None
    try:
        return (
            parse_uint(row.get("index"), "index"),
            parse_uint(row.get("balance"), "balance"),
            parse_uint(validator.get("effective_balance"), "effective_balance"),
        )
    except UsageError:
        return None


def _snapshot_balances(rows: Sequence[object]) -> dict[int, tuple[int, int]]:
    out: dict[int, tuple[int, int]] = {}
    for row in rows:
        parsed = _row_balance(row)
        if parsed is not None:
            index, balance, eb = parsed
            out[index] = (balance, eb)
    return out


def _snapshot(
    client: BeaconClient, slot: int, ids: list[str]
) -> dict[int, tuple[int, int]] | None:
    # D5: this route carries balance and validator.effective_balance.
    try:
        rows = client.states_validators(str(slot), ids)
    except (BeaconStatus, BeaconTransport):
        return None
    out = _snapshot_balances(rows)
    return out or None


def collect_balances(
    client: BeaconClient,
    w: Window,
    refs: Sequence[ValidatorRef],
    *,
    start: dict[int, tuple[int, int]] | None = None,
) -> tuple[dict[int, BalanceSnapshot], list[Degradation]]:
    ids = [str(ref.index) for ref in refs if ref.index is not None]
    degradations: list[Degradation] = []
    end: dict[int, tuple[int, int]] = {}
    if start is None:
        start = {}
        if ids:
            got = _snapshot(client, w.start_slot, ids)
            if got is None:
                degradations.append(
                    Degradation(
                        "balance",
                        "run",
                        "state_unavailable",
                        f"slot {w.start_slot}",
                    )
                )
            else:
                start = got
    if ids:
        if w.end_slot_reachable:
            got = _snapshot(client, w.end_slot, ids)
            if got is None:
                degradations.append(
                    Degradation(
                        "balance", "run", "state_unavailable", f"slot {w.end_slot}"
                    )
                )
            else:
                end = got
        else:
            degradations.append(
                Degradation(
                    "balance", "run", "state_unavailable", "end_slot unreachable"
                )
            )
    snaps: dict[int, BalanceSnapshot] = {}
    for ref in refs:
        if ref.index is None:
            continue
        s_bal, s_eb = start.get(ref.index, (None, None))
        e_bal, e_eb = end.get(ref.index, (None, None))
        snaps[ref.index] = BalanceSnapshot(s_bal, e_bal, s_eb, e_eb)
    return snaps, degradations


def effective_balance_for(
    snap: BalanceSnapshot, ref: ValidatorRef
) -> tuple[int | None, bool]:
    if snap.eb_end_gwei is None:
        return ref.effective_balance_gwei, False
    if snap.eb_start_gwei is None:
        return snap.eb_end_gwei, False
    return snap.eb_end_gwei, snap.eb_start_gwei != snap.eb_end_gwei


def reconcile_balance(
    delta_gwei: int | None, consensus_reward_gwei: int | None
) -> BalanceReconciliation:
    if delta_gwei is None or consensus_reward_gwei is None:
        status = "unavailable"
    elif abs(delta_gwei - consensus_reward_gwei) > BALANCE_TOLERANCE_GWEI:
        status = "diverged"
    else:
        status = "consistent"
    # A8: annotation only; never rewrite the consensus reward or raise.
    return BalanceReconciliation(status, consensus_reward_gwei, EXIT_OK)


def _use_rewards_api(
    outcomes: Sequence[EpochOutcome],
    ref: ValidatorRef,
    window: Window,
    attestation_degraded: bool,
) -> bool:
    if outcomes or not attestation_degraded:
        return True
    # Unknown is missing data, not R9 (known, zero active epochs).
    if ref.index is None:
        return False
    return ref.active_epochs_in(window) == 0


def _assemble_rewards(
    outcomes: Sequence[EpochOutcome],
    *,
    delta_gwei: int | None,
    proposer_gwei: int | None,
    sync_gwei: int,
    use_api: bool,
) -> tuple[dict, int | None, str | None]:
    if use_api:
        inactivity = sum(o.inactivity_gwei for o in outcomes)
        total = (
            sum(o.flag_actual_gwei for o in outcomes) + inactivity + sync_gwei
        )
        if proposer_gwei is not None:
            total += proposer_gwei
        components = {
            "source": sum(o.source_gwei for o in outcomes),
            "target": sum(o.target_gwei for o in outcomes),
            "head": sum(o.head_gwei for o in outcomes),
            "inactivity": inactivity,
            "proposer": proposer_gwei,
            "sync": sync_gwei,
            "total": total,
        }
        return components, total, "rewards_api"
    # G5: no flag data must not become a silent 0.
    total = delta_gwei
    components = {
        "source": None,
        "target": None,
        "head": None,
        "inactivity": None,
        "proposer": None,
        "sync": None,
        "total": total,
    }
    source = "balance_delta" if total is not None else None
    return components, total, source


# ===== § 14. Aggregation, APR, thresholds =====


def _rate(numerator: float, denominator: float) -> float | None:
    if not denominator:
        return None
    return numerator / denominator


def _weighted(
    values: Sequence[float], weights: Sequence[float]
) -> float | None:
    acc = 0.0
    total_w = 0.0
    for value, weight in zip(values, weights):
        acc += value * weight
        total_w += weight
    return _rate(acc, total_w)


@dataclass(frozen=True)
class ValidatorReport:
    ref: ValidatorRef
    active_epochs: int
    participation_rate: float | None
    source_rate: float | None
    target_rate: float | None
    head_rate: float | None
    missed_attestations: int | None
    attester_effectiveness: float | None
    effectiveness_method: str
    leak_epochs_excluded: int
    proposals: dict
    sync: SyncOutcome | None
    balance: BalanceSnapshot
    rewards_gwei: dict
    reward_source: str | None
    estimated_apr: float | None
    window_epochs: int
    degradations: list[Degradation]
    liveness_sanity: list | None = None


def _proposal_counts(
    outcomes: Sequence[ProposalOutcome], duties_available: bool
) -> dict:
    included = sum(1 for o in outcomes if o.included is True)
    if not duties_available:
        return {"scheduled": None, "included": included, "missed": None}
    return {
        "scheduled": len(outcomes),
        "included": included,
        "missed": sum(1 for o in outcomes if o.included is False),
    }


def _proposer_reward_gwei(outcomes: Sequence[ProposalOutcome]) -> int | None:
    # Included-but-unreadable is null, never 0 (G5 / RD-8).
    readable = 0
    for outcome in outcomes:
        if outcome.included is not True:
            continue
        if outcome.reward_gwei is None:
            return None
        readable += outcome.reward_gwei
    return readable


def build_validator_report(
    ref: ValidatorRef,
    outcomes: list[EpochOutcome],
    snap: BalanceSnapshot,
    spec: Spec,
    window: Window,
    degradations: list[Degradation] | None = None,
    *,
    proposer_gwei: int | None = None,
    sync_gwei: int = 0,
    proposal_outcomes: Sequence[ProposalOutcome] | None = None,
    duties_available: bool = True,
    sync: SyncOutcome | None = None,
    attestation_degraded: bool = False,
) -> ValidatorReport:
    degs = list(degradations or ())
    props = list(proposal_outcomes or ())
    if proposer_gwei is None:
        proposer_gwei = _proposer_reward_gwei(props)
    if sync is not None and sync.in_committee:
        sync_gwei = sync.reward_gwei
    else:
        sync = None
    # Unknown to the BN is state_unavailable (exit 3), not R9's known zero-active.
    if ref.index is None or ref.status == "unknown":
        degs.append(
            Degradation(
                "attestation",
                "validator:unknown",
                "state_unavailable",
                ref.pubkey,
            )
        )
    n_active = len(outcomes)
    n_head = sum(1 for o in outcomes if o.head_credited is not None)
    m6_actual = 0
    m6_ideal = 0
    for o in outcomes:
        if o.flag_ideal_gwei is not None:
            m6_actual += o.flag_actual_gwei
            m6_ideal += o.flag_ideal_gwei
        elif not o.leak:
            degs.append(
                Degradation(
                    "attester_effectiveness",
                    f"epoch:{o.epoch}",
                    "ideal_row_missing",
                    "",
                )
            )
    raw = _rate(m6_actual, m6_ideal)
    effectiveness = None if raw is None else max(0.0, min(1.0, raw))
    use_api = _use_rewards_api(outcomes, ref, window, attestation_degraded)
    rewards_gwei, total, reward_source = _assemble_rewards(
        outcomes,
        delta_gwei=snap.delta_gwei,
        proposer_gwei=proposer_gwei,
        sync_gwei=sync_gwei,
        use_api=use_api,
    )
    eb, _changed = effective_balance_for(snap, ref)
    window_epochs = window.epochs
    # 0/EB annualizes to 0.0; an empty rewards-api series is null.
    apr = (
        None
        if total is None or (use_api and n_active == 0)
        else _rate(total * spec.epochs_per_year, (eb or 0) * window_epochs)
    )
    return ValidatorReport(
        ref=ref,
        active_epochs=n_active,
        participation_rate=_rate(
            sum(1 for o in outcomes if o.source_credited or o.target_credited),
            n_active,
        ),
        source_rate=_rate(sum(1 for o in outcomes if o.source_credited), n_active),
        target_rate=_rate(sum(1 for o in outcomes if o.target_credited), n_active),
        head_rate=_rate(
            sum(1 for o in outcomes if o.head_credited is True), n_head
        ),
        missed_attestations=(
            None if n_active == 0 else sum(1 for o in outcomes if o.missed)
        ),
        attester_effectiveness=effectiveness,
        effectiveness_method="reward_ratio",
        leak_epochs_excluded=sum(1 for o in outcomes if o.leak),
        proposals=_proposal_counts(props, duties_available),
        sync=sync,
        balance=snap,
        rewards_gwei=rewards_gwei,
        reward_source=reward_source,
        estimated_apr=apr,
        window_epochs=window_epochs,
        degradations=degs,
    )


def build_aggregate(reports: list[ValidatorReport], spec: Spec) -> dict:
    by_status: dict[str, int] = {}
    for report in reports:
        status = report.ref.status
        by_status[status] = by_status.get(status, 0) + 1
    included = [
        r
        for r in reports
        if r.ref.index is not None
        and not r.ref.status.startswith("active_slashed")
    ]

    def mean(attr: str) -> float | None:
        pairs = [
            (getattr(r, attr), r.active_epochs)
            for r in included
            if getattr(r, attr) is not None
        ]
        return _weighted([v for v, _ in pairs], [w for _, w in pairs])

    missed_parts = [
        r.missed_attestations
        for r in included
        if r.missed_attestations is not None
    ]
    reward_parts = [
        r.rewards_gwei["total"]
        for r in included
        if r.rewards_gwei.get("total") is not None
    ]
    sources = [r.reward_source for r in included]
    # Rates weigh by active_epochs; APR weighs by EB (RD-5).
    reward_sum = 0
    eb_sum = 0
    window_epochs = 0
    for report in included:
        if (
            report.active_epochs == 0
            and report.reward_source != "balance_delta"
        ):
            continue
        eb, _ = effective_balance_for(report.balance, report.ref)
        total = report.rewards_gwei.get("total")
        if not eb or total is None:
            continue
        if eb_sum == 0:
            window_epochs = report.window_epochs
        reward_sum += total
        eb_sum += eb
    scheduled = 0
    prop_included = 0
    prop_missed = 0
    sched_null = False
    missed_null = False
    for report in reports:
        if report.ref.index is None:
            continue
        row = report.proposals or {}
        if row.get("scheduled") is None:
            sched_null = True
        else:
            scheduled += row["scheduled"]
        prop_included += row.get("included") or 0
        if row.get("missed") is None:
            missed_null = True
        else:
            prop_missed += row["missed"]
    return {
        "validators": len(reports),
        "by_status": by_status,
        "participation_rate": mean("participation_rate"),
        "source_rate": mean("source_rate"),
        "target_rate": mean("target_rate"),
        "head_rate": mean("head_rate"),
        "attester_effectiveness": mean("attester_effectiveness"),
        "missed_attestations": sum(missed_parts) if missed_parts else None,
        "proposals": {
            "scheduled": None if sched_null else scheduled,
            "included": prop_included,
            "missed": None if missed_null else prop_missed,
        },
        "consensus_reward_gwei": sum(reward_parts) if reward_parts else None,
        "estimated_apr": _rate(
            reward_sum * spec.epochs_per_year, eb_sum * window_epochs
        ),
        "reward_source": (
            "balance_delta"
            if any(s == "balance_delta" for s in sources)
            else (
                "rewards_api"
                if sources and all(s == "rewards_api" for s in sources)
                else None
            )
        ),
    }


@dataclass(frozen=True)
class RunReport:
    ctx: ChainContext
    window: Window
    validators: list[ValidatorReport]
    aggregate: dict
    degradations: list[Degradation]
    endpoints_used: list[str]
    exit_code: int
    threshold_breaches: list[str] = field(default_factory=list)
    liveness_checked: bool = False
    liveness_unavailable: str | None = None


def _breaches(value: float | None, threshold: float) -> bool:
    # Decision 8: null already forced exit 3; it is not a threshold miss.
    return value is not None and value < threshold


def _threshold_scope(report: ValidatorReport) -> str:
    if report.ref.index is not None:
        return f"validator:{report.ref.index}"
    return f"pubkey:{report.ref.pubkey}"


def _threshold_value(source: ValidatorReport | dict, name: str) -> float | None:
    if name == "sync_participation_rate":
        if isinstance(source, dict):
            return source.get(name)
        sync = source.sync
        return None if sync is None else sync.participation_rate
    if isinstance(source, dict):
        got = source.get(name)
        if isinstance(got, (int, float)) and not isinstance(got, bool):
            return float(got)
        return None
    return getattr(source, name, None)


def _metrics_for_scope(breaches: Sequence[str], scope: str) -> list[str]:
    names: list[str] = []
    for item in breaches:
        left, sep, name = item.rpartition(":")
        if sep and left == scope:
            names.append(name)
    return names


def evaluate_thresholds(
    run: RunReport, thresholds: dict[str, float]
) -> list[str]:
    hits: list[str] = []
    for report in run.validators:
        scope = _threshold_scope(report)
        for name, threshold in thresholds.items():
            if _breaches(_threshold_value(report, name), threshold):
                hits.append(f"{scope}:{name}")
    for name, threshold in thresholds.items():
        if _breaches(_threshold_value(run.aggregate, name), threshold):
            hits.append(f"aggregate:{name}")
    return hits


def decide_exit_code(run: RunReport, opts: Options) -> int:
    # D8: completed runs are 4 > 3 > 0. --degraded-ok maps 3 → 0 only.
    if evaluate_thresholds(run, parse_thresholds(opts.fail_under)):
        return EXIT_THRESHOLD
    if run.degradations:
        return EXIT_OK if opts.degraded_ok else EXIT_DEGRADED
    return EXIT_OK


# ===== § 15. Reporting =====

_EM_DASH = "—"
_LIVENESS_FOOTNOTE = (
    "liveness_sanity is a head-window observation check "
    "(current and previous epoch only); it does not mean an "
    "attestation was included on chain, is not canonical, "
    "and is not participation_rate"
)
_TABLE_HEADERS = (
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
)


def _cell(value: object) -> str:
    return _EM_DASH if value is None else str(value)


def _fmt_pct(rate: float | None, *, mark: bool = False) -> str:
    text = _cell(None) if rate is None else f"{rate * 100:.2f}"
    return f"{text}!" if mark else text


def _fmt_eth(delta_gwei: int | None) -> str:
    if delta_gwei is None:
        return _cell(None)
    return f"{delta_gwei / 1_000_000_000:.6f}"


def _abbrev_pubkey(pubkey: str) -> str:
    body = pubkey[2:] if pubkey.startswith("0x") else pubkey
    return f"0x{body[:4]}…{body[-4:]}"


def _slot_utc(ctx: ChainContext, slot: int) -> str:
    ts = ctx.genesis_time + slot * ctx.spec.seconds_per_slot
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _fmt_incl_sched(proposals: object) -> str:
    row = proposals if isinstance(proposals, dict) else {}
    return f"{_cell(row.get('included'))}/{_cell(row.get('scheduled'))}"


def _table_row(report: ValidatorReport, marks: set[str] | None = None) -> list[str]:
    marked = marks or set()
    sync = report.sync
    pubkey = _abbrev_pubkey(report.ref.pubkey)
    if marked:
        pubkey += "!"
    return [
        pubkey,
        _cell(report.ref.index),
        report.ref.status,
        str(report.active_epochs),
        _fmt_pct(
            report.participation_rate, mark="participation_rate" in marked
        ),
        _fmt_pct(report.source_rate, mark="source_rate" in marked),
        _fmt_pct(report.target_rate, mark="target_rate" in marked),
        _fmt_pct(report.head_rate, mark="head_rate" in marked),
        _cell(report.missed_attestations),
        _fmt_incl_sched(report.proposals),
        _fmt_pct(
            None if sync is None else sync.participation_rate,
            mark="sync_participation_rate" in marked,
        ),
        _fmt_eth(report.balance.delta_gwei),
        _fmt_pct(
            report.attester_effectiveness,
            mark="attester_effectiveness" in marked,
        ),
        _fmt_pct(report.estimated_apr, mark="estimated_apr" in marked),
    ]


def _align_rows(rows: list[list[str]]) -> list[str]:
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    return ["  ".join(f"{cell:<{w}}" for cell, w in zip(row, widths)) for row in rows]


def render_table(run: RunReport, out: TextIO) -> None:
    ordered = sorted(
        run.validators,
        key=lambda r: (r.attester_effectiveness is None, r.attester_effectiveness),
    )
    by_scope: dict[str, set[str]] = {}
    for item in run.threshold_breaches:
        scope, sep, name = item.rpartition(":")
        if sep:
            by_scope.setdefault(scope, set()).add(name)
    lines = _align_rows(
        [
            list(_TABLE_HEADERS),
            *(
                _table_row(r, by_scope.get(_threshold_scope(r), set()))
                for r in ordered
            ),
        ]
    )
    agg = run.aggregate
    agg_marks = by_scope.get("aggregate", set())
    by_status = agg.get("by_status") or {}
    status_txt = ", ".join(f"{name}: {count}" for name, count in by_status.items())
    window = run.window
    proposals = agg.get("proposals") or {}

    def agg_pct(name: str) -> str:
        return _fmt_pct(agg.get(name), mark=name in agg_marks)

    lines.extend(
        [
            "",
            f"validators: {agg.get('validators', 0)}  ({status_txt})",
            f"window: epochs {window.from_epoch}–{window.to_epoch} "
            f"({_slot_utc(run.ctx, window.start_slot)} – "
            f"{_slot_utc(run.ctx, window.end_slot)})",
            f"part% {agg_pct('participation_rate')}  "
            f"src% {agg_pct('source_rate')}  "
            f"tgt% {agg_pct('target_rate')}  "
            f"head% {agg_pct('head_rate')}  "
            f"eff% {agg_pct('attester_effectiveness')}",
            f"missed {_cell(agg.get('missed_attestations'))}  "
            f"incl/sched {_fmt_incl_sched(proposals)}  "
            f"consensus_reward_gwei {_cell(agg.get('consensus_reward_gwei'))}  "
            f"APR% {agg_pct('estimated_apr')}",
            "",
            "inclusion distance is absent because it requires a full block scan",
            "0/0 proposals is normal at this key count — 200 keys over 32 epochs "
            "expect ≈0.19 proposals; proposals_expected is not implemented",
            "an orphaned block is not canonical and reads as missed",
        ]
    )
    if run.liveness_checked:
        lines.append(_LIVENESS_FOOTNOTE)
        if run.liveness_unavailable:
            lines.append(
                f"liveness_sanity unavailable: {run.liveness_unavailable}; "
                "the run is not degraded"
            )
    lines.extend(
        [
            "",
            "DEGRADED:",
        ]
    )
    if run.degradations:
        lines.extend(
            _align_rows(
                [[d.metric, d.reason, d.scope] for d in run.degradations]
            )
        )
    out.write("\n".join(lines) + "\n")


def _json_default(obj: object) -> object:
    # Fail closed so dataclasses/datetime cannot silently become strings.
    raise TypeError(f"{type(obj).__name__} is not JSON serializable")


def _sync_json(sync: object) -> dict | None:
    if not isinstance(sync, SyncOutcome) or not sync.in_committee:
        return None
    return {
        "in_committee": True,
        "participation_rate": sync.participation_rate,
        "slots_eligible": sync.slots_eligible,
        "slots_signed": sync.slots_signed,
        "reward_gwei": sync.reward_gwei,
    }


def _degradation_json(d: Degradation) -> dict[str, str]:
    return {
        "metric": d.metric,
        "scope": d.scope,
        "reason": d.reason,
        "detail": d.detail,
    }


def _generated_at(clock: Callable[[], datetime] | None) -> str:
    now = clock() if clock is not None else datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise TypeError("generated_at clock must be timezone-aware")
    return now.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _redact_endpoint_url(url: str) -> str:
    # Persist scheme://host:port only; already-redacted URLs round-trip.
    return redact(parse_endpoint(url, "json"))


def _validator_json(
    report: ValidatorReport,
    window: Window,
    breaches: Sequence[str] = (),
    *,
    include_liveness: bool = False,
) -> dict:
    snap = report.balance
    eb, changed = effective_balance_for(snap, report.ref)
    rec = reconcile_balance(snap.delta_gwei, report.rewards_gwei.get("total"))
    # Fallback total is the delta; nothing independent remains to reconcile.
    if report.reward_source != "rewards_api":
        rec = replace(rec, reconciliation="unavailable")
    row = {
        "pubkey": report.ref.pubkey,
        "index": report.ref.index,
        "status": report.ref.status,
        "active_epochs": report.active_epochs,
        "participation_rate": report.participation_rate,
    }
    # Distinct key, adjacent to M1; omitted unless --liveness-check (RD-6).
    if include_liveness:
        row["liveness_sanity"] = report.liveness_sanity
    row.update(
        {
            "source_rate": report.source_rate,
            "target_rate": report.target_rate,
            "head_rate": report.head_rate,
            "missed_attestations": report.missed_attestations,
            "attester_effectiveness": report.attester_effectiveness,
            "effectiveness_method": report.effectiveness_method,
            "leak_epochs_excluded": report.leak_epochs_excluded,
            "proposals": report.proposals,
            "sync": _sync_json(report.sync),
            "balance": {
                "start_gwei": snap.start_gwei,
                "end_gwei": snap.end_gwei,
                "delta_gwei": snap.delta_gwei,
                "effective_balance_gwei": eb,
                "effective_balance_changed": changed,
                "start_slot": window.start_slot,
                "end_slot": window.end_slot,
                "reconciliation": rec.reconciliation,
            },
            "rewards_gwei": dict(report.rewards_gwei),
            "estimated_apr": report.estimated_apr,
            "reward_source": report.reward_source,
            "degradations": [_degradation_json(d) for d in report.degradations],
            "threshold_breaches": _metrics_for_scope(
                breaches, _threshold_scope(report)
            ),
        }
    )
    return row


def render_json(
    run: RunReport, clock: Callable[[], datetime] | None = None
) -> str:
    used = [_redact_endpoint_url(ep) for ep in run.endpoints_used]
    aggregate = dict(run.aggregate)
    aggregate.setdefault("reward_source", None)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _generated_at(clock),
        "network": {
            "name": run.ctx.network_name,
            "genesis_time": run.ctx.genesis_time,
            "slots_per_epoch": run.ctx.spec.slots_per_epoch,
            "seconds_per_slot": run.ctx.spec.seconds_per_slot,
        },
        "window": {
            "from_epoch": run.window.from_epoch,
            "to_epoch": run.window.to_epoch,
            "epochs": run.window.epochs,
            "head_epoch": run.window.head_epoch,
            "finalized_epoch": run.window.finalized_epoch,
            "finalized_only": run.window.finalized_only,
        },
        "beacon": {
            "endpoint": used[-1] if used else "",
            "version": run.ctx.node_version,
            "rewards_api": run.ctx.rewards_api,
            "endpoints_used": used,
        },
        "validators": [
            _validator_json(
                v,
                run.window,
                run.threshold_breaches,
                include_liveness=run.liveness_checked,
            )
            for v in run.validators
        ],
        "aggregate": aggregate,
        "degradations": [_degradation_json(d) for d in run.degradations],
        "threshold_breaches": list(run.threshold_breaches),
        "exit_code": run.exit_code,
    }
    return json.dumps(doc, default=_json_default)


def _flatten(d: object, prefix: str = "") -> dict[str, object]:
    if not isinstance(d, dict):
        return {prefix: d} if prefix else {}
    out: dict[str, object] = {}
    for key, value in d.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(value, dict):
            out.update(_flatten(value, path))
        else:
            out[path] = value
    return out


def _csv_template_report() -> ValidatorReport:
    # In-committee sync so the header always has dotted sync.* (A7 first row).
    return ValidatorReport(
        ref=ValidatorRef("", None, "", None, None, None, False),
        active_epochs=0,
        participation_rate=None,
        source_rate=None,
        target_rate=None,
        head_rate=None,
        missed_attestations=None,
        attester_effectiveness=None,
        effectiveness_method="reward_ratio",
        leak_epochs_excluded=0,
        proposals=_proposal_counts((), True),
        sync=SyncOutcome(True, 0, 0, 0),
        balance=BalanceSnapshot(None, None, None, None),
        rewards_gwei=_assemble_rewards(
            (),
            delta_gwei=None,
            proposer_gwei=None,
            sync_gwei=0,
            use_api=True,
        )[0],
        reward_source=None,
        estimated_apr=None,
        window_epochs=0,
        degradations=[],
    )


def _csv_cell(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        text = ";".join(
            f"{item.get('reason', '')}@{item.get('scope', '')}"
            if isinstance(item, dict)
            else str(item)
            for item in value
        )
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, str):
        text = value
    else:
        return str(value)
    # BN-controlled strings (=cmd|…) must not become spreadsheet formulas.
    if text and text[0] in "=+-@":
        return "'" + text
    return text


def render_csv(run: RunReport, path: str) -> None:
    """Write one CSV row per validator.

    Nested objects flatten with a dotted prefix. The degradations column is a
    `;`-joined reason@scope summary; JSON is authoritative for the detail.
    None renders as an empty cell, never 0.
    """
    fieldnames = list(
        _flatten(_validator_json(_csv_template_report(), run.window))
    )
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for report in run.validators:
            row = _flatten(
                _validator_json(report, run.window, run.threshold_breaches)
            )
            writer.writerow({k: _csv_cell(row.get(k)) for k in fieldnames})


_PROM_PREFIX = "rvc_validator_perf_"
_PROM_VALIDATOR = (
    ("participation_rate", "participation_rate", "gauge"),
    ("source_rate", "source_rate", "gauge"),
    ("target_rate", "target_rate", "gauge"),
    ("head_rate", "head_rate", "gauge"),
    ("attester_effectiveness", "attester_effectiveness", "gauge"),
    ("missed_attestations", "missed_attestations_total", "gauge"),
    ("proposals.included", "proposals_included_total", "gauge"),
    ("proposals.scheduled", "proposals_scheduled_total", "gauge"),
    ("sync.participation_rate", "sync_participation_rate", "gauge"),
    ("rewards_gwei.total", "consensus_reward_gwei", "gauge"),
    ("estimated_apr", "estimated_apr", "gauge"),
)


def _prom_escape(value: object) -> str:
    return (
        str(value)
        .replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace('"', '\\"')
    )


def _prom_number(value: int | float) -> str:
    if isinstance(value, float):
        return format(value, ".15g")
    return str(value)


def _emit(name: str, value: object, labels: dict[str, str]) -> str | None:
    # Prometheus has no null; omit the series, never emit 0 for None (G5).
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, float) and not math.isfinite(value):
        return None
    inner = ",".join(
        f'{key}="{_prom_escape(val)}"' for key, val in labels.items()
    )
    return f"{name}{{{inner}}} {_prom_number(value)}"


def _validator_labels(ref: "ValidatorRef") -> dict[str, str]:
    return {
        "pubkey": _abbrev_pubkey(ref.pubkey),
        "index": "" if ref.index is None else str(ref.index),
        "status": ref.status,
    }


def _atomic_text_write(path: str, text: str, prefix: str) -> None:
    dest = os.path.abspath(path)
    directory = os.path.dirname(dest) or "."
    fd, tmp = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o644)  # mkstemp is 0600; node_exporter must read dest
        os.replace(tmp, dest)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def render_prometheus(
    run: RunReport,
    path: str,
    clock: Callable[[], datetime] | None = None,
) -> None:
    """Write a node_exporter textfile. None metrics are omitted, not zero."""
    rows = [
        (
            _validator_labels(report.ref),
            _flatten(_validator_json(report, run.window, run.threshold_breaches)),
        )
        for report in run.validators
    ]
    lines: list[str] = []

    def _family(name: str, typ: str, samples: list[str]) -> None:
        if not samples:
            return
        lines.append(f"# HELP {name} {name[len(_PROM_PREFIX):].replace('_', ' ')}")
        lines.append(f"# TYPE {name} {typ}")
        lines.extend(samples)

    for field, suffix, typ in _PROM_VALIDATOR:
        name = _PROM_PREFIX + suffix
        samples = []
        for labels, flat in rows:
            line = _emit(name, flat.get(field), labels)
            if line is not None:
                samples.append(line)
        _family(name, typ, samples)

    degs = list(run.degradations) or [
        d for report in run.validators for d in report.degradations
    ]
    counts: dict[str, int] = {}
    for deg in degs:
        counts[deg.reason] = counts.get(deg.reason, 0) + 1
    deg_name = _PROM_PREFIX + "degradations_total"
    deg_samples = []
    for reason in sorted(counts):
        line = _emit(deg_name, counts[reason], {"reason": reason})
        if line is not None:
            deg_samples.append(line)
    _family(deg_name, "gauge", deg_samples)

    now = clock() if clock is not None else datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise TypeError("generated_at clock must be timezone-aware")
    now = now.astimezone(timezone.utc)
    exit_name = _PROM_PREFIX + "run_exit_code"
    _family(
        exit_name,
        "gauge",
        [line for line in [_emit(exit_name, run.exit_code, {})] if line],
    )
    ts_name = _PROM_PREFIX + "run_generated_timestamp_seconds"
    _family(
        ts_name,
        "gauge",
        [
            line
            for line in [_emit(ts_name, int(now.timestamp()), {})]
            if line
        ],
    )
    # Random tmp name; dest+".tmp" is symlink-plantable.
    _atomic_text_write(path, "\n".join(lines) + "\n", prefix="prom.")


# ===== § 16. main =====


def _render_dry_run(
    ctx: ChainContext,
    window: Window,
    refs: Sequence[ValidatorRef],
    log: Log,
    endpoint: str,
) -> None:
    print(
        f"window: epochs {window.from_epoch}–{window.to_epoch} "
        f"(slots {window.start_slot}, {window.end_slot})"
    )
    print(f"endpoint: {endpoint}")
    print(f"rewards_api: {ctx.rewards_api}")
    print(f"node version: {ctx.node_version}")
    for ref in refs:
        print(
            f"{ref.pubkey} index={ref.index} status={ref.status} "
            f"eb={ref.effective_balance_gwei} gwei"
        )


def _abort_log_line(exc: BaseException) -> str:
    # Status + template only; never a URL (P0-12). Tuple str(BeaconStatus) is unreadable.
    if isinstance(exc, BeaconStatus):
        return f"HTTP {exc.status} {exc.template}"
    if isinstance(exc, BeaconTransport) and exc.args:
        return f"transport error {exc.args[0]}"
    return str(exc)


def main(
    argv: list[str] | None = None, *, transport: Transport | None = None
) -> int:
    log = Log(0, sys.stderr)
    active = transport
    pool = None
    try:
        opts = build_options(argv)
        log = Log(opts.verbosity, sys.stderr)
        if active is None:
            active = HttpTransport(opts.connect_timeout, opts.read_timeout)
        pool = ThreadPoolExecutor(max_workers=opts.concurrency)
        budget = RequestBudget()
        client = BeaconClient(
            list(opts.endpoints),
            active,
            request_delay=opts.request_delay_ms / 1000.0,
            log=log,
        )
        select_endpoint(client)
        ctx = load_chain_context(client)
        window = resolve_window(opts, ctx, log)
        keys = list(opts.pubkeys)
        cached = (
            None
            if opts.no_cache
            else _cache_read(ctx.genesis_validators_root, keys, log)
        )
        hydrate_rows = None
        if cached is None:
            refs = resolve_validators(client, keys)
            if not opts.no_cache:
                _cache_write(
                    ctx.genesis_validators_root,
                    {r.pubkey: r.index for r in refs if r.index is not None},
                    log,
                )
        else:
            state_id = "head" if opts.dry_run else str(window.start_slot)
            refs, hydrate_rows = _hydrate_cached_refs(
                client, state_id, keys, cached, log
            )
            if refs is None:
                refs = resolve_validators(client, keys)
                hydrate_rows = None
                if not opts.no_cache:
                    _cache_write(
                        ctx.genesis_validators_root,
                        {
                            r.pubkey: r.index
                            for r in refs
                            if r.index is not None
                        },
                        log,
                    )
        start_balances = (
            _snapshot_balances(hydrate_rows) or None
            if hydrate_rows is not None
            else None
        )
        ids = [str(ref.index) for ref in refs if ref.rewards_eligible][:1]
        ctx = replace(
            ctx, rewards_api=probe_rewards_api(client, ctx.head_epoch, ids)
        )
        if opts.dry_run:
            endpoint = client.endpoints_used[-1] if client.endpoints_used else ""
            _render_dry_run(ctx, window, refs, log, endpoint)
            return EXIT_OK
        outcomes, att_degs = collect_attestations(
            client, window, refs, pool, budget, ctx.rewards_api
        )
        att_failed = any(
            d.metric == "attestation"
            and d.reason
            in (
                "rewards_api_unsupported",
                "state_unavailable",
                "endpoint_failover",
            )
            for d in att_degs
        )
        index_set = {ref.index for ref in refs if ref.index is not None}
        proposals, prop_degs, duties_available = collect_proposals(
            client, window, index_set, pool, budget, ctx.rewards_api
        )
        snaps, bal_degs = collect_balances(
            client, window, refs, start=start_balances
        )
        index_set = {ref.index for ref in refs if ref.index is not None}
        sync_map, sync_degs = collect_sync(
            client, window, ctx, index_set, pool, budget
        )
        live_by_index: dict[int, list] = {}
        liveness_unavail: str | None = None
        if opts.liveness_check:
            live_ids = [str(r.index) for r in refs if r.index is not None]
            live_by_index, liveness_unavail = collect_liveness(
                client, ctx.head_epoch, live_ids, ctx.node_version, log
            )
        empty_snap = BalanceSnapshot(None, None, None, None)
        reports: list[ValidatorReport] = []
        report_degs: list[Degradation] = []
        for ref in refs:
            snap = (
                snaps.get(ref.index, empty_snap)
                if ref.index is not None
                else empty_snap
            )
            series = (
                outcomes.get(ref.index, []) if ref.index is not None else []
            )
            prop_series = (
                proposals.get(ref.index, []) if ref.index is not None else []
            )
            sync_out = (
                sync_map.get(ref.index) if ref.index is not None else None
            )
            report = build_validator_report(
                ref,
                series,
                snap,
                ctx.spec,
                window,
                proposal_outcomes=prop_series,
                duties_available=duties_available,
                sync_gwei=0 if sync_out is None else sync_out.reward_gwei,
                sync=sync_out,
                attestation_degraded=att_failed,
            )
            if opts.liveness_check:
                sanity = None
                if liveness_unavail is None and ref.index is not None:
                    sanity = live_by_index.get(ref.index)
                report = replace(report, liveness_sanity=sanity)
            reports.append(report)
            report_degs.extend(report.degradations)
        run = RunReport(
            ctx,
            window,
            reports,
            build_aggregate(reports, ctx.spec),
            att_degs + prop_degs + bal_degs + sync_degs + report_degs,
            client.endpoints_used,
            EXIT_OK,
            liveness_checked=opts.liveness_check,
            liveness_unavailable=liveness_unavail,
        )
        breaches = evaluate_thresholds(run, parse_thresholds(opts.fail_under))
        code = decide_exit_code(run, opts)
        run = replace(run, threshold_breaches=breaches, exit_code=code)
        if opts.json:
            print(render_json(run))
        else:
            render_table(run, sys.stdout)
        if opts.csv:
            render_csv(run, opts.csv)
        if opts.prometheus:
            render_prometheus(run, opts.prometheus)
        return code
    except UsageError as exc:
        log.error("%s", exc)
        return EXIT_USAGE
    except (NoBeaconAvailable, BeaconStatus, BeaconTransport) as exc:
        # Phase 0/1/2 wire failures abort the run (5), never degrade (3).
        log.error("%s", _abort_log_line(exc))
        return EXIT_NO_BEACON
    except Exception as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    finally:
        if pool is not None:
            pool.shutdown(wait=True)
        closer = getattr(active, "close", None)
        if callable(closer):
            closer()


if __name__ == "__main__":
    sys.exit(main())
