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
import re
import socket
import ssl
import stat
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


# ===== § 3. Prometheus text-format 0.0.4 =====

_TYPE_RE = re.compile(
    r"^#\s*TYPE\s+([a-zA-Z_:][a-zA-Z0-9_:]*)\s+(\S+)\s*$"
)
_SAMPLE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:[ \t]*\{(.*)\})?"
    r"[ \t]+"
    r"(\S+)"
    r"(?:[ \t]+\S+)?"
    r"[ \t]*$"
)
_HISTOGRAM_SUFFIXES = ("_bucket", "_sum", "_count")
_MAX_METRIC_LINE = 8 * 1024
_MAX_METRIC_SAMPLES = 100_000
_MAX_LABEL_VALUE_BYTES = 4 * 1024
_ERROR_SNIPPET = 200


@dataclass(frozen=True)
class Sample:
    labels: dict[str, str]
    value: float
    name: str = ""


@dataclass
class Family:
    name: str
    type: str
    samples: list[Sample]


def _unescape(raw: str) -> str:
    return raw.replace("\\\\", "\\").replace('\\"', '"').replace("\\n", "\n")


def _snippet(text: str) -> str:
    if len(text) <= _ERROR_SNIPPET:
        return text
    return f"{text[:_ERROR_SNIPPET]}..."


def _label_name_start(ch: str) -> bool:
    return ("A" <= ch <= "Z") or ("a" <= ch <= "z") or ch == "_"


def _label_name_cont(ch: str) -> bool:
    return _label_name_start(ch) or ("0" <= ch <= "9")


def _parse_labels(raw: str) -> dict[str, str]:
    if not raw:
        return {}
    labels: dict[str, str] = {}
    i = 0
    n = len(raw)
    while True:
        while i < n and raw[i] in " \t":
            i += 1
        if i >= n:
            return labels
        if not _label_name_start(raw[i]):
            raise InfraError(f"invalid prometheus labels: {_snippet(raw)}")
        start = i
        i += 1
        while i < n and _label_name_cont(raw[i]):
            i += 1
        name = raw[start:i]
        if i >= n or raw[i] != "=":
            raise InfraError(f"invalid prometheus labels: {_snippet(raw)}")
        i += 1
        if i >= n or raw[i] != '"':
            raise InfraError(f"invalid prometheus labels: {_snippet(raw)}")
        i += 1
        val_start = i
        closed = False
        while i < n:
            ch = raw[i]
            if ch == "\\":
                if i + 1 >= n:
                    break
                i += 2
                continue
            if ch == '"':
                closed = True
                break
            i += 1
        if not closed:
            raise InfraError("unclosed label value")
        encoded = raw[val_start:i]
        if len(encoded.encode("utf-8")) > _MAX_LABEL_VALUE_BYTES:
            raise InfraError("label value exceeded cap")
        i += 1
        labels[name] = _unescape(encoded)
        while i < n and raw[i] in " \t":
            i += 1
        if i >= n:
            return labels
        if raw[i] != ",":
            raise InfraError(f"invalid prometheus labels: {_snippet(raw)}")
        i += 1


def _parse_le(raw: str) -> float:
    if raw == "+Inf":
        return math.inf
    return float(raw)


def series_key(
    name: str, labels: dict[str, str]
) -> tuple[str, tuple[tuple[str, str], ...]]:
    return (name, tuple(sorted(labels.items())))


def unit_for(name: str) -> str:
    if name.endswith("_seconds"):
        return "seconds"
    if name.endswith("_ms"):
        return "milliseconds"
    return "count"


def _family_name_for(sample_name: str, type_map: dict[str, str]) -> str:
    if sample_name in type_map:
        return sample_name
    for suffix in _HISTOGRAM_SUFFIXES:
        if sample_name.endswith(suffix):
            base = sample_name[: -len(suffix)]
            if type_map.get(base) in {"histogram", "summary"}:
                return base
    return sample_name


def parse_metrics(text: str) -> dict[str, Family]:
    if len(text) > MAX_RESPONSE_BYTES:
        raise InfraError("metrics text exceeded MAX_RESPONSE_BYTES")
    lines = text.splitlines()
    type_map: dict[str, str] = {}
    for line in lines:
        if len(line) > _MAX_METRIC_LINE:
            raise InfraError("metrics line exceeded cap")
        match = _TYPE_RE.match(line.strip())
        if match is None:
            continue
        name, typ = match.group(1), match.group(2)
        if typ == "summary":
            raise UsageError("summary families are not supported")
        if name not in type_map:
            type_map[name] = typ

    families: dict[str, Family] = {}
    n_samples = 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _SAMPLE_RE.match(stripped)
        if match is None:
            raise InfraError(f"invalid prometheus sample: {_snippet(stripped)}")
        sample_name, raw_labels, raw_value = (
            match.group(1),
            match.group(2),
            match.group(3),
        )
        try:
            labels = _parse_labels(raw_labels or "")
        except InfraError as exc:
            raise InfraError(
                f"invalid prometheus labels: {_snippet(stripped)}"
            ) from exc
        if "quantile" in labels:
            raise UsageError("summary families are not supported")
        try:
            value = float(raw_value)
        except ValueError as exc:
            raise InfraError(
                f"invalid prometheus value: {_snippet(raw_value)}"
            ) from exc
        n_samples += 1
        if n_samples > _MAX_METRIC_SAMPLES:
            raise InfraError("metrics sample count exceeded cap")
        fam_name = _family_name_for(sample_name, type_map)
        fam_type = type_map.get(fam_name, "untyped")
        sample = Sample(labels=labels, value=value, name=sample_name)
        family = families.get(fam_name)
        if family is None:
            family = Family(name=fam_name, type=fam_type, samples=[])
            families[fam_name] = family
        family.samples.append(sample)
    return families


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


def main(
    argv: list[str] | None = None,
    *,
    transport=None,
    clock: Callable[[], datetime] | None = None,
) -> int:
    log = Log(0, sys.stderr)
    active = transport
    try:
        opts = build_options(argv)
        if opts.command == "scrape":
            if active is None:
                active = HttpTransport(
                    DEFAULT_CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT
                )
            cmd_scrape(opts, transport=active, clock=clock)
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


def cmd_scrape(
    opts: Options,
    *,
    transport: Transport,
    clock: Callable[[], datetime] | None = None,
) -> None:
    raw = fetch_metrics(opts.url or "", transport=transport)
    if raw.truncated:
        raise InfraError("metrics response exceeded MAX_RESPONSE_BYTES")
    if raw.status != 200:
        raise InfraError(f"metrics HTTP {raw.status}")
    if opts.gauges_only:
        dest = opts.append
        slot = opts.slot
        if dest is None or slot is None:
            raise UsageError("--gauges-only requires --slot and --append")
        try:
            text = raw.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InfraError("metrics response is not valid UTF-8") from exc
        _append_jsonl_line(
            dest, gauge_line(parse_metrics(text), slot, clock)
        )
        return
    dest = opts.out
    if dest is None:
        raise UsageError("--out is required")
    try:
        with open(dest, "wb") as fh:
            fh.write(raw.body)
    except OSError as exc:
        raise InfraError(f"failed to write {dest}: {exc}") from exc


# ===== § 6. Counter deltas and gauge samples =====

_MAX_JSONL_LINE = 64 * 1024
_MAX_JSONL_BYTES = 8 * 1024 * 1024


def _label_key(labels: dict[str, str]) -> tuple[tuple[str, str], ...]:
    return tuple(sorted(labels.items()))


def _family_values(
    family: Family | None,
) -> dict[tuple[tuple[str, str], ...], float]:
    values: dict[tuple[tuple[str, str], ...], float] = {}
    if family is None:
        return values
    for sample in family.samples:
        values[_label_key(sample.labels)] = sample.value
    return values


def counter_delta(
    start: dict[str, Family],
    end: dict[str, Family],
    *,
    epochs: float,
) -> dict[str, list[dict[str, object]]]:
    names = {
        name
        for snap in (start, end)
        for name, family in snap.items()
        if family.type == "counter"
    }
    out: dict[str, list[dict[str, object]]] = {}
    for name in sorted(names):
        start_vals = _family_values(start.get(name))
        end_vals = _family_values(end.get(name))
        rows: list[dict[str, object]] = []
        for key in sorted(set(start_vals) | set(end_vals)):
            start_v = start_vals.get(key, 0.0)
            end_v = end_vals.get(key, 0.0)
            delta = end_v - start_v
            rows.append(
                {
                    "labels": dict(key),
                    "start": start_v,
                    "end": end_v,
                    "delta": delta,
                    "per_epoch": delta / epochs,
                    "monotonic_violation": delta < 0,
                }
            )
        out[name] = rows
    return out


def gauge_line(
    snapshot: dict[str, Family],
    slot: int,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    gauges: dict[str, list[dict[str, object]]] = {}
    for name, family in snapshot.items():
        if family.type != "gauge":
            continue
        gauges[name] = [
            {"labels": dict(sample.labels), "v": sample.value}
            for sample in family.samples
        ]
    return {"t": _generated_at(clock), "slot": slot, "gauges": gauges}


def _jsonl_open_flags(*, write: bool) -> int:
    flags = os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    if write:
        return flags | os.O_WRONLY | os.O_CREAT | os.O_APPEND
    return flags | os.O_RDONLY


def _refuse_non_regular(st: os.stat_result, dest: str) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise InfraError(f"{dest} is a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise InfraError(f"{dest} is not a regular file")


def _open_jsonl_fd(path: str | os.PathLike[str], *, write: bool) -> int:
    dest = os.fspath(path)
    action = "append" if write else "read"
    try:
        existing = os.lstat(dest)
    except FileNotFoundError:
        if not write:
            raise InfraError(f"failed to read {dest}: not found") from None
        existing = None
    except OSError as exc:
        raise InfraError(f"failed to {action} {dest}: {exc}") from exc
    if existing is not None:
        _refuse_non_regular(existing, dest)
        if existing.st_size > _MAX_JSONL_BYTES:
            raise InfraError(f"{dest} exceeded jsonl size cap")
    try:
        fd = os.open(dest, _jsonl_open_flags(write=write), 0o644)
    except OSError as exc:
        raise InfraError(f"failed to {action} {dest}: {exc}") from exc
    try:
        opened = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise InfraError(f"failed to {action} {dest}: {exc}") from exc
    if not stat.S_ISREG(opened.st_mode):
        os.close(fd)
        raise InfraError(f"{dest} is not a regular file")
    if opened.st_size > _MAX_JSONL_BYTES:
        os.close(fd)
        raise InfraError(f"{dest} exceeded jsonl size cap")
    return fd


def _append_jsonl_line(path: str | os.PathLike[str], obj: object) -> None:
    dest = os.fspath(path)
    payload = json.dumps(
        _finite_or_none(obj), allow_nan=False, sort_keys=True
    )
    data = (payload + "\n").encode("utf-8")
    if len(data) > _MAX_JSONL_LINE:
        raise InfraError(f"{dest} jsonl line exceeded cap")
    fd = _open_jsonl_fd(dest, write=True)
    try:
        size = os.fstat(fd).st_size
        if size + len(data) > _MAX_JSONL_BYTES:
            raise InfraError(f"{dest} exceeded jsonl size cap")
        # Single O_APPEND write so a concurrent soak tick cannot interleave.
        written = os.write(fd, data)
        if written != len(data):
            raise InfraError(f"failed to append {dest}: short write")
    except OSError as exc:
        raise InfraError(f"failed to append {dest}: {exc}") from exc
    finally:
        os.close(fd)


def _iter_jsonl_objects(path: str | os.PathLike[str]):
    dest = os.fspath(path)
    fd = _open_jsonl_fd(dest, write=False)
    try:
        fh = os.fdopen(fd, "rb")
    except OSError as exc:
        os.close(fd)
        raise InfraError(f"failed to read {dest}: {exc}") from exc
    with fh:
        while True:
            raw = fh.readline(_MAX_JSONL_LINE + 1)
            if not raw:
                break
            if len(raw) > _MAX_JSONL_LINE:
                raise InfraError(f"{dest} jsonl line exceeded cap")
            try:
                stripped = raw.decode("utf-8").strip()
            except UnicodeDecodeError:
                continue
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            canon = _finite_or_none(obj)
            if isinstance(canon, dict):
                yield canon


def _slot_of(obj: dict) -> int | None:
    slot = obj.get("slot")
    if isinstance(slot, bool) or not isinstance(slot, int):
        return None
    return slot


def _finite_numbers(values: list[object]) -> list[float]:
    finite: list[float] = []
    for value in values:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if math.isfinite(value):
            finite.append(value)
    return finite


@dataclass
class _GaugeAcc:
    labels: dict[str, str]
    last: object
    samples: int
    values: list[object]


def _series_labels(raw: object) -> dict[str, str] | None:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        return None
    labels: dict[str, str] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return None
        labels[key] = value
    return labels


def fold_gauges(
    samples_path: str | os.PathLike[str],
) -> dict[str, list[dict[str, object]]]:
    acc: dict[tuple[str, tuple[tuple[str, str], ...]], _GaugeAcc] = {}
    order: list[tuple[str, tuple[tuple[str, str], ...]]] = []
    for obj in _iter_jsonl_objects(samples_path):
        gauges = obj.get("gauges")
        if not isinstance(gauges, dict):
            continue
        for name, series in gauges.items():
            if not isinstance(name, str) or not isinstance(series, list):
                continue
            for item in series:
                if not isinstance(item, dict) or "v" not in item:
                    continue
                labels = _series_labels(item.get("labels"))
                if labels is None:
                    continue
                value = _finite_or_none(item["v"])
                key = (name, _label_key(labels))
                rec = acc.get(key)
                if rec is None:
                    rec = _GaugeAcc(
                        labels=dict(key[1]),
                        last=value,
                        samples=0,
                        values=[],
                    )
                    acc[key] = rec
                    order.append(key)
                rec.last = value
                rec.samples += 1
                rec.values.append(value)
    out: dict[str, list[dict[str, object]]] = {}
    for key in order:
        rec = acc[key]
        finite = _finite_numbers(rec.values)
        out.setdefault(key[0], []).append(
            {
                "labels": rec.labels,
                "last": rec.last,
                "min": min(finite) if finite else None,
                "max": max(finite) if finite else None,
                "samples": rec.samples,
            }
        )
    return out


def window_from_samples(path: str | os.PathLike[str]) -> dict[str, int]:
    slots: list[int] = []
    for obj in _iter_jsonl_objects(path):
        slot = _slot_of(obj)
        if slot is None:
            continue
        slots.append(slot)
    if len(slots) < 2:
        raise UsageError("samples.jsonl has fewer than 2 rows")
    start_slot = slots[0]
    end_slot = slots[-1]
    if end_slot <= start_slot:
        raise UsageError(
            "samples.jsonl end_slot must be greater than start_slot"
        )
    return {
        "start_slot": start_slot,
        "end_slot": end_slot,
        "slots": end_slot - start_slot,
    }


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
