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


_REPORT_PRODUCERS = {
    "run.json": "run.sh",
    "metrics-start.txt": "soak.sh",
    "metrics-end.txt": "soak.sh",
    "samples.jsonl": "soak.sh",
}


def _input_name(path: str) -> str:
    return os.path.basename(os.fspath(path))


def _artifact_msg(path: str, template: str) -> str:
    name = _input_name(path)
    msg = template.format(name=name)
    stage = _REPORT_PRODUCERS.get(name)
    if stage is None:
        return msg
    return f"{msg} (produced by {stage})"


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
    try:
        value = float(raw)
    except ValueError as exc:
        raise InfraError(f"invalid histogram le: {_snippet(raw)}") from exc
    if not math.isfinite(value):
        raise InfraError(f"invalid histogram le: {_snippet(raw)}")
    return value


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


def _validate_report(args: argparse.Namespace) -> None:
    if not args.run_dir:
        raise UsageError("--run-dir is required")


def build_options(argv: list[str] | None = None) -> Options:
    args = build_parser().parse_args(argv)
    if args.command == "scrape":
        _validate_scrape(args)
    elif args.command == "report":
        _validate_report(args)
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
            cmd_report(opts, clock=clock)
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
        raise InfraError(_artifact_msg(dest, "{name} is a symlink"))
    if not stat.S_ISREG(st.st_mode):
        raise InfraError(_artifact_msg(dest, "{name} is not a regular file"))


def _open_jsonl_fd(path: str | os.PathLike[str], *, write: bool) -> int:
    dest = os.fspath(path)
    action = "append" if write else "read"
    try:
        existing = os.lstat(dest)
    except FileNotFoundError:
        if not write:
            raise InfraError(_artifact_msg(dest, "failed to read {name}")) from None
        existing = None
    except OSError as exc:
        raise InfraError(
            _artifact_msg(dest, f"failed to {action} {{name}}")
        ) from exc
    if existing is not None:
        _refuse_non_regular(existing, dest)
        if existing.st_size > _MAX_JSONL_BYTES:
            raise InfraError(
                _artifact_msg(dest, "{name} exceeded jsonl size cap")
            )
    try:
        fd = os.open(dest, _jsonl_open_flags(write=write), 0o644)
    except OSError as exc:
        raise InfraError(
            _artifact_msg(dest, f"failed to {action} {{name}}")
        ) from exc
    try:
        opened = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise InfraError(
            _artifact_msg(dest, f"failed to {action} {{name}}")
        ) from exc
    if not stat.S_ISREG(opened.st_mode):
        os.close(fd)
        raise InfraError(_artifact_msg(dest, "{name} is not a regular file"))
    if opened.st_size > _MAX_JSONL_BYTES:
        os.close(fd)
        raise InfraError(_artifact_msg(dest, "{name} exceeded jsonl size cap"))
    return fd


def _append_jsonl_line(path: str | os.PathLike[str], obj: object) -> None:
    dest = os.fspath(path)
    payload = json.dumps(
        _finite_or_none(obj), allow_nan=False, sort_keys=True
    )
    data = (payload + "\n").encode("utf-8")
    if len(data) > _MAX_JSONL_LINE:
        raise InfraError(_artifact_msg(dest, "{name} jsonl line exceeded cap"))
    fd = _open_jsonl_fd(dest, write=True)
    try:
        size = os.fstat(fd).st_size
        if size + len(data) > _MAX_JSONL_BYTES:
            raise InfraError(
                _artifact_msg(dest, "{name} exceeded jsonl size cap")
            )
        # Single O_APPEND write so a concurrent soak tick cannot interleave.
        written = os.write(fd, data)
        if written != len(data):
            raise InfraError(_artifact_msg(dest, "failed to append {name}"))
    except OSError as exc:
        raise InfraError(_artifact_msg(dest, "failed to append {name}")) from exc
    finally:
        os.close(fd)


def _iter_jsonl_objects(path: str | os.PathLike[str]):
    dest = os.fspath(path)
    fd = _open_jsonl_fd(dest, write=False)
    try:
        fh = os.fdopen(fd, "rb")
    except OSError as exc:
        os.close(fd)
        raise InfraError(_artifact_msg(dest, "failed to read {name}")) from exc
    with fh:
        while True:
            raw = fh.readline(_MAX_JSONL_LINE + 1)
            if not raw:
                break
            if len(raw) > _MAX_JSONL_LINE:
                raise InfraError(
                    _artifact_msg(dest, "{name} jsonl line exceeded cap")
                )
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


# ===== § 7. Bucket deltas and histogram_quantile =====


@dataclass(frozen=True)
class HistogramDeltas:
    name: str
    labels: dict[str, str]
    unit: str
    buckets: tuple[tuple[float, float], ...]
    sum_delta: float | None
    count_delta: float


@dataclass
class _HistogramComponents:
    buckets: dict[float, float]
    sum_value: float | None = None
    count_value: float | None = None


def _labels_without_le(labels: dict[str, str]) -> dict[str, str]:
    return {key: value for key, value in labels.items() if key != "le"}


def _is_plus_inf(value: float) -> bool:
    return math.isinf(value) and value > 0


def _clamp_cumulative(
    buckets: list[tuple[float, float]],
) -> list[tuple[float, float]]:
    clamped: list[tuple[float, float]] = []
    prev: float | None = None
    for le, count in buckets:
        if not math.isfinite(count):
            count = 0.0 if prev is None else prev
        elif prev is not None and count < prev:
            count = prev
        clamped.append((le, count))
        prev = count
    return clamped


def _coerce_le(le: object) -> float:
    if isinstance(le, str):
        return _parse_le(le)
    if isinstance(le, bool) or not isinstance(le, (int, float)):
        raise InfraError("invalid histogram le")
    value = float(le)
    if _is_plus_inf(value) or math.isfinite(value):
        return value
    raise InfraError("invalid histogram le")


def _coerce_buckets(buckets: object) -> list[tuple[float, float]]:
    if isinstance(buckets, HistogramDeltas):
        items = list(buckets.buckets)
    elif isinstance(buckets, dict):
        items = [(_coerce_le(le), float(count)) for le, count in buckets.items()]
    elif isinstance(buckets, (list, tuple)):
        items = [(_coerce_le(le), float(count)) for le, count in buckets]
    else:
        raise TypeError(f"unsupported buckets type: {type(buckets)!r}")
    items.sort(key=lambda pair: pair[0])
    return _clamp_cumulative(items)


def _finite_delta(start: float | None, end: float | None) -> float | None:
    if start is None and end is None:
        return None
    start_v = 0.0 if start is None else start
    end_v = 0.0 if end is None else end
    if not math.isfinite(start_v) or not math.isfinite(end_v):
        return None
    return end_v - start_v


def _plus_inf_count(buckets: list[tuple[float, float]]) -> float | None:
    if buckets and _is_plus_inf(buckets[-1][0]):
        return buckets[-1][1]
    return None


def _group_histogram_series(
    family: Family,
) -> dict[tuple[str, tuple[tuple[str, str], ...]], _HistogramComponents]:
    groups: dict[
        tuple[str, tuple[tuple[str, str], ...]], _HistogramComponents
    ] = {}
    for sample in family.samples:
        key = series_key(family.name, _labels_without_le(sample.labels))
        group = groups.get(key)
        if group is None:
            group = _HistogramComponents(buckets={})
            groups[key] = group
        name = sample.name
        if name.endswith("_bucket") and "le" in sample.labels:
            group.buckets[_parse_le(sample.labels["le"])] = sample.value
        elif name.endswith("_sum"):
            group.sum_value = sample.value
        elif name.endswith("_count"):
            group.count_value = sample.value
    return groups


def bucket_deltas(
    start: dict[str, Family], end: dict[str, Family]
) -> dict[tuple[str, tuple[tuple[str, str], ...]], HistogramDeltas]:
    names = {n for n, f in start.items() if f.type == "histogram"} | {
        n for n, f in end.items() if f.type == "histogram"
    }
    result: dict[tuple[str, tuple[tuple[str, str], ...]], HistogramDeltas] = {}
    for name in names:
        start_family = start.get(name)
        end_family = end.get(name)
        start_groups = (
            _group_histogram_series(start_family)
            if start_family is not None and start_family.type == "histogram"
            else {}
        )
        end_groups = (
            _group_histogram_series(end_family)
            if end_family is not None and end_family.type == "histogram"
            else {}
        )
        for key in set(start_groups) | set(end_groups):
            start_g = start_groups.get(key)
            end_g = end_groups.get(key)
            start_buckets = start_g.buckets if start_g is not None else {}
            end_buckets = end_g.buckets if end_g is not None else {}
            raw = [
                (le, end_buckets.get(le, 0.0) - start_buckets.get(le, 0.0))
                for le in sorted(set(start_buckets) | set(end_buckets))
            ]
            clamped = _clamp_cumulative(raw)
            sum_delta = _finite_delta(
                start_g.sum_value if start_g is not None else None,
                end_g.sum_value if end_g is not None else None,
            )
            count_delta = _finite_delta(
                start_g.count_value if start_g is not None else None,
                end_g.count_value if end_g is not None else None,
            )
            if count_delta is None:
                count_delta = _plus_inf_count(clamped) or 0.0
            result[key] = HistogramDeltas(
                name=name,
                labels=dict(key[1]),
                unit=unit_for(name),
                buckets=tuple(clamped),
                sum_delta=sum_delta,
                count_delta=count_delta,
            )
    return result


def _quantile_parts(
    buckets: object, q: float
) -> tuple[float | None, bool, float | None, float | None]:
    items = _coerce_buckets(buckets)
    if len(items) < 2 or not _is_plus_inf(items[-1][0]):
        return None, False, None, None
    observations = items[-1][1]
    if observations == 0 or not math.isfinite(observations):
        return None, False, None, None
    if not math.isfinite(q):
        return None, False, None, None
    rank = q * observations
    chosen = len(items) - 1
    for i, (_le, count) in enumerate(items[:-1]):
        if count >= rank:
            chosen = i
            break
    if chosen == len(items) - 1:
        finite_le = items[-2][0]
        return finite_le, True, finite_le, math.inf
    bucket_end = items[chosen][0]
    count = items[chosen][1]
    if chosen == 0:
        if bucket_end <= 0:
            return bucket_end, False, bucket_end, bucket_end
        bucket_start = 0.0
    else:
        bucket_start = items[chosen - 1][0]
        count -= items[chosen - 1][1]
        rank -= items[chosen - 1][1]
    if count == 0:
        value = bucket_start
    else:
        value = bucket_start + (bucket_end - bucket_start) * (rank / count)
    return value, False, bucket_start, bucket_end


def _json_float(value: float | None) -> float | None:
    if value is None or not math.isfinite(value):
        return None
    return value


def _json_row(row: dict[str, object]) -> dict[str, object]:
    sanitized = _finite_or_none(row)
    return sanitized if isinstance(sanitized, dict) else row


def histogram_quantile(buckets: object, q: float) -> float | None:
    value, _saturated, _lo, _hi = _quantile_parts(buckets, q)
    return _json_float(value)


# IEEE-754 exact integers; JSON.parse stays finite and exact in this range.
_JSON_SAFE_INT = 2**53


def _samples_value(count_delta: float) -> int | float:
    if not math.isfinite(count_delta) or count_delta <= 0:
        return 0
    if abs(count_delta) <= _JSON_SAFE_INT and count_delta == math.floor(
        count_delta
    ):
        return int(count_delta)
    return count_delta


def _row_label_key(row: dict[str, object]) -> tuple[tuple[str, str], ...]:
    labels = row.get("labels") or {}
    if not isinstance(labels, dict):
        return ()
    return tuple(sorted((str(k), str(v)) for k, v in labels.items()))


def _no_observations_row(
    delta: HistogramDeltas, sum_delta: float | None
) -> dict[str, object]:
    return {
        "annotation": "no_observations",
        "labels": dict(delta.labels),
        "mean": None,
        "p50": None,
        "p50_bucket": None,
        "p95": None,
        "p99": None,
        "samples": 0,
        "saturated": False,
        "sum_delta": sum_delta,
        "unit": delta.unit,
    }


def histogram_stats(
    source: object,
    *,
    sum_delta: float | None = None,
    count_delta: float | None = None,
    name: str = "",
    labels: dict[str, str] | None = None,
    unit: str | None = None,
) -> dict[str, object]:
    if isinstance(source, HistogramDeltas):
        delta = source
    else:
        coerced = _coerce_buckets(source)
        inf_count = _plus_inf_count(coerced) or 0.0
        resolved_count = inf_count if count_delta is None else float(count_delta)
        resolved_unit = unit if unit is not None else (
            unit_for(name) if name else "count"
        )
        delta = HistogramDeltas(
            name=name,
            labels=dict(labels or {}),
            unit=resolved_unit,
            buckets=tuple(coerced),
            sum_delta=sum_delta,
            count_delta=resolved_count,
        )
    samples = _samples_value(delta.count_delta)
    sum_d = _json_float(delta.sum_delta)
    inf_count = _plus_inf_count(list(delta.buckets))
    usable_inf = (
        inf_count is not None and math.isfinite(inf_count) and inf_count > 0
    )
    if samples == 0 or not usable_inf:
        return _json_row(_no_observations_row(delta, sum_d))
    p50, sat50, lo, hi = _quantile_parts(delta.buckets, 0.50)
    p95, sat95, _, _ = _quantile_parts(delta.buckets, 0.95)
    p99, sat99, _, _ = _quantile_parts(delta.buckets, 0.99)
    p50 = _json_float(p50)
    p95 = _json_float(p95)
    p99 = _json_float(p99)
    if p50 is None and p95 is None and p99 is None:
        return _json_row(_no_observations_row(delta, sum_d))
    mean = None
    if sum_d is not None and delta.count_delta != 0:
        mean = sum_d / delta.count_delta
    p50_bucket = None
    if lo is not None or hi is not None:
        p50_bucket = [_json_float(lo), _json_float(hi)]
    return _json_row(
        {
            "annotation": None,
            "labels": dict(delta.labels),
            "mean": _json_float(mean),
            "p50": p50,
            "p50_bucket": p50_bucket,
            "p95": p95,
            "p99": p99,
            "samples": samples,
            "saturated": sat50 or sat95 or sat99,
            "sum_delta": sum_d,
            "unit": delta.unit,
        }
    )


def fold_histograms(
    start: dict[str, Family], end: dict[str, Family]
) -> dict[str, list[dict[str, object]]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for delta in bucket_deltas(start, end).values():
        grouped.setdefault(delta.name, []).append(histogram_stats(delta))
    for rows in grouped.values():
        rows.sort(key=_row_label_key)
    return grouped


# ===== § 8. client.json report =====

_PROPOSALS_FAMILY = "rvc_proposals_total"
_K6_FORCE_REGISTERED = frozenset({"envelope_late"})
_ANN_NO_PROPOSAL = "no_proposal_window"
_ANN_NO_OBSERVATIONS = "no_observations"
_PRESENCE_CHILD_ABSENT = "family_present_child_absent"
_PRESENCE_ALL_CHILDREN = "all_children_present"
_MAX_REPORT_JSON_BYTES = 1024 * 1024
_RUN_JSON_KEYS = (
    "epochs",
    "fingerprint",
    "generated_at",
    "genesis_validators_root",
    "git_sha",
    "images",
    "key_range",
    "profile",
    "pubkeys",
    "run_id",
    "rvc_version",
    "schema_version",
)
_TABLE_DASH = "—"
_CELL_CTRL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SECRET_LABEL_KEYS = frozenset({"password", "mnemonic", "jwt", "secret", "token"})
_COUNTER_HEADERS = (
    "family",
    "labels",
    "unit",
    "start",
    "end",
    "delta",
    "per_epoch",
)
_HISTOGRAM_HEADERS = (
    "family",
    "labels",
    "unit",
    "samples",
    "mean",
    "p50",
    "p95",
    "p99",
)
_GAUGE_HEADERS = (
    "family",
    "labels",
    "unit",
    "last",
    "min",
    "max",
    "samples",
)


def _require_regular_file(path: str, *, cap: int) -> None:
    dest = os.fspath(path)
    try:
        st = os.lstat(dest)
    except FileNotFoundError:
        raise UsageError(_artifact_msg(dest, "failed to read {name}")) from None
    except OSError as exc:
        raise InfraError(_artifact_msg(dest, "failed to read {name}")) from exc
    if stat.S_ISLNK(st.st_mode):
        raise InfraError(_artifact_msg(dest, "{name} is a symlink"))
    if not stat.S_ISREG(st.st_mode):
        raise InfraError(_artifact_msg(dest, "{name} is not a regular file"))
    if st.st_size > cap:
        raise InfraError(_artifact_msg(dest, "{name} exceeded size cap"))


def _read_regular_text(path: str, *, cap: int) -> str:
    dest = os.fspath(path)
    _require_regular_file(dest, cap=cap)
    try:
        fd = os.open(dest, _jsonl_open_flags(write=False))
    except OSError as exc:
        raise InfraError(_artifact_msg(dest, "failed to read {name}")) from exc
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise InfraError(_artifact_msg(dest, "{name} is not a regular file"))
        if opened.st_size > cap:
            raise InfraError(_artifact_msg(dest, "{name} exceeded size cap"))
        data = os.read(fd, cap + 1)
    except OSError as exc:
        raise InfraError(_artifact_msg(dest, "failed to read {name}")) from exc
    finally:
        os.close(fd)
    if len(data) > cap:
        raise InfraError(_artifact_msg(dest, "{name} exceeded size cap"))
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InfraError(_artifact_msg(dest, "{name} is not valid UTF-8")) from exc


def _load_json_object(path: str) -> object:
    try:
        return json.loads(
            _read_regular_text(path, cap=_MAX_REPORT_JSON_BYTES)
        )
    except json.JSONDecodeError as exc:
        raise UsageError(
            _artifact_msg(path, "invalid JSON in {name}")
        ) from exc


def _validate_run_dir(run_dir: str) -> None:
    try:
        st = os.lstat(run_dir)
    except FileNotFoundError:
        raise UsageError(f"--run-dir is not a directory: {run_dir}") from None
    except OSError as exc:
        raise InfraError("failed to read run dir") from exc
    if stat.S_ISLNK(st.st_mode):
        raise InfraError("run dir is a symlink")
    if not stat.S_ISDIR(st.st_mode):
        raise UsageError(f"--run-dir is not a directory: {run_dir}")


def _copy_run(run: dict[str, object]) -> dict[str, object]:
    return {key: run[key] for key in _RUN_JSON_KEYS if key in run}


def _run_epochs(run: dict[str, object]) -> int:
    epochs = run.get("epochs")
    if isinstance(epochs, bool) or not isinstance(epochs, int) or epochs <= 0:
        raise UsageError(
            _artifact_msg("run.json", "{name} epochs must be a positive integer")
        )
    return epochs


def _with_counter_units(
    counters: dict[str, list[dict[str, object]]],
) -> dict[str, list[dict[str, object]]]:
    for name, rows in counters.items():
        unit = unit_for(name)
        for row in rows:
            row["unit"] = unit
    return counters


def _proposals_delta(counters: dict[str, list[dict[str, object]]]) -> float:
    total = 0.0
    for row in counters.get(_PROPOSALS_FAMILY, []):
        delta = row.get("delta")
        if isinstance(delta, bool) or not isinstance(delta, (int, float)):
            continue
        if math.isfinite(delta):
            total += delta
    return total


def _k6_presence(
    counters: dict[str, list[dict[str, object]]],
) -> dict[str, str]:
    rows = counters.get(_PROPOSALS_FAMILY)
    if rows is None:
        return {"K6": _PRESENCE_CHILD_ABSENT}
    outcomes: set[object] = set()
    for row in rows:
        labels = row.get("labels")
        if isinstance(labels, dict) and "outcome" in labels:
            outcomes.add(labels["outcome"])
    if outcomes <= _K6_FORCE_REGISTERED:
        return {"K6": _PRESENCE_CHILD_ABSENT}
    return {"K6": _PRESENCE_ALL_CHILDREN}


def _client_annotations(
    counters: dict[str, list[dict[str, object]]],
    histograms: dict[str, list[dict[str, object]]],
) -> list[str]:
    notes: list[str] = []
    if _proposals_delta(counters) == 0:
        notes.append(_ANN_NO_PROPOSAL)
    if any(
        row.get("annotation") == _ANN_NO_OBSERVATIONS
        for rows in histograms.values()
        for row in rows
    ):
        notes.append(_ANN_NO_OBSERVATIONS)
    notes.sort()
    return notes


def build_client_json(
    run: dict[str, object],
    window: dict[str, object],
    start: dict[str, Family],
    end: dict[str, Family],
    samples: dict[str, list[dict[str, object]]],
    *,
    clock: Callable[[], datetime] | None = None,
) -> dict[str, object]:
    epochs = _run_epochs(run)
    counters = _with_counter_units(
        counter_delta(start, end, epochs=float(epochs))
    )
    histograms = fold_histograms(start, end)
    window_out = dict(window)
    window_out["epochs"] = epochs
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": _generated_at(clock),
        "run": _copy_run(run),
        "window": window_out,
        "counters": counters,
        "histograms": histograms,
        "gauges": samples,
        "presence": _k6_presence(counters),
        "annotations": _client_annotations(counters, histograms),
    }


def _fmt_number(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return _TABLE_DASH
    number = float(value)
    if not math.isfinite(number):
        return _TABLE_DASH
    if number == math.trunc(number) and abs(number) <= _JSON_SAFE_INT:
        return str(int(number))
    return format(number, ".10g")


def _sanitize_cell(text: object) -> str:
    raw = text if isinstance(text, str) else str(text)
    return _CELL_CTRL_RE.sub("?", raw)


def _secret_label_key(key: str) -> bool:
    lowered = key.lower()
    return lowered in _SECRET_LABEL_KEYS or lowered.startswith("secret")


def _fmt_labels(labels: object) -> str:
    if not isinstance(labels, dict) or not labels:
        return _TABLE_DASH
    parts: list[tuple[str, str]] = []
    for key, value in labels.items():
        key_s = key if isinstance(key, str) else str(key)
        if _secret_label_key(key_s):
            continue
        val_s = value if isinstance(value, str) else str(value)
        parts.append((_sanitize_cell(key_s), _sanitize_cell(val_s)))
    if not parts:
        return _TABLE_DASH
    return ",".join(
        f"{key}={value}" for key, value in sorted(parts)
    )


def _align_rows(rows: list[list[str]]) -> list[str]:
    if not rows:
        return []
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    return [
        "  ".join(f"{cell:<{w}}" for cell, w in zip(row, widths)).rstrip()
        for row in rows
    ]


def _series_rows(block: object) -> list[tuple[str, dict[str, object]]]:
    if not isinstance(block, dict):
        return []
    rows: list[tuple[str, dict[str, object]]] = []
    for name in sorted(block):
        series = block[name]
        if not isinstance(name, str) or not isinstance(series, list):
            continue
        for item in series:
            if isinstance(item, dict):
                rows.append((name, item))
    return rows


def _shown_unit(name: str, row: dict[str, object]) -> str:
    unit = row.get("unit")
    shown = unit if isinstance(unit, str) and unit else unit_for(name)
    return _sanitize_cell(shown)


def _counter_row(name: str, row: dict[str, object]) -> list[str]:
    return [
        _sanitize_cell(name),
        _fmt_labels(row.get("labels")),
        _shown_unit(name, row),
        _fmt_number(row.get("start")),
        _fmt_number(row.get("end")),
        _fmt_number(row.get("delta")),
        _fmt_number(row.get("per_epoch")),
    ]


def _histogram_row(name: str, row: dict[str, object]) -> list[str]:
    return [
        _sanitize_cell(name),
        _fmt_labels(row.get("labels")),
        _shown_unit(name, row),
        _fmt_number(row.get("samples")),
        _fmt_number(row.get("mean")),
        _fmt_number(row.get("p50")),
        _fmt_number(row.get("p95")),
        _fmt_number(row.get("p99")),
    ]


def _gauge_row(name: str, row: dict[str, object]) -> list[str]:
    return [
        _sanitize_cell(name),
        _fmt_labels(row.get("labels")),
        _sanitize_cell(unit_for(name)),
        _fmt_number(row.get("last")),
        _fmt_number(row.get("min")),
        _fmt_number(row.get("max")),
        _fmt_number(row.get("samples")),
    ]


def render_table(client: dict[str, object]) -> str:
    sections = (
        (_COUNTER_HEADERS, _series_rows(client.get("counters")), _counter_row),
        (
            _HISTOGRAM_HEADERS,
            _series_rows(client.get("histograms")),
            _histogram_row,
        ),
        (_GAUGE_HEADERS, _series_rows(client.get("gauges")), _gauge_row),
    )
    lines: list[str] = []
    for headers, series, build_row in sections:
        table = _align_rows(
            [list(headers), *[build_row(name, row) for name, row in series]]
        )
        if lines:
            lines.append("")
        lines.extend(table)
    return "\n".join(lines).rstrip("\n") + "\n"


def cmd_report(
    opts: Options,
    *,
    clock: Callable[[], datetime] | None = None,
) -> None:
    run_dir = opts.run_dir
    if not run_dir:
        raise UsageError("--run-dir is required")
    _validate_run_dir(run_dir)
    run_path = os.path.join(run_dir, "run.json")
    start_path = os.path.join(run_dir, "metrics-start.txt")
    end_path = os.path.join(run_dir, "metrics-end.txt")
    samples_path = os.path.join(run_dir, "samples.jsonl")
    run_obj = _load_json_object(run_path)
    if not isinstance(run_obj, dict):
        raise UsageError(_artifact_msg(run_path, "{name} must be an object"))
    start = parse_metrics(
        _read_regular_text(start_path, cap=MAX_RESPONSE_BYTES)
    )
    end = parse_metrics(
        _read_regular_text(end_path, cap=MAX_RESPONSE_BYTES)
    )
    _require_regular_file(samples_path, cap=_MAX_JSONL_BYTES)
    window = window_from_samples(samples_path)
    gauges = fold_gauges(samples_path)
    client = build_client_json(
        run_obj, window, start, end, gauges, clock=clock
    )
    table = render_table(client)
    client_path = os.path.join(run_dir, "client.json")
    report_path = os.path.join(run_dir, "report.txt")
    try:
        write_json_atomic(client_path, client)
    except OSError as exc:
        raise InfraError(_artifact_msg(client_path, "failed to write {name}")) from exc
    try:
        _write_text_atomic(report_path, table)
    except OSError as exc:
        raise InfraError(_artifact_msg(report_path, "failed to write {name}")) from exc
    sys.stdout.write(table)


# ===== § 9. Compare =====


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


def _write_text_atomic(path: str | os.PathLike[str], text: str) -> None:
    dest = os.path.abspath(path)
    directory = os.path.dirname(dest) or "."
    fd, tmp = tempfile.mkstemp(
        prefix="devnet_report.", suffix=".tmp", dir=directory
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.replace(tmp, dest)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_json_atomic(path: str | os.PathLike[str], obj: object) -> None:
    payload = json.dumps(
        _finite_or_none(obj), allow_nan=False, sort_keys=True
    )
    _write_text_atomic(path, payload + "\n")


if __name__ == "__main__":
    sys.exit(main())
