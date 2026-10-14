#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Cross-check a devnet config.yaml against each BN's advertised spec and genesis."""

import argparse
import base64
import http.client
import json
import os
import re
import socket
import ssl
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TextIO
from urllib.parse import unquote, urlsplit

# ===== § 1. Header, constants, exit codes =====

DEFAULT_CONNECT_TIMEOUT = 5.0
DEFAULT_READ_TIMEOUT = 30.0
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2

COMPARE_ALWAYS = (
    "GLOAS_FORK_EPOCH",
    "GLOAS_FORK_VERSION",
    "SLOT_DURATION_MS",
)
REPORT_ONLY_KEY = "AGGREGATE_DUE_BPS_GLOAS"
SPEC_PATH = "/eth/v1/config/spec"
GENESIS_PATH = "/eth/v1/beacon/genesis"
VERSION_PATH = "/eth/v1/node/version"

# ===== § 2. Errors and diagnostics =====


class UsageError(Exception):
    pass


class Error(Exception):
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


# ===== § 3. Parsing =====


_UINT = re.compile(r"[0-9]+")
_HEX = re.compile(r"[0-9a-f]+")


def _scalar(raw: str, origin: str, lineno: int) -> str:
    text = raw.strip()
    if not text:
        return ""
    if text[0] in ("'", '"'):
        quote = text[0]
        i = 1
        out: list[str] = []
        while i < len(text):
            ch = text[i]
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                return "".join(out)
            out.append(ch)
            i += 1
        raise UsageError(f"{origin}:{lineno}: unclosed quoted value")
    if " #" in text:
        text = text[: text.index(" #")].rstrip()
    return text


def parse_config_yaml(text: str, origin: str) -> dict[str, str]:
    """Parse the flat KEY: value subset used by consensus config.yaml files."""
    out: dict[str, str] = {}
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if line[:1] in " \t-":
            continue
        if ":" not in line:
            raise UsageError(f"{origin}:{lineno}: expected KEY: value")
        key, _, rest = line.partition(":")
        key = key.strip()
        if not key or any(ch.isspace() for ch in key):
            raise UsageError(f"{origin}:{lineno}: invalid key")
        value = _scalar(rest, origin, lineno)
        if not value:
            continue
        if key in out:
            raise UsageError(f"{origin}:{lineno}: duplicate key {key}")
        out[key] = value
    return out


def _token(raw: object) -> str | None:
    if isinstance(raw, bool) or raw is None:
        return None
    if isinstance(raw, int):
        if raw < 0:
            return None
        return str(raw)
    if isinstance(raw, str):
        text = raw.strip()
        return text or None
    return None


def _canonical_uint(token: str) -> int:
    if _UINT.fullmatch(token) is None:
        raise ValueError
    return int(token)


def _canonical_hex(token: str, nbytes: int) -> str:
    text = token.lower()
    if text.startswith("0x"):
        text = text[2:]
    if _HEX.fullmatch(text) is None or len(text) != nbytes * 2:
        raise ValueError
    return "0x" + text


def _is_hex_key(key: str) -> bool:
    return (
        key.endswith("_VERSION")
        or key.endswith("_ROOT")
        or key == "genesis_validators_root"
    )


def _hex_nbytes(key: str) -> int:
    if key == "genesis_validators_root":
        return 32
    return 4


def canonical_value(key: str, raw: object) -> str:
    token = _token(raw)
    if token is None:
        raise ValueError
    if _is_hex_key(key):
        return _canonical_hex(token, _hex_nbytes(key))
    return str(_canonical_uint(token))


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


def parse_endpoint(url: str, label: str) -> "Endpoint":
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        port = parsed.port
    except ValueError as exc:
        raise UsageError(f"invalid URL: {_redact_url(url)}") from exc
    if parsed.scheme not in ("http", "https"):
        raise UsageError(f"unsupported URL scheme: {parsed.scheme!r}")
    if ":" in host:
        host = f"[{host}]"
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if not host:
        raise UsageError(f"invalid URL: {_redact_url(url)}")
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


def _source(ep: "Endpoint", path: str) -> str:
    return f"{redact(ep)}={path.split('?', 1)[0]}"


def _safe_cause(exc: BaseException) -> str:
    name = type(exc).__name__
    text = str(exc).strip()
    if not text:
        return name
    if any(marker in text for marker in ("://", "@", "?", "token=")):
        return name
    return f"{name}: {text}"


def _is_due_bps(key: str) -> bool:
    return "_DUE_BPS" in key


def compare_keys(*dicts: Mapping[str, object]) -> tuple[str, ...]:
    keys = set(COMPARE_ALWAYS)
    for mapping in dicts:
        for key in mapping:
            if _is_due_bps(key) and key != REPORT_ONLY_KEY:
                keys.add(key)
    return tuple(sorted(keys))


# ===== § 4. CLI =====


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Cross-check a devnet config.yaml against each BN's "
            "/eth/v1/config/spec and /eth/v1/beacon/genesis."
        ),
    )
    p.add_argument("--network-config")
    p.add_argument("--beacon-url", action="append")
    p.add_argument("--connect-timeout", type=float)
    p.add_argument("--read-timeout", type=float)
    p.add_argument("-v", action="count", default=0, dest="verbose")
    p.add_argument("-q", action="store_true", dest="quiet")
    return p


@dataclass(frozen=True)
class Options:
    network_config: str
    endpoints: tuple["Endpoint", ...]
    verbosity: int
    connect_timeout: float
    read_timeout: float


def build_options(argv: list[str] | None) -> Options:
    args = build_parser().parse_args(argv)
    if args.quiet and args.verbose:
        raise UsageError("-v and -q are mutually exclusive")
    if not args.network_config:
        raise UsageError("no network config: supply --network-config")
    if not args.beacon_url:
        raise UsageError("no beacon URL: supply --beacon-url")
    endpoints = tuple(
        parse_endpoint(url, f"bn{i}") for i, url in enumerate(args.beacon_url)
    )
    connect = (
        DEFAULT_CONNECT_TIMEOUT
        if args.connect_timeout is None
        else args.connect_timeout
    )
    read = DEFAULT_READ_TIMEOUT if args.read_timeout is None else args.read_timeout
    verbosity = -1 if args.quiet else args.verbose
    return Options(
        network_config=args.network_config,
        endpoints=endpoints,
        verbosity=verbosity,
        connect_timeout=connect,
        read_timeout=read,
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
    truncated: bool = False
    headers: dict[str, str] = field(default_factory=dict)


Transport = Callable[[Endpoint, str, str, bytes | None], RawResponse]


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
            if ep.auth_header:
                headers["Authorization"] = ep.auth_header
            if body is not None:
                headers["Content-Type"] = "application/json"
            conn.request(method, ep.base_path + path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            return RawResponse(resp.status, raw, len(raw) > MAX_RESPONSE_BYTES)
        finally:
            conn.close()

    def drop(self, _ep: Endpoint) -> None:
        return None

    def close(self) -> None:
        return None


def get_raw(ep: Endpoint, transport: Transport, path: str) -> RawResponse:
    source = _source(ep, path)
    try:
        raw = transport(ep, "GET", path, None)
    except (
        ssl.SSLError,
        socket.gaierror,
        TimeoutError,
        ConnectionError,
        http.client.HTTPException,
        OSError,
    ) as exc:
        raise Error(f"transport error {source}: {_safe_cause(exc)}") from exc
    if raw.truncated:
        raise Error(f"truncated {source}")
    if raw.status != 200:
        raise Error(f"HTTP {raw.status} {source}")
    return raw


def get_json(ep: Endpoint, transport: Transport, path: str) -> object:
    source = _source(ep, path)
    raw = get_raw(ep, transport, path)
    try:
        return json.loads(raw.body)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Error(f"invalid JSON {source}: {_safe_cause(exc)}") from exc


def _data_dict(payload: object, source: str) -> dict:
    if not isinstance(payload, dict) or "data" not in payload:
        raise Error(f"missing data in {source}")
    data = payload["data"]
    if not isinstance(data, dict):
        raise Error(f"invalid data in {source}")
    return data


# ===== § 6. Load config and BN views =====


def _request_path(url: str) -> str:
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    return path


def load_network_config(
    config_ref: str, transport: Transport
) -> tuple[dict[str, str], str]:
    parsed = urlsplit(config_ref)
    if parsed.scheme and parsed.scheme not in ("http", "https"):
        raise UsageError(f"unsupported URL scheme: {parsed.scheme!r}")
    if parsed.scheme in ("http", "https"):
        labeled = parse_endpoint(config_ref, "config")
        ep = Endpoint(
            labeled.label,
            labeled.scheme,
            labeled.host,
            labeled.port,
            "",
            labeled.auth_header,
        )
        origin = redact(ep)
        path = _request_path(config_ref)
        raw = get_raw(ep, transport, path)
        try:
            text = raw.body.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise Error(
                f"invalid UTF-8 {_source(ep, path)}: {_safe_cause(exc)}"
            ) from exc
        return parse_config_yaml(text, origin), origin
    path = config_ref
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise UsageError(f"{path}: {exc.strerror or exc}") from exc
    origin = os.path.abspath(path)
    return parse_config_yaml(text, origin), origin


@dataclass(frozen=True)
class BnView:
    endpoint: Endpoint
    version: str
    spec: dict
    genesis: dict


def fetch_bn(ep: Endpoint, transport: Transport) -> BnView:
    version_source = f"{redact(ep)}={VERSION_PATH}"
    version_data = _data_dict(get_json(ep, transport, VERSION_PATH), version_source)
    version = version_data.get("version")
    if not isinstance(version, str) or not version.strip():
        raise Error(f"missing version from {version_source}")
    spec_source = f"{redact(ep)}={SPEC_PATH}"
    spec = _data_dict(get_json(ep, transport, SPEC_PATH), spec_source)
    genesis_source = f"{redact(ep)}={GENESIS_PATH}"
    genesis = _data_dict(get_json(ep, transport, GENESIS_PATH), genesis_source)
    return BnView(ep, version.strip(), spec, genesis)


# ===== § 7. Compare =====


def _source_config(origin: str) -> str:
    return f"network-config={origin}"


def _source_spec(ep: Endpoint) -> str:
    return f"{redact(ep)}={SPEC_PATH}"


def _source_genesis(ep: Endpoint) -> str:
    return f"{redact(ep)}={GENESIS_PATH}"


def _invalid(key: str, source: str, raw: object) -> str:
    return f"invalid {key} from {source}: {raw!r}"


def diff_spec(
    config: Mapping[str, str],
    views: Sequence[BnView],
    origin: str,
) -> list[str]:
    errors: list[str] = []
    keys = compare_keys(config, *(view.spec for view in views))
    for key in keys:
        if key not in config:
            errors.append(f"{key} missing from {_source_config(origin)}")
        for view in views:
            spec_src = _source_spec(view.endpoint)
            if key not in view.spec:
                errors.append(f"{key} missing from {spec_src}")
                continue
            if key not in config:
                continue
            left_raw = config[key]
            right_raw = view.spec[key]
            try:
                left = canonical_value(key, left_raw)
            except ValueError:
                errors.append(_invalid(key, _source_config(origin), left_raw))
                continue
            try:
                right = canonical_value(key, right_raw)
            except ValueError:
                errors.append(_invalid(key, spec_src, right_raw))
                continue
            if left != right:
                errors.append(
                    f"{key} mismatch: {_source_config(origin)} value={left_raw}; "
                    f"{spec_src} value={right_raw}"
                )
    return errors


def diff_genesis(views: Sequence[BnView]) -> list[str]:
    errors: list[str] = []
    fields = ("genesis_time", "genesis_validators_root")
    parsed: list[dict[str, str]] = []
    for view in views:
        source = _source_genesis(view.endpoint)
        row: dict[str, str] = {}
        for field_name in fields:
            if field_name not in view.genesis:
                errors.append(f"{field_name} missing from {source}")
                continue
            raw = view.genesis[field_name]
            try:
                row[field_name] = canonical_value(field_name, raw)
            except ValueError:
                errors.append(_invalid(field_name, source, raw))
        parsed.append(row)
    if errors:
        return errors
    ref = parsed[0]
    ref_src = _source_genesis(views[0].endpoint)
    for view, row in zip(views[1:], parsed[1:], strict=True):
        src = _source_genesis(view.endpoint)
        for field_name in fields:
            if ref[field_name] != row[field_name]:
                errors.append(
                    f"{field_name} mismatch: {ref_src} "
                    f"value={views[0].genesis[field_name]}; "
                    f"{src} value={view.genesis[field_name]}"
                )
    return errors


def agreed_genesis(views: Sequence[BnView]) -> tuple[int, str]:
    genesis = views[0].genesis
    time_token = canonical_value("genesis_time", genesis["genesis_time"])
    root = canonical_value(
        "genesis_validators_root", genesis["genesis_validators_root"]
    )
    return int(time_token), root


def render_rvc_fragment(genesis_time: int, genesis_validators_root: str) -> str:
    return (
        'network = "custom"\n'
        f"genesis_time = {genesis_time}\n"
        f'genesis_validators_root = "{genesis_validators_root}"\n'
    )


# ===== § 8. main =====


def main(
    argv: list[str] | None = None, *, transport: Transport | None = None
) -> int:
    log = Log(0, sys.stderr)
    active = transport
    try:
        opts = build_options(argv)
        log = Log(opts.verbosity, sys.stderr)
        if active is None:
            active = HttpTransport(opts.connect_timeout, opts.read_timeout)
        config, origin = load_network_config(opts.network_config, active)
        views: list[BnView] = []
        for ep in opts.endpoints:
            view = fetch_bn(ep, active)
            print(f"{redact(ep)}: {view.version}", file=sys.stderr)
            views.append(view)
        errors = diff_spec(config, views, origin) + diff_genesis(views)
        if errors:
            raise Error("\n".join(errors))
        if REPORT_ONLY_KEY in config:
            print(
                f"{REPORT_ONLY_KEY}: {config[REPORT_ONLY_KEY]} (network-config)",
                file=sys.stderr,
            )
        genesis_time, genesis_root = agreed_genesis(views)
        sys.stdout.write(render_rvc_fragment(genesis_time, genesis_root))
        return EXIT_OK
    except UsageError as exc:
        log.error("%s", exc)
        return EXIT_USAGE
    except Error as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except Exception as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    finally:
        closer = getattr(active, "close", None)
        if callable(closer):
            closer()


if __name__ == "__main__":
    sys.exit(main())
