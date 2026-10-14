#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Daily soak snapshot: zero-slashing, PTC, BN capability, signer gates."""

from __future__ import annotations

import argparse
import http.client
import importlib.util
import json
import math
import os
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, TextIO
from urllib.parse import urlsplit

sys.dont_write_bytecode = True

# ===== § 1. Header, constants, exit codes =====

SCHEMA_VERSION = 1
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
DEFAULT_CONNECT_TIMEOUT = 5.0
EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_THRESHOLD = 0, 1, 2, 4
TARGET_RATE_MIN = 0.99
TARGET_RATE_FAIL_UNDER = "target_rate=0.99"

FORK_CURRENT = "rvc_fork_current_id"
FORK_NEXT = "rvc_fork_next_activation_epoch"
BN_CAPABILITY = "rvc_bn_capability_state"
SIGNER_REJECTIONS = "rvc_signer_rejections_total"

# D5 six families, plus the slashing pair the zero-slashing gate reads.
SIX_FAMILIES = (
    FORK_CURRENT,
    FORK_NEXT,
    "rvc_ptc_duties_total",
    "rvc_ptc_attestations_total",
    BN_CAPABILITY,
    SIGNER_REJECTIONS,
)
GATE_ZERO_SLASHING = "zero_slashing"
GATE_PTC = "ptc_submission"
GATE_BN = "bn_capability"
GATE_SIGNER = "signer_rejections"
GATE_TARGET_RATE = "target_rate"
BLOCKING_GATES = frozenset({GATE_ZERO_SLASHING, GATE_PTC, GATE_BN, GATE_TARGET_RATE})

# ===== § 2. Errors and diagnostics =====


class UsageError(Exception):
    pass


class SnapshotError(Exception):
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


def _load_scorecard():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "devnet_scorecard.py")
    spec = importlib.util.spec_from_file_location("_rvc_gloas_soak_scorecard", path)
    if spec is None or spec.loader is None:
        raise SnapshotError(f"cannot load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_SC = None


def scorecard():
    global _SC
    if _SC is None:
        _SC = _load_scorecard()
    return _SC


# ===== § 3. CLI =====


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    p = _ArgumentParser(
        description=(
            "Daily soak snapshot: validator_perf --fail-under target_rate=0.99, "
            "rvc /metrics scrape, zero-slashing and PTC gates. "
            "Writes one JSON per UTC day to --out-dir (never the repo)."
        ),
    )
    p.add_argument("--out-dir", metavar="DIR")
    p.add_argument("--metrics", metavar="PATH")
    p.add_argument("--metrics-start", metavar="PATH")
    p.add_argument("--metrics-url", metavar="URL")
    p.add_argument("--perf-json", metavar="PATH")
    p.add_argument("--json", action="store_true")
    p.add_argument("-v", action="count", default=0, dest="verbose")
    p.add_argument("-q", action="store_true", dest="quiet")
    return p


@dataclass(frozen=True)
class Options:
    out_dir: str
    metrics: str | None
    metrics_start: str | None
    metrics_url: str | None
    perf_json: str | None
    as_json: bool
    verbosity: int
    perf_argv: tuple[str, ...]


def build_options(argv: list[str] | None = None) -> Options:
    args, rest = build_parser().parse_known_args(argv)
    if args.quiet and args.verbose:
        raise UsageError("-v and -q are mutually exclusive")
    if not args.out_dir:
        raise UsageError("--out-dir is required")
    if args.metrics and args.metrics_url:
        raise UsageError("--metrics and --metrics-url are mutually exclusive")
    if not args.metrics and not args.metrics_url:
        raise UsageError("--metrics or --metrics-url is required")
    return Options(
        out_dir=args.out_dir,
        metrics=args.metrics,
        metrics_start=args.metrics_start,
        metrics_url=args.metrics_url,
        perf_json=args.perf_json,
        as_json=bool(args.json),
        verbosity=-1 if args.quiet else args.verbose,
        perf_argv=tuple(rest),
    )


# ===== § 4. Paths and I/O =====


def repo_root() -> str:
    return os.path.realpath(
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
    )


def _refuse_repo_path(dest: str) -> None:
    root = repo_root()
    abs_dest = os.path.abspath(dest)
    try:
        common = os.path.commonpath([root, abs_dest])
    except ValueError:
        return
    if common == root:
        raise UsageError(
            f"--out-dir must not be inside the repository ({root})"
        )


def resolve_out_dir(raw: str) -> str:
    dest = os.path.abspath(raw)
    if os.path.lexists(dest) and os.path.islink(dest):
        raise UsageError(f"refusing symlink --out-dir: {dest}")
    if os.path.lexists(dest) and not os.path.isdir(dest):
        raise UsageError(f"--out-dir is not a directory: {dest}")
    _refuse_repo_path(dest)
    try:
        os.makedirs(dest, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise UsageError(f"cannot create --out-dir {dest}: {exc}") from exc
    if os.path.islink(dest):
        raise UsageError(f"refusing symlink --out-dir: {dest}")
    dest = os.path.realpath(dest)
    _refuse_repo_path(dest)
    return dest


def _write_text(path: str, text: str) -> None:
    dest = os.fspath(path)
    directory = os.path.dirname(dest) or "."
    try:
        existing = os.lstat(dest)
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise SnapshotError(f"cannot write {dest}: {exc}") from exc
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode):
            raise SnapshotError(f"{dest} is a symlink")
        if not stat.S_ISREG(existing.st_mode):
            raise SnapshotError(f"{dest} is not a regular file")
        if existing.st_nlink > 1:
            raise SnapshotError(f"{dest} is a hardlink")
    fd, tmp = tempfile.mkstemp(prefix=".gloas-soak-", suffix=".tmp", dir=directory)
    try:
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise SnapshotError(f"{dest} is not a regular file")
            os.fchmod(fd, 0o600)
            data = text.encode("utf-8")
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, dest)
        tmp = None
    except OSError as exc:
        raise SnapshotError(f"cannot write {dest}: {exc}") from exc
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def fetch_metrics_text(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise UsageError(f"unsupported URL scheme: {parsed.scheme!r}")
    host = parsed.hostname or ""
    if not host:
        raise UsageError(f"invalid URL: {url!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise UsageError(f"invalid URL: {url!r}") from exc
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    path = parsed.path or "/metrics"
    if path == "/":
        path = "/metrics"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    factory = (
        http.client.HTTPSConnection
        if parsed.scheme == "https"
        else http.client.HTTPConnection
    )
    conn = factory(host, port, timeout=DEFAULT_CONNECT_TIMEOUT)
    try:
        conn.connect()
        conn.request("GET", path)
        resp = conn.getresponse()
        raw = resp.read(MAX_RESPONSE_BYTES + 1)
        if resp.status != 200:
            raise SnapshotError(f"metrics HTTP {resp.status}")
        if len(raw) > MAX_RESPONSE_BYTES:
            raise SnapshotError("metrics response exceeded MAX_RESPONSE_BYTES")
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SnapshotError("metrics response is not valid UTF-8") from exc
    except SnapshotError:
        raise
    except Exception as exc:
        raise SnapshotError(f"metrics fetch failed: {exc}") from exc
    finally:
        conn.close()


def parse_selected(text: str) -> dict[str, Any]:
    """Parse with 7.6b's helper; keep the six D5 families plus slashing by name."""
    sc = scorecard()
    parsed = sc.parse_metrics(text)
    names = set(SIX_FAMILIES) | {sc.SLASHED_TOTAL, sc.SLASHING_CHECKS}
    return {name: parsed[name] for name in names if name in parsed}


def load_metrics_file(path: str) -> dict[str, Any]:
    sc = scorecard()
    try:
        text = sc._read_text(path)
    except sc.UsageError as exc:
        raise UsageError(str(exc)) from exc
    except sc.ScorecardError as exc:
        raise SnapshotError(str(exc)) from exc
    try:
        return parse_selected(text)
    except sc.ScorecardError as exc:
        raise SnapshotError(str(exc)) from exc


def load_perf_json(path: str) -> dict[str, Any]:
    sc = scorecard()
    try:
        text = sc._read_text(path)
    except sc.UsageError as exc:
        raise UsageError(str(exc)) from exc
    except sc.ScorecardError as exc:
        raise SnapshotError(str(exc)) from exc
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise SnapshotError(f"{path}: not valid JSON") from exc
    if not isinstance(doc, dict):
        raise SnapshotError(f"{path}: validator_perf JSON must be an object")
    return doc


def _validator_perf_cmd() -> str:
    env = os.environ.get("VALIDATOR_PERF")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(here, "validator_perf.py")


def run_validator_perf(perf_argv: tuple[str, ...]) -> dict[str, Any]:
    cmd = [
        _validator_perf_cmd(),
        "--json",
        "--fail-under",
        TARGET_RATE_FAIL_UNDER,
        *perf_argv,
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as exc:
        raise SnapshotError(f"validator_perf failed: {exc}") from exc
    if proc.returncode == EXIT_USAGE:
        raise UsageError(proc.stderr.strip() or "validator_perf usage error")
    if proc.returncode not in (EXIT_OK, EXIT_THRESHOLD) and proc.returncode != 3:
        err = proc.stderr.strip() or proc.stdout.strip() or "validator_perf failed"
        raise SnapshotError(err)
    try:
        doc = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise SnapshotError("validator_perf stdout is not JSON") from exc
    if not isinstance(doc, dict):
        raise SnapshotError("validator_perf JSON must be an object")
    doc.setdefault("exit_code", proc.returncode)
    return doc


# ===== § 5. Gates =====


def _series_sum(families: dict[str, Any], name: str, labels: dict[str, str] | None):
    if name not in families:
        return None
    sc = scorecard()
    try:
        return sc.sample_sum(families, name, labels)
    except sc.ScorecardError as exc:
        raise SnapshotError(str(exc)) from exc


def _counter_delta(
    start: dict[str, Any] | None,
    end: dict[str, Any],
    name: str,
    labels: dict[str, str] | None,
) -> dict[str, Any]:
    if name not in end:
        return {
            "status": "unavailable",
            "start": None,
            "end": None,
            "delta": None,
        }
    end_v = _series_sum(end, name, labels)
    start_v = 0.0
    if start is not None and name in start:
        start_v = _series_sum(start, name, labels) or 0.0
    assert end_v is not None
    return {
        "status": "pass",
        "start": start_v,
        "end": end_v,
        "delta": end_v - start_v,
    }


def eval_zero_slashing(
    start: dict[str, Any] | None, end: dict[str, Any]
) -> dict[str, Any]:
    sc = scorecard()
    slashed = _counter_delta(start, end, sc.SLASHED_TOTAL, {})
    blocked = _counter_delta(
        start, end, sc.SLASHING_CHECKS, {"result": "blocked"}
    )
    unavailable: list[str] = []
    if slashed["status"] == "unavailable":
        unavailable.append(sc.SLASHED_TOTAL)
    if blocked["status"] == "unavailable":
        unavailable.append(sc.SLASHING_CHECKS)
    if unavailable:
        status = "unavailable"
    elif slashed["delta"] or blocked["delta"]:
        # Nonzero includes a counter reset (end < start); that must not pass.
        status = "fail"
        if slashed["delta"]:
            slashed["status"] = "fail"
        if blocked["delta"]:
            blocked["status"] = "fail"
    else:
        status = "pass"
    return {
        "status": status,
        "slashed_total": slashed,
        "blocked": blocked,
        "unavailable": unavailable,
    }


def eval_ptc(start: dict[str, Any] | None, end: dict[str, Any]) -> dict[str, Any]:
    sc = scorecard()
    missing = [
        name
        for name in (sc.PTC_DUTIES, sc.PTC_ATTESTATIONS)
        if name not in end
    ]
    if missing:
        return {
            "status": "unavailable",
            "ptc_rate": None,
            "threshold": sc.PTC_RATE_MIN,
            "unavailable": missing,
        }
    try:
        if start is not None and sc.PTC_DUTIES in start and sc.PTC_ATTESTATIONS in start:
            success = _series_sum(
                end, sc.PTC_ATTESTATIONS, {"status": "success"}
            ) - (
                _series_sum(start, sc.PTC_ATTESTATIONS, {"status": "success"}) or 0.0
            )
            scheduled = _series_sum(
                end, sc.PTC_DUTIES, {"outcome": "scheduled"}
            ) - (
                _series_sum(start, sc.PTC_DUTIES, {"outcome": "scheduled"}) or 0.0
            )
            skipped = _series_sum(
                end, sc.PTC_DUTIES, {"outcome": "skipped_no_data"}
            ) - (
                _series_sum(start, sc.PTC_DUTIES, {"outcome": "skipped_no_data"})
                or 0.0
            )
            if scheduled == 0:
                rate = 1.0 if skipped > 0 else None
            else:
                rate = success / scheduled
        else:
            try:
                rate = sc.ptc_rate(end)
            except sc.ScorecardError as exc:
                if "scheduled=0" in str(exc):
                    rate = None
                else:
                    raise SnapshotError(str(exc)) from exc
    except sc.ScorecardError as exc:
        raise SnapshotError(str(exc)) from exc
    if rate is None:
        status = "pass"
    elif not math.isfinite(rate):
        raise SnapshotError(f"invalid ptc_rate: {rate}")
    elif rate < sc.PTC_RATE_MIN:
        status = "fail"
    else:
        status = "pass"
    return {
        "status": status,
        "ptc_rate": rate,
        "threshold": sc.PTC_RATE_MIN,
        "unavailable": [],
    }


def eval_bn(end: dict[str, Any]) -> dict[str, Any]:
    family = end.get(BN_CAPABILITY)
    if family is None:
        return {
            "status": "unavailable",
            "incapable": [],
            "unavailable": [BN_CAPABILITY],
        }
    incapable: list[dict[str, str]] = []
    for sample in family.samples:
        if not math.isfinite(sample.value):
            raise SnapshotError(
                f"invalid {BN_CAPABILITY} value: {sample.value}"
            )
        if sample.value == 0:
            incapable.append(dict(sample.labels))
    return {
        "status": "fail" if incapable else "pass",
        "incapable": incapable,
        "unavailable": [],
    }


def eval_signer(
    start: dict[str, Any] | None, end: dict[str, Any]
) -> dict[str, Any]:
    family = end.get(SIGNER_REJECTIONS)
    if family is None:
        return {
            "status": "unavailable",
            "delta": None,
            "unavailable": [SIGNER_REJECTIONS],
        }
    end_total = 0.0
    for sample in family.samples:
        if not math.isfinite(sample.value) or sample.value < 0:
            raise SnapshotError(
                f"invalid {SIGNER_REJECTIONS} value: {sample.value}"
            )
        end_total += sample.value
    start_total = 0.0
    if start is not None and SIGNER_REJECTIONS in start:
        for sample in start[SIGNER_REJECTIONS].samples:
            if not math.isfinite(sample.value) or sample.value < 0:
                raise SnapshotError(
                    f"invalid {SIGNER_REJECTIONS} value: {sample.value}"
                )
            start_total += sample.value
    delta = end_total - start_total
    return {
        "status": "fail" if delta > 0 else "pass",
        "delta": delta,
        "unavailable": [],
    }


def eval_target_rate(perf: dict[str, Any]) -> dict[str, Any]:
    code = perf.get("exit_code")
    agg = perf.get("aggregate") if isinstance(perf.get("aggregate"), dict) else {}
    rate = agg.get("target_rate") if isinstance(agg, dict) else None
    breaches = perf.get("threshold_breaches") or []
    failed = code == EXIT_THRESHOLD or bool(breaches)
    if isinstance(rate, (int, float)) and math.isfinite(rate) and rate < TARGET_RATE_MIN:
        failed = True
    return {
        "status": "fail" if failed else "pass",
        "target_rate": rate,
        "threshold": TARGET_RATE_MIN,
        "exit_code": code,
        "unavailable": [],
    }


def _family_json(family: Any) -> dict[str, Any]:
    return {
        "name": family.name,
        "type": family.type,
        "samples": [
            {"labels": dict(sample.labels), "value": sample.value}
            for sample in family.samples
        ],
    }


def evaluate(
    start: dict[str, Any] | None,
    end: dict[str, Any],
    perf: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    gates = {
        GATE_ZERO_SLASHING: eval_zero_slashing(start, end),
        GATE_PTC: eval_ptc(start, end),
        GATE_BN: eval_bn(end),
        GATE_SIGNER: eval_signer(start, end),
        GATE_TARGET_RATE: eval_target_rate(perf),
    }
    failed = tuple(
        name for name, gate in gates.items() if gate["status"] == "fail"
    )
    unavailable: list[str] = []
    seen: set[str] = set()
    for gate in gates.values():
        for item in gate.get("unavailable") or []:
            if item not in seen:
                seen.add(item)
                unavailable.append(item)
    for name in SIX_FAMILIES:
        if name not in end and name not in seen:
            seen.add(name)
            unavailable.append(name)
    blocking_unavail = tuple(
        name
        for name, gate in gates.items()
        if gate["status"] == "unavailable" and name in BLOCKING_GATES
    )
    if failed:
        verdict = "fail"
        exit_code = EXIT_THRESHOLD
    elif blocking_unavail:
        verdict = "unavailable"
        exit_code = EXIT_ERROR
    else:
        verdict = "pass"
        exit_code = EXIT_OK
    families = {name: _family_json(end[name]) for name in sorted(end)}
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "verdict": verdict,
        "exit_code": exit_code,
        "gates": gates,
        "failed_gates": list(failed),
        "unavailable": unavailable,
        "families": families,
        "validator_perf": perf,
    }


# ===== § 6. main =====


def _generated_at() -> datetime:
    return datetime.now(timezone.utc)


def main(argv: list[str] | None = None) -> int:
    log = Log(0, sys.stderr)
    try:
        opts = build_options(argv)
        log = Log(opts.verbosity, sys.stderr)
        out_dir = resolve_out_dir(opts.out_dir)
        if opts.metrics_url:
            text = fetch_metrics_text(opts.metrics_url)
            try:
                end = parse_selected(text)
            except scorecard().ScorecardError as exc:
                raise SnapshotError(str(exc)) from exc
        else:
            assert opts.metrics is not None
            end = load_metrics_file(opts.metrics)
        start = (
            load_metrics_file(opts.metrics_start) if opts.metrics_start else None
        )
        if opts.perf_json:
            perf = load_perf_json(opts.perf_json)
        else:
            perf = run_validator_perf(opts.perf_argv)
        now = _generated_at()
        generated_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        doc = evaluate(start, end, perf, generated_at)
        filename = f"gloas-soak-{now.strftime('%Y-%m-%d')}.json"
        dest = os.path.join(out_dir, filename)
        payload = json.dumps(doc, sort_keys=True) + "\n"
        _write_text(dest, payload)
        if opts.as_json:
            print(payload, end="")
        else:
            print(f"verdict {doc['verdict']}")
            print(f"wrote {dest}")
        if doc["failed_gates"]:
            for name in doc["failed_gates"]:
                log.error("gate: %s", name)
        elif doc["verdict"] == "unavailable":
            for name in doc["unavailable"]:
                log.error("unavailable: %s", name)
        return int(doc["exit_code"])
    except UsageError as exc:
        log.error("%s", exc)
        return EXIT_USAGE
    except SnapshotError as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except Exception as exc:
        log.error("%s", exc)
        return EXIT_ERROR


# Load 7.6b's parse_metrics once at import (sys.dont_write_bytecode is on).
scorecard()


if __name__ == "__main__":
    sys.exit(main())
