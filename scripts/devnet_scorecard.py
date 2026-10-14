#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Turn one devnet run into a pass/fail verdict against the phase thresholds."""

import argparse
import csv
import json
import math
import os
import re
import stat
import sys
from dataclasses import dataclass
from typing import TextIO

# ===== § 1. Header, constants, exit codes =====

SCHEMA_VERSION = 1
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2
EXIT_THRESHOLD = 4

EFFECTIVENESS_MIN = 0.99
PTC_RATE_MIN = 0.99

PTC_DUTIES = "rvc_ptc_duties_total"
PTC_ATTESTATIONS = "rvc_ptc_attestations_total"
SLASHED_TOTAL = "rvc_validators_slashed_total"
SLASHING_CHECKS = "rvc_slashing_protection_checks_total"
REQUIRED_FAMILIES = (
    PTC_DUTIES,
    PTC_ATTESTATIONS,
    SLASHED_TOTAL,
    SLASHING_CHECKS,
)

# ===== § 2. Errors and diagnostics =====


class UsageError(Exception):
    pass


class ScorecardError(Exception):
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


# ===== § 3. Prometheus scrape =====

_TYPE_RE = re.compile(r"^#\s*TYPE\s+([a-zA-Z_:][a-zA-Z0-9_:]*)\s+(\S+)\s*$")
_SAMPLE_RE = re.compile(
    r"^([a-zA-Z_:][a-zA-Z0-9_:]*)"
    r"(?:[ \t]*\{(.*)\})?"
    r"[ \t]+"
    r"(\S+)"
    r"(?:[ \t]+\S+)?"
    r"[ \t]*$"
)
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


def _snippet(text: str) -> str:
    if len(text) <= _ERROR_SNIPPET:
        return text
    return f"{text[:_ERROR_SNIPPET]}..."


def _unescape(raw: str) -> str:
    return raw.replace("\\\\", "\\").replace('\\"', '"').replace("\\n", "\n")


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
        start = i
        if not (("A" <= raw[i] <= "Z") or ("a" <= raw[i] <= "z") or raw[i] == "_"):
            raise ScorecardError(f"invalid prometheus labels: {_snippet(raw)}")
        i += 1
        while i < n and (
            ("A" <= raw[i] <= "Z")
            or ("a" <= raw[i] <= "z")
            or ("0" <= raw[i] <= "9")
            or raw[i] == "_"
        ):
            i += 1
        name = raw[start:i]
        if i >= n or raw[i] != "=":
            raise ScorecardError(f"invalid prometheus labels: {_snippet(raw)}")
        i += 1
        if i >= n or raw[i] != '"':
            raise ScorecardError(f"invalid prometheus labels: {_snippet(raw)}")
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
            raise ScorecardError("unclosed label value")
        encoded = raw[val_start:i]
        if len(encoded.encode("utf-8")) > _MAX_LABEL_VALUE_BYTES:
            raise ScorecardError("label value exceeded cap")
        labels[name] = _unescape(encoded)
        i += 1
        while i < n and raw[i] in " \t":
            i += 1
        if i >= n:
            return labels
        if raw[i] != ",":
            raise ScorecardError(f"invalid prometheus labels: {_snippet(raw)}")
        i += 1


def parse_metrics(text: str) -> dict[str, Family]:
    """Parse Prometheus text exposition 0.0.4 into families by name."""
    if len(text) > MAX_RESPONSE_BYTES:
        raise ScorecardError("metrics text exceeded MAX_RESPONSE_BYTES")
    families: dict[str, Family] = {}
    n_samples = 0
    for line in text.splitlines():
        if len(line) > _MAX_METRIC_LINE:
            raise ScorecardError("metrics line exceeded cap")
        stripped = line.strip()
        if not stripped:
            continue
        match = _TYPE_RE.match(stripped)
        if match is not None:
            name, typ = match.group(1), match.group(2)
            family = families.get(name)
            if family is None:
                families[name] = Family(name=name, type=typ, samples=[])
            else:
                family.type = typ
            continue
        if stripped.startswith("#"):
            continue
        match = _SAMPLE_RE.match(stripped)
        if match is None:
            raise ScorecardError(f"invalid prometheus sample: {_snippet(stripped)}")
        sample_name, raw_labels, raw_value = (
            match.group(1),
            match.group(2),
            match.group(3),
        )
        try:
            labels = _parse_labels(raw_labels or "")
        except ScorecardError as exc:
            raise ScorecardError(
                f"invalid prometheus labels: {_snippet(stripped)}"
            ) from exc
        try:
            value = float(raw_value)
        except ValueError as exc:
            raise ScorecardError(
                f"invalid prometheus value: {_snippet(raw_value)}"
            ) from exc
        n_samples += 1
        if n_samples > _MAX_METRIC_SAMPLES:
            raise ScorecardError("metrics sample count exceeded cap")
        family = families.get(sample_name)
        if family is None:
            family = Family(name=sample_name, type="untyped", samples=[])
            families[sample_name] = family
        family.samples.append(
            Sample(labels=labels, value=value, name=sample_name)
        )
    return families


def sample_sum(
    families: dict[str, Family], name: str, labels: dict[str, str] | None = None
) -> float:
    family = families.get(name)
    if family is None:
        return 0.0
    want = labels or {}
    total = 0.0
    found = False
    for sample in family.samples:
        if sample.labels == want:
            if not math.isfinite(sample.value) or sample.value < 0:
                raise ScorecardError(f"invalid {name} value: {sample.value}")
            total += sample.value
            found = True
    return total if found else 0.0


def missing_required_families(families: dict[str, Family]) -> list[str]:
    return [name for name in REQUIRED_FAMILIES if name not in families]


# ===== § 4. CSV =====


def _refuse_non_regular(st: os.stat_result, path: str) -> None:
    if stat.S_ISLNK(st.st_mode):
        raise ScorecardError(f"{path} is a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise ScorecardError(f"{path} is not a regular file")


def _read_text(path: str) -> str:
    dest = os.fspath(path)
    try:
        st = os.lstat(dest)
    except FileNotFoundError as e:
        raise UsageError(f"{dest}: {e.strerror}") from e
    except OSError as e:
        raise UsageError(f"{dest}: {e.strerror}") from e
    _refuse_non_regular(st, dest)
    if st.st_size > MAX_RESPONSE_BYTES:
        raise ScorecardError(f"{dest}: exceeded MAX_RESPONSE_BYTES")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        fd = os.open(dest, flags)
    except OSError as e:
        raise ScorecardError(f"{dest}: {e.strerror}") from e
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode):
            raise ScorecardError(f"{dest} is not a regular file")
        if opened.st_size > MAX_RESPONSE_BYTES:
            raise ScorecardError(f"{dest}: exceeded MAX_RESPONSE_BYTES")
        data = os.read(fd, MAX_RESPONSE_BYTES + 1)
    except OSError as e:
        raise ScorecardError(f"{dest}: {e.strerror}") from e
    finally:
        os.close(fd)
    if len(data) > MAX_RESPONSE_BYTES:
        raise ScorecardError(f"{dest}: exceeded MAX_RESPONSE_BYTES")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ScorecardError(f"{dest}: not valid UTF-8") from e


def _parse_number(raw: object, field: str) -> float | None:
    if raw is None:
        return None
    text = str(raw).strip()
    if text == "":
        return None
    try:
        value = float(text)
    except ValueError as exc:
        raise ScorecardError(f"invalid {field}: {raw!r}") from exc
    if not math.isfinite(value):
        raise ScorecardError(f"invalid {field}: {raw!r}")
    return value


def load_csv(path: str) -> list[dict[str, str]]:
    text = _read_text(path)
    reader = csv.DictReader(text.splitlines())
    if reader.fieldnames is None:
        raise ScorecardError(f"{path}: empty CSV")
    missing = [
        col
        for col in ("attester_effectiveness", "proposals.missed")
        if col not in reader.fieldnames
    ]
    if missing:
        raise ScorecardError(f"{path}: missing column {missing[0]}")
    return list(reader)


def attester_effectiveness(rows: list[dict[str, str]]) -> float:
    values: list[float] = []
    weights: list[float] = []
    for row in rows:
        value = _parse_number(
            row.get("attester_effectiveness"), "attester_effectiveness"
        )
        if value is None:
            continue
        if value < 0:
            raise ScorecardError(f"invalid attester_effectiveness: {value}")
        weight = _parse_number(row.get("active_epochs"), "active_epochs")
        if weight is not None and weight < 0:
            raise ScorecardError(f"invalid active_epochs: {weight}")
        values.append(value)
        weights.append(1.0 if weight is None else weight)
    if not values:
        raise ScorecardError("no attester_effectiveness values")
    total_w = sum(weights)
    if total_w == 0:
        return sum(values) / len(values)
    return sum(v * w for v, w in zip(values, weights)) / total_w


def missed_proposals(rows: list[dict[str, str]]) -> float:
    total = 0.0
    found = False
    for row in rows:
        value = _parse_number(row.get("proposals.missed"), "proposals.missed")
        if value is None:
            continue
        if value < 0:
            raise ScorecardError(f"invalid proposals.missed: {value}")
        total += value
        found = True
    if not found:
        raise ScorecardError("no proposals.missed values")
    return total


# ===== § 5. CLI =====


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise UsageError(message)


def build_parser() -> argparse.ArgumentParser:
    p = _ArgumentParser(
        description=(
            "Score one devnet run against the phase thresholds: "
            "attester effectiveness ≥ 99%, PTC submission ≥ 99%, "
            "0 missed proposals, 0 slashable events."
        ),
    )
    p.add_argument("--metrics", metavar="PATH")
    p.add_argument("--csv", metavar="PATH")
    p.add_argument("--json", action="store_true")
    p.add_argument("-v", action="count", default=0, dest="verbose")
    p.add_argument("-q", action="store_true", dest="quiet")
    return p


@dataclass(frozen=True)
class Options:
    metrics: str
    csv: str
    as_json: bool
    verbosity: int


def build_options(argv: list[str] | None = None) -> Options:
    args = build_parser().parse_args(argv)
    if args.quiet and args.verbose:
        raise UsageError("-v and -q are mutually exclusive")
    if not args.metrics:
        raise UsageError("--metrics is required")
    if not args.csv:
        raise UsageError("--csv is required")
    return Options(
        metrics=args.metrics,
        csv=args.csv,
        as_json=bool(args.json),
        verbosity=-1 if args.quiet else args.verbose,
    )


# ===== § 6. Scorecard =====


@dataclass(frozen=True)
class Scorecard:
    attester_effectiveness: float
    ptc_rate: float
    missed_proposals: float
    slashable_events: float
    breaches: tuple[str, ...]

    @property
    def verdict(self) -> str:
        return "pass" if not self.breaches else "fail"


def ptc_rate(families: dict[str, Family]) -> float:
    # success / scheduled. skipped_no_data (HTTP 204) is never a failure.
    success = sample_sum(families, PTC_ATTESTATIONS, {"status": "success"})
    scheduled = sample_sum(families, PTC_DUTIES, {"outcome": "scheduled"})
    if scheduled == 0:
        skipped = sample_sum(
            families, PTC_DUTIES, {"outcome": "skipped_no_data"}
        )
        if skipped > 0:
            return 1.0
        raise ScorecardError("ptc_rate undefined: scheduled=0")
    return success / scheduled


def slashable_events(families: dict[str, Family]) -> float:
    slashed = sample_sum(families, SLASHED_TOTAL, {})
    blocked = sample_sum(families, SLASHING_CHECKS, {"result": "blocked"})
    return slashed + blocked


def evaluate(families: dict[str, Family], rows: list[dict[str, str]]) -> Scorecard:
    missing = missing_required_families(families)
    if missing:
        raise ScorecardError("missing metric: " + ", ".join(missing))
    effectiveness = attester_effectiveness(rows)
    rate = ptc_rate(families)
    missed = missed_proposals(rows)
    slashable = slashable_events(families)
    breaches: list[str] = []
    if effectiveness < EFFECTIVENESS_MIN:
        breaches.append("attester_effectiveness")
    if rate < PTC_RATE_MIN:
        breaches.append("ptc_rate")
    if missed > 0:
        breaches.append("missed_proposals")
    if slashable > 0:
        breaches.append("slashable_events")
    return Scorecard(
        attester_effectiveness=effectiveness,
        ptc_rate=rate,
        missed_proposals=missed,
        slashable_events=slashable,
        breaches=tuple(breaches),
    )


def _fmt(value: float) -> str:
    return format(value, ".15g")


def render_text(card: Scorecard, stream: TextIO) -> None:
    print(f"verdict {card.verdict}", file=stream)
    print(f"attester_effectiveness {_fmt(card.attester_effectiveness)}", file=stream)
    print(f"ptc_rate {_fmt(card.ptc_rate)}", file=stream)
    print(f"missed_proposals {_fmt(card.missed_proposals)}", file=stream)
    print(f"slashable_events {_fmt(card.slashable_events)}", file=stream)


def render_json(card: Scorecard, exit_code: int) -> str:
    return json.dumps(
        {
            "schema_version": SCHEMA_VERSION,
            "verdict": card.verdict,
            "attester_effectiveness": card.attester_effectiveness,
            "ptc_rate": card.ptc_rate,
            "missed_proposals": card.missed_proposals,
            "slashable_events": card.slashable_events,
            "breaches": list(card.breaches),
            "exit_code": exit_code,
        },
        sort_keys=True,
    )


# ===== § 7. main =====


def main(argv: list[str] | None = None) -> int:
    log = Log(0, sys.stderr)
    try:
        opts = build_options(argv)
        log = Log(opts.verbosity, sys.stderr)
        families = parse_metrics(_read_text(opts.metrics))
        rows = load_csv(opts.csv)
        card = evaluate(families, rows)
        code = EXIT_OK if not card.breaches else EXIT_THRESHOLD
        if opts.as_json:
            print(render_json(card, code))
        else:
            render_text(card, sys.stdout)
        if card.breaches:
            for name in card.breaches:
                log.error("threshold: %s", name)
        return code
    except UsageError as exc:
        log.error("%s", exc)
        return EXIT_USAGE
    except ScorecardError as exc:
        log.error("%s", exc)
        return EXIT_ERROR
    except Exception as exc:
        log.error("%s", exc)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
