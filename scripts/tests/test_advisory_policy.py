"""The RustSec ignore lists of cargo-audit and cargo-deny agree, and CI runs both."""

from __future__ import annotations

import re
import tomllib
from datetime import date
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
AUDIT_TOML = ROOT / ".cargo" / "audit.toml"
DENY_TOML = ROOT / "deny.toml"
CI_YML = ROOT / ".github" / "workflows" / "ci.yml"

DENY_RUN = "cargo deny check advisories sources"
CRATES_IO_INDEX = "https://github.com/rust-lang/crates.io-index"

_ADVISORY_ID_RE = re.compile(r"RUSTSEC-\d{4}-\d{4}")
_REVIEW_RE = re.compile(r"Review by (\S+?)\.?$")


def _entry_id(entry: str | dict) -> str:
    """cargo-deny and cargo-audit accept a bare ID or a table with an `id` key."""
    return entry if isinstance(entry, str) else entry["id"]


def _ignores(path: Path) -> list[str | dict]:
    return tomllib.loads(path.read_text())["advisories"]["ignore"]


def _ignore_ids(path: Path) -> list[str]:
    return [_entry_id(entry) for entry in _ignores(path)]


def _deny_config() -> dict:
    return tomllib.loads(DENY_TOML.read_text())


def test_deny_and_audit_ignore_the_same_advisories():
    audit_ids = _ignore_ids(AUDIT_TOML)
    deny_ids = _ignore_ids(DENY_TOML)
    assert len(set(audit_ids)) == len(audit_ids), "duplicate id in .cargo/audit.toml"
    assert len(set(deny_ids)) == len(deny_ids), "duplicate id in deny.toml"
    assert sorted(audit_ids) == sorted(deny_ids)


def test_every_deny_ignore_has_a_reason():
    missing = [
        _entry_id(entry)
        for entry in _ignores(DENY_TOML)
        if isinstance(entry, str) or not str(entry.get("reason", "")).strip()
    ]
    assert not missing, f"deny.toml ignores without a reason: {missing}"


def _review_date(path: Path, advisory_id: str) -> date:
    lines = path.read_text().splitlines()
    entry_lines = [
        i
        for i, line in enumerate(lines)
        if not line.lstrip().startswith("#") and f'"{advisory_id}"' in line
    ]
    assert len(entry_lines) == 1, f"{path.name}: {advisory_id} is not on exactly one line"
    index = entry_lines[0]
    others = set(_ADVISORY_ID_RE.findall(lines[index])) - {advisory_id}
    assert not others, f"{path.name}: line {index + 1} has more than one id: {others}"

    comment = []
    for line in reversed(lines[:index]):
        if not line.strip().startswith("#"):
            break
        comment.append(line.strip())
    review = next((m for line in comment if (m := _REVIEW_RE.search(line))), None)
    assert review is not None, f"{path.name}: {advisory_id} has no 'Review by <date>' comment"
    return date.fromisoformat(review.group(1))


def test_every_ignore_has_a_review_date_in_both_files():
    for path in (AUDIT_TOML, DENY_TOML):
        for advisory_id in _ignore_ids(path):
            _review_date(path, advisory_id)


def test_deny_fails_on_every_unsound_unmaintained_or_yanked_crate():
    advisories = _deny_config()["advisories"]
    assert advisories.get("unsound") == "all"
    assert advisories.get("unmaintained") == "all"
    assert advisories.get("yanked") == "deny"


def test_deny_allows_only_the_crates_io_registry():
    sources = _deny_config().get("sources", {})
    assert sources.get("unknown-registry") == "deny"
    assert sources.get("unknown-git") == "deny"
    assert sources.get("allow-registry") == [CRATES_IO_INDEX]
    assert not sources.get("allow-git"), "deny.toml allows a git source"


def _job_with_run(workflow: dict, command: str) -> tuple[list[dict], int]:
    for job in workflow["jobs"].values():
        steps = job.get("steps", [])
        index = next(
            (i for i, step in enumerate(steps) if step.get("run", "").strip() == command),
            None,
        )
        if index is not None:
            return steps, index
    raise AssertionError(f"no CI step runs `{command}`")


def test_ci_runs_cargo_deny_where_it_runs_cargo_audit():
    workflow = yaml.safe_load(CI_YML.read_text())
    audit_steps, audit_index = _job_with_run(workflow, "cargo audit")
    steps, deny_index = _job_with_run(workflow, DENY_RUN)
    assert steps is audit_steps, "cargo deny and cargo audit run in different jobs"
    audit_if = audit_steps[audit_index].get("if")
    assert steps[deny_index].get("if") == audit_if

    install_index = next(
        (
            i
            for i, step in enumerate(steps)
            if "uses" in step and step.get("with", {}).get("tool") == "cargo-deny"
        ),
        None,
    )
    assert install_index is not None, "the cargo deny job does not install cargo-deny"
    assert install_index < deny_index, "cargo-deny is installed after it runs"
    assert steps[install_index].get("if") == audit_if
