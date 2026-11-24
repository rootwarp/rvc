"""Tests for scripts/check_lock_only_advisories.py.

The Scripts job has no Rust toolchain, so these tests give the check a fake
`cargo tree` result. The Check job runs the check against the real graph.
"""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

from conftest import load_script

ROOT = Path(__file__).resolve().parents[2]
CHECK_RUN = "python3 scripts/check_lock_only_advisories.py"
DENY_RUN = "cargo deny check advisories sources"

CLEAN_GRAPH = """\
rvc v0.9.0 (/work/crates/rvc)
url v2.5.9
serde_with v3.17.0
vsss-rs v5.3.0
"""


@pytest.fixture(scope="module")
def check():
    return load_script("check_lock_only_advisories")


def _fake_run(stdout: str, returncode: int = 0, stderr: str = ""):
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, returncode, stdout, stderr)

    run.calls = calls
    return run


def test_clean_graph_passes_with_the_ci_cargo_tree_command(check, capsys):
    run = _fake_run(CLEAN_GRAPH)
    assert check.main(run=run) == 0
    args, kwargs = run.calls[0]
    assert args[:2] == ("cargo", "tree")
    for flag in ("--locked", "--workspace", "--all-features"):
        assert flag in args
    assert args[args.index("--target") + 1] == "all"
    assert set(args[args.index("-e") + 1].split(",")) == {"normal", "build", "dev"}
    assert kwargs["cwd"] == check.ROOT
    assert "not in the build graph" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("line", "crate", "advisory"),
    [
        ("heapless v0.8.0", "heapless 0.8.0", "RUSTSEC-2026-0574"),
        ("heapless v0.9.3 (*)", "heapless 0.9.3", "RUSTSEC-2026-0582"),
        ("heapless v0.9.4-rc.1", "heapless 0.9.4-rc.1", "RUSTSEC-2026-0574"),
        ("chrono v0.4.44", "chrono 0.4.44", "RUSTSEC-2026-0543"),
        ("chrono v0.4.45", "chrono 0.4.45", "RUSTSEC-2026-0543"),
        ("derivative v2.2.0", "derivative 2.2.0", "RUSTSEC-2024-0388"),
    ],
)
def test_affected_crate_in_the_graph_fails_and_names_the_crate(check, capsys, line, crate, advisory):
    assert check.main(run=_fake_run(CLEAN_GRAPH + line + "\n")) == 1
    err = capsys.readouterr().err
    assert crate in err
    assert advisory in err


@pytest.mark.parametrize("version", ["0.9.4", "0.9.4+build.1", "0.9.5-rc.1", "0.10.0"])
def test_fixed_heapless_version_passes(check, version):
    assert check.main(run=_fake_run(CLEAN_GRAPH + f"heapless v{version}\n")) == 0


@pytest.mark.parametrize(
    "lower, higher",
    [
        ("0.9.4-alpha", "0.9.4-alpha.1"),
        ("0.9.4-alpha.1", "0.9.4-alpha.beta"),
        ("0.9.4-alpha.beta", "0.9.4-beta"),
        ("0.9.4-beta.2", "0.9.4-beta.11"),
        ("0.9.4-rc.1", "0.9.4"),
        ("0.9.3", "0.9.4-rc.1"),
    ],
)
def test_semver_key_follows_semver_precedence(check, lower, higher):
    assert check.semver_key(lower) < check.semver_key(higher)


def test_cargo_tree_failure_fails_the_check(check, capsys):
    run = _fake_run("", returncode=101, stderr="error: cannot update the lock file")
    assert check.main(run=run) == 2
    assert "cannot update the lock file" in capsys.readouterr().err


def test_empty_graph_fails_the_check(check):
    assert check.main(run=_fake_run("")) == 2


def _ignore_ids(path: Path) -> set[str]:
    entries = tomllib.loads(path.read_text())["advisories"]["ignore"]
    return {entry if isinstance(entry, str) else entry["id"] for entry in entries}


@pytest.mark.parametrize("path", [ROOT / ".cargo" / "audit.toml", ROOT / "deny.toml"])
def test_every_checked_advisory_is_ignored(check, path):
    checked = {a for rule in check.LOCK_ONLY_IGNORES for a in rule.advisories}
    assert checked <= _ignore_ids(path)


def test_check_job_runs_the_check_after_cargo_deny():
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text())
    steps = workflow["jobs"]["check"]["steps"]
    runs = [step.get("run", "").strip() for step in steps]
    assert CHECK_RUN in runs, "the Check job does not run the lock-only advisory check"
    assert runs.index(CHECK_RUN) > runs.index(DENY_RUN)
    step = steps[runs.index(CHECK_RUN)]
    assert "if" not in step and "continue-on-error" not in step
