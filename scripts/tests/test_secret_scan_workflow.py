"""Structural gates for the gitleaks jobs in ci.yml and secret-history-scan.yml."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from test_workflow_hardening import action_name, iter_use_steps, load_workflow

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
CI = WORKFLOWS / "ci.yml"
HISTORY = WORKFLOWS / "secret-history-scan.yml"
AGENTS = ROOT / "AGENTS.md"

STRICT_BUILD = "python3 scripts/gitleaks_strict_config.py --out-dir"
INSTALL = "./scripts/install_gitleaks.sh"
STRICT_CONFIGS = {'"$RVC_GITLEAKS_CONFIG"', '"$RVC_GITLEAKS_EMITTED_CONFIG"'}
_CONFIG_ARG = re.compile(r"--config\s+(\S+)")


def _load(path: Path) -> dict:
    return load_workflow(path.read_text(encoding="utf-8"))


def _job(path: Path, name: str) -> dict:
    return _load(path)["jobs"][name]


def _runs(job: dict) -> list[str]:
    return [step.get("run", "") for step in job["steps"]]


def _index(job: dict, needle: str) -> int:
    for index, run in enumerate(_runs(job)):
        if needle in run:
            return index
    raise AssertionError(f"no step runs {needle!r}")


def _checkout(job: dict) -> dict:
    steps = [step for step in iter_use_steps(job) if action_name(step["uses"]) == "actions/checkout"]
    assert len(steps) == 1
    return steps[0].get("with") or {}


GITLEAKS_JOBS = {"ci": (CI, "secret-scan"), "history": (HISTORY, "history-scan")}


def _gitleaks_job(label: str) -> dict:
    return _job(*GITLEAKS_JOBS[label])


def test_secret_scan_runs_on_pull_requests_and_on_pushes_to_develop_and_main():
    triggers = _load(CI)["on"]
    assert set(triggers["pull_request"]["branches"]) == {"develop", "main"}
    assert set(triggers["push"]["branches"]) == {"develop", "main"}
    assert "if" not in _job(CI, "secret-scan")


@pytest.mark.parametrize("label", GITLEAKS_JOBS)
def test_gitleaks_jobs_check_out_full_history_without_credentials(label):
    job = _gitleaks_job(label)
    with_ = _checkout(job)
    assert with_.get("fetch-depth") == 0, label
    assert with_.get("persist-credentials") is False, label
    assert "filter" not in with_, label
    assert "sparse-checkout" not in with_, label


@pytest.mark.parametrize("label", GITLEAKS_JOBS)
def test_every_gitleaks_scan_uses_a_strict_config_built_first(label):
    job = _gitleaks_job(label)
    install = _index(job, INSTALL)
    build = _index(job, STRICT_BUILD)
    assert install < build, label
    scans = 0
    for index, run in enumerate(_runs(job)):
        if "gitleaks detect" not in run and "gitleaks_range_scan.sh" not in run:
            continue
        scans += 1
        assert index > build, (label, run)
        configs = set(_CONFIG_ARG.findall(run))
        if "gitleaks_range_scan.sh" in run:
            configs.add(run.split("gitleaks_range_scan.sh", 1)[1].split()[0])
        assert configs, (label, run)
        assert configs <= STRICT_CONFIGS | {'"$RUNNER_TEMP/gitleaks/gitleaks.toml"'}, (label, run)
    assert scans >= 1, label


@pytest.mark.parametrize("label", GITLEAKS_JOBS)
def test_no_gitleaks_run_step_expands_event_data_inline(label):
    job = _gitleaks_job(label)
    for run in _runs(job):
        assert "${{" not in run, (label, run)


def test_secret_scan_scans_the_pull_request_or_push_range_in_git_mode():
    job = _job(CI, "secret-scan")
    steps = [step for step in job["steps"] if "gitleaks_range_scan.sh" in step.get("run", "")]
    assert len(steps) == 1
    step = steps[0]
    assert step["run"].strip() == (
        './scripts/gitleaks_range_scan.sh "$RVC_GITLEAKS_CONFIG" "$RANGE_BASE"'
    )
    base = step["env"]["RANGE_BASE"]
    assert "github.event.pull_request.base.sha" in base
    assert "github.event.before" in base


def test_secret_scan_runs_every_canary_against_the_strict_config():
    job = _job(CI, "secret-scan")
    build = _index(job, STRICT_BUILD)
    for script in (
        "gitleaks_verify_false_canary.sh",
        "gitleaks_line_shift_canary.py",
        "gitleaks_scope_canary.py",
    ):
        assert _index(job, script) > build, script
    build_run = _runs(job)[build]
    assert 'RVC_GITLEAKS_CONFIG=$RUNNER_TEMP/gitleaks/gitleaks.toml' in build_run
    assert 'RVC_GITLEAKS_EMITTED_CONFIG=$RUNNER_TEMP/gitleaks/gitleaks-emitted.toml' in build_run
    assert "GITHUB_ENV" in build_run


def test_secret_scan_runs_the_gitleaks_architecture_gate_with_gitleaks_required():
    job = _job(CI, "secret-scan")
    steps = [step for step in job["steps"] if "--test gitleaks_allow_scope" in step.get("run", "")]
    assert len(steps) == 1
    step = steps[0]
    assert step["env"]["REQUIRE_GITLEAKS"] == "1"
    assert "-p rvc-architecture-tests" in step["run"]
    assert job["steps"].index(step) > _index(job, INSTALL)


def test_history_scan_is_weekly_and_manual_only():
    doc = _load(HISTORY)
    triggers = doc["on"]
    assert set(triggers) == {"schedule", "workflow_dispatch"}
    assert len(triggers["schedule"]) == 1
    _minute, _hour, day, month, weekday = triggers["schedule"][0]["cron"].split()
    assert (day, month) == ("*", "*") and weekday.isdigit()
    assert doc["permissions"] == {"contents": "read"}
    assert "permissions" not in doc["jobs"]["history-scan"]


def test_history_scan_reads_every_commit_with_the_develop_config_on_schedule():
    job = _job(HISTORY, "history-scan")
    assert _checkout(job)["ref"] == (
        "${{ github.event_name == 'schedule' && 'develop' || github.ref }}"
    )
    scans = [run for run in _runs(job) if "gitleaks" in run and "install" not in run]
    scans = [run for run in scans if "gitleaks_strict_config.py" not in run]
    # The script adds -m, --text, --all and --full-history, and fails on a git error.
    assert [run.strip() for run in scans] == [
        './scripts/gitleaks_range_scan.sh "$RUNNER_TEMP/gitleaks/gitleaks.toml" --history'
    ]


def test_gitleaks_is_installed_only_through_the_pinned_script():
    for path in sorted(WORKFLOWS.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert "gitleaks/releases/download" not in text, path.name
    for label in GITLEAKS_JOBS:
        job = _gitleaks_job(label)
        assert sum(INSTALL in run for run in _runs(job)) == 1, label


def test_agents_md_says_the_history_scan_needs_a_full_clone():
    line = next(
        line for line in AGENTS.read_text(encoding="utf-8").splitlines() if "History scan:" in line
    )
    assert "full clone" in line
    assert "blob:none" in line
    assert "secret-history-scan.yml" in line
