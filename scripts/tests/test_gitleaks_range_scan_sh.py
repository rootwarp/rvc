"""Tests for scripts/gitleaks_range_scan.sh.

A stub records the gitleaks arguments. Other tests run ``fake_gitleaks.py``,
which reads ``git log -p`` output the way gitleaks 8.21.2 does. Each test
repository is a temporary git repository with real commits.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "gitleaks_range_scan.sh"
ZERO = "0" * 40
STUB = """#!/usr/bin/env bash
printf '%s\\n' "$@" > "$FAKE_ARGS"
printf '%b' "${FAKE_STDERR:-}" >&2
exit "${FAKE_EXIT:-0}"
"""
GIT_ENV = {
    "GIT_AUTHOR_NAME": "t",
    "GIT_AUTHOR_EMAIL": "t@example.invalid",
    "GIT_COMMITTER_NAME": "t",
    "GIT_COMMITTER_EMAIL": "t@example.invalid",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
}
FULL_HISTORY = "--log-opts=-m --text --all --full-history"


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, **GIT_ENV},
    )
    return proc.stdout.strip()


def _commit(repo: Path, message: str, files: dict[str, str] | None = None) -> str:
    for rel, text in (files or {}).items():
        (repo / rel).write_text(text, encoding="utf-8")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _token() -> str:
    return "k7Qm9pL2xV8n" + "R4wT6yH3cB5d" + "F1aE0sZ"


def _key_line() -> str:
    return f'let api_key = "{_token()}";\n'


@pytest.fixture
def repo(tmp_path: Path) -> dict[str, str | Path]:
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q", "-b", "main")
    base = _commit(path, "base")
    _git(path, "checkout", "-q", "-b", "side")
    side = _commit(path, "side")
    _git(path, "checkout", "-q", "main")
    _commit(path, "head")
    return {"path": path, "base": base, "side": side}


def _run(cwd: Path, gitleaks: Path, config: str, base: str, *extra: str, **env: str):
    proc = subprocess.run(
        [str(SCRIPT), config, base, *extra],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, **GIT_ENV, "GITLEAKS_BIN": str(gitleaks), **env},
    )
    return proc


def _stub_run(repo_path: Path, tmp_path: Path, base: str, *extra: str, **env: str):
    stub = tmp_path / "gitleaks-stub"
    stub.write_text(STUB, encoding="utf-8")
    stub.chmod(0o755)
    args_file = tmp_path / "args.txt"
    proc = _run(repo_path, stub, "/abs/strict.toml", base, *extra, FAKE_ARGS=str(args_file), **env)
    args = args_file.read_text(encoding="utf-8").splitlines() if args_file.exists() else None
    return proc, args


COMMON = [
    "--config",
    "/abs/strict.toml",
    "--ignore-gitleaks-allow",
    "--redact",
    "--no-banner",
    "--exit-code",
    "1",
]


def test_ancestor_base_scans_the_range_with_merge_diffs_and_text(repo, tmp_path):
    proc, args = _stub_run(repo["path"], tmp_path, repo["base"])
    assert proc.returncode == 0, proc.stderr
    assert args == [
        "detect",
        "--source",
        ".",
        f"--log-opts=-m --text {repo['base']}..HEAD",
        *COMMON,
    ]


def test_force_pushed_base_scans_from_the_merge_base(repo, tmp_path):
    proc, args = _stub_run(repo["path"], tmp_path, repo["side"])
    assert proc.returncode == 0, proc.stderr
    assert args[3] == f"--log-opts=-m --text {repo['base']}..HEAD"


@pytest.mark.parametrize("base", [ZERO, "1234567" * 5 + "89abc", "--history"])
def test_missing_base_or_history_mode_scans_all_history_in_git_mode(repo, tmp_path, base):
    proc, args = _stub_run(repo["path"], tmp_path, base)
    assert proc.returncode == 0, proc.stderr
    assert args == ["detect", "--source", ".", FULL_HISTORY, *COMMON]
    assert "--no-git" not in args


def test_unrelated_history_scans_all_history(repo, tmp_path):
    other = tmp_path / "other"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    orphan = _commit(other, "orphan")
    _git(repo["path"], "fetch", "-q", str(other), "main")
    proc, args = _stub_run(repo["path"], tmp_path, orphan)
    assert proc.returncode == 0, proc.stderr
    assert args[3] == FULL_HISTORY


def test_gitleaks_exit_code_is_the_script_exit_code(repo, tmp_path):
    proc, _ = _stub_run(repo["path"], tmp_path, repo["base"], FAKE_EXIT="1")
    assert proc.returncode == 1
    proc, _ = _stub_run(repo["path"], tmp_path, "--history", FAKE_EXIT="3")
    assert proc.returncode == 3


@pytest.mark.parametrize(
    "stderr",
    [
        "ERR failed to scan Git repository\\nINF no leaks found\\n",
        "ERR [git] fatal: bad revision\\nINF no leaks found\\n",
    ],
    ids=["failed-to-scan", "git-prefix"],
)
def test_a_git_error_fails_the_scan_even_when_gitleaks_exits_0(repo, tmp_path, stderr):
    proc, _ = _stub_run(repo["path"], tmp_path, repo["base"], FAKE_STDERR=stderr)
    assert proc.returncode == 1
    assert "no leaks found" in proc.stderr
    assert "gitleaks did not read the whole git log" in proc.stderr


def test_extra_arguments_go_to_gitleaks_after_the_common_flags(repo, tmp_path):
    extra = ("--report-format", "json", "--report-path", "/abs/report.json")
    _, args = _stub_run(repo["path"], tmp_path, repo["base"], *extra)
    assert args[-4:] == list(extra)
    _, args = _stub_run(repo["path"], tmp_path, "--history", *extra)
    assert args[-4:] == list(extra)


@pytest.mark.parametrize("base", ["", "HEAD~1", "--all", "abc..HEAD"])
def test_base_that_is_not_a_full_sha_is_rejected(repo, tmp_path, base):
    proc, args = _stub_run(repo["path"], tmp_path, base)
    assert proc.returncode == 2
    assert args is None


def test_missing_arguments_are_a_usage_error(repo, tmp_path):
    proc = subprocess.run([str(SCRIPT), "/abs/strict.toml"], cwd=repo["path"], check=False)
    assert proc.returncode == 2


def test_secret_added_only_by_a_merge_resolution_is_found(
    repo, fake_gitleaks, strict_gitleaks_config
):
    path = repo["path"]
    _git(path, "merge", "-q", "--no-ff", "--no-commit", "side")
    _commit(path, "merge", {"merge.rs": _key_line()})
    proc = _run(path, fake_gitleaks, str(strict_gitleaks_config), repo["base"])
    assert proc.returncode == 1, proc.stderr


def test_secret_in_a_file_that_gitattributes_marks_binary_is_found(
    repo, fake_gitleaks, strict_gitleaks_config
):
    path = repo["path"]
    _commit(path, "hide", {".gitattributes": "*.rs -diff\n", "hidden.rs": _key_line()})
    proc = _run(path, fake_gitleaks, str(strict_gitleaks_config), repo["base"])
    assert proc.returncode == 1, proc.stderr


@pytest.mark.parametrize("label", ["force-push", "new-branch"])
def test_pushed_commits_get_a_git_mode_scan_without_a_usable_range(
    repo, fake_gitleaks, strict_gitleaks_config, label
):
    path = repo["path"]
    _commit(path, "add", {"pushed.rs": _key_line()})
    _commit(path, "remove", {"pushed.rs": "\n"})
    base = repo["side"] if label == "force-push" else ZERO
    proc = _run(path, fake_gitleaks, str(strict_gitleaks_config), base)
    assert proc.returncode == 1, proc.stderr


def test_a_git_error_with_no_finding_fails_the_scan(repo, fake_gitleaks, strict_gitleaks_config):
    path = repo["path"]
    _git(path, "branch", repo["base"])
    proc = _run(path, fake_gitleaks, str(strict_gitleaks_config), repo["base"])
    assert "failed to scan Git repository" in proc.stderr
    assert "no leaks found" in proc.stderr
    assert proc.returncode == 1
