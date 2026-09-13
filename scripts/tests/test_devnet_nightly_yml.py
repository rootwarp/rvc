"""Contract tests for .github/workflows/devnet-nightly.yml (DN-16 / issue 6.5)."""

from __future__ import annotations

import re
from pathlib import Path

NIGHTLY = (
    Path(__file__).resolve().parents[2] / ".github" / "workflows" / "devnet-nightly.yml"
)
CI_YML = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"


def _on_block(text: str) -> str:
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line == "on:":
            start = i
            break
    assert start is not None, "missing top-level on:"
    buf: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line[0].isspace() and not line.startswith("#"):
            break
        buf.append(line)
    return "\n".join(buf)


def _jobs(text: str) -> dict[str, str]:
    lines = text.splitlines()
    i = 0
    while i < len(lines) and lines[i] != "jobs:":
        i += 1
    jobs: dict[str, str] = {}
    current: str | None = None
    buf: list[str] = []
    job_re = re.compile(r"^  ([A-Za-z0-9_-]+):\s*(#.*)?$")
    for line in lines[i + 1 :]:
        match = job_re.match(line)
        if match:
            if current is not None:
                jobs[current] = "\n".join(buf)
            current = match.group(1)
            buf = []
            continue
        if current is not None:
            buf.append(line)
    if current is not None:
        jobs[current] = "\n".join(buf)
    return jobs


def test_nightly_workflow_exists():
    assert NIGHTLY.is_file()
    text = NIGHTLY.read_text(encoding="utf-8")
    assert text.startswith("name: Devnet (nightly)\n")


def test_triggers_are_exactly_schedule_and_workflow_dispatch():
    text = NIGHTLY.read_text(encoding="utf-8")
    on_block = _on_block(text)
    keys = {
        m.group(1)
        for m in re.finditer(r"^  ([A-Za-z0-9_]+):", on_block, re.MULTILINE)
    }
    assert keys == {"schedule", "workflow_dispatch"}
    assert "pull_request" not in text
    assert "merge_group" not in on_block
    assert re.search(r'cron:\s*"0 2 \* \* \*"', on_block)
    assert "profile:" in on_block
    assert "epochs:" in on_block


def test_concurrency_group_cancels_in_progress():
    text = NIGHTLY.read_text(encoding="utf-8")
    assert re.search(r"(?m)^concurrency:\s*$", text)
    assert "group: devnet-nightly" in text
    assert "cancel-in-progress: true" in text


def test_jobs_are_build_then_soak():
    text = NIGHTLY.read_text(encoding="utf-8")
    jobs = _jobs(text)
    assert list(jobs) == ["build", "soak"]
    assert "timeout-minutes: 60" in jobs["build"]
    assert "timeout-minutes: 110" in jobs["soak"]
    assert "needs: build" in jobs["soak"]
    assert "runs-on: ubuntu-latest" in jobs["build"]
    assert "runs-on: ubuntu-latest" in jobs["soak"]
    assert "continue-on-error" not in text


def test_build_matches_ci_check_cache_and_pins():
    nightly = NIGHTLY.read_text(encoding="utf-8")
    ci = CI_YML.read_text(encoding="utf-8")
    build = _jobs(nightly)["build"]
    check = _jobs(ci)["check"]
    cache_key = "${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}"
    assert cache_key in check
    assert cache_key in build
    assert "~/.cargo/registry" in build
    assert "~/.cargo/git" in build
    assert "target" in build
    assert "dtolnay/rust-toolchain@stable" in build
    assert "arduino/setup-protoc@v3" in build
    assert 'version: "27.x"' in build
    assert "cargo build --release --locked -p rvc-bin" in build
    assert "actions/upload-artifact@v4" in build
    assert "path: target/release/rvc" in build
    assert "name: rvc-bin" in build
    assert "rustfmt" not in build
    assert "clippy" not in build


def test_soak_downloads_to_run_sh_path_and_chmod():
    soak = _jobs(NIGHTLY.read_text(encoding="utf-8"))["soak"]
    assert "actions/download-artifact@v4" in soak
    assert "name: rvc-bin" in soak
    assert "path: target/release" in soak
    assert "chmod +x target/release/rvc" in soak
    assert "RUN_ID=\"${GITHUB_RUN_ID}\"" in soak
    assert "--run-id" in soak
    assert "scripts/devnet/run.sh" in soak
    assert "--profile" in soak
    assert "--epochs" in soak
    assert "cargo" not in soak.lower()
    assert "dtolnay" not in soak
    assert "rust-toolchain" not in soak


def test_soak_always_uploads_and_tears_down():
    soak = _jobs(NIGHTLY.read_text(encoding="utf-8"))["soak"]
    assert "include-hidden-files: true" in soak
    assert "retention-days: 7" in soak
    assert "scripts/devnet/runs/${{ github.run_id }}" in soak
    assert soak.count("if: always()") >= 2
    assert "scripts/devnet/down.sh --data" in soak
    upload_idx = soak.index("include-hidden-files: true")
    down_idx = soak.index("scripts/devnet/down.sh --data")
    assert upload_idx < down_idx
