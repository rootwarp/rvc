"""Structural gates for third-party action pins and workflow permissions (FU-C3)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

# First-party actions stay on major tags. Pinning them is a follow-up; the
# predicate below still rejects an unpinned first-party `uses:` so a fixture
# can prove the rule. The repo scan exempts these prefixes.
_FIRST_PARTY = ("actions/", "github/")

_SHA_AT_END = re.compile(r"@[0-9a-f]{40}$")
_VERSION_COMMENT_RE = re.compile(r"#\s+v\S+")

# qemu-v10.2.3 index digest. setup-qemu-action otherwise runs binfmt:latest.
BINFMT_IMAGE = (
    "tonistiigi/binfmt@sha256:"
    "400a4873b838d1b89194d982c45e5fb3cda4593fbfd7e08a02e76b03b21166f0"
)

SCAN_PATHS = {
    "Dockerfile",
    ".dockerignore",
    ".github/workflows/docker*.yml",
    "Cargo.toml",
    "Cargo.lock",
    "crates/**",
    "bin/**",
    "proto/**",
    ".trivyignore",
    "scripts/docker-cargo-features.sh",
}

ALLOWED_IGNORED_CVE = "CVE-2023-45853"


class WorkflowLoader(yaml.SafeLoader):
    """GitHub Actions loader.

    PyYAML 1.1 tags `on` as a bool, which would hide the workflow trigger key.
    `true` and `false` stay booleans.
    """


def _construct_loose_bool(loader: yaml.SafeLoader, node: yaml.Node):
    raw = loader.construct_scalar(node)
    lowered = raw.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    return raw


WorkflowLoader.add_constructor("tag:yaml.org,2002:bool", _construct_loose_bool)


def load_workflow(text: str):
    return yaml.load(text, Loader=WorkflowLoader)


def normalize_uses(uses: object) -> str:
    return " ".join(str(uses).split())


def uses_is_sha_pinned(uses: object) -> bool:
    """Local `./` paths are allowed. Every other `uses:` needs `@<40-hex>`."""
    text = normalize_uses(uses)
    if text.startswith("./"):
        return True
    return _SHA_AT_END.search(text) is not None


def action_name(uses: object) -> str:
    return normalize_uses(uses).split("@", 1)[0]


def iter_use_steps(node):
    if isinstance(node, dict):
        if "uses" in node:
            yield node
        for value in node.values():
            yield from iter_use_steps(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_use_steps(item)


def _workflow_texts() -> list[tuple[Path, str]]:
    paths = sorted(WORKFLOWS.glob("*.yml")) + sorted(WORKFLOWS.glob("*.yaml"))
    return [(path, path.read_text(encoding="utf-8")) for path in paths]


def _version_comment_ok(text: str, uses: str) -> bool:
    sha = uses.rsplit("@", 1)[-1]
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if sha in line and _VERSION_COMMENT_RE.search(line):
            return True
    return False


def _trivy_uses_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if "aquasecurity/trivy-action@" in line and not line.lstrip().startswith("#")
    ]


def _is_trivy_step(step: dict) -> bool:
    return action_name(step.get("uses", "")).startswith("aquasecurity/trivy-action")


def step_is_disabled(node: dict) -> bool:
    cond = node.get("if")
    if cond is False:
        return True
    return isinstance(cond, str) and cond.strip().lower() == "false"


def step_continues_on_error(node: dict) -> bool:
    flag = node.get("continue-on-error")
    if flag is True:
        return True
    return isinstance(flag, str) and flag.strip().lower() == "true"


def _ignore_unfixed_enabled(with_: dict) -> bool:
    if "ignore-unfixed" not in with_:
        return False
    value = with_["ignore-unfixed"]
    if value is False:
        return False
    return not (isinstance(value, str) and value.strip().lower() == "false")


def trivy_gate_problems(doc) -> list[str]:
    """Problems in parsed Trivy steps. Comments in the YAML do not count."""
    problems: list[str] = []
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        return ["jobs is not a mapping"]
    sarif_gates = 0
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if not isinstance(step, dict) or not _is_trivy_step(step):
                continue
            where = f"{job_name}: {normalize_uses(step.get('uses'))}"
            if step_continues_on_error(step) or step_continues_on_error(job):
                problems.append(f"{where}: continue-on-error")
            if step_is_disabled(step) or step_is_disabled(job):
                problems.append(f"{where}: if false")
            with_ = step.get("with")
            if not isinstance(with_, dict):
                problems.append(f"{where}: with is not a mapping")
                continue
            if with_.get("limit-severities-for-sarif") is not True:
                problems.append(f"{where}: limit-severities-for-sarif")
            if with_.get("trivyignores") != ".trivyignore":
                problems.append(f"{where}: trivyignores")
            if with_.get("severity") != "CRITICAL":
                problems.append(f"{where}: severity")
            if _ignore_unfixed_enabled(with_):
                problems.append(f"{where}: ignore-unfixed")
            if with_.get("format") == "sarif" and str(with_.get("exit-code")) == "1":
                sarif_gates += 1
    if sarif_gates < 1:
        problems.append("no sarif step with exit-code 1")
    return problems


def trivy_table_steps(doc) -> list[dict]:
    found: list[dict] = []
    for step in iter_use_steps(doc):
        if not _is_trivy_step(step):
            continue
        with_ = step.get("with") or {}
        if isinstance(with_, dict) and with_.get("format") == "table":
            found.append(step)
    return found


def trivyignore_entries(text: str) -> list[str]:
    entries: list[str] = []
    for line in text.splitlines():
        code = line.split("#", 1)[0].strip()
        if code:
            entries.append(code)
    return entries


def ignore_file_problems(files: dict[str, str]) -> list[str]:
    problems: list[str] = []
    if sorted(files) != [".trivyignore"]:
        problems.append(f"unexpected ignore files: {sorted(files)}")
    if trivyignore_entries(files.get(".trivyignore", "")) != [ALLOWED_IGNORED_CVE]:
        problems.append("ignore entries")
    return problems


def discover_ignore_files() -> dict[str, str]:
    found: dict[str, str] = {}
    for path in ROOT.rglob("*trivyignore*"):
        if any(part in {".git", "target"} for part in path.parts):
            continue
        found[str(path.relative_to(ROOT))] = path.read_text(encoding="utf-8")
    return found


def test_uses_pin_predicate_rejects_anything_but_sha_or_local():
    assert uses_is_sha_pinned("./.github/actions/local")
    assert uses_is_sha_pinned("aquasecurity/trivy-action@" + ("a" * 40))
    assert not uses_is_sha_pinned("actions/checkout@v4")
    assert not uses_is_sha_pinned("github/codeql-action/upload-sarif@v3")
    assert not uses_is_sha_pinned("docker://ghcr.io/example/img:latest")
    assert not uses_is_sha_pinned(
        "docker://ghcr.io/example/img@sha256:" + ("ab" * 32)
    )


def test_parser_sees_quoted_flow_and_folded_uses():
    text = """
name: fixture
on: push
jobs:
  demo:
    steps:
      - "uses": "third/party@v1"
      - {uses: docker://ghcr.io/example/img:latest, with: {image: nope}}
      - uses: >
          another/action@main
      - uses: ./.github/actions/local
      - uses: actions/checkout@v4
"""
    uses = [normalize_uses(step["uses"]) for step in iter_use_steps(load_workflow(text))]
    assert uses == [
        "third/party@v1",
        "docker://ghcr.io/example/img:latest",
        "another/action@main",
        "./.github/actions/local",
        "actions/checkout@v4",
    ]
    pinned = [item for item in uses if uses_is_sha_pinned(item)]
    assert pinned == ["./.github/actions/local"]
    assert load_workflow(text)["on"] == "push"


def test_trivy_gate_parses_mappings_not_comments():
    text = """
# severity: CRITICAL
# exit-code: '1'
# limit-severities-for-sarif: true
# trivyignores: .trivyignore
name: fixture
on: push
jobs:
  scan:
    steps:
      - uses: aquasecurity/trivy-action@%s
        with:
          format: sarif
          severity: HIGH
          exit-code: '0'
""" % ("b" * 40)
    problems = trivy_gate_problems(load_workflow(text))
    assert any("severity" in item for item in problems)
    assert any("limit-severities-for-sarif" in item for item in problems)
    assert any("trivyignores" in item for item in problems)
    assert any("no sarif step" in item for item in problems)


def test_trivy_step_rejects_continue_on_error_and_if_false():
    sha = "c" * 40
    text = f"""
name: fixture
on: push
jobs:
  scan:
    continue-on-error: true
    if: false
    steps:
      - uses: aquasecurity/trivy-action@{sha}
        with:
          format: sarif
          severity: CRITICAL
          exit-code: '1'
          limit-severities-for-sarif: true
          trivyignores: .trivyignore
"""
    problems = trivy_gate_problems(load_workflow(text))
    assert any("continue-on-error" in item for item in problems)
    assert any("if false" in item for item in problems)
    assert step_is_disabled({"if": "false"})
    assert step_is_disabled({"if": False})
    assert not step_is_disabled({"if": "success() || failure()"})
    assert step_continues_on_error({"continue-on-error": "true"})


def test_ignore_file_problems_reject_extra_entries_and_files():
    assert ignore_file_problems({".trivyignore": "# note\nCVE-2023-45853\n"}) == []
    extra = ignore_file_problems({".trivyignore": "CVE-2023-45853\nCVE-2099-0001\n"})
    assert extra == ["ignore entries"]
    other = ignore_file_problems(
        {
            ".trivyignore": "CVE-2023-45853\n",
            "nested/extra.trivyignore": "CVE-2023-45853\n",
        }
    )
    assert any("unexpected ignore files" in item for item in other)


def test_every_third_party_action_is_sha_pinned():
    failures: list[str] = []
    for path, text in _workflow_texts():
        for step in iter_use_steps(load_workflow(text)):
            uses = normalize_uses(step["uses"])
            if uses.startswith("./"):
                continue
            name = action_name(uses)
            if name.startswith(_FIRST_PARTY):
                continue
            if not uses_is_sha_pinned(uses) or not _version_comment_ok(text, uses):
                failures.append(f"{path.name}: {uses}")
    assert failures == [], f"{len(failures)} unpinned third-party actions:\n" + "\n".join(
        failures
    )


def test_every_workflow_has_top_level_permissions():
    missing: list[str] = []
    for path, text in _workflow_texts():
        perms = load_workflow(text).get("permissions")
        if not isinstance(perms, dict) or perms.get("contents") != "read":
            missing.append(path.name)
    assert missing == [], f"{len(missing)} workflows without top-level contents: read: {missing}"


def test_rust_toolchain_and_install_action_keep_their_inputs():
    failures: list[str] = []
    for path, text in _workflow_texts():
        for step in iter_use_steps(load_workflow(text)):
            name = action_name(step.get("uses"))
            with_ = step.get("with") or {}
            if name == "dtolnay/rust-toolchain" and with_.get("toolchain") != "stable":
                failures.append(f"{path.name}: rust-toolchain missing toolchain: stable")
            if name == "taiki-e/install-action" and not with_.get("tool"):
                failures.append(f"{path.name}: install-action missing tool:")
    assert failures == [], "\n".join(failures)


def test_checkouts_do_not_persist_credentials_except_claude():
    for path, text in _workflow_texts():
        steps = [
            step
            for step in iter_use_steps(load_workflow(text))
            if action_name(step.get("uses")) == "actions/checkout"
        ]
        if path.name == "claude.yml":
            for step in steps:
                assert "persist-credentials" not in (step.get("with") or {})
            continue
        assert steps, path.name
        for step in steps:
            with_ = step.get("with") or {}
            assert with_.get("persist-credentials") is False, path.name


def test_trivy_uses_line_is_identical_and_gate_holds():
    docker_text = (WORKFLOWS / "docker.yml").read_text(encoding="utf-8")
    scan_path = WORKFLOWS / "docker-scan.yml"
    assert scan_path.is_file(), "docker-scan.yml missing"
    scan_text = scan_path.read_text(encoding="utf-8")
    docker = load_workflow(docker_text)
    scan = load_workflow(scan_text)

    docker_pins = _trivy_uses_lines(docker_text)
    scan_pins = _trivy_uses_lines(scan_text)
    assert docker_pins and len(set(docker_pins)) == 1
    assert set(scan_pins) == set(docker_pins)

    assert trivy_gate_problems(docker) == []
    assert trivy_gate_problems(scan) == []
    assert trivy_table_steps(docker) == []
    tables = trivy_table_steps(scan)
    assert len(tables) == 1
    assert str(tables[0]["with"]["exit-code"]) == "0"
    assert "GITHUB_STEP_SUMMARY" in scan_text

    scan_job = docker["jobs"]["scan"]
    assert scan_job["name"] == "scan (${{ matrix.target }})"
    assert scan_job["if"] == "github.event_name != 'pull_request'"
    assert docker["jobs"]["push"]["needs"] == ["build", "scan"]
    assert docker["jobs"]["push"]["if"] == "startsWith(github.ref, 'refs/tags/')"
    assert "workflow_dispatch" in docker["on"]

    assert scan["jobs"]["scan"]["name"] == "pr-scan (${{ matrix.target }})"
    scan_uses = [normalize_uses(step["uses"]) for step in iter_use_steps(scan)]
    assert not any("upload-sarif" in item for item in scan_uses)
    assert not any(item.startswith("docker/login-action") for item in scan_uses)
    for job in scan["jobs"].values():
        perms = job.get("permissions") or {}
        assert "security-events" not in perms
        assert "packages" not in perms
    build = next(
        step
        for step in iter_use_steps(scan)
        if action_name(step["uses"]).startswith("docker/build-push-action")
    )
    assert build["with"]["platforms"] == "linux/amd64"
    assert build["with"]["load"] is True
    triggers = scan["on"]
    assert "workflow_dispatch" in triggers
    assert triggers["pull_request"]["branches"] == ["develop", "main"]
    assert set(triggers["pull_request"]["paths"]) == SCAN_PATHS
    assert triggers["schedule"] == [{"cron": "0 6 * * 1"}]


def test_qemu_binfmt_is_digest_pinned():
    text = (WORKFLOWS / "docker.yml").read_text(encoding="utf-8")
    found = 0
    for step in iter_use_steps(load_workflow(text)):
        if not action_name(step.get("uses")).startswith("docker/setup-qemu-action"):
            continue
        found += 1
        image = (step.get("with") or {}).get("image")
        assert image == BINFMT_IMAGE
        assert ":latest" not in image
    assert found == 2
    assert "qemu-v10.2.3" in text


def test_reviewed_trivyignore_is_the_only_ignore_file():
    files = discover_ignore_files()
    assert ignore_file_problems(files) == []
    text = files[".trivyignore"]
    assert "https://security-tracker.debian.org/tracker/CVE-2023-45853" in text
    assert "2027-01-18" in text
    assert "minizip" in text
    assert "will_not_fix" in text


def test_dependabot_tracks_github_actions():
    doc = load_workflow((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
    matched = [
        item
        for item in doc["updates"]
        if item.get("package-ecosystem") == "github-actions"
        and (item.get("schedule") or {}).get("interval") == "weekly"
        and item.get("target-branch") == "develop"
    ]
    assert len(matched) == 1
