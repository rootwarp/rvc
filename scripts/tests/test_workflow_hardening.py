"""Structural gates for action pins, workflow permissions, the Trivy gate and CI test limits."""

from __future__ import annotations

import datetime
import os
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

_SHA_AT_END = re.compile(r"@[0-9a-f]{40}$")
# A version comment is `# v` and a number, for example `# v3.7.0`. `# vulnerable` is not.
_VERSION_COMMENT_RE = re.compile(r"#\s+v\d+(\.\d+)*\b")

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
    ".trivyignore.yaml",
    "scripts/docker-cargo-features.sh",
    ".cargo/config.toml",
}

TARGET_EXPR = "${{ matrix.target }}"
SCAN_REF = f"{TARGET_EXPR}:scan"

# This constant names the only Trivy ignore file. Both Trivy workflows pass it as `trivyignores`.
IGNORE_FILE = ".trivyignore.yaml"

# Each entry contains a reviewed CVE and its expiry option. On that date Trivy stops
# ignoring the CVE, and the image scan turns red until a review renews the entry.
# The package URLs (purls) limit the entry to the reviewed packages.
ALLOWED_IGNORED_CVES = [
    ("CVE-2023-45853", ("pkg:deb/debian/zlib1g",), datetime.date(2027, 1, 18)),
]
# This set lists the keys that an ignore entry can have. A different key needs a review.
_IGNORE_ENTRY_KEYS = frozenset({"id", "purls", "expired_at", "statement"})

# The table report and the docker.yml gate use this severity filter.
TRIVY_SEVERITY = "HIGH,CRITICAL"

# Each Trivy step has one of these severity policies. A policy gives the format, the
# severity, the exit code and the ignore-unfixed value of the step.
#
# The table report shows each HIGH and CRITICAL finding. This includes a finding without a fix.
TABLE_REPORT = ("table", TRIVY_SEVERITY, "0", False)
# Gate A fails the job for each CRITICAL finding. This includes a finding without a fix.
GATE_A = ("sarif", "CRITICAL", "1", False)
# Gate B fails the job for a HIGH finding only when a fixed version exists.
GATE_B = ("sarif", "HIGH", "1", True)
# The docker.yml gate fails the job for each HIGH and CRITICAL finding.
RELEASE_GATE = ("sarif", TRIVY_SEVERITY, "1", False)

# This map gives the reviewed Trivy steps of each workflow, in step order.
TRIVY_STEP_PLAN = {
    "docker-scan.yml": (TABLE_REPORT, GATE_A, GATE_B),
    "docker.yml": (RELEASE_GATE,),
}
_REVIEWED_POLICIES = tuple(dict.fromkeys(p for plan in TRIVY_STEP_PLAN.values() for p in plan))

# The only inputs that a Trivy step can set. A new input needs a review of this set.
TRIVY_ALLOWED_INPUTS = frozenset(
    {
        "image-ref",
        "format",
        "output",
        "severity",
        "exit-code",
        "ignore-unfixed",
        "limit-severities-for-sarif",
        "trivyignores",
    }
)

# The only images that a Trivy step can scan. The build step of the job makes this image.
ALLOWED_IMAGE_REFS = frozenset({"${{ matrix.target }}:scan"})

# The only steps that can come before the last SARIF gate of a Trivy job.
TRIVY_JOB_PRE_GATE_ACTIONS = frozenset(
    {
        "actions/checkout",
        "docker/setup-qemu-action",
        "docker/setup-buildx-action",
        "docker/metadata-action",
        "docker/login-action",
        "docker/build-push-action",
        "aquasecurity/trivy-action",
    }
)

# The reviewed `if` of a Trivy job, by workflow file and job name. Other Trivy
# jobs cannot have an `if`.
ALLOWED_TRIVY_JOB_IFS = {("docker.yml", "scan"): "github.event_name != 'pull_request'"}

# Build inputs that replace the Dockerfile or a build context of the scanned image.
_RETARGETING_BUILD_INPUTS = ("file", "build-contexts")

# Trivy reads each TRIVY_<FLAG> environment variable as that flag.
_TRIVY_ENV_RE = re.compile(r"trivy_", re.IGNORECASE)

# A run step in a Trivy job must not touch the ignore file, a Trivy config file,
# or the job environment or PATH. GITHUB_ENV alone is enough, because a script
# can build the TRIVY_ name at run time.
_RUN_TOUCHES_SCAN_RE = re.compile(
    r"\.trivyignore|trivy\.y|\bGITHUB_ENV\b|\bGITHUB_PATH\b", re.IGNORECASE
)
# `trivy` in command position: at a line start, or after `;`, `&`, `|`, `$(` or a backtick.
_TRIVY_COMMAND_RE = re.compile(r"(?:^|[;&|`]|\$\()\s*trivy\b", re.IGNORECASE | re.MULTILINE)

# Trivy reads trivy.yaml from the working directory when no --config is given.
TRIVY_CONFIG_NAMES = {"trivy.yaml", "trivy.yml"}


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


def _pinned_version(text: str, uses: str) -> tuple[int, ...] | None:
    """Return the version in the comment on the line of the `uses:` ref, or None."""
    ref = uses.rsplit("@", 1)[-1]
    for line in text.splitlines():
        if line.lstrip().startswith("#") or ref not in line:
            continue
        match = _VERSION_COMMENT_RE.search(line)
        if match:
            return tuple(int(part) for part in match.group(0).split("v", 1)[1].split("."))
    return None


def _version_comment_ok(text: str, uses: str) -> bool:
    return _pinned_version(text, uses) is not None


def _pin_problem(label: str, text: str, uses: str) -> list[str]:
    """Return a problem when a `uses:` has no SHA pin or no version comment.

    First-party actions are not exempt.
    """
    if uses_is_sha_pinned(uses) and _version_comment_ok(text, uses):
        return []
    return [f"{label}: {uses}"]


def local_action_problems(root: Path, ref: str, seen: frozenset[str] = frozenset()) -> list[str]:
    """Return pin errors for this local action and each local action that it uses."""
    folder = root / ref.removeprefix("./")
    paths = [folder / name for name in ("action.yml", "action.yaml") if (folder / name).is_file()]
    if not paths:
        return [f"{ref}: action.yml is missing"]
    text = paths[0].read_text(encoding="utf-8")
    seen = seen | {ref}
    problems: list[str] = []
    for step in iter_use_steps((load_workflow(text) or {}).get("runs")):
        uses = normalize_uses(step["uses"])
        if not uses.startswith("./"):
            problems.extend(_pin_problem(ref, text, uses))
        elif uses not in seen:
            problems.extend(local_action_problems(root, uses, seen))
    return problems


def top_level_permission_problems(doc) -> list[str]:
    """The top-level permissions must be exactly `contents: read`."""
    permissions = doc.get("permissions")
    if permissions == {"contents": "read"}:
        return []
    return [f"top-level permissions {permissions!r}"]


def _trivy_uses_lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in text.splitlines()
        if "aquasecurity/trivy-action@" in line and not line.lstrip().startswith("#")
    ]


def _is_trivy_step(step: dict) -> bool:
    return action_name(step.get("uses", "")).startswith("aquasecurity/trivy-action")


def _ignore_unfixed(inputs: dict) -> object:
    """Return the ignore-unfixed value of a step as a bool. The action default is False.

    For a value other than a bool, `'true'` or `'false'`, the function returns a
    string. No reviewed policy matches a string.
    """
    value = inputs.get("ignore-unfixed", False)
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "false"):
        return text == "true"
    return str(value)


def trivy_policy(inputs: dict) -> tuple:
    """Return the format, the severity, the exit code and the ignore-unfixed value."""
    return (
        inputs.get("format"),
        inputs.get("severity"),
        str(inputs.get("exit-code")),
        _ignore_unfixed(inputs),
    )


def trivy_env_problems(label: str, env) -> list[str]:
    """TRIVY_* keys (any case) in one `env:` map."""
    if not isinstance(env, dict):
        return []
    return [f"{label}: {key}" for key in env if _TRIVY_ENV_RE.match(str(key))]


def _fold_keys(mapping: dict) -> tuple[dict[str, object], list[str]]:
    """Map each key to lowercase, and return each case-only duplicate key.

    Action inputs ignore case, so `Severity` and `severity` set the same input.
    The first spelling stays in the map.
    """
    folded: dict[str, object] = {}
    duplicates: list[str] = []
    for key, value in mapping.items():
        low = str(key).lower()
        if low in folded:
            duplicates.append(str(key))
            continue
        folded[low] = value
    return folded, duplicates


def _step_inputs(where: str, step: dict) -> tuple[dict[str, object], list[str]]:
    raw = step.get("with")
    if not isinstance(raw, dict):
        return {}, [f"{where}: with is not a mapping"]
    folded, duplicates = _fold_keys(raw)
    return folded, [f"{where}: case-only duplicate input {key}" for key in duplicates]


def _is_sarif_gate(inputs: dict) -> bool:
    return inputs.get("format") == "sarif" and str(inputs.get("exit-code")) == "1"


def trivy_reports(inputs: dict, severity: str, fixed: bool) -> bool:
    """Return True when the Trivy step reports one finding of `severity`.

    `fixed` is True when a fixed version of the package exists. The step reports a
    finding only when its `severity` input names the level of the finding. With
    `ignore-unfixed: true`, the step does not report a finding without a fixed version.
    """
    levels = {item.strip().upper() for item in str(inputs.get("severity", "")).split(",")}
    return severity in levels and (fixed or _ignore_unfixed(inputs) is not True)


def scan_fails_for(inputs: dict, severity: str, fixed: bool) -> bool:
    """Return True when the Trivy step fails the job for one finding of `severity`.

    The step must set `exit-code: '1'` and report the finding. This model applies to a
    step with `limit-severities-for-sarif: true`. The gate check requires that flag.
    """
    return str(inputs.get("exit-code")) == "1" and trivy_reports(inputs, severity, fixed)


def _run_step_problems(where: str, step: dict) -> list[str]:
    run = step.get("run")
    if not isinstance(run, str):
        return []
    problems = []
    if _RUN_TOUCHES_SCAN_RE.search(run):
        problems.append(f"{where} run touches the scan")
    if _TRIVY_COMMAND_RE.search(run):
        problems.append(f"{where} run starts trivy")
    return problems


def _trivy_step_problems(where: str, step: dict) -> tuple[list[str], dict[str, object]]:
    problems = [f"{where}: {key}" for key in ("if", "continue-on-error") if key in step]
    problems.extend(trivy_env_problems(f"{where}: env", step.get("env")))
    inputs, input_problems = _step_inputs(where, step)
    problems.extend(input_problems)
    problems.extend(f"{where}: input {key}" for key in inputs if key not in TRIVY_ALLOWED_INPUTS)
    image_ref = inputs.get("image-ref")
    if not isinstance(image_ref, str) or image_ref not in ALLOWED_IMAGE_REFS:
        problems.append(f"{where}: image-ref {image_ref!r}")
    if inputs.get("limit-severities-for-sarif") is not True:
        problems.append(f"{where}: limit-severities-for-sarif")
    if inputs.get("trivyignores") != IGNORE_FILE:
        problems.append(f"{where}: trivyignores")
    policy = trivy_policy(inputs)
    if policy not in _REVIEWED_POLICIES:
        problems.append(f"{where}: severity policy {policy!r}")
    return problems, inputs


def _build_problems(job_name: str, steps: list[dict], image_refs: set[str]) -> list[str]:
    """Each build step makes the scanned image from the repository Dockerfile."""
    problems: list[str] = []
    tagged: set[str] = set()
    for step in steps:
        if action_name(step.get("uses", "")) != "docker/build-push-action":
            continue
        where = f"{job_name}: {normalize_uses(step['uses'])}"
        inputs, input_problems = _step_inputs(where, step)
        problems.extend(input_problems)
        if inputs.get("context") != ".":
            problems.append(f"{where}: context {inputs.get('context')!r}")
        if inputs.get("target") != TARGET_EXPR:
            problems.append(f"{where}: target {inputs.get('target')!r}")
        problems.extend(
            f"{where}: input {key}" for key in _RETARGETING_BUILD_INPUTS if key in inputs
        )
        tagged.update(tag.strip() for tag in re.split(r"[,\n]", str(inputs.get("tags", ""))))
    problems.extend(f"{job_name}: no build step tags {ref}" for ref in sorted(image_refs - tagged))
    return problems


def _trivy_job_problems(workflow: str, job_name: str, job: dict, steps: list[dict]):
    """Return the problems of one Trivy job and its number of SARIF gates."""
    problems = trivy_env_problems(f"{job_name}: env", job.get("env"))
    if "continue-on-error" in job:
        problems.append(f"{job_name}: job continue-on-error")
    if "if" in job and job["if"] != ALLOWED_TRIVY_JOB_IFS.get((workflow, job_name)):
        problems.append(f"{job_name}: job if {job['if']!r} is not allowed")
    gates: list[int] = []
    image_refs: set[str] = set()
    for number, step in enumerate(steps, start=1):
        problems.extend(_run_step_problems(f"{job_name}: step {number}", step))
        if not _is_trivy_step(step):
            continue
        where = f"{job_name}: {normalize_uses(step.get('uses'))}"
        step_problems, inputs = _trivy_step_problems(where, step)
        problems.extend(step_problems)
        if isinstance(inputs.get("image-ref"), str):
            image_refs.add(inputs["image-ref"])
        if _is_sarif_gate(inputs):
            gates.append(number)
    before_gate = steps[: gates[-1] - 1] if gates else []
    problems.extend(
        f"{job_name}: step {number} before the gate is not an allowed action"
        for number, step in enumerate(before_gate, start=1)
        if "uses" not in step or action_name(step["uses"]) not in TRIVY_JOB_PRE_GATE_ACTIONS
    )
    problems.extend(_build_problems(job_name, steps, image_refs))
    return problems, len(gates)


def trivy_gate_problems(doc, workflow: str = "") -> list[str]:
    """Return problems in the Trivy jobs of this workflow. YAML comments do not count.

    `workflow` is the workflow file name. It selects the reviewed job `if`. The
    Trivy inputs, the severity policies, the image, and the steps before the last
    gate are allow-lists. `test_trivy_steps_follow_the_reviewed_plan` checks the
    policy of each step in each workflow.
    """
    problems: list[str] = []
    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        return ["jobs is not a mapping"]
    problems.extend(trivy_env_problems("workflow env", doc.get("env")))
    sarif_gates = 0
    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue
        steps = [step for step in job.get("steps") or [] if isinstance(step, dict)]
        if not any(_is_trivy_step(step) for step in steps):
            continue
        job_problems, gates = _trivy_job_problems(workflow, job_name, job, steps)
        problems.extend(job_problems)
        sarif_gates += gates
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


def _ignore_vulnerabilities(text: str) -> list | None:
    """Return the `vulnerabilities` list of a YAML ignore file, or None for another shape."""
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict) or set(doc) != {"vulnerabilities"}:
        return None
    entries = doc["vulnerabilities"]
    if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
        return None
    return entries


def trivyignore_entries(text: str) -> list[tuple[object, tuple[str, ...], object]]:
    """Read the id, the purls and the `expired_at` date of each vulnerability entry."""
    return [
        (entry.get("id"), tuple(entry.get("purls") or ()), entry.get("expired_at"))
        for entry in _ignore_vulnerabilities(text) or []
    ]


def ignore_file_problems(files: dict[str, str]) -> list[str]:
    problems: list[str] = []
    if sorted(files) != [IGNORE_FILE]:
        problems.append(f"unexpected ignore files: {sorted(files)}")
    entries = _ignore_vulnerabilities(files.get(IGNORE_FILE, ""))
    if entries is None:
        return [*problems, "ignore file shape"]
    for entry in entries:
        if set(entry) != _IGNORE_ENTRY_KEYS:
            problems.append(f"ignore entry keys {sorted(entry)}")
        elif not str(entry["statement"] or "").strip():
            problems.append(f"ignore entry {entry['id']} has no statement")
    if trivyignore_entries(files.get(IGNORE_FILE, "")) != ALLOWED_IGNORED_CVES:
        problems.append("ignore entries")
    return problems


def _purl_parts(purl: str) -> tuple[tuple[str, str, str], str, dict[str, str]]:
    """Split a package URL into (type, namespace, name), the version and the qualifiers."""
    body = purl.removeprefix("pkg:").split("#", 1)[0]
    body, _, query = body.partition("?")
    path, _, version = body.partition("@")
    kind, *namespace, name = path.split("/")
    qualifiers = dict(item.split("=", 1) for item in query.split("&") if item)
    return (kind, "/".join(namespace), name), version, qualifiers


def trivy_ignores(entries, cve: str, purl: str) -> bool:
    """Return True when an ignore entry hides the finding `cve` in the package `purl`.

    This model follows the purl match in Trivy `pkg/result/ignore.go`:

    - An entry without purls matches each package.
    - The type, the namespace and the name must be equal.
    - A purl without a version matches each version.
    - Each qualifier of the entry purl must occur in the package purl.
    """
    target, target_version, target_qualifiers = _purl_parts(purl)
    for entry_id, purls, _expired_at in entries:
        if entry_id != cve:
            continue
        if not purls:
            return True
        for package, version, qualifiers in map(_purl_parts, purls):
            if package != target or version not in ("", target_version):
                continue
            if all(target_qualifiers.get(key) == value for key, value in qualifiers.items()):
                return True
    return False


def trivy_config_file_problems(paths: list[str]) -> list[str]:
    return [
        f"trivy config file: {path}"
        for path in sorted(paths)
        if Path(path).name in TRIVY_CONFIG_NAMES
    ]


def discover_trivy_config_files() -> list[str]:
    found: list[str] = []
    for name in TRIVY_CONFIG_NAMES:
        for path in ROOT.rglob(name):
            if any(part in {".git", "target"} for part in path.parts):
                continue
            found.append(str(path.relative_to(ROOT)))
    return found


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
# severity: HIGH,CRITICAL
# exit-code: '1'
# limit-severities-for-sarif: true
# trivyignores: .trivyignore.yaml
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


_TRIVY_FIXTURE_USES = f"aquasecurity/trivy-action@{'e' * 40}"
_BUILD_FIXTURE_USES = f"docker/build-push-action@{'f' * 40}"


def _trivy_job_with(
    workflow_env: str = "",
    job_keys: str = "",
    build_extra: str = "",
    pre_steps: str = "",
    trivy_extra: str = "",
    post_steps: str = "",
) -> str:
    """Return a reviewed Trivy job. Step 1 builds the image and step 2 is the gate."""
    return f"""
name: fixture
on: push
{workflow_env}jobs:
  scan:
{job_keys}    steps:
      - uses: {_BUILD_FIXTURE_USES}
        with:
          context: .
          target: {TARGET_EXPR}
          load: true
          tags: {SCAN_REF}
{build_extra}{pre_steps}      - uses: {_TRIVY_FIXTURE_USES}
        with:
          image-ref: {SCAN_REF}
          format: sarif
          output: trivy.sarif
          severity: {TRIVY_SEVERITY}
          exit-code: '1'
          limit-severities-for-sarif: true
          trivyignores: {IGNORE_FILE}
{trivy_extra}{post_steps}"""


def _reviewed_trivy_step(extra: str) -> str:
    return _trivy_job_with(trivy_extra=extra)


def test_trivy_gate_rejects_trivy_env_at_each_level():
    assert trivy_gate_problems(load_workflow(_trivy_job_with())) == []
    workflow = _trivy_job_with(workflow_env="env:\n  TRIVY_IGNORE_UNFIXED: 'true'\n")
    assert "workflow env: TRIVY_IGNORE_UNFIXED" in trivy_gate_problems(load_workflow(workflow))
    job = _trivy_job_with(job_keys="    env:\n      trivy_skip_dirs: usr/lib\n")
    assert "scan: env: trivy_skip_dirs" in trivy_gate_problems(load_workflow(job))
    step = _reviewed_trivy_step("        env:\n          TRIVY_CONFIG: trivy.yaml\n")
    assert any(
        item.endswith("env: TRIVY_CONFIG") for item in trivy_gate_problems(load_workflow(step))
    )
    harmless = _trivy_job_with(workflow_env="env:\n  REGISTRY: ghcr.io\n")
    assert trivy_gate_problems(load_workflow(harmless)) == []


@pytest.mark.parametrize(
    ("job_keys", "trivy_extra", "expected"),
    [
        pytest.param(
            "",
            "        if: ${{ false }}\n",
            f"scan: {_TRIVY_FIXTURE_USES}: if",
            id="step-if-expression",
        ),
        pytest.param(
            "", "        if: false\n", f"scan: {_TRIVY_FIXTURE_USES}: if", id="step-if-false"
        ),
        pytest.param(
            "",
            "        continue-on-error: ${{ true }}\n",
            f"scan: {_TRIVY_FIXTURE_USES}: continue-on-error",
            id="step-continue-on-error-expression",
        ),
        pytest.param(
            "    if: ${{ false }}\n",
            "",
            "scan: job if '${{ false }}' is not allowed",
            id="job-if-expression",
        ),
        pytest.param("    if: false\n", "", "scan: job if False is not allowed", id="job-if-false"),
        pytest.param(
            "    continue-on-error: true\n",
            "",
            "scan: job continue-on-error",
            id="job-continue-on-error",
        ),
    ],
)
def test_trivy_gate_rejects_expression_if_and_continue_on_error(job_keys, trivy_extra, expected):
    """The gate rejects an `if` or `continue-on-error` key, also when it holds an expression."""
    text = _trivy_job_with(job_keys=job_keys, trivy_extra=trivy_extra)
    problems = trivy_gate_problems(load_workflow(text))
    assert expected in problems, f"The gate must report {expected!r}. It reported {problems}."


@pytest.mark.parametrize(
    ("condition", "expected"),
    [
        pytest.param("always()", ["scan: job if 'always()' is not allowed"], id="drift"),
        pytest.param("github.event_name != 'pull_request'", [], id="allowed"),
    ],
)
def test_trivy_gate_allows_only_the_listed_job_if(condition, expected):
    """The docker.yml scan job can have only its reviewed `if` value."""
    text = (WORKFLOWS / "docker.yml").read_text(encoding="utf-8")
    reviewed = "if: github.event_name != 'pull_request'"
    assert text.count(reviewed) == 1, "The docker.yml scan job must have the reviewed if value."
    doc = load_workflow(text.replace(reviewed, f"if: {condition}"))
    problems = trivy_gate_problems(doc, "docker.yml")
    assert problems == expected, f"The gate must report {expected}. It reported {problems}."


@pytest.mark.parametrize(
    ("command", "after_gate"),
    [
        pytest.param("echo CVE-2099-0001 >> .trivyignore", "touches the scan", id="ignore-file"),
        pytest.param("printf 'severity: LOW\\n' > trivy.yaml", "touches the scan", id="config"),
        pytest.param(
            "printf '%s_SKIP_DIRS=usr\\n' TRIVY >> \"$GITHUB_ENV\"",
            "touches the scan",
            id="built-env-name",
        ),
        pytest.param('echo /tmp/bin >> "$GITHUB_PATH"', "touches the scan", id="path-shadow"),
        pytest.param("docker tag busybox rvc:scan", None, id="retag"),
        pytest.param("trivy image --ignorefile x rvc:scan", "starts trivy", id="trivy-command"),
        pytest.param("echo ok && trivy fs .", "starts trivy", id="trivy-after-and"),
        pytest.param("version=$(trivy --version)", "starts trivy", id="trivy-in-substitution"),
        pytest.param("echo x | trivy image rvc:scan", "starts trivy", id="trivy-after-pipe"),
        pytest.param(
            'echo "TRIVY_SKIP_DIRS=usr/lib" >> "$GITHUB_ENV"', "touches the scan", id="env-writer"
        ),
        pytest.param(
            "echo trivy_config=x.yaml >> $GITHUB_ENV", "touches the scan", id="env-writer-lowercase"
        ),
        pytest.param('cat trivy-rvc.txt >> "$GITHUB_STEP_SUMMARY"', None, id="summary"),
    ],
)
def test_trivy_gate_rejects_run_steps_that_touch_the_scan(command, after_gate):
    """A run step before the gate is a problem.

    After the gate, a run step is a problem only when it touches the scan setup
    or starts trivy.
    """
    step = f"      - run: |\n          {command}\n"
    before = trivy_gate_problems(load_workflow(_trivy_job_with(pre_steps=step)))
    expected = "scan: step 2 before the gate is not an allowed action"
    assert expected in before, f"The gate must report {expected!r}. It reported {before}."
    after = trivy_gate_problems(load_workflow(_trivy_job_with(post_steps=step)))
    expected_after = [] if after_gate is None else [f"scan: step 3 run {after_gate}"]
    assert after == expected_after, f"The gate must report {expected_after}. It reported {after}."


def test_trivy_step_rejects_case_only_duplicate_inputs():
    """Action inputs ignore case, so a second spelling of one input is a problem.

    One spelling in a different case is not a problem.
    """
    text = _reviewed_trivy_step("").replace(
        f"          severity: {TRIVY_SEVERITY}\n",
        f"          severity: LOW\n          Severity: {TRIVY_SEVERITY}\n",
    )
    problems = trivy_gate_problems(load_workflow(text))
    expected = f"scan: {_TRIVY_FIXTURE_USES}: case-only duplicate input Severity"
    assert expected in problems, f"The gate must report {expected!r}. It reported {problems}."
    mixed = _reviewed_trivy_step("").replace(
        f"severity: {TRIVY_SEVERITY}", f"Severity: {TRIVY_SEVERITY}"
    )
    problems = trivy_gate_problems(load_workflow(mixed))
    assert problems == [], (
        f"One Severity input must not be a problem. The gate reported {problems}."
    )


# Inputs that remove paths, files, or scanners from the scan, or that load a
# config file that can do the same. The allow-list rejects each of them.
_NARROWING_INPUTS = [
    ("skip-dirs", "usr/lib"),
    ("skip-files", "usr/lib/x86_64-linux-gnu/libbrotlidec.so.1"),
    ("scanners", "secret"),
    ("trivy-config", "trivy.yaml"),
    ("vuln-type", "library"),
    ("ignore-policy", "policy.rego"),
    ("skip-setup-trivy", "true"),
    ("version", "v0.50.0"),
    ("Skip-Dirs", "usr/lib"),
    ("SCANNERS", "secret"),
]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        *(
            pytest.param(
                _reviewed_trivy_step(f"          {key}: {value}\n"),
                f"scan: {_TRIVY_FIXTURE_USES}: input {key.lower()}",
                id=f"narrowing-{key}",
            )
            for key, value in _NARROWING_INPUTS
        ),
        pytest.param(
            _trivy_job_with(build_extra="          build-contexts: chef=docker-image://busybox\n"),
            f"scan: {_BUILD_FIXTURE_USES}: input build-contexts",
            id="build-contexts",
        ),
        pytest.param(
            _trivy_job_with().replace("context: .", "context: ./other"),
            f"scan: {_BUILD_FIXTURE_USES}: context './other'",
            id="build-context",
        ),
        pytest.param(
            _trivy_job_with().replace(f"target: {TARGET_EXPR}", "target: chef"),
            f"scan: {_BUILD_FIXTURE_USES}: target 'chef'",
            id="build-target",
        ),
        pytest.param(
            _trivy_job_with().replace(f"tags: {SCAN_REF}", "tags: other:scan"),
            f"scan: no build step tags {SCAN_REF}",
            id="build-tags",
        ),
        pytest.param(
            _reviewed_trivy_step("          scan-type: fs\n"),
            f"scan: {_TRIVY_FIXTURE_USES}: input scan-type",
            id="scan-type",
        ),
        pytest.param(
            _reviewed_trivy_step("          input: x.tar\n"),
            f"scan: {_TRIVY_FIXTURE_USES}: input input",
            id="input",
        ),
        pytest.param(
            _reviewed_trivy_step("").replace(f"image-ref: {SCAN_REF}", "image-ref: busybox:latest"),
            f"scan: {_TRIVY_FIXTURE_USES}: image-ref 'busybox:latest'",
            id="image-ref",
        ),
        pytest.param(
            _trivy_job_with(build_extra="          file: Other.Dockerfile\n"),
            f"scan: {_BUILD_FIXTURE_USES}: input file",
            id="build-file",
        ),
    ],
)
def test_trivy_step_accepts_only_allow_listed_inputs(text, expected):
    """The Trivy step and its build step can have only the reviewed inputs and values."""
    problems = trivy_gate_problems(load_workflow(text))
    assert expected in problems, f"The gate must report {expected!r}. It reported {problems}."


def _gate_with(severity: str, extra: str) -> str:
    """Return the reviewed Trivy job with a different gate severity and more gate inputs."""
    text = _reviewed_trivy_step(extra)
    old = f"          severity: {TRIVY_SEVERITY}\n"
    assert text.count(old) == 1, "The fixture must contain one severity input."
    return text.replace(old, f"          severity: {severity}\n")


_IGNORE_UNFIXED_TRUE = "          ignore-unfixed: true\n"
_IGNORE_UNFIXED_FALSE = "          ignore-unfixed: false\n"


@pytest.mark.parametrize(
    ("severity", "extra", "policy"),
    [
        pytest.param(TRIVY_SEVERITY, "", None, id="release-gate"),
        pytest.param("CRITICAL", _IGNORE_UNFIXED_FALSE, None, id="gate-a"),
        pytest.param("HIGH", _IGNORE_UNFIXED_TRUE, None, id="gate-b"),
        pytest.param("HIGH", "          Ignore-Unfixed: 'true'\n", None, id="gate-b-string"),
        pytest.param(
            TRIVY_SEVERITY,
            _IGNORE_UNFIXED_TRUE,
            ("sarif", TRIVY_SEVERITY, "1", True),
            id="release-gate-hides-unfixed",
        ),
        pytest.param(
            "CRITICAL",
            _IGNORE_UNFIXED_TRUE,
            ("sarif", "CRITICAL", "1", True),
            id="gate-a-hides-unfixed",
        ),
        pytest.param(
            "HIGH", _IGNORE_UNFIXED_FALSE, ("sarif", "HIGH", "1", False), id="gate-b-shows-unfixed"
        ),
        pytest.param("HIGH", "", ("sarif", "HIGH", "1", False), id="gate-b-default"),
        pytest.param(
            "HIGH", "          ignore-unfixed: yes\n", ("sarif", "HIGH", "1", "yes"), id="word"
        ),
        pytest.param(
            "HIGH", "          ignore-unfixed: 1\n", ("sarif", "HIGH", "1", "1"), id="number"
        ),
        pytest.param(
            "MEDIUM,HIGH,CRITICAL",
            "",
            ("sarif", "MEDIUM,HIGH,CRITICAL", "1", False),
            id="other-severity",
        ),
    ],
)
def test_trivy_step_accepts_only_reviewed_severity_policies(severity, extra, policy):
    """A Trivy step can have only a reviewed severity policy.

    The gate check reports each other combination of severity and ignore-unfixed.
    """
    problems = trivy_gate_problems(load_workflow(_gate_with(severity, extra)))
    expected = (
        [] if policy is None else [f"scan: {_TRIVY_FIXTURE_USES}: severity policy {policy!r}"]
    )
    assert problems == expected, f"The gate must report {expected}. It reported {problems}."


def test_trivy_config_files_are_rejected():
    assert trivy_config_file_problems([]) == []
    for name in ["trivy.yaml", "trivy.yml", "nested/trivy.yaml"]:
        assert trivy_config_file_problems([name]) == [f"trivy config file: {name}"]
    assert trivy_config_file_problems(discover_trivy_config_files()) == []


_REVIEWED_IGNORE = """\
# note
vulnerabilities:
  - id: CVE-2023-45853
    purls:
      - pkg:deb/debian/zlib1g
    expired_at: 2027-01-18
    statement: zlib1g does not contain minizip.
"""
_EXTRA_ENTRY = "  - id: {}\n    purls: ['{}']\n    expired_at: 2026-12-31\n    statement: x\n"


def _reviewed_ignore_with(old: str, new: str) -> dict[str, str]:
    assert _REVIEWED_IGNORE.count(old) == 1, f"The fixture must contain {old!r} one time."
    return {IGNORE_FILE: _REVIEWED_IGNORE.replace(old, new)}


@pytest.mark.parametrize(
    ("files", "expected"),
    [
        pytest.param({IGNORE_FILE: _REVIEWED_IGNORE}, [], id="reviewed"),
        pytest.param(
            _reviewed_ignore_with("    purls:\n      - pkg:deb/debian/zlib1g\n", ""),
            ["ignore entry keys ['expired_at', 'id', 'statement']", "ignore entries"],
            id="no-purls",
        ),
        pytest.param(
            _reviewed_ignore_with("debian/zlib1g", "debian/minizip"),
            ["ignore entries"],
            id="other-purl",
        ),
        pytest.param(
            _reviewed_ignore_with("2027-01-18", "2099-01-01"), ["ignore entries"], id="other-expiry"
        ),
        pytest.param(
            _reviewed_ignore_with("    expired_at: 2027-01-18\n", ""),
            ["ignore entry keys ['id', 'purls', 'statement']", "ignore entries"],
            id="no-expiry",
        ),
        pytest.param(
            _reviewed_ignore_with("zlib1g does not contain minizip.", "''"),
            ["ignore entry CVE-2023-45853 has no statement"],
            id="empty-statement",
        ),
        pytest.param(
            {IGNORE_FILE: _REVIEWED_IGNORE + "    paths: [usr/lib]\n"},
            ["ignore entry keys ['expired_at', 'id', 'paths', 'purls', 'statement']"],
            id="extra-key",
        ),
        pytest.param(
            {IGNORE_FILE: _REVIEWED_IGNORE + _EXTRA_ENTRY.format("CVE-2099-0001", "pkg:deb/x/y")},
            ["ignore entries"],
            id="extra-cve",
        ),
        pytest.param(
            {
                IGNORE_FILE: _REVIEWED_IGNORE
                + _EXTRA_ENTRY.format("CVE-2026-111497", "pkg:deb/debian/libbrotli1")
            },
            ["ignore entries"],
            id="retired-cve",
        ),
        pytest.param(
            {IGNORE_FILE: _REVIEWED_IGNORE + "misconfigurations:\n  - id: AVD-DS-0002\n"},
            ["ignore file shape"],
            id="extra-section",
        ),
        pytest.param(
            {IGNORE_FILE: "CVE-2023-45853 exp:2027-01-18\n"}, ["ignore file shape"], id="plain-form"
        ),
        pytest.param(
            {IGNORE_FILE: _REVIEWED_IGNORE, ".trivyignore": "CVE-2023-45853\n"},
            [f"unexpected ignore files: ['.trivyignore', '{IGNORE_FILE}']"],
            id="plain-file-kept",
        ),
        pytest.param(
            {IGNORE_FILE: _REVIEWED_IGNORE, "nested/.trivyignore.yaml": _REVIEWED_IGNORE},
            [f"unexpected ignore files: ['{IGNORE_FILE}', 'nested/.trivyignore.yaml']"],
            id="nested-file",
        ),
    ],
)
def test_ignore_file_problems_reject_extra_entries_and_files(files, expected):
    """The ignore check accepts only the reviewed entry in the one reviewed file."""
    problems = ignore_file_problems(files)
    assert problems == expected, f"The ignore check must report {expected}. It reported {problems}."


def _real_ignore_entries():
    return trivyignore_entries((ROOT / IGNORE_FILE).read_text(encoding="utf-8"))


def test_trivy_ignore_is_purl_scoped_and_expires():
    """The real entry names the zlib1g purl and the date 2027-01-18.

    On the `expired_at` date, Trivy reports the CVE again, so the exception expires by itself.
    """
    entries = _real_ignore_entries()
    expected = [("CVE-2023-45853", ("pkg:deb/debian/zlib1g",), datetime.date(2027, 1, 18))]
    assert entries == expected, f"The {IGNORE_FILE} entries must be {expected}, not {entries}."


# This example uses the Trivy package URL format for Debian 12.
_ZLIB1G = "pkg:deb/debian/zlib1g@1.2.13.dfsg-1?arch=amd64&distro=debian-12.12&epoch=1"
_MINIZIP = "pkg:deb/debian/minizip@1.1-8%2Bb1?arch=amd64&distro=debian-12.12"


def test_trivy_ignore_hides_the_reviewed_zlib1g_finding():
    """The real entry must hide CVE-2023-45853 in the Debian zlib1g package."""
    hidden = trivy_ignores(_real_ignore_entries(), "CVE-2023-45853", _ZLIB1G)
    assert hidden, f"The {IGNORE_FILE} entry must hide CVE-2023-45853 in {_ZLIB1G}."


@pytest.mark.parametrize(
    ("cve", "purl"),
    [
        pytest.param("CVE-2023-45853", _MINIZIP, id="minizip"),
        pytest.param(
            "CVE-2023-45853",
            "pkg:deb/debian/libminizip1@1.1-8%2Bb1?arch=amd64&distro=debian-12.12",
            id="libminizip1",
        ),
        pytest.param(
            "CVE-2023-45853", _ZLIB1G.replace("/zlib1g@", "/zlib1g-dev@"), id="zlib1g-dev"
        ),
        pytest.param(
            "CVE-2023-45853", _ZLIB1G.replace("/debian/", "/ubuntu/"), id="other-namespace"
        ),
        pytest.param("CVE-2023-45853", "pkg:cargo/libz-sys@1.1.20", id="other-type"),
        pytest.param("CVE-2099-0001", _ZLIB1G, id="other-cve"),
    ],
)
def test_trivy_ignore_keeps_findings_outside_the_scope_visible(cve, purl):
    """A finding outside the reviewed package scope must remain visible in the scan."""
    hidden = trivy_ignores(_real_ignore_entries(), cve, purl)
    assert not hidden, f"The {IGNORE_FILE} entry must not hide {cve} in {purl}."


@pytest.mark.parametrize(
    ("purls", "purl", "hidden"),
    [
        pytest.param((), _MINIZIP, True, id="no-purls-hide-each-package"),
        pytest.param(("pkg:deb/debian/zlib1g@1.2.11",), _ZLIB1G, False, id="other-version"),
        pytest.param(("pkg:deb/debian/zlib1g@1.2.13.dfsg-1",), _ZLIB1G, True, id="same-version"),
        pytest.param(("pkg:deb/debian/zlib1g?arch=arm64",), _ZLIB1G, False, id="other-arch"),
        pytest.param(("pkg:deb/debian/zlib1g?arch=amd64",), _ZLIB1G, True, id="same-arch"),
    ],
)
def test_trivy_ignore_model_follows_the_trivy_purl_rules(purls, purl, hidden):
    """The scope model must give the Trivy result for each purl rule."""
    result = trivy_ignores([("CVE-2023-45853", purls, None)], "CVE-2023-45853", purl)
    assert result is hidden, f"For the entry purls {purls}, the model must give {hidden} for {purl}."


def _trivy_inputs(workflow: str) -> list[dict]:
    """Return the inputs of each Trivy step of the workflow, in step order."""
    doc = load_workflow((WORKFLOWS / workflow).read_text(encoding="utf-8"))
    return [_step_inputs(workflow, step)[0] for step in iter_use_steps(doc) if _is_trivy_step(step)]


def _sarif_gate_inputs(workflow: str) -> list[dict]:
    return [inputs for inputs in _trivy_inputs(workflow) if _is_sarif_gate(inputs)]


def _fix_state(fixed: bool) -> str:
    return "with a fix" if fixed else "without a fix"


@pytest.mark.parametrize("workflow", sorted(TRIVY_STEP_PLAN))
def test_trivy_steps_follow_the_reviewed_plan(workflow):
    """The Trivy steps of each workflow must have the reviewed severity policies, in order.

    In docker-scan.yml, the table report is the first Trivy step. Thus the job summary
    shows the findings also when a gate fails.
    """
    plan = [trivy_policy(inputs) for inputs in _trivy_inputs(workflow)]
    expected = list(TRIVY_STEP_PLAN[workflow])
    assert plan == expected, f"The {workflow} Trivy steps must be {expected}, not {plan}."


def test_each_pr_scan_trivy_step_sets_ignore_unfixed():
    """Each Trivy step in docker-scan.yml must set ignore-unfixed.

    Thus the workflow file states the policy of each step.
    """
    for inputs in _trivy_inputs("docker-scan.yml"):
        assert "ignore-unfixed" in inputs, (
            f"The Trivy step that writes {inputs.get('output')!r} must set ignore-unfixed."
        )


# Each case gives a workflow, the severity of one finding, the fix state and the result.
# A finding has a fix when a fixed version of the package exists. The ignore file does
# not hide the finding.
_GATE_POLICY_CASES = [
    ("docker-scan.yml", "CRITICAL", True, True),
    ("docker-scan.yml", "CRITICAL", False, True),
    ("docker-scan.yml", "HIGH", True, True),
    ("docker-scan.yml", "HIGH", False, False),
    ("docker-scan.yml", "MEDIUM", True, False),
    ("docker.yml", "CRITICAL", True, True),
    ("docker.yml", "CRITICAL", False, True),
    ("docker.yml", "HIGH", True, True),
    ("docker.yml", "HIGH", False, True),
    ("docker.yml", "MEDIUM", True, False),
]


@pytest.mark.parametrize(
    ("workflow", "severity", "fixed", "fails"),
    [
        pytest.param(*case, id=f"{case[0]}-{case[1].lower()}-{'fixed' if case[2] else 'unfixed'}")
        for case in _GATE_POLICY_CASES
    ],
)
def test_scan_result_follows_the_gate_policy(workflow, severity, fixed, fails):
    """The scan result for one finding must follow the gate policy of the workflow.

    - In docker-scan.yml, each CRITICAL finding fails the scan.
    - In docker-scan.yml, a HIGH finding fails the scan only when it has a fix.
    - In docker.yml, each HIGH and CRITICAL finding fails the scan.
    """
    gates = _sarif_gate_inputs(workflow)
    assert gates, f"{workflow} must have a SARIF gate."
    result = any(scan_fails_for(inputs, severity, fixed) for inputs in gates)
    verdict = "must fail" if fails else "must not fail"
    assert result is fails, (
        f"The {workflow} scan {verdict} for a {severity} finding {_fix_state(fixed)}."
    )


@pytest.mark.parametrize("fixed", [True, False], ids=["fixed", "unfixed"])
@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_table_report_shows_each_high_and_critical_finding(severity, fixed):
    """The docker-scan.yml table report must show each HIGH and CRITICAL finding.

    This includes a finding without a fix. The table report must not gate the job.
    """
    tables = [item for item in _trivy_inputs("docker-scan.yml") if item.get("format") == "table"]
    assert len(tables) == 1, "docker-scan.yml must have one Trivy table report."
    assert trivy_reports(tables[0], severity, fixed), (
        f"The table report must show a {severity} finding {_fix_state(fixed)}."
    )
    assert str(tables[0].get("exit-code")) == "0", "The table report must not gate the job."


@pytest.mark.parametrize(
    ("severity", "exit_code", "ignore_unfixed", "finding", "fixed", "fails"),
    [
        pytest.param("HIGH,CRITICAL", "1", None, "HIGH", True, True, id="high-gated"),
        pytest.param("HIGH,CRITICAL", "1", None, "CRITICAL", True, True, id="critical-gated"),
        pytest.param("HIGH,CRITICAL", "1", None, "MEDIUM", True, False, id="medium-not-gated"),
        pytest.param("CRITICAL", "1", None, "HIGH", True, False, id="critical-only"),
        pytest.param("HIGH", "1", None, "CRITICAL", True, False, id="high-only"),
        pytest.param("HIGH,CRITICAL", "0", None, "CRITICAL", True, False, id="exit-code-0"),
        pytest.param("HIGH", "1", None, "HIGH", False, True, id="default-reports-unfixed"),
        pytest.param("CRITICAL", "1", False, "CRITICAL", False, True, id="unfixed-critical-gated"),
        pytest.param("HIGH", "1", True, "HIGH", True, True, id="fixed-high-gated"),
        pytest.param("HIGH", "1", True, "HIGH", False, False, id="unfixed-high-hidden"),
        pytest.param("HIGH", "1", "true", "HIGH", False, False, id="unfixed-high-hidden-string"),
        pytest.param("CRITICAL", "1", True, "CRITICAL", False, False, id="unfixed-critical-hidden"),
    ],
)
def test_scan_failure_model_reads_severity_exit_code_and_ignore_unfixed(
    severity, exit_code, ignore_unfixed, finding, fixed, fails
):
    """The failure model must give the Trivy result for each combination of inputs.

    The model reads the severity, the exit code and the ignore-unfixed value.
    """
    inputs = {"severity": severity, "exit-code": exit_code}
    if ignore_unfixed is not None:
        inputs["ignore-unfixed"] = ignore_unfixed
    result = scan_fails_for(inputs, finding, fixed)
    assert result is fails, (
        f"For {inputs}, a {finding} finding {_fix_state(fixed)} must give {fails}."
    )


@pytest.mark.parametrize(
    ("comment", "is_version"),
    [
        pytest.param("# vulnerable", False, id="word"),
        pytest.param("# version", False, id="word-with-v"),
        pytest.param("# v", False, id="v-only"),
        pytest.param("# v1", True, id="major"),
        pytest.param("# v3.7.0", True, id="full"),
    ],
)
def test_version_comment_requires_a_numeric_version(comment, is_version):
    """A version comment is `v` and a number. A word after `#` is not a version comment."""
    uses = f"a/b@{'a' * 40}"
    result = _version_comment_ok(f"uses: {uses} {comment}", uses)
    assert result is is_version, f"The result for {comment!r} must be {is_version}."


def _write_action(root: Path, ref: str, steps: str, name: str = "action.yml") -> None:
    folder = root / ref.removeprefix("./")
    folder.mkdir(parents=True, exist_ok=True)
    body = f"name: local\nruns:\n  using: composite\n  steps:\n{steps}"
    (folder / name).write_text(body, encoding="utf-8")


_LOCAL_REF = "./.github/actions/x"
_PINNED = f"third/party@{'a' * 40}"


@pytest.mark.parametrize(
    ("actions", "expected"),
    [
        pytest.param(
            {_LOCAL_REF: "    - uses: third/party@v1\n"},
            [f"{_LOCAL_REF}: third/party@v1"],
            id="unpinned",
        ),
        pytest.param(
            {_LOCAL_REF: f"    - uses: {_PINNED} # v1.2.3\n"},
            [],
            id="pinned",
        ),
        pytest.param(
            {_LOCAL_REF: f"    - uses: {_PINNED} # vulnerable\n"},
            [f"{_LOCAL_REF}: {_PINNED}"],
            id="word-comment",
        ),
        pytest.param(
            {_LOCAL_REF: "    - uses: actions/cache@v4\n"},
            [f"{_LOCAL_REF}: actions/cache@v4"],
            id="first-party",
        ),
        pytest.param({}, [f"{_LOCAL_REF}: action.yml is missing"], id="missing"),
        pytest.param(
            {
                _LOCAL_REF: "    - uses: ./.github/actions/y\n",
                "./.github/actions/y": "    - uses: other/party@main\n",
            },
            ["./.github/actions/y: other/party@main"],
            id="nested",
        ),
        pytest.param({_LOCAL_REF: f"    - uses: {_LOCAL_REF}\n"}, [], id="self-reference"),
    ],
)
def test_pin_check_follows_local_composite_actions(tmp_path, actions, expected):
    """The pin rule also applies to each `uses:` in a local composite action."""
    for ref, steps in actions.items():
        _write_action(tmp_path, ref, steps)
    problems = local_action_problems(tmp_path, _LOCAL_REF)
    assert problems == expected, f"The pin check must report {expected}. It reported {problems}."


def test_pin_check_reads_action_yaml(tmp_path):
    """The pin check also reads a composite action from `action.yaml`."""
    _write_action(tmp_path, _LOCAL_REF, "    - uses: third/party@v1\n", name="action.yaml")
    problems = local_action_problems(tmp_path, _LOCAL_REF)
    expected = [f"{_LOCAL_REF}: third/party@v1"]
    assert problems == expected, f"The pin check must report {expected}. It reported {problems}."


def _workflow_uses() -> list[tuple[Path, str, str]]:
    return [
        (path, text, normalize_uses(step["uses"]))
        for path, text in _workflow_texts()
        for step in iter_use_steps(load_workflow(text))
    ]


def test_every_action_is_sha_pinned():
    """Each `uses:` must have a commit SHA and a version comment.

    No action is exempt. A tag ref, for example `@v4`, fails this test.
    """
    failures: list[str] = []
    for path, text, uses in _workflow_uses():
        if uses.startswith("./"):
            failures.extend(local_action_problems(ROOT, uses))
        else:
            failures.extend(_pin_problem(path.name, text, uses))
    assert failures == [], f"{len(failures)} actions have no SHA pin:\n" + "\n".join(failures)


def test_every_workflow_has_top_level_permissions():
    problems = [
        f"{path.name}: {problem}"
        for path, text in _workflow_texts()
        for problem in top_level_permission_problems(load_workflow(text))
    ]
    assert problems == [], f"Each workflow must set exactly contents: read at the top: {problems}"


@pytest.mark.parametrize(
    ("permissions", "allowed"),
    [
        pytest.param("permissions:\n  contents: read\n", True, id="contents-read"),
        pytest.param(
            "permissions:\n  contents: read\n  packages: write\n", False, id="extra-write-scope"
        ),
        pytest.param("permissions:\n  contents: write\n", False, id="contents-write"),
        pytest.param("permissions: read-all\n", False, id="read-all"),
        pytest.param("", False, id="missing"),
    ],
)
def test_top_level_permissions_are_exactly_contents_read(permissions, allowed):
    """The top-level permissions must be `contents: read` and no other scope."""
    doc = load_workflow(f"name: fixture\non: push\n{permissions}jobs: {{}}\n")
    problems = top_level_permission_problems(doc)
    verdict = "no problem" if allowed else "a problem"
    assert (problems == []) is allowed, (
        f"For {permissions!r}, the check must report {verdict}. It reported {problems}."
    )


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


def test_checkouts_do_not_persist_credentials():
    """Each checkout must set `persist-credentials: false`. No workflow is an exception.

    The pinned `anthropics/claude-code-action` gets its own GitHub token through
    OIDC. It does not use the checkout credential. The claude.yml job must not let
    a user without write access start the action.
    """
    for path, text in _workflow_texts():
        steps = [
            step
            for step in iter_use_steps(load_workflow(text))
            if action_name(step.get("uses")) == "actions/checkout"
        ]
        assert steps, path.name
        for step in steps:
            with_ = step.get("with") or {}
            assert with_.get("persist-credentials") is False, (
                f"Each checkout in {path.name} must set persist-credentials: false."
            )
    claude = load_workflow((WORKFLOWS / "claude.yml").read_text(encoding="utf-8"))
    claude_steps = [
        step
        for step in iter_use_steps(claude)
        if action_name(step.get("uses")) == "anthropics/claude-code-action"
    ]
    assert claude_steps, "claude.yml must run anthropics/claude-code-action."
    for step in claude_steps:
        keys = {str(key).lower() for key in step.get("with") or {}}
        assert "allowed_non_write_users" not in keys, (
            "claude.yml must not set allowed_non_write_users."
        )


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

    assert trivy_gate_problems(docker, "docker.yml") == []
    assert trivy_gate_problems(scan, "docker-scan.yml") == []
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
    sarif_uploads = [
        normalize_uses(step["uses"])
        for step in iter_use_steps(docker)
        if action_name(step["uses"]) == "github/codeql-action/upload-sarif"
    ]
    assert sarif_uploads, "docker.yml must upload the SARIF report."
    for uses in sarif_uploads:
        assert uses_is_sha_pinned(uses), f"docker.yml must pin upload-sarif to a SHA, not {uses}."
        version = _pinned_version(docker_text, uses)
        assert version is not None and version[0] >= 4, (
            f"The upload-sarif SHA must have a v4 or later version comment, not {version}."
        )

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


def _publish_findings_script() -> str:
    scan = load_workflow((WORKFLOWS / "docker-scan.yml").read_text(encoding="utf-8"))
    steps = [
        step
        for step in scan["jobs"]["scan"]["steps"]
        if step.get("name") == "Publish Trivy findings"
    ]
    assert len(steps) == 1, "docker-scan.yml must have one step named Publish Trivy findings."
    return steps[0]["run"]


@pytest.mark.parametrize(
    ("report", "fence"),
    [
        pytest.param("no backticks\n", "```", id="minimum"),
        pytest.param("before\n```\ninside\n```\nafter\n", "````", id="three-backtick-fence"),
        pytest.param("a `````` run\n", "```````", id="six-backtick-run"),
    ],
)
def test_trivy_summary_fence_cannot_be_closed_by_the_report(tmp_path, report, fence):
    """The summary fence is one backtick longer than the longest run in the report.

    The fence has a minimum of three backticks.
    """
    script = tmp_path / "publish.sh"
    script.write_text(_publish_findings_script(), encoding="utf-8")
    (tmp_path / "trivy-rvc.txt").write_text(report, encoding="utf-8")
    summary = tmp_path / "summary.md"
    env = {"PATH": os.environ["PATH"], "TARGET": "rvc", "GITHUB_STEP_SUMMARY": str(summary)}
    subprocess.run(["bash", "-e", str(script)], cwd=tmp_path, env=env, check=True, timeout=60)
    expected = f"### Trivy HIGH and CRITICAL findings (rvc)\n\n{fence}\n{report}{fence}\n"
    actual = summary.read_text(encoding="utf-8")
    assert actual == expected, f"The summary must be {expected!r}, not {actual!r}."


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
    problems = ignore_file_problems(files)
    assert problems == [], f"The ignore files must have no problems. They have {problems}."
    text = files[IGNORE_FILE]
    assert "https://security-tracker.debian.org/tracker/CVE-2023-45853" in text
    assert "2027-01-18" in text
    assert "minizip" in text
    assert "will_not_fix" in text
    # The images no longer install curl, so libbrotli1 is gone with it.
    assert "CVE-2026-111497" not in text
    assert "libbrotli1" not in text


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
    days = (matched[0].get("cooldown") or {}).get("default-days", 0)
    assert days >= 7, "The github-actions entry must set cooldown.default-days to 7 or more."


_RUST_TEST_COMMANDS = ("cargo nextest", "cargo test", "cargo llvm-cov")
_RUST_TEST_JOBS = {
    "check",
    "test-all-features",
    "secret-scan",
    "coverage",
    "arch-gates",
    "spec-vectors",
}


def test_rust_test_jobs_have_a_timeout():
    """Each ci.yml job that runs Rust tests must set timeout-minutes.

    A stuck test then fails the job and does not hold the runner.
    """
    jobs = load_workflow((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))["jobs"]
    test_jobs = {
        name
        for name, job in jobs.items()
        if any(
            command in str(step.get("run", ""))
            for step in job.get("steps") or []
            for command in _RUST_TEST_COMMANDS
        )
    }
    assert test_jobs >= _RUST_TEST_JOBS, (
        f"The scan must find each Rust test job. It found {test_jobs}."
    )
    missing = sorted(
        name
        for name in test_jobs
        if type(jobs[name].get("timeout-minutes")) is not int or jobs[name]["timeout-minutes"] <= 0
    )
    assert missing == [], (
        f"These ci.yml jobs run Rust tests and must set timeout-minutes: {missing}"
    )


def test_nextest_profile_terminates_a_stuck_test():
    """The default nextest profile must stop a test that runs for too long."""
    path = ROOT / ".config" / "nextest.toml"
    assert path.is_file(), "The repository must have .config/nextest.toml."
    profile = tomllib.loads(path.read_text(encoding="utf-8"))["profile"]["default"]
    timeouts = [profile.get("slow-timeout")]
    timeouts += [
        override["slow-timeout"]
        for override in profile.get("overrides", [])
        if "slow-timeout" in override
    ]
    for timeout in timeouts:
        assert isinstance(timeout, dict), f"The slow-timeout {timeout!r} must be a table."
        assert "period" in timeout, f"The slow-timeout {timeout} must set a period."
        after = timeout.get("terminate-after")
        assert type(after) is int and after >= 1, (
            f"The slow-timeout {timeout} must set terminate-after."
        )


DOCTEST_COMMAND = "cargo test --workspace --all-features --doc --locked"


def _make_recipe(target: str) -> list[str]:
    lines = (ROOT / "Makefile").read_text(encoding="utf-8").splitlines()
    start = lines.index(f"{target}:")
    recipe: list[str] = []
    for line in lines[start + 1 :]:
        if not line.startswith("\t"):
            break
        recipe.append(line)
    return recipe


def test_ci_runs_doctests():
    """CI and `make test` must run the doctests, because nextest does not run them."""
    jobs = load_workflow((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))["jobs"]
    runs = [str(step.get("run", "")).strip() for step in jobs["test-all-features"]["steps"]]
    assert DOCTEST_COMMAND in runs, f"The test-all-features job must run {DOCTEST_COMMAND!r}."
    recipe = _make_recipe("test")
    nextest = [index for index, line in enumerate(recipe) if "cargo nextest run" in line]
    doctest = [index for index, line in enumerate(recipe) if DOCTEST_COMMAND in line]
    assert nextest and doctest, (
        f"The Makefile test target must run nextest and {DOCTEST_COMMAND!r}."
    )
    assert doctest[0] > nextest[0], "The Makefile test target must run the doctests after nextest."
