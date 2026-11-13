"""Structural gates for action pins, workflow permissions, the Trivy gate and CI test limits."""

from __future__ import annotations

import os
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"

# First-party actions stay on major tags. Pinning them is a follow-up; the
# predicate below still rejects an unpinned first-party `uses:` so a fixture
# can prove the rule. The repo scan exempts these prefixes.
_FIRST_PARTY = ("actions/", "github/")

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
    ".trivyignore",
    "scripts/docker-cargo-features.sh",
    ".cargo/config.toml",
}

TARGET_EXPR = "${{ matrix.target }}"
SCAN_REF = f"{TARGET_EXPR}:scan"

# Each reviewed exception with its Trivy expiry option. On that date Trivy stops
# ignoring the CVE, and the image scan turns red until a review renews the entry.
ALLOWED_IGNORED_CVES = [("CVE-2023-45853", "exp:2027-01-18")]

# The only inputs that a Trivy step can set. A new input needs a review of this set.
TRIVY_ALLOWED_INPUTS = frozenset(
    {
        "image-ref",
        "format",
        "output",
        "severity",
        "exit-code",
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


def _version_comment_ok(text: str, uses: str) -> bool:
    sha = uses.rsplit("@", 1)[-1]
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if sha in line and _VERSION_COMMENT_RE.search(line):
            return True
    return False


def _pin_problem(label: str, text: str, uses: str) -> list[str]:
    """Return a problem when a third-party `uses:` has no SHA pin or no version comment."""
    if action_name(uses).startswith(_FIRST_PARTY):
        return []
    if uses_is_sha_pinned(uses) and _version_comment_ok(text, uses):
        return []
    return [f"{label}: {uses}"]


def local_action_problems(root: Path, ref: str, seen: frozenset[str] = frozenset()) -> list[str]:
    """Pin problems in the local composite action at `ref` and in the local actions it uses."""
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


def _ignore_unfixed_enabled(with_: dict) -> bool:
    if "ignore-unfixed" not in with_:
        return False
    value = with_["ignore-unfixed"]
    if value is False:
        return False
    return not (isinstance(value, str) and value.strip().lower() == "false")


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
    if inputs.get("trivyignores") != ".trivyignore":
        problems.append(f"{where}: trivyignores")
    if inputs.get("severity") != "CRITICAL":
        problems.append(f"{where}: severity")
    if _ignore_unfixed_enabled(inputs):
        problems.append(f"{where}: ignore-unfixed")
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
    """Problems in the Trivy jobs of one parsed workflow. YAML comments do not count.

    `workflow` is the workflow file name. It selects the reviewed job `if`. The
    Trivy inputs, the image, and the steps before the gate are allow-lists.
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


def trivyignore_entries(text: str) -> list[tuple[str, str]]:
    """Read the id and the options, for example `exp:2027-01-18`, of each entry."""
    entries: list[tuple[str, str]] = []
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if fields:
            entries.append((fields[0], " ".join(fields[1:])))
    return entries


def ignore_file_problems(files: dict[str, str]) -> list[str]:
    problems: list[str] = []
    if sorted(files) != [".trivyignore"]:
        problems.append(f"unexpected ignore files: {sorted(files)}")
    if trivyignore_entries(files.get(".trivyignore", "")) != ALLOWED_IGNORED_CVES:
        problems.append("ignore entries")
    return problems


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
          severity: CRITICAL
          exit-code: '1'
          limit-severities-for-sarif: true
          trivyignores: .trivyignore
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
        "          severity: CRITICAL\n",
        "          severity: LOW\n          Severity: CRITICAL\n",
    )
    problems = trivy_gate_problems(load_workflow(text))
    expected = f"scan: {_TRIVY_FIXTURE_USES}: case-only duplicate input Severity"
    assert expected in problems, f"The gate must report {expected!r}. It reported {problems}."
    mixed = _reviewed_trivy_step("").replace("severity: CRITICAL", "Severity: CRITICAL")
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
    ("Ignore-Unfixed", "true"),
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


def test_trivy_config_files_are_rejected():
    assert trivy_config_file_problems([]) == []
    for name in ["trivy.yaml", "trivy.yml", "nested/trivy.yaml"]:
        assert trivy_config_file_problems([name]) == [f"trivy config file: {name}"]
    assert trivy_config_file_problems(discover_trivy_config_files()) == []


def test_ignore_file_problems_reject_extra_entries_and_files():
    reviewed = "# note\n" + "".join(f"{cve} {options}\n" for cve, options in ALLOWED_IGNORED_CVES)
    assert ignore_file_problems({".trivyignore": reviewed}) == []
    for entry in ("CVE-2023-45853\n", "CVE-2023-45853 exp:2099-01-01\n"):
        problems = ignore_file_problems({".trivyignore": "# note\n" + entry})
        assert problems == ["ignore entries"], (
            f"The entry {entry!r} must not pass without a review."
        )
    extra = ignore_file_problems({".trivyignore": reviewed + "CVE-2099-0001\n"})
    assert extra == ["ignore entries"]
    retired = ignore_file_problems(
        {".trivyignore": reviewed + "CVE-2026-111497 exp:2026-12-31\n"}
    )
    assert retired == ["ignore entries"]
    other = ignore_file_problems(
        {
            ".trivyignore": reviewed,
            "nested/extra.trivyignore": reviewed,
        }
    )
    assert any("unexpected ignore files" in item for item in other)


def test_trivyignore_entry_expires_on_the_review_date():
    """Trivy stops ignoring the CVE on its `exp:` date, so the exception expires by itself."""
    text = (ROOT / ".trivyignore").read_text(encoding="utf-8")
    entries = trivyignore_entries(text)
    expected = [("CVE-2023-45853", "exp:2027-01-18")]
    assert entries == expected, f"The .trivyignore entries must be {expected}, not {entries}."


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
            [],
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


def test_every_third_party_action_is_sha_pinned():
    failures: list[str] = []
    for path, text in _workflow_texts():
        for step in iter_use_steps(load_workflow(text)):
            uses = normalize_uses(step["uses"])
            if uses.startswith("./"):
                failures.extend(local_action_problems(ROOT, uses))
                continue
            failures.extend(_pin_problem(path.name, text, uses))
    assert failures == [], f"{len(failures)} unpinned third-party actions:\n" + "\n".join(
        failures
    )


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


def test_checkouts_do_not_persist_credentials_except_claude():
    """Each checkout must set `persist-credentials: false`. claude.yml is the one exception.

    Decision 4 (#868) removes the exception only after a review confirms that the
    pinned `anthropics/claude-code-action` does not use the checkout credential.
    The action runs git commands on the checkout. The W4-T1 change could not read
    the action source, so the exception stays. The claude.yml job must not let a
    user without write access start the action.
    """
    for path, text in _workflow_texts():
        doc = load_workflow(text)
        steps = [
            step
            for step in iter_use_steps(doc)
            if action_name(step.get("uses")) == "actions/checkout"
        ]
        if path.name == "claude.yml":
            for step in steps:
                assert "persist-credentials" not in (step.get("with") or {})
            claude_steps = [
                step
                for step in iter_use_steps(doc)
                if action_name(step.get("uses")) == "anthropics/claude-code-action"
            ]
            assert claude_steps, "claude.yml must run anthropics/claude-code-action."
            for step in claude_steps:
                keys = {str(key).lower() for key in step.get("with") or {}}
                assert "allowed_non_write_users" not in keys, (
                    "claude.yml must not set allowed_non_write_users."
                )
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
        major = int(uses.rsplit("@v", 1)[-1].split(".")[0])
        assert major >= 4, f"docker.yml must use upload-sarif v4 or later, not {uses}."

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
    expected = f"### Trivy CRITICAL findings (rvc)\n\n{fence}\n{report}{fence}\n"
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
    assert ignore_file_problems(files) == []
    text = files[".trivyignore"]
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
