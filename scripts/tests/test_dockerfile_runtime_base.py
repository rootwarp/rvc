"""These tests check the Dockerfile base images and the Rust build target.

The runtime images use a pinned Alpine image. The builder uses a pinned
cargo-chef image. It compiles musl binaries for the platform of each image,
with a portable CPU baseline and a position-independent executable.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "Dockerfile"
CARGO_CONFIG = ROOT / ".cargo" / "config.toml"

# Each runtime stage has the same name as the binary that it ships.
RUNTIME_STAGES = ("rvc", "rvc-signer", "rvc-keygen")

# The reviewed runtime base uses Alpine 3.24.4 and the digest of its image index.
# The index has linux/amd64 and linux/arm64/v8 manifests. If you change this
# reference, give registry evidence for the two platforms in the pull request.
RUNTIME_BASE = "alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"

# The reviewed builder uses cargo-chef 0.1.78 and Rust 1.97.1 on Alpine 3.24.
# Its image index contains both platforms. If you change this reference,
# record the Rust and cargo-chef versions in the pull request.
BUILDER_BASE = (
    "lukemathwalker/cargo-chef:latest-rust-1.97-alpine3.24"
    "@sha256:980619ec8e88608ad967ee0fb697ed3b3e4368acdbac71e5e85ae61f9e2f1a2a"
)

# The `chef` stage maps the image platform to a Rust target. It writes the
# target triple to RUST_TARGET_FILE for the later stages.
TARGET_MAP_STAGE = "chef"
RUST_TARGET_FILE = "/rust-target"
TARGET_ASSIGNMENT = f'rust_target="$(cat {RUST_TARGET_FILE})"'
TARGET_OPTION = '--target "$rust_target"'

# This map gives the musl target triple for each Docker architecture.
# docker.yml builds linux/amd64 and linux/arm64. The legacy builder does not
# set TARGETARCH, thus the map also accepts the apk architecture names.
MUSL_TARGETS = {
    "amd64": "x86_64-unknown-linux-musl",
    "arm64": "aarch64-unknown-linux-musl",
    "x86_64": "x86_64-unknown-linux-musl",
    "aarch64": "aarch64-unknown-linux-musl",
}

# These stages run cargo chef cook and cargo build.
CARGO_STAGES = ("cook", "builder")

# This map gives the CPU baseline for each musl target. A binary for the
# baseline runs on each CPU of its platform. The value "native" selects the
# CPU of the build host.
PORTABLE_CPU = {
    "x86_64-unknown-linux-musl": "x86-64",
    "aarch64-unknown-linux-musl": "generic",
}

# rustc makes a static PIE for x86_64-unknown-linux-musl. rustc has no static
# PIE for aarch64-unknown-linux-musl, thus the arm64 binaries link musl
# dynamically (crt-static off). A dynamic musl binary is a PIE, and the kernel
# loads it at a random address.
CRT_STATIC = {
    "x86_64-unknown-linux-musl": True,
    "aarch64-unknown-linux-musl": False,
}

# Cargo reads these variables. Each of them can replace the target flags.
_RUSTFLAGS_NAME_RE = re.compile(r"\b[A-Z0-9_]*RUSTFLAGS\b")


def target_rustflags_variable(triple: str) -> str:
    return f"CARGO_TARGET_{triple.upper().replace('-', '_')}_RUSTFLAGS"


# The builder copies the binaries to this directory. The runtime stages copy them from it.
DIST_DIR = "/app/dist"
DIST_MKDIR = f"mkdir -p {DIST_DIR}"
DIST_COPY = "cp " + " ".join(f'"target/$rust_target/release/{name}"' for name in RUNTIME_STAGES) + f" {DIST_DIR}/"

# The runtime images install only these packages. The arm64 binaries also
# need libgcc_s, because they link musl dynamically.
RUNTIME_PACKAGES = {
    "x86_64": {"ca-certificates"},
    "aarch64": {"ca-certificates", "libgcc"},
}

# Each runtime image runs as this non-root user. The uid and the gid are the
# same as in the earlier images, thus the owner of an existing volume does not change.
USER_SETUP = (
    "RUN addgroup -g 10001 rvc && "
    "adduser -u 10001 -G rvc -s /sbin/nologin -D rvc"
)


@dataclass
class Stage:
    name: str
    base: str
    instructions: list[str] = field(default_factory=list)


def dockerfile_stages(text: str) -> list[Stage]:
    """Return the stages of a Dockerfile. Each `\\` continuation is part of one instruction."""
    stages: list[Stage] = []
    pending = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1].rstrip() + " "
            continue
        instruction = pending + stripped
        pending = ""
        words = instruction.split()
        if words[0].upper() == "FROM":
            name = words[3] if len(words) == 4 and words[2].upper() == "AS" else ""
            stages.append(Stage(name, words[1]))
        elif stages:
            stages[-1].instructions.append(instruction)
    return stages


def stage(stages: list[Stage], name: str) -> Stage:
    found = [s for s in stages if s.name == name]
    assert len(found) == 1, f"The Dockerfile must have one `{name}` stage."
    return found[0]


def shell_commands(instruction: str) -> list[str]:
    """Return the commands of a shell-form RUN instruction. The split is at each `&&`."""
    assert instruction.startswith("RUN "), instruction
    return [part.strip() for part in instruction[len("RUN ") :].split("&&")]


def runs(s: Stage) -> list[str]:
    return [i for i in s.instructions if i.startswith("RUN ")]


def stage_chain(stages: list[Stage], name: str) -> list[Stage]:
    """Return the stage and each stage that it starts from. The first stage starts from an image."""
    chain = [stage(stages, name)]
    names = {s.name for s in stages}
    while chain[0].base in names:
        chain.insert(0, stage(stages, chain[0].base))
    return chain


def stage_env(stages: list[Stage], name: str) -> dict[str, str]:
    """Return the ENV values that a stage gets from its own instructions and from its parent stages."""
    env: dict[str, str] = {}
    for s in stage_chain(stages, name):
        for instruction in s.instructions:
            if not instruction.startswith("ENV "):
                continue
            words = shlex.split(instruction[len("ENV ") :])
            if "=" not in words[0]:
                env[words[0]] = " ".join(words[1:])
                continue
            for word in words:
                key, _, value = word.partition("=")
                env[key] = value
    return env


def _flag_list(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    assert isinstance(value, list), value
    return [str(v) for v in value]


def cargo_rustflags(env: dict[str, str], config: dict, triple: str) -> list[str]:
    """Return the flags that Cargo gives rustc for `--target <triple>`.

    Cargo uses the first source that has flags: CARGO_ENCODED_RUSTFLAGS,
    RUSTFLAGS, the target.<triple>.rustflags values, then build.rustflags.
    The target values come from the config file first and then from the
    CARGO_TARGET_<TRIPLE>_RUSTFLAGS variable.
    """
    if env.get("CARGO_ENCODED_RUSTFLAGS"):
        return env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")
    if env.get("RUSTFLAGS", "").strip():
        return env["RUSTFLAGS"].split()
    targets = config.get("target", {})
    cfg_keys = [k for k, v in targets.items() if k.startswith("cfg(") and "rustflags" in v]
    assert not cfg_keys, f"This test does not evaluate target.'cfg(..)'.rustflags: {cfg_keys}"
    flags = _flag_list(targets.get(triple, {}).get("rustflags"))
    flags += _flag_list(env.get(target_rustflags_variable(triple)))
    if flags:
        return flags
    return _flag_list(config.get("build", {}).get("rustflags")) + _flag_list(env.get("CARGO_BUILD_RUSTFLAGS"))


def codegen_options(flags: list[str]) -> list[str]:
    """Return the values of each `-C` and `--codegen` option in a rustc flag list."""
    options = []
    words = iter(flags)
    for word in words:
        if word in ("-C", "--codegen"):
            options.append(next(words, ""))
        elif word.startswith("--codegen="):
            options.append(word[len("--codegen=") :])
        elif word.startswith("-C"):
            options.append(word[len("-C") :])
    return options


def target_cpu(flags: list[str]) -> str:
    """Return the last target-cpu value. rustc uses the last value. Without a value, rustc uses its default."""
    cpus = [o.partition("=")[2] for o in codegen_options(flags) if o.startswith("target-cpu=")]
    return cpus[-1] if cpus else "<default>"


def crt_static(flags: list[str]) -> bool:
    """Return the crt-static setting. The musl targets of rustc enable crt-static by default."""
    enabled = True
    for option in codegen_options(flags):
        if option.startswith("target-feature="):
            for feature in option.partition("=")[2].split(","):
                if feature in ("+crt-static", "-crt-static"):
                    enabled = feature == "+crt-static"
    return enabled


@pytest.fixture(scope="module")
def stages() -> list[Stage]:
    return dockerfile_stages(DOCKERFILE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def cargo_config() -> dict:
    return tomllib.loads(CARGO_CONFIG.read_text(encoding="utf-8"))


def test_stage_parser_joins_continuations_and_skips_comments():
    text = (
        "ARG X=1\n"
        "FROM a:1 AS one\n"
        "RUN apk add \\\n"
        "    # a comment inside the continuation\n"
        "    b \\\n"
        "    && true\n"
        "FROM one AS two\n"
        "USER rvc\n"
    )
    parsed = dockerfile_stages(text)
    assert [(s.name, s.base) for s in parsed] == [("one", "a:1"), ("two", "one")]
    assert parsed[0].instructions == ["RUN apk add b && true"]
    assert shell_commands(parsed[0].instructions[0]) == ["apk add b", "true"]
    assert parsed[1].instructions == ["USER rvc"]


def test_runtime_stages_use_one_pinned_alpine_image(stages):
    for name in RUNTIME_STAGES:
        base = stage(stages, name).base
        assert base == RUNTIME_BASE, f"The `{name}` stage must start from {RUNTIME_BASE}, not {base}."


def test_chef_stage_uses_the_pinned_builder_image(stages):
    base = stage(stages, TARGET_MAP_STAGE).base
    assert base == BUILDER_BASE, f"The `{TARGET_MAP_STAGE}` stage must start from {BUILDER_BASE}, not {base}."


def test_each_external_base_image_is_alpine(stages):
    names = {s.name for s in stages}
    external = [s for s in stages if s.base not in names]
    assert {s.name for s in external} >= {TARGET_MAP_STAGE, *RUNTIME_STAGES}
    for s in external:
        image, _, tag = s.base.partition(":")
        assert image == "alpine" or "alpine" in tag, (
            f"The `{s.name}` stage must start from an Alpine image, not {s.base}."
        )


def test_dockerfile_does_not_name_debian():
    text = DOCKERFILE.read_text(encoding="utf-8")
    for word in ("debian", "bookworm", "apt-get"):
        assert word not in text.lower(), f"The Dockerfile must not contain `{word}`."


def _target_map_script(stages: list[Stage]) -> str:
    writers = [i for i in runs(stage(stages, TARGET_MAP_STAGE)) if RUST_TARGET_FILE in i]
    assert len(writers) == 1, (
        f"The `{TARGET_MAP_STAGE}` stage must have one RUN instruction that writes "
        f"{RUST_TARGET_FILE}: {writers}"
    )
    return writers[0][len("RUN ") :]


def _fake_apk(tmp_path: Path, apk_arch: str) -> tuple[Path, Path]:
    """Make an `apk` stub. It prints the architecture and writes each other call to a log file."""
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    log = tmp_path / "apk.log"
    apk = fake_bin / "apk"
    apk.write_text(
        "#!/bin/sh\n"
        f'if [ "$1" = --print-arch ]; then echo "{apk_arch}"; exit 0; fi\n'
        f'echo "$*" >> "{log}"\n'
    )
    apk.chmod(0o755)
    return fake_bin, log


def _run_target_map(script: str, tmp_path: Path, targetarch: str, apk_arch: str = "") -> tuple:
    """Run the map with `sh`. The map writes the triple to a temporary file, not to the root."""
    out = tmp_path / "rust-target"
    fake_bin, _ = _fake_apk(tmp_path, apk_arch)
    env = {"PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}", "TARGETARCH": targetarch}
    proc = subprocess.run(
        ["sh", "-c", script.replace(RUST_TARGET_FILE, str(out))],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    written = out.read_text(encoding="utf-8").strip() if out.exists() else ""
    return proc.returncode, written, proc.stderr


@pytest.mark.parametrize(
    ("targetarch", "apk_arch", "triple"),
    [
        pytest.param("amd64", "", MUSL_TARGETS["amd64"], id="buildkit-amd64"),
        pytest.param("arm64", "", MUSL_TARGETS["arm64"], id="buildkit-arm64"),
        pytest.param("", "x86_64", MUSL_TARGETS["x86_64"], id="legacy-x86_64"),
        pytest.param("", "aarch64", MUSL_TARGETS["aarch64"], id="legacy-aarch64"),
        pytest.param("amd64", "aarch64", MUSL_TARGETS["amd64"], id="targetarch-first"),
    ],
)
def test_target_map_gives_the_musl_triple(stages, tmp_path, targetarch, apk_arch, triple):
    code, written, stderr = _run_target_map(_target_map_script(stages), tmp_path, targetarch, apk_arch)
    assert code == 0, f"The target map must accept {targetarch or apk_arch}: {stderr}"
    assert written == triple, f"The target map must write {triple} for {targetarch or apk_arch}."


@pytest.mark.parametrize("targetarch", ["arm", "s390x", "riscv64"])
def test_target_map_refuses_other_architectures(stages, tmp_path, targetarch):
    code, written, _ = _run_target_map(_target_map_script(stages), tmp_path, targetarch, "x86_64")
    assert code != 0, f"The target map must fail for {targetarch}."
    assert written == "", f"The target map must not write a triple for {targetarch}."


def test_each_cargo_build_uses_the_mapped_target(stages):
    builds = []
    for s in stages:
        for instruction in runs(s):
            commands = shell_commands(instruction)
            cargo = [i for i, c in enumerate(commands) if c.startswith(("cargo build", "cargo chef cook"))]
            if not cargo:
                continue
            assert TARGET_ASSIGNMENT in commands, (
                f"The `{s.name}` stage must read {RUST_TARGET_FILE} before cargo runs: {instruction}"
            )
            assigned = commands.index(TARGET_ASSIGNMENT)
            assert assigned < cargo[0], (
                f"The `{s.name}` stage must set rust_target before the first cargo command: {instruction}"
            )
            builds.extend((s.name, commands[i]) for i in cargo)
    assert [name for name, _ in builds] == ["cook", "builder", "builder", "builder"], builds
    for name, command in builds:
        assert TARGET_OPTION in command, f"The cargo command in the `{name}` stage must set {TARGET_OPTION}: {command}"


def test_builder_copies_the_three_binaries_to_the_dist_directory(stages):
    builder = runs(stage(stages, "builder"))
    assert len(builder) == 1, f"The builder must have one RUN instruction: {builder}"
    commands = shell_commands(builder[0])
    last_build = max(i for i, c in enumerate(commands) if c.startswith("cargo build"))
    assert commands[last_build + 1 :] == [DIST_MKDIR, DIST_COPY], (
        f"After the last cargo build, the builder must make {DIST_DIR} and then copy the "
        f"three binaries into it: {commands[last_build + 1 :]}"
    )


def test_runtime_stages_copy_the_musl_build_output(stages):
    for name in RUNTIME_STAGES:
        copies = [i for i in stage(stages, name).instructions if i.startswith("COPY ")]
        assert copies == [f"COPY --from=builder {DIST_DIR}/{name} /usr/local/bin/{name}"], (
            f"The `{name}` stage must copy only its binary from {DIST_DIR}: {copies}"
        )


def test_only_the_chef_stage_sets_rust_flags(stages):
    allowed = {target_rustflags_variable(triple) for triple in PORTABLE_CPU}
    setters = []
    for s in stages:
        for instruction in s.instructions:
            names = set(_RUSTFLAGS_NAME_RE.findall(instruction))
            if names:
                setters.append((s.name, instruction.split()[0], names))
    assert setters == [(TARGET_MAP_STAGE, "ENV", allowed)], (
        f"One ENV instruction in the `{TARGET_MAP_STAGE}` stage must set {sorted(allowed)}, "
        f"and no other instruction can set Cargo flags: {setters}"
    )


@pytest.mark.parametrize("triple", sorted(PORTABLE_CPU))
@pytest.mark.parametrize("stage_name", CARGO_STAGES)
def test_image_builds_use_a_portable_cpu_baseline(stages, cargo_config, stage_name, triple):
    flags = cargo_rustflags(stage_env(stages, stage_name), cargo_config, triple)
    assert not any("target-cpu=native" in flag for flag in flags), (
        f"The `{stage_name}` stage must not compile {triple} for the CPU of the build host: {flags}"
    )
    assert target_cpu(flags) == PORTABLE_CPU[triple], (
        f"The `{stage_name}` stage must compile {triple} with target-cpu={PORTABLE_CPU[triple]}: {flags}"
    )


@pytest.mark.parametrize("triple", sorted(CRT_STATIC))
@pytest.mark.parametrize("stage_name", CARGO_STAGES)
def test_image_binaries_are_position_independent(stages, cargo_config, stage_name, triple):
    flags = cargo_rustflags(stage_env(stages, stage_name), cargo_config, triple)
    link = "static" if CRT_STATIC[triple] else "dynamic"
    assert crt_static(flags) == CRT_STATIC[triple], (
        f"The `{stage_name}` stage must link musl as {link} for {triple}: {flags}"
    )


def _package_script(s: Stage) -> str:
    installers = [i for i in runs(s) if re.search(r"\bapk\b", i)]
    assert len(installers) == 1, f"The `{s.name}` stage must have one RUN instruction that runs apk: {installers}"
    return installers[0][len("RUN ") :]


@pytest.mark.parametrize("apk_arch", sorted(RUNTIME_PACKAGES))
@pytest.mark.parametrize("name", RUNTIME_STAGES)
def test_runtime_stages_install_only_the_required_packages(stages, tmp_path, name, apk_arch):
    fake_bin, log = _fake_apk(tmp_path, apk_arch)
    proc = subprocess.run(
        ["sh", "-c", _package_script(stage(stages, name))],
        env={"PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, f"The package step of the `{name}` stage must pass on {apk_arch}: {proc.stderr}"
    calls = [line.split() for line in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
    assert calls[:1] == [["upgrade", "--no-cache"]], (
        f"The `{name}` stage must upgrade the base packages first on {apk_arch}: {calls}"
    )
    added = set()
    for words in calls[1:]:
        assert words[:2] == ["add", "--no-cache"], (
            f"The `{name}` stage must add packages with `apk add --no-cache`: {words}"
        )
        added.update(words[2:])
    expected = RUNTIME_PACKAGES[apk_arch]
    assert added == expected, f"The `{name}` stage must install only {sorted(expected)} on {apk_arch}: {sorted(added)}"


def test_runtime_stages_keep_the_non_root_user_and_entrypoint(stages):
    for name in RUNTIME_STAGES:
        instructions = stage(stages, name).instructions
        assert USER_SETUP in instructions, f"The `{name}` stage must make the user rvc with uid 10001 and gid 10001."
        assert instructions[-2:] == ["USER rvc", f'ENTRYPOINT ["/usr/local/bin/{name}"]'], (
            f"The `{name}` stage must end with USER rvc and the {name} ENTRYPOINT."
        )
