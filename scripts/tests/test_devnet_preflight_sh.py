"""Contract tests for scripts/devnet/00-preflight.sh.

DOCKER stubs are scratch scripts (P1-A8); disable_socket() via conftest autouse.
Phase 6's 6.1 extends this file with the DN-19 index-entry matrix.
"""

from __future__ import annotations

import os
import re
import shlex
import stat
import subprocess
from pathlib import Path

import pytest

from test_devnet_env import ENV_PATH, IMG_PIN_RE, parse_env

PREFLIGHT = Path(__file__).resolve().parents[1] / "devnet" / "00-preflight.sh"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

_ISOLATE_KEYS = (
    "DOCKER",
    "CURL",
    "RUN_DIR",
    "FORCE",
    "PROFILE",
    "DRY_RUN",
    "INTERACTIVE",
    "DEVNET_STAGE_DIR",
    "DATA_DIR",
    "RUNS_DIR",
    "CHAIN_ID",
    "EPOCHS",
    "DOPPELGANGER",
    "FAIL_UNDER",
    "IMG_GETH",
    "IMG_LIGHTHOUSE",
    "IMG_GENESIS",
    "REQUIRED_PLATFORMS",
    "PREFLIGHT_MIN_CPUS",
    "PREFLIGHT_MIN_RAM_GIB",
    "PREFLIGHT_MIN_FREE_GIB",
)

_MNEMONIC = "test test test test test test test test test test test junk"

_DAEMON_STDERR = "STUB_DAEMON_STDERR_UNIQUE: cannot connect to unix:///var/run/docker.sock"


def _images() -> dict[str, str]:
    env = parse_env(ENV_PATH)
    return {k: v for k, v in env.items() if k.startswith("IMG_")}


def _manifest_fixture(name: str) -> Path:
    path = Path(name)
    if not path.is_absolute():
        path = FIXTURES / name
    if not path.is_file():
        raise FileNotFoundError(path)
    return path


def write_docker_stub(
    tmp_path: Path,
    *,
    inspect_ok: bool = True,
    info_ok: bool = True,
    pull_ok: bool = True,
    info_stderr: str = "",
    info_format: str = "",
    server_os: str = "linux",
    server_arch: str = "arm64",
    manifest_fixture: str = "manifest__multiarch.json",
    manifest_ok: bool = True,
    imagetools_ok: bool = False,
    imagetools_fixture: str | None = None,
    manifest_stderr: str = "",
    imagetools_stderr: str = "",
) -> tuple[Path, Path]:
    log = tmp_path / "docker.log"
    stub = tmp_path / "docker"
    manifest_path = _manifest_fixture(manifest_fixture)
    tools_path = _manifest_fixture(imagetools_fixture or manifest_fixture)
    platform = f"{server_os}/{server_arch}"
    stub.write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log))}\n"
        "cmd=\"$1\"\n"
        "shift || true\n"
        "case \"$cmd\" in\n"
        "  version)\n"
        f"    printf '%s\\n' {shlex.quote(platform)}\n"
        "    exit 0\n"
        "    ;;\n"
        "  info)\n"
        f"    if [ {0 if info_ok else 1} -ne 0 ]; then\n"
        f"      printf '%s\\n' {shlex.quote(info_stderr)} >&2\n"
        "    fi\n"
        "    if [ \"${1:-}\" = --format ]; then\n"
        f"      printf '%s\\n' {shlex.quote(info_format)}\n"
        "    fi\n"
        f"    exit {0 if info_ok else 1}\n"
        "    ;;\n"
        "  image)\n"
        "    if [ \"${1:-}\" = inspect ]; then\n"
        f"      exit {0 if inspect_ok else 1}\n"
        "    fi\n"
        "    exit 0\n"
        "    ;;\n"
        "  pull)\n"
        f"    exit {0 if pull_ok else 1}\n"
        "    ;;\n"
        "  manifest)\n"
        "    if [ \"${1:-}\" = inspect ]; then\n"
        f"      if [ {0 if manifest_ok else 1} -ne 0 ]; then\n"
        f"        printf '%s\\n' {shlex.quote(manifest_stderr)} >&2\n"
        "        exit 1\n"
        "      fi\n"
        f"      cat -- {shlex.quote(str(manifest_path))} || exit 1\n"
        "      exit 0\n"
        "    fi\n"
        "    exit 1\n"
        "    ;;\n"
        "  buildx)\n"
        f"    if [ {0 if imagetools_ok else 1} -ne 0 ]; then\n"
        f"      printf '%s\\n' {shlex.quote(imagetools_stderr)} >&2\n"
        "      exit 1\n"
        "    fi\n"
        f"    cat -- {shlex.quote(str(tools_path))} || exit 1\n"
        "    exit 0\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub, log


def path_hiding(tool: str, tmp_path: Path) -> str:
    """PATH with `tool` removed; other binaries from its dir are re-homed."""
    shadow = tmp_path / f"shadow-{tool}"
    shadow.mkdir()
    parts: list[str] = [str(shadow)]
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        if not raw:
            continue
        directory = Path(raw)
        candidate = directory / tool
        if candidate.exists() or candidate.is_symlink():
            try:
                for item in directory.iterdir():
                    dest = shadow / item.name
                    if item.name == tool or dest.exists():
                        continue
                    if item.is_file() or item.is_symlink():
                        dest.symlink_to(item)
            except OSError:
                continue
            continue
        parts.append(raw)
    return os.pathsep.join(parts)


def preflight_env(
    tmp_path: Path,
    extra: dict[str, str] | None = None,
    *,
    docker: Path | None = None,
) -> dict[str, str]:
    full = os.environ.copy()
    for key in _ISOLATE_KEYS:
        full.pop(key, None)
    full["DOCKER"] = str(docker or (tmp_path / "docker"))
    full["CURL"] = "/bin/echo"
    full["DATA_DIR"] = str(tmp_path / "data")
    full["RUNS_DIR"] = str(tmp_path / "runs")
    # Hermetic on CI runners that may have < 4 CPU / < 8 GiB / < 20 GiB free.
    full["PREFLIGHT_MIN_CPUS"] = "0"
    full["PREFLIGHT_MIN_RAM_GIB"] = "0"
    full["PREFLIGHT_MIN_FREE_GIB"] = "0"
    if extra:
        full.update(extra)
    return full


def run_preflight(
    tmp_path: Path,
    args: list[str] | tuple[str, ...] = (),
    *,
    env: dict[str, str] | None = None,
    inspect_ok: bool = True,
    info_ok: bool = True,
    pull_ok: bool = True,
    info_stderr: str = "",
    info_format: str = "",
    server_os: str = "linux",
    server_arch: str = "arm64",
    manifest_fixture: str = "manifest__multiarch.json",
    manifest_ok: bool = True,
    imagetools_ok: bool = False,
    imagetools_fixture: str | None = None,
    manifest_stderr: str = "",
    imagetools_stderr: str = "",
    timeout: float = 15,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    stub, log = write_docker_stub(
        tmp_path,
        inspect_ok=inspect_ok,
        info_ok=info_ok,
        pull_ok=pull_ok,
        info_stderr=info_stderr,
        info_format=info_format,
        server_os=server_os,
        server_arch=server_arch,
        manifest_fixture=manifest_fixture,
        manifest_ok=manifest_ok,
        imagetools_ok=imagetools_ok,
        imagetools_fixture=imagetools_fixture,
        manifest_stderr=manifest_stderr,
        imagetools_stderr=imagetools_stderr,
    )
    full = preflight_env(tmp_path, env, docker=stub)
    return (
        subprocess.run(
            ["bash", str(PREFLIGHT), *args],
            capture_output=True,
            text=True,
            env=full,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        ),
        log,
    )


def stub_cmds(log: Path) -> list[str]:
    if not log.is_file():
        return []
    return [line for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]


def pull_cmds(cmds: list[str]) -> list[str]:
    out: list[str] = []
    for c in cmds:
        first = c.split(None, 1)[0] if c.strip() else ""
        if first == "pull":
            out.append(c)
    return out


def inspect_cmds(cmds: list[str]) -> list[str]:
    return [c for c in cmds if c.startswith("image inspect -- ")]


def assert_pull_images_not_entered(log: Path) -> None:
    """image inspect is pull_images's first docker call; empty ⇒ gate died first."""
    cmds = stub_cmds(log)
    assert pull_cmds(cmds) == []
    assert inspect_cmds(cmds) == []


def assert_no_secret(proc: subprocess.CompletedProcess[str]) -> None:
    blob = proc.stdout + proc.stderr
    assert _MNEMONIC not in blob


def test_preflight_sh_exists_and_syntax():
    assert PREFLIGHT.is_file(), PREFLIGHT
    proc = subprocess.run(
        ["bash", "-n", str(PREFLIGHT)], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stderr
    text = PREFLIGHT.read_text(encoding="utf-8")
    assert re.search(r"\bread\b", text) is None
    assert '"$DOCKER"' in text
    assert '"$CURL"' in text
    assert "source" in text and "lib/common.sh" in text
    assert IMG_PIN_RE.pattern in text
    assert 'image inspect --' in text
    assert 'pull --' in text
    assert "assert_image_platforms" in text
    main_fn = text[text.index("main() {") :]
    live = re.search(
        r"(?m)^    check_pins\n    assert_image_platforms\n    pull_images\n",
        main_fn,
    )
    assert live is not None, "main() must call assert_image_platforms immediately before pull_images"


def test_inspect_hit_skips_pull(tmp_path: Path):
    proc, log = run_preflight(tmp_path, inspect_ok=True)
    assert proc.returncode == 0, proc.stderr
    cmds = stub_cmds(log)
    assert pull_cmds(cmds) == []
    assert len(inspect_cmds(cmds)) == len(_images())
    assert_no_secret(proc)


def test_inspect_miss_pulls_each_img_once(tmp_path: Path):
    images = _images()
    proc, log = run_preflight(tmp_path, inspect_ok=False)
    assert proc.returncode == 0, proc.stderr
    cmds = stub_cmds(log)
    pulls = pull_cmds(cmds)
    assert len(pulls) == len(images)
    for value in images.values():
        assert any(value in line for line in pulls), value
    assert_no_secret(proc)


@pytest.mark.parametrize("tool", ["jq", "openssl", "python3"])
def test_missing_tool_exits_2_naming_tool(tmp_path: Path, tool: str):
    proc, log = run_preflight(
        tmp_path,
        env={"PATH": path_hiding(tool, tmp_path)},
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert tool in proc.stderr
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_chain_id_1_exits_2(tmp_path: Path):
    proc, log = run_preflight(tmp_path, env={"CHAIN_ID": "1"})
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "1337" in proc.stderr
    assert "1" in proc.stderr
    assert stub_cmds(log) == []
    assert_no_secret(proc)


def test_unpinned_img_exits_2_without_pull(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        env={"IMG_GETH": "ethereum/client-go:v1.17.5"},
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "IMG_GETH" in proc.stderr
    assert "@sha256:" in proc.stderr
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_dead_daemon_exits_2_without_raw_stderr(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        info_ok=False,
        info_stderr=_DAEMON_STDERR,
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    blob = proc.stdout + proc.stderr
    assert _DAEMON_STDERR not in blob
    assert "Start Docker" in proc.stderr
    error_lines = [
        line for line in proc.stderr.splitlines() if "[ERROR]" in line
    ]
    assert len(error_lines) == 1
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_dry_run_exits_0_inspect_only(tmp_path: Path):
    proc, log = run_preflight(tmp_path, ["--dry-run"], inspect_ok=True)
    assert proc.returncode == 0, proc.stderr
    cmds = stub_cmds(log)
    assert cmds == inspect_cmds(cmds)
    assert pull_cmds(cmds) == []
    assert len(cmds) == len(_images())
    assert "check plan" in proc.stderr
    assert "check_tools" in proc.stderr
    assert "pull_images" in proc.stderr
    assert "would assert_image_platforms (daemon)" in proc.stderr
    assert not any("version -f" in c for c in cmds)
    assert not any("manifest inspect" in c for c in cmds)
    assert_no_secret(proc)


def test_dry_run_inspect_miss_still_skips_pull(tmp_path: Path):
    proc, log = run_preflight(tmp_path, ["--dry-run"], inspect_ok=False)
    assert proc.returncode == 0, proc.stderr
    cmds = stub_cmds(log)
    assert cmds == inspect_cmds(cmds)
    assert pull_cmds(cmds) == []
    assert "would pull" in proc.stderr
    assert_no_secret(proc)


def test_dry_run_catches_broken_pin(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        ["--dry-run"],
        env={"IMG_LIGHTHOUSE": "sigp/lighthouse:v8.2.2"},
    )
    assert proc.returncode == 2
    assert "IMG_LIGHTHOUSE" in proc.stderr
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_pull_failure_exits_1(tmp_path: Path):
    proc, log = run_preflight(tmp_path, inspect_ok=False, pull_ok=False)
    assert proc.returncode == 1
    assert proc.stdout == ""
    assert "failed to pull" in proc.stderr
    assert len(pull_cmds(stub_cmds(log))) >= 1
    assert_no_secret(proc)


def test_low_cpu_exits_2(tmp_path: Path):
    proc, log = run_preflight(tmp_path, env={"PREFLIGHT_MIN_CPUS": "99999"})
    assert proc.returncode == 2
    assert "CPU" in proc.stderr
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_purge_root_not_writable_exits_2(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    data.chmod(0o555)
    try:
        proc, log = run_preflight(tmp_path)
        assert proc.returncode == 2
        assert str(os.getuid()) in proc.stderr or "writable" in proc.stderr
        assert pull_cmds(stub_cmds(log)) == []
        assert_no_secret(proc)
    finally:
        data.chmod(0o755)


def test_second_run_is_noop_without_force(tmp_path: Path):
    proc1, log = run_preflight(tmp_path, inspect_ok=True)
    assert proc1.returncode == 0, proc1.stderr
    first = stub_cmds(log)
    proc2, _ = run_preflight(
        tmp_path,
        inspect_ok=True,
        env={"DOCKER": str(tmp_path / "docker")},
    )
    assert proc2.returncode == 0, proc2.stderr
    second = stub_cmds(log)
    assert pull_cmds(first) == []
    assert pull_cmds(second) == []
    assert len(inspect_cmds(second)) == 2 * len(_images())


def test_umask_does_not_create_world_writable_probe(tmp_path: Path):
    data = tmp_path / "data"
    data.mkdir()
    proc, _ = run_preflight(tmp_path)
    assert proc.returncode == 0, proc.stderr
    leftover = list(data.glob(".preflight-write-*"))
    assert leftover == []
    mode = stat.S_IMODE(data.stat().st_mode)
    assert mode & 0o077 == 0 or mode in (0o755, 0o700, 0o500, 0o555)


def test_purge_root_symlink_exits_2(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    data = tmp_path / "data"
    data.symlink_to(real)
    proc, log = run_preflight(tmp_path)
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_write_probe_does_not_truncate_symlink_target(tmp_path: Path):
    victim = tmp_path / "victim"
    victim.write_text("untouched\n", encoding="utf-8")
    data = tmp_path / "data"
    data.mkdir()
    stub, log = write_docker_stub(tmp_path)
    wrapper = tmp_path / "wrap.sh"
    wrapper.write_text(
        "#!/bin/sh\n"
        f"ln -s {shlex.quote(str(victim))} "
        f"{shlex.quote(str(data))}/.preflight-write-$$\n"
        f"exec /bin/bash {shlex.quote(str(PREFLIGHT))} \"$@\"\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)
    proc = subprocess.run(
        [str(wrapper)],
        capture_output=True,
        text=True,
        env=preflight_env(tmp_path, docker=stub),
        timeout=15,
        stdin=subprocess.DEVNULL,
    )
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert victim.read_text(encoding="utf-8") == "untouched\n"
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_preflight_min_cpus_rejects_non_digits(tmp_path: Path):
    marker = tmp_path / "pwned"
    payload = f"ncpu[$(touch {shlex.quote(str(marker))}; printf 0)]"
    proc, log = run_preflight(tmp_path, env={"PREFLIGHT_MIN_CPUS": payload})
    assert proc.returncode == 2
    assert "PREFLIGHT_MIN_CPUS" in proc.stderr
    assert not marker.exists()
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_pin_regex_is_anchored(tmp_path: Path):
    digest = "a" * 64
    proc, log = run_preflight(
        tmp_path,
        env={"IMG_GETH": f"ethereum/client-go:v1.17.5@sha256:{digest}x"},
    )
    assert proc.returncode == 2
    assert "IMG_GETH" in proc.stderr
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_docker_vm_low_ram_exits_2(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        env={"PREFLIGHT_MIN_RAM_GIB": "8", "PREFLIGHT_MIN_CPUS": "0"},
        info_format="8 1073741824",
    )
    assert proc.returncode == 2
    assert "docker VM" in proc.stderr
    assert "RAM" in proc.stderr
    assert pull_cmds(stub_cmds(log)) == []
    assert_no_secret(proc)


def test_preflight_passes_on_multiarch_index(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        server_arch="arm64",
        manifest_fixture="manifest__multiarch.json",
    )
    assert proc.returncode == 0, proc.stderr
    cmds = stub_cmds(log)
    assert pull_cmds(cmds) == []
    inspects = [c for c in cmds if "manifest inspect" in c]
    assert len(inspects) == len(_images())
    for value in _images().values():
        assert any(value in line for line in inspects), value
        assert "@sha256:" in value
    for line in inspects:
        assert "@sha256:" in line
        assert "imagetools" not in line
    assert not any("imagetools" in c for c in cmds)
    assert any(
        "version -f" in c and "Server.Os" in c and "Server.Arch" in c for c in cmds
    )
    assert "image index ok" in proc.stderr
    assert "linux/arm64" in proc.stderr
    assert_no_secret(proc)


def test_preflight_exits_2_on_amd64_only_index(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        inspect_ok=False,
        server_os="linux",
        server_arch="arm64",
        manifest_fixture="manifest__amd64_only.json",
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    err = proc.stderr
    assert "linux/arm64" in err
    assert "IMG_GETH" in err
    assert "ethereum/client-go" in err
    assert "no index entry" in err
    assert "not a multi-arch index" not in err
    assert_pull_images_not_entered(log)
    assert_no_secret(proc)


def test_preflight_exits_2_when_required_platform_missing(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        inspect_ok=False,
        server_os="linux",
        server_arch="amd64",
        manifest_fixture="manifest__amd64_only.json",
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    err = proc.stderr
    assert "linux/arm64" in err
    assert "missing required platform" in err
    assert "IMG_GETH" in err
    assert_pull_images_not_entered(log)
    assert_no_secret(proc)


def test_single_manifest_digest_message(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        inspect_ok=False,
        manifest_fixture="manifest__single.json",
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    err = proc.stderr
    assert "not a multi-arch index" in err
    assert "no index entry" not in err
    assert "missing required platform" not in err
    assert "platform missing" not in err.lower()
    assert "IMG_GETH" in err
    assert_pull_images_not_entered(log)
    assert_no_secret(proc)


def test_preflight_falls_back_to_imagetools(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        manifest_ok=False,
        imagetools_ok=True,
        imagetools_fixture="manifest__multiarch.json",
    )
    assert proc.returncode == 0, proc.stderr
    cmds = stub_cmds(log)
    assert any("manifest inspect" in c for c in cmds)
    tools = [c for c in cmds if "imagetools inspect" in c]
    assert len(tools) == len(_images())
    for value in _images().values():
        assert any(value in line and "@sha256:" in line for line in tools), value
    assert pull_cmds(cmds) == []
    assert "image index ok" in proc.stderr
    assert_no_secret(proc)


def test_unknown_unknown_never_counts_as_platform(tmp_path: Path):
    # linux/amd64 + unknown/unknown only. Host amd64 is in the index; linux/arm64
    # is required and present iff attestation rows were kept as a fill-in.
    proc, log = run_preflight(
        tmp_path,
        inspect_ok=False,
        server_os="linux",
        server_arch="amd64",
        manifest_fixture="manifest__amd64_only.json",
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "linux/arm64" in proc.stderr
    assert "missing required platform" in proc.stderr
    assert "unknown/unknown" not in proc.stderr
    assert_pull_images_not_entered(log)
    assert_no_secret(proc)

    only_dir = tmp_path / "unknown_only"
    only_dir.mkdir()
    only_attest, attest_log = run_preflight(
        only_dir,
        inspect_ok=False,
        server_arch="arm64",
        manifest_fixture="manifest__unknown_only.json",
    )
    assert only_attest.returncode == 2
    assert "not a multi-arch index" in only_attest.stderr
    assert "no index entry" not in only_attest.stderr
    assert_pull_images_not_entered(attest_log)
    assert_no_secret(only_attest)


def test_gate_fails_if_ref_lacks_sha256(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        inspect_ok=False,
        env={"IMG_GETH": "ethereum/client-go:v1.17.5"},
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "IMG_GETH" in proc.stderr
    assert "@sha256:" in proc.stderr
    cmds = stub_cmds(log)
    assert_pull_images_not_entered(log)
    assert not any("manifest inspect" in c for c in cmds)
    assert_no_secret(proc)


def test_preflight_exits_2_when_host_not_in_required(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        inspect_ok=False,
        server_os="linux",
        server_arch="ppc64le",
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "linux/ppc64le" in proc.stderr
    assert "REQUIRED_PLATFORMS" in proc.stderr
    cmds = stub_cmds(log)
    assert_pull_images_not_entered(log)
    assert any("version -f" in c for c in cmds)
    assert not any("manifest inspect" in c for c in cmds)
    assert not any("imagetools" in c for c in cmds)
    assert_no_secret(proc)


def test_cannot_inspect_names_last_error(tmp_path: Path):
    proc, log = run_preflight(
        tmp_path,
        inspect_ok=False,
        manifest_ok=False,
        imagetools_ok=False,
        manifest_stderr="STUB_MANIFEST_ERR: experimental disabled",
        imagetools_stderr="STUB_IMAGETOOLS_ERR: 401 Unauthorized",
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "cannot inspect manifest index" in proc.stderr
    assert "STUB_IMAGETOOLS_ERR: 401 Unauthorized" in proc.stderr
    assert_pull_images_not_entered(log)
    assert_no_secret(proc)
