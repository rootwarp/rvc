"""Renderer tests for RVC config.toml / validators.toml (issue 3.2)."""

from __future__ import annotations

import json
import re
import shlex
import stat
from pathlib import Path

from test_devnet_common_sh import COMMON_SH, FIXTURES, assert_no_secret, run_common
from test_devnet_env import ENV_PATH, parse_env

_MNEMONIC = parse_env(ENV_PATH)["MNEMONIC"]
_DEV_ACCOUNT = parse_env(ENV_PATH)["DEV_ACCOUNT"]
_ZERO_FEE = "0x" + "00" * 20

_GENESIS = json.loads((FIXTURES / "bn_genesis.json").read_text(encoding="utf-8"))
_GENESIS_TIME = "".join(str(_GENESIS["data"]["genesis_time"]).split())
_GENESIS_GVR = "".join(str(_GENESIS["data"]["genesis_validators_root"]).split())


def file_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


def strip_at_most_one_0x(value: str) -> str:
    if value.startswith(("0x", "0X")):
        return value[2:]
    return value


def _curl_genesis_stub(tmp_path: Path) -> Path:
    stub = tmp_path / "curl"
    stub.write_text(
        "#!/bin/sh\n"
        f"cat {shlex.quote(str(FIXTURES / 'bn_genesis.json'))}\n",
        encoding="utf-8",
    )
    stub.chmod(0o755)
    return stub


def _keystore_body(pubkey: str) -> str:
    return json.dumps(
        {
            "crypto": {"kdf": {"function": "pbkdf2", "params": {"c": 262144}}},
            "pubkey": pubkey,
            "version": 4,
        },
        separators=(",", ":"),
    ) + "\n"


def plant_rvc_tree(
    data_dir: Path,
    *,
    pubkeys: list[str] | None = None,
    with_manifest: bool = True,
) -> list[str]:
    if pubkeys is None:
        pubkeys = [f"{i:096x}" for i in range(2)]
    keys = data_dir / "keys"
    rvc = keys / "rvc"
    rvc.mkdir(parents=True, exist_ok=True)
    pw_lines: list[str] = []
    validators: list[dict[str, object]] = []
    for i, pk in enumerate(pubkeys):
        bare_file = pk.lower().removeprefix("0x")
        (rvc / f"keystore-0x{bare_file}.json").write_text(
            _keystore_body(pk), encoding="utf-8"
        )
        pw_lines.append(f"0x{pk}=secret-{i}")
        validators.append(
            {
                "index": i,
                "pubkey": f"0x{bare_file}",
                "keystore_path": f"keys/rvc/keystore-0x{bare_file}.json",
            }
        )
    pw_path = rvc / "passwords.txt"
    pw_path.write_text("\n".join(pw_lines) + "\n", encoding="utf-8")
    pw_path.chmod(0o600)
    if with_manifest:
        man = keys / "manifest.json"
        man.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "generated_at": "2026-09-12T00:00:00Z",
                    "validators": validators,
                }
            )
            + "\n",
            encoding="utf-8",
        )
        man.chmod(0o600)
    return pubkeys


def assert_no_password(proc, data_dir: Path) -> None:
    blob = proc.stdout + proc.stderr
    for candidate in (
        data_dir / "keys" / "rvc" / "passwords.txt",
        data_dir / "rvc" / "passwords.txt",
    ):
        if not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8").splitlines():
            if "=" not in line:
                continue
            password = line.split("=", 1)[1]
            if password:
                assert password not in blob
    assert _MNEMONIC not in blob


def _render_env(data_dir: Path, curl: Path | None = None) -> dict[str, str]:
    return {
        "DATA_DIR": str(data_dir),
        "CURL": str(curl) if curl is not None else "/usr/bin/false",
    }


def test_render_config_matches_golden(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o700)
    plant_rvc_tree(data_dir)
    curl = _curl_genesis_stub(tmp_path)
    proc = run_common(
        "resolve_profile fast; render_rvc_config",
        env=_render_env(data_dir, curl),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    assert_no_password(proc, data_dir)

    got = (data_dir / "rvc" / "config.toml").read_text(encoding="utf-8")
    want = (FIXTURES / "expected_config.toml").read_text(encoding="utf-8")
    want = want.replace("__DATA_DIR__", str(data_dir))
    assert got == want
    assert f"genesis_time = {_GENESIS_TIME}" in got
    assert f'genesis_validators_root = "{_GENESIS_GVR}"' in got
    assert _GENESIS_GVR in got
    assert _GENESIS_TIME in got

    validators = (data_dir / "rvc" / "validators.toml").read_text(encoding="utf-8")
    expected_v = (FIXTURES / "expected_validators.toml").read_text(encoding="utf-8")
    assert validators == expected_v
    assert _DEV_ACCOUNT in validators


def test_render_fails_on_unsubstituted_token(tmp_path: Path):
    tmpl = tmp_path / "in.toml"
    out = tmp_path / "out.toml"
    tmpl.write_text('x = "@@FOO@@"\ny = "@@MISSING@@"\n', encoding="utf-8")
    proc = run_common(
        "RENDER_KEYS=(FOO); RENDER_VALS=(bar); "
        f"render_template {shlex.quote(str(tmpl))} {shlex.quote(str(out))}"
    )
    assert proc.returncode != 0
    assert proc.stdout == ""
    assert "MISSING" in proc.stderr
    assert "@@MISSING@@" in proc.stderr
    assert not out.exists()
    assert "envsubst" not in COMMON_SH.read_text(encoding="utf-8")
    assert_no_secret(proc)


def test_render_zero_fee_recipient_exits_2(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o700)
    plant_rvc_tree(data_dir)
    rvc_dir = data_dir / "rvc"
    rvc_dir.mkdir()
    marker = rvc_dir / "config.toml"
    marker.write_text("KEEP\n", encoding="utf-8")
    before = marker.read_bytes()
    proc = run_common(
        f"DEV_ACCOUNT={shlex.quote(_ZERO_FEE)}; resolve_profile fast; render_rvc_config",
        env=_render_env(data_dir),
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "DEV_ACCOUNT" in proc.stderr or "fee_recipient" in proc.stderr
    assert marker.read_bytes() == before
    assert not (data_dir / "rvc" / "validators.toml").exists()
    assert not (data_dir / "rvc" / "passwords.txt").exists()
    assert_no_secret(proc)


def test_render_missing_manifest_exits_2(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o700)
    plant_rvc_tree(data_dir, with_manifest=False)
    curl = _curl_genesis_stub(tmp_path)
    proc = run_common(
        "resolve_profile fast; render_rvc_config",
        env=_render_env(data_dir, curl),
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "manifest.json" in proc.stderr
    assert "02-keys.sh" in proc.stderr
    assert not (data_dir / "rvc").exists()
    assert_no_secret(proc)
    assert_no_password(proc, data_dir)


def test_doppelganger_follows_profile(tmp_path: Path):
    text = COMMON_SH.read_text(encoding="utf-8")
    assert text.count("resolve_profile()") == 1
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o700)
    plant_rvc_tree(data_dir)
    curl = _curl_genesis_stub(tmp_path)
    env = _render_env(data_dir, curl)

    fast = run_common("resolve_profile fast; render_rvc_config", env=env)
    assert fast.returncode == 0, fast.stderr
    fast_config = (data_dir / "rvc" / "config.toml").read_text(encoding="utf-8")
    assert "doppelganger_detection = false" in fast_config
    assert "doppelganger_detection = true" not in fast_config
    assert_no_secret(fast)
    assert_no_password(fast, data_dir)

    safe = run_common("resolve_profile safe; render_rvc_config", env=env)
    assert safe.returncode == 0, safe.stderr
    safe_config = (data_dir / "rvc" / "config.toml").read_text(encoding="utf-8")
    assert "doppelganger_detection = true" in safe_config
    assert_no_secret(safe)
    assert_no_password(safe, data_dir)

    for rel in ("rvc/config.toml", "rvc/validators.toml", "rvc/passwords.txt"):
        path = data_dir / rel
        assert path.is_file(), rel
        assert file_mode(path) == 0o600, (rel, oct(file_mode(path)))
        assert stat.S_ISREG(path.stat().st_mode)


def test_password_keys_match_keystore_pubkey_form(tmp_path: Path):
    mixed = "Ab" + ("cd" * 47)
    assert len(mixed) == 96
    lower = "11" * 48
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o700)
    plant_rvc_tree(data_dir, pubkeys=[mixed, lower])
    curl = _curl_genesis_stub(tmp_path)
    proc = run_common(
        "resolve_profile fast; render_rvc_config",
        env=_render_env(data_dir, curl),
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == ""
    assert_no_secret(proc)
    assert_no_password(proc, data_dir)

    src_pw = data_dir / "keys" / "rvc" / "passwords.txt"
    dest_pw = data_dir / "rvc" / "passwords.txt"
    assert dest_pw.is_file()
    assert file_mode(dest_pw) == 0o600
    assert dest_pw.read_bytes() == src_pw.read_bytes()

    ks_dir = data_dir / "keys" / "rvc"
    keystores = {
        p: json.loads(p.read_text(encoding="utf-8"))["pubkey"]
        for p in ks_dir.glob("keystore-*.json")
        if p.is_file()
    }
    used: set[Path] = set()
    for line in dest_pw.read_text(encoding="utf-8").splitlines():
        if not line or "=" not in line:
            continue
        key, _password = line.split("=", 1)
        stripped = strip_at_most_one_0x(key)
        matches = [path for path, pk in keystores.items() if pk == stripped]
        assert len(matches) == 1, (key, stripped, matches)
        assert stripped == keystores[matches[0]]
        used.add(matches[0])
    assert used == set(keystores)

    config = (data_dir / "rvc" / "config.toml").read_text(encoding="utf-8")
    match = re.search(r'^keystore_path = "(.*)"$', config, re.M)
    assert match, config
    assert Path(match.group(1)).resolve() == (data_dir / "keys" / "rvc").resolve()
    assert match.group(1).endswith("/keys/rvc") or match.group(1).endswith("/keys/rvc/")


def test_copy_600_refuses_source_and_parent_symlinks(tmp_path: Path):
    real_src = tmp_path / "src-real"
    real_src.mkdir()
    src_file = real_src / "passwords.txt"
    src_file.write_text("0xab=secret\n", encoding="utf-8")
    src_file.chmod(0o600)
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    dest = dest_dir / "passwords.txt"

    src_link = tmp_path / "src-file-link"
    src_link.symlink_to(src_file)
    proc = run_common(
        f"_copy_600 {shlex.quote(str(src_link))} {shlex.quote(str(dest))}"
    )
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert not dest.exists()
    assert_no_secret(proc)

    src_parent_link = tmp_path / "src-dir-link"
    src_parent_link.symlink_to(real_src)
    proc = run_common(
        "_copy_600 "
        f"{shlex.quote(str(src_parent_link / 'passwords.txt'))} "
        f"{shlex.quote(str(dest))}"
    )
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert not dest.exists()


def test_copy_600_refuses_dest_and_parent_symlinks(tmp_path: Path):
    src = tmp_path / "passwords.txt"
    src.write_text("0xab=secret\n", encoding="utf-8")
    src.chmod(0o600)
    victim = tmp_path / "victim"
    victim.write_text("untouched\n", encoding="utf-8")

    dest_link = tmp_path / "dest-link"
    dest_link.symlink_to(victim)
    proc = run_common(
        f"_copy_600 {shlex.quote(str(src))} {shlex.quote(str(dest_link))}"
    )
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert dest_link.is_symlink()
    assert victim.read_text(encoding="utf-8") == "untouched\n"

    real_dest = tmp_path / "dest-real"
    real_dest.mkdir()
    dest_parent_link = tmp_path / "dest-dir-link"
    dest_parent_link.symlink_to(real_dest)
    proc = run_common(
        "_copy_600 "
        f"{shlex.quote(str(src))} "
        f"{shlex.quote(str(dest_parent_link / 'passwords.txt'))}"
    )
    assert proc.returncode == 2
    assert "symlink" in proc.stderr
    assert not (real_dest / "passwords.txt").exists()
    assert_no_secret(proc)


def test_render_chmods_existing_world_writable_rvc_dir(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o700)
    plant_rvc_tree(data_dir)
    rvc_dir = data_dir / "rvc"
    rvc_dir.mkdir()
    rvc_dir.chmod(0o777)
    curl = _curl_genesis_stub(tmp_path)
    proc = run_common(
        "resolve_profile fast; render_rvc_config",
        env=_render_env(data_dir, curl),
    )
    assert proc.returncode == 0, proc.stderr
    assert file_mode(rvc_dir) == 0o700
    assert file_mode(rvc_dir / "passwords.txt") == 0o600
    assert file_mode(rvc_dir / "config.toml") == 0o600
    assert_no_secret(proc)
    assert_no_password(proc, data_dir)


def test_render_rejects_newline_or_token_in_value(tmp_path: Path):
    tmpl = tmp_path / "in.toml"
    out = tmp_path / "out.toml"
    tmpl.write_text('x = "@@FOO@@"\n', encoding="utf-8")
    nl = run_common(
        "RENDER_KEYS=(FOO); RENDER_VALS=($'a\\nb'); "
        f"render_template {shlex.quote(str(tmpl))} {shlex.quote(str(out))}"
    )
    assert nl.returncode == 2
    assert "newline" in nl.stderr or "@@" in nl.stderr
    assert not out.exists()
    tok = run_common(
        "RENDER_KEYS=(FOO); RENDER_VALS=('x@@BAR@@y'); "
        f"render_template {shlex.quote(str(tmpl))} {shlex.quote(str(out))}"
    )
    assert tok.returncode == 2
    assert "@@" in tok.stderr
    assert not out.exists()
    set_nl = run_common("_render_set FOO $'a\\nb'")
    assert set_nl.returncode == 2
    assert "newline" in set_nl.stderr or "@@" in set_nl.stderr
    assert_no_secret(nl)
    assert_no_secret(tok)


def test_render_rejects_nondigit_metrics_port(tmp_path: Path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    data_dir.chmod(0o700)
    plant_rvc_tree(data_dir)
    curl = _curl_genesis_stub(tmp_path)
    proc = run_common(
        "RVC_METRICS_PORT='8080;pwn=1'; resolve_profile fast; render_rvc_config",
        env=_render_env(data_dir, curl),
    )
    assert proc.returncode == 2
    assert proc.stdout == ""
    assert "RVC_METRICS_PORT" in proc.stderr
    assert not (data_dir / "rvc").exists()
    assert_no_secret(proc)
    assert_no_password(proc, data_dir)
