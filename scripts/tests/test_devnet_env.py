"""Contract tests for scripts/devnet/devnet.env.

Stdlib key=value parse under disable_socket(); no Docker, no network.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ENV_PATH = Path(__file__).resolve().parents[1] / "devnet" / "devnet.env"

IMG_PIN_RE = re.compile(r"^[a-z0-9./-]+:[^@]+@sha256:[0-9a-f]{64}$")
FLOATING_TAG_RE = re.compile(r":(latest|stable|master)")
SHA256_PIN_RE = re.compile(r"@sha256:[0-9a-f]{64}")
BARE_64_HEX_RE = re.compile(r"[0-9a-f]{64}")


def parse_env(path: Path) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].lstrip()
        if "=" not in line:
            raise ValueError(f"not key=value: {raw}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        parsed[key] = value
    return parsed


@pytest.fixture(scope="module")
def env() -> dict[str, str]:
    assert ENV_PATH.is_file(), ENV_PATH
    return parse_env(ENV_PATH)


def test_no_floating_image_tags():
    text = ENV_PATH.read_text(encoding="utf-8")
    match = FLOATING_TAG_RE.search(text)
    assert match is None, f"floating tag: {match.group(0)}"


def test_every_img_pinned_by_index_digest(env: dict[str, str]):
    img = {k: v for k, v in env.items() if k.startswith("IMG_")}
    assert set(img) == {"IMG_GETH", "IMG_LIGHTHOUSE", "IMG_GENESIS"}
    for key, value in img.items():
        assert IMG_PIN_RE.fullmatch(value), f"{key}={value}"
    assert env["IMG_GETH"].startswith("ethereum/client-go:v1.17.5@sha256:")
    assert env["IMG_LIGHTHOUSE"].startswith("sigp/lighthouse:v8.2.2@sha256:")
    assert env["IMG_GENESIS"].startswith(
        "ethpandaops/ethereum-genesis-generator:6.2.1@sha256:"
    )


def test_chain_id_is_1337(env: dict[str, str]):
    assert env["CHAIN_ID"] == "1337"


def test_electra_at_epoch_zero(env: dict[str, str]):
    assert env["ELECTRA_FORK_EPOCH"] == "0"


def test_rvc_keys_less_than_num_validators(env: dict[str, str]):
    n = int(env["NUM_VALIDATORS"])
    k = int(env["RVC_KEYS"])
    assert n == 64
    assert k == 16
    assert k < n


def test_no_bare_64_hex_literal():
    text = ENV_PATH.read_text(encoding="utf-8")
    stripped = SHA256_PIN_RE.sub("", text)
    match = BARE_64_HEX_RE.search(stripped)
    assert match is None, f"bare 64-hex literal: {match.group(0)}"


def test_required_platforms_matrix(env: dict[str, str]):
    assert env["REQUIRED_PLATFORMS"].split() == ["linux/amd64", "linux/arm64"]
