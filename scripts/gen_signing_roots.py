#!/usr/bin/env python3
"""Emit Gloas container and L3 signing-root vectors from eth-ssz-specs.

Pinned to eth-ssz-specs==0.1.0. Imports that package and the stdlib only.
Implements pyspec compute_domain / get_domain / compute_signing_root and the
three Gloas containers using eth-ssz-specs types (the SSZ library pyspec uses
at v1.7.0-beta.0). Fork version, genesis validators root, and spec tag come
from argv. DOMAIN_PTC_ATTESTER / DOMAIN_PROPOSER_PREFERENCES are parsed from
the pinned gloas beacon-chain spec (not hardcoded).

Output path comes from --out (argv); this file must not name a destination.
"""

from __future__ import annotations

import argparse
import re
import sys
from importlib.metadata import version
from pathlib import Path
from subprocess import run

if sys.version_info < (3, 12):
    raise SystemExit(
        f"error: python >= 3.12 required, got {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )

from ssz import Boolean, ByteVector, Container, Root, Uint64, hash_tree_root

SPEC_TAG_RE = re.compile(r"^[A-Za-z0-9._-]+$")
DOMAIN_ROW_RE = re.compile(
    r"`(DOMAIN_PTC_ATTESTER|DOMAIN_PROPOSER_PREFERENCES)`\s*\|\s*"
    r"`DomainType\(['\"]0x([0-9A-Fa-f]{8})['\"]\)`"
)

# Deterministic non-zero objects (not mix_in_length, not a random case).
DATA_BEACON_BLOCK_ROOT = bytes.fromhex("11" * 32)
DATA_SLOT = 1
DATA_PAYLOAD_PRESENT = True
DATA_BLOB_DATA_AVAILABLE = False
MESSAGE_VALIDATOR_INDEX = 7
MESSAGE_SIGNATURE = bytes.fromhex("22" * 96)
PREFS_DEPENDENT_ROOT = bytes.fromhex("33" * 32)
PREFS_PROPOSAL_SLOT = 32
PREFS_VALIDATOR_INDEX = 3
PREFS_FEE_RECIPIENT = bytes.fromhex("44" * 20)
PREFS_TARGET_GAS_LIMIT = 36_000_000


class Bytes4(ByteVector):
    LENGTH = 4


class Bytes20(ByteVector):
    LENGTH = 20


class Bytes96(ByteVector):
    LENGTH = 96


class DomainType(Bytes4):
    pass


class Version(Bytes4):
    pass


class Domain(Root):
    pass


class ExecutionAddress(Bytes20):
    pass


class BLSSignature(Bytes96):
    pass


class ForkData(Container):
    current_version: Version
    genesis_validators_root: Root


class SigningData(Container):
    object_root: Root
    domain: Domain


class PayloadAttestationData(Container):
    beacon_block_root: Root
    slot: Uint64
    payload_present: Boolean
    blob_data_available: Boolean


class PayloadAttestationMessage(Container):
    validator_index: Uint64
    data: PayloadAttestationData
    signature: BLSSignature


class ProposerPreferences(Container):
    dependent_root: Root
    proposal_slot: Uint64
    validator_index: Uint64
    fee_recipient: ExecutionAddress
    target_gas_limit: Uint64


def hex_bytes(node: bytes) -> str:
    return "0x" + bytes(node).hex()


def hex32(node: bytes) -> str:
    raw = bytes(node)
    if len(raw) != 32:
        raise SystemExit(f"error: expected 32-byte node, got {len(raw)}")
    return hex_bytes(raw)


def load_gloas_beacon_chain(spec_tag: str) -> str:
    if not SPEC_TAG_RE.fullmatch(spec_tag) or spec_tag in {".", ".."}:
        raise SystemExit(f"error: invalid spec-tag {spec_tag!r}")
    url = (
        "https://raw.githubusercontent.com/ethereum/consensus-specs/"
        + spec_tag
        + "/specs/gloas/beacon-chain.md"
    )
    result = run(
        [
            "curl",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "-fsSL",
            "--retry",
            "3",
            "--retry-delay",
            "1",
            "--connect-timeout",
            "30",
            url,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        err = (result.stderr or result.stdout or "curl failed").strip()
        raise SystemExit(f"error: failed to fetch gloas beacon-chain spec: {err}")
    if not result.stdout.strip():
        raise SystemExit("error: gloas beacon-chain spec was empty")
    return result.stdout


def parse_domain_types(markdown: str) -> tuple[bytes, bytes]:
    found: dict[str, bytes] = {}
    for match in DOMAIN_ROW_RE.finditer(markdown):
        found[match.group(1)] = bytes.fromhex(match.group(2))
    missing = [
        name
        for name in ("DOMAIN_PTC_ATTESTER", "DOMAIN_PROPOSER_PREFERENCES")
        if name not in found
    ]
    if missing:
        raise SystemExit(
            "error: pyspec gloas beacon-chain.md missing " + ", ".join(missing)
        )
    return found["DOMAIN_PTC_ATTESTER"], found["DOMAIN_PROPOSER_PREFERENCES"]


def parse_hex_bytes(label: str, raw: str, length: int) -> bytes:
    s = raw.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    try:
        out = bytes.fromhex(s)
    except ValueError as exc:
        raise SystemExit(f"error: {label} is not hex: {raw}") from exc
    if len(out) != length:
        raise SystemExit(f"error: {label} must be {length} bytes, got {len(out)}")
    return out


def compute_fork_data_root(current_version: Version, genesis_validators_root: Root) -> Root:
    """pyspec compute_fork_data_root (phase0)."""
    return hash_tree_root(
        ForkData(
            current_version=current_version,
            genesis_validators_root=genesis_validators_root,
        )
    )


def compute_domain(
    domain_type: DomainType,
    fork_version: Version | None = None,
    genesis_validators_root: Root | None = None,
) -> Domain:
    """pyspec compute_domain (phase0)."""
    if fork_version is None:
        fork_version = Version()
    if genesis_validators_root is None:
        genesis_validators_root = Root()
    fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root)
    return Domain(bytes(domain_type) + bytes(fork_data_root)[:28])


def get_domain(
    domain_type: DomainType,
    fork_version: Version,
    genesis_validators_root: Root,
) -> Domain:
    """pyspec get_domain at the current fork (KAT has no BeaconState)."""
    return compute_domain(domain_type, fork_version, genesis_validators_root)


def compute_signing_root(ssz_object: Container, domain: Domain) -> Root:
    """pyspec compute_signing_root (phase0)."""
    return hash_tree_root(
        SigningData(
            object_root=hash_tree_root(ssz_object),
            domain=domain,
        )
    )


def yaml_bool(value: bool) -> str:
    return "true" if value else "false"


def payload_attestation_data() -> PayloadAttestationData:
    return PayloadAttestationData(
        beacon_block_root=Root(DATA_BEACON_BLOCK_ROOT),
        slot=Uint64(DATA_SLOT),
        payload_present=Boolean(DATA_PAYLOAD_PRESENT),
        blob_data_available=Boolean(DATA_BLOB_DATA_AVAILABLE),
    )


def payload_attestation_message(data: PayloadAttestationData) -> PayloadAttestationMessage:
    return PayloadAttestationMessage(
        validator_index=Uint64(MESSAGE_VALIDATOR_INDEX),
        data=data,
        signature=BLSSignature(MESSAGE_SIGNATURE),
    )


def proposer_preferences() -> ProposerPreferences:
    return ProposerPreferences(
        dependent_root=Root(PREFS_DEPENDENT_ROOT),
        proposal_slot=Uint64(PREFS_PROPOSAL_SLOT),
        validator_index=Uint64(PREFS_VALIDATOR_INDEX),
        fee_recipient=ExecutionAddress(PREFS_FEE_RECIPIENT),
        target_gas_limit=Uint64(PREFS_TARGET_GAS_LIMIT),
    )


def emit_yaml(
    spec_tag: str,
    fork_version: Version,
    genesis_validators_root: Root,
    domain_ptc_attester: bytes,
    domain_proposer_preferences: bytes,
) -> str:
    data = payload_attestation_data()
    message = payload_attestation_message(data)
    prefs = proposer_preferences()

    ptc_domain = get_domain(
        DomainType(domain_ptc_attester), fork_version, genesis_validators_root
    )
    prefs_domain = get_domain(
        DomainType(domain_proposer_preferences), fork_version, genesis_validators_root
    )

    data_root = hash_tree_root(data)
    message_root = hash_tree_root(message)
    prefs_root = hash_tree_root(prefs)
    data_signing = compute_signing_root(data, ptc_domain)
    prefs_signing = compute_signing_root(prefs, prefs_domain)

    lines = [
        "# Gloas container roots and L3 signing roots from eth-ssz-specs==0.1.0.",
        "# compute_domain / get_domain / compute_signing_root match pyspec phase0.",
        "# DOMAIN_PTC_ATTESTER / DOMAIN_PROPOSER_PREFERENCES parsed from gloas beacon-chain.md.",
        "# Do not copy mix_in_length-wrapped list roots into this file.",
        "package: eth-ssz-specs==0.1.0",
        f"spec_tag: {spec_tag}",
        f"fork_version: '{hex_bytes(fork_version)}'",
        f"genesis_validators_root: '{hex32(genesis_validators_root)}'",
        f"domain_ptc_attester: '{hex_bytes(domain_ptc_attester)}'",
        f"domain_proposer_preferences: '{hex_bytes(domain_proposer_preferences)}'",
        "containers:",
        "  - name: PayloadAttestationData",
        "    value:",
        f"      beacon_block_root: '0x{DATA_BEACON_BLOCK_ROOT.hex()}'",
        f"      slot: {DATA_SLOT}",
        f"      payload_present: {yaml_bool(DATA_PAYLOAD_PRESENT)}",
        f"      blob_data_available: {yaml_bool(DATA_BLOB_DATA_AVAILABLE)}",
        f"    root: '{hex32(data_root)}'",
        f"    signing_root: '{hex32(data_signing)}'",
        "  - name: PayloadAttestationMessage",
        "    value:",
        f"      validator_index: {MESSAGE_VALIDATOR_INDEX}",
        "      data:",
        f"        beacon_block_root: '0x{DATA_BEACON_BLOCK_ROOT.hex()}'",
        f"        slot: {DATA_SLOT}",
        f"        payload_present: {yaml_bool(DATA_PAYLOAD_PRESENT)}",
        f"        blob_data_available: {yaml_bool(DATA_BLOB_DATA_AVAILABLE)}",
        f"      signature: '0x{MESSAGE_SIGNATURE.hex()}'",
        f"    root: '{hex32(message_root)}'",
        "  - name: ProposerPreferences",
        "    value:",
        f"      dependent_root: '0x{PREFS_DEPENDENT_ROOT.hex()}'",
        f"      proposal_slot: {PREFS_PROPOSAL_SLOT}",
        f"      validator_index: {PREFS_VALIDATOR_INDEX}",
        f"      fee_recipient: '0x{PREFS_FEE_RECIPIENT.hex()}'",
        f"      target_gas_limit: {PREFS_TARGET_GAS_LIMIT}",
        f"    root: '{hex32(prefs_root)}'",
        f"    signing_root: '{hex32(prefs_signing)}'",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Gloas signing-root vectors.")
    parser.add_argument("--out", required=True, help="Destination YAML path")
    parser.add_argument(
        "--fork-version",
        required=True,
        help="4-byte fork version (0x-prefixed hex); recorded in vectors.lock argv",
    )
    parser.add_argument(
        "--genesis-validators-root",
        required=True,
        help="32-byte genesis validators root (0x-prefixed hex); recorded in vectors.lock argv",
    )
    parser.add_argument(
        "--spec-tag",
        required=True,
        help="consensus-specs tag whose gloas beacon-chain.md supplies DOMAIN_*",
    )
    args = parser.parse_args()

    try:
        pkg_ver = version("eth-ssz-specs")
    except Exception as exc:
        raise SystemExit(f"error: eth-ssz-specs==0.1.0 is required ({exc})") from exc
    if pkg_ver != "0.1.0":
        raise SystemExit(f"error: need eth-ssz-specs==0.1.0, got {pkg_ver}")

    fork_version = Version(parse_hex_bytes("fork-version", args.fork_version, 4))
    genesis_validators_root = Root(
        parse_hex_bytes("genesis-validators-root", args.genesis_validators_root, 32)
    )
    domain_ptc_attester, domain_proposer_preferences = parse_domain_types(
        load_gloas_beacon_chain(args.spec_tag)
    )

    body = emit_yaml(
        args.spec_tag,
        fork_version,
        genesis_validators_root,
        domain_ptc_attester,
        domain_proposer_preferences,
    )
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(body, encoding="utf-8", newline="\n")
    tmp.replace(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
