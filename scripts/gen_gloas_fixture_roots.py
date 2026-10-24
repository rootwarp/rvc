#!/usr/bin/env python3
"""Hash a self-build Gloas body, block, and bound envelope with eth-ssz-specs.

The unmodified body and envelope are the official ssz_static minimal
`ssz_random/case_0` bytes at consensus-specs v1.7.0-beta.2 (read from a
checked-in spec module). This script refuses to emit a rewritten root unless
`hash_tree_root` of those bytes equals the published root in the same module.

The rewrite sets the bid (and the envelope) the way a self-build fixture does:
`builder_index = 2**64-1`, the fixture slot, and the fixture beacon parent.
The block root is `hash_tree_root` of the BeaconBlock whose body is that
rewrite. The envelope's `beacon_block_root` is that block root.

Pinned package: eth-ssz-specs==0.1.0. Stdlib and that package only.
Does not name a destination path.
"""

from __future__ import annotations

import argparse
import re
import sys
from importlib.metadata import version

if sys.version_info < (3, 12):
    raise SystemExit(
        f"error: python >= 3.12 required, got {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )

from ssz import (
    BitVector,
    Boolean,
    Byte,
    ByteList,
    ByteVector,
    Container,
    ProgressiveBitList,
    ProgressiveContainer,
    ProgressiveList,
    Root,
    Uint64,
    Uint256,
    Vector,
    active_fields,
    hash_tree_root,
)

PRESETS = {
    "minimal": {"committees": 4, "sync": 32, "ptc": 16},
    "mainnet": {"committees": 64, "sync": 512, "ptc": 512},
}


class Bytes20(ByteVector):
    LENGTH = 20


class Bytes32(ByteVector):
    LENGTH = 32


class Bytes48(ByteVector):
    LENGTH = 48


class Bytes96(ByteVector):
    LENGTH = 96


class LogsBloom(ByteVector):
    LENGTH = 256


class ExtraData(ByteList):
    LIMIT = 32


class AggregationBits(ProgressiveBitList):
    pass


class Transaction(ProgressiveList[Byte]):
    pass


class Transactions(ProgressiveList[Transaction]):
    pass


class BlockAccessList(ProgressiveList[Byte]):
    pass


class KzgCommitments(ProgressiveList[Bytes48]):
    pass


class Checkpoint(Container):
    epoch: Uint64
    root: Root


class AttestationData(Container):
    slot: Uint64
    index: Uint64
    beacon_block_root: Root
    source: Checkpoint
    target: Checkpoint


class Eth1Data(Container):
    deposit_root: Root
    deposit_count: Uint64
    block_hash: Root


class BeaconBlockHeader(Container):
    slot: Uint64
    proposer_index: Uint64
    parent_root: Root
    state_root: Root
    body_root: Root


class SignedBeaconBlockHeader(Container):
    message: BeaconBlockHeader
    signature: Bytes96


class ProposerSlashing(Container):
    signed_header_1: SignedBeaconBlockHeader
    signed_header_2: SignedBeaconBlockHeader


class DepositData(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    amount: Uint64
    signature: Bytes96


class DepositProof(Vector[Bytes32]):
    LENGTH = 33


class Deposit(Container):
    proof: DepositProof
    data: DepositData


class VoluntaryExit(Container):
    epoch: Uint64
    validator_index: Uint64


class SignedVoluntaryExit(Container):
    message: VoluntaryExit
    signature: Bytes96


class BlsToExecutionChange(Container):
    validator_index: Uint64
    from_bls_pubkey: Bytes48
    to_execution_address: Bytes20


class SignedBlsToExecutionChange(Container):
    message: BlsToExecutionChange
    signature: Bytes96


class DepositRequest(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    amount: Uint64
    signature: Bytes96
    index: Uint64


class WithdrawalRequest(Container):
    source_address: Bytes20
    validator_pubkey: Bytes48
    amount: Uint64


class ConsolidationRequest(Container):
    source_address: Bytes20
    source_pubkey: Bytes48
    target_pubkey: Bytes48


class BuilderDepositRequest(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    amount: Uint64
    signature: Bytes96


class BuilderExitRequest(Container):
    source_address: Bytes20
    pubkey: Bytes48


class Withdrawal(Container):
    index: Uint64
    validator_index: Uint64
    address: Bytes20
    amount: Uint64


class ProposerSlashings(ProgressiveList[ProposerSlashing]):
    pass


class Deposits(ProgressiveList[Deposit]):
    pass


class VoluntaryExits(ProgressiveList[SignedVoluntaryExit]):
    pass


class BlsChanges(ProgressiveList[SignedBlsToExecutionChange]):
    pass


class DepositRequests(ProgressiveList[DepositRequest]):
    pass


class WithdrawalRequests(ProgressiveList[WithdrawalRequest]):
    pass


class ConsolidationRequests(ProgressiveList[ConsolidationRequest]):
    pass


class BuilderDepositRequests(ProgressiveList[BuilderDepositRequest]):
    pass


class BuilderExitRequests(ProgressiveList[BuilderExitRequest]):
    pass


class Withdrawals(ProgressiveList[Withdrawal]):
    pass


class IndexedAttestation(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(3)
    attesting_indices: ProgressiveList[Uint64]
    data: AttestationData
    signature: Bytes96


class AttesterSlashing(Container):
    attestation_1: IndexedAttestation
    attestation_2: IndexedAttestation


class AttesterSlashings(ProgressiveList[AttesterSlashing]):
    pass


class PayloadAttestationData(Container):
    beacon_block_root: Root
    slot: Uint64
    payload_present: Boolean
    blob_data_available: Boolean


class ExecutionRequests(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(5)
    deposits: DepositRequests
    withdrawals: WithdrawalRequests
    consolidations: ConsolidationRequests
    builder_deposits: BuilderDepositRequests
    builder_exits: BuilderExitRequests


class ExecutionPayloadBid(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(12)
    parent_block_hash: Root
    parent_block_root: Root
    block_hash: Root
    prev_randao: Root
    fee_recipient: Bytes20
    gas_limit: Uint64
    builder_index: Uint64
    slot: Uint64
    value: Uint64
    execution_payment: Uint64
    blob_kzg_commitments: KzgCommitments
    execution_requests_root: Root


class SignedExecutionPayloadBid(Container):
    message: ExecutionPayloadBid
    signature: Bytes96


class ExecutionPayload(ProgressiveContainer):
    ACTIVE_FIELDS = active_fields(19)
    parent_hash: Root
    fee_recipient: Bytes20
    state_root: Root
    receipts_root: Root
    logs_bloom: LogsBloom
    prev_randao: Root
    block_number: Uint64
    gas_limit: Uint64
    gas_used: Uint64
    timestamp: Uint64
    extra_data: ExtraData
    base_fee_per_gas: Uint256
    block_hash: Root
    transactions: Transactions
    withdrawals: Withdrawals
    blob_gas_used: Uint64
    excess_blob_gas: Uint64
    block_access_list: BlockAccessList
    slot_number: Uint64


def preset_types(name: str) -> tuple[type, type, type]:
    """BeaconBlockBody, ExecutionPayloadEnvelope, and PayloadAttestation for one preset."""
    cfg = PRESETS[name]

    class CommitteeBits(BitVector):
        LENGTH = cfg["committees"]

    class SyncBits(BitVector):
        LENGTH = cfg["sync"]

    class PtcBits(BitVector):
        LENGTH = cfg["ptc"]

    class SyncAggregate(Container):
        sync_committee_bits: SyncBits
        sync_committee_signature: Bytes96

    class Attestation(ProgressiveContainer):
        ACTIVE_FIELDS = active_fields(4)
        aggregation_bits: AggregationBits
        data: AttestationData
        signature: Bytes96
        committee_bits: CommitteeBits

    class Attestations(ProgressiveList[Attestation]):
        pass

    class PayloadAttestation(ProgressiveContainer):
        ACTIVE_FIELDS = active_fields(3)
        aggregation_bits: PtcBits
        data: PayloadAttestationData
        signature: Bytes96

    class PayloadAttestations(ProgressiveList[PayloadAttestation]):
        pass

    class BeaconBlockBody(ProgressiveContainer):
        ACTIVE_FIELDS = active_fields(13)
        randao_reveal: Bytes96
        eth1_data: Eth1Data
        graffiti: Bytes32
        proposer_slashings: ProposerSlashings
        attester_slashings: AttesterSlashings
        attestations: Attestations
        deposits: Deposits
        voluntary_exits: VoluntaryExits
        sync_aggregate: SyncAggregate
        bls_to_execution_changes: BlsChanges
        signed_execution_payload_bid: SignedExecutionPayloadBid
        payload_attestations: PayloadAttestations
        parent_execution_requests: ExecutionRequests

    class ExecutionPayloadEnvelope(ProgressiveContainer):
        ACTIVE_FIELDS = active_fields(5)
        payload: ExecutionPayload
        execution_requests: ExecutionRequests
        builder_index: Uint64
        beacon_block_root: Root
        parent_beacon_block_root: Root

    class FixtureBeaconBlock(Container):
        slot: Uint64
        proposer_index: Uint64
        parent_root: Root
        state_root: Root
        body: BeaconBlockBody

    return BeaconBlockBody, ExecutionPayloadEnvelope, FixtureBeaconBlock


def module_text(path: str, module: str) -> str:
    text = open(path, encoding="utf-8").read()
    start = text.find(f"pub mod {module} {{")
    if start < 0:
        raise SystemExit(f"error: pub mod {module} not in {path}")
    end = text.find("\npub mod ", start + 1)
    return text[start:] if end < 0 else text[start:end]


def rust_hex_const(module: str, const: str) -> str:
    marker = f"pub const {const}:"
    start = module.find(marker)
    if start < 0:
        raise SystemExit(f"error: missing {const}")
    decl = module[start:].split(";", 1)[0]
    if "concat!(" in decl:
        body = decl.split("concat!(", 1)[1]
        parts = re.findall(r'"([0-9a-fA-F]*)"', body)
        hex_text = "".join(parts)
    else:
        found = re.findall(r'"([0-9a-fA-F]+)"', decl)
        if len(found) != 1:
            raise SystemExit(f"error: {const} is not one hex string")
        hex_text = found[0]
    if len(hex_text) % 2 != 0:
        raise SystemExit(f"error: {const} hex length {len(hex_text)} is odd")
    return hex_text


def require_root(got: bytes, expected_hex: str, label: str) -> None:
    if got.hex() != expected_hex:
        raise SystemExit(
            f"error: {label} hash {got.hex()} != published {expected_hex}; schema does not match the vector"
        )


def main() -> int:
    parser = argparse.ArgumentParser(description="Gloas self-build fixture roots from eth-ssz-specs.")
    parser.add_argument("--spec-module", required=True, help="Rust module file holding SPEC_*_SSZ constants")
    parser.add_argument("--preset", choices=sorted(PRESETS), default="minimal")
    parser.add_argument("--module", default="minimal", help="pub mod name inside --spec-module")
    parser.add_argument("--slot", type=int, required=True)
    parser.add_argument("--proposer-index", type=int, required=True)
    parser.add_argument("--parent-root", required=True, help="32-byte hex, no 0x")
    parser.add_argument("--state-root", required=True, help="32-byte hex, no 0x")
    parser.add_argument("--builder-index", type=int, required=True)
    args = parser.parse_args()

    try:
        pkg = version("eth-ssz-specs")
    except Exception as exc:
        raise SystemExit(f"error: eth-ssz-specs==0.1.0 is required ({exc})") from exc
    if pkg != "0.1.0":
        raise SystemExit(f"error: need eth-ssz-specs==0.1.0, got {pkg}")

    parent = bytes.fromhex(args.parent_root)
    state = bytes.fromhex(args.state_root)
    if len(parent) != 32 or len(state) != 32:
        raise SystemExit("error: parent-root and state-root must be 32 bytes")
    if not 0 <= args.slot < 2**64 or not 0 <= args.proposer_index < 2**64:
        raise SystemExit("error: slot and proposer-index must fit in uint64")
    if not 0 <= args.builder_index < 2**64:
        raise SystemExit("error: builder-index must fit in uint64")

    mod = module_text(args.spec_module, args.module)
    body_ssz = bytes.fromhex(rust_hex_const(mod, "SPEC_GLOAS_BEACON_BLOCK_BODY_SSZ"))
    body_root_hex = rust_hex_const(mod, "SPEC_GLOAS_BEACON_BLOCK_BODY_ROOT")
    envelope_ssz = bytes.fromhex(rust_hex_const(mod, "SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_SSZ"))
    envelope_root_hex = rust_hex_const(mod, "SPEC_GLOAS_EXECUTION_PAYLOAD_ENVELOPE_ROOT")

    body_ty, envelope_ty, block_ty = preset_types(args.preset)
    body = body_ty.decode_bytes(body_ssz)
    require_root(bytes(hash_tree_root(body)), body_root_hex, "unmodified BeaconBlockBody")
    envelope = envelope_ty.decode_bytes(envelope_ssz)
    require_root(bytes(hash_tree_root(envelope)), envelope_root_hex, "unmodified ExecutionPayloadEnvelope")

    bid = body.signed_execution_payload_bid.message
    bid.builder_index = Uint64(args.builder_index)
    bid.slot = Uint64(args.slot)
    bid.parent_block_root = Root(parent)
    body.signed_execution_payload_bid.message = bid

    block = block_ty(
        slot=Uint64(args.slot),
        proposer_index=Uint64(args.proposer_index),
        parent_root=Root(parent),
        state_root=Root(state),
        body=body,
    )
    block_root = hash_tree_root(block)
    body_root = hash_tree_root(body)

    envelope.builder_index = Uint64(args.builder_index)
    envelope.beacon_block_root = Root(bytes(block_root))
    envelope.parent_beacon_block_root = Root(parent)
    envelope_root = hash_tree_root(envelope)

    print(f"package: eth-ssz-specs=={pkg}")
    print("spec_tag: v1.7.0-beta.2")
    print(f"preset: {args.preset}")
    print(f"slot: {args.slot}")
    print(f"proposer_index: {args.proposer_index}")
    print(f"parent_root: {parent.hex()}")
    print(f"state_root: {state.hex()}")
    print(f"builder_index: {args.builder_index}")
    print(f"published_body_root: {body_root_hex}")
    print(f"published_envelope_root: {envelope_root_hex}")
    print(f"self_build_body_root: {bytes(body_root).hex()}")
    print(f"self_build_block_root: {bytes(block_root).hex()}")
    print(f"bound_envelope_root: {bytes(envelope_root).hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
