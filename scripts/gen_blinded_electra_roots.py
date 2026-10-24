#!/usr/bin/env python3
"""Remerkleable roots for blinded Electra fixtures and two attestation-data rows.

Consensus-specs preset is mainnet (the eth-types body limits). Package
remerkleable is independent of the Rust tree-hash implementation.

Prints:
- the published empty blinded Electra body, checked against the known vector
- the same body with one withdrawal request
- a body whose attestation, committee bits, blob commitment, and withdrawal
  request lists are non-empty
- AttestationData roots for committee index 0 and index 5 (slot 500)
"""

import sys

if sys.version_info < (3, 12):
    raise SystemExit(
        f"error: python >= 3.12 required, got {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )

from importlib.metadata import version

from remerkleable.basic import uint64, uint256
from remerkleable.bitfields import Bitlist, Bitvector
from remerkleable.byte_arrays import ByteVector, Bytes32, Bytes48, Bytes96, ByteList

Bytes20 = ByteVector[20]
from remerkleable.complex import Container, List

# Published empty blinded Electra body (graffiti rvc-sec6d-blinded-electra!!!!).
PUBLISHED_EMPTY = "e9e9fd39cc7fc4345e43bf31af21838d9389767cf62c0f8fdaf740b06d26f3e7"


class Eth1Data(Container):
    deposit_root: Bytes32
    deposit_count: uint64
    block_hash: Bytes32


class Checkpoint(Container):
    epoch: uint64
    root: Bytes32


class AttestationData(Container):
    slot: uint64
    index: uint64
    beacon_block_root: Bytes32
    source: Checkpoint
    target: Checkpoint


class AggregationBits(Bitlist[131072]):
    pass


class CommitteeBits(Bitvector[64]):
    pass


class Attestation(Container):
    aggregation_bits: AggregationBits
    data: AttestationData
    signature: Bytes96
    committee_bits: CommitteeBits


class DummyComposite(Container):
    """Empty-list element. Composite, so the empty root depends only on the limit."""

    index: uint64


class ProposerSlashings(List[DummyComposite, 16]):
    pass


class AttesterSlashings(List[DummyComposite, 1]):
    pass


class Attestations(List[Attestation, 8]):
    pass


class Deposits(List[DummyComposite, 16]):
    pass


class VoluntaryExits(List[DummyComposite, 16]):
    pass


class SyncBits(Bitvector[512]):
    pass


class SyncAggregate(Container):
    sync_committee_bits: SyncBits
    sync_committee_signature: Bytes96


class ExtraData(ByteList[32]):
    pass


class Transactions(List[DummyComposite, 1048576]):
    pass


class Withdrawal(Container):
    index: uint64
    validator_index: uint64
    address: Bytes20
    amount: uint64


class Withdrawals(List[Withdrawal, 16]):
    pass


class LogsBloomBytes(ByteVector[256]):
    pass


class ExecutionPayloadHeaderFixed(Container):
    parent_hash: Bytes32
    fee_recipient: Bytes20
    state_root: Bytes32
    receipts_root: Bytes32
    logs_bloom: LogsBloomBytes
    prev_randao: Bytes32
    block_number: uint64
    gas_limit: uint64
    gas_used: uint64
    timestamp: uint64
    extra_data: ExtraData
    base_fee_per_gas: uint256
    block_hash: Bytes32
    transactions_root: Bytes32
    withdrawals_root: Bytes32
    blob_gas_used: uint64
    excess_blob_gas: uint64


class BlsChanges(List[DummyComposite, 16]):
    pass


class KzgCommitments(List[Bytes48, 4096]):
    pass


class DepositRequest(Container):
    pubkey: Bytes48
    withdrawal_credentials: Bytes32
    amount: uint64
    signature: Bytes96
    index: uint64


class WithdrawalRequest(Container):
    source_address: Bytes20
    validator_pubkey: Bytes48
    amount: uint64


class ConsolidationRequest(Container):
    source_address: Bytes20
    source_pubkey: Bytes48
    target_pubkey: Bytes48


class DepositRequests(List[DepositRequest, 8192]):
    pass


class WithdrawalRequests(List[WithdrawalRequest, 16]):
    pass


class ConsolidationRequests(List[ConsolidationRequest, 2]):
    pass


class ExecutionRequests(Container):
    deposits: DepositRequests
    withdrawals: WithdrawalRequests
    consolidations: ConsolidationRequests


class BlindedBody(Container):
    randao_reveal: Bytes96
    eth1_data: Eth1Data
    graffiti: Bytes32
    proposer_slashings: ProposerSlashings
    attester_slashings: AttesterSlashings
    attestations: Attestations
    deposits: Deposits
    voluntary_exits: VoluntaryExits
    sync_aggregate: SyncAggregate
    execution_payload_header: ExecutionPayloadHeaderFixed
    bls_to_execution_changes: BlsChanges
    blob_kzg_commitments: KzgCommitments
    execution_requests: ExecutionRequests


def b32(byte: int) -> Bytes32:
    return Bytes32(bytes([byte]) * 32)


def empty_body() -> BlindedBody:
    graffiti = b"rvc-sec6d-blinded-electra!!!!" + b"\x00" * 3
    if len(graffiti) != 32:
        raise SystemExit(f"error: graffiti length {len(graffiti)}")
    return BlindedBody(
        randao_reveal=Bytes96(b"\x11" * 96),
        eth1_data=Eth1Data(
            deposit_root=b32(0x22),
            deposit_count=uint64(7),
            block_hash=b32(0x33),
        ),
        graffiti=Bytes32(graffiti),
        proposer_slashings=ProposerSlashings(),
        attester_slashings=AttesterSlashings(),
        attestations=Attestations(),
        deposits=Deposits(),
        voluntary_exits=VoluntaryExits(),
        sync_aggregate=SyncAggregate(
            sync_committee_bits=SyncBits(),
            sync_committee_signature=Bytes96(b"\x44" * 96),
        ),
        execution_payload_header=ExecutionPayloadHeaderFixed(
            parent_hash=b32(0x55),
            fee_recipient=Bytes20(b"\x66" * 20),
            state_root=b32(0x77),
            receipts_root=b32(0x88),
            logs_bloom=LogsBloomBytes(b"\x00" * 256),
            prev_randao=b32(0x99),
            block_number=uint64(12345),
            gas_limit=uint64(30_000_000),
            gas_used=uint64(1_000_000),
            timestamp=uint64(1_700_000_000),
            extra_data=ExtraData(b""),
            base_fee_per_gas=uint256(7),
            block_hash=b32(0xAA),
            transactions_root=Transactions().hash_tree_root(),
            withdrawals_root=Withdrawals().hash_tree_root(),
            blob_gas_used=uint64(0),
            excess_blob_gas=uint64(0),
        ),
        bls_to_execution_changes=BlsChanges(),
        blob_kzg_commitments=KzgCommitments(),
        execution_requests=ExecutionRequests(
            deposits=DepositRequests(),
            withdrawals=WithdrawalRequests(),
            consolidations=ConsolidationRequests(),
        ),
    )


def one_withdrawal() -> WithdrawalRequest:
    return WithdrawalRequest(
        source_address=Bytes20(b"\xab" * 20),
        validator_pubkey=Bytes48(b"\xcd" * 48),
        amount=uint64(32_000_000_000),
    )


def sample_data(index: int) -> AttestationData:
    return AttestationData(
        slot=uint64(500),
        index=uint64(index),
        beacon_block_root=b32(0xAA),
        source=Checkpoint(epoch=uint64(15), root=b32(0xBB)),
        target=Checkpoint(epoch=uint64(16), root=b32(0xCC)),
    )


def main() -> int:
    pkg = version("remerkleable")
    empty = empty_body()
    empty_root = empty.hash_tree_root().hex()
    if empty_root != PUBLISHED_EMPTY:
        raise SystemExit(
            f"error: empty blinded body {empty_root} != published {PUBLISHED_EMPTY}"
        )

    withdrawn = empty_body()
    withdrawn.execution_requests.withdrawals = WithdrawalRequests(one_withdrawal())
    withdrawal_root = withdrawn.hash_tree_root().hex()

    rich = empty_body()
    att = Attestation(
        aggregation_bits=AggregationBits(True, True, True, True, True, True, True, True),
        data=sample_data(0),
        signature=Bytes96(b"\xaa" * 96),
        committee_bits=CommitteeBits([True] + [False] * 63),
    )
    rich.attestations = Attestations(att)
    rich.blob_kzg_commitments = KzgCommitments(Bytes48(b"\xab" * 48))
    rich.execution_requests.withdrawals = WithdrawalRequests(one_withdrawal())
    nonempty_root = rich.hash_tree_root().hex()

    print(f"package: remerkleable=={pkg}")
    print("preset: mainnet")
    print("spec: electra BeaconBlockBody blinded (execution_payload_header)")
    print(f"empty_body_root: {empty_root}")
    print(f"withdrawal_body_root: {withdrawal_root}")
    print(f"nonempty_body_root: {nonempty_root}")
    print(f"attestation_data_index_0: {sample_data(0).hash_tree_root().hex()}")
    print(f"attestation_data_index_5: {sample_data(5).hash_tree_root().hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
