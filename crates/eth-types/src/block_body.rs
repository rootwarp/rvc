//! Typed SSZ `BeaconBlockBody` containers for body-leaf `hash_tree_root` (SEC-6).
//!
//! Production per-fork full + blinded bodies and shared sub-containers with
//! `TreeHash` (via `tree_hash_derive`) and SSZ Encode/Decode (via `ssz08` =
//! ethereum_ssz 0.8, matching `ssz_types` trait impls).
//!
//! Wire `Vec<u8>` bodies still live on [`crate::BeaconBlock`]; SEC-6c/6d decode
//! them via the Electra or Deneb typed body (and blinded counterparts) inside
//! `try_tree_hash_root` for the body leaf.
//!
//! Design (see `plan/security-2026-07-18/spike-sec6-block-body-htr.md`):
//! hand-typed per-fork containers via `tree_hash_derive` + `ssz_types`
//! (`VariableList` / `FixedVector` / `BitVector`) — not a full consensus-types
//! library. Encode/Decode use ethereum_ssz **0.8** because `ssz_types` 0.10.1
//! implements those traits against 0.8 only (workspace `ssz` remains 0.9).
//!
//! Body-variant matrix (SEC-6d):
//! - [`BeaconBlockBodyElectra`] / [`BlindedBeaconBlockBodyElectra`] — 13 fields
//! - [`BeaconBlockBodyDeneb`] / [`BlindedBeaconBlockBodyDeneb`] — 12 fields
//!   (no `execution_requests`; pre-Electra attestation limits/types)
//!
//! # Dual SSZ — Path C (one struct per container)
//!
//! Crate-root types carry both workspace `ssz` 0.9 and `ssz08` 0.8
//! `Encode`/`Decode`. Typed bodies still encode through `ssz08` because
//! `ssz_types` 0.10.1 implements those traits against 0.8 only.
//!
//! Isomorphic containers (primitive / already-aliased fields) use
//! `ssz_container! { impl Type { fields… } }`. JSON `Vec<u8>` fields that are
//! spec bitlist / bitvector / Bytes96 get **custom** impls — naive decorate
//! encodes `Vec<u8>` as List[byte] (variable signature / committee bits).
//!
//! **Path C landed ARCH-7h, 2026-08-18, baseline `ce9048c`.** Do not
//! reintroduce encode/decode-facing twins. Path A (`ssz_types` 0.11+ /
//! workspace `tree_hash` 0.10) and Path B (drop `ssz` 0.9) are not required;
//! see `docs/forks.md` §3 and
//! `plan/architecture-2026-08-12/measurements/wire-twins-spike.md`.

use ssz08::{Decode, DecodeError, Encode, SszDecoderBuilder, SszEncoder, BYTES_PER_LENGTH_OFFSET};
use ssz_types::{
    typenum::{
        U1, U1048576, U1073741824, U128, U131072, U16, U2, U2048, U256, U32, U33, U4096, U512, U64,
        U8, U8192,
    },
    BitList, BitVector, FixedVector, VariableList,
};
use thiserror::Error;
use tree_hash::{Hash256, PackedEncoding, TreeHash, TreeHashType};
use tree_hash_derive::TreeHash;

// ---------------------------------------------------------------------------
// Mainnet preset bounds (consensus-specs presets/mainnet)
// ---------------------------------------------------------------------------

/// `MAX_PROPOSER_SLASHINGS`
pub type MaxProposerSlashings = U16;
/// `MAX_ATTESTER_SLASHINGS` (phase0–Deneb)
pub type MaxAttesterSlashings = U2;
/// `MAX_ATTESTER_SLASHINGS_ELECTRA`
pub type MaxAttesterSlashingsElectra = U1;
/// `MAX_ATTESTATIONS` (phase0–Deneb)
pub type MaxAttestations = U128;
/// `MAX_ATTESTATIONS_ELECTRA`
pub type MaxAttestationsElectra = U8;
/// `MAX_DEPOSITS`
pub type MaxDeposits = U16;
/// `MAX_VOLUNTARY_EXITS`
pub type MaxVoluntaryExits = U16;
/// `MAX_BLS_TO_EXECUTION_CHANGES`
pub type MaxBlsToExecutionChanges = U16;
/// `MAX_BLOB_COMMITMENTS_PER_BLOCK`
pub type MaxBlobCommitmentsPerBlock = U4096;
/// `SYNC_COMMITTEE_SIZE`
pub type SyncCommitteeSize = U512;
/// `BYTES_PER_LOGS_BLOOM`
pub type BytesPerLogsBloom = U256;
/// `MAX_EXTRA_DATA_BYTES`
pub type MaxExtraDataBytes = U32;
/// `MAX_BYTES_PER_TRANSACTION`
pub type MaxBytesPerTransaction = U1073741824;
/// `MAX_TRANSACTIONS_PER_PAYLOAD`
pub type MaxTransactionsPerPayload = U1048576;
/// `MAX_WITHDRAWALS_PER_PAYLOAD`
pub type MaxWithdrawalsPerPayload = U16;
/// `MAX_DEPOSIT_REQUESTS_PER_PAYLOAD`
pub type MaxDepositRequestsPerPayload = U8192;
/// `MAX_WITHDRAWAL_REQUESTS_PER_PAYLOAD`
pub type MaxWithdrawalRequestsPerPayload = U16;
/// `MAX_CONSOLIDATION_REQUESTS_PER_PAYLOAD`
pub type MaxConsolidationRequestsPerPayload = U2;
/// `DEPOSIT_CONTRACT_TREE_DEPTH + 1` (Deposit.proof length)
pub type DepositProofLength = U33;
/// `MAX_VALIDATORS_PER_COMMITTEE` (phase0–Deneb attestation bitlist / indices)
pub type MaxValidatorsPerCommittee = U2048;
/// `MAX_VALIDATORS_PER_COMMITTEE * MAX_COMMITTEES_PER_SLOT` (= 131072)
pub type MaxValidatorsPerSlot = U131072;
/// `MAX_COMMITTEES_PER_SLOT`
pub type MaxCommitteesPerSlot = U64;

// ---------------------------------------------------------------------------
// Decode errors (public surface for Vec<u8> → typed body)
// ---------------------------------------------------------------------------

/// Error decoding a typed `BeaconBlockBody` (or sub-container) from SSZ bytes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BodySszError {
    #[error("invalid SSZ body encoding: {0}")]
    InvalidEncoding(String),
    /// Gloas has no body decoder yet; fail closed rather than `Ok(vec![])`.
    #[error("Gloas BeaconBlockBody layout is not supported")]
    GloasUnsupported,
}

impl From<DecodeError> for BodySszError {
    fn from(err: DecodeError) -> Self {
        BodySszError::InvalidEncoding(format!("{err:?}"))
    }
}

// ---------------------------------------------------------------------------
// SSZ container Encode/Decode helper (ethereum_ssz 0.8 trait surface)
// ---------------------------------------------------------------------------

/// `ssz08::{Encode, Decode}` for an existing container (Path C decorate-macro).
///
/// Field order is merkleization- and serialization-sensitive — keep in sync
/// with the consensus-specs container. Used both by [`ssz_container!`] (new
/// types) and by `ssz_container! { impl ExistingType { … } }` (crate-root
/// types that already carry `ssz` 0.9 + `TreeHash`).
macro_rules! ssz08_codec_impls {
    (
        $ty:ty {
            $(
                $field:ident : $ftype:ty
            ),* $(,)?
        }
    ) => {
        impl Encode for $ty {
            fn is_ssz_fixed_len() -> bool {
                $( <$ftype as Encode>::is_ssz_fixed_len() && )* true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as Encode>::is_ssz_fixed_len() {
                    $( <$ftype as Encode>::ssz_fixed_len() + )* 0
                } else {
                    BYTES_PER_LENGTH_OFFSET
                }
            }

            fn ssz_bytes_len(&self) -> usize {
                if <Self as Encode>::is_ssz_fixed_len() {
                    <Self as Encode>::ssz_fixed_len()
                } else {
                    let mut len = 0usize;
                    $(
                        len += if <$ftype as Encode>::is_ssz_fixed_len() {
                            <$ftype as Encode>::ssz_fixed_len()
                        } else {
                            BYTES_PER_LENGTH_OFFSET + self.$field.ssz_bytes_len()
                        };
                    )*
                    len
                }
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                let offset = $( <$ftype as Encode>::ssz_fixed_len() + )* 0;
                let mut encoder = SszEncoder::container(buf, offset);
                $( encoder.append(&self.$field); )*
                encoder.finalize();
            }
        }

        impl Decode for $ty {
            fn is_ssz_fixed_len() -> bool {
                $( <$ftype as Decode>::is_ssz_fixed_len() && )* true
            }

            fn ssz_fixed_len() -> usize {
                if <Self as Decode>::is_ssz_fixed_len() {
                    $( <$ftype as Decode>::ssz_fixed_len() + )* 0
                } else {
                    BYTES_PER_LENGTH_OFFSET
                }
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                let mut builder = SszDecoderBuilder::new(bytes);
                $( builder.register_type::<$ftype>()?; )*
                let mut decoder = builder.build()?;
                Ok(Self {
                    $( $field: decoder.decode_next()?, )*
                })
            }
        }
    };
}

/// Define an SSZ container struct and its `ssz08::{Encode, Decode}` impls from
/// a single field list (merkleization- and serialization-sensitive order).
///
/// The `impl $ty { fields… }` arm decorates an existing struct (Path C).
macro_rules! ssz_container {
    (
        $(#[$meta:meta])*
        pub struct $ty:ident {
            $(
                $(#[$field_meta:meta])*
                pub $field:ident : $ftype:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $ty {
            $(
                $(#[$field_meta])*
                pub $field: $ftype,
            )*
        }

        ssz08_codec_impls! {
            $ty {
                $($field: $ftype),*
            }
        }
    };

    (
        impl $ty:ty {
            $(
                $field:ident : $ftype:ty
            ),* $(,)?
        }
    ) => {
        ssz08_codec_impls! {
            $ty {
                $($field: $ftype),*
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Primitive wrappers
// ---------------------------------------------------------------------------

/// SSZ `uint256` (little-endian 32 bytes). Matches `alloy_primitives::U256`
/// `TreeHash` used by `tree_hash` 0.9 without pinning a direct alloy version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Uint256(pub [u8; 32]);

impl Uint256 {
    /// Construct from a `u64` (low limb); used by tests and small fixtures.
    pub fn from_u64(v: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&v.to_le_bytes());
        Self(bytes)
    }
}

impl TreeHash for Uint256 {
    fn tree_hash_type() -> TreeHashType {
        TreeHashType::Basic
    }

    fn tree_hash_packed_encoding(&self) -> PackedEncoding {
        PackedEncoding::from(self.0)
    }

    fn tree_hash_packing_factor() -> usize {
        1
    }

    fn tree_hash_root(&self) -> Hash256 {
        Hash256::from(self.0)
    }
}

impl Encode for Uint256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn ssz_bytes_len(&self) -> usize {
        32
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.0);
    }
}

impl Decode for Uint256 {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        32
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let arr = <[u8; 32]>::from_ssz_bytes(bytes)?;
        Ok(Self(arr))
    }
}

/// SSZ `Transaction` = `ByteList[MAX_BYTES_PER_TRANSACTION]`.
pub type Transaction = VariableList<u8, MaxBytesPerTransaction>;
/// SSZ `KZGCommitment` = `Bytes48`.
pub type KzgCommitment = [u8; 48];

// ---------------------------------------------------------------------------
// Shared sub-containers
// ---------------------------------------------------------------------------

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct Eth1Data {
        pub deposit_root: [u8; 32],
        pub deposit_count: u64,
        pub block_hash: [u8; 32],
    }
}

// Path C: crate-root Checkpoint already has ssz 0.9 + TreeHash.
ssz_container! {
    impl crate::Checkpoint {
        epoch: crate::Epoch,
        root: crate::Root,
    }
}

ssz_container! {
    impl crate::AttestationData {
        slot: crate::Slot,
        index: crate::CommitteeIndex,
        beacon_block_root: crate::Root,
        source: crate::Checkpoint,
        target: crate::Checkpoint,
    }
}

ssz_container! {
    impl crate::BeaconBlockHeader {
        slot: crate::Slot,
        proposer_index: u64,
        parent_root: crate::Root,
        state_root: crate::Root,
        body_root: crate::Root,
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct SignedBeaconBlockHeader {
        pub message: crate::BeaconBlockHeader,
        pub signature: [u8; 96],
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct ProposerSlashing {
        pub signed_header_1: SignedBeaconBlockHeader,
        pub signed_header_2: SignedBeaconBlockHeader,
    }
}

ssz_container! {
    /// Pre-Electra (phase0–Deneb) `IndexedAttestation`.
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct IndexedAttestation {
        pub attesting_indices: VariableList<u64, MaxValidatorsPerCommittee>,
        pub data: crate::AttestationData,
        pub signature: [u8; 96],
    }
}

ssz_container! {
    /// Pre-Electra (phase0–Deneb) `AttesterSlashing`.
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct AttesterSlashing {
        pub attestation_1: IndexedAttestation,
        pub attestation_2: IndexedAttestation,
    }
}

// Path C: crate-root Attestation stores JSON `Vec<u8>` for bitlist / Bytes96.
// Naive decorate-macro would encode those as List[byte] (signature becomes a
// variable field). Custom impls treat the existing bytes as spec SSZ.
fn ssz08_bitlist<N: ssz_types::typenum::Unsigned + Clone>(
    bytes: &[u8],
) -> Result<BitList<N>, DecodeError> {
    BitList::<N>::from_ssz_bytes(bytes)
}

fn ssz08_sig96(bytes: &[u8]) -> Result<[u8; 96], DecodeError> {
    <[u8; 96]>::from_ssz_bytes(bytes)
}

fn ssz08_bitvector<N: ssz_types::typenum::Unsigned + Clone>(
    bytes: &[u8],
) -> Result<BitVector<N>, DecodeError> {
    BitVector::<N>::from_ssz_bytes(bytes)
}

/// Variable-length raw bytes for `ssz` 0.9 container fields (bitlist payload).
struct Ssz09VarBytes<'a>(&'a [u8]);

impl ssz::Encode for Ssz09VarBytes<'_> {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        self.0.len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(self.0);
    }
}

struct Ssz09VarBytesOwned(Vec<u8>);

impl ssz::Decode for Ssz09VarBytesOwned {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        Ok(Self(bytes.to_vec()))
    }
}

impl Encode for crate::Attestation {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        BYTES_PER_LENGTH_OFFSET
            + self.aggregation_bits.len()
            + <crate::AttestationData as Encode>::ssz_fixed_len()
            + <[u8; 96] as Encode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let bits = ssz08_bitlist::<MaxValidatorsPerCommittee>(&self.aggregation_bits)
            .expect("Attestation.aggregation_bits must be Bitlist[MAX_VALIDATORS_PER_COMMITTEE]");
        let sig = ssz08_sig96(&self.signature).expect("Attestation.signature must be 96 bytes");
        let offset = <BitList<MaxValidatorsPerCommittee> as Encode>::ssz_fixed_len()
            + <crate::AttestationData as Encode>::ssz_fixed_len()
            + <[u8; 96] as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        encoder.append(&bits);
        encoder.append(&self.data);
        encoder.append(&sig);
        encoder.finalize();
    }
}

impl Decode for crate::Attestation {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<BitList<MaxValidatorsPerCommittee>>()?;
        builder.register_type::<crate::AttestationData>()?;
        builder.register_type::<[u8; 96]>()?;
        let mut decoder = builder.build()?;
        let bits: BitList<MaxValidatorsPerCommittee> = decoder.decode_next()?;
        let data: crate::AttestationData = decoder.decode_next()?;
        let sig: [u8; 96] = decoder.decode_next()?;
        Ok(Self { aggregation_bits: bits.as_ssz_bytes(), data, signature: sig.to_vec() })
    }
}

impl ssz::Encode for crate::Attestation {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        BYTES_PER_LENGTH_OFFSET
            + self.aggregation_bits.len()
            + <crate::AttestationData as ssz::Encode>::ssz_fixed_len()
            + <[u8; 96] as ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let _ = ssz08_bitlist::<MaxValidatorsPerCommittee>(&self.aggregation_bits)
            .expect("Attestation.aggregation_bits must be Bitlist[MAX_VALIDATORS_PER_COMMITTEE]");
        let sig = ssz08_sig96(&self.signature).expect("Attestation.signature must be 96 bytes");
        let offset = BYTES_PER_LENGTH_OFFSET
            + <crate::AttestationData as ssz::Encode>::ssz_fixed_len()
            + <[u8; 96] as ssz::Encode>::ssz_fixed_len();
        let mut encoder = ssz::SszEncoder::container(buf, offset);
        encoder.append(&Ssz09VarBytes(&self.aggregation_bits));
        encoder.append(&self.data);
        encoder.append(&sig);
        encoder.finalize();
    }
}

impl ssz::Decode for crate::Attestation {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<Ssz09VarBytesOwned>()?;
        builder.register_type::<crate::AttestationData>()?;
        builder.register_type::<[u8; 96]>()?;
        let mut decoder = builder.build()?;
        let bits = decoder.decode_next::<Ssz09VarBytesOwned>()?;
        let data: crate::AttestationData = decoder.decode_next()?;
        let sig: [u8; 96] = decoder.decode_next()?;
        ssz08_bitlist::<MaxValidatorsPerCommittee>(&bits.0)
            .map_err(|e| ssz::DecodeError::BytesInvalid(format!("aggregation_bits: {e:?}")))?;
        Ok(Self { aggregation_bits: bits.0, data, signature: sig.to_vec() })
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct IndexedAttestationElectra {
        pub attesting_indices: VariableList<u64, MaxValidatorsPerSlot>,
        pub data: crate::AttestationData,
        pub signature: [u8; 96],
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct AttesterSlashingElectra {
        pub attestation_1: IndexedAttestationElectra,
        pub attestation_2: IndexedAttestationElectra,
    }
}

impl Encode for crate::ElectraAttestation {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        BYTES_PER_LENGTH_OFFSET
            + self.aggregation_bits.len()
            + <crate::AttestationData as Encode>::ssz_fixed_len()
            + <[u8; 96] as Encode>::ssz_fixed_len()
            + <BitVector<MaxCommitteesPerSlot> as Encode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let bits = ssz08_bitlist::<MaxValidatorsPerSlot>(&self.aggregation_bits)
            .expect("ElectraAttestation.aggregation_bits must be Bitlist[MAX_VALIDATORS_PER_SLOT]");
        let sig =
            ssz08_sig96(&self.signature).expect("ElectraAttestation.signature must be 96 bytes");
        let committee = ssz08_bitvector::<MaxCommitteesPerSlot>(&self.committee_bits)
            .expect("ElectraAttestation.committee_bits must be Bitvector[MAX_COMMITTEES_PER_SLOT]");
        let offset = <BitList<MaxValidatorsPerSlot> as Encode>::ssz_fixed_len()
            + <crate::AttestationData as Encode>::ssz_fixed_len()
            + <[u8; 96] as Encode>::ssz_fixed_len()
            + <BitVector<MaxCommitteesPerSlot> as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        encoder.append(&bits);
        encoder.append(&self.data);
        encoder.append(&sig);
        encoder.append(&committee);
        encoder.finalize();
    }
}

impl Decode for crate::ElectraAttestation {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<BitList<MaxValidatorsPerSlot>>()?;
        builder.register_type::<crate::AttestationData>()?;
        builder.register_type::<[u8; 96]>()?;
        builder.register_type::<BitVector<MaxCommitteesPerSlot>>()?;
        let mut decoder = builder.build()?;
        let bits: BitList<MaxValidatorsPerSlot> = decoder.decode_next()?;
        let data: crate::AttestationData = decoder.decode_next()?;
        let sig: [u8; 96] = decoder.decode_next()?;
        let committee: BitVector<MaxCommitteesPerSlot> = decoder.decode_next()?;
        Ok(Self {
            aggregation_bits: bits.as_ssz_bytes(),
            data,
            signature: sig.to_vec(),
            committee_bits: committee.as_ssz_bytes(),
        })
    }
}

impl ssz::Encode for crate::ElectraAttestation {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        BYTES_PER_LENGTH_OFFSET
            + self.aggregation_bits.len()
            + <crate::AttestationData as ssz::Encode>::ssz_fixed_len()
            + <[u8; 96] as ssz::Encode>::ssz_fixed_len()
            + 8
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let _ = ssz08_bitlist::<MaxValidatorsPerSlot>(&self.aggregation_bits)
            .expect("ElectraAttestation.aggregation_bits must be Bitlist[MAX_VALIDATORS_PER_SLOT]");
        let sig =
            ssz08_sig96(&self.signature).expect("ElectraAttestation.signature must be 96 bytes");
        let committee: [u8; 8] = self
            .committee_bits
            .as_slice()
            .try_into()
            .expect("ElectraAttestation.committee_bits must be Bitvector[64] (8 bytes)");
        let offset = BYTES_PER_LENGTH_OFFSET
            + <crate::AttestationData as ssz::Encode>::ssz_fixed_len()
            + <[u8; 96] as ssz::Encode>::ssz_fixed_len()
            + 8;
        let mut encoder = ssz::SszEncoder::container(buf, offset);
        encoder.append(&Ssz09VarBytes(&self.aggregation_bits));
        encoder.append(&self.data);
        encoder.append(&sig);
        encoder.append(&committee);
        encoder.finalize();
    }
}

impl ssz::Decode for crate::ElectraAttestation {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<Ssz09VarBytesOwned>()?;
        builder.register_type::<crate::AttestationData>()?;
        builder.register_type::<[u8; 96]>()?;
        builder.register_type::<[u8; 8]>()?;
        let mut decoder = builder.build()?;
        let bits = decoder.decode_next::<Ssz09VarBytesOwned>()?;
        let data: crate::AttestationData = decoder.decode_next()?;
        let sig: [u8; 96] = decoder.decode_next()?;
        let committee: [u8; 8] = decoder.decode_next()?;
        ssz08_bitlist::<MaxValidatorsPerSlot>(&bits.0)
            .map_err(|e| ssz::DecodeError::BytesInvalid(format!("aggregation_bits: {e:?}")))?;
        Ok(Self {
            aggregation_bits: bits.0,
            data,
            signature: sig.to_vec(),
            committee_bits: committee.to_vec(),
        })
    }
}

impl Encode for crate::ElectraAggregateAndProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn ssz_bytes_len(&self) -> usize {
        <u64 as Encode>::ssz_fixed_len()
            + BYTES_PER_LENGTH_OFFSET
            + self.aggregate.ssz_bytes_len()
            + <[u8; 96] as Encode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let proof = ssz08_sig96(&self.selection_proof)
            .expect("ElectraAggregateAndProof.selection_proof must be 96 bytes");
        let offset = <u64 as Encode>::ssz_fixed_len()
            + <crate::ElectraAttestation as Encode>::ssz_fixed_len()
            + <[u8; 96] as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        encoder.append(&self.aggregator_index);
        encoder.append(&self.aggregate);
        encoder.append(&proof);
        encoder.finalize();
    }
}

impl Decode for crate::ElectraAggregateAndProof {
    fn is_ssz_fixed_len() -> bool {
        false
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<u64>()?;
        builder.register_type::<crate::ElectraAttestation>()?;
        builder.register_type::<[u8; 96]>()?;
        let mut decoder = builder.build()?;
        Ok(Self {
            aggregator_index: decoder.decode_next()?,
            aggregate: decoder.decode_next()?,
            selection_proof: decoder.decode_next::<[u8; 96]>()?.to_vec(),
        })
    }
}

ssz_container! {
    impl crate::DepositData {
        pubkey: [u8; 48],
        withdrawal_credentials: [u8; 32],
        amount: u64,
        signature: [u8; 96],
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct Deposit {
        pub proof: FixedVector<[u8; 32], DepositProofLength>,
        pub data: crate::DepositData,
    }
}

ssz_container! {
    impl crate::VoluntaryExit {
        epoch: crate::Epoch,
        validator_index: u64,
    }
}

impl Encode for crate::SignedVoluntaryExit {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        <crate::VoluntaryExit as Encode>::ssz_fixed_len() + <[u8; 96] as Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        <Self as Encode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let sig =
            ssz08_sig96(&self.signature).expect("SignedVoluntaryExit.signature must be 96 bytes");
        let offset = <Self as Encode>::ssz_fixed_len();
        let mut encoder = SszEncoder::container(buf, offset);
        encoder.append(&self.message);
        encoder.append(&sig);
        encoder.finalize();
    }
}

impl Decode for crate::SignedVoluntaryExit {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        <crate::VoluntaryExit as Decode>::ssz_fixed_len() + <[u8; 96] as Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut builder = SszDecoderBuilder::new(bytes);
        builder.register_type::<crate::VoluntaryExit>()?;
        builder.register_type::<[u8; 96]>()?;
        let mut decoder = builder.build()?;
        Ok(Self {
            message: decoder.decode_next()?,
            signature: decoder.decode_next::<[u8; 96]>()?.to_vec(),
        })
    }
}

impl ssz::Encode for crate::SignedVoluntaryExit {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        <crate::VoluntaryExit as ssz::Encode>::ssz_fixed_len()
            + <[u8; 96] as ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_bytes_len(&self) -> usize {
        <Self as ssz::Encode>::ssz_fixed_len()
    }

    fn ssz_append(&self, buf: &mut Vec<u8>) {
        let sig =
            ssz08_sig96(&self.signature).expect("SignedVoluntaryExit.signature must be 96 bytes");
        let offset = <Self as ssz::Encode>::ssz_fixed_len();
        let mut encoder = ssz::SszEncoder::container(buf, offset);
        encoder.append(&self.message);
        encoder.append(&sig);
        encoder.finalize();
    }
}

impl ssz::Decode for crate::SignedVoluntaryExit {
    fn is_ssz_fixed_len() -> bool {
        true
    }

    fn ssz_fixed_len() -> usize {
        <crate::VoluntaryExit as ssz::Decode>::ssz_fixed_len()
            + <[u8; 96] as ssz::Decode>::ssz_fixed_len()
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, ssz::DecodeError> {
        let mut builder = ssz::SszDecoderBuilder::new(bytes);
        builder.register_type::<crate::VoluntaryExit>()?;
        builder.register_type::<[u8; 96]>()?;
        let mut decoder = builder.build()?;
        Ok(Self {
            message: decoder.decode_next()?,
            signature: decoder.decode_next::<[u8; 96]>()?.to_vec(),
        })
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct SyncAggregate {
        pub sync_committee_bits: BitVector<SyncCommitteeSize>,
        pub sync_committee_signature: [u8; 96],
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct Withdrawal {
        pub index: u64,
        pub validator_index: u64,
        pub address: [u8; 20],
        pub amount: u64,
    }
}

ssz_container! {
    /// Deneb+ full `ExecutionPayload` (Electra unchanged).
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct ExecutionPayload {
        pub parent_hash: [u8; 32],
        pub fee_recipient: [u8; 20],
        pub state_root: [u8; 32],
        pub receipts_root: [u8; 32],
        pub logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
        pub prev_randao: [u8; 32],
        pub block_number: u64,
        pub gas_limit: u64,
        pub gas_used: u64,
        pub timestamp: u64,
        pub extra_data: VariableList<u8, MaxExtraDataBytes>,
        pub base_fee_per_gas: Uint256,
        pub block_hash: [u8; 32],
        pub transactions: VariableList<Transaction, MaxTransactionsPerPayload>,
        pub withdrawals: VariableList<Withdrawal, MaxWithdrawalsPerPayload>,
        pub blob_gas_used: u64,
        pub excess_blob_gas: u64,
    }
}

ssz_container! {
    /// Blinded header form of the execution payload (body field for MEV path).
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct ExecutionPayloadHeader {
        pub parent_hash: [u8; 32],
        pub fee_recipient: [u8; 20],
        pub state_root: [u8; 32],
        pub receipts_root: [u8; 32],
        pub logs_bloom: FixedVector<u8, BytesPerLogsBloom>,
        pub prev_randao: [u8; 32],
        pub block_number: u64,
        pub gas_limit: u64,
        pub gas_used: u64,
        pub timestamp: u64,
        pub extra_data: VariableList<u8, MaxExtraDataBytes>,
        pub base_fee_per_gas: Uint256,
        pub block_hash: [u8; 32],
        pub transactions_root: [u8; 32],
        pub withdrawals_root: [u8; 32],
        pub blob_gas_used: u64,
        pub excess_blob_gas: u64,
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct BlsToExecutionChange {
        pub validator_index: u64,
        pub from_bls_pubkey: [u8; 48],
        pub to_execution_address: [u8; 20],
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct SignedBlsToExecutionChange {
        pub message: BlsToExecutionChange,
        pub signature: [u8; 96],
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct DepositRequest {
        pub pubkey: [u8; 48],
        pub withdrawal_credentials: [u8; 32],
        pub amount: u64,
        pub signature: [u8; 96],
        pub index: u64,
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct WithdrawalRequest {
        pub source_address: [u8; 20],
        pub validator_pubkey: [u8; 48],
        pub amount: u64,
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct ConsolidationRequest {
        pub source_address: [u8; 20],
        pub source_pubkey: [u8; 48],
        pub target_pubkey: [u8; 48],
    }
}

ssz_container! {
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct ExecutionRequests {
        pub deposits: VariableList<DepositRequest, MaxDepositRequestsPerPayload>,
        pub withdrawals: VariableList<WithdrawalRequest, MaxWithdrawalRequestsPerPayload>,
        pub consolidations: VariableList<ConsolidationRequest, MaxConsolidationRequestsPerPayload>,
    }
}

// ---------------------------------------------------------------------------
// Electra body variants
// ---------------------------------------------------------------------------

ssz_container! {
    /// Electra `BeaconBlockBody` (13 fields; Fulu shares this layout).
    ///
    /// Spec order is merkleization-sensitive — do not reorder.
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct BeaconBlockBodyElectra {
        pub randao_reveal: [u8; 96],
        pub eth1_data: Eth1Data,
        pub graffiti: [u8; 32],
        pub proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
        pub attester_slashings: VariableList<AttesterSlashingElectra, MaxAttesterSlashingsElectra>,
        pub attestations: VariableList<crate::ElectraAttestation, MaxAttestationsElectra>,
        pub deposits: VariableList<Deposit, MaxDeposits>,
        pub voluntary_exits: VariableList<crate::SignedVoluntaryExit, MaxVoluntaryExits>,
        pub sync_aggregate: SyncAggregate,
        pub execution_payload: ExecutionPayload,
        pub bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
        pub blob_kzg_commitments: VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>,
        pub execution_requests: ExecutionRequests,
    }
}

impl BeaconBlockBodyElectra {
    /// Decode SSZ bytes into a typed Electra `BeaconBlockBody`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, BodySszError> {
        <Self as Decode>::from_ssz_bytes(bytes).map_err(Into::into)
    }

    /// Encode this body to canonical SSZ bytes.
    pub fn as_ssz_bytes(&self) -> Vec<u8> {
        Encode::as_ssz_bytes(self)
    }
}

ssz_container! {
    /// Electra blinded body: `execution_payload` → `ExecutionPayloadHeader`.
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct BlindedBeaconBlockBodyElectra {
        pub randao_reveal: [u8; 96],
        pub eth1_data: Eth1Data,
        pub graffiti: [u8; 32],
        pub proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
        pub attester_slashings: VariableList<AttesterSlashingElectra, MaxAttesterSlashingsElectra>,
        pub attestations: VariableList<crate::ElectraAttestation, MaxAttestationsElectra>,
        pub deposits: VariableList<Deposit, MaxDeposits>,
        pub voluntary_exits: VariableList<crate::SignedVoluntaryExit, MaxVoluntaryExits>,
        pub sync_aggregate: SyncAggregate,
        pub execution_payload_header: ExecutionPayloadHeader,
        pub bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
        pub blob_kzg_commitments: VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>,
        pub execution_requests: ExecutionRequests,
    }
}

impl BlindedBeaconBlockBodyElectra {
    /// Decode SSZ bytes into a typed Electra blinded `BeaconBlockBody`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, BodySszError> {
        <Self as Decode>::from_ssz_bytes(bytes).map_err(Into::into)
    }

    /// Encode this blinded body to canonical SSZ bytes.
    pub fn as_ssz_bytes(&self) -> Vec<u8> {
        Encode::as_ssz_bytes(self)
    }
}

// ---------------------------------------------------------------------------
// Deneb body variants (SEC-6d)
// ---------------------------------------------------------------------------

ssz_container! {
    /// Deneb `BeaconBlockBody` (12 fields; no `execution_requests`).
    ///
    /// Attester/attestation list limits and element types are pre-Electra
    /// (`MAX_ATTESTER_SLASHINGS=2`, `MAX_ATTESTATIONS=128`, no `committee_bits`).
    /// Spec order is merkleization-sensitive — do not reorder.
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct BeaconBlockBodyDeneb {
        pub randao_reveal: [u8; 96],
        pub eth1_data: Eth1Data,
        pub graffiti: [u8; 32],
        pub proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
        pub attester_slashings: VariableList<AttesterSlashing, MaxAttesterSlashings>,
        pub attestations: VariableList<crate::Attestation, MaxAttestations>,
        pub deposits: VariableList<Deposit, MaxDeposits>,
        pub voluntary_exits: VariableList<crate::SignedVoluntaryExit, MaxVoluntaryExits>,
        pub sync_aggregate: SyncAggregate,
        pub execution_payload: ExecutionPayload,
        pub bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
        pub blob_kzg_commitments: VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>,
    }
}

impl BeaconBlockBodyDeneb {
    /// Decode SSZ bytes into a typed Deneb `BeaconBlockBody`.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, BodySszError> {
        <Self as Decode>::from_ssz_bytes(bytes).map_err(Into::into)
    }

    /// Encode this body to canonical SSZ bytes.
    pub fn as_ssz_bytes(&self) -> Vec<u8> {
        Encode::as_ssz_bytes(self)
    }
}

ssz_container! {
    /// Deneb blinded body: `execution_payload` → `ExecutionPayloadHeader`, no
    /// `execution_requests`.
    #[derive(Debug, Clone, PartialEq, Eq, TreeHash)]
    pub struct BlindedBeaconBlockBodyDeneb {
        pub randao_reveal: [u8; 96],
        pub eth1_data: Eth1Data,
        pub graffiti: [u8; 32],
        pub proposer_slashings: VariableList<ProposerSlashing, MaxProposerSlashings>,
        pub attester_slashings: VariableList<AttesterSlashing, MaxAttesterSlashings>,
        pub attestations: VariableList<crate::Attestation, MaxAttestations>,
        pub deposits: VariableList<Deposit, MaxDeposits>,
        pub voluntary_exits: VariableList<crate::SignedVoluntaryExit, MaxVoluntaryExits>,
        pub sync_aggregate: SyncAggregate,
        pub execution_payload_header: ExecutionPayloadHeader,
        pub bls_to_execution_changes: VariableList<SignedBlsToExecutionChange, MaxBlsToExecutionChanges>,
        pub blob_kzg_commitments: VariableList<KzgCommitment, MaxBlobCommitmentsPerBlock>,
    }
}

impl BlindedBeaconBlockBodyDeneb {
    /// Decode SSZ bytes into a typed Deneb blinded body.
    pub fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, BodySszError> {
        <Self as Decode>::from_ssz_bytes(bytes).map_err(Into::into)
    }

    /// Encode this blinded body to canonical SSZ bytes.
    pub fn as_ssz_bytes(&self) -> Vec<u8> {
        Encode::as_ssz_bytes(self)
    }
}

// ---------------------------------------------------------------------------
// Convenience free functions (stable names for SEC-6c/6d wiring)
// ---------------------------------------------------------------------------

/// Decode wire `Vec<u8>` / SSZ body bytes into [`BeaconBlockBodyElectra`].
pub fn decode_beacon_block_body_electra(
    bytes: &[u8],
) -> Result<BeaconBlockBodyElectra, BodySszError> {
    BeaconBlockBodyElectra::from_ssz_bytes(bytes)
}

/// Decode wire SSZ bytes into [`BlindedBeaconBlockBodyElectra`].
pub fn decode_blinded_beacon_block_body_electra(
    bytes: &[u8],
) -> Result<BlindedBeaconBlockBodyElectra, BodySszError> {
    BlindedBeaconBlockBodyElectra::from_ssz_bytes(bytes)
}

/// Decode wire SSZ body bytes into [`BeaconBlockBodyDeneb`].
pub fn decode_beacon_block_body_deneb(bytes: &[u8]) -> Result<BeaconBlockBodyDeneb, BodySszError> {
    BeaconBlockBodyDeneb::from_ssz_bytes(bytes)
}

/// Decode wire SSZ bytes into [`BlindedBeaconBlockBodyDeneb`].
pub fn decode_blinded_beacon_block_body_deneb(
    bytes: &[u8],
) -> Result<BlindedBeaconBlockBodyDeneb, BodySszError> {
    BlindedBeaconBlockBodyDeneb::from_ssz_bytes(bytes)
}

/// Spec body-leaf root for a full (unblinded) block: Electra then Deneb.
///
/// Production `BeaconBlock` wire bodies do not carry a fork tag; the two layouts
/// differ in fixed-portion length and trailing fields, so decode is unambiguous
/// for valid SSZ. Prefer [`crate::BodyForkLayout`] when the BN
/// `consensus_version` is already known (see
/// [`body_tree_hash_root_for_layout`]).
pub fn body_tree_hash_root(bytes: &[u8]) -> Result<Hash256, BodySszError> {
    match decode_beacon_block_body_electra(bytes) {
        Ok(body) => Ok(body.tree_hash_root()),
        Err(electra_err) => match decode_beacon_block_body_deneb(bytes) {
            Ok(body) => Ok(body.tree_hash_root()),
            Err(_) => Err(electra_err),
        },
    }
}

/// Spec body-leaf root for a blinded block: Electra then Deneb.
pub fn blinded_body_tree_hash_root(bytes: &[u8]) -> Result<Hash256, BodySszError> {
    match decode_blinded_beacon_block_body_electra(bytes) {
        Ok(body) => Ok(body.tree_hash_root()),
        Err(electra_err) => match decode_blinded_beacon_block_body_deneb(bytes) {
            Ok(body) => Ok(body.tree_hash_root()),
            Err(_) => Err(electra_err),
        },
    }
}

/// Body-leaf root with an explicit fork layout (when `consensus_version` is known).
pub fn body_tree_hash_root_for_layout(
    bytes: &[u8],
    layout: crate::BodyForkLayout,
) -> Result<Hash256, BodySszError> {
    match layout {
        crate::BodyForkLayout::Electra => {
            Ok(decode_beacon_block_body_electra(bytes)?.tree_hash_root())
        }
        crate::BodyForkLayout::Deneb => Ok(decode_beacon_block_body_deneb(bytes)?.tree_hash_root()),
        crate::BodyForkLayout::Gloas => Err(BodySszError::GloasUnsupported),
    }
}

/// Blinded body-leaf root with an explicit fork layout.
pub fn blinded_body_tree_hash_root_for_layout(
    bytes: &[u8],
    layout: crate::BodyForkLayout,
) -> Result<Hash256, BodySszError> {
    match layout {
        crate::BodyForkLayout::Electra => {
            Ok(decode_blinded_beacon_block_body_electra(bytes)?.tree_hash_root())
        }
        crate::BodyForkLayout::Deneb => {
            Ok(decode_blinded_beacon_block_body_deneb(bytes)?.tree_hash_root())
        }
        crate::BodyForkLayout::Gloas => Err(BodySszError::GloasUnsupported),
    }
}

// ---------------------------------------------------------------------------
// External-vector fixtures (SEC-6a/b/c/d KATs; also usable as valid bodies)
// Gated: compiled for crate-local unit tests or the `test-fixtures` feature
// (RF3-19 / G5). Not part of the default production public API.
// ---------------------------------------------------------------------------

/// External known-good Electra body root from independent `remerkleable` oracle.
///
/// Matches [`external_vector_electra_body`]'s field construction.
#[cfg(any(test, feature = "test-fixtures"))]
pub const EXTERNAL_ELECTRA_BODY_ROOT_HEX: &str =
    "58953d11e9b51a6e95c8c70ca51b7ad6b6e557a91caab298a71688dfab9e4870";

/// External known-good Electra **block** root (`remerkleable` over the full
/// `BeaconBlock` with slot=3_000_000, proposer=42, parent=`0x11…`, state=`0x22…`,
/// body=[`external_vector_electra_body`]).
#[cfg(any(test, feature = "test-fixtures"))]
pub const EXTERNAL_ELECTRA_BLOCK_ROOT_HEX: &str =
    "b3f19bf190b0ab2466738ba06bbaf6e481041ca66db733c549975b27b53c92b9";

/// Blinded Electra body root with SEC-6d distinct graffiti
/// (`"rvc-sec6d-blinded-electra!!!!"`). Independent `remerkleable` KAT.
#[cfg(any(test, feature = "test-fixtures"))]
pub const EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX: &str =
    "e9e9fd39cc7fc4345e43bf31af21838d9389767cf62c0f8fdaf740b06d26f3e7";

/// Blinded Electra **block** root for [`external_vector_blinded_electra_body`]
/// (slot=3_000_000, proposer=42, parent=`0x11…`, state=`0x22…`).
#[cfg(any(test, feature = "test-fixtures"))]
pub const EXTERNAL_BLINDED_ELECTRA_BLOCK_ROOT_HEX: &str =
    "6bf364098fe8b865ffecc0b1d88c5b6edada937e5c9c3c69726d1d46cf2e1d24";

/// Deneb full body root (`remerkleable`; graffiti `"rvc-sec6d-deneb-body!!!!!!!!!"`).
#[cfg(any(test, feature = "test-fixtures"))]
pub const EXTERNAL_DENEB_BODY_ROOT_HEX: &str =
    "6c74513b682d097373d9f9a962637d753a8f8d6af4efb0283ae5c4941308ec67";

/// Deneb **block** root for [`external_vector_deneb_body`] (same header fields
/// as the Electra block vector).
#[cfg(any(test, feature = "test-fixtures"))]
pub const EXTERNAL_DENEB_BLOCK_ROOT_HEX: &str =
    "86714640e5ee761d6ccc664996816f10ec496324bcac46a999f778abce1f906e";

/// Shared scalar fields for external-vector bodies (eth1 / payload / sync).
#[cfg(any(test, feature = "test-fixtures"))]
fn external_vector_eth1_data() -> Eth1Data {
    Eth1Data { deposit_root: [0x22; 32], deposit_count: 7, block_hash: [0x33; 32] }
}

#[cfg(any(test, feature = "test-fixtures"))]
fn external_vector_sync_aggregate() -> SyncAggregate {
    SyncAggregate { sync_committee_bits: BitVector::new(), sync_committee_signature: [0x44; 96] }
}

#[cfg(any(test, feature = "test-fixtures"))]
fn external_vector_execution_payload() -> ExecutionPayload {
    ExecutionPayload {
        parent_hash: [0x55; 32],
        fee_recipient: [0x66; 20],
        state_root: [0x77; 32],
        receipts_root: [0x88; 32],
        logs_bloom: FixedVector::from(vec![0u8; 256]),
        prev_randao: [0x99; 32],
        block_number: 12_345,
        gas_limit: 30_000_000,
        gas_used: 1_000_000,
        timestamp: 1_700_000_000,
        extra_data: VariableList::from(vec![]),
        base_fee_per_gas: Uint256::from_u64(7),
        block_hash: [0xaa; 32],
        transactions: VariableList::from(vec![]),
        withdrawals: VariableList::from(vec![]),
        blob_gas_used: 0,
        excess_blob_gas: 0,
    }
}

#[cfg(any(test, feature = "test-fixtures"))]
fn external_vector_empty_execution_requests() -> ExecutionRequests {
    ExecutionRequests {
        deposits: VariableList::from(vec![]),
        withdrawals: VariableList::from(vec![]),
        consolidations: VariableList::from(vec![]),
    }
}

/// Deterministic Electra body matching the external `remerkleable` vector:
/// fixed non-zero leaves for signatures / eth1 / payload fields; empty op lists.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn external_vector_electra_body() -> BeaconBlockBodyElectra {
    let mut graffiti = [0u8; 32];
    graffiti[..28].copy_from_slice(b"rvc-sec6a-spike-electra!!!!!");

    BeaconBlockBodyElectra {
        randao_reveal: [0x11; 96],
        eth1_data: external_vector_eth1_data(),
        graffiti,
        proposer_slashings: VariableList::from(vec![]),
        attester_slashings: VariableList::from(vec![]),
        attestations: VariableList::from(vec![]),
        deposits: VariableList::from(vec![]),
        voluntary_exits: VariableList::from(vec![]),
        sync_aggregate: external_vector_sync_aggregate(),
        execution_payload: external_vector_execution_payload(),
        bls_to_execution_changes: VariableList::from(vec![]),
        blob_kzg_commitments: VariableList::from(vec![]),
        execution_requests: external_vector_empty_execution_requests(),
    }
}

/// Execution payload header corresponding to the external-vector payload
/// (empty txs/withdrawals → their empty-list roots).
#[cfg(any(test, feature = "test-fixtures"))]
pub fn external_vector_execution_payload_header() -> ExecutionPayloadHeader {
    let p = external_vector_execution_payload();
    ExecutionPayloadHeader {
        parent_hash: p.parent_hash,
        fee_recipient: p.fee_recipient,
        state_root: p.state_root,
        receipts_root: p.receipts_root,
        logs_bloom: p.logs_bloom,
        prev_randao: p.prev_randao,
        block_number: p.block_number,
        gas_limit: p.gas_limit,
        gas_used: p.gas_used,
        timestamp: p.timestamp,
        extra_data: p.extra_data,
        base_fee_per_gas: p.base_fee_per_gas,
        block_hash: p.block_hash,
        // Empty list roots for transactions / withdrawals (spec empty List roots).
        transactions_root: {
            let root = VariableList::<Transaction, MaxTransactionsPerPayload>::from(vec![])
                .tree_hash_root();
            let mut out = [0u8; 32];
            out.copy_from_slice(root.as_slice());
            out
        },
        withdrawals_root: {
            let root =
                VariableList::<Withdrawal, MaxWithdrawalsPerPayload>::from(vec![]).tree_hash_root();
            let mut out = [0u8; 32];
            out.copy_from_slice(root.as_slice());
            out
        },
        blob_gas_used: p.blob_gas_used,
        excess_blob_gas: p.excess_blob_gas,
    }
}

/// Blinded Electra body external vector (SEC-6d distinct graffiti).
///
/// Uses header form of the payload and graffiti `rvc-sec6d-blinded-electra!!!!`
/// so the body root is distinct from the full Electra vector.
#[cfg(any(test, feature = "test-fixtures"))]
pub fn external_vector_blinded_electra_body() -> BlindedBeaconBlockBodyElectra {
    let mut graffiti = [0u8; 32];
    graffiti[..29].copy_from_slice(b"rvc-sec6d-blinded-electra!!!!");

    BlindedBeaconBlockBodyElectra {
        randao_reveal: [0x11; 96],
        eth1_data: external_vector_eth1_data(),
        graffiti,
        proposer_slashings: VariableList::from(vec![]),
        attester_slashings: VariableList::from(vec![]),
        attestations: VariableList::from(vec![]),
        deposits: VariableList::from(vec![]),
        voluntary_exits: VariableList::from(vec![]),
        sync_aggregate: external_vector_sync_aggregate(),
        execution_payload_header: external_vector_execution_payload_header(),
        bls_to_execution_changes: VariableList::from(vec![]),
        blob_kzg_commitments: VariableList::from(vec![]),
        execution_requests: external_vector_empty_execution_requests(),
    }
}

/// Deneb full body external vector (SEC-6d; no `execution_requests`).
#[cfg(any(test, feature = "test-fixtures"))]
pub fn external_vector_deneb_body() -> BeaconBlockBodyDeneb {
    let mut graffiti = [0u8; 32];
    graffiti[..29].copy_from_slice(b"rvc-sec6d-deneb-body!!!!!!!!!");

    BeaconBlockBodyDeneb {
        randao_reveal: [0x11; 96],
        eth1_data: external_vector_eth1_data(),
        graffiti,
        proposer_slashings: VariableList::from(vec![]),
        attester_slashings: VariableList::from(vec![]),
        attestations: VariableList::from(vec![]),
        deposits: VariableList::from(vec![]),
        voluntary_exits: VariableList::from(vec![]),
        sync_aggregate: external_vector_sync_aggregate(),
        execution_payload: external_vector_execution_payload(),
        bls_to_execution_changes: VariableList::from(vec![]),
        blob_kzg_commitments: VariableList::from(vec![]),
    }
}

/// Deneb blinded body external vector (header instead of payload).
///
/// With empty txs/withdrawals the body HTR equals [`EXTERNAL_DENEB_BODY_ROOT_HEX`].
#[cfg(any(test, feature = "test-fixtures"))]
pub fn external_vector_blinded_deneb_body() -> BlindedBeaconBlockBodyDeneb {
    let full = external_vector_deneb_body();
    BlindedBeaconBlockBodyDeneb {
        randao_reveal: full.randao_reveal,
        eth1_data: full.eth1_data,
        graffiti: full.graffiti,
        proposer_slashings: full.proposer_slashings,
        attester_slashings: full.attester_slashings,
        attestations: full.attestations,
        deposits: full.deposits,
        voluntary_exits: full.voluntary_exits,
        sync_aggregate: full.sync_aggregate,
        execution_payload_header: external_vector_execution_payload_header(),
        bls_to_execution_changes: full.bls_to_execution_changes,
        blob_kzg_commitments: full.blob_kzg_commitments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_hash::TreeHash;

    fn hex32(s: &str) -> Hash256 {
        let bytes = hex::decode(s.trim_start_matches("0x")).expect("hex");
        Hash256::from_slice(&bytes)
    }

    /// remerkleable `Checkpoint(epoch=100, root=0x00…32)` SSZ + HTR.
    const SPEC_CHECKPOINT_SSZ_HEX: &str =
        "64000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const SPEC_CHECKPOINT_HTR_HEX: &str =
        "f59927591e6e3283d4419e376e4ebb4e08f4f547a3d1076474a29c9d44a07b28";

    #[test]
    fn test_checkpoint_ssz09_and_ssz08_match_spec_bytes() {
        let checkpoint = crate::Checkpoint { epoch: 100, root: [0u8; 32] };
        let expected = hex::decode(SPEC_CHECKPOINT_SSZ_HEX).expect("hex");
        assert_eq!(ssz::Encode::as_ssz_bytes(&checkpoint), expected);
        assert_eq!(Encode::as_ssz_bytes(&checkpoint), expected);
        assert_eq!(checkpoint.tree_hash_root(), hex32(SPEC_CHECKPOINT_HTR_HEX));
        let back = <crate::Checkpoint as Decode>::from_ssz_bytes(&expected).unwrap();
        assert_eq!(back, checkpoint);
    }

    /// remerkleable `AttestationData` matching `aggregation.rs` Electra sample.
    const SPEC_ATTESTATION_DATA_SSZ_HEX: &str = concat!(
        "64000000000000000000000000000000",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0300000000000000",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0400000000000000",
        "0303030303030303030303030303030303030303030303030303030303030303",
    );
    const SPEC_ATTESTATION_DATA_HTR_HEX: &str =
        "3810cbc2daad89c727791c249ea17025b976d05c2fd41344285bc86ecd5105c6";

    #[test]
    fn test_attestation_data_ssz09_and_ssz08_match_spec_bytes() {
        let data = crate::AttestationData {
            slot: 100,
            index: 0,
            beacon_block_root: [1u8; 32],
            source: crate::Checkpoint { epoch: 3, root: [2u8; 32] },
            target: crate::Checkpoint { epoch: 4, root: [3u8; 32] },
        };
        let expected = hex::decode(SPEC_ATTESTATION_DATA_SSZ_HEX).expect("hex");
        assert_eq!(ssz::Encode::as_ssz_bytes(&data), expected);
        assert_eq!(Encode::as_ssz_bytes(&data), expected);
        assert_eq!(data.tree_hash_root(), hex32(SPEC_ATTESTATION_DATA_HTR_HEX));
        let back = <crate::AttestationData as Decode>::from_ssz_bytes(&expected).unwrap();
        assert_eq!(back, data);
    }

    /// remerkleable header from the non-empty-ops fixture (slot=1, proposer=2).
    const SPEC_BEACON_BLOCK_HEADER_SSZ_HEX: &str = concat!(
        "01000000000000000200000000000000",
        "abababababababababababababababababababababababababababababababab",
        "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
        "efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef",
    );
    const SPEC_BEACON_BLOCK_HEADER_HTR_HEX: &str =
        "67fcec3237c5acf5a660dda06f4fbe5af7a87620dd6c3cdd4cc9d6b1240f3e29";

    #[test]
    fn test_beacon_block_header_ssz09_and_ssz08_match_spec_bytes() {
        let header = crate::BeaconBlockHeader {
            slot: 1,
            proposer_index: 2,
            parent_root: [0xab; 32],
            state_root: [0xcd; 32],
            body_root: [0xef; 32],
        };
        let expected = hex::decode(SPEC_BEACON_BLOCK_HEADER_SSZ_HEX).expect("hex");
        assert_eq!(ssz::Encode::as_ssz_bytes(&header), expected);
        assert_eq!(Encode::as_ssz_bytes(&header), expected);
        assert_eq!(header.tree_hash_root(), hex32(SPEC_BEACON_BLOCK_HEADER_HTR_HEX));
        let back = <crate::BeaconBlockHeader as Decode>::from_ssz_bytes(&expected).unwrap();
        assert_eq!(back, header);
    }

    /// remerkleable `DepositData` from the non-empty-ops fixture.
    const SPEC_DEPOSIT_DATA_SSZ_HEX: &str = concat!(
        "dededededededededededededededededededededededededededededededededededededededededededededededede",
        "adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad",
        "0040597307000000",
        "bebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebe",
        "bebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebe",
        "bebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebebe",
    );
    const SPEC_DEPOSIT_DATA_HTR_HEX: &str =
        "85b8a34fb09ac7acf35e59aca082f742ca0d96abedd61c17cb9a3c6d8abaee5b";

    #[test]
    fn test_deposit_data_ssz09_and_ssz08_match_spec_bytes() {
        let data = crate::DepositData {
            pubkey: [0xde; 48],
            withdrawal_credentials: [0xad; 32],
            amount: 32_000_000_000,
            signature: [0xbe; 96],
        };
        let expected = hex::decode(SPEC_DEPOSIT_DATA_SSZ_HEX).expect("hex");
        assert_eq!(ssz::Encode::as_ssz_bytes(&data), expected);
        assert_eq!(Encode::as_ssz_bytes(&data), expected);
        assert_eq!(data.tree_hash_root(), hex32(SPEC_DEPOSIT_DATA_HTR_HEX));
        let back = <crate::DepositData as Decode>::from_ssz_bytes(&expected).unwrap();
        assert_eq!(back, data);
    }

    /// remerkleable `VoluntaryExit(epoch=100, validator_index=42)`.
    const SPEC_VOLUNTARY_EXIT_SSZ_HEX: &str = "64000000000000002a00000000000000";
    const SPEC_VOLUNTARY_EXIT_HTR_HEX: &str =
        "e723f4e7c43eee8834008a6a65806077b39842db5e84c590a5d74d2208cc4083";

    #[test]
    fn test_voluntary_exit_ssz09_and_ssz08_match_spec_bytes() {
        let exit = crate::VoluntaryExit { epoch: 100, validator_index: 42 };
        let expected = hex::decode(SPEC_VOLUNTARY_EXIT_SSZ_HEX).expect("hex");
        assert_eq!(ssz::Encode::as_ssz_bytes(&exit), expected);
        assert_eq!(Encode::as_ssz_bytes(&exit), expected);
        assert_eq!(exit.tree_hash_root(), hex32(SPEC_VOLUNTARY_EXIT_HTR_HEX));
        let back = <crate::VoluntaryExit as Decode>::from_ssz_bytes(&expected).unwrap();
        assert_eq!(back, exit);
    }

    /// remerkleable `SignedVoluntaryExit` (exit above + signature `[0xaa;96]`).
    const SPEC_SIGNED_VOLUNTARY_EXIT_SSZ_HEX: &str = concat!(
        "64000000000000002a00000000000000",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    const SPEC_SIGNED_VOLUNTARY_EXIT_HTR_HEX: &str =
        "e96f711d5a3078da1f80423c46f61362620bb20134c23f1d56fd3b50d74c10b8";
    const KAT_SIGNED_VOLUNTARY_EXIT_LIST_ROOT_HEX: &str =
        "eedb73e7adbabc2b1d6571e94a28ce97e43ec229e4a796ac81e6ed30466f7188";

    #[test]
    fn test_signed_voluntary_exit_ssz09_and_ssz08_match_spec_bytes() {
        let signed = crate::SignedVoluntaryExit {
            message: crate::VoluntaryExit { epoch: 100, validator_index: 42 },
            signature: vec![0xaa; 96],
        };
        let expected = hex::decode(SPEC_SIGNED_VOLUNTARY_EXIT_SSZ_HEX).expect("hex");
        assert_eq!(ssz::Encode::as_ssz_bytes(&signed), expected);
        assert_eq!(Encode::as_ssz_bytes(&signed), expected);
        assert_eq!(signed.tree_hash_root(), hex32(SPEC_SIGNED_VOLUNTARY_EXIT_HTR_HEX));
        assert_eq!(
            <crate::SignedVoluntaryExit as Decode>::from_ssz_bytes(&expected).unwrap(),
            signed
        );
        assert_eq!(
            <crate::SignedVoluntaryExit as ssz::Decode>::from_ssz_bytes(&expected).unwrap(),
            signed
        );
        let list =
            VariableList::<crate::SignedVoluntaryExit, MaxVoluntaryExits>::from(vec![signed]);
        assert_eq!(Encode::as_ssz_bytes(&list), expected);
        assert_eq!(list.tree_hash_root(), hex32(KAT_SIGNED_VOLUNTARY_EXIT_LIST_ROOT_HEX));
    }

    /// remerkleable Electra `Attestation` matching `aggregation.rs` sample:
    /// Bitlist[131072] of 31 set bits (`0xffffffff`), data as
    /// [`SPEC_ATTESTATION_DATA_HTR_HEX`], signature `[0xaa;96]`,
    /// Bitvector[64] = `[0x01;8]`.
    const KAT_ELECTRA_ATTESTATION_SSZ_HEX: &str = concat!(
        "ec000000",
        "64000000000000000000000000000000",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0300000000000000",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0400000000000000",
        "0303030303030303030303030303030303030303030303030303030303030303",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0101010101010101",
        "ffffffff",
    );
    const KAT_ELECTRA_ATTESTATION_HTR_HEX: &str =
        "26b23c318b00c7e774670fa8c54f3ba256018f798226d717df0d82c2e143914f";
    /// `List[Attestation, MAX_ATTESTATIONS_ELECTRA=8]` of one
    /// [`KAT_ELECTRA_ATTESTATION_SSZ_HEX`] element (remerkleable).
    const KAT_ELECTRA_ATTESTATION_LIST_SSZ_HEX: &str = concat!(
        "04000000",
        "ec000000",
        "64000000000000000000000000000000",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0300000000000000",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0400000000000000",
        "0303030303030303030303030303030303030303030303030303030303030303",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "0101010101010101",
        "ffffffff",
    );
    const KAT_ELECTRA_ATTESTATION_LIST_ROOT_HEX: &str =
        "64a119d1221d09e3da3eb8e25bd302f4ccd6498ba3d637bbf4411145c7633af1";

    fn kat_electra_attestation() -> crate::ElectraAttestation {
        crate::ElectraAttestation {
            aggregation_bits: vec![0xff; 4],
            data: crate::AttestationData {
                slot: 100,
                index: 0,
                beacon_block_root: [1u8; 32],
                source: crate::Checkpoint { epoch: 3, root: [2u8; 32] },
                target: crate::Checkpoint { epoch: 4, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
            committee_bits: vec![0x01; 8],
        }
    }

    /// remerkleable pre-Electra `Attestation` matching `aggregation.rs` sample
    /// (index=1, 31-bit aggregation_bits, signature `[0xaa;96]`).
    const KAT_ATTESTATION_SSZ_HEX: &str = concat!(
        "e4000000",
        "64000000000000000100000000000000",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0300000000000000",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0400000000000000",
        "0303030303030303030303030303030303030303030303030303030303030303",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ffffffff",
    );
    const KAT_ATTESTATION_HTR_HEX: &str =
        "9f5f284edccbab25e3cd3686c60131988a0aec3619f026e51b17e90db79f4102";
    const KAT_ATTESTATION_LIST_SSZ_HEX: &str = concat!(
        "04000000",
        "e4000000",
        "64000000000000000100000000000000",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0300000000000000",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0400000000000000",
        "0303030303030303030303030303030303030303030303030303030303030303",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "ffffffff",
    );
    const KAT_ATTESTATION_LIST_ROOT_HEX: &str =
        "f4fb5c71694f4c9acf6807b74e89a12c866903e15fa36a657734111d95438ec4";

    fn kat_pre_electra_attestation() -> crate::Attestation {
        crate::Attestation {
            aggregation_bits: vec![0xff; 4],
            data: crate::AttestationData {
                slot: 100,
                index: 1,
                beacon_block_root: [1u8; 32],
                source: crate::Checkpoint { epoch: 3, root: [2u8; 32] },
                target: crate::Checkpoint { epoch: 4, root: [3u8; 32] },
            },
            signature: vec![0xaa; 96],
        }
    }

    #[test]
    fn test_attestation_ssz09_and_ssz08_match_spec_bytes() {
        let att = kat_pre_electra_attestation();
        let expected = hex::decode(KAT_ATTESTATION_SSZ_HEX).expect("hex");
        assert_eq!(ssz::Encode::as_ssz_bytes(&att), expected);
        assert_eq!(Encode::as_ssz_bytes(&att), expected);
        assert_eq!(att.tree_hash_root(), hex32(KAT_ATTESTATION_HTR_HEX));
        assert_eq!(<crate::Attestation as Decode>::from_ssz_bytes(&expected).unwrap(), att);
        assert_eq!(<crate::Attestation as ssz::Decode>::from_ssz_bytes(&expected).unwrap(), att);
        let list = VariableList::<crate::Attestation, MaxAttestations>::from(vec![att]);
        assert_eq!(
            Encode::as_ssz_bytes(&list),
            hex::decode(KAT_ATTESTATION_LIST_SSZ_HEX).expect("hex"),
        );
        assert_eq!(list.tree_hash_root(), hex32(KAT_ATTESTATION_LIST_ROOT_HEX));
    }

    #[test]
    fn test_electra_attestation_list_encode_and_tree_hash_root() {
        let att = kat_electra_attestation();
        assert_eq!(
            att.tree_hash_root(),
            hex32(KAT_ELECTRA_ATTESTATION_HTR_HEX),
            "single Electra attestation HTR must match remerkleable KAT"
        );
        let expected = hex::decode(KAT_ELECTRA_ATTESTATION_SSZ_HEX).expect("hex");
        assert_eq!(Encode::as_ssz_bytes(&att), expected);
        assert_eq!(ssz::Encode::as_ssz_bytes(&att), expected);
        assert_eq!(<crate::ElectraAttestation as Decode>::from_ssz_bytes(&expected).unwrap(), att);
        assert_eq!(
            <crate::ElectraAttestation as ssz::Decode>::from_ssz_bytes(&expected).unwrap(),
            att
        );
        let list =
            VariableList::<crate::ElectraAttestation, MaxAttestationsElectra>::from(vec![att]);
        assert_eq!(
            Encode::as_ssz_bytes(&list),
            hex::decode(KAT_ELECTRA_ATTESTATION_LIST_SSZ_HEX).expect("hex"),
            "non-empty Electra attestation list SSZ must match remerkleable"
        );
        assert_eq!(
            list.tree_hash_root(),
            hex32(KAT_ELECTRA_ATTESTATION_LIST_ROOT_HEX),
            "non-empty Electra attestation list HTR must match remerkleable"
        );
    }

    #[test]
    fn test_beacon_block_body_electra_htr_matches_external_vector() {
        let body = external_vector_electra_body();
        let root = body.tree_hash_root();
        assert_eq!(
            root,
            hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX),
            "Electra BeaconBlockBody hash_tree_root must match external remerkleable KAT"
        );
    }

    /// Alias retained for continuity with SEC-6a test name.
    #[test]
    fn test_electra_body_htr_matches_external_vector() {
        let body = external_vector_electra_body();
        assert_eq!(body.tree_hash_root(), hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX));
    }

    #[test]
    fn test_execution_payload_htr_matches_vector() {
        let body = external_vector_electra_body();
        assert_eq!(
            body.execution_payload.tree_hash_root(),
            hex32("d87a64ee3dee74c2b0f88fdae16256f0b81d5a58e1729f62089406ba46b6074d"),
        );
    }

    #[test]
    fn test_sync_aggregate_htr_matches_vector() {
        let body = external_vector_electra_body();
        assert_eq!(
            body.sync_aggregate.tree_hash_root(),
            hex32("40f2635c94dcb243d972e11a55968c92d8bbc8f9715cc8a4a14b6dd2179044f6"),
        );
    }

    #[test]
    fn test_empty_list_roots_match_spec_limits() {
        // Empty List[Composite, N] roots depend only on N (composite packing_factor=1).
        // remerkleable KATs (same oracle as the body vector):
        assert_eq!(
            VariableList::<ProposerSlashing, MaxProposerSlashings>::from(vec![]).tree_hash_root(),
            hex32("792930bbd5baac43bcc798ee49aa8185ef76bb3b44ba62b91d86ae569e4bb535"),
        );
        assert_eq!(
            VariableList::<AttesterSlashingElectra, MaxAttesterSlashingsElectra>::from(vec![])
                .tree_hash_root(),
            hex32("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
        );
        assert_eq!(
            VariableList::<crate::ElectraAttestation, MaxAttestationsElectra>::from(vec![])
                .tree_hash_root(),
            hex32("e8e527e84f666163a90ef900e013f56b0a4d020148b2224057b719f351b003a6"),
        );
        assert_eq!(
            VariableList::<KzgCommitment, MaxBlobCommitmentsPerBlock>::from(vec![])
                .tree_hash_root(),
            hex32("dba9671bac9513c9482f1416a53aabd2c6ce90d5a5f865ce5a55c775325c9136"),
        );
    }

    #[test]
    fn test_subcontainer_roots_match_external_vector_components() {
        let body = external_vector_electra_body();
        assert_eq!(
            body.eth1_data.tree_hash_root(),
            hex32("80967e80c7b8a102a59fc1827ef03adae06eb892466e61a12c25fdb370fa2ab4"),
        );
        assert_eq!(
            body.sync_aggregate.tree_hash_root(),
            hex32("40f2635c94dcb243d972e11a55968c92d8bbc8f9715cc8a4a14b6dd2179044f6"),
        );
        assert_eq!(
            body.execution_payload.tree_hash_root(),
            hex32("d87a64ee3dee74c2b0f88fdae16256f0b81d5a58e1729f62089406ba46b6074d"),
        );
        assert_eq!(
            body.execution_requests.tree_hash_root(),
            hex32("85e253b40599d0df756be043ea6949e49a07e756deef72b3588a4b05362206b5"),
        );
    }

    #[test]
    fn test_beacon_block_body_electra_decode_roundtrip() {
        let original = external_vector_electra_body();
        let encoded = original.as_ssz_bytes();
        let decoded = BeaconBlockBodyElectra::from_ssz_bytes(&encoded)
            .expect("decode external-vector Electra body");
        assert_eq!(decoded, original);
        // HTR is preserved across the wire encode/decode path.
        assert_eq!(decoded.tree_hash_root(), hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX));
        // Free-function entry point matches the method.
        let via_fn = decode_beacon_block_body_electra(&encoded).expect("fn decode");
        assert_eq!(via_fn, original);
    }

    #[test]
    fn test_beacon_block_body_electra_decode_rejects_truncated() {
        let encoded = external_vector_electra_body().as_ssz_bytes();
        assert!(encoded.len() > 16);
        let err = BeaconBlockBodyElectra::from_ssz_bytes(&encoded[..16]);
        assert!(err.is_err(), "truncated body must fail decode");
    }

    #[test]
    fn test_blinded_beacon_block_body_htr_matches_external_vector() {
        let body = external_vector_blinded_electra_body();
        assert_eq!(
            body.tree_hash_root(),
            hex32(EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX),
            "Blinded Electra body hash_tree_root must match external remerkleable KAT"
        );
        // Distinct from the full Electra empty-ops vector (different graffiti).
        assert_ne!(body.tree_hash_root(), hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX));
    }

    #[test]
    fn test_deneb_body_htr_matches_external_vector() {
        let body = external_vector_deneb_body();
        assert_eq!(
            body.tree_hash_root(),
            hex32(EXTERNAL_DENEB_BODY_ROOT_HEX),
            "Deneb BeaconBlockBody hash_tree_root must match external remerkleable KAT"
        );
        // Distinct from Electra (different layout + graffiti).
        assert_ne!(body.tree_hash_root(), hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX));
    }

    #[test]
    fn test_blinded_deneb_body_htr_matches_external_vector() {
        let body = external_vector_blinded_deneb_body();
        // Empty txs/withdrawals → header HTR == payload HTR → same as full Deneb body.
        assert_eq!(body.tree_hash_root(), hex32(EXTERNAL_DENEB_BODY_ROOT_HEX));
        assert_eq!(
            body.execution_payload_header.tree_hash_root(),
            external_vector_deneb_body().execution_payload.tree_hash_root(),
        );
    }

    #[test]
    fn test_blinded_and_full_bodies_share_subcontainers() {
        // SEC-6d: sub-containers are shared type definitions (not duplicated per variant).
        let full_e = external_vector_electra_body();
        let blinded_e = external_vector_blinded_electra_body();
        let full_d = external_vector_deneb_body();
        let blinded_d = external_vector_blinded_deneb_body();

        // Same Eth1Data / SyncAggregate / ExecutionPayload scalar construction.
        assert_eq!(full_e.eth1_data, blinded_e.eth1_data);
        assert_eq!(full_e.eth1_data, full_d.eth1_data);
        assert_eq!(full_d.eth1_data, blinded_d.eth1_data);
        assert_eq!(full_e.sync_aggregate, full_d.sync_aggregate);
        assert_eq!(full_e.execution_payload, full_d.execution_payload);
        assert_eq!(
            blinded_e.execution_payload_header.tree_hash_root(),
            full_e.execution_payload.tree_hash_root(),
        );
        assert_eq!(
            blinded_d.execution_payload_header.tree_hash_root(),
            full_d.execution_payload.tree_hash_root(),
        );
        // Type identity: Deneb attester/attestation lists use pre-Electra containers.
        let _: VariableList<AttesterSlashing, MaxAttesterSlashings> = full_d.attester_slashings;
        let _: VariableList<crate::Attestation, MaxAttestations> = full_d.attestations;
        let _: VariableList<AttesterSlashingElectra, MaxAttesterSlashingsElectra> =
            full_e.attester_slashings;
        let _: VariableList<crate::ElectraAttestation, MaxAttestationsElectra> =
            full_e.attestations;
    }

    #[test]
    fn test_blinded_beacon_block_body_electra_decode_roundtrip() {
        let original = external_vector_blinded_electra_body();
        let encoded = original.as_ssz_bytes();
        let decoded = BlindedBeaconBlockBodyElectra::from_ssz_bytes(&encoded)
            .expect("decode blinded Electra body");
        assert_eq!(decoded, original);
        assert_eq!(decoded.tree_hash_root(), hex32(EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX));
        // Payload header HTR matches full payload HTR (empty txs/withdrawals).
        let full = external_vector_electra_body();
        assert_eq!(
            original.execution_payload_header.tree_hash_root(),
            full.execution_payload.tree_hash_root(),
        );
        // Wire encodings differ (payload bytes vs header roots) and graffiti differs
        // from the full Electra external vector.
        assert_ne!(encoded, full.as_ssz_bytes());
        assert_ne!(original.tree_hash_root(), full.tree_hash_root());
    }

    #[test]
    fn test_deneb_body_decode_roundtrip() {
        let original = external_vector_deneb_body();
        let encoded = original.as_ssz_bytes();
        let decoded = BeaconBlockBodyDeneb::from_ssz_bytes(&encoded).expect("decode Deneb body");
        assert_eq!(decoded, original);
        assert_eq!(decoded.tree_hash_root(), hex32(EXTERNAL_DENEB_BODY_ROOT_HEX));
        assert_eq!(decode_beacon_block_body_deneb(&encoded).unwrap(), original);

        // Fixed portion: Deneb = 392 (no execution_requests offset).
        const DENEB_FIXED_LEN: u32 = 392;
        let first_var_offset = u32::from_le_bytes(encoded[200..204].try_into().unwrap());
        assert_eq!(first_var_offset, DENEB_FIXED_LEN);

        // Electra decode must reject a valid Deneb body (layout mismatch).
        assert!(decode_beacon_block_body_electra(&encoded).is_err());
    }

    #[test]
    fn test_deneb_empty_list_roots_match_pre_electra_limits() {
        // remerkleable KATs for Deneb list limits (distinct from Electra 1 / 8).
        assert_eq!(
            VariableList::<AttesterSlashing, MaxAttesterSlashings>::from(vec![]).tree_hash_root(),
            hex32("7a0501f5957bdf9cb3a8ff4966f02265f968658b7a9c62642cba1165e86642f5"),
        );
        assert_eq!(
            VariableList::<crate::Attestation, MaxAttestations>::from(vec![]).tree_hash_root(),
            hex32("96559674a79656e540871e1f39c9b91e152aa8cddb71493e754827c4cc809d57"),
        );
    }

    #[test]
    fn test_body_tree_hash_root_auto_detects_fork() {
        let electra = external_vector_electra_body().as_ssz_bytes();
        let deneb = external_vector_deneb_body().as_ssz_bytes();
        assert_eq!(body_tree_hash_root(&electra).unwrap(), hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX));
        assert_eq!(body_tree_hash_root(&deneb).unwrap(), hex32(EXTERNAL_DENEB_BODY_ROOT_HEX));

        let blinded_e = external_vector_blinded_electra_body().as_ssz_bytes();
        let blinded_d = external_vector_blinded_deneb_body().as_ssz_bytes();
        assert_eq!(
            blinded_body_tree_hash_root(&blinded_e).unwrap(),
            hex32(EXTERNAL_BLINDED_ELECTRA_BODY_ROOT_HEX),
        );
        assert_eq!(
            blinded_body_tree_hash_root(&blinded_d).unwrap(),
            hex32(EXTERNAL_DENEB_BODY_ROOT_HEX),
        );
    }

    #[test]
    fn test_electra_body_with_nonempty_ops_roundtrip_and_stable_htr() {
        // Non-empty lists exercise VariableList of composites + FixedVector proof.
        let mut body = external_vector_electra_body();

        let header = crate::BeaconBlockHeader {
            slot: 1,
            proposer_index: 2,
            parent_root: [0xab; 32],
            state_root: [0xcd; 32],
            body_root: [0xef; 32],
        };
        let signed = SignedBeaconBlockHeader { message: header, signature: [0x5a; 96] };
        let slashing = ProposerSlashing {
            signed_header_1: signed.clone(),
            signed_header_2: SignedBeaconBlockHeader {
                message: crate::BeaconBlockHeader {
                    slot: 1,
                    proposer_index: 2,
                    parent_root: [0xab; 32],
                    state_root: [0xcd; 32],
                    body_root: [0x11; 32], // differ body_root so headers are distinct
                },
                signature: [0x5b; 96],
            },
        };
        body.proposer_slashings = VariableList::from(vec![slashing]);

        let proof_leaves: Vec<[u8; 32]> = (0..33).map(|i| [i as u8; 32]).collect();
        let deposit = Deposit {
            proof: FixedVector::from(proof_leaves),
            data: crate::DepositData {
                pubkey: [0xde; 48],
                withdrawal_credentials: [0xad; 32],
                amount: 32_000_000_000,
                signature: [0xbe; 96],
            },
        };
        body.deposits = VariableList::from(vec![deposit]);

        let withdrawal =
            Withdrawal { index: 9, validator_index: 42, address: [0xca; 20], amount: 1_000 };
        body.execution_payload.withdrawals = VariableList::from(vec![withdrawal]);

        let tx: Transaction = VariableList::from(vec![0x02, 0xf8, 0x01]);
        body.execution_payload.transactions = VariableList::from(vec![tx]);

        body.blob_kzg_commitments = VariableList::from(vec![[0xbb; 48], [0xcc; 48]]);

        body.execution_requests.deposits = VariableList::from(vec![DepositRequest {
            pubkey: [0x11; 48],
            withdrawal_credentials: [0x22; 32],
            amount: 1,
            signature: [0x33; 96],
            index: 0,
        }]);

        let encoded = body.as_ssz_bytes();
        let decoded =
            BeaconBlockBodyElectra::from_ssz_bytes(&encoded).expect("non-empty ops body decode");
        assert_eq!(decoded, body);
        // HTR must be stable across encode/decode (not compared to external KAT —
        // field set differs from the empty-ops vector).
        assert_eq!(decoded.tree_hash_root(), body.tree_hash_root());
        assert_ne!(
            body.tree_hash_root(),
            hex32(EXTERNAL_ELECTRA_BODY_ROOT_HEX),
            "non-empty ops must change the body root vs empty-ops external vector"
        );
    }

    #[test]
    fn test_eth1_data_ssz_roundtrip() {
        let eth1 = Eth1Data { deposit_root: [0x22; 32], deposit_count: 7, block_hash: [0x33; 32] };
        let bytes = Encode::as_ssz_bytes(&eth1);
        assert_eq!(bytes.len(), 32 + 8 + 32);
        let back = <Eth1Data as Decode>::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(back, eth1);
        assert_eq!(
            eth1.tree_hash_root(),
            hex32("80967e80c7b8a102a59fc1827ef03adae06eb892466e61a12c25fdb370fa2ab4"),
        );
    }

    #[test]
    fn test_uint256_ssz_roundtrip() {
        let v = Uint256::from_u64(7);
        let bytes = Encode::as_ssz_bytes(&v);
        assert_eq!(bytes.len(), 32);
        assert_eq!(bytes[0], 7);
        let back = <Uint256 as Decode>::from_ssz_bytes(&bytes).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn test_electra_body_fixed_portion_length() {
        // Electra fixed portion: 396 bytes (Deneb 392 + 4 for execution_requests offset).
        // Verified by encoding an empty-ops body and reading the first variable offset.
        let encoded = external_vector_electra_body().as_ssz_bytes();
        // First variable field is proposer_slashings; its offset equals the fixed portion length.
        // Layout fixed fields before first var offset: randao(96)+eth1(72)+graffiti(32) = 200,
        // then 5 var offsets (20) → 220, then sync_aggregate(160) → 380, then 4 var offsets (16) → 396.
        const ELECTRA_FIXED_LEN: u32 = 396;
        let first_var_offset = u32::from_le_bytes(encoded[200..204].try_into().unwrap());
        assert_eq!(first_var_offset, ELECTRA_FIXED_LEN);
        assert!(encoded.len() >= ELECTRA_FIXED_LEN as usize);
    }

    fn electra_aap_with_bits(aggregation_bits: Vec<u8>) -> crate::ElectraAggregateAndProof {
        crate::ElectraAggregateAndProof {
            aggregator_index: 42,
            aggregate: crate::ElectraAttestation { aggregation_bits, ..kat_electra_attestation() },
            selection_proof: vec![0xbb; 96],
        }
    }

    #[test]
    fn test_electra_aggregate_and_proof_ssz_roundtrip() {
        let proof = electra_aap_with_bits(vec![0xff; 4]);
        let encoded = Encode::as_ssz_bytes(&proof);
        let decoded = <crate::ElectraAggregateAndProof as Decode>::from_ssz_bytes(&encoded)
            .expect("decode ElectraAggregateAndProof");
        assert_eq!(decoded, proof);

        // aggregator_index, aggregate offset, selection_proof, then ElectraAttestation bytes
        assert_eq!(&encoded[0..8], &42u64.to_le_bytes());
        let aggregate_offset = u32::from_le_bytes(encoded[8..12].try_into().unwrap());
        assert_eq!(aggregate_offset, 108);
        assert_eq!(&encoded[12..108], &[0xbb; 96]);
        assert_eq!(&encoded[108..], Encode::as_ssz_bytes(&proof.aggregate));
    }

    #[test]
    fn test_electra_aggregate_and_proof_ssz_bytes_len_empty_and_dense() {
        let empty = electra_aap_with_bits(vec![0x01]);
        let dense = electra_aap_with_bits(vec![0xff; 512]);
        for proof in [&empty, &dense] {
            let encoded = Encode::as_ssz_bytes(proof);
            assert_eq!(encoded.len(), Encode::ssz_bytes_len(proof));
            let decoded =
                <crate::ElectraAggregateAndProof as Decode>::from_ssz_bytes(&encoded).unwrap();
            assert_eq!(&decoded, proof);
        }
    }

    #[test]
    fn test_electra_aggregate_and_proof_rejects_bad_selection_proof_and_overlength_bits() {
        let mut bad_proof = electra_aap_with_bits(vec![0x01]);
        bad_proof.selection_proof = vec![0xbb; 95];
        assert!(ssz08_sig96(&bad_proof.selection_proof).is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Encode::as_ssz_bytes(&bad_proof)
        }))
        .is_err());

        // Bitlist[MAX_VALIDATORS_PER_SLOT=131072] encodes in at most 16385 bytes.
        let over = vec![0xff; 16386];
        assert!(ssz08_bitlist::<MaxValidatorsPerSlot>(&over).is_err());
        let over_proof = electra_aap_with_bits(over);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            Encode::as_ssz_bytes(&over_proof)
        }))
        .is_err());
    }
}
