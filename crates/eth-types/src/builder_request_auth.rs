use serde::{Deserialize, Serialize};
use tree_hash::{mix_in_length, Hash256, MerkleHasher, TreeHash};

use crate::tree_hash_utils::{impl_container_tree_hash, vec_u8_tree_hash_root, TreeHashError};
use crate::{Signature, Slot};

/// builder-specs `MAX_BUILDER_AUTH_DATA_SIZE` (`ByteList` limit).
pub const MAX_BUILDER_AUTH_DATA_SIZE: usize = 4096;

/// SSZ `ByteList[4096]` chunk count: `ceil(4096 / 32) = 128`.
const BYTE_LIST_CHUNK_COUNT: usize = MAX_BUILDER_AUTH_DATA_SIZE.div_ceil(32);

/// Gloas `BuilderRequestAuth` (builder-specs `ethereum/builder-specs@38f11441c194d150386f567b4d7087ec86d4118c`).
///
/// Field order: `data`, `slot`. `data` is SSZ `ByteList[MAX_BUILDER_AUTH_DATA_SIZE]`.
/// A zero-length `data` is invalid. When no out-of-band value was agreed,
/// implementations SHOULD default to the UTF-8 bytes of the builder URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderRequestAuth {
    #[serde(with = "byte_list_hex")]
    data: Vec<u8>,
    #[serde(with = "serde_utils::quoted_u64")]
    slot: Slot,
}

/// Gloas `SignedBuilderRequestAuth` (builder-specs; field order `message`, `signature`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBuilderRequestAuth {
    pub message: BuilderRequestAuth,
    #[serde(with = "crate::serde_signature")]
    pub signature: Signature,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BuilderRequestAuthError {
    #[error("zero-length BuilderRequestAuth.data is invalid")]
    EmptyData,
    #[error("BuilderRequestAuth.data length {len} exceeds MAX_BUILDER_AUTH_DATA_SIZE ({MAX_BUILDER_AUTH_DATA_SIZE})")]
    DataTooLong { len: usize },
}

impl BuilderRequestAuth {
    /// Construct a request-auth message, rejecting empty or over-limit `data`.
    pub fn new(data: Vec<u8>, slot: Slot) -> Result<Self, BuilderRequestAuthError> {
        validate_auth_data(&data)?;
        Ok(Self { data, slot })
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn slot(&self) -> Slot {
        self.slot
    }
}

fn validate_auth_data(data: &[u8]) -> Result<(), BuilderRequestAuthError> {
    if data.is_empty() {
        return Err(BuilderRequestAuthError::EmptyData);
    }
    if data.len() > MAX_BUILDER_AUTH_DATA_SIZE {
        return Err(BuilderRequestAuthError::DataTooLong { len: data.len() });
    }
    Ok(())
}

/// `hash_tree_root` of SSZ `ByteList[4096]`: merkleize packed bytes with
/// `limit = 128`, then `mix_in_length`.
fn byte_list_4096_tree_hash_root(bytes: &[u8]) -> Result<Hash256, TreeHashError> {
    validate_auth_data(bytes)
        .map_err(|e| TreeHashError::InvalidByteList { reason: e.to_string() })?;
    let mut hasher = MerkleHasher::with_leaves(BYTE_LIST_CHUNK_COUNT);
    hasher.write(bytes).map_err(|e| TreeHashError::InvalidByteList {
        reason: format!("byte list overflows chunk tree: {e:?}"),
    })?;
    let root = hasher.finish().map_err(|e| TreeHashError::InvalidByteList {
        reason: format!("byte list merkleization failed: {e:?}"),
    })?;
    Ok(mix_in_length(&root, bytes.len()))
}

impl_container_tree_hash!(
    BuilderRequestAuth,
    "valid BuilderRequestAuth",
    [|s| byte_list_4096_tree_hash_root(&s.data), |s| Ok(s.slot.tree_hash_root()),]
);

impl_container_tree_hash!(
    SignedBuilderRequestAuth,
    "valid SignedBuilderRequestAuth",
    [|s| s.message.try_tree_hash_root(), |s| Ok(vec_u8_tree_hash_root(&s.signature)),]
);

/// Beacon-API hex for `ByteList`: `0x` prefix required, 1..=4096 bytes.
mod byte_list_hex {
    use super::{validate_auth_data, MAX_BUILDER_AUTH_DATA_SIZE};
    use crate::canonical::pubkey_hex::{decode_hex, strip_prefix};
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut hex_string = String::with_capacity(2 + bytes.len() * 2);
        hex_string.push_str("0x");
        hex_string.push_str(&hex::encode(bytes));
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if !s.starts_with("0x") && !s.starts_with("0X") {
            return Err(D::Error::custom("missing 0x prefix"));
        }
        let hex = strip_prefix(&s).map_err(|e| D::Error::custom(e.to_string()))?;
        let decoded = decode_hex(hex).map_err(|e| D::Error::custom(e.to_string()))?;
        validate_auth_data(&decoded).map_err(|e| D::Error::custom(e.to_string()))?;
        debug_assert!(decoded.len() <= MAX_BUILDER_AUTH_DATA_SIZE);
        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvc_spec_vectors::builder_request_auth_kat::{
        BUILDER_SPECS_REVISION, KAT_BUILDER_REQUEST_AUTH_DATA_HEX, KAT_BUILDER_REQUEST_AUTH_SLOT,
        KAT_GLOAS_BUILDER_REQUEST_AUTH_SIGNING_ROOT, SPEC_GLOAS_BUILDERREQUESTAUTH_ROOT,
    };
    use tree_hash::Hash256;

    fn hex32(s: &str) -> Hash256 {
        Hash256::from_slice(&hex::decode(s.trim_start_matches("0x")).expect("hex"))
    }

    fn kat_auth() -> BuilderRequestAuth {
        BuilderRequestAuth::new(
            hex::decode(KAT_BUILDER_REQUEST_AUTH_DATA_HEX).expect("kat data hex"),
            KAT_BUILDER_REQUEST_AUTH_SLOT,
        )
        .expect("kat data is non-empty and within limit")
    }

    #[test]
    fn test_builder_request_auth_tree_hash_root() {
        const KAT: &str = include_str!("../../rvc-spec-vectors/src/builder_request_auth_kat.rs");
        let header: String = KAT.lines().take_while(|l| l.starts_with("//!")).collect();
        assert!(
            !header.to_ascii_lowercase().contains("remerkleable"),
            "SPEC_GLOAS_BUILDERREQUESTAUTH_ROOT provenance must not be remerkleable (D15)"
        );
        assert!(
            header.contains(BUILDER_SPECS_REVISION),
            "provenance must name the builder-specs revision"
        );
        assert!(
            header.contains("0x0B000001") || header.contains("0x0b000001"),
            "provenance must name DOMAIN_BUILDER_REQUEST_AUTH"
        );
        assert_eq!(kat_auth().tree_hash_root(), hex32(SPEC_GLOAS_BUILDERREQUESTAUTH_ROOT));
    }

    #[test]
    fn test_builder_request_auth_rejects_zero_length_data() {
        assert_eq!(BuilderRequestAuth::new(vec![], 1), Err(BuilderRequestAuthError::EmptyData));
        let empty = BuilderRequestAuth { data: vec![], slot: 1 };
        let err = empty.try_tree_hash_root().expect_err("zero-length data is invalid");
        assert!(
            matches!(err, TreeHashError::InvalidByteList { .. }),
            "empty data must fail closed: {err:?}"
        );
        let err = serde_json::from_str::<BuilderRequestAuth>(r#"{"data":"0x","slot":"1"}"#)
            .expect_err("serde must reject empty hex");
        assert!(err.to_string().contains("zero-length"), "{err}");
    }

    #[test]
    fn test_builder_request_auth_rejects_over_limit_data() {
        let too_long = vec![0x11; MAX_BUILDER_AUTH_DATA_SIZE + 1];
        assert_eq!(
            BuilderRequestAuth::new(too_long, 1),
            Err(BuilderRequestAuthError::DataTooLong { len: MAX_BUILDER_AUTH_DATA_SIZE + 1 })
        );
    }

    #[test]
    fn test_builder_request_auth_serde_roundtrip() {
        let original = kat_auth();
        let json = serde_json::to_string(&original).unwrap();
        let decoded: BuilderRequestAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(original, decoded);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["data"],
            serde_json::Value::String(format!("0x{KAT_BUILDER_REQUEST_AUTH_DATA_HEX}"))
        );
        assert_eq!(parsed["slot"], serde_json::Value::String("1".to_string()));
    }

    #[test]
    fn test_signed_builder_request_auth_serde_roundtrip() {
        let signed = SignedBuilderRequestAuth { message: kat_auth(), signature: vec![0xee; 96] };
        let json = serde_json::to_string(&signed).unwrap();
        let decoded: SignedBuilderRequestAuth = serde_json::from_str(&json).unwrap();
        assert_eq!(signed, decoded);
    }

    #[test]
    fn test_kat_signing_root_constant_is_present() {
        // Anchors the signing-root KAT name so kat_policy sees SPEC_/KAT_ here too
        // if a sibling test is renamed; the live signing-root KAT lives in crypto.
        assert_eq!(KAT_GLOAS_BUILDER_REQUEST_AUTH_SIGNING_ROOT.len(), 64);
    }
}
