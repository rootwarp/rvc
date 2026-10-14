//! Slashing protection types for EIP-3076 interchange format and internal records.
//!
//! # Internal records vs interchange DTOs (VD-5.5 / ARCH-5o)
//!
//! [`SignedAttestation`] and [`SignedBlock`] are **internal** history records.
//! `pubkey` is [`CanonicalPubkey`] (normalised); `signing_root` is stored TEXT
//! identity ([`SigningRoot`]), not hex-canonical — live equality is the same
//! string compare as before.
//!
//! The `Interchange*` types ([`InterchangeFormat`], [`InterchangeMetadata`],
//! [`ValidatorRecord`], [`InterchangeBlock`], [`InterchangeAttestation`]) are
//! the EIP-3076 **wire** format. Their `String` fields are mandated by the
//! spec (slot and epoch values serialize as JSON strings; pubkey and
//! signing_root are hex strings on the wire). They stay `String` so
//! import/export remains spec-compatible. Typed conversion happens at the
//! DTO↔record edges (`db/records.rs`, `db/interchange.rs`), not by changing
//! the DTOs. The PRD-literal "no `String` in `types.rs`" criterion is
//! unsatisfiable for that reason (VD-5.5).
//!
//! # `signing_root` representation
//!
//! Internal `signing_root` is the small [`SigningRoot`] newtype, **not**
//! [`eth_types::Root`] / [`eth_types::canonical::signing_root_hex::SigningRootHex`].
//! History TEXT columns and the existing test/legacy corpus store values that
//! are not 32-byte roots (`0xabcd`, `0xroot1`, `0xefgh`). A 32-byte `Root`
//! would reject those rows at the record edge. GVR already uses `Root` via
//! `parse_gvr_hex` because it is always 32 bytes.

use std::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

use eth_types::{Epoch, Slot};

pub use observability::pubkey::CanonicalPubkey;

/// Statistics returned by a prune operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneStats {
    pub attestations_deleted: u64,
    pub blocks_deleted: u64,
}

/// Stored TEXT signing root on internal slashing history rows.
///
/// Wraps the column value as-is. Equality is string identity (`0xABCD` ≠
/// `0xabcd`). Not a 32-byte `eth_types::Root` — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SigningRoot(String);

impl SigningRoot {
    /// Wrap a stored or wire string (DTO↔record edge / trusted DB read).
    pub fn from_hex(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Stored TEXT form used on the interchange DTO edge and in SQL binds.
    pub fn as_hex(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for SigningRoot {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Deref for SigningRoot {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SigningRoot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<SigningRoot> for String {
    fn from(root: SigningRoot) -> Self {
        root.0
    }
}

impl PartialEq<str> for SigningRoot {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for SigningRoot {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for SigningRoot {
    fn eq(&self, other: &String) -> bool {
        &self.0 == other
    }
}

impl PartialEq<SigningRoot> for str {
    fn eq(&self, other: &SigningRoot) -> bool {
        self == other.0
    }
}

impl PartialEq<SigningRoot> for String {
    fn eq(&self, other: &SigningRoot) -> bool {
        self == &other.0
    }
}

/// Parse a pubkey for an internal slashing record.
///
/// Adopts [`CanonicalPubkey`] (no second pubkey type). `CanonicalPubkey`'s
/// `FromStr` is infallible, so "malformed" is a slashing-record policy on
/// top: after normalisation the hex body must be non-empty even-length
/// hex digits.
pub(crate) fn parse_record_pubkey(
    raw: &str,
) -> Result<CanonicalPubkey, crate::error::SlashingError> {
    let canonical = match raw.parse::<CanonicalPubkey>() {
        Ok(pk) => pk,
        Err(never) => match never {},
    };
    let body = canonical.as_ref().strip_prefix("0x").unwrap_or(canonical.as_ref());
    if body.is_empty() {
        return Err(crate::error::SlashingError::InvalidPubkey("empty"));
    }
    if body.len() % 2 != 0 || !body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(crate::error::SlashingError::InvalidPubkey("not hex"));
    }
    Ok(canonical)
}

/// Internal record of a signed attestation for slashing protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAttestation {
    pub pubkey: CanonicalPubkey,
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Option<SigningRoot>,
}

impl SignedAttestation {
    /// Extra slashing-record hex policy on pubkey; write paths use
    /// infallible `normalize_pubkey` instead.
    pub fn new(
        pubkey: &str,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root: Option<&str>,
    ) -> Result<Self, crate::error::SlashingError> {
        Ok(Self {
            pubkey: parse_record_pubkey(pubkey)?,
            source_epoch,
            target_epoch,
            signing_root: signing_root.map(SigningRoot::from_hex),
        })
    }

    /// Rebuild a record from already-stored TEXT columns (record edge).
    pub(crate) fn from_stored(
        pubkey: String,
        source_epoch: Epoch,
        target_epoch: Epoch,
        signing_root: Option<String>,
    ) -> Self {
        let pubkey = match pubkey.parse::<CanonicalPubkey>() {
            Ok(pk) => pk,
            Err(never) => match never {},
        };
        Self {
            pubkey,
            source_epoch,
            target_epoch,
            signing_root: signing_root.map(SigningRoot::from_hex),
        }
    }
}

/// Internal record of a signed block for slashing protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlock {
    pub pubkey: CanonicalPubkey,
    pub slot: Slot,
    pub signing_root: Option<SigningRoot>,
}

impl SignedBlock {
    /// Extra slashing-record hex policy on pubkey; write paths use
    /// infallible `normalize_pubkey` instead.
    pub fn new(
        pubkey: &str,
        slot: Slot,
        signing_root: Option<&str>,
    ) -> Result<Self, crate::error::SlashingError> {
        Ok(Self {
            pubkey: parse_record_pubkey(pubkey)?,
            slot,
            signing_root: signing_root.map(SigningRoot::from_hex),
        })
    }

    /// Rebuild a record from already-stored TEXT columns (record edge).
    pub(crate) fn from_stored(pubkey: String, slot: Slot, signing_root: Option<String>) -> Self {
        let pubkey = match pubkey.parse::<CanonicalPubkey>() {
            Ok(pk) => pk,
            Err(never) => match never {},
        };
        Self { pubkey, slot, signing_root: signing_root.map(SigningRoot::from_hex) }
    }
}

/// EIP-3076 interchange format root container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterchangeFormat {
    pub metadata: InterchangeMetadata,
    pub data: Vec<ValidatorRecord>,
}

/// Metadata for the EIP-3076 interchange format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterchangeMetadata {
    pub interchange_format_version: String,
    pub genesis_validators_root: String,
}

/// Validator signing history record in EIP-3076 format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub pubkey: String,
    pub signed_blocks: Vec<InterchangeBlock>,
    pub signed_attestations: Vec<InterchangeAttestation>,
}

/// Block signing record in EIP-3076 format.
/// Note: slot is serialized as string per EIP-3076 specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterchangeBlock {
    pub slot: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

/// Attestation signing record in EIP-3076 format.
/// Note: epoch values are serialized as strings per EIP-3076 specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterchangeAttestation {
    pub source_epoch: String,
    pub target_epoch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_root: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed_attestation_creation() {
        let attestation =
            SignedAttestation::new("0x1234", 100, 101, Some("0xabcd")).expect("valid hex pubkey");

        assert_eq!(attestation.pubkey.as_ref(), "0x1234");
        assert_eq!(attestation.source_epoch, 100);
        assert_eq!(attestation.target_epoch, 101);
        assert_eq!(attestation.signing_root.as_ref().map(|r| r.as_hex()), Some("0xabcd"));
    }

    #[test]
    fn test_signed_attestation_without_signing_root() {
        let attestation =
            SignedAttestation::new("0x1234", 100, 101, None).expect("valid hex pubkey");

        assert!(attestation.signing_root.is_none());
    }

    #[test]
    fn test_signed_block_creation() {
        let block = SignedBlock::new("0x1234", 1000, Some("0xabcd")).expect("valid hex pubkey");

        assert_eq!(block.pubkey.as_ref(), "0x1234");
        assert_eq!(block.slot, 1000);
        assert_eq!(block.signing_root.as_ref().map(|r| r.as_hex()), Some("0xabcd"));
    }

    #[test]
    fn test_interchange_metadata_json_roundtrip() {
        let metadata = InterchangeMetadata {
            interchange_format_version: "5".to_string(),
            genesis_validators_root:
                "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673".to_string(),
        };

        let json = serde_json::to_string(&metadata).expect("serialization should succeed");
        let deserialized: InterchangeMetadata =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(metadata, deserialized);
    }

    #[test]
    fn test_interchange_block_json_roundtrip() {
        let block = InterchangeBlock {
            slot: "81952".to_string(),
            signing_root: Some(
                "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b".to_string(),
            ),
        };

        let json = serde_json::to_string(&block).expect("serialization should succeed");
        let deserialized: InterchangeBlock =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_interchange_block_without_signing_root() {
        let block = InterchangeBlock { slot: "81952".to_string(), signing_root: None };

        let json = serde_json::to_string(&block).expect("serialization should succeed");

        assert!(!json.contains("signing_root"));

        let deserialized: InterchangeBlock =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(block, deserialized);
    }

    #[test]
    fn test_interchange_attestation_json_roundtrip() {
        let attestation = InterchangeAttestation {
            source_epoch: "2290".to_string(),
            target_epoch: "3007".to_string(),
            signing_root: Some(
                "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d".to_string(),
            ),
        };

        let json = serde_json::to_string(&attestation).expect("serialization should succeed");
        let deserialized: InterchangeAttestation =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_interchange_attestation_without_signing_root() {
        let attestation = InterchangeAttestation {
            source_epoch: "2290".to_string(),
            target_epoch: "3007".to_string(),
            signing_root: None,
        };

        let json = serde_json::to_string(&attestation).expect("serialization should succeed");

        assert!(!json.contains("signing_root"));

        let deserialized: InterchangeAttestation =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(attestation, deserialized);
    }

    #[test]
    fn test_validator_record_json_roundtrip() {
        let record = ValidatorRecord {
            pubkey: "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
                .to_string(),
            signed_blocks: vec![InterchangeBlock {
                slot: "81952".to_string(),
                signing_root: Some(
                    "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                        .to_string(),
                ),
            }],
            signed_attestations: vec![InterchangeAttestation {
                source_epoch: "2290".to_string(),
                target_epoch: "3007".to_string(),
                signing_root: Some(
                    "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
                        .to_string(),
                ),
            }],
        };

        let json = serde_json::to_string(&record).expect("serialization should succeed");
        let deserialized: ValidatorRecord =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(record, deserialized);
    }

    #[test]
    fn test_full_interchange_format_json_roundtrip() {
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root:
                    "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
                        .to_string(),
            },
            data: vec![
                ValidatorRecord {
                    pubkey: "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
                        .to_string(),
                    signed_blocks: vec![
                        InterchangeBlock {
                            slot: "81952".to_string(),
                            signing_root: Some(
                                "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                                    .to_string(),
                            ),
                        },
                    ],
                    signed_attestations: vec![
                        InterchangeAttestation {
                            source_epoch: "2290".to_string(),
                            target_epoch: "3007".to_string(),
                            signing_root: Some(
                                "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
                                    .to_string(),
                            ),
                        },
                    ],
                },
            ],
        };

        let json =
            serde_json::to_string_pretty(&interchange).expect("serialization should succeed");
        let deserialized: InterchangeFormat =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(interchange, deserialized);
    }

    #[test]
    fn test_interchange_format_eip3076_example() {
        let json = r#"{
            "metadata": {
                "interchange_format_version": "5",
                "genesis_validators_root": "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
            },
            "data": [
                {
                    "pubkey": "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed",
                    "signed_blocks": [
                        {
                            "slot": "81952",
                            "signing_root": "0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b"
                        }
                    ],
                    "signed_attestations": [
                        {
                            "source_epoch": "2290",
                            "target_epoch": "3007",
                            "signing_root": "0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d"
                        }
                    ]
                }
            ]
        }"#;

        let interchange: InterchangeFormat =
            serde_json::from_str(json).expect("deserialization should succeed");

        assert_eq!(interchange.metadata.interchange_format_version, "5");
        assert_eq!(
            interchange.metadata.genesis_validators_root,
            "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
        );
        assert_eq!(interchange.data.len(), 1);

        let validator = &interchange.data[0];
        assert_eq!(
            validator.pubkey,
            "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
        );
        assert_eq!(validator.signed_blocks.len(), 1);
        assert_eq!(validator.signed_attestations.len(), 1);

        let block = &validator.signed_blocks[0];
        assert_eq!(block.slot, "81952");
        assert_eq!(
            block.signing_root,
            Some("0x4ff6f743a43f3b4f95350831aeaf0a122a1a392922c45d804280284a69eb850b".to_string())
        );

        let attestation = &validator.signed_attestations[0];
        assert_eq!(attestation.source_epoch, "2290");
        assert_eq!(attestation.target_epoch, "3007");
        assert_eq!(
            attestation.signing_root,
            Some("0x587d6a4f59a58fe24f406e0502413e77fe1babddee641fda30034ed37ecc884d".to_string())
        );
    }

    #[test]
    fn test_interchange_format_empty_data() {
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root:
                    "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673".to_string(),
            },
            data: vec![],
        };

        let json = serde_json::to_string(&interchange).expect("serialization should succeed");
        let deserialized: InterchangeFormat =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(interchange, deserialized);
        assert!(deserialized.data.is_empty());
    }

    #[test]
    fn test_validator_record_empty_blocks_and_attestations() {
        let record = ValidatorRecord {
            pubkey: "0xb845089a1457f811bfc000588fbb4e713669be8ce060ea6be3c6ece09afc3794106c91ca73acda5e5457122d58723bed"
                .to_string(),
            signed_blocks: vec![],
            signed_attestations: vec![],
        };

        let json = serde_json::to_string(&record).expect("serialization should succeed");
        let deserialized: ValidatorRecord =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(record, deserialized);
        assert!(deserialized.signed_blocks.is_empty());
        assert!(deserialized.signed_attestations.is_empty());
    }

    #[test]
    fn test_multiple_validators_in_interchange() {
        let interchange = InterchangeFormat {
            metadata: InterchangeMetadata {
                interchange_format_version: "5".to_string(),
                genesis_validators_root:
                    "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673".to_string(),
            },
            data: vec![
                ValidatorRecord {
                    pubkey: "0xaaa".to_string(),
                    signed_blocks: vec![InterchangeBlock {
                        slot: "100".to_string(),
                        signing_root: None,
                    }],
                    signed_attestations: vec![],
                },
                ValidatorRecord {
                    pubkey: "0xbbb".to_string(),
                    signed_blocks: vec![],
                    signed_attestations: vec![InterchangeAttestation {
                        source_epoch: "10".to_string(),
                        target_epoch: "11".to_string(),
                        signing_root: None,
                    }],
                },
            ],
        };

        let json = serde_json::to_string(&interchange).expect("serialization should succeed");
        let deserialized: InterchangeFormat =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(interchange, deserialized);
        assert_eq!(deserialized.data.len(), 2);
    }

    /// ARCH-5o / CLAUDE.md: production slashing code must not `.expect(`.
    #[test]
    fn test_no_expect_in_slashing_production_code() {
        let src_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut rs_files = Vec::new();
        collect_rs_files(&src_root, &mut rs_files);
        assert!(!rs_files.is_empty(), "expected crates/slashing/src/**/*.rs");

        let mut hits = Vec::new();
        for path in &rs_files {
            let src = std::fs::read_to_string(path).unwrap_or_else(|e| {
                panic!("read {}: {e}", path.display());
            });
            let production = strip_cfg_test_items(&src);
            for (idx, line) in production.lines().enumerate() {
                if line.contains(".expect(") {
                    hits.push(format!("{}:{}:{line}", path.display(), idx + 1));
                }
            }
        }

        assert!(
            hits.is_empty(),
            "production crates/slashing/src/** must not contain `.expect(` \
             (exclude #[cfg(test)] items): {hits:?}"
        );
    }

    #[test]
    fn test_signed_block_rejects_a_malformed_pubkey_at_construction() {
        let err = SignedBlock::new("not-a-pubkey", 1000, Some("0xabcd"))
            .expect_err("malformed pubkey must fail at construction");
        assert!(
            matches!(err, crate::error::SlashingError::InvalidPubkey(_)),
            "expected InvalidPubkey, got: {err:?}"
        );
    }

    #[test]
    fn test_interchange_dtos_still_serialize_strings() {
        let block = InterchangeBlock { slot: "81952".to_string(), signing_root: None };
        let json = serde_json::to_string(&block).expect("serialization should succeed");
        let value: serde_json::Value =
            serde_json::from_str(&json).expect("json value parse should succeed");
        assert!(value["slot"].is_string(), "EIP-3076 slot must stay a JSON string: {json}");
        assert_eq!(value["slot"], "81952");
    }

    fn collect_rs_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        let entries = std::fs::read_dir(dir).unwrap_or_else(|e| {
            panic!("read_dir {}: {e}", dir.display());
        });
        for entry in entries {
            let entry = entry.unwrap_or_else(|e| panic!("dir entry: {e}"));
            let path = entry.path();
            if path.is_dir() {
                collect_rs_files(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// Drop `#[cfg(test)]` items (modules, fns, impls) so their `.expect(` is ignored.
    fn strip_cfg_test_items(src: &str) -> String {
        let lines: Vec<&str> = src.lines().collect();
        let mut out = String::new();
        let mut i = 0;
        while i < lines.len() {
            if lines[i].trim() == "#[cfg(test)]" {
                i += 1;
                while i < lines.len() && lines[i].trim().starts_with("#[") {
                    i += 1;
                }
                if i < lines.len() {
                    i = skip_item(&lines, i);
                }
                continue;
            }
            out.push_str(lines[i]);
            out.push('\n');
            i += 1;
        }
        out
    }

    fn skip_item(lines: &[&str], start: usize) -> usize {
        let mut i = start;
        let mut depth = 0i32;
        let mut seen_brace = false;
        while i < lines.len() {
            for ch in lines[i].chars() {
                match ch {
                    '{' => {
                        depth += 1;
                        seen_brace = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            i += 1;
            if seen_brace && depth <= 0 {
                return i;
            }
            if !seen_brace && lines[i - 1].contains(';') {
                return i;
            }
        }
        i
    }
}
