use async_trait::async_trait;

use eth_types::{
    ForkName, SignedBeaconBlock, SignedBlindedBeaconBlock, SignedBlockContentsJson, Slot,
};

use crate::BlockServiceError;

pub use beacon::{BuilderConfig, ProduceBlockResponse, RankedBlock, WireBody};

/// Cached V4 `BuilderConfig` (6.17 signed auth). Implemented in `rvc`, not here:
/// `rvc-block-service → rvc-builder` is a forbidden edge.
#[async_trait]
pub trait BuilderConfigProvider: Send + Sync {
    async fn builder_config_for(&self, pubkey: &[u8; 48], slot: Slot) -> BuilderConfig;
}

/// Duty fields applied before a produced block is ranked or returned.
#[derive(Debug, Clone, Copy)]
pub struct ProduceDuty {
    pub expected_proposer_index: u64,
    pub expected_parent_root: Option<[u8; 32]>,
    /// Parent of [`Self::expected_parent_root`] when that header is at N-1.
    ///
    /// A block on this root is accepted, but it does not close the soft
    /// deadline and the unsynced fallback does not use it. `None` when the
    /// captured header is below N-1, or when the primary parent is unknown.
    pub alternate_parent_root: Option<[u8; 32]>,
    /// The parent walk cannot name an ancestor. Every parent is rejected.
    /// [`Self::expected_parent_root`] stays `None`.
    pub parent_closed: bool,
    pub expected_fee_recipient: Option<[u8; 20]>,
    /// Slot fork. A candidate whose `consensus_version` is not this fork is
    /// not ranked and does not close the soft deadline.
    pub expected_consensus_version: ForkName,
}

/// Minimal beacon client trait for block production and publication.
///
/// Defined locally for testability; the real `beacon::BeaconClient`
/// can be adapted to implement this trait.
#[async_trait]
pub trait BeaconBlockClient: Send + Sync {
    fn duty_fence(&self) -> Result<beacon::DutyFence, BlockServiceError> {
        Ok(beacon::DutyFence::open())
    }

    async fn produce_block_v3(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError>;

    /// [`Self::produce_block_v3`] plus the duty checks applied before ranking.
    ///
    /// The default ignores the duty and calls [`Self::produce_block_v3`].
    /// `BnManager` uses the checks to drop a block that fails slot, proposer,
    /// parent, or consensus version before it can win, and to keep fallback
    /// on proposal-role nodes when [`ProduceDuty::expected_parent_root`] is
    /// known.
    async fn produce_block_v3_for_duty(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        duty: ProduceDuty,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        let _ = duty;
        self.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await
    }

    /// Every arrived produce-block candidate, best first.
    ///
    /// The default ignores `duty` and returns one candidate from
    /// [`Self::produce_block_v3`]. `BnManager` returns the value-ranked list
    /// and applies `duty` before a candidate can be signed.
    /// [`Self::produce_block_v3`] and [`Self::produce_block_v3_for_duty`] are
    /// the head of that list.
    async fn produce_block_v3_ranked(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        duty: Option<ProduceDuty>,
    ) -> Result<Vec<RankedBlock>, BlockServiceError> {
        let _ = duty;
        let response =
            self.produce_block_v3(slot, randao_reveal, graffiti, builder_boost_factor).await?;
        Ok(vec![RankedBlock { bn_index: 0, response }])
    }

    /// [`Self::produce_block_v3_ranked`] capped at `deadline` for this call only.
    ///
    /// The default ignores `deadline`.
    async fn produce_block_v3_ranked_by(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
        duty: Option<ProduceDuty>,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<Vec<RankedBlock>, BlockServiceError> {
        let _ = deadline;
        self.produce_block_v3_ranked(slot, randao_reveal, graffiti, builder_boost_factor, duty)
            .await
    }

    async fn produce_block_v4(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BlockServiceError>;

    /// [`Self::produce_block_v4`] capped at `deadline` for this call only.
    ///
    /// The default ignores `deadline`.
    async fn produce_block_v4_by(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        let _ = deadline;
        self.produce_block_v4(slot, randao_reveal, graffiti, builder_config).await
    }

    /// `builder_url` is the produce-time `Eth-Builder-Url` echo; omit the header when `None`.
    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
        builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError>;

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError>;

    /// Publish a block as raw SSZ bytes using `Content-Type: application/octet-stream`.
    /// `builder_url` is the produce-time `Eth-Builder-Url` echo; omit the header when `None`.
    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
        builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError>;

    /// Publish `{signed_block, kzg_proofs, blobs}` as JSON.
    ///
    /// Overriding is required for any client on a live JSON publish path. The
    /// default exists so test doubles fail closed rather than silently dropping
    /// sidecars.
    async fn publish_block_contents(
        &self,
        _contents: &SignedBlockContentsJson,
        _consensus_version: &str,
        _builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        Err(BlockServiceError::Unsupported("publish_block_contents"))
    }

    async fn publish_execution_payload_envelope(
        &self,
        signed_envelope: &WireBody,
        blobs: &WireBody,
        kzg_proofs: &WireBody,
        consensus_version: &str,
        broadcast_validation: Option<&str>,
    ) -> Result<(), BlockServiceError>;
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crates/")
            .parent()
            .expect("workspace root")
            .to_path_buf()
    }

    fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rs(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    /// M9: `rg` for the ProduceBlockResponse struct over `crates/**/src` is one path.
    /// Needle is assembled so this file cannot itself match the scan.
    #[test]
    fn only_one_produce_block_response_definition_exists() {
        let root = workspace_root();
        let crates_dir = root.join("crates");
        let needle = ["struct ", "ProduceBlockResponse"].concat();
        let mut hits = Vec::new();

        let entries = std::fs::read_dir(&crates_dir).expect("read crates/");
        for entry in entries.flatten() {
            let src = entry.path().join("src");
            if !src.is_dir() {
                continue;
            }
            let mut files = Vec::new();
            collect_rs(&src, &mut files);
            for file in files {
                let Ok(contents) = std::fs::read_to_string(&file) else {
                    continue;
                };
                if contents.contains(&needle) {
                    let rel = file.strip_prefix(&root).unwrap_or(&file);
                    hits.push(rel.display().to_string());
                }
            }
        }
        hits.sort();

        let expected =
            Path::new("crates").join("beacon").join("src").join("types.rs").display().to_string();
        assert_eq!(
            hits.as_slice(),
            [expected.as_str()],
            "ProduceBlockResponse must have exactly one struct definition under crates/**/src; found: {hits:?}"
        );
    }
}

#[cfg(test)]
struct BareClient;

#[cfg(test)]
#[async_trait]
impl BeaconBlockClient for BareClient {
    async fn produce_block_v3(
        &self,
        _slot: eth_types::Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        unreachable!("unused")
    }

    async fn produce_block_v4(
        &self,
        _slot: eth_types::Slot,
        _randao_reveal: &str,
        _graffiti: Option<&str>,
        _builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BlockServiceError> {
        unreachable!("unused")
    }

    async fn publish_block(
        &self,
        _signed_block: &eth_types::SignedBeaconBlock,
        _consensus_version: &str,
        _builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        unreachable!("unused")
    }

    async fn publish_blinded_block(
        &self,
        _signed_block: &eth_types::SignedBlindedBeaconBlock,
        _consensus_version: &str,
    ) -> Result<(), BlockServiceError> {
        unreachable!("unused")
    }

    async fn publish_block_ssz(
        &self,
        _ssz_bytes: &[u8],
        _consensus_version: &str,
        _is_blinded: bool,
        _builder_url: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        unreachable!("unused")
    }

    async fn publish_execution_payload_envelope(
        &self,
        _signed_envelope: &WireBody,
        _blobs: &WireBody,
        _kzg_proofs: &WireBody,
        _consensus_version: &str,
        _broadcast_validation: Option<&str>,
    ) -> Result<(), BlockServiceError> {
        unreachable!("unused")
    }
}

#[cfg(test)]
#[tokio::test]
async fn default_publish_block_contents_is_an_error() {
    let signed = eth_types::SignedBeaconBlock {
        message: eth_types::external_vector_electra_block(),
        signature: vec![0x11; eth_types::SIGNATURE_BYTES_LEN],
    };
    let contents = eth_types::SignedBlockContentsJson::from_signed_block(
        &signed,
        Vec::new(),
        Vec::new(),
        eth_types::BodyForkLayout::Electra,
    )
    .expect("electra body encodes");

    let err = BareClient.publish_block_contents(&contents, "electra", None).await.unwrap_err();
    match err {
        BlockServiceError::Unsupported(op) => assert_eq!(op, "publish_block_contents"),
        other => panic!("expected Unsupported, got {other}"),
    }
}
