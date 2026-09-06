use async_trait::async_trait;

use eth_types::{SignedBeaconBlock, SignedBlindedBeaconBlock, Slot};

use crate::BlockServiceError;

pub use beacon::{BuilderConfig, ProduceBlockResponse};

/// Minimal beacon client trait for block production and publication.
///
/// Defined locally for testability; the real `beacon::BeaconClient`
/// can be adapted to implement this trait.
#[async_trait]
pub trait BeaconBlockClient: Send + Sync {
    async fn produce_block_v3(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_boost_factor: Option<u64>,
    ) -> Result<ProduceBlockResponse, BlockServiceError>;

    async fn produce_block_v4(
        &self,
        slot: Slot,
        randao_reveal: &str,
        graffiti: Option<&str>,
        builder_config: &BuilderConfig,
    ) -> Result<ProduceBlockResponse, BlockServiceError>;

    async fn publish_block(
        &self,
        signed_block: &SignedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError>;

    async fn publish_blinded_block(
        &self,
        signed_block: &SignedBlindedBeaconBlock,
        consensus_version: &str,
    ) -> Result<(), BlockServiceError>;

    /// Publish a block as raw SSZ bytes using `Content-Type: application/octet-stream`.
    async fn publish_block_ssz(
        &self,
        ssz_bytes: &[u8],
        consensus_version: &str,
        is_blinded: bool,
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
