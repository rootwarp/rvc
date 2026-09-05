//! Wiremock-backed beacon node stub for CLI startup smoke tests (RF5-01).
//!
//! Serves the BN HTTP endpoints required for `rvc start` to pass genesis-root
//! validation, fork-schedule fetch, and fork-compat check. Optional duty /
//! block-root stubs keep the post-ready duty loop from spamming hard failures.

use eth_types::{ForkName, NetworkPreset};
use wiremock::matchers::{method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Mainnet GVR used by default config (`network = "mainnet"`).
pub const MAINNET_GVR: &str = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95";

/// A running mock beacon node. Drop to tear down the HTTP server.
pub struct MockBn {
    server: MockServer,
    genesis_validators_root: String,
    genesis_time: u64,
    head_fork_version: String,
}

/// Builder for [`MockBn`]. Prefer [`MockBn::start`] for defaults.
#[derive(Debug, Clone)]
pub struct MockBnBuilder {
    genesis_validators_root: String,
    genesis_time: u64,
    head_fork: ForkName,
    /// When set, overrides the head-fork `current_version` (for mismatch tests).
    head_fork_version_override: Option<String>,
}

impl Default for MockBnBuilder {
    fn default() -> Self {
        Self {
            genesis_validators_root: MAINNET_GVR.to_string(),
            genesis_time: NetworkPreset::MAINNET.genesis_time,
            head_fork: ForkName::Electra,
            head_fork_version_override: None,
        }
    }
}

impl MockBnBuilder {
    /// Point the mock genesis validators root at a specific value.
    pub fn with_genesis_validators_root(mut self, gvr: impl Into<String>) -> Self {
        self.genesis_validators_root = gvr.into();
        self
    }

    /// Select which known fork the head state reports.
    pub fn with_fork(mut self, fork: ForkName) -> Self {
        self.head_fork = fork;
        self.head_fork_version_override = None;
        self
    }

    /// Force an arbitrary head fork version hex (e.g. unsupported `0xdeadbeef`).
    pub fn with_head_fork_version(mut self, version_hex: impl Into<String>) -> Self {
        self.head_fork_version_override = Some(version_hex.into());
        self
    }

    /// Start the mock server and mount startup endpoints.
    pub async fn start(self) -> MockBn {
        let server = MockServer::start().await;
        let head_fork_version =
            self.head_fork_version_override.unwrap_or_else(|| fork_version_hex(self.head_fork));

        let bn = MockBn {
            server,
            genesis_validators_root: self.genesis_validators_root,
            genesis_time: self.genesis_time,
            head_fork_version,
        };
        bn.mount_endpoints().await;
        bn
    }
}

impl MockBn {
    /// Start a mock BN with mainnet-compatible genesis and Electra head fork.
    pub async fn start() -> Self {
        MockBnBuilder::default().start().await
    }

    /// Builder entry point (same as [`MockBnBuilder::default`]).
    pub fn builder() -> MockBnBuilder {
        MockBnBuilder::default()
    }

    /// Convenience: builder with a known fork (see [`MockBnBuilder::with_fork`]).
    #[allow(dead_code)] // known-fork ready path still covered by default Electra
    pub fn with_fork(fork: ForkName) -> MockBnBuilder {
        MockBnBuilder::default().with_fork(fork)
    }

    /// Base URL of the mock (e.g. `http://127.0.0.1:PORT`).
    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// Genesis validators root the mock advertises.
    #[allow(dead_code)]
    pub fn genesis_validators_root(&self) -> &str {
        &self.genesis_validators_root
    }

    async fn mount_endpoints(&self) {
        let gvr = &self.genesis_validators_root;
        let genesis_time = self.genesis_time.to_string();
        let head_fork_version = &self.head_fork_version;

        // /eth/v1/beacon/genesis
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/genesis"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "genesis_time": genesis_time,
                    "genesis_validators_root": gvr,
                    "genesis_fork_version": "0x00000000"
                }
            })))
            .mount(&self.server)
            .await;

        // /eth/v1/config/spec — full enough for ForkSchedule parsing
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/spec"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "GENESIS_FORK_VERSION": "0x00000000",
                    "ALTAIR_FORK_EPOCH": "74240",
                    "ALTAIR_FORK_VERSION": "0x01000000",
                    "BELLATRIX_FORK_EPOCH": "144896",
                    "BELLATRIX_FORK_VERSION": "0x02000000",
                    "CAPELLA_FORK_EPOCH": "194048",
                    "CAPELLA_FORK_VERSION": "0x03000000",
                    "DENEB_FORK_EPOCH": "269568",
                    "DENEB_FORK_VERSION": "0x04000000",
                    "ELECTRA_FORK_EPOCH": "364544",
                    "ELECTRA_FORK_VERSION": "0x05000000",
                    "FULU_FORK_EPOCH": "18446744073709551615",
                    "FULU_FORK_VERSION": "0x06000000",
                    "GLOAS_FORK_EPOCH": "18446744073709551615",
                    "GLOAS_FORK_VERSION": "0x07000000",
                    "SECONDS_PER_SLOT": "12",
                    "SLOTS_PER_EPOCH": "32"
                }
            })))
            .mount(&self.server)
            .await;

        // /eth/v1/config/fork_schedule (not used by current client, but listed in the issue)
        Mock::given(method("GET"))
            .and(path("/eth/v1/config/fork_schedule"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": []
            })))
            .mount(&self.server)
            .await;

        // /eth/v1/node/syncing
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "is_syncing": false,
                    "is_optimistic": false,
                    "el_offline": false,
                    "head_slot": "10000000",
                    "sync_distance": "0"
                }
            })))
            .mount(&self.server)
            .await;

        // /eth/v1/node/version
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/version"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "version": "mock-bn/rf5-01" }
            })))
            .mount(&self.server)
            .await;

        // GET /eth/v1/beacon/states/head/fork — fork-compat gate
        Mock::given(method("GET"))
            .and(path("/eth/v1/beacon/states/head/fork"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "execution_optimistic": false,
                "finalized": false,
                "data": {
                    "previous_version": "0x04000000",
                    "current_version": head_fork_version,
                    "epoch": "364544"
                }
            })))
            .mount(&self.server)
            .await;

        // POST /eth/v1/beacon/states/head/validators — index resolution (empty set)
        Mock::given(method("POST"))
            .and(path("/eth/v1/beacon/states/head/validators"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "execution_optimistic": false,
                "finalized": false,
                "data": []
            })))
            .mount(&self.server)
            .await;

        // GET form of validators (small-set path)
        Mock::given(method("GET"))
            .and(path_regex(r"^/eth/v1/beacon/states/head/validators.*"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "execution_optimistic": false,
                "finalized": false,
                "data": []
            })))
            .mount(&self.server)
            .await;

        // Soft stubs so the duty loop does not thrash on hard 404s.
        Mock::given(method("GET"))
            .and(path_regex(r"^/eth/v1/beacon/blocks/.+/root$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "execution_optimistic": false,
                "finalized": false,
                "data": {
                    "root": "0x0000000000000000000000000000000000000000000000000000000000000001"
                }
            })))
            .mount(&self.server)
            .await;

        Mock::given(method("GET"))
            .and(path_regex(r"^/eth/v1/validator/duties/proposer/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000002",
                "execution_optimistic": false,
                "data": []
            })))
            .mount(&self.server)
            .await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/eth/v1/validator/duties/attester/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "dependent_root": "0x0000000000000000000000000000000000000000000000000000000000000003",
                "execution_optimistic": false,
                "data": []
            })))
            .mount(&self.server)
            .await;

        Mock::given(method("POST"))
            .and(path_regex(r"^/eth/v1/validator/duties/sync/\d+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "execution_optimistic": false,
                "data": []
            })))
            .mount(&self.server)
            .await;
    }
}

fn fork_version_hex(fork: ForkName) -> String {
    match fork {
        ForkName::Phase0 => "0x00000000".to_string(),
        ForkName::Altair => "0x01000000".to_string(),
        ForkName::Bellatrix => "0x02000000".to_string(),
        ForkName::Capella => "0x03000000".to_string(),
        ForkName::Deneb => "0x04000000".to_string(),
        ForkName::Electra => "0x05000000".to_string(),
        ForkName::Fulu => "0x06000000".to_string(),
        ForkName::Gloas => "0x07000000".to_string(),
    }
}
