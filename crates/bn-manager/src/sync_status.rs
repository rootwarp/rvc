use std::sync::Arc;
use std::time::Duration;

use beacon::BeaconClient;
use futures::future::join_all;
use observability::logging::RedactedUrl;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::types::{HealthTier, TierThresholds};

/// Sync status of a single beacon node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BnSyncStatus {
    /// Status not yet determined (before first poll).
    Unknown,
    /// Node is fully synced and ready for queries.
    Synced,
    /// Node is still syncing (head behind chain tip).
    Syncing,
    /// Beacon is synced but EL is offline; usable for non-EL queries only.
    ElOffline,
    /// Node is unreachable (network error, timeout, etc.).
    Unreachable,
}

impl BnSyncStatus {
    /// Returns `true` if the BN is fully synced (including EL).
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Synced)
    }

    /// Returns `true` if the BN is usable for non-EL-dependent operations.
    pub fn is_usable_for_non_el(&self) -> bool {
        matches!(self, Self::Synced | Self::ElOffline)
    }
}

/// Extended sync status with additional fields for health tier computation.
#[derive(Debug, Clone, PartialEq)]
pub struct BnSyncDetail {
    pub status: BnSyncStatus,
    pub sync_distance: Option<u64>,
    /// Latest head slot reported by `/eth/v1/node/syncing`, when parseable.
    pub head_slot: Option<u64>,
    pub is_optimistic: bool,
    pub el_offline: bool,
}

impl BnSyncDetail {
    /// Creates a detail with unknown status.
    pub fn unknown() -> Self {
        Self {
            status: BnSyncStatus::Unknown,
            sync_distance: None,
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        }
    }

    /// Computes the health tier from sync distance and thresholds.
    ///
    /// - Unreachable/Unknown BNs are always `Unsynced`
    /// - EL-offline BNs are `Unsynced` (not eligible for EL-dependent operations)
    /// - Optimistic BNs are deprioritized within same tier
    /// - Otherwise, tier is derived from sync_distance
    pub fn tier(&self, thresholds: &TierThresholds) -> HealthTier {
        match self.status {
            BnSyncStatus::Unreachable | BnSyncStatus::Unknown => HealthTier::Unsynced,
            BnSyncStatus::ElOffline => HealthTier::Unsynced,
            BnSyncStatus::Syncing | BnSyncStatus::Synced => {
                match self.sync_distance {
                    Some(d) => thresholds.tier_for_distance(d),
                    // No distance info — treat as unsynced if syncing, synced if synced
                    None => {
                        if self.status == BnSyncStatus::Synced {
                            HealthTier::Synced
                        } else {
                            HealthTier::Unsynced
                        }
                    }
                }
            }
        }
    }
}

/// Shared sync status tracker for all configured beacon nodes.
pub type SharedSyncStatuses = Arc<RwLock<Vec<BnSyncDetail>>>;

/// Creates a new shared sync status vector, initially marking all BNs as unknown.
pub fn new_shared_sync_statuses(count: usize) -> SharedSyncStatuses {
    Arc::new(RwLock::new(vec![BnSyncDetail::unknown(); count]))
}

/// Polls the sync status of all beacon nodes in parallel and updates the shared state.
///
/// Also updates [`metrics::definitions::RVC_BN_HEALTH_TIER`] per endpoint from the
/// polled detail (DSR-2.2). Tier values follow [`BnSyncDetail::tier`].
pub async fn check_all_sync_statuses(
    clients: &[BeaconClient],
    statuses: &SharedSyncStatuses,
    thresholds: &TierThresholds,
) {
    let futs: Vec<_> = clients
        .iter()
        .enumerate()
        .map(|(i, client)| async move {
            let detail = check_single_sync_status(client).await;
            (i, client.endpoint().to_string(), detail)
        })
        .collect();

    let results = join_all(futs).await;

    let previous = { statuses.read().await.clone() };
    let mut new_statuses = vec![BnSyncDetail::unknown(); clients.len()];
    for (i, endpoint, detail) in results {
        let old_status = previous.get(i).map(|d| d.status).unwrap_or(BnSyncStatus::Unknown);
        if old_status != detail.status {
            info!(
                bn_url = %RedactedUrl(&endpoint),
                sync_distance = detail.sync_distance.map(|d| d.to_string()).as_deref().unwrap_or("unknown"),
                old_status = ?old_status,
                new_status = ?detail.status,
                "BN sync status changed"
            );
        }
        match detail.status {
            BnSyncStatus::Synced => {
                info!(bn_index = i, endpoint = %RedactedUrl(&endpoint), "BN is synced");
            }
            BnSyncStatus::Syncing => {
                warn!(
                    bn_index = i,
                    endpoint = %RedactedUrl(&endpoint),
                    "BN is still syncing, will be skipped for duties"
                );
            }
            BnSyncStatus::ElOffline => {
                warn!(
                    bn_index = i,
                    endpoint = %RedactedUrl(&endpoint),
                    "BN execution layer is offline, usable for non-EL queries only"
                );
            }
            BnSyncStatus::Unreachable => {
                warn!(bn_index = i, endpoint = %RedactedUrl(&endpoint), "BN is unreachable");
            }
            BnSyncStatus::Unknown => {}
        }
        let tier = detail.tier(thresholds);
        // Issue 8.3 label hygiene — never put userinfo/path/query on /metrics.
        let endpoint_label = crate::metrics::endpoint_label(&endpoint);
        metrics::definitions::RVC_BN_HEALTH_TIER
            .with_label_values(&[endpoint_label.as_str()])
            .set(tier.as_metric_value());
        new_statuses[i] = detail;
    }

    let mut guard = statuses.write().await;
    *guard = new_statuses;
}

/// Checks the sync status of a single beacon node.
///
/// Returns `ElOffline` when the beacon layer is synced but `el_offline` is true,
/// allowing the BN to still serve non-EL-dependent queries.
/// Stores sync_distance and flags for health tier computation.
async fn check_single_sync_status(client: &BeaconClient) -> BnSyncDetail {
    match client.get_node_syncing().await {
        Ok(response) => {
            let data = &response.data;
            let sync_distance = data.sync_distance.parse::<u64>().ok();
            let head_slot = data.head_slot.parse::<u64>().ok();
            let is_optimistic = data.is_optimistic;
            let el_offline = data.el_offline;
            let status = if data.is_syncing || data.is_optimistic {
                BnSyncStatus::Syncing
            } else if data.el_offline {
                BnSyncStatus::ElOffline
            } else {
                BnSyncStatus::Synced
            };
            BnSyncDetail { status, sync_distance, head_slot, is_optimistic, el_offline }
        }
        Err(_) => BnSyncDetail {
            status: BnSyncStatus::Unreachable,
            sync_distance: None,
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        },
    }
}

/// Starts a background task that periodically polls sync status of all BNs.
///
/// The task runs until the shutdown signal fires. Each poll updates
/// `rvc_bn_health_tier` via [`check_all_sync_statuses`].
pub fn start_sync_monitor(
    clients: Vec<BeaconClient>,
    statuses: SharedSyncStatuses,
    thresholds: TierThresholds,
    interval: Duration,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            check_all_sync_statuses(&clients, &statuses, &thresholds).await;

            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = shutdown.changed() => {
                    info!("sync monitor shutting down");
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- BnSyncStatus unit tests --

    #[test]
    fn test_sync_status_synced_is_usable() {
        assert!(BnSyncStatus::Synced.is_usable());
    }

    #[test]
    fn test_sync_status_syncing_not_usable() {
        assert!(!BnSyncStatus::Syncing.is_usable());
    }

    #[test]
    fn test_sync_status_unreachable_not_usable() {
        assert!(!BnSyncStatus::Unreachable.is_usable());
    }

    #[test]
    fn test_sync_status_unknown_not_usable() {
        assert!(!BnSyncStatus::Unknown.is_usable());
    }

    #[test]
    fn test_sync_status_eq() {
        assert_eq!(BnSyncStatus::Synced, BnSyncStatus::Synced);
        assert_ne!(BnSyncStatus::Synced, BnSyncStatus::Syncing);
        assert_ne!(BnSyncStatus::Syncing, BnSyncStatus::Unreachable);
    }

    #[test]
    fn test_sync_status_clone() {
        let s = BnSyncStatus::Syncing;
        let c = s;
        assert_eq!(s, c);
    }

    #[test]
    fn test_sync_status_debug() {
        let s = BnSyncStatus::Synced;
        assert!(format!("{:?}", s).contains("Synced"));
    }

    #[test]
    fn test_new_shared_sync_statuses_initial() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let statuses = new_shared_sync_statuses(3);
            let guard = statuses.read().await;
            assert_eq!(guard.len(), 3);
            assert!(guard.iter().all(|d| d.status == BnSyncStatus::Unknown));
        });
    }

    #[tokio::test]
    async fn test_is_usable_filter_all_synced() {
        let statuses = Arc::new(RwLock::new(vec![
            BnSyncDetail {
                status: BnSyncStatus::Synced,
                sync_distance: Some(0),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
            BnSyncDetail {
                status: BnSyncStatus::Synced,
                sync_distance: Some(0),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
            BnSyncDetail {
                status: BnSyncStatus::Synced,
                sync_distance: Some(0),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
        ]));
        let guard = statuses.read().await;
        let usable: Vec<usize> = guard
            .iter()
            .enumerate()
            .filter(|(_, d)| d.status.is_usable())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(usable, vec![0, 1, 2]);
    }

    #[tokio::test]
    async fn test_is_usable_filter_some_syncing() {
        let statuses = Arc::new(RwLock::new(vec![
            BnSyncDetail {
                status: BnSyncStatus::Synced,
                sync_distance: Some(0),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
            BnSyncDetail {
                status: BnSyncStatus::Syncing,
                sync_distance: Some(500),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
            BnSyncDetail {
                status: BnSyncStatus::Synced,
                sync_distance: Some(0),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
        ]));
        let guard = statuses.read().await;
        let usable: Vec<usize> = guard
            .iter()
            .enumerate()
            .filter(|(_, d)| d.status.is_usable())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(usable, vec![0, 2]);
    }

    #[tokio::test]
    async fn test_is_usable_filter_all_unreachable() {
        let statuses = Arc::new(RwLock::new(vec![
            BnSyncDetail {
                status: BnSyncStatus::Unreachable,
                sync_distance: None,
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
            BnSyncDetail {
                status: BnSyncStatus::Unreachable,
                sync_distance: None,
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
        ]));
        let guard = statuses.read().await;
        let usable: Vec<usize> = guard
            .iter()
            .enumerate()
            .filter(|(_, d)| d.status.is_usable())
            .map(|(i, _)| i)
            .collect();
        assert!(usable.is_empty());
    }

    #[tokio::test]
    async fn test_is_usable_filter_mixed() {
        let statuses = Arc::new(RwLock::new(vec![
            BnSyncDetail {
                status: BnSyncStatus::Syncing,
                sync_distance: Some(500),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
            BnSyncDetail {
                status: BnSyncStatus::Synced,
                sync_distance: Some(0),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
            BnSyncDetail {
                status: BnSyncStatus::Unreachable,
                sync_distance: None,
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
            BnSyncDetail {
                status: BnSyncStatus::Synced,
                sync_distance: Some(0),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
        ]));
        let guard = statuses.read().await;
        let usable: Vec<usize> = guard
            .iter()
            .enumerate()
            .filter(|(_, d)| d.status.is_usable())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(usable, vec![1, 3]);
    }

    // -- BnSyncDetail tier tests --

    #[test]
    fn test_sync_detail_tier_synced() {
        let thresholds = TierThresholds::default();
        let detail = BnSyncDetail {
            status: BnSyncStatus::Synced,
            sync_distance: Some(0),
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::Synced);

        let detail = BnSyncDetail {
            status: BnSyncStatus::Synced,
            sync_distance: Some(8),
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::Synced);
    }

    #[test]
    fn test_sync_detail_tier_small_lag() {
        let thresholds = TierThresholds::default();
        let detail = BnSyncDetail {
            status: BnSyncStatus::Synced,
            sync_distance: Some(9),
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::SmallLag);

        let detail = BnSyncDetail {
            status: BnSyncStatus::Synced,
            sync_distance: Some(16),
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::SmallLag);
    }

    #[test]
    fn test_sync_detail_tier_large_lag() {
        let thresholds = TierThresholds::default();
        let detail = BnSyncDetail {
            status: BnSyncStatus::Synced,
            sync_distance: Some(17),
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::LargeLag);

        let detail = BnSyncDetail {
            status: BnSyncStatus::Synced,
            sync_distance: Some(64),
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::LargeLag);
    }

    #[test]
    fn test_sync_detail_tier_unsynced_by_distance() {
        let thresholds = TierThresholds::default();
        let detail = BnSyncDetail {
            status: BnSyncStatus::Synced,
            sync_distance: Some(65),
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::Unsynced);
    }

    #[test]
    fn test_sync_detail_tier_unreachable_is_unsynced() {
        let thresholds = TierThresholds::default();
        let detail = BnSyncDetail {
            status: BnSyncStatus::Unreachable,
            sync_distance: None,
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::Unsynced);
    }

    #[test]
    fn test_sync_detail_tier_el_offline_is_unsynced() {
        let thresholds = TierThresholds::default();
        let detail = BnSyncDetail {
            status: BnSyncStatus::ElOffline,
            sync_distance: Some(0),
            head_slot: None,
            is_optimistic: false,
            el_offline: true,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::Unsynced);
    }

    #[test]
    fn test_sync_detail_tier_unknown_is_unsynced() {
        let thresholds = TierThresholds::default();
        let detail = BnSyncDetail::unknown();
        assert_eq!(detail.tier(&thresholds), HealthTier::Unsynced);
    }

    #[test]
    fn test_sync_detail_tier_syncing_with_distance() {
        let thresholds = TierThresholds::default();
        // Syncing but close — still classified by distance
        let detail = BnSyncDetail {
            status: BnSyncStatus::Syncing,
            sync_distance: Some(5),
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::Synced);
    }

    #[test]
    fn test_sync_detail_tier_no_distance_synced() {
        let thresholds = TierThresholds::default();
        let detail = BnSyncDetail {
            status: BnSyncStatus::Synced,
            sync_distance: None,
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::Synced);
    }

    #[test]
    fn test_sync_detail_tier_no_distance_syncing() {
        let thresholds = TierThresholds::default();
        let detail = BnSyncDetail {
            status: BnSyncStatus::Syncing,
            sync_distance: None,
            head_slot: None,
            is_optimistic: false,
            el_offline: false,
        };
        assert_eq!(detail.tier(&thresholds), HealthTier::Unsynced);
    }

    // -- Integration tests with wiremock --

    use beacon::BeaconClientConfig;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SYNCED_RESPONSE: &str = r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#;
    const SYNCING_RESPONSE: &str = r#"{"data":{"head_slot":"500","sync_distance":"500","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#;
    const EL_OFFLINE_RESPONSE: &str = r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":false,"el_offline":true}}"#;
    const OPTIMISTIC_RESPONSE: &str = r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":true,"el_offline":false}}"#;

    fn make_client(endpoint: &str) -> BeaconClient {
        // max_retries=0 under multi-BN: see BnManager type docs (retries-under-failover).
        let config = BeaconClientConfig::new(endpoint).with_max_retries(0);
        BeaconClient::new(config).unwrap()
    }

    #[tokio::test]
    async fn test_check_all_sync_statuses_all_synced() {
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server2)
            .await;

        let clients = vec![make_client(&server1.uri()), make_client(&server2.uri())];
        let statuses = new_shared_sync_statuses(2);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Synced);
        assert_eq!(guard[0].sync_distance, Some(0));
        assert_eq!(guard[0].head_slot, Some(1000));
        assert_eq!(guard[1].status, BnSyncStatus::Synced);
        assert_eq!(guard[1].head_slot, Some(1000));
    }

    #[tokio::test]
    async fn test_check_all_sync_statuses_one_syncing() {
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_RESPONSE))
            .mount(&server2)
            .await;

        let clients = vec![make_client(&server1.uri()), make_client(&server2.uri())];
        let statuses = new_shared_sync_statuses(2);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Synced);
        assert_eq!(guard[0].head_slot, Some(1000));
        assert_eq!(guard[1].status, BnSyncStatus::Syncing);
        assert_eq!(guard[1].sync_distance, Some(500));
        assert_eq!(guard[1].head_slot, Some(500));
    }

    #[tokio::test]
    async fn test_check_all_sync_statuses_unreachable() {
        let server1 = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&server1)
            .await;

        let clients = vec![make_client(&server1.uri())];
        let statuses = new_shared_sync_statuses(1);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Unreachable);
        assert_eq!(guard[0].sync_distance, None);
        assert_eq!(guard[0].head_slot, None);
    }

    #[tokio::test]
    async fn test_sync_monitor_runs_and_shuts_down() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = start_sync_monitor(
            clients,
            statuses.clone(),
            TierThresholds::default(),
            Duration::from_millis(50),
            shutdown_rx,
        );

        // Wait a bit for at least one poll
        tokio::time::sleep(Duration::from_millis(100)).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Synced);
        drop(guard);

        // Shut down
        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_sync_monitor_detects_status_change() {
        let server = MockServer::start().await;

        // Initially syncing
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_RESPONSE))
            .expect(1..)
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let handle = start_sync_monitor(
            clients,
            statuses.clone(),
            TierThresholds::default(),
            Duration::from_millis(50),
            shutdown_rx,
        );

        // Wait for initial poll
        tokio::time::sleep(Duration::from_millis(100)).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Syncing);
        drop(guard);

        shutdown_tx.send(true).unwrap();
        handle.await.unwrap();
    }

    // -- el_offline and is_optimistic tests --

    #[tokio::test]
    async fn test_check_single_el_offline_marks_el_offline() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(EL_OFFLINE_RESPONSE))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::ElOffline);
        assert!(guard[0].el_offline);
    }

    #[tokio::test]
    async fn test_check_single_is_optimistic_marks_syncing() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(OPTIMISTIC_RESPONSE))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Syncing);
        assert!(guard[0].is_optimistic);
    }

    #[tokio::test]
    async fn test_check_all_sync_statuses_polls_in_parallel() {
        // Use a slow server to verify parallel polling completes faster than sequential.
        let server1 = MockServer::start().await;
        let server2 = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(SYNCED_RESPONSE)
                    .set_delay(Duration::from_millis(200)),
            )
            .mount(&server1)
            .await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(SYNCED_RESPONSE)
                    .set_delay(Duration::from_millis(200)),
            )
            .mount(&server2)
            .await;

        let clients = vec![make_client(&server1.uri()), make_client(&server2.uri())];
        let statuses = new_shared_sync_statuses(2);

        let start = tokio::time::Instant::now();
        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;
        let elapsed = start.elapsed();

        // If sequential, would take >= 400ms. Parallel should complete in ~200ms.
        assert!(
            elapsed < Duration::from_millis(350),
            "polling took {:?}, expected < 350ms (parallel)",
            elapsed
        );

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Synced);
        assert_eq!(guard[1].status, BnSyncStatus::Synced);
    }

    #[test]
    fn test_sync_status_el_offline_not_usable() {
        assert!(!BnSyncStatus::ElOffline.is_usable());
    }

    #[test]
    fn test_sync_status_el_offline_is_usable_for_non_el() {
        assert!(BnSyncStatus::ElOffline.is_usable_for_non_el());
    }

    #[test]
    fn test_sync_status_synced_is_usable_for_non_el() {
        assert!(BnSyncStatus::Synced.is_usable_for_non_el());
    }

    #[test]
    fn test_sync_status_syncing_not_usable_for_non_el() {
        assert!(!BnSyncStatus::Syncing.is_usable_for_non_el());
    }

    #[test]
    fn test_sync_status_unreachable_not_usable_for_non_el() {
        assert!(!BnSyncStatus::Unreachable.is_usable_for_non_el());
    }

    #[tokio::test]
    async fn test_syncing_and_el_offline_returns_syncing() {
        let server = MockServer::start().await;

        // Both is_syncing=true and el_offline=true → should be Syncing, not ElOffline
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"500","sync_distance":"500","is_syncing":true,"is_optimistic":false,"el_offline":true}}"#,
            ))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Syncing);
    }

    #[tokio::test]
    async fn test_optimistic_and_el_offline_returns_syncing() {
        let server = MockServer::start().await;

        // is_optimistic=true takes precedence over el_offline=true → Syncing
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"1000","sync_distance":"0","is_syncing":false,"is_optimistic":true,"el_offline":true}}"#,
            ))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].status, BnSyncStatus::Syncing);
    }

    #[tokio::test]
    async fn test_unknown_status_not_usable_in_filter() {
        let statuses = Arc::new(RwLock::new(vec![
            BnSyncDetail::unknown(),
            BnSyncDetail {
                status: BnSyncStatus::Synced,
                sync_distance: Some(0),
                head_slot: None,
                is_optimistic: false,
                el_offline: false,
            },
            BnSyncDetail::unknown(),
        ]));
        let guard = statuses.read().await;
        let usable: Vec<usize> = guard
            .iter()
            .enumerate()
            .filter(|(_, d)| d.status.is_usable())
            .map(|(i, _)| i)
            .collect();
        assert_eq!(usable, vec![1]);
    }

    // -- Sync distance storage tests --

    #[tokio::test]
    async fn test_sync_distance_stored_for_synced_bn() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"1000","sync_distance":"5","is_syncing":false,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].sync_distance, Some(5));
        assert_eq!(guard[0].tier(&TierThresholds::default()), HealthTier::Synced);
    }

    #[tokio::test]
    async fn test_sync_distance_tier_for_syncing_bn() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                r#"{"data":{"head_slot":"900","sync_distance":"100","is_syncing":true,"is_optimistic":false,"el_offline":false}}"#,
            ))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let guard = statuses.read().await;
        assert_eq!(guard[0].sync_distance, Some(100));
        assert_eq!(guard[0].tier(&TierThresholds::default()), HealthTier::Unsynced);
    }

    // -- DSR-2.2: rvc_bn_health_tier updates from sync poller --

    fn health_tier_gauge(endpoint: &str) -> i64 {
        let label = crate::metrics::endpoint_label(endpoint);
        metrics::definitions::RVC_BN_HEALTH_TIER.with_label_values(&[label.as_str()]).get()
    }

    #[tokio::test]
    async fn test_health_tier_gauge_updates_to_synced_on_poll() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);
        let endpoint = clients[0].endpoint().to_string();

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        assert_eq!(
            health_tier_gauge(&endpoint),
            HealthTier::Synced.as_metric_value(),
            "synced BN /eth/v1/node/syncing must set rvc_bn_health_tier=1"
        );
    }

    #[tokio::test]
    async fn test_health_tier_gauge_updates_to_unsynced_when_syncing() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_RESPONSE))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);
        let endpoint = clients[0].endpoint().to_string();

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        assert_eq!(
            health_tier_gauge(&endpoint),
            HealthTier::Unsynced.as_metric_value(),
            "syncing BN (large sync_distance) must set rvc_bn_health_tier=4"
        );
    }

    #[tokio::test]
    async fn test_health_tier_gauge_transitions_match_syncing_endpoint() {
        let server = MockServer::start().await;

        // First poll: synced
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);
        let endpoint = clients[0].endpoint().to_string();

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;
        assert_eq!(health_tier_gauge(&endpoint), HealthTier::Synced.as_metric_value());

        // Second poll: unsynced / syncing
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCING_RESPONSE))
            .mount(&server)
            .await;

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;
        assert_eq!(
            health_tier_gauge(&endpoint),
            HealthTier::Unsynced.as_metric_value(),
            "gauge must transition synced→unsynced when BN syncing endpoint flips"
        );

        // Third poll: back to synced
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server)
            .await;

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;
        assert_eq!(
            health_tier_gauge(&endpoint),
            HealthTier::Synced.as_metric_value(),
            "gauge must transition unsynced→synced when BN reports synced again"
        );
    }

    #[tokio::test]
    async fn test_health_tier_gauge_endpoint_label_strips_credentials() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server)
            .await;

        // Inject userinfo into the mock URI — mirrors issue 8.3 capability hygiene.
        let credentialed = server.uri().replacen("http://", "http://user:s3cretpw@", 1);
        let expected = crate::metrics::endpoint_label(&credentialed);
        assert!(
            !expected.contains("s3cretpw") && !expected.contains("user:"),
            "sanitizer must strip userinfo; got {expected}"
        );

        let clients = vec![make_client(&credentialed)];
        let statuses = new_shared_sync_statuses(1);

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        assert_eq!(
            health_tier_gauge(&expected),
            HealthTier::Synced.as_metric_value(),
            "gauge must be keyed on the sanitized endpoint"
        );

        let series = crate::metrics::gather_health_tier_series();
        let ours: Vec<&(String, i64)> = series
            .iter()
            .filter(|(ep, _)| ep.contains("s3cretpw") || ep == &expected || ep.contains("user:"))
            .collect();
        assert!(!ours.is_empty(), "credentialed URL must emit a series; got {series:?}");
        for (ep, _) in &ours {
            assert_eq!(ep, &expected, "endpoint must be scheme://host:port without userinfo");
        }
        assert!(
            !series.iter().any(|(ep, _)| ep.contains("s3cretpw")),
            "raw userinfo must not appear in rvc_bn_health_tier labels; got {series:?}"
        );
        assert!(
            !series.iter().any(|(ep, _)| ep.as_str() == credentialed),
            "raw credentialed URL must not be a label"
        );
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_synced_bn_logs_and_metric_stay_truthful() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/eth/v1/node/syncing"))
            .respond_with(ResponseTemplate::new(200).set_body_string(SYNCED_RESPONSE))
            .mount(&server)
            .await;

        let clients = vec![make_client(&server.uri())];
        let statuses = new_shared_sync_statuses(1);
        let endpoint = clients[0].endpoint().to_string();

        check_all_sync_statuses(&clients, &statuses, &TierThresholds::default()).await;

        let tier = health_tier_gauge(&endpoint);
        assert_ne!(
            tier,
            HealthTier::Unsynced.as_metric_value(),
            "must not claim unsynced metric while BN /eth/v1/node/syncing reports synced"
        );
        assert_eq!(tier, HealthTier::Synced.as_metric_value());
        assert!(logs_contain("BN is synced"));
        assert!(
            !logs_contain("BN is still syncing"),
            "must not claim syncing in logs while BN reports synced"
        );
        logs_assert(|lines: &[&str]| {
            // Inspect message bodies only — the test span name is prefixed on every line.
            let bad: Vec<_> = lines
                .iter()
                .filter(|l| l.contains("rvc_bn_manager::sync_status:"))
                .filter(|l| {
                    l.split("rvc_bn_manager::sync_status:")
                        .nth(1)
                        .is_some_and(|msg| msg.contains("unsynced"))
                })
                .collect();
            if !bad.is_empty() {
                return Err(format!(
                    "sync_status messages must not claim unsynced while BN is synced: {bad:?}"
                ));
            }
            Ok(())
        });
    }
}
