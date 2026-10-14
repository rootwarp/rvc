//! `DutyTracker` must accept a beacon client that implements only [`DutiesProvider`].
//!
//! The mock deliberately does not implement [`bn_manager::BeaconNodeClient`]. Construction
//! is the proof: a wide-trait constructor cannot name this type.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use bn_manager::{
    AttesterDutiesResponse, BeaconError, DutiesProvider, ProposerDutiesResponse, PtcDutiesResponse,
    SyncCommitteeDutiesResponse,
};
use eth_types::ForkSchedule;
use rvc_duty_tracker::DutyTracker;

/// Beacon stand-in that implements [`DutiesProvider`] and nothing else.
struct DutiesOnlyMock;

type BoxFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

impl DutiesProvider for DutiesOnlyMock {
    fn get_attester_duties<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _epoch: u64,
        _validator_indices: &'life1 [String],
    ) -> BoxFut<'async_trait, Result<AttesterDutiesResponse, BeaconError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async {
            Ok(AttesterDutiesResponse {
                dependent_root: "0x00".into(),
                execution_optimistic: false,
                data: vec![],
            })
        })
    }

    fn get_proposer_duties<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _epoch: u64,
        _schedule: &'life1 ForkSchedule,
    ) -> BoxFut<'async_trait, Result<ProposerDutiesResponse, BeaconError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async {
            Ok(ProposerDutiesResponse {
                dependent_root: "0x00".into(),
                execution_optimistic: false,
                data: vec![],
            })
        })
    }

    fn post_sync_committee_duties<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _epoch: u64,
        _validator_indices: &'life1 [String],
    ) -> BoxFut<'async_trait, Result<SyncCommitteeDutiesResponse, BeaconError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async {
            Ok(SyncCommitteeDutiesResponse { execution_optimistic: false, data: vec![] })
        })
    }

    fn post_ptc_duties<'life0, 'life1, 'async_trait>(
        &'life0 self,
        _epoch: u64,
        _validator_indices: &'life1 [String],
    ) -> BoxFut<'async_trait, Result<PtcDutiesResponse, BeaconError>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        Self: 'async_trait,
    {
        Box::pin(async {
            Ok(PtcDutiesResponse {
                dependent_root: "0x00".into(),
                execution_optimistic: false,
                data: vec![],
            })
        })
    }
}

/// Constructing [`DutyTracker`] from a duties-only client must compile and serve duties.
#[tokio::test]
async fn duties_only_mock_satisfies_duty_tracker() {
    let tracker = DutyTracker::new(Arc::new(DutiesOnlyMock), vec!["1".to_string()]);
    let duties = tracker.fetch_duties_for_epoch(0).await.expect("empty duties");
    assert!(duties.is_empty());
}
