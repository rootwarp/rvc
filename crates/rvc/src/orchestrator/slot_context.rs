//! Slot-scoped context with two chain positions, captured at two times.
//!
//! `parent_root` is captured at t=0 by walking back from `slot - 1` over
//! skipped slots (up to four attempts). The first 200 wins. After four
//! misses the literal `"head"` block_id is a counted last resort (ARCH-3d).
//! `head_root` is captured at phase 2 (t=slot/3) via the slot-qualified
//! current slot, bounded by a caller deadline, and reused at phase 3 so
//! messages and contributions agree (H-5). The fetch does not run while the
//! slot-context lock is held.
//!
//! Primary queries stay slot-qualified. `"head"` is only the terminal
//! fallback after four misses (L-5). Do not repair the t=0 query to return
//! the current slot's root: that value is never a valid parent of a slot-N
//! block (ADR-003).

use tracing::warn;

use beacon::{BeaconError, BlockHeaderSummary};
use block_service::ExpectedParents;
use bn_manager::BeaconNodeClient;
use eth_types::{Epoch, Root, Slot};
use metrics::definitions::{slot_context_parent_fallback, RVC_SLOT_CONTEXT_PARENT_FALLBACK_TOTAL};

/// Maximum slot-qualified parent attempts (`slot-1` … `slot-4`).
const PARENT_WALKBACK_ATTEMPTS: u64 = 4;

/// Per-slot chain context. `parent_root` and `head_root` are different
/// positions, captured at different times.
#[derive(Clone)]
pub(crate) struct SlotContext {
    /// The slot this context was captured for.
    pub slot: Slot,
    /// The epoch this slot belongs to.
    pub epoch: Epoch,
    /// Parent of a block proposed for `slot`. Captured at t=0 by walking
    /// back from `slot - 1`. This is the found header's root, and the phase-2
    /// fallback when the current slot has no block. `None` if every attempt failed.
    pub parent_root: Option<Root>,
    /// Parents a block at `slot` may build on. `None` means no parent check
    /// (the walk stopped on a non-404 error, or no header was found).
    /// [`ExpectedParents::closed`] rejects every parent.
    pub expected_parents: Option<ExpectedParents>,
    /// Canonical head as of phase 2. Captured once at t=slot/3 and reused
    /// at phase 3 (H-5). Left `None` at t=0 — a current-slot 404 then is
    /// the normal path, not an exception. A timeout or a body that is not
    /// `0x` plus 64 hex digits falls back to [`Self::parent_root`]. That
    /// fallback is a liveness choice: the parent is the last head this
    /// client verified, and signing it is valid and non-slashable for sync
    /// messages. `None` after that fallback means no parent was verified
    /// either, and sync duties skip.
    pub head_root: Option<Root>,
    pub fence: beacon::DutyFence,
}

impl SlotContext {
    /// Captures `parent_root` at t=0 by walking back `slot-1` … `slot-4`.
    ///
    /// First 200 wins. Four misses fall back to `"head"` (warn + metric).
    /// Only a spec 404 continues the walk. A non-404 error stops and leaves
    /// the parent filter off (`expected_parents` is `None`). A header slot
    /// that disagrees with the requested id, or a head at slot N or later,
    /// rejects every parent. `head_root` stays `None`.
    pub(crate) async fn capture_parent(
        beacon: &dyn BeaconNodeClient,
        slot: Slot,
        epoch: Epoch,
    ) -> Self {
        let fence = beacon.duty_fence().unwrap_or_else(|_| beacon::DutyFence::closed());
        let (parent_root, expected_parents) = match walk_back_parent(beacon, slot).await {
            ParentCapture::Header(header) => {
                (Some(header.root), Some(expected_parents_for(slot, &header)))
            }
            ParentCapture::Unchecked => (None, None),
            ParentCapture::Closed => (None, Some(ExpectedParents::closed())),
        };
        Self { slot, epoch, parent_root, expected_parents, head_root: None, fence }
    }

    /// Records the phase-2 head. The first root wins; a later call leaves it.
    #[cfg(test)]
    pub(crate) fn bare(slot: Slot, epoch: Epoch) -> Self {
        Self {
            slot,
            epoch,
            parent_root: None,
            expected_parents: None,
            head_root: None,
            fence: beacon::DutyFence::open(),
        }
    }

    pub(crate) fn set_head(&mut self, root: Root) {
        if self.head_root.is_none() {
            self.head_root = Some(root);
        }
    }

    /// Phase-2 head for a test that already owns `self`.
    ///
    /// The coordinator must not use this while holding the slot-context lock.
    /// It fetches with [`fetch_head_root`], then [`Self::set_head`]. A missing
    /// block falls back to `parent_root`. The deadline is one minute; a past
    /// deadline does not call the beacon node.
    #[cfg(test)]
    pub(crate) async fn apply_phase2_head(&mut self, beacon: &dyn BeaconNodeClient) {
        let now = tokio::time::Instant::now();
        let deadline = now.checked_add(std::time::Duration::from_secs(60)).unwrap_or(now);
        let fetched = fetch_head_root(beacon, self.slot, deadline).await;
        if let Some(root) = fetched.or(self.parent_root) {
            self.set_head(root);
        }
    }
}

/// Fence for a slot whose parent capture timed out.
///
/// An open fence would let a later phase sign after a revoke. The beacon
/// fence still fails `holds` when a later revoke lands. No admitted node is
/// [`beacon::DutyFence::closed`].
pub(crate) fn fence_when_parent_capture_times_out(
    result: Result<beacon::DutyFence, beacon::BeaconError>,
) -> beacon::DutyFence {
    result.unwrap_or_else(|_| beacon::DutyFence::closed())
}

/// `true` when `duty` signs admitted chain data and any fence no longer holds.
pub(crate) fn admission_blocks(duty: signer::SigningDuty, fences: &[&beacon::DutyFence]) -> bool {
    signer::duty_requires_beacon_admission(duty) && fences.iter().any(|fence| !fence.holds())
}

/// Run `fut` inside the signer's admission scope when the fence tracks a generation.
pub(crate) async fn under_admission<T>(
    fence: &beacon::DutyFence,
    fut: impl std::future::Future<Output = T>,
) -> T {
    match fence.generation() {
        Some(current) => {
            signer::with_beacon_admission(signer::BeaconAdmission::new(fence.seen(), current), fut)
                .await
        }
        None => fut.await,
    }
}

/// Slot-qualified block root for `slot`, or `None` when the deadline has
/// passed, the beacon node fails, or the body is not a block root.
///
/// Beacon API `GET /eth/v1/beacon/blocks/{block_id}/root` with `block_id`
/// equal to the decimal slot. A deadline at or before now does not send the
/// request. The caller applies the parent fallback.
pub(crate) async fn fetch_head_root(
    beacon: &dyn BeaconNodeClient,
    slot: Slot,
    deadline: tokio::time::Instant,
) -> Option<Root> {
    if tokio::time::Instant::now() >= deadline {
        warn!(slot, "head root deadline already passed; skipping the beacon node");
        return None;
    }
    match tokio::time::timeout_at(
        deadline,
        fetch_slot_qualified_root(beacon, &slot.to_string(), slot),
    )
    .await
    {
        Ok(root) => root,
        Err(_) => {
            warn!(slot, "head root fetch exceeded its deadline");
            None
        }
    }
}

enum ParentCapture {
    Header(BlockHeaderSummary),
    /// Non-404, or no header. The parent check is skipped.
    Unchecked,
    /// The header slot cannot be an ancestor. Reject every parent.
    Closed,
}

enum ParentLookup {
    Found(BlockHeaderSummary),
    Miss,
    Unchecked,
    Closed,
}

/// Header at N-1 accepts its root and its parent. A header below N-1 accepts
/// only its root.
fn expected_parents_for(proposal_slot: Slot, header: &BlockHeaderSummary) -> ExpectedParents {
    let at_previous = proposal_slot.checked_sub(1).is_some_and(|previous| header.slot == previous);
    ExpectedParents::open(header.root, at_previous.then_some(header.parent_root))
}

fn note_parent_fallback() {
    RVC_SLOT_CONTEXT_PARENT_FALLBACK_TOTAL
        .with_label_values(&[slot_context_parent_fallback::WALK_BACK_EXHAUSTED])
        .inc();
    #[cfg(any(test, feature = "test-utils"))]
    crate::test_metrics::add_parent_fallback();
}

async fn walk_back_parent(beacon: &dyn BeaconNodeClient, slot: Slot) -> ParentCapture {
    let mut attempts = 0u32;
    for offset in 1..=PARENT_WALKBACK_ATTEMPTS {
        let Some(parent_slot) = slot.checked_sub(offset) else {
            break;
        };
        attempts += 1;
        match lookup_header(beacon, &parent_slot.to_string(), slot).await {
            ParentLookup::Found(header) => return ParentCapture::Header(header),
            ParentLookup::Miss => {}
            ParentLookup::Unchecked => return ParentCapture::Unchecked,
            ParentLookup::Closed => return ParentCapture::Closed,
        }
    }

    warn!(slot, attempts, "parent_root walk-back exhausted; falling back to head");
    note_parent_fallback();
    match lookup_header(beacon, "head", slot).await {
        ParentLookup::Found(header) if header.slot >= slot => {
            warn!(
                slot,
                header_slot = header.slot,
                "head fallback header is not before the proposal slot"
            );
            ParentCapture::Closed
        }
        ParentLookup::Found(header) => ParentCapture::Header(header),
        ParentLookup::Miss | ParentLookup::Unchecked => ParentCapture::Unchecked,
        ParentLookup::Closed => ParentCapture::Closed,
    }
}

async fn lookup_header(beacon: &dyn BeaconNodeClient, block_id: &str, slot: Slot) -> ParentLookup {
    match beacon.get_block_header(block_id).await {
        Ok(header) => {
            if let Some(requested) = decimal_slot_id(block_id) {
                if header.slot != requested {
                    warn!(
                        slot,
                        block_id,
                        header_slot = header.slot,
                        "block header slot does not match the requested block id"
                    );
                    return ParentLookup::Closed;
                }
            }
            ParentLookup::Found(header)
        }
        // ARCH-3a: only ApiError { status: 404 } is a spec skip.
        Err(BeaconError::ApiError { status: 404, .. }) => ParentLookup::Miss,
        // 5xx/429/transport/parse/body-too-large: stop so we do not bind
        // root(N-2) while N-1 still exists (H-4 ParentRootMismatch).
        // A root mismatch, a missing execution_optimistic flag, or true is
        // that parse error. expected_parents stays unset, so the parent
        // filter is off. An optimistic or flagless header is also a health
        // error for the beacon node that returned it, on every slot fetched.
        Err(e) => {
            warn!(slot, error = %e, "Failed to fetch block header for slot context");
            ParentLookup::Unchecked
        }
    }
}

/// Phase-2 block root: lowercase `0x` and exactly 64 hex digits (`A-F` allowed).
fn parse_phase2_root(hex_str: &str) -> Option<Root> {
    let rest = hex_str.strip_prefix("0x")?;
    if rest.len() != 64 || !rest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(rest).ok()?;
    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    Some(root)
}

fn decimal_slot_id(block_id: &str) -> Option<Slot> {
    if block_id.is_empty() || !block_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    block_id.parse().ok()
}

async fn fetch_slot_qualified_root(
    beacon: &dyn BeaconNodeClient,
    block_id: &str,
    slot: Slot,
) -> Option<Root> {
    match beacon.get_block_root(block_id).await {
        Ok(response) => match parse_phase2_root(&response.data.root) {
            Some(root) => Some(root),
            None => {
                warn!(slot, "block root is not 0x plus 64 hex digits");
                None
            }
        },
        Err(e) => {
            warn!(
                slot,
                error = %e,
                "Failed to fetch block root for slot context"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use super::super::utils::parse_hex_root;
    use super::*;

    #[test]
    fn parent_capture_timeout_does_not_use_an_open_fence() {
        let closed = fence_when_parent_capture_times_out(Err(beacon::BeaconError::NoAdmittedNode));
        assert!(!closed.holds());
        let current = Arc::new(AtomicU64::new(3));
        let held =
            fence_when_parent_capture_times_out(Ok(beacon::DutyFence::at(3, Arc::clone(&current))));
        assert!(held.holds());
        current.fetch_add(1, Ordering::Release);
        assert!(!held.holds());
    }

    use beacon::{BlockRootData, DataResponse};
    use bn_manager::MockBeaconNodeClient;
    use tracing_test::traced_test;

    fn slot_vs_head_beacon(
        head_slot: Slot,
        slot_root: String,
        head_root: String,
    ) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_slot_aware_block_root(head_slot, &[], move |queried| {
            match queried {
                None => head_root.clone(),
                Some(_) => slot_root.clone(),
            }
        })
    }

    fn error_beacon() -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_get_block_header(|_| {
            Err(beacon::BeaconError::HttpError("simulated BN error".to_string()))
        })
    }

    fn hex_for_slot(s: Slot) -> String {
        format!("0x{s:064x}")
    }

    fn hex_for_head() -> String {
        format!("0x{}", "aa".repeat(32))
    }

    fn fallback_count() -> u64 {
        crate::test_metrics::parent_fallback()
    }

    /// ARCH-3b stub: 404 on `head_slot` and every `skipped` slot; `"head"` uses
    /// a distinct root so a silent L-5 regression is visible.
    fn walkback_beacon(head_slot: Slot, skipped: &[Slot]) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_slot_aware_block_root(head_slot, skipped, |queried| {
            match queried {
                None => hex_for_head(),
                Some(s) => hex_for_slot(s),
            }
        })
    }

    fn not_found_beacon(head_slot: Slot) -> MockBeaconNodeClient {
        MockBeaconNodeClient::new().with_slot_aware_block_root(head_slot, &[], |queried| {
            match queried {
                None => {
                    "0x2222222222222222222222222222222222222222222222222222222222222222".to_string()
                }
                Some(_) => {
                    "0x1111111111111111111111111111111111111111111111111111111111111111".to_string()
                }
            }
        })
    }

    // -----------------------------------------------------------------------
    // Tests
    // -----------------------------------------------------------------------

    /// Both captures must be slot-qualified — NOT the literal `"head"`.
    ///
    /// The mock returns distinct roots for `"head"` vs any other id; the
    /// assertions verify that neither capture used `"head"`.
    #[tokio::test]
    async fn test_capture_uses_slot_qualified_query() {
        let slot_root =
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let head_root =
            "0x2222222222222222222222222222222222222222222222222222222222222222".to_string();

        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let beacon = slot_vs_head_beacon(slot, slot_root.clone(), head_root);

        let mut ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert_eq!(ctx.slot, slot);
        assert_eq!(ctx.epoch, epoch);

        let expected = parse_hex_root(&slot_root).unwrap();
        assert_eq!(
            ctx.parent_root,
            Some(expected),
            "capture_parent must use slot-qualified slot-1, not 'head'"
        );
        assert_eq!(
            ctx.expected_parents,
            Some(ExpectedParents { root: expected, parent: Some([0x42; 32]), closed: false }),
            "a header at N-1 accepts its root and its parent"
        );
        assert!(ctx.head_root.is_none());

        ctx.apply_phase2_head(&beacon).await;
        assert_eq!(
            ctx.head_root,
            Some(expected),
            "phase-2 head must use slot-qualified current slot, not 'head'"
        );
    }

    /// When the beacon node returns an error, both roots stay `None` and
    /// the slot loop must not be aborted (no panic, no propagated error).
    #[tokio::test]
    async fn test_capture_handles_bn_error() {
        let beacon = error_beacon();

        let slot: Slot = 200;
        let epoch: Epoch = slot / 32;

        let mut ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert_eq!(ctx.slot, slot);
        assert_eq!(ctx.epoch, epoch);
        assert!(
            ctx.parent_root.is_none(),
            "BN error must yield parent_root = None, not a panic or propagated error"
        );
        assert!(ctx.expected_parents.is_none(), "a non-404 error skips the parent check");
        assert!(ctx.head_root.is_none());

        ctx.apply_phase2_head(&beacon).await;
        assert!(
            ctx.head_root.is_none(),
            "BN error must yield head_root = None, not a panic or propagated error"
        );

        // 404 sibling: a missing current-slot block is not a transport error.
        // slot-1 still resolves; phase-2 capture_head falls back to parent.
        let slot: Slot = 200;
        let epoch: Epoch = slot / 32;
        let beacon = not_found_beacon(slot);
        let mut ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;
        assert!(
            ctx.parent_root.is_some(),
            "spec 404 at the current slot must still resolve slot-1"
        );
        assert!(ctx.head_root.is_none());
        ctx.apply_phase2_head(&beacon).await;
        assert_eq!(
            ctx.head_root, ctx.parent_root,
            "phase-2 capture_head falls back to parent when the current slot 404s"
        );
    }

    /// ARCH-3a pin, kept after the 3c split (do not invert).
    ///
    /// A spec-conformant BN 404s `get_block_root(<current slot>)`. t=0
    /// `capture_parent` queries slot-1 and must leave `head_root` unset;
    /// the message phase on that t=0 context still produces **zero**
    /// messages. Messages after phase-2 `capture_head` are covered by
    /// `test_sync_messages_are_produced_when_bn_404s_the_current_slot`.
    /// Do not stuff a root into `head_root` at t=0 to make this test submit.
    #[tokio::test]
    async fn test_capture_yields_no_context_when_bn_404s_current_slot() {
        use std::sync::{Arc, Mutex};

        use beacon::{BeaconClient, BeaconClientConfig, ExecutionOptimisticResponse};
        use crypto::{CompositeSigner, KeyManager, LocalSigner, SecretKey};
        use duty_tracker::DutyTracker;
        use eth_types::SyncCommitteeDuty;
        use signer::{always_enabled, SignerService};
        use slashing::SlashingDb;
        use validator_store::{ValidatorConfig, ValidatorStore};
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        use crate::orchestrator::coordinator::tests::create_test_config;
        use crate::orchestrator::sync_committee::SyncCommitteeService;

        let slot: Slot = 1000;
        let epoch: Epoch = slot / 32;
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/beacon/blocks/{slot}/root")))
            .respond_with(ResponseTemplate::new(404).set_body_string(
                r#"{"code":404,"message":"NOT_FOUND: beacon block at slot 1000"}"#,
            ))
            .expect(0)
            .mount(&mock_server)
            .await;

        let parent_slot = slot - 1;
        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/beacon/headers/{parent_slot}")))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string(consistent_header_json(parent_slot, Some(false))),
            )
            .expect(1)
            .mount(&mock_server)
            .await;

        // Real HTTP client (not MockBeaconNodeClient): t=0 queries slot-1.
        let client =
            BeaconClient::new(BeaconClientConfig::new(mock_server.uri()).with_max_retries(0))
                .unwrap();
        let ctx = SlotContext::capture_parent(&client, slot, epoch).await;
        assert!(
            ctx.head_root.is_none(),
            "t=0 capture_parent must leave head_root unset even when slot-1 succeeds"
        );

        let sk = SecretKey::generate();
        let pk = sk.public_key();
        let submitted = Arc::new(Mutex::new(Vec::<Root>::new()));
        let submitted_for_hook = Arc::clone(&submitted);
        let duty_pk = pk.to_bytes();

        let beacon: Arc<dyn BeaconNodeClient> = Arc::new(
            MockBeaconNodeClient::new()
                .with_post_sync_committee_duties(move |_epoch, _indices| {
                    Ok(ExecutionOptimisticResponse {
                        execution_optimistic: false,
                        data: vec![SyncCommitteeDuty {
                            pubkey: duty_pk,
                            validator_index: 1,
                            validator_sync_committee_indices: vec![0],
                        }],
                    })
                })
                .with_submit_sync_committee_messages(move |messages| {
                    submitted_for_hook
                        .lock()
                        .unwrap()
                        .extend(messages.iter().map(|m| m.beacon_block_root));
                    Ok(())
                }),
        );

        let store = Arc::new(ValidatorStore::new([0u8; 20], 0));
        store.add_validator(ValidatorConfig::new(pk.to_bytes())).unwrap();
        let mut key_manager = KeyManager::new();
        key_manager.insert(sk);
        let signer = Arc::new(
            SignerService::new(
                Arc::new(CompositeSigner::new(LocalSigner::new(key_manager))),
                Arc::new(SlashingDb::open_in_memory().unwrap()),
            )
            .with_enablement(always_enabled()),
        );
        // Upcast: wide object only.
        let duty_tracker = Arc::new(DutyTracker::new(beacon.clone(), vec!["1".to_string()]));
        duty_tracker.fetch_sync_committee_duties(0).await.unwrap();
        assert!(
            !duty_tracker.get_sync_committee_duties(slot).await.is_empty(),
            "harness must have sync duties for slot {slot}; empty-duty skip is not this pin"
        );
        assert!(
            store.is_signing_enabled(&pk.to_bytes()),
            "harness validator must be signing-enabled"
        );

        let mut map = std::collections::HashMap::new();
        map.insert(pk.to_bytes(), pk);
        let service = SyncCommitteeService::new(
            signer,
            beacon,
            duty_tracker,
            Arc::new(parking_lot::RwLock::new(map)),
            create_test_config(),
            store,
        );

        service
            .maybe_produce_sync_messages(
                slot,
                epoch,
                &ctx,
                tokio::time::Instant::now() + std::time::Duration::from_secs(60),
            )
            .await;
        assert!(
            submitted.lock().unwrap().is_empty(),
            "ARCH-3a defect: capture 404 → head_root=None → zero sync committee messages"
        );
    }

    /// t=0 `capture_parent` must leave `head_root` unset. A later
    /// `capture_head` fills it from the slot-qualified current slot — not
    /// by stuffing a parent into `head_root` at t=0.
    #[tokio::test]
    async fn test_capture_parent_leaves_head_unset_until_phase_two() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let parent_hex =
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let current_hex =
            "0x2222222222222222222222222222222222222222222222222222222222222222".to_string();
        let head_hex =
            "0x3333333333333333333333333333333333333333333333333333333333333333".to_string();

        let beacon = MockBeaconNodeClient::new()
            .with_get_block_header({
                let parent_hex = parent_hex.clone();
                move |block_id| {
                    if block_id != (slot - 1).to_string() {
                        return Err(beacon::BeaconError::HttpError(format!(
                            "unexpected block_id {block_id}"
                        )));
                    }
                    Ok(BlockHeaderSummary {
                        root: parse_hex_root(&parent_hex).expect("parent hex"),
                        slot: slot - 1,
                        proposer_index: 1,
                        parent_root: [0x44; 32],
                    })
                }
            })
            .with_get_block_root({
                let current_hex = current_hex.clone();
                let head_hex = head_hex.clone();
                move |block_id| {
                    let root = if block_id == "head" {
                        head_hex.clone()
                    } else if block_id == slot.to_string() {
                        current_hex.clone()
                    } else {
                        return Err(beacon::BeaconError::HttpError(format!(
                            "unexpected block_id {block_id}"
                        )));
                    };
                    Ok(DataResponse { data: BlockRootData { root } })
                }
            });

        let mut ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;
        assert_eq!(ctx.slot, slot);
        assert_eq!(ctx.epoch, epoch);
        let parent = parse_hex_root(&parent_hex).unwrap();
        assert_eq!(
            ctx.parent_root,
            Some(parent),
            "t=0 must capture slot-1, not the current slot or \"head\""
        );
        assert_eq!(
            ctx.expected_parents,
            Some(ExpectedParents { root: parent, parent: Some([0x44; 32]), closed: false }),
        );
        assert!(
            ctx.head_root.is_none(),
            "t=0 must leave head_root unset; do not stuff a root into head_root at capture_parent"
        );

        ctx.apply_phase2_head(&beacon).await;
        assert_eq!(
            ctx.head_root,
            Some(parse_hex_root(&current_hex).unwrap()),
            "phase-2 capture_head must use the slot-qualified current slot, not \"head\""
        );
        assert_ne!(
            ctx.head_root, ctx.parent_root,
            "head and parent name different chain positions; copying parent is not capture_head"
        );
    }

    /// ARCH-3d: a single skipped predecessor is not `parent_root = None`.
    #[tokio::test(flavor = "current_thread")]
    async fn test_capture_parent_walks_back_over_a_skipped_slot() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let before = fallback_count();
        let beacon = walkback_beacon(slot, &[slot - 1]);

        let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        let root = parse_hex_root(&hex_for_slot(slot - 2)).unwrap();
        assert_eq!(
            ctx.parent_root,
            Some(root),
            "one skipped predecessor must resolve to the root of slot-2"
        );
        assert_eq!(
            ctx.expected_parents,
            Some(ExpectedParents { root, parent: None, closed: false }),
            "a header below N-1 accepts only that header's root"
        );
        assert!(ctx.head_root.is_none());
        assert_eq!(
            beacon.get_block_header_calls(),
            vec![(slot - 1).to_string(), (slot - 2).to_string()],
            "first 200 wins; must not keep walking after slot-2"
        );
        assert_eq!(fallback_count(), before, "a successful walk-back is not a fallback");
    }

    /// ARCH-3d: three consecutive skips still resolve inside the four-attempt budget.
    #[tokio::test(flavor = "current_thread")]
    async fn test_capture_parent_walks_back_over_three_consecutive_skips() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let before = fallback_count();
        let beacon = walkback_beacon(slot, &[slot - 1, slot - 2, slot - 3]);

        let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        let root = parse_hex_root(&hex_for_slot(slot - 4)).unwrap();
        assert_eq!(
            ctx.parent_root,
            Some(root),
            "three consecutive skips must resolve to the root of slot-4"
        );
        assert_eq!(
            ctx.expected_parents,
            Some(ExpectedParents { root, parent: None, closed: false })
        );
        assert!(ctx.head_root.is_none());
        assert_eq!(
            beacon.get_block_header_calls(),
            vec![
                (slot - 1).to_string(),
                (slot - 2).to_string(),
                (slot - 3).to_string(),
                (slot - 4).to_string(),
            ],
        );
        assert_eq!(fallback_count(), before, "a successful walk-back is not a fallback");
    }

    /// ARCH-3d: four misses take the counted, warn-logged `"head"` last resort.
    #[tokio::test(flavor = "current_thread")]
    #[traced_test]
    async fn test_capture_parent_falls_back_to_head_after_four_misses() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let before = fallback_count();
        let beacon = walkback_beacon(slot, &[slot - 1, slot - 2, slot - 3, slot - 4]);

        let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        let root = parse_hex_root(&hex_for_head()).unwrap();
        assert_eq!(
            ctx.parent_root,
            Some(root),
            "four consecutive misses must use the terminal \"head\" root"
        );
        assert_eq!(
            ctx.expected_parents,
            Some(ExpectedParents { root, parent: None, closed: false }),
            "head below N-1 accepts only the header root"
        );
        assert!(ctx.head_root.is_none());
        assert_eq!(
            beacon.get_block_header_calls(),
            vec![
                (slot - 1).to_string(),
                (slot - 2).to_string(),
                (slot - 3).to_string(),
                (slot - 4).to_string(),
                "head".to_string(),
            ],
        );
        assert_eq!(fallback_count(), before + 1, "walk_back_exhausted must increment by exactly 1");
        assert!(
            logs_contain("parent_root walk-back exhausted"),
            "terminal fallback must be warn!-logged with the attempt context"
        );
    }

    /// ARCH-3d: a down BN must not burn the remaining walk-back attempts.
    #[tokio::test(flavor = "current_thread")]
    async fn test_capture_parent_stops_walking_on_transport_error() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let before = fallback_count();
        let beacon = error_beacon();

        let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert!(ctx.parent_root.is_none());
        assert!(ctx.expected_parents.is_none());
        assert!(ctx.head_root.is_none());
        assert!(
            beacon.get_block_header_calls().len() <= 1,
            "transport error must stop the walk; issued {} queries",
            beacon.get_block_header_calls().len()
        );
        assert_eq!(fallback_count(), before, "transport stop is not walk_back_exhausted");
    }

    /// Slot-1 503 is not a skip. Walking to N-2 would arm H-4 with a stale ancestor.
    #[tokio::test(flavor = "current_thread")]
    async fn test_capture_parent_stops_walking_on_non_404_api_error() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let before = fallback_count();
        let beacon = MockBeaconNodeClient::new().with_get_block_header(move |block_id| {
            if block_id == (slot - 1).to_string() {
                return Err(beacon::BeaconError::ApiError {
                    status: 503,
                    message: "service unavailable".to_string(),
                });
            }
            Ok(BlockHeaderSummary {
                root: parse_hex_root(&hex_for_slot(slot - 2)).expect("slot-2 hex"),
                slot: slot - 2,
                proposer_index: 1,
                parent_root: [0x22; 32],
            })
        });

        let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert!(
            ctx.parent_root.is_none(),
            "non-404 on slot-1 must not bind slot-2 as expected parent"
        );
        assert!(ctx.expected_parents.is_none(), "a non-404 error skips the parent check");
        assert!(ctx.head_root.is_none());
        assert_eq!(
            beacon.get_block_header_calls(),
            vec![(slot - 1).to_string()],
            "5xx must not walk to slot-2"
        );
        assert_eq!(fallback_count(), before, "5xx stop is not walk_back_exhausted");
    }

    /// Unusable 200 on slot-1 is not a skip — the block may still exist.
    #[tokio::test(flavor = "current_thread")]
    async fn test_capture_parent_stops_walking_on_unparseable_response() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let before = fallback_count();
        let beacon = MockBeaconNodeClient::new().with_get_block_header(move |block_id| {
            if block_id == (slot - 1).to_string() {
                return Err(beacon::BeaconError::ParseError("not-a-root".to_string()));
            }
            Err(beacon::BeaconError::HttpError(format!("unexpected block_id {block_id}")))
        });

        let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert!(
            ctx.parent_root.is_none(),
            "parse failure on slot-1 must not bind slot-2 as expected parent"
        );
        assert!(ctx.expected_parents.is_none());
        assert!(ctx.head_root.is_none());
        assert_eq!(
            beacon.get_block_header_calls(),
            vec![(slot - 1).to_string()],
            "parse error must not walk to slot-2"
        );
        assert_eq!(fallback_count(), before, "parse stop is not walk_back_exhausted");
    }

    /// A numeric id whose header slot disagrees is not a miss. The walk stops.
    #[tokio::test(flavor = "current_thread")]
    async fn test_capture_parent_stops_when_header_slot_disagrees() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let before = fallback_count();
        let beacon = MockBeaconNodeClient::new().with_get_block_header(move |block_id| {
            if block_id != (slot - 1).to_string() {
                return Err(beacon::BeaconError::HttpError(format!(
                    "unexpected block_id {block_id}"
                )));
            }
            Ok(BlockHeaderSummary {
                root: [0x11; 32],
                slot: slot - 5,
                proposer_index: 1,
                parent_root: [0x22; 32],
            })
        });

        let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert!(ctx.parent_root.is_none());
        let parents = ctx.expected_parents.expect("slot mismatch fails closed");
        assert!(parents.closed);
        assert!(!parents.accepts([0x11; 32]));
        assert!(!parents.accepts([0xff; 32]));
        assert_eq!(beacon.get_block_header_calls(), vec![(slot - 1).to_string()]);
        assert_eq!(fallback_count(), before);
    }

    /// Head at slot N or later is not an ancestor. Every parent is rejected.
    #[tokio::test]
    async fn test_capture_parent_head_at_or_after_proposal_slot_rejects_every_parent() {
        for header_slot in [100u64, 101] {
            let slot: Slot = 100;
            let epoch: Epoch = slot / 32;
            let beacon = MockBeaconNodeClient::new().with_get_block_header(move |block_id| {
                if block_id == "head" {
                    Ok(BlockHeaderSummary {
                        root: [0x11; 32],
                        slot: header_slot,
                        proposer_index: 1,
                        parent_root: [0x22; 32],
                    })
                } else {
                    Err(beacon::BeaconError::ApiError {
                        status: 404,
                        message: "missing".to_string(),
                    })
                }
            });

            let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

            assert!(ctx.parent_root.is_none(), "header slot {header_slot} is not a parent");
            let parents = ctx.expected_parents.expect("head at N or later fails closed");
            assert!(parents.closed);
            assert!(!parents.accepts([0x11; 32]));
            assert!(!parents.accepts([0x22; 32]));
            assert!(!parents.accepts([0u8; 32]));
        }
    }

    /// Head fallback whose header is exactly N-1 accepts that header's parent.
    #[tokio::test]
    async fn test_capture_parent_head_at_previous_slot_keeps_reorg_parent() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let header_root = [0x11; 32];
        let header_parent = [0x22; 32];
        let beacon = MockBeaconNodeClient::new().with_get_block_header(move |block_id| {
            if block_id == "head" {
                Ok(BlockHeaderSummary {
                    root: header_root,
                    slot: slot - 1,
                    proposer_index: 1,
                    parent_root: header_parent,
                })
            } else {
                Err(beacon::BeaconError::ApiError { status: 404, message: "missing".to_string() })
            }
        });

        let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert_eq!(ctx.parent_root, Some(header_root));
        assert_eq!(
            ctx.expected_parents,
            Some(ExpectedParents { root: header_root, parent: Some(header_parent), closed: false })
        );
    }

    /// Head fallback below N-1 accepts only the header root.
    #[tokio::test]
    async fn test_capture_parent_head_below_previous_slot_drops_reorg_parent() {
        let slot: Slot = 100;
        let epoch: Epoch = slot / 32;
        let header_root = [0x11; 32];
        let header_parent = [0x22; 32];
        let beacon = MockBeaconNodeClient::new().with_get_block_header(move |block_id| {
            if block_id == "head" {
                Ok(BlockHeaderSummary {
                    root: header_root,
                    slot: slot - 2,
                    proposer_index: 1,
                    parent_root: header_parent,
                })
            } else {
                Err(beacon::BeaconError::ApiError { status: 404, message: "missing".to_string() })
            }
        });

        let ctx = SlotContext::capture_parent(&beacon, slot, epoch).await;

        assert_eq!(ctx.parent_root, Some(header_root));
        assert_eq!(
            ctx.expected_parents,
            Some(ExpectedParents { root: header_root, parent: None, closed: false })
        );
    }

    fn parent_root() -> Root {
        [0x11; 32]
    }

    fn ctx_with_parent(slot: Slot) -> SlotContext {
        SlotContext {
            slot,
            epoch: slot / 32,
            parent_root: Some(parent_root()),
            expected_parents: None,
            head_root: None,
            fence: beacon::DutyFence::open(),
        }
    }

    /// A body that is not `0x` plus 64 hex digits is rejected as a whole.
    /// The stored head is the parent, not a partial decode of the body.
    #[tokio::test]
    async fn invalid_block_root_falls_back_to_parent_and_is_not_stored() {
        let slot: Slot = 40;
        let bad = [
            "",
            "abc",
            "0xabcd",
            "0Xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ];
        for body in bad {
            let owned = body.to_string();
            let slot_id = slot.to_string();
            let beacon = MockBeaconNodeClient::new().with_get_block_root(move |block_id| {
                if block_id != slot_id {
                    return Err(beacon::BeaconError::HttpError(format!(
                        "unexpected block_id {block_id}"
                    )));
                }
                Ok(DataResponse { data: BlockRootData { root: owned.clone() } })
            });
            let mut ctx = ctx_with_parent(slot);
            ctx.apply_phase2_head(&beacon).await;
            assert_eq!(ctx.head_root, Some(parent_root()), "body {body}");
            assert_ne!(ctx.head_root, Some([0u8; 32]));
        }
    }

    /// Uppercase hex digits under a lowercase `0x` are a block root.
    #[tokio::test]
    async fn uppercase_hex_digits_are_a_phase2_head() {
        let root_hex = format!("0x{}", "AB".repeat(32));
        let beacon = MockBeaconNodeClient::new().with_slot_aware_block_root(41, &[], {
            let root_hex = root_hex.clone();
            move |_| root_hex.clone()
        });
        let mut ctx = ctx_with_parent(40);
        ctx.apply_phase2_head(&beacon).await;
        assert_eq!(ctx.head_root, Some([0xAB; 32]));
    }

    /// A deadline that has already passed does not call the beacon node.
    #[tokio::test(start_paused = true)]
    async fn past_head_deadline_does_not_call_the_beacon_node() {
        let beacon = MockBeaconNodeClient::new()
            .with_slot_aware_block_root(41, &[], |_| format!("0x{}", "cd".repeat(32)));
        let deadline = tokio::time::Instant::now();
        let fetched = fetch_head_root(&beacon, 40, deadline).await;
        assert!(fetched.is_none());
        assert!(beacon.get_block_root_calls().is_empty());
    }

    /// The first phase-2 root stays. A second call does not replace it.
    #[test]
    fn set_head_keeps_the_first_written_head() {
        let mut ctx = ctx_with_parent(40);
        ctx.set_head([0x01; 32]);
        ctx.set_head([0x02; 32]);
        assert_eq!(ctx.head_root, Some([0x01; 32]));
    }

    /// Head lives on the slot context only. A new capture starts at `None`.
    #[tokio::test]
    async fn a_new_slot_context_does_not_keep_another_contexts_head() {
        let beacon = MockBeaconNodeClient::new()
            .with_get_block_header(|_| Err(beacon::BeaconError::HttpError("no disk".into())));
        let mut first = ctx_with_parent(40);
        first.set_head([0x01; 32]);
        let second = SlotContext::capture_parent(&beacon, 40, 1).await;
        assert!(second.head_root.is_none());
        assert_eq!(first.head_root, Some([0x01; 32]));
    }

    fn consistent_header_json(slot: u64, optimistic: Option<bool>) -> String {
        use tree_hash::TreeHash;
        let parent = parse_hex_root(&format!(
            "0x{}",
            eth_types::EXTERNAL_BEACON_BLOCK_HEADER_PARENT_ROOT_HEX
        ))
        .unwrap();
        let state = parse_hex_root(&format!(
            "0x{}",
            eth_types::EXTERNAL_BEACON_BLOCK_HEADER_STATE_ROOT_HEX
        ))
        .unwrap();
        let body =
            parse_hex_root(&format!("0x{}", eth_types::EXTERNAL_BEACON_BLOCK_HEADER_BODY_ROOT_HEX))
                .unwrap();
        let header = eth_types::BeaconBlockHeader {
            slot,
            proposer_index: 7,
            parent_root: parent,
            state_root: state,
            body_root: body,
        };
        let root = hex::encode(header.tree_hash_root().as_slice());
        let flag = match optimistic {
            Some(true) => r#""execution_optimistic":true,"#,
            Some(false) => r#""execution_optimistic":false,"#,
            None => "",
        };
        format!(
            r#"{{{flag}"finalized":false,"data":{{"root":"0x{root}","canonical":true,"header":{{"message":{{"slot":"{slot}","proposer_index":"7","parent_root":"0x{}","state_root":"0x{}","body_root":"0x{}"}},"signature":"0x00"}}}}}}"#,
            eth_types::EXTERNAL_BEACON_BLOCK_HEADER_PARENT_ROOT_HEX,
            eth_types::EXTERNAL_BEACON_BLOCK_HEADER_STATE_ROOT_HEX,
            eth_types::EXTERNAL_BEACON_BLOCK_HEADER_BODY_ROOT_HEX,
        )
    }

    async fn mount_header(server: &wiremock::MockServer, block_id: &str, status: u16, body: &str) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("GET"))
            .and(path(format!("/eth/v1/beacon/headers/{block_id}")))
            .respond_with(ResponseTemplate::new(status).set_body_string(body))
            .mount(server)
            .await;
    }

    fn manager_for(endpoints: Vec<String>) -> bn_manager::BnManager {
        bn_manager::BnManager::new(bn_manager::BnManagerConfig::new(endpoints)).unwrap()
    }

    async fn header_paths(server: &wiremock::MockServer) -> Vec<String> {
        server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .map(|request| request.url.path().to_string())
            .collect()
    }

    #[tokio::test]
    async fn parent_lookup_is_unchecked_when_one_bn_404s_and_another_errors() {
        let primary = wiremock::MockServer::start().await;
        let secondary = wiremock::MockServer::start().await;
        let slot: Slot = 100;
        mount_header(&primary, "99", 500, "down").await;
        mount_header(&secondary, "99", 404, r#"{"message":"NOT_FOUND"}"#).await;
        let bait = consistent_header_json(98, Some(false));
        mount_header(&primary, "98", 200, &bait).await;
        mount_header(&secondary, "98", 200, &bait).await;

        let manager = manager_for(vec![primary.uri(), secondary.uri()]);
        let ctx = SlotContext::capture_parent(&manager, slot, slot / 32).await;
        assert!(ctx.parent_root.is_none(), "a mixed 500/404 must not bind slot 98");
        assert!(ctx.expected_parents.is_none(), "the parent check stays unchecked");
        let paths = header_paths(&primary).await;
        let secondary_paths = header_paths(&secondary).await;
        assert!(
            paths.iter().chain(secondary_paths.iter()).all(|path| !path.ends_with("/98")),
            "walk must not reach slot 98: {paths:?} {secondary_paths:?}"
        );
    }

    #[tokio::test]
    async fn parent_lookup_is_unchecked_when_a_404_precedes_a_500() {
        let primary = wiremock::MockServer::start().await;
        let secondary = wiremock::MockServer::start().await;
        let slot: Slot = 100;
        mount_header(&primary, "99", 404, r#"{"message":"NOT_FOUND"}"#).await;
        mount_header(&secondary, "99", 500, "down").await;
        let bait = consistent_header_json(98, Some(false));
        mount_header(&primary, "98", 200, &bait).await;
        mount_header(&secondary, "98", 200, &bait).await;

        let manager = manager_for(vec![primary.uri(), secondary.uri()]);
        let ctx = SlotContext::capture_parent(&manager, slot, slot / 32).await;
        assert!(ctx.parent_root.is_none(), "a 404 then a 500 must not bind slot 98");
        assert!(ctx.expected_parents.is_none(), "the parent filter stays off");
        let paths = header_paths(&primary).await;
        let secondary_paths = header_paths(&secondary).await;
        assert!(
            paths.iter().chain(secondary_paths.iter()).all(|path| !path.ends_with("/98")),
            "walk must not reach slot 98: {paths:?} {secondary_paths:?}"
        );
    }

    #[tokio::test]
    async fn parent_lookup_uses_a_valid_peer_when_the_first_header_is_optimistic() {
        let primary = wiremock::MockServer::start().await;
        let secondary = wiremock::MockServer::start().await;
        let slot: Slot = 100;
        mount_header(&primary, "99", 200, &consistent_header_json(99, Some(true))).await;
        mount_header(&secondary, "99", 200, &consistent_header_json(99, Some(false))).await;

        let manager = manager_for(vec![primary.uri(), secondary.uri()]);
        let ctx = SlotContext::capture_parent(&manager, slot, slot / 32).await;
        let root = header_root_for_slot(99);
        assert_eq!(ctx.parent_root, Some(root));
        assert!(ctx.expected_parents.is_some(), "the valid peer keeps the parent filter on");
        let trackers = manager.health_trackers().read().await;
        assert!(
            trackers[0].error_rate() > 0.0,
            "an optimistic header is a health error for that beacon node"
        );
        assert_eq!(trackers[1].error_rate(), 0.0);
    }

    #[tokio::test]
    async fn parent_lookup_walks_back_when_every_attempted_bn_returns_404() {
        let primary = wiremock::MockServer::start().await;
        let secondary = wiremock::MockServer::start().await;
        let slot: Slot = 100;
        for server in [&primary, &secondary] {
            for id in ["99", "98", "97", "96"] {
                mount_header(server, id, 404, r#"{"message":"NOT_FOUND"}"#).await;
            }
            mount_header(server, "head", 200, &consistent_header_json(90, Some(false))).await;
        }
        let manager = manager_for(vec![primary.uri(), secondary.uri()]);
        let ctx = SlotContext::capture_parent(&manager, slot, slot / 32).await;
        let root = header_root_for_slot(90);
        assert_eq!(ctx.parent_root, Some(root));
        assert_eq!(
            ctx.expected_parents,
            Some(block_service::ExpectedParents { root, parent: None, closed: false })
        );
    }

    fn header_root_for_slot(slot: u64) -> [u8; 32] {
        use tree_hash::TreeHash;
        eth_types::BeaconBlockHeader {
            slot,
            proposer_index: 7,
            parent_root: parse_hex_root(&format!(
                "0x{}",
                eth_types::EXTERNAL_BEACON_BLOCK_HEADER_PARENT_ROOT_HEX
            ))
            .unwrap(),
            state_root: parse_hex_root(&format!(
                "0x{}",
                eth_types::EXTERNAL_BEACON_BLOCK_HEADER_STATE_ROOT_HEX
            ))
            .unwrap(),
            body_root: parse_hex_root(&format!(
                "0x{}",
                eth_types::EXTERNAL_BEACON_BLOCK_HEADER_BODY_ROOT_HEX
            ))
            .unwrap(),
        }
        .tree_hash_root()
        .as_slice()
        .try_into()
        .unwrap()
    }

    #[tokio::test]
    async fn parent_lookup_keeps_a_verified_header_and_rejects_bad_ones() {
        let slot: Slot = 100;
        let good = wiremock::MockServer::start().await;
        mount_header(&good, "99", 200, &consistent_header_json(99, Some(false))).await;
        let manager = manager_for(vec![good.uri()]);
        let ctx = SlotContext::capture_parent(&manager, slot, slot / 32).await;
        let root = header_root_for_slot(99);
        let parent = parse_hex_root(&format!(
            "0x{}",
            eth_types::EXTERNAL_BEACON_BLOCK_HEADER_PARENT_ROOT_HEX
        ))
        .unwrap();
        assert_eq!(ctx.parent_root, Some(root));
        assert_eq!(
            ctx.expected_parents,
            Some(block_service::ExpectedParents { root, parent: Some(parent), closed: false })
        );

        let good_body = consistent_header_json(99, Some(false));
        let advertised = hex::encode(root);
        let mut flipped = advertised.clone();
        let last = flipped.pop().unwrap();
        flipped.push(if last == 'a' { 'b' } else { 'a' });
        let mismatch = good_body
            .replace(&format!("\"root\":\"0x{advertised}\""), &format!("\"root\":\"0x{flipped}\""));
        let malformed = good_body.replacen(
            &format!(
                ",\"body_root\":\"0x{}\"",
                eth_types::EXTERNAL_BEACON_BLOCK_HEADER_BODY_ROOT_HEX
            ),
            "",
            1,
        );
        for body in [
            consistent_header_json(99, Some(true)),
            consistent_header_json(99, None),
            mismatch,
            malformed,
        ] {
            let server = wiremock::MockServer::start().await;
            mount_header(&server, "99", 200, &body).await;
            let manager = manager_for(vec![server.uri()]);
            let ctx = SlotContext::capture_parent(&manager, slot, slot / 32).await;
            assert!(ctx.parent_root.is_none(), "{body}");
            assert!(ctx.expected_parents.is_none(), "{body}");
            let paths = header_paths(&server).await;
            assert!(paths.iter().all(|path| path.ends_with("/99")), "{paths:?}");
        }
    }
}
