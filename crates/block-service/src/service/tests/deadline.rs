//! Gloas payload deadline follows the beacon-node slot length.

use super::*;
use eth_types::{ForkName, SLOT_DURATION_MS};
use std::sync::Arc;
use std::time::Instant;
use timing::{DeadlineBps, DeadlineSchedule};

fn gloas_schedule() -> DeadlineSchedule {
    DeadlineSchedule {
        pre_gloas: DeadlineBps { payload: 1_000, ..DeadlineBps::default() },
        gloas: DeadlineBps { payload: 5_000, ..DeadlineBps::default() },
    }
}

fn service(slot_duration_ms: u64) -> BlockService<MockSigner, MockBeaconClient> {
    let pubkey = test_pubkey();
    BlockService::new(
        Arc::new(MockSigner::new()),
        Arc::new(MockBeaconClient::from_response(ProduceBlockResponse {
            data: serde_json::json!({}),
            is_blinded: false,
            consensus_version: "gloas".to_string(),
            execution_payload_value: None,
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        })),
        Arc::new(test_validator_store(&pubkey)),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    )
    .with_slot_duration_ms(slot_duration_ms)
    .with_deadline_schedule(gloas_schedule())
}

#[test]
fn gloas_payload_deadline_is_half_the_slot() {
    let start = Instant::now();
    let schedule = gloas_schedule();
    let six = PayloadDeadline::new(ForkName::Gloas, &schedule, start, 6_000);
    assert_eq!(six.deadline_ms, 3_000);
    let twelve = PayloadDeadline::new(ForkName::Gloas, &schedule, start, 12_000);
    assert_eq!(twelve.deadline_ms, 6_000);
    // Pre-Gloas uses its own payload basis points, not the Gloas 5000.
    let pre = PayloadDeadline::new(ForkName::Electra, &schedule, start, 6_000);
    assert_eq!(pre.deadline_ms, 600);
}

#[test]
fn block_service_payload_deadline_uses_stored_slot_duration() {
    let untouched = BlockService::new(
        Arc::new(MockSigner::new()),
        Arc::new(MockBeaconClient::from_response(ProduceBlockResponse {
            data: serde_json::json!({}),
            is_blinded: false,
            consensus_version: "gloas".to_string(),
            execution_payload_value: None,
            is_ssz: false,
            ssz_bytes: None,
            payload_included: false,
            builder_url: None,
            consensus_block_value: None,
        })),
        Arc::new(test_validator_store(&test_pubkey())),
        Arc::new(test_fork_schedule()),
        [0xaa; 32],
    );
    assert_eq!(untouched.slot_duration_ms(), SLOT_DURATION_MS);
    assert_eq!(untouched.slot_duration_ms(), 12_000);

    let start = Instant::now();
    assert_eq!(service(6_000).payload_deadline(ForkName::Gloas, start).deadline_ms, 3_000);
    assert_eq!(service(12_000).payload_deadline(ForkName::Gloas, start).deadline_ms, 6_000);
    assert_eq!(service(6_000).slot_duration_ms(), 6_000);
    // Zero is not rewritten to 12 s. A zero deadline overruns immediately.
    assert_eq!(service(0).payload_deadline(ForkName::Gloas, start).deadline_ms, 0);
}
