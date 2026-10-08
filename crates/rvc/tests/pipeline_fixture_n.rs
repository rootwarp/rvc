//! N-validator `pipeline_fixture` (RR0-06).
//!
//! The shared harness stays in [`common::pipeline_fixture`]. This binary only
//! checks that `with_validators(N)` builds N seeded keys and N attester duties.

mod common;

use std::collections::HashSet;
use std::time::{Duration, Instant};

use common::pipeline_fixture::{
    pipeline_fixture, PipelineFixtureOpts, PreparedPipelineFixture, SLOTS_PER_EPOCH, SLOT_A,
};

fn n_opts(n: usize) -> PreparedPipelineFixture {
    PipelineFixtureOpts { duty_slots: vec![SLOT_A], initial_slot: SLOT_A, ..Default::default() }
        .with_validators(n)
}

fn duty_pubkey_bytes(pubkey: &str) -> [u8; 48] {
    let hex_str = pubkey.strip_prefix("0x").unwrap_or(pubkey);
    let bytes = hex::decode(hex_str).expect("duty pubkey hex");
    let mut out = [0u8; 48];
    assert_eq!(bytes.len(), 48, "duty pubkey length");
    out.copy_from_slice(&bytes);
    out
}

#[tokio::test]
async fn fixture_builds_n_keys_and_n_duties() {
    const N: usize = 200;

    let started = Instant::now();
    let fixture = pipeline_fixture(n_opts(N));
    let build = started.elapsed();
    assert!(
        build < Duration::from_secs(5),
        "N=200 pipeline_fixture built in {build:?}, budget is 5s"
    );
    eprintln!("N=200 pipeline_fixture build: {build:?}");

    let keys = fixture.composite_signer.local_public_keys();
    assert_eq!(keys.len(), N, "composite signer local keys");
    let key_set: HashSet<[u8; 48]> = keys.iter().copied().collect();
    assert_eq!(key_set.len(), N, "local BLS keys must be distinct");

    let mut registered = fixture.validator_store.list_enabled_pubkeys();
    registered.sort();
    assert_eq!(registered, keys, "ValidatorStore must register every local key");

    let mut mapped: Vec<[u8; 48]> = fixture.pubkey_map.read().keys().copied().collect();
    mapped.sort();
    assert_eq!(mapped, keys, "PubkeyMap must hold every local key");

    let epoch = SLOT_A / SLOTS_PER_EPOCH;
    fixture.duty_tracker.fetch_duties_for_epoch(epoch).await.expect("fetch attester duties");
    let duties = fixture.duty_tracker.get_duties_for_slot(SLOT_A).await;
    assert_eq!(duties.len(), N, "one attester duty per validator for slot {SLOT_A}");

    let mut positions = HashSet::new();
    let mut duty_keys = HashSet::new();
    for duty in &duties {
        assert_eq!(duty.raw.slot, SLOT_A.to_string());
        assert_eq!(duty.raw.committee_index, "0");
        assert_eq!(duty.committees_at_slot, "1");
        let committee_length: usize = duty.raw.committee_length.parse().expect("committee_length");
        let position: usize =
            duty.raw.validator_committee_index.parse().expect("validator_committee_index");
        assert_eq!(committee_length, N);
        assert!(
            position < committee_length,
            "validator_committee_index {position} must be in range for make_aggregation_bits"
        );
        assert!(positions.insert(position), "duplicate committee position {position}");
        assert!(duty_keys.insert(duty_pubkey_bytes(&duty.pubkey)), "duplicate duty pubkey");
    }
    assert_eq!(positions.len(), N);
    assert_eq!(duty_keys, key_set, "duties must use the registered pubkeys");

    let again = pipeline_fixture(n_opts(N));
    assert_eq!(
        again.composite_signer.local_public_keys(),
        keys,
        "two builds at N={N} must share the seeded pubkey set"
    );

    let path = fixture.slashing_db_path().expect("N>1 opens an on-disk slashing db");
    assert!(path.is_file(), "missing slashing db at {}", path.display());
    // `journal_mode=wal` is persisted by `SlashingDb::open` (production
    // `configure_pragmas`). `synchronous=EXTRA` is per-connection and is not
    // visible on a second handle.
    let conn = rusqlite::Connection::open(&path).expect("reopen slashing db");
    let journal: String =
        conn.query_row("PRAGMA journal_mode", [], |row| row.get(0)).expect("journal_mode");
    assert!(journal.eq_ignore_ascii_case("wal"), "journal_mode={journal}");
}
