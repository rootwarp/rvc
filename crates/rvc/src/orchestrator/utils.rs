use std::future::Future;
use std::time::Duration;

use beacon::AttesterDuty;
use crypto::PublicKey;
use duty_tracker::DutyTracker;
use eth_types::{ForkName, Root, Slot};
use timing::SLOTS_PER_EPOCH;
use tracing::warn;

use super::coordinator::PubkeyMap;
use super::error::OrchestratorError;
use crate::pubkey_index::parse_pubkey_bytes;

/// Outcome of running a future under a wall-clock timeout.
///
/// Flattens nested `Result<Result<T, E>, Elapsed>` so call sites match once
/// without repeating the `tokio::time::timeout` idiom. Callers own log
/// messages and metrics so labels stay byte-identical to the pre-refactor path.
#[derive(Debug)]
pub(crate) enum TimedOutcome<T, E> {
    Ok(T),
    Err(E),
    Timeout,
}

/// Run `fut` under `timeout`, returning a flat [`TimedOutcome`].
///
/// `op_name` documents the timed operation (for call-site clarity / grepping);
/// logging and metric increments remain at the caller so messages are unchanged.
pub(crate) async fn timed<T, E, F>(
    _op_name: &'static str,
    timeout: Duration,
    fut: F,
) -> TimedOutcome<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(v)) => TimedOutcome::Ok(v),
        Ok(Err(e)) => TimedOutcome::Err(e),
        Err(_) => TimedOutcome::Timeout,
    }
}

/// Constructs a hex-encoded SSZ bitlist where only the validator's position
/// in the committee is set (pre-Electra aggregation_bits format).
pub(crate) fn make_aggregation_bits(duty: &AttesterDuty) -> Option<String> {
    let committee_length: usize = match duty.committee_length.parse() {
        Ok(0) => {
            warn!(
                validator_index = %duty.validator_index,
                "committee_length is 0, cannot produce aggregation bits"
            );
            return None;
        }
        Ok(v) => v,
        Err(e) => {
            warn!(
                validator_index = %duty.validator_index,
                raw_value = %duty.committee_length,
                error = %e,
                "failed to parse committee_length, skipping duty"
            );
            return None;
        }
    };

    let validator_committee_index: usize = match duty.validator_committee_index.parse() {
        Ok(v) => v,
        Err(e) => {
            warn!(
                validator_index = %duty.validator_index,
                raw_value = %duty.validator_committee_index,
                error = %e,
                "failed to parse validator_committee_index, skipping duty"
            );
            return None;
        }
    };

    // ISSUE-4.4 / L-4: out-of-bounds validator_committee_index returns None.
    // Previously this fell through to a bitlist with only the sentinel bit
    // set (validator position not bound), which the BN would silently
    // accept as a zero-participation attestation.  The caller's `None`
    // branch already drops the duty.
    if validator_committee_index >= committee_length {
        warn!(
            validator_index = %duty.validator_index,
            committee_length = committee_length,
            validator_committee_index = validator_committee_index,
            "validator_committee_index is out of range, skipping duty (ISSUE-4.4 / L-4)"
        );
        return None;
    }

    // SSZ bitlist: ceil((committee_length + 1) / 8) bytes
    // The "+1" is for the length bit at position committee_length
    let byte_count = (committee_length + 8) / 8;
    let mut bits = vec![0u8; byte_count];

    // Set the validator's bit (in-range guaranteed by the check above).
    bits[validator_committee_index / 8] |= 1 << (validator_committee_index % 8);

    // Set the length bit (sentinel) at position committee_length
    bits[committee_length / 8] |= 1 << (committee_length % 8);

    Some(format!("0x{}", hex::encode(bits)))
}

/// Finds a public key by matching against a duty pubkey hex string.
///
/// Decodes the duty pubkey to compressed bytes (case-insensitive hex, optional
/// `0x`/`0X` prefix) and does an O(1) map lookup. Invalid hex or wrong length
/// yields `None` (fail-closed) — there is no linear case-insensitive scan.
pub(crate) fn find_pubkey(pubkey_map: &PubkeyMap, duty_pubkey: &str) -> Option<PublicKey> {
    let bytes = parse_pubkey_bytes(duty_pubkey)?;
    pubkey_map.read().get(&bytes).cloned()
}

/// Finds a public key by compressed duty pubkey bytes (O(1) map lookup).
pub(crate) fn find_pubkey_bytes(
    pubkey_map: &PubkeyMap,
    duty_pubkey: &[u8; 48],
) -> Option<PublicKey> {
    pubkey_map.read().get(duty_pubkey).cloned()
}

/// Whether EIP-7549 zeroes `AttestationData.index` at this fork.
///
/// Half-open `Electra..Gloas`: Electra and Fulu zero the committee index.
/// At Gloas the chain asserts `index < 2` (payload EMPTY=0 / FULL=1) and
/// rs-vc **preserves, never computes**, the BN-supplied value.
pub(crate) fn zeroes_committee_index(fork: ForkName) -> bool {
    (ForkName::Electra..ForkName::Gloas).contains(&fork)
}

/// Whether this fork uses the Electra+ attestation wire.
///
/// `SingleAttestation`, the aggregate `committee_index` query, and the
/// Electra aggregate-and-proof variant. Open-ended so Gloas keeps that
/// shape; index zeroing is the separate [`zeroes_committee_index`] rule.
pub(crate) fn uses_electra_attestation_wire(fork: ForkName) -> bool {
    fork >= ForkName::Electra
}

/// Converts BN-supplied attestation data and normalizes it per-fork.
///
/// Per EIP-7549 (Electra through Fulu): `AttestationData.index` must be set to 0
/// before computing the tree-hash root or signing. The BN still returns the
/// real committee index in the response, so callers must zero it explicitly.
/// Pre-Electra forks keep the original index intact. At Gloas, `index` is the
/// payload-status bit and is preserved as supplied by the BN.
///
/// Use this helper everywhere a signing root or aggregate query root is needed
/// to ensure consistent normalization across the attestation and aggregation paths.
pub(crate) fn convert_and_normalize_attestation_data(
    beacon_data: &beacon::AttestationData,
    fork_name: ForkName,
) -> Result<eth_types::AttestationData, OrchestratorError> {
    let mut data = convert_attestation_data(beacon_data)?;
    if zeroes_committee_index(fork_name) {
        data.index = 0;
    }
    Ok(data)
}

pub(crate) fn convert_attestation_data(
    beacon_data: &beacon::AttestationData,
) -> Result<eth_types::AttestationData, OrchestratorError> {
    let slot: u64 = beacon_data
        .slot
        .parse()
        .map_err(|_| OrchestratorError::ParseError("Invalid slot".to_string()))?;

    let index: u64 = beacon_data
        .index
        .parse()
        .map_err(|_| OrchestratorError::ParseError("Invalid index".to_string()))?;

    let beacon_block_root = parse_hex_root(&beacon_data.beacon_block_root)?;

    let source_epoch: u64 = beacon_data
        .source
        .epoch
        .parse()
        .map_err(|_| OrchestratorError::ParseError("Invalid source epoch".to_string()))?;

    let source_root = parse_hex_root(&beacon_data.source.root)?;

    let target_epoch: u64 = beacon_data
        .target
        .epoch
        .parse()
        .map_err(|_| OrchestratorError::ParseError("Invalid target epoch".to_string()))?;

    let target_root = parse_hex_root(&beacon_data.target.root)?;

    Ok(eth_types::AttestationData {
        slot,
        index,
        beacon_block_root,
        source: eth_types::Checkpoint { epoch: source_epoch, root: source_root },
        target: eth_types::Checkpoint { epoch: target_epoch, root: target_root },
    })
}

pub(crate) fn parse_hex_root(hex_str: &str) -> Result<Root, OrchestratorError> {
    let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    let bytes = hex::decode(hex_str)
        .map_err(|e| OrchestratorError::ParseError(format!("Invalid hex: {}", e)))?;

    if bytes.len() != 32 {
        return Err(OrchestratorError::ParseError(format!(
            "Invalid root length: expected 32, got {}",
            bytes.len()
        )));
    }

    let mut root = [0u8; 32];
    root.copy_from_slice(&bytes);
    Ok(root)
}

pub(crate) async fn get_duties_for_slot(
    pubkey_map: &PubkeyMap,
    duty_tracker: &DutyTracker,
    slot: Slot,
) -> Result<Vec<AttesterDuty>, OrchestratorError> {
    // Borrow keys only — no full map clone / PublicKey clone on the hot path.
    let our_keys: std::collections::HashSet<[u8; 48]> = {
        let map = pubkey_map.read();
        if map.is_empty() {
            return Ok(Vec::new());
        }
        map.keys().copied().collect()
    };

    let epoch = slot / SLOTS_PER_EPOCH;

    if !duty_tracker.is_epoch_cached(epoch).await {
        duty_tracker.fetch_duties_for_epoch(epoch).await?;
    }

    let all_duties = duty_tracker.get_duties_for_slot(slot).await;
    let duties: Vec<AttesterDuty> = all_duties
        .into_iter()
        .filter(|duty| {
            parse_pubkey_bytes(&duty.pubkey).is_some_and(|bytes| our_keys.contains(&bytes))
        })
        .collect();

    Ok(duties)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_root_with_prefix() {
        let root =
            parse_hex_root("0x1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        assert_eq!(root, [0x11; 32]);
    }

    #[test]
    fn test_parse_hex_root_without_prefix() {
        let root =
            parse_hex_root("2222222222222222222222222222222222222222222222222222222222222222")
                .unwrap();
        assert_eq!(root, [0x22; 32]);
    }

    #[test]
    fn test_parse_hex_root_invalid_length() {
        let result = parse_hex_root("0x1111111111");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_hex_root_invalid_hex() {
        let result = parse_hex_root("0xgggggggg");
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_attestation_data_success() {
        let beacon_data = beacon::AttestationData {
            slot: "1000".to_string(),
            index: "5".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "100".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "101".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let crypto_data = convert_attestation_data(&beacon_data).unwrap();

        assert_eq!(crypto_data.slot, 1000);
        assert_eq!(crypto_data.index, 5);
        assert_eq!(crypto_data.beacon_block_root, [0x11; 32]);
        assert_eq!(crypto_data.source.epoch, 100);
        assert_eq!(crypto_data.source.root, [0x22; 32]);
        assert_eq!(crypto_data.target.epoch, 101);
        assert_eq!(crypto_data.target.root, [0x33; 32]);
    }

    fn make_duty_with_committee(
        committee_length: &str,
        validator_committee_index: &str,
    ) -> AttesterDuty {
        AttesterDuty {
            pubkey: "0xaabb".to_string(),
            validator_index: "1".to_string(),
            committee_index: "0".to_string(),
            committee_length: committee_length.to_string(),
            committees_at_slot: "1".to_string(),
            validator_committee_index: validator_committee_index.to_string(),
            slot: "100".to_string(),
        }
    }

    /// ISSUE-4.4 / L-4: validator_committee_index == committee_length must
    /// return None (previously: Some with only the sentinel bit set).
    #[test]
    fn test_aggregation_bits_index_equals_length_returns_none() {
        let duty = make_duty_with_committee("4", "4");
        assert!(make_aggregation_bits(&duty).is_none());
    }

    /// ISSUE-4.4 / L-4: a far-out-of-range index also returns None.
    #[test]
    fn test_aggregation_bits_index_far_exceeds_length_returns_none() {
        let duty = make_duty_with_committee("4", "100");
        assert!(make_aggregation_bits(&duty).is_none());
    }

    /// Regression guard: in-range index still returns Some with the
    /// validator bit set.  Sanity that the L-4 fix did not over-reject.
    #[test]
    fn test_aggregation_bits_in_range_index_returns_some() {
        let duty = make_duty_with_committee("8", "3");
        let bits_hex = make_aggregation_bits(&duty).expect("in-range must return Some");
        // Validator bit at position 3 -> 0b00001000, sentinel bit at position 8 -> 0b00000001.
        // byte_count = (8 + 8) / 8 = 2 bytes.
        assert_eq!(bits_hex, "0x0801");
    }

    #[test]
    fn test_aggregation_bits_committee_length_zero() {
        // committee_length == 0 returns None (early return with warning)
        let duty = make_duty_with_committee("0", "0");
        let result = make_aggregation_bits(&duty);
        assert!(result.is_none(), "committee_length=0 must return None");
    }

    #[test]
    fn test_convert_attestation_data_invalid_slot() {
        let beacon_data = beacon::AttestationData {
            slot: "invalid".to_string(),
            index: "5".to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "100".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "101".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        };

        let result = convert_attestation_data(&beacon_data);
        assert!(result.is_err());
    }

    fn make_test_beacon_attestation_data(index: &str) -> beacon::AttestationData {
        beacon::AttestationData {
            slot: "1000".to_string(),
            index: index.to_string(),
            beacon_block_root: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            source: beacon::Checkpoint {
                epoch: "100".to_string(),
                root: "0x2222222222222222222222222222222222222222222222222222222222222222"
                    .to_string(),
            },
            target: beacon::Checkpoint {
                epoch: "101".to_string(),
                root: "0x3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            },
        }
    }

    #[test]
    fn test_zeroes_committee_index_false_phase0_through_deneb_true_electra_and_fulu() {
        let table = [
            (ForkName::Phase0, false),
            (ForkName::Altair, false),
            (ForkName::Bellatrix, false),
            (ForkName::Capella, false),
            (ForkName::Deneb, false),
            (ForkName::Electra, true),
            (ForkName::Fulu, true),
            (ForkName::Gloas, false),
        ];
        assert_eq!(table.len(), ForkName::COUNT, "table must cover every ForkName");
        for (fork, expected) in table {
            assert_eq!(
                zeroes_committee_index(fork),
                expected,
                "{fork:?}: zeroes_committee_index is false Phase0..=Deneb, true Electra..Gloas"
            );
        }
    }

    #[test]
    fn test_uses_electra_attestation_wire_false_phase0_through_deneb_true_from_electra() {
        let table = [
            (ForkName::Phase0, false),
            (ForkName::Altair, false),
            (ForkName::Bellatrix, false),
            (ForkName::Capella, false),
            (ForkName::Deneb, false),
            (ForkName::Electra, true),
            (ForkName::Fulu, true),
            (ForkName::Gloas, true),
        ];
        assert_eq!(table.len(), ForkName::COUNT, "table must cover every ForkName");
        for (fork, expected) in table {
            assert_eq!(
                uses_electra_attestation_wire(fork),
                expected,
                "{fork:?}: Electra+ wire is false Phase0..=Deneb, true Electra onward"
            );
        }
    }

    #[test]
    fn test_zeroing_and_electra_wire_diverge_only_at_gloas() {
        for fork in ForkName::ALL {
            let zero = zeroes_committee_index(fork);
            let wire = uses_electra_attestation_wire(fork);
            if fork == ForkName::Gloas {
                assert!(!zero && wire, "Gloas preserves index but keeps the Electra+ wire");
            } else {
                assert_eq!(zero, wire, "{fork:?}: zeroing and Electra+ wire match except at Gloas");
            }
        }
    }

    /// Electra 364544, Fulu 500000, Gloas 600000 — all finite (not `u64::MAX`).
    fn finite_electra_fulu_gloas_schedule() -> eth_types::ForkSchedule {
        eth_types::ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 74240,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 144896,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 194048,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 269568,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 364544,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: 500000,
            fulu_fork_version: [6, 0, 0, 0],
            gloas_fork_epoch: 600000,
            gloas_fork_version: [7, 0, 0, 0],
        }
    }

    // --- RED tests for convert_and_normalize_attestation_data ---

    #[test]
    fn test_convert_and_normalize_electra_zeros_index() {
        let beacon_data = make_test_beacon_attestation_data("5");
        let result =
            convert_and_normalize_attestation_data(&beacon_data, ForkName::Electra).unwrap();
        assert_eq!(
            result.index, 0,
            "Electra: EIP-7549 requires index zeroed before tree_hash_root"
        );
    }

    #[test]
    fn test_convert_and_normalize_fulu_zeros_index() {
        let beacon_data = make_test_beacon_attestation_data("7");
        let result = convert_and_normalize_attestation_data(&beacon_data, ForkName::Fulu).unwrap();
        assert_eq!(result.index, 0, "Fulu inherits EIP-7549: index must be zeroed");
    }

    #[test]
    fn test_convert_and_normalize_deneb_keeps_index() {
        let beacon_data = make_test_beacon_attestation_data("5");
        let result = convert_and_normalize_attestation_data(&beacon_data, ForkName::Deneb).unwrap();
        assert_eq!(result.index, 5, "Deneb: index must NOT be zeroed (pre-Electra)");
    }

    #[test]
    fn test_convert_and_normalize_phase0_keeps_index() {
        let beacon_data = make_test_beacon_attestation_data("3");
        let result =
            convert_and_normalize_attestation_data(&beacon_data, ForkName::Phase0).unwrap();
        assert_eq!(result.index, 3, "Phase0: index must NOT be zeroed");
    }

    #[test]
    fn test_convert_and_normalize_altair_keeps_index() {
        let beacon_data = make_test_beacon_attestation_data("2");
        let result =
            convert_and_normalize_attestation_data(&beacon_data, ForkName::Altair).unwrap();
        assert_eq!(result.index, 2, "Altair: index must NOT be zeroed");
    }

    #[test]
    fn test_convert_and_normalize_capella_keeps_index() {
        let beacon_data = make_test_beacon_attestation_data("6");
        let result =
            convert_and_normalize_attestation_data(&beacon_data, ForkName::Capella).unwrap();
        assert_eq!(result.index, 6, "Capella: index must NOT be zeroed");
    }

    #[test]
    fn test_convert_and_normalize_preserves_other_fields() {
        let beacon_data = make_test_beacon_attestation_data("5");
        let result =
            convert_and_normalize_attestation_data(&beacon_data, ForkName::Electra).unwrap();
        assert_eq!(result.slot, 1000);
        assert_eq!(result.beacon_block_root, [0x11; 32]);
        assert_eq!(result.source.epoch, 100);
        assert_eq!(result.target.epoch, 101);
    }

    #[test]
    fn test_convert_and_normalize_invalid_data_returns_err() {
        let mut beacon_data = make_test_beacon_attestation_data("5");
        beacon_data.slot = "invalid".to_string();
        let result = convert_and_normalize_attestation_data(&beacon_data, ForkName::Electra);
        assert!(result.is_err());
    }

    #[test]
    fn test_convert_and_normalize_electra_zero_index_input_stays_zero() {
        let beacon_data = make_test_beacon_attestation_data("0");
        let result =
            convert_and_normalize_attestation_data(&beacon_data, ForkName::Electra).unwrap();
        assert_eq!(result.index, 0);
    }

    #[test]
    fn test_convert_and_normalize_preserves_gloas_index_zeroes_electra_and_fulu() {
        let schedule = finite_electra_fulu_gloas_schedule();
        let beacon_full = make_test_beacon_attestation_data("1");
        let beacon_empty = make_test_beacon_attestation_data("0");

        let gloas = ForkName::from_epoch(600000, &schedule);
        assert_eq!(gloas, ForkName::Gloas);
        assert_eq!(
            convert_and_normalize_attestation_data(&beacon_full, gloas).unwrap().index,
            1,
            "Gloas preserves BN payload FULL=1"
        );
        assert_eq!(
            convert_and_normalize_attestation_data(&beacon_empty, gloas).unwrap().index,
            0,
            "Gloas preserves BN payload EMPTY=0"
        );

        for (label, epoch, expected_fork) in
            [("electra", 364544, ForkName::Electra), ("fulu", 500000, ForkName::Fulu)]
        {
            let fork = ForkName::from_epoch(epoch, &schedule);
            assert_eq!(fork, expected_fork, "{label}: from_epoch on finite schedule");
            assert_eq!(
                convert_and_normalize_attestation_data(&beacon_full, fork).unwrap().index,
                0,
                "{label}: EIP-7549 still zeroes BN index 1"
            );
        }
    }

    // --- RF6-31: find_pubkey O(1) by compressed bytes ---

    #[test]
    fn test_find_pubkey_accepts_case_and_prefix_variants() {
        let sk = crypto::SecretKey::generate();
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        let mut map = std::collections::HashMap::new();
        map.insert(bytes, pk.clone());
        let pubkey_map: PubkeyMap = std::sync::Arc::new(parking_lot::RwLock::new(map));

        let lower = format!("0x{}", hex::encode(bytes));
        let upper = format!("0X{}", hex::encode(bytes).to_uppercase());
        let bare = hex::encode(bytes).to_uppercase();

        assert_eq!(find_pubkey(&pubkey_map, &lower).unwrap().to_bytes(), bytes);
        assert_eq!(find_pubkey(&pubkey_map, &upper).unwrap().to_bytes(), bytes);
        assert_eq!(find_pubkey(&pubkey_map, &bare).unwrap().to_bytes(), bytes);
    }

    #[test]
    fn test_find_pubkey_rejects_invalid_hex_without_linear_scan() {
        let sk = crypto::SecretKey::generate();
        let pk = sk.public_key();
        let mut map = std::collections::HashMap::new();
        map.insert(pk.to_bytes(), pk);
        let pubkey_map: PubkeyMap = std::sync::Arc::new(parking_lot::RwLock::new(map));

        // Non-hex and wrong length used to be reachable via the O(n) fallback;
        // with typed keys they miss immediately.
        assert!(find_pubkey(&pubkey_map, "0xzzzz").is_none());
        assert!(find_pubkey(&pubkey_map, "0xabcd").is_none());
        assert!(find_pubkey(&pubkey_map, "not-a-key").is_none());
    }

    #[test]
    fn test_find_pubkey_bytes_is_o1_lookup() {
        let sk = crypto::SecretKey::generate();
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        let mut map = std::collections::HashMap::new();
        map.insert(bytes, pk.clone());
        let pubkey_map: PubkeyMap = std::sync::Arc::new(parking_lot::RwLock::new(map));

        assert_eq!(find_pubkey_bytes(&pubkey_map, &bytes).unwrap().to_bytes(), bytes);
        assert!(find_pubkey_bytes(&pubkey_map, &[0u8; 48]).is_none());
    }
}
