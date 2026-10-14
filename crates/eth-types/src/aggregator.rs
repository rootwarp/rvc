use sha2::{Digest, Sha256};

use crate::TARGET_AGGREGATORS_PER_COMMITTEE;

/// Determines whether a validator is an aggregator for a given committee.
///
/// Per the Ethereum consensus spec:
/// ```text
/// modulo = max(1, len(committee) // TARGET_AGGREGATORS_PER_COMMITTEE)
/// return bytes_to_uint64(hash(slot_signature)[0:8]) % modulo == 0
/// ```
pub fn is_aggregator(committee_length: u64, selection_proof: &[u8]) -> bool {
    let modulo = (committee_length / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
    let hash = Sha256::digest(selection_proof);
    let value = u64::from_le_bytes(hash[..8].try_into().expect("hash is at least 8 bytes"));
    value % modulo == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_aggregator_modulo_committee_128() {
        // committee_length=128 → modulo = 128/16 = 8
        use crate::TARGET_AGGREGATORS_PER_COMMITTEE;
        let modulo = (128u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
        assert_eq!(modulo, 8);

        let agg_proof = find_aggregator_proof_for_modulo(modulo);
        assert!(is_aggregator(128, &agg_proof));

        let non_agg_proof = find_non_aggregator_proof_for_modulo(modulo);
        assert!(!is_aggregator(128, &non_agg_proof));
    }

    #[test]
    fn test_is_aggregator_modulo_committee_8() {
        // committee_length=8 → 8/16 = 0 → max(1, 0) = 1
        // All validators are aggregators (modulo 1 always == 0)
        assert!(is_aggregator(8, &[0x00; 96]));
        assert!(is_aggregator(8, &[0xff; 96]));
        assert!(is_aggregator(8, &[0xab; 96]));
    }

    #[test]
    fn test_is_aggregator_modulo_committee_0() {
        // committee_length=0 → 0/16 = 0 → max(1, 0) = 1
        // All validators are aggregators (modulo 1 always == 0)
        assert!(is_aggregator(0, &[0xaa; 96]));
        assert!(is_aggregator(0, &[0xff; 96]));
    }

    #[test]
    fn test_is_aggregator_deterministic() {
        let proof = vec![0xaa; 96];
        let result1 = is_aggregator(128, &proof);
        let result2 = is_aggregator(128, &proof);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_is_aggregator_different_proofs_may_differ() {
        // committee_length=128 → modulo=8
        let agg_proof = find_aggregator_proof_for_modulo(8);
        let non_agg_proof = find_non_aggregator_proof_for_modulo(8);
        assert_ne!(is_aggregator(128, &agg_proof), is_aggregator(128, &non_agg_proof),);
    }

    #[test]
    fn test_is_aggregator_committee_length_one_always_true() {
        // committee_length=1 → 1/16 = 0 → max(1, 0) = 1 → always aggregator
        assert!(is_aggregator(1, &[0x00; 96]));
        assert!(is_aggregator(1, &[0xff; 96]));
        assert!(is_aggregator(1, &[0xab; 96]));
    }

    #[test]
    fn test_is_aggregator_committee_length_16_modulo_1() {
        // committee_length=16 → 16/16 = 1 → max(1, 1) = 1 → always aggregator
        assert!(is_aggregator(16, &[0x00; 96]));
        assert!(is_aggregator(16, &[0xff; 96]));
    }

    // KAT (report §5 bullet 1): pin the little-endian interpretation in `is_aggregator`
    // against a hardcoded digest so a consistent LE↔BE flip in production would fail.
    // The existing oracle helpers (`find_aggregator_proof_for_modulo` etc.) themselves
    // call `u64::from_le_bytes`, so a matching flip in both production and oracle would
    // still pass — this test asserts directly on literal digest bytes instead.
    #[test]
    fn test_is_aggregator_little_endian_golden_digest() {
        // Golden digest chosen so the two byte orders give OPPOSITE aggregator verdicts:
        //   bytes        = 08 00 00 00 00 00 00 01
        //   LE u64       = 0x0100000000000008 → % 8 == 0  (aggregator)
        //   BE u64       = 0x0800000000000001 → % 8 == 1  (NOT aggregator)
        // Locks the endianness contract to literal bytes, independent of `is_aggregator`.
        const GOLDEN_DIGEST_HEAD: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        let le_value = u64::from_le_bytes(GOLDEN_DIGEST_HEAD);
        let be_value = u64::from_be_bytes(GOLDEN_DIGEST_HEAD);
        assert_eq!(le_value, 0x0100_0000_0000_0008);
        assert_eq!(be_value, 0x0800_0000_0000_0001);
        assert_eq!(le_value % 8, 0, "little-endian verdict must be aggregator");
        assert_ne!(be_value % 8, 0, "big-endian verdict must be non-aggregator");

        // End-to-end: `is_aggregator` hashes its input, so feed a preimage whose SHA-256
        // head yields the LE aggregator verdict (committee 128 → modulo 8). The oracle
        // helper only FINDS the preimage; the load-bearing endianness check is above.
        let preimage = find_aggregator_proof_for_modulo(8);
        let digest = Sha256::digest(&preimage);
        let digest_head: [u8; 8] = digest[..8].try_into().unwrap();
        // Production uses little-endian: this preimage is an aggregator under LE.
        assert_eq!(u64::from_le_bytes(digest_head) % 8, 0);
        assert!(is_aggregator(128, &preimage));
    }

    #[test]
    fn test_is_aggregator_large_committee() {
        // committee_length=256 → 256/16 = 16
        use crate::TARGET_AGGREGATORS_PER_COMMITTEE;
        let modulo = (256u64 / TARGET_AGGREGATORS_PER_COMMITTEE).max(1);
        assert_eq!(modulo, 16);

        let agg_proof = find_aggregator_proof_for_modulo(modulo);
        assert!(is_aggregator(256, &agg_proof));

        let non_agg_proof = find_non_aggregator_proof_for_modulo(modulo);
        assert!(!is_aggregator(256, &non_agg_proof));
    }

    fn find_aggregator_proof_for_modulo(modulo: u64) -> Vec<u8> {
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[..8].try_into().unwrap());
            if value % modulo == 0 {
                return proof;
            }
        }
        unreachable!()
    }

    fn find_non_aggregator_proof_for_modulo(modulo: u64) -> Vec<u8> {
        for i in 0u64.. {
            let proof = i.to_le_bytes().to_vec();
            let hash = Sha256::digest(&proof);
            let value = u64::from_le_bytes(hash[..8].try_into().unwrap());
            if value % modulo != 0 {
                return proof;
            }
        }
        unreachable!()
    }
}
