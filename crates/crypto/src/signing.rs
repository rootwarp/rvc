use tracing::trace;
use tree_hash::TreeHash;

use eth_types::{Domain, DomainType, ForkData, Root, SigningData};
use observability::logging::TruncatedRoot;

fn hash_tree_root<T: TreeHash>(object: &T) -> Root {
    object.tree_hash_root().0
}

pub fn compute_fork_data_root(current_version: [u8; 4], genesis_validators_root: Root) -> Root {
    let fork_data = ForkData { current_version, genesis_validators_root };
    hash_tree_root(&fork_data)
}

pub fn compute_domain(
    domain_type: DomainType,
    fork_version: [u8; 4],
    genesis_validators_root: Root,
) -> Domain {
    let fork_data_root = compute_fork_data_root(fork_version, genesis_validators_root);
    let mut domain = [0u8; 32];
    domain[..4].copy_from_slice(&domain_type);
    domain[4..32].copy_from_slice(&fork_data_root[..28]);
    domain
}

pub fn compute_signing_root<T: TreeHash>(ssz_object: &T, domain: Domain) -> Root {
    let object_root = hash_tree_root(ssz_object);
    let signing_data = SigningData { object_root, domain };
    let signing_root = hash_tree_root(&signing_data);
    trace!(
        domain = %TruncatedRoot::new(&domain),
        signing_root = %TruncatedRoot::new(&signing_root),
        "Computed signing root"
    );
    signing_root
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::{AttestationData, Checkpoint, DOMAIN_BEACON_ATTESTER};
    use tree_hash::TreeHash;

    #[test]
    fn test_hash_tree_root_uses_spec_compliant_tree_hash() {
        let fork_data = ForkData {
            current_version: [0x00, 0x00, 0x00, 0x00],
            genesis_validators_root: [0x00; 32],
        };

        let expected = fork_data.tree_hash_root();
        let actual = hash_tree_root(&fork_data);

        assert_eq!(actual, expected.0);
    }

    #[test]
    fn test_checkpoint_tree_hash_root() {
        let checkpoint = Checkpoint { epoch: 100, root: [0xab; 32] };

        let expected = checkpoint.tree_hash_root();
        let actual = hash_tree_root(&checkpoint);

        assert_eq!(actual, expected.0);
    }

    #[test]
    fn test_attestation_data_tree_hash_root() {
        let data = create_test_attestation_data();

        let expected = data.tree_hash_root();
        let actual = hash_tree_root(&data);

        assert_eq!(actual, expected.0);
    }

    #[test]
    fn test_signing_data_tree_hash_root() {
        let signing_data = SigningData { object_root: [0x11; 32], domain: [0x22; 32] };

        let expected = signing_data.tree_hash_root();
        let actual = hash_tree_root(&signing_data);

        assert_eq!(actual, expected.0);
    }

    #[test]
    fn test_domain_beacon_attester_value() {
        assert_eq!(DOMAIN_BEACON_ATTESTER, [0x01, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_compute_fork_data_root_deterministic() {
        let version = [0x00, 0x00, 0x00, 0x01];
        let genesis_root = [0xab; 32];

        let root1 = compute_fork_data_root(version, genesis_root);
        let root2 = compute_fork_data_root(version, genesis_root);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_fork_data_root_different_inputs_different_outputs() {
        let version1 = [0x00, 0x00, 0x00, 0x01];
        let version2 = [0x00, 0x00, 0x00, 0x02];
        let genesis_root = [0xab; 32];

        let root1 = compute_fork_data_root(version1, genesis_root);
        let root2 = compute_fork_data_root(version2, genesis_root);

        assert_ne!(root1, root2);
    }

    #[test]
    fn test_compute_domain_includes_domain_type() {
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, [0x00, 0x00, 0x00, 0x01], [0x00; 32]);

        assert_eq!(&domain[..4], &DOMAIN_BEACON_ATTESTER);
    }

    #[test]
    fn test_compute_domain_different_fork_versions() {
        let genesis_root = [0x00; 32];

        let domain1 =
            compute_domain(DOMAIN_BEACON_ATTESTER, [0x00, 0x00, 0x00, 0x01], genesis_root);
        let domain2 =
            compute_domain(DOMAIN_BEACON_ATTESTER, [0x00, 0x00, 0x00, 0x02], genesis_root);

        assert_ne!(domain1, domain2);
        assert_eq!(&domain1[..4], &domain2[..4]);
    }

    #[test]
    fn test_compute_signing_root_deterministic() {
        let data = create_test_attestation_data();
        let domain = [0x01; 32];

        let root1 = compute_signing_root(&data, domain);
        let root2 = compute_signing_root(&data, domain);

        assert_eq!(root1, root2);
    }

    #[test]
    fn test_compute_signing_root_different_domains() {
        let data = create_test_attestation_data();

        let root1 = compute_signing_root(&data, [0x01; 32]);
        let root2 = compute_signing_root(&data, [0x02; 32]);

        assert_ne!(root1, root2);
    }

    /// Gate-3 (redaction) seed: `compute_signing_root`'s trace must render the
    /// domain and the signing root TRUNCATED — the full 32-byte hex of neither
    /// may appear at any level.
    #[test]
    #[tracing_test::traced_test]
    // kat_exempt: logging truncation only — asserts domain/root hex is redacted, not a spec root
    fn test_compute_signing_root_trace_truncates_domain_and_root() {
        // Distinct bytes (0x00,0x01,…,0x1f) so the full-hex needle is a real,
        // non-vacuous match — a repeating-byte domain plus `?`-Debug's decimal
        // rendering would make the negative assertion always pass.
        let object: Root = [0x11; 32];
        let domain: Domain = std::array::from_fn(|i| i as u8);
        let root = compute_signing_root(&object, domain);

        // The domain is truncated (first 5 + last 4 bytes), never logged in full,
        // and a middle slice present only in the full encoding is absent.
        assert!(logs_contain("0x0001020304...1c1d1e1f"), "domain must be truncated");
        assert!(!logs_contain(&hex::encode(domain)), "full 32-byte domain hex must be absent");
        assert!(!logs_contain("0a0b0c0d"), "middle domain bytes must be truncated away");
        // The computed signing root is likewise never logged in full.
        assert!(!logs_contain(&hex::encode(root)), "full signing-root hex must be absent");
    }

    // KAT (report §5 bullet 3): first absolute-byte vector for `compute_fork_data_root`.
    // Golden value derived independently with `remerkleable` (ForkData = Container{
    // current_version: Bytes4, genesis_validators_root: Bytes32 }) — NOT recomputed via
    // rvc's compute_* in this test. Cross-checked: ForkData(00000000, zeros).htr ==
    // sha256(zeros32||zeros32) == f5a5fd42… (the canonical consensus-spec zero-hash).
    //   inputs: current_version = 0x01000000, genesis_validators_root = 0x00…00 (32 zeros)
    //   fork_data_root = 16abab341fb7f370e27e4dadcf81766dd0dfd0ae64469477bb2cf6614938b2af
    #[test]
    fn test_compute_fork_data_root_known_answer_bytes() {
        const EXPECTED: Root = [
            0x16, 0xab, 0xab, 0x34, 0x1f, 0xb7, 0xf3, 0x70, 0xe2, 0x7e, 0x4d, 0xad, 0xcf, 0x81,
            0x76, 0x6d, 0xd0, 0xdf, 0xd0, 0xae, 0x64, 0x46, 0x94, 0x77, 0xbb, 0x2c, 0xf6, 0x61,
            0x49, 0x38, 0xb2, 0xaf,
        ];
        let root = compute_fork_data_root([0x01, 0x00, 0x00, 0x00], [0x00; 32]);
        assert_eq!(root, EXPECTED);
    }

    // KAT (report §5 bullet 3): first absolute-byte vector for `compute_domain`. Pins the
    // `domain[..4] = domain_type` / `domain[4..32] = fork_data_root[..28]` layout against
    // an externally-derived literal. Golden value from `remerkleable` (see above).
    //   inputs: domain_type = DOMAIN_BEACON_ATTESTER (0x01000000),
    //           fork_version = 0x01000000, genesis_validators_root = 0x00…00 (32 zeros)
    //   domain = 0100000016abab341fb7f370e27e4dadcf81766dd0dfd0ae64469477bb2cf661
    #[test]
    fn test_compute_domain_known_answer_bytes() {
        const EXPECTED: Domain = [
            0x01, 0x00, 0x00, 0x00, 0x16, 0xab, 0xab, 0x34, 0x1f, 0xb7, 0xf3, 0x70, 0xe2, 0x7e,
            0x4d, 0xad, 0xcf, 0x81, 0x76, 0x6d, 0xd0, 0xdf, 0xd0, 0xae, 0x64, 0x46, 0x94, 0x77,
            0xbb, 0x2c, 0xf6, 0x61,
        ];
        let domain = compute_domain(DOMAIN_BEACON_ATTESTER, [0x01, 0x00, 0x00, 0x00], [0x00; 32]);
        assert_eq!(domain, EXPECTED);
    }

    // KAT (report §5 bullet 3): first absolute-byte vector for `compute_signing_root`. Pins
    // the SigningData = Container{ object_root: Bytes32, domain: Bytes32 } field order and
    // hashing against an externally-derived literal. Golden value from `remerkleable`.
    // The object is a Root ([u8;32]); its hash_tree_root is the identity, so object_root is
    // the 32 input bytes themselves.
    //   inputs: object = 0x11…11 (32 bytes),
    //           domain = 0100000016abab341fb7f370e27e4dadcf81766dd0dfd0ae64469477bb2cf661
    //   signing_root = 18029e3e0be198604599daad88e7b3bc5c1aae9084c041669abd64e1a7b32de5
    #[test]
    fn test_compute_signing_root_known_answer_bytes() {
        const DOMAIN: Domain = [
            0x01, 0x00, 0x00, 0x00, 0x16, 0xab, 0xab, 0x34, 0x1f, 0xb7, 0xf3, 0x70, 0xe2, 0x7e,
            0x4d, 0xad, 0xcf, 0x81, 0x76, 0x6d, 0xd0, 0xdf, 0xd0, 0xae, 0x64, 0x46, 0x94, 0x77,
            0xbb, 0x2c, 0xf6, 0x61,
        ];
        const EXPECTED: Root = [
            0x18, 0x02, 0x9e, 0x3e, 0x0b, 0xe1, 0x98, 0x60, 0x45, 0x99, 0xda, 0xad, 0x88, 0xe7,
            0xb3, 0xbc, 0x5c, 0x1a, 0xae, 0x90, 0x84, 0xc0, 0x41, 0x66, 0x9a, 0xbd, 0x64, 0xe1,
            0xa7, 0xb3, 0x2d, 0xe5,
        ];
        let object: Root = [0x11; 32];
        let root = compute_signing_root(&object, DOMAIN);
        assert_eq!(root, EXPECTED);
    }

    fn create_test_attestation_data() -> AttestationData {
        AttestationData {
            slot: 1000,
            index: 5,
            beacon_block_root: [0x11; 32],
            source: Checkpoint { epoch: 99, root: [0x22; 32] },
            target: Checkpoint { epoch: 100, root: [0x33; 32] },
        }
    }
}
