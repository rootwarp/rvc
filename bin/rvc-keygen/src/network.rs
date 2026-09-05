use anyhow::{bail, Result};
use eth_types::{network_from_name, ForkSchedule, NetworkPreset};

/// Thin alias onto the shared [`NetworkPreset`] table (RF3-04).
///
/// Network constants live once in `eth_types::networks`; keygen only adds
/// EIP-7044 exit-fork schedule construction on top.
pub type KeygenNetwork = NetworkPreset;

pub fn from_name(name: &str) -> Result<&'static KeygenNetwork> {
    match network_from_name(name) {
        Some(preset) => Ok(preset),
        None => bail!("Unknown network: '{}'. Supported: mainnet, hoodi, holesky, sepolia", name),
    }
}

/// Creates a `ForkSchedule` suitable for EIP-7044 voluntary exit signing.
///
/// Sets Capella as active at epoch 0 and all post-Capella forks at `u64::MAX`.
/// `from_epoch` at `u64::MAX` therefore picks Gloas; the Capella cap lives in
/// `>= ForkName::Capella` (`crypto::capella_capped_fork_version`).
pub fn exit_fork_schedule(network: &KeygenNetwork) -> ForkSchedule {
    ForkSchedule {
        genesis_fork_version: network.genesis_fork_version,
        altair_fork_epoch: 0,
        altair_fork_version: network.genesis_fork_version,
        bellatrix_fork_epoch: 0,
        bellatrix_fork_version: network.genesis_fork_version,
        capella_fork_epoch: 0,
        capella_fork_version: network.capella_fork_version,
        deneb_fork_epoch: u64::MAX,
        deneb_fork_version: [0xFF, 0xFF, 0xFF, 0xFF],
        electra_fork_epoch: u64::MAX,
        electra_fork_version: [0xFF, 0xFF, 0xFF, 0xFF],
        fulu_fork_epoch: u64::MAX,
        fulu_fork_version: [0xFF, 0xFF, 0xFF, 0xFF],
        gloas_fork_epoch: u64::MAX,
        gloas_fork_version: [0xFF, 0xFF, 0xFF, 0xFF],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eth_types::ForkName;

    // KAT anchors — byte literals that used to live in this file before RF3-04
    // delegation. Independent check that values did not change.
    const MAINNET_GVR: [u8; 32] = [
        0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd,
        0x4e, 0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b,
        0xfe, 0x95,
    ];
    const HOODI_GVR: [u8; 32] = [
        0x21, 0x2f, 0x13, 0xfc, 0x4d, 0xf0, 0x78, 0xb6, 0xcb, 0x7d, 0xb2, 0x28, 0xf1, 0xc8, 0x30,
        0x75, 0x66, 0xdc, 0xec, 0xf9, 0x00, 0x86, 0x74, 0x01, 0xa9, 0x20, 0x23, 0xd7, 0xba, 0x99,
        0xcb, 0x5f,
    ];
    const HOLESKY_GVR: [u8; 32] = [
        0x91, 0x43, 0xaa, 0x7c, 0x61, 0x5a, 0x7f, 0x71, 0x15, 0xe2, 0xb6, 0xaa, 0xc3, 0x19, 0xc0,
        0x35, 0x29, 0xdf, 0x82, 0x42, 0xae, 0x70, 0x5f, 0xba, 0x9d, 0xf3, 0x9b, 0x79, 0xc5, 0x9f,
        0xa8, 0xb1,
    ];
    const SEPOLIA_GVR: [u8; 32] = [
        0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05,
        0x2a, 0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b,
        0x80, 0x78,
    ];

    struct ByteKat {
        name: &'static str,
        genesis_fork_version: [u8; 4],
        genesis_validators_root: [u8; 32],
        capella_fork_version: [u8; 4],
    }

    #[test]
    fn test_keygen_network_values_unchanged_after_delegation() {
        let cases = [
            ByteKat {
                name: "mainnet",
                genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
                genesis_validators_root: MAINNET_GVR,
                capella_fork_version: [0x03, 0x00, 0x00, 0x00],
            },
            ByteKat {
                name: "hoodi",
                genesis_fork_version: [0x10, 0x00, 0x09, 0x10],
                genesis_validators_root: HOODI_GVR,
                capella_fork_version: [0x40, 0x00, 0x09, 0x10],
            },
            ByteKat {
                name: "holesky",
                genesis_fork_version: [0x01, 0x01, 0x70, 0x00],
                genesis_validators_root: HOLESKY_GVR,
                capella_fork_version: [0x04, 0x01, 0x70, 0x00],
            },
            ByteKat {
                name: "sepolia",
                genesis_fork_version: [0x90, 0x00, 0x00, 0x69],
                genesis_validators_root: SEPOLIA_GVR,
                capella_fork_version: [0x90, 0x00, 0x00, 0x72],
            },
        ];
        for kat in &cases {
            let net = from_name(kat.name).unwrap();
            assert_eq!(net.name, kat.name);
            assert_eq!(
                net.genesis_fork_version, kat.genesis_fork_version,
                "genesis_fork_version for {}",
                kat.name
            );
            assert_eq!(
                net.genesis_validators_root, kat.genesis_validators_root,
                "GVR for {}",
                kat.name
            );
            assert_eq!(
                net.capella_fork_version, kat.capella_fork_version,
                "capella_fork_version for {}",
                kat.name
            );
        }
    }

    #[test]
    fn test_from_name_mainnet() {
        let net = from_name("mainnet").unwrap();
        assert_eq!(net.name, "mainnet");
        assert_eq!(net.genesis_fork_version, [0x00, 0x00, 0x00, 0x00]);
        assert_eq!(net.capella_fork_version, [0x03, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_from_name_hoodi() {
        let net = from_name("hoodi").unwrap();
        assert_eq!(net.name, "hoodi");
        assert_eq!(net.genesis_fork_version, [0x10, 0x00, 0x09, 0x10]);
        assert_eq!(net.capella_fork_version, [0x40, 0x00, 0x09, 0x10]);
    }

    #[test]
    fn test_from_name_holesky() {
        let net = from_name("holesky").unwrap();
        assert_eq!(net.name, "holesky");
        assert_eq!(net.genesis_fork_version, [0x01, 0x01, 0x70, 0x00]);
        assert_eq!(net.capella_fork_version, [0x04, 0x01, 0x70, 0x00]);
    }

    #[test]
    fn test_from_name_sepolia() {
        let net = from_name("sepolia").unwrap();
        assert_eq!(net.name, "sepolia");
        assert_eq!(net.genesis_fork_version, [0x90, 0x00, 0x00, 0x69]);
        assert_eq!(net.capella_fork_version, [0x90, 0x00, 0x00, 0x72]);
    }

    #[test]
    fn test_from_name_case_insensitive() {
        assert!(from_name("Mainnet").is_ok());
        assert!(from_name("HOODI").is_ok());
        assert!(from_name("Holesky").is_ok());
        assert!(from_name("SEPOLIA").is_ok());
    }

    #[test]
    fn test_from_name_unknown() {
        let result = from_name("unknown");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unknown network"));
    }

    #[test]
    fn test_unknown_network_error_text_preserved() {
        // CLI-visible error text for rvc-keygen (kept distinct from rvc's lowercase form).
        let err = from_name("goerli").unwrap_err().to_string();
        assert_eq!(err, "Unknown network: 'goerli'. Supported: mainnet, hoodi, holesky, sepolia");
    }

    #[test]
    fn test_mainnet_genesis_root() {
        let expected =
            hex::decode("4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95")
                .unwrap();
        assert_eq!(NetworkPreset::MAINNET.genesis_validators_root, expected.as_slice());
    }

    #[test]
    fn test_hoodi_genesis_root() {
        let expected =
            hex::decode("212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f")
                .unwrap();
        assert_eq!(NetworkPreset::HOODI.genesis_validators_root, expected.as_slice());
    }

    #[test]
    fn test_holesky_genesis_root() {
        let expected =
            hex::decode("9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1")
                .unwrap();
        assert_eq!(NetworkPreset::HOLESKY.genesis_validators_root, expected.as_slice());
    }

    #[test]
    fn test_sepolia_genesis_root() {
        let expected =
            hex::decode("d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078")
                .unwrap();
        assert_eq!(NetworkPreset::SEPOLIA.genesis_validators_root, expected.as_slice());
    }

    #[test]
    fn test_exit_fork_schedule_caps_at_capella() {
        let net = from_name("mainnet").unwrap();
        let schedule = exit_fork_schedule(net);

        // Any epoch should resolve to at most Capella
        assert_eq!(ForkName::from_epoch(0, &schedule), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(1000, &schedule), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(999999, &schedule), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(u64::MAX - 1, &schedule), ForkName::Capella);
    }

    #[test]
    fn test_exit_fork_schedule_hoodi() {
        let net = from_name("hoodi").unwrap();
        let schedule = exit_fork_schedule(net);
        assert_eq!(schedule.capella_fork_version, [0x40, 0x00, 0x09, 0x10]);
        assert_eq!(ForkName::from_epoch(0, &schedule), ForkName::Capella);
    }
}
