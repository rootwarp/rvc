use std::fmt;
use std::str::FromStr;

use crate::block::BodyForkLayout;
use crate::{Epoch, Version};

/// All known consensus forks, in activation order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ForkName {
    Phase0,
    Altair,
    Bellatrix,
    Capella,
    Deneb,
    Electra,
    Fulu,
    Gloas,
}

/// Network fork schedule: activation epoch and version per fork.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkSchedule {
    pub genesis_fork_version: Version,
    pub altair_fork_epoch: Epoch,
    pub altair_fork_version: Version,
    pub bellatrix_fork_epoch: Epoch,
    pub bellatrix_fork_version: Version,
    pub capella_fork_epoch: Epoch,
    pub capella_fork_version: Version,
    pub deneb_fork_epoch: Epoch,
    pub deneb_fork_version: Version,
    pub electra_fork_epoch: Epoch,
    pub electra_fork_version: Version,
    pub fulu_fork_epoch: Epoch,
    pub fulu_fork_version: Version,
    pub gloas_fork_epoch: Epoch,
    pub gloas_fork_version: Version,
}

/// Error returned when parsing an unknown fork name string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseForkNameError;

impl fmt::Display for ParseForkNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unknown fork name")
    }
}

impl std::error::Error for ParseForkNameError {}

/// Error returned when converting an unknown numeric fork id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownForkIdError(pub u32);

impl fmt::Display for UnknownForkIdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown fork id: {}", self.0)
    }
}

impl std::error::Error for UnknownForkIdError {}

impl ForkSchedule {
    /// Schedule with every fork through Fulu active from epoch 0 and Gloas
    /// unscheduled (`u64::MAX`).
    ///
    /// Used when a caller has not yet injected a reconciled BN schedule:
    /// `ForkName::from_epoch` resolves Fulu for every practical epoch, so
    /// proposer-duties routing stays on v1 until Gloas is actually scheduled.
    pub fn unscheduled_gloas() -> Self {
        Self {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 0,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: 0,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: 0,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: 0,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: 0,
            fulu_fork_version: [6, 0, 0, 0],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [7, 0, 0, 0],
        }
    }

    /// Fork table in ascending fork order (Phase0 … Gloas).
    ///
    /// When several forks share an activation epoch, reverse iteration over this
    /// table selects the latest fork — matching the historical descending
    /// if-else chain (including keygen's EIP-7044 Capella-cap schedule).
    ///
    /// The per-fork field list stays here; `ForkSchedule` remains a flat struct
    /// and is not reshaped. Length is [`ForkName::COUNT`].
    pub fn entries(&self) -> [(ForkName, Epoch, Version); ForkName::COUNT] {
        [
            (ForkName::Phase0, 0, self.genesis_fork_version),
            (ForkName::Altair, self.altair_fork_epoch, self.altair_fork_version),
            (ForkName::Bellatrix, self.bellatrix_fork_epoch, self.bellatrix_fork_version),
            (ForkName::Capella, self.capella_fork_epoch, self.capella_fork_version),
            (ForkName::Deneb, self.deneb_fork_epoch, self.deneb_fork_version),
            (ForkName::Electra, self.electra_fork_epoch, self.electra_fork_version),
            (ForkName::Fulu, self.fulu_fork_epoch, self.fulu_fork_version),
            (ForkName::Gloas, self.gloas_fork_epoch, self.gloas_fork_version),
        ]
    }
}

impl AsRef<str> for ForkName {
    fn as_ref(&self) -> &str {
        Self::NAMES
            .iter()
            .find(|(name, _, _)| name == self)
            .map(|(_, s, _)| *s)
            .expect("all ForkName variants appear in NAMES")
    }
}

impl FromStr for ForkName {
    type Err = ParseForkNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::NAMES
            .iter()
            .find(|(_, name, _)| *name == s)
            .map(|(fork, _, _)| *fork)
            .ok_or(ParseForkNameError)
    }
}

impl TryFrom<u32> for ForkName {
    type Error = UnknownForkIdError;

    fn try_from(id: u32) -> Result<Self, Self::Error> {
        Self::NAMES
            .iter()
            .find(|(_, _, n)| *n == id)
            .map(|(fork, _, _)| *fork)
            .ok_or(UnknownForkIdError(id))
    }
}

impl ForkName {
    /// All fork variants in ascending order.
    pub const ALL: [Self; 8] = [
        Self::Phase0,
        Self::Altair,
        Self::Bellatrix,
        Self::Capella,
        Self::Deneb,
        Self::Electra,
        Self::Fulu,
        Self::Gloas,
    ];

    /// Number of known forks; equal to [`Self::ALL`] length.
    pub const COUNT: usize = Self::ALL.len();

    const NAMES: [(ForkName, &str, u32); Self::COUNT] = [
        (Self::Phase0, "phase0", 0),
        (Self::Altair, "altair", 1),
        (Self::Bellatrix, "bellatrix", 2),
        (Self::Capella, "capella", 3),
        (Self::Deneb, "deneb", 4),
        (Self::Electra, "electra", 5),
        (Self::Fulu, "fulu", 6),
        (Self::Gloas, "gloas", 7),
    ];

    /// Stable numeric id (PHASE0=0 … GLOAS=7), matching signer SSZ `fork_id`.
    ///
    /// Exhaustive `match self` with no `_ =>` arm: the fork-addition tripwire.
    pub fn id(self) -> u32 {
        match self {
            Self::Phase0 => 0,
            Self::Altair => 1,
            Self::Bellatrix => 2,
            Self::Capella => 3,
            Self::Deneb => 4,
            Self::Electra => 5,
            Self::Fulu => 6,
            Self::Gloas => 7,
        }
    }

    /// Body SSZ layout for KZG extraction, if the fork has blob commitments.
    ///
    /// Deneb → Deneb layout; Electra/Fulu → Electra layout; Gloas → Gloas
    /// (typed error; no decoder yet); pre-Deneb → `None`.
    /// [`crate::block::body_fork_layout`] delegates here after parsing the name.
    pub fn body_layout(self) -> Option<BodyForkLayout> {
        match self {
            Self::Deneb => Some(BodyForkLayout::Deneb),
            Self::Electra | Self::Fulu => Some(BodyForkLayout::Electra),
            Self::Gloas => Some(BodyForkLayout::Gloas),
            Self::Phase0 | Self::Altair | Self::Bellatrix | Self::Capella => None,
        }
    }

    /// Resolve the active fork at `epoch` from `schedule.entries()`.
    ///
    /// Scans the table in reverse so equal activation epochs pick the latest
    /// fork (same as the historical descending if-else).
    pub fn from_epoch(epoch: Epoch, schedule: &ForkSchedule) -> Self {
        schedule
            .entries()
            .into_iter()
            .rev()
            .find(|(_, activation, _)| *activation <= epoch)
            .map(|(name, _, _)| name)
            .expect("Phase0 activates at epoch 0; at least one entry always matches")
    }

    pub fn fork_version(&self, schedule: &ForkSchedule) -> Version {
        schedule
            .entries()
            .into_iter()
            .find(|(name, _, _)| name == self)
            .map(|(_, _, version)| version)
            .expect("all ForkName variants appear in entries()")
    }

    pub fn activation_epoch(&self, schedule: &ForkSchedule) -> Epoch {
        schedule
            .entries()
            .into_iter()
            .find(|(name, _, _)| name == self)
            .map(|(_, epoch, _)| epoch)
            .expect("all ForkName variants appear in entries()")
    }

    pub fn previous_fork(&self, schedule: &ForkSchedule) -> ForkName {
        let epoch = self.activation_epoch(schedule);
        if epoch == 0 {
            ForkName::Phase0
        } else {
            ForkName::from_epoch(epoch - 1, schedule)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::body_fork_layout;

    fn test_schedule() -> ForkSchedule {
        ForkSchedule {
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
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [7, 0, 0, 0],
        }
    }

    /// EIP-7044-style schedule used by rvc-keygen: pre-Capella at epoch 0,
    /// post-Capella at `u64::MAX`.
    fn exit_cap_schedule() -> ForkSchedule {
        ForkSchedule {
            genesis_fork_version: [0x00, 0x00, 0x00, 0x00],
            altair_fork_epoch: 0,
            altair_fork_version: [0x00, 0x00, 0x00, 0x00],
            bellatrix_fork_epoch: 0,
            bellatrix_fork_version: [0x00, 0x00, 0x00, 0x00],
            capella_fork_epoch: 0,
            capella_fork_version: [0x03, 0x00, 0x00, 0x00],
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

    #[test]
    fn test_fork_name_from_epoch_phase0() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(0, &schedule), ForkName::Phase0);
    }

    #[test]
    fn test_unscheduled_gloas_is_fulu_until_sentinel() {
        let schedule = ForkSchedule::unscheduled_gloas();
        assert_eq!(ForkName::from_epoch(0, &schedule), ForkName::Fulu);
        assert_eq!(ForkName::from_epoch(u64::MAX - 1, &schedule), ForkName::Fulu);
        assert_eq!(ForkName::from_epoch(u64::MAX, &schedule), ForkName::Gloas);
    }

    #[test]
    fn test_fork_name_from_epoch_altair_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(74239, &schedule), ForkName::Phase0);
        assert_eq!(ForkName::from_epoch(74240, &schedule), ForkName::Altair);
    }

    #[test]
    fn test_fork_name_from_epoch_bellatrix_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(144895, &schedule), ForkName::Altair);
        assert_eq!(ForkName::from_epoch(144896, &schedule), ForkName::Bellatrix);
    }

    #[test]
    fn test_fork_name_from_epoch_capella_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(194047, &schedule), ForkName::Bellatrix);
        assert_eq!(ForkName::from_epoch(194048, &schedule), ForkName::Capella);
    }

    #[test]
    fn test_fork_name_from_epoch_deneb_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(269567, &schedule), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(269568, &schedule), ForkName::Deneb);
    }

    #[test]
    fn test_fork_name_from_epoch_electra_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(364543, &schedule), ForkName::Deneb);
        assert_eq!(ForkName::from_epoch(364544, &schedule), ForkName::Electra);
    }

    #[test]
    fn test_fork_name_from_epoch_far_future() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(u64::MAX, &schedule), ForkName::Gloas);
    }

    #[test]
    fn test_fork_name_from_epoch_unscheduled_forks() {
        let schedule = ForkSchedule {
            genesis_fork_version: [0, 0, 0, 0],
            altair_fork_epoch: 10,
            altair_fork_version: [1, 0, 0, 0],
            bellatrix_fork_epoch: u64::MAX,
            bellatrix_fork_version: [2, 0, 0, 0],
            capella_fork_epoch: u64::MAX,
            capella_fork_version: [3, 0, 0, 0],
            deneb_fork_epoch: u64::MAX,
            deneb_fork_version: [4, 0, 0, 0],
            electra_fork_epoch: u64::MAX,
            electra_fork_version: [5, 0, 0, 0],
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [6, 0, 0, 0],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [7, 0, 0, 0],
        };
        assert_eq!(ForkName::from_epoch(0, &schedule), ForkName::Phase0);
        assert_eq!(ForkName::from_epoch(10, &schedule), ForkName::Altair);
        assert_eq!(ForkName::from_epoch(1_000_000, &schedule), ForkName::Altair);
    }

    #[test]
    fn test_fork_version_phase0() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Phase0.fork_version(&schedule), [0, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_altair() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Altair.fork_version(&schedule), [1, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_bellatrix() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Bellatrix.fork_version(&schedule), [2, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_capella() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Capella.fork_version(&schedule), [3, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_deneb() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Deneb.fork_version(&schedule), [4, 0, 0, 0]);
    }

    #[test]
    fn test_fork_version_electra() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Electra.fork_version(&schedule), [5, 0, 0, 0]);
    }

    #[test]
    fn test_fork_name_as_ref() {
        assert_eq!(ForkName::Phase0.as_ref(), "phase0");
        assert_eq!(ForkName::Altair.as_ref(), "altair");
        assert_eq!(ForkName::Bellatrix.as_ref(), "bellatrix");
        assert_eq!(ForkName::Capella.as_ref(), "capella");
        assert_eq!(ForkName::Deneb.as_ref(), "deneb");
        assert_eq!(ForkName::Electra.as_ref(), "electra");
        assert_eq!(ForkName::Gloas.as_ref(), "gloas");
    }

    #[test]
    fn test_fork_name_ordering() {
        assert!(ForkName::Phase0 < ForkName::Altair);
        assert!(ForkName::Altair < ForkName::Bellatrix);
        assert!(ForkName::Bellatrix < ForkName::Capella);
        assert!(ForkName::Capella < ForkName::Deneb);
        assert!(ForkName::Deneb < ForkName::Electra);
    }

    #[test]
    fn test_fork_name_equality() {
        assert_eq!(ForkName::Phase0, ForkName::Phase0);
        assert_ne!(ForkName::Phase0, ForkName::Altair);
    }

    #[test]
    fn test_fork_name_from_epoch_fulu_boundary() {
        let schedule = test_schedule();
        assert_eq!(ForkName::from_epoch(499999, &schedule), ForkName::Electra);
        assert_eq!(ForkName::from_epoch(500000, &schedule), ForkName::Fulu);
    }

    #[test]
    fn test_fork_version_fulu() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Fulu.fork_version(&schedule), [6, 0, 0, 0]);
    }

    #[test]
    fn test_fork_name_as_ref_fulu() {
        assert_eq!(ForkName::Fulu.as_ref(), "fulu");
    }

    #[test]
    fn test_fork_name_ordering_fulu() {
        assert!(ForkName::Electra < ForkName::Fulu);
        assert!(ForkName::Fulu < ForkName::Gloas);
    }

    #[test]
    fn test_fork_name_from_epoch_unscheduled_fulu() {
        let schedule = ForkSchedule {
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
            fulu_fork_epoch: u64::MAX,
            fulu_fork_version: [6, 0, 0, 0],
            gloas_fork_epoch: u64::MAX,
            gloas_fork_version: [7, 0, 0, 0],
        };
        assert_eq!(ForkName::from_epoch(1_000_000, &schedule), ForkName::Electra);
    }

    #[test]
    fn test_activation_epoch_all_forks() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Phase0.activation_epoch(&schedule), 0);
        assert_eq!(ForkName::Altair.activation_epoch(&schedule), 74240);
        assert_eq!(ForkName::Bellatrix.activation_epoch(&schedule), 144896);
        assert_eq!(ForkName::Capella.activation_epoch(&schedule), 194048);
        assert_eq!(ForkName::Deneb.activation_epoch(&schedule), 269568);
        assert_eq!(ForkName::Electra.activation_epoch(&schedule), 364544);
        assert_eq!(ForkName::Fulu.activation_epoch(&schedule), 500000);
        assert_eq!(ForkName::Gloas.activation_epoch(&schedule), u64::MAX);
    }

    #[test]
    fn test_previous_fork_fulu() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Fulu.previous_fork(&schedule), ForkName::Electra);
    }

    #[test]
    fn test_previous_fork_electra() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Electra.previous_fork(&schedule), ForkName::Deneb);
    }

    #[test]
    fn test_previous_fork_phase0() {
        let schedule = test_schedule();
        assert_eq!(ForkName::Phase0.previous_fork(&schedule), ForkName::Phase0);
    }

    #[test]
    fn test_previous_fork_same_epoch() {
        let mut schedule = test_schedule();
        schedule.altair_fork_epoch = 0;
        assert_eq!(ForkName::Altair.previous_fork(&schedule), ForkName::Phase0);
    }

    /// Pin boundary behaviour of the entries()-backed lookup for a realistic
    /// mainnet-like schedule and the keygen Capella-cap degenerate schedule.
    #[test]
    fn test_from_epoch_table_matches_legacy_if_else_for_every_boundary() {
        let schedule = test_schedule();
        let boundaries = [
            (0u64, ForkName::Phase0),
            (74239, ForkName::Phase0),
            (74240, ForkName::Altair),
            (144895, ForkName::Altair),
            (144896, ForkName::Bellatrix),
            (194047, ForkName::Bellatrix),
            (194048, ForkName::Capella),
            (269567, ForkName::Capella),
            (269568, ForkName::Deneb),
            (364543, ForkName::Deneb),
            (364544, ForkName::Electra),
            (499999, ForkName::Electra),
            (500000, ForkName::Fulu),
            (u64::MAX - 1, ForkName::Fulu),
            (u64::MAX, ForkName::Gloas),
        ];
        for (epoch, expected) in boundaries {
            assert_eq!(ForkName::from_epoch(epoch, &schedule), expected, "epoch {epoch}");
        }

        // Degenerate: several forks at epoch 0, post-Capella at MAX — latest wins.
        let cap = exit_cap_schedule();
        assert_eq!(ForkName::from_epoch(0, &cap), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(1, &cap), ForkName::Capella);
        assert_eq!(ForkName::from_epoch(u64::MAX - 1, &cap), ForkName::Capella);
        // At u64::MAX every post-Capella entry activates; reverse scan picks Gloas.
        assert_eq!(ForkName::from_epoch(u64::MAX, &cap), ForkName::Gloas);
    }

    #[test]
    fn test_fork_name_str_roundtrip_all_variants() {
        for name in ForkName::ALL {
            assert_eq!(ForkName::from_str(name.as_ref()), Ok(name));
        }
        assert!(ForkName::from_str("Deneb").is_err());
        assert!(ForkName::from_str("").is_err());
        assert!(ForkName::from_str("electra ").is_err());
    }

    #[test]
    fn test_fork_name_id_roundtrip_all_variants() {
        for name in ForkName::ALL {
            assert_eq!(ForkName::try_from(name.id()), Ok(name));
        }
    }

    #[test]
    fn test_fork_name_gloas_identity() {
        assert_eq!(ForkName::from_str("gloas"), Ok(ForkName::Gloas));
        assert_eq!(ForkName::try_from(7u32), Ok(ForkName::Gloas));
        assert_eq!(ForkName::Gloas.id(), 7);
        assert!(ForkName::Fulu < ForkName::Gloas);
        assert_eq!(ForkName::COUNT, 8);
        assert_eq!(ForkName::ALL.len(), 8);
        assert_eq!(ForkName::try_from(8u32), Err(UnknownForkIdError(8)));
        assert!(ForkName::try_from(u32::MAX).is_err());
    }

    #[test]
    fn test_body_layout_matches_body_fork_layout_string_mapping() {
        for s in ["phase0", "altair", "bellatrix", "capella", "deneb", "electra", "fulu", "gloas"] {
            let name = ForkName::from_str(s).unwrap();
            assert_eq!(name.body_layout(), body_fork_layout(s), "layout mismatch for {s}");
        }
        assert_eq!(ForkName::Phase0.body_layout(), None);
        assert_eq!(ForkName::Deneb.body_layout(), Some(BodyForkLayout::Deneb));
        assert_eq!(ForkName::Electra.body_layout(), Some(BodyForkLayout::Electra));
        assert_eq!(ForkName::Fulu.body_layout(), Some(BodyForkLayout::Electra));
        assert_eq!(ForkName::Gloas.body_layout(), Some(BodyForkLayout::Gloas));
    }

    #[test]
    fn test_fork_version_and_activation_epoch_unchanged_for_all_eight() {
        let schedule = test_schedule();
        let expected = [
            (ForkName::Phase0, 0u64, [0u8, 0, 0, 0]),
            (ForkName::Altair, 74240, [1, 0, 0, 0]),
            (ForkName::Bellatrix, 144896, [2, 0, 0, 0]),
            (ForkName::Capella, 194048, [3, 0, 0, 0]),
            (ForkName::Deneb, 269568, [4, 0, 0, 0]),
            (ForkName::Electra, 364544, [5, 0, 0, 0]),
            (ForkName::Fulu, 500000, [6, 0, 0, 0]),
            (ForkName::Gloas, u64::MAX, [7, 0, 0, 0]),
        ];
        for (name, epoch, version) in expected {
            assert_eq!(name.activation_epoch(&schedule), epoch);
            assert_eq!(name.fork_version(&schedule), version);
        }

        let entries = schedule.entries();
        assert_eq!(entries.len(), 8);
        assert_eq!(entries.len(), ForkName::COUNT);
        for (i, (name, epoch, version)) in expected.into_iter().enumerate() {
            assert_eq!(entries[i], (name, epoch, version));
        }
    }

    /// Every `ForkName::ALL` variant appears exactly once in `entries()`, and
    /// `entries().len() == ForkName::COUNT`.
    ///
    /// `ForkName::id` is the deliberate fork-addition tripwire: an exhaustive
    /// `match self` with no `_ =>` arm, so adding a variant without updating
    /// `id()` (and `ALL`) is a compile error.
    #[test]
    fn test_entries_contains_each_all_variant_exactly_once() {
        let schedule = test_schedule();
        let entries = schedule.entries();
        assert_eq!(entries.len(), ForkName::COUNT);
        for name in ForkName::ALL {
            let count = entries.iter().filter(|(n, _, _)| *n == name).count();
            assert_eq!(count, 1, "{name:?} must appear exactly once in entries()");
        }
    }
}
