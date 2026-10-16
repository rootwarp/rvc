//! A key reaches Safe only after `monitoring_epochs + 1` closed not-live epochs
//! at or after `next_check`. One tick is the previous epoch and the current
//! epoch together. Any live answer at or after `next_check` is Detected before
//! a decrement. The model below is that spec: it does not follow the machine's
//! statement order, and a tick that applied the previous epoch before looking
//! at the current one would disagree with it.

use std::sync::Arc;

use proptest::prelude::*;
use rvc_doppelganger::{
    EpochLiveness, ForwardWindowMachine, ForwardWindowStatus, SigningEnablement,
    ValidatorLivenessData, CLOSED_EPOCH_SLOT, DEFAULT_MONITORING_EPOCHS,
};

use crypto::SecretKey;
use eth_types::Root;

const PROPTEST_CASES: u32 = 64;

struct NoPriorAttestation;

impl slashing::SlashingDbReader for NoPriorAttestation {
    fn last_signed_attestation(&self, _pubkey: &str, _gvr: &Root) -> Option<slashing::TargetEpoch> {
        None
    }
}

fn pubkey() -> crypto::PublicKey {
    static PK: std::sync::OnceLock<crypto::PublicKey> = std::sync::OnceLock::new();
    PK.get_or_init(|| SecretKey::generate().public_key()).clone()
}

#[derive(Debug, Clone)]
enum Kind {
    AnsweredNotLive,
    AnsweredLive,
    Failed,
    NoIndex,
}

#[derive(Debug, Clone)]
struct Tick {
    /// Current epoch, relative to boot registration.
    current_offset: u8,
    previous: Kind,
    current: Kind,
    /// Slot of the current epoch at which both answers are applied.
    slot: u8,
}

fn kind_strategy() -> impl Strategy<Value = Kind> {
    prop_oneof![
        Just(Kind::AnsweredNotLive),
        Just(Kind::AnsweredLive),
        Just(Kind::Failed),
        Just(Kind::NoIndex),
    ]
}

fn tick_strategy() -> impl Strategy<Value = Tick> {
    (0u8..12, kind_strategy(), kind_strategy(), 0u8..32).prop_map(
        |(current_offset, previous, current, slot)| Tick {
            current_offset,
            previous,
            current,
            slot,
        },
    )
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ModelStatus {
    Pending,
    Safe,
    Detected,
}

struct Model {
    next_check: u64,
    remaining: u64,
    status: ModelStatus,
}

impl Model {
    fn new(start: u64) -> Self {
        Self {
            next_check: start,
            remaining: DEFAULT_MONITORING_EPOCHS + 1,
            status: ModelStatus::Pending,
        }
    }

    /// Live anywhere in the tick is decided before a count is removed.
    fn apply_tick(
        &mut self,
        previous_epoch: u64,
        previous: &Kind,
        current_epoch: u64,
        current: &Kind,
        slot: u64,
    ) {
        if self.status != ModelStatus::Pending {
            return;
        }
        let due_live = [(previous_epoch, previous), (current_epoch, current)]
            .into_iter()
            .any(|(epoch, kind)| epoch >= self.next_check && matches!(kind, Kind::AnsweredLive));
        if due_live {
            self.status = ModelStatus::Detected;
            return;
        }

        let previous_counts = slot >= CLOSED_EPOCH_SLOT
            && previous_epoch >= self.next_check
            && matches!(previous, Kind::AnsweredNotLive);
        if !previous_counts {
            return;
        }
        let current_not_live =
            current_epoch >= self.next_check && matches!(current, Kind::AnsweredNotLive);
        if self.remaining == 1 && !current_not_live {
            return;
        }
        self.remaining = self.remaining.saturating_sub(1);
        self.next_check = previous_epoch.saturating_add(1);
        if self.remaining == 0 {
            self.status = ModelStatus::Safe;
        }
    }
}

fn samples(kind: &Kind, hex: &str) -> Option<Vec<ValidatorLivenessData>> {
    match kind {
        Kind::AnsweredNotLive => {
            Some(vec![ValidatorLivenessData { index: hex.to_string(), is_live: false }])
        }
        Kind::AnsweredLive => {
            Some(vec![ValidatorLivenessData { index: hex.to_string(), is_live: true }])
        }
        Kind::Failed => None,
        Kind::NoIndex => {
            Some(vec![ValidatorLivenessData { index: "other".to_string(), is_live: false }])
        }
    }
}

fn machine() -> ForwardWindowMachine {
    let reader: Arc<dyn slashing::SlashingDbReader> = Arc::new(NoPriorAttestation);
    ForwardWindowMachine::new(reader, DEFAULT_MONITORING_EPOCHS, [0xab; 32])
}

proptest! {
    #![proptest_config(ProptestConfig { cases: PROPTEST_CASES, ..ProptestConfig::default() })]

    #[test]
    fn safe_only_after_three_closed_not_live_epochs(steps in proptest::collection::vec(tick_strategy(), 0..24)) {
        const START: u64 = 50;
        let machine = machine();
        let pubkey = pubkey();
        let hex = hex::encode(pubkey.to_bytes());
        machine.register(&pubkey, START);
        let mut model = Model::new(START);

        for step in steps {
            let current_epoch = START + u64::from(step.current_offset);
            let previous_epoch = current_epoch - 1;
            let slot = u64::from(step.slot);
            let answers = [
                EpochLiveness { epoch: previous_epoch, samples: samples(&step.previous, &hex) },
                EpochLiveness { epoch: current_epoch, samples: samples(&step.current, &hex) },
            ];
            let _ = machine.apply_liveness_tick(&answers, current_epoch, slot);
            model.apply_tick(previous_epoch, &step.previous, current_epoch, &step.current, slot);

            let status = machine.status(&pubkey);
            match model.status {
                ModelStatus::Pending => {
                    prop_assert_eq!(status, ForwardWindowStatus::Pending);
                    prop_assert!(!machine.is_signing_enabled(&pubkey));
                }
                ModelStatus::Safe => {
                    prop_assert_eq!(status, ForwardWindowStatus::Safe);
                    prop_assert!(machine.is_signing_enabled(&pubkey));
                }
                ModelStatus::Detected => {
                    prop_assert_eq!(status, ForwardWindowStatus::Detected);
                    prop_assert!(!machine.is_signing_enabled(&pubkey));
                }
            }
        }
    }
}
