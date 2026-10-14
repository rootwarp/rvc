//! Pure EIP-3076 Conditions 1–5, transcribed from the EIP text.
//!
//! Does not call interchange import, `rules.rs`, or any rs-vc checker.
//! rs-vc's importer raises watermarks to the file maxima, so a round trip
//! through it cannot see a weakened minimum.

use rvc_slashing::{InterchangeAttestation, InterchangeBlock, InterchangeFormat};

/// A signing candidate with a fresh root in the export tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Candidate {
    Attestation { source_epoch: u64, target_epoch: u64, signing_root: Option<String> },
    Block { slot: u64, signing_root: Option<String> },
}

#[derive(Debug, Clone)]
struct ParsedAtt {
    source: u64,
    target: u64,
    signing_root: Option<String>,
}

#[derive(Debug, Clone)]
struct ParsedBlock {
    slot: u64,
    signing_root: Option<String>,
}

/// `true` when an EIP-3076 importer of `file` must refuse `candidate` for `pubkey`.
pub fn refuses(file: &InterchangeFormat, pubkey: &str, candidate: &Candidate) -> bool {
    let Some((blocks, atts)) = history(file, pubkey) else {
        return true;
    };
    match candidate {
        Candidate::Block { slot, signing_root } => refuses_block(&blocks, *slot, signing_root),
        Candidate::Attestation { source_epoch, target_epoch, signing_root } => {
            refuses_attestation(&atts, *source_epoch, *target_epoch, signing_root)
        }
    }
}

/// Condition 3 between two interchange attestations (both surround directions).
pub fn slashable_attestation_pair(
    left: &InterchangeAttestation,
    right: &InterchangeAttestation,
) -> bool {
    let (Ok(left_source), Ok(left_target), Ok(right_source), Ok(right_target)) = (
        left.source_epoch.parse::<u64>(),
        left.target_epoch.parse::<u64>(),
        right.source_epoch.parse::<u64>(),
        right.target_epoch.parse::<u64>(),
    ) else {
        return true;
    };
    attestation_slashable(
        left_source,
        left_target,
        left.signing_root.as_deref(),
        right_source,
        right_target,
        right.signing_root.as_deref(),
    )
}

/// Condition 1 between two interchange blocks that share a slot.
pub fn same_slot_is_double_proposal(left: &InterchangeBlock, right: &InterchangeBlock) -> bool {
    left.slot == right.slot
        && !matches!(
            (&left.signing_root, &right.signing_root),
            (Some(existing), Some(new)) if existing == new
        )
}

fn history(file: &InterchangeFormat, pubkey: &str) -> Option<(Vec<ParsedBlock>, Vec<ParsedAtt>)> {
    let mut blocks = Vec::new();
    let mut atts = Vec::new();
    for record in &file.data {
        if record.pubkey != pubkey {
            continue;
        }
        for block in &record.signed_blocks {
            blocks.push(ParsedBlock {
                slot: block.slot.parse().ok()?,
                signing_root: block.signing_root.clone(),
            });
        }
        for att in &record.signed_attestations {
            atts.push(ParsedAtt {
                source: att.source_epoch.parse().ok()?,
                target: att.target_epoch.parse().ok()?,
                signing_root: att.signing_root.clone(),
            });
        }
    }
    Some((blocks, atts))
}

fn refuses_block(blocks: &[ParsedBlock], slot: u64, signing_root: &Option<String>) -> bool {
    if blocks.is_empty() {
        return false;
    }
    // Condition 1. An imported block with no signing root makes every new
    // block at that slot slashable.
    for block in blocks {
        if block.slot != slot {
            continue;
        }
        match (&block.signing_root, signing_root) {
            (Some(existing), Some(new)) if existing == new => {}
            _ => return true,
        }
    }
    // Condition 2, except a repeat determined by the signing root.
    let min_slot = blocks.iter().map(|block| block.slot).min().expect("non-empty");
    if slot <= min_slot && !repeat_block(blocks, slot, signing_root) {
        return true;
    }
    false
}

fn repeat_block(blocks: &[ParsedBlock], slot: u64, signing_root: &Option<String>) -> bool {
    let Some(root) = signing_root else {
        return false;
    };
    blocks.iter().any(|block| block.slot == slot && block.signing_root.as_ref() == Some(root))
}

fn refuses_attestation(
    atts: &[ParsedAtt],
    source: u64,
    target: u64,
    signing_root: &Option<String>,
) -> bool {
    if atts.is_empty() {
        return false;
    }
    let min_source = atts.iter().map(|att| att.source).min().expect("non-empty");
    let min_target = atts.iter().map(|att| att.target).min().expect("non-empty");
    // Condition 4. No repeat exception in the EIP text.
    if source < min_source {
        return true;
    }
    // Condition 5, except a repeat determined by the signing root.
    if target <= min_target && !repeat_attestation(atts, source, target, signing_root) {
        return true;
    }
    // Condition 3.
    for att in atts {
        if attestation_slashable(
            source,
            target,
            signing_root.as_deref(),
            att.source,
            att.target,
            att.signing_root.as_deref(),
        ) {
            return true;
        }
    }
    false
}

fn repeat_attestation(
    atts: &[ParsedAtt],
    source: u64,
    target: u64,
    signing_root: &Option<String>,
) -> bool {
    let Some(root) = signing_root else {
        return false;
    };
    atts.iter().any(|att| {
        att.source == source && att.target == target && att.signing_root.as_ref() == Some(root)
    })
}

/// `is_slashable_attestation_data` in both orders. Equal signing roots are one message.
fn attestation_slashable(
    left_source: u64,
    left_target: u64,
    left_root: Option<&str>,
    right_source: u64,
    right_target: u64,
    right_root: Option<&str>,
) -> bool {
    if let (Some(left), Some(right)) = (left_root, right_root) {
        if left == right {
            return false;
        }
    }
    if left_target == right_target {
        return true;
    }
    surrounds(left_source, left_target, right_source, right_target)
        || surrounds(right_source, right_target, left_source, left_target)
}

fn surrounds(source: u64, target: u64, other_source: u64, other_target: u64) -> bool {
    source < other_source && other_target < target
}
