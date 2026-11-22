//! Parent-header lookup that two beacon nodes must confirm.
//!
//! The header root check proves only that a header is self-consistent. One
//! beacon node can return a header that is not on the canonical chain. When
//! two or more nodes are asked, a header can narrow or close the parent set
//! only when two of them return the same header. A 404 also needs two votes
//! and no header from another node, so one node cannot skip a real parent.
//! When only one node is asked, its answer decides.

use beacon::{BeaconError, BlockHeaderSummary};
use eth_types::Slot;

/// Agreeing answers needed when two or more beacon nodes are asked.
const HEADER_QUORUM: usize = 2;

/// Answer of a parent-header lookup for a proposal slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckedHeader {
    /// The header slot is the requested slot and is before the proposal slot.
    Found(BlockHeaderSummary),
    /// No block at the requested slot (HTTP 404).
    NotFound,
    /// The header cannot be a parent. Its slot is not the requested slot, or
    /// it is at or after the proposal slot.
    Rejected(BlockHeaderSummary),
    /// The beacon nodes answered, but no two answers agreed.
    Unconfirmed,
}

impl CheckedHeader {
    /// Checks one header against `block_id` and `proposal_slot`.
    ///
    /// A decimal `block_id` must equal the header slot. Every header must be
    /// before `proposal_slot`.
    ///
    /// ```
    /// use beacon::BlockHeaderSummary;
    /// use rvc_bn_manager::CheckedHeader;
    ///
    /// let header = BlockHeaderSummary { root: [1; 32], slot: 9, proposer_index: 0, parent_root: [2; 32] };
    /// assert_eq!(CheckedHeader::check("9", 10, header), CheckedHeader::Found(header));
    /// assert_eq!(CheckedHeader::check("8", 10, header), CheckedHeader::Rejected(header));
    /// ```
    pub fn check(block_id: &str, proposal_slot: Slot, header: BlockHeaderSummary) -> Self {
        let requested = decimal_slot_id(block_id).is_none_or(|slot| header.slot == slot);
        if requested && header.slot < proposal_slot {
            Self::Found(header)
        } else {
            Self::Rejected(header)
        }
    }

    /// One beacon node decides. A 404 is [`Self::NotFound`]. Another error stays an error.
    pub fn from_single(
        block_id: &str,
        proposal_slot: Slot,
        answer: Result<BlockHeaderSummary, BeaconError>,
    ) -> Result<Self, BeaconError> {
        let mut tally = HeaderTally::new(block_id, proposal_slot, 1);
        match tally.add(0, answer) {
            Some(checked) => Ok(checked),
            None => tally.finish(),
        }
    }
}

fn decimal_slot_id(block_id: &str) -> Option<Slot> {
    if block_id.is_empty() || !block_id.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    block_id.parse().ok()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Vote {
    NotFound,
    Header(BlockHeaderSummary),
}

/// Answers of one lookup, one for each beacon node that was asked.
///
/// Two headers with the same root decide at once. A 404 is a vote that the
/// slot is empty, but [`CheckedHeader::NotFound`] needs a quorum of 404s, no
/// header vote, and no node with an unknown answer. It is decided only by
/// [`Self::finish`]. A node that returned an error other than a 404, or that
/// did not answer in time, can still have the block. Thus that node blocks
/// `NotFound`. A revoked node does not.
pub(crate) struct HeaderTally<'a> {
    block_id: &'a str,
    proposal_slot: Slot,
    quorum: usize,
    votes: Vec<(Vote, usize)>,
    /// Error of the lowest node index. A revoke is kept only when no other error exists.
    error: Option<(usize, BeaconError)>,
    /// One or more nodes gave an error that is not a 404 or a revoke.
    unknown: bool,
}

impl<'a> HeaderTally<'a> {
    /// `asked` is the number of beacon nodes that got the request.
    pub(crate) fn new(block_id: &'a str, proposal_slot: Slot, asked: usize) -> Self {
        Self {
            block_id,
            proposal_slot,
            quorum: asked.clamp(1, HEADER_QUORUM),
            votes: Vec::new(),
            error: None,
            unknown: false,
        }
    }

    /// Adds the answer of the node at `index`. Returns the result when
    /// enough headers agree.
    ///
    /// A header is a vote for that header, and a 404 is a vote for
    /// [`CheckedHeader::NotFound`]. Another error is not a vote.
    pub(crate) fn add(
        &mut self,
        index: usize,
        answer: Result<BlockHeaderSummary, BeaconError>,
    ) -> Option<CheckedHeader> {
        let vote = match answer {
            Ok(header) => Vote::Header(header),
            Err(BeaconError::ApiError { status: 404, .. }) => Vote::NotFound,
            Err(err) => {
                self.keep_error(index, err);
                return None;
            }
        };
        let count = match self.votes.iter_mut().find(|(seen, _)| *seen == vote) {
            Some((_, count)) => {
                *count += 1;
                *count
            }
            None => {
                self.votes.push((vote, 1));
                1
            }
        };
        match vote {
            Vote::Header(header) if count >= self.quorum => {
                Some(CheckedHeader::check(self.block_id, self.proposal_slot, header))
            }
            _ => None,
        }
    }

    fn keep_error(&mut self, index: usize, err: BeaconError) {
        self.unknown |= !matches!(err, BeaconError::RevokedInFlight);
        let revoke = |err: &BeaconError| matches!(err, BeaconError::RevokedInFlight);
        let replace = match &self.error {
            None => true,
            Some((kept_index, kept)) => match (revoke(kept), revoke(&err)) {
                (true, false) => true,
                (false, true) => false,
                _ => index < *kept_index,
            },
        };
        if replace {
            self.error = Some((index, err));
        }
    }

    /// `true` when a quorum of nodes returned 404 and no node has an unknown answer.
    pub(crate) fn not_found_quorum(&self) -> bool {
        let not_found = self
            .votes
            .iter()
            .find_map(|(vote, count)| (*vote == Vote::NotFound).then_some(*count))
            .unwrap_or(0);
        not_found >= self.quorum && !self.unknown
    }

    /// Result after the last answer. The caller adds a timeout error for each
    /// node that is silent at the time limit, so that node is unknown.
    ///
    /// [`Self::not_found_quorum`] and no header vote is [`CheckedHeader::NotFound`].
    /// Another set of votes is [`CheckedHeader::Unconfirmed`]. With no vote,
    /// the error of the lowest node index is returned. A revoke is returned
    /// only when no other error exists.
    pub(crate) fn finish(self) -> Result<CheckedHeader, BeaconError> {
        let headers = self.votes.iter().any(|(vote, _)| matches!(vote, Vote::Header(_)));
        if !headers && self.not_found_quorum() {
            return Ok(CheckedHeader::NotFound);
        }
        if !self.votes.is_empty() {
            return Ok(CheckedHeader::Unconfirmed);
        }
        Err(self.error.map_or(BeaconError::RevokedInFlight, |(_, err)| err))
    }
}

/// `true` when `block_id` is a slot and `header` is at another slot. Such a
/// header is wrong, whatever the other beacon nodes answer.
pub(crate) fn wrong_requested_slot(block_id: &str, header: &BlockHeaderSummary) -> bool {
    decimal_slot_id(block_id).is_some_and(|slot| slot != header.slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROPOSAL: Slot = 100;

    fn header(slot: Slot, root: u8) -> BlockHeaderSummary {
        BlockHeaderSummary { root: [root; 32], slot, proposer_index: 1, parent_root: [0x22; 32] }
    }

    fn not_found() -> BeaconError {
        BeaconError::ApiError { status: 404, message: "missing".to_string() }
    }

    fn silent() -> BeaconError {
        BeaconError::OperationTimeout {
            operation: "get_block_header".to_string(),
            timeout: std::time::Duration::from_millis(150),
        }
    }

    #[test]
    fn silent_nodes_alone_give_a_timeout_error() {
        let err = tally_of("99", 2, vec![Err(silent()), Err(silent())]).unwrap_err();
        assert!(matches!(err, BeaconError::OperationTimeout { .. }), "{err:?}");
    }

    fn server_error() -> BeaconError {
        BeaconError::ApiError { status: 500, message: "down".to_string() }
    }

    fn tally_of(
        block_id: &str,
        asked: usize,
        answers: Vec<Result<BlockHeaderSummary, BeaconError>>,
    ) -> Result<CheckedHeader, BeaconError> {
        let mut tally = HeaderTally::new(block_id, PROPOSAL, asked);
        for (index, answer) in answers.into_iter().enumerate() {
            if let Some(checked) = tally.add(index, answer) {
                return Ok(checked);
            }
        }
        tally.finish()
    }

    #[test]
    fn check_accepts_the_requested_slot_before_the_proposal() {
        let found = header(99, 1);
        assert_eq!(CheckedHeader::check("99", PROPOSAL, found), CheckedHeader::Found(found));
        let head = header(97, 1);
        assert_eq!(CheckedHeader::check("head", PROPOSAL, head), CheckedHeader::Found(head));
    }

    #[test]
    fn check_rejects_a_wrong_slot_and_a_head_at_or_after_the_proposal() {
        let wrong = header(95, 1);
        assert_eq!(CheckedHeader::check("99", PROPOSAL, wrong), CheckedHeader::Rejected(wrong));
        for slot in [PROPOSAL, PROPOSAL + 1] {
            let late = header(slot, 1);
            assert_eq!(CheckedHeader::check("head", PROPOSAL, late), CheckedHeader::Rejected(late));
        }
    }

    #[test]
    fn single_node_answer_decides() {
        let found = header(99, 1);
        assert_eq!(tally_of("99", 1, vec![Ok(found)]).unwrap(), CheckedHeader::Found(found));
        assert_eq!(tally_of("99", 1, vec![Err(not_found())]).unwrap(), CheckedHeader::NotFound);
        let wrong = header(90, 1);
        assert_eq!(tally_of("99", 1, vec![Ok(wrong)]).unwrap(), CheckedHeader::Rejected(wrong));
        let err = tally_of("99", 1, vec![Err(server_error())]).unwrap_err();
        assert!(matches!(err, BeaconError::ApiError { status: 500, .. }), "{err:?}");
    }

    #[test]
    fn from_single_matches_the_tally_of_one_node() {
        let found = header(99, 1);
        assert_eq!(
            CheckedHeader::from_single("99", PROPOSAL, Ok(found)).unwrap(),
            CheckedHeader::Found(found)
        );
        assert_eq!(
            CheckedHeader::from_single("99", PROPOSAL, Err(not_found())).unwrap(),
            CheckedHeader::NotFound
        );
        let err = CheckedHeader::from_single("99", PROPOSAL, Err(server_error())).unwrap_err();
        assert!(matches!(err, BeaconError::ApiError { status: 500, .. }), "{err:?}");
    }

    #[test]
    fn two_nodes_must_return_the_same_header() {
        let honest = header(99, 1);
        let fabricated = header(99, 2);
        assert_eq!(
            tally_of("99", 2, vec![Ok(fabricated), Ok(honest)]).unwrap(),
            CheckedHeader::Unconfirmed
        );
        assert_eq!(
            tally_of("99", 3, vec![Ok(fabricated), Ok(honest), Ok(honest)]).unwrap(),
            CheckedHeader::Found(honest)
        );
    }

    #[test]
    fn one_wrong_slot_header_does_not_close_the_set() {
        let wrong = header(90, 1);
        let honest = header(99, 2);
        assert_eq!(
            tally_of("99", 2, vec![Ok(wrong), Ok(honest)]).unwrap(),
            CheckedHeader::Unconfirmed
        );
        assert_eq!(
            tally_of("99", 3, vec![Ok(wrong), Ok(honest), Ok(honest)]).unwrap(),
            CheckedHeader::Found(honest)
        );
        assert_eq!(
            tally_of("99", 2, vec![Ok(wrong), Ok(wrong)]).unwrap(),
            CheckedHeader::Rejected(wrong)
        );
    }

    #[test]
    fn one_404_does_not_skip_a_header_from_another_node() {
        let honest = header(99, 1);
        assert_eq!(
            tally_of("99", 2, vec![Err(not_found()), Ok(honest)]).unwrap(),
            CheckedHeader::Unconfirmed
        );
        assert_eq!(
            tally_of("99", 2, vec![Err(not_found()), Err(not_found())]).unwrap(),
            CheckedHeader::NotFound
        );
        assert_eq!(
            tally_of("99", 2, vec![Err(not_found()), Err(server_error())]).unwrap(),
            CheckedHeader::Unconfirmed
        );
    }

    /// Two lagging nodes return 404 before a third node returns the block.
    /// One header against two 404s is a disagreement, so the walk must not
    /// skip that slot. One node does not decide the parent either.
    #[test]
    fn two_404s_do_not_skip_a_header_from_a_third_node() {
        let block = header(99, 1);
        assert_eq!(
            tally_of("99", 3, vec![Err(not_found()), Err(not_found()), Ok(block)]).unwrap(),
            CheckedHeader::Unconfirmed
        );
        assert_eq!(
            tally_of("99", 3, vec![Err(not_found()), Err(not_found()), Err(silent())]).unwrap(),
            CheckedHeader::Unconfirmed,
            "a silent third node can still have the block"
        );
        assert_eq!(
            tally_of("99", 3, vec![Err(not_found()), Err(not_found()), Err(server_error())])
                .unwrap(),
            CheckedHeader::Unconfirmed,
            "a node that errors can still have the block"
        );
        let optimistic = BeaconError::ParseError("execution_optimistic header".into());
        assert_eq!(
            tally_of("99", 3, vec![Err(not_found()), Err(not_found()), Err(optimistic)]).unwrap(),
            CheckedHeader::Unconfirmed
        );
        assert_eq!(
            tally_of(
                "99",
                3,
                vec![Err(not_found()), Err(not_found()), Err(BeaconError::RevokedInFlight)]
            )
            .unwrap(),
            CheckedHeader::NotFound,
            "a revoked node is not asked"
        );
    }

    #[test]
    fn errors_alone_return_the_error_of_the_lowest_node_index() {
        let mut tally = HeaderTally::new("99", PROPOSAL, 3);
        assert!(tally.add(2, Err(BeaconError::ParseError("bad".into()))).is_none());
        assert!(tally.add(0, Err(BeaconError::RevokedInFlight)).is_none());
        assert!(tally.add(1, Err(server_error())).is_none());
        let err = tally.finish().unwrap_err();
        assert!(matches!(err, BeaconError::ApiError { status: 500, .. }), "{err:?}");
    }

    #[test]
    fn errors_alone_return_the_first_error_that_is_not_a_revoke() {
        let err = tally_of(
            "99",
            3,
            vec![
                Err(BeaconError::RevokedInFlight),
                Err(BeaconError::ParseError("bad".into())),
                Err(server_error()),
            ],
        )
        .unwrap_err();
        assert!(matches!(err, BeaconError::ParseError(_)), "{err:?}");
        let err = tally_of("99", 2, vec![Err(BeaconError::RevokedInFlight)]).unwrap_err();
        assert!(matches!(err, BeaconError::RevokedInFlight), "{err:?}");
    }
}
