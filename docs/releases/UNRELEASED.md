# Unreleased

Operator-visible behavior changes land here during the development cycle and
are folded into `docs/releases/vX.Y.Z.md` at release time.

## Block production: a block may build on the parent of the previous slot

At proposal slot N, the parent walk reads `GET /eth/v1/beacon/headers/{block_id}`.
The first header found is the canonical parent. When that header is exactly at
slot N-1, a block whose parent is that header's own parent is also signed and
published, but only after the soft deadline and only when no block on the
header root is in hand. That covers a single-slot proposer re-org. The header
root ranks ahead of that re-org parent. A header below N-1 accepts only that
header's root. A non-404 error skips the parent check rather than binding an
older block. A header whose slot does not match the requested id, or a head
fallback at slot N or later, rejects every parent. Every produced block is
still checked for slot, proposer index, and parent before it is signed. A
block that fails those checks is logged at warning, and that log names the
re-org parent when one is allowed. A rejection does not stop the search while
another candidate matches.

## Block production: a slow beacon node no longer drops a block already in hand

`produce_block_v3` treats a block as in hand only when it passes the hard
checks and carries the expected fee recipient. The hard checks are the duty's
slot, proposer, parent, and consensus version. A full block from Bellatrix on
is also rejected when its fee is missing, invalid, or present only on a
builder header. A blinded block is not: the builder header's fee is the
builder's. Before Bellatrix a missing fee is still accepted. A block that
fails a hard check does not close the soft window (half the block-production
budget). The rejection is logged with the beacon-node index and the expected
and actual slot, proposer, parent, fork, fee recipient, and value parse. A
rejection that arrives after the call has already returned is logged the same
way.

A readable fee that does not match is a penalty when `fee_recipient_policy`
is `sign` (the default). It does not close the soft window and it does not
stop the unsynced fallback. It is signed only after every selected beacon
node has answered or the hard deadline (the budget) passes, and only when no
fee-matching block is in hand. The warning names the beacon-node index and is
emitted only for the block that is signed. That win increments
`rvc_produce_block_fee_recipient_penalty_total`. `fee_recipient_policy =
"reject"` drops a readable mismatch instead, and that drop is not counted.

Ranking within a fee class adds the execution payload value and the consensus
block value. Each value has to be a whole decimal number; a value that does
not parse, or a sum that overflows, does not win. If a fee-matching block is
in hand by the soft window, that block is returned. A node still in flight is
finished afterwards, and a timeout is recorded as an error on that node.
Recording that sample does not delay the block already in hand. Once any
signable block is held, including a fee-penalized one, it is returned 50 ms
before the outer backstop (the budget plus 250 ms), so a beacon node that
never answers cannot turn it into an operation timeout.

`prepare_beacon_proposer` and `register_validator` run on their own task from
startup, including before genesis (epoch 0), with no builder jitter. A
failure retries once per slot until both succeed. A slow beacon node on that
task does not hold the slot loop. The epoch-boundary send still runs after
that slot's proposal.

If every synced proposal node fails or misses the budget, another
proposal-role node is tried only when it is still above the health floor
(small lag or better, healthy, not optimistic, and execution online) and the
expected parent root is known. Its block has to match that primary parent.
The re-org parent is not accepted on this path. A readable
fee mismatch is kept only when no fee-matching block is available. A blinded
block keeps the builder header's fee recipient. The attempt stays inside the
time left in the backstop, and ends 50 ms early once a block is held. The
block-proposal deadline includes that same 250 ms, so publishing is not
shortened by it. A block-production budget of zero is treated as no budget.
With no budget configured, block production still waits for every selected
beacon node.

## Beacon node broadcast: the first complete acceptance completes the call

A submission broadcast returns when the first matching beacon node fully
accepts it. A partial acceptance, such as a 400 that lists failed
attestations, does not finish the call: the other beacon nodes keep running
until one accepts the whole batch, the publish deadline, or every attempt
finishes. Once any node has accepted, those remaining publishes move to a
detached task. Cancelling the caller does not cancel them. A slot timeout
returns the best partial seen so far instead of failing every validator. The
caller returns 50 ms before that deadline so its result wins the race against
the outer timeout. If the timeout still wins, that error path keeps the same
partial. A later beacon node with fewer failures replaces the partial that
deadline reports. If none accepts the whole batch, the partial with the fewest
failures is kept, so a later full acceptance is not thrown away and a validator is
not marked rejected while another node accepted the batch. That covers
attestations, aggregates, sync-committee messages, blocks, registrations,
and the other publish paths. Each beacon node gets that operation's own
budget. A node still in flight when the call returns is finished afterwards,
and a timeout is recorded as an error on that node. At most 16 of those
background finishes record health at once. That cap limits health recording,
not sends. If 16 are already running, further nodes still receive the
publish. Those overflow drains are not dropped to make room. Each one ends
at that attempt's budget, or at the beacon client's HTTP timeout when no
budget is set, so how many are in flight follows publish rate times that
timeout (`rvc_bn_broadcast_overflow_drains`, labelled by the redacted
endpoint). The gauge drops when that beacon node's HTTP call finishes. A
success health sample is skipped when that 16-permit pool is full
(`rvc_bn_broadcast_drain_health_skipped_total`). An error or a timeout is
still recorded then, when the recorder queue has room. When that queue is
full, an error or a timeout sample can be dropped. The drop is counted on
the same counter, and the attempt does not wait. Liveness
and builder-preference merges still wait for every matching beacon node.
When no budget is configured, the publish itself stays unbounded up to the
HTTP client timeout. Shutdown drops the unregistered recorder and any
overflow publish, so a queued health sample is not kept.
