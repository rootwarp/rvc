# Unreleased

Operator-visible behavior changes land here during the development cycle and
are folded into `docs/releases/vX.Y.Z.md` at release time.

## Block production: a slow beacon node no longer drops a block already in hand

`produce_block_v3` returns the blocks that have arrived by half the
block-production budget and that match the duty's slot, proposer, parent,
consensus version, and, on a full block, the fee recipient. A block that
fails those checks does not close
that window. Ranking adds the execution payload value and the consensus
block value. Each value has to be a whole decimal number; a value that does
not parse, or a sum that overflows, does not win. If none have been accepted,
it returns the first matching block that arrives before the budget. A node
still in flight is finished afterwards, and a timeout is recorded as an
error on that node. Recording that sample does not delay the block already
in hand.

If every synced proposal node fails or misses the budget, another
proposal-role node is tried only when it is still above the health floor
(small lag or better, healthy, not optimistic, and execution online) and the
expected parent root is known. Its block has to match that parent. From
Bellatrix on, a full block has to carry the duty's fee recipient. A missing
fee recipient is rejected, and a full SSZ block whose fee recipient cannot
be read is rejected. A blinded block keeps the builder header's fee
recipient. The attempt stays inside the time
left in the backstop (the budget plus 250 ms). The block-proposal deadline
includes that same 250 ms, so publishing is not shortened by it. A
block-production budget of zero is treated as no budget. With no budget
configured, block production still waits for every selected beacon node.

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
