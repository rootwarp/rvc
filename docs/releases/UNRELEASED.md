# Unreleased

Operator-visible behavior changes land here during the development cycle and
are folded into `docs/releases/vX.Y.Z.md` at release time.

## Proposer-pool timeouts, the global selection mode, and URL proposer reset

A dedicated proposer beacon-node pool uses the same operation timeouts as the
main pool. `block_production_timeout`, `attestation_timeout`,
`aggregate_timeout`, and `duty_fetch_timeout` apply to that pool. With
`block_production_timeout = 6`, block production on the proposer pool has a
6 second budget. The other budgets stay at their built-in values unless they
are set too. An empty `proposer_nodes` list still builds no proposer pool. A
proposer URL that is not `http` or `https` fails startup and builds no pool.
A stored budget of zero is still no budget.

`--block-selection-mode` and the top-level TOML key `block_selection_mode`
set the global default. A validator with no per-validator mode uses that
default. A per-validator mode still wins. When both are unset, the global
default stays `max-profit`. A malformed builder URL, or a zero default fee
recipient, still refuses to build the store, so the mode is not published.
The mode and the proposer-pool budget do not read the fork schedule.

A proposer-config URL owns each fee recipient, gas limit, and builder flag
on its own. When the remote document starts owning a field, that field's
baseline is the live local value at that moment. A later remote value for a
field the URL still owns keeps that baseline. Any keymanager or other
durable write of a field the URL owns drops that ownership, including a
write of the same value. The written value is the new local baseline, in
memory and in the validators file. The URL owns the field again only when a
later document sets it, and the baseline is the live value at that moment.
A later successful fetch that omits the pubkey restores each field the URL
still owns. A field the URL does not own is left as it is. Naming the
pubkey again after that restore starts ownership from the restored row.

Deleting a key removes its ownership record. Importing it again starts from
the imported row. An omission after that delete does not write the old
baseline onto the new row. Refresh application, the ownership record, and
keymanager durable writes run under the store save lock and one state write.
The generation check stays held across the restore.

URL values stay in memory for proposals and are not written into the
validators file. A keymanager save of an unrelated field, such as graffiti,
persists that field and leaves the local baseline of each field the URL
still owns on disk.

`default_config` changes the live defaults only. It is not written as
`[defaults]`. After a restart with the remote document gone, a validator
with no per-validator override uses the local `[defaults]` from the file.
A later body that omits `default_config` does not restore the previous
remote defaults.

A 401, a body that is not JSON, a 200 whose JSON has neither
`proposer_config` nor `default_config`, or one invalid entry leaves every
previous URL value in place. One bad entry rejects the whole fetch: a
sibling is not applied and an omission is not restored. A document that has
only `default_config` is accepted and does not treat missing pubkeys as
omissions. A pubkey that was not in the store is not tracked. These paths
do not sign or publish a block.

Each of the four timeout knobs must be from 1 to 60 seconds. Zero is still
rejected with the existing message. `operation_timeouts` also clamps, so a
skipped validation cannot store `u64::MAX`. While a slot is open, the slot
end is passed only into proposer-pool block production. That call is capped
at the time left in the slot. The main pool keeps its configured budgets.
Attestation, sync, and aggregate publication keep slot end plus 500 ms.
Adding a timeout to the clock uses checked arithmetic, so `u64::MAX` seconds
returns instead of panicking.

Review findings B-033, B-034, and B-114 are fixed.

## Doppelganger liveness runs even with no keys loaded

The liveness loop starts whenever doppelganger protection is on, including a
boot with an empty keystore. It asks beacon nodes only for the previous epoch
and the current epoch, and an empty index registry makes no liveness call.
A key becomes Safe after three closed not-live epochs (the previous epoch,
answered at or after three quarters of an epoch — slot 24 when an epoch has
32 slots). A gap, a missing index, or a failed query does not count and
delays Safe. A live answer in the same check as the last closed epoch stays
Detected; that check does not open the gate first. A failed or partial
answer for the current epoch does not let the last closed epoch open the
gate. A clock reading before genesis does not mark boot keys Safe. There is
no timeout that opens the gate. An imported key starts counting at the epoch
after import. A live answer at or after that epoch closes the gate for good.

## Slot duration comes from the beacon node

Doppelganger epoch, liveness sleep, the index-resolver tick, the import hold,
the keymanager and CLI default exit epoch, the slashing-monitor interval, and
the Gloas payload deadline use the slot duration from `GET /eth/v1/config/spec`.
Responding beacon nodes must report the same `SLOT_DURATION_MS` or
`SECONDS_PER_SLOT`, the same `SLOTS_PER_EPOCH` as the network preset, and the
same genesis time as the configured genesis. A missing, zero, conflicting,
out-of-range (outside 1 s..=60 s), or disagreeing value fails startup. A
named network must report that network's preset duration and preset genesis
time. An explicit `genesis_time` that differs from the preset is rejected.
On a named network, a beacon node that does not respond is skipped, and at
least one must respond. Custom still requires every configured beacon node.
A beacon node whose genesis validators root is not the configured root is
rejected. It is not admitted, it is not the chain identity, and it is not a
source of liveness or head and reorg events. A skipped node stays out of
duties and liveness until its slot duration, slots per epoch, genesis time,
and genesis validators root match the boot agreement. Recovering `/eth/v1/node/syncing` does not admit it. A spec that
arrives before a genesis timeout is still compared. HTTP 502, 503, 504, and
429 count as not responding. HTTP 500 does not.
The client does not assume 12 seconds. Slot boundaries use that duration in
milliseconds, including lengths that are not a whole number of seconds.

The keymanager voluntary exit uses the duration and genesis time checked at
startup. It does not read the spec or genesis again from whichever pool node
answers first. The CLI exit command has a single beacon URL, so it cannot
cross-check a pool; it still rejects a missing, zero, conflicting,
out-of-range, or non-preset duration, a `SLOTS_PER_EPOCH` that is not the
preset, and a genesis time that is not the named-network preset.

Epoch 0 marks normally registered keys Safe only on a named network, after
the responding beacon nodes match that preset genesis. Custom does not open
the bypass: the same nodes choose the slot duration, and a long duration can
hold the clock at epoch 0. A duration outside the bound cannot produce epoch 0.

`BlockService::new` still stores the 12 s constant until the coordinator
passes the beacon-node duration. `KeystoreManagerAdapter::new` builds its
private admission clock at 12 s; production replaces that clock with
`with_admission_service`. Those two constructors are the remaining 12 s
assumptions.

## Keymanager import passwords survive a restart

`POST /eth/v1/keystores` writes each import password under
`<keystore_path>/.rvc.keymanager-secrets/0x<pubkey>` before the keystore file
is published. A password longer than 4096 bytes is rejected and nothing is
written. The directory is mode `0700` and the file is mode `0600`. Mode
`0600` is not encryption at rest, so a backup of that directory holds usable
keys. The write is a new file, an fsync, and a rename, staged inside the
secrets directory. Boot loads these passwords even when `--password-file` is
unset, and a secret overrides a per-pubkey entry and a `*` entry in that
file. A secret whose mode is not `0600`, whose owner is not the current user,
or whose body is larger than 4096 bytes, a secrets directory whose mode is
not `0700`, an unreadable secret, a corrupt keystore for that secret, or a
secret that does not decrypt its non-denylisted keystore aborts startup. The
error names the path and the reason, and does not include the password. A
deposit-data or slashing-interchange JSON file that only contains the pubkey
does not abort startup. A secret with no keystore is a warning. Imported keys persist across restarts,
so moving a key needs `DELETE /eth/v1/keystores`, which removes the secret
with the keystore before the deletion denylist entry. A keystore whose
`pubkey` field is missing, not lowercase bare hex, or not the decrypted key
is rejected and nothing is written.

## Block production: the selection mode binds the response and the V4 builder list

Builder-only rejects a pre-Gloas unblinded block and a Gloas self-build
bid. Execution-only rejects a pre-Gloas blinded block and a Gloas external
bid. On Gloas the bid is the block's `builder_index`: the self-build index
is `18446744073709551615`, and every other index is an external bid. Wrapping
an external bid in `BlockContents`, or sending a self-build as a bare
`BeaconBlock`, does not change that. The envelope is present exactly when
the bid is a self-build, in every mode. A self-build envelope is signed only
when its `builder_index`, `beacon_block_root`, and `parent_beacon_block_root`
match the block. The bid `slot` and `parent_block_root` must match the block
as well, including a bare external bid. A mismatch is dropped before the
block is signed. A Gloas response flagged blinded
is dropped before decode; that drop is not a shape rejection. The shape
check runs on each candidate before the block is signed. A rejected
candidate is skipped, and each shape rejection increments
`rvc_block_shape_rejections_total`. When a builder-only candidate was the
wrong shape, the proposal still returns a builder-only error and names that
shape, even if a later candidate fails for another reason. A lone wrong-slot
blinded block stays a slot mismatch. Execution-only returns a mode mismatch, which does not trip
the builder circuit breaker. Max-profit and builder-always still accept
either shape.

On `produceBlockV4`, a boost of 0 clears `builders`. That is execution-only,
and max-profit or builder-always while the circuit breaker is tripped. A
non-zero boost writes that boost and the validator's `min_bid` onto every
per-builder entry, including a duplicate URL. Entries cannot keep a provider
boost that would ask for a bid after the mode turned builders off. A fresh
process starts with the breaker clear, so those entries are sent again.

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
emitted for the candidate that is signed. A fee-matching candidate that fails
the proposal checks is skipped and does not take the penalty. That signed
mismatch increments `rvc_produce_block_fee_recipient_penalty_total`.
`fee_recipient_policy =
"reject"` drops a readable mismatch instead, and that drop is not counted.

Ranking within a fee class adds the execution payload value and the consensus
block value. Each header is a whole decimal. A missing, empty, signed, or
non-digit header, or a digit string that does not fit in `u128`, contributes
0. A non-UTF-8 `Eth-Consensus-Block-Value` on a V3 response is ignored the
same way: the block is still returned and that header contributes 0. One bad
header does not zero the other. The sum saturates at `u128::MAX`. An unparsed
header is logged as `unparsed`, not as `ok:0`.
Equal totals keep the lower beacon-node index. `produce_block_v3` returns the
head of that list. `produce_block_v3_ranked` returns every accepted candidate,
best first, including a fee-penalized block behind a fee-matching one. Block
proposal walks that list and signs the first candidate whose slot, proposer,
and parent match the duty. A candidate that fails those checks is logged once
and skipped. Once a signature exists, a signer or publish error is final and
the next candidate is not signed. If a fee-matching block is
in hand by the soft window, that block is the head. A node still in flight is
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
