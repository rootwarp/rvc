# Unreleased

Operator-visible behavior changes land here during the development cycle and
are folded into `docs/releases/vX.Y.Z.md` at release time.

## A raw beacon client refuses a produce duty

`BeaconClient` does not rank blocks and does not check the fee recipient, the fork, or the parent. `produce_block_v3_ranked` and `produce_block_v3_ranked_by` return an error when a duty is passed. `produce_block_v3_for_duty` always returns that error. The message is `duty-aware production requires BnManager`. With no duty, the raw client still returns the one block from that node, and `produce_block_v4_by` still calls that node. The validator client produces through the beacon-node pool, which already applies the duty.

## Builder policy follows the flag, and the boost ranks across beacon nodes

A key whose effective block-selection mode is `builder-only` warns once at startup when `builder_proposals` is off, or when that key's Gloas builder list is empty. Both missing is still one warning. The line is `builder_only_without_builder`. It names the truncated pubkey, `builder_enabled`, and `gloas_builders`. It does not name a relay URL or a fee recipient. Startup continues. Keys already in the validators file are checked when the store is built. A keystore key that was not in the file is checked when it is registered, so each key warns once.

Before Gloas, `max-profit` and `builder-always` with `builder_proposals` off do not request a builder bid. The produce call uses boost 0 and accepts only a local block. A blinded response is rejected before it is signed, and a produce error on that path is not a builder-circuit miss. `builder-only` is not downgraded: it still asks with boost `u64::MAX`, still refuses a local block, and still warns at startup. Gloas is unchanged. V4 keeps the configured boost and the configured builder list.

When more than one beacon node returns a block, a blinded block is ranked at `value * builder_boost_factor / 100` and a local block at its raw value. The scale is a checked multiply. When that product does not fit in `u128`, a divide-first path runs, and the quotient is capped at `u128::MAX`. Overflow does not always yield `u128::MAX`: `u128::MAX` at boost 50 is `u128::MAX / 2`. Saturating the product and then dividing would turn `u128::MAX / 2 * 1000` into `u128::MAX / 100`. Boost `u64::MAX` ranks any blinded block above any local block. Boost 0 ranks any local block above any blinded block, including a local value of 0 against a blinded value of `u128::MAX`. No boost on the duty compares raw values. The primary parent still outranks the re-org parent before the boost.

Turning `builder_proposals` off does not tell the relay to forget the validator, and it does not drop a registration the builder service already cached. The relay keeps the last registration until a later registration update.

## Broadcast drains are bounded per beacon node and joined on shutdown

Each beacon node accepts at most 4 in-flight broadcast sends. That cap is
`MAX_INFLIGHT_PER_BN` in `fan_out`: 2 × the default publish concurrency of 2.
It does not follow a live change of `duty_publish_concurrency`. A node that
is already at the cap waits up to one attempt budget for a permit
(`rvc_bn_broadcast_inflight_waits_total`, labelled by the redacted endpoint).
The HTTP call starts only after the permit is held. The wait does not shrink
that call's budget, and it does not skip the node. If the permit does not
arrive, the attempt times out and the HTTP call is not started. A send that
already holds a permit runs to its own attempt budget and is not cancelled
to free the slot. The caller's backstop, 250 ms past that budget, does not
cancel it either. The overflow gauge is unchanged: it still counts publishes
past the 16-permit health-sample cap, and it still drops when that HTTP call
finishes.

Detached drains are joined on shutdown after the duty orchestrator stops,
for up to the block-publication budget (2 s by default). A configured zero
is no budget, the same rule as the publication timeout itself: shutdown
waits until those drains finish. A hung send still ends at the HTTP client
timeout. The join does not cancel a send that is still running when a
positive budget elapses. The health recorder is still not joined, so a
sample that is only queued at process exit is not kept.

Drains keep the attempt budget. They do not use the caller's slot deadline.
A background send is already bounded by one budget after it starts. Cutting
it at the slot deadline would cancel late gossip, and an attestation can
still be included for 32 slots.

The execution-payload envelope is sent to every role-matching beacon node as
soon as the first block acceptance returns. A slower node may not have
imported the block yet. It can answer "unknown block", and that answer
counts as a health error until the node imports the block. Sending the
envelope only to the nodes that accepted the block stays parked until Gloas
is scheduled.

## Startup proposer preparation ends when the orchestrator returns

`DutyOrchestrator::run` polls startup proposer preparation beside the slot loop. That future is dropped when `run` returns, including on shutdown. A slow `prepare_beacon_proposer` still does not hold the slot loop. Before genesis the epoch is 0. A failed prepare or register retries once per slot until both succeed or `run` returns.

## A hard-rejected block does not improve beacon-node health

A produce candidate that fails a hard check no longer counts as a successful health sample. The beacon node's score, error rate, and latency stay where they were. A readable fee-recipient mismatch under `fee_recipient_policy = sign` is still a success. The fallback records that sample only after the fallback accept check, so a rejected fallback body does not improve the node either.

When every finished candidate is dropped and no transport error was stored, `produce_block_v3` returns `all candidates rejected` and names each beacon node: `bn {index} {reason}`, in index order, joined by `, `. The reason is `fork`, `unreadable`, `slot`, `proposer`, `parent`, `fee`, `shape`, `prepare`, or `fallback_parent`. `fallback_parent` is a fallback body that passed the hard checks and did not use the primary parent. A stored transport error stays the highest-index transport error, and a reject does not replace it. `RevokedInFlight` is not stored as that error.

`rvc_bn_produce_candidates_rejected_total` counts those drops, including `fallback_parent`. The label is `reason`. A fee-only penalty is not counted. `rvc_bn_produce_soft_deadline_returns_total` counts a best-of produce round that returns because a block is in hand at the soft deadline, or because the first in-hand block arrives after it. `rvc_bn_produce_fallback_total` counts an unsynced proposal fallback that starts an attempt. Best-of drain samples that are not recorded now increment `rvc_bn_best_of_drain_health_skipped_total`. They no longer increment `rvc_bn_broadcast_drain_health_skipped_total`. A dashboard that used the broadcast counter for best-of skips should add the new series. The 16-permit pool is still shared.

`health_scores` takes the sync lock and then the health lock, the same order as synced selection and the proposal fallback.

## Keystore boot names and delete durability

Import writes a keystore as `0x` plus the lowercase pubkey hex plus `.json`. Startup treats that exact name as the key's keystore. An empty file, a truncated file, or a file that cannot be read at that name fails startup when an import secret for the same pubkey is present and the key did not load. The error names the secret and says the keystore is corrupt. A symlink at that name whose target is outside the keystore directory, or that does not resolve to a regular file inside it, is the same failure.

A `*.json` file with any other name is a keystore only when it validates, or when it has a pubkey and a `crypto` field and validation fails. A file that only carries the pubkey and a `version` does not block startup. That secret is a warning, the same as a secret with no keystore file. A valid keystore under another name, such as `keystore-<hex>.json`, still loads. If that file loads the key, an empty `0x<pk>.json` for the same pubkey does not fail startup. An unreadable canonical file is recorded with the same invalid mark, and a valid file for that pubkey is kept. A canonical file whose body validates as a different pubkey is corrupt for the name in the filename.

DELETE writes the deletion denylist after it tries to remove the import secret, including when that removal fails. A loaded key stays in the signing registry until secret removal and the denylist write both succeed, so the DELETE can be retried. A restart skips a key that is on the denylist. A failure to remove the keystore JSON returns before the denylist write. The keystore directory is not fsynced on DELETE.

After an import-secret file or a staged partial is removed, boot and DELETE fsync that secret directory. A later directory-entry error or a failed unlink does not skip that fsync when something was already removed. If the fsync also fails, the error keeps the first removal error and includes the fsync failure. A partial-cleanup error is attached to an earlier final-secret unlink error.

## V3 block production arms the fallback at the slot deadline

`produce_block_v3` on the proposer pool takes the slot end as a per-call deadline. The production budget was already the shorter of the configured budget and the time left. The 250 ms backstop and the unsynced fallback used to be armed past that deadline. Both are now armed at the earlier of (call start + budget + 250 ms) and the deadline.

The outer wait is the earlier of (budget + 250 ms) and the time left until the deadline. A deadline that is already past arms a zero timeout, so the call is not asked to wait out the 250 ms. A deadline later than the budget plus 250 ms leaves that budget and its backstop unchanged. The subtraction saturates, so a deadline in the past does not panic.

`produce_block_v4` has no 250 ms backstop. Its wait stays the production budget capped at the time left. This note does not change that path.

The deadline is an argument of that produce call. The next produce call, and attestation, aggregate, and publication, do not keep it.

The bound is a tokio timeout, the same poll order as the orchestrator's proposal timeout. When the runtime is responsive, the call is not asked to wait past it. Under scheduler lag the runtime can poll the task after the timer has fired, and a result that is already ready on that poll can still be returned. That wake-up is best-effort.

With builder boost greater than 0, a V3 produce timeout at slot end can now count as a builder circuit-breaker miss. Counting that timeout as a miss biases toward local blocks. The outer proposal timeout still does not count a miss.

## Parent lookup does not treat a mixed beacon-node failure as an empty slot

`query_first`, `query_first_prefer_some`, and `query_failover` return a 404 only when every beacon node that was attempted returned 404. Otherwise the result is the first non-404 error, in attempt order. A later 404 does not replace that error. Parent lookup therefore stops when one node returns 500 and another returns 404, in either order. It does not walk back and bind an older block. Stopping leaves `expected_parents` unset, which turns the parent filter off.

On `produce_block_v4`, HTTP 405 and 501 are a capability gap and rank like a 404 when the round chooses which error to keep. A 500 or a timeout replaces a 405 or 501 seen earlier. A 405 or 501 does not replace an earlier 500. A v4 produce round in which every attempted node returns 404, 405, or 501 is still "no eligible beacon node".

A header is used only when `execution_optimistic` is false and `data.root` equals `hash_tree_root` of the header message. A missing flag, `true`, a non-boolean flag, or a root that does not match is a parse error. Each of those responses is a health error for the beacon node that returned it, on every slot whose header is fetched. A later beacon node that returns a valid header still supplies that header. The header signature is not checked. The header container is the same from phase0 through Gloas. The known-answer vector is `ethereum/consensus-specs` tag `v1.7.0-beta.2`, `tests/minimal/gloas/ssz_static/BeaconBlockHeader/ssz_random/case_0`.

Two returned-error labels changed. A fast 500 followed by a hung peer on `query_first` is reported as that 500, not as an operation timeout. The same 500 stays when the last remaining attempt hits the deadline.

An HTTP 204 is still "no data" when the other attempts are 404s or other errors that are not an operation timeout. `BeaconError::Timeout` does not beat a 204. An operation timeout anywhere in that round does. If the attempt budget is already exhausted, the round returns that timeout without starting the next request.

## Selection shape is applied when the block is collected

Builder-only drops a local block while candidates are collected. That block does not end the wait, and the fallback does not return it. Execution-only drops a blinded block the same way. Max-profit and builder-always still accept either shape while the builder circuit breaker is clear.

While the breaker is tripped, max-profit and builder-always use the execution-only shape check. A pre-Gloas blinded block and a Gloas external bid are not signed. The produce request uses boost 0, and on Gloas the builder list stays empty. Builder-only still misses the slot when the breaker is tripped.

A failed publish of a pre-Gloas blinded block, or of a Gloas external bid, counts toward the breaker. A local publish does not. Only a successful publish on that builder path resets the consecutive miss count: a blinded block the beacon node accepted, or a Gloas external bid. A later local block does not reset it. The proposal timeout still does not count a miss.

The breaker is clear or tripped. Misses below the limit leave it clear. There is no half-open state.

The per-validator builder flag is unchanged.

## Aggregate responses are checked before signing

An aggregate is signed only when its slot, attestation-data root, committee, attester-bit length, and fork match the request. The root is the unmodified attestation data. At Electra and Fulu the data index must be zero. Before Electra it must be the duty's committee index. At Gloas the index stays in that root. A beacon node without aggregate v2 returns an Electra body on Fulu and Gloas; that body is accepted. The duty's committee length must be 1 through 2048 on every fork. The attester bitlist must be exactly that length, and still inside the fork's spec maximum. A mismatch increments `rvc_aggregations_total{status="failed"}` and is not signed.

Aggregation and sync contributions share one phase-2 cap of `duty_dispatch_concurrency`. Selection proofs and the following aggregate-and-proof or contribution-and-proof signatures take permits from that same cap, and only while the signer call runs. A permit is not kept once the phase deadline has passed. When that wait expires on the aggregate-and-proof signature, `rvc_aggregations_total{status="failed"}` increments. That expiry is not a slot-end intake drop. A cancelled selection-proof wait does not increment the counter. Time spent waiting for a permit counts against the sync contribution timeout. Attestations and sync messages at the 1/3 offset are not on this cap.

## Full blocks and one JSON block shape

A full block whose body does not decode under its consensus version is rejected before signing; a JSON block document with both top-level and nested block fields is rejected.

That hybrid rejection also covers a blinded JSON document, and a document that is not a JSON object. A bare Deneb, Electra, or Fulu JSON block is published as `{message, signature}` with the object body that was hashed.

The fork layout is the header's `Eth-Consensus-Version`, which is already checked against the slot's fork. A Deneb body under an Electra or Fulu header is a parse error, and nothing is signed. Pre-Deneb full blocks stay unsupported. A produce document that carries block fields at the top level and a nested `block` is rejected, so the fee check and the signed block cannot be different objects.

## Proposer-config URL refresh

Shutdown cancels an in-flight proposer-config fetch. Dropping the fetch
stops this task from waiting on it. An apply that has already started still
runs to completion, including a release of omitted fields. Shutdown does not
roll that release back. A DNS lookup or a connect already
spawned inside the HTTP stack can outlive that drop until the connect
timeout or the request deadline. The client uses a 10 second connect
timeout and a 30 second total deadline. The connect timeout covers DNS,
TCP, and TLS, not only the TCP handshake. In reqwest 0.12 the 30 second
deadline covers DNS, connect, TLS, redirects, and the body. There is no
client-level read timeout. Body reads also use a 10 second idle timeout
between chunks, re-armed on every chunk, on top of that total deadline. A 4 MiB body needs about 140 KB/s or better
to finish inside the deadline. A failed fetch is not retried. Responses are
not decompressed, so `Content-Length` is the wire size. Only a same-origin
redirect is followed (same scheme, host, and port), in both secure and
insecure modes. A cross-origin redirect is an error and counts as a refresh
failure. That includes `https://h:8443` to `http://h:8443` and a redirect
onto loopback. Redirects do not send `Referer`. Query strings and fragments
are removed from logged URLs, and query strings are removed from fetch
errors. A refresh interval of 0 is rejected when a proposer-config URL is
set, and is still accepted when no URL is configured. The interval cannot
exceed 24 hours.

A document that names the same validator twice is rejected. That includes
an exact duplicate JSON key and two spellings of one key (`0x` prefix and
hex case). No row from that document is applied.

The response body is capped at 4 MiB. A `Content-Length` above the cap is
rejected before the body is buffered. A chunked body with no
`Content-Length` is rejected as soon as the bytes read pass the cap.

## CLI voluntary exit signs again

`rvc voluntary-exit` and `rvc prepare-exit` sign with the local keystore again.
They are offline tools and are not doppelganger-gated: a voluntary exit is not
a slashable duty, and the command logs a warning when it signs. `prepare-exit`
writes the signed message and does not broadcast it. `voluntary-exit` submits
it to the beacon node after `--confirm`. `rvc-keygen exit` stays an offline
ungated tool.

The keymanager exit path stays doppelganger-gated. `Pending` and `Detected`
keys are refused. The exit adapter takes the beacon slot duration as a
required argument and no longer defaults it to 12 s.

## Doppelganger detection stops the process

The first time a validator is reported live inside its forward window, the
process overwrites the pre-allocated `.rvc.doppelganger_record` in the
validator data directory and writes `.rvc.doppelganger_detected` there as
well. The record is a fixed-size file created at startup, before any
signing, and the detection update is an in-place overwrite. An in-place
overwrite does not allocate a new directory entry. On copy-on-write or thin
storage (btrfs, ZFS, thin LVM) it can still allocate a new block. The marker
records the detected public keys, the epoch, and the time. The process
requests exit 12 once a write and its fsync have succeeded. A read of the
file is not enough: if `pwrite` updated the page cache and `fsync` then
failed, the process keeps retrying and does not exit 12. If none of those
writes succeeds, the process stays up, refuses every new signature, and
retries. Each failed marker attempt increments
`rvc_doppelganger_marker_write_failures_total`. `SIGINT`, `SIGTERM`,
cancellation, or a panicking registered task still exits 12 when a write
and its fsync have already succeeded, and a later rewrite failure does not
retry forever. When nothing is durable yet, the drain keeps retrying and
does not exit 0 or 16. `SIGKILL` before the first successful fsync loses
the latch. Do not stop the node while that failure counter is rising. The
drain also writes the marker
in the parent of `slashing_db_path` when that directory is not the keystore
directory. The next start reads the record and either marker before it
builds a signer or the keymanager API and exits 12 again, and it reads them
again after the keystore lock. A `detected` record, a file that cannot be
read, a symlink or FIFO at that path, or a file that is not valid also
refuses to start. Restart-skip and a keymanager import cannot skip the
forward window while a marker is present or the record is `detected`.

With detection enabled, startup refuses to run when that directory is not
writable or when the detection record cannot be pre-allocated. The latch
cannot be guaranteed without that file. `keystore_path` must be a persistent,
writable volume. In the shipped compose file that is `/data/keystores` on
the `rvc-data` volume.

Clear the marker only after the other instance is gone. The command takes
the keystore lock and refuses while a process holds it. A validator client
started with `--disable-keystore-locking` holds no lock, so stop that
process before clearing. Pass `--slashing-db-path` so a fallback marker
beside the slashing database is removed too. The command resets the in-place
record to `not-detected` before it unlinks the keystore marker. The next
start runs a full forward window and does not restart-skip. That
force-window file stays until every key loaded on that boot has finished a
window.

```bash
rvc doppelganger clear-detection --datadir /var/lib/rvc/keystores --confirm
```

Deleting only the detection marker by hand leaves a detected record in
place. The next start still exits 12, and that deletion does not force a
fresh window. Use the command when a fresh window is required.

If the record is not a regular 4096-byte file (truncated, unreadable, a
symlink, or a FIFO), `clear-detection` returns an error and leaves the
marker in place. Stop the process, remove the broken record, and run the
command again. Do this only for a broken record. A valid `detected` record
is reset by the command. Deleting that file by hand skips the force-window
file.

```bash
rm /var/lib/rvc/keystores/.rvc.doppelganger_record
rvc doppelganger clear-detection --datadir /var/lib/rvc/keystores --confirm
```

From the moment of detection every new signing request is refused, including
keys that had already finished the window. A slashable signature is checked
again after its slashing-protection row is reserved and before the BLS call.
That check is the admission boundary. It is not atomic with the BLS call. If
detection has landed before the call, the call is not made and the reserved
row stays, so a later process cannot sign that duty. A BLS call that has
already started still finishes, bounded by the sign timeout. That includes a
request already sent to a remote signer. A non-slashable signature that
passed its check before detection can still finish inside that same timeout.

A false positive is an outage for every validator this process runs. systemd
should set `RestartPreventExitStatus=12`. Docker cannot exclude one exit
code. The process stays up and refuses signing until a write and its fsync
have succeeded, then exits 12. A restarted container finds that record and
exits 12 again. `SIGKILL` before the first successful fsync loses the
latch. Do not stop the node while
`rvc_doppelganger_marker_write_failures_total` is rising.

## Head capture deadline and concurrent sync contributions

Phase-2 head capture calls Beacon API `GET /eth/v1/beacon/blocks/{slot}/root`
with the decimal slot. The slot-context lock is not held across that fetch.
One capture runs per slot. A second caller waits until that capture finishes
or its own deadline, and does not start another fetch. The first root written
is kept.

When the attestation or sync-message phase owns the fetch, the request stops
at the earlier of slot end and `now` plus the `attestation_fetch` budget.
When the contribution phase owns the fetch, the deadline is the earliest of
those two and the contribution signing deadline. The signing deadline is
recomputed as a fresh `now` plus `sync_contribution`, capped at slot end plus
500 ms, so it can sit past slot end. The head fetch does not use that 500 ms
overhang. When the contribution and aggregate deadlines match and the
contribution arm owns the fetch, the deadline is slot end when slot end is
at or before both `now` plus `attestation_fetch` and the signing deadline.
It is the earlier of those two when either one is before slot end. A
deadline at or before `now` does not call the beacon node.

When the fetch returns no root, the stored head is the parent captured at
t=0. If that parent was not stored, the head stays unset. The fetch returns
no root when the deadline has already passed, the fetch times out, the slot
is empty (HTTP 404), the beacon node returns any other error, or the body is
not `0x` plus 64 hex digits (`A-F` allowed). The parent is not always a head
this client verified. The t=0 walk tries slot-1 through slot-4. After four
misses it uses the beacon node's `head` header and keeps that header's root
when `header.slot` is below the proposal slot. Signing the fallback root is
valid and non-slashable for sync messages. Attestations do not wait for the
fetch. When the attestation and sync-message deadlines match, the fetch runs
beside attestations. When they differ, the attestation arm does not capture
the head.

`BnManager::get_block_root` uses the same `attestation_fetch` budget, so a
hung beacon node fails over inside that budget.

Sync contributions use the phase-2 head. They do not start a second fetch
while that capture is running. When the contribution and aggregate deadlines
match, aggregation starts at that shared wait. Contributions run the head
fetch when they win it, and otherwise wait for the in-flight capture. That
wait uses the contribution head deadline above. It does not delay
aggregation. Contribution intake stops at slot end. Items not pulled onto
the pipeline before slot end increment the slot-end drop counter.
Sync-message drops are duties. Contribution drops are one item per duty and
subcommittee. The counter adds those counts, so one increment is not always
one subcommittee. It is cumulative for the sync-committee service, and it is
a log field, not a Prometheus metric. An in-flight fetch or signature is not
a drop. A fetch, a signature, or a publish already running stops at the
earlier of a fresh `now` plus the `sync_contribution` timeout and slot end
plus 500 ms. Each step computes that deadline again. Only the slot end plus
500 ms cap is shared. A slow remote signer cannot stretch one step past its
own deadline. A subcommittee index outside `0..4` is skipped before any
signature. Duplicate subcommittee indices are one fetch and one
contribution-and-proof. The contribution body must match the duty slot, the
phase-2 head, and the requested subcommittee, with a 16-byte aggregation
bitfield that has at least one participant bit and a 96-byte signature. An
empty bitfield is rejected before `sign_contribution_and_proof`. A body that
does not match is rejected as a whole. A sibling subcommittee that matches
is still published. The head is memory for that slot context only.

Beacon API: block root `GET /eth/v1/beacon/blocks/{block_id}/root`; sync
contribution `GET /eth/v1/validator/sync_committee_contribution`; publish
`POST /eth/v1/validator/contribution_and_proofs`. Consensus specs:
`subcommittee_index = position // (SYNC_COMMITTEE_SIZE // SYNC_COMMITTEE_SUBNET_COUNT)`
and `is_sync_committee_aggregator`.

Review findings B-008 and B-044 are fixed.

## JSON blinded Deneb and Electra blocks

A produce-v3 JSON response with the header `Eth-Execution-Payload-Blinded: true`
parses a Deneb or Electra blinded block body from a JSON object into canonical
SSZ before the block is signed. Fulu uses the Electra blinded body. The signed
publish to `POST /eth/v1/beacon/blinded_blocks` sends `message.body` as that
JSON object. The object is built once, before the publish is fanned out.
`Eth-Consensus-Version` must name the slot's fork before the body is decoded
or signed. A hex `body` is kept as SSZ only when that SSZ is the blinded
container for the same fork; a Deneb body under an Electra or Fulu header is
rejected before any signature. On the blinded path, a key that the
re-encoded SSZ does not contain at the same path is rejected. That includes
a nested key on `execution_payload_header`, on `eth1_data`, on
`sync_aggregate`, and on an element of `execution_requests.withdrawals`, and
a key on the blinded block object other than `slot`, `proposer_index`,
`parent_root`, `state_root`, and `body`. A positional JSON array is rejected
when the re-encoded SSZ at that path is an object, including
`execution_requests` written as `[deposits, withdrawals, consolidations]`, so
a nested key inside that array is not dropped. `execution_requests` on a Deneb body
and `execution_payload` beside `execution_payload_header` are rejected. Those
container types stay lenient on other beacon-node responses, so an unknown
nested field there does not fail the duty. A full (unblinded) JSON body
rejects an unknown field of the body object. A nested field inside that body
is not a parse error, and it is not part of the signed SSZ. Duplicate JSON
keys are a parse error. The key is the UTF-8 string JSON defines, so a raw
non-ASCII key and the same key written with `\u` escapes are one key, and two
different surrogate-pair keys are not. A hex prefix must be lowercase `0x`
(digits may be `A-F`). A quoted integer must not start with `+`. The full
JSON produce path uses those same two spelling rules, on the block object and
inside the body, before the body is decoded. A `uint256` decimal longer than
78 significant digits is rejected. Gloas and pre-Deneb object bodies fail with
a parse error in
`parse_blinded_block`. On the proposal path a Gloas blinded response is still
dropped as blinded-not-supported before that parse, and a pre-Deneb object
body fails with a parse error before the block is signed. A blinded publish
for Gloas, pre-Deneb, or an invalid body fails before any beacon node is
called. An invalid or partial body is rejected as a whole: nothing is signed
and the stored produce payload is left unchanged. SSZ publish is unchanged.

This follows Beacon API `produceBlockV3` and `publishBlindedBlock`, and the
consensus-specs builder container `BlindedBeaconBlockBody` (the execution
payload is `execution_payload_header`; Electra also carries
`execution_requests`).

Review finding B-019 is fixed.

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
pubkey but omitting one field restores that field when the live value is
still the remote one, and leaves the fields the document still sets.
Naming the pubkey again after that restore starts ownership from the
restored row.

Operators whose URL publishes a partial document now see omitted fields
snap back to the local baseline. A failed fetch does not snap them back.

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
A later successful body that omits `default_config`, or omits one of its
fields, restores that field's local value when the live value is still the
remote one. A failed fetch does not.

`reload_config` keeps URL ownership for a validator that is not in the
file, so a later save still writes that validator's local baseline. A
validator the file replaces takes the file values, and that URL ownership
is dropped. Remote defaults are cleared because the file replaces them.
Nothing in the shipped binary calls `reload_config`.

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

A not-live answer counts only when at least one admitted beacon node that is
Synced or SmallLag, not optimistic, and not execution-offline reported it.
A missing or unreadable sync distance is not that witness. A live answer
from any admitted node still counts. The loop reads the epoch again after
those queries. If the epoch changed, a live answer still detects and a
not-live answer does not decrement. A closed epoch older than the previous
one is not queried again. A missed closed window is not queried again, and
the remaining decrements are still required, so a miss never closes the
window early.

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
duties and liveness until its slot duration, `SLOTS_PER_EPOCH`, genesis time,
`genesis_fork_version`, and genesis validators root match the boot agreement.
Recovering `/eth/v1/node/syncing` does not admit it. A spec that arrives
before a genesis timeout is still compared. A genesis timeout before any
node has seeded still merges that spec's slot duration and `SLOTS_PER_EPOCH`.
It does not seed genesis time or `genesis_fork_version`. If no node returns
genesis, boot fails and chain identity stays unset. HTTP 502, 503, 504, and
429 count as not responding. HTTP 500 does not.

The monitor re-checks identity once per epoch. A parsed mismatch revokes the
node, including a pass that would otherwise be Unreachable or Unknown when
one side has already parsed a disagreement. When the last admitted node is
revoked, duties halt in place and the process stays up. `rvc_bn_admitted`
for that endpoint is 0.

The proposer pool is admitted against that same main-pool identity. A
proposer node whose spec or genesis disagrees, or that does not answer at
boot, is left unadmitted. Startup still succeeds. When that boot pass admits
nobody, block production uses the main pool and startup logs one warning:
`no admitted proposer node; block production uses the main pool`. The same
monitor interval re-checks proposer identity. A parsed mismatch revokes the
node, including the last admitted proposer node, and production uses the
main pool. A monitor pass that finds no admitted proposer node logs that
same sentence. It does not log `no admitted beacon node; duties halted`.
A timeout or an HTTP 5xx leaves admission unchanged when neither response
parses a disagreement. A parsed disagreement still revokes, including when
the other response is a timeout or a 5xx. A revoked proposer node is still
probed and is admitted again when it matches. The block duty fails closed
when the main pool has no admitted node, including when a proposer node is
still admitted. When a proposer pool is configured, the block fence watches
the main pool's revocation generation and the proposer pool's revocation
generation, including when the proposer pool has no admitted node. Produce
still asks whichever pool is admitted when the block is requested, so a
proposer node granted after that fence can be asked. If either watched
generation moves before the header is signed, the candidate is dropped and
the header is not signed. Combining fences keeps every generation.
`rvc_bn_admitted` and `rvc_bn_health_tier` carry a `pool` label (`main` or
`proposer`), so one URL configured in both pools does not share a series.
The proposer sync monitor publishes health tiers for admitted proposer
endpoints. An empty `proposer_nodes` list still builds no proposer pool. A
parent-capture fence that no longer holds signs no RANDAO. With no proposer
pool, the fence watches only the main generation.

The sync monitor waits one epoch of the beacon-node slot duration (6 000 ms
and 32 slots is 192 s). The head-event fallback poll waits one slot of that
duration. The subscriber samples the admission generation before it connects.
A silent stream wakes every 200 ms and leaves when that generation moved.
When the duration is not known yet the poll backs off 200 ms and retries the
stream; it does not wait for shutdown. Block production's default slot length
and the keystore admission clock still use 12 seconds. Slot boundaries use
the beacon-node duration in milliseconds, including lengths that are not a
whole number of seconds.

The keymanager voluntary exit uses the duration and genesis time checked at
startup. It does not read the spec or genesis again from whichever pool node
answers first. The CLI exit command has a single beacon URL, so it cannot
cross-check a pool; it still rejects a missing, zero, conflicting,
out-of-range, or non-preset duration, a `SLOTS_PER_EPOCH` that is not the
preset, and a genesis time that is not the named-network preset.

Epoch 0 marks normally registered keys Safe only on a named network, after
the responding beacon nodes match that preset genesis, and only when every
admitted beacon node in the All role reports a head slot below
`SLOTS_PER_EPOCH`. That is an admitted node whose role set contains `All`
(`BnRole::matches` in `crates/bn-manager/src/types.rs`). A query
error, a missing head slot, or a head slot that is not a number leaves the
bypass closed, and those boot keys stay Pending for the forward window.
Custom does not open the bypass: the same nodes choose the slot duration,
and a long duration can hold the clock at epoch 0. A duration outside the
bound cannot produce epoch 0.

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
either shape while the builder circuit breaker is clear.

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
published when no block on the header root is in hand. If every selected
beacon node has already answered, that re-org parent is returned then, before
the soft deadline, because waiting cannot bring a better block. While a
selected node is still in flight, the re-org parent does not close the soft
window. That covers a single-slot proposer re-org. The header
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

After slot, proposer, parent, and fee pass, a body that still cannot be signed is reason `prepare`. That covers a blinded body whose layout is not the slot fork, a block root that cannot be computed, and a KZG proof count that is not the count that fork signs for its blobs. The candidate is not held and it does not close the soft window. A document that names two block objects, or a body that cannot be read at all, stays `unreadable`. A full SSZ block with a proof-byte length that is not a multiple of 48, a blob-byte length that is not a multiple of 131072, or the wrong proof count for the fork is rejected before the header is signed. A Gloas slot on this pre-Gloas path is rejected. `produce_block_v4` does not use this check. Blinded blocks at Gloas stay a blinded-at-Gloas drop.

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

The first round of a duty keeps the usual tier selection, then drops any
beacon node below small lag, any optimistic node, and any node whose
execution client is offline. A healthy node whose sync status has not been
read yet stays in that round, including when the expected parent was not
supplied. A synced node still leaves a small-lag peer for the fallback
round. When that filter leaves nobody and the expected parent is known, the
round uses the wider set, so a measured node below the floor can still
propose. When the parent is unknown, that wider set is not used: a large-lag,
optimistic, or execution-offline node is not asked for the block.

If every synced proposal node fails or misses the budget, another
proposal-role node is tried only when it is still above the health floor
(small lag or better, healthy, not optimistic, and execution online) and the
expected parent root is known. Its block has to match that primary parent.
The re-org parent is not accepted on this path. A readable
fee mismatch is kept only when no fee-matching block is available. Every
penalized block from that fallback is kept and ranked; the higher value is
first. A blinded
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
budget is set, so how many used to be in flight followed publish rate times that
timeout. Sends are now capped at 4 per beacon node (2 × the default publish
concurrency of 2). A saturated node waits up to one attempt budget
(`rvc_bn_broadcast_inflight_waits_total`, labelled by the redacted
endpoint). The overflow gauge is still `rvc_bn_broadcast_overflow_drains`.
The gauge drops when that beacon node's HTTP call finishes. A
success health sample is skipped when that 16-permit pool is full
(`rvc_bn_broadcast_drain_health_skipped_total`). An error or a timeout is
still recorded then, when the recorder queue has room. When that queue is
full, an error or a timeout sample can be dropped. The drop is counted on
the same counter, and the attempt does not wait. Liveness
and builder-preference merges still wait for every matching beacon node.
When no budget is configured, the publish itself stays unbounded up to the
HTTP client timeout, and so does the permit wait. Drains keep that attempt
budget. They do not use the caller's slot deadline. Shutdown joins detached
drains after the orchestrator tier, for up to the block-publication budget.
A zero budget waits until the drains finish. A positive budget does not
cancel a send that is still running. The recorder stays
unregistered, so a sample that is only queued at process exit is not kept.
