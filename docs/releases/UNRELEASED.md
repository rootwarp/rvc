# Unreleased

Operator-visible behavior changes land here during the development cycle and
are folded into `docs/releases/vX.Y.Z.md` at release time.

## Shipped in v0.9.0 without a release note

The code of the changes below is in v0.9.0. The v0.9.0 release notes do not describe them. The text of each change is the release note of its PR.

### Proposer preparation: no POST from an index registry that went stale after a revocation; re-sent once the indices are re-checked

- After rvc marks a beacon node as revoked, proposer preparation waits for the validator indices
  to pass a re-check. rvc stops proposer preparation when it detects a stale registry after a node
  revocation. While the index registry is stale, rvc sends no `prepare_beacon_proposer` POST. The
  revoked node can retain an earlier preparation. If a revocation occurs during a POST, that POST
  can reach the node with old indices. rvc sends the corrected indices after revalidation. It
  sends them in the same epoch. It does this also when the preparation for that epoch was already
  done. It does this also when the number of resolved keys does not change. If a revocation occurs
  during a preparation POST, rvc does not count that POST as done. Before Gloas, if the registry
  stays stale until the end of the epoch, the existing end-of-epoch warning names
  `PrepareProposers`. Proposals in that window use the default fee recipient of the beacon node. A
  beacon node can keep a preparation from before the revocation until that preparation expires on
  the node. The Beacon API has no "unprepare".

### Detection record: atomic create through a temp file and hard_link, non-blocking opens, temp sweep under the lock

The process creates the doppelganger detection record (`.rvc.doppelganger_record`) through a temporary file in the keystore directory.
The process publishes the complete record with a hard link.
A crash during the first write leaves no partial record at the final name.
The next boot does not exit 12 because of that partial write.
With detection on, the next boot removes stale temporary files after the lock step.
A keystore filesystem without hard links causes boot to exit 1 with detection on.
The error message names the missing hard-link support.

### Epoch boundary runner: the builder-registration step every epoch, with the 0–29 s jitter removed

#### Builder registration is re-sent every epoch

- The epoch-boundary runner re-sends the validator registration of each builder key in every epoch. It sends the registration at the first processed slot of each epoch. No random delay (jitter) comes before it.
- A re-send carries the cached signed registration. The service signs new keys and keys with changed fee recipients or gas limits.
- From the next epoch, the service removes a key whose `builder_proposals` flag is off. The relay keeps its registration of that key. When the flag returns to true, the service signs the key again.
- The runner retries a failed registration at the next slot of the same epoch, with no new signature. One registration round has a time budget of 10 s, plus one `validator_registration_batch_delay` for each batch after the first.
- Each epoch sends one registration POST for each batch of `validator_registration_batch_size` keys.
- The runner also makes the proposer preferences broadcast (Gloas-1 and later), one time per epoch, with no random delay. One preferences attempt has a time budget of 10 s.

*Changed by #1007 (W4-E6b1): the proposer preferences step no longer makes one attempt per epoch. An attempt that fails or reaches its 10 s budget runs again at the next processed slot, until the beacon node accepts both broadcasts.*

### Detection record: a reused clear record is checked for owner and mode and fsynced again before signing

With doppelganger detection on, boot checks each reused detection record for owner and mode.
Boot then fsyncs the record and the keystore directory again.
Boot refuses to start with exit 1 until you fix a record with either condition:

- Another user owns the record.
- Group or other permission bits let another user access the record.

This includes a record that another user can read.
The error names these items:

- The record path.
- The uid or mode that boot finds.
- The required owner and mode.

Change the owner to the process user. Set mode 0600.
If an upgrade changes the container user, change the record owner before you start the new version.
Boot does not write the record during this check.

### Epoch boundary runner: proposer preferences from Gloas−1 with a per-slot retry and runner-fetched proposer duties

The validator client now sends the Gloas proposer preferences and builder preferences from the epoch before Gloas, and it retries them at each slot until the beacon node accepts them. Before this change, one failed attempt left the proposals of that epoch without preferences. On a cold start, the client first fetches the proposer duties that it needs, and it does not count an empty send as done.

### Detection record: clear-detection replaces an unparseable regular record; the refusal prints the clear hint

`rvc doppelganger clear-detection` now replaces a regular record that does not parse.
This includes a truncated, zero-filled, torn, or newer-format record.
The command holds the keystore lock and makes the force-window file durable first.
The next start runs a full forward window.

The command writes and fsyncs a clear temp record.
It then exchanges that file with the old record in one atomic step and fsyncs the directory.
If the record changes after the command reads it, or if the command cannot read it, the record and the marker stay.
The replace needs Linux. On another platform, the command refuses the replace.

The command leaves these entries unchanged at `.rvc.doppelganger_record`:

- A symlink.
- A directory.
- A FIFO.

For these entries, the error names the path. The marker stays. Do these steps:

1. Stop the process.
2. Remove the named entry. Use `rm` for a symlink or a FIFO. Use `rmdir` for an empty directory. Examine a directory that is not empty before you remove it.
3. Run the command again.

```bash
rm /var/lib/rvc/keystores/.rvc.doppelganger_record      # a symlink or a FIFO only
rmdir /var/lib/rvc/keystores/.rvc.doppelganger_record   # an empty directory only
rvc doppelganger clear-detection --datadir /var/lib/rvc/keystores --confirm
```

Do not remove a valid `detected` record by hand. That action skips the force-window file.
The boot refusal of a record that does not parse now gives the `clear-detection` command.
Boot still exits 12 for that record.

### Proposer preferences: one admission fence taken before reading duties and passed through both broadcasts

#### Gloas proposer preferences use one beacon-node admission per attempt

From the epoch before Gloas, the epoch-boundary runner signs and sends the proposer preferences and the builder preferences of the local proposals. Each attempt now takes one beacon-node admission before it reads the cached proposer duties. It signs each preference of the attempt under that admission. The runner signs Gloas proposer preferences only while the beacon node that served the duties is still admitted. When that node is revoked during an attempt, rvc does not sign the remaining preferences of the attempt. The step fails. It runs again at the next slot, with a new admission and with duties that rvc fetches again.

With no admitted node, the step does these three actions:

- It logs one warning with this message:
  `skipping builder preference sign: beacon node admission revoked`
- It signs nothing.
- It retries at the next slot.

### Fallback marker: one owned file per slashing database, refused at boot and cleared only by its own keystore

**Fallback detection marker: one file for each slashing database.** If the keystore and database directories differ, the drain can write the marker beside the database. The file name is `.rvc.doppelganger_detected.<db file name>`. The file records the keystore path. Boot stops with exit code 12 if it finds the owned file or the legacy file `.rvc.doppelganger_detected`. The writes and clears of these files in one directory hold the lock file `.rvc.doppelganger_lock`. `rvc doppelganger clear-detection --datadir <keys> --slashing-db-path <db> --confirm` removes the owned file only when it belongs to `--datadir`. It keeps a file that belongs to another keystore and prints its path and owner. If the owned file cannot be read, does not parse, or records no owner, or if a legacy file exists, the command stops and prints the path. Before you remove that file, stop each validator client whose slashing database is in that directory. Make sure that its validators do not run in another place. Remove the file. Run the clear command for each of those clients before it starts again. Boot refuses a slashing database file name that starts with `.rvc.doppelganger` (exit code 1). Unless boot can show that the database directory is the keystore directory, boot also refuses these paths (exit code 1): a file name longer than 228 bytes, a missing database directory, a symlink or a `..` in the directory path, a database file that is a symlink, and a database file with more than one hard link. A symlink in the directory path is refused also when it points to the keystore directory. Use the real path of the database. For a bare file name such as `slashing.sqlite`, the marker is in the working directory. The file records the keystore path as given, made absolute, so give `--datadir` with the same path as the validator client.

**Migration:** Do not install an older release until you clear the detection. An older release does not read the owned fallback name. If both keystore writes fail, the owned fallback can be the only detection record.

### Detection refusal: the exact clear command on every branch, a fallback-dir probe, and a bare DB file name

#### Boot refusal prints the exact clear-detection command

Boot refuses to start if it finds detection evidence. The log prints the exact clear-detection
command for the configured keystore and slashing database, for example
`rvc doppelganger clear-detection --datadir '/var/lib/rvc/keystores' --slashing-db-path
'/var/lib/rvc/slashing_protection.sqlite' --confirm`. Each path is absolute and in single quotes,
so you can run the command from any working directory, also when a path has a space or a shell
character. If a path is not valid UTF-8 or has a control character, the log gives no command:
type each path yourself. Every refusal prints this text: a keystore marker that is present,
corrupt or unreadable, the fallback marker beside the slashing database (owned or legacy name), a
`detected` record, and a record that does not parse. Before, some of these logs printed
`<data dir>` / `<slashing db>` placeholders and some printed no command.

With doppelganger detection enabled, startup now also tests the slashing database directory when
it is not the keystore directory. The shutdown drain writes the fallback marker there when the
keystore write fails. If that directory cannot take a durable test write, startup exits 1 and the
error names the directory. A setup whose database directory is read-only to the process now
refuses to start with detection enabled. Such a setup already failed at the first database write.

A bare database file name (`--slashing-db-path slashing.sqlite`) now gets the fallback marker in
the working directory, the same as `./slashing.sqlite`.

*Changed by #1020 (W4-D3b): the shutdown drain writes the fallback marker in each round, not only when the keystore write fails.*

### Liveness loop starts after the last fallible boot step, with SIGINT/SIGTERM handlers installed first

**Doppelganger: the liveness loop starts after the last boot step that can fail.** The liveness loop now starts after the last boot step, and the `SIGINT` and `SIGTERM` handlers are installed just before it starts. Before this change, the loop started in boot step 6. A later boot error (the remaining services, the keymanager API, the background tasks or the epoch-boundary runner) returned without the shutdown drain. A detection that the loop had latched was then not written, and the next start gave the detected key a fresh window. A `SIGINT` or `SIGTERM` that came after the loop started and before the drain listened had the default action and stopped the process without the drain. Now no boot step can fail after the loop starts, and both signals go to the drain. Before handler installation, the operating system stops the process when it receives either signal. The loop cannot set the latch during those boot steps. If the process cannot install the handlers, boot stops with exit 1 before the loop starts. If boot fails after it starts its tasks, it stops those tasks before it returns the error. With doppelganger detection on, the startup probe of the HTTP remote signer does not sign with a loaded key. The probe then reports each Gloas sign type as unknown.

### Detection drain pins: loop fsync failure, both paths down then recovered, drain counter, ARCH-2h sleep count

A restarted container finds that record or marker and exits 12 again.

### Detection persist: one shared persist that tries every path, used by the drain, with every failure logged

The drain attempts each configured detection path in each round. It logs each failed path with its error. `rvc_doppelganger_marker_write_failures_total` counts each failed path attempt. A round can add up to three.

*Changed by #1039 (W4-D3d2): the drain writes each path on its own blocking thread and waits at most 5 s for each path. A path whose earlier write still runs gets no new write in that round, and the drain logs and counts it as a failed path.*

### Detection persist: the running liveness loop uses the shared persist and writes the fallback marker

The running liveness loop also writes the fallback marker beside the slashing database, as well as the record and the marker in the keystore directory. It writes all three on each attempt. It requests exit 12 after these writes are complete and at least one of them is durable (the write and its fsync returned `Ok`). A keystore volume that fails no longer keeps the process up with no durable latch when the database directory can still be written. The loop logs each failed path at the error level with its `path`, its `error` and `context="liveness loop"`. It increments `rvc_doppelganger_marker_write_failures_total` one time for each failed path, as the shutdown drain does. The loop now also logs and counts a failed marker write when the record write succeeds. One attempt can add up to 3 to the counter. A loop with no keystore directory adds 1 for each attempt. The loop log line "failed to persist doppelganger detection marker; staying up and retrying" is replaced by "failed to persist the doppelganger detection on this path".

*Changed by #1039 (W4-D3d2): the loop waits at most 5 s for each path and does not write a path again while its earlier write still runs. It requests exit 12 when each path has returned or timed out and at least one path is durable.*

## Committee subscriptions: selection proofs signed concurrently (at most 32 at a time) and POSTed in chunks of 512

### Part 1 of 3 (#1043): signing and chunks

Committee subscriptions sign up to 32 selection proofs at a time. The cap is the lower value of 32 and `[duties] duty_dispatch_concurrency` (default 32). An operator who lowered it for a remote signer gets the lower value. The subscriptions go to the beacon node in chunks of 512 per POST, with a maximum of 4 chunks of one epoch in flight at the same time. If one chunk fails, the client still sends the other chunks. The step tries again in the next slot and sends only the chunks that no beacon node accepted. If a beacon node loses its admission during the pass, the client starts no new subscription POST from that pass, and the step tries again with current duties. A POST that is on the network at that time can complete. A selection proof that is in flight when a key is disabled or a beacon node loses its admission is not kept. Committee subscriptions and aggregation use the same selection proof from the selection-proof cache. For this reason, a retry or an aggregation does not sign it again. In a test with 2,000 keys and a signer that takes 2 ms, the subscriptions of one epoch take less than 1 s, not 4 s.

### Part 2 of 3 (#1044): the fenced subscription POST in the beacon-node pool

Committee subscriptions: if a beacon node loses its admission during a subscription pass, the client starts no new subscription request of that pass. This applies to each beacon node. It also applies to a request that waits for a send permit, for an earlier beacon node, or for a retry, and to a request to the beacon node whose admission is revoked. The send then fails with "beacon node admission revoked", also when an earlier beacon node gave a different error, and also when a request that started before the revocation fails or times out after it. These requests follow no HTTP redirect: a 3xx response is an error of that beacon node.

Limit: the client checks the admission just before it sends each request. A revocation after that check does not stop the request. The request is then on the network, and the beacon node can accept it.

The beacon node pool keeps a maximum of 8 subscription requests active at one time, for all beacon nodes. This is also the maximum with more than 8 beacon nodes. The other subscription requests wait in a queue in the client. A request in this queue has no connection to a beacon node. A slow beacon node then delays the later subscription requests.

A subscription request that fails after a revocation does not count against the health of a beacon node. The logs and the errors of these requests show only the HTTP status and the error class, not the response text of the beacon node.

### Part 3 of 3 (#1046): the admission and store check at the backend sign

The VC signer now checks the beacon admission and the validator store `enabled` flag just before each backend sign, and again when the backend returns. Each check reads the admission again after the store read. The check just before the backend call is the start boundary. A key that the store disables, or an admission that moves, before that check gets no signature, and the signer does not call the backend. A change that completes after that check is a change during the backend call: the backend can get the call (also a remote request that the client has queued or sent), but the signer drops the signature and returns the refusal (`BlockedByDoppelganger` for the store, `BeaconAdmissionRevoked` for the admission). The check after the backend returns reads the store flag at that time, so a disable and an enable of the key before the backend returns do not drop the signature. The use boundary is the time when the signer returns the signature. A slashable sign keeps its reserved row after a store refusal or a dropped signature. It deletes the row that it inserted after an admission refusal before BLS, as before, also when the store disabled the key at the same time. A voluntary exit does not read the store flag. A `SignerService` with no store gate, and signer-server, do not change.

## Committee subscriptions: the runner remembers subscribed epochs, sends E+1 first, and subscribes from its own fetched duties on a cold cache

Committee subscriptions are sent for the next epoch first, and then for the current epoch. The subnets of the next epoch need the most lead time, and at a start in the middle of an epoch, the current epoch is partly in the past. An epoch already sent is not sent again: when an epoch starts, the client does not send again the subscriptions that it sent for that epoch one epoch before. The client sends an epoch again after a failed POST, after a beacon node loses its admission, and after a change in the number of keys with a validator index. On a cold start, the client sends the subscriptions from the duties that it fetches itself. It does not wait for the duty warm-up.

## Detection persist: the loop and the drain write through the off-runtime persister, so a hung keystore mount still reaches the fallback and the process still exits 12

- Doppelganger detection: the liveness loop and the shutdown drain now write the detection record, the keystore marker and the fallback marker each on its own blocking thread, with a 5 s timeout for each path. A hung keystore mount no longer stops the fallback marker beside the slashing database or exit 12. After shutdown, rvc waits at most 2 s for blocking work that is still stuck, then it exits with its exit status. A write that is stuck in an uninterruptible kernel wait can still delay the exit status. When keystore locking is enabled (the default), rvc keeps the keystore lock on exit 12 until the process ends, so `rvc doppelganger clear-detection` cannot run while an old detection write can still change the keystore directory.

## Sync-committee subscriptions: the runner step, runner-fetched period duties, a prefetch of 4 epochs, and the `slot + 1` duty lookup

rvc now sends sync-committee subscriptions to its beacon nodes, so that the beacon nodes join the sync-committee subnets of the local validators. In each epoch, rvc sends them for the local members of the current sync-committee period. In the last 4 epochs of a period, it also sends them for the local members of the next period. Each subscription is valid until the end of its period. On a cold start, rvc fetches the sync-committee duties that it needs itself, and it does not wait for the duty warm-up. The warm-up now gets the duties of the next period 4 epochs before the period ends (before, 2 epochs). At the last slot of a period, the incoming sync committee signs the sync-committee messages and contributions, as the specification requires. Before this change, the outgoing committee signed them at that slot.

## Detection drain: back-off, one up-front error, repeated-signal log, and latch and durability gauges

**Doppelganger shutdown drain: back-off, one up-front error, repeated-signal warnings and a durability gauge.** When the detection latch is set and no detection record is durable yet, the drain does not exit and writes again. The wait between two failed rounds is now 1 s, then two times the wait before it, up to 30 s (1, 2, 4, 8, 16, 30, 30 … s). It was a fixed 1 s. Before the first wait, the drain logs one error with the keystore directory and the fallback marker path: "will not exit until a detection record is durable; SIGKILL now loses the latch; watch the logs, metrics are not served during shutdown". Each SIGINT or SIGTERM during a wait gives one warning, "shutdown already in progress; not exiting until a detection record is durable", and the drain continues. It does not exit on a repeated signal. The drain now sets `rvc_doppelganger_detection_latch` to 1 when it sees the latch. The new gauge `rvc_doppelganger_detection_durable` is 0 when the liveness loop starts and 1 after a write of the detection and its fsync returned `Ok`, in the loop or in the drain. The metrics server does not run during the drain, so a scrape cannot read these values or `rvc_doppelganger_marker_write_failures_total` then. Watch the logs during shutdown.

## Corrections to the v0.9.0 notes

The items below give the correct text for parts of the v0.9.0 release notes that do not agree with the code or that a W4.4 note replaces.

1. **W4-E5 (#959): the time budget of a registration round.** Section: "Builder registrations: cache signed registrations, re-send each epoch, re-sign only changes, evict flag-off keys, report failed batches, apply the batch knobs". This v0.9.0 text is not correct:

   > Until W4-E6a, a single registration round is still cut at 10 s. At the defaults, a round can send at most about 20 batches (about 10,000 builder keys) before that cut. Batches already sent stay registered, and the keys the cut left out are sent in a later round.

   W4-E6a (#1005) removed the fixed 10 s cut. One registration round now has the budget `registration_step_timeout()`: 10 s, plus one `validator_registration_batch_delay` for each batch after the first. Thus the limit of about 20 batches at the defaults does not apply. A round that fails or reaches its budget runs again at the next processed slot of the same epoch, with the cached signatures. See "Epoch boundary runner: the builder-registration step every epoch, with the 0–29 s jitter removed".

2. **W4-E4c (#994): a batch that the relay refuses.** Section: "Startup preparation is the boot epoch of the epoch-boundary task". This v0.9.0 text is not correct:

   > A batch that the relay refuses still reports success, so the boot epoch does not send it again.

   After W4-E6a (#1005), a refused batch is an error. The runner logs the WARN `Epoch builder registration failed`, with the error `<failed> of <total> builder registration batches failed`. The `BuilderRegistration` step is then `Failed`. It runs again at the next processed slot of the same epoch, with no new signature. The step runs in every epoch, not only in the boot epoch.

3. **W4-E7d (#986): the gate of proposer preparation.** Section: "Index registry: stamped with the revocation generation it was validated under; revalidated after a revocation". This v0.9.0 text is not correct:

   > Proposer preparation is gated by a follow-up change (W4-E7e).

   W4-E7e merged in #1000. While the index registry is stale after a revocation, rvc sends no `prepare_beacon_proposer` POST. After the indices pass the re-check, rvc sends the corrected indices in the same epoch. See "Proposer preparation: no POST from an index registry that went stale after a revocation; re-sent once the indices are re-checked".

4. **W4-E2b (#969): the steps of the epoch-boundary runner.** Section: "Epoch boundary runner: its own Orchestrator-tier task, woken by every processed slot, boot epoch included". This v0.9.0 text names four steps:

   > Epoch-boundary work now runs on its own task at the first processed slot of every epoch, including the epoch the validator client starts in: the circuit-breaker reset, the reorg check, `prepare_beacon_proposer`, and committee subscriptions for the current and next epoch.

   The runner now has eight steps. It runs them in this order:

   1. `BreakerReset`: the circuit-breaker reset.
   2. `ReorgCheck`: the reorg check.
   3. `DutyFetch`: the fetch of the attester, proposer and sync-committee duties that are not in the cache.
   4. `PrepareProposers`: the `prepare_beacon_proposer` POST.
   5. `CommitteeSubscriptions`: the committee subscriptions of the next epoch, then of the current epoch.
   6. `SyncCommitteeSubscriptions`: the sync-committee subscriptions (W4-E9b, #1048).
   7. `BuilderRegistration`: the builder registration, in every epoch (W4-E6a, #1005).
   8. `ProposerPreferences`: the Gloas proposer and builder preferences, from the epoch before Gloas (W4-E6a, #1005, and W4-E6b1, #1007).

5. **W4-D1d (#1010): the paragraph on a broken record.** Section: "Doppelganger detection stops the process". The text of the section "Detection record: clear-detection replaces an unparseable regular record; the refusal prints the clear hint" above replaces the v0.9.0 paragraph that starts "If the record is not a regular 4096-byte file".

6. **W4-D2b (#1016): item 746-6.** Section: "Doppelganger detection stops the process". The W4-D2b PR body changes this v0.9.0 sentence:

   > Restart-skip and a keymanager import cannot skip the
   > forward window while a marker is present or the record is `detected`.

   The new sentence is:

   > Restart-skip and a keymanager import cannot skip
   > the forward window while a marker is present, and a `detected` record stops boot before any key is
   > registered.

7. **W4-D2b (#1016): item 748-2.** Section: "Doppelganger detection stops the process". The W4-D2b PR body gives this change:

   > The first clear example and the `rm …/.rvc.doppelganger_record` recipe gain
   > `--slashing-db-path`:

   The v0.9.0 text has this first clear example:

   ```bash
   rvc doppelganger clear-detection --datadir /var/lib/rvc/keystores --confirm
   ```

   The new example is:

   ```bash
   rvc doppelganger clear-detection \
     --datadir /var/lib/rvc/keystores \
     --slashing-db-path /var/lib/rvc/slashing_protection.sqlite \
     --confirm
   ```

   The v0.9.0 text has this `rm` recipe:

   ```bash
   rm /var/lib/rvc/keystores/.rvc.doppelganger_record
   rvc doppelganger clear-detection --datadir /var/lib/rvc/keystores --confirm
   ```

   The new recipe is:

   ```bash
   rm /var/lib/rvc/keystores/.rvc.doppelganger_record
   rvc doppelganger clear-detection \
     --datadir /var/lib/rvc/keystores \
     --slashing-db-path /var/lib/rvc/slashing_protection.sqlite \
     --confirm
   ```

8. **W4-D3a (#1018): item 748-4.** Section: "Doppelganger detection stops the process". The W4-D3a note replaces this v0.9.0 sentence in the paragraph that starts "A false positive is an outage for every validator this process runs.":

   > A restarted container finds that record and exits 12 again.

   The new sentence is:

   > A restarted container finds that record or marker and exits 12 again.

9. **W4-D3e (#1049): the advice on the failure counter during the drain.** Section: "Doppelganger detection stops the process". This v0.9.0 sentence is in the text about the shutdown drain, and it is not correct:

   > Do not stop the node while that failure counter is rising.

   The metrics server does not run during the drain, so a scrape cannot read `rvc_doppelganger_marker_write_failures_total` then. Watch the logs for the line "will not exit until a detection record is durable". After that line appears, do not stop the node until it exits 12. See "Detection drain: back-off, one up-front error, repeated-signal log, and latch and durability gauges".

   The same advice at the end of the paragraph that starts "A false positive is an outage for every validator this process runs." stays. That paragraph is about the running process, and the metrics server runs then.

## W4.4 migration: changes and steps for operators

These changes can stop a start, refuse a command, or change a log line or a metric that a script reads. Each item names the section above that describes it. The code of items 1 to 7 is already in v0.9.0. Their sections are under "Shipped in v0.9.0 without a release note".

With doppelganger detection on, boot has four new refusals with exit code 1:

| Item | Boot exits 1 when | Operator action |
|---|---|---|
| 1 | The keystore filesystem has no hard links. | Put the keystore directory on a filesystem that supports hard links. |
| 2 | A reused detection record has the wrong owner or mode. | Change the owner to the process user. Set mode 0600. |
| 3 | The slashing database path breaks a path rule. | Use the real path of the database. |
| 4 | The slashing database directory cannot take a durable test write. | Give the process write access to the slashing database directory. |

1. **Boot exits 1 when the keystore filesystem has no hard links.** Section: "Detection record: atomic create through a temp file and hard_link, non-blocking opens, temp sweep under the lock". With doppelganger detection on, the keystore filesystem must support hard links. Else boot exits 1, and the error names the missing hard-link support.
   Operator action: before you upgrade, make sure that the keystore filesystem supports hard links. Read the "Shutdown" section of `docs/running-guide.md` for the detection files.
2. **Boot exits 1 when a reused detection record has the wrong owner or mode.** Section: "Detection record: a reused clear record is checked for owner and mode and fsynced again before signing". With doppelganger detection on, boot refuses a record that another user owns or that group or other permission bits let another user access. The error names the record path, the uid or mode that boot finds, and the required owner and mode. Change the owner to the process user. Set mode 0600. If an upgrade changes the container user, change the record owner before you start the new version.
3. **Boot exits 1 for some slashing database paths.** Section: "Fallback marker: one owned file per slashing database, refused at boot and cleared only by its own keystore". Boot refuses a slashing database file name that starts with `.rvc.doppelganger`. Unless boot can show that the database directory is the keystore directory, boot also refuses these paths:
   - A file name longer than 228 bytes.
   - A missing database directory.
   - A symlink or a `..` in the directory path, also a symlink that points to the keystore directory.
   - A database file that is a symlink.
   - A database file with more than one hard link.

   Use the real path of the database.
4. **Boot exits 1 when the slashing database directory cannot take a test write.** Section: "Detection refusal: the exact clear command on every branch, a fallback-dir probe, and a bare DB file name". With doppelganger detection on, startup tests the slashing database directory when it is not the keystore directory. If that directory cannot take a durable test write, startup exits 1, and the error names the directory. A database directory that is read-only to the process now stops the start.
   Operator action: before you upgrade, make sure that the process can write to the slashing database directory. Read the "Shutdown" section of `docs/running-guide.md` for the detection files.
5. **Do not install an older release until you clear the detection.** Section: "Fallback marker: one owned file per slashing database, refused at boot and cleared only by its own keystore". An older release does not read the owned fallback name. If both keystore writes fail, the owned fallback can be the only detection record.
6. **The fallback marker has a new name, and `clear-detection` removes only the file of its own keystore.** Section: "Fallback marker: one owned file per slashing database, refused at boot and cleared only by its own keystore". The fallback marker beside the slashing database is now `.rvc.doppelganger_detected.<db file name>`, and the file records the keystore path. The running liveness loop also writes it (see "Detection persist: the running liveness loop uses the shared persist and writes the fallback marker"). Boot stops with exit code 12 if it finds the owned file or the legacy file `.rvc.doppelganger_detected`.
   - Pass `--slashing-db-path` to `rvc doppelganger clear-detection`. When the database is in the keystore directory, the option has no effect.
   - Give `--datadir` with the same path as the validator client.
   - The command stops and prints the path when the owned file cannot be read, does not parse, or records no owner, or when a legacy file exists. Then do these steps:
     1. Stop each validator client whose slashing database is in that directory.
     2. Make sure that its validators do not run in another place.
     3. Remove the file.
     4. Run the clear command for each of those clients before it starts again.

   Before you remove a legacy file, make sure that no client uses that directory as its keystore directory. A keystore marker has the same name.
7. **The recovery steps for a broken detection record change.** Section: "Detection record: clear-detection replaces an unparseable regular record; the refusal prints the clear hint". `rvc doppelganger clear-detection` now replaces a regular record that does not parse. The command can replace the record only on Linux. On another platform, it refuses to replace it. For a symlink, a directory or a FIFO at `.rvc.doppelganger_record`, the command leaves the entry and the marker. Do the three steps of that section. Do not remove a valid `detected` record by hand.
8. **`[duties] duty_dispatch_concurrency` also limits the selection proofs that committee subscriptions sign at one time.** Section: "Committee subscriptions: selection proofs signed concurrently (at most 32 at a time) and POSTed in chunks of 512". Committee subscriptions sign at most the lower value of 32 and `[duties] duty_dispatch_concurrency` (default 32) selection proofs at a time. If you lowered `duty_dispatch_concurrency` for a remote signer, the subscriptions use that lower value.
9. **The validator client sends more POSTs to the beacon node in each epoch.**
   - Section: "Epoch boundary runner: the builder-registration step every epoch, with the 0–29 s jitter removed". The runner re-sends the registration of each builder key in every epoch. Each epoch sends one registration POST for each batch of `validator_registration_batch_size` keys. The batch settings now set the number of POSTs in each epoch.
   - Section: "Sync-committee subscriptions: the runner step, runner-fetched period duties, a prefetch of 4 epochs, and the `slot + 1` duty lookup". The runner sends sync-committee subscriptions in every epoch. The beacon node must serve the standard Beacon API endpoint `POST /eth/v1/validator/sync_committee_subscriptions`.
   - Section: "Committee subscriptions: selection proofs signed concurrently (at most 32 at a time) and POSTed in chunks of 512". Committee subscriptions go to the beacon node in chunks of 512 for each POST, with a maximum of 4 chunks of one epoch in flight at the same time.

   Operator action: examine `validator_registration_batch_size` and `validator_registration_batch_delay`, because these settings now apply. Make sure that each beacon node serves the standard Beacon API endpoints for these POSTs.
10. **Committee subscription requests follow no HTTP redirect.** Section: "Committee subscriptions: selection proofs signed concurrently (at most 32 at a time) and POSTed in chunks of 512". A 3xx response to a committee subscription request is an error of that beacon node.
   Operator action: make sure that each beacon node URL answers the standard Beacon API endpoints itself, with no redirect.
11. **New and changed log lines and metrics.** Detection failures are now visible in the logs and the metrics.
    Operator action: update the alerts and the queries that read the items below. Read the "Shutdown" section of `docs/running-guide.md`.
    - Section: "Proposer preferences: one admission fence taken before reading duties and passed through both broadcasts". New WARN when no beacon node is admitted for a preferences attempt: `skipping builder preference sign: beacon node admission revoked`. The step then retries at the next slot.
    - Section: "Detection refusal: the exact clear command on every branch, a fallback-dir probe, and a bare DB file name". Each boot refusal for detection evidence now prints the exact `rvc doppelganger clear-detection` command, with absolute paths in single quotes. The `<data dir>` and `<slashing db>` placeholders are gone.
    - Section: "Detection persist: the running liveness loop uses the shared persist and writes the fallback marker". The loop log line "failed to persist doppelganger detection marker; staying up and retrying" is replaced by "failed to persist the doppelganger detection on this path". Match the new line.
    - Section: "Detection persist: one shared persist that tries every path, used by the drain, with every failure logged". `rvc_doppelganger_marker_write_failures_total` counts each failed path, in the drain and in the running liveness loop. One drain round or one loop attempt can add up to 3.
    - Section: "Committee subscriptions: selection proofs signed concurrently (at most 32 at a time) and POSTed in chunks of 512". The logs and the errors of committee subscription requests show only the HTTP status and the error class, not the response text of the beacon node.
    - Section: "Detection drain: back-off, one up-front error, repeated-signal log, and latch and durability gauges". Before the first drain wait, the drain logs one error: "will not exit until a detection record is durable; SIGKILL now loses the latch; watch the logs, metrics are not served during shutdown". Each SIGINT or SIGTERM during a wait logs one warning: "shutdown already in progress; not exiting until a detection record is durable". The new gauge `rvc_doppelganger_detection_durable` is 1 after a durable detection write. The drain now sets `rvc_doppelganger_detection_latch` to 1.
12. **During the shutdown drain, watch the logs, not the metrics.** Section: "Detection drain: back-off, one up-front error, repeated-signal log, and latch and durability gauges". The metrics server does not run during the drain. A scrape cannot read `rvc_doppelganger_marker_write_failures_total` or the two gauges then. Watch the logs for the line "will not exit until a detection record is durable". After that line appears, do not stop the node until it exits 12. The wait between two failed drain rounds now grows from 1 s to 30 s.

Operators do not need to make changes for the items below:

- While the index registry is stale after a revocation, rvc sends no `prepare_beacon_proposer` POST. It sends the corrected indices in the same epoch (W4-E7e).
- The builder registration goes out at the first processed slot of each epoch, with no random delay. The service signs only new or changed keys (W4-E6a).
- From the epoch before Gloas, the proposer preferences retry at each slot, under one beacon-node admission for each attempt (W4-E6b1, W4-E6b2).
- Committee subscriptions go for the next epoch first. An epoch already sent is not sent again. Aggregation uses the same cached selection proof (W4-E8b, W4-E8c).
- At the last slot of a sync-committee period, the incoming committee signs. The warm-up gets the duties of the next period 4 epochs before the period ends (W4-E9b).
- A crash during the first record write leaves no partial record. With a bare database file name, the fallback marker is in the working directory (W4-D1b, W4-D2a).
- The liveness loop starts after the last boot step that can fail. If the process cannot install the signal handlers, boot stops with exit 1. With detection on, the HTTP remote-signer probe reports each Gloas sign type as unknown (W4-D2c).
- Each detection path is written on its own blocking thread, with a 5 s timeout. On exit 12, rvc keeps the keystore lock until the process ends (W4-D3d2).
