# Validators Config Reference

> Per-validator overrides (fee recipient, gas limit, graffiti, builder settings) for the rvc Validator Client.

## Overview

Unknown keys in `config.toml` and in the validators file fail startup.

`validators_config` is a separate TOML file (not the main `config.toml`) that holds:

- **Global defaults** — fee recipient, gas limit, graffiti applied to every validator that doesn't override them.
- **Per-validator overrides** — one `[[validators]]` entry per BLS pubkey, overriding any subset of the defaults plus builder/block-selection settings that have no global equivalent.

It is loaded by `ValidatorStore::load_from_config` (`crates/validator-store/src/store.rs:88`), a component independent of the main `Config` struct — the main config only stores the *path* to this file.

**Enabling it:**

```bash
rvc start -c config.toml --validators-config validators.toml
```

or in `config.toml`:

```toml
validators_config = "./validators.toml"
```

A ready-to-copy sample lives at [`validators.example.toml`](../validators.example.toml) (repo root, alongside [`config.example.toml`](../config.example.toml)).

### This file is effectively mandatory

`rvc` has **no top-level fee recipient setting**. On startup, `ServiceBuilder::build_validator_store` (`crates/rvc/src/config/builder.rs:317-333`) refuses to start if the effective default fee recipient is the zero address:

```
default_fee_recipient is the zero address
(0x0000000000000000000000000000000000000000), which routes all EL
fees and MEV rewards to the burn address.
Set a non-zero fee_recipient in your validators config file:

[defaults]
fee_recipient = "0x<your-fee-address>"

Pass the file with --validators-config <path>.
```

If `--validators-config` / `validators_config` is omitted entirely, the store is constructed with a zero-address default (`ValidatorStore::new([0u8; 20], 30_000_000)`) and the same check fails. A minimal file with just a `[defaults]` table (no `[[validators]]` entries) is sufficient to boot.

---

## File format

```toml
[defaults]
fee_recipient = "0xYourFeeRecipientAddress0000000000000000"
gas_limit = 30000000
graffiti = "rvc"

[[validators]]
pubkey = "0xabc123...48-byte-BLS-pubkey..."
fee_recipient = "0xOverrideAddress0000000000000000000000"
gas_limit = 36000000
builder_proposals = true
builder_boost_factor = 90
graffiti = "custom"
enabled = true
block_selection_mode = "execution-only"

[[validators]]
pubkey = "0xdef456..."
# no overrides — inherits every [defaults] value
```

### `[defaults]`

| Key | Type | Default if omitted | Notes |
|---|---|---|---|
| `fee_recipient` | string | `0x0000...0000` | 20-byte hex address, `0x` prefix optional, case-insensitive. Startup fails if this resolves to the zero address (see above). |
| `gas_limit` | integer | `30000000` | Execution-layer gas limit target passed to the builder/EL. |
| `graffiti` | string | none (empty) | UTF-8 string. **Silently truncated to 32 bytes** if longer (byte-level truncation via `parse_graffiti`, `store.rs:435-440`) — unlike the HTTP API, which rejects oversized graffiti with `400` instead of truncating. |

There is no `block_selection_mode` key under `[defaults]`. The CLI flag `--block-selection-mode` and the top-level TOML key `block_selection_mode` (on the rvc config, not in this file) set the global default. A per-validator `block_selection_mode` still wins. `ValidatorStore::set_global_block_selection_mode` sets the same global. When the flag and the TOML key are both unset, the global default is `max-profit`.

### `[[validators]]`

| Key | Type | Required | Default if omitted | Notes |
|---|---|---|---|---|
| `pubkey` | string | **yes** | — | 48-byte BLS pubkey hex, `0x` prefix optional. Used as the table key for lookups (all HTTP/Rust APIs address validators by this value). |
| `fee_recipient` | string | no | inherits `[defaults].fee_recipient` | Same format/validation as above. |
| `gas_limit` | integer | no | inherits `[defaults].gas_limit` | |
| `builder_proposals` | bool | no | `false` | Whether this validator opts in to builder (MEV-boost) block production at all. No global default — off unless explicitly enabled per validator. See [Builder flag, boost, and what the relay keeps](#builder-flag-boost-and-what-the-relay-keeps). |
| `builder_boost_factor` | integer | no | `100` | Weight applied to a blinded block when beacon nodes are ranked against each other. A local block keeps its raw value. `0` ranks every local block above every blinded block. `u64::MAX` ranks every blinded block above every local block. |
| `graffiti` | string | no | inherits `[defaults].graffiti` | Same truncation behavior as above. |
| `enabled` | bool | no | `true` | Master per-validator signing gate — `false` blocks all attesting/proposing for this key. Unknown pubkeys (not listed here and not loaded from a keystore) are treated as `enabled = false` (fail-closed). |
| `block_selection_mode` | string | no | the global default set by `--block-selection-mode` or the top-level TOML key `block_selection_mode` (`max-profit` when both are unset) | One of `max-profit`, `execution-only`, `builder-always`, `builder-only` (kebab-case; no-hyphen spellings like `executiononly` also parse). A per-validator value wins over that global default. See below. |

**Malformed entries fail the whole file:** an invalid hex string/length in any `fee_recipient` or `pubkey` (defaults or per-validator) makes `load_from_config` return an error and the process refuses to start — there's no partial/best-effort loading of a broken file.

**Unknown keys fail closed.** A key that is not in the tables above, including `enable = false` (the field is `enabled`), fails startup. The error names the key and the validators file. The same rejection applies inside `[defaults]` and to a misspelled table such as `[default]`. A file the store itself writes uses only these keys and reloads.

### `block_selection_mode` values

| Value | Effect |
|---|---|
| `max-profit` (default) | With `builder_proposals` on, request a builder bid and propose whichever side is worth more after the boost. With the flag off, before Gloas, the proposal is local. |
| `execution-only` | Forces `builder_boost_factor = 0` — never uses the builder. |
| `builder-always` | With the flag on, forces `builder_boost_factor = u64::MAX` and falls back to a local block if the builder fails or the circuit breaker has tripped. With the flag off, before Gloas, the proposal is local. |
| `builder-only` | Same weighting as `builder-always` but **never falls back** — the proposal fails outright if the builder is unavailable. The flag does not turn this into a local proposal. Intended for DVT clusters where a local fallback would be unsafe/incorrect. |

### Builder flag, boost, and what the relay keeps

`builder_proposals` defaults to off. Startup warns, and does not exit, when a key's effective mode is `builder-only` and that flag is off, or when that key's Gloas builder URL list is empty. The warning is once per key. The log reason is `builder_only_without_builder`. It names the truncated pubkey, whether the flag is on, and how many Gloas builder URLs the key has. It does not name a relay URL or a fee recipient.

Before Gloas, `max-profit` and `builder-always` with the flag off do not request a builder bid: the produce call uses boost 0 and accepts only a local block. `builder-only` still requests a builder block and fails the proposal when the only candidate is local. At Gloas the flag does not change the V4 boost or the builder list.

When more than one beacon node returns a block, a blinded block is ranked at `value * builder_boost_factor / 100` and a local block at its raw value. The quotient saturates at the maximum `u128`. Boost `u64::MAX` puts every blinded block ahead of every local block. Boost `0` puts every local block ahead of every blinded block. A block on the primary parent still wins before that comparison.

Setting `builder_proposals` to false does not deregister the validator at the relay and does not evict a registration this process already sent. The relay keeps that registration until a later registration update.

---

## How values are resolved (`effective_*` methods)

For any pubkey, `ValidatorStore::effective_config`/`effective_fee_recipient`/`effective_gas_limit`/`effective_graffiti`/`effective_block_selection_mode` merge the per-validator record over the global defaults in a single locked snapshot — reads are atomic with respect to concurrent writes, so a caller never sees half-updated defaults mixed with a half-updated override.

If a validator is entirely absent from this file (no `[[validators]]` entry) but was loaded from a keystore, `ServiceBuilder::register_loaded_validators` (`crates/rvc/src/config/builder.rs:350-364`) adds it to the store as `enabled = true` with no overrides at startup — otherwise the fail-closed `enabled` default would silently block every validator when no `validators_config` is supplied at all. This registration is additive/idempotent: it never overwrites a pubkey that's already tracked (e.g. explicitly `enabled = false` in the TOML, or already disabled by the doppelganger-detection window).

---

## Runtime mutation: Rust API vs. HTTP API vs. hand-editing

There are three ways this data can change while `rvc` is running, and they interact in a way that's easy to get wrong:

### 1. Keymanager HTTP API (see [`docs/keymanager-api.md`](./keymanager-api.md))

Only three fields are HTTP-writable, via `/eth/v1/validator/{pubkey}/feerecipient`, `/gas_limit`, and `/graffiti` (`GET`/`POST`/`DELETE`). Every `POST`/`DELETE` on these routes:

1. Writes the validators file first (`update_config_durable`: temp file, `fsync`, rename, then `fsync` the parent directory).
2. Publishes the same change to the live store only after that write succeeds. A failed write leaves the previous live value in place.

This means changes made through the HTTP API **persist across restarts** without needing to touch the file yourself.

**Not exposed over HTTP at all:** `builder_proposals`, `builder_boost_factor`, `block_selection_mode`, and the `enabled` flag have no HTTP setter. Hand-edit the TOML and restart, or call `ValidatorStore::update_config` / `set_enabled` if you embed the crate. A slashed-validator disable publishes `enabled = false` before it persists (see below). The doppelganger window's re-enable is written to this file before it is published.

### 2. Hand-editing the TOML file

Safe **only while the process is stopped**. There is currently no reload trigger while `rvc` is running:

- `ValidatorStore::reload_config()` exists (parses the file fresh, applies parse-first/apply-second so a broken file never partially mutates the store, and preserves any validator that was registered programmatically but isn't in the file). It refuses an unknown key, and it refuses a missing or zero `[defaults] fee_recipient`, without changing defaults, rows, or URL ownership. **Nothing in the shipped `rvc` binary calls it.** No file watcher, no HTTP endpoint, no signal handler triggers it (SIGHUP only reloads the log filter).
- Because HTTP writes call `update_config_durable`, which re-serializes from in-memory state rather than re-reading the file, a hand-edit made while the process is running can be **silently overwritten** the next time any fee-recipient/gas-limit/graffiti HTTP write fires.

**Recommendation:** treat "edit the file directly" and "use the HTTP API" as mutually exclusive while the process is live. Stop `rvc`, edit, restart — or manage everything through the Keymanager API.

### 3. `proposer_config_url` / `proposer_config_file`

These are separate, MEV-boost/Prysm-style config options (`Config.proposer_config_url`, `Config.proposer_config_file`) that parse a different JSON schema keyed by pubkey.

- `proposer_config_url` is fetched on a timer and applied to the **live** store. Each fee recipient, gas limit, and builder flag is owned on its own. When the URL starts owning a field, the baseline is that field's live value at that moment. A keymanager write of an owned field, including a write of the same value, drops ownership and becomes the new baseline in memory and in this file. A later fetch that sets the field again owns it from the value at that moment. Omitting the pubkey restores each field the URL still owns. Omitting one field while the pubkey stays in the document restores that field when the live value is still the remote one, and leaves the fields the document still sets. A successful document that omits `default_config`, or omits one of its fields, restores that default the same way. A failed fetch does not. `reload_config` keeps URL ownership for a validator that is not in the file, so a later save still writes that validator's local baseline, and drops URL ownership for validators the file replaces. A body with neither `proposer_config` nor `default_config`, or any one invalid entry, is rejected and changes nothing. One bad entry rejects the whole fetch. A document that names the same validator twice is rejected, whether the JSON key is repeated exactly or the two keys are different spellings of one pubkey (`0x` prefix and hex case). No row from that document is applied. The response body is capped at 4 MiB: a `Content-Length` above the cap is rejected before the body is buffered, and a chunked body is rejected on the chunk that would pass the cap. A body of exactly 4 MiB is accepted. The connect timeout is 10 seconds and covers DNS, TCP, and TLS. The fetch deadline is 30 seconds for DNS, connect, TLS, redirects, and the body, plus a 10 second idle gap between body chunks that re-arms on every chunk; a 4 MiB body needs about 140 KB/s. Redirects stay on the same scheme, host, and port. A cross-origin redirect, including `https` to `http`, fails the fetch. `proposer_config_refresh_interval` must be from 1 to 86400 seconds when a URL is set. 0 is accepted when no URL is configured. The interval cannot exceed 24 hours. A document with only `default_config` is accepted and does not restore omitted pubkeys. Deleting a key and importing it again drops that key's ownership record. Fields the URL still owns are not written into this file. `default_config` changes the live defaults and is not written as `[defaults]`. After a restart with the remote document gone, validators fall back to the local `[defaults]`.
- `proposer_config_file` is parsed as a config field but never read from disk by any code path.

`validators_config` and the Keymanager HTTP API remain the durable source for fee recipient, gas limit, and graffiti. Builder proposals have no HTTP setter; `ValidatorStore::update_config_durable` is the durable path. `--graffiti` is an in-memory validator-store default at startup; a per-validator `graffiti` and a keymanager-set default still win. Startup does not rewrite this file. The next keymanager save persists that in-memory default over `[defaults].graffiti`.

---

## Rust API summary (for embedders)

`ValidatorStore` (`rvc-validator-store` crate) is `Send + Sync`, normally held as `Arc<ValidatorStore>`, using `parking_lot::RwLock`/`Mutex` internally — safe to call concurrently from multiple async tasks/HTTP handlers.

| Method | Kind | Disk I/O |
|---|---|---|
| `ValidatorStore::load_from_config(path)` | constructor | reads once |
| `ValidatorStore::new(default_fee_recipient, default_gas_limit)` | constructor | none (no `config_path`; `save_config`/`reload_config` will error) |
| `effective_config` / `effective_fee_recipient` / `effective_gas_limit` / `effective_graffiti` / `effective_block_selection_mode` | read | none |
| `is_signing_enabled(pubkey)` | read | none — fail-closed: unknown pubkey → `false` |
| `list_enabled_pubkeys()` / `has_validator(pubkey)` / `get_config(pubkey)` | read | none |
| `add_validator(config)` / `remove_validator(pubkey)` / `set_enabled(pubkey, bool)` / `update_config(pubkey, update)` | write | **in-memory only** — does not persist |
| `save_config()` | write | atomically serializes the snapshot to `config_path` (temp file + `fsync` + rename). A field a proposer-config URL still owns is written as the local baseline from when the URL started owning it. A remote `default_config` is not written as `[defaults]`. Errors if `config_path` is `None` |
| `reload_config()` | write | re-reads `config_path` from disk, parse-first/apply-second; not called anywhere in the shipped binary today. An unknown key or a missing or zero `[defaults] fee_recipient` returns before any change. URL ownership is kept for validators absent from the file and dropped for validators the file replaces. Remote defaults are cleared |

`ValidatorConfigUpdate` (the argument to `update_config`) is a sparse patch: each optional field is `Option<Option<T>>` — outer `None` means "don't touch", `Some(None)` means "clear back to default", `Some(Some(v))` means "set to `v`".

---

## Full example

```toml
[defaults]
fee_recipient = "0xYourFeeRecipientAddress0000000000000000"
gas_limit = 30000000
graffiti = "rvc"

[[validators]]
pubkey = "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
fee_recipient = "0xAbcF8e0d4e9587369b2301D0790347320302cc09"
gas_limit = 36000000
builder_proposals = true
builder_boost_factor = 90
graffiti = "custom-graffiti"
enabled = true
block_selection_mode = "execution-only"

[[validators]]
pubkey = "0xa1b2c3...another-pubkey..."
# inherits all defaults, builder disabled (builder_proposals default is false)
```

## Related docs

- [`docs/keymanager-api.md`](./keymanager-api.md) — HTTP API for fee recipient / gas limit / graffiti / keystores / remote keys
- [`docs/keymanager-api.openapi.yaml`](./keymanager-api.openapi.yaml) — OpenAPI 3.0 spec for the same HTTP API
- [`docs/running-guide.md`](./running-guide.md) — CLI flags and general operation
- [`validators.example.toml`](../validators.example.toml) — copy-and-edit sample file
- [`validator-perf.md`](validator-perf.md) — estimate consensus-layer performance of these pubkeys from a beacon node

## Persist, bounds, and a missing validators file

A change that makes signing safer publishes first. `disable_slashed` and the doppelganger disable set live `enabled = false` immediately, then persist under `save_lock`. If that write fails, the validator stays disabled in memory and the error is returned. The previous file is not put back: a failure after rename already has the safer bytes on disk.

A doppelganger import hold is not an operator or slashing disable. The row stores `doppelganger_hold_until` (a unix-second deadline) beside `enabled = false`. At boot, a hold whose deadline has passed is re-enabled and the field is cleared. A hold that is still open stays disabled. When the keymanager is running, the wall-clock enable task is started again for the time left. A restart does not replay doppelganger observations. An open hold also registers the key Pending on the forward window, so voluntary exit stays blocked until that liveness window completes. Epoch 0 and a recent attestation do not skip it. Any `*.import_meta.json` sidecar does the same, including one older than the 768 second hold. The file stays until this process observes the forward window to Safe and removes it while holding the same lock DELETE and import use, so a concurrent re-import cannot lose a newer marker. A sidecar that cannot be read, a leftover `*.import_meta.json.partial`, or a leftover `*.import_meta.json.removing.*` set-aside from an older cleanup does the same. If `keystore_path` is not a readable directory, or this file cannot be read, every loaded key stays Pending for that start. A missing keystore directory has no sidecars. A row with `enabled = false` and no deadline stays disabled, and importing over that row does not arm a hold or re-enable the key. A failed re-enable is retried. The re-enable task, while holding `state_lock`, releases the key only when `doppelganger_hold_until` is still set. It does not read `key_gen`. Any disable cancels that task. DELETE cancels it before the disable write returns, including when the write fails. If that delete write fails while a hold was set, the validators file is moved off the boot path so a restart cannot reload the old hold and re-enable the key.

A change that makes signing less safe persists first, then publishes. Import, delete, enable, and the doppelganger re-enable build a candidate, write it (temp file, `fsync`, rename, parent-directory `fsync`), and only then update the live store. If the parent-directory `fsync` fails, the previous file is restored and memory is left unchanged. If that restore fails before its own rename, the validators file is moved off the boot path so the rejected document is not loaded. The `.rejected` file holds that rejected document. To recover, copy it aside, set the affected key to `enabled = false`, delete `doppelganger_hold_until`, and replace `validators.toml` with that edited file. Restoring `.rejected` unchanged puts the hold back on the boot path, and boot reconcile re-enables it. Dropping `--validators-config` builds a zero fee recipient and boot fails with `ZeroFeeRecipient`. A windowed keystore import writes `enabled = false` and the hold in one durable update before the signer is published. That import keeps the key files as `.json.partial` until the hold is durable, then renames them and `fsync`s the directory. A duplicate import deletes the keystore json it just renamed, so boot does not load it. A failed import revokes the in-memory key before those files are deleted. The revoke bumps `key_gen` so duty caches drop the key; that bump is not a check the re-enable task performs. A validators row is removed only when that admission created it. A remote import whose lifecycle write fails is reported as an error.

Keymanager fee-recipient, gas-limit, and graffiti setters use the same persist-then-publish path (`update_config_durable`). If `validators_config` is unset, the store is `ValidatorStore::new` and those setters return HTTP 500 with `no validators_config path set; the change is not persisted`. Nothing is published. Set a validators file if those routes must stick.

`gas_limit`, `min_bid`, and `builder_boost_factor` above `i64::MAX` are rejected before a write. `gas_limit` is also rejected at the keymanager API (HTTP 400) and by the proposer-config refresher. `i64::MAX` itself is accepted. TOML cannot store a larger integer.

A slashed validator (`slashed_action = "disable-only"`) is disabled in memory and then written `enabled = false`. If every save fails, the process logs the error and leaves the validator disabled in memory. If that key had a doppelganger hold, the validators file is moved off the boot path so a restart cannot re-enable it.
