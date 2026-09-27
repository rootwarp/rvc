# Validators Config Reference

> Per-validator overrides (fee recipient, gas limit, graffiti, builder settings) for the rvc Validator Client.

## Overview

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

There is **no global `block_selection_mode` key under `[defaults]`** — block selection mode can only be set per-validator (see below) or via the Rust API (`ValidatorStore::set_global_block_selection_mode`), which nothing in the shipped binary currently calls (the effective global default is permanently `max-profit`).

### `[[validators]]`

| Key | Type | Required | Default if omitted | Notes |
|---|---|---|---|---|
| `pubkey` | string | **yes** | — | 48-byte BLS pubkey hex, `0x` prefix optional. Used as the table key for lookups (all HTTP/Rust APIs address validators by this value). |
| `fee_recipient` | string | no | inherits `[defaults].fee_recipient` | Same format/validation as above. |
| `gas_limit` | integer | no | inherits `[defaults].gas_limit` | |
| `builder_proposals` | bool | no | `false` | Whether this validator opts in to builder (MEV-boost) block production at all. No global default — off unless explicitly enabled per validator. |
| `builder_boost_factor` | integer | no | `100` | Weighting used when comparing local vs. builder block value; `0` effectively disables the builder path for this validator, `u64::MAX` forces builder-always/only semantics. |
| `graffiti` | string | no | inherits `[defaults].graffiti` | Same truncation behavior as above. |
| `enabled` | bool | no | `true` | Master per-validator signing gate — `false` blocks all attesting/proposing for this key. Unknown pubkeys (not listed here and not loaded from a keystore) are treated as `enabled = false` (fail-closed). |
| `block_selection_mode` | string | no | falls back to the (currently fixed) global default `max-profit` | One of `max-profit`, `execution-only`, `builder-always`, `builder-only` (kebab-case; no-hyphen spellings like `executiononly` also parse). See below. |

**Malformed entries fail the whole file:** an invalid hex string/length in any `fee_recipient` or `pubkey` (defaults or per-validator) makes `load_from_config` return an error and the process refuses to start — there's no partial/best-effort loading of a broken file.

### `block_selection_mode` values

| Value | Effect |
|---|---|
| `max-profit` (default) | Request both local and builder blocks, propose whichever is worth more. |
| `execution-only` | Forces `builder_boost_factor = 0` — never uses the builder. |
| `builder-always` | Forces `builder_boost_factor = u64::MAX`; falls back to a local block if the builder fails or the circuit breaker has tripped. |
| `builder-only` | Same weighting as `builder-always` but **never falls back** — the proposal fails outright if the builder is unavailable. Intended for DVT clusters where a local fallback would be unsafe/incorrect. |

---

## How values are resolved (`effective_*` methods)

For any pubkey, `ValidatorStore::effective_config`/`effective_fee_recipient`/`effective_gas_limit`/`effective_graffiti`/`effective_block_selection_mode` merge the per-validator record over the global defaults in a single locked snapshot — reads are atomic with respect to concurrent writes, so a caller never sees half-updated defaults mixed with a half-updated override.

If a validator is entirely absent from this file (no `[[validators]]` entry) but was loaded from a keystore, `ServiceBuilder::register_loaded_validators` (`crates/rvc/src/config/builder.rs:350-364`) adds it to the store as `enabled = true` with no overrides at startup — otherwise the fail-closed `enabled` default would silently block every validator when no `validators_config` is supplied at all. This registration is additive/idempotent: it never overwrites a pubkey that's already tracked (e.g. explicitly `enabled = false` in the TOML, or already disabled by the doppelganger-detection window).

---

## Runtime mutation: Rust API vs. HTTP API vs. hand-editing

There are three ways this data can change while `rvc` is running, and they interact in a way that's easy to get wrong:

### 1. Keymanager HTTP API (see [`docs/keymanager-api.md`](./keymanager-api.md))

Only three fields are HTTP-writable, via `/eth/v1/validator/{pubkey}/feerecipient`, `/gas_limit`, and `/graffiti` (`GET`/`POST`/`DELETE`). Every `POST`/`DELETE` on these routes:

1. Applies the change to the in-memory `ValidatorStore` (`update_config`).
2. Immediately calls `ValidatorStore::save_config()`, which serializes the **entire current in-memory snapshot** (defaults + every tracked validator) to a temp file, `fsync`s it, and atomically renames it over the TOML file.

This means changes made through the HTTP API **persist across restarts** without needing to touch the file yourself.

**Not exposed over HTTP at all:** `builder_proposals`, `builder_boost_factor`, `block_selection_mode`, and the `enabled` flag have no HTTP setter. The only ways to change them are: hand-edit the TOML and restart, or call `ValidatorStore::update_config`/`set_enabled` directly if you're embedding the crate. (`enabled` does flip indirectly and only in-memory — e.g. the doppelganger-detection window re-enabling a freshly imported key — but that flip is **not persisted**; see below.)

### 2. Hand-editing the TOML file

Safe **only while the process is stopped**. There is currently no reload trigger while `rvc` is running:

- `ValidatorStore::reload_config()` exists (parses the file fresh, applies parse-first/apply-second so a broken file never partially mutates the store, and preserves any validator that was registered programmatically but isn't in the file) — but **nothing in the shipped `rvc` binary calls it**. No file watcher, no HTTP endpoint, no signal handler triggers it (SIGHUP only reloads the log filter).
- Because HTTP writes call `save_config()`, which re-serializes from in-memory state rather than re-reading the file, a hand-edit made while the process is running can be **silently overwritten** the next time any fee-recipient/gas-limit/graffiti HTTP write fires.

**Recommendation:** treat "edit the file directly" and "use the HTTP API" as mutually exclusive while the process is live. Stop `rvc`, edit, restart — or manage everything through the Keymanager API.

### 3. `proposer_config_url` / `proposer_config_file`

These are separate, MEV-boost/Prysm-style config options (`Config.proposer_config_url`, `Config.proposer_config_file`) that parse a different JSON schema keyed by pubkey. As of the current codebase:

- `proposer_config_url` is fetched and parsed on a timer, but the only call site logs the parsed updates and never applies them to `ValidatorStore`.
- `proposer_config_file` is parsed as a config field but never read from disk by any code path.

**Neither currently affects `validators_config`/`ValidatorStore` state.** `validators_config` and the Keymanager HTTP API populate fee recipient, gas limit, and builder settings. `--graffiti` is an in-memory validator-store default at startup; a per-validator `graffiti` and a keymanager-set default still win. Startup does not rewrite this file. The next keymanager save persists that in-memory default over `[defaults].graffiti`.

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
| `save_config()` | write | atomically serializes the full in-memory snapshot to `config_path` (temp file + `fsync` + rename); errors if `config_path` is `None` |
| `reload_config()` | write | re-reads `config_path` from disk, parse-first/apply-second; not called anywhere in the shipped binary today |

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
