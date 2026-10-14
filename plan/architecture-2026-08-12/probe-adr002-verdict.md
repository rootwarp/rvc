# ADR-002 spawnability probe verdict (ARCH-2a)

**Date:** 2026-08-12T15:11:37Z (UTC)  
**Base:** `develop` @ `d795fb41dd57d0b6708b5ac8d7be4aa549ed8143`  
**Branch:** `feature/p2-2a-adr002-spawnability-probe`  
**Worktree:** `/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f`  
**Issue:** P2/ARCH-2a (Phase 2 plan §6)  
**Spike only:** probe code changes were applied, measured, then **reverted**. Product sources match develop.

---

## Verdict

**Clean — proceed with ARCH-2b.**

ADR-002's removal of `#[async_trait(?Send)]` and the addition of `Send + Sync` on
`BeaconBlockClient` does **not** introduce a `!Send` compile failure in production or
test targets for `rvc-block-service` / `rvc`. The static audit holds under a real typecheck.

There is **no** named blocking type under `crates/block-service/src/service/**` or mock
call-log locks. Route B (adding `+ Send + Sync` at bound sites) is not required.

---

## Probe edits applied (then reverted)

### VD-2a list (7 sites) + supertrait

| File | Change |
|------|--------|
| `crates/block-service/src/traits.rs` | `#[async_trait(?Send)]` → `#[async_trait]`; `pub trait BeaconBlockClient: Send + Sync` |
| `crates/rvc/src/beacon_adapter.rs` | drop `?Send` on production impl |
| `crates/rvc/src/orchestrator/coordinator/tests/mod.rs` | drop `?Send` on `MockBlockBeacon` and `BadProposerBlockBeacon` |
| `crates/block-service/src/service/tests/mocks.rs` | drop `?Send` on `MockBeaconClient` |
| `crates/rvc/tests/common/pipeline_fixture.rs` | drop `?Send` on `NoopBlockBeacon` |
| `crates/rvc/tests/sync_independent_of_attesting.rs` | drop `?Send` on `NoopBlockBeacon` (prose at `:249` left) |

### HEAD delta vs VD-2a (8th attribute site)

At `d795fb4`, `rg 'async_trait\(\?Send\)'` finds **eight** attribute sites, not seven.
The eighth is:

- `crates/rvc/tests/proposal_under_duty_stall.rs:368` — `impl BeaconBlockClient for TrackingBlockBeacon`

Leaving only the VD-2a seven fixed fails the focused check with trait-incompatibility
(`expected … + Send`, found non-`Send` future) **only** on that eighth attribute — not a
structural `!Send` body. The definitive probe therefore also removed that attribute
(ARCH-2b must include it; update the edit list from 7 → **8** attribute sites).

C10: no orphan paths (`crates/rvc-signer/`, `crates/rvc-keygen/`, `crates/rvc/src/main.rs`,
`crates/rvc/src/commands/`) were opened or edited.

---

## Commands and results

### 1. Definitive ADR-002 package check — **PASS (exit 0)**

```text
cargo check -p rvc-block-service -p rvc --all-targets --all-features
```

After all 8 attribute removals + `Send + Sync` supertrait, with `cargo clean -p rvc -p rvc-block-service` then rebuild:

```text
   Compiling rvc v0.7.0 (...)
    Checking rvc-block-service v0.7.0 (...)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 20.32s
```

**Exit code: 0.** Zero `Send` / `async_trait` / `BeaconBlockClient` diagnostics.

### 2. Workspace check as specified — **exit 101, unrelated pre-existing failure**

```text
cargo check --workspace --all-targets --all-features
```

Fails only with:

```text
error[E0599]: no method named `try_lock_free` found for struct `Arc<SlashingDb>` in the current scope
   --> crates/signer/tests/audit_subscriber_deadlock.rs:211:43
    |
211 |         self.free_at_staged.store(self.db.try_lock_free(), Ordering::SeqCst);
    |                                           ^^^^^^^^^^^^^ method not found in `Arc<SlashingDb>`

error: could not compile `rvc-signer` (test "audit_subscriber_deadlock") due to 1 previous error
```

**Confirmed baseline:** the same diagnostic reproduces on clean `develop` with **no** probe
edits (`cargo check -p rvc-signer --tests --all-features`). It is **not** caused by ADR-002
and contains no `Send` / `async_trait` / `BeaconBlockClient` content.

With probe applied, the full workspace log likewise has **no** ADR-002/`!Send` diagnostics.

### 3. Intermediate (7 of 8 sites) — mechanical remainder only

With only the VD-2a seven sites fixed, `cargo check -p rvc-block-service -p rvc --all-targets --all-features` fails solely on the eighth attribute:

```text
error[E0053]: method `produce_block_v3` has an incompatible type for trait
   --> crates/rvc/tests/proposal_under_duty_stall.rs:368:1
    |
368 | #[async_trait(?Send)]
    | ^^^^^^^^^^^^^^^^^^^^^ expected trait `Future<Output = …> + Send`, found trait `Future<Output = …>`
```

(and the same shape for `publish_block`, `publish_blinded_block`, `publish_block_ssz`).

This is the leftover `?Send` attribute, not a `!Send` implementation body.

---

## Implications for ARCH-2b / ARCH-2c / ARCH-2h

| Item | Implication |
|------|-------------|
| ARCH-2b | **Proceed.** Supertrait + attribute removals typecheck. Edit list must cover **8** attribute sites (VD-2a 7 + `proposal_under_duty_stall.rs`). |
| ARCH-2c | Scaffold deletion remains valid after 2b (future is `Send`). |
| ARCH-2h | Spawn/join of the orchestrator is not blocked by `?Send`. |
| Route B | Rejected as planned — not needed. |
| Pre-existing | `audit_subscriber_deadlock` / `try_lock_free` is out of scope for Phase 2 ADR-002; do not treat as probe failure. |

---

## Full cargo check transcript

The following is the archived probe transcript (commands A–D). Product tree was restored after capture.

```text
# Probe ADR-002 cargo check transcript
# base: develop @ d795fb41dd57d0b6708b5ac8d7be4aa549ed8143
# date: 2026-08-12T15:11:37Z
# probe edits: remove #[async_trait(?Send)] at 8 attribute sites + Send+Sync supertrait on BeaconBlockClient

================================================================================
COMMAND A: cargo check --workspace --all-targets --all-features
NOTE: First full cold-ish compile (7 VD-2a sites only; 8th site still present).
      Exit non-zero due to pre-existing rvc-signer test error (also fails on clean develop).
      No Send/async_trait/BeaconBlockClient diagnostics in this log.
================================================================================
   Compiling proc-macro2 v1.0.106
   Compiling unicode-ident v1.0.24
   Compiling quote v1.0.45
   Compiling libc v0.2.182
    Checking cfg-if v1.0.4
   Compiling serde_core v1.0.228
   Compiling serde v1.0.228
    Checking memchr v2.8.0
    Checking itoa v1.0.17
    Checking smallvec v1.15.1
    Checking once_cell v1.21.3
    Checking pin-project-lite v0.2.17
   Compiling zmij v1.0.21
   Compiling serde_json v1.0.149
    Checking log v0.4.29
   Compiling find-msvc-tools v0.1.9
   Compiling shlex v1.3.0
    Checking percent-encoding v2.3.2
    Checking subtle v2.6.1
    Checking tracing-core v0.1.36
   Compiling thiserror v2.0.18
    Checking foldhash v0.2.0
    Checking futures-core v0.3.32
    Checking stable_deref_trait v1.2.1
   Compiling parking_lot_core v0.9.12
    Checking scopeguard v1.2.0
    Checking form_urlencoded v1.2.2
    Checking futures-sink v0.3.32
    Checking writeable v0.6.2
    Checking lock_api v0.4.14
    Checking litemap v0.8.1
   Compiling zerocopy v0.8.40
   Compiling icu_properties_data v2.1.2
    Checking untrusted v0.9.0
   Compiling icu_normalizer_data v2.1.1
    Checking slab v0.4.12
    Checking futures-channel v0.3.32
    Checking futures-io v0.3.32
    Checking equivalent v1.0.2
   Compiling version_check v0.9.5
    Checking utf8_iter v1.0.4
    Checking futures-task v0.3.32
    Checking fnv v1.0.7
   Compiling typenum v1.19.0
    Checking base64 v0.22.1
    Checking rand_core v0.10.0
   Compiling getrandom v0.4.2
    Checking tower-service v0.3.3
    Checking bitflags v2.11.0
   Compiling generic-array v0.14.7
   Compiling httparse v1.10.1
    Checking atomic-waker v1.1.2
    Checking try-lock v0.2.5
    Checking tower-layer v0.3.3
    Checking want v0.3.1
    Checking sync_wrapper v1.0.2
    Checking httpdate v1.0.3
    Checking lazy_static v1.5.0
    Checking pin-utils v0.1.0
    Checking ipnet v2.12.0
   Compiling ident_case v1.0.1
   Compiling strsim v0.11.1
   Compiling syn v2.0.117
    Checking regex-syntax v0.8.10
   Compiling autocfg v1.5.0
    Checking mime v0.3.17
    Checking ryu v1.0.23
    Checking aho-corasick v1.1.4
   Compiling unicode-segmentation v1.12.0
    Checking hashbrown v0.16.1
    Checking regex-automata v0.4.14
   Compiling convert_case v0.10.0
    Checking indexmap v2.13.0
   Compiling paste v1.0.15
   Compiling unicode-xid v0.2.6
    Checking either v1.15.0
   Compiling ruint-macro v1.2.1
    Checking const-hex v1.18.1
   Compiling crunchy v0.2.4
   Compiling synstructure v0.13.2
    Checking hex v0.4.3
    Checking sharded-slab v0.1.7
    Checking ruint v1.17.2
    Checking tracing-log v0.2.0
    Checking thread_local v1.1.9
   Compiling tiny-keccak v2.0.2
    Checking nu-ansi-term v0.50.3
   Compiling num-traits v0.2.19
    Checking foldhash v0.1.5
    Checking matchers v0.2.0
   Compiling darling_core v0.20.11
    Checking getrandom v0.2.17
   Compiling jobserver v0.1.34
    Checking errno v0.3.14
   Compiling cc v1.2.56
    Checking parking_lot v0.12.5
    Checking signal-hook-registry v1.4.8
    Checking socket2 v0.6.3
    Checking mio v1.1.1
    Checking cpufeatures v0.2.17
    Checking rand_core v0.6.4
    Checking keccak v0.1.6
    Checking uuid v1.22.0
    Checking itertools v0.13.0
    Checking rustc-hash v2.1.1
   Compiling cmake v0.1.57
   Compiling fs_extra v1.3.0
   Compiling dunce v1.0.5
   Compiling crc32fast v1.5.0
    Checking simd-adler32 v0.3.8
    Checking adler2 v2.0.1
    Checking miniz_oxide v0.8.9
   Compiling aws-lc-rs v1.16.3
    Checking compression-core v0.4.31
   Compiling rustls v0.23.37
    Checking iri-string v0.7.10
    Checking core-foundation-sys v0.8.7
    Checking core-foundation v0.10.1
    Checking security-framework-sys v2.17.0
   Compiling rustversion v1.0.22
    Checking security-framework v3.7.0
   Compiling rustix v1.1.4
    Checking serde_path_to_error v0.1.20
    Checking matchit v0.7.3
   Compiling unicase v2.9.0
   Compiling crossbeam-utils v0.8.21
   Compiling mime_guess v2.0.5
   Compiling prometheus v0.14.0
    Checking fastrand v2.3.0
    Checking num_cpus v1.17.0
   Compiling getrandom v0.3.4
   Compiling anyhow v1.0.102
   Compiling crossbeam-epoch v0.9.20
   Compiling time-core v0.1.8
    Checking powerfmt v0.2.0
   Compiling num-conv v0.2.0
   Compiling time-macros v0.2.27
    Checking num-integer v0.1.46
    Checking deranged v0.5.8
    Checking flate2 v1.1.9
   Compiling ring v0.17.14
   Compiling aws-lc-sys v0.40.0
    Checking compression-codecs v0.4.37
    Checking regex v1.12.3
   Compiling rayon-core v1.13.0
    Checking arrayvec v0.7.6
    Checking tinyvec_macros v0.1.1
    Checking tinyvec v1.10.0
    Checking hex-conservative v0.2.2
   Compiling blst v0.3.16
    Checking tempfile v3.26.0
    Checking base64ct v1.8.3
    Checking bitcoin_hashes v0.14.1
    Checking password-hash v0.5.0
    Checking unicode-normalization v0.1.25
    Checking threadpool v1.8.1
   Compiling ahash v0.8.12
   Compiling pkg-config v0.3.32
   Compiling itertools v0.14.0
   Compiling vcpkg v0.2.15
    Checking time v0.3.47
    Checking rand_core v0.9.5
    Checking fallible-iterator v0.3.0
    Checking fallible-streaming-iterator v0.1.9
   Compiling heck v0.5.0
    Checking pem v3.0.6
    Checking opentelemetry-semantic-conventions v0.31.0
   Compiling thiserror v1.0.69
    Checking matchit v0.8.4
   Compiling syn v1.0.109
    Checking iana-time-zone v0.1.65
    Checking signature v2.2.0
    Checking crossbeam-channel v0.5.15
    Checking utf8parse v0.2.2
    Checking anstyle-parse v0.2.7
    Checking colorchoice v1.0.4
    Checking crossbeam-deque v0.8.6
    Checking is_terminal_polyfill v1.70.2
    Checking anstyle-query v1.1.5
    Checking anstyle v1.0.13
    Checking clap_lex v1.0.0
    Checking anstream v0.6.21
    Checking minimal-lexical v0.2.1
    Checking clap_builder v4.5.60
    Checking nom v7.1.3
    Checking rayon v1.11.0
   Compiling libsqlite3-sys v0.30.1
   Compiling prettyplease v0.2.37
   Compiling bytes v1.11.1
   Compiling fixedbitset v0.5.7
   Compiling indexmap v1.9.3
   Compiling petgraph v0.7.1
   Compiling multimap v0.10.1
    Checking hashbrown v0.12.3
    Checking socket2 v0.5.10
    Checking winnow v0.7.15
    Checking toml_write v0.1.2
    Checking wait-timeout v0.2.1
    Checking quick-error v1.2.3
    Checking bit-vec v0.8.0
    Checking bit-set v0.8.0
    Checking rusty-fork v0.3.1
    Checking rand_xorshift v0.4.0
    Checking unarray v0.1.4
    Checking deadpool-runtime v0.1.4
   Compiling darling_core v0.21.3
   Compiling radium v0.7.0
    Checking ciborium-io v0.2.2
    Checking itertools v0.10.5
    Checking cast v0.3.0
    Checking tap v1.0.1
    Checking same-file v1.0.6
    Checking walkdir v2.5.0
    Checking wyz v0.5.1
    Checking eventsource-stream v0.2.3
    Checking is-terminal v0.4.17
    Checking oorandom v11.1.5
    Checking criterion-plot v0.5.0
   Compiling semver v1.0.27
    Checking funty v2.0.0
    Checking anes v0.1.6
    Checking futures-timer v3.0.3
   Compiling rustc_version v0.4.1
    Checking yasna v0.5.2
    Checking rusticata-macros v4.1.0
    Checking chacha20 v0.10.0
    Checking rand v0.10.0
    Checking base16ct v0.2.0
   Compiling oid-registry v0.7.1
   Compiling serde_derive v1.0.228
   Compiling zeroize_derive v1.4.3
   Compiling tracing-attributes v0.1.31
   Compiling thiserror-impl v2.0.18
   Compiling zerofrom-derive v0.1.6
   Compiling displaydoc v0.2.5
   Compiling yoke-derive v0.8.1
   Compiling zerovec-derive v0.11.2
   Compiling tokio-macros v2.6.1
   Compiling zerocopy-derive v0.8.40
   Compiling futures-macro v0.3.32
    Checking zeroize v1.8.2
    Checking crypto-common v0.1.7
   Compiling async-trait v0.1.89
    Checking block-buffer v0.10.4
    Checking digest v0.10.7
   Compiling derive_more-impl v2.1.1
    Checking sha3 v0.10.8
   Compiling darling_macro v0.20.11
   Compiling darling v0.20.11
    Checking sha2 v0.10.9
    Checking ethereum_hashing v0.7.0
   Compiling tree_hash_derive v0.9.1
    Checking tracing v0.1.44
   Compiling ethereum_ssz_derive v0.9.1
    Checking rustls-pki-types v1.14.0
    Checking rustls-native-certs v0.8.3
    Checking futures-util v0.3.32
    Checking webpki-roots v1.0.6
   Compiling axum-macros v0.4.2
    Checking hmac v0.12.1
    Checking inout v0.1.4
    Checking cipher v0.4.4
    Checking hkdf v0.12.4
    Checking salsa20 v0.10.2
    Checking pbkdf2 v0.12.2
    Checking scrypt v0.11.0
    Checking zerofrom v0.1.6
    Checking ctr v0.9.2
    Checking aes v0.8.4
    Checking secrecy v0.10.3
   Compiling pin-project-internal v1.1.11
    Checking yoke v0.8.1
   Compiling tracing-test-macro v0.2.6
    Checking futures-executor v0.3.32
    Checking futures v0.3.32
   Compiling prost-derive v0.14.3
    Checking zerovec v0.11.5
    Checking zerotrie v0.2.3
    Checking tinystr v0.8.2
    Checking potential_utf v0.1.4
    Checking icu_collections v2.1.1
    Checking tokio v1.50.0
    Checking http v1.4.0
    Checking icu_locale_core v2.1.1
    Checking serde_urlencoded v0.7.1
    Checking tracing-serde v0.2.0
    Checking tracing-subscriber v0.3.22
    Checking hashbrown v0.15.5
   Compiling thiserror-impl v1.0.69
    Checking http-body v1.0.1
    Checking http-body-util v0.1.3
    Checking icu_provider v2.1.1
    Checking opentelemetry v0.31.0
    Checking axum-core v0.5.6
    Checking icu_normalizer v2.1.1
    Checking icu_properties v2.1.2
    Checking chrono v0.4.44
    Checking tracing-test v0.2.6
   Compiling rvs_derive v0.3.2
    Checking idna_adapter v1.2.1
    Checking idna v1.1.0
    Checking secret-vault-value v1.0.1
   Compiling rsb_derive v0.5.1
    Checking url v2.5.8
    Checking tracing-opentelemetry v0.32.1
    Checking rvc-observability v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/observability)
    Checking tracing-appender v0.2.4
   Compiling clap_derive v4.5.55
   Compiling prost-derive v0.13.5
    Checking tokio-util v0.7.18
    Checking h2 v0.4.13
    Checking ppv-lite86 v0.2.21
    Checking tower v0.5.3
    Checking rand_chacha v0.3.1
    Checking rand v0.8.5
    Checking async-compression v0.4.41
    Checking num-bigint v0.4.6
    Checking axum-core v0.4.5
    Checking tower-http v0.6.8
    Checking rand_chacha v0.9.0
    Checking rand v0.9.2
    Checking bip39 v2.2.2
    Checking hashbrown v0.14.5
    Checking tokio-stream v0.1.18
    Checking axum v0.8.8
    Checking hyper v1.8.1
    Checking opentelemetry_sdk v0.31.0
    Checking hashlink v0.9.1
    Checking rusqlite v0.32.1
    Checking simple_asn1 v0.6.4
    Checking hyper-util v0.1.20
    Checking jsonwebtoken v10.3.0
    Checking rvstruct v0.3.2
   Compiling async-stream-impl v0.3.6
    Checking toml_datetime v0.6.11
    Checking serde_spanned v0.6.9
    Checking rustls-pemfile v2.2.0
    Checking hyper-timeout v0.5.2
    Checking toml_edit v0.22.27
    Checking proptest v1.10.0
    Checking deadpool v0.12.3
    Checking assert-json-diff v2.0.2
    Checking half v2.7.1
    Checking wiremock v0.6.5
   Compiling darling_macro v0.21.3
    Checking ciborium-ll v0.2.2
    Checking prost v0.14.3
    Checking ciborium v0.2.2
    Checking tinytemplate v1.2.1
    Checking rcgen v0.13.2
    Checking bitvec v1.0.1
    Checking pin-project v1.1.11
    Checking toml v0.8.23
   Compiling asn1-rs-impl v0.2.0
    Checking prost-types v0.14.3
   Compiling asn1-rs-derive v0.5.1
    Checking crypto-bigint v0.5.5
    Checking tower v0.4.13
   Compiling google-cloud-auth v1.6.0
    Checking num-rational v0.4.2
    Checking axum v0.7.9
    Checking num-complex v0.4.6
    Checking ff v0.13.1
    Checking group v0.13.0
    Checking logroller v0.1.10
    Checking elliptic-curve v0.13.8
   Compiling google-cloud-gax-internal v0.7.9
    Checking num-iter v0.1.45
    Checking num v0.4.3
    Checking pairing v0.23.0
    Checking generic-array v1.3.5
    Checking hybrid-array v0.4.8
    Checking data-encoding v2.11.0
    Checking arrayref v0.3.9
    Checking rvc-signer-registry v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/signer-registry)
    Checking bls12_381_plus v0.8.18
    Checking fd-lock v4.0.4
    Checking vsss-rs v5.3.0
    Checking rvc-architecture-tests v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/architecture-tests)
   Compiling darling v0.21.3
    Checking rpassword v5.0.1
    Checking async-stream v0.3.6
   Compiling prost v0.13.5
    Checking clap v4.5.60
    Checking derive_more v2.1.1
    Checking rvc-metrics v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/metrics)
   Compiling serde_with_macros v3.17.0
    Checking asn1-rs v0.6.2
   Compiling prost-types v0.13.5
    Checking criterion v0.5.1
   Compiling prost-build v0.13.5
    Checking alloy-primitives v0.8.26
    Checking alloy-primitives v1.5.7
    Checking serde_with v3.17.0
   Compiling tonic-build v0.12.3
    Checking ethereum_serde_utils v0.8.0
    Checking ethereum_serde_utils v0.7.0
    Checking ethereum_ssz v0.9.1
    Checking ethereum_ssz v0.8.3
    Checking tree_hash v0.9.1
    Checking ssz_types v0.10.1
    Checking rvc-eth-types v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/eth-types)
    Checking google-cloud-wkt v1.2.1
    Checking der-parser v9.0.0
   Compiling rvc-signer-proto v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/signer-proto)
   Compiling rvc v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/rvc)
    Checking x509-parser v0.16.0
    Checking google-cloud-rpc v1.2.0
    Checking google-cloud-type v1.2.0
    Checking google-cloud-gax v1.7.0
    Checking rvc-web3signer-wire v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/web3signer-wire)
    Checking rvc-slashing v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/slashing)
    Checking rvc-keymanager-api v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/keymanager-api)
    Checking rvc-validator-store v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/validator-store)
    Checking rvc-timing v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/timing)
    Checking rustls-webpki v0.103.13
    Checking tokio-rustls v0.26.4
    Checking rustls-platform-verifier v0.6.2
    Checking hyper-rustls v0.27.7
    Checking tonic v0.14.5
    Checking tonic v0.12.3
    Checking reqwest v0.12.28
    Checking reqwest v0.13.2
    Checking rvc-crypto v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/crypto)
    Checking opentelemetry-http v0.31.0
    Checking reqwest-eventsource v0.6.0
    Checking rvc-test-support v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/rvc-test-support)
    Checking tonic-prost v0.14.5
    Checking opentelemetry-proto v0.31.0
    Checking gcloud-sdk v0.28.5
    Checking opentelemetry-otlp v0.31.0
    Checking rvc-doppelganger v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/doppelganger)
    Checking rvc-grpc-signer v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/grpc-signer)
    Checking rvc-keygen v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/bin/rvc-keygen)
    Checking rvc-signer v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/signer)
    Checking opentelemetry-gcloud-trace v0.22.0
    Checking google-cloud-iam-v1 v1.5.0
    Checking google-cloud-location v1.5.0
    Checking google-cloud-secretmanager-v1 v1.5.0
    Checking rvc-telemetry v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/telemetry)
error[E0599]: no method named `try_lock_free` found for struct `Arc<SlashingDb>` in the current scope
   --> crates/signer/tests/audit_subscriber_deadlock.rs:211:43
    |
211 |         self.free_at_staged.store(self.db.try_lock_free(), Ordering::SeqCst);
    |                                           ^^^^^^^^^^^^^ method not found in `Arc<SlashingDb>`

For more information about this error, try `rustc --explain E0599`.
error: could not compile `rvc-signer` (test "audit_subscriber_deadlock") due to 1 previous error
warning: build failed, waiting for other jobs to finish...

================================================================================
COMMAND B: cargo check -p rvc-block-service -p rvc --all-targets --all-features
NOTE: After 7 VD-2a sites only (8th site still #[async_trait(?Send)]).
================================================================================
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on build directory
    Checking indexmap v2.13.0
    Checking tokio v1.50.0
    Checking aws-lc-rs v1.16.3
    Checking deranged v0.5.8
    Checking uuid v1.22.0
    Checking tree_hash v0.9.1
    Checking axum-core v0.4.5
    Checking opentelemetry v0.31.0
    Checking tracing-serde v0.2.0
    Checking prost v0.14.3
    Checking serde_with v3.17.0
    Checking chrono v0.4.44
    Checking blst v0.3.16
    Checking bip39 v2.2.2
    Checking tracing-subscriber v0.3.22
    Checking ssz_types v0.10.1
    Checking rvc-observability v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/observability)
    Checking serde_spanned v0.6.9
    Checking toml_datetime v0.6.11
    Checking rvc-eth-types v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/eth-types)
    Checking opentelemetry-semantic-conventions v0.31.0
    Checking prost v0.13.5
    Checking rustls-pemfile v2.2.0
   Compiling tracing-test-macro v0.2.6
    Checking toml_edit v0.22.27
    Checking assert-json-diff v2.0.2
    Checking criterion v0.5.1
    Checking rustls-webpki v0.103.13
    Checking logroller v0.1.10
    Checking time v0.3.47
    Checking tracing-opentelemetry v0.32.1
    Checking rustls v0.23.37
    Checking toml v0.8.23
    Checking rvc-web3signer-wire v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/web3signer-wire)
    Checking rvc-timing v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/timing)
    Checking rvc-validator-store v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/validator-store)
    Checking google-cloud-wkt v1.2.1
    Checking tracing-appender v0.2.4
    Checking tracing-test v0.2.6
    Checking tokio-util v0.7.18
    Checking tower v0.5.3
    Checking tokio-stream v0.1.18
    Checking deadpool v0.12.3
    Checking google-cloud-rpc v1.2.0
    Checking google-cloud-type v1.2.0
    Checking tonic v0.14.5
    Checking opentelemetry_sdk v0.31.0
    Checking tower-http v0.6.8
    Checking google-cloud-gax v1.7.0
    Checking h2 v0.4.13
    Checking tower v0.4.13
    Checking tonic-prost v0.14.5
    Checking opentelemetry-proto v0.31.0
    Checking tokio-rustls v0.26.4
    Checking rustls-platform-verifier v0.6.2
    Checking hyper v1.8.1
    Checking hyper-util v0.1.20
    Checking hyper-rustls v0.27.7
    Checking axum v0.7.9
    Checking hyper-timeout v0.5.2
    Checking wiremock v0.6.5
    Checking reqwest v0.12.28
    Checking reqwest v0.13.2
    Checking opentelemetry-http v0.31.0
    Checking rvc-crypto v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/crypto)
    Checking google-cloud-auth v1.6.0
    Checking reqwest-eventsource v0.6.0
    Checking opentelemetry-otlp v0.31.0
    Checking rvc-telemetry v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/telemetry)
    Checking beacon v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/beacon)
    Checking rvc-metrics v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/metrics)
    Checking tonic v0.12.3
    Checking rvc-slashing v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/slashing)
    Checking rvc-bn-manager v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/bn-manager)
    Checking rvc-keymanager-api v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/keymanager-api)
    Checking google-cloud-gax-internal v0.7.9
    Checking google-cloud-iam-v1 v1.5.0
    Checking google-cloud-location v1.5.0
    Checking rvc-doppelganger v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/doppelganger)
    Checking google-cloud-secretmanager-v1 v1.5.0
    Checking rvc-signer-proto v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/signer-proto)
    Checking rvc-signer v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/signer)
    Checking rvc-grpc-signer v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/grpc-signer)
    Checking rvc-secret-provider v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/secret-provider)
    Checking rvc-block-service v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/block-service)
    Checking rvc-duty-tracker v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/duty-tracker)
    Checking rvc-builder v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/builder)
    Checking rvc v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/rvc)
error[E0053]: method `produce_block_v3` has an incompatible type for trait
   --> crates/rvc/tests/proposal_under_duty_stall.rs:368:1
    |
368 | #[async_trait(?Send)]
    | ^^^^^^^^^^^^^^^^^^^^^ expected trait `Future<Output = Result<rvc_block_service::ProduceBlockResponse, BlockServiceError>> + Send`, found trait `Future<Output = Result<rvc_block_service::ProduceBlockResponse, BlockServiceError>>`
    |
    = note: expected signature `fn(&'life0 TrackingBlockBeacon, _, &'life1 _, Option<_>, Option<_>) -> Pin<Box<(dyn Future<Output = Result<rvc_block_service::ProduceBlockResponse, BlockServiceError>> + Send + 'async_trait)>>`
               found signature `fn(&'life0 TrackingBlockBeacon, _, &'life1 _, Option<_>, Option<_>) -> Pin<Box<(dyn Future<Output = Result<rvc_block_service::ProduceBlockResponse, BlockServiceError>> + 'async_trait)>>`

error[E0053]: method `publish_block` has an incompatible type for trait
   --> crates/rvc/tests/proposal_under_duty_stall.rs:368:1
    |
368 | #[async_trait(?Send)]
    | ^^^^^^^^^^^^^^^^^^^^^ expected trait `Future<Output = Result<(), BlockServiceError>> + Send`, found trait `Future<Output = Result<(), BlockServiceError>>`
    |
    = note: expected signature `fn(&'life0 TrackingBlockBeacon, &'life1 SignedBeaconBlock, &'life2 _) -> Pin<Box<(dyn Future<Output = Result<(), BlockServiceError>> + Send + 'async_trait)>>`
               found signature `fn(&'life0 TrackingBlockBeacon, &'life1 SignedBeaconBlock, &'life2 _) -> Pin<Box<(dyn Future<Output = Result<(), BlockServiceError>> + 'async_trait)>>`

error[E0053]: method `publish_blinded_block` has an incompatible type for trait
   --> crates/rvc/tests/proposal_under_duty_stall.rs:368:1
    |
368 | #[async_trait(?Send)]
    | ^^^^^^^^^^^^^^^^^^^^^ expected trait `Future<Output = Result<(), BlockServiceError>> + Send`, found trait `Future<Output = Result<(), BlockServiceError>>`
    |
    = note: expected signature `fn(&'life0 TrackingBlockBeacon, &'life1 SignedBlindedBeaconBlock, &'life2 _) -> Pin<Box<(dyn Future<Output = Result<(), BlockServiceError>> + Send + 'async_trait)>>`
               found signature `fn(&'life0 TrackingBlockBeacon, &'life1 SignedBlindedBeaconBlock, &'life2 _) -> Pin<Box<(dyn Future<Output = Result<(), BlockServiceError>> + 'async_trait)>>`

error[E0053]: method `publish_block_ssz` has an incompatible type for trait
   --> crates/rvc/tests/proposal_under_duty_stall.rs:368:1
    |
368 | #[async_trait(?Send)]
    | ^^^^^^^^^^^^^^^^^^^^^ expected trait `Future<Output = Result<(), BlockServiceError>> + Send`, found trait `Future<Output = Result<(), BlockServiceError>>`
    |
    = note: expected signature `fn(&'life0 TrackingBlockBeacon, &'life1 _, &'life2 _, _) -> Pin<Box<(dyn Future<Output = Result<(), BlockServiceError>> + Send + 'async_trait)>>`
               found signature `fn(&'life0 TrackingBlockBeacon, &'life1 _, &'life2 _, _) -> Pin<Box<(dyn Future<Output = Result<(), BlockServiceError>> + 'async_trait)>>`

For more information about this error, try `rustc --explain E0053`.
error: could not compile `rvc` (test "proposal_under_duty_stall") due to 4 previous errors
warning: build failed, waiting for other jobs to finish...

================================================================================
COMMAND C: cargo check -p rvc-block-service -p rvc --all-targets --all-features
NOTE: After all 8 attribute sites + supertrait (definitive ADR-002 probe). EXIT 0.
================================================================================
   Compiling rvc v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/rvc)
    Checking rvc-block-service v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/block-service)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 20.32s

================================================================================
COMMAND D: cargo check --workspace --all-targets --all-features
NOTE: Final workspace recheck with all 8 sites fixed. EXIT 101 — only pre-existing
      rvc-signer audit_subscriber_deadlock try_lock_free error (confirmed on clean develop).
      No Send/async_trait/BeaconBlockClient diagnostics.
================================================================================
    Checking rvc-bn-manager v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/bn-manager)
    Checking rvc-block-service v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/block-service)
    Checking rvc-signer-server v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/signer-server)
    Checking rvc-signer-bin v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/bin/rvc-signer)
    Checking rvc-secret-provider v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/secret-provider)
    Checking rvc-signer v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/signer)
    Checking beacon v0.7.0 (/Users/nil/.grok/worktrees/dsrv-rvc/subagent-019ff684-5aa2-7db1-932c-0da4e9b6137f/crates/beacon)
error[E0599]: no method named `try_lock_free` found for struct `Arc<SlashingDb>` in the current scope
   --> crates/signer/tests/audit_subscriber_deadlock.rs:211:43
    |
211 |         self.free_at_staged.store(self.db.try_lock_free(), Ordering::SeqCst);
    |                                           ^^^^^^^^^^^^^ method not found in `Arc<SlashingDb>`

For more information about this error, try `rustc --explain E0599`.
error: could not compile `rvc-signer` (test "audit_subscriber_deadlock") due to 1 previous error
warning: build failed, waiting for other jobs to finish...

```
