//! BuilderRequestAuth container and L3 signing-root KATs.
//!
//! Generated with the 4.0 pyspec recipe (`eth-ssz-specs==0.1.0`
//! `hash_tree_root` / `compute_domain` / `compute_signing_root`).
//! `ssz_static` has no builder-specs container.
//!
//! # Provenance
//!
//! provenance-source: ethereum/ssz-specs@v0.1.0 ethereum/builder-specs@38f11441c194d150386f567b4d7087ec86d4118c
//! provenance-pyspec-revision: eth-ssz-specs==0.1.0
//! provenance-builder-specs: 38f11441c194d150386f567b4d7087ec86d4118c
//! provenance-domain: DOMAIN_BUILDER_REQUEST_AUTH 0x0B000001
//! provenance-domain-inputs: compute_domain(DOMAIN_BUILDER_REQUEST_AUTH) genesis fork 0x00000000 zero GVR
//! provenance-fixture: builder-specs examples/gloas/signed_builder_request_auth.json data=0x1234567890abcdef slot=1

/// builder-specs revision that defines `DOMAIN_BUILDER_REQUEST_AUTH = 0x0B000001`.
pub const BUILDER_SPECS_REVISION: &str = "38f11441c194d150386f567b4d7087ec86d4118c";

/// Fixture `data` bytes from builder-specs `examples/gloas/signed_builder_request_auth.json`.
pub const KAT_BUILDER_REQUEST_AUTH_DATA_HEX: &str = "1234567890abcdef";

/// Fixture `slot` from builder-specs `examples/gloas/signed_builder_request_auth.json`.
pub const KAT_BUILDER_REQUEST_AUTH_SLOT: u64 = 1;

/// `BuilderRequestAuth` hash tree root from the 4.0 pyspec recipe
/// (`eth-ssz-specs==0.1.0`, builder-specs@38f11441c194d150386f567b4d7087ec86d4118c,
/// `DOMAIN_BUILDER_REQUEST_AUTH 0x0B000001`).
pub const SPEC_GLOAS_BUILDERREQUESTAUTH_ROOT: &str =
    "3d6f2e216a08828a2bc2c9644edacd56fef00f2be824abc49f6d1a28569bd880";

/// `BuilderRequestAuth` signing root under `compute_domain(DOMAIN_BUILDER_REQUEST_AUTH)`
/// (genesis fork `0x00000000`, zero GVR) from the 4.0 pyspec recipe
/// (`eth-ssz-specs==0.1.0`, builder-specs@38f11441c194d150386f567b4d7087ec86d4118c,
/// `DOMAIN_BUILDER_REQUEST_AUTH 0x0B000001`).
pub const KAT_GLOAS_BUILDER_REQUEST_AUTH_SIGNING_ROOT: &str =
    "eb87fafdb60e7b3174caf705302b2c16b56a85eb6df9e4ab50ba49563977403d";
