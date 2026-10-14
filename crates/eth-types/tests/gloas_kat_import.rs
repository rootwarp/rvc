//! Issue 4.0: Gloas KAT constants resolve from eth-types test targets.

use rvc_spec_vectors::spec_kat::{
    KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT, KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT,
    SPEC_GLOAS_PAYLOADATTESTATIONDATA_ROOT, SPEC_GLOAS_PAYLOADATTESTATIONMESSAGE_ROOT,
    SPEC_GLOAS_PROPOSERPREFERENCES_ROOT,
};

#[test]
fn test_gloas_kat_constants_are_importable() {
    for hex in [
        SPEC_GLOAS_PAYLOADATTESTATIONDATA_ROOT,
        SPEC_GLOAS_PAYLOADATTESTATIONMESSAGE_ROOT,
        SPEC_GLOAS_PROPOSERPREFERENCES_ROOT,
        KAT_GLOAS_PAYLOAD_ATTESTATION_SIGNING_ROOT,
        KAT_GLOAS_PROPOSER_PREFERENCES_SIGNING_ROOT,
    ] {
        assert_eq!(hex.len(), 64);
        assert!(!hex.starts_with("0x"));
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()), "{hex}");
    }
}
