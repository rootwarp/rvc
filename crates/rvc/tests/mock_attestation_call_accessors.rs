//! RR0-05: call-capture accessors are reachable from a `crates/rvc` integration test.

#[test]
fn attestation_call_accessors_are_visible_from_rvc_tests() {
    let mock = bn_manager::MockBeaconNodeClient::new();
    assert!(
        mock.get_attestation_data_calls().is_empty() && mock.submit_attestation_calls().is_empty()
    );
}
