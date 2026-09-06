//! Fetched-cache consumer: skip vs required is owned by [`support::vector_root_from_env`].

mod support;

#[test]
fn test_fetched_cache_from_env_or_skip() {
    let Some(root) = support::vector_root_from_env() else {
        return;
    };
    let cases = root.cases("electra", "ssz_static", "AttestationData").expect("walk cases");
    assert!(cases.cases_run() > 0, "vacuous AttestationData suite");
}
