//! ARCH-4f: clean-section migration guards (flat alias + config-else-env).
//!
//! Test names do not end in `_root` (KAT scan).

use rvc::config::Config;
use tempfile::NamedTempFile;

#[test]
fn tracing_section_flat_alias_still_parses() {
    let flat: Config = toml::from_str(r#"tracing_endpoint = "http://x""#)
        .expect("flat legacy key must still parse");
    let nested: Config = toml::from_str(
        r#"
[tracing]
endpoint = "http://x"
"#,
    )
    .expect("nested [tracing] table must parse");
    assert_eq!(flat.tracing.endpoint, nested.tracing.endpoint);
    assert_eq!(flat.tracing.endpoint.as_deref(), Some("http://x"));
}

#[test]
fn nested_table_flat_legacy_names_do_not_bind() {
    let nested: Config = toml::from_str(
        r#"
[keymanager]
keymanager_enabled = true
keymanager_address = "0.0.0.0:5062"
keymanager_body_limit = 104857600

[tracing]
tracing_endpoint = "http://nested-must-not-bind:4318"
"#,
    )
    .expect("unknown keys inside nested tables are ignored (no deny_unknown_fields)");
    assert!(!nested.keymanager.enabled, "prefixed names inside [keymanager] must not bind");
    assert!(nested.keymanager.address.is_none());
    assert_eq!(nested.keymanager.body_limit, 10 * 1024 * 1024);
    assert!(nested.tracing.endpoint.is_none());

    let flat: Config = toml::from_str(
        r#"
keymanager_enabled = true
keymanager_address = "0.0.0.0:5062"
tracing_endpoint = "http://x"
"#,
    )
    .expect("top-level ConfigWire flat keys must still parse");
    assert!(flat.keymanager.enabled);
    assert_eq!(flat.keymanager.address.as_deref(), Some("0.0.0.0:5062"));
    assert_eq!(flat.tracing.endpoint.as_deref(), Some("http://x"));

    let section: Config = toml::from_str(
        r#"
[keymanager]
enabled = true
address = "127.0.0.1:5062"
"#,
    )
    .expect("section-relative nested names must parse");
    assert!(section.keymanager.enabled);
    assert_eq!(section.keymanager.address.as_deref(), Some("127.0.0.1:5062"));
}

#[test]
fn otel_env_fallback_is_still_config_else_env() {
    let _guard = otel_env_lock();
    std::env::set_var("OTEL_EXPORTER_OTLP_ENDPOINT", "http://env-must-lose:4318");

    let cfg: Config = toml::from_str(
        r#"
[tracing]
endpoint = "http://config-wins:4318"
"#,
    )
    .expect("nested tracing.endpoint must parse");
    assert_eq!(cfg.tracing.endpoint.as_deref(), Some("http://config-wins:4318"));
    assert_eq!(cfg.tracing.resolve_endpoint().as_deref(), Some("http://config-wins:4318"));

    let mut file = NamedTempFile::new().expect("temp config");
    std::io::Write::write_all(&mut file, b"[tracing]\nendpoint = \"http://config-wins:4318\"\n")
        .expect("write");
    let cfg = Config::load(Some(file.path()), rvc::config::StartArgs::default())
        .expect("empty CLI must not change a file-loaded endpoint");
    assert_eq!(
        cfg.tracing.resolve_endpoint().as_deref(),
        Some("http://config-wins:4318"),
        "absent CLI must not let OTEL env override a set Config.tracing.endpoint"
    );

    std::env::remove_var("OTEL_EXPORTER_OTLP_ENDPOINT");
}

fn otel_env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap_or_else(|e| e.into_inner())
}
