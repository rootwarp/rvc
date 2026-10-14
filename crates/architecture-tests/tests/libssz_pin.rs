//! Issue 3.9a / 3.7: the libssz family is pinned at exact `=0.3.0` in `[workspace.dependencies]`.
//!
//! A caret (`"0.3.0"` / `"^0.3.0"`) would silently float a hasher that computes signing roots.
//! Feature names are the published 0.3.0 names (`sha2-backend` on libssz-merkle; no `sha2` feature).
//! No external dependency (Phase-1 rule P6): hand-rolled scan, same style as `kat_policy.rs`.

use rvc_architecture_tests::workspace_root;

const LIBSSZ_FAMILY: &[&str] = &["libssz", "libssz-derive", "libssz-merkle", "libssz-types"];

/// Per-crate pin spec. Published 0.3.0: hasher is `sha2-backend` on `libssz-merkle` only.
const EXPECTED_SPEC: &[(&str, &str)] = &[
    ("libssz", r#"{ version = "=0.3.0", default-features = false, features = ["alloc"] }"#),
    ("libssz-derive", r#"{ version = "=0.3.0", default-features = false }"#),
    (
        "libssz-merkle",
        r#"{ version = "=0.3.0", default-features = false, features = ["alloc", "sha2-backend"] }"#,
    ),
    ("libssz-types", r#"{ version = "=0.3.0", default-features = false, features = ["alloc"] }"#),
];

fn expected_spec(name: &str) -> &'static str {
    EXPECTED_SPEC
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, spec)| *spec)
        .unwrap_or_else(|| panic!("missing EXPECTED_SPEC for {name}"))
}

/// Body of `[workspace.dependencies]`, excluding later unrelated tables.
fn workspace_dependencies(manifest: &str) -> &str {
    const HEADER: &str = "[workspace.dependencies]";
    let start = manifest.find(HEADER).expect("root Cargo.toml must have [workspace.dependencies]");
    let after = &manifest[start + HEADER.len()..];
    let mut search_from = 0;
    loop {
        match after[search_from..].find("\n[") {
            None => return after,
            Some(rel) => {
                let abs = search_from + rel + 1;
                let header = after[abs..].lines().next().unwrap_or("");
                if header.starts_with("[workspace.dependencies") {
                    search_from = abs + 1;
                    continue;
                }
                return &after[..abs];
            }
        }
    }
}

/// Inline-table or string value on `{name} = …`, if present as a single line.
fn pin_spec<'a>(section: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name} =");
    for line in section.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            // `libssz =` must not match `libssz-merkle =`.
            return Some(rest.trim());
        }
    }
    None
}

fn check_libssz_pins(manifest: &str) -> Result<(), Vec<String>> {
    let section = workspace_dependencies(manifest);
    let mut errors = Vec::new();
    for name in LIBSSZ_FAMILY {
        let expected = expected_spec(name);
        match pin_spec(section, name) {
            None => errors.push(format!("{name} missing from [workspace.dependencies]")),
            Some(spec) => {
                if spec != expected {
                    errors.push(format!(
                        "{name} must be `{name} = {expected}` (exact =0.3.0, no caret); \
                         found `{name} = {spec}`"
                    ));
                }
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[test]
fn caret_version_is_rejected() {
    let manifest = r#"
[workspace.dependencies]
libssz = { version = "0.3.0", default-features = false, features = ["alloc"] }
libssz-derive = { version = "^0.3.0", default-features = false }
libssz-merkle = "0.3.0"
libssz-types = { version = "=0.3.0", default-features = false, features = ["alloc"] }
"#;
    let errors = check_libssz_pins(manifest).expect_err("caret pins must fail");
    assert!(
        errors.iter().any(|e| e.contains("libssz must be") && e.contains("version = \"0.3.0\"")),
        "libssz caret must be named: {errors:?}"
    );
    assert!(
        errors.iter().any(|e| e.contains("libssz-derive must be") && e.contains("^0.3.0")),
        "libssz-derive caret must be named: {errors:?}"
    );
    assert!(
        errors.iter().any(|e| e.contains("libssz-merkle must be") && e.contains("\"0.3.0\"")),
        "libssz-merkle string caret must be named: {errors:?}"
    );
    assert!(
        errors.iter().all(|e| !e.contains("libssz-types must be")),
        "exact libssz-types pin must pass: {errors:?}"
    );
}

#[test]
fn exact_inline_table_is_accepted() {
    let manifest = format!(
        "[workspace.dependencies]\n{}\n",
        LIBSSZ_FAMILY
            .iter()
            .map(|name| format!("{name} = {}", expected_spec(name)))
            .collect::<Vec<_>>()
            .join("\n")
    );
    check_libssz_pins(&manifest).unwrap_or_else(|errors| panic!("{}", errors.join("\n")));
}

#[test]
fn live_workspace_manifest_pins_libssz_family_at_0_3_0() {
    let manifest =
        std::fs::read_to_string(workspace_root().join("Cargo.toml")).expect("read root Cargo.toml");
    check_libssz_pins(&manifest).unwrap_or_else(|errors| {
        panic!("root Cargo.toml [workspace.dependencies] libssz pins:\n  {}", errors.join("\n  "))
    });
}
