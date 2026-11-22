//! W4-C2: unknown config keys fail closed, and parse errors do not echo values.
//!
//! Test names do not end in `_root` (KAT scan).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use rvc::config::{
    BnRole, Config, ConfigError, ConfigSource, ParseKind, ServiceBuilder, StartArgs,
};
use validator_store::{ValidatorStore, ValidatorStoreError};

const SECRET: &str = "https://alice:SECRET@host";

fn write_toml(contents: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("temp config");
    file.write_all(contents.as_bytes()).expect("write config");
    file
}

fn load_err(contents: &str) -> (NamedTempFile, ConfigError) {
    let file = write_toml(contents);
    let err = Config::load(Some(file.path()), StartArgs::default()).expect_err("config must fail");
    (file, err)
}

fn renderings(err: ConfigError) -> (String, String, String) {
    let display = err.to_string();
    let debug = format!("{err:?}");
    let chained = format!("{:?}", anyhow::Error::from(err));
    (display, debug, chained)
}

fn assert_no_secret(label: &str, display: &str, debug: &str, chained: &str) {
    for (kind, text) in [("display", display), ("debug", debug), ("anyhow", chained)] {
        assert!(!text.contains("SECRET"), "{label} {kind} echoes a value: {text}");
        assert!(!text.contains(SECRET), "{label} {kind} echoes a value: {text}");
    }
}

fn assert_names_file(text: &str, path: &Path) {
    assert!(
        text.contains(&path.display().to_string()),
        "error must name the file {path:?}, got {text}"
    );
}

#[test]
fn running_guide_secret_provider_block_is_removed_key() {
    let (file, err) = load_err(
        r#"
[secret_provider]
provider = "gcp"
gcp_project_id = "my-project"
gcp_secret_prefix = "validator-key-"
refresh_interval = 3600
"#,
    );
    assert!(
        matches!(
            &err,
            ConfigError::RemovedKey {
                key: "provider",
                replacement: "providers = [\"gcp\"]",
                file: Some(p),
            } if p == file.path()
        ),
        "{err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains("provider"), "{msg}");
    assert!(msg.contains("providers = [\"gcp\"]"), "{msg}");
    assert_names_file(&msg, file.path());
}

#[test]
fn removed_gcp_keys_name_their_replacement() {
    let cases = [
        ("gcp_project_id", "[secret_provider.gcp] project_id"),
        ("gcp_secret_prefix", "[secret_provider.gcp] secret_prefix"),
    ];
    for (key, replacement) in cases {
        let (file, err) = load_err(&format!("[secret_provider]\n{key} = \"x\"\n"));
        assert!(
            matches!(
                &err,
                ConfigError::RemovedKey { key: got, replacement: got_replacement, file: Some(p) }
                    if *got == key && *got_replacement == replacement && p == file.path()
            ),
            "{key}: {err:?}"
        );
        let msg = err.to_string();
        assert!(msg.contains(replacement), "{msg}");
        assert_names_file(&msg, file.path());
    }

    let (file, err) = load_err("[secret_provider.gcp]\ngcp_project_id = \"nested\"\n");
    assert!(
        matches!(
            &err,
            ConfigError::UnknownKey { key, file: Some(p) }
                if key == "gcp_project_id" && p == file.path()
        ),
        "nested gcp_project_id is an unknown key, got {err:?}"
    );
}

#[test]
fn unknown_slashing_key_names_key_and_file() {
    let (file, err) = load_err("[slashing]\nslashing_db = \"x\"\n");
    assert!(
        matches!(
            &err,
            ConfigError::UnknownKey { key, file: Some(p) }
                if key == "slashing_db" && p == file.path()
        ),
        "{err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains("slashing_db"), "{msg}");
    assert_names_file(&msg, file.path());
}

#[test]
fn top_level_typo_names_key_and_file() {
    let (file, err) = load_err("beacon_ulr = \"http://localhost:5052\"\n");
    assert!(
        matches!(
            &err,
            ConfigError::UnknownKey { key, file: Some(p) }
                if key == "beacon_ulr" && p == file.path()
        ),
        "{err:?}"
    );
    let msg = err.to_string();
    assert!(msg.contains("beacon_ulr"), "{msg}");
    assert_names_file(&msg, file.path());
}

#[test]
fn unknown_key_inside_beacon_table_is_rejected() {
    let (file, err) = load_err("[beacon]\nnot_a_beacon_key = 1\n");
    assert!(
        matches!(
            &err,
            ConfigError::UnknownKey { key, file: Some(p) }
                if key == "not_a_beacon_key" && p == file.path()
        ),
        "{err:?}"
    );
    assert_names_file(&err.to_string(), file.path());
}

#[test]
fn unknown_key_inside_server_table_is_rejected() {
    let (file, err) = load_err("[server]\nnot_a_server_key = 1\n");
    assert!(
        matches!(
            &err,
            ConfigError::UnknownKey { key, file: Some(p) }
                if key == "not_a_server_key" && p == file.path()
        ),
        "{err:?}"
    );
    assert_names_file(&err.to_string(), file.path());
}

#[test]
fn security_tables_reject_unknown_keys_at_load() {
    for doc in [
        "[slashing]\nnot_a_key = 1\n",
        "[safety]\nnot_a_key = 1\n",
        "[keymanager]\nnot_a_key = 1\n",
        "[secret_provider]\nnot_a_key = 1\n",
        "[secret_provider.gcp]\nnot_a_key = 1\n",
    ] {
        let (file, err) = load_err(doc);
        assert!(
            matches!(
                &err,
                ConfigError::UnknownKey { key, file: Some(p) }
                    if key == "not_a_key" && p == file.path()
            ),
            "{doc}: {err:?}"
        );
    }
}

#[test]
fn config_load_errors_are_typed_and_carry_the_file() {
    let (file, err) = load_err("[secret_provider]\nprovider = \"gcp\"\n");
    assert!(
        matches!(
            &err,
            ConfigError::RemovedKey { key: "provider", file: Some(p), .. } if p == file.path()
        ),
        "{err:?}"
    );

    let (file, err) = load_err("[slashing]\nslashing_db = \"x\"\n");
    assert!(
        matches!(
            &err,
            ConfigError::UnknownKey { key, file: Some(p) }
                if key == "slashing_db" && p == file.path()
        ),
        "{err:?}"
    );

    let (file, err) = load_err("beacon_ulr = \"..\"\n");
    assert!(
        matches!(
            &err,
            ConfigError::UnknownKey { key, file: Some(p) }
                if key == "beacon_ulr" && p == file.path()
        ),
        "{err:?}"
    );
}

#[test]
fn an_invalid_type_error_does_not_echo_the_value() {
    let (file, err) = load_err(&format!("beacon_nodes = \"{SECRET}\"\n"));
    assert!(
        matches!(
            &err,
            ConfigError::Parse {
                kind: ParseKind::InvalidType { .. },
                file: Some(p),
                ..
            } if p == file.path()
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_no_secret("invalid type", &display, &debug, &chained);
    assert!(display.contains("invalid type"), "{display}");
    assert_names_file(&display, file.path());
}

#[test]
fn a_syntax_error_does_not_echo_the_source_line() {
    let contents = "# comment\nbeacon_url = \"https://alice:SECRET@host\n";
    // Toml reports the newline that ends the unterminated basic string.
    let bad_newline = contents.match_indices('\n').nth(1).expect("bad line").0;
    let (expect_line, expect_col) = offset_to_line_column(contents, bad_newline);
    assert_eq!((expect_line, expect_col), (2, 40));

    let (file, err) = load_err(contents);
    assert!(
        matches!(
            &err,
            ConfigError::Parse {
                kind: ParseKind::Syntax(message),
                file: Some(p),
                line: Some(line),
                column: Some(column),
                ..
            } if p == file.path()
                && *line == expect_line
                && *column == expect_col
                && message == "invalid basic string"
                && !message.contains("SECRET")
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_no_secret("syntax", &display, &debug, &chained);
    assert!(display.contains("at line 2, column 40"), "{display}");
    assert!(display.contains("invalid basic string"), "{display}");
    assert!(!display.contains("beacon_url"), "{display}");
    assert_names_file(&display, file.path());
}

fn offset_to_line_column(content: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    for (idx, ch) in content.char_indices() {
        if idx >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

#[test]
fn a_non_table_network_does_not_echo_the_value() {
    let (file, err) = load_err(&format!("network = [\"{SECRET}\"]\n"));
    assert!(
        matches!(
            &err,
            ConfigError::Invalid {
                field: "config",
                message,
                source_layer: ConfigSource::File(p),
            } if p == file.path()
                && message.contains("array")
                && !message.contains("SECRET")
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_no_secret("network array", &display, &debug, &chained);
    assert!(display.contains("array"), "{display}");
    assert!(!display.contains("Array"), "{display}");

    let (file, err) = load_err(&format!("network = \"{SECRET}\"\n"));
    assert!(
        matches!(
            &err,
            ConfigError::Parse {
                kind: ParseKind::UnknownVariant { ref expected },
                file: Some(p),
                ..
            } if p == file.path() && !expected.contains("SECRET")
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_no_secret("unknown network", &display, &debug, &chained);
    assert!(display.contains("unknown variant"), "{display}");
    assert_names_file(&display, file.path());

    let (file, err) = load_err("logfile = 5\n");
    assert!(
        matches!(
            &err,
            ConfigError::Invalid { field: "config", message, .. }
                if message.contains("integer") && !message.contains("Integer")
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert!(!display.contains("Integer(5)"), "{display}");
    assert!(display.contains("integer"), "{display}");
    assert_names_file(&display, file.path());
    assert!(!debug.contains("Integer(5)"), "{debug}");
    assert!(!chained.contains("Integer(5)"), "{chained}");

    let (file, err) = load_err(&format!("logfile = [\"{SECRET}\"]\n"));
    assert!(
        matches!(
            &err,
            ConfigError::Invalid { field: "config", message, .. }
                if message.contains("array") && !message.contains("SECRET")
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_no_secret("logfile array", &display, &debug, &chained);
    assert!(display.contains("array"), "{display}");
    assert_names_file(&display, file.path());
}

#[test]
fn unknown_key_display_escapes_controls_and_caps_length() {
    let raw = format!("\n\u{1b}[31m{}", "A".repeat(80));
    assert!(raw.chars().count() > 64);
    let err = ConfigError::UnknownKey { key: raw, file: None };
    let (display, debug, chained) = renderings(err);
    assert!(!display.contains('\n'), "{display:?}");
    assert!(!display.contains('\r'), "{display:?}");
    assert!(!display.contains('\u{1b}'), "{display:?}");
    assert!(display.contains("\\n"), "{display}");
    assert!(display.contains("\\u{1b}"), "{display}");
    let start = display.find('`').expect("opening backtick");
    let end = display.rfind('`').expect("closing backtick");
    let shown = &display[start + 1..end];
    assert!(shown.chars().count() <= 64, "shown key is {} chars: {shown}", shown.chars().count());
    assert!(shown.matches('A').count() < 80, "{shown}");
    assert_eq!(display.lines().count(), 1, "{display:?}");
    assert!(!debug.contains('\n') || debug.lines().count() == 1);
    assert!(!debug.contains('\u{1b}'), "{debug:?}");
    // CI sets RUST_BACKTRACE, so anyhow's Debug appends a stack backtrace.
    // The key's own text is the part before that trailer.
    let chain_msg =
        chained.split_once("\n\nStack backtrace:").map(|(head, _)| head).unwrap_or(&chained);
    assert_eq!(chain_msg.lines().count(), 1, "{chain_msg:?}");
    assert!(!chain_msg.contains('\u{1b}'), "{chain_msg:?}");
    assert!(chained.lines().all(|line| !line.contains('\u{1b}')), "{chained:?}");
}

#[test]
fn beacon_nodes_config_still_binds_in_the_beacon_table() {
    let cfg: Config = toml::from_str(
        r#"
[[beacon.beacon_nodes_config]]
url = "http://bn-section:5052"
roles = ["proposal"]
"#,
    )
    .expect("beacon_nodes_config inside [beacon] must bind");
    assert_eq!(cfg.beacon_nodes_config.len(), 1);
    assert_eq!(cfg.beacon_nodes_config[0].url, "http://bn-section:5052");
    assert_eq!(cfg.beacon_nodes_config[0].roles, vec![BnRole::Proposal]);
}

#[test]
fn every_shipped_toml_parses_strict() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut paths = vec![
        root.join("config.example.toml"),
        root.join("crates/rvc/tests/fixtures/rvc-v0.6.toml"),
        root.join("scripts/tests/fixtures/expected_config.toml"),
        root.join("scripts/tests/fixtures/expected_config_docker.toml"),
        root.join("scripts/tests/fixtures/config__beacon_url_only.toml"),
        root.join("scripts/tests/fixtures/config__both_keys.toml"),
        root.join("scripts/tests/fixtures/config__empty_nodes.toml"),
    ];
    let fixtures = root.join("crates/rvc/tests/fixtures/config");
    for entry in fs::read_dir(&fixtures).expect("fixture dir") {
        let path = entry.expect("fixture entry").path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("toml") {
            paths.push(path);
        }
    }
    assert!(paths.len() > 10, "sweep must see the shipped fixture set, got {}", paths.len());
    for path in &paths {
        Config::from_file(path).unwrap_or_else(|err| {
            panic!("{} must parse under strict keys: {err}", path.display());
        });
    }
}

#[test]
fn unknown_key_in_beacon_node_entry_is_rejected() {
    let (file, err) = load_err(
        r#"
[[beacon.beacon_nodes_config]]
url = "http://a:5052"
rolez = ["proposal"]
"#,
    );
    assert!(
        matches!(
            &err,
            ConfigError::UnknownKey { key, file: Some(p) }
                if key == "rolez" && p == file.path()
        ),
        "{err:?}"
    );

    let (file, err) = load_err(
        r#"
[[beacon_nodes_config]]
url = "http://a:5052"
role = ["proposal"]
"#,
    );
    assert!(
        matches!(
            &err,
            ConfigError::UnknownKey { key, file: Some(p) }
                if key == "role" && p == file.path()
        ),
        "{err:?}"
    );
}

fn chain_message(chained: &str) -> &str {
    chained.split_once("\n\nStack backtrace:").map(|(head, _)| head).unwrap_or(chained)
}

fn assert_rendered_key_is_escaped(display: &str, debug: &str, chained: &str) {
    for text in [display, debug, chain_message(chained)] {
        assert!(!text.contains('\n'), "{text:?}");
        assert!(!text.contains('\r'), "{text:?}");
        assert!(!text.contains('\u{1b}'), "{text:?}");
    }
    assert!(display.contains("\\n"), "{display}");
    assert!(display.contains("\\r"), "{display}");
    assert!(display.contains("\\t"), "{display}");
    assert!(display.contains("\\u{1b}"), "{display}");
    let head = chain_message(chained);
    assert!(head.contains("\\n") && head.contains("\\u{1b}"), "{head}");
    assert!(chained.lines().all(|line| !line.contains('\u{1b}') && !line.contains('\r')));
}

#[test]
fn duplicate_and_dotted_keys_escape_controls() {
    let quoted = "\"\\n\\u001B\\r\\t\"";
    let (file, err) = load_err(&format!("{quoted} = 1\n{quoted} = 2\n"));
    assert!(
        matches!(
            &err,
            ConfigError::Parse {
                kind: ParseKind::DuplicateKey(name),
                file: Some(p),
                ..
            } if p == file.path()
                && name.contains('\n')
                && name.contains('\u{1b}')
                && name.contains('\r')
                && name.contains('\t')
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_rendered_key_is_escaped(&display, &debug, &chained);

    let (file, err) = load_err(&format!("{quoted} = 1\n{quoted}.child = 2\n"));
    assert!(
        matches!(
            &err,
            ConfigError::Parse {
                kind: ParseKind::Syntax(message),
                file: Some(p),
                ..
            } if p == file.path()
                && message.starts_with("dotted key `")
                && !message.contains('\n')
                && !message.contains('\u{1b}')
                && !message.contains('\r')
                && message.contains("\\n")
                && message.contains("\\u{1b}")
                && message.contains("\\r")
                && message.contains("\\t")
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_rendered_key_is_escaped(&display, &debug, &chained);
}

#[test]
fn mixed_duplicate_table_header_escapes_controls() {
    let quoted = "\"k\\u001B[2J\\n\\rX\"";
    let contents = format!("[t]\n{quoted}.y = 1\n[t.{quoted}]\n");
    let (file, err) = load_err(&contents);
    assert!(
        matches!(
            &err,
            ConfigError::Parse {
                kind: ParseKind::Syntax(message),
                file: Some(p),
                ..
            } if p == file.path()
                && message.starts_with("invalid table header")
                && !message.chars().any(char::is_control)
        ),
        "{err:?}"
    );
    let (display, _, chained) = renderings(err);
    assert!(!display.chars().any(char::is_control), "{display:?}");
    assert!(display.contains("invalid table header"), "{display}");
    assert!(display.contains("\\n"), "{display}");
    let (head, trailer) = match chained.split_once("\n\nStack backtrace:") {
        Some((head, trailer)) => (head, Some(trailer)),
        None => (chained.as_str(), None),
    };
    assert!(!head.chars().any(char::is_control), "{head:?}");
    if let Some(trailer) = trailer {
        assert!(trailer.chars().all(|c| c == '\n' || !c.is_control()), "{trailer:?}");
    }
}

fn boot_validators(contents: &str) -> (NamedTempFile, ConfigError) {
    let file = write_toml(contents);
    let err = match ServiceBuilder::new(Config::default()).build_validator_store(Some(file.path()))
    {
        Err(err) => err,
        Ok(_) => panic!("validators file must fail"),
    };
    (file, err)
}

fn reload_validators(contents: &str) -> ValidatorStoreError {
    let file =
        write_toml("[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\n");
    let store = ValidatorStore::load_from_config(file.path()).expect("baseline validators file");
    fs::write(file.path(), contents).expect("rewrite validators file");
    store.reload_config().expect_err("reload must fail")
}

fn assert_store_clean(label: &str, err: ValidatorStoreError) -> String {
    let display = err.to_string();
    let debug = format!("{err:?}");
    let chained = format!("{:?}", anyhow::Error::from(err));
    assert_no_secret(label, &display, &debug, &chained);
    display
}

fn toml_basic_string(raw: &str) -> String {
    let mut out = String::from("\"");
    for ch in raw.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn shown_key(display: &str) -> &str {
    let start = display.find('`').expect("opening backtick");
    let end = display.rfind('`').expect("closing backtick");
    &display[start + 1..end]
}

/// Type, value, and syntax errors in the validators file stay value-free at boot and on reload.
#[test]
fn validators_file_parse_errors_do_not_echo_values() {
    let fee = "0x0000000000000000000000000000000000000001";
    let pk = "0x".to_string() + &"11".repeat(48);

    let type_body = format!("[defaults]\nfee_recipient = \"{fee}\"\ngas_limit = \"{SECRET}\"\n");
    let (file, err) = boot_validators(&type_body);
    assert!(
        matches!(
            &err,
            ConfigError::Parse { kind: ParseKind::InvalidType { .. }, file: Some(p), .. }
                if p == file.path()
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_no_secret("boot invalid type", &display, &debug, &chained);
    assert_names_file(&display, file.path());
    let reloaded = assert_store_clean("reload invalid type", reload_validators(&type_body));
    assert!(reloaded.contains("invalid type"), "{reloaded}");

    let value_body = format!(
        "[defaults]\nfee_recipient = \"{fee}\"\n\n[[validators]]\npubkey = \"{pk}\"\nblock_selection_mode = \"{SECRET}\"\n"
    );
    let (file, err) = boot_validators(&value_body);
    assert!(
        matches!(
            &err,
            ConfigError::Parse {
                kind: ParseKind::UnknownVariant { ref expected },
                file: Some(p),
                ..
            } if p == file.path() && !expected.contains("SECRET")
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_no_secret("boot unknown variant", &display, &debug, &chained);
    let reloaded = assert_store_clean("reload unknown variant", reload_validators(&value_body));
    assert!(reloaded.contains("unknown variant"), "{reloaded}");
    assert!(!reloaded.contains("SECRET"), "{reloaded}");

    let syntax = "# comment\nfee_recipient = \"https://alice:SECRET@host\n";
    let (file, err) = boot_validators(syntax);
    assert!(
        matches!(
            &err,
            ConfigError::Parse {
                kind: ParseKind::Syntax(message),
                file: Some(p),
                line: Some(line),
                column: Some(_),
                ..
            } if p == file.path() && *line == 2 && message == "invalid basic string"
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_no_secret("boot syntax", &display, &debug, &chained);
    assert_names_file(&display, file.path());
    assert!(!display.contains("fee_recipient"), "{display}");
    let reloaded = assert_store_clean("reload syntax", reload_validators(syntax));
    assert!(reloaded.contains("invalid basic string"), "{reloaded}");
    assert!(reloaded.contains("at line 2"), "{reloaded}");

    let missing =
        format!("[defaults]\nfee_recipient = \"{fee}\"\n\n[[validators]]\nenabled = true\n");
    let (file, err) = boot_validators(&missing);
    assert!(
        matches!(
            &err,
            ConfigError::Parse { kind: ParseKind::MissingField(name), file: Some(p), .. }
                if name == "pubkey" && p == file.path()
        ),
        "{err:?}"
    );
    let reloaded = reload_validators(&missing);
    match &reloaded {
        ValidatorStoreError::TomlParse(parsed) => {
            assert!(matches!(&parsed.kind, ParseKind::MissingField(name) if name == "pubkey"));
        }
        other => panic!("{other:?}"),
    }
}

/// A validators-file key with controls and a long name is one escaped, bounded line.
#[test]
fn validators_unknown_key_display_escapes_controls_and_caps_length() {
    let fee = "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\n";
    let cases = [
        ("mid", "A".repeat(32)),
        ("boundary", "A".repeat(64)),
        ("boundary+1", "A".repeat(65)),
        ("controls", format!("\n\u{1b}\r\t{}", "A".repeat(80))),
    ];
    for (label, raw) in cases {
        let contents = format!("{fee}{} = 1\n", toml_basic_string(&raw));
        let (file, err) = boot_validators(&contents);
        assert!(
            matches!(
                &err,
                ConfigError::UnknownKey { key, file: Some(p) } if key == &raw && p == file.path()
            ),
            "{label}: {err:?}"
        );
        let (display, debug, chained) = renderings(err);
        assert_eq!(display.lines().count(), 1, "{label}: {display:?}");
        assert!(!display.contains('\n') && !display.contains('\r') && !display.contains('\u{1b}'));
        let shown = shown_key(&display);
        assert!(shown.chars().count() <= 64, "{label}: {shown}");
        if raw.chars().count() <= 64 && !raw.chars().any(char::is_control) {
            assert_eq!(shown, raw, "{label}");
        } else {
            assert!(shown.chars().count() < raw.chars().count(), "{label}: {shown}");
        }
        if label == "boundary+1" {
            assert_eq!(shown, "A".repeat(64), "{label}: {shown}");
        }
        if label == "controls" {
            assert!(display.contains("\\n") && display.contains("\\r") && display.contains("\\t"));
            assert!(display.contains("\\u{1b}"), "{display}");
            assert_rendered_key_is_escaped(&display, &debug, &chained);
        }
        let reloaded = assert_store_clean(label, reload_validators(&contents));
        assert_eq!(reloaded.lines().count(), 1, "{label}: {reloaded:?}");
        assert!(!reloaded.contains('\u{1b}'), "{reloaded:?}");
        let shown = shown_key(&reloaded);
        assert!(shown.chars().count() <= 64, "{label} reload: {shown}");
        if label == "boundary+1" {
            assert_eq!(shown, "A".repeat(64), "{label} reload: {shown}");
        }
    }
}

/// Duplicate, dotted, and mixed table-header failures on the validators path stay escaped.
#[test]
fn validators_file_duplicate_and_dotted_keys_escape_controls() {
    let quoted = "\"\\n\\u001B\\r\\t\"";
    let duplicate = format!("{quoted} = 1\n{quoted} = 2\n");
    let (file, err) = boot_validators(&duplicate);
    assert!(
        matches!(
            &err,
            ConfigError::Parse { kind: ParseKind::DuplicateKey(name), file: Some(p), .. }
                if p == file.path() && name.contains('\n') && name.contains('\u{1b}')
        ),
        "{err:?}"
    );
    let (display, debug, chained) = renderings(err);
    assert_rendered_key_is_escaped(&display, &debug, &chained);
    let reloaded = reload_validators(&duplicate);
    match &reloaded {
        ValidatorStoreError::TomlParse(parsed) => {
            assert!(matches!(&parsed.kind, ParseKind::DuplicateKey(name) if name.contains('\n')));
        }
        other => panic!("{other:?}"),
    }
    let reloaded = assert_store_clean("reload duplicate", reloaded);
    assert_rendered_key_is_escaped(&reloaded, &reloaded, &reloaded);

    let dotted = format!("{quoted} = 1\n{quoted}.child = 2\n");
    let (file, err) = boot_validators(&dotted);
    assert!(
        matches!(
            &err,
            ConfigError::Parse { kind: ParseKind::Syntax(message), file: Some(p), .. }
                if p == file.path()
                    && message.starts_with("dotted key `")
                    && !message.chars().any(char::is_control)
        ),
        "{err:?}"
    );
    let reloaded = assert_store_clean("reload dotted", reload_validators(&dotted));
    assert!(reloaded.contains("dotted key `"), "{reloaded}");
    assert!(!reloaded.chars().any(char::is_control), "{reloaded:?}");

    let header = format!("[t]\n{quoted}.y = 1\n[t.{quoted}]\n");
    let (file, err) = boot_validators(&header);
    assert!(
        matches!(
            &err,
            ConfigError::Parse { kind: ParseKind::Syntax(message), file: Some(p), .. }
                if p == file.path()
                    && message.starts_with("invalid table header")
                    && !message.chars().any(char::is_control)
        ),
        "{err:?}"
    );
    let reloaded = assert_store_clean("reload header", reload_validators(&header));
    assert!(reloaded.contains("invalid table header"), "{reloaded}");
    assert!(reloaded.contains("\\n"), "{reloaded}");
    assert!(!reloaded.chars().any(char::is_control), "{reloaded:?}");
}

/// A structural validators error that is not a parse failure still names the file.
#[test]
fn validators_config_error_names_the_file() {
    let (file, err) = boot_validators(
        "[defaults]\nfee_recipient = \"0x0000000000000000000000000000000000000001\"\n\n[[validators]]\npubkey = \"zz\"\n",
    );
    match err {
        ConfigError::ValidatorStoreError(message) => {
            assert!(message.contains(&file.path().display().to_string()), "{message}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn every_shipped_validators_toml_parses_strict() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let paths = [
        root.join("validators.example.toml"),
        root.join("scripts/tests/fixtures/expected_validators.toml"),
        root.join("scripts/tests/fixtures/validators__three_entries.toml"),
        root.join("scripts/tests/fixtures/validators__unprefixed.toml"),
    ];
    for path in paths {
        ValidatorStore::load_from_config(&path).unwrap_or_else(|err| {
            panic!("{} must load under strict keys: {err}", path.display());
        });
    }
    let template = fs::read_to_string(root.join("scripts/devnet/config/templates/validators.toml"))
        .expect("devnet validators template")
        .replace("@@FEE_RECIPIENT@@", "0x0000000000000000000000000000000000000001");
    let file = write_toml(&template);
    ValidatorStore::load_from_config(file.path()).unwrap_or_else(|err| {
        panic!("devnet template must load under strict keys: {err}");
    });
}
