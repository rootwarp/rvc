//! Configuration error types.

use std::fmt;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Display cap for an unknown-key name. Control characters are escaped first,
/// then the escaped form is cut so a crafted key cannot inject a new log line
/// or a terminal escape, and cannot grow the line without bound.
const KEY_DISPLAY_MAX_CHARS: usize = 64;

/// Fixed text for a serde message [`ParseKind::from_serde_message`] does not
/// recognise. The raw message is dropped, so a credential in it cannot render.
const UNRECOGNIZED_PARSE: &str = "unrecognized config parse error";

/// Category of a config parse failure. The unexpected value is never stored.
///
/// W4-C3 reuses this type for the validators file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseKind {
    /// Toml's `message()` only. The source snippet is not included.
    Syntax(String),
    /// Serde `invalid type`, keeping the static `expected` tail.
    InvalidType { expected: String },
    /// Serde `invalid value`, keeping the static `expected` tail.
    InvalidValue { expected: String },
    /// Serde `unknown variant`, keeping the static `expected` tail.
    UnknownVariant { expected: String },
    /// Serde `missing field`.
    MissingField(String),
    /// Toml/serde duplicate key. Empty when the message names no key.
    DuplicateKey(String),
    /// Serde `invalid length`. The length and the value are not stored.
    InvalidLength,
    /// A message shape this parser does not recognise. Fixed text only.
    Other,
}

impl ParseKind {
    /// Classify a serde error message, keeping only the static `expected` tail.
    ///
    /// The "unexpected" half holds the operator's value and is dropped. A shape
    /// this function does not recognise becomes [`ParseKind::Other`].
    pub fn from_serde_message(message: &str) -> Self {
        let message = message.trim();
        if let Some(kind) = classify_serde_message(message) {
            return kind;
        }
        Self::Other
    }
}

impl fmt::Display for ParseKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Syntax(message) => f.write_str(message),
            Self::InvalidType { expected } => write!(f, "invalid type: expected {expected}"),
            Self::InvalidValue { expected } => write!(f, "invalid value: expected {expected}"),
            Self::UnknownVariant { expected } => write!(f, "unknown variant: expected {expected}"),
            Self::MissingField(name) => write!(f, "missing field `{name}`"),
            Self::DuplicateKey(name) if name.is_empty() => f.write_str("duplicate key"),
            Self::DuplicateKey(name) => write!(f, "duplicate key `{}`", escape_key(name)),
            Self::InvalidLength => f.write_str("invalid length"),
            Self::Other => f.write_str(UNRECOGNIZED_PARSE),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    FileNotFound(PathBuf),

    #[error("failed to read config file: {0}")]
    ReadError(#[from] std::io::Error),

    /// A TOML parse or type error. The value and the source line are not stored.
    #[error("{}", format_parse(.file, .line, .column, .path, .kind))]
    Parse {
        /// Config file, when the error came from [`crate::config::Config::from_file`].
        file: Option<PathBuf>,
        /// 1-based row from `err.span()` over the file text. Absent when toml has no span.
        line: Option<usize>,
        /// 1-based column from `err.span()` over the file text.
        column: Option<usize>,
        /// Dotted key path. Display escapes and caps it. None for document syntax errors.
        path: Option<String>,
        /// Fixed category. Never the raw toml error.
        kind: ParseKind,
    },

    /// Field-level error that names the provenance layer (`defaults < file < CLI`).
    #[error("{field}: {message} (from {source_layer})")]
    Invalid {
        /// Dotted field path (e.g. `config`).
        field: &'static str,
        /// Human-readable reason.
        message: String,
        /// Layer that supplied the bad value.
        source_layer: rvc_config::ConfigSource,
    },

    #[error("invalid beacon URL: {0}")]
    InvalidBeaconUrl(String),

    #[error("keystore path does not exist: {0}")]
    KeystorePathNotFound(PathBuf),

    #[error("slashing db path parent directory does not exist: {0}")]
    SlashingDbPathInvalid(PathBuf),

    /// Missing slashing DB without an explicit operator opt-in (SEC-3).
    ///
    /// Creating a fresh empty DB would let the process sign with **zero history**.
    /// For a genuine new deployment, pass `--init-slashing-db` or set
    /// `allow_fresh_db = true` in the config file.
    #[error(
        "slashing protection database does not exist at {0}. \
         Refusing to create a fresh empty DB (would sign with zero history). \
         For a genuine new deployment, pass --init-slashing-db or set \
         allow_fresh_db = true in config. If this path should hold existing \
         history, restore the DB from backup."
    )]
    SlashingDbMissing(PathBuf),

    /// 0-byte or corrupt-header slashing DB (SEC-3). Always a hard error.
    #[error(
        "slashing protection database at {0} is empty or corrupt \
         (0-byte or invalid SQLite header). This indicates truncation or \
         corruption — never treated as a fresh init. Restore from backup; \
         --init-slashing-db / allow_fresh_db cannot override this."
    )]
    SlashingDbCorrupt(PathBuf),

    #[error("invalid network: {0}")]
    InvalidNetwork(String),

    #[error("missing required field: {0}")]
    MissingField(String),

    #[error("invalid port number: {0}")]
    InvalidPort(u16),

    /// A key that is not a field of any config table.
    ///
    /// `key` is the name serde reported. Display escapes control characters and
    /// caps the name at 64 characters; Debug keeps the raw name.
    #[error("unknown key `{}`{}", escape_key(.key.as_str()), file_location(.file.as_ref()))]
    UnknownKey {
        /// Key name from serde's `unknown field` message.
        key: String,
        /// Config file, when the error came from a path-bearing load.
        file: Option<PathBuf>,
    },

    /// A key removed in this release. `replacement` names what to write instead.
    #[error(
        "`{key}` was removed in this release. Use {replacement} instead{}",
        file_location(.file.as_ref())
    )]
    RemovedKey {
        /// Operator-facing key (`grpc_port`, `provider`, …).
        key: &'static str,
        /// What replaces the removed key.
        replacement: &'static str,
        /// Config file, when the error came from a path-bearing load.
        file: Option<PathBuf>,
    },

    #[error("invalid graffiti: {0}")]
    InvalidGraffiti(String),

    #[error("password file not found: {0}")]
    PasswordFileNotFound(PathBuf),

    #[error("failed to read password file: {0}")]
    PasswordReadError(String),

    /// A persisted keymanager import password cannot be used at boot.
    ///
    /// `reason` is a fixed phrase. The password itself is never included.
    #[error("import password secret at {path} is unusable: {reason}")]
    ImportSecret {
        /// File or directory that failed the check.
        path: PathBuf,
        /// Why it cannot be used. Never the password bytes.
        reason: &'static str,
    },

    #[error("key manager error: {0}")]
    KeyManagerError(#[from] crypto::KeyManagerError),

    #[error("slashing db error: {0}")]
    SlashingDbError(#[from] slashing::SlashingError),

    #[error("beacon client error: {0}")]
    BeaconClientError(#[from] beacon::BeaconError),

    #[error("feature not enabled: {0}")]
    FeatureNotEnabled(String),

    #[error("secret provider error: {0}")]
    SecretProviderError(String),

    #[error(
        "--allow-insecure-remote-signer requires RVC_ALLOW_INSECURE=true environment variable"
    )]
    InsecureFlagRequiresEnvVar,

    /// Returned when the effective default fee recipient is the zero address.
    ///
    /// All EL fees and MEV rewards would be silently routed to the burn
    /// address.  Operators must set a non-zero address in their validators
    /// config file:
    ///
    /// ```toml
    /// [defaults]
    /// fee_recipient = "0x<your-fee-address>"
    /// ```
    #[error(
        "default_fee_recipient is the zero address \
         (0x0000000000000000000000000000000000000000), which routes all EL \
         fees and MEV rewards to the burn address.\n\
         Set a non-zero fee_recipient in your validators config file:\n\
         \n\
         [defaults]\n\
         fee_recipient = \"0x<your-fee-address>\"\n\
         \n\
         Pass the file with --validators-config <path>."
    )]
    ZeroFeeRecipient,

    /// The validators config file exists and has no content.
    ///
    /// Boot refuses it. Recover from `validators.toml.rejected` by editing
    /// that document, not by treating the empty file as a missing fee recipient.
    #[error(
        "validators config file is empty; boot refuses it. \
         Recover from validators.toml.rejected by copying it aside, \
         setting the affected key to enabled = false, deleting doppelganger_hold_until, \
         and replacing validators.toml with that edited file. \
         Do not restore validators.toml.rejected unchanged."
    )]
    EmptyValidatorsConfig,

    /// Wraps a `ValidatorStoreError` that occurs during validator store construction.
    #[error("validator store error: {0}")]
    ValidatorStoreError(String),
}

impl From<rvc_config::ConfigError> for ConfigError {
    fn from(err: rvc_config::ConfigError) -> Self {
        match err {
            rvc_config::ConfigError::Invalid { field, message, source_layer } => {
                Self::Invalid { field, message, source_layer }
            }
        }
    }
}

/// Where a toml error was raised.
enum DeOrigin {
    /// `toml::from_str` of the file. Unrecognised messages stay [`ParseKind::Syntax`].
    Document,
    /// A value that already parsed. Unrecognised messages become [`ParseKind::Other`].
    Data,
}

/// Map a toml deserialize error onto [`ConfigError`] without keeping the error.
///
/// Line and column come from `err.span()` over `content`. An `unknown field`
/// message becomes [`ConfigError::UnknownKey`]. Unrecognised messages from the
/// document parse stay [`ParseKind::Syntax`]; [`parse_data_error`] maps those
/// to [`ParseKind::Other`]. W4-C3 reuses this for the validators file. The toml
/// error is borrowed and dropped here: no variant stores it or a `String` built
/// from its Display.
pub(crate) fn parse_error(
    err: &toml::de::Error,
    content: Option<&str>,
    file: Option<&Path>,
) -> ConfigError {
    map_de_error(err, content, file.map(Path::to_path_buf), None, DeOrigin::Document)
}

/// Map a semantic deserialize error. `path` is the key path, never the value.
pub(crate) fn parse_data_error(err: &toml::de::Error, path: Option<String>) -> ConfigError {
    map_de_error(err, None, None, path, DeOrigin::Data)
}

fn map_de_error(
    err: &toml::de::Error,
    content: Option<&str>,
    file: Option<PathBuf>,
    path: Option<String>,
    origin: DeOrigin,
) -> ConfigError {
    let message = err.message();
    let (line, column) = line_column(content, err.span());

    if let Some(key) = unknown_field_key(message) {
        return ConfigError::UnknownKey { key, file };
    }
    if message.trim_start().starts_with("unknown field") {
        return ConfigError::Parse { file, line, column, path, kind: ParseKind::Other };
    }
    if serde_data_prefix(message) {
        return ConfigError::Parse {
            file,
            line,
            column,
            path,
            kind: ParseKind::from_serde_message(message),
        };
    }
    if let Some(key) = dotted_key_name(message) {
        return ConfigError::Parse {
            file,
            line,
            column,
            path,
            kind: ParseKind::Syntax(format!("dotted key `{}`", escape_key(key))),
        };
    }

    let kind = match origin {
        DeOrigin::Data => ParseKind::Other,
        DeOrigin::Document => ParseKind::Syntax(escape_controls(message)),
    };
    ConfigError::Parse { file, line, column, path, kind }
}

fn dotted_key_name(message: &str) -> Option<&str> {
    let rest = message.trim_start().strip_prefix("dotted key `")?;
    let end = rest.find('`')?;
    let key = &rest[..end];
    if key.is_empty() {
        None
    } else {
        Some(key)
    }
}

fn classify_serde_message(message: &str) -> Option<ParseKind> {
    if message.starts_with("invalid type:") {
        return Some(match expected_tail(message, "invalid type:") {
            Some(expected) => ParseKind::InvalidType { expected },
            None => ParseKind::Other,
        });
    }
    if message.starts_with("invalid value:") {
        return Some(match expected_tail(message, "invalid value:") {
            Some(expected) => ParseKind::InvalidValue { expected },
            None => ParseKind::Other,
        });
    }
    if message.starts_with("unknown variant") {
        return Some(match expected_tail(message, "unknown variant") {
            Some(expected) => ParseKind::UnknownVariant { expected },
            None => ParseKind::Other,
        });
    }
    if message.starts_with("missing field") {
        return Some(match backtick_payload(message) {
            Some(name) => ParseKind::MissingField(name),
            None => ParseKind::Other,
        });
    }
    if message.starts_with("duplicate key") {
        return Some(ParseKind::DuplicateKey(backtick_payload(message).unwrap_or_default()));
    }
    if message.starts_with("invalid length") {
        return Some(ParseKind::InvalidLength);
    }
    None
}

fn serde_data_prefix(message: &str) -> bool {
    let message = message.trim_start();
    message.starts_with("invalid type:")
        || message.starts_with("invalid value:")
        || message.starts_with("unknown variant")
        || message.starts_with("missing field")
        || message.starts_with("duplicate key")
        || message.starts_with("invalid length")
}

/// Text after the last `, expected ` marker. `None` when that tail is missing,
/// so the unexpected half (which holds the value) is never returned.
fn expected_tail(message: &str, prefix: &str) -> Option<String> {
    let rest = message.strip_prefix(prefix)?;
    let marker = ", expected ";
    let idx = rest.rfind(marker)?;
    let tail = rest[idx + marker.len()..].trim();
    if tail.is_empty() {
        None
    } else {
        Some(tail.to_string())
    }
}

fn backtick_payload(message: &str) -> Option<String> {
    let start = message.find('`')?;
    let rest = &message[start + '`'.len_utf8()..];
    let end = rest.find('`')?;
    Some(rest[..end].to_string())
}

fn unknown_field_key(message: &str) -> Option<String> {
    let rest = message.trim_start().strip_prefix("unknown field ")?;
    let rest = rest.strip_prefix('`')?;
    let end = rest.find('`')?;
    Some(rest[..end].to_string())
}

fn line_column(
    content: Option<&str>,
    span: Option<std::ops::Range<usize>>,
) -> (Option<usize>, Option<usize>) {
    let (Some(content), Some(span)) = (content, span) else {
        return (None, None);
    };
    let (line, column) = offset_to_line_column(content, span.start);
    (Some(line), Some(column))
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

/// Escape C0 controls so a document `Syntax` message cannot split a log line.
///
/// Unlike [`escape_key`], this does not cap the length: the sentence after the
/// controls is the diagnostic.
fn escape_controls(text: &str) -> String {
    let mut out = String::new();
    for ch in text.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                out.push_str(&format!("\\u{{{:x}}}", u32::from(c)));
            }
            c => out.push(c),
        }
    }
    out
}

fn escape_key(key: &str) -> String {
    let mut out = String::new();
    for ch in key.chars() {
        let piece = match ch {
            '\n' => "\\n".to_string(),
            '\r' => "\\r".to_string(),
            '\t' => "\\t".to_string(),
            c if c.is_control() => format!("\\u{{{:x}}}", u32::from(c)),
            c => c.to_string(),
        };
        if out.chars().count() + piece.chars().count() > KEY_DISPLAY_MAX_CHARS {
            break;
        }
        out.push_str(&piece);
    }
    out
}

fn file_location(file: Option<&PathBuf>) -> String {
    match file {
        Some(path) => format!(" in {}", path.display()),
        None => String::new(),
    }
}

fn format_parse(
    file: &Option<PathBuf>,
    line: &Option<usize>,
    column: &Option<usize>,
    path: &Option<String>,
    kind: &ParseKind,
) -> String {
    let mut message = match file {
        Some(file) => format!("failed to parse {}", file.display()),
        None => "failed to parse config".to_string(),
    };
    if let Some(path) = path {
        message.push_str(&format!(": key `{}`", escape_key(path)));
    }
    message.push_str(&format!(": {kind}"));
    if let (Some(line), Some(column)) = (line, column) {
        message.push_str(&format!(" at line {line}, column {column}"));
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn boom<'de, D: serde::Deserializer<'de>>(_: D) -> Result<u8, D::Error> {
        Err(serde::de::Error::custom(
            "totally unexpected shape with https://alice:SECRET@host inside",
        ))
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct CustomProbe {
        #[serde(deserialize_with = "boom")]
        value: u8,
    }

    const SECRET: &str = "https://alice:SECRET@host";

    fn assert_no_secret(kind: &ParseKind, message: &str) {
        let display = kind.to_string();
        let debug = format!("{kind:?}");
        assert!(!display.contains("SECRET"), "{message} -> {display}");
        assert!(!debug.contains("SECRET"), "{message} -> {debug}");
        assert!(!display.contains(SECRET), "{message} -> {display}");
        assert!(!debug.contains(SECRET), "{message} -> {debug}");
    }

    #[test]
    fn parse_kind_keeps_no_unexpected_value() {
        let rows = [
            (
                format!("invalid type: string \"{SECRET}\", expected a sequence"),
                "invalid type",
                false,
            ),
            (
                format!("invalid type: string \"value, expected {SECRET}\", expected a sequence"),
                "invalid type",
                false,
            ),
            (
                format!("invalid value: string \"{SECRET}\", expected one of `sign`, `reject`"),
                "invalid value",
                false,
            ),
            (
                format!("unknown variant `{SECRET}`, expected one of `mainnet`, `hoodi`"),
                "unknown variant",
                false,
            ),
            (format!("invalid type: string \"{SECRET}\""), UNRECOGNIZED_PARSE, true),
            (format!("totally unexpected shape with {SECRET} inside"), UNRECOGNIZED_PARSE, true),
        ];

        for (message, needle, is_other) in rows {
            let kind = ParseKind::from_serde_message(&message);
            assert_no_secret(&kind, &message);
            let display = kind.to_string();
            assert!(display.contains(needle), "{message} -> {display}");
            assert_eq!(matches!(kind, ParseKind::Other), is_other, "{message} -> {kind:?}");
            if is_other {
                assert_eq!(display, UNRECOGNIZED_PARSE);
                assert!(!display.contains(&message), "{display}");
            }
        }

        let missing = ParseKind::from_serde_message("missing field `fee_recipient`");
        assert_eq!(missing, ParseKind::MissingField("fee_recipient".to_string()));
        assert_no_secret(&missing, "missing field");

        let duplicate = ParseKind::from_serde_message("duplicate key `beacon_url`");
        assert_eq!(duplicate, ParseKind::DuplicateKey("beacon_url".to_string()));

        let length = ParseKind::from_serde_message(&format!(
            "invalid length 3, expected a tuple of size 2 holding {SECRET}"
        ));
        assert_eq!(length, ParseKind::InvalidLength);
        assert_no_secret(&length, "invalid length");
        assert_eq!(length.to_string(), "invalid length");
    }

    #[test]
    fn data_path_custom_error_keeps_no_raw_text() {
        let err = toml::from_str::<CustomProbe>("value = 1").expect_err("custom");
        assert!(
            err.message().contains("SECRET"),
            "probe must carry the raw text: {}",
            err.message()
        );
        let mapped = parse_data_error(&err, Some("value".to_string()));
        assert!(
            matches!(
                &mapped,
                ConfigError::Parse {
                    kind: ParseKind::Other,
                    path: Some(path),
                    line: None,
                    column: None,
                    file: None,
                } if path == "value"
            ),
            "{mapped:?}"
        );
        let display = mapped.to_string();
        let debug = format!("{mapped:?}");
        assert!(!display.contains("SECRET"), "{display}");
        assert!(!debug.contains("SECRET"), "{debug}");
        assert!(display.contains(UNRECOGNIZED_PARSE), "{display}");
        assert!(display.contains("value"), "{display}");
    }
}
