//! Validator-store errors and the shared TOML classifier.
//!
//! [`classify_document_error`] is the one place a toml deserialize error is
//! turned into key, line, column, and [`ParseKind`]. `ConfigError` in `rvc`
//! and [`ValidatorStoreError::TomlParse`] both render that result. The toml
//! error itself is never stored: its Display quotes the source line, and a
//! validators file can hold builder URLs.

use std::fmt;

use thiserror::Error;

/// Display cap for an unknown-key name. Control characters are escaped first,
/// then the escaped form is cut so a crafted key cannot inject a new log line
/// or a terminal escape, and cannot grow the line without bound.
const KEY_DISPLAY_MAX_CHARS: usize = 64;

/// Fixed text for a serde message [`ParseKind::from_serde_message`] does not
/// recognise. The raw message is dropped, so a credential in it cannot render.
pub const UNRECOGNIZED_PARSE: &str = "unrecognized config parse error";

/// Category of a config parse failure. The unexpected value is never stored.
///
/// `rvc::config::ParseKind` is a re-export of this type. W4-C2 introduced it
/// for `config.toml`; the validators file uses the same classifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseKind {
    /// Toml's `message()` only, with C0 controls escaped. The source snippet
    /// is not included.
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

/// Where a toml error was raised.
#[derive(Clone, Copy)]
enum DeOrigin {
    /// `toml::from_str` of the file. Unrecognised messages stay [`ParseKind::Syntax`].
    Document,
    /// A value that already parsed. Unrecognised messages become [`ParseKind::Other`].
    Data,
}

/// A toml deserialize failure with the value and the source line removed.
///
/// `unknown_key` is set only for serde's `unknown field` message. Display
/// escapes and caps that name. Debug keeps the raw name inside the `String`
/// debug form, which escapes controls; it does not include a source snippet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedToml {
    /// Key from `unknown field \`name\``. `None` for every other failure.
    pub unknown_key: Option<String>,
    /// 1-based row from `err.span()` over the file text. Absent when toml has no span.
    pub line: Option<usize>,
    /// 1-based column from `err.span()` over the file text.
    pub column: Option<usize>,
    /// Fixed category. Ignored by Display when [`Self::unknown_key`] is set.
    pub kind: ParseKind,
}

impl fmt::Display for ClassifiedToml {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(key) = &self.unknown_key {
            return write!(f, "unknown key `{}`", escape_key(key));
        }
        write!(f, "{}", self.kind)?;
        if let (Some(line), Some(column)) = (self.line, self.column) {
            write!(f, " at line {line}, column {column}")?;
        }
        Ok(())
    }
}

/// Classify a document-level toml error. `content` supplies line and column.
///
/// The returned value does not borrow `err`. Drop `err` after this call.
pub fn classify_document_error(err: &toml::de::Error, content: Option<&str>) -> ClassifiedToml {
    classify_toml(err, content, DeOrigin::Document)
}

/// Classify a semantic deserialize error. Unrecognised messages become
/// [`ParseKind::Other`] and line/column are absent.
pub fn classify_data_error(err: &toml::de::Error) -> ClassifiedToml {
    classify_toml(err, None, DeOrigin::Data)
}

fn classify_toml(err: &toml::de::Error, content: Option<&str>, origin: DeOrigin) -> ClassifiedToml {
    let message = err.message();
    let (line, column) = line_column(content, err.span());

    if let Some(key) = unknown_field_key(message) {
        return ClassifiedToml { unknown_key: Some(key), line, column, kind: ParseKind::Other };
    }
    if message.trim_start().starts_with("unknown field") {
        return ClassifiedToml { unknown_key: None, line, column, kind: ParseKind::Other };
    }
    if serde_data_prefix(message) {
        return ClassifiedToml {
            unknown_key: None,
            line,
            column,
            kind: ParseKind::from_serde_message(message),
        };
    }
    if let Some(key) = dotted_key_name(message) {
        return ClassifiedToml {
            unknown_key: None,
            line,
            column,
            kind: ParseKind::Syntax(format!("dotted key `{}`", escape_key(key))),
        };
    }

    let kind = match origin {
        DeOrigin::Data => ParseKind::Other,
        DeOrigin::Document => ParseKind::Syntax(escape_controls(message)),
    };
    ClassifiedToml { unknown_key: None, line, column, kind }
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
pub fn escape_controls(text: &str) -> String {
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

/// Escape C0 controls in a key name and cap the escaped form at 64 characters.
pub fn escape_key(key: &str) -> String {
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

#[derive(Debug, Error)]
pub enum ValidatorStoreError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    /// A validators-file parse failure.
    ///
    /// The toml error is not stored, so Display, Debug, and `source` cannot
    /// quote the source line or the unexpected value.
    #[error("{0}")]
    TomlParse(ClassifiedToml),
    #[error("config error: {0}")]
    Config(String),
    /// The durable update did not publish.
    ///
    /// The pubkey was absent when the candidate was cloned, or its identity
    /// changed during the write (removed or replaced) and the in-flight delta
    /// was dropped. Neither case is a successful publish.
    #[error("validator not found")]
    NotFound,
    /// Reload refused a missing or zero `[defaults] fee_recipient`.
    ///
    /// Boot keeps its own check in `ServiceBuilder::build_validator_store`.
    /// `load_from_config` still accepts the zero address so tests and the
    /// doppelganger-hold pre-read can open a file that has not been checked.
    #[error(
        "[defaults] fee_recipient is the zero address \
         (0x0000000000000000000000000000000000000000); \
         reload refuses a missing or zero default fee recipient"
    )]
    ZeroDefaultFeeRecipient,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    const SECRET: &str = "https://alice:SECRET@host";

    fn boom<'de, D: serde::Deserializer<'de>>(_: D) -> Result<u8, D::Error> {
        Err(serde::de::Error::custom(format!("unknown field without a backtick {SECRET}")))
    }

    fn boom_line<'de, D: serde::Deserializer<'de>>(_: D) -> Result<u8, D::Error> {
        Err(serde::de::Error::custom(format!("broken header\n{SECRET}")))
    }

    #[derive(Debug, Deserialize)]
    struct Probe {
        #[serde(deserialize_with = "boom")]
        #[allow(dead_code)]
        value: u8,
    }

    #[derive(Debug, Deserialize)]
    struct LineProbe {
        #[serde(deserialize_with = "boom_line")]
        #[allow(dead_code)]
        value: u8,
    }

    /// `unknown field` with no backtick payload is [`ParseKind::Other`], not the raw message.
    #[test]
    fn unknown_field_without_a_key_drops_the_message() {
        let err = toml::from_str::<Probe>("value = 1").expect_err("custom");
        assert!(err.message().contains("SECRET"), "{}", err.message());
        let classified = classify_document_error(&err, Some("value = 1"));
        assert!(classified.unknown_key.is_none());
        assert!(matches!(classified.kind, ParseKind::Other));
        let display = classified.to_string();
        let debug = format!("{classified:?}");
        assert!(!display.contains("SECRET"), "{display}");
        assert!(!debug.contains("SECRET"), "{debug}");
        assert!(display.starts_with(UNRECOGNIZED_PARSE), "{display}");
        assert!(display.contains("at line 1, column 9"), "{display}");
    }

    /// A document message that is not a serde shape is syntax text with controls escaped.
    #[test]
    fn document_fallback_escapes_controls_in_the_message() {
        let err = toml::from_str::<LineProbe>("value = 1").expect_err("custom");
        let classified = classify_document_error(&err, Some("value = 1"));
        let ParseKind::Syntax(message) = &classified.kind else {
            panic!("{:?}", classified.kind);
        };
        assert!(!message.contains('\n'), "{message:?}");
        assert!(message.contains("\\n"), "{message}");
        assert!(!classified.to_string().contains('\n'), "{}", classified);
    }
}
