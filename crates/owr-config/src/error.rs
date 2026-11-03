//! Error and validation-issue types.

use std::fmt::{self, Write as _};
use std::path::PathBuf;

use owr_common::AtomicWriteError;

/// One validation failure at a config path such as `network.vlans[1].ports[0]`.
///
/// Messages never contain secret values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    pub path: String,
    pub message: String,
}

impl Issue {
    pub fn new(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for Issue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

/// Everything that can go wrong loading, validating or storing a config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{}", describe_parse(.0))]
    Parse(toml::de::Error),
    #[error("serializing config: {0}")]
    Serialize(toml::ser::Error),
    #[error("invalid configuration: {}", join_issues(.0))]
    Invalid(Vec<Issue>),
    #[error("unsupported config schema {0} (this build supports up to {max})", max = crate::CURRENT_SCHEMA)]
    UnsupportedSchema(u32),
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error(transparent)]
    Atomic(#[from] AtomicWriteError),
}

impl ConfigError {
    /// The validation issues, if this is an [`ConfigError::Invalid`].
    pub fn issues(&self) -> &[Issue] {
        match self {
            Self::Invalid(issues) => issues,
            _ => &[],
        }
    }
}

impl From<toml::de::Error> for ConfigError {
    fn from(e: toml::de::Error) -> Self {
        Self::Parse(e)
    }
}

impl From<toml::ser::Error> for ConfigError {
    fn from(e: toml::ser::Error) -> Self {
        Self::Serialize(e)
    }
}

fn join_issues(issues: &[Issue]) -> String {
    let list: Vec<String> = issues.iter().map(ToString::to_string).collect();
    format!("{} issue(s): {}", list.len(), list.join("; "))
}

/// `toml::de::Error`'s own `Display` echoes the offending source line, which may be a
/// passphrase. Print only the message and byte span.
fn describe_parse(e: &toml::de::Error) -> String {
    match e.span() {
        Some(span) => format!(
            "parsing config: {} (bytes {}..{})",
            redact_values(e.message()),
            span.start,
            span.end
        ),
        None => format!("parsing config: {}", redact_values(e.message())),
    }
}

impl ConfigError {
    /// A deserialization failure with the field path. The message is sanitized by
    /// [`redact_values`] (via `Display`), so the offending value is never echoed.
    pub(crate) fn from_path_error(e: &serde_path_to_error::Error<toml::de::Error>) -> Self {
        let raw = e.inner().message();
        let mut segments: Vec<&serde_path_to_error::Segment> = e.path().iter().collect();
        // For an unknown or duplicate key the last segment is the user's key, not a schema
        // field; report the table that holds it instead.
        if raw.starts_with("unknown field") || raw.starts_with("duplicate field") {
            segments.pop();
        }
        let path = format_path(&segments);
        let message = redact_values(raw);
        Self::Parse(<toml::de::Error as serde::de::Error>::custom(format!(
            "invalid value at {path}: {message}"
        )))
    }
}

/// Same shape as `serde_path_to_error::Path`'s `Display`: `users[0].password_hash`, or `.`
/// for the document root.
fn format_path(segments: &[&serde_path_to_error::Segment]) -> String {
    if segments.is_empty() {
        return ".".to_owned();
    }
    let mut out = String::new();
    let mut separator = "";
    for segment in segments {
        if !matches!(segment, serde_path_to_error::Segment::Seq { .. }) {
            out.push_str(separator);
        }
        let _ = write!(out, "{segment}");
        separator = ".";
    }
    out
}

/// Replace everything between backticks or quotes with `…`.
///
/// serde type errors look like ``invalid type: integer `12345678`, expected a string`` or
/// `unknown variant "x", expected ...`; the quoted part is the user's input and may be a
/// passphrase or password hash. An unterminated quote swallows the rest of the message.
pub(crate) fn redact_values(msg: &str) -> String {
    let mut out = String::with_capacity(msg.len());
    let mut chars = msg.chars();
    let mut prev: Option<char> = None;
    while let Some(c) = chars.next() {
        // An apostrophe inside a word ("doesn't") is punctuation, not a quote.
        let apostrophe = c == '\'' && prev.is_some_and(char::is_alphanumeric);
        if !matches!(c, '`' | '"' | '\'') || apostrophe {
            out.push(c);
            prev = Some(c);
            continue;
        }
        // `missing field `width_mhz`` names a field of our own schema, not user input.
        if c == '`' && out.ends_with("missing field ") {
            let name: String = chars.clone().take_while(|n| *n != '`').collect();
            let closed = chars.clone().nth(name.len()) == Some('`');
            if closed
                && name
                    .chars()
                    .all(|n| n.is_ascii_alphanumeric() || matches!(n, '_' | '-'))
            {
                out.push('`');
                out.push_str(&name);
                out.push('`');
                chars.nth(name.len());
                prev = Some('`');
                continue;
            }
        }
        let mut escaped = false;
        for n in chars.by_ref() {
            if escaped {
                escaped = false;
            } else if n == '\\' && c == '"' {
                escaped = true;
            } else if n == c {
                break;
            }
        }
        out.push(c);
        out.push('…');
        out.push(c);
        prev = Some(c);
    }
    out
}
