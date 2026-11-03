//! Error types for loading and validating board descriptors.

use std::fmt;
use std::path::PathBuf;

/// One validation failure, located by a JSON-pointer-like path such as
/// `ethernet.ports[2].switch_port`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationIssue {
    pub path: String,
    pub message: String,
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

fn list_issues(issues: &[ValidationIssue]) -> String {
    issues.iter().fold(String::new(), |mut acc, i| {
        acc.push_str("\n  - ");
        acc.push_str(&i.to_string());
        acc
    })
}

#[derive(Debug, thiserror::Error)]
pub enum BoardError {
    #[error("cannot read board file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot parse board descriptor: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("unknown built-in board {0:?}")]
    UnknownBoard(String),
    #[error("invalid board descriptor ({} issue(s)):{}", .0.len(), list_issues(.0))]
    Invalid(Vec<ValidationIssue>),
}
