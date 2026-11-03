//! Config documents (`serde_json` values shaped like the owr-config model) and their
//! validation, shared by the mock and the production backend.

use owr_board::Board;
use owr_config::{Config, Issue};
use serde_json::Value;

use crate::dto::ValidationErrors;

/// Deserialize a document into the typed model. serde messages can echo offending values
/// (a passphrase in the wrong place, say), so only the parts outside backticks are kept.
pub fn parse_doc(doc: &Value) -> Result<Config, ValidationErrors> {
    serde_json::from_value(doc.clone()).map_err(|e| {
        let msg = e.to_string();
        let sanitized = msg.split('`').step_by(2).collect::<Vec<_>>().join("…");
        ValidationErrors::single(
            "",
            format!("does not match the configuration schema: {sanitized}"),
        )
    })
}

/// Field-level errors for owr-config validation issues.
pub fn issues_to_errors(issues: Vec<Issue>) -> ValidationErrors {
    ValidationErrors {
        errors: issues
            .into_iter()
            .map(|i| crate::dto::FieldError {
                path: i.path,
                message: i.message,
            })
            .collect(),
    }
}

/// Validate `cfg` against the hardware.
pub fn check(cfg: &Config, board: &Board) -> Result<(), ValidationErrors> {
    cfg.validate_against(board).map_err(issues_to_errors)
}

/// Parse and validate an (unredacted) document; empty when it is acceptable.
pub fn validate_doc(doc: &Value, board: &Board) -> ValidationErrors {
    match parse_doc(doc) {
        Ok(cfg) => check(&cfg, board).err().unwrap_or_default(),
        Err(errs) => errs,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn board() -> Board {
        owr_board::builtin("glinet_gl-mt6000").unwrap()
    }

    #[test]
    fn defaults_validate() {
        let b = board();
        let doc = serde_json::to_value(Config::defaults_for(&b)).unwrap();
        assert!(validate_doc(&doc, &b).is_empty());
    }

    #[test]
    fn schema_errors_do_not_echo_values() {
        let b = board();
        let mut doc = serde_json::to_value(Config::defaults_for(&b)).unwrap();
        doc["system"]["hostname"] = json!({"leak": "hunter2-secret"});
        let errs = validate_doc(&doc, &b);
        assert_eq!(errs.errors.len(), 1);
        assert!(!errs.errors[0].message.contains("hunter2"));
    }

    #[test]
    fn board_issues_carry_paths() {
        let b = board();
        let mut doc = serde_json::to_value(Config::defaults_for(&b)).unwrap();
        doc["network"]["lan"]["ports"] = json!(["no-such-port"]);
        let errs = validate_doc(&doc, &b);
        assert!(
            errs.errors
                .iter()
                .any(|e| e.path.starts_with("network.lan"))
        );
    }
}
