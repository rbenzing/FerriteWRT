//! Secret handling shared by every backend: redaction of config documents on the way out,
//! and restoring `"***"` placeholders from the stored document on the way in.
//!
//! Documents are `serde_json` values shaped like the owr-config model. Redaction here is
//! by key name; `redact_matches_owr_config` pins it to `owr_config::redact`.

use serde_json::Value;

use crate::dto::ValidationErrors;

/// Replacement for secret values in redacted output.
pub const REDACTED: &str = "***";
/// Object keys whose string values are secrets: exactly the `Secret` fields of the
/// owr-config model (user `password_hash`, Wi-Fi `passphrase`, `PPPoE` `password`).
/// `redact_matches_owr_config` fails when the model grows another one.
const SECRET_KEYS: [&str; 3] = ["password_hash", "passphrase", "password"];

/// Replace every secret string in `value` with [`REDACTED`].
pub fn redact(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, v) in map.iter_mut() {
                if SECRET_KEYS.contains(&key.as_str()) && v.is_string() {
                    *v = Value::String(REDACTED.into());
                } else {
                    redact(v);
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(redact),
        _ => {}
    }
}

/// Arrays whose elements have a stable identity in the model (see [`identity`]).
const IDENTIFIED_ARRAYS: [&str; 7] = [
    "aps",
    "users",
    "radios",
    "vlans",
    "port_forwards",
    "rules",
    "static_leases",
];

/// Stable identity of an element of the array stored under `array_key`. Elements are
/// matched by it, so reordering, inserting or deleting entries cannot attach a stored
/// secret to the wrong element.
fn identity(array_key: &str, element: &Value) -> Option<String> {
    let text = |field: &str| element.get(field).and_then(Value::as_str);
    match array_key {
        "aps" => Some(format!("{}\0{}", text("radio")?, text("ssid")?)),
        "users" | "vlans" | "port_forwards" | "rules" => text("name").map(str::to_owned),
        "radios" => text("id").map(str::to_owned),
        "static_leases" => text("mac").map(str::to_ascii_lowercase),
        _ => None,
    }
}

/// Replace `"***"` placeholders in `new` with the stored value from `old`: objects by key,
/// arrays by [`identity`] where the model defines one (an element without a matching old
/// element keeps its placeholder and is rejected later), otherwise by position.
pub fn unredact(new: &mut Value, old: &Value) {
    unredact_under(new, old, "");
}

fn unredact_under(new: &mut Value, old: &Value, key: &str) {
    match (new, old) {
        (Value::String(s), Value::String(o)) if s == REDACTED => s.clone_from(o),
        (Value::Object(n), Value::Object(o)) => {
            for (k, v) in n.iter_mut() {
                if let Some(ov) = o.get(k) {
                    unredact_under(v, ov, k);
                }
            }
        }
        (Value::Array(n), Value::Array(o)) if IDENTIFIED_ARRAYS.contains(&key) => {
            for v in n.iter_mut() {
                let matched = identity(key, v).and_then(|id| {
                    o.iter()
                        .find(|ov| identity(key, ov).as_deref() == Some(id.as_str()))
                });
                if let Some(ov) = matched {
                    unredact_under(v, ov, "");
                }
            }
        }
        (Value::Array(n), Value::Array(o)) => {
            for (v, ov) in n.iter_mut().zip(o) {
                unredact_under(v, ov, "");
            }
        }
        _ => {}
    }
}

pub fn find_placeholders(value: &Value, path: &str, errs: &mut ValidationErrors) {
    match value {
        Value::String(s) if s == REDACTED => {
            errs.push(path, "redacted placeholder has no stored value to keep");
        }
        Value::Object(map) => {
            for (k, v) in map {
                find_placeholders(v, &format!("{path}.{k}"), errs);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                find_placeholders(v, &format!("{path}[{i}]"), errs);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::password;

    #[test]
    fn redact_hides_all_secret_keys() {
        let mut v = json!({
            "a": { "passphrase": "x", "keep": "y" },
            "users": [{ "password_hash": "$argon2id$..", "password": "p" }],
            "n": { "password": 5 }
        });
        redact(&mut v);
        assert_eq!(v["a"]["passphrase"], REDACTED);
        assert_eq!(v["a"]["keep"], "y");
        assert_eq!(v["users"][0]["password_hash"], REDACTED);
        assert_eq!(v["users"][0]["password"], REDACTED);
        assert_eq!(v["n"]["password"], 5);
    }

    #[test]
    fn identity_keys_per_array() {
        assert_eq!(
            identity("aps", &json!({"radio": "r0", "ssid": "x"})).as_deref(),
            Some("r0\0x")
        );
        assert_eq!(identity("aps", &json!({"radio": "r0"})), None);
        assert_eq!(
            identity("users", &json!({"name": "a"})).as_deref(),
            Some("a")
        );
        assert_eq!(
            identity("radios", &json!({"id": "r"})).as_deref(),
            Some("r")
        );
        assert_eq!(
            identity("static_leases", &json!({"mac": "AA:BB"})).as_deref(),
            Some("aa:bb")
        );
        assert_eq!(identity("dns_servers", &json!({"name": "a"})), None);
    }

    fn two_aps() -> Value {
        json!([
            {
                "radio": "radio0", "ssid": "ferritewrt", "hidden": false,
                "security": { "type": "wpa2_wpa3_mixed", "passphrase": "correct-horse-battery" },
                "network": "lan", "isolate_clients": false
            },
            {
                "radio": "radio1", "ssid": "ferritewrt-5G", "hidden": false,
                "security": { "type": "wpa2_wpa3_mixed", "passphrase": "staple-correct-horse" },
                "network": "lan", "isolate_clients": false
            }
        ])
    }

    #[test]
    fn redact_matches_owr_config() {
        let board = owr_board::builtin("glinet_gl-mt6000").unwrap();
        let mut doc = serde_json::to_value(owr_config::Config::defaults_for(&board)).unwrap();
        doc["network"]["wan"]["proto"] =
            json!({"type": "pppoe", "username": "isp-user", "password": "pppoe-secret-pw"});
        doc["wireless"]["aps"] = two_aps();
        let hash = password::hash_password("correct horse battery").unwrap();
        doc["users"] = json!([{
            "name": "admin", "role": "admin", "enabled": true, "password_hash": hash
        }]);
        let cfg: owr_config::Config = serde_json::from_value(doc.clone()).unwrap();

        let mut ours = doc.clone();
        redact(&mut ours);
        let theirs = serde_json::to_value(owr_config::redact(&cfg)).unwrap();
        assert_eq!(ours, theirs, "redaction diverged from owr_config::redact");
        let text = ours.to_string();
        for secret in [
            "pppoe-secret-pw",
            "correct-horse-battery",
            "staple-correct-horse",
            hash.as_str(),
        ] {
            assert!(!text.contains(secret), "{secret} survived redaction");
        }
        assert_ne!(ours, doc);
    }

    #[test]
    fn unredact_matches_arrays_by_identity() {
        let stored = json!({ "wireless": { "aps": two_aps() } });
        let mut edited = stored.clone();
        redact(&mut edited);
        // reorder: the stored secret must follow the AP, not the position
        edited["wireless"]["aps"].as_array_mut().unwrap().reverse();
        unredact(&mut edited, &stored);
        let aps = &edited["wireless"]["aps"];
        assert_eq!(aps[0]["ssid"], "ferritewrt-5G");
        assert_eq!(aps[0]["security"]["passphrase"], "staple-correct-horse");
        assert_eq!(aps[1]["security"]["passphrase"], "correct-horse-battery");
    }

    #[test]
    fn placeholders_without_a_stored_value_are_reported() {
        let stored = json!({ "wireless": { "aps": two_aps() } });
        let mut edited = stored.clone();
        redact(&mut edited);
        edited["wireless"]["aps"][0]["ssid"] = json!("renamed");
        unredact(&mut edited, &stored);
        let mut errs = ValidationErrors::default();
        find_placeholders(&edited, "", &mut errs);
        assert_eq!(errs.errors.len(), 1);
        assert_eq!(errs.errors[0].path, ".wireless.aps[0].security.passphrase");
    }
}
