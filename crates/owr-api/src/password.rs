//! Argon2id hashing, verification and the password policy.

use std::sync::OnceLock;

use argon2::Argon2;
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};

/// Minimum password length in characters.
pub const MIN_PASSWORD_CHARS: usize = 12;
/// Maximum password length in characters (bounds hashing work).
pub const MAX_PASSWORD_CHARS: usize = 256;

/// Hashing failure (practically only possible on RNG failure).
#[derive(Debug, thiserror::Error)]
#[error("password hashing failed: {0}")]
pub struct HashError(String);

/// Hash with Argon2id using the crate defaults: m = 19456 KiB, t = 2, p = 1 (OWASP).
pub fn hash_password(password: &str) -> Result<String, HashError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| HashError(e.to_string()))
}

/// Verify `password` against a PHC string. Malformed hashes never verify.
pub fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// A valid hash of a random unguessable value, used to equalise timing for unknown users.
pub fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("owr-dummy-hash-input").unwrap_or_default())
}

/// The 50 most common passwords (plus 12+ character variants, which are the only ones
/// the length rule does not already reject).
const WORST: [&str; 50] = [
    "123456",
    "password",
    "12345678",
    "qwerty",
    "123456789",
    "12345",
    "1234",
    "111111",
    "1234567",
    "dragon",
    "123123",
    "baseball",
    "abc123",
    "football",
    "monkey",
    "letmein",
    "696969",
    "shadow",
    "master",
    "666666",
    "qwertyuiop",
    "123321",
    "mustang",
    "1234567890",
    "michael",
    "654321",
    "superman",
    "1qaz2wsx",
    "7777777",
    "121212",
    "000000",
    "qazwsx",
    "123qwe",
    "killer",
    "trustno1",
    "jordan",
    "jennifer",
    "zxcvbnm",
    "asdfgh",
    "hunter",
    "buster",
    "soccer",
    "harley",
    "batman",
    "andrew",
    "tigger",
    "sunshine",
    "iloveyou",
    "123456789012",
    "passwordpassword",
];

/// Enforce the password policy; the error string is safe to show to the user.
pub fn check_policy(username: &str, password: &str) -> Result<(), String> {
    let chars = password.chars().count();
    if chars < MIN_PASSWORD_CHARS {
        return Err(format!(
            "password must be at least {MIN_PASSWORD_CHARS} characters"
        ));
    }
    if chars > MAX_PASSWORD_CHARS {
        return Err(format!(
            "password must be at most {MAX_PASSWORD_CHARS} characters"
        ));
    }
    let lowered = password.to_lowercase();
    if lowered == username.to_lowercase() {
        return Err("password must not equal the username".into());
    }
    if WORST.contains(&lowered.as_str())
        || lowered.starts_with("password") && lowered.chars().skip(8).all(|c| c.is_ascii_digit())
    {
        return Err("password is too common".into());
    }
    if password
        .chars()
        .next()
        .is_some_and(|first| password.chars().all(|c| c == first))
    {
        return Err("password must not be a single repeated character".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_roundtrip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("wrong", &h));
        assert!(!verify_password("x", "not a phc string"));
    }

    #[test]
    fn dummy_hash_is_valid() {
        assert!(dummy_hash().starts_with("$argon2id$"));
    }

    #[test]
    fn policy() {
        assert!(check_policy("admin", "short").is_err());
        assert!(check_policy("administrator", "Administrator").is_err());
        assert!(check_policy("bob", "123456789012").is_err());
        assert!(check_policy("bob", "password1234").is_err());
        assert!(check_policy("bob", "aaaaaaaaaaaaaa").is_err());
        assert!(check_policy("bob", "x".repeat(300).as_str()).is_err());
        assert!(check_policy("bob", "correct horse battery").is_ok());
    }
}
