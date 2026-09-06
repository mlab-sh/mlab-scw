//! Does this environment variable hold a credential?
//!
//! The single most valuable check in the catalogue and the easiest to get
//! wrong. A detector that flags `LOG_LEVEL=debug` gets switched off in a day;
//! one that misses `DATABASE_URL=postgres://user:hunter2@db/app` was not worth
//! writing. So it answers on two independent grounds, and says which:
//!
//! - **the value is shaped like a known credential** — a JWT, a PEM block, an
//!   AWS or Scaleway or GitHub key, a URL with a password in it. These are
//!   flagged whatever the variable is called, because nothing else looks like
//!   them.
//! - **the name says it is a secret and the value could be one.** `TOKEN_TTL`
//!   is a name that says secret and a value that cannot be one, so it is not
//!   flagged; `API_TOKEN=x7f2…` is both.
//!
//! Nothing here ever returns the value. A finding names the variable and the
//! reason, and that is all it may ever carry: an audit report is copied into
//! tickets and terminals, and a leak detector that leaks is worse than none.

/// Words in a variable name that claim it holds a credential.
const SECRET_WORDS: [&str; 14] = [
    "secret",
    "password",
    "passwd",
    "token",
    "apikey",
    "api_key",
    "accesskey",
    "access_key",
    "private_key",
    "privatekey",
    "credential",
    "auth",
    "signing",
    "session_key",
];

/// Words that turn a secret-sounding name into a harmless one. `TOKEN_URL`,
/// `SECRET_NAME` and `PASSWORD_MIN_LENGTH` all name a secret without being one.
const NOT_SECRET_SUFFIXES: [&str; 12] = [
    "_name",
    "_names",
    "_id",
    "_ids",
    "_path",
    "_file",
    "_url",
    "_ttl",
    "_enabled",
    "_required",
    "_length",
    "_expiry",
];

/// Shortest value that can plausibly be a secret. Below this it is a flag, an
/// enum, a port or a version.
const MIN_SECRET_LEN: usize = 8;

/// Why a value was flagged. Never contains the value.
pub struct Leak {
    pub name: String,
    pub reason: String,
    /// True when the shape alone gave it away, regardless of the name. Those
    /// are the ones worth waking somebody for.
    pub certain: bool,
}

/// Judge one environment variable.
pub fn inspect(name: &str, value: &str) -> Option<Leak> {
    if let Some(reason) = shape(value) {
        return Some(Leak {
            name: name.to_string(),
            reason,
            certain: true,
        });
    }
    if named_as_secret(name) && could_be_secret(value) {
        return Some(Leak {
            name: name.to_string(),
            reason: format!(
                "the name says credential and the value is {} opaque characters",
                value.chars().count()
            ),
            certain: false,
        });
    }
    None
}

/// Whether a name claims to hold a credential.
pub fn named_as_secret(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if NOT_SECRET_SUFFIXES.iter().any(|s| n.ends_with(s)) {
        return false;
    }
    SECRET_WORDS.iter().any(|w| n.contains(w))
}

/// Whether a value is even capable of being a secret.
fn could_be_secret(value: &str) -> bool {
    let v = value.trim();
    if v.chars().count() < MIN_SECRET_LEN {
        return false;
    }
    // A reference to a secret is the correct pattern, not a leak.
    if v.starts_with("${") || v.starts_with("$(") || v.starts_with("secret:") {
        return false;
    }
    // Booleans, numbers, versions and durations are configuration.
    if v.chars()
        .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
    {
        return false;
    }
    if matches!(
        v.to_ascii_lowercase().as_str(),
        "true" | "false" | "none" | "null" | "disabled" | "enabled"
    ) {
        return false;
    }
    // A value with spaces is prose, a path list, or a command.
    if v.contains(' ') {
        return false;
    }
    true
}

/// A value whose shape is a credential, whatever it is called.
fn shape(value: &str) -> Option<String> {
    let v = value.trim();
    if v.is_empty() {
        return None;
    }

    if v.starts_with("-----BEGIN") {
        return Some("a PEM block: a private key or certificate, inline".into());
    }
    if is_jwt(v) {
        return Some("a JSON Web Token".into());
    }
    if let Some(scheme) = url_with_password(v) {
        return Some(format!("a {scheme} URL with a password in it"));
    }
    if v.len() == 20
        && v.starts_with("SCW")
        && v[3..]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Some("a Scaleway access key".into());
    }
    if v.len() == 20
        && v.starts_with("AKIA")
        && v[4..]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return Some("an AWS access key id".into());
    }
    if is_github_token(v) {
        return Some("a GitHub token".into());
    }
    if v.starts_with("xoxb-")
        || v.starts_with("xoxp-")
        || v.starts_with("xoxa-")
        || v.starts_with("xoxs-")
    {
        return Some("a Slack token".into());
    }
    if v.starts_with("sk-") && v.len() >= 32 {
        return Some("an OpenAI-style secret key".into());
    }
    if v.starts_with("glpat-") {
        return Some("a GitLab personal access token".into());
    }
    None
}

/// `header.payload.signature`, each base64url.
fn is_jwt(v: &str) -> bool {
    if !v.starts_with("eyJ") {
        return false;
    }
    let parts: Vec<&str> = v.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '=')
        })
}

fn is_github_token(v: &str) -> bool {
    let Some(rest) = ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]
        .iter()
        .find_map(|p| v.strip_prefix(p))
    else {
        return false;
    };
    rest.len() >= 30 && rest.chars().all(|c| c.is_ascii_alphanumeric())
}

/// A connection string carrying credentials: `scheme://user:pass@host`.
///
/// The password has to be non-empty and the authority has to look like one, so
/// `https://example.com/a:b@c` is not mistaken for a credential.
fn url_with_password(v: &str) -> Option<String> {
    let (scheme, rest) = v.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-')
    {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    let (userinfo, host) = authority.rsplit_once('@')?;
    if host.is_empty() {
        return None;
    }
    let (user, password) = userinfo.split_once(':')?;
    if user.is_empty() || password.is_empty() {
        return None;
    }
    Some(scheme.to_string())
}

/// Every leak in a map of environment variables, by name.
pub fn inspect_all(vars: &serde_json::Value) -> Vec<Leak> {
    let Some(map) = vars.as_object() else {
        return Vec::new();
    };
    let mut out: Vec<Leak> = map
        .iter()
        .filter_map(|(k, v)| v.as_str().and_then(|value| inspect(k, value)))
        .collect();
    out.sort_by(|a, b| b.certain.cmp(&a.certain).then_with(|| a.name.cmp(&b.name)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn flagged(name: &str, value: &str) -> bool {
        inspect(name, value).is_some()
    }

    #[test]
    fn a_credential_shape_is_caught_whatever_it_is_called() {
        // These are the ones worth waking somebody for: nothing else looks
        // like them, so the variable's name is irrelevant.
        let cases = [
            ("X", "-----BEGIN RSA PRIVATE KEY-----", "PEM"),
            (
                "CONFIG",
                "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc-_123",
                "Token",
            ),
            ("DB", "postgres://app:hunter2@db.internal:5432/app", "URL"),
            ("A", "SCWEXAMPLEACCESSKEY0", "Scaleway"),
            ("B", "AKIAIOSFODNN7EXAMPLE", "AWS"),
            ("C", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "GitHub"),
            ("D", "xoxb-000000000000-000000000000-abcdefghijkl", "Slack"),
            ("E", "glpat-abcdefghijklmnopqrst", "GitLab"),
        ];
        for (name, value, what) in cases {
            let leak = inspect(name, value).unwrap_or_else(|| panic!("{what} missed"));
            assert!(leak.certain, "{what} is not a guess");
            assert!(
                !leak.reason.contains(value),
                "the reason must never carry the value: {}",
                leak.reason
            );
        }
    }

    #[test]
    fn a_secret_name_with_a_secret_value_is_caught_but_marked_as_a_guess() {
        let leak = inspect("API_TOKEN", "x7f2k9dl2mzq0war").unwrap();
        assert!(!leak.certain, "a name is evidence, not proof");
        assert!(leak.reason.contains("16 opaque characters"));
    }

    #[test]
    fn a_name_that_only_mentions_a_secret_is_not_one() {
        // The four that make a naive detector unusable within a day.
        assert!(!flagged("TOKEN_TTL", "3600"));
        assert!(!flagged("SECRET_NAME", "database-password"));
        assert!(!flagged("PASSWORD_MIN_LENGTH", "12"));
        assert!(!flagged("API_KEY_FILE", "/run/secrets/api-key"));
        assert!(!flagged("AUTH_URL", "https://auth.example.com/oauth"));
        assert!(!flagged(
            "SECRET_ID",
            "cccccccc-1111-2222-3333-444444444444"
        ));
    }

    #[test]
    fn ordinary_configuration_is_left_alone() {
        for (name, value) in [
            ("LOG_LEVEL", "debug"),
            ("NODE_ENV", "production"),
            ("PORT", "8080"),
            ("TIMEOUT", "30"),
            ("VERSION", "1.24.3"),
            ("FEATURE_X", "true"),
            ("REGION", "fr-par"),
            ("ENDPOINT", "https://api.example.com"),
            ("COMMAND", "python -m app.worker"),
        ] {
            assert!(!flagged(name, value), "{name}={value} is configuration");
        }
    }

    #[test]
    fn a_reference_to_a_secret_is_the_right_pattern_not_a_leak() {
        // These are what a correctly-configured deployment looks like, and
        // flagging them would punish the people who did it properly.
        assert!(!flagged("DB_PASSWORD", "${DB_PASSWORD}"));
        assert!(!flagged("API_TOKEN", "$(vault read token)"));
        assert!(!flagged("API_TOKEN", "secret:prod/api-token"));
    }

    #[test]
    fn a_url_needs_an_actual_password_to_count() {
        assert!(flagged("X", "redis://default:s3cr3t@cache:6379"));
        assert!(
            !flagged("X", "https://example.com/a:b@c"),
            "no authority userinfo"
        );
        assert!(!flagged("X", "postgres://app@db:5432/app"), "no password");
        assert!(
            !flagged("X", "postgres://app:@db:5432/app"),
            "empty password"
        );
    }

    #[test]
    fn a_short_value_cannot_be_a_secret_however_it_is_named() {
        assert!(!flagged("PASSWORD", "abc"));
        assert!(!flagged("SECRET", "1234567"));
        assert!(flagged("PASSWORD", "abcdefgh"));
    }

    #[test]
    fn a_map_is_sorted_with_the_certain_ones_first() {
        let vars = json!({
            "LOG_LEVEL": "debug",
            "ZZZ_TOKEN": "x7f2k9dl2mzq0war",
            "DATABASE_URL": "postgres://app:hunter2@db/app",
            "AAA_SECRET": "q0war2mzx7f2k9dl",
        });
        let leaks = inspect_all(&vars);
        assert_eq!(leaks.len(), 3, "LOG_LEVEL is not one");
        assert_eq!(leaks[0].name, "DATABASE_URL", "the certain one leads");
        assert!(leaks[0].certain);
        assert_eq!(leaks[1].name, "AAA_SECRET", "then alphabetical");
    }

    #[test]
    fn a_missing_or_empty_environment_is_not_an_error() {
        assert!(inspect_all(&json!(null)).is_empty());
        assert!(inspect_all(&json!({})).is_empty());
        assert!(inspect_all(&json!({"EMPTY": ""})).is_empty());
    }
}
