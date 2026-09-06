//! The graded checks, as pure functions over fetched data.
//!
//! Nothing in this module makes a request. Everything it knows arrives as
//! already-fetched JSON, which is what makes the checks testable against
//! fixtures rather than against an account, and what will let a later `sweep`
//! feed the same functions from a file instead of from the API.

pub mod advisories;
pub mod credential;
pub mod exposure;
pub mod iam;
pub mod quiet;
pub mod report;

use serde_json::Value;

use crate::scw::Severity;

/// One thing worth telling somebody about.
pub struct Finding {
    /// The catalogue id, `product.resource.slug`. Stable, and what a mute list
    /// will key on.
    pub id: &'static str,
    pub severity: Severity,
    /// What the finding is about, named the way the console names it.
    pub subject: String,
    /// The evidence. Specific enough to act on without opening the console.
    pub detail: String,
}

impl Finding {
    pub fn new(
        id: &'static str,
        severity: Severity,
        subject: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Finding {
            id,
            severity,
            subject: subject.into(),
            detail: detail.into(),
        }
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({
            "id": self.id,
            "severity": self.severity.as_str(),
            "subject": self.subject,
            "detail": self.detail,
        })
    }
}

/// Sort worst first, then by id, then by subject, so two runs over unchanged
/// data produce byte-identical output and a diff means something.
pub fn sort(findings: &mut [Finding]) {
    findings.sort_by(|a, b| {
        a.severity
            .cmp(&b.severity)
            .then_with(|| a.id.cmp(b.id))
            .then_with(|| a.subject.cmp(&b.subject))
    });
}

/// A string field, or empty.
pub fn s(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

/// A boolean field, defaulting to false.
pub fn b(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// An integer field, or `None` when absent — which is different from zero and
/// usually means "no limit set".
pub fn n(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(Value::as_i64)
}

/// The length of an array field.
pub fn len(v: &Value, key: &str) -> usize {
    v.get(key).and_then(Value::as_array).map_or(0, Vec::len)
}

/// The elements of a string array field.
pub fn strings(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The name of a thing, falling back to its id, falling back to a placeholder.
pub fn name_or_id(v: &Value) -> String {
    for key in ["name", "email", "id"] {
        let found = s(v, key);
        if !found.is_empty() {
            return found;
        }
    }
    "(unnamed)".to_string()
}

/// Seconds in a protobuf duration as Scaleway renders it: `"2592000s"`.
///
/// `"0s"` is the API's way of saying "no limit", which is a different thing
/// from zero seconds and is why this returns an `Option` rather than a count.
pub fn duration_secs(v: &Value, key: &str) -> Option<i64> {
    let raw = s(v, key);
    let digits = raw.strip_suffix('s')?;
    let secs = digits.split('.').next()?.parse::<i64>().ok()?;
    if secs == 0 {
        None
    } else {
        Some(secs)
    }
}

/// How long ago a timestamp was, in seconds. `None` when it is absent or
/// unparseable — an absent date is not an old one.
pub fn age_secs(v: &Value, key: &str, now: i64) -> Option<i64> {
    crate::scw::epoch_of(&s(v, key)).map(|epoch| now - epoch)
}

pub const DAY: i64 = 86_400;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_zero_duration_is_no_limit_rather_than_no_time() {
        // Scaleway writes "no maximum API key lifetime" as "0s". Reading that
        // as zero seconds would turn the strictest possible setting into the
        // most permissive one.
        let v = json!({"max_api_key_expiration_duration": "0s",
                       "max_login_session_duration": "2592000s"});
        assert_eq!(duration_secs(&v, "max_api_key_expiration_duration"), None);
        assert_eq!(
            duration_secs(&v, "max_login_session_duration"),
            Some(2_592_000)
        );
        assert_eq!(duration_secs(&v, "absent"), None);
        assert_eq!(
            duration_secs(&json!({"d": "90"}), "d"),
            None,
            "no unit, no answer"
        );
    }

    #[test]
    fn findings_sort_worst_first_and_deterministically() {
        let mut f = vec![
            Finding::new("b.b.b", Severity::Low, "z", ""),
            Finding::new("a.a.a", Severity::Critical, "b", ""),
            Finding::new("a.a.a", Severity::Critical, "a", ""),
            Finding::new("c.c.c", Severity::High, "m", ""),
        ];
        sort(&mut f);
        let order: Vec<&str> = f.iter().map(|x| x.subject.as_str()).collect();
        assert_eq!(order, vec!["a", "b", "m", "z"]);
    }

    #[test]
    fn an_absent_number_is_not_zero() {
        let v = json!({"login_attempts_before_locked": 5});
        assert_eq!(n(&v, "login_attempts_before_locked"), Some(5));
        assert_eq!(
            n(&v, "absent"),
            None,
            "absent means unset, not none allowed"
        );
    }

    #[test]
    fn a_thing_is_named_by_whatever_it_has() {
        assert_eq!(name_or_id(&json!({"name": "audit"})), "audit");
        assert_eq!(name_or_id(&json!({"email": "a@b.c"})), "a@b.c");
        assert_eq!(name_or_id(&json!({"id": "x"})), "x");
        assert_eq!(name_or_id(&json!({})), "(unnamed)");
    }
}
