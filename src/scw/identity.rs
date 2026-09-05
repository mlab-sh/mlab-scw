//! Resolving an API key to the organization it belongs to.
//!
//! Scaleway has no "who am I" endpoint, and the two obvious candidates each
//! fall one field short:
//!
//! - `GET /account/v3/projects` — the natural first call, and it *requires*
//!   `organization_id`. Without it the API answers 400 `invalid_arguments`.
//! - `GET /iam/v1alpha1/api-keys/{access_key}` — needs no organization, but the
//!   API key object does not carry one either. It names a principal.
//!
//! So the organization is one hop further out: key, then the application or
//! user bearing it, which does carry `organization_id`. That path needs an IAM
//! read permission, so it can legitimately fail on a valid key — in which case
//! the only remaining source is the operator, who can read it off the console's
//! IAM page.

use anyhow::{Context, Result};
use serde_json::Value;

use crate::scw::{esc, Client};

/// The principal an API key belongs to.
pub struct Principal {
    /// `application` or `user`.
    pub kind: &'static str,
    pub id: String,
}

/// `GET /iam/v1alpha1/api-keys/{access_key}` — the key as IAM sees it.
pub async fn api_key(c: &Client) -> Result<Value> {
    anyhow::ensure!(
        !c.access_key().is_empty(),
        "no access key in this profile; the API authenticates on the secret key alone, \
         but IAM is queried by access key"
    );
    c.get(
        &format!("/iam/v1alpha1/api-keys/{}", esc(c.access_key())),
        &[],
    )
    .await
    .context("reading the API key from IAM")
}

/// The principal named by an API key object.
pub fn principal_of(key: &Value) -> Option<Principal> {
    for (field, kind) in [("application_id", "application"), ("user_id", "user")] {
        if let Some(id) = key
            .get(field)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            return Some(Principal {
                kind,
                id: id.to_string(),
            });
        }
    }
    None
}

/// The path of a principal's own record, which is where `organization_id` lives.
pub fn principal_path(p: &Principal) -> String {
    match p.kind {
        "application" => format!("/iam/v1alpha1/applications/{}", esc(&p.id)),
        _ => format!("/iam/v1alpha1/users/{}", esc(&p.id)),
    }
}

/// Discover the organization this key belongs to, or `None` if the key cannot
/// read enough of IAM to say.
///
/// Never fatal: a key with no IAM permission set is a perfectly valid audit key
/// that simply has to be told which organization it is auditing.
pub async fn organization(c: &Client) -> Option<String> {
    let key = api_key(c).await.ok()?;
    let principal = principal_of(&key)?;
    let record = c.get(&principal_path(&principal), &[]).await.ok()?;
    record
        .get("organization_id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// A UUID, in the one shape every Scaleway identifier takes. Checked before a
/// request is spent, because a mistyped organization comes back as the same
/// unhelpful 400 as a missing one.
pub fn looks_like_uuid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12] == parts.iter().map(|p| p.len()).collect::<Vec<_>>()[..]
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_application_key_and_a_user_key_resolve_differently() {
        let app = json!({"access_key": "SCW…", "application_id": "a-1"});
        let p = principal_of(&app).unwrap();
        assert_eq!(p.kind, "application");
        assert_eq!(principal_path(&p), "/iam/v1alpha1/applications/a-1");

        let user = json!({"access_key": "SCW…", "user_id": "u-1"});
        let p = principal_of(&user).unwrap();
        assert_eq!(p.kind, "user");
        assert_eq!(principal_path(&p), "/iam/v1alpha1/users/u-1");
    }

    #[test]
    fn a_key_bearing_neither_has_no_principal() {
        assert!(principal_of(&json!({"access_key": "SCW…"})).is_none());
        assert!(
            principal_of(&json!({"user_id": ""})).is_none(),
            "an empty id is an absence, not an identity"
        );
    }

    #[test]
    fn uuids_are_checked_before_a_request_is_spent() {
        assert!(looks_like_uuid("aaaaaaaa-1111-2222-3333-444444444444"));
        assert!(!looks_like_uuid("aaaaaaaa"));
        assert!(
            !looks_like_uuid("SCWEXAMPLEACCESSKEY0"),
            "the access key in the organization field is the mistake to catch"
        );
    }
}
