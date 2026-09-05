//! `whoami` — what this API key is, and everything it is allowed to do.
//!
//! The question an audit starts and ends with. A finding that says "no public
//! databases" is worth exactly as much as the key's reach: if the policy covers
//! one project out of nine, the sweep saw one project out of nine. This command
//! is what makes the rest of the output honest, so it resolves the grant the
//! long way — key, principal, group memberships, policies, rules — rather than
//! trusting what the profile says about itself.

use anyhow::Result;
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::scw::{self, identity, Client, Paging};
use crate::ui::{self, render};

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    if c.access_key().is_empty() {
        anyhow::bail!(
            "no access key in profile {:?}; the API authenticates on the secret key alone, \
             but IAM is queried by access key. Add it with `mlab-scw login`.",
            ctx.name
        );
    }

    let key = ui::spin("Reading the API key", identity::api_key(c)).await?;

    let (kind, principal_id) = match identity::principal_of(&key) {
        Some(p) => (p.kind, p.id),
        None => ("user", String::new()),
    };

    // The principal's own record carries both its name and its organization,
    // so one call answers what would otherwise be two questions — and it is
    // the only way to learn an organization from a bare key.
    let record = c
        .get(
            &identity::principal_path(&identity::Principal {
                kind,
                id: principal_id.clone(),
            }),
            &[],
        )
        .await
        .ok();

    // `owner` is not a role granted by a policy: it is the account's root, and
    // it is why an empty grant table can mean the opposite of what it looks
    // like. `mfa` comes from the same record, and on an owner it is the single
    // control standing between a password and the whole organization.
    let is_owner = record
        .as_ref()
        .is_some_and(|r| str_of(r, "type") == "owner");
    let mfa = record
        .as_ref()
        .is_some_and(|r| r.get("mfa").and_then(Value::as_bool).unwrap_or(false));
    let last_login = record.as_ref().map(|r| str_of(r, "last_login_at"));

    let organization = match &record {
        Some(r) if !str_of(r, "organization_id").is_empty() => str_of(r, "organization_id"),
        _ => ctx.profile.organization_id.clone(),
    };
    let principal = match &record {
        Some(r) => [str_of(r, "name"), str_of(r, "email"), principal_id.clone()]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or_else(|| "(unknown)".into()),
        None => principal_id.clone(),
    };

    // The groups whose policies a human also inherits. A grant arriving
    // through a group is the one people forget they made.
    let group_ids = if organization.is_empty() {
        Vec::new()
    } else {
        groups_of(c, &organization, kind, &principal_id).await
    };

    let grants = if organization.is_empty() {
        Vec::new()
    } else {
        collect_grants(c, &organization, kind, &principal_id, &group_ids).await?
    };

    let expires = str_of(&key, "expires_at");
    let identity = json!({
        "accessKey": c.access_key(),
        "principalType": kind,
        "owner": is_owner,
        "twoFactor": if kind == "user" { Some(mfa) } else { None },
        "lastLoginAt": last_login.clone().unwrap_or_default(),
        "principalId": principal_id,
        "principal": principal,
        "organizationId": organization,
        "objectStorageProject": str_of(&key, "default_project_id"),
        "createdAt": str_of(&key, "created_at"),
        "createdFrom": str_of(&key, "creation_ip"),
        "expiresAt": if expires.is_empty() { "never".to_string() } else { expires.clone() },
        "description": str_of(&key, "description"),
        "groups": group_ids.len(),
        "grants": grants,
    });

    if render::is_json() {
        render::print_json(&identity);
        return Ok(());
    }

    render::heading("Identity");
    render::pairs(&[
        ("access key", c.access_key().to_string()),
        ("principal", format!("{principal} ({kind})")),
        ("organization", organization.clone()),
        (
            "role",
            if is_owner {
                "organization owner".to_string()
            } else if kind == "user" {
                "member".to_string()
            } else {
                "application".to_string()
            },
        ),
        (
            "two-factor",
            match (kind, mfa) {
                ("user", true) => "enabled".to_string(),
                ("user", false) => "none".to_string(),
                _ => String::new(),
            },
        ),
        (
            "last login",
            last_login
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(scw::dated)
                .unwrap_or_default(),
        ),
        ("created", scw::dated(&str_of(&key, "created_at"))),
        ("created from", str_of(&key, "creation_ip")),
        (
            "expires",
            if expires.is_empty() {
                "never".to_string()
            } else {
                scw::dated(&expires)
            },
        ),
        ("object storage project", str_of(&key, "default_project_id")),
    ]);

    if expires.is_empty() {
        ui::warning("this key has no expiry date; it will outlive the reason it was made");
    }
    if organization.is_empty() {
        ui::warning(
            "the organization could not be resolved, so no policy can be listed; pass \
             --organization-id, or run `mlab-scw login` to record it",
        );
    }
    if is_owner {
        ui::warning(
            "this is the Organization Owner. It holds every permission on every product in every \
             project, implicitly — no policy grants that and no policy can take it away, so the \
             grant table below is not the limit of what this key can do",
        );
    } else if kind == "user" {
        ui::warning(
            "this key belongs to a person, so it inherits every permission that person is ever \
             given; an audit key belongs to an application of its own",
        );
    }
    if kind == "user" && !mfa {
        ui::warning("this person has no second factor, and their key is this key");
    }

    render::heading("Grants");
    if grants.is_empty() {
        println!();
        if is_owner {
            println!(
                "  none — and none is needed. The owner is above the policy system, not outside it."
            );
        } else {
            println!(
                "  no policy readable; either the key holds no IAM permission set, or it truly has none"
            );
        }
        println!();
    } else {
        render::list(&grants, render::GRANT_COLS);
        render::count(grants.len(), "grant");
    }
    Ok(())
}

/// The groups the principal belongs to.
///
/// IAM has no "groups of this principal" endpoint, so the membership is read
/// out of the group list. A key that cannot read groups simply reports none,
/// and the grant table says so by being shorter.
async fn groups_of(c: &Client, organization: &str, kind: &str, id: &str) -> Vec<String> {
    let q = vec![("organization_id".to_string(), organization.to_string())];
    let field = if kind == "application" {
        "application_ids"
    } else {
        "user_ids"
    };
    match c
        .list(
            "/iam/v1alpha1/groups",
            &q,
            Paging::Page,
            Some("groups"),
            None,
        )
        .await
    {
        Ok(groups) => groups
            .iter()
            .filter(|g| {
                g.get(field)
                    .and_then(Value::as_array)
                    .is_some_and(|ids| ids.iter().any(|v| v.as_str() == Some(id)))
            })
            .map(|g| str_of(g, "id"))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Every policy that binds to this principal, flattened into one row per
/// permission set per scope.
async fn collect_grants(
    c: &Client,
    organization: &str,
    kind: &str,
    id: &str,
    group_ids: &[String],
) -> Result<Vec<Value>> {
    let filter = if kind == "application" {
        "application_ids"
    } else {
        "user_ids"
    };
    let mut queries = vec![vec![
        ("organization_id".to_string(), organization.to_string()),
        (filter.to_string(), id.to_string()),
    ]];
    for g in group_ids {
        queries.push(vec![
            ("organization_id".to_string(), organization.to_string()),
            ("group_ids".to_string(), g.clone()),
        ]);
    }

    let mut policies: Vec<Value> = Vec::new();
    for q in &queries {
        if let Ok(found) = c
            .list(
                "/iam/v1alpha1/policies",
                q,
                Paging::Page,
                Some("policies"),
                None,
            )
            .await
        {
            for p in found {
                let pid = str_of(&p, "id");
                if !policies.iter().any(|e| str_of(e, "id") == pid) {
                    policies.push(p);
                }
            }
        }
    }

    let mut rows = Vec::new();
    for p in &policies {
        let policy = {
            let n = str_of(p, "name");
            if n.is_empty() {
                str_of(p, "id")
            } else {
                n
            }
        };
        let via = if str_of(p, "group_id").is_empty() {
            "direct"
        } else {
            "group"
        };

        let rules = c
            .list(
                "/iam/v1alpha1/rules",
                &[("policy_id".to_string(), str_of(p, "id"))],
                Paging::Page,
                Some("rules"),
                None,
            )
            .await
            .unwrap_or_default();

        for r in &rules {
            let scope = str_of(r, "permission_sets_scope_type");
            let on = match r.get("project_ids").and_then(Value::as_array) {
                Some(ids) if !ids.is_empty() => format!("{} project(s)", ids.len()),
                _ => "whole organization".to_string(),
            };
            let sets = r
                .get("permission_set_names")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for s in sets {
                rows.push(json!({
                    "policy": policy,
                    "permissionSet": s.as_str().unwrap_or_default(),
                    "scope": if scope.is_empty() { via.to_string() } else { scope.clone() },
                    "on": on,
                }));
            }
        }
    }
    Ok(rows)
}

fn str_of(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}
