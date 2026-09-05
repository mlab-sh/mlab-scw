//! `ping` — can this profile reach the API, and what does it get back.
//!
//! A Scaleway key has no universal "who am I" endpoint: every path is behind a
//! permission set, so a key can be perfectly valid and still be refused by the
//! first thing tried. `ping` therefore probes a short ladder and reports which
//! rungs answered, because *that* is the useful answer — a refusal from IAM and
//! a 200 from Account is a working key with a narrow policy, not a broken one.
//!
//! The ladder starts at IAM, and not for tidiness: `/account/v3/projects`
//! requires an `organization_id`, and the only way to learn one from a bare key
//! is through IAM. A profile that already recorded one skips that hop.

use anyhow::{bail, Result};
use serde_json::{json, Value};

use crate::cli::Ctx;
use crate::scw::client::ApiError;
use crate::scw::{identity, Client, Paging};
use crate::ui::{self, render};

pub async fn run(c: &Client, ctx: &Ctx) -> Result<()> {
    let started = std::time::Instant::now();
    let mut results = Vec::new();
    let mut reached = false;
    let mut organization = ctx.profile.organization_id.clone();

    if c.access_key().is_empty() {
        results.push(json!({
            "probe": "iam",
            "status": "skipped",
            "grants": "IAMReadOnly",
            "detail": "no access key in the profile; IAM is queried by access key",
        }));
    } else {
        match ui::spin("Probing IAM", identity::api_key(c)).await {
            Ok(key) => {
                reached = true;
                if organization.is_empty() {
                    organization = organization_of(c, &key).await;
                }
                results.push(json!({"probe": "iam", "status": "ok", "grants": "IAMReadOnly"}));
            }
            Err(e) => {
                reached |= is_denied(&e);
                results.push(probe_failure("iam", "IAMReadOnly", &e));
            }
        }
    }

    if organization.is_empty() {
        results.push(json!({
            "probe": "account",
            "status": "skipped",
            "grants": "ProjectReadOnly",
            "detail": "needs an organization id: pass --organization-id, or run `mlab-scw login`",
        }));
    } else {
        let query = vec![("organization_id".to_string(), organization.clone())];
        let probe = c.list(
            "/account/v3/projects",
            &query,
            Paging::Page,
            Some("projects"),
            Some(1),
        );
        match ui::spin("Probing Account", probe).await {
            Ok(_) => {
                reached = true;
                results
                    .push(json!({"probe": "account", "status": "ok", "grants": "ProjectReadOnly"}));
            }
            Err(e) => {
                reached |= is_denied(&e);
                results.push(probe_failure("account", "ProjectReadOnly", &e));
            }
        }
    }

    let took = ui::elapsed(started.elapsed());

    if render::is_json() {
        render::print_json(&json!({
            "profile": ctx.name,
            "endpoint": c.base(),
            "accessKey": c.access_key(),
            "organizationId": organization,
            "reached": reached,
            "probes": results,
            "elapsed": took,
        }));
        if !reached {
            bail!("no probe reached the API");
        }
        return Ok(());
    }

    if reached {
        ui::success(&format!("answered in {took}"));
    } else {
        ui::warning("nothing answered");
    }
    render::pairs(&[
        ("profile", ctx.name.clone()),
        ("endpoint", c.base().to_string()),
        (
            "access key",
            if c.access_key().is_empty() {
                "(not stored; whoami needs it)".to_string()
            } else {
                c.access_key().to_string()
            },
        ),
        (
            "organization",
            if organization.is_empty() {
                "(unknown)".to_string()
            } else {
                organization
            },
        ),
    ]);
    render::heading("Probes");
    render::list(
        &results,
        &[
            render::Col("PROBE", &["probe"]),
            render::Col("STATUS", &["status"]),
            render::Col("PERMISSION SET", &["grants"]),
            render::Col("DETAIL", &["detail"]),
        ],
    );
    println!();

    if !reached {
        bail!("no probe reached the API");
    }
    Ok(())
}

/// The organization behind an API key: one more hop, through the principal.
async fn organization_of(c: &Client, key: &Value) -> String {
    let Some(principal) = identity::principal_of(key) else {
        return String::new();
    };
    match c.get(&identity::principal_path(&principal), &[]).await {
        Ok(record) => record
            .get("organization_id")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        Err(_) => String::new(),
    }
}

fn probe_failure(name: &str, grants: &str, e: &anyhow::Error) -> Value {
    json!({
        "probe": name,
        "status": if is_denied(e) { "denied" } else { "failed" },
        "grants": grants,
        // `{e:#}` rather than `{e}`: the outermost layer is this tool's own
        // context ("reading the API key from IAM"), and the API's answer —
        // which is the useful half — sits underneath it.
        "detail": format!("{e:#}").lines().next().unwrap_or_default(),
    })
}

/// A refusal still proves the key authenticated: only a network failure or a
/// 401 says the profile itself is wrong.
fn is_denied(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ApiError>()
        .is_some_and(|a| a.status == reqwest::StatusCode::FORBIDDEN)
}
