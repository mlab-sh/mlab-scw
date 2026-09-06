//! `iam` — read who can do what, and grade it.
//!
//! The first command to run against an account and the last one to be
//! satisfied by: every other finding this tool can produce is reachable by
//! whoever holds the wrong credential here.
//!
//! Fetching lives in this module; the judgement lives in [`crate::audit::iam`]
//! as pure functions, so the checks are tested against fixtures rather than
//! against somebody's organization.

use anyhow::{bail, Result};
use clap::Subcommand;
use colored::Colorize;
use serde_json::{json, Value};

use crate::audit::{self, iam::Iam};
use crate::cli::Ctx;
use crate::scw::client::ApiError;
use crate::scw::{catalog, identity, Client, Paging};
use crate::ui::{self, render};

#[derive(Subcommand, Debug)]
pub enum IamCmd {
    /// Every IAM check, worst first (the default)
    Audit {
        /// Only this severity or worse
        #[arg(long, value_parser = ["critical", "high", "medium", "low", "info"], value_name = "LEVEL")]
        severity: Option<String>,
    },
    /// Human accounts, their MFA state and their last login
    Users,
    /// Non-human principals
    #[command(alias = "apps")]
    Applications,
    /// Every credential that can call this API
    #[command(alias = "api-keys")]
    Keys,
    /// The bindings between principals and permission sets
    Policies,
    /// Group membership, which is how a permission arrives unannounced
    Groups,
    /// Keys injected into every machine at boot
    #[command(alias = "ssh")]
    SshKeys,
    /// The organization's own password, session and key-expiry rules
    #[command(alias = "security-settings")]
    Settings,
}

pub async fn run(c: &Client, ctx: &Ctx, cmd: Option<IamCmd>) -> Result<()> {
    let org = organization(c, ctx).await?;
    let cmd = cmd.unwrap_or(IamCmd::Audit { severity: None });

    // A listing is one call; the audit is all of them.
    match cmd {
        IamCmd::Audit { severity } => {
            let iam = ui::spin("Reading IAM", gather(c, &org)).await;
            report(&iam, severity.as_deref())
        }
        IamCmd::Users => show(c, &org, "/users", "Users", "user", render::USER_COLS).await,
        IamCmd::Applications => {
            show(
                c,
                &org,
                "/applications",
                "Applications",
                "application",
                render::APPLICATION_COLS,
            )
            .await
        }
        IamCmd::Keys => {
            show(
                c,
                &org,
                "/api-keys",
                "API keys",
                "key",
                render::API_KEY_COLS,
            )
            .await
        }
        IamCmd::Policies => {
            show(
                c,
                &org,
                "/policies",
                "Policies",
                "policy",
                render::POLICY_COLS,
            )
            .await
        }
        IamCmd::Groups => show(c, &org, "/groups", "Groups", "group", render::GROUP_COLS).await,
        IamCmd::SshKeys => {
            show(
                c,
                &org,
                "/ssh-keys",
                "SSH keys",
                "key",
                render::SSH_KEY_COLS,
            )
            .await
        }
        IamCmd::Settings => {
            let path = format!("/iam/v1alpha1/organizations/{}/security-settings", org);
            let v = ui::spin("Reading the security settings", c.get(&path, &[])).await?;
            render::heading("Organization security settings");
            render::one(&v);
            Ok(())
        }
    }
}

/// The organization every IAM call is scoped by.
async fn organization(c: &Client, ctx: &Ctx) -> Result<String> {
    if !ctx.profile.organization_id.is_empty() {
        return Ok(ctx.profile.organization_id.clone());
    }
    match ui::spin("Resolving the organization", identity::organization(c)).await {
        Some(org) => Ok(org),
        None => bail!(
            "IAM is queried per organization, and this key cannot read its own principal to \
             find one. Pass --organization-id, set SCW_DEFAULT_ORGANIZATION_ID, or run \
             `mlab-scw login` to record it."
        ),
    }
}

/// One listing.
async fn show(
    c: &Client,
    org: &str,
    path: &str,
    title: &str,
    noun: &str,
    cols: &[render::Col],
) -> Result<()> {
    let rows = ui::spin(&format!("Listing {title}"), list(c, org, path, "")).await?;
    render::heading(title);
    render::list(&rows, cols);
    render::count(rows.len(), noun);
    Ok(())
}

/// A paged IAM listing, scoped to the organization.
async fn list(c: &Client, org: &str, path: &str, collection: &str) -> Result<Vec<Value>> {
    let q = vec![("organization_id".to_string(), org.to_string())];
    let collection = (!collection.is_empty()).then_some(collection);
    c.list(
        &format!("/iam/v1alpha1{path}"),
        &q,
        Paging::Page,
        collection,
        None,
    )
    .await
}

/// Read everything the checks need, recording what could not be read.
///
/// The seven listings are independent, so they go out together — thirty-six
/// products over ten zones is what phase two has to survive, and IAM is where
/// the pattern gets established. Rules depend on policies and follow after.
async fn gather(c: &Client, org: &str) -> Iam {
    let mut iam = Iam {
        organization_id: org.to_string(),
        ..Default::default()
    };

    let settings_path = format!("/iam/v1alpha1/organizations/{org}/security-settings");
    let (users, applications, api_keys, policies, groups, ssh_keys, settings) = tokio::join!(
        list(c, org, "/users", "users"),
        list(c, org, "/applications", "applications"),
        list(c, org, "/api-keys", "api_keys"),
        list(c, org, "/policies", "policies"),
        list(c, org, "/groups", "groups"),
        list(c, org, "/ssh-keys", "ssh_keys"),
        c.get(&settings_path, &[]),
    );

    iam.users = keep(users, "users", &mut iam.gaps);
    iam.applications = keep(applications, "applications", &mut iam.gaps);
    iam.api_keys = keep(api_keys, "api-keys", &mut iam.gaps);
    iam.policies = keep(policies, "policies", &mut iam.gaps);
    iam.groups = keep(groups, "groups", &mut iam.gaps);
    iam.ssh_keys = keep(ssh_keys, "ssh-keys", &mut iam.gaps);
    iam.settings = match settings {
        Ok(v) => Some(v),
        Err(e) => {
            iam.gaps.push(gap("security-settings", &e));
            None
        }
    };

    // Rules are per policy, so they cannot start until the policies land.
    for p in &iam.policies {
        let id = audit::s(p, "id");
        if id.is_empty() {
            continue;
        }
        let q = vec![("policy_id".to_string(), id.clone())];
        match c
            .list("/iam/v1alpha1/rules", &q, Paging::Page, Some("rules"), None)
            .await
        {
            Ok(rules) => {
                iam.rules.insert(id, rules);
            }
            Err(e) => iam
                .gaps
                .push(gap(&format!("rules of {:?}", audit::name_or_id(p)), &e)),
        }
    }

    iam
}

/// Take a listing, or record why it is missing. A refused product is not a
/// failed run: it is a smaller report, and the report has to say so.
fn keep(result: Result<Vec<Value>>, what: &str, gaps: &mut Vec<String>) -> Vec<Value> {
    match result {
        Ok(v) => v,
        Err(e) => {
            gaps.push(gap(what, &e));
            Vec::new()
        }
    }
}

fn gap(what: &str, e: &anyhow::Error) -> String {
    let reason = match e.downcast_ref::<ApiError>().map(|a| a.status) {
        Some(reqwest::StatusCode::FORBIDDEN) => "no permission set for it".to_string(),
        Some(s) => format!("{}", s.as_u16()),
        None => format!("{e}")
            .lines()
            .next()
            .unwrap_or_default()
            .to_string(),
    };
    format!("{what}: {reason}")
}

/// Catalogue ids for IAM that this tool does not yet derive.
///
/// Printed with every report. A catalogue that promises more than the code
/// delivers is worse than a shorter catalogue, and the honest way to hold both
/// is to say which is which.
fn not_implemented() -> Vec<&'static str> {
    let done = crate::audit::iam::IMPLEMENTED;
    catalog::product("iam")
        .map(|p| {
            p.resources
                .iter()
                .flat_map(|r| r.checks.iter().map(|c| c.id))
                .filter(|id| !done.contains(id))
                .collect()
        })
        .unwrap_or_default()
}

fn report(iam: &Iam, floor: Option<&str>) -> Result<()> {
    let findings = audit::iam::audit(iam, crate::scw::now());
    let floor = floor.map(audit::report::rank).unwrap_or(u8::MAX);
    let shown: Vec<&audit::Finding> = findings
        .iter()
        .filter(|f| audit::report::rank(f.severity.as_str()) <= floor)
        .collect();

    let inventory = json!({
        "users": iam.users.len(),
        "applications": iam.applications.len(),
        "apiKeys": iam.api_keys.len(),
        "policies": iam.policies.len(),
        "groups": iam.groups.len(),
        "sshKeys": iam.ssh_keys.len(),
    });

    if render::is_json() {
        render::print_json(&json!({
            "organizationId": iam.organization_id,
            "inventory": inventory,
            "findings": shown.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
            "gaps": iam.gaps,
            "notImplemented": not_implemented(),
        }));
        return Ok(());
    }

    render::heading("IAM");
    render::pairs(&[
        ("organization", iam.organization_id.clone()),
        ("users", iam.users.len().to_string()),
        ("applications", iam.applications.len().to_string()),
        ("api keys", iam.api_keys.len().to_string()),
        ("policies", iam.policies.len().to_string()),
        ("groups", iam.groups.len().to_string()),
        ("ssh keys", iam.ssh_keys.len().to_string()),
    ]);

    if !iam.gaps.is_empty() {
        ui::warning("this report is partial; what follows describes only what could be read");
        for g in &iam.gaps {
            println!("    {}", g.dimmed());
        }
        println!();
    }

    render::heading("Findings");
    if shown.is_empty() {
        println!();
        println!("  {}", "nothing at or above this severity".dimmed());
        println!();
    } else {
        audit::report::print(&shown);
        audit::report::tally(&shown);
    }

    let missing = not_implemented();
    if !missing.is_empty() {
        println!(
            "  {}",
            format!(
                "{} catalogued IAM check(s) are not derived yet: {}",
                missing.len(),
                missing.join(", ")
            )
            .dimmed()
        );
        println!();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_report_says_which_catalogued_checks_it_does_not_derive() {
        // The list may be empty one day. What must never happen is the report
        // implying full coverage of the catalogue when it has partial coverage.
        let missing = not_implemented();
        let total = catalog::product("iam")
            .unwrap()
            .resources
            .iter()
            .map(|r| r.checks.len())
            .sum::<usize>();
        assert!(
            missing.len() < total,
            "if nothing is implemented the command has no reason to exist"
        );
        for id in missing {
            assert!(
                !crate::audit::iam::IMPLEMENTED.contains(&id),
                "{id} is both implemented and reported as missing"
            );
        }
    }
}
