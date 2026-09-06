//! `quiet` — the products nobody looks at.
//!
//! Registry visibility, credentials pasted into environment variables, DNS
//! records pointing at addresses released last year, device fleets configured
//! to trust anything that connects, runners nobody remembers renting. Nothing
//! in an account's daily operation surfaces any of it, which is why it is where
//! the surprising findings are.
//!
//! Two things separate this sweep from [`super::exposure`]. It needs the
//! *projects*, because a few products are only addressable per project. And its
//! second round is keyed by name rather than by id: a DNS zone has no UUID.

use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde_json::json;

use crate::audit::{self, quiet::Quiet};
use crate::cli::Ctx;
use crate::scw::sweep::{self, Fetch, Fetched};
use crate::scw::{catalog, identity, Client, Paging};
use crate::ui::{self, render};

/// What the first round asks for, as catalogue keys.
///
/// The last five are not about the quiet products at all: they are the account's
/// addresses and platform hostnames, and a DNS record can only be called
/// dangling by checking it against them.
const ROUND_ONE: [(&str, &str); 30] = [
    ("containers", "namespaces"),
    ("containers", "containers"),
    ("functions", "namespaces"),
    ("functions", "functions"),
    ("jobs", "job-definitions"),
    ("registry", "namespaces"),
    ("registry", "images"),
    ("domain", "domains"),
    ("domain", "dns-zones"),
    ("domain", "ssl-certificates"),
    ("iot", "hubs"),
    ("iot", "devices"),
    ("iot", "routes"),
    ("apple-silicon", "servers"),
    ("secret-manager", "secrets"),
    ("key-manager", "keys"),
    ("mnq", "sqs-credentials"),
    ("mnq", "sns-credentials"),
    ("tem", "domains"),
    ("instance", "images"),
    ("instance", "volumes"),
    ("instance", "snapshots"),
    ("block", "volumes"),
    ("block", "snapshots"),
    ("file", "filesystems"),
    ("instance", "ips"),
    ("flexible-ip", "fips"),
    ("lb", "ips"),
    ("ipam", "ips"),
    ("k8s", "clusters"),
];

#[derive(Args, Debug)]
pub struct QuietArgs {
    /// Only this severity or worse
    #[arg(long, value_parser = ["critical", "high", "medium", "low", "info"], value_name = "LEVEL")]
    pub severity: Option<String>,

    /// Requests in flight at once
    #[arg(long, default_value_t = sweep::DEFAULT_CONCURRENCY, value_name = "N")]
    pub concurrency: usize,
}

pub async fn run(c: Client, ctx: &Ctx, args: &QuietArgs) -> Result<()> {
    let client = Arc::new(c);

    let mut organization = ctx.profile.organization_id.clone();
    if organization.is_empty() {
        organization = identity::organization(&client).await.unwrap_or_default();
    }
    let projects = projects(&client, ctx).await;
    let mut all: Vec<Fetched> = Vec::new();

    let round_one: Vec<Fetch> = ROUND_ONE
        .iter()
        .flat_map(|(p, r)| plan(ctx, &projects, p, r, None))
        .map(|f| {
            // `instance/images` answers with Scaleway's marketplace as well as
            // the account's own images — tens of thousands of them. Filtering
            // at the API rather than in the client turns a twelve-second sweep
            // into a one-second one.
            if f.product == "instance" && f.resource == "images" && !organization.is_empty() {
                f.query("organization", &organization)
            } else {
                f
            }
        })
        .collect();
    all.extend(
        ui::spin(
            &format!(
                "Sweeping {} calls across the quiet products",
                round_one.len()
            ),
            sweep::sweep(Arc::clone(&client), round_one, args.concurrency),
        )
        .await,
    );

    let zones = dns_zones(ctx, &all);
    if !zones.is_empty() {
        all.extend(
            ui::spin(
                &format!("Reading {} DNS zone(s)", zones.len()),
                sweep::sweep(Arc::clone(&client), zones, args.concurrency),
            )
            .await,
        );
    }

    report(&all, args, projects.len(), &organization)
}

/// The projects to fan project-scoped resources out over.
///
/// A few products — Messaging & Queuing among them — refuse a call without a
/// `project_id`. Without the list, those are silently unaudited, so the sweep
/// asks for it first and says so if it could not have it.
async fn projects(client: &Client, ctx: &Ctx) -> Vec<String> {
    if !ctx.profile.project_id.is_empty() {
        return vec![ctx.profile.project_id.clone()];
    }
    let mut org = ctx.profile.organization_id.clone();
    if org.is_empty() {
        org = identity::organization(client).await.unwrap_or_default();
    }
    if org.is_empty() {
        return Vec::new();
    }
    let q = vec![("organization_id".to_string(), org)];
    client
        .list(
            "/account/v3/projects",
            &q,
            Paging::Page,
            Some("projects"),
            None,
        )
        .await
        .map(|items| items.iter().map(|p| audit::s(p, "id")).collect())
        .unwrap_or_default()
}

/// Every call for one catalogue resource: one per locality, and one per project
/// on top of that when the resource insists on being asked per project.
fn plan(
    ctx: &Ctx,
    projects: &[String],
    product_key: &str,
    resource_key: &str,
    parent: Option<(&str, &str)>,
) -> Vec<Fetch> {
    let Some(product) = catalog::product(product_key) else {
        return Vec::new();
    };
    let Some(resource) = product.resources.iter().find(|r| r.key == resource_key) else {
        return Vec::new();
    };

    let localities: Vec<String> = match parent {
        Some((locality, _)) => vec![locality.to_string()],
        None => ctx.localities(product.scope),
    };

    let mut out = Vec::new();
    for locality in localities {
        let mut path = product.path_of(resource, &locality);
        if let Some((_, id)) = parent {
            path = path.replace("{id}", id);
        }
        let base = Fetch::new(product.key, resource.key, &locality, path)
            .paging(resource.paging.unwrap_or(product.paging));

        match resource.needs {
            "organization_id" => {
                out.push(base.query("organization_id", &ctx.profile.organization_id))
            }
            "project_id" => {
                for project in projects {
                    out.push(base.clone().query("project_id", project));
                }
            }
            _ => out.push(base),
        }
    }
    out
}

/// The record listing for each DNS zone found.
///
/// Keyed by name rather than by id, because a Scaleway DNS zone has no UUID:
/// its identity is `subdomain.domain`, and that is what goes in the path.
fn dns_zones(ctx: &Ctx, fetched: &[Fetched]) -> Vec<Fetch> {
    sweep::items(fetched, "domain", "dns-zones")
        .into_iter()
        .filter_map(|(locality, zone)| {
            let domain = audit::s(zone, "domain");
            if domain.is_empty() {
                return None;
            }
            let subdomain = audit::s(zone, "subdomain");
            let name = if subdomain.is_empty() {
                domain
            } else {
                format!("{subdomain}.{domain}")
            };
            plan(ctx, &[], "domain", "records", Some((locality, &name))).pop()
        })
        .collect()
}

fn report(
    fetched: &[Fetched],
    args: &QuietArgs,
    projects: usize,
    organization: &str,
) -> Result<()> {
    let quiet = Quiet::new(fetched, organization);
    let findings = quiet.audit(crate::scw::now());
    let gaps = sweep::gaps(fetched);

    let floor = args
        .severity
        .as_deref()
        .map(audit::report::rank)
        .unwrap_or(u8::MAX);
    let shown: Vec<&audit::Finding> = findings
        .iter()
        .filter(|f| audit::report::rank(f.severity.as_str()) <= floor)
        .collect();

    if render::is_json() {
        render::print_json(&json!({
            "calls": fetched.len(),
            "projects": projects,
            "findings": shown.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
            "gaps": gaps,
        }));
        return Ok(());
    }

    render::heading("The quiet products");
    render::pairs(&[
        ("calls", fetched.len().to_string()),
        (
            "projects",
            if projects == 0 {
                "unknown; project-scoped products were skipped".to_string()
            } else {
                projects.to_string()
            },
        ),
        ("findings", findings.len().to_string()),
    ]);

    if !gaps.is_empty() {
        ui::warning("this report is partial; these were not readable");
        for g in &gaps {
            println!("    {}", g.dimmed());
        }
        println!();
    }

    render::heading("Findings");
    if shown.is_empty() {
        println!();
        println!("  {}", "nothing at or above this severity".dimmed());
        println!();
        return Ok(());
    }

    audit::report::print(&shown);
    audit::report::tally(&shown);
    println!(
        "  {}",
        format!(
            "{} of the catalogue's checks are about the products nobody looks at and are \
             derived here. `mlab-scw catalog --checks` is the whole list.",
            audit::quiet::IMPLEMENTED.len()
        )
        .dimmed()
    );
    println!();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_resource_the_sweep_asks_for_is_in_the_catalogue() {
        // `plan` returns nothing for an unknown key rather than failing, so a
        // typo here would silently shrink the sweep — the worst failure mode an
        // audit tool has.
        for (product_key, resource_key) in ROUND_ONE {
            let product = catalog::product(product_key)
                .unwrap_or_else(|| panic!("{product_key} is not a catalogue product"));
            assert!(
                product.resources.iter().any(|r| r.key == resource_key),
                "{product_key}/{resource_key} is not a catalogue resource"
            );
        }
        let domain = catalog::product("domain").unwrap();
        assert!(
            domain.resources.iter().any(|r| r.key == "records"),
            "the second round reads domain/records"
        );
    }

    #[test]
    fn every_product_this_command_judges_is_one_it_actually_reads() {
        // A check on a product the sweep never fetches can never fire, and
        // would sit in IMPLEMENTED looking like coverage.
        let mut swept: Vec<&str> = ROUND_ONE.iter().map(|(p, _)| *p).collect();
        swept.push("domain");
        for id in audit::quiet::IMPLEMENTED {
            let product = id.split('.').next().unwrap();
            assert!(
                swept.contains(&product),
                "{id} judges {product}, which round one does not fetch"
            );
        }
    }
}
