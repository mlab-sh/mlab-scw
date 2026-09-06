//! `exposure` — what answers from the internet, and what stands in front of it.
//!
//! The first command that has to sweep. Twenty-one resources across ten zones
//! and four regions, then a second round for the controls that hang off what
//! the first found, then a third for the ones that hang off *those*.
//!
//! The plan is built from the catalogue rather than written out here, so a path
//! or a paging style corrected in one place is corrected for this command too.

use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde_json::{json, Value};

use crate::audit::{self, exposure::Edge};
use crate::cli::Ctx;
use crate::scw::sweep::{self, Fetch, Fetched};
use crate::scw::{catalog, Client};
use crate::ui::{self, render};

/// What the first round asks for, as catalogue keys.
const ROUND_ONE: [(&str, &str); 22] = [
    ("instance", "servers"),
    ("instance", "ips"),
    ("instance", "security-groups"),
    ("baremetal", "servers"),
    ("baremetal", "server-private-networks"),
    ("apple-silicon", "servers"),
    ("flexible-ip", "fips"),
    ("lb", "lbs"),
    ("lb", "ips"),
    ("redis", "clusters"),
    ("vpc-gw", "gateways"),
    ("vpc-gw", "pat-rules"),
    ("ipam", "ips"),
    ("k8s", "clusters"),
    ("rdb", "instances"),
    ("mongodb", "instances"),
    ("searchdb", "deployments"),
    ("kafka", "clusters"),
    ("containers", "containers"),
    ("functions", "functions"),
    ("inference", "deployments"),
    ("registry", "namespaces"),
];

/// The controls, each hanging off something the previous round found.
const ROUND_TWO: [(&str, &str, &str); 6] = [
    ("instance", "security-group-rules", "security-groups"),
    ("lb", "frontends", "lbs"),
    ("lb", "certificates", "lbs"),
    ("k8s", "acls", "clusters"),
    ("k8s", "pools", "clusters"),
    ("rdb", "acls", "instances"),
];

/// And the one control that hangs off a control.
const ROUND_THREE: [(&str, &str, &str); 1] = [("lb", "acls", "frontends")];

#[derive(Args, Debug)]
pub struct ExposureArgs {
    /// Only this severity or worse
    #[arg(long, value_parser = ["critical", "high", "medium", "low", "info"], value_name = "LEVEL")]
    pub severity: Option<String>,

    /// Print the exposure map and skip the findings
    #[arg(long)]
    pub map: bool,

    /// Requests in flight at once
    #[arg(long, default_value_t = sweep::DEFAULT_CONCURRENCY, value_name = "N")]
    pub concurrency: usize,
}

pub async fn run(c: Client, ctx: &Ctx, args: &ExposureArgs) -> Result<()> {
    let client = Arc::new(c);
    let mut all: Vec<Fetched> = Vec::new();

    let round_one: Vec<Fetch> = ROUND_ONE
        .iter()
        .flat_map(|(p, r)| plan(ctx, p, r, None))
        .collect();
    let mut localities: Vec<&str> = round_one
        .iter()
        .map(|f| f.locality.as_str())
        .filter(|l| !l.is_empty())
        .collect();
    localities.sort_unstable();
    localities.dedup();
    let localities = localities.len();
    all.extend(
        ui::spin(
            &format!("Sweeping {} calls for what is reachable", round_one.len()),
            sweep::sweep(Arc::clone(&client), round_one, args.concurrency),
        )
        .await,
    );

    let round_two = dependent(ctx, &all, &ROUND_TWO);
    if !round_two.is_empty() {
        all.extend(
            ui::spin(
                &format!("Reading the {} control(s) in front", round_two.len()),
                sweep::sweep(Arc::clone(&client), round_two, args.concurrency),
            )
            .await,
        );
    }

    let round_three = dependent(ctx, &all, &ROUND_THREE);
    if !round_three.is_empty() {
        all.extend(
            ui::spin(
                "Reading the frontend allow-lists",
                sweep::sweep(Arc::clone(&client), round_three, args.concurrency),
            )
            .await,
        );
    }

    report(&all, args, localities)
}

/// Every call for one catalogue resource, one per locality this run covers.
fn plan(
    ctx: &Ctx,
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

    // A dependent call inherits the locality of the thing it hangs off, so it
    // is not swept again — asking for one cluster's ACLs in ten zones would be
    // nine guaranteed 404s.
    let localities: Vec<String> = match parent {
        Some((locality, _)) => vec![locality.to_string()],
        None => ctx.localities(product.scope),
    };

    localities
        .into_iter()
        .map(|locality| {
            let mut path = product.path_of(resource, &locality);
            if let Some((_, id)) = parent {
                path = path.replace("{id}", id);
            }
            let mut fetch = Fetch::new(product.key, resource.key, &locality, path)
                .paging(resource.paging.unwrap_or(product.paging));
            match resource.needs {
                "organization_id" => {
                    fetch = fetch.query("organization_id", &ctx.profile.organization_id)
                }
                "project_id" if !ctx.profile.project_id.is_empty() => {
                    fetch = fetch.query("project_id", &ctx.profile.project_id)
                }
                _ => {}
            }
            fetch
        })
        .collect()
}

/// Build the calls that hang off what has already been fetched.
fn dependent(ctx: &Ctx, fetched: &[Fetched], spec: &[(&str, &str, &str)]) -> Vec<Fetch> {
    let mut out = Vec::new();
    for (product, resource, parent_resource) in spec {
        for (locality, item) in sweep::items(fetched, product, parent_resource) {
            let id = audit::s(item, "id");
            if id.is_empty() {
                continue;
            }
            out.extend(plan(ctx, product, resource, Some((locality, &id))));
        }
    }
    out
}

fn report(fetched: &[Fetched], args: &ExposureArgs, localities: usize) -> Result<()> {
    let edge = Edge::new(fetched);
    let exposures = edge.exposures();
    let findings = edge.audit(crate::scw::now());
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
            "exposures": exposures.iter().map(|e| e.to_json()).collect::<Vec<_>>(),
            "findings": shown.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
            "gaps": gaps,
        }));
        return Ok(());
    }

    let open = exposures
        .iter()
        .filter(|e| e.control.verdict() == "open")
        .count();

    render::heading("The public edge");
    render::pairs(&[
        (
            "calls",
            format!("{} across {localities} localities", fetched.len()),
        ),
        ("reachable", exposures.len().to_string()),
        ("of those, open", open.to_string()),
    ]);

    if !gaps.is_empty() {
        ui::warning("this map is partial; these were not readable");
        for g in &gaps {
            println!("    {}", g.dimmed());
        }
        println!();
    }

    render::heading("Exposure map");
    if exposures.is_empty() {
        println!();
        println!(
            "  {}",
            "nothing in this account answers from the internet".dimmed()
        );
        println!();
    } else {
        let rows: Vec<Value> = exposures.iter().map(|e| e.to_json()).collect();
        render::list(&rows, render::EXPOSURE_COLS);
        render::count(exposures.len(), "exposure");
    }

    if args.map {
        return Ok(());
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
    println!();
    // The catalogue holds far more checks than this command derives, and most
    // of them are about configuration rather than reachability. Saying how many
    // this one covers is the honest way to stop a clean edge reading as a clean
    // account.
    println!(
        "  {}",
        format!(
            "{} of the catalogue's checks are about the public edge and are derived here. \
             The rest are about configuration this command does not read; \
             `mlab-scw catalog --checks` is the whole list.",
            audit::exposure::IMPLEMENTED.len()
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
        // The plan is built from catalogue lookups that return nothing when a
        // key is wrong, so a typo here would silently shrink the sweep rather
        // than fail it — which is the worst failure mode an audit tool has.
        let mut all: Vec<(&str, &str)> = ROUND_ONE.to_vec();
        all.extend(ROUND_TWO.iter().map(|(p, r, _)| (*p, *r)));
        all.extend(ROUND_THREE.iter().map(|(p, r, _)| (*p, *r)));

        for (product_key, resource_key) in all {
            let product = catalog::product(product_key)
                .unwrap_or_else(|| panic!("{product_key} is not a catalogue product"));
            assert!(
                product.resources.iter().any(|r| r.key == resource_key),
                "{product_key}/{resource_key} is not a catalogue resource"
            );
        }
    }

    #[test]
    fn every_dependent_call_hangs_off_something_the_sweep_actually_fetches() {
        for (product, resource, parent) in ROUND_TWO {
            assert!(
                ROUND_ONE.contains(&(product, parent)),
                "{product}/{resource} needs {product}/{parent}, which round one does not fetch"
            );
        }
        for (product, resource, parent) in ROUND_THREE {
            assert!(
                ROUND_TWO
                    .iter()
                    .any(|(p, r, _)| *p == product && *r == parent),
                "{product}/{resource} needs {product}/{parent} from round two"
            );
        }
    }
}
