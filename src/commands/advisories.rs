//! `advisories` — what the account runs, against what has been published.
//!
//! The only command that talks to anything but `api.scaleway.com`, and the only
//! one that can leak. It sends a product identifier and a page number; it never
//! probes anything; and without `--allow-web` it sends nothing at all and says
//! so instead of reading as a clean result.

use std::sync::Arc;

use anyhow::Result;
use clap::Args;
use colored::Colorize;
use serde_json::json;

use crate::audit::{self, advisories as check};
use crate::cli::Ctx;
use crate::enrich::corpus::{self, Corpus};
use crate::scw::sweep::{self, Fetch, Fetched};
use crate::scw::{catalog, Client};
use crate::ui::{self, render};

/// Where a version can be found. Everything else in the catalogue reports state
/// rather than a version, so this list is short on purpose.
const VERSIONED: [(&str, &str); 6] = [
    ("k8s", "clusters"),
    ("rdb", "instances"),
    ("redis", "clusters"),
    ("kafka", "clusters"),
    ("searchdb", "deployments"),
    ("functions", "functions"),
];

/// The platform's own verdict on its runtimes, which needs no corpus.
const RUNTIME_CATALOGUE: (&str, &str) = ("functions", "runtimes");

#[derive(Args, Debug)]
pub struct AdvisoryArgs {
    /// Let this run reach vuln.mlab.sh
    ///
    /// Without it the corpus is read from the local cache only, and anything
    /// missing is reported as unchecked rather than as clean.
    #[arg(long)]
    pub allow_web: bool,

    /// Print the requests that would be sent, and send nothing
    #[arg(long)]
    pub explain: bool,

    /// Only this severity or worse
    #[arg(long, value_parser = ["critical", "high", "medium", "low", "info"], value_name = "LEVEL")]
    pub severity: Option<String>,

    /// Requests in flight at once
    #[arg(long, default_value_t = sweep::DEFAULT_CONCURRENCY, value_name = "N")]
    pub concurrency: usize,
}

pub async fn run(c: Client, ctx: &Ctx, args: &AdvisoryArgs) -> Result<()> {
    let client = Arc::new(c);

    let mut plan: Vec<Fetch> = VERSIONED
        .iter()
        .flat_map(|(p, r)| fetches(ctx, p, r))
        .collect();
    plan.extend(fetches(ctx, RUNTIME_CATALOGUE.0, RUNTIME_CATALOGUE.1));

    let fetched = ui::spin(
        &format!("Reading {} version-bearing listing(s)", plan.len()),
        sweep::sweep(Arc::clone(&client), plan, args.concurrency),
    )
    .await;

    let components = check::components(&fetched);
    let wanted = check::cpes(&components);

    // `--explain` is the honest form of "nothing leaves unless you allow it":
    // the payload can be read before it is sent, and this path sends nothing.
    if args.explain {
        return explain(&components, &wanted);
    }

    let mut corpora: Vec<Corpus> = Vec::new();
    if !wanted.is_empty() {
        let label = if args.allow_web {
            format!("Asking vuln.mlab.sh about {} product(s)", wanted.len())
        } else {
            "Reading the local advisory cache".to_string()
        };
        let lookups = async {
            let mut out = Vec::new();
            for cpe in &wanted {
                out.push(corpus::fetch(cpe, args.allow_web).await);
            }
            out
        };
        corpora = ui::spin(&label, lookups).await;
    }

    report(&components, &corpora, &fetched, args)
}

/// Every call for one catalogue resource, one per locality this run covers.
fn fetches(ctx: &Ctx, product_key: &str, resource_key: &str) -> Vec<Fetch> {
    let Some(product) = catalog::product(product_key) else {
        return Vec::new();
    };
    let Some(resource) = product.resources.iter().find(|r| r.key == resource_key) else {
        return Vec::new();
    };
    ctx.localities(product.scope)
        .into_iter()
        .map(|locality| {
            Fetch::new(
                product.key,
                resource.key,
                &locality,
                product.path_of(resource, &locality),
            )
            .paging(resource.paging.unwrap_or(product.paging))
        })
        .collect()
}

fn explain(components: &[check::Component], cpes: &[String]) -> Result<()> {
    let requests = corpus::requests(cpes);

    if render::is_json() {
        render::print_json(&json!({
            "wouldSend": requests,
            "components": components
                .iter()
                .map(|c| json!({"software": c.software, "version": c.version}))
                .collect::<Vec<_>>(),
        }));
        return Ok(());
    }

    render::heading("What this run would send");
    if requests.is_empty() {
        println!();
        println!("  {}", "nothing: no versioned resource was found".dimmed());
        println!();
        return Ok(());
    }
    println!();
    for r in &requests {
        println!("  {r}");
    }
    println!();
    println!(
        "  {}",
        "and nothing else. No organization, no project, no resource id, no name, no address — \
         what goes out identifies software, never an account."
            .dimmed()
    );
    println!();
    Ok(())
}

fn report(
    components: &[check::Component],
    corpora: &[Corpus],
    fetched: &[Fetched],
    args: &AdvisoryArgs,
) -> Result<()> {
    let findings = check::audit(components, corpora, fetched);
    let coverage = check::coverage(components, corpora);
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
            "components": components
                .iter()
                .map(|c| json!({"software": c.software, "subject": c.subject,
                                "version": c.version}))
                .collect::<Vec<_>>(),
            "findings": shown.iter().map(|f| f.to_json()).collect::<Vec<_>>(),
            "coverage": coverage,
            "gaps": gaps,
            "allowedWeb": args.allow_web,
        }));
        return Ok(());
    }

    render::heading("What this account runs");
    if components.is_empty() {
        println!();
        println!(
            "  {}",
            "no versioned resource found; nothing here to look up".dimmed()
        );
        println!();
    } else {
        let rows: Vec<serde_json::Value> = components
            .iter()
            .map(|c| {
                json!({
                    "software": crate::enrich::cpe::software(c.software)
                        .map(|s| s.label).unwrap_or(c.software),
                    "version": c.version,
                    "subject": c.subject,
                })
            })
            .collect();
        render::list(&rows, render::COMPONENT_COLS);
        render::count(components.len(), "component");
    }

    if !args.allow_web {
        ui::warning(
            "the corpus was not fetched; run with --allow-web to check these versions against \
             published advisories, or --explain to see exactly what that would send",
        );
    }
    if !gaps.is_empty() {
        ui::warning("some listings were not readable");
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
    } else {
        audit::report::print(&shown);
        audit::report::tally(&shown);
    }

    // Coverage last and always: a version nobody could check must not read the
    // same as a version nothing was published about.
    if !coverage.is_empty() {
        println!("  {}", "Not checked".bold());
        for c in &coverage {
            println!("    {}", c.dimmed());
        }
        println!();
    }

    // Where the answer came from matters here more than anywhere else in the
    // tool: a corpus read off yesterday's disk is a different claim from one
    // read a second ago, and the report should not blur them.
    let fresh = corpora
        .iter()
        .filter(|c| !c.cached && c.error.is_none())
        .count();
    let cached = corpora.iter().filter(|c| c.cached).count();
    let source = match (fresh, cached) {
        (0, 0) => "no corpus was consulted".to_string(),
        (0, n) => format!("{n} corpus lookup(s) served from the local cache"),
        (n, 0) => format!("{n} corpus lookup(s) fetched from vuln.mlab.sh"),
        (n, m) => format!("{n} fetched from vuln.mlab.sh, {m} served from cache"),
    };
    println!(
        "  {}",
        format!(
            "{source}. {} of the catalogue's checks are about published advisories and are \
             derived here; `mlab-scw catalog --checks` is the whole list.",
            check::IMPLEMENTED.len()
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
    fn every_listing_this_command_reads_is_in_the_catalogue() {
        let mut all: Vec<(&str, &str)> = VERSIONED.to_vec();
        all.push(RUNTIME_CATALOGUE);
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
    fn every_product_this_command_judges_is_one_it_reads() {
        let mut swept: Vec<&str> = VERSIONED.iter().map(|(p, _)| *p).collect();
        swept.push(RUNTIME_CATALOGUE.0);
        for id in check::IMPLEMENTED {
            let product = id.split('.').next().unwrap();
            assert!(
                swept.contains(&product),
                "{id} judges {product}, which this command does not read"
            );
        }
    }
}
