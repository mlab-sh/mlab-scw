//! `catalog` — what this tool can audit, why, and with which permission sets.
//!
//! Reads nothing and needs no credentials. Three uses, in order of how often
//! they come up: deciding what a run will cover before running it, generating
//! the least-privilege policy the key should carry, and reviewing the checks
//! themselves — a catalogue nobody can read is a catalogue nobody can correct.

use anyhow::{bail, Result};
use clap::Args;
use colored::Colorize;
use serde_json::{json, Value};

use crate::scw::catalog::{self, PRODUCTS};
use crate::scw::Paging;
use crate::ui::render::{self, wrap};

#[derive(Args, Debug)]
pub struct CatalogArgs {
    /// Only this product, by key (see `mlab-scw catalog` with no argument)
    pub product: Option<String>,

    /// List the checks rather than the resources
    #[arg(long)]
    pub checks: bool,

    /// Print only the read-only permission sets the catalogue needs
    #[arg(long)]
    pub permissions: bool,

    /// With --checks: only this severity or worse
    #[arg(long, value_parser = ["critical", "high", "medium", "low", "info"], value_name = "LEVEL")]
    pub severity: Option<String>,
}

pub fn run(args: &CatalogArgs) -> Result<()> {
    if let Some(key) = &args.product {
        if catalog::product(key).is_none() {
            bail!(
                "unknown product {key:?} (known: {})",
                PRODUCTS
                    .iter()
                    .map(|p| p.key)
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    let wanted = |k: &str| args.product.as_deref().is_none_or(|w| w == k);

    if args.permissions {
        return permissions();
    }
    if args.checks {
        return checks(args, &wanted);
    }
    resources(args, &wanted)
}

/// The policy to attach to the audit application, and nothing more.
fn permissions() -> Result<()> {
    let sets = catalog::permission_sets();
    if render::is_json() {
        render::print_json(&json!(sets));
        return Ok(());
    }
    render::heading("Read-only permission sets this catalogue needs");
    println!();
    for s in &sets {
        println!("  {s}");
    }
    println!();
    println!(
        "  {}",
        format!(
            "{} permission sets. Attach them to an application of its own, scoped to the \
             projects you mean to audit — not to your user, and not at organization scope \
             unless the account really is one project.",
            sets.len()
        )
        .dimmed()
    );
    println!();
    Ok(())
}

/// One row per readable resource: the map of the sweep.
fn resources(args: &CatalogArgs, wanted: &dyn Fn(&str) -> bool) -> Result<()> {
    let mut rows = Vec::new();
    for p in PRODUCTS {
        if !wanted(p.key) {
            continue;
        }
        for r in p.resources {
            rows.push(json!({
                "product": p.name,
                "productKey": p.key,
                "productAbout": p.about,
                "base": p.base,
                "resource": r.key,
                "scope": p.scope.as_str(),
                "permission": p.permission,
                "path": p.path_of(r, &format!("{{{}}}", p.scope.as_str())),
                "needs": r.needs,
                "paging": match r.paging.unwrap_or(p.paging) {
                    Paging::Page => "page",
                    Paging::PerPage => "per_page",
                    Paging::Token => "page_token",
                    Paging::None => "none",
                },
                "collection": r.collection.unwrap_or_default(),
                "parent": r.parent.unwrap_or_default(),
                "about": r.about,
                "checks": r.checks.len(),
            }));
        }
    }

    if render::is_json() {
        render::print_json(&Value::Array(rows));
        return Ok(());
    }

    // With one product asked for, the prose is the point; across the whole
    // catalogue it would be a wall, so that view is a table.
    if let Some(key) = &args.product {
        let p = catalog::product(key).expect("checked in run");
        render::heading(p.name);
        println!();
        println!("  {}", wrap(p.about, 2));
        render::pairs(&[
            ("base", p.base.to_string()),
            ("scope", p.scope.as_str().to_string()),
            ("permission set", p.permission.to_string()),
        ]);
        for r in p.resources {
            println!(
                "  {}  {}",
                r.key.bold(),
                p.path_of(r, &format!("{{{}}}", p.scope.as_str())).dimmed()
            );
            println!("  {}", wrap(r.about, 2));
            println!();
        }
        return Ok(());
    }

    render::heading("Audit surface");
    render::list(&rows, render::CATALOG_COLS);
    render::count(rows.len(), "resource");
    Ok(())
}

/// One row per check: the work list.
fn checks(args: &CatalogArgs, wanted: &dyn Fn(&str) -> bool) -> Result<()> {
    let floor = args
        .severity
        .as_deref()
        .map(severity_rank)
        .unwrap_or(u8::MAX);

    let mut rows = Vec::new();
    for p in PRODUCTS {
        if !wanted(p.key) {
            continue;
        }
        for r in p.resources {
            for ch in r.checks {
                if severity_rank(ch.severity.as_str()) > floor {
                    continue;
                }
                rows.push(json!({
                    "id": ch.id,
                    "product": p.name,
                    "resource": r.key,
                    "severity": ch.severity.as_str(),
                    "check": ch.what,
                }));
            }
        }
    }
    rows.sort_by_key(|r| {
        (
            severity_rank(r["severity"].as_str().unwrap_or("info")),
            r["id"].as_str().unwrap_or_default().to_string(),
        )
    });

    if render::is_json() {
        render::print_json(&Value::Array(rows));
        return Ok(());
    }

    render::heading("Checks");
    println!();
    let mut current = "";
    for r in &rows {
        let sev = r["severity"].as_str().unwrap_or_default();
        if sev != current {
            current = sev;
            println!();
            println!("  {}", sev.to_uppercase().bold());
        }
        println!("  {}", r["id"].as_str().unwrap_or_default().dimmed());
        println!("  {}", wrap(r["check"].as_str().unwrap_or_default(), 2));
    }
    render::count(rows.len(), "check");
    Ok(())
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_ranks_worst_first_and_treats_the_unknown_as_noise() {
        assert!(severity_rank("critical") < severity_rank("high"));
        assert!(severity_rank("low") < severity_rank("info"));
        assert_eq!(severity_rank("banana"), severity_rank("info"));
    }

    #[test]
    fn a_short_text_is_returned_whole() {
        assert_eq!(wrap("short enough", 4), "short enough");
        assert_eq!(wrap("", 4), "");
    }
}
