//! `api` — a raw GET against any path, for everything the catalogue does not
//! wrap yet.
//!
//! Deliberately GET-only. There is no flag to send anything else: a tool that
//! can be talked into a POST is no longer a tool you can point at production
//! without reading its source first.

use anyhow::{bail, Result};
use clap::Args;
use serde_json::Value;

use crate::cli::Ctx;
use crate::scw::{Client, Paging};
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct ApiArgs {
    /// Path on api.scaleway.com, e.g. /iam/v1alpha1/users
    pub path: String,

    /// Query parameter, repeatable: -Q key=value
    ///
    /// Uppercase because `-q` is `--quiet` everywhere else in this CLI, and a
    /// short that means one thing globally and another inside one subcommand is
    /// a trap rather than a convenience.
    #[arg(long, short = 'Q', value_name = "KEY=VALUE")]
    pub query: Vec<String>,

    /// Walk every page and print the collection as a list
    #[arg(long)]
    pub list: bool,

    /// With --list: the body field holding the items, when guessing is wrong
    #[arg(long, value_name = "FIELD")]
    pub collection: Option<String>,

    /// With --list: return one page of this size instead of everything
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,

    /// With --list: page with page_token instead of page numbers
    #[arg(long)]
    pub token_paging: bool,

    /// With --list: page with per_page instead of page_size (Instances)
    #[arg(long)]
    pub per_page: bool,

    /// Print secret values instead of replacing them with their length
    ///
    /// Several read endpoints return live credentials — an Apple silicon sudo
    /// password, a BMC login, a managed certificate's private key. They are
    /// masked by default so that piping this command into a file, a ticket or
    /// a terminal recording is not a disclosure. Pass this only when the value
    /// itself is the thing you came for.
    #[arg(long)]
    pub unsafe_values: bool,
}

pub async fn run(c: &Client, ctx: &Ctx, args: ApiArgs) -> Result<()> {
    let path = expand(&args.path, c, ctx)?;

    let mut query = Vec::new();
    for q in &args.query {
        let Some((k, v)) = q.split_once('=') else {
            bail!("query {q:?} is not KEY=VALUE");
        };
        query.push((k.to_string(), expand(v, c, ctx)?));
    }

    if !args.list {
        let mut v = ui::spin(&format!("GET {path}"), c.get(&path, &query)).await?;
        mask(&mut v, args.unsafe_values);
        render::one(&v);
        return Ok(());
    }

    let paging = match (args.token_paging, args.per_page) {
        (true, _) => Paging::Token,
        (_, true) => Paging::PerPage,
        _ => Paging::Page,
    };
    let mut rows = ui::spin(
        &format!("GET {path}"),
        c.list(
            &path,
            &query,
            paging,
            args.collection.as_deref(),
            args.limit,
        ),
    )
    .await?;

    for row in &mut rows {
        mask(row, args.unsafe_values);
    }

    if render::is_json() {
        render::print_json(&Value::Array(rows));
        return Ok(());
    }
    render::list_auto(&rows);
    render::count(rows.len(), "item");
    Ok(())
}

/// Replace any credential in a response with its length, and say so once.
fn mask(v: &mut Value, unsafe_values: bool) {
    if unsafe_values {
        return;
    }
    let n = crate::scw::secrets::redact(v);
    if n > 0 {
        ui::warning(&format!(
            "{n} secret value(s) in this response were replaced by their length; \
             --unsafe-values prints them"
        ));
    }
}

/// Replace the placeholders a path may carry with what the profile resolved.
///
/// `{region}` and `{zone}` refuse to guess: a sweep that silently picked
/// `fr-par` would report a clean account while the finding sat in `pl-waw`.
fn expand(s: &str, c: &Client, ctx: &Ctx) -> Result<String> {
    let mut out = s.to_string();

    if out.contains("{region}") {
        let r = ctx.localities(crate::scw::Scope::Region);
        if r.len() != 1 {
            bail!(
                "{{region}} needs --region (or --zone); this profile covers {}",
                r.len()
            );
        }
        out = out.replace("{region}", &r[0]);
    }
    if out.contains("{zone}") {
        let z = ctx.localities(crate::scw::Scope::Zone);
        if z.len() != 1 {
            bail!("{{zone}} needs --zone; this profile covers {}", z.len());
        }
        out = out.replace("{zone}", &z[0]);
    }
    if out.contains("{org}") {
        if c.organization_id().is_empty() {
            bail!("{{org}} needs --organization-id, or a profile that recorded one at login");
        }
        out = out.replace("{org}", c.organization_id());
    }
    if out.contains("{project}") {
        if c.project_id().is_empty() {
            bail!("{{project}} needs --project-id");
        }
        out = out.replace("{project}", c.project_id());
    }
    Ok(out)
}
