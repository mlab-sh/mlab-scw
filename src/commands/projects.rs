//! `project` — the projects a key can see.
//!
//! Short command, load-bearing result: every regional and zonal listing in this
//! catalogue is filtered by project, so what this prints is the boundary of
//! every other answer the tool will give.

use anyhow::Result;
use clap::Args;

use crate::cli::Ctx;
use crate::scw::{identity, Client, Paging};
use crate::ui::render;

#[derive(Args, Debug, Clone, Default)]
pub struct ProjectArgs {
    /// Return a single page of this size instead of everything
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
}

pub async fn run(c: &Client, ctx: &Ctx, args: &ProjectArgs) -> Result<()> {
    // Not optional: without it the API answers 400 invalid_arguments. And the
    // organization is not something an API key carries — it takes two IAM
    // calls to find one, which a profile that recorded it at login skips.
    let mut organization = ctx.profile.organization_id.clone();
    if organization.is_empty() {
        organization = crate::ui::spin("Resolving the organization", identity::organization(c))
            .await
            .unwrap_or_default();
    }
    if organization.is_empty() {
        anyhow::bail!(
            "listing projects needs an organization id, and this key cannot read its own \
             principal in IAM to find one. Pass --organization-id, set \
             SCW_DEFAULT_ORGANIZATION_ID, or run `mlab-scw login` to record it — the \
             console shows it on the IAM page."
        );
    }
    let query = vec![("organization_id".to_string(), organization)];

    let projects = crate::ui::spin(
        "Listing projects",
        c.list(
            "/account/v3/projects",
            &query,
            Paging::Page,
            Some("projects"),
            args.limit,
        ),
    )
    .await?;

    render::heading("Projects");
    render::list(&projects, render::PROJECT_COLS);
    render::count(projects.len(), "project");
    Ok(())
}
