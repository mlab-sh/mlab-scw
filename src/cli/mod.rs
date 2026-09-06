//! The command line surface, and the dispatch behind it.
//!
//! Adding a command means: a module under [`crate::commands`], a variant in
//! [`Cmd`], and one arm in [`run`].

mod context;

pub use context::{Ctx, Overrides};

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};

use crate::commands;
use crate::scw::{config, Client};
use crate::ui::{self, render};

#[derive(Parser, Debug)]
#[command(
    name = "mlab-scw",
    version,
    about = "Read a Scaleway account over its API, for audit work",
    long_about = "Read a Scaleway account over its API, for audit work.\n\n\
                  Credentials live in profiles in $HOME/.mlab/scw.conf; run \
                  `mlab-scw login` once to create one. Flags override environment \
                  variables (MLAB_SCW_* then SCW_*), which override the profile.\n\n\
                  Every request this tool makes is a GET.",
    after_help = "Create an API key in the console: IAM -> API keys. Give it an \
                  application of its own, and only the read-only permission sets \
                  `mlab-scw catalog --permissions` prints."
)]
pub struct Cli {
    /// Profile to use (default: the one marked default in the config)
    #[arg(long, short = 'p', global = true, value_name = "NAME")]
    pub profile: Option<String>,

    /// Access key of the API key (SCW…)
    #[arg(long, global = true, value_name = "KEY")]
    pub access_key: Option<String>,

    /// Secret key; prefer SCW_SECRET_KEY, a command line is visible to other users
    #[arg(long, global = true, value_name = "KEY")]
    pub secret_key: Option<String>,

    /// Organization to query (default: the one the key belongs to)
    #[arg(long, global = true, value_name = "UUID")]
    pub organization_id: Option<String>,

    /// Project to work in. Today it fills {project} in `api`; nothing else
    /// reads it yet, because no command lists project-scoped resources on its
    /// own. Leaving it unset is what an audit wants: without it the API answers
    /// for every project the key can reach.
    #[arg(long, global = true, value_name = "UUID")]
    pub project_id: Option<String>,

    /// Narrow the sweep to one region
    #[arg(long, global = true, value_name = "fr-par|nl-ams|pl-waw|it-mil")]
    pub region: Option<String>,

    /// Narrow the sweep to one availability zone
    #[arg(long, global = true, value_name = "ZONE")]
    pub zone: Option<String>,

    /// Override the API base URL
    #[arg(long, global = true, value_name = "URL", hide = true)]
    pub api_url: Option<String>,

    /// Output format: a terminal render, or raw JSON for scripting
    #[arg(long, short = 'o', global = true, value_parser = ["human", "json"], value_name = "FORMAT")]
    pub output: Option<String>,

    /// Silence progress and status lines on stderr
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// Per-request timeout, in seconds
    #[arg(long, global = true, default_value_t = 30, value_name = "SECS")]
    pub timeout: u64,

    #[command(subcommand)]
    pub command: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Create or update a profile, test it, and save it to the config file
    #[command(alias = "configure", alias = "setup")]
    Login(commands::login::LoginArgs),

    /// Manage saved profiles
    Profile {
        #[command(subcommand)]
        cmd: commands::profile::ProfileCmd,
    },

    /// Print a shell completion script
    #[command(after_help = "Add it to the shell that will use it, for example:\n  \
                            mlab-scw completions zsh > ~/.zfunc/_mlab-scw\n  \
                            mlab-scw completions bash > /etc/bash_completion.d/mlab-scw\n  \
                            mlab-scw completions fish > ~/.config/fish/completions/mlab-scw.fish")]
    Completions {
        /// Shell to generate for
        #[arg(value_name = "SHELL")]
        shell: clap_complete::Shell,
    },

    /// Inspect the config file
    Config {
        #[command(subcommand)]
        cmd: commands::settings::ConfigCmd,
    },

    /// What can be audited, why, and with which permission sets
    #[command(alias = "surface")]
    Catalog(commands::catalog::CatalogArgs),

    /// Check that the current profile can reach the API
    Ping,

    /// What answers from the internet, and what stands in front of it
    #[command(alias = "edge")]
    Exposure(commands::exposure::ExposureArgs),

    /// Who can do what: principals, credentials, policies, and the checks on them
    Iam {
        #[command(subcommand)]
        cmd: Option<commands::iam::IamCmd>,
    },

    /// What this API key is, and everything it is allowed to do
    #[command(alias = "identity")]
    Whoami,

    /// Projects of the organization
    #[command(alias = "projects")]
    Project(commands::projects::ProjectArgs),

    /// Raw GET against any path, for anything not wrapped yet
    #[command(
        after_help = "PATH is absolute on api.scaleway.com and may contain {region},\n\
                      {zone}, {org} and {project}, replaced from the current profile.\n\n\
                      Only GET is issued. Examples:\n  \
                      mlab-scw api /iam/v1alpha1/users --list -Q organization_id={org}\n  \
                      mlab-scw api '/instance/v1/zones/{zone}/servers' --list --per-page\n  \
                      mlab-scw api '/k8s/v1/regions/{region}/clusters' --list\n  \
                      mlab-scw api /account/v3/projects --list -Q organization_id={org}"
    )]
    Api(commands::api::ApiArgs),
}

/// Parse, set up output, then hand over to a command.
pub async fn run() -> Result<()> {
    let cli = Cli::parse();
    ui::init(cli.quiet);
    // Resolved again from the profile in `Ctx::build` when neither the flag nor
    // the environment picked a format.
    render::init(cli.output.as_deref().or(config::env("OUTPUT").as_deref()));

    // Commands that touch no credentials and no network.
    match &cli.command {
        Cmd::Login(args) => return commands::login::run(&Overrides::from(&cli), args).await,
        Cmd::Profile { cmd } => return commands::profile::run(cmd),
        Cmd::Config { cmd } => return commands::settings::run(cmd),
        Cmd::Catalog(args) => return commands::catalog::run(args),
        Cmd::Completions { shell } => return commands::completions::run(*shell),
        _ => {}
    }

    if let Some(w) = config::perms_warning() {
        ui::warning(&w);
    }

    let ctx = Ctx::build(&cli)?;
    let c = Client::new(&ctx.profile, ctx.timeout)
        .with_context(|| format!("profile {:?}", ctx.name))?;

    match cli.command {
        Cmd::Login(_)
        | Cmd::Profile { .. }
        | Cmd::Config { .. }
        | Cmd::Catalog(_)
        | Cmd::Completions { .. } => unreachable!(),
        Cmd::Ping => commands::ping::run(&c, &ctx).await,
        Cmd::Whoami => commands::whoami::run(&c, &ctx).await,
        Cmd::Exposure(a) => commands::exposure::run(c, &ctx, &a).await,
        Cmd::Iam { cmd } => commands::iam::run(&c, &ctx, cmd).await,
        Cmd::Project(a) => commands::projects::run(&c, &ctx, &a).await,
        Cmd::Api(a) => commands::api::run(&c, &ctx, a).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// clap accepts a subcommand that redefines a global short flag, and
    /// resolves it in the subcommand's favour without a word. That is how `-q`
    /// silently stopped meaning `--quiet` inside `api`. This catches the whole
    /// family of definition mistakes — duplicate shorts, duplicate longs,
    /// unreachable arguments — at test time rather than in someone's terminal.
    #[test]
    fn the_command_definition_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    /// The global shorts, spelled out so that taking one for a subcommand is a
    /// deliberate act with a failing test attached rather than an accident.
    #[test]
    fn no_subcommand_steals_a_global_short_flag() {
        let cmd = Cli::command();
        let globals: Vec<char> = cmd
            .get_arguments()
            .filter(|a| a.is_global_set())
            .filter_map(|a| a.get_short())
            .collect();
        assert!(globals.contains(&'q'), "--quiet is global");

        for sub in cmd.get_subcommands() {
            for arg in sub.get_arguments() {
                if let Some(short) = arg.get_short() {
                    assert!(
                        !globals.contains(&short),
                        "`{}` redefines the global short -{short} as --{}",
                        sub.get_name(),
                        arg.get_id()
                    );
                }
            }
        }
    }
}
