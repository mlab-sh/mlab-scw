//! `completions` — shell completion for the commands, the flags and the
//! catalogue's product keys.
//!
//! Written to stdout so it can be redirected, with nothing else on it: this is
//! the one command whose output is meant to be `eval`'d.

use std::io;

use anyhow::Result;
use clap::CommandFactory;
use clap_complete::Shell;

use crate::cli::Cli;

pub fn run(shell: Shell) -> Result<()> {
    let mut cmd = Cli::command();
    let name = cmd.get_name().to_string();
    clap_complete::generate(shell, &mut cmd, name, &mut io::stdout());
    Ok(())
}
