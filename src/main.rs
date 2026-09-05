//! `mlab-scw` — a CLI over the Scaleway API, built for read-only audit work.
//!
//! Layout:
//!
//! | module     | role                                                          |
//! | ---------- | ------------------------------------------------------------- |
//! | `scw`      | the API: HTTP handler, profiles, localities, the catalogue     |
//! | `audit`    | the graded checks, as pure functions over fetched data         |
//! | `ui`       | everything the user sees: progress on stderr, rendering        |
//! | `cli`      | the clap surface and the dispatch                              |
//! | `commands` | one module per command                                         |

mod audit;
mod cli;
mod commands;
mod scw;
mod ui;

use colored::Colorize;

#[tokio::main]
async fn main() {
    if let Err(e) = cli::run().await {
        // A spinner may own a half-drawn line; wipe it before the message.
        ui::restore();
        eprintln!("  {} {e:#}", "✖".red().bold());
        std::process::exit(1);
    }
}
