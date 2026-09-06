//! One module per command.
//!
//! Each exposes a `run` taking whatever it needs — a [`Client`](crate::scw::Client)
//! and the resolved [`Ctx`](crate::cli::Ctx) for the API commands, nothing but
//! its own arguments for the ones that only touch the config file.

pub mod advisories;
pub mod api;
pub mod catalog;
pub mod completions;
pub mod exposure;
pub mod iam;
pub mod login;
pub mod ping;
pub mod profile;
pub mod projects;
pub mod prompt;
pub mod quiet;
pub mod settings;
pub mod whoami;
