//! `login` — create or update a profile, prove the credentials work, save them.
//!
//! The wizard exists for one reason: the failure it prevents. A Scaleway API
//! key is two opaque strings that differ only in shape, the secret half is
//! shown exactly once at creation, and pasting it into the wrong field produces
//! a 401 that says nothing useful. So the secret is read without echo, both
//! halves are shape-checked before a request is made, and the profile is only
//! written after the API has agreed that the pair works.

use anyhow::{bail, Result};
use clap::Args;

use crate::cli::Overrides;
use crate::commands::prompt;
use reqwest::StatusCode;
use serde_json::Value;

use crate::scw::{config, identity, Client, Paging, Profile};
use crate::ui::{self, render};

#[derive(Args, Debug)]
pub struct LoginArgs {
    /// Profile name to create or update
    #[arg(long, short = 'n', value_name = "NAME")]
    pub name: Option<String>,

    /// Do not make this the default profile
    #[arg(long)]
    pub no_default: bool,

    /// Save without testing the credentials first
    #[arg(long)]
    pub no_verify: bool,

    /// Answer nothing interactively; every value must come from flags or env
    #[arg(long)]
    pub non_interactive: bool,
}

pub async fn run(ov: &Overrides, args: &LoginArgs) -> Result<()> {
    let mut cfg = config::load()?;

    let name = match &args.name {
        Some(n) => n.clone(),
        None if args.non_interactive => "default".to_string(),
        None => prompt::ask(
            "Profile name",
            cfg.default_profile.as_deref().unwrap_or("default"),
        )?,
    };
    if name.trim().is_empty() {
        bail!("a profile needs a name");
    }

    // An existing profile is the source of defaults, so `login` doubles as
    // "rotate the key on this profile" without retyping everything else.
    let mut p = cfg.profiles.get(&name).cloned().unwrap_or_default();

    p.access_key = pick(
        ov.access_key.clone(),
        config::env("ACCESS_KEY"),
        &p.access_key,
        "Access key",
        args.non_interactive,
        false,
    )?;
    if !p.access_key.is_empty() && !config::looks_like_access_key(&p.access_key) {
        bail!(
            "{:?} does not look like an access key (SCW + 17 characters)",
            p.access_key
        );
    }

    p.secret_key = pick(
        ov.secret_key.clone(),
        config::env("SECRET_KEY"),
        &p.secret_key,
        "Secret key",
        args.non_interactive,
        true,
    )?;
    if !config::looks_like_secret_key(&p.secret_key) {
        bail!(
            "the secret key is not a UUID. It is the second half of the key pair, shown once \
             when the key is created — not the access key, and not the key id."
        );
    }

    if let Some(v) = &ov.organization_id {
        if !identity::looks_like_uuid(v) {
            bail!("{v:?} is not an organization id; it is a UUID, shown on the console's IAM page");
        }
        p.organization_id = v.clone();
    }
    if let Some(v) = &ov.project_id {
        p.project_id = v.clone();
    }
    if let Some(v) = &ov.region {
        crate::scw::locality::check_region(v)?;
        p.region = v.clone();
    }
    if let Some(v) = &ov.zone {
        crate::scw::locality::check_zone(v)?;
        p.zone = v.clone();
    }
    if let Some(v) = &ov.api_url {
        p.api_url = Some(v.clone());
    }

    if !args.no_verify {
        verify(&mut p, args.non_interactive).await?;
    }

    let is_default = !args.no_default || cfg.default_profile.is_none();
    cfg.profiles.insert(name.clone(), p.clone());
    if is_default {
        cfg.default_profile = Some(name.clone());
    }
    config::save(&cfg)?;

    ui::success(&format!(
        "saved profile {name:?} to {}",
        config::path().display()
    ));
    render::pairs(&[
        ("access key", p.access_key.clone()),
        ("secret key", config::redact(&p.secret_key)),
        ("organization", p.organization_id.clone()),
        (
            "scope",
            match (p.region.as_str(), p.zone.as_str()) {
                ("", "") => "every region and zone".to_string(),
                (r, "") => r.to_string(),
                (_, z) => z.to_string(),
            },
        ),
        ("default", is_default.to_string()),
    ]);
    ui::info("next: `mlab-scw whoami` to see what this key is allowed to read");
    Ok(())
}

/// Flag, then environment, then the stored value, then a question.
fn pick(
    flag: Option<String>,
    env: Option<String>,
    stored: &str,
    label: &str,
    non_interactive: bool,
    secret: bool,
) -> Result<String> {
    if let Some(v) = flag.filter(|v| !v.is_empty()) {
        return Ok(v.trim().to_string());
    }
    if let Some(v) = env.filter(|v| !v.is_empty()) {
        ui::info(&format!("{label} taken from the environment"));
        return Ok(v.trim().to_string());
    }
    if non_interactive {
        if stored.is_empty() {
            bail!("{label} is missing and --non-interactive forbids asking for it");
        }
        return Ok(stored.to_string());
    }
    if secret {
        // Never offer a secret as a visible default; a blank answer keeps it.
        let hint = if stored.is_empty() {
            String::new()
        } else {
            format!(" (blank keeps {})", config::redact(stored))
        };
        let v = prompt::ask_secret(&format!("{label}{hint}"))?;
        return Ok(if v.is_empty() { stored.to_string() } else { v });
    }
    prompt::ask(label, stored)
}

/// Prove the pair works, and learn the organization while we are there.
///
/// The order is forced by the API rather than chosen. Listing projects is the
/// cheapest proof the credentials work, but it *requires* an `organization_id`
/// — and nothing in an API key carries one. So the ladder is: read the key
/// from IAM, follow it to the application or user bearing it, take the
/// organization from there, and only then ask for projects.
///
/// Each rung fails differently and the difference is the whole point:
///
/// | answer | means |
/// | --- | --- |
/// | 401 | the secret key is wrong. Fatal — never save this. |
/// | 404 | the secret key works, the *access* key names nothing. |
/// | 403 | both work; the key simply holds no IAM permission set. |
async fn verify(p: &mut Profile, non_interactive: bool) -> Result<()> {
    let c = Client::new(p, std::time::Duration::from_secs(30))?;
    let mut proven = false;

    if p.access_key.is_empty() {
        ui::warning("no access key, so the credentials cannot be checked against IAM");
    } else {
        match ui::spin("Checking the credentials", identity::api_key(&c)).await {
            Ok(key) => {
                proven = true;
                ui::success("the credentials work");
                if p.organization_id.is_empty() {
                    if let Some(principal) = identity::principal_of(&key) {
                        if let Ok(record) = c.get(&identity::principal_path(&principal), &[]).await
                        {
                            if let Some(org) = record.get("organization_id").and_then(Value::as_str)
                            {
                                p.organization_id = org.to_string();
                                ui::info(&format!("organization {org}"));
                            }
                        }
                    }
                }
            }
            Err(e) => match status(&e) {
                Some(StatusCode::UNAUTHORIZED) => bail!(
                    "the secret key was refused. It is the UUID shown once when the key is \
                     created, not the access key and not the key's name.\n{e:#}"
                ),
                Some(StatusCode::NOT_FOUND) => bail!(
                    "the secret key authenticates, but no API key has access key {:?}. \
                     Check the access key, or pass --no-verify to save anyway.",
                    p.access_key
                ),
                Some(StatusCode::FORBIDDEN) => {
                    proven = true;
                    ui::success("the credentials authenticate");
                    ui::warning("this key cannot read IAM, so its own identity is invisible to it");
                }
                _ => return Err(e),
            },
        }
    }

    if p.organization_id.is_empty() {
        ui::info("the organization is not in the key; it is on the console's IAM page");
        if non_interactive {
            bail!(
                "organization id is missing; pass --organization-id, set \
                 SCW_DEFAULT_ORGANIZATION_ID, or drop --non-interactive"
            );
        }
        let answer = prompt::ask("Organization ID", "")?;
        if answer.is_empty() {
            ui::warning("no organization; `project` and `whoami` will have to resolve it each run");
        } else if !identity::looks_like_uuid(&answer) {
            bail!("{answer:?} is not a UUID");
        } else {
            p.organization_id = answer;
        }
    }

    if p.organization_id.is_empty() {
        if !proven {
            ui::warning("credentials saved unverified");
        }
        return Ok(());
    }

    let query = vec![("organization_id".to_string(), p.organization_id.clone())];
    let probe = c.list(
        "/account/v3/projects",
        &query,
        Paging::Page,
        Some("projects"),
        Some(1),
    );
    match ui::spin("Listing projects", probe).await {
        Ok(_) => {
            if !proven {
                ui::success("the credentials work");
            }
            Ok(())
        }
        Err(e) if status(&e) == Some(StatusCode::FORBIDDEN) => {
            ui::warning(
                "the key cannot list projects (no ProjectReadOnly); run \
                 `mlab-scw catalog --permissions` for what an audit needs",
            );
            Ok(())
        }
        Err(e) if !proven => Err(e),
        Err(e) => {
            ui::warning(&format!("projects could not be listed: {e:#}"));
            Ok(())
        }
    }
}

/// The HTTP status behind an error, when the API is what produced it. `None`
/// means the request never got an answer at all — a network failure, which is
/// a different problem from any refusal.
fn status(e: &anyhow::Error) -> Option<StatusCode> {
    e.downcast_ref::<crate::scw::client::ApiError>()
        .map(|a| a.status)
}
