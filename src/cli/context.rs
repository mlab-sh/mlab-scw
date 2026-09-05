//! Turning flags, environment and config file into one resolved connection.

use std::time::Duration;

use anyhow::Result;

use crate::cli::Cli;
use crate::scw::locality::{self, Scope};
use crate::scw::{config, Profile};
use crate::ui::render;

/// Settings a flag may override on top of a stored profile. Kept apart from
/// [`Cli`] so the login wizard can take the same shape without clap in scope.
#[derive(Debug, Default)]
pub struct Overrides {
    pub access_key: Option<String>,
    pub secret_key: Option<String>,
    pub organization_id: Option<String>,
    pub project_id: Option<String>,
    pub region: Option<String>,
    pub zone: Option<String>,
    pub api_url: Option<String>,
    pub output: Option<String>,
}

impl From<&Cli> for Overrides {
    fn from(cli: &Cli) -> Self {
        Overrides {
            access_key: cli.access_key.clone(),
            secret_key: cli.secret_key.clone(),
            organization_id: cli.organization_id.clone(),
            project_id: cli.project_id.clone(),
            region: cli.region.clone(),
            zone: cli.zone.clone(),
            api_url: cli.api_url.clone(),
            output: cli.output.clone(),
        }
    }
}

/// The resolved settings for this invocation.
pub struct Ctx {
    pub name: String,
    pub profile: Profile,
    pub timeout: Duration,
}

impl Ctx {
    /// Resolve the profile for this run: file, then environment, then flags.
    pub fn build(cli: &Cli) -> Result<Ctx> {
        let cfg = config::load()?;
        let ov = Overrides::from(cli);

        let (name, mut p) = match cfg.profile(cli.profile.as_deref()) {
            Ok(found) => found,
            Err(e) => {
                // Usable with no config file at all when the key is given.
                let has_key = ov.secret_key.is_some() || config::env("SECRET_KEY").is_some();
                if cli.profile.is_none() && has_key {
                    ("(flags)".to_string(), Profile::default())
                } else {
                    return Err(e);
                }
            }
        };

        // Environment second. The names without the `MLAB_` prefix are the ones
        // Scaleway's own tooling already exports.
        if let Some(v) = config::env("ACCESS_KEY") {
            p.access_key = v;
        }
        if let Some(v) = config::env("SECRET_KEY") {
            p.secret_key = v;
        }
        if let Some(v) = config::env("DEFAULT_ORGANIZATION_ID") {
            p.organization_id = v;
        }
        if let Some(v) = config::env("DEFAULT_PROJECT_ID") {
            p.project_id = v;
        }
        if let Some(v) = config::env("DEFAULT_REGION") {
            p.region = v;
        }
        if let Some(v) = config::env("DEFAULT_ZONE") {
            p.zone = v;
        }
        if let Some(v) = config::env("API_URL") {
            p.api_url = Some(v);
        }

        // Flags last.
        if let Some(v) = &ov.access_key {
            p.access_key = v.clone();
        }
        if let Some(v) = &ov.secret_key {
            p.secret_key = v.clone();
        }
        if let Some(v) = &ov.organization_id {
            p.organization_id = v.clone();
        }
        if let Some(v) = &ov.project_id {
            p.project_id = v.clone();
        }
        if let Some(v) = &ov.region {
            p.region = v.clone();
        }
        if let Some(v) = &ov.zone {
            p.zone = v.clone();
        }
        if let Some(v) = &ov.api_url {
            p.api_url = Some(v.clone());
        }

        if !p.region.is_empty() {
            locality::check_region(&p.region)?;
        }
        if !p.zone.is_empty() {
            locality::check_zone(&p.zone)?;
        }

        // The flag and the environment were applied at startup; a profile-level
        // preference only speaks when neither of them did.
        if ov.output.is_none() && config::env("OUTPUT").is_none() {
            render::init(p.output.as_deref());
        }

        Ok(Ctx {
            name,
            profile: p,
            timeout: Duration::from_secs(cli.timeout.max(1)),
        })
    }

    /// The localities a sweep of `scope` should cover for this run.
    ///
    /// A `--zone` narrows a zonal sweep to that zone and a regional sweep to
    /// its region, so one flag means the same thing to every product.
    pub fn localities(&self, scope: Scope) -> Vec<String> {
        let (region, zone) = (self.profile.region.as_str(), self.profile.zone.as_str());
        match scope {
            Scope::Global => vec![String::new()],
            Scope::Region => {
                if !region.is_empty() {
                    vec![region.to_string()]
                } else if let Some(r) = locality::region_of(zone) {
                    vec![r]
                } else {
                    locality::REGIONS.iter().map(|s| s.to_string()).collect()
                }
            }
            Scope::Zone => {
                if !zone.is_empty() {
                    vec![zone.to_string()]
                } else if !region.is_empty() {
                    locality::zones_of(region)
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                } else {
                    locality::ZONES.iter().map(|s| s.to_string()).collect()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(region: &str, zone: &str) -> Ctx {
        Ctx {
            name: "t".into(),
            profile: Profile {
                region: region.into(),
                zone: zone.into(),
                ..Default::default()
            },
            timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn an_unnarrowed_run_sweeps_everything() {
        let c = ctx("", "");
        assert_eq!(c.localities(Scope::Global), vec![""]);
        assert_eq!(c.localities(Scope::Region).len(), locality::REGIONS.len());
        assert_eq!(c.localities(Scope::Zone).len(), locality::ZONES.len());
    }

    #[test]
    fn a_region_narrows_both_regional_and_zonal_sweeps() {
        let c = ctx("fr-par", "");
        assert_eq!(c.localities(Scope::Region), vec!["fr-par"]);
        assert_eq!(
            c.localities(Scope::Zone),
            vec!["fr-par-1", "fr-par-2", "fr-par-3"]
        );
    }

    #[test]
    fn a_zone_implies_its_region_so_one_flag_means_one_place() {
        let c = ctx("", "nl-ams-2");
        assert_eq!(c.localities(Scope::Zone), vec!["nl-ams-2"]);
        assert_eq!(
            c.localities(Scope::Region),
            vec!["nl-ams"],
            "a zonal narrowing must not leave regional products sweeping the world"
        );
    }
}
