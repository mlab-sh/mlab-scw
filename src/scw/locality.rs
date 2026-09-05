//! Regions and zones.
//!
//! Scaleway splits its surface three ways. A **global** API is one endpoint for
//! the whole account (IAM, Account, Billing, Domains). A **regional** API is one
//! endpoint per region. A **zonal** API is one endpoint per Availability Zone.
//!
//! This matters more here than it looks: an audit that only queries `fr-par`
//! reports a clean account while a forgotten public Instance runs in `pl-waw-2`.
//! Everything in this CLI therefore fans out over every locality it knows,
//! unless a flag narrows it.

use anyhow::{bail, Result};

/// Every region Scaleway serves.
pub const REGIONS: [&str; 4] = ["fr-par", "nl-ams", "pl-waw", "it-mil"];

/// Every Availability Zone Scaleway serves.
pub const ZONES: [&str; 10] = [
    "fr-par-1", "fr-par-2", "fr-par-3", "nl-ams-1", "nl-ams-2", "nl-ams-3", "pl-waw-1", "pl-waw-2",
    "pl-waw-3", "it-mil-1",
];

/// Where an API's endpoints live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// One endpoint for the account: no locality segment in the path.
    Global,
    /// `/regions/{region}` in the path.
    Region,
    /// `/zones/{zone}` in the path.
    Zone,
}

impl Scope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Scope::Global => "global",
            Scope::Region => "region",
            Scope::Zone => "zone",
        }
    }

    /// The locality segment to splice between an API's base and its resource
    /// path, for one locality value.
    pub fn segment(&self, locality: &str) -> String {
        match self {
            Scope::Global => String::new(),
            Scope::Region => format!("/regions/{locality}"),
            Scope::Zone => format!("/zones/{locality}"),
        }
    }
}

/// The region a zone belongs to: `fr-par-2` is in `fr-par`.
pub fn region_of(zone: &str) -> Option<String> {
    let parts: Vec<&str> = zone.split('-').collect();
    if parts.len() != 3 {
        return None;
    }
    Some(format!("{}-{}", parts[0], parts[1]))
}

/// Reject a region that does not exist, so a typo fails at parse time rather
/// than as a wall of 404s.
pub fn check_region(r: &str) -> Result<()> {
    if !REGIONS.contains(&r) {
        bail!("unknown region {r:?} (known: {})", REGIONS.join(", "));
    }
    Ok(())
}

/// Reject a zone that does not exist.
pub fn check_zone(z: &str) -> Result<()> {
    if !ZONES.contains(&z) {
        bail!("unknown zone {z:?} (known: {})", ZONES.join(", "));
    }
    Ok(())
}

/// The zones inside a region, for a run narrowed to one region.
pub fn zones_of(region: &str) -> Vec<&'static str> {
    ZONES
        .iter()
        .copied()
        .filter(|z| region_of(z).as_deref() == Some(region))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_zone_belongs_to_a_known_region() {
        for z in ZONES {
            let r = region_of(z).expect("a zone is xx-yyy-n");
            assert!(REGIONS.contains(&r.as_str()), "{z} -> {r}");
        }
    }

    #[test]
    fn a_scope_splices_the_right_segment() {
        assert_eq!(Scope::Global.segment("fr-par"), "");
        assert_eq!(Scope::Region.segment("fr-par"), "/regions/fr-par");
        assert_eq!(Scope::Zone.segment("fr-par-1"), "/zones/fr-par-1");
    }

    #[test]
    fn zones_of_narrows_a_sweep_to_one_region() {
        assert_eq!(zones_of("fr-par"), vec!["fr-par-1", "fr-par-2", "fr-par-3"]);
        assert_eq!(zones_of("it-mil"), vec!["it-mil-1"]);
        assert!(zones_of("nope").is_empty());
    }

    #[test]
    fn a_typo_is_refused_with_the_list_of_what_exists() {
        assert!(check_region("fr-par").is_ok());
        assert!(check_region("fr-par-1").is_err(), "that is a zone");
        assert!(check_zone("it-mil-1").is_ok());
        assert!(check_zone("it-mil").is_err(), "that is a region");
    }
}
