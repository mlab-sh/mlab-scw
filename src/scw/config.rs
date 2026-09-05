//! Config storage for the `mlab-scw` CLI: the API key manager.
//!
//! One file, `$HOME/.mlab/scw.conf` (JSON), holding any number of named
//! profiles plus the name of the default one. Written 0600 inside a 0700 dir:
//! it contains secret keys.
//!
//! A Scaleway API key is a pair. The **access key** (`SCWXXXXXXXXXXXXXXXXX`) is
//! an identifier and is not sensitive; the **secret key** is a UUID that
//! authenticates it and is. Both are stored, because the pair is also what
//! signs Object Storage requests — the same credentials serve the JSON API
//! through `X-Auth-Token` and S3 through SigV4.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// The one base URL every Scaleway product API hangs off.
pub const DEFAULT_API_URL: &str = "https://api.scaleway.com";

/// Credentials and defaults for one Scaleway account.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Profile {
    /// Access key of the API key: `SCW` followed by 17 characters.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub access_key: String,
    /// Secret key of the API key. This is the `X-Auth-Token` value.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_key: String,
    /// Organization the key belongs to. Discovered at login.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub organization_id: String,
    /// Default project. Today it only fills `{project}` in the `api` command;
    /// empty means every project the key can see, which is what an audit wants.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub project_id: String,
    /// Narrow every sweep to this region. Empty means all of them.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    /// Narrow every sweep to this zone. Empty means all of them.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub zone: String,
    /// Override the API base URL, for a proxy or a test double.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_url: Option<String>,
    /// `json` or `human`; `None` means the global default (`human`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

impl Profile {
    /// The API base URL this profile talks to.
    pub fn api_url(&self) -> String {
        self.api_url
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_API_URL)
            .trim_end_matches('/')
            .to_string()
    }

    /// Reject a profile that cannot produce a request.
    pub fn validate(&self) -> Result<()> {
        if self.secret_key.is_empty() {
            bail!(
                "secret key is missing (set --secret-key, SCW_SECRET_KEY, or run `mlab-scw login`)"
            );
        }
        if !looks_like_secret_key(&self.secret_key) {
            bail!("secret key is not a UUID; the console shows it once, at key creation");
        }
        if !self.access_key.is_empty() && !looks_like_access_key(&self.access_key) {
            bail!("access key {:?} does not look like SCW…", self.access_key);
        }
        Ok(())
    }

    /// A copy with the secret key masked, for printing.
    pub fn redacted(&self) -> Profile {
        let mut p = self.clone();
        p.secret_key = redact(&self.secret_key);
        p
    }
}

/// Mask a secret down to its last 4 characters.
pub fn redact(key: &str) -> String {
    if key.is_empty() {
        return String::new();
    }
    let tail: String = key
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("****{tail}")
}

/// A secret key is a UUID. Checking the shape catches the most common mistake
/// by far: pasting the access key into both fields.
pub fn looks_like_secret_key(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && [8, 4, 4, 4, 12] == parts.iter().map(|p| p.len()).collect::<Vec<_>>()[..]
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// An access key is `SCW` plus 17 uppercase alphanumerics.
pub fn looks_like_access_key(s: &str) -> bool {
    s.len() == 20
        && s.starts_with("SCW")
        && s[3..]
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
}

/// The whole config file.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ConfigFile {
    /// Name of the profile used when `--profile` is not given.
    #[serde(rename = "default", default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    #[serde(default)]
    pub profiles: BTreeMap<String, Profile>,
}

impl ConfigFile {
    /// Resolve `name` (or the default profile when `None`).
    pub fn profile(&self, name: Option<&str>) -> Result<(String, Profile)> {
        let wanted = match name {
            Some(n) => n.to_string(),
            None => match &self.default_profile {
                Some(d) => d.clone(),
                None if self.profiles.len() == 1 => self.profiles.keys().next().unwrap().clone(),
                _ => bail!("no profile selected and no default set; run `mlab-scw login`"),
            },
        };
        match self.profiles.get(&wanted) {
            Some(p) => Ok((wanted, p.clone())),
            None => bail!(
                "profile {wanted:?} not found in {} (known: {})",
                path().display(),
                if self.profiles.is_empty() {
                    "none".to_string()
                } else {
                    self.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
                }
            ),
        }
    }
}

/// `$MLAB_SCW_CONFIG`, else `$HOME/.mlab/scw.conf`.
pub fn path() -> PathBuf {
    if let Ok(p) = std::env::var("MLAB_SCW_CONFIG") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".mlab").join("scw.conf")
}

/// Read the config file. A missing file is an empty config, not an error.
pub fn load() -> Result<ConfigFile> {
    let p = path();
    let data = match fs::read_to_string(&p) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(ConfigFile::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", p.display())),
    };
    if data.trim().is_empty() {
        return Ok(ConfigFile::default());
    }
    serde_json::from_str(&data).with_context(|| format!("parsing {}", p.display()))
}

/// Write the config file, 0600 in a 0700 directory.
pub fn save(cfg: &ConfigFile) -> Result<()> {
    let p = path();
    if let Some(dir) = p.parent() {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        set_mode(dir, 0o700)?;
    }
    let mut data = serde_json::to_string_pretty(cfg)?;
    data.push('\n');
    fs::write(&p, data).with_context(|| format!("writing {}", p.display()))?;
    set_mode(&p, 0o600)?;
    Ok(())
}

/// Non-empty when the config file is readable or writable by group/others.
pub fn perms_warning() -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let p = path();
        let meta = fs::metadata(&p).ok()?;
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Some(format!(
                "config {} has mode {mode:04o}; it holds secret keys, 0600 is recommended",
                p.display()
            ));
        }
    }
    None
}

fn set_mode(path: &std::path::Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {mode:o} {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}

/// First non-empty of `MLAB_SCW_<name>` then `SCW_<name>`.
///
/// The second spelling is deliberate: `SCW_ACCESS_KEY`, `SCW_SECRET_KEY`,
/// `SCW_DEFAULT_ORGANIZATION_ID` and friends are what Scaleway's own CLI and
/// Terraform provider already export, so a shell set up for those needs no
/// second set of variables here.
pub fn env(name: &str) -> Option<String> {
    for key in [format!("MLAB_SCW_{name}"), format!("SCW_{name}")] {
        if let Ok(v) = std::env::var(&key) {
            if !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_shapes_catch_the_usual_paste_mistake() {
        assert!(looks_like_access_key("SCW0123456789ABCDEFG"));
        assert!(!looks_like_access_key("SCW-0123"));
        assert!(looks_like_secret_key(
            "11111111-2222-3333-4444-555555555555"
        ));
        assert!(
            !looks_like_secret_key("SCW0123456789ABCDEFG"),
            "the access key in the secret field is the mistake to catch"
        );
    }

    #[test]
    fn validate_requires_a_well_shaped_secret_key() {
        let mut p = Profile::default();
        assert!(p.validate().is_err(), "no key at all");
        p.secret_key = "not-a-uuid".into();
        assert!(p.validate().is_err());
        p.secret_key = "11111111-2222-3333-4444-555555555555".into();
        assert!(
            p.validate().is_ok(),
            "an access key is optional for the API"
        );
        p.access_key = "nope".into();
        assert!(p.validate().is_err());
    }

    #[test]
    fn redact_keeps_only_the_tail() {
        assert_eq!(redact("11111111-2222-3333-4444-555555555555"), "****5555");
        assert_eq!(redact(""), "");
    }

    #[test]
    fn the_api_url_has_a_default_and_loses_its_trailing_slash() {
        let mut p = Profile::default();
        assert_eq!(p.api_url(), DEFAULT_API_URL);
        p.api_url = Some("https://proxy.example/".into());
        assert_eq!(p.api_url(), "https://proxy.example");
    }

    #[test]
    fn profile_falls_back_to_the_only_one() {
        let mut cfg = ConfigFile::default();
        cfg.profiles.insert("only".into(), Profile::default());
        assert_eq!(cfg.profile(None).unwrap().0, "only");
        assert!(cfg.profile(Some("other")).is_err());
    }
}
