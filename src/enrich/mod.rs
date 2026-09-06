//! What the account runs, against what has been published about it.
//!
//! This is the only part of the tool that talks to anything but
//! `api.scaleway.com`, so it is the only part that can leak. Three rules hold
//! it in place:
//!
//! * **it is opt-in, per run.** Without `--allow-web` nothing is sent, and the
//!   report says so rather than reading as a clean bill of health.
//! * **only a version string and a CPE ever leave.** No organization, no
//!   project, no resource id, no name, no address. What goes out identifies
//!   software, never an account.
//! * **it never probes.** The corpus is a document store; asking it a question
//!   sends no packet at anything you own. The tool's promise that every request
//!   is a read stays true.

pub mod corpus;
pub mod cpe;

use std::fs;
use std::path::PathBuf;

/// Where the corpus cache lives: `$HOME/.mlab/scw/`.
pub fn cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    PathBuf::from(home).join(".mlab").join("scw")
}

/// Read a cache file, or `None` when it is absent or unreadable. A corrupt
/// cache is never fatal: the caller refetches.
pub fn read_cache<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Option<T> {
    serde_json::from_str(&fs::read_to_string(path).ok()?).ok()
}

/// Write a cache file, 0600 inside a 0700 directory.
pub fn write_cache<T: serde::Serialize>(path: &PathBuf, value: &T) {
    if let Some(dir) = path.parent() {
        if fs::create_dir_all(dir).is_err() {
            return;
        }
        set_mode(dir, 0o700);
    }
    if let Ok(data) = serde_json::to_string(value) {
        if fs::write(path, data).is_ok() {
            set_mode(path, 0o600);
        }
    }
}

fn set_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

pub fn now() -> i64 {
    crate::scw::now()
}
