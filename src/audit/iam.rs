//! The IAM checks.
//!
//! Read first, and fixed first: every other finding an audit can produce is
//! reachable by whoever holds the wrong credential here.
//!
//! Pure functions over already-fetched JSON. [`Iam`] is what the command
//! gathers; [`audit`] turns it into findings and never makes a request.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::{age_secs, b, duration_secs, len, n, name_or_id, s, strings, Finding, DAY};
use crate::scw::Severity;

/// A key older than this has outlived the reason it was made.
const STALE_KEY: i64 = 365 * DAY;
/// An SSH key older than this is on machines nobody remembers provisioning.
const STALE_SSH_KEY: i64 = 730 * DAY;
/// No login for this long: an account nobody would notice being used.
const DORMANT: i64 = 90 * DAY;
/// A console session should not outlive a working day.
const LONG_SESSION: i64 = DAY;
/// More attempts than this is not a lockout policy.
const LOCKOUT_CEILING: i64 = 10;
/// RSA below this is below current guidance.
const MIN_RSA_BITS: u32 = 3072;

/// Everything the IAM audit reads, as fetched.
#[derive(Default)]
pub struct Iam {
    pub organization_id: String,
    pub users: Vec<Value>,
    pub applications: Vec<Value>,
    pub api_keys: Vec<Value>,
    pub policies: Vec<Value>,
    /// Policy id to its rules.
    pub rules: BTreeMap<String, Vec<Value>>,
    pub groups: Vec<Value>,
    pub ssh_keys: Vec<Value>,
    pub settings: Option<Value>,
    /// What could not be read, and why. A finding list is only worth its
    /// coverage, so this is printed with the report rather than swallowed.
    pub gaps: Vec<String>,
}

/// Every check id this module can emit. Kept beside the code so a test can
/// prove none of them has drifted from the catalogue.
pub const IMPLEMENTED: [&str; 26] = [
    "iam.users.no-mfa",
    "iam.users.owner-daily-driver",
    "iam.users.dormant",
    "iam.users.locked",
    "iam.applications.keyless",
    "iam.applications.undescribed",
    "iam.api-keys.never-expires",
    "iam.api-keys.stale",
    "iam.api-keys.user-bound",
    "iam.api-keys.default-project",
    "iam.api-keys.creation-ip",
    "iam.policies.no-principal",
    "iam.policies.all-products-full-access",
    "iam.policies.org-scope",
    "iam.policies.unused",
    "iam.rules.write-in-a-read-role",
    "iam.rules.condition-free",
    "iam.groups.empty",
    "iam.groups.everyone",
    "iam.groups.mixed",
    "iam.ssh-keys.weak",
    "iam.ssh-keys.stale",
    "iam.ssh-keys.disabled",
    "iam.security-settings.no-key-expiry",
    "iam.security-settings.long-sessions",
    "iam.security-settings.no-lockout",
];

/// Run every check. `now` is passed in rather than read, so a test can pin it.
pub fn audit(iam: &Iam, now: i64) -> Vec<Finding> {
    let mut f = Vec::new();
    users(iam, now, &mut f);
    applications(iam, &mut f);
    api_keys(iam, now, &mut f);
    policies(iam, &mut f);
    rules(iam, &mut f);
    groups(iam, &mut f);
    ssh_keys(iam, now, &mut f);
    settings(iam, &mut f);
    super::sort(&mut f);
    f
}

// ---- users ------------------------------------------------------------------

fn users(iam: &Iam, now: i64, out: &mut Vec<Finding>) {
    for u in &iam.users {
        let who = name_or_id(u);
        let owner = s(u, "type") == "owner";

        // `mfa` is the authoritative field; `two_factor_enabled` is the older
        // spelling of the same thing and is not always present.
        if !b(u, "mfa") && !b(u, "two_factor_enabled") {
            out.push(Finding::new(
                "iam.users.no-mfa",
                Severity::Critical,
                &who,
                if owner {
                    "no second factor, on the organization owner — a password is the only thing \
                     between anyone and the whole account"
                } else {
                    "no second factor"
                },
            ));
        }

        if owner {
            let keys = iam
                .api_keys
                .iter()
                .filter(|k| s(k, "user_id") == s(u, "id"))
                .count();
            if keys > 0 {
                out.push(Finding::new(
                    "iam.users.owner-daily-driver",
                    Severity::High,
                    &who,
                    format!(
                        "the owner bears {keys} API key(s). An owner key is above the policy \
                         system: nothing can scope it, and nothing will refuse it"
                    ),
                ));
            }
        }

        if b(u, "locked") {
            out.push(Finding::new(
                "iam.users.locked",
                Severity::Medium,
                &who,
                "locked, but still present and still carrying whatever policies name it",
            ));
        }

        // An account that has never logged in is not dormant, it is unused, and
        // saying "no login for 0 days" would be nonsense.
        match age_secs(u, "last_login_at", now) {
            Some(age) if age > DORMANT => out.push(Finding::new(
                "iam.users.dormant",
                Severity::Medium,
                &who,
                format!(
                    "no login for {}",
                    crate::scw::relative(age).trim_end_matches(" ago")
                ),
            )),
            None if s(u, "status") == "activated" => out.push(Finding::new(
                "iam.users.dormant",
                Severity::Medium,
                &who,
                "activated but has never logged in",
            )),
            _ => {}
        }
    }
}

// ---- applications -----------------------------------------------------------

fn applications(iam: &Iam, out: &mut Vec<Finding>) {
    for a in &iam.applications {
        // A Scaleway-managed application is not the operator's to explain or
        // delete, so hygiene findings about it are noise.
        if b(a, "managed") {
            continue;
        }
        let who = name_or_id(a);

        if n(a, "nb_api_keys") == Some(0) {
            out.push(Finding::new(
                "iam.applications.keyless",
                Severity::Medium,
                &who,
                "no API key: whatever policies name it are attached to nothing, and the name no \
                 longer says what would break if it were deleted",
            ));
        }
        if s(a, "description").is_empty() {
            out.push(Finding::new(
                "iam.applications.undescribed",
                Severity::Low,
                &who,
                "no description, so nobody can say what breaks if it is deleted",
            ));
        }
    }
}

// ---- api keys ---------------------------------------------------------------

fn api_keys(iam: &Iam, now: i64, out: &mut Vec<Finding>) {
    let mut ips: BTreeSet<String> = BTreeSet::new();

    for k in &iam.api_keys {
        let who = bearer(iam, k);

        if s(k, "expires_at").is_empty() {
            out.push(Finding::new(
                "iam.api-keys.never-expires",
                Severity::Critical,
                &who,
                "no expiry date: the credential outlives the person, the project and the reason \
                 it was made",
            ));
        }
        if let Some(age) = age_secs(k, "created_at", now) {
            if age > STALE_KEY {
                out.push(Finding::new(
                    "iam.api-keys.stale",
                    Severity::High,
                    &who,
                    format!("created {}, never rotated since", crate::scw::relative(age)),
                ));
            }
        }
        if !s(k, "user_id").is_empty() {
            out.push(Finding::new(
                "iam.api-keys.user-bound",
                Severity::High,
                &who,
                "bound to a person rather than an application, so it inherits every permission \
                 that person is ever given",
            ));
        }
        // The preferred Object Storage project is fixed at creation and cannot
        // be overridden per call, so a key pointed at `default` can never see
        // another project's buckets however wide its IAM policy is.
        if !iam.organization_id.is_empty() && s(k, "default_project_id") == iam.organization_id {
            out.push(Finding::new(
                "iam.api-keys.default-project",
                Severity::Low,
                &who,
                "Object Storage calls with this key land in the `default` project, whatever its \
                 policy allows elsewhere",
            ));
        }
        let ip = s(k, "creation_ip");
        if !ip.is_empty() {
            ips.insert(ip);
        }
    }

    if !ips.is_empty() {
        out.push(Finding::new(
            "iam.api-keys.creation-ip",
            Severity::Info,
            format!("{} key(s)", iam.api_keys.len()),
            format!(
                "created from {} distinct address(es): {}",
                ips.len(),
                ips.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
        ));
    }
}

/// A key names a principal by id; the report should name it the way a person
/// would.
fn bearer(iam: &Iam, key: &Value) -> String {
    let access = s(key, "access_key");
    let (field, pool) = if !s(key, "application_id").is_empty() {
        ("application_id", &iam.applications)
    } else {
        ("user_id", &iam.users)
    };
    let id = s(key, field);
    let named = pool
        .iter()
        .find(|p| s(p, "id") == id)
        .map(name_or_id)
        .unwrap_or_else(|| id.clone());
    if named.is_empty() {
        access
    } else {
        format!("{named} · {access}")
    }
}

// ---- policies and rules -----------------------------------------------------

fn policies(iam: &Iam, out: &mut Vec<Finding>) {
    for p in &iam.policies {
        let who = name_or_id(p);
        let mut already_flagged = false;

        if b(p, "no_principal") {
            out.push(Finding::new(
                "iam.policies.no-principal",
                Severity::Critical,
                &who,
                "no principal: dormant permission that becomes live the moment somebody is \
                 attached to it",
            ));
        }

        for r in iam.rules.get(&s(p, "id")).into_iter().flatten() {
            let sets = strings(r, "permission_set_names");
            let org_wide = s(r, "permission_sets_scope_type") == "organization";

            if sets.iter().any(|x| x == "AllProductsFullAccess") {
                already_flagged = true;
                out.push(Finding::new(
                    "iam.policies.all-products-full-access",
                    Severity::Critical,
                    &who,
                    if org_wide {
                        "AllProductsFullAccess at organization scope — the account's root, \
                         granted by name"
                            .to_string()
                    } else {
                        "AllProductsFullAccess, scoped to projects — full control of every \
                         product in them"
                            .to_string()
                    },
                ));
            }
        }

        if !already_flagged {
            let org_rules = iam
                .rules
                .get(&s(p, "id"))
                .into_iter()
                .flatten()
                .filter(|r| s(r, "permission_sets_scope_type") == "organization")
                .count();
            if org_rules > 0 {
                out.push(Finding::new(
                    "iam.policies.org-scope",
                    Severity::High,
                    &who,
                    format!(
                        "{org_rules} rule(s) at organization scope, where a project list would \
                         have bounded the blast radius"
                    ),
                ));
            }
        }

        if let Some(reason) = unused_reason(iam, p) {
            out.push(Finding::new(
                "iam.policies.unused",
                Severity::Medium,
                &who,
                reason,
            ));
        }
    }
}

/// Why a policy grants nothing to anybody today, if it does not.
fn unused_reason(iam: &Iam, policy: &Value) -> Option<String> {
    if b(policy, "managed") || b(policy, "no_principal") {
        return None; // managed is not ours; no-principal already has its own finding
    }
    let app_id = s(policy, "application_id");
    if !app_id.is_empty() {
        let app = iam.applications.iter().find(|a| s(a, "id") == app_id)?;
        if n(app, "nb_api_keys") == Some(0) {
            return Some(format!(
                "its principal, the application {:?}, has no API key",
                name_or_id(app)
            ));
        }
        return None;
    }
    let group_id = s(policy, "group_id");
    if !group_id.is_empty() {
        let group = iam.groups.iter().find(|g| s(g, "id") == group_id)?;
        if is_empty_group(group) {
            return Some(format!(
                "its principal, the group {:?}, has no members",
                name_or_id(group)
            ));
        }
    }
    None
}

fn rules(iam: &Iam, out: &mut Vec<Finding>) {
    for p in &iam.policies {
        let who = name_or_id(p);
        let reads_only_by_name = names_a_read_role(&who);

        for r in iam.rules.get(&s(p, "id")).into_iter().flatten() {
            let sets = strings(r, "permission_set_names");

            if reads_only_by_name {
                let writers: Vec<&String> =
                    sets.iter().filter(|x| !x.ends_with("ReadOnly")).collect();
                if !writers.is_empty() {
                    out.push(Finding::new(
                        "iam.rules.write-in-a-read-role",
                        Severity::High,
                        &who,
                        format!(
                            "named for reading, but grants {}",
                            writers
                                .iter()
                                .map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }
        }

        // Counted per policy rather than emitted per rule: the finding is "this
        // policy is unconditional", and a policy with three such rules is one
        // finding about one policy, not the same name printed three times.
        let unconditional = iam
            .rules
            .get(&s(p, "id"))
            .into_iter()
            .flatten()
            .filter(|r| {
                s(r, "permission_sets_scope_type") == "organization" && s(r, "condition").is_empty()
            })
            .count();
        if unconditional > 0 {
            out.push(Finding::new(
                "iam.rules.condition-free",
                Severity::Medium,
                &who,
                format!(
                    "{unconditional} organization-wide rule(s) with no condition: they apply \
                     from any address, at any hour, to every project that will ever exist"
                ),
            ));
        }
    }
}

/// Whether a policy's name claims it only reads.
fn names_a_read_role(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    [
        "readonly",
        "read-only",
        "read_only",
        "audit",
        "viewer",
        "observer",
    ]
    .iter()
    .any(|needle| n.contains(needle))
        || n.ends_with("-ro")
        || n.ends_with("_ro")
        || n.split(['-', '_', ' ']).any(|w| w == "read" || w == "ro")
}

// ---- groups -----------------------------------------------------------------

fn is_empty_group(g: &Value) -> bool {
    len(g, "user_ids") == 0
        && len(g, "application_ids") == 0
        && !b(g, "all_users")
        && !b(g, "all_applications")
}

fn groups(iam: &Iam, out: &mut Vec<Finding>) {
    let carries_policy = |id: &str| iam.policies.iter().any(|p| s(p, "group_id") == id);

    for g in &iam.groups {
        let who = name_or_id(g);
        let id = s(g, "id");

        // A group can be defined as "everyone", in which case membership is not
        // a list somebody curates but a rule that captures whatever is created
        // next. A policy on such a group is a standing grant to the future.
        if b(g, "all_users") || b(g, "all_applications") {
            if carries_policy(&id) {
                let what = match (b(g, "all_users"), b(g, "all_applications")) {
                    (true, true) => "every user and every application",
                    (true, false) => "every user",
                    _ => "every application",
                };
                out.push(Finding::new(
                    "iam.groups.everyone",
                    Severity::High,
                    &who,
                    format!(
                        "automatically contains {what} in the organization, including the ones \
                         nobody has created yet, and carries policies"
                    ),
                ));
            }
            continue;
        }

        if is_empty_group(g) && carries_policy(&id) {
            out.push(Finding::new(
                "iam.groups.empty",
                Severity::Medium,
                &who,
                "no members, and it carries policies: permission waiting for somebody to be \
                 added to it",
            ));
        }
        if len(g, "user_ids") > 0 && len(g, "application_ids") > 0 {
            out.push(Finding::new(
                "iam.groups.mixed",
                Severity::Low,
                &who,
                format!(
                    "{} user(s) and {} application(s) together, so a grant meant for people \
                     silently becomes a grant for machines",
                    len(g, "user_ids"),
                    len(g, "application_ids")
                ),
            ));
        }
    }
}

// ---- ssh keys ---------------------------------------------------------------

fn ssh_keys(iam: &Iam, now: i64, out: &mut Vec<Finding>) {
    for k in &iam.ssh_keys {
        let who = name_or_id(k);
        let public = s(k, "public_key");

        if let Some(weakness) = weak_ssh_key(&public) {
            out.push(Finding::new(
                "iam.ssh-keys.weak",
                Severity::Medium,
                &who,
                format!("{weakness}, and it is injected into every machine at boot"),
            ));
        }
        if b(k, "disabled") {
            out.push(Finding::new(
                "iam.ssh-keys.disabled",
                Severity::Low,
                &who,
                "disabled but not deleted: it is on no machine, and it is also not a decision \
                 anybody has to revisit",
            ));
            continue; // a disabled key is on no machine, so its age is not the problem
        }
        if let Some(age) = age_secs(k, "created_at", now) {
            if age > STALE_SSH_KEY {
                out.push(Finding::new(
                    "iam.ssh-keys.stale",
                    Severity::High,
                    &who,
                    format!(
                        "added {}, still installed on every machine created since",
                        crate::scw::relative(age)
                    ),
                ));
            }
        }
    }
}

/// Why an SSH public key is below current guidance, if it is.
///
/// Only the algorithm and, for RSA, the modulus size can be judged from the
/// key itself — which is the whole of what this API returns.
pub fn weak_ssh_key(public_key: &str) -> Option<String> {
    let mut parts = public_key.split_whitespace();
    let algo = parts.next()?;
    match algo {
        "ssh-dss" => Some("DSA, which is 1024-bit by definition and long deprecated".to_string()),
        "ssh-rsa" => {
            let bits = rsa_bits(parts.next()?)?;
            (bits < MIN_RSA_BITS)
                .then(|| format!("RSA {bits}-bit, below the {MIN_RSA_BITS} minimum"))
        }
        _ => None, // ed25519 and the ECDSA curves are fixed-strength and fine
    }
}

/// Modulus size of an `ssh-rsa` blob, in bits.
///
/// The blob is a sequence of length-prefixed byte strings: the algorithm name,
/// the exponent, then the modulus. The modulus carries a leading zero byte when
/// its top bit is set, which is not part of the number.
fn rsa_bits(blob_b64: &str) -> Option<u32> {
    let blob = base64_decode(blob_b64)?;
    let mut at = 0usize;
    let mut take = || -> Option<&[u8]> {
        let len = u32::from_be_bytes(blob.get(at..at + 4)?.try_into().ok()?) as usize;
        at += 4;
        let out = blob.get(at..at + len)?;
        at += len;
        Some(out)
    };
    take()?; // algorithm name
    take()?; // public exponent
    let modulus = take()?;
    let significant = modulus.iter().position(|&x| x != 0)?;
    let bytes = &modulus[significant..];
    let top = *bytes.first()?;
    Some((bytes.len() as u32 - 1) * 8 + (8 - top.leading_zeros()))
}

/// Standard base64 with padding, enough for an SSH key blob.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\n' | b'\r' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// ---- organization security settings -----------------------------------------

fn settings(iam: &Iam, out: &mut Vec<Finding>) {
    let Some(set) = &iam.settings else { return };
    let who = "organization security settings";

    if duration_secs(set, "max_api_key_expiration_duration").is_none() {
        out.push(Finding::new(
            "iam.security-settings.no-key-expiry",
            Severity::High,
            who,
            "no maximum API key lifetime, so a key that never expires can be created by anyone \
             who can create keys at all",
        ));
    }
    if let Some(secs) = duration_secs(set, "max_login_session_duration") {
        if secs > LONG_SESSION {
            out.push(Finding::new(
                "iam.security-settings.long-sessions",
                Severity::Medium,
                who,
                format!(
                    "a console session lasts up to {}, so revoking access does not end one",
                    crate::scw::relative(-secs).trim_start_matches("in ")
                ),
            ));
        }
    }
    match n(set, "login_attempts_before_locked") {
        None => out.push(Finding::new(
            "iam.security-settings.no-lockout",
            Severity::Medium,
            who,
            "no lockout after repeated failed logins",
        )),
        Some(attempts) if attempts > LOCKOUT_CEILING => out.push(Finding::new(
            "iam.security-settings.no-lockout",
            Severity::Medium,
            who,
            format!("{attempts} failed logins allowed before lockout"),
        )),
        _ => {}
    }
}

#[cfg(test)]
mod tests;
