//! Fixtures are the shapes the real API returns, with every identifier
//! invented. Each test states one property the checks must hold.

use super::*;
use serde_json::json;
use std::collections::BTreeSet;

/// A fixed "now" so an age never depends on when the suite runs.
const NOW: i64 = 1_800_000_000; // 2027-01-15T08:00:00Z

fn ids(f: &[Finding]) -> Vec<&str> {
    f.iter().map(|x| x.id).collect()
}

fn has(f: &[Finding], id: &str) -> bool {
    f.iter().any(|x| x.id == id)
}

fn only<'a>(f: &'a [Finding], id: &str) -> Vec<&'a Finding> {
    f.iter().filter(|x| x.id == id).collect()
}

fn iso(secs_ago: i64) -> String {
    let e = NOW - secs_ago;
    let d = e / 86_400;
    // Good enough for a fixture: the parser only needs a well-formed date, and
    // `epoch_of` is tested on its own.
    let mut y = 1970;
    let mut days = d;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let in_year = if leap { 366 } else { 365 };
        if days < in_year {
            break;
        }
        days -= in_year;
        y += 1;
    }
    format!("{y:04}-01-01T00:00:00Z").replace(
        "-01-01",
        &format!("-{:02}-{:02}", 1 + days / 31, 1 + days % 31),
    )
}

// ---- users ------------------------------------------------------------------

#[test]
fn a_member_without_a_second_factor_is_critical_and_the_owner_is_told_why() {
    let iam = Iam {
        users: vec![
            json!({"id": "u1", "email": "a@example.com", "type": "member", "mfa": false,
                   "status": "activated", "last_login_at": iso(DAY)}),
            json!({"id": "u2", "email": "b@example.com", "type": "owner", "mfa": false,
                   "status": "activated", "last_login_at": iso(DAY)}),
        ],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    let found = only(&f, "iam.users.no-mfa");
    assert_eq!(found.len(), 2);
    let owner = found.iter().find(|x| x.subject == "b@example.com").unwrap();
    assert!(
        owner.detail.contains("owner"),
        "the owner's version says what it costs: {}",
        owner.detail
    );
}

#[test]
fn the_older_spelling_of_mfa_still_counts_as_having_it() {
    // `two_factor_enabled` is the field's previous name and is not always
    // present alongside `mfa`. Ignoring it would report every account as
    // unprotected on an organization that predates the rename.
    let iam = Iam {
        users: vec![
            json!({"id": "u1", "email": "a@example.com", "type": "member",
                           "two_factor_enabled": true, "status": "activated",
                           "last_login_at": iso(DAY)}),
        ],
        ..Default::default()
    };
    assert!(!has(&audit(&iam, NOW), "iam.users.no-mfa"));
}

#[test]
fn an_owner_bearing_api_keys_is_a_finding_and_a_bare_owner_is_not() {
    let owner = json!({"id": "u1", "email": "a@example.com", "type": "owner", "mfa": true,
                       "status": "activated", "last_login_at": iso(DAY)});
    let bare = Iam {
        users: vec![owner.clone()],
        ..Default::default()
    };
    assert!(!has(&audit(&bare, NOW), "iam.users.owner-daily-driver"));

    let keyed = Iam {
        users: vec![owner],
        api_keys: vec![
            json!({"access_key": "SCWEXAMPLEACCESSKEY0", "user_id": "u1",
                              "expires_at": iso(-DAY), "created_at": iso(DAY)}),
        ],
        ..Default::default()
    };
    assert!(has(&audit(&keyed, NOW), "iam.users.owner-daily-driver"));
}

#[test]
fn never_having_logged_in_is_reported_differently_from_having_stopped() {
    let iam = Iam {
        users: vec![
            json!({"id": "u1", "email": "old@example.com", "type": "member", "mfa": true,
                   "status": "activated", "last_login_at": iso(200 * DAY)}),
            json!({"id": "u2", "email": "new@example.com", "type": "member", "mfa": true,
                   "status": "activated"}),
        ],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    let found = only(&f, "iam.users.dormant");
    assert_eq!(found.len(), 2);
    assert!(found
        .iter()
        .any(|x| x.subject == "new@example.com" && x.detail.contains("never logged in")));
}

#[test]
fn a_recent_login_is_not_dormancy() {
    let iam = Iam {
        users: vec![
            json!({"id": "u1", "email": "a@example.com", "type": "member", "mfa": true,
                           "status": "activated", "last_login_at": iso(3 * DAY)}),
        ],
        ..Default::default()
    };
    assert!(!has(&audit(&iam, NOW), "iam.users.dormant"));
}

// ---- api keys ---------------------------------------------------------------

#[test]
fn a_key_with_no_expiry_is_critical_and_names_the_thing_that_bears_it() {
    let iam = Iam {
        applications: vec![json!({"id": "a1", "name": "ci-deploy", "nb_api_keys": 1,
                                  "description": "x"})],
        api_keys: vec![
            json!({"access_key": "SCWEXAMPLEACCESSKEY0", "application_id": "a1",
                              "created_at": iso(DAY)}),
        ],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    let found = only(&f, "iam.api-keys.never-expires");
    assert_eq!(found.len(), 1);
    assert!(
        found[0].subject.contains("ci-deploy") && found[0].subject.contains("SCWEXAMPLE"),
        "a bearer id nobody can read is not a subject: {}",
        found[0].subject
    );
}

#[test]
fn an_object_storage_project_pointing_at_default_is_worth_saying_once() {
    // The preferred project is fixed at creation and cannot be overridden per
    // call, so this key can never see another project's buckets.
    let org = "aaaaaaaa-1111-2222-3333-444444444444";
    let iam = Iam {
        organization_id: org.into(),
        api_keys: vec![
            json!({"access_key": "SCWEXAMPLEACCESSKEY0", "application_id": "a1",
                              "created_at": iso(DAY), "expires_at": iso(-DAY),
                              "default_project_id": org}),
        ],
        ..Default::default()
    };
    assert!(has(&audit(&iam, NOW), "iam.api-keys.default-project"));
}

#[test]
fn creation_addresses_are_summarised_once_rather_than_per_key() {
    let iam = Iam {
        api_keys: vec![
            json!({"access_key": "SCWEXAMPLEACCESSKEY0", "application_id": "a1",
                   "created_at": iso(DAY), "expires_at": iso(-DAY), "creation_ip": "203.0.113.7"}),
            json!({"access_key": "SCWEXAMPLEACCESSKEY1", "application_id": "a1",
                   "created_at": iso(DAY), "expires_at": iso(-DAY), "creation_ip": "203.0.113.7"}),
            json!({"access_key": "SCWEXAMPLEACCESSKEY2", "application_id": "a1",
                   "created_at": iso(DAY), "expires_at": iso(-DAY), "creation_ip": "198.51.100.9"}),
        ],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    let found = only(&f, "iam.api-keys.creation-ip");
    assert_eq!(found.len(), 1, "one line, not one per key");
    assert!(found[0].detail.contains("2 distinct"));
}

// ---- policies and rules -----------------------------------------------------

fn policy_with_rule(name: &str, scope: &str, sets: Vec<&str>) -> Iam {
    let mut rules = BTreeMap::new();
    rules.insert(
        "p1".to_string(),
        vec![
            json!({"permission_sets_scope_type": scope, "permission_set_names": sets,
                    "condition": ""}),
        ],
    );
    Iam {
        policies: vec![json!({"id": "p1", "name": name, "nb_rules": 1})],
        rules,
        ..Default::default()
    }
}

#[test]
fn full_access_is_critical_and_says_which_scope_it_was_granted_at() {
    let org = policy_with_rule("everything", "organization", vec!["AllProductsFullAccess"]);
    let f = audit(&org, NOW);
    let found = only(&f, "iam.policies.all-products-full-access");
    assert_eq!(found.len(), 1);
    assert!(found[0].detail.contains("organization scope"));

    let proj = policy_with_rule("everything", "projects", vec!["AllProductsFullAccess"]);
    let f = audit(&proj, NOW);
    assert!(only(&f, "iam.policies.all-products-full-access")[0]
        .detail
        .contains("scoped to projects"));
}

#[test]
fn a_policy_flagged_for_full_access_is_not_also_flagged_for_being_org_wide() {
    // Both are true, and saying it twice about one policy is noise that pushes
    // a different policy's finding off the top of the report.
    let iam = policy_with_rule("everything", "organization", vec!["AllProductsFullAccess"]);
    let f = audit(&iam, NOW);
    assert!(has(&f, "iam.policies.all-products-full-access"));
    assert!(!has(&f, "iam.policies.org-scope"));
}

#[test]
fn an_organization_wide_read_role_is_still_organization_wide() {
    let iam = policy_with_rule(
        "support-readonly",
        "organization",
        vec!["AllProductsReadOnly"],
    );
    let f = audit(&iam, NOW);
    assert!(has(&f, "iam.policies.org-scope"));
    assert!(has(&f, "iam.rules.condition-free"));
}

#[test]
fn a_policy_named_for_reading_that_writes_is_caught() {
    for name in [
        "audit-ro",
        "billing_readonly",
        "read only viewer",
        "platform-audit",
    ] {
        let iam = policy_with_rule(name, "projects", vec!["InstancesFullAccess"]);
        assert!(
            has(&audit(&iam, NOW), "iam.rules.write-in-a-read-role"),
            "{name:?} claims to read"
        );
    }
}

#[test]
fn a_policy_that_does_not_claim_to_read_is_not_held_to_it() {
    for name in ["platform-deploy", "ci", "romain-access", "microscope"] {
        let iam = policy_with_rule(name, "projects", vec!["InstancesFullAccess"]);
        assert!(
            !has(&audit(&iam, NOW), "iam.rules.write-in-a-read-role"),
            "{name:?} never claimed to be read-only"
        );
    }
}

#[test]
fn a_read_role_that_only_reads_passes() {
    let iam = policy_with_rule("audit-ro", "projects", vec!["IAMReadOnly", "VPCReadOnly"]);
    assert!(!has(&audit(&iam, NOW), "iam.rules.write-in-a-read-role"));
}

#[test]
fn a_policy_with_no_principal_is_critical() {
    let iam = Iam {
        policies: vec![json!({"id": "p1", "name": "orphan", "no_principal": true})],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    assert!(has(&f, "iam.policies.no-principal"));
    assert!(
        !has(&f, "iam.policies.unused"),
        "one policy, one reason; the no-principal finding already says it"
    );
}

#[test]
fn a_policy_on_a_keyless_application_is_reported_as_unused() {
    let iam = Iam {
        applications: vec![json!({"id": "a1", "name": "retired", "nb_api_keys": 0,
                                  "description": "x"})],
        policies: vec![json!({"id": "p1", "name": "retired-access", "application_id": "a1"})],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    let found = only(&f, "iam.policies.unused");
    assert_eq!(found.len(), 1);
    assert!(found[0].detail.contains("retired"));
}

#[test]
fn a_scaleway_managed_policy_is_not_the_operators_to_tidy() {
    let iam = Iam {
        applications: vec![json!({"id": "a1", "name": "managed-app", "nb_api_keys": 0,
                                  "managed": true})],
        policies: vec![
            json!({"id": "p1", "name": "managed", "application_id": "a1",
                              "managed": true}),
        ],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    assert!(!has(&f, "iam.policies.unused"));
    assert!(!has(&f, "iam.applications.keyless"));
    assert!(!has(&f, "iam.applications.undescribed"));
}

// ---- groups -----------------------------------------------------------------

#[test]
fn a_group_that_means_everyone_outranks_a_group_that_is_merely_empty() {
    // Both look like "zero members" in the listing. One is an oversight; the
    // other is a standing grant to every principal that will ever be created.
    let iam = Iam {
        groups: vec![
            json!({"id": "g1", "name": "all-people", "all_users": true,
                   "user_ids": [], "application_ids": []}),
            json!({"id": "g2", "name": "forgotten", "all_users": false,
                   "user_ids": [], "application_ids": []}),
        ],
        policies: vec![
            json!({"id": "p1", "name": "a", "group_id": "g1"}),
            json!({"id": "p2", "name": "b", "group_id": "g2"}),
        ],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    let everyone = only(&f, "iam.groups.everyone");
    assert_eq!(everyone.len(), 1);
    assert_eq!(everyone[0].subject, "all-people");
    assert!(everyone[0].detail.contains("every user"));

    let empty = only(&f, "iam.groups.empty");
    assert_eq!(empty.len(), 1);
    assert_eq!(empty[0].subject, "forgotten");
    assert!(
        everyone[0].severity < empty[0].severity,
        "everyone is worse"
    );
}

#[test]
fn an_empty_group_carrying_nothing_is_not_a_finding() {
    let iam = Iam {
        groups: vec![json!({"id": "g1", "name": "spare", "user_ids": [], "application_ids": []})],
        ..Default::default()
    };
    assert!(!has(&audit(&iam, NOW), "iam.groups.empty"));
}

#[test]
fn people_and_machines_in_one_group_is_worth_a_note() {
    let iam = Iam {
        groups: vec![
            json!({"id": "g1", "name": "platform", "user_ids": ["u1", "u2"],
                            "application_ids": ["a1"]}),
        ],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    let found = only(&f, "iam.groups.mixed");
    assert_eq!(found.len(), 1);
    assert!(found[0].detail.contains("2 user(s) and 1 application(s)"));
}

// ---- ssh keys ---------------------------------------------------------------

#[test]
fn rsa_key_strength_is_read_out_of_the_key_itself() {
    // Real keys, generated for this test with `ssh-keygen` and used nowhere.
    // A key's strength is not in its text: the modulus has to be decoded out
    // of the SSH wire format, which is the only reason this check can exist.
    const RSA_1024: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDCoWqOVJvpdaFWMgG0/6SLVdTcGiUmjCP9bp3jQemMMwHU/L1cLZk24hJvYLaT4HEg4IgycMb+bfFU815pMjnw3gqCim09IE646SZo8o+vso3g6DI63IdDFXSjwPkFxNCWbXoB20jG8xj/bLHZbV6NLqH+Khh0ACCBpPGTHQnuQQ== fixture@example";
    const RSA_4096: &str = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDyfBnJhG9leJh0or1zDXp+KVAOmr4+tTMM/2az1pZVVagf9zHe/n1HWEqQBZbYGXYvMBBidhBu8bZRuzYxRfIr2Z6FsB6O9b5h/CByU4X/N7Pf1eab98R8f4JOVK/RNuJhgUa2l39WiqqelJD8oQXCZYK9uS1AVr6nKrgWtEl8wHxHdM+hF6Qhvj2q5zW2FmyAHGameO/y+PhWa4c137FjSg56FolRGZpD7VwS2PyJ7X34v9f2M4ysvE8YRtsshACtJJi3/teyhVnm8yBA3UdkbpfySrY/BGqvYYZ04LJmX5xBr6/b8AMMMg2GNVusnZVUqGTg6lpQSzvZQqsmoueXDsmIxtwFu1TSnOm/rfidu8wFNVRSaeEdnXcaWjzth6jRjNbLxzT+jPFocsxZbDvrTjqKf5Xtm9bB5ywOyC2vuD/D3O5mRbccDthfg7gnzoKjcqWzlI8SQicHn4nyabei9Bni7eL73sSzDmaqquAOVjuhifN+0N39MF6nul53oZiJCS7nFQOvTqOQV0t4eZUswqs4mwiwW1i0fP3sngR0hsbZkNEfY/Y0awOAVnT5WX+HneWN9lyfhIk3tNwrpLsvCazm9ZnD+MvDVQshoZPLecxW7v6QuQW4wtBLRGCLdsHNO8Iyh+gnDN2RIgoiI67lImyqeDaopp7VGppT8JL4MQ== fixture@example";

    let weak = weak_ssh_key(RSA_1024).expect("1024-bit RSA is below guidance");
    assert!(weak.contains("RSA 1024-bit"), "{weak}");
    assert!(weak.contains("3072"), "it says what the bar is: {weak}");

    assert_eq!(weak_ssh_key(RSA_4096), None, "4096-bit RSA is fine");
}

#[test]
fn modern_algorithms_are_left_alone_and_dsa_never_is() {
    assert_eq!(
        weak_ssh_key("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample alice@host"),
        None
    );
    assert_eq!(
        weak_ssh_key("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= a@b"),
        None
    );
    assert!(
        weak_ssh_key("ssh-dss AAAAB3NzaC1kc3MAAACBAExample a@b").is_some_and(|r| r.contains("DSA"))
    );
}

#[test]
fn a_key_that_cannot_be_parsed_is_not_called_weak() {
    // Reporting "weak" on something unreadable would be a guess presented as a
    // finding, which is worse than saying nothing.
    assert_eq!(weak_ssh_key(""), None);
    assert_eq!(weak_ssh_key("ssh-rsa"), None);
    assert_eq!(weak_ssh_key("ssh-rsa !!!not-base64!!! a@b"), None);
    assert_eq!(weak_ssh_key("ssh-rsa AAAA a@b"), None);
}

#[test]
fn an_old_key_is_a_finding_until_it_is_disabled() {
    let live = Iam {
        ssh_keys: vec![
            json!({"id": "k1", "name": "laptop-2019", "created_at": iso(1000 * DAY),
                              "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample a@b",
                              "disabled": false}),
        ],
        ..Default::default()
    };
    assert!(has(&audit(&live, NOW), "iam.ssh-keys.stale"));

    let disabled = Iam {
        ssh_keys: vec![
            json!({"id": "k1", "name": "laptop-2019", "created_at": iso(1000 * DAY),
                              "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample a@b",
                              "disabled": true}),
        ],
        ..Default::default()
    };
    assert!(
        !has(&audit(&disabled, NOW), "iam.ssh-keys.stale"),
        "a disabled key is on no machine, so its age is not the problem"
    );
}

// ---- organization security settings -----------------------------------------

#[test]
fn the_settings_that_would_have_prevented_the_other_findings() {
    let iam = Iam {
        settings: Some(json!({
            "enforce_password_renewal": false,
            "grace_period_duration": "259200s",
            "login_attempts_before_locked": 5,
            "max_api_key_expiration_duration": "0s",
            "max_login_session_duration": "2592000s"
        })),
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    assert!(
        has(&f, "iam.security-settings.no-key-expiry"),
        "0s is no limit"
    );
    assert!(has(&f, "iam.security-settings.long-sessions"), "30 days");
    assert!(
        !has(&f, "iam.security-settings.no-lockout"),
        "5 attempts is a lockout policy"
    );
}

#[test]
fn settings_that_are_in_order_produce_nothing() {
    let iam = Iam {
        settings: Some(json!({
            "login_attempts_before_locked": 5,
            "max_api_key_expiration_duration": "7776000s",
            "max_login_session_duration": "28800s"
        })),
        ..Default::default()
    };
    assert!(audit(&iam, NOW).is_empty());
}

#[test]
fn settings_that_could_not_be_read_produce_nothing_rather_than_everything() {
    // A key without IAMReadOnly cannot fetch these. Treating "absent" as "unset"
    // would invent three findings out of a permission error.
    let iam = Iam {
        settings: None,
        ..Default::default()
    };
    assert!(audit(&iam, NOW).is_empty());
}

// ---- the whole thing --------------------------------------------------------

#[test]
fn an_empty_account_produces_no_findings() {
    assert!(audit(&Iam::default(), NOW).is_empty());
}

#[test]
fn findings_come_back_worst_first() {
    let iam = Iam {
        users: vec![
            json!({"id": "u1", "email": "a@example.com", "type": "member", "mfa": false,
                           "status": "activated", "last_login_at": iso(DAY)}),
        ],
        applications: vec![json!({"id": "a1", "name": "app", "nb_api_keys": 1})],
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    assert_eq!(
        ids(&f),
        vec!["iam.users.no-mfa", "iam.applications.undescribed"],
        "critical before low"
    );
}

#[test]
fn a_policy_with_several_unconditional_rules_is_named_once() {
    // Seen on a real organization: one policy, three organization-scoped rules,
    // and the policy's name printed three times under the same check.
    let mut rules = BTreeMap::new();
    rules.insert(
        "p1".to_string(),
        vec![
            json!({"permission_sets_scope_type": "organization",
                   "permission_set_names": ["IAMReadOnly"], "condition": ""}),
            json!({"permission_sets_scope_type": "organization",
                   "permission_set_names": ["VPCReadOnly"], "condition": ""}),
            json!({"permission_sets_scope_type": "organization",
                   "permission_set_names": ["BillingReadOnly"], "condition": "1 == 1"}),
        ],
    );
    let iam = Iam {
        policies: vec![json!({"id": "p1", "name": "admins", "nb_rules": 3})],
        rules,
        ..Default::default()
    };
    let f = audit(&iam, NOW);
    let found = only(&f, "iam.rules.condition-free");
    assert_eq!(found.len(), 1, "one policy, one finding");
    assert!(
        found[0].detail.starts_with("2 organization-wide"),
        "and it counts the rules rather than hiding them: {}",
        found[0].detail
    );
}

/// One account carrying every implemented weakness at once, so the set of ids
/// the module emits can be compared against what it claims to emit.
fn everything() -> Iam {
    let org = "aaaaaaaa-1111-2222-3333-444444444444";
    let mut rules = BTreeMap::new();
    rules.insert(
        "p-full".into(),
        vec![json!({"permission_sets_scope_type": "organization",
                    "permission_set_names": ["AllProductsFullAccess"], "condition": ""})],
    );
    rules.insert(
        "p-read".into(),
        vec![json!({"permission_sets_scope_type": "organization",
                    "permission_set_names": ["InstancesFullAccess"], "condition": ""})],
    );
    Iam {
        organization_id: org.into(),
        users: vec![
            json!({"id": "u1", "email": "owner@example.com", "type": "owner",
                           "mfa": false, "status": "activated", "locked": true}),
        ],
        applications: vec![json!({"id": "a1", "name": "retired", "nb_api_keys": 0})],
        api_keys: vec![
            json!({"access_key": "SCWEXAMPLEACCESSKEY0", "user_id": "u1",
                              "created_at": iso(400 * DAY), "default_project_id": org,
                              "creation_ip": "203.0.113.7"}),
        ],
        policies: vec![
            json!({"id": "p-full", "name": "everything"}),
            json!({"id": "p-read", "name": "audit-ro"}),
            json!({"id": "p-orphan", "name": "orphan", "no_principal": true}),
            json!({"id": "p-app", "name": "retired-access", "application_id": "a1"}),
            json!({"id": "p-group", "name": "empty-group-access", "group_id": "g-empty"}),
            json!({"id": "p-all", "name": "everyone-access", "group_id": "g-all"}),
        ],
        rules,
        groups: vec![
            json!({"id": "g-empty", "name": "empty", "user_ids": [], "application_ids": []}),
            json!({"id": "g-all", "name": "everyone", "all_users": true,
                   "user_ids": [], "application_ids": []}),
            json!({"id": "g-mixed", "name": "mixed", "user_ids": ["u1"],
                   "application_ids": ["a1"]}),
        ],
        ssh_keys: vec![
            json!({"id": "k1", "name": "dsa", "created_at": iso(DAY), "disabled": false,
                   "public_key": "ssh-dss AAAAB3NzaC1kc3MAAACBAExample a@b"}),
            json!({"id": "k2", "name": "ancient", "created_at": iso(1000 * DAY),
                   "disabled": false,
                   "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample a@b"}),
            json!({"id": "k3", "name": "retired", "created_at": iso(DAY), "disabled": true,
                   "public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample a@b"}),
        ],
        settings: Some(json!({"max_api_key_expiration_duration": "0s",
                              "max_login_session_duration": "2592000s"})),
        gaps: Vec::new(),
    }
}

#[test]
fn the_module_emits_exactly_what_it_claims_to_emit() {
    // The report prints "these catalogued checks are not derived yet" from the
    // difference between the catalogue and IMPLEMENTED. If IMPLEMENTED drifts
    // from the code, the report contradicts itself — which it did: three
    // security-settings checks fired and were listed as underived in the same
    // output.
    let emitted: BTreeSet<&str> = audit(&everything(), NOW).iter().map(|f| f.id).collect();
    let claimed: BTreeSet<&str> = IMPLEMENTED.into_iter().collect();

    let unclaimed: Vec<&&str> = emitted.difference(&claimed).collect();
    assert!(
        unclaimed.is_empty(),
        "emitted but not in IMPLEMENTED: {unclaimed:?}"
    );

    let unreachable: Vec<&&str> = claimed.difference(&emitted).collect();
    assert!(
        unreachable.is_empty(),
        "claimed in IMPLEMENTED but not emitted by an account carrying every weakness: \
         {unreachable:?}"
    );
}

#[test]
fn every_id_this_module_emits_exists_in_the_catalogue() {
    // The catalogue is the specification. An id emitted here that is not in it
    // is a finding nobody can look up, and one in the catalogue that is never
    // emitted is a promise the tool does not keep — the report states the
    // second case out loud rather than hiding it.
    let catalogued: Vec<&str> = crate::scw::catalog::product("iam")
        .expect("iam is in the catalogue")
        .resources
        .iter()
        .flat_map(|r| r.checks.iter().map(|c| c.id))
        .collect();

    for id in IMPLEMENTED {
        assert!(
            catalogued.contains(&id),
            "{id} is emitted but not catalogued"
        );
    }
}
