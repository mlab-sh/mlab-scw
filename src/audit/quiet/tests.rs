//! Fixtures are the shapes the real API returns, with every identifier
//! invented.

use super::*;
use crate::scw::sweep::{Fetch, Fetched};
use serde_json::json;

const NOW: i64 = 1_800_000_000; // 2027-01-15
const ORG: &str = "aaaaaaaa-1111-2222-3333-444444444444";

fn got(
    product: &'static str,
    resource: &'static str,
    locality: &str,
    items: Vec<Value>,
) -> Fetched {
    Fetched {
        fetch: Fetch::new(
            product,
            resource,
            locality,
            format!("/{product}/{resource}"),
        ),
        items,
        gap: None,
    }
}

fn zone_records(zone: &str, items: Vec<Value>) -> Fetched {
    Fetched {
        fetch: Fetch::new(
            "domain",
            "records",
            "",
            format!("/domain/v2beta1/dns-zones/{zone}/records"),
        ),
        items,
        gap: None,
    }
}

fn has(f: &[Finding], id: &str) -> bool {
    f.iter().any(|x| x.id == id)
}

fn only<'a>(f: &'a [Finding], id: &str) -> Vec<&'a Finding> {
    f.iter().filter(|x| x.id == id).collect()
}

/// A zone with everything an SPF/DMARC/CAA check wants, so the tests that care
/// about one record are not tripped by the absence of the others.
fn healthy_zone() -> Vec<Value> {
    vec![
        json!({"type": "CAA", "name": "", "data": "0 issue \"letsencrypt.org\"", "ttl": 3600}),
        json!({"type": "TXT", "name": "_dmarc", "data": "v=DMARC1; p=reject", "ttl": 3600}),
        json!({"type": "TXT", "name": "", "data": "v=spf1 include:_spf.example.com -all",
               "ttl": 3600}),
    ]
}

// ---- plaintext credentials --------------------------------------------------

#[test]
fn a_credential_in_a_plain_environment_variable_is_critical_and_names_no_value() {
    let sweep = vec![got(
        "containers",
        "containers",
        "fr-par",
        vec![json!({"id": "c1", "name": "api", "environment_variables": {
            "LOG_LEVEL": "debug",
            "DATABASE_URL": "postgres://app:hunter2@db.internal/app"
        }})],
    )];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    let found = only(&f, "containers.containers.plaintext-secret");
    assert_eq!(found.len(), 1);
    assert!(found[0].detail.contains("DATABASE_URL"));
    assert!(
        !found[0].detail.contains("hunter2"),
        "a leak detector that prints the leak is worse than none: {}",
        found[0].detail
    );
}

#[test]
fn an_environment_of_ordinary_configuration_produces_nothing() {
    let sweep = vec![got(
        "functions",
        "functions",
        "fr-par",
        vec![
            json!({"id": "f1", "name": "hook", "environment_variables": {
                "LOG_LEVEL": "info", "PORT": "8080", "SECRET_NAME": "prod-db-password"
            }}),
        ],
    )];
    assert!(Quiet::new(&sweep, ORG)
        .audit(NOW)
        .iter()
        .all(|f| f.id != "functions.functions.plaintext-secret"));
}

#[test]
fn a_namespace_environment_is_inherited_so_it_is_checked_too() {
    let sweep = vec![got(
        "containers",
        "namespaces",
        "fr-par",
        vec![
            json!({"id": "n1", "name": "prod", "environment_variables": {
                "GITHUB_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
            }}),
        ],
    )];
    assert!(has(
        &Quiet::new(&sweep, ORG).audit(NOW),
        "containers.namespaces.plaintext-secret"
    ));
}

// ---- dangling names ---------------------------------------------------------

#[test]
fn a_record_pointing_at_scaleway_infrastructure_the_account_does_not_hold_is_a_takeover() {
    let mut records = healthy_zone();
    records.push(json!({"type": "CNAME", "name": "old-api",
                        "data": "gone.functions.fnc.fr-par.scw.cloud.", "ttl": 300}));
    records.push(json!({"type": "CNAME", "name": "api",
                        "data": "live.functions.fnc.fr-par.scw.cloud.", "ttl": 300}));

    let sweep = vec![
        got(
            "domain",
            "dns-zones",
            "",
            vec![json!({"domain": "example.com", "subdomain": ""})],
        ),
        zone_records("example.com", records),
        got(
            "containers",
            "containers",
            "fr-par",
            vec![json!({"id": "c1", "name": "api",
                        "domain_name": "live.functions.fnc.fr-par.scw.cloud"})],
        ),
    ];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    let found = only(&f, "domain.records.dangling-cname");
    assert_eq!(found.len(), 1, "only the one that is not held");
    assert!(found[0].subject.starts_with("old-api.example.com"));
}

#[test]
fn a_record_pointing_somewhere_that_is_not_scaleway_is_not_guessed_at() {
    // An arbitrary host cannot be attributed to a provider from this API, and
    // guessing would turn every third-party CNAME into a false takeover.
    let mut records = healthy_zone();
    records.push(json!({"type": "CNAME", "name": "docs",
                        "data": "hosting.example.net.", "ttl": 300}));
    records.push(json!({"type": "A", "name": "mail", "data": "198.51.100.9", "ttl": 300}));

    let sweep = vec![
        got(
            "domain",
            "dns-zones",
            "",
            vec![json!({"domain": "example.com", "subdomain": ""})],
        ),
        zone_records("example.com", records),
    ];
    assert!(!has(
        &Quiet::new(&sweep, ORG).audit(NOW),
        "domain.records.dangling-cname"
    ));
}

#[test]
fn mail_and_certificate_records_are_judged_on_what_they_say() {
    let sweep = vec![
        got(
            "domain",
            "dns-zones",
            "",
            vec![json!({"domain": "example.com", "subdomain": ""})],
        ),
        zone_records(
            "example.com",
            vec![
                json!({"type": "TXT", "name": "", "data": "v=spf1 include:_spf.example.com ?all",
                       "ttl": 3600}),
                json!({"type": "TXT", "name": "_dmarc", "data": "v=DMARC1; p=none", "ttl": 3600}),
            ],
        ),
    ];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    assert!(has(&f, "domain.records.spf-weak"), "?all permits everyone");
    assert!(
        has(&f, "domain.records.dmarc-none"),
        "p=none rejects nothing"
    );
    assert!(has(&f, "domain.records.no-caa"), "no CAA at all");
}

#[test]
fn a_zone_that_is_configured_properly_produces_no_mail_findings() {
    let sweep = vec![
        got(
            "domain",
            "dns-zones",
            "",
            vec![json!({"domain": "example.com", "subdomain": ""})],
        ),
        zone_records("example.com", healthy_zone()),
    ];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    for id in [
        "domain.records.spf-weak",
        "domain.records.dmarc-none",
        "domain.records.no-caa",
    ] {
        assert!(!has(&f, id), "{id} should not fire on a healthy zone");
    }
}

#[test]
fn a_wildcard_and_a_long_ttl_are_noted_but_not_alarming() {
    let mut records = healthy_zone();
    records.push(json!({"type": "A", "name": "*", "data": "198.51.100.9", "ttl": 604800}));
    let sweep = vec![
        got(
            "domain",
            "dns-zones",
            "",
            vec![json!({"domain": "example.com", "subdomain": ""})],
        ),
        zone_records("example.com", records),
    ];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    assert_eq!(only(&f, "domain.records.wildcard").len(), 1);
    let ttl = only(&f, "domain.records.long-ttl");
    assert_eq!(ttl.len(), 1);
    assert!(ttl[0].detail.contains("7d"), "{}", ttl[0].detail);
}

// ---- the read-only-is-not-read-only demonstration ---------------------------

#[test]
fn the_certificate_listing_is_reported_because_of_what_it_returns() {
    let sweep = vec![got(
        "domain",
        "ssl-certificates",
        "",
        vec![json!({"dns_zone": "example.com", "status": "success"})],
    )];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    let found = only(&f, "domain.ssl-certificates.private-key-readable");
    assert_eq!(
        found.len(),
        1,
        "one finding about the endpoint, not one per certificate"
    );
    assert!(found[0].detail.contains("DomainsDNSReadOnly"));
}

// ---- device fleets ----------------------------------------------------------

#[test]
fn a_device_that_may_skip_tls_is_a_device_anything_can_impersonate() {
    let sweep = vec![got(
        "iot",
        "devices",
        "fr-par",
        vec![
            json!({"id": "d1", "name": "sensor-01", "allow_insecure": true,
                   "allow_multiple_connections": true}),
            json!({"id": "d2", "name": "sensor-02", "allow_insecure": false,
                   "allow_multiple_connections": false}),
        ],
    )];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    assert_eq!(only(&f, "iot.devices.allow-insecure").len(), 1);
    assert_eq!(only(&f, "iot.devices.shared-identity").len(), 1);
    assert!(only(&f, "iot.devices.allow-insecure")[0]
        .subject
        .starts_with("sensor-01"));
}

#[test]
fn a_route_to_your_own_platform_is_not_a_route_off_it() {
    let sweep = vec![got(
        "iot",
        "routes",
        "fr-par",
        vec![
            json!({"id": "r1", "name": "to-elsewhere",
                   "rest_config": {"uri": "https://collector.example.net/ingest"}}),
            json!({"id": "r2", "name": "to-here",
                   "rest_config": {"uri": "https://api.fnc.fr-par.scw.cloud/x"}}),
            json!({"id": "r3", "name": "to-storage", "s3_config": {"bucket_name": "b"}}),
        ],
    )];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    let found = only(&f, "iot.routes.foreign-endpoint");
    assert_eq!(found.len(), 1);
    assert!(found[0].subject.starts_with("to-elsewhere"));
}

// ---- leftovers --------------------------------------------------------------

#[test]
fn a_public_custom_image_outranks_a_merely_old_one() {
    let sweep = vec![got(
        "instance",
        "images",
        "fr-par-1",
        vec![
            json!({"id": "i1", "name": "golden", "public": true, "organization": ORG,
                   "creation_date": "2026-06-01T00:00:00Z"}),
            json!({"id": "i2", "name": "old", "public": false, "organization": ORG,
                   "creation_date": "2023-01-01T00:00:00Z"}),
            json!({"id": "i3", "name": "AlmaLinux 8", "public": true,
                   "organization": "51b656e3-4865-41e8-adbc-0c45bdd780db",
                   "creation_date": "2023-01-01T00:00:00Z"}),
        ],
    )];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    assert_eq!(only(&f, "instance.images.public").len(), 1);
    assert_eq!(only(&f, "instance.images.stale").len(), 1);
    assert!(f[0].id == "instance.images.public", "worst first");
}

#[test]
fn an_attached_volume_is_not_an_orphan() {
    let sweep = vec![
        got(
            "instance",
            "volumes",
            "fr-par-1",
            vec![
                json!({"id": "v1", "name": "detached", "server": null}),
                json!({"id": "v2", "name": "in-use", "server": {"id": "s1"}}),
            ],
        ),
        got(
            "block",
            "volumes",
            "fr-par-1",
            vec![json!({"id": "v3", "name": "block-detached", "references": []})],
        ),
    ];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    let found = only(&f, "instance.volumes.orphan");
    assert_eq!(found.len(), 2, "both products, only the detached ones");
}

// ---- vaults -----------------------------------------------------------------

#[test]
fn a_secret_with_one_ancient_version_has_never_been_rotated() {
    let sweep = vec![got(
        "secret-manager",
        "secrets",
        "fr-par",
        vec![
            json!({"id": "s1", "name": "old", "version_count": 1, "protected": true,
                   "used_by": ["x"], "key_id": "k1", "created_at": "2024-01-01T00:00:00Z"}),
            json!({"id": "s2", "name": "fresh", "version_count": 4, "protected": true,
                   "used_by": ["x"], "key_id": "k1", "created_at": "2024-01-01T00:00:00Z"}),
        ],
    )];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    let found = only(&f, "secret-manager.secrets.never-rotated");
    assert_eq!(found.len(), 1);
    assert!(found[0].subject.starts_with("old"));
}

// ---- the whole thing --------------------------------------------------------

#[test]
fn the_marketplace_is_not_this_account_s_golden_images() {
    // `instance/images` returns Scaleway's whole catalogue alongside your own:
    // some twenty-three thousand images, every one of them public. Judging them
    // produced a report that was 99.99% AlmaLinux.
    let sweep = vec![got(
        "instance",
        "images",
        "fr-par-1",
        vec![
            json!({"id": "mine", "name": "golden", "public": true, "organization": ORG,
                   "creation_date": "2026-06-01T00:00:00Z"}),
            json!({"id": "theirs", "name": "Ubuntu 24.04", "public": true,
                   "organization": "51b656e3-4865-41e8-adbc-0c45bdd780db",
                   "creation_date": "2026-06-01T00:00:00Z"}),
        ],
    )];
    let f = Quiet::new(&sweep, ORG).audit(NOW);
    let found = only(&f, "instance.images.public");
    assert_eq!(found.len(), 1);
    assert!(found[0].subject.starts_with("golden"));
}

#[test]
fn without_an_organization_no_image_is_judged_at_all() {
    // Judging somebody else's resources is worse than judging none.
    let sweep = vec![got(
        "instance",
        "images",
        "fr-par-1",
        vec![
            json!({"id": "i1", "name": "img", "public": true, "organization": ORG,
                    "creation_date": "2026-06-01T00:00:00Z"}),
        ],
    )];
    assert!(!has(
        &Quiet::new(&sweep, "").audit(NOW),
        "instance.images.public"
    ));
}

#[test]
fn an_account_with_nothing_quiet_in_it_produces_nothing() {
    let sweep = vec![
        got("containers", "containers", "fr-par", vec![]),
        got("iot", "hubs", "fr-par", vec![]),
        got("secret-manager", "secrets", "fr-par", vec![]),
    ];
    assert!(Quiet::new(&sweep, ORG).audit(NOW).is_empty());
}

/// One account carrying every quiet weakness at once.
fn everything() -> Vec<Fetched> {
    let mut records = vec![
        json!({"type": "TXT", "name": "", "data": "v=spf1 ?all", "ttl": 604800}),
        json!({"type": "CNAME", "name": "old", "data": "gone.fnc.fr-par.scw.cloud.", "ttl": 300}),
        json!({"type": "A", "name": "*", "data": "198.51.100.9", "ttl": 604800}),
    ];
    records.push(json!({"type": "TXT", "name": "_dmarc", "data": "v=DMARC1; p=none", "ttl": 300}));

    vec![
        got(
            "containers",
            "namespaces",
            "fr-par",
            vec![json!({"id": "n1", "name": "ns", "environment_variables":
                        {"TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}})],
        ),
        got(
            "containers",
            "containers",
            "fr-par",
            vec![
                json!({"id": "c1", "name": "api", "http_option": "enabled", "sandbox": "v1",
                        "environment_variables": {"DB": "postgres://a:b@h/d"}}),
            ],
        ),
        got(
            "functions",
            "namespaces",
            "fr-par",
            vec![json!({"id": "n2", "name": "fns", "environment_variables":
                        {"SECRET": "AKIAIOSFODNN7EXAMPLE"}})],
        ),
        got(
            "functions",
            "functions",
            "fr-par",
            vec![json!({"id": "f1", "name": "fn", "http_option": "enabled",
                        "environment_variables": {"K": "-----BEGIN RSA PRIVATE KEY-----"}})],
        ),
        got(
            "jobs",
            "job-definitions",
            "fr-par",
            vec![
                json!({"id": "j1", "name": "job", "image_uri": "docker.io/library/alpine",
                        "environment_variables": {"PASSWORD": "s3cr3tvalue1"}}),
            ],
        ),
        got(
            "registry",
            "images",
            "fr-par",
            vec![json!({"id": "i1", "name": "img", "visibility": "public"})],
        ),
        got(
            "registry",
            "namespaces",
            "fr-par",
            vec![json!({"id": "rn1", "name": "empty-ns", "image_count": 0})],
        ),
        got(
            "domain",
            "domains",
            "",
            vec![
                json!({"domain": "example.com", "dnssec": "disabled", "is_external": true,
                        "auto_renew_status": "disabled", "expired_at": "2027-02-01T00:00:00Z"}),
            ],
        ),
        got(
            "domain",
            "dns-zones",
            "",
            vec![json!({"domain": "example.com", "subdomain": ""})],
        ),
        zone_records("example.com", records),
        got(
            "domain",
            "ssl-certificates",
            "",
            vec![json!({"dns_zone": "example.com"})],
        ),
        got(
            "iot",
            "hubs",
            "fr-par",
            vec![
                json!({"id": "h1", "name": "hub", "enable_device_auto_provisioning": true,
                        "has_custom_ca": false, "disable_events": true}),
            ],
        ),
        got(
            "iot",
            "devices",
            "fr-par",
            vec![json!({"id": "d1", "name": "dev", "allow_insecure": true,
                        "allow_multiple_connections": true,
                        "last_activity_at": "2025-01-01T00:00:00Z"})],
        ),
        got(
            "iot",
            "routes",
            "fr-par",
            vec![json!({"id": "r1", "name": "route",
                        "rest_config": {"uri": "https://elsewhere.example.net"}})],
        ),
        got(
            "apple-silicon",
            "servers",
            "fr-par-3",
            vec![
                json!({"id": "m1", "name": "mac", "sudo_password": "hunter2",
                        "status": "ready", "updated_at": "2026-01-01T00:00:00Z"}),
            ],
        ),
        got(
            "secret-manager",
            "secrets",
            "fr-par",
            vec![
                json!({"id": "s1", "name": "sec", "version_count": 1, "protected": false,
                        "used_by": [], "created_at": "2024-01-01T00:00:00Z"}),
            ],
        ),
        got(
            "key-manager",
            "keys",
            "fr-par",
            vec![
                json!({"id": "k1", "name": "key", "protected": false, "rotation_count": 0,
                        "created_at": "2024-01-01T00:00:00Z"}),
            ],
        ),
        got(
            "mnq",
            "sqs-credentials",
            "fr-par",
            vec![json!({"id": "q1", "name": "sqs", "permissions": {"can_manage": true}})],
        ),
        got(
            "mnq",
            "sns-credentials",
            "fr-par",
            vec![json!({"id": "q2", "name": "sns", "permissions": {"can_manage": true}})],
        ),
        got(
            "tem",
            "domains",
            "fr-par",
            vec![
                json!({"id": "t1", "name": "mail.example.com", "status": "invalid",
                        "reputation": {"status": "bad"}}),
            ],
        ),
        got(
            "instance",
            "images",
            "fr-par-1",
            vec![
                json!({"id": "im1", "name": "img", "public": true, "organization": ORG,
                        "creation_date": "2023-01-01T00:00:00Z"}),
                json!({"id": "im2", "name": "old", "public": false, "organization": ORG,
                        "creation_date": "2023-01-01T00:00:00Z"}),
            ],
        ),
        got(
            "instance",
            "volumes",
            "fr-par-1",
            vec![json!({"id": "v1", "name": "vol", "server": null})],
        ),
        got(
            "instance",
            "snapshots",
            "fr-par-1",
            vec![json!({"id": "sn1", "name": "snap", "creation_date": "2023-01-01T00:00:00Z"})],
        ),
        got(
            "block",
            "snapshots",
            "fr-par-1",
            vec![json!({"id": "sn2", "name": "bsnap", "created_at": "2023-01-01T00:00:00Z"})],
        ),
        got(
            "file",
            "filesystems",
            "fr-par",
            vec![json!({"id": "fs1", "name": "fs", "number_of_attachments": 0})],
        ),
    ]
}

#[test]
fn the_module_emits_exactly_what_it_claims_to_emit() {
    use std::collections::BTreeSet;
    let sweep = everything();
    let emitted: BTreeSet<&str> = Quiet::new(&sweep, ORG)
        .audit(NOW)
        .iter()
        .map(|f| f.id)
        .collect();
    let claimed: BTreeSet<&str> = IMPLEMENTED.into_iter().collect();
    assert_eq!(
        claimed.len(),
        IMPLEMENTED.len(),
        "IMPLEMENTED lists an id twice; a set comparison would never notice"
    );

    let unclaimed: Vec<&&str> = emitted.difference(&claimed).collect();
    assert!(
        unclaimed.is_empty(),
        "emitted but not in IMPLEMENTED: {unclaimed:?}"
    );

    let unreachable: Vec<&&str> = claimed.difference(&emitted).collect();
    assert!(
        unreachable.is_empty(),
        "claimed in IMPLEMENTED but never emitted by an account carrying every weakness: \
         {unreachable:?}"
    );
}

#[test]
fn every_id_this_module_emits_exists_in_the_catalogue() {
    let mut catalogued: Vec<&str> = Vec::new();
    for p in crate::scw::catalog::PRODUCTS {
        for r in p.resources {
            for c in r.checks {
                catalogued.push(c.id);
            }
        }
    }
    for id in IMPLEMENTED {
        assert!(
            catalogued.contains(&id),
            "{id} is emitted but not catalogued"
        );
    }
}
