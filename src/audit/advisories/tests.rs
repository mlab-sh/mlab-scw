//! Fixtures are the shapes the corpus and the API return, with every
//! identifier invented.

use super::*;
use crate::enrich::corpus::Corpus;
use crate::scw::sweep::{Fetch, Fetched};
use serde_json::json;

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

fn corpus(cpe: &str, items: Vec<Value>) -> Corpus {
    Corpus {
        cpe: cpe.to_string(),
        total: items.len() as u64,
        items,
        cached: true,
        error: None,
    }
}

/// One advisory affecting `postgresql` between two bounds.
fn advisory(id: &str, from: &str, to: &str, cvss: f64, kev: bool) -> Value {
    json!({
        "id": id,
        "cvss_score": cvss,
        "in_kev": kev,
        "cpe_matches": [{
            "criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
            "vulnerable": true,
            "version_start_including": from,
            "version_end_excluding": to
        }]
    })
}

fn has(f: &[Finding], id: &str) -> bool {
    f.iter().any(|x| x.id == id)
}

// ---- what the account runs --------------------------------------------------

#[test]
fn an_engine_name_yields_both_the_software_and_the_version() {
    let sweep = vec![got(
        "rdb",
        "instances",
        "fr-par",
        vec![
            json!({"id": "d1", "name": "app", "engine": "PostgreSQL-14"}),
            json!({"id": "d2", "name": "legacy", "engine": "MySQL-8"}),
        ],
    )];
    let c = components(&sweep);
    assert_eq!(c.len(), 2);
    assert_eq!(c[0].software, "postgresql");
    assert_eq!(c[0].version, "PostgreSQL-14");
    assert_eq!(c[1].software, "mysql");
    assert_eq!(cpe::parse(&c[0].version), vec![14]);
}

#[test]
fn a_version_that_is_a_word_is_skipped_rather_than_guessed_at() {
    // Comparing an unparseable version against a range produces a confident
    // answer with nothing behind it.
    let sweep = vec![got(
        "k8s",
        "clusters",
        "fr-par",
        vec![
            json!({"id": "c1", "name": "prod", "version": "1.29.2"}),
            json!({"id": "c2", "name": "odd", "version": "latest"}),
            json!({"id": "c3", "name": "none"}),
        ],
    )];
    let c = components(&sweep);
    assert_eq!(c.len(), 1);
    assert!(c[0].subject.starts_with("prod"));
}

#[test]
fn an_unknown_engine_is_not_forced_into_a_corpus() {
    let sweep = vec![got(
        "rdb",
        "instances",
        "fr-par",
        vec![json!({"id": "d1", "name": "x", "engine": "CockroachDB-23"})],
    )];
    assert!(components(&sweep).is_empty());
}

#[test]
fn one_lookup_is_planned_per_product_however_many_instances_run_it() {
    let sweep = vec![got(
        "rdb",
        "instances",
        "fr-par",
        vec![
            json!({"id": "d1", "name": "a", "engine": "PostgreSQL-14"}),
            json!({"id": "d2", "name": "b", "engine": "PostgreSQL-15"}),
            json!({"id": "d3", "name": "c", "engine": "MySQL-8"}),
        ],
    )];
    let c = components(&sweep);
    let planned = cpes(&c);
    assert_eq!(
        planned.len(),
        2,
        "three databases, two products: {planned:?}"
    );
}

// ---- the grading ------------------------------------------------------------

#[test]
fn only_advisories_whose_range_covers_the_version_are_reported() {
    let sweep = vec![got(
        "rdb",
        "instances",
        "fr-par",
        vec![json!({"id": "d1", "name": "app", "engine": "PostgreSQL-14"})],
    )];
    let c = components(&sweep);
    let k = vec![corpus(
        "cpe:2.3:a:postgresql:postgresql",
        vec![
            advisory("CVE-2026-1", "13.0", "13.9", 9.8, false),
            advisory("CVE-2026-2", "14.0", "14.9", 7.5, false),
            advisory("CVE-2026-3", "15.0", "15.4", 9.1, false),
        ],
    )];
    let f = audit(&c, &k, &sweep);
    assert_eq!(f.len(), 1);
    assert!(f[0].detail.contains("CVE-2026-2"));
    assert!(!f[0].detail.contains("CVE-2026-1"), "13.x is not 14");
    assert!(!f[0].detail.contains("CVE-2026-3"), "15.x is not 14");
}

#[test]
fn something_being_exploited_now_outranks_something_merely_severe() {
    let sweep = vec![got(
        "rdb",
        "instances",
        "fr-par",
        vec![json!({"id": "d1", "name": "app", "engine": "PostgreSQL-14"})],
    )];
    let c = components(&sweep);

    let severe = vec![corpus(
        "cpe:2.3:a:postgresql:postgresql",
        vec![advisory("CVE-2026-9", "14.0", "14.9", 9.8, false)],
    )];
    assert_eq!(audit(&c, &severe, &sweep)[0].severity, Severity::High);

    let exploited = vec![corpus(
        "cpe:2.3:a:postgresql:postgresql",
        vec![advisory("CVE-2026-9", "14.0", "14.9", 5.3, true)],
    )];
    let f = audit(&c, &exploited, &sweep);
    assert_eq!(
        f[0].severity,
        Severity::Critical,
        "a lower CVSS that is being used today still outranks a higher one that is not"
    );
    assert!(f[0].detail.contains("KEV"));
}

#[test]
fn a_version_nothing_covers_produces_no_finding() {
    let sweep = vec![got(
        "rdb",
        "instances",
        "fr-par",
        vec![json!({"id": "d1", "name": "app", "engine": "PostgreSQL-17"})],
    )];
    let c = components(&sweep);
    let k = vec![corpus(
        "cpe:2.3:a:postgresql:postgresql",
        vec![advisory("CVE-2026-1", "13.0", "13.9", 9.8, false)],
    )];
    assert!(audit(&c, &k, &sweep).is_empty());
}

#[test]
fn a_corpus_that_files_nothing_produces_no_finding_and_one_coverage_line() {
    // The distinction the whole module rests on: "nothing found" and "nothing
    // looked" must never render the same way.
    let sweep = vec![got(
        "redis",
        "clusters",
        "fr-par-1",
        vec![json!({"id": "r1", "name": "cache", "version": "7.0.5"})],
    )];
    let c = components(&sweep);
    let empty = vec![corpus("cpe:2.3:a:redis:redis", vec![])];

    assert!(audit(&c, &empty, &sweep).is_empty());
    let gaps = coverage(&c, &empty);
    assert_eq!(gaps.len(), 1);
    assert!(gaps[0].contains("files no advisory"), "{}", gaps[0]);
}

#[test]
fn a_corpus_that_could_not_be_fetched_says_so_rather_than_reading_as_clean() {
    let sweep = vec![got(
        "redis",
        "clusters",
        "fr-par-1",
        vec![json!({"id": "r1", "name": "cache", "version": "7.0.5"})],
    )];
    let c = components(&sweep);
    let failed = vec![Corpus {
        cpe: "cpe:2.3:a:redis:redis".into(),
        items: Vec::new(),
        total: 0,
        cached: false,
        error: Some("not fetched: --allow-web was not given".into()),
    }];
    assert!(audit(&c, &failed, &sweep).is_empty());
    assert!(coverage(&c, &failed)[0].contains("--allow-web"));
}

#[test]
fn a_partial_read_of_a_large_corpus_is_declared() {
    let sweep = vec![got(
        "rdb",
        "instances",
        "fr-par",
        vec![json!({"id": "d1", "name": "app", "engine": "MySQL-8"})],
    )];
    let c = components(&sweep);
    let big = vec![Corpus {
        cpe: "cpe:2.3:a:oracle:mysql".into(),
        items: vec![json!({"id": "CVE-1", "cpe_matches": []})],
        total: 1328,
        cached: true,
        error: None,
    }];
    let gaps = coverage(&c, &big);
    assert_eq!(gaps.len(), 1);
    assert!(
        gaps[0].contains("1328 advisories exist and 1 were read"),
        "{}",
        gaps[0]
    );
}

// ---- the check that needs nobody else ---------------------------------------

#[test]
fn the_platform_is_its_own_authority_on_a_dead_runtime() {
    let sweep = vec![
        got(
            "functions",
            "runtimes",
            "fr-par",
            vec![
                json!({"name": "node26", "status": "available"}),
                json!({"name": "node20", "status": "end_of_support"}),
                json!({"name": "node14", "status": "end_of_life"}),
            ],
        ),
        got(
            "functions",
            "functions",
            "fr-par",
            vec![
                json!({"id": "f1", "name": "current", "runtime": "node26"}),
                json!({"id": "f2", "name": "trailing", "runtime": "node20"}),
                json!({"id": "f3", "name": "abandoned", "runtime": "node14"}),
            ],
        ),
    ];
    let f = audit(&[], &[], &sweep);
    let eol: Vec<&Finding> = f
        .iter()
        .filter(|x| x.id == "functions.functions.eol-runtime")
        .collect();
    assert_eq!(eol.len(), 2, "the available one is not a finding");
    assert_eq!(eol[0].severity, Severity::High, "end of life first");
    assert!(eol[0].subject.starts_with("abandoned"));
    assert_eq!(eol[1].severity, Severity::Medium);
}

#[test]
fn without_the_runtime_catalogue_no_runtime_is_judged() {
    let sweep = vec![got(
        "functions",
        "functions",
        "fr-par",
        vec![json!({"id": "f1", "name": "x", "runtime": "node14"})],
    )];
    assert!(!has(
        &audit(&[], &[], &sweep),
        "functions.functions.eol-runtime"
    ));
}

// ---- bookkeeping ------------------------------------------------------------

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
    // A set comparison would never notice a repeated entry, which is exactly
    // how one sat unnoticed in the exposure module's list.
    let unique: std::collections::BTreeSet<&str> = IMPLEMENTED.into_iter().collect();
    assert_eq!(
        unique.len(),
        IMPLEMENTED.len(),
        "IMPLEMENTED lists an id twice"
    );
}

#[test]
fn every_software_in_the_table_is_reachable_from_a_component() {
    // A CPE nothing can produce a component for is dead weight that reads as
    // coverage.
    let reachable = [
        "kubernetes",
        "postgresql",
        "mysql",
        "redis",
        "kafka",
        "opensearch",
    ];
    for s in cpe::SOFTWARE {
        assert!(
            reachable.contains(&s.key),
            "{} is in the table but no sweep produces it",
            s.key
        );
    }
}
