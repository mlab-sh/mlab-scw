//! Naming software the way the advisory corpus names it, and deciding whether
//! one version falls inside an advisory's range.
//!
//! Two pieces of domain knowledge live here, and both fail quietly if they are
//! wrong — which is why both are tested rather than trusted:
//!
//! * **the table.** `cpe:2.3:a:postgresql:postgresql` is the identifier the
//!   corpus files PostgreSQL under. A typo does not error: the corpus ignores
//!   an unparseable filter and answers with everything it has.
//! * **the comparison.** An advisory says "from 10.0.0 up to but not including
//!   10.0.7". Getting `10.0.10 < 10.0.7` wrong turns a real finding into
//!   silence, or silence into a false alarm.

use std::cmp::Ordering;

use serde_json::Value;

/// One piece of software this tool can recognise, and how the corpus files it.
pub struct Software {
    /// How this tool refers to it.
    pub key: &'static str,
    /// How a person refers to it.
    pub label: &'static str,
    /// `vendor:product`, the part of a CPE 2.3 name that identifies the thing.
    pub cpe: &'static str,
}

/// Everything a Scaleway account can be running that the corpus knows about.
///
/// Every entry here was checked against the live corpus: an entry that returns
/// nothing is not a clean bill of health, it is a gap, and the report says so.
/// MongoDB is deliberately absent — the corpus files no `mongodb:*` product at
/// all, so claiming to check it would be a lie.
pub static SOFTWARE: &[Software] = &[
    Software {
        key: "kubernetes",
        label: "Kubernetes",
        cpe: "cpe:2.3:a:kubernetes:kubernetes",
    },
    Software {
        key: "postgresql",
        label: "PostgreSQL",
        cpe: "cpe:2.3:a:postgresql:postgresql",
    },
    Software {
        key: "mysql",
        label: "MySQL",
        cpe: "cpe:2.3:a:oracle:mysql",
    },
    Software {
        key: "redis",
        label: "Redis",
        cpe: "cpe:2.3:a:redis:redis",
    },
    Software {
        key: "kafka",
        label: "Apache Kafka",
        cpe: "cpe:2.3:a:apache:kafka",
    },
    Software {
        key: "opensearch",
        label: "OpenSearch",
        cpe: "cpe:2.3:a:amazon:opensearch",
    },
];

pub fn software(key: &str) -> Option<&'static Software> {
    SOFTWARE.iter().find(|s| s.key == key)
}

/// Whether a string is a `vendor:product` CPE this tool may send.
///
/// The corpus ignores a filter it cannot parse and answers with its entire
/// contents — three hundred thousand advisories presented as findings about
/// your Redis. So the shape is checked here, before the request.
pub fn is_valid(cpe: &str) -> bool {
    let parts: Vec<&str> = cpe.split(':').collect();
    parts.len() == 5
        && parts[0] == "cpe"
        && parts[1] == "2.3"
        && matches!(parts[2], "a" | "o" | "h")
        && !parts[3].is_empty()
        && !parts[4].is_empty()
}

/// A version as comparable numbers.
///
/// Everything that is not a digit separates components, so `1.29.2`,
/// `8.2.2.1`, `14`, `7.0.5-rc1` and `v2.1` all parse. A trailing pre-release
/// tag is dropped rather than ordered: the corpus states ranges in released
/// versions, and pretending to order `-rc1` against `-beta` would be invention.
pub fn parse(version: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let mut current = String::new();
    for c in version.chars() {
        if c.is_ascii_digit() {
            current.push(c);
        } else {
            if !current.is_empty() {
                out.push(current.parse().unwrap_or(0));
                current.clear();
            }
            // A letter ends the version proper: `7.0.5-rc1` is 7.0.5.
            if c.is_ascii_alphabetic() && !out.is_empty() {
                return out;
            }
        }
    }
    if !current.is_empty() {
        out.push(current.parse().unwrap_or(0));
    }
    out
}

/// Compare two parsed versions, treating a missing component as zero.
///
/// `14` and `14.0` are the same version; `14` is older than `14.1`.
pub fn cmp(a: &[u64], b: &[u64]) -> Ordering {
    let len = a.len().max(b.len());
    for i in 0..len {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        match x.cmp(&y) {
            Ordering::Equal => continue,
            other => return other,
        }
    }
    Ordering::Equal
}

/// Whether `version` falls inside one `cpe_matches` entry.
///
/// An entry is either an exact version in the CPE name itself, or a range
/// expressed by up to four bounds. An entry with neither — a bare `*` and no
/// bounds — means every version of the product is affected.
pub fn affected(version: &[u64], entry: &Value) -> bool {
    if version.is_empty() {
        return false;
    }
    if entry.get("vulnerable").and_then(Value::as_bool) == Some(false) {
        return false;
    }

    // `cpe:2.3:a:vendor:product:VERSION:...` — position 5.
    let criteria = entry
        .get("criteria")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if let Some(pinned) = criteria.split(':').nth(5) {
        if pinned != "*" && pinned != "-" && !pinned.is_empty() {
            return cmp(version, &parse(pinned)) == Ordering::Equal;
        }
    }

    let bound = |key: &str| {
        entry
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(parse)
    };

    let mut bounded = false;
    if let Some(start) = bound("version_start_including") {
        bounded = true;
        if cmp(version, &start) == Ordering::Less {
            return false;
        }
    }
    if let Some(start) = bound("version_start_excluding") {
        bounded = true;
        if cmp(version, &start) != Ordering::Greater {
            return false;
        }
    }
    if let Some(end) = bound("version_end_including") {
        bounded = true;
        if cmp(version, &end) == Ordering::Greater {
            return false;
        }
    }
    if let Some(end) = bound("version_end_excluding") {
        bounded = true;
        if cmp(version, &end) != Ordering::Less {
            return false;
        }
    }

    // No pinned version and no bounds: the whole product is named.
    bounded || criteria.split(':').nth(5).is_some_and(|v| v == "*")
}

/// Whether an advisory affects `version` of the product named by `cpe`.
///
/// Only entries for that product are considered: a single advisory routinely
/// covers several vendors, and one of the others being in range says nothing
/// about yours.
pub fn advisory_affects(advisory: &Value, cpe: &str, version: &[u64]) -> bool {
    advisory
        .get("cpe_matches")
        .and_then(Value::as_array)
        .is_some_and(|entries| {
            entries.iter().any(|e| {
                e.get("criteria")
                    .and_then(Value::as_str)
                    .is_some_and(|c| c.starts_with(&format!("{cpe}:")))
                    && affected(version, e)
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_entry_in_the_table_is_a_well_formed_cpe() {
        // A malformed filter is not refused by the corpus: it is ignored, and
        // the answer is the whole corpus presented as findings about you.
        for s in SOFTWARE {
            assert!(is_valid(s.cpe), "{}: {}", s.key, s.cpe);
        }
    }

    #[test]
    fn a_partial_cpe_is_refused_before_it_is_sent() {
        assert!(is_valid("cpe:2.3:a:redis:redis"));
        assert!(!is_valid("cpe:2.3:a:redis"), "no product");
        assert!(!is_valid("cpe:2.3:redis:redis"), "no part");
        assert!(!is_valid("redis"), "not a cpe at all");
        assert!(!is_valid("cpe:2.3:a::redis"), "empty vendor");
        assert!(!is_valid("cpe:2.3:x:redis:redis"), "unknown part");
    }

    #[test]
    fn versions_parse_however_they_are_punctuated() {
        assert_eq!(parse("14"), vec![14]);
        assert_eq!(parse("1.29.2"), vec![1, 29, 2]);
        assert_eq!(parse("8.2.2.1"), vec![8, 2, 2, 1]);
        assert_eq!(parse("v2.1"), vec![2, 1]);
        assert_eq!(
            parse("PostgreSQL-14"),
            vec![14],
            "the name is not a version"
        );
        assert_eq!(parse("7.0.5-rc1"), vec![7, 0, 5], "the tag is dropped");
        assert!(parse("").is_empty());
        assert!(parse("latest").is_empty());
    }

    #[test]
    fn a_missing_component_is_zero_not_infinity() {
        assert_eq!(cmp(&parse("14"), &parse("14.0")), Ordering::Equal);
        assert_eq!(cmp(&parse("14"), &parse("14.1")), Ordering::Less);
        assert_eq!(cmp(&parse("14.1"), &parse("14")), Ordering::Greater);
    }

    #[test]
    fn components_compare_as_numbers_rather_than_as_text() {
        // The comparison that a string sort gets wrong, and that decides
        // whether a real advisory is reported at all.
        assert_eq!(cmp(&parse("10.0.10"), &parse("10.0.7")), Ordering::Greater);
        assert_eq!(cmp(&parse("1.9.0"), &parse("1.10.0")), Ordering::Less);
    }

    #[test]
    fn a_range_excludes_its_upper_bound_and_includes_its_lower() {
        // Taken from a real advisory: 10.0.0 <= affected < 10.0.7.
        let entry = json!({
            "criteria": "cpe:2.3:a:splunk:splunk:*:*:*:*:enterprise:*:*:*",
            "vulnerable": true,
            "version_start_including": "10.0.0",
            "version_end_excluding": "10.0.7"
        });
        assert!(
            affected(&parse("10.0.0"), &entry),
            "the lower bound is included"
        );
        assert!(affected(&parse("10.0.6"), &entry));
        assert!(
            !affected(&parse("10.0.7"), &entry),
            "the upper bound is excluded"
        );
        assert!(!affected(&parse("10.0.10"), &entry), "and 10 is after 7");
        assert!(!affected(&parse("9.9.9"), &entry));
    }

    #[test]
    fn exclusive_and_inclusive_bounds_are_read_apart() {
        let excl_start = json!({"criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*",
                                "version_start_excluding": "2.0"});
        assert!(!affected(&parse("2.0"), &excl_start));
        assert!(affected(&parse("2.0.1"), &excl_start));

        let incl_end = json!({"criteria": "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*",
                              "version_end_including": "3.4"});
        assert!(affected(&parse("3.4"), &incl_end));
        assert!(!affected(&parse("3.4.1"), &incl_end));
    }

    #[test]
    fn a_pinned_version_in_the_cpe_matches_only_itself() {
        let entry = json!({"criteria": "cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*",
                           "vulnerable": true});
        assert!(affected(&parse("7.0.5"), &entry));
        assert!(!affected(&parse("7.0.6"), &entry));
        assert!(!affected(&parse("7.0"), &entry));
    }

    #[test]
    fn a_product_named_with_no_bounds_at_all_affects_every_version() {
        let entry = json!({"criteria": "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
                           "vulnerable": true});
        assert!(affected(&parse("1.0"), &entry));
        assert!(affected(&parse("99.0"), &entry));
    }

    #[test]
    fn an_entry_marked_not_vulnerable_is_not_a_finding() {
        // The corpus uses these to say "this configuration is required for the
        // vulnerable one", not "this is affected".
        let entry = json!({"criteria": "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
                           "vulnerable": false});
        assert!(!affected(&parse("7.0.5"), &entry));
    }

    #[test]
    fn an_unparseable_version_matches_nothing_rather_than_everything() {
        let entry = json!({"criteria": "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
                           "vulnerable": true});
        assert!(!affected(&parse("latest"), &entry));
        assert!(!affected(&[], &entry));
    }

    #[test]
    fn another_vendors_range_in_the_same_advisory_says_nothing_about_yours() {
        // One advisory routinely covers several products. Matching on the
        // advisory rather than on its entry for *your* product is how a tool
        // reports Splunk's vulnerability as PostgreSQL's.
        let advisory = json!({"cpe_matches": [
            {"criteria": "cpe:2.3:a:splunk:splunk:*:*:*:*:*:*:*:*", "vulnerable": true,
             "version_start_including": "10.0.0", "version_end_excluding": "99.0"},
            {"criteria": "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", "vulnerable": true,
             "version_start_including": "13.0", "version_end_excluding": "13.5"}
        ]});
        let cpe = "cpe:2.3:a:postgresql:postgresql";
        assert!(advisory_affects(&advisory, cpe, &parse("13.2")));
        assert!(
            !advisory_affects(&advisory, cpe, &parse("14.11")),
            "in Splunk's range, outside PostgreSQL's"
        );
    }

    #[test]
    fn an_advisory_with_no_matches_at_all_affects_nothing() {
        let advisory = json!({"cpe_matches": []});
        assert!(!advisory_affects(
            &advisory,
            "cpe:2.3:a:redis:redis",
            &parse("7.0")
        ));
        assert!(!advisory_affects(
            &json!({}),
            "cpe:2.3:a:redis:redis",
            &parse("7.0")
        ));
    }
}
