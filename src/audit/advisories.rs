//! What the account runs, against what has been published about it.
//!
//! Pure over already-fetched data on both sides: the components come from a
//! sweep, the advisories come from the corpus cache, and this module joins them
//! and grades the result. No request is made here.
//!
//! The grading rests on one distinction. An advisory is a document; an advisory
//! whose affected range covers your version is a finding; and an advisory in the
//! KEV catalogue is a finding about something being exploited **now**. Reporting
//! all three the same way is how a vulnerability report becomes wallpaper.

use serde_json::Value;

use super::{name_or_id, s, Finding};
use crate::enrich::corpus::Corpus;
use crate::enrich::cpe;
use crate::scw::sweep::{items, Fetched};
use crate::scw::Severity;

/// Every check id this module can emit.
pub const IMPLEMENTED: [&str; 6] = [
    "k8s.clusters.known-cve",
    "rdb.instances.known-cve",
    "redis.clusters.known-cve",
    "kafka.clusters.known-cve",
    "searchdb.deployments.known-cve",
    "functions.functions.eol-runtime",
];

/// One thing the account runs, named the way the corpus names it.
pub struct Component {
    /// Key into [`cpe::SOFTWARE`].
    pub software: &'static str,
    /// The resource this came from, as a person would name it.
    pub subject: String,
    /// The version as the API reports it.
    pub version: String,
    /// The catalogue check a finding about it is filed under.
    pub check: &'static str,
}

/// Everything version-bearing in a sweep.
///
/// A resource with no version, or one the API reports as a word rather than a
/// number, is skipped rather than guessed at: an unparseable version compared
/// against a range produces a confident answer with nothing behind it.
pub fn components(fetched: &[Fetched]) -> Vec<Component> {
    let mut out = Vec::new();

    for (region, cl) in items(fetched, "k8s", "clusters") {
        push(
            &mut out,
            "kubernetes",
            "k8s.clusters.known-cve",
            cl,
            region,
            s(cl, "version"),
        );
    }

    // `PostgreSQL-14` and `MySQL-8`: the engine names both the software and the
    // version, and which software it is decides which corpus to ask.
    for (region, inst) in items(fetched, "rdb", "instances") {
        let engine = s(inst, "engine");
        let software = match engine.to_ascii_lowercase() {
            e if e.starts_with("postgresql") => "postgresql",
            e if e.starts_with("mysql") => "mysql",
            _ => continue,
        };
        push(
            &mut out,
            software,
            "rdb.instances.known-cve",
            inst,
            region,
            engine,
        );
    }

    for (zone, cl) in items(fetched, "redis", "clusters") {
        push(
            &mut out,
            "redis",
            "redis.clusters.known-cve",
            cl,
            zone,
            s(cl, "version"),
        );
    }
    for (region, cl) in items(fetched, "kafka", "clusters") {
        push(
            &mut out,
            "kafka",
            "kafka.clusters.known-cve",
            cl,
            region,
            s(cl, "version"),
        );
    }
    for (region, d) in items(fetched, "searchdb", "deployments") {
        push(
            &mut out,
            "opensearch",
            "searchdb.deployments.known-cve",
            d,
            region,
            s(d, "version"),
        );
    }

    out
}

fn push(
    out: &mut Vec<Component>,
    software: &'static str,
    check: &'static str,
    thing: &Value,
    locality: &str,
    version: String,
) {
    if cpe::parse(&version).is_empty() {
        return;
    }
    out.push(Component {
        software,
        subject: format!("{} ({locality})", name_or_id(thing)),
        version,
        check,
    });
}

/// The distinct CPEs a set of components needs looked up.
pub fn cpes(components: &[Component]) -> Vec<String> {
    let mut out: Vec<String> = components
        .iter()
        .filter_map(|c| cpe::software(c.software).map(|s| s.cpe.to_string()))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Grade every component against the corpora that were read for them.
pub fn audit(components: &[Component], corpora: &[Corpus], fetched: &[Fetched]) -> Vec<Finding> {
    let mut out = Vec::new();

    for c in components {
        let Some(software) = cpe::software(c.software) else {
            continue;
        };
        let Some(corpus) = corpora.iter().find(|k| k.cpe == software.cpe) else {
            continue;
        };
        if !corpus.covered() {
            continue; // reported as a coverage gap, not as a clean result
        }

        let version = cpe::parse(&c.version);
        let hits: Vec<&Value> = corpus
            .items
            .iter()
            .filter(|a| cpe::advisory_affects(a, software.cpe, &version))
            .collect();
        if hits.is_empty() {
            continue;
        }

        let exploited: Vec<&&Value> = hits
            .iter()
            .filter(|a| a.get("in_kev").and_then(Value::as_bool) == Some(true))
            .collect();
        let worst = hits
            .iter()
            .filter_map(|a| a.get("cvss_score").and_then(Value::as_f64))
            .fold(0.0f64, f64::max);

        // Being in KEV means somebody is using it today. Nothing else in an
        // advisory carries that weight, so nothing else sets this severity.
        let severity = if !exploited.is_empty() {
            Severity::Critical
        } else if worst >= 9.0 {
            Severity::High
        } else {
            Severity::Medium
        };

        let mut ids: Vec<String> = hits
            .iter()
            .filter_map(|a| a.get("id").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        ids.sort();
        ids.dedup();
        let shown = ids.iter().take(6).cloned().collect::<Vec<_>>().join(", ");

        out.push(Finding::new(
            c.check,
            severity,
            &c.subject,
            format!(
                "{} runs {}, which {} published advisor{} cover{}{}. Worst CVSS {worst:.1}. {shown}{}",
                software.label,
                c.version,
                hits.len(),
                if hits.len() == 1 { "y" } else { "ies" },
                if hits.len() == 1 { "s" } else { "" },
                if exploited.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", {} of them in the KEV catalogue of vulnerabilities being exploited now",
                        exploited.len()
                    )
                },
                if ids.len() > 6 {
                    format!(" and {} more", ids.len() - 6)
                } else {
                    String::new()
                }
            ),
        ));
    }

    // The one check here that needs no corpus at all: the platform publishes
    // its own verdict on each runtime, so asking anyone else would be worse.
    runtimes(fetched, &mut out);

    super::sort(&mut out);
    out
}

/// Functions on a runtime the platform itself calls end of life or end of
/// support.
fn runtimes(fetched: &[Fetched], out: &mut Vec<Finding>) {
    let catalogue = items(fetched, "functions", "runtimes");
    if catalogue.is_empty() {
        return;
    }
    for (region, f) in items(fetched, "functions", "functions") {
        let runtime = s(f, "runtime");
        let Some((_, entry)) = catalogue.iter().find(|(_, r)| s(r, "name") == runtime) else {
            continue;
        };
        let status = s(entry, "status");
        if !matches!(status.as_str(), "end_of_life" | "end_of_support") {
            continue;
        }
        out.push(Finding::new(
            "functions.functions.eol-runtime",
            if status == "end_of_life" {
                Severity::High
            } else {
                Severity::Medium
            },
            format!("{} ({region})", name_or_id(f)),
            format!(
                "runs {runtime}, which Scaleway itself marks {}: it keeps serving, and it stops \
                 receiving patches",
                status.replace('_', " ")
            ),
        ));
    }
}

/// Products this run could not check, and why.
///
/// A corpus that files nothing under a name is not a clean result, and neither
/// is one that was never fetched. Both have to be said out loud, or the report
/// reads as "nothing found" when it means "nothing looked".
pub fn coverage(components: &[Component], corpora: &[Corpus]) -> Vec<String> {
    let mut out = Vec::new();
    for c in components {
        let Some(software) = cpe::software(c.software) else {
            out.push(format!(
                "{}: no CPE known for it, so nothing was checked",
                c.software
            ));
            continue;
        };
        let Some(corpus) = corpora.iter().find(|k| k.cpe == software.cpe) else {
            continue;
        };
        let line = match (&corpus.error, corpus.covered(), corpus.truncated()) {
            (Some(e), _, _) => format!("{}: {e}", software.label),
            (None, false, _) => format!(
                "{}: the corpus files no advisory under {}, so this version was not checked",
                software.label, software.cpe
            ),
            (None, true, true) => format!(
                "{}: {} advisories exist and {} were read",
                software.label,
                corpus.total,
                corpus.items.len()
            ),
            _ => continue,
        };
        if !out.contains(&line) {
            out.push(line);
        }
    }
    out.sort();
    out
}

#[cfg(test)]
mod tests;
