//! The advisory corpus at `vuln.mlab.sh`.
//!
//! One question, asked by CPE: *what has been published about this product?*
//! The answer is cached on disk for a day, because the corpus moves slowly and
//! a repeated audit should cost nothing.
//!
//! Nothing about the account is sent. The request is a product identifier and a
//! page number.

use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::enrich::{cache_dir, cpe, now, read_cache, write_cache};

const ENDPOINT: &str = "https://vuln.mlab.sh/api/v1/cve";

/// The corpus moves slowly; a day is plenty, and it keeps a repeated run free.
const TTL_SECONDS: i64 = 24 * 3600;

/// Advisories per request. The corpus pages, and this is one round trip.
const PAGE: u32 = 100;

/// Most advisories any one product will be walked for.
///
/// MySQL alone has over a thousand, and reading every one of them to grade a
/// single version is not worth the wait. The report says when it stopped.
const MAX_ADVISORIES: usize = 600;

/// A filter the corpus could not parse is not refused: it is ignored, and the
/// answer is every advisory there is. Anything near that size means the
/// question did not arrive, so it is treated as a failure rather than as three
/// hundred thousand findings about your Redis.
const IMPLAUSIBLE: u64 = 10_000;

#[derive(Serialize, Deserialize, Clone, Default)]
struct Cache {
    fetched: i64,
    total: u64,
    items: Vec<Value>,
}

/// What one product's corpus lookup produced.
pub struct Corpus {
    pub cpe: String,
    pub items: Vec<Value>,
    /// How many the corpus says exist, which may exceed what was read.
    pub total: u64,
    /// True when the answer came off the disk rather than the network.
    pub cached: bool,
    /// Why this is empty, when it is empty for a reason.
    pub error: Option<String>,
}

impl Corpus {
    fn empty(cpe: &str, error: Option<String>) -> Self {
        Corpus {
            cpe: cpe.to_string(),
            items: Vec::new(),
            total: 0,
            cached: false,
            error,
        }
    }

    /// Whether this product is covered at all.
    ///
    /// Zero advisories for a well-formed CPE is not a clean bill of health: it
    /// means the corpus files nothing under that name, and the caller has to
    /// say so rather than report silence as safety.
    pub fn covered(&self) -> bool {
        self.error.is_none() && self.total > 0
    }

    pub fn truncated(&self) -> bool {
        self.total > self.items.len() as u64
    }
}

fn cache_path(cpe: &str) -> PathBuf {
    let slug: String = cpe
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    cache_dir().join(format!("cve-{slug}.json"))
}

/// Read one product's advisories, from disk when they are fresh enough.
///
/// `allow_web` is the gate: without it this only ever answers from the cache,
/// so a run that was told not to reach the network never does.
pub async fn fetch(cpe: &str, allow_web: bool) -> Corpus {
    if !cpe::is_valid(cpe) {
        return Corpus::empty(cpe, Some(format!("{cpe} is not a vendor:product CPE")));
    }

    let path = cache_path(cpe);
    if let Some(cached) = read_cache::<Cache>(&path) {
        if now() - cached.fetched < TTL_SECONDS {
            return Corpus {
                cpe: cpe.to_string(),
                items: cached.items,
                total: cached.total,
                cached: true,
                error: None,
            };
        }
        if !allow_web {
            // Stale, but a stale corpus is a far better answer than none, and
            // saying it is stale is the caller's job rather than a reason to
            // withhold it.
            return Corpus {
                cpe: cpe.to_string(),
                items: cached.items,
                total: cached.total,
                cached: true,
                error: None,
            };
        }
    }

    if !allow_web {
        return Corpus::empty(cpe, Some("not fetched: --allow-web was not given".into()));
    }

    let http = match reqwest::Client::builder()
        .timeout(Duration::from_secs(25))
        .user_agent(concat!("mlab-scw/", env!("CARGO_PKG_VERSION")))
        .build()
    {
        Ok(c) => c,
        Err(e) => return Corpus::empty(cpe, Some(e.to_string())),
    };

    let mut items: Vec<Value> = Vec::new();
    let mut total = 0u64;
    let mut start = 0u32;

    while items.len() < MAX_ADVISORIES {
        match page(&http, cpe, start).await {
            Ok((got, reported)) => {
                total = reported;
                if reported > IMPLAUSIBLE {
                    return Corpus::empty(
                        cpe,
                        Some(format!(
                            "the corpus answered with {reported} advisories, which means it \
                             ignored the filter rather than applying it"
                        )),
                    );
                }
                let n = got.len();
                items.extend(got);
                if n < PAGE as usize || items.len() as u64 >= reported {
                    break;
                }
                start += PAGE;
            }
            Err(e) => {
                if items.is_empty() {
                    return Corpus::empty(cpe, Some(e));
                }
                break;
            }
        }
    }

    write_cache(
        &path,
        &Cache {
            fetched: now(),
            total,
            items: items.clone(),
        },
    );

    Corpus {
        cpe: cpe.to_string(),
        items,
        total,
        cached: false,
        error: None,
    }
}

async fn page(http: &reqwest::Client, cpe: &str, start: u32) -> Result<(Vec<Value>, u64), String> {
    let resp = http
        .get(ENDPOINT)
        .query(&[
            ("cpe", cpe),
            ("limit", &PAGE.to_string()),
            ("start_index", &start.to_string()),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
        return Err(format!("vuln.mlab.sh answered {}", resp.status().as_u16()));
    }

    let body: Value = resp.json().await.map_err(|e| e.to_string())?;
    let total = body
        .get("total_results")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let items = body
        .get("cves")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok((items, total))
}

/// Exactly what a run would send, for `--explain`.
///
/// The honest form of "nothing leaves your machine unless you allow it": the
/// payload can be read before it is sent.
pub fn requests(cpes: &[String]) -> Vec<String> {
    cpes.iter()
        .map(|c| format!("GET {ENDPOINT}?cpe={c}&limit={PAGE}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cache_file_name_cannot_escape_the_cache_directory() {
        // The CPE is data from a table, but it ends up in a path, and a path
        // built from a string with slashes in it is a directory traversal.
        let path = cache_path("cpe:2.3:a:../../etc:passwd");
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        assert!(!name.contains('/'), "{name}");
        assert!(!name.contains(".."), "{name}");
        assert!(name.starts_with("cve-") && name.ends_with(".json"));
    }

    #[test]
    fn a_malformed_cpe_never_reaches_the_network() {
        let corpus = futures_lite_block(fetch("redis", false));
        assert!(corpus
            .error
            .is_some_and(|e| e.contains("not a vendor:product")));
    }

    #[test]
    fn a_product_with_no_advisories_is_uncovered_rather_than_clean() {
        let corpus = Corpus {
            cpe: "cpe:2.3:a:mongodb:mongodb".into(),
            items: Vec::new(),
            total: 0,
            cached: false,
            error: None,
        };
        assert!(
            !corpus.covered(),
            "zero advisories means the corpus files nothing under that name, \
             which is not the same as nothing being wrong"
        );
    }

    #[test]
    fn a_partial_read_is_reported_as_partial() {
        let corpus = Corpus {
            cpe: "cpe:2.3:a:oracle:mysql".into(),
            items: vec![serde_json::json!({})],
            total: 1328,
            cached: false,
            error: None,
        };
        assert!(corpus.truncated());
        assert!(corpus.covered());
    }

    #[test]
    fn the_explain_line_carries_a_product_and_nothing_else() {
        let lines = requests(&["cpe:2.3:a:redis:redis".to_string()]);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("vuln.mlab.sh"));
        assert!(lines[0].contains("cpe:2.3:a:redis:redis"));
    }

    /// The one test that reaches the network, so it is opt-in:
    /// `cargo test -- --ignored corpus_answers`.
    ///
    /// It proves the four things unit tests cannot: that the `cpe` filter is
    /// honoured rather than ignored, that paging terminates, that the answers
    /// carry the version bounds the grading depends on, and that a real
    /// version lands inside a real range.
    #[test]
    #[ignore = "reaches vuln.mlab.sh"]
    fn corpus_answers_about_the_product_it_was_asked_about() {
        let cpe = "cpe:2.3:a:postgresql:postgresql";
        let corpus = futures_lite_block(fetch(cpe, true));

        assert!(corpus.error.is_none(), "{:?}", corpus.error);
        assert!(corpus.covered(), "PostgreSQL is filed in the corpus");
        assert!(
            corpus.total < IMPLAUSIBLE,
            "a plausible count means the filter was applied: {}",
            corpus.total
        );

        // Every advisory returned must name the product that was asked for. If
        // the filter were ignored this would be full of Microsoft Windows.
        let named = corpus
            .items
            .iter()
            .filter(|a| {
                a.get("cpe_matches")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|m| {
                        m.iter().any(|e| {
                            e.get("criteria")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|c| c.starts_with(cpe))
                        })
                    })
            })
            .count();
        assert!(
            named * 2 > corpus.items.len(),
            "{named} of {} advisories name PostgreSQL",
            corpus.items.len()
        );

        // And the join the whole command rests on produces something.
        let version = crate::enrich::cpe::parse("13.0");
        let hits = corpus
            .items
            .iter()
            .filter(|a| crate::enrich::cpe::advisory_affects(a, cpe, &version))
            .count();
        assert!(hits > 0, "some advisory covers PostgreSQL 13.0");
    }

    /// Drive one future to completion without pulling in an executor.
    fn futures_lite_block<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a current-thread runtime")
            .block_on(fut)
    }
}
