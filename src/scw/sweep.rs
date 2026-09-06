//! Fanning one question out over every locality, concurrently.
//!
//! A Scaleway account is not one place. Asking "what Instances are there" means
//! ten zonal calls; asking it of every product an exposure map needs means a
//! few hundred. Sequentially that is minutes; all at once it is a rate limit.
//!
//! So this is the middle: a bounded pool, and a result that records what came
//! back *and what did not*. A refusal is not a failure here — a key with no
//! `RedisReadOnly` is a key with no Redis findings, and the report has to say
//! which of those it is.

use std::sync::Arc;

use serde_json::Value;
use tokio::task::JoinSet;

use crate::scw::client::ApiError;
use crate::scw::{Client, Paging};

/// How many requests are in flight at once.
///
/// Eight is polite rather than measured: the client already backs off on 429,
/// and an audit that finishes a minute later is worth more than one the
/// account's other users notice.
pub const DEFAULT_CONCURRENCY: usize = 8;

/// One GET to make.
#[derive(Clone)]
pub struct Fetch {
    /// Catalogue keys, so a gap can be reported as `redis/clusters` rather than
    /// as a URL.
    pub product: &'static str,
    pub resource: &'static str,
    /// The region or zone this asks about; empty for a global product.
    pub locality: String,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub paging: Paging,
    pub collection: Option<&'static str>,
}

impl Fetch {
    pub fn new(
        product: &'static str,
        resource: &'static str,
        locality: &str,
        path: String,
    ) -> Self {
        Fetch {
            product,
            resource,
            locality: locality.to_string(),
            path,
            query: Vec::new(),
            paging: Paging::Page,
            collection: None,
        }
    }

    pub fn paging(mut self, paging: Paging) -> Self {
        self.paging = paging;
        self
    }

    pub fn query(mut self, key: &str, value: &str) -> Self {
        self.query.push((key.to_string(), value.to_string()));
        self
    }

    /// `product/resource`, for a gap line.
    pub fn what(&self) -> String {
        format!("{}/{}", self.product, self.resource)
    }
}

/// What one [`Fetch`] produced.
pub struct Fetched {
    pub fetch: Fetch,
    pub items: Vec<Value>,
    /// Why this came back empty, when it did not simply come back empty.
    pub gap: Option<Gap>,
}

/// A question that could not be answered, and what kind of silence it is.
#[derive(Clone, PartialEq, Eq)]
pub struct Gap {
    pub what: String,
    pub locality: String,
    pub kind: GapKind,
    pub detail: String,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GapKind {
    /// 403: the key holds no permission set for this product. The commonest
    /// one, and the one that most changes what a clean report means.
    Denied,
    /// 412: the product is not switched on in that project. An answer.
    NotActivated,
    /// 404 or 501: the product does not serve this locality. Also an answer,
    /// and not worth reporting — Scaleway does not run every product in every
    /// zone, and says so with `501 Not Implemented` rather than a 404.
    Absent,
    /// Anything else: a real failure.
    Failed,
}

impl GapKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            GapKind::Denied => "denied",
            GapKind::NotActivated => "not activated",
            GapKind::Absent => "not available here",
            GapKind::Failed => "failed",
        }
    }

    /// Whether this silence is worth a line in the report.
    ///
    /// `Absent` is not: a product that does not run in `it-mil-1` answering 404
    /// there is the API working correctly, and printing ten of those per
    /// product would bury the one gap that matters.
    pub fn worth_reporting(&self) -> bool {
        !matches!(self, GapKind::Absent)
    }
}

/// Run every fetch, at most `concurrency` at a time, in the order given.
pub async fn sweep(client: Arc<Client>, fetches: Vec<Fetch>, concurrency: usize) -> Vec<Fetched> {
    let mut out: Vec<Option<Fetched>> = (0..fetches.len()).map(|_| None).collect();
    let mut running: JoinSet<(usize, Fetched)> = JoinSet::new();
    let mut queue = fetches.into_iter().enumerate();
    let width = concurrency.max(1);

    loop {
        while running.len() < width {
            let Some((i, f)) = queue.next() else { break };
            let c = Arc::clone(&client);
            running.spawn(async move { (i, one(&c, f).await) });
        }
        let Some(done) = running.join_next().await else {
            break;
        };
        match done {
            Ok((i, fetched)) => out[i] = Some(fetched),
            // A panicked task would otherwise silently become an empty result,
            // which is the one outcome this module exists to prevent.
            Err(e) => panic!("a sweep task did not finish: {e}"),
        }
    }

    out.into_iter().flatten().collect()
}

async fn one(client: &Client, fetch: Fetch) -> Fetched {
    let result = client
        .list(
            &fetch.path,
            &fetch.query,
            fetch.paging,
            fetch.collection,
            None,
        )
        .await;

    match result {
        Ok(items) => Fetched {
            fetch,
            items,
            gap: None,
        },
        Err(e) => {
            let gap = Gap {
                what: fetch.what(),
                locality: fetch.locality.clone(),
                kind: classify(&e),
                detail: format!("{e:#}")
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_string(),
            };
            Fetched {
                fetch,
                items: Vec::new(),
                gap: Some(gap),
            }
        }
    }
}

fn classify(e: &anyhow::Error) -> GapKind {
    use reqwest::StatusCode;
    match e.downcast_ref::<ApiError>().map(|a| a.status) {
        Some(StatusCode::FORBIDDEN) | Some(StatusCode::UNAUTHORIZED) => GapKind::Denied,
        Some(StatusCode::PRECONDITION_FAILED) => GapKind::NotActivated,
        Some(StatusCode::NOT_FOUND) | Some(StatusCode::NOT_IMPLEMENTED) => GapKind::Absent,
        _ => GapKind::Failed,
    }
}

/// Every gap worth telling somebody about, deduplicated by product.
///
/// A key with no `RedisReadOnly` produces ten identical refusals, one per zone.
/// That is one fact about the key, not ten facts about the account.
pub fn gaps(fetched: &[Fetched]) -> Vec<String> {
    let mut seen: Vec<(String, GapKind, Vec<String>)> = Vec::new();

    for f in fetched {
        let Some(gap) = &f.gap else { continue };
        if !gap.kind.worth_reporting() {
            continue;
        }
        match seen
            .iter_mut()
            .find(|(w, k, _)| *w == gap.what && *k == gap.kind)
        {
            Some((_, _, localities)) => localities.push(gap.locality.clone()),
            None => seen.push((gap.what.clone(), gap.kind, vec![gap.locality.clone()])),
        }
    }

    seen.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    seen.into_iter()
        .map(|(what, kind, localities)| {
            let where_ = localities.iter().filter(|l| !l.is_empty()).count();
            if where_ > 1 {
                format!("{what}: {} in {where_} localities", kind.as_str())
            } else {
                format!("{what}: {}", kind.as_str())
            }
        })
        .collect()
}

/// Every item returned for one product and resource, paired with its locality.
pub fn items<'a>(
    fetched: &'a [Fetched],
    product: &str,
    resource: &str,
) -> Vec<(&'a str, &'a Value)> {
    fetched
        .iter()
        .filter(|f| f.fetch.product == product && f.fetch.resource == resource)
        .flat_map(|f| f.items.iter().map(move |v| (f.fetch.locality.as_str(), v)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fetched(
        product: &'static str,
        resource: &'static str,
        locality: &str,
        gap: Option<GapKind>,
    ) -> Fetched {
        Fetched {
            fetch: Fetch::new(product, resource, locality, "/x".into()),
            items: if gap.is_some() {
                Vec::new()
            } else {
                vec![json!({"id": "a"})]
            },
            gap: gap.map(|kind| Gap {
                what: format!("{product}/{resource}"),
                locality: locality.to_string(),
                kind,
                detail: String::new(),
            }),
        }
    }

    #[test]
    fn one_missing_permission_is_one_gap_not_ten() {
        // A key without RedisReadOnly is refused in every zone. That is one
        // fact about the key; printing it ten times buries the gap that is
        // actually about the account.
        let sweep: Vec<Fetched> = ["fr-par-1", "fr-par-2", "nl-ams-1"]
            .iter()
            .map(|z| fetched("redis", "clusters", z, Some(GapKind::Denied)))
            .collect();
        let g = gaps(&sweep);
        assert_eq!(g.len(), 1);
        assert!(g[0].starts_with("redis/clusters: denied"), "{}", g[0]);
        assert!(g[0].contains("3 localities"));
    }

    #[test]
    fn a_product_that_does_not_run_in_a_zone_is_not_a_gap() {
        // Scaleway does not serve every product everywhere; a 404 there is the
        // API working, and ten of those per product would drown the report.
        let sweep = vec![
            fetched("kafka", "clusters", "it-mil-1", Some(GapKind::Absent)),
            fetched("kafka", "clusters", "fr-par", None),
        ];
        assert!(gaps(&sweep).is_empty());
    }

    #[test]
    fn different_silences_about_one_product_stay_apart() {
        let sweep = vec![
            fetched(
                "mnq",
                "sqs-credentials",
                "fr-par",
                Some(GapKind::NotActivated),
            ),
            fetched("mnq", "sqs-credentials", "nl-ams", Some(GapKind::Denied)),
        ];
        let g = gaps(&sweep);
        assert_eq!(
            g.len(),
            2,
            "a refusal and an unactivated product are different facts"
        );
        assert!(g[0].contains("denied"), "worst first: {g:?}");
    }

    #[test]
    fn items_are_returned_with_the_locality_that_produced_them() {
        let sweep = vec![
            fetched("instance", "servers", "fr-par-1", None),
            fetched("instance", "servers", "nl-ams-2", None),
            fetched("instance", "ips", "fr-par-1", None),
        ];
        let found = items(&sweep, "instance", "servers");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, "fr-par-1");
        assert_eq!(found[1].0, "nl-ams-2");
        assert!(items(&sweep, "instance", "nothing").is_empty());
    }
}
