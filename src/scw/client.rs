//! HTTP handler for the Scaleway API.
//!
//! One base URL (`https://api.scaleway.com`), one header (`X-Auth-Token`), and
//! a path that names the product, its version, its locality and the resource:
//!
//! ```text
//! https://api.scaleway.com/instance/v1/zones/fr-par-1/servers
//!                         └ product  └ ver  └ locality  └ resource
//! ```
//!
//! What differs between products is only how they paginate; see [`Paging`].

use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde_json::Value;

use crate::scw::config::Profile;

/// Cap on a response body, so a misbehaving endpoint cannot exhaust memory.
const MAX_RESPONSE_BYTES: usize = 64 << 20;

/// Page size when walking every page. 100 is the ceiling most products accept.
const PAGE_SIZE: u32 = 100;

/// Refuse to walk forever if an endpoint never stops handing out pages.
const MAX_PAGES: u32 = 500;

/// How many times a request is retried before the error is the answer.
///
/// A full sweep is thirty-six product APIs over ten zones, which is enough
/// requests to meet Scaleway's rate limiter on a normal afternoon. A 429 is not
/// a finding, it is a queue, and a tool that reports "could not read Instances
/// in pl-waw-2" because it did not wait two seconds is worse than useless: it
/// reports an absence of exposure that was never checked.
const MAX_RETRIES: u32 = 3;

/// Ceiling on a server-suggested wait, so a `Retry-After: 3600` cannot hang the
/// run for an hour without anyone seeing why.
const MAX_BACKOFF: Duration = Duration::from_secs(20);

/// How a product paginates its list endpoints.
///
/// Three styles, because Scaleway's products were not written at the same time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Paging {
    /// `page` + `page_size`, with `total_count` in the body. The common case.
    #[default]
    Page,
    /// `page` + `per_page`. Instances only, and its age shows.
    PerPage,
    /// `page_size` + `page_token`, with `next_page_token` in the body.
    Token,
    /// Not a collection: one GET, one body.
    None,
}

impl Paging {
    fn size_param(&self) -> &'static str {
        match self {
            Paging::PerPage => "per_page",
            _ => "page_size",
        }
    }
}

/// A non-2xx response from the API.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub kind: String,
    pub message: String,
    pub retry_after: Option<u64>,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "API error {}", self.status.as_u16())?;
        if !self.kind.is_empty() {
            write!(f, " [{}]", self.kind)?;
        }
        if !self.message.is_empty() {
            write!(f, ": {}", self.message)?;
        }
        if let Some(ra) = self.retry_after {
            write!(f, " (retry after {ra}s)")?;
        }
        match self.status {
            StatusCode::UNAUTHORIZED => write!(
                f,
                "\nhint: the secret key is wrong, expired, or belongs to a deleted application"
            )?,
            StatusCode::FORBIDDEN => write!(
                f,
                "\nhint: the key authenticates but lacks the permission set for this product; \
                 run `mlab-scw whoami` to see what it holds"
            )?,
            // Several products have to be switched on per project before they
            // answer at all — Messaging & Queuing is the one most people meet.
            // "precondition is not respected" is not a permission problem and
            // not a bug in the request; it means the product is not activated
            // here, which for an audit is a finding rather than a failure.
            StatusCode::PRECONDITION_FAILED => write!(
                f,
                "\nhint: this product is probably not activated in that project; \
                 that is an answer, not an error"
            )?,
            _ => {}
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

/// A configured connection to the Scaleway API.
pub struct Client {
    http: reqwest::Client,
    base: String,
    access_key: String,
    organization_id: String,
    project_id: String,
}

impl Client {
    /// Build a client from a validated profile.
    pub fn new(profile: &Profile, timeout: Duration) -> Result<Self> {
        profile.validate()?;

        let mut headers = HeaderMap::new();
        let mut token = HeaderValue::from_str(profile.secret_key.trim())
            .context("secret key contains characters that cannot go in a header")?;
        token.set_sensitive(true);
        headers.insert("X-Auth-Token", token);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            reqwest::header::USER_AGENT,
            HeaderValue::from_static(concat!("mlab-scw/", env!("CARGO_PKG_VERSION"))),
        );

        let http = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(timeout)
            // The token rides in a default header, which reqwest would replay on
            // a cross-host redirect; refuse to follow one instead.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("building the HTTP client")?;

        Ok(Client {
            http,
            base: profile.api_url(),
            access_key: profile.access_key.clone(),
            organization_id: profile.organization_id.clone(),
            project_id: profile.project_id.clone(),
        })
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn access_key(&self) -> &str {
        &self.access_key
    }

    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// The core handler: one request, one parsed JSON body.
    ///
    /// `path` is absolute on the API host and starts with `/`; it is sent as
    /// given, so callers escape their own path segments.
    pub async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let mut attempt = 0;
        loop {
            let out = self.attempt(method.clone(), path, query, body).await;
            let Err(e) = out else { return out };

            let Some(wait) = e
                .downcast_ref::<ApiError>()
                .and_then(|a| backoff(a, attempt))
                .filter(|_| attempt < MAX_RETRIES)
            else {
                return Err(e);
            };

            attempt += 1;
            crate::ui::info(&format!(
                "{} {path}: {}, retrying in {:.0}s ({attempt}/{MAX_RETRIES})",
                method,
                e.downcast_ref::<ApiError>()
                    .map(|a| a.status.as_u16())
                    .unwrap_or(0),
                wait.as_secs_f64()
            ));
            tokio::time::sleep(wait).await;
        }
    }

    /// One try, with no retry logic in it.
    async fn attempt(
        &self,
        method: Method,
        path: &str,
        query: &[(String, String)],
        body: Option<&Value>,
    ) -> Result<Value> {
        let url = format!("{}{}", self.base, path);
        let mut req = self.http.request(method.clone(), &url);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(b) = body {
            req = req.header(CONTENT_TYPE, "application/json").json(b);
        }

        let resp = req.send().await.map_err(|e| {
            // reqwest hides the interesting part (DNS, refused, TLS) in the
            // source chain, so flatten it before adding a hint.
            let cause = error_chain(&e);
            let mut msg = format!("{method} {url}: {cause}");
            if e.is_timeout() {
                msg.push_str("\nhint: raise --timeout");
            } else if e.is_connect() {
                msg.push_str("\nhint: is api.scaleway.com reachable from here?");
            }
            anyhow!(msg)
        })?;

        let status = resp.status();
        if status.is_redirection() {
            let to = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("(no Location)");
            return Err(anyhow!(
                "{method} {url} redirected to {to}; not following it, the secret key would leak to the new host"
            ));
        }

        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let bytes = resp.bytes().await.context("reading the response body")?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(anyhow!("response body over {MAX_RESPONSE_BYTES} bytes"));
        }

        if !status.is_success() {
            return Err(parse_error(status, &bytes, retry_after).into());
        }
        if bytes.is_empty() {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&bytes).with_context(|| {
            let preview: String = String::from_utf8_lossy(&bytes).chars().take(200).collect();
            format!("decoding the response of {method} {url}: {preview}")
        })
    }

    /// GET a single object.
    pub async fn get(&self, path: &str, query: &[(String, String)]) -> Result<Value> {
        self.request(Method::GET, path, query, None).await
    }

    /// Walk a list endpoint to the end.
    ///
    /// `collection` is the body field holding the items; `None` takes the first
    /// array in the body, which is what every Scaleway list response has
    /// exactly one of. `limit` returns a single page of that size instead.
    pub async fn list(
        &self,
        path: &str,
        query: &[(String, String)],
        paging: Paging,
        collection: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        if paging == Paging::None {
            // A singleton GET answers with the object itself. `items_of` would
            // find no array in it and report an absence, which for something
            // like Cockpit's alert manager is exactly the wrong answer.
            let v = self.get(path, query).await?;
            let items = items_of(&v, collection);
            return Ok(if items.is_empty() && v.is_object() {
                vec![v]
            } else {
                items
            });
        }
        if paging == Paging::Token {
            return self.list_token(path, query, collection, limit).await;
        }

        let size = limit.unwrap_or(PAGE_SIZE);
        let mut out = Vec::new();

        for page in 1..=MAX_PAGES {
            let mut q = query.to_vec();
            q.push(("page".into(), page.to_string()));
            q.push((paging.size_param().into(), size.to_string()));

            let body = self.get(path, &q).await?;
            let items = items_of(&body, collection);
            let got = items.len() as u32;
            let total = body.get("total_count").and_then(Value::as_u64);
            out.extend(items);

            // Three ways a walk ends: the caller only wanted one page, the page
            // came back short, or `total_count` says we have them all. The
            // short-page test is the one that matters — `total_count` is absent
            // from a few endpoints and wrong on a couple more.
            if limit.is_some() || got < size || total.is_some_and(|t| out.len() as u64 >= t) {
                break;
            }
        }
        Ok(out)
    }

    /// `page_token` paging: follow `next_page_token` until it stops coming.
    async fn list_token(
        &self,
        path: &str,
        query: &[(String, String)],
        collection: Option<&str>,
        limit: Option<u32>,
    ) -> Result<Vec<Value>> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;

        for _ in 0..MAX_PAGES {
            let mut q = query.to_vec();
            q.push(("page_size".into(), limit.unwrap_or(PAGE_SIZE).to_string()));
            if let Some(t) = &token {
                q.push(("page_token".into(), t.clone()));
            }

            let body = self.get(path, &q).await?;
            out.extend(items_of(&body, collection));

            token = body
                .get("next_page_token")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            if limit.is_some() || token.is_none() {
                break;
            }
        }
        Ok(out)
    }
}

/// The items of a list response.
///
/// A Scaleway list body is `{"<noun>": [...], "total_count": n}` where the noun
/// changes with the endpoint, so the collection is found by shape rather than
/// by name unless the caller knows it.
pub fn items_of(body: &Value, collection: Option<&str>) -> Vec<Value> {
    if let Some(key) = collection {
        return match body.get(key) {
            Some(Value::Array(a)) => a.clone(),
            _ => Vec::new(),
        };
    }
    match body {
        Value::Array(a) => a.clone(),
        Value::Object(map) => map
            .values()
            .find_map(|v| match v {
                Value::Array(a) => Some(a.clone()),
                _ => None,
            })
            .unwrap_or_default(),
        Value::Null => Vec::new(),
        other => vec![other.clone()],
    }
}

/// Turn an API JSON error body into a typed error.
///
/// Scaleway answers with `{"type": "...", "message": "..."}`, but a gateway in
/// front of it can answer with anything at all.
fn parse_error(status: StatusCode, body: &[u8], retry_after: Option<u64>) -> ApiError {
    let text = summarize(&String::from_utf8_lossy(body));

    let (kind, message) = match serde_json::from_slice::<Value>(body) {
        Ok(v) => {
            let kind = v
                .get("type")
                .or_else(|| v.get("error"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let mut message = v
                .get("message")
                .or_else(|| v.get("error_message"))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| text.clone());
            // "invalid argument(s)" on its own is unactionable, and it is what
            // the API says for a missing required query parameter. The detail
            // list names the parameter, so fold it into the message.
            if let Some(d) = details(&v) {
                message.push_str(&format!(": {d}"));
            }
            (kind, message)
        }
        Err(_) => (String::new(), text),
    };

    ApiError {
        status,
        kind,
        message,
        retry_after,
    }
}

/// How long to wait before retrying, or `None` when the answer will not change.
///
/// Retried: 429 (a queue), and 502/503/504 (a gateway between us and the
/// product API). Never retried: anything the account itself decides — a 400, a
/// 401, a 403 and a 404 are all the same answer however many times they are
/// asked, and retrying a 403 across ten zones just makes an audit slow.
///
/// A `Retry-After` is honoured when the server sends one, capped; otherwise the
/// wait doubles from a second.
fn backoff(e: &ApiError, attempt: u32) -> Option<Duration> {
    let retryable = e.status == StatusCode::TOO_MANY_REQUESTS || e.status.is_server_error();
    if !retryable {
        return None;
    }
    let wait = match e.retry_after {
        Some(secs) => Duration::from_secs(secs),
        None => Duration::from_secs(1 << attempt.min(4)),
    };
    Some(wait.min(MAX_BACKOFF))
}

/// Flatten Scaleway's `details` array — `[{argument_name, reason, help_message}]`
/// — into one clause naming the parameters at fault.
fn details(v: &Value) -> Option<String> {
    let items = v.get("details")?.as_array()?;
    let parts: Vec<String> = items
        .iter()
        .filter_map(|d| {
            let name = d.get("argument_name").and_then(Value::as_str)?;
            let reason = match d.get("reason").and_then(Value::as_str) {
                Some("required") => "is required".to_string(),
                Some("format") => "is wrongly formatted".to_string(),
                Some("constraint") => "does not respect a constraint".to_string(),
                Some(other) => format!("is invalid ({other})"),
                None => "is invalid".to_string(),
            };
            let help = d
                .get("help_message")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(|s| format!(" ({s})"))
                .unwrap_or_default();
            Some(format!("{name} {reason}{help}"))
        })
        .collect();
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

/// Reduce a response body to one readable line: markup stripped, whitespace
/// collapsed, truncated. A refusal from a gateway is a whole HTML page, which
/// would otherwise bury the status code under a stylesheet.
fn summarize(body: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    let mut tag = String::new();
    let mut in_opaque = false;
    let mut last_space = true;

    for ch in body.chars() {
        match ch {
            '<' => {
                in_tag = true;
                tag.clear();
            }
            '>' if in_tag => {
                in_tag = false;
                let name = tag.trim().to_ascii_lowercase();
                if name.starts_with("style") || name.starts_with("script") {
                    in_opaque = true;
                } else if name.starts_with("/style") || name.starts_with("/script") {
                    in_opaque = false;
                }
            }
            c if in_tag => tag.push(c),
            _ if in_opaque => {}
            c if c.is_whitespace() => {
                if !last_space {
                    out.push(' ');
                    last_space = true;
                }
            }
            c => {
                out.push(c);
                last_space = false;
                if out.chars().count() >= 160 {
                    out.push('…');
                    break;
                }
            }
        }
    }

    let trimmed = out.trim();
    if trimmed.is_empty() && !body.is_empty() {
        return format!("non-JSON body, {} bytes", body.len());
    }
    trimmed.to_string()
}

/// Flatten an error and its sources into one line.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut parts = vec![e.to_string()];
    let mut src = e.source();
    while let Some(s) = src {
        parts.push(s.to_string());
        src = s.source();
    }
    parts.join(": ")
}

/// Percent-escape one path segment.
pub fn esc(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for b in segment.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn esc_escapes_path_separators() {
        assert_eq!(esc("abc-123_x.y~z"), "abc-123_x.y~z");
        assert_eq!(esc("a/b c"), "a%2Fb%20c");
    }

    #[test]
    fn the_collection_is_found_by_shape_when_it_is_not_named() {
        let body = json!({"total_count": 2, "servers": [{"id": "a"}, {"id": "b"}]});
        assert_eq!(items_of(&body, None).len(), 2);
        assert_eq!(items_of(&body, Some("servers")).len(), 2);
        assert!(
            items_of(&body, Some("clusters")).is_empty(),
            "a named collection that is absent is empty, not the wrong list"
        );
    }

    #[test]
    fn a_body_with_no_collection_yields_nothing_rather_than_itself() {
        assert!(items_of(&json!({"total_count": 0}), None).is_empty());
        assert!(items_of(&Value::Null, None).is_empty());
    }

    #[test]
    fn instances_page_differently_from_everything_else() {
        assert_eq!(Paging::Page.size_param(), "page_size");
        assert_eq!(Paging::PerPage.size_param(), "per_page");
    }

    #[test]
    fn parse_error_reads_the_scaleway_shape_and_survives_anything_else() {
        let e = parse_error(
            StatusCode::FORBIDDEN,
            br#"{"type":"permissions_denied","message":"insufficient permissions"}"#,
            None,
        );
        assert_eq!(e.kind, "permissions_denied");
        assert_eq!(e.message, "insufficient permissions");
        assert!(e.to_string().contains("whoami"));

        let e = parse_error(
            StatusCode::BAD_REQUEST,
            br#"{"type":"invalid_arguments","message":"invalid argument(s)",
                 "details":[{"argument_name":"organization_id","reason":"required",
                             "help_message":"cannot be empty"}]}"#,
            None,
        );
        assert_eq!(
            e.message, "invalid argument(s): organization_id is required (cannot be empty)",
            "the parameter at fault has to reach the user; \"invalid argument(s)\" alone does not"
        );

        let e = parse_error(StatusCode::BAD_GATEWAY, b"<html>nope</html>", Some(3));
        assert_eq!(e.message, "nope");
        assert!(e.to_string().contains("retry after 3s"));
    }

    fn err(status: u16, retry_after: Option<u64>) -> ApiError {
        ApiError {
            status: StatusCode::from_u16(status).unwrap(),
            kind: String::new(),
            message: String::new(),
            retry_after,
        }
    }

    #[test]
    fn only_a_queue_or_a_gateway_is_worth_asking_again() {
        assert!(backoff(&err(429, None), 0).is_some(), "a queue");
        assert!(backoff(&err(503, None), 0).is_some(), "a gateway");
        assert!(
            backoff(&err(403, None), 0).is_none(),
            "a policy does not change"
        );
        assert!(backoff(&err(404, None), 0).is_none());
        assert!(backoff(&err(400, None), 0).is_none());
    }

    #[test]
    fn the_wait_doubles_and_the_server_gets_the_last_word() {
        assert_eq!(backoff(&err(429, None), 0), Some(Duration::from_secs(1)));
        assert_eq!(backoff(&err(429, None), 2), Some(Duration::from_secs(4)));
        assert_eq!(
            backoff(&err(429, Some(7)), 0),
            Some(Duration::from_secs(7)),
            "Retry-After beats our own guess"
        );
        assert_eq!(
            backoff(&err(429, Some(3600)), 0),
            Some(MAX_BACKOFF),
            "but not by an hour"
        );
    }

    #[test]
    fn an_html_error_page_is_reduced_to_a_line() {
        let page = "<!doctype html><html><head><title>502 Bad Gateway</title>\
                    <style>body {font-family:Tahoma;}</style></head>\
                    <body><h1>502 Bad Gateway</h1></body></html>";
        let got = summarize(page);
        assert!(
            got.contains("502 Bad Gateway"),
            "the useful part survives: {got}"
        );
        assert!(!got.contains('<'), "no markup survives");
        assert!(!got.contains("Tahoma"), "the stylesheet goes with its tag");
    }

    #[test]
    fn a_body_with_no_text_at_all_is_described_rather_than_echoed() {
        assert_eq!(
            summarize("<html><body></body></html>"),
            "non-JSON body, 26 bytes"
        );
        assert_eq!(summarize(""), "");
    }
}
