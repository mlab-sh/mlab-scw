//! Rendering.
//!
//! The default is a plain, quiet terminal render: two-space indent, dimmed
//! labels, one blank line around each block. `-o json` switches every command
//! to raw JSON on stdout, untouched and parsable — nothing is humanized there,
//! so a pipeline always sees exactly what the API returned.

use std::sync::atomic::{AtomicU8, Ordering};

use colored::Colorize;
use serde_json::Value;

use crate::scw;

/// Longest cell a table will print before truncating; a UUID (36) still fits.
const MAX_CELL: usize = 44;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Human,
    Json,
}

static FORMAT: AtomicU8 = AtomicU8::new(0);

/// Resolve the format once at startup. Anything unknown means human.
pub fn init(format: Option<&str>) {
    let v = match format
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("json") => 1,
        _ => 0,
    };
    FORMAT.store(v, Ordering::SeqCst);
}

pub fn format() -> Format {
    match FORMAT.load(Ordering::SeqCst) {
        1 => Format::Json,
        _ => Format::Human,
    }
}

pub fn is_json() -> bool {
    format() == Format::Json
}

/// A table column: a header plus the JSON paths to try, in order.
pub struct Col(pub &'static str, pub &'static [&'static str]);

/// Projects of the organization.
pub const PROJECT_COLS: &[Col] = &[
    Col("NAME", &["name"]),
    Col("ID", &["id"]),
    Col("CREATED", &["created_at"]),
    Col("DESCRIPTION", &["description"]),
];

/// What an API key turns out to be, once IAM is asked about it.
pub const GRANT_COLS: &[Col] = &[
    Col("POLICY", &["policy"]),
    Col("PERMISSION SET", &["permissionSet"]),
    Col("SCOPE", &["scope"]),
    Col("ON", &["on"]),
];

/// The audit catalogue: one row per readable resource.
pub const CATALOG_COLS: &[Col] = &[
    Col("PRODUCT", &["product"]),
    Col("RESOURCE", &["resource"]),
    Col("SCOPE", &["scope"]),
    Col("PERMISSION SET", &["permission"]),
    Col("PATH", &["path"]),
];

// ---- blocks -----------------------------------------------------------------

/// A section title, printed above a block.
pub fn heading(text: &str) {
    if is_json() {
        return;
    }
    println!();
    println!("  {}", text.bold());
}

/// The count line closing a list.
pub fn count(n: usize, noun: &str) {
    if is_json() {
        return;
    }
    println!();
    println!("  {}", format!("{n} {}", plural(noun, n)).dimmed());
}

/// English plural, enough for the nouns this CLI counts.
fn plural(noun: &str, n: usize) -> String {
    if n == 1 {
        return noun.to_string();
    }
    match noun.chars().last() {
        // "policy" -> "policies", but "day" -> "days": only a consonant before
        // the y takes the -ies form.
        Some('y') if !noun.ends_with(['a', 'e', 'i', 'o', 'u', 'y']) => noun.to_string(),
        Some('y') => format!("{}ies", &noun[..noun.len() - 1]),
        Some('s') | Some('x') | Some('z') => format!("{noun}es"),
        _ => format!("{noun}s"),
    }
}

/// An aligned key/value block, for status output the CLI composes itself
/// rather than reading from the API.
pub fn pairs(rows: &[(&str, String)]) {
    if is_json() {
        return;
    }
    let width = rows
        .iter()
        .map(|(k, _)| k.chars().count())
        .max()
        .unwrap_or(0);
    println!();
    for (k, v) in rows {
        println!("  {:<width$}  {}", k.dimmed(), tint(v));
    }
    println!();
}

/// Render one value: an object as a key/value block, anything else inline.
pub fn one(v: &Value) {
    if is_json() {
        print_json(v);
        return;
    }
    println!();
    block(v, 2);
    println!();
}

/// Render a list with known columns.
pub fn list(rows: &[Value], cols: &[Col]) {
    let spec: Vec<(String, Vec<String>)> = cols
        .iter()
        .map(|c| (c.0.to_string(), c.1.iter().map(|p| p.to_string()).collect()))
        .collect();
    render(rows, &spec);
}

/// Render a list whose shape is only known at runtime, i.e. `api ... --list`:
/// columns are the scalar fields of the first row.
pub fn list_auto(rows: &[Value]) {
    render(rows, &auto_spec(rows));
}

fn auto_spec(rows: &[Value]) -> Vec<(String, Vec<String>)> {
    const MAX_COLS: usize = 8;
    let Some(map) = rows.first().and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut keys: Vec<&String> = map
        .iter()
        .filter(|(_, v)| !matches!(v, Value::Object(_) | Value::Array(_)))
        .map(|(k, _)| k)
        .collect();
    // Identity first, then the switches, then everything else. In this API a
    // boolean is almost always a control — `is_public`, `protected`,
    // `disable_auth`, `allow_insecure` — so when eight columns have to stand in
    // for forty fields, the booleans are the ones an auditor came for.
    keys.sort_by_key(|k| {
        let is_switch = u8::from(!map[*k].is_boolean());
        (rank(k), is_switch, k.to_string())
    });
    keys.into_iter()
        .take(MAX_COLS)
        .map(|k| (k.to_uppercase(), vec![k.clone()]))
        .collect()
}

fn render(rows: &[Value], spec: &[(String, Vec<String>)]) {
    if is_json() {
        print_json(&Value::Array(rows.to_vec()));
        return;
    }
    if rows.is_empty() || spec.is_empty() {
        println!();
        println!("  {}", "no results".dimmed());
        return;
    }

    // Keep only the columns that actually carry data on this console.
    let used: Vec<&(String, Vec<String>)> = spec
        .iter()
        .filter(|c| {
            let paths: Vec<&str> = c.1.iter().map(String::as_str).collect();
            rows.iter().any(|r| !first(r, &paths).is_empty())
        })
        .collect();
    if used.is_empty() {
        println!();
        println!("  {}", "no results".dimmed());
        return;
    }

    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            used.iter()
                .map(|c| {
                    let paths: Vec<&str> = c.1.iter().map(String::as_str).collect();
                    clip(&cell(row, &paths))
                })
                .collect()
        })
        .collect();

    let mut widths: Vec<usize> = used.iter().map(|c| c.0.chars().count()).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }

    println!();
    let head: Vec<String> = used.iter().map(|c| c.0.clone()).collect();
    println!("  {}", pad_join(&head, &widths, |s| s.dimmed().to_string()));
    for row in &cells {
        println!("  {}", pad_join(row, &widths, |s| tint(s).to_string()));
    }
}

/// Pad every cell but the last to its column width, then colour it.
fn pad_join(cells: &[String], widths: &[usize], paint: impl Fn(&str) -> String) -> String {
    let mut out = String::new();
    for (i, c) in cells.iter().enumerate() {
        out.push_str(&paint(c));
        if i + 1 != cells.len() {
            out.push_str(&" ".repeat(widths[i].saturating_sub(c.chars().count()) + 2));
        }
    }
    out.trim_end().to_string()
}

/// A key/value block, recursing into nested objects and tables of objects.
fn block(v: &Value, indent: usize) {
    let pad = " ".repeat(indent);
    let Some(map) = v.as_object() else {
        println!("{pad}{}", tint(&scalar(v)));
        return;
    };

    let mut keys: Vec<&String> = map.keys().collect();
    keys.sort_by_key(|k| (rank(k), k.to_string()));

    let width = keys
        .iter()
        .filter(|k| !matches!(map[**k], Value::Object(_) | Value::Array(_)))
        .map(|k| k.chars().count())
        .max()
        .unwrap_or(0);

    // Scalars first, so the identity of the thing is at the top of the block.
    for k in &keys {
        match &map[*k] {
            Value::Object(_) | Value::Array(_) => {}
            val => println!("{pad}{:<width$}  {}", k.dimmed(), tint(&humanize(k, val))),
        }
    }

    for k in &keys {
        // A branch that would print nothing but its own title is noise.
        if !has_content(&map[*k]) {
            continue;
        }
        match &map[*k] {
            Value::Array(items) if items.iter().all(|i| i.is_object()) => {
                println!();
                println!("{pad}{}", k.bold());
                let spec = auto_spec(items);
                for line in table_lines(items, &spec) {
                    println!("{pad}  {line}");
                }
            }
            Value::Array(items) => {
                let joined = items.iter().map(scalar).collect::<Vec<_>>().join(", ");
                println!("{pad}{:<width$}  {}", k.dimmed(), tint(&clip(&joined)));
            }
            Value::Object(_) => {
                println!();
                println!("{pad}{}", k.bold());
                block(&map[*k], indent + 2);
            }
            _ => {}
        }
    }
}

/// The lines of a sub-table, so a nested block can indent them.
fn table_lines(rows: &[Value], spec: &[(String, Vec<String>)]) -> Vec<String> {
    if spec.is_empty() {
        return Vec::new();
    }
    let cells: Vec<Vec<String>> = rows
        .iter()
        .map(|row| {
            spec.iter()
                .map(|c| {
                    let paths: Vec<&str> = c.1.iter().map(String::as_str).collect();
                    clip(&cell(row, &paths))
                })
                .collect()
        })
        .collect();

    let mut widths: Vec<usize> = spec.iter().map(|c| c.0.chars().count()).collect();
    for row in &cells {
        for (i, c) in row.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count());
        }
    }

    let mut out = vec![pad_join(
        &spec.iter().map(|c| c.0.clone()).collect::<Vec<_>>(),
        &widths,
        |s| s.dimmed().to_string(),
    )];
    out.extend(
        cells
            .iter()
            .map(|r| pad_join(r, &widths, |s| tint(s).to_string())),
    );
    out
}

/// Print raw JSON on stdout. The only thing `-o json` ever emits.
pub fn print_json(v: &Value) {
    println!(
        "{}",
        serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string())
    );
}

// ---- helpers ----------------------------------------------------------------

/// Whether a value carries anything printable, however deeply nested.
fn has_content(v: &Value) -> bool {
    match v {
        Value::Object(m) => m.values().any(has_content),
        Value::Array(a) => a.iter().any(has_content),
        Value::Null => false,
        _ => true,
    }
}

/// Identity fields float to the top of a block and to the left of a table.
fn rank(key: &str) -> u8 {
    match key {
        "name" | "idx" => 0,
        "id" => 1,
        "status" | "state" => 2,
        "type" => 3,
        "region" | "zone" => 4,
        // Which project a thing is in matters, but never as much as what the
        // thing is: two 36-character UUIDs will crowd every switch off an
        // eight-column table if they are allowed to sort early.
        "project_id" => 60,
        "organization_id" => 61,
        _ => 50,
    }
}

/// Colour a cell by what it says: statuses read faster than they scan.
fn tint(s: &str) -> colored::ColoredString {
    match s {
        "running" | "ready" | "available" | "enabled" | "true" => s.green(),
        // `locked` is not a state a healthy resource reaches: it means Scaleway
        // has suspended it, usually for payment or abuse.
        "stopped" | "error" | "locked" | "failed" | "unavailable" => s.red(),
        // `false` is an absence, not a fault — an inventory of things that are
        // simply switched off must not read as a wall of errors.
        "false" => s.dimmed(),
        "starting" | "stopping" | "pending" | "provisioning" | "creating" | "configuring"
        | "unknown" | "denied" => s.yellow(),
        "deleting" | "deleted" | "skipped" => s.dimmed(),
        "public" => s.red(),
        "private" => s.green(),
        "ok" | "pass" => s.green(),
        "appeared" => s.yellow(),
        "disappeared" => s.dimmed(),
        "changed" => s.cyan(),
        "critical" => s.red().bold(),
        "high" => s.red(),
        "medium" => s.yellow(),
        "low" | "info" => s.dimmed(),
        "" => s.normal(),
        _ => s.normal(),
    }
}

/// Units and dates the API leaves raw. Only applied to unambiguously named
/// keys, and only in human mode — `-o json` keeps the original values, because
/// a pipeline wants the timestamp, not "3y ago".
fn humanize(key: &str, v: &Value) -> String {
    let raw = scalar(v);

    // Every date the API returns is RFC 3339, and the question one answers in
    // an audit is almost always "how old is this" — a key created three years
    // ago is a finding, and 2022-11-08T09:14:02Z is arithmetic homework.
    if key.ends_with("_at") {
        if let Some(epoch) = v.as_str().and_then(scw::epoch_of) {
            return format!(
                "{raw}  {}",
                format!("({})", scw::relative(scw::now() - epoch)).dimmed()
            );
        }
    }

    // Sizes are bytes. `memory_limit` and `cpu_limit` are deliberately left
    // alone: those are megabytes and millicores, and guessing wrong prints a
    // confident lie.
    if key == "size" || key.ends_with("_size") || key.ends_with("_capacity") {
        if let Some(n) = v.as_u64() {
            if n >= 1024 {
                return format!("{raw}  {}", format!("({})", scw::bytes(n)).dimmed());
            }
        }
    }

    raw
}

/// First non-empty value among `paths`, as a display string.
fn first(v: &Value, paths: &[&str]) -> String {
    for p in paths {
        if let Some(found) = dig(v, p) {
            let s = scalar(found);
            if !s.is_empty() {
                return s;
            }
        }
    }
    String::new()
}

/// The same, rendered for a table cell.
///
/// A column knows which field it came from, which is the one thing `first`
/// throws away — and it is what tells a timestamp apart from a string that
/// merely looks like one.
fn cell(v: &Value, paths: &[&str]) -> String {
    for p in paths {
        if let Some(found) = dig(v, p) {
            let s = scalar(found);
            if !s.is_empty() {
                return tabular(p, found, &s);
            }
        }
    }
    String::new()
}

/// A value narrowed to what fits a column.
///
/// Dates lose their time and gain their age: in a table, the microseconds of
/// `2022-05-17T17:47:51.178901Z` are eight characters of noise, and what an
/// auditor reads the column for is "four years old". The full value is one
/// `-o json` away, and is what a block prints.
fn tabular(key: &str, v: &Value, raw: &str) -> String {
    if key.ends_with("_at") || key.ends_with("_before") || key.ends_with("_after") {
        if let Some(epoch) = v.as_str().and_then(scw::epoch_of) {
            let day = raw.split('T').next().unwrap_or(raw);
            return format!("{day}  ({})", scw::relative(scw::now() - epoch));
        }
    }
    raw.to_string()
}

/// Follow a dotted path into a JSON object.
fn dig<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = v;
    for part in path.split('.') {
        cur = cur.get(part)?;
    }
    Some(cur)
}

/// One-line rendering of a value; nested ones fall back to compact JSON.
fn scalar(v: &Value) -> String {
    match v {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        // An empty list is an absence, not the two characters "[]", and a list
        // of scalars reads better as a list than as JSON.
        Value::Array(a) if a.is_empty() => String::new(),
        Value::Array(a) if a.iter().all(|i| !i.is_object() && !i.is_array()) => {
            a.iter().map(scalar).collect::<Vec<_>>().join(", ")
        }
        other => other.to_string(),
    }
}

/// Truncate an over-long cell so one field cannot wreck the alignment.
fn clip(s: &str) -> String {
    if s.chars().count() <= MAX_CELL {
        return s.to_string();
    }
    let kept: String = s.chars().take(MAX_CELL - 1).collect();
    format!("{kept}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_unknown_or_missing_format_falls_back_to_human() {
        init(None);
        assert_eq!(format(), Format::Human);
        init(Some("banana"));
        assert_eq!(format(), Format::Human);
        init(Some("JSON"));
        assert!(is_json(), "the format is matched case-insensitively");
        init(None);
    }

    #[test]
    fn auto_columns_are_scalars_only_with_identity_first() {
        let rows = vec![json!({"zzz": 1, "name": "ap", "ports": [{"idx": 1}], "id": "x"})];
        let cols: Vec<String> = auto_spec(&rows).into_iter().map(|c| c.0).collect();
        assert_eq!(
            cols,
            vec!["NAME", "ID", "ZZZ"],
            "nested fields stay out of the table"
        );
    }

    #[test]
    fn a_switch_outranks_a_scoping_uuid_when_columns_run_out() {
        // Taken from a real Container Registry namespace: `is_public` is the
        // entire reason to read the resource, and two UUIDs nobody reads were
        // pushing it off the table.
        let rows = vec![json!({
            "name": "mlab", "id": "n-1", "status": "ready", "region": "fr-par",
            "project_id": "p-1", "organization_id": "o-1",
            "is_public": false, "image_count": 15, "size": 4096,
            "description": "", "endpoint": "rg.fr-par.scw.cloud/mlab",
            "created_at": "2025-04-03T12:47:40Z", "updated_at": "2025-04-03T12:47:40Z"
        })];
        let cols: Vec<String> = auto_spec(&rows).into_iter().map(|c| c.0).collect();
        let at = |c: &str| cols.iter().position(|x| x == c);
        assert!(
            at("IS_PUBLIC").is_some(),
            "the switch made the table: {cols:?}"
        );
        assert!(
            at("IS_PUBLIC") < at("PROJECT_ID").or(Some(usize::MAX)),
            "and it came before the scoping UUIDs: {cols:?}"
        );
        assert_eq!(cols[0], "NAME");
    }

    #[test]
    fn a_path_can_be_dotted_with_fallbacks() {
        let v = json!({"meta": {"name": "HQ"}});
        assert_eq!(first(&v, &["name", "meta.name"]), "HQ");
        assert_eq!(first(&v, &["nope"]), "");
    }

    #[test]
    fn dates_gain_an_age_and_sizes_gain_a_unit() {
        assert!(
            humanize("created_at", &json!("2020-01-01T00:00:00Z")).contains("ago"),
            "a date is worth reading as an age"
        );
        assert!(humanize("size", &json!(107_374_182_400u64)).contains("100.0 GiB"));
        assert_eq!(
            humanize("memory_limit", &json!(2048)),
            "2048",
            "megabytes are not bytes, so this one is left alone"
        );
        assert_eq!(
            humanize("size", &json!(512)),
            "512",
            "small numbers stay raw"
        );
    }

    #[test]
    fn a_table_shows_the_day_and_the_age_rather_than_the_microseconds() {
        let got = tabular(
            "created_at",
            &json!("2022-05-17T17:47:51.178901Z"),
            "2022-05-17T17:47:51.178901Z",
        );
        assert!(got.starts_with("2022-05-17  ("), "{got}");
        assert!(got.ends_with("ago)"), "{got}");
        assert!(
            !got.contains("178901"),
            "the microseconds are noise in a column"
        );
    }

    #[test]
    fn a_column_that_is_not_a_date_passes_through_untouched() {
        assert_eq!(tabular("name", &json!("prod-at"), "prod-at"), "prod-at");
        assert_eq!(
            tabular("created_at", &json!("never"), "never"),
            "never",
            "a word in a date field is not a date"
        );
    }

    #[test]
    fn a_field_that_only_looks_like_a_date_is_left_alone() {
        assert_eq!(humanize("created_at", &json!("never")), "never");
        assert_eq!(humanize("created_at", &json!(17)), "17");
        assert_eq!(
            humanize("name", &json!("2020-01-01T00:00:00Z")),
            "2020-01-01T00:00:00Z"
        );
    }

    #[test]
    fn a_branch_with_nothing_in_it_is_not_printable() {
        assert!(!has_content(&json!({"switching": {"lags": []}})));
        assert!(!has_content(&json!({})));
        assert!(has_content(&json!({"switching": {"lags": [{"id": 1}]}})));
        assert!(
            has_content(&json!(false)),
            "false is a value, not an absence"
        );
    }

    #[test]
    fn nouns_are_pluralized_rather_than_suffixed() {
        assert_eq!(plural("device", 2), "devices");
        assert_eq!(plural("policy", 2), "policies", "not \"policys\"");
        assert_eq!(plural("client", 1), "client");
        assert_eq!(plural("zone", 0), "zones", "none is still plural");
    }

    #[test]
    fn lists_read_as_lists_and_an_empty_one_reads_as_nothing() {
        assert_eq!(scalar(&json!([])), "", "an empty list is an absence");
        assert_eq!(scalar(&json!(["CVE-1", "CVE-2"])), "CVE-1, CVE-2");
        assert_eq!(
            scalar(&json!([{"a": 1}])),
            "[{\"a\":1}]",
            "objects still fall back to JSON"
        );
    }

    #[test]
    fn long_cells_are_clipped_to_keep_columns_aligned() {
        let long = "x".repeat(80);
        assert_eq!(clip(&long).chars().count(), MAX_CELL);
        assert!(clip(&long).ends_with('…'));
        assert_eq!(clip("short"), "short");
    }
}
