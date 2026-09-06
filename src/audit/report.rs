//! Printing a finding list.
//!
//! Shared by every audit command, because the shape of the output is a
//! decision about readability rather than about any one product.

use colored::Colorize;

use super::Finding;
use crate::ui::render;

/// Longest subject list printed before it stops being a report and starts being
/// a data dump. The rest is one `-o json` away.
const MAX_SUBJECTS: usize = 25;

/// Print findings grouped by check, worst first.
///
/// One check firing on thirteen keys is one finding about thirteen keys, not
/// thirteen findings. Repeating the same two-line explanation under each of
/// them buries every *other* check below a wall of identical prose — which is
/// exactly how audit output stops being read.
pub fn print(findings: &[&Finding]) {
    let mut severity = "";
    let mut i = 0;

    while i < findings.len() {
        let f = findings[i];
        if f.severity.as_str() != severity {
            severity = f.severity.as_str();
            println!();
            println!("  {}", paint(severity, &severity.to_uppercase()).bold());
        }

        // Findings are sorted by severity then id, so a group is contiguous.
        let end = findings[i..]
            .iter()
            .position(|x| x.id != f.id)
            .map_or(findings.len(), |n| i + n);
        let group = &findings[i..end];
        i = end;

        println!();
        let count = if group.len() == 1 {
            String::new()
        } else {
            format!("  {}", format!("×{}", group.len()).bold())
        };
        println!("  {}{count}", f.id.dimmed());

        // When every subject earned the finding for the same reason, the reason
        // is a property of the check and belongs above the list. When they
        // differ, the difference *is* the evidence and has to stay attached.
        if group.iter().all(|x| x.detail == f.detail) {
            println!("  {}", render::wrap(&f.detail, 2));
            for x in group.iter().take(MAX_SUBJECTS) {
                println!("    {}", x.subject);
            }
        } else {
            for x in group.iter().take(MAX_SUBJECTS) {
                println!("    {}", x.subject.bold());
                println!("      {}", render::wrap(&x.detail, 6).dimmed());
            }
        }
        if group.len() > MAX_SUBJECTS {
            println!(
                "    {}",
                format!(
                    "… and {} more; -o json for all of them",
                    group.len() - MAX_SUBJECTS
                )
                .dimmed()
            );
        }
    }
}

/// The count of each severity present, in order.
pub fn tally(findings: &[&Finding]) {
    let mut parts = Vec::new();
    for level in ["critical", "high", "medium", "low", "info"] {
        let n = findings
            .iter()
            .filter(|f| f.severity.as_str() == level)
            .count();
        if n > 0 {
            parts.push(format!("{n} {}", paint(level, level)));
        }
    }
    if !parts.is_empty() {
        println!();
        println!("  {}", parts.join("  ·  "));
        println!();
    }
}

pub fn paint(severity: &str, text: &str) -> colored::ColoredString {
    match severity {
        "critical" => text.red().bold(),
        "high" => text.red(),
        "medium" => text.yellow(),
        "low" => text.cyan(),
        _ => text.dimmed(),
    }
}

/// Worst first. An unknown level sorts with the noise.
pub fn rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_severity_floor_includes_everything_worse_than_it() {
        assert!(rank("critical") < rank("high"));
        assert!(rank("low") < rank("info"));
        assert_eq!(rank("banana"), rank("info"), "an unknown level is noise");
    }
}
