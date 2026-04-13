/// Nikto plain-text output parser.
use crate::error::ParseError;
use crate::schema::{Finding, SeverityLevel};

/// Map an OSVDB ID to a severity level.
fn severity_for_osvdb(osvdb_id: u64) -> SeverityLevel {
    match osvdb_id {
        1..=999 => SeverityLevel::Low,
        1000..=4999 => SeverityLevel::Medium,
        5000..=9999 => SeverityLevel::High,
        _ => SeverityLevel::Medium,
    }
}

/// Parse nikto plain-text output and return a list of findings.
///
/// Finding lines start with `+`.  Metadata lines (Target IP, port, etc.) are
/// used to populate the `target` and `evidence` fields.
pub fn parse_nikto_text(text: &str) -> Result<Vec<Finding>, ParseError> {
    let mut findings: Vec<Finding> = Vec::new();
    let mut target_ip = String::from("unknown");
    let mut target_host = String::from("unknown");
    let mut target_port = String::from("80");

    for line in text.lines() {
        // Extract metadata
        if let Some(rest) = line.strip_prefix("+ Target IP:") {
            target_ip = rest.trim().to_string();
            continue;
        }
        if let Some(rest) = line.strip_prefix("+ Target Hostname:") {
            target_host = rest.trim().to_string();
            continue;
        }
        if let Some(rest) = line.strip_prefix("+ Target Port:") {
            target_port = rest.trim().to_string();
            continue;
        }

        if !line.starts_with('+') {
            continue;
        }

        let content = line[1..].trim();
        // Skip summary / header lines
        if content.starts_with("Target")
            || content.starts_with("Start Time")
            || content.starts_with("End Time")
            || content.starts_with("1 host")
        {
            continue;
        }

        let severity = extract_osvdb_severity(content);
        let target = if target_host != "unknown" {
            target_host.clone()
        } else {
            target_ip.clone()
        };

        let title: String = content.chars().take(120).collect();
        findings.push(Finding::new(
            title,
            severity,
            content,
            format!("{}:{}", target, target_port),
            "nikto",
            target,
        ));
    }

    Ok(findings)
}

fn extract_osvdb_severity(content: &str) -> SeverityLevel {
    // Look for OSVDB-<number> pattern
    if let Some(pos) = content.find("OSVDB-") {
        let rest = &content[pos + 6..];
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(id) = digits.parse::<u64>() {
            return severity_for_osvdb(id);
        }
    }
    SeverityLevel::Info
}
