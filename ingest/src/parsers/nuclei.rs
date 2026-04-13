/// Nuclei JSONL output parser.
use serde_json::Value;

use crate::error::ParseError;
use crate::schema::{Finding, SeverityLevel};

fn map_severity(s: &str) -> SeverityLevel {
    match s.to_lowercase().as_str() {
        "critical" => SeverityLevel::Critical,
        "high" => SeverityLevel::High,
        "medium" => SeverityLevel::Medium,
        "low" => SeverityLevel::Low,
        _ => SeverityLevel::Info,
    }
}

/// Parse nuclei JSONL output (one JSON object per line) into findings.
pub fn parse_nuclei_jsonl(jsonl: &str) -> Result<Vec<Finding>, ParseError> {
    let mut findings: Vec<Finding> = Vec::new();

    for line in jsonl.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let record: Value = serde_json::from_str(line)?;

        let info = record.get("info").and_then(Value::as_object);
        let severity_str = info
            .and_then(|i| i.get("severity"))
            .and_then(Value::as_str)
            .unwrap_or("info");
        let severity = map_severity(severity_str);

        let template_id = record
            .get("template-id")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let name = info
            .and_then(|i| i.get("name"))
            .and_then(Value::as_str)
            .unwrap_or(template_id);
        let description = info
            .and_then(|i| i.get("description"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let matched_at = record
            .get("matched-at")
            .or_else(|| record.get("host"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let host = record
            .get("host")
            .and_then(Value::as_str)
            .unwrap_or(matched_at);

        // Build evidence string
        let mut evidence_parts = vec![matched_at.to_string()];
        if let Some(matcher) = record.get("matcher-name").and_then(Value::as_str) {
            evidence_parts.push(format!("matcher: {}", matcher));
        }
        if let Some(extracted) = record.get("extracted-results").and_then(Value::as_array) {
            let vals: Vec<String> = extracted
                .iter()
                .take(3)
                .filter_map(Value::as_str)
                .map(String::from)
                .collect();
            if !vals.is_empty() {
                evidence_parts.push(format!("extracted: {}", vals.join(", ")));
            }
        }

        let desc = if description.is_empty() {
            format!("Nuclei template {} matched at {}", template_id, matched_at)
        } else {
            description
        };

        findings.push(Finding::new(
            format!("[{}] {}", template_id, name),
            severity,
            desc,
            evidence_parts.join(" | "),
            "nuclei",
            host,
        ));
    }

    Ok(findings)
}
