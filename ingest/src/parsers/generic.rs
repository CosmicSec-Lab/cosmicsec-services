use super::Parser;
use crate::normalizer::{Finding, Severity};
use anyhow::Result;
use serde_json::Value;

/// Generic JSON finding parser.
///
/// Accepts either a JSON array of finding objects or a single JSON object.
/// Mapping is best-effort using common field names across tools.
pub struct GenericJsonParser;

impl Parser for GenericJsonParser {
    fn name(&self) -> &'static str {
        "generic_json"
    }

    fn parse(&self, scan_id: &str, raw: &[u8]) -> Result<Vec<Finding>> {
        let value: Value = serde_json::from_slice(raw)
            .map_err(|e| anyhow::anyhow!("generic JSON parse error: {e}"))?;

        let items: Vec<&Value> = match &value {
            Value::Array(arr) => arr.iter().collect(),
            obj @ Value::Object(_) => vec![obj],
            _ => return Ok(vec![]),
        };

        let mut findings = Vec::new();

        for item in items {
            if let Some(f) = map_finding(scan_id, item) {
                findings.push(f);
            }
        }

        Ok(findings)
    }
}

/// Attempt to map a single JSON object to a `Finding`.
fn map_finding(scan_id: &str, item: &Value) -> Option<Finding> {
    let title = str_field(item, &["title", "name", "vulnerability", "check_id", "rule_id"])
        .unwrap_or_else(|| "Generic Finding".to_owned());

    let mut f = Finding::new(scan_id, title);

    if let Some(s) = str_field(item, &["description", "message", "details", "summary"]) {
        f.description = s;
    }
    if let Some(s) = str_field(item, &["severity", "risk", "impact", "priority"]) {
        f.severity = Severity::from_str(&s);
    }
    if let Some(s) = str_field(item, &["host", "target", "ip", "address"]) {
        f.host = s;
    }
    if let Some(s) = str_field(item, &["recommendation", "solution", "remediation", "fix"]) {
        f.recommendation = s;
    }
    if let Some(s) = str_field(item, &["category", "type", "class", "owasp"]) {
        f.category = s;
    }
    if let Some(s) = str_field(item, &["cve", "cve_id", "cve-id"]) {
        f.cve_id = Some(s);
    }
    if let Some(v) = num_field(item, &["cvss", "cvss_score", "score"]) {
        f.cvss_score = Some(v);
    }
    if let Some(v) = num_field(item, &["port"]) {
        f.port = Some(v as u16);
    }
    if let Some(s) = str_field(item, &["protocol", "proto"]) {
        f.protocol = Some(s);
    }

    // Store the raw JSON item as evidence
    f.raw_evidence = serde_json::to_string_pretty(item).unwrap_or_default();
    f.truncate_evidence(4096);

    Some(f)
}

fn str_field(item: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(Value::String(s)) = item.get(key) {
            return Some(s.clone());
        }
    }
    None
}

fn num_field(item: &Value, keys: &[&str]) -> Option<f32> {
    for key in keys {
        match item.get(key) {
            Some(Value::Number(n)) => return n.as_f64().map(|v| v as f32),
            Some(Value::String(s)) => {
                if let Ok(v) = s.parse::<f32>() {
                    return Some(v);
                }
            }
            _ => {}
        }
    }
    None
}
