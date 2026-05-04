use crate::normalizer::{Finding, Severity};
use anyhow::Result;
use chrono::Utc;

/// Parser for Semgrep JSON output (`semgrep scan --json`).
pub struct SemgrepParser;

impl super::Parser for SemgrepParser {
    fn parse(&self, scan_id: &str, raw: &[u8]) -> Result<Vec<Finding>> {
        let report: SemgrepReport = serde_json::from_slice(raw)?;
        let mut findings = Vec::new();

        for r in report.results {
            let mut f = Finding::new(scan_id, &r.check_id);
            f.severity = severity_from_semgrep(&r.extra.severity);
            f.description = r.extra.message.clone();
            f.title = format!(
                "{}: {}",
                r.check_id,
                r.extra.message.chars().take(120).collect::<String>(),
            );
            f.category = r
                .extra
                .metadata
                .category
                .unwrap_or_else(|| "security".to_string());
            f.cve_id = r.extra.metadata.cve_id;
            f.cvss_score = r
                .extra
                .metadata
                .cvss_score
                .map(|v| v as f32)
                .filter(|v| *v > 0.0);
            f.recommendation = r.extra.fix_text.unwrap_or_default();
            f.host = r.path.clone();
            f.raw_evidence = format!("File: {}\n{}", r.path, r.extra.lines);
            f.truncate_evidence(4096);
            f.detected_at = Utc::now();
            findings.push(f);
        }

        Ok(findings)
    }

    fn name(&self) -> &'static str {
        "semgrep"
    }
}

#[derive(serde::Deserialize)]
struct SemgrepReport {
    #[serde(default)]
    results: Vec<SemgrepResult>,
}

#[derive(serde::Deserialize)]
struct SemgrepResult {
    #[serde(default)]
    check_id: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    extra: SemgrepExtra,
}

#[derive(serde::Deserialize)]
struct SemgrepExtra {
    #[serde(default)]
    severity: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    lines: String,
    #[serde(default)]
    metadata: SemgrepMetadata,
    #[serde(default)]
    fix_text: Option<String>,
}

#[derive(serde::Deserialize)]
struct SemgrepMetadata {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    cve_id: Option<String>,
    #[serde(default)]
    cvss_score: Option<f64>,
}

fn severity_from_semgrep(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" | "error" => Severity::Critical,
        "high" | "warning" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Unknown,
    }
}
