use super::Parser;
use crate::normalizer::{Finding, Severity};
use anyhow::Result;
use serde::Deserialize;

/// Nuclei JSONL parser.
///
/// Nuclei writes one JSON object per line.  Each line represents a single
/// template match (finding).  We stream line-by-line to avoid loading the
/// entire file into memory.
pub struct NucleiParser;

/// Subset of the Nuclei JSON finding schema.
#[derive(Debug, Deserialize)]
struct NucleiFinding {
    #[serde(rename = "template-id", default)]
    template_id: String,

    #[serde(default)]
    info: NucleiInfo,

    #[serde(rename = "matched-at", default)]
    matched_at: String,

    #[serde(rename = "extracted-results", default)]
    extracted_results: Vec<String>,

    #[serde(default)]
    host: String,

    #[serde(rename = "ip", default)]
    ip: String,

    #[serde(rename = "curl-command", default)]
    curl_command: String,
}

#[derive(Debug, Deserialize, Default)]
struct NucleiInfo {
    #[serde(default)]
    name: String,

    #[serde(default)]
    description: String,

    #[serde(default)]
    severity: String,

    #[serde(default)]
    tags: Vec<String>,

    #[serde(default)]
    classification: NucleiClassification,

    #[serde(default)]
    remediation: String,
}

#[derive(Debug, Deserialize, Default)]
struct NucleiClassification {
    #[serde(rename = "cve-id", default)]
    cve_id: Vec<String>,

    #[serde(rename = "cvss-score", default)]
    cvss_score: Option<f32>,
}

impl Parser for NucleiParser {
    fn name(&self) -> &'static str {
        "nuclei"
    }

    fn parse(&self, scan_id: &str, raw: &[u8]) -> Result<Vec<Finding>> {
        let text = std::str::from_utf8(raw)
            .map_err(|e| anyhow::anyhow!("nuclei output is not valid UTF-8: {e}"))?;

        let mut findings = Vec::new();

        for (line_no, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let nf: NucleiFinding = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(line = line_no, error = %e, "skipping unparseable nuclei line");
                    continue;
                }
            };

            let title = if nf.info.name.is_empty() {
                nf.template_id.clone()
            } else {
                nf.info.name.clone()
            };

            let mut f = Finding::new(scan_id, title);
            f.host = if !nf.host.is_empty() { nf.host } else { nf.ip };
            f.severity = Severity::from_str(&nf.info.severity);
            f.description = nf.info.description.clone();
            f.recommendation = nf.info.remediation.clone();
            f.category = nf.info.tags.first().cloned().unwrap_or_else(|| "nuclei".to_owned());
            f.cve_id = nf.info.classification.cve_id.first().cloned();
            f.cvss_score = nf.info.classification.cvss_score;

            // Build evidence from matched URL + extracted results
            let mut evidence_parts = Vec::new();
            if !nf.matched_at.is_empty() {
                evidence_parts.push(format!("matched-at: {}", nf.matched_at));
            }
            if !nf.extracted_results.is_empty() {
                evidence_parts.push(format!("extracted: {}", nf.extracted_results.join(", ")));
            }
            if !nf.curl_command.is_empty() {
                evidence_parts.push(format!("curl: {}", nf.curl_command));
            }
            f.raw_evidence = evidence_parts.join("\n");
            f.truncate_evidence(4096);

            findings.push(f);
        }

        Ok(findings)
    }
}
